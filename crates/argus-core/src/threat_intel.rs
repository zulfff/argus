use chrono::{DateTime, Utc};
use reqwest::Client;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{info, instrument, warn};

use argus_common::error::{ArgusError, Result};

const BLOCKLIST_TTL_SECONDS: i64 = 86400;
const REFRESH_INTERVAL_SECS: u64 = 3600;
const MAX_BLOCKLIST_SIZE: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct ThreatEntry {
    pub ip: IpAddr,
    pub cidr: Option<String>,
    pub source: String,
    pub reason: String,
    pub added_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct ThreatIntelligence {
    entries: Mutex<HashMap<IpAddr, ThreatEntry>>,
    cidr_entries: Mutex<Vec<ThreatEntry>>,
    client: Client,
    last_refresh: Mutex<Option<DateTime<Utc>>>,
}

impl ThreatIntelligence {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            cidr_entries: Mutex::new(Vec::new()),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("argus-threat-intel/0.1.0")
                .build()
                .expect("failed to build reqwest client"),
            last_refresh: Mutex::new(None),
        }
    }

    #[instrument(skip(self))]
    pub async fn refresh_spamhaus_drop(&self) -> Result<usize> {
        let url = "https://www.spamhaus.org/drop/drop.txt";
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("Spamhaus DROP fetch failed: {}", e)))?;

        let body = response
            .text()
            .await
            .map_err(|e| ArgusError::Network(format!("Spamhaus response read: {}", e)))?;

        let count = self.parse_drop_list(&body, "Spamhaus DROP");
        self.refresh_timestamp();
        info!("Loaded {} entries from Spamhaus DROP", count);
        Ok(count)
    }

    #[instrument(skip(self))]
    pub async fn refresh_spamhaus_edrop(&self) -> Result<usize> {
        let url = "https://www.spamhaus.org/drop/edrop.txt";
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("Spamhaus EDROP fetch failed: {}", e)))?;

        let body = response
            .text()
            .await
            .map_err(|e| ArgusError::Network(format!("Spamhaus EDROP read: {}", e)))?;

        let count = self.parse_drop_list(&body, "Spamhaus EDROP");
        info!("Loaded {} entries from Spamhaus EDROP", count);
        Ok(count)
    }

    #[instrument(skip(self))]
    pub async fn refresh_abuseipdb(&self, api_key: &str, confidence_min: u8) -> Result<usize> {
        if confidence_min > 100 {
            return Err(ArgusError::Validation(
                "AbuseIPDB confidence_min must be 0–100".into(),
            ));
        }
        let url = format!(
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={}",
            confidence_min
        );

        let response = self
            .client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("AbuseIPDB fetch failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ArgusError::External(format!(
                "AbuseIPDB returned {}",
                response.status()
            )));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ArgusError::Network(format!("AbuseIPDB parse: {}", e)))?;

        let mut count = 0;
        let now = Utc::now();

        if let Some(data_list) = json.get("data").and_then(|d| d.as_array()) {
            let mut entries = match self.entries.lock() {
                Ok(e) => e,
                Err(_) => return Ok(0),
            };

            if entries.len() >= MAX_BLOCKLIST_SIZE {
                warn!(
                    "Blocklist full at {} entries, skipping AbuseIPDB",
                    entries.len()
                );
                return Ok(0);
            }

            for item in data_list {
                let ip_str = item.get("ipAddress").and_then(|v| v.as_str()).unwrap_or("");
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    let reason = item
                        .get("abuseConfidenceScore")
                        .and_then(|v| v.as_i64())
                        .map(|s| format!("AbuseIPDB score: {}", s))
                        .unwrap_or_else(|| "AbuseIPDB blacklist".into());

                    let ttl_hours = item
                        .get("lastReportedAt")
                        .map(|_| BLOCKLIST_TTL_SECONDS)
                        .unwrap_or(86400);

                    entries.insert(
                        ip,
                        ThreatEntry {
                            ip,
                            cidr: None,
                            source: "AbuseIPDB".into(),
                            reason,
                            added_at: now,
                            expires_at: now + chrono::Duration::seconds(ttl_hours),
                        },
                    );
                    count += 1;
                }
            }
        }

        self.refresh_timestamp();
        info!("Loaded {} entries from AbuseIPDB", count);
        Ok(count)
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = Utc::now();
        let Ok(entries) = self.entries.lock() else {
            return true;
        };
        if entries.get(&ip).is_some_and(|e| e.expires_at > now) {
            return true;
        }
        drop(entries);
        if let Ok(cidr_entries) = self.cidr_entries.lock() {
            for entry in cidr_entries.iter() {
                if entry.expires_at <= now {
                    continue;
                }
                if let Some(ref cidr) = entry.cidr {
                    if argus_common::net::ip_in_cidr(ip, cidr) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn lookup_entry(&self, ip: IpAddr) -> Option<ThreatEntry> {
        let now = Utc::now();
        self.entries
            .lock()
            .ok()
            .and_then(|e| e.get(&ip).cloned())
            .filter(|e| e.expires_at > now)
    }

    pub fn blocklist_size(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn gc(&self) {
        let now = Utc::now();
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, e| e.expires_at > now);
        }
        if let Ok(mut cidr_entries) = self.cidr_entries.lock() {
            cidr_entries.retain(|e| e.expires_at > now);
        }
    }

    pub async fn auto_refresh_all(&self, abuseipdb_key: Option<String>, confidence_min: u8) {
        let should_refresh = match self.last_refresh.lock() {
            Ok(last) => {
                last.is_none_or(|t| (Utc::now() - t).num_seconds() as u64 >= REFRESH_INTERVAL_SECS)
            }
            Err(_) => true,
        };

        if !should_refresh {
            return;
        }

        let _ = self.refresh_spamhaus_drop().await;
        let _ = self.refresh_spamhaus_edrop().await;

        if let Some(key) = abuseipdb_key {
            if !key.is_empty() {
                let _ = self.refresh_abuseipdb(&key, confidence_min).await;
            }
        }
    }

    fn parse_drop_list(&self, body: &str, source: &str) -> usize {
        let mut count = 0;
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(BLOCKLIST_TTL_SECONDS);

        let mut entries = match self.entries.lock() {
            Ok(e) => e,
            Err(_) => return 0,
        };
        let mut cidr_entries = match self.cidr_entries.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            let cidr = line.split(';').next().unwrap_or(line).trim();

            if cidr.contains('/') {
                if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
                    let base_ip = net.ip();
                    entries.insert(
                        base_ip,
                        ThreatEntry {
                            ip: base_ip,
                            cidr: Some(cidr.to_string()),
                            source: source.to_string(),
                            reason: format!("{} blocklist", source),
                            added_at: now,
                            expires_at,
                        },
                    );
                    cidr_entries.push(ThreatEntry {
                        ip: base_ip,
                        cidr: Some(cidr.to_string()),
                        source: source.to_string(),
                        reason: format!("{} blocklist", source),
                        added_at: now,
                        expires_at,
                    });
                    count += 1;
                }
            } else if let Ok(ip) = cidr.parse::<IpAddr>() {
                entries.insert(
                    ip,
                    ThreatEntry {
                        ip,
                        cidr: None,
                        source: source.to_string(),
                        reason: format!("{} blocklist", source),
                        added_at: now,
                        expires_at,
                    },
                );
                count += 1;
            }
        }

        count
    }

    fn refresh_timestamp(&self) {
        if let Ok(mut last) = self.last_refresh.lock() {
            *last = Some(Utc::now());
        }
    }

    pub fn export_blocklist(&self) -> Vec<IpAddr> {
        let now = Utc::now();
        self.entries
            .lock()
            .map(|e| {
                e.values()
                    .filter(|entry| entry.expires_at > now)
                    .map(|entry| entry.ip)
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for ThreatIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_drop_list() {
        let ti = ThreatIntelligence::new();
        let body = "; Spamhaus DROP list\n10.0.0.0/8 ; SBL12345\n; comment line\n192.168.0.0/16 ; SBL67890\n";
        let count = ti.parse_drop_list(body, "Test");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_is_blocked() {
        let ti = ThreatIntelligence::new();
        let body = "1.2.3.0/24 ; test\n";
        ti.parse_drop_list(body, "Test");

        let ip: IpAddr = "1.2.3.1".parse().unwrap();
        assert!(ti.is_blocked(ip), "IP in CIDR range should be blocked");
        let ip_prefix: IpAddr = "1.2.3.0".parse().unwrap();
        assert!(ti.is_blocked(ip_prefix));
        let ip_outside: IpAddr = "1.2.4.1".parse().unwrap();
        assert!(!ti.is_blocked(ip_outside));
    }

    #[test]
    fn test_gc_removes_expired() {
        let ti = ThreatIntelligence::new();
        let now = Utc::now();
        let past = now - chrono::Duration::seconds(BLOCKLIST_TTL_SECONDS + 1);

        if let Ok(mut entries) = ti.entries.lock() {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            entries.insert(
                ip,
                ThreatEntry {
                    ip,
                    cidr: None,
                    source: "test".into(),
                    reason: "test".into(),
                    added_at: past,
                    expires_at: past,
                },
            );
        }

        ti.gc();
        assert_eq!(ti.blocklist_size(), 0);
    }
}
