use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct IpReputation {
    pub ip: IpAddr,
    pub score: i32,
    pub threat_intel_hits: u32,
    pub scan_attempts: u32,
    pub anomaly_hits: u32,
    pub manual_blocks: u32,
    pub last_updated: DateTime<Utc>,
}

pub struct ReputationManager {
    entries: Mutex<HashMap<IpAddr, IpReputation>>,
    threshold_block: i32,
    pub active_threats: DashMap<IpAddr, crate::threat_intel::ThreatEntry>,
}

pub fn calculate_score(
    source: &str,
    source_score: f64,
    confidence: f64,
    recency_factor: f64,
) -> f64 {
    let weight = match source {
        "CrowdSec" => 1.8,
        "Internal" => 2.0,
        "AlienVault" => 1.3,
        "AbuseIPDB" => 1.0,
        _ => 0.6,
    };
    source_score * confidence * recency_factor * weight
}

pub fn calculate_ttl(confidence: f64) -> chrono::Duration {
    let days = if confidence > 0.95 {
        30
    } else if confidence > 0.80 {
        14
    } else if confidence > 0.60 {
        7
    } else if confidence > 0.40 {
        3
    } else {
        1
    };
    chrono::Duration::days(days)
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            threshold_block: -50,
            active_threats: DashMap::new(),
        }
    }

    pub async fn sync_reputation_flow(
        &self,
        db_pool: &sqlx::PgPool,
        ebpf: &crate::ebpf::EbpfController,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let rows = sqlx::query_as::<_, crate::threat_intel::ThreatEntryRow>(
            "SELECT id, ip_address, cidr, source, reason, added_at, expires_at, last_seen, metadata FROM threat_entries WHERE expires_at > NOW()"
        )
        .fetch_all(db_pool)
        .await?;

        self.active_threats.clear();
        let mut ipv4_entries = Vec::new();
        let mut ipv6_entries = Vec::new();

        for row in rows {
            let entry: crate::threat_intel::ThreatEntry = row.into();

            if let Some(ip) = entry.ip_address {
                self.active_threats.insert(ip, entry.clone());
                if ip.is_ipv4() {
                    if let Ok(ipv4) = ip.to_string().parse::<std::net::Ipv4Addr>() {
                        ipv4_entries.push((
                            ipv4,
                            32,
                            crate::ebpf::ReputationValue {
                                score: -50,
                                category: 1,
                            },
                        ));
                    }
                } else {
                    if let Ok(ipv6) = ip.to_string().parse::<std::net::Ipv6Addr>() {
                        ipv6_entries.push((
                            ipv6,
                            128,
                            crate::ebpf::ReputationValue {
                                score: -50,
                                category: 1,
                            },
                        ));
                    }
                }
            } else if let Some(ref cidr_str) = entry.cidr {
                if let Ok(ip_net) = cidr_str.parse::<ipnetwork::IpNetwork>() {
                    self.active_threats.insert(ip_net.ip(), entry.clone());
                    if ip_net.ip().is_ipv4() {
                        if let Ok(ipv4) = ip_net.ip().to_string().parse::<std::net::Ipv4Addr>() {
                            ipv4_entries.push((
                                ipv4,
                                ip_net.prefix() as u32,
                                crate::ebpf::ReputationValue {
                                    score: -50,
                                    category: 1,
                                },
                            ));
                        }
                    } else {
                        if let Ok(ipv6) = ip_net.ip().to_string().parse::<std::net::Ipv6Addr>() {
                            ipv6_entries.push((
                                ipv6,
                                ip_net.prefix() as u32,
                                crate::ebpf::ReputationValue {
                                    score: -50,
                                    category: 1,
                                },
                            ));
                        }
                    }
                }
            }
        }
        ebpf.sync_reputation_v4(&ipv4_entries)?;
        ebpf.sync_reputation_v6(&ipv6_entries)?;

        Ok(())
    }

    pub fn adjust_score(&self, ip: IpAddr, delta: i32, reason: &str) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let entry = entries.entry(ip).or_insert(IpReputation {
            ip,
            score: 0,
            threat_intel_hits: 0,
            scan_attempts: 0,
            anomaly_hits: 0,
            manual_blocks: 0,
            last_updated: Utc::now(),
        });

        entry.score = (entry.score + delta).clamp(-100, 100);
        entry.last_updated = Utc::now();

        match reason {
            "threat_intel" => entry.threat_intel_hits += 1,
            "scan" => entry.scan_attempts += 1,
            "anomaly" => entry.anomaly_hits += 1,
            "manual_block" => entry.manual_blocks += 1,
            _ => {}
        }
    }

    pub fn get_reputation(&self, ip: &IpAddr) -> Option<IpReputation> {
        self.entries.lock().ok()?.get(ip).cloned()
    }

    pub fn list_lowest(&self, count: usize) -> Vec<IpReputation> {
        self.entries.lock().ok().map_or(Vec::new(), |entries| {
            let mut list: Vec<IpReputation> = entries.values().cloned().collect();
            list.sort_by_key(|e| e.score);
            list.truncate(count);
            list
        })
    }

    pub fn bulk_set_from_threat_intel(&self, ips: &[IpAddr], score: i32) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        for ip in ips {
            let entry = entries.entry(*ip).or_insert(IpReputation {
                ip: *ip,
                score: 0,
                threat_intel_hits: 0,
                scan_attempts: 0,
                anomaly_hits: 0,
                manual_blocks: 0,
                last_updated: Utc::now(),
            });
            entry.score = (entry.score + score).clamp(-100, 100);
            entry.threat_intel_hits += 1;
            entry.last_updated = Utc::now();
        }
    }

    pub fn should_block(&self, ip: &IpAddr) -> bool {
        self.entries
            .lock()
            .ok()
            .map(|entries| {
                entries
                    .get(ip)
                    .map(|e| e.score <= self.threshold_block)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}
