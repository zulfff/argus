use argus_common::types::ScanAlert;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::instrument;

const PORT_SCAN_THRESHOLD: usize = 10;
const PORT_SCAN_WINDOW_SECS: i64 = 10;
const AUTO_BLOCK_DURATION_SECS: i64 = 300;

pub struct ScanDetector {
    attempts: Mutex<HashMap<IpAddr, ScanRecord>>,
    blocked: Mutex<HashMap<IpAddr, DateTime<Utc>>>,
    manual_blocks: Mutex<HashSet<IpAddr>>,
}

struct ScanRecord {
    ports: Vec<u16>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    alert_sent: bool,
}

impl ScanDetector {
    const MAX_PORTS_SCANNED: usize = 65536;

    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            blocked: Mutex::new(HashMap::new()),
            manual_blocks: Mutex::new(HashSet::new()),
        }
    }

    #[instrument(skip(self))]
    pub fn record_attempt(&self, src_ip: IpAddr, dst_port: u16) -> Option<ScanAlert> {
        let now = Utc::now();
        if self.is_blocked(src_ip, now) {
            return None;
        }

        let mut attempts = match self.attempts.lock() {
            Ok(a) => a,
            Err(_) => return None,
        };

        let record = attempts.entry(src_ip).or_insert(ScanRecord {
            ports: Vec::new(),
            first_seen: now,
            last_seen: now,
            alert_sent: false,
        });

        let window_elapsed = (now - record.first_seen).num_seconds();
        if window_elapsed > PORT_SCAN_WINDOW_SECS {
            record.ports.clear();
            record.first_seen = now;
            record.alert_sent = false;
        }

        if !record.ports.contains(&dst_port) {
            record.ports.push(dst_port);
            if record.ports.len() > Self::MAX_PORTS_SCANNED {
                record.ports.truncate(Self::MAX_PORTS_SCANNED);
            }
        }
        record.last_seen = now;

        if record.ports.len() >= PORT_SCAN_THRESHOLD && !record.alert_sent {
            record.alert_sent = true;
            let alert = ScanAlert {
                src_ip,
                dst_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                ports_scanned: record.ports.clone(),
                start_time: record.first_seen,
                severity: argus_common::types::ScanSeverity::Medium,
                blocked: true,
            };
            self.block_ip(src_ip, now);
            Some(alert)
        } else {
            None
        }
    }

    fn block_ip(&self, ip: IpAddr, now: DateTime<Utc>) {
        if let Ok(mut blocked) = self.blocked.lock() {
            blocked.insert(ip, now);
        }
    }

    pub fn unblock_ip(&self, ip: IpAddr) {
        if let Ok(mut blocked) = self.blocked.lock() {
            blocked.remove(&ip);
        }
        if let Ok(mut manual) = self.manual_blocks.lock() {
            manual.remove(&ip);
        }
    }

    pub fn manual_block(&self, ip: IpAddr) {
        if let Ok(mut manual) = self.manual_blocks.lock() {
            manual.insert(ip);
        }
    }

    fn is_blocked(&self, ip: IpAddr, now: DateTime<Utc>) -> bool {
        if let Ok(manual) = self.manual_blocks.lock() {
            if manual.contains(&ip) {
                return true;
            }
        }
        if let Ok(mut blocked) = self.blocked.lock() {
            if let Some(&since) = blocked.get(&ip) {
                if (now - since).num_seconds() > AUTO_BLOCK_DURATION_SECS {
                    blocked.remove(&ip);
                    return false;
                }
                return true;
            }
        }
        false
    }

    pub fn gc(&self) {
        let now = Utc::now();
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts.retain(|_, r| (now - r.last_seen).num_seconds() < PORT_SCAN_WINDOW_SECS * 2);
        }
        if let Ok(mut blocked) = self.blocked.lock() {
            blocked.retain(|_, &mut since| (now - since).num_seconds() < AUTO_BLOCK_DURATION_SECS);
        }
    }

    pub fn blocked_count(&self) -> usize {
        let auto = self.blocked.lock().map(|b| b.len()).unwrap_or(0);
        let manual = self.manual_blocks.lock().map(|m| m.len()).unwrap_or(0);
        auto + manual
    }
}

impl Default for ScanDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_port_scan_detection() {
        let detector = ScanDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for port in 1..=15 {
            if let Some(alert) = detector.record_attempt(ip, port) {
                assert!(alert.ports_scanned.len() >= PORT_SCAN_THRESHOLD);
                assert!(alert.blocked);
                return;
            }
        }
        panic!("scan should have been detected");
    }

    #[test]
    fn test_block_expiry() {
        let detector = ScanDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for port in 1..=15 {
            detector.record_attempt(ip, port);
        }
        assert!(detector.blocked_count() > 0);

        detector.unblock_ip(ip);
        assert_eq!(detector.blocked_count(), 0);
    }
}
