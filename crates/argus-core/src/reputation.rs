use chrono::{DateTime, Utc};
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
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            threshold_block: -50,
        }
    }

    pub fn adjust_score(&self, ip: IpAddr, delta: i32, reason: &str) {
        let mut entries = self.entries.lock().unwrap();
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
        let entries = self.entries.lock().unwrap();
        entries.get(ip).cloned()
    }

    pub fn list_lowest(&self, count: usize) -> Vec<IpReputation> {
        let entries = self.entries.lock().unwrap();
        let mut list: Vec<IpReputation> = entries.values().cloned().collect();
        list.sort_by_key(|e| e.score);
        list.truncate(count);
        list
    }

    pub fn bulk_set_from_threat_intel(&self, ips: &[IpAddr], score: i32) {
        let mut entries = self.entries.lock().unwrap();
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
        let entries = self.entries.lock().unwrap();
        entries
            .get(ip)
            .map(|e| e.score <= self.threshold_block)
            .unwrap_or(false)
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}
