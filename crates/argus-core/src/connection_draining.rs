use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::{info, warn};

use crate::connection_tracker::ConnectionTracker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainConfig {
    pub ip: IpAddr,
    pub started_at: DateTime<Utc>,
    pub timeout_secs: u64,
}

pub struct ConnectionDrainer {
    draining_ips: Mutex<HashSet<IpAddr>>,
    drain_configs: Mutex<Vec<DrainConfig>>,
}

impl Default for ConnectionDrainer {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionDrainer {
    pub fn new() -> Self {
        Self {
            draining_ips: Mutex::new(HashSet::new()),
            drain_configs: Mutex::new(Vec::new()),
        }
    }

    pub fn start_drain(&self, ip: IpAddr, timeout_secs: u64, tracker: &ConnectionTracker) {
        if let Ok(mut ips) = self.draining_ips.lock() {
            ips.insert(ip);
        }
        if let Ok(mut configs) = self.drain_configs.lock() {
            configs.push(DrainConfig {
                ip,
                started_at: Utc::now(),
                timeout_secs,
            });
        }
        tracker.mark_draining(ip);
        info!(
            "Started connection draining for {} (timeout: {}s)",
            ip, timeout_secs
        );
    }

    pub fn is_draining(&self, ip: &IpAddr) -> bool {
        self.draining_ips
            .lock()
            .ok()
            .map(|ips| ips.contains(ip))
            .unwrap_or(false)
    }

    pub fn check_and_finalize(&self, tracker: &ConnectionTracker) -> Vec<IpAddr> {
        let mut finalized = Vec::new();
        let now = Utc::now();

        let expired: Vec<IpAddr> = {
            let configs = match self.drain_configs.lock() {
                Ok(c) => c,
                Err(_) => return finalized,
            };
            configs
                .iter()
                .filter(|cfg| (now - cfg.started_at).num_seconds() >= cfg.timeout_secs as i64)
                .map(|cfg| cfg.ip)
                .collect()
        };

        for ip in expired {
            let active = tracker.count_for_ip(ip);
            if active == 0 {
                info!("Connection drain complete for {}", ip);
            } else {
                warn!(
                    "Force-closing {} active connections for {} (timeout reached)",
                    active, ip
                );
                tracker.close_all_for_ip(ip);
            }
            self.stop_drain(&ip);
            finalized.push(ip);
        }

        finalized
    }

    fn stop_drain(&self, ip: &IpAddr) {
        if let Ok(mut ips) = self.draining_ips.lock() {
            ips.remove(ip);
        }
        if let Ok(mut configs) = self.drain_configs.lock() {
            configs.retain(|cfg| cfg.ip != *ip);
        }
    }

    pub fn list_draining(&self) -> Vec<DrainConfig> {
        self.drain_configs
            .lock()
            .ok()
            .map(|c| c.clone())
            .unwrap_or_default()
    }
}
