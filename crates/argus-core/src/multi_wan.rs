use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;
use tracing::{info, instrument, warn};

use argus_common::error::{ArgusError, Result};

const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;
const HEALTH_CHECK_TIMEOUT_SECS: u64 = 3;
const FAILOVER_THRESHOLD: u32 = 3;
const FAILBACK_COOLDOWN_SECS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanLink {
    pub name: String,
    pub interface: String,
    pub gateway: IpAddr,
    pub weight: u32,
    pub is_primary: bool,
    pub health_endpoints: Vec<String>,
    pub health_interval_secs: u64,
    pub failover_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanStatus {
    pub link_name: String,
    pub active: bool,
    pub failed_checks: u32,
    pub last_success: Option<DateTime<Utc>>,
    pub last_failure: Option<DateTime<Utc>>,
    pub last_latency_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub timestamp: DateTime<Utc>,
    pub from_link: String,
    pub to_link: String,
    pub reason: String,
    pub auto_recovery: bool,
}

pub struct MultiWanManager {
    links: Mutex<HashMap<String, WanLink>>,
    statuses: Mutex<HashMap<String, WanStatus>>,
    active_link: Mutex<Option<String>>,
    failover_history: Mutex<Vec<FailoverEvent>>,
    client: Client,
}

impl MultiWanManager {
    pub fn new() -> Self {
        Self {
            links: Mutex::new(HashMap::new()),
            statuses: Mutex::new(HashMap::new()),
            active_link: Mutex::new(None),
            failover_history: Mutex::new(Vec::new()),
            client: Client::builder()
                .timeout(Duration::from_secs(HEALTH_CHECK_TIMEOUT_SECS))
                .no_proxy()
                .build()
                .expect("failed to build health check client"),
        }
    }

    #[instrument(skip(self))]
    pub fn add_link(&self, link: WanLink) -> Result<()> {
        let name = link.name.clone();
        let is_primary = link.is_primary;

        for endpoint in &link.health_endpoints {
            if !endpoint.starts_with("https://") {
                return Err(ArgusError::Validation(format!(
                    "health endpoint '{}' must use HTTPS",
                    endpoint
                )));
            }
        }

        let mut links = self
            .links
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        if links.contains_key(&name) {
            return Err(ArgusError::Validation(format!(
                "WAN link {} already exists",
                name
            )));
        }

        links.insert(name.clone(), link);

        let mut statuses = self
            .statuses
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        statuses.insert(
            name.clone(),
            WanStatus {
                link_name: name.clone(),
                active: false,
                failed_checks: 0,
                last_success: None,
                last_failure: None,
                last_latency_ms: None,
                last_error: None,
            },
        );

        if is_primary {
            let mut active = self
                .active_link
                .lock()
                .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;
            if active.is_none() {
                *active = Some(name);
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn check_health(&self, link_name: &str) -> WanStatus {
        let link = {
            let links = match self.links.lock() {
                Ok(l) => l,
                Err(_) => {
                    return WanStatus {
                        link_name: link_name.to_string(),
                        active: false,
                        failed_checks: 0,
                        last_success: None,
                        last_failure: None,
                        last_latency_ms: None,
                        last_error: Some("lock error".into()),
                    };
                }
            };

            match links.get(link_name) {
                Some(l) => l.clone(),
                None => {
                    return WanStatus {
                        link_name: link_name.to_string(),
                        active: false,
                        failed_checks: 0,
                        last_success: None,
                        last_failure: None,
                        last_latency_ms: None,
                        last_error: Some("link not found".into()),
                    };
                }
            }
        };

        if link.health_endpoints.is_empty() {
            return WanStatus {
                link_name: link_name.to_string(),
                active: true,
                failed_checks: 0,
                last_success: Some(Utc::now()),
                last_failure: None,
                last_latency_ms: None,
                last_error: None,
            };
        }

        let mut success = false;
        let mut latency = 0u64;
        let mut last_error = None;

        for endpoint in &link.health_endpoints {
            let start = std::time::Instant::now();

            match self.client.get(endpoint).send().await {
                Ok(resp) if resp.status().is_success() => {
                    success = true;
                    latency = start.elapsed().as_millis() as u64;
                    break;
                }
                Ok(resp) => {
                    last_error = Some(format!(
                        "health endpoint {} returned {}",
                        endpoint,
                        resp.status()
                    ));
                }
                Err(e) => {
                    last_error = Some(format!("health endpoint {} error: {}", endpoint, e));
                }
            }
        }

        let now = Utc::now();
        let mut statuses = self.statuses.lock().expect("status lock");
        let status = statuses.get_mut(link_name).expect("status exists");

        if success {
            status.failed_checks = 0;
            status.last_success = Some(now);
            status.last_latency_ms = Some(latency);
            status.active = true;
            status.last_error = None;
        } else {
            status.failed_checks += 1;
            status.last_failure = Some(now);
            status.last_error = last_error;

            if status.failed_checks >= link.failover_threshold {
                status.active = false;
                warn!(
                    link = %link_name,
                    failures = status.failed_checks,
                    "WAN link health check failed repeatedly"
                );
            }
        }

        status.clone()
    }

    #[instrument(skip(self))]
    pub async fn check_all_links(&self) -> Vec<WanStatus> {
        let link_names = {
            let links = self.links.lock().expect("links lock");
            links.keys().cloned().collect::<Vec<String>>()
        };

        let mut statuses = Vec::new();
        for name in &link_names {
            let status = self.check_health(name).await;
            statuses.push(status);
        }

        statuses
    }

    #[instrument(skip(self))]
    pub async fn perform_failover_if_needed(&self) -> Option<FailoverEvent> {
        let statuses = self.check_all_links().await;

        let current_active = self.active_link.lock().expect("active lock").clone();

        if let Some(ref active_name) = current_active {
            let active_down = statuses
                .iter()
                .any(|s| s.link_name == *active_name && !s.active);

            if !active_down {
                return None;
            }

            warn!(
                current = %active_name,
                "Active WAN link is down — initiating failover"
            );
        }

        let candidates: Vec<&WanStatus> = statuses
            .iter()
            .filter(|s| s.active && Some(s.link_name.clone()) != current_active)
            .collect();

        if candidates.is_empty() {
            warn!("No healthy WAN links available for failover");
            return None;
        }

        let new_active = {
            let links = self.links.lock().expect("links lock");
            candidates
                .iter()
                .filter_map(|s| links.get(&s.link_name))
                .max_by_key(|l| l.weight)
                .map(|l| l.name.clone())
        };

        let new_active = match new_active {
            Some(name) => name,
            None => candidates.first()?.link_name.clone(),
        };

        let mut active = self.active_link.lock().expect("active lock");
        let old = active.replace(new_active.clone());

        let event = FailoverEvent {
            timestamp: Utc::now(),
            from_link: old.unwrap_or_else(|| "none".into()),
            to_link: new_active,
            reason: "health check failure".into(),
            auto_recovery: true,
        };

        if let Ok(mut history) = self.failover_history.lock() {
            history.push(event.clone());
            if history.len() > 100 {
                history.drain(0..50);
            }
        }

        info!(
            from = %event.from_link,
            to = %event.to_link,
            "WAN failover complete"
        );

        Some(event)
    }

    pub fn get_active_link(&self) -> Option<String> {
        self.active_link.lock().ok()?.clone()
    }

    pub fn get_link_status(&self, name: &str) -> Option<WanStatus> {
        self.statuses.lock().ok()?.get(name).cloned()
    }

    pub fn get_all_statuses(&self) -> Vec<WanStatus> {
        self.statuses
            .lock()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_failover_history(&self) -> Vec<FailoverEvent> {
        self.failover_history
            .lock()
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    pub async fn start_health_check_loop(self: std::sync::Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS)).await;
                let _ = self.perform_failover_if_needed().await;
            }
        });
    }
}

impl Default for MultiWanManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_add_wan_links() {
        let mgr = MultiWanManager::new();

        let primary = WanLink {
            name: "wan1".into(),
            interface: "eth0".into(),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            weight: 100,
            is_primary: true,
            health_endpoints: vec!["https://1.1.1.1".into()],
            health_interval_secs: 5,
            failover_threshold: 3,
        };

        let backup = WanLink {
            name: "wan2".into(),
            interface: "eth1".into(),
            gateway: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            weight: 50,
            is_primary: false,
            health_endpoints: vec!["https://8.8.8.8".into()],
            health_interval_secs: 5,
            failover_threshold: 3,
        };

        assert!(mgr.add_link(primary).is_ok());
        assert!(mgr.add_link(backup).is_ok());

        assert_eq!(mgr.get_active_link(), Some("wan1".into()));
    }

    #[test]
    fn test_duplicate_link_rejected() {
        let mgr = MultiWanManager::new();
        let link = WanLink {
            name: "wan1".into(),
            interface: "eth0".into(),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            weight: 100,
            is_primary: true,
            health_endpoints: vec![],
            health_interval_secs: 5,
            failover_threshold: 3,
        };

        assert!(mgr.add_link(link.clone()).is_ok());
        assert!(mgr.add_link(link).is_err());
    }
}
