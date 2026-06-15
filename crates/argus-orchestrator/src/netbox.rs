use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, error, instrument};

use argus_common::error::{ArgusError, Result};

const DEFAULT_PAGE_SIZE: u32 = 100;
const MAX_RETRIES: u32 = 3;
const RETRY_BACKOFF_MS: u64 = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetboxDevice {
    pub id: u64,
    pub name: String,
    pub display_name: String,
    pub device_type: DeviceTypeRef,
    pub device_role: DeviceRoleRef,
    pub site: SiteRef,
    pub status: DeviceStatus,
    pub serial: String,
    pub primary_ip4: Option<IpAddressRef>,
    pub primary_ip6: Option<IpAddressRef>,
    pub platform: Option<PlatformRef>,
    pub custom_fields: serde_json::Value,
    pub tags: Vec<String>,
    pub created: String,
    pub last_updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTypeRef {
    pub id: u64,
    pub model: String,
    pub manufacturer: ManufacturerRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManufacturerRef {
    pub id: u64,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRoleRef {
    pub id: u64,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteRef {
    pub id: u64,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformRef {
    pub id: u64,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddressRef {
    pub id: u64,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetboxPrefix {
    pub id: u64,
    pub prefix: String,
    pub site: Option<SiteRef>,
    pub vlan: Option<VlanRef>,
    pub status: DeviceStatus,
    pub description: String,
    pub role: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanRef {
    pub id: u64,
    pub vid: u16,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetboxIpAddress {
    pub id: u64,
    pub address: String,
    pub family: Family,
    pub status: DeviceStatus,
    pub assigned_object_type: Option<String>,
    pub assigned_object_id: Option<u64>,
    pub dns_name: String,
    pub description: String,
    pub created: String,
    pub last_updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Family {
    pub value: i32,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: Option<u64>,
    pub source_prefix: Option<NetboxPrefix>,
    pub destination_prefix: Option<NetboxPrefix>,
    pub source_ips: Vec<NetboxIpAddress>,
    pub destination_ips: Vec<NetboxIpAddress>,
    pub action: String,
    pub protocol: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PaginatedResponse<T> {
    count: u64,
    next: Option<String>,
    previous: Option<String>,
    results: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub event: String,
    pub timestamp: String,
    pub model: String,
    pub username: String,
    pub request_id: String,
    pub data: serde_json::Value,
    pub snapshots: serde_json::Value,
}

pub struct NetboxClient {
    base_url: String,
    api_token: String,
    client: reqwest::Client,
    circuit_state: Arc<Mutex<CircuitState>>,
}

#[derive(Debug)]
struct CircuitState {
    failures: u32,
    last_failure: Option<chrono::DateTime<chrono::Utc>>,
    open: bool,
}

impl CircuitState {
    fn new() -> Self {
        Self {
            failures: 0,
            last_failure: None,
            open: false,
        }
    }

    fn record_success(&mut self) {
        self.failures = 0;
        self.open = false;
        self.last_failure = None;
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(chrono::Utc::now());
        if self.failures >= 5 {
            self.open = true;
        }
    }

    fn is_open(&self) -> bool {
        if !self.open {
            return false;
        }
        if let Some(lf) = self.last_failure {
            let elapsed = chrono::Utc::now() - lf;
            if elapsed.num_seconds() > 30 {
                return false;
            }
        }
        true
    }
}

impl NetboxClient {
    pub fn new(base_url: String, api_token: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent("argus-orchestrator/0.1.0")
            .build()
            .expect("failed to build reqwest client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token,
            client,
            circuit_state: Arc::new(Mutex::new(CircuitState::new())),
        }
    }

    #[instrument(skip(self))]
    pub async fn get_devices(&self, status: Option<&str>) -> Result<Vec<NetboxDevice>> {
        let mut params = Vec::new();
        if let Some(s) = status {
            params.push(("status", s.to_string()));
        }
        self.fetch_all("/api/dcim/devices/", &params).await
    }

    #[instrument(skip(self))]
    pub async fn get_devices_by_site(&self, site_slug: &str) -> Result<Vec<NetboxDevice>> {
        let params = vec![("site", site_slug.to_string())];
        self.fetch_all("/api/dcim/devices/", &params).await
    }

    #[instrument(skip(self))]
    pub async fn get_device(&self, id: u64) -> Result<NetboxDevice> {
        self.get_single(&format!("/api/dcim/devices/{}/", id)).await
    }

    #[instrument(skip(self))]
    pub async fn get_prefixes(&self, site_slug: Option<&str>) -> Result<Vec<NetboxPrefix>> {
        let mut params = Vec::new();
        if let Some(s) = site_slug {
            params.push(("site", s.to_string()));
        }
        self.fetch_all("/api/ipam/prefixes/", &params).await
    }

    #[instrument(skip(self))]
    pub async fn get_ip_addresses(&self, device_id: Option<u64>) -> Result<Vec<NetboxIpAddress>> {
        let mut params = Vec::new();
        if let Some(d) = device_id {
            params.push(("device_id", d.to_string()));
        }
        self.fetch_all("/api/ipam/ip-addresses/", &params).await
    }

    #[instrument(skip(self))]
    pub async fn get_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        let custom_field_url = format!(
            "{}/api/extras/custom-fields/?content_type=dcim.device",
            self.base_url
        );

        let response = self
            .client
            .get(&custom_field_url)
            .header("Authorization", format!("Token {}", self.api_token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                self.record_circuit_failure();
                ArgusError::Network(format!("failed to fetch custom fields: {}", e))
            })?;

        if !response.status().is_success() {
            self.record_circuit_failure();
            return Err(ArgusError::External(format!(
                "NetBox returned {}",
                response.status()
            )));
        }

        Ok(vec![])
    }

    #[instrument(skip(self))]
    pub async fn create_ip_address(
        &self,
        address: &str,
        dns_name: &str,
        device_id: u64,
    ) -> Result<NetboxIpAddress> {
        let body = serde_json::json!({
            "address": address,
            "dns_name": dns_name,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": device_id,
            "status": "active",
        });

        self.post("/api/ipam/ip-addresses/", &body).await
    }

    #[instrument(skip(self))]
    pub async fn update_ip_address(
        &self,
        id: u64,
        address: &str,
        dns_name: &str,
    ) -> Result<NetboxIpAddress> {
        let body = serde_json::json!({
            "address": address,
            "dns_name": dns_name,
        });

        self.put(&format!("/api/ipam/ip-addresses/{}/", id), &body)
            .await
    }

    #[instrument(skip(self))]
    pub async fn delete_ip_address(&self, id: u64) -> Result<()> {
        self.delete(&format!("/api/ipam/ip-addresses/{}/", id))
            .await
    }

    #[instrument(skip(self))]
    pub async fn process_webhook(&self, event: WebhookEvent) -> Result<Vec<WebhookAction>> {
        debug!(
            "Processing NetBox webhook: {} for model {}",
            event.event, event.model
        );

        let mut actions = Vec::new();

        match event.model.as_str() {
            "dcim.device" => {
                if let Some(data) = event.data.as_object() {
                    let device_id = data.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    if let Some(name) = data.get("name").and_then(|v| v.as_str()) {
                        actions.push(WebhookAction::ReconcileDevice {
                            device_id,
                            device_name: name.to_string(),
                            reason: format!("NetBox {} event", event.event),
                        });
                    }
                }
            }
            "ipam.prefix" | "ipam.ipaddress" => {
                actions.push(WebhookAction::ReconcileConfig {
                    reason: format!(
                        "NetBox {} event for {} {}",
                        event.event,
                        event.model,
                        event
                            .data
                            .get("address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    ),
                });
            }
            _ => {
                debug!("No action needed for model: {}", event.model);
            }
        }

        Ok(actions)
    }

    async fn fetch_all<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<T>> {
        self.check_circuit()?;

        let mut all_results = Vec::new();
        let mut next_url = Some(format!(
            "{}{}?limit={}",
            self.base_url, path, DEFAULT_PAGE_SIZE
        ));

        for (k, v) in params {
            if let Some(ref mut url) = next_url {
                url.push_str(&format!("&{}={}", k, v));
            }
        }

        let mut retries = 0;

        while let Some(url) = next_url.take() {
            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("Token {}", self.api_token))
                .header("Accept", "application/json")
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    self.record_circuit_success();
                    retries = 0;
                    let page: PaginatedResponse<T> = resp.json().await.map_err(|e| {
                        ArgusError::External(format!("NetBox pagination parse error: {}", e))
                    })?;
                    all_results.extend(page.results);
                    next_url = page.next;
                }
                Ok(resp) if resp.status().as_u16() == 429 => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        self.record_circuit_failure();
                        return Err(ArgusError::RateLimited(60));
                    }
                    let wait = RETRY_BACKOFF_MS * 2u64.pow(retries);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    next_url = Some(url);
                }
                Ok(resp) => {
                    self.record_circuit_failure();
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(ArgusError::External(format!(
                            "NetBox API error {}: {}",
                            status, body
                        )));
                    }
                    let wait = RETRY_BACKOFF_MS * 2u64.pow(retries);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    next_url = Some(url);
                }
                Err(e) => {
                    self.record_circuit_failure();
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(ArgusError::Network(format!(
                            "NetBox request failed after {} retries: {}",
                            MAX_RETRIES, e
                        )));
                    }
                    let wait = RETRY_BACKOFF_MS * 2u64.pow(retries);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    next_url = Some(url);
                }
            }
        }

        Ok(all_results)
    }

    async fn get_single<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.check_circuit()?;
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Token {}", self.api_token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                self.record_circuit_failure();
                ArgusError::Network(format!("NetBox request failed: {}", e))
            })?;

        if !response.status().is_success() {
            self.record_circuit_failure();
            return Err(ArgusError::External(format!(
                "NetBox returned {}",
                response.status()
            )));
        }

        self.record_circuit_success();
        response
            .json()
            .await
            .map_err(|e| ArgusError::External(format!("NetBox parse error: {}", e)))
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        self.check_circuit()?;
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Token {}", self.api_token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| {
                self.record_circuit_failure();
                ArgusError::Network(format!("NetBox POST failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            self.record_circuit_failure();
            return Err(ArgusError::External(format!(
                "NetBox POST {} failed ({}): {}",
                path, status, body_text
            )));
        }

        self.record_circuit_success();
        response
            .json()
            .await
            .map_err(|e| ArgusError::External(format!("NetBox parse error: {}", e)))
    }

    async fn put<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        self.check_circuit()?;
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .put(&url)
            .header("Authorization", format!("Token {}", self.api_token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| {
                self.record_circuit_failure();
                ArgusError::Network(format!("NetBox PUT failed: {}", e))
            })?;

        if !response.status().is_success() {
            self.record_circuit_failure();
            return Err(ArgusError::External(format!(
                "NetBox PUT {} returned {}",
                path,
                response.status()
            )));
        }

        self.record_circuit_success();
        response
            .json()
            .await
            .map_err(|e| ArgusError::External(format!("NetBox parse error: {}", e)))
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.check_circuit()?;
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Token {}", self.api_token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                self.record_circuit_failure();
                ArgusError::Network(format!("NetBox DELETE failed: {}", e))
            })?;

        if !response.status().is_success() {
            self.record_circuit_failure();
            return Err(ArgusError::External(format!(
                "NetBox DELETE {} returned {}",
                path,
                response.status()
            )));
        }

        self.record_circuit_success();
        Ok(())
    }

    fn check_circuit(&self) -> Result<()> {
        if let Ok(state) = self.circuit_state.try_lock() {
            if state.is_open() {
                return Err(ArgusError::External(
                    "NetBox circuit breaker is open — too many failures".into(),
                ));
            }
        }
        Ok(())
    }

    fn record_circuit_success(&self) {
        if let Ok(mut state) = self.circuit_state.try_lock() {
            state.record_success();
        }
    }

    fn record_circuit_failure(&self) {
        if let Ok(mut state) = self.circuit_state.try_lock() {
            state.record_failure();
            error!(
                failures = state.failures,
                open = state.open,
                "NetBox circuit breaker state updated"
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookAction {
    ReconcileDevice {
        device_id: u64,
        device_name: String,
        reason: String,
    },
    ReconcileConfig {
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_state() {
        let mut cs = CircuitState::new();
        assert!(!cs.is_open());

        for _ in 0..5 {
            assert!(!cs.is_open());
            cs.record_failure();
        }
        assert!(cs.is_open());

        cs.record_success();
        assert!(!cs.is_open());
    }
}
