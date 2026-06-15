use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::instrument;

use argus_common::error::{ArgusError, Result};

const HTTP_TIMEOUT_SECS: u64 = 30;
const DEFAULT_PORT: u16 = 443;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VyosConfig {
    pub firewall: VyosFirewallConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VyosFirewallConfig {
    pub rules: Vec<VyosRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VyosRule {
    pub id: u32,
    pub action: String,
    pub protocol: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VyosDeviceInfo {
    pub hostname: String,
    pub address: String,
    pub port: u16,
}

pub struct VyosClient {
    device: VyosDeviceInfo,
    client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VyosApiRequest {
    op: String,
    path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct VyosApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VyosConfigLoadRequest {
    op: String,
    path: Vec<String>,
    file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VyosHealthStatus {
    pub reachable: bool,
    pub version: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub config_errors: Option<Vec<String>>,
    pub last_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VyosDiffResult {
    pub has_diff: bool,
    pub diff_lines: Vec<String>,
    pub diff_summary: String,
}

impl VyosClient {
    pub fn new(address: String, port: Option<u16>) -> Self {
        let hostname = address.split(':').next().unwrap_or(&address).to_string();
        let parsed_port = address.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());
        let effective_port = port.or(parsed_port).unwrap_or(DEFAULT_PORT);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(10))
            .tls_built_in_root_certs(true)
            .user_agent("argus-orchestrator/0.1.0")
            .build()
            .expect("failed to build reqwest client");

        Self {
            device: VyosDeviceInfo {
                hostname: hostname.clone(),
                address: address.clone(),
                port: effective_port,
            },
            client,
        }
    }

    pub fn device_url(&self) -> String {
        let host = self.device.address.split(':').next().unwrap_or(&self.device.address);
        format!("https://{}:{}", host, self.device.port)
    }

    #[instrument(skip(self))]
    pub async fn health_check(&self) -> Result<VyosHealthStatus> {
        let url = format!("{}/retrieve", self.device_url());

        let request = VyosApiRequest {
            op: "showVersion".to_string(),
            path: vec![],
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS unreachable: {}", e)))?;

        if !response.status().is_success() {
            return Ok(VyosHealthStatus {
                reachable: false,
                version: None,
                uptime_seconds: None,
                config_errors: None,
                last_commit: None,
            });
        }

        let raw: serde_json::Value = response.json().await.unwrap_or_default();
        let version_str = raw
            .get("data")
            .and_then(|d| d.get("version"))
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(VyosHealthStatus {
            reachable: true,
            version: version_str,
            uptime_seconds: None,
            config_errors: None,
            last_commit: None,
        })
    }

    #[instrument(skip(self))]
    pub async fn get_running_config(&self) -> Result<String> {
        let url = format!("{}/retrieve", self.device_url());

        let request = VyosApiRequest {
            op: "showConfig".to_string(),
            path: vec![],
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS config retrieve failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ArgusError::External(format!(
                "VyOS returned {}",
                response.status()
            )));
        }

        let raw: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ArgusError::External(format!("VyOS config parse error: {}", e)))?;

        raw.get("data")
            .and_then(|d| d.get("config"))
            .and_then(|c| c.as_str())
            .map(String::from)
            .ok_or_else(|| ArgusError::External("VyOS returned empty config".into()))
    }

    #[instrument(skip(self))]
    pub async fn get_firewall_rules(&self) -> Result<Vec<VyosRule>> {
        let config = self.get_running_config().await?;
        self.parse_firewall_rules(&config)
    }

    #[instrument(skip(self))]
    pub async fn load_config(&self, config_text: &str) -> Result<()> {
        let url = format!("{}/load", self.device_url());

        let request = VyosConfigLoadRequest {
            op: "loadFile".to_string(),
            path: vec![],
            file: config_text.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS config load failed: {}", e)))?;

        self.check_response(response, "load config")
            .await
            .map(|_| ())
    }

    #[instrument(skip(self))]
    pub async fn load_config_and_compare(&self, config_text: &str) -> Result<VyosDiffResult> {
        let current = self.get_running_config().await.unwrap_or_default();

        self.load_config(config_text).await?;

        let diff = self.compare_config().await?;

        let merged = current != config_text;
        Ok(VyosDiffResult {
            has_diff: merged,
            diff_lines: diff
                .lines()
                .filter(|l| l.starts_with('+') || l.starts_with('-'))
                .map(String::from)
                .collect(),
            diff_summary: if merged {
                format!(
                    "{} additions, {} deletions",
                    diff.lines().filter(|l| l.starts_with('+')).count(),
                    diff.lines().filter(|l| l.starts_with('-')).count(),
                )
            } else {
                "no changes detected".into()
            },
        })
    }

    #[instrument(skip(self))]
    pub async fn compare_config(&self) -> Result<String> {
        let url = format!("{}/retrieve", self.device_url());

        let request = VyosApiRequest {
            op: "compare".to_string(),
            path: vec![],
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS compare failed: {}", e)))?;

        let raw: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ArgusError::External(format!("VyOS compare parse error: {}", e)))?;

        raw.get("data")
            .and_then(|d| d.get("diff"))
            .and_then(|d| d.as_str())
            .map(String::from)
            .ok_or_else(|| ArgusError::External("VyOS compare returned no diff".into()))
    }

    #[instrument(skip(self))]
    pub async fn commit_config(&self, comment: Option<&str>) -> Result<bool> {
        let url = format!("{}/commit", self.device_url());

        let request = serde_json::json!({
            "op": "commit",
            "path": [],
            "comment": comment.unwrap_or("argus automated commit"),
        });

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS commit failed: {}", e)))?;

        self.check_response(response, "commit config").await
    }

    #[instrument(skip(self))]
    pub async fn commit_confirm(&self, comment: Option<&str>) -> Result<bool> {
        let url = format!("{}/commit", self.device_url());

        let request = serde_json::json!({
            "op": "commit-confirm",
            "path": [],
            "comment": comment.unwrap_or("argus automated commit with rollback"),
        });

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS commit-confirm failed: {}", e)))?;

        self.check_response(response, "commit-confirm").await
    }

    #[instrument(skip(self))]
    pub async fn discard_changes(&self) -> Result<bool> {
        let url = format!("{}/discard", self.device_url());

        let request = VyosApiRequest {
            op: "discard".to_string(),
            path: vec![],
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS discard failed: {}", e)))?;

        self.check_response(response, "discard changes").await
    }

    #[instrument(skip(self))]
    pub async fn save_config(&self) -> Result<bool> {
        let url = format!("{}/save", self.device_url());

        let request = VyosApiRequest {
            op: "save".to_string(),
            path: vec![],
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS save failed: {}", e)))?;

        self.check_response(response, "save config").await
    }

    #[instrument(skip(self))]
    pub async fn rollback(&self, revisions_back: u32) -> Result<bool> {
        let url = format!("{}/retrieve", self.device_url());

        let request = serde_json::json!({
            "op": "rollback",
            "path": [],
            "rev": revisions_back.to_string(),
        });

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS rollback failed: {}", e)))?;

        self.check_response(response, "rollback").await
    }

    #[instrument(skip(self))]
    pub async fn safe_apply_config(
        &self,
        config_text: &str,
        health_check_cmd: Option<&str>,
    ) -> Result<bool> {
        self.load_config(config_text).await?;

        self.commit_confirm(Some("argus safe-apply with auto-rollback"))
            .await?;

        if let Some(cmd) = health_check_cmd {
            let healthy = self.run_op_command(cmd).await;
            if healthy.is_err() {
                tracing::warn!("Health check failed, rolling back config");
                self.rollback(1).await?;
                return Err(ArgusError::External(
                    "Post-commit health check failed — config rolled back".into(),
                ));
            }
        }

        self.save_config().await?;
        Ok(true)
    }

    #[instrument(skip(self))]
    pub async fn run_op_command(&self, command: &str) -> Result<String> {
        let url = format!("{}/retrieve", self.device_url());

        let parts: Vec<&str> = command.split_whitespace().collect();
        let op = parts.first().copied().unwrap_or("show");
        let subpath: Vec<String> = parts.iter().skip(1).map(|s| s.to_string()).collect();

        let request = VyosApiRequest {
            op: op.to_string(),
            path: subpath,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ArgusError::Network(format!("VyOS op command failed: {}", e)))?;

        let raw: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ArgusError::External(format!("VyOS op parse: {}", e)))?;

        let output = raw
            .get("data")
            .and_then(|d| d.get("output"))
            .and_then(|o| o.as_str())
            .map(String::from)
            .unwrap_or_default();

        Ok(output)
    }

    async fn check_response(&self, response: reqwest::Response, operation: &str) -> Result<bool> {
        if !response.status().is_success() {
            return Err(ArgusError::External(format!(
                "VyOS {} failed with status {}",
                operation,
                response.status()
            )));
        }

        let raw: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ArgusError::External(format!("VyOS response parse error: {}", e)))?;

        if let Some(true) = raw.get("success").and_then(|s| s.as_bool()) {
            return Ok(true);
        }

        let err_msg = raw
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");

        Err(ArgusError::External(format!(
            "VyOS {} error: {}",
            operation, err_msg
        )))
    }

    fn parse_firewall_rules(&self, config: &str) -> Result<Vec<VyosRule>> {
        let mut rules = Vec::new();
        let mut rule_id = 0u32;

        for line in config.lines() {
            let line = line.trim();
            if line.starts_with("rule ") {
                if let Some(rest) = line.strip_prefix("rule ") {
                    if let Ok(id) = rest.split_whitespace().next().unwrap_or("0").parse::<u32>() {
                        rule_id = id;
                    }
                }
            }

            if line.starts_with("action ") {
                let action = line
                    .strip_prefix("action ")
                    .unwrap_or("")
                    .trim_single_quotes()
                    .to_string();
                rules.push(VyosRule {
                    id: rule_id,
                    action,
                    protocol: None,
                    source: None,
                    destination: None,
                });
            }
        }

        Ok(rules)
    }

    pub fn device_info(&self) -> &VyosDeviceInfo {
        &self.device
    }
}

trait TrimSingleQuotes {
    fn trim_single_quotes(&self) -> &str;
}

impl TrimSingleQuotes for &str {
    fn trim_single_quotes(&self) -> &str {
        self.trim_matches('\'')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_firewall_rules_from_config() {
        let config = r#"
firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            action 'accept'
            state established enable
            state related enable
        }
        rule 20 {
            action 'drop'
            source {
                address 10.0.0.0/8
            }
        }
    }
}
"#;
        let client = VyosClient::new("192.168.1.1".into(), None);
        let rules = client.parse_firewall_rules(config).unwrap();
        assert!(!rules.is_empty());
        assert_eq!(rules[0].action, "accept");
        assert_eq!(rules[1].action, "drop");
    }
}
