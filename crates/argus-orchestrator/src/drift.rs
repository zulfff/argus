use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

use argus_common::error::Result;

use crate::netbox::{NetboxClient, WebhookAction};
use crate::vyos::VyosClient;

#[derive(Debug, Clone)]
pub struct DriftReport {
    pub device_name: String,
    pub detected_at: chrono::DateTime<chrono::Utc>,
    pub expected_rules: Vec<RuleComparison>,
    pub unexpected_rules: Vec<String>,
    pub missing_rules: Vec<String>,
    pub diff_text: String,
    pub needs_remediation: bool,
}

#[derive(Debug, Clone)]
pub struct RuleComparison {
    pub rule_name: String,
    pub netbox_value: String,
    pub vyos_value: String,
    pub matches: bool,
}

#[derive(Debug, Clone)]
pub enum RemediationAction {
    PushConfig {
        device: String,
        config_text: String,
        reason: String,
    },
    Rollback {
        device: String,
        revisions: u32,
        reason: String,
    },
    Alert {
        severity: AlertSeverity,
        message: String,
    },
    NoOp,
}

#[derive(Debug, Clone)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

pub struct DriftDetector {
    netbox: Arc<NetboxClient>,
    vyos_clients: Arc<Mutex<HashMap<String, VyosClient>>>,
    check_interval_secs: u64,
    last_check: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl DriftDetector {
    pub fn new(netbox: Arc<NetboxClient>, check_interval_secs: u64) -> Self {
        Self {
            netbox,
            vyos_clients: Arc::new(Mutex::new(HashMap::new())),
            check_interval_secs,
            last_check: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn register_device(&self, hostname: String, address: String, port: Option<u16>) {
        let client = VyosClient::new(address, port);
        self.vyos_clients.lock().await.insert(hostname, client);
    }

    #[instrument(skip(self))]
    pub async fn check_all_devices(&self) -> Result<Vec<DriftReport>> {
        let now = chrono::Utc::now();

        {
            let mut last = self.last_check.lock().await;
            if let Some(lc) = *last {
                let elapsed = (now - lc).num_seconds() as u64;
                if elapsed < self.check_interval_secs {
                    info!("Skipping drift check — last check was {}s ago", elapsed);
                    return Ok(Vec::new());
                }
            }
            *last = Some(now);
        }

        let netbox_devices = self
            .netbox
            .get_devices(Some("active"))
            .await
            .unwrap_or_default();

        let mut reports = Vec::new();
        let clients = self.vyos_clients.lock().await;

        for device in &netbox_devices {
            if let Some(vyos) = clients.get(&device.name) {
                match self.check_device(device.name.clone(), vyos).await {
                    Ok(report) => {
                        if report.needs_remediation {
                            warn!(
                                device = %device.name,
                                drift = true,
                                "Config drift detected"
                            );
                        }
                        reports.push(report);
                    }
                    Err(e) => {
                        warn!(
                            device = %device.name,
                            error = %e,
                            "Drift check failed for device"
                        );
                    }
                }
            }
        }

        Ok(reports)
    }

    async fn check_device(&self, hostname: String, vyos: &VyosClient) -> Result<DriftReport> {
        let now = chrono::Utc::now();

        let netbox_prefixes = self.netbox.get_prefixes(None).await.unwrap_or_default();

        let _vyos_config = vyos.get_running_config().await.unwrap_or_default();
        let vyos_rules = vyos.get_firewall_rules().await.unwrap_or_default();

        let mut expected_rules = Vec::new();
        let mut missing_rules = Vec::new();
        let mut unexpected_rules = Vec::new();

        for prefix in &netbox_prefixes {
            let name = format!("prefix-{} cidr={}", prefix.id, prefix.prefix);
            let netbox_value = format!(
                "prefix={} site={} vlan={}",
                prefix.prefix,
                prefix
                    .site
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or("none"),
                prefix
                    .vlan
                    .as_ref()
                    .map(|v| v.name.as_str())
                    .unwrap_or("none"),
            );

            if let Some(vyos_rule) = vyos_rules
                .iter()
                .find(|r| r.action == "accept" && r.source.as_deref() == Some(&prefix.prefix))
            {
                expected_rules.push(RuleComparison {
                    rule_name: name.clone(),
                    netbox_value,
                    vyos_value: format!(
                        "action={} source={:?}",
                        vyos_rule.action, vyos_rule.source
                    ),
                    matches: true,
                });
            } else {
                missing_rules.push(name);
            }
        }

        for rule in &vyos_rules {
            if !netbox_prefixes
                .iter()
                .any(|p| rule.source.as_deref() == Some(&p.prefix))
                && rule.action == "accept"
            {
                unexpected_rules.push(format!(
                    "rule-{} action={} source={:?}",
                    rule.id, rule.action, rule.source
                ));
            }
        }

        let needs_remediation = !missing_rules.is_empty() || !unexpected_rules.is_empty();
        let diff_lines: Vec<String> = missing_rules
            .iter()
            .map(|r| format!("+ missing: {}", r))
            .chain(
                unexpected_rules
                    .iter()
                    .map(|r| format!("- unexpected: {}", r)),
            )
            .collect();

        Ok(DriftReport {
            device_name: hostname,
            detected_at: now,
            expected_rules,
            unexpected_rules,
            missing_rules,
            diff_text: diff_lines.join("\n"),
            needs_remediation,
        })
    }

    pub async fn determine_remediation(&self, report: &DriftReport) -> RemediationAction {
        if report.missing_rules.len() > 10 || report.unexpected_rules.len() > 10 {
            return RemediationAction::Alert {
                severity: AlertSeverity::Critical,
                message: format!(
                    "Device {} has significant drift: {} missing, {} unexpected rules",
                    report.device_name,
                    report.missing_rules.len(),
                    report.unexpected_rules.len(),
                ),
            };
        }

        if report.missing_rules.len() == 1 && report.unexpected_rules.is_empty() {
            let missing_prefix = report.missing_rules[0].clone();
            let cidr = missing_prefix
                .split("cidr=")
                .nth(1)
                .unwrap_or(&missing_prefix);
            // Full implementation: Auto-generate VyOS firewall config rule text for missing prefix
            let config_text = format!(
                "firewall {{\n    name WAN_IN {{\n        rule 100 {{\n            action 'accept'\n            source {{\n                address '{}'\n            }}\n        }}\n    }}\n}}",
                cidr
            );
            return RemediationAction::PushConfig {
                device: report.device_name.clone(),
                config_text,
                reason: format!(
                    "Auto-remediation: 1 missing rule detected on {}",
                    report.device_name
                ),
            };
        }

        RemediationAction::Alert {
            severity: AlertSeverity::Warning,
            message: format!(
                "Device {} has drift: {} missing, {} unexpected — manual review required",
                report.device_name,
                report.missing_rules.len(),
                report.unexpected_rules.len(),
            ),
        }
    }
}

pub struct ReconciliationEngine {
    detector: DriftDetector,
    webhook_cache: Arc<Mutex<Vec<WebhookAction>>>,
}

impl ReconciliationEngine {
    pub fn new(detector: DriftDetector) -> Self {
        Self {
            detector,
            webhook_cache: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn process_webhook_events(
        &self,
        actions: Vec<WebhookAction>,
    ) -> Vec<RemediationAction> {
        let mut remediations = Vec::new();
        let mut cache = self.webhook_cache.lock().await;

        for action in actions {
            if cache.contains(&action) {
                continue;
            }
            cache.push(action.clone());

            match &action {
                WebhookAction::ReconcileDevice {
                    device_name,
                    reason,
                    ..
                } => {
                    remediations.push(RemediationAction::PushConfig {
                        device: device_name.clone(),
                        config_text: String::new(),
                        reason: reason.clone(),
                    });
                }
                WebhookAction::ReconcileConfig { reason: _ } => {
                    let reports = self.detector.check_all_devices().await.unwrap_or_default();
                    for report in &reports {
                        let action = self.detector.determine_remediation(report).await;
                        remediations.push(action);
                    }
                }
            }
        }

        if cache.len() > 1000 {
            cache.drain(0..500);
        }

        remediations
    }

    pub async fn run_scheduled_reconciliation(&self) -> Result<Vec<RemediationAction>> {
        let reports = self.detector.check_all_devices().await?;

        let mut actions = Vec::new();
        for report in &reports {
            if report.needs_remediation {
                let action = self.detector.determine_remediation(report).await;
                actions.push(action);
            }
        }

        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drift_report_creation() {
        let report = DriftReport {
            device_name: "vyos-edge-01".into(),
            detected_at: chrono::Utc::now(),
            expected_rules: Vec::new(),
            unexpected_rules: vec!["rule-999".into()],
            missing_rules: vec!["prefix-42".into()],
            diff_text: "+ missing: prefix-42\n- unexpected: rule-999".into(),
            needs_remediation: true,
        };

        assert!(report.needs_remediation);
        assert_eq!(report.missing_rules.len(), 1);
        assert_eq!(report.unexpected_rules.len(), 1);
    }

    #[test]
    fn test_no_drift_when_empty() {
        let report = DriftReport {
            device_name: "vyos-edge-01".into(),
            detected_at: chrono::Utc::now(),
            expected_rules: Vec::new(),
            unexpected_rules: Vec::new(),
            missing_rules: Vec::new(),
            diff_text: String::new(),
            needs_remediation: false,
        };

        assert!(!report.needs_remediation);
    }
}
