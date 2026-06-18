use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use uuid::Uuid;

pub struct SystemSnapshot {
    pub blocked_ips: usize,
    pub active_connections: usize,
    pub packets_per_second: u64,
    pub anomaly_score: f64,
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub audit_tampered: bool,
    pub wan_failed_over: bool,
    pub rule_match_counts: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: Uuid,
    pub name: String,
    pub condition: AlertCondition,
    pub channels: Vec<NotificationChannel>,
    pub enabled: bool,
    pub cooldown_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    BlockedIpThreshold { count: usize, window_secs: u64 },
    AnomalyScoreAbove { zscore: f64 },
    ConnectionFlood { rate_per_second: u64 },
    RuleMatchCount { rule_name: String, count: u64 },
    WanFailover,
    AuditTamperDetected,
    CpuUsageAbovePercent { percent: f64 },
    MemoryUsageAbovePercent { percent: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub channel_type: ChannelType,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelType {
    #[serde(rename = "webhook")]
    Webhook,
    #[serde(rename = "slack")]
    Slack,
    #[serde(rename = "email")]
    Email,
    #[serde(rename = "discord")]
    Discord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub condition: String,
    pub message: String,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
}

impl AlertCondition {
    pub fn describe(&self) -> String {
        match self {
            AlertCondition::BlockedIpThreshold { count, window_secs } => {
                format!("Blocked IP threshold: {} in {}s", count, window_secs)
            }
            AlertCondition::AnomalyScoreAbove { zscore } => {
                format!("Anomaly score above {}", zscore)
            }
            AlertCondition::ConnectionFlood { rate_per_second } => {
                format!("Connection flood > {} conn/s", rate_per_second)
            }
            AlertCondition::RuleMatchCount { rule_name, count } => {
                format!("Rule '{}' matched {} times", rule_name, count)
            }
            AlertCondition::WanFailover => "WAN failover detected".into(),
            AlertCondition::AuditTamperDetected => "Audit log tampering detected".into(),
            AlertCondition::CpuUsageAbovePercent { percent } => {
                format!("CPU usage above {}%", percent)
            }
            AlertCondition::MemoryUsageAbovePercent { percent } => {
                format!("Memory usage above {}%", percent)
            }
        }
    }
}

pub struct AlertManager {
    rules: Mutex<Vec<AlertRule>>,
    history: Mutex<VecDeque<AlertEvent>>,
    last_sent: Mutex<HashMap<Uuid, DateTime<Utc>>>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            history: Mutex::new(VecDeque::new()),
            last_sent: Mutex::new(HashMap::new()),
        }
    }

    pub fn add_rule(&self, rule: AlertRule) -> Uuid {
        let id = rule.id;
        if let Ok(mut rules) = self.rules.lock() {
            rules.push(rule);
        }
        id
    }

    pub fn remove_rule(&self, id: &Uuid) -> bool {
        if let Ok(mut rules) = self.rules.lock() {
            if let Some(pos) = rules.iter().position(|r| r.id == *id) {
                rules.remove(pos);
                return true;
            }
        }
        false
    }

    pub fn list_rules(&self) -> Vec<AlertRule> {
        self.rules.lock().map(|r| r.clone()).unwrap_or_default()
    }

    pub fn list_history(&self, limit: usize) -> Vec<AlertEvent> {
        self.history
            .lock()
            .map(|h| h.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    pub fn acknowledge(&self, id: &Uuid) -> bool {
        if let Ok(mut history) = self.history.lock() {
            if let Some(event) = history.iter_mut().find(|e| e.id == *id) {
                event.acknowledged = true;
                return true;
            }
        }
        false
    }

    pub async fn evaluate(&self, snapshot: &SystemSnapshot) {
        let rules = self.list_rules();
        let now = Utc::now();

        for rule in rules {
            if !rule.enabled {
                continue;
            }

            let should_alert = match &rule.condition {
                AlertCondition::BlockedIpThreshold { count, window_secs } => {
                    let _ = window_secs;
                    snapshot.blocked_ips >= *count
                }
                AlertCondition::AnomalyScoreAbove { zscore } => snapshot.anomaly_score > *zscore,
                AlertCondition::ConnectionFlood { rate_per_second } => {
                    snapshot.packets_per_second > *rate_per_second
                }
                AlertCondition::RuleMatchCount { rule_name, count } => {
                    snapshot
                        .rule_match_counts
                        .get(rule_name)
                        .copied()
                        .unwrap_or(0)
                        >= *count
                }
                AlertCondition::WanFailover => snapshot.wan_failed_over,
                AlertCondition::AuditTamperDetected => snapshot.audit_tampered,
                AlertCondition::CpuUsageAbovePercent { percent } => {
                    snapshot.cpu_usage_percent >= *percent
                }
                AlertCondition::MemoryUsageAbovePercent { percent } => {
                    snapshot.memory_usage_percent >= *percent
                }
            };

            if !should_alert {
                continue;
            }

            if let Ok(last_sent) = self.last_sent.lock() {
                if let Some(last_time) = last_sent.get(&rule.id) {
                    if (now - *last_time).num_seconds() < rule.cooldown_secs as i64 {
                        continue;
                    }
                }
            }

            let severity = match &rule.condition {
                AlertCondition::AuditTamperDetected => "critical",
                AlertCondition::ConnectionFlood { .. } => "warning",
                AlertCondition::AnomalyScoreAbove { zscore } if *zscore > 3.0 => "critical",
                _ => "info",
            };

            let event = AlertEvent {
                id: Uuid::new_v4(),
                rule_id: rule.id,
                rule_name: rule.name.clone(),
                condition: rule.condition.describe(),
                message: format!(
                    "Alert triggered: {} — {}",
                    rule.name,
                    rule.condition.describe()
                ),
                severity: severity.to_string(),
                timestamp: now,
                acknowledged: false,
            };

            if let Ok(mut history) = self.history.lock() {
                history.push_back(event.clone());
                while history.len() > 10_000 {
                    history.pop_front();
                }
            }

            if let Ok(mut last_sent) = self.last_sent.lock() {
                last_sent.insert(rule.id, now);
            }

            self.send_notification(&event, &rule.channels).await;
        }
    }

    async fn send_notification(&self, event: &AlertEvent, channels: &[NotificationChannel]) {
        let payload = serde_json::json!({
            "id": event.id.to_string(),
            "rule": event.rule_name,
            "condition": event.condition,
            "message": event.message,
            "severity": event.severity,
            "timestamp": event.timestamp.to_rfc3339(),
        });

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        for channel in channels {
            match channel.channel_type {
                ChannelType::Webhook => {
                    if let Some(url) = channel.config.get("url").and_then(|v| v.as_str()) {
                        let _ = client.post(url).json(&payload).send().await;
                    }
                }
                ChannelType::Slack => {
                    if let Some(url) = channel.config.get("webhook_url").and_then(|v| v.as_str()) {
                        let slack_payload = serde_json::json!({
                            "text": format!("*ARGUS Alert*: {}\n> {}", event.message, event.condition),
                        });
                        let _ = client.post(url).json(&slack_payload).send().await;
                    }
                }
                ChannelType::Discord => {
                    if let Some(url) = channel.config.get("webhook_url").and_then(|v| v.as_str()) {
                        let discord_payload = serde_json::json!({
                            "content": format!("**ARGUS Alert**\n{}: {}", event.severity.to_uppercase(), event.message),
                        });
                        let _ = client.post(url).json(&discord_payload).send().await;
                    }
                }
                ChannelType::Email => {
                    let _to = channel.config.get("to").and_then(|v| v.as_str());
                    let _from = channel.config.get("from").and_then(|v| v.as_str());
                    let _smtp = channel.config.get("smtp_url").and_then(|v| v.as_str());
                    tracing::debug!(
                        rule = %event.rule_name,
                        severity = %event.severity,
                        "Email notification would be sent"
                    );
                }
            }
        }
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}
