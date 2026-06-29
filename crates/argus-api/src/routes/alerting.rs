use axum::http::StatusCode;
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::AppState;
use argus_core::alerting::{AlertCondition, AlertEvent, AlertRule, NotificationChannel};

#[derive(Serialize)]
pub struct AlertRuleResponse {
    pub id: Uuid,
    pub name: String,
    pub condition: AlertCondition,
    pub channels: Vec<NotificationChannel>,
    pub enabled: bool,
    pub cooldown_secs: u64,
}

impl From<AlertRule> for AlertRuleResponse {
    fn from(r: AlertRule) -> Self {
        AlertRuleResponse {
            id: r.id,
            name: r.name,
            condition: r.condition,
            channels: r.channels.into_iter().map(redact_channel).collect(),
            enabled: r.enabled,
            cooldown_secs: r.cooldown_secs,
        }
    }
}

fn redact_channel(ch: NotificationChannel) -> NotificationChannel {
    let mut config = ch.config.clone();
    let map = config.as_object_mut();
    if let Some(map) = map {
        for key in &["webhook_url", "url", "smtp_url", "to", "from"] {
            if map.contains_key(*key) {
                map.insert(key.to_string(), serde_json::Value::String("[REDACTED]".into()));
            }
        }
    }
    NotificationChannel {
        channel_type: ch.channel_type,
        config,
    }
}

pub async fn list_alert_rules(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<AlertRuleResponse>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let rules = state.alert_manager.list_rules();
    Ok(Json(
        rules.into_iter().map(AlertRuleResponse::from).collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateAlertRuleRequest {
    pub name: String,
    pub condition: AlertCondition,
    #[serde(default)]
    pub channels: Vec<NotificationChannel>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_enabled() -> bool {
    true
}

fn default_cooldown() -> u64 {
    300
}

pub async fn create_alert_rule(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateAlertRuleRequest>,
) -> Result<Json<AlertRuleResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    if req.name.is_empty() || req.name.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Name must be 1-256 characters", "code": 400})),
        ));
    }

    // Validate notification channel URLs block SSRF
    for channel in &req.channels {
        for key in &["url", "webhook_url", "smtp_url"] {
            if let Some(url) = channel.config.get(key).and_then(|v| v.as_str()) {
                validate_notification_url(url).map_err(|msg| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": msg, "code": 400})),
                    )
                })?;
            }
        }
    }

    let rule = AlertRule {
        id: Uuid::new_v4(),
        name: req.name,
        condition: req.condition,
        channels: req.channels,
        enabled: req.enabled,
        cooldown_secs: req.cooldown_secs,
    };

    state.alert_manager.add_rule(rule.clone());

    Ok(Json(AlertRuleResponse::from(rule)))
}

pub async fn delete_alert_rule(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_delete() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    if state.alert_manager.remove_rule(&id) {
        Ok(Json(serde_json::json!({"deleted": id.to_string()})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Alert rule not found", "code": 404})),
        ))
    }
}

pub async fn list_alert_history(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<AlertEvent>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let history = state.alert_manager.list_history(100);
    Ok(Json(history))
}

pub async fn acknowledge_alert(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    if state.alert_manager.acknowledge(&id) {
        Ok(Json(serde_json::json!({"acknowledged": id.to_string()})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Alert event not found", "code": 404})),
        ))
    }
}

fn validate_notification_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    match parsed.scheme() {
        "https" => {}
        "http" => {}
        _ => {
            return Err(format!(
                "URL scheme must be http or https, got: {}",
                parsed.scheme()
            ))
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Block loopback
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
        return Err("URL pointing to loopback interface is not allowed".to_string());
    }

    // Block AWS/cloud metadata endpoints
    let lowered = host.to_lowercase();
    if lowered == "169.254.169.254" || lowered.ends_with(".compute.internal") {
        return Err("URL pointing to cloud metadata is not allowed".to_string());
    }

    // Block RFC 1918 private IPv4 ranges
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        let octets = addr.octets();
        if octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
            || octets[0] == 127
        {
            return Err("URL pointing to private IP range is not allowed".to_string());
        }
    }

    if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        if addr.is_loopback() || addr.is_unspecified() {
            return Err("URL pointing to loopback/unspecified IPv6 is not allowed".to_string());
        }
    }

    if lowered.contains("internal") || lowered.contains("local") || lowered.ends_with(".local") {
        return Err("URL with 'internal' or '.local' domain is not allowed".to_string());
    }

    Ok(())
}
