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
            channels: r.channels,
            enabled: r.enabled,
            cooldown_secs: r.cooldown_secs,
        }
    }
}

pub async fn list_alert_rules(
    State(state): State<Arc<AppState>>,
    Extension(_claims): Extension<Claims>,
) -> Json<Vec<AlertRuleResponse>> {
    let rules = state.alert_manager.list_rules();
    Json(rules.into_iter().map(AlertRuleResponse::from).collect())
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
    Extension(_claims): Extension<Claims>,
) -> Json<Vec<AlertEvent>> {
    let history = state.alert_manager.list_history(100);
    Json(history)
}

pub async fn acknowledge_alert(
    State(state): State<Arc<AppState>>,
    Extension(_claims): Extension<Claims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if state.alert_manager.acknowledge(&id) {
        Ok(Json(serde_json::json!({"acknowledged": id.to_string()})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Alert event not found", "code": 404})),
        ))
    }
}
