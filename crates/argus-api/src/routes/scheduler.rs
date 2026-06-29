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
use argus_core::scheduler::{RuleSchedule, ScheduleAction};

#[derive(Serialize)]
pub struct ScheduleResponse {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub cron_expression: String,
    pub action: String,
    pub enabled: bool,
    pub description: String,
    pub created_at: String,
    pub last_run: Option<String>,
}

impl From<RuleSchedule> for ScheduleResponse {
    fn from(s: RuleSchedule) -> Self {
        let action_str = match s.action {
            ScheduleAction::Enable => "enable",
            ScheduleAction::Disable => "disable",
        };
        ScheduleResponse {
            id: s.id,
            rule_id: s.rule_id,
            cron_expression: s.cron_expression,
            action: action_str.to_string(),
            enabled: s.enabled,
            description: s.description,
            created_at: s.created_at.to_rfc3339(),
            last_run: s.last_run.map(|t| t.to_rfc3339()),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateScheduleRequest {
    pub rule_id: Uuid,
    pub cron_expression: String,
    pub action: String,
    #[serde(default = "default_schedule_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

fn default_schedule_enabled() -> bool {
    true
}

pub async fn list_schedules(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<ScheduleResponse>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let schedules = state.scheduler_engine.list_schedules().await;
    Ok(Json(
        schedules.into_iter().map(ScheduleResponse::from).collect(),
    ))
}

pub async fn create_schedule(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<Json<ScheduleResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let action = match req.action.to_lowercase().as_str() {
        "enable" => ScheduleAction::Enable,
        "disable" => ScheduleAction::Disable,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": "Invalid action, must be 'enable' or 'disable'", "code": 400}),
                ),
            ));
        }
    };

    let parts: Vec<&str> = req.cron_expression.split_whitespace().collect();
    if parts.len() != 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Cron expression must have exactly 5 fields", "code": 400}),
            ),
        ));
    }

    if let Err(err_msg) = argus_core::scheduler::validate_cron(&req.cron_expression) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": err_msg, "code": 400})),
        ));
    }

    let schedule = RuleSchedule {
        id: Uuid::new_v4(),
        rule_id: req.rule_id,
        cron_expression: req.cron_expression,
        action,
        enabled: req.enabled,
        description: req.description,
        created_at: chrono::Utc::now(),
        last_run: None,
    };

    let created = state.scheduler_engine.add_schedule(schedule).await;

    state.audit_log.log(
        &claims.username,
        "schedule.create",
        &format!("schedule/{}", created.id),
        &format!(
            "Created schedule for rule {}: {}",
            created.rule_id, created.cron_expression
        ),
        None,
        true,
    );

    Ok(Json(ScheduleResponse::from(created)))
}

pub async fn delete_schedule(
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

    if state.scheduler_engine.remove_schedule(&id).await {
        state.audit_log.log(
            &claims.username,
            "schedule.delete",
            &format!("schedule/{}", id),
            "Deleted schedule",
            None,
            true,
        );
        Ok(Json(serde_json::json!({"deleted": id.to_string()})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Schedule not found", "code": 404})),
        ))
    }
}
