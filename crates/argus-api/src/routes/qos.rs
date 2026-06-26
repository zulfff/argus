use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::qos::{QosPolicy, QosTarget};

#[derive(Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub target: QosTarget,
    pub bandwidth_limit_bps: u64,
    pub priority: u8,
    pub dscp_mark: Option<u8>,
    pub enabled: Option<bool>,
}

pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<QosPolicy>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((StatusCode::FORBIDDEN, Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        )));
    }
    Ok(Json(state.qos.list_policies()))
}

pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreatePolicyRequest>,
) -> Result<Json<QosPolicy>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((StatusCode::FORBIDDEN, Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        )));
    }
    let policy = QosPolicy {
        id: uuid::Uuid::nil(),
        name: payload.name,
        target: payload.target,
        bandwidth_limit_bps: payload.bandwidth_limit_bps,
        priority: payload.priority,
        dscp_mark: payload.dscp_mark,
        enabled: payload.enabled.unwrap_or(true),
    };
    let id = state.qos.add_policy(policy);
    let policies = state.qos.list_policies();
    let created = policies.into_iter().find(|p| p.id == id).ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to create policy", "code": 500})))
    })?;
    Ok(Json(created))
}

pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_delete() {
        return Err((StatusCode::FORBIDDEN, Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        )));
    }
    if state.qos.remove_policy(&id) {
        Ok(Json(serde_json::json!({"deleted": id.to_string()})))
    } else {
        Err((StatusCode::NOT_FOUND, Json(
            serde_json::json!({"error": "Policy not found", "code": 404}),
        )))
    }
}
