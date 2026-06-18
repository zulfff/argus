use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::syslog::SyslogConfig;

#[derive(Deserialize)]
pub struct CreateConfigRequest {
    pub server: String,
    pub port: u16,
    pub protocol: argus_core::syslog::SyslogProtocol,
    pub min_severity: String,
    pub enabled: Option<bool>,
}

pub async fn list_configs(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<SyslogConfig>>, Json<serde_json::Value>> {
    if !claims.role.can_read() {
        return Err(Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        ));
    }
    Ok(Json(state.syslog.list_configs()))
}

pub async fn add_config(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateConfigRequest>,
) -> Result<Json<SyslogConfig>, Json<serde_json::Value>> {
    if !claims.role.can_write() {
        return Err(Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        ));
    }
    let config = SyslogConfig {
        id: uuid::Uuid::nil(),
        server: payload.server,
        port: payload.port,
        protocol: payload.protocol,
        min_severity: payload.min_severity,
        enabled: payload.enabled.unwrap_or(true),
    };
    let id = state.syslog.add_config(config);
    let configs = state.syslog.list_configs();
    let created = configs.into_iter().find(|c| c.id == id).ok_or_else(|| {
        Json(serde_json::json!({"error": "Failed to create config", "code": 500}))
    })?;
    Ok(Json(created))
}

pub async fn remove_config(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    if !claims.role.can_delete() {
        return Err(Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        ));
    }
    if state.syslog.remove_config(&id) {
        Ok(Json(serde_json::json!({"deleted": id.to_string()})))
    } else {
        Err(Json(
            serde_json::json!({"error": "Config not found", "code": 404}),
        ))
    }
}
