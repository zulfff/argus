use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;

#[derive(Deserialize)]
pub struct StartDrainRequest {
    pub ip: IpAddr,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    300
}

#[derive(Serialize)]
pub struct DrainStatusResponse {
    pub ip: IpAddr,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub timeout_secs: u64,
    pub elapsed_secs: i64,
    pub active_connections: usize,
}

pub async fn start_drain(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<StartDrainRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions"})),
        ));
    }

    if req.timeout_secs > 3600 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Timeout must be <= 3600 seconds"})),
        ));
    }

    state
        .connection_drainer
        .start_drain(req.ip, req.timeout_secs, &state.connection_tracker);

    Ok(Json(serde_json::json!({
        "message": "Connection draining started",
        "ip": req.ip.to_string(),
        "timeout_secs": req.timeout_secs
    })))
}

pub async fn list_draining(
    State(state): State<Arc<AppState>>,
    Extension(_claims): Extension<Claims>,
) -> Json<Vec<DrainStatusResponse>> {
    let draining = state.connection_drainer.list_draining();
    let now = chrono::Utc::now();

    let response = draining
        .into_iter()
        .map(|cfg| {
            let active = state.connection_tracker.count_for_ip(cfg.ip);
            DrainStatusResponse {
                ip: cfg.ip,
                started_at: cfg.started_at,
                timeout_secs: cfg.timeout_secs,
                elapsed_secs: (now - cfg.started_at).num_seconds(),
                active_connections: active,
            }
        })
        .collect();

    Json(response)
}
