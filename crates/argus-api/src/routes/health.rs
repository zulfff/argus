use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::health_check::HealthChecker;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub components: Vec<ComponentResponse>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct ComponentResponse {
    pub name: String,
    pub status: String,
    pub message: Option<String>,
    pub response_time_ms: Option<u64>,
}

pub async fn deep_health_check(
    State(state): State<Arc<AppState>>,
    Extension(_claims): Extension<Claims>,
) -> Result<Json<HealthResponse>, (StatusCode, Json<serde_json::Value>)> {
    let redis_url = std::env::var("REDIS_URL").ok();

    let health = HealthChecker::check_all(
        &state.db_pool,
        &redis_url,
        &state.ebpf_controller,
        &state.netbox_client,
    )
    .await;

    let status_code = match health.overall_status {
        argus_core::health_check::HealthStatus::Healthy => StatusCode::OK,
        argus_core::health_check::HealthStatus::Degraded => StatusCode::OK,
        argus_core::health_check::HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    let response = HealthResponse {
        status: format!("{:?}", health.overall_status),
        components: health
            .components
            .into_iter()
            .map(|c| ComponentResponse {
                name: c.name,
                status: format!("{:?}", c.status),
                message: c.message,
                response_time_ms: c.response_time_ms,
            })
            .collect(),
        timestamp: health.timestamp,
    };

    if status_code == StatusCode::OK {
        Ok(Json(response))
    } else {
        Err((status_code, Json(serde_json::json!(response))))
    }
}
