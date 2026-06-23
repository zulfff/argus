use axum::http::StatusCode;
use axum::{extract::State, Extension, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;

#[derive(Serialize)]
pub struct StatsResponse {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub active_connections: usize,
    pub blocked_ips: usize,
    pub rate_limit_buckets: usize,
}

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<StatsResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    Ok(Json(StatsResponse {
        packets_allowed: 0,
        packets_dropped: 0,
        active_connections: state.connection_tracker.active_count(),
        blocked_ips: state.scan_detector.blocked_count(),
        rate_limit_buckets: state.rate_limiter.get_bucket_size(),
    }))
}
