use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;

#[derive(Serialize)]
pub struct StatsResponse {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub active_connections: usize,
    pub blocked_ips: usize,
    pub rate_limit_buckets: usize,
}

pub async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    Json(StatsResponse {
        packets_allowed: 0,
        packets_dropped: 0,
        active_connections: state.connection_tracker.active_count(),
        blocked_ips: state.scan_detector.blocked_count(),
        rate_limit_buckets: state.rate_limiter.get_bucket_size(),
    })
}
