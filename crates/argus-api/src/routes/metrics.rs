use axum::{extract::State, response::IntoResponse};
use std::sync::Arc;

use crate::AppState;

pub async fn metrics_handler(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(body) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4",
            )],
            body,
        ),
        Err(e) => (
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            format!("prometheus encoding error: {}", e),
        ),
    }
}
