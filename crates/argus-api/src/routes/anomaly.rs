use axum::{extract::State, http::StatusCode, Extension, Json};
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;

pub async fn get_baseline(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((StatusCode::FORBIDDEN, Json(
            serde_json::json!({"error": "Insufficient permissions"}),
        )));
    }

    match state.anomaly_detector.get_baseline("all-interfaces") {
        Some(b) => Ok(Json(serde_json::json!({
            "interface": "all-interfaces",
            "mean_pps": b.mean_pps,
            "stddev_pps": b.stddev_pps,
            "mean_bps": b.mean_bps,
            "stddev_bps": b.stddev_bps,
            "mean_connections": b.mean_connections,
            "stddev_connections": b.stddev_connections,
            "sample_count": b.sample_count,
            "last_updated": b.last_updated.to_rfc3339(),
        }))),
        None => Ok(Json(serde_json::json!({
            "status": "no baseline computed yet",
            "interface": "all-interfaces"
        }))),
    }
}

pub async fn get_anomaly_alerts(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((StatusCode::FORBIDDEN, Json(
            serde_json::json!({"error": "Insufficient permissions"}),
        )));
    }

    let alerts = state.anomaly_detector.get_recent_alerts(100);
    let items: Vec<serde_json::Value> = alerts
        .iter()
        .map(|a| {
            serde_json::json!({
                "interface": a.interface,
                "metric": a.metric,
                "current_value": a.current_value,
                "expected_range": [a.expected_range.0, a.expected_range.1],
                "deviation_multiple": a.deviation_multiple,
                "severity": a.severity.to_string(),
                "timestamp": a.timestamp.to_rfc3339(),
                "description": a.description,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "count": items.len(),
        "alerts": items,
    })))
}
