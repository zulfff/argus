use axum::{extract::{Path, State}, Json};
use serde::Deserialize;
use std::sync::Arc;

use crate::AppState;

#[derive(Deserialize)]
pub struct BlockRequest {
    pub ip: String,
}

pub async fn block_ip(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    let ip: std::net::IpAddr = req.ip.parse()
        .map_err(|e| Json(serde_json::json!({"error": format!("invalid IP: {}", e)})))?;

    state.scan_detector.manual_block(ip);

    Ok(Json(serde_json::json!({"blocked": ip.to_string()})))
}

pub async fn unblock_ip(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Json<serde_json::Value> {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        state.scan_detector.unblock_ip(addr);
    }

    Json(serde_json::json!({"unblocked": ip}))
}
