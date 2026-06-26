use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;

#[derive(Deserialize)]
pub struct BlockRequest {
    pub ip: String,
}

pub async fn block_ip(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    if !claims.role.can_write() {
        return Err(Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        ));
    }

    let ip: std::net::IpAddr = req
        .ip
        .parse()
        .map_err(|e| Json(serde_json::json!({"error": format!("invalid IP: {}", e)})))?;

    state.scan_detector.manual_block(ip);

    Ok(Json(serde_json::json!({"blocked": ip.to_string()})))
}

pub async fn unblock_ip(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    if !claims.role.can_delete() {
        return Err(Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        ));
    }

    let addr: std::net::IpAddr = ip
        .parse()
        .map_err(|e| Json(serde_json::json!({"error": format!("invalid IP: {}", e)})))?;
    state.scan_detector.unblock_ip(addr);
    Ok(Json(serde_json::json!({"unblocked": addr.to_string()})))
}
