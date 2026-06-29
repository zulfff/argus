use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;

pub async fn download_wg_config(
    State(state): State<Arc<AppState>>,
    Path(iface_name): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions"})),
        ));
    }

    match state.ztna_mesh.generate_wg_config(&iface_name) {
        Ok(config) => Ok(Json(serde_json::json!({
            "interface": iface_name,
            "config": config,
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to generate config: {}", e)
            })),
        )),
    }
}

pub async fn list_ztna_peers(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions"})),
        ));
    }

    let peers = state.ztna_mesh.list_peers();
    Ok(Json(serde_json::json!({
        "count": peers.len(),
        "peers": peers,
    })))
}
