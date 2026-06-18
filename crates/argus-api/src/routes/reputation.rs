use axum::{
    extract::{Path, State},
    Extension, Json,
};
use std::net::IpAddr;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::reputation::IpReputation;

pub async fn get_reputation(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(ip): Path<String>,
) -> Result<Json<IpReputation>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let addr: IpAddr = ip.parse().map_err(|_| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid IP address", "code": 400})),
        )
    })?;

    match state.reputation_manager.get_reputation(&addr) {
        Some(rep) => Ok(Json(rep)),
        None => Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No reputation data for this IP", "code": 404})),
        )),
    }
}

pub async fn list_reputations(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<IpReputation>>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    Ok(Json(state.reputation_manager.list_lowest(usize::MAX)))
}
