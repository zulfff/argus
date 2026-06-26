use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::vpn_portal::{VpnPeerRequest, VpnPeerStatus};

#[derive(Deserialize)]
pub struct SubmitRequest {
    pub public_key: String,
    pub allowed_ips: String,
}

pub async fn submit_request(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<SubmitRequest>,
) -> Result<Json<VpnPeerRequest>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let key = payload.public_key.trim();
    if key.len() != 44
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid WireGuard public key format", "code": 400})),
        ));
    }
    if !payload.allowed_ips.is_empty() {
        for ip_str in payload.allowed_ips.split(',') {
            let trimmed = ip_str.trim();
            if !trimmed.is_empty() && argus_common::net::validate_cidr(trimmed).is_err() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"error": format!("Invalid CIDR in allowed_ips: {}", trimmed), "code": 400}),
                    ),
                ));
            }
        }
    }
    let req = state.vpn_portal.submit_request(
        &claims.username,
        &payload.public_key,
        &payload.allowed_ips,
    );
    Ok(Json(req))
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
}

pub async fn list_requests(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<VpnPeerRequest>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let status = query.status.as_deref().and_then(|s| match s {
        "pending" => Some(VpnPeerStatus::Pending),
        "approved" => Some(VpnPeerStatus::Approved),
        "denied" => Some(VpnPeerStatus::Denied),
        "active" => Some(VpnPeerStatus::Active),
        "revoked" => Some(VpnPeerStatus::Revoked),
        _ => None,
    });
    let mut requests = state.vpn_portal.list(status);
    if !claims.role.can_manage_users() {
        requests.retain(|r| r.user_id == claims.username);
    }
    Ok(Json(requests))
}

pub async fn approve_request(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    if state.vpn_portal.approve(&id) {
        Ok(Json(
            serde_json::json!({"status": "approved", "id": id.to_string()}),
        ))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": "Request not found or not in pending state", "code": 404}),
            ),
        ))
    }
}

pub async fn deny_request(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    if state.vpn_portal.deny(&id) {
        Ok(Json(
            serde_json::json!({"status": "denied", "id": id.to_string()}),
        ))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": "Request not found or not in pending state", "code": 404}),
            ),
        ))
    }
}

pub async fn revoke_request(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_delete() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    if state.vpn_portal.revoke(&id) {
        Ok(Json(
            serde_json::json!({"status": "revoked", "id": id.to_string()}),
        ))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": "Request not found or not in active/approved state", "code": 404}),
            ),
        ))
    }
}

pub async fn download_config(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let requests = state.vpn_portal.list(None);
    let peer = requests.iter().find(|r| r.id == id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Request not found or not approved", "code": 404})),
        )
    })?;

    if !claims.role.can_manage_users() && peer.user_id != claims.username {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Request not found or not approved", "code": 404})),
        ));
    }

    let server_public_key = std::env::var("ARGUS_WG_PUBLIC_KEY").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Server configuration incomplete", "code": 500})),
        )
    })?;
    let endpoint = std::env::var("ARGUS_WG_ENDPOINT").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Server configuration incomplete", "code": 500})),
        )
    })?;
    match state
        .vpn_portal
        .generate_client_config(&id, &server_public_key, &endpoint)
    {
        Some(config) => Ok(Json(serde_json::json!({"config": config}))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Request not found or not approved", "code": 404})),
        )),
    }
}
