use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::cluster::ClusterNode;

#[derive(Deserialize)]
pub struct RegisterNodeRequest {
    pub name: String,
    pub address: String,
    pub port: u16,
}

pub async fn list_nodes(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<ClusterNode>>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    Ok(Json(state.cluster_manager.list_nodes()))
}

pub async fn register_node(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<RegisterNodeRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let id = state
        .cluster_manager
        .register_node(&req.name, &req.address, req.port);

    state.audit_log.log(
        &claims.username,
        "cluster.node.register",
        "cluster",
        &format!(
            "Registered node '{}' at {}:{}",
            req.name, req.address, req.port
        ),
        None,
        true,
    );

    Ok(Json(serde_json::json!({
        "id": id.to_string(),
        "name": req.name,
        "address": req.address,
        "port": req.port,
    })))
}

pub async fn remove_node(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_delete() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    if state.cluster_manager.remove_node(&id) {
        state.audit_log.log(
            &claims.username,
            "cluster.node.remove",
            "cluster",
            &format!("Removed node {}", id),
            None,
            true,
        );
        Ok(Json(serde_json::json!({"removed": id.to_string()})))
    } else {
        Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": "Node not found or cannot remove local node", "code": 404}),
            ),
        ))
    }
}

pub async fn cluster_status(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let nodes = state.cluster_manager.list_nodes();
    let leader = nodes
        .iter()
        .find(|n| n.role == argus_core::cluster::NodeRole::Leader);
    let total = nodes.len();
    let healthy = nodes.iter().filter(|n| n.healthy).count();

    Ok(Json(serde_json::json!({
        "total_nodes": total,
        "healthy_nodes": healthy,
        "leader": leader.map(|l| serde_json::json!({
            "id": l.id.to_string(),
            "name": l.name,
            "address": l.address,
        })),
        "nodes": nodes.iter().map(|n| serde_json::json!({
            "id": n.id.to_string(),
            "name": n.name,
            "address": n.address,
            "port": n.port,
            "role": n.role.to_string(),
            "healthy": n.healthy,
            "last_heartbeat": n.last_heartbeat.to_rfc3339(),
        })).collect::<Vec<_>>(),
    })))
}
