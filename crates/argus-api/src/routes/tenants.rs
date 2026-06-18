use axum::{
    extract::{Path, State},
    Extension, Json,
};
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::tenancy::Tenant;

pub async fn list_tenants(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<Tenant>>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    Ok(Json(state.tenant_manager.list_tenants()))
}

pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<Tenant>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'name' field", "code": 400})),
            )
        })?;
    let description = payload
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let tenant = state.tenant_manager.create_tenant(name, description);

    state.audit_log.log(
        &claims.username,
        "tenant.create",
        "tenancy",
        &format!("Created tenant '{}' ({})", tenant.name, tenant.id),
        None,
        true,
    );

    Ok(Json(tenant))
}

pub async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    if state.tenant_manager.delete_tenant(&id) {
        state.audit_log.log(
            &claims.username,
            "tenant.delete",
            "tenancy",
            &format!("Deleted tenant {}", id),
            None,
            true,
        );
        Ok(Json(serde_json::json!({"deleted": id.to_string()})))
    } else {
        Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Tenant not found", "code": 404})),
        ))
    }
}
