use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::compliance::ComplianceReport;

#[derive(Deserialize)]
pub struct GenerateRequest {
    pub report_type: String,
    pub data: serde_json::Value,
}

#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<usize>,
}

pub async fn generate_report(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<GenerateRequest>,
) -> Result<Json<ComplianceReport>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let report =
        state
            .compliance
            .generate_report(&payload.report_type, &claims.username, &payload.data);
    Ok(Json(report))
}

pub async fn list_reports(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ComplianceReport>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let limit = params.limit.unwrap_or(50);
    Ok(Json(state.compliance.list_reports(limit)))
}

pub async fn get_report(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ComplianceReport>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    match state.compliance.get_report(&id) {
        Some(report) => Ok(Json(report)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Report not found", "code": 404})),
        )),
    }
}
