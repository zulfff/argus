use axum::http::{header, StatusCode};
use axum::{extract::State, response::IntoResponse, Extension, Json};
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::import_export::RuleExport;

pub async fn export_json(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    if !claims.role.can_read() {
        return (
            StatusCode::FORBIDDEN,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, ""),
            ],
            serde_json::json!({"error": "Insufficient permissions", "code": 403}).to_string(),
        );
    }
    let rules = state
        .rule_engine
        .store()
        .list_rules()
        .await
        .unwrap_or_default();
    let export = RuleExport::new(rules);
    match export.to_json() {
        Ok(json) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"rules.json\"",
                ),
            ],
            json,
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, ""),
            ],
            serde_json::json!({"error": e}).to_string(),
        ),
    }
}

pub async fn export_yaml(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    if !claims.role.can_read() {
        return (
            StatusCode::FORBIDDEN,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, ""),
            ],
            serde_json::json!({"error": "Insufficient permissions", "code": 403}).to_string(),
        );
    }
    let rules = state
        .rule_engine
        .store()
        .list_rules()
        .await
        .unwrap_or_default();
    let export = RuleExport::new(rules);
    match export.to_yaml() {
        Ok(yaml) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/x-yaml"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"rules.yaml\"",
                ),
            ],
            yaml,
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, ""),
            ],
            serde_json::json!({"error": e}).to_string(),
        ),
    }
}

pub async fn export_csv(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    if !claims.role.can_read() {
        return (
            StatusCode::FORBIDDEN,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, ""),
            ],
            serde_json::json!({"error": "Insufficient permissions", "code": 403}).to_string(),
        );
    }
    let rules = state
        .rule_engine
        .store()
        .list_rules()
        .await
        .unwrap_or_default();
    let export = RuleExport::new(rules);
    match export.to_csv() {
        Ok(csv) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/csv"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"rules.csv\"",
                ),
            ],
            csv,
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, ""),
            ],
            serde_json::json!({"error": e}).to_string(),
        ),
    }
}

#[derive(serde::Deserialize)]
pub struct ImportRequest {
    pub data: String,
}

pub async fn import_rules(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let export = match RuleExport::from_json(&req.data) {
        Ok(e) => e,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid JSON: {}", e), "code": 400})),
            ));
        }
    };

    if let Err(errors) = export.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Validation failed", "details": errors, "code": 400})),
        ));
    }

    let mut imported = 0;
    let mut errors = Vec::new();
    for rule in export.rules {
        match state.rule_engine.store().create_rule(rule).await {
            Ok(_) => imported += 1,
            Err(e) => errors.push(e.to_string()),
        }
    }

    state.audit_log.log(
        &claims.username,
        "rules.import",
        "rules",
        &format!("Imported {} rules with {} errors", imported, errors.len()),
        None,
        errors.is_empty(),
    );

    Ok(Json(serde_json::json!({
        "imported": imported,
        "errors": errors,
    })))
}
