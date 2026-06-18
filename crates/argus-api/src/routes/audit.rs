use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Serialize)]
pub struct AuditEntryResponse {
    pub id: String,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub details: String,
    pub ip_address: Option<String>,
    pub success: bool,
    pub hash: String,
    pub previous_hash: String,
}

impl From<argus_core::audit_log::AuditEntry> for AuditEntryResponse {
    fn from(e: argus_core::audit_log::AuditEntry) -> Self {
        AuditEntryResponse {
            id: e.id.to_string(),
            timestamp: e.timestamp.to_rfc3339(),
            actor: e.actor,
            action: e.action,
            resource: e.resource,
            details: e.details,
            ip_address: e.ip_address,
            success: e.success,
            hash: e.hash,
            previous_hash: e.previous_hash,
        }
    }
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub tampered_count: usize,
    pub total_entries: usize,
    pub first_broken_at: Option<usize>,
}

pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditQuery>,
) -> Json<Vec<AuditEntryResponse>> {
    let entries = state.audit_log.query(
        query.actor.as_deref(),
        query.action.as_deref(),
        query.limit.min(1000),
    );
    Json(entries.into_iter().map(AuditEntryResponse::from).collect())
}

pub async fn verify_audit(State(state): State<Arc<AppState>>) -> Json<VerifyResponse> {
    let result = state.audit_log.verify_integrity();
    Json(VerifyResponse {
        valid: result.valid,
        tampered_count: result.tampered_count,
        total_entries: result.total_entries,
        first_broken_at: result.first_broken_at,
    })
}

pub async fn export_audit(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    use axum::http::{header, HeaderMap, HeaderValue};

    let json = state.audit_log.export_json();
    let fname = format!(
        "attachment; filename=\"audit-export-{}.json\"",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&fname).unwrap(),
    );

    (headers, json)
}
