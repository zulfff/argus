use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::Serialize;
use std::sync::Arc;
use tracing::error;

use crate::auth::Claims;
use crate::AppState;

#[derive(Serialize)]
pub struct DriftStatusResponse {
    pub configured: bool,
    pub reports: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ReconciliationResponse {
    pub triggered: bool,
    pub message: String,
}

pub async fn get_drift_status(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<DriftStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    match &state.drift_detector {
        Some(dd) => match dd.check_all_devices().await {
            Ok(reports) => {
                let reports_json: Vec<serde_json::Value> = reports
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "device": r.device_name,
                            "detected_at": r.detected_at.to_rfc3339(),
                            "needs_remediation": r.needs_remediation,
                            "unexpected_rules": r.unexpected_rules,
                            "missing_rules": r.missing_rules,
                            "diff_text": r.diff_text,
                        })
                    })
                    .collect();
                Ok(Json(DriftStatusResponse {
                    configured: true,
                    reports: reports_json,
                }))
            }
            Err(e) => {
                tracing::error!("Orchestrator drift check failed: {:#}", e);
                Ok(Json(DriftStatusResponse {
                    configured: true,
                    reports: vec![serde_json::json!({"error": "Drift detection failed — check server logs"})],
                }))
            },
        },
        None => Ok(Json(DriftStatusResponse {
            configured: false,
            reports: vec![],
        })),
    }
}

pub async fn trigger_reconciliation(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ReconciliationResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    match &state.drift_detector {
        Some(dd) => match dd.check_all_devices().await {
            Ok(reports) => {
                let needs_fix: Vec<_> = reports.iter().filter(|r| r.needs_remediation).collect();
                Ok(Json(ReconciliationResponse {
                    triggered: true,
                    message: format!(
                        "Reconciliation complete: {} reports, {} need remediation (use auto-remediation to fix)",
                        reports.len(),
                        needs_fix.len()
                    ),
                }))
            }
            Err(e) => {
                tracing::error!("Orchestrator reconciliation failed: {:#}", e);
                Ok(Json(ReconciliationResponse {
                    triggered: true,
                    message: "Reconciliation failed — check server logs".into(),
                }))
            }
        },
        None => Ok(Json(ReconciliationResponse {
            triggered: false,
            message: "Orchestrator not configured (set NETBOX_URL and NETBOX_TOKEN)".into(),
        })),
    }
}

pub async fn get_netbox_devices(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions"})),
        ));
    }

    match &state.netbox_client {
        Some(nb) => match nb.get_devices(None).await {
            Ok(devices) => Ok(Json(serde_json::json!({
                "devices": devices,
                "count": devices.len()
            }))),
            Err(e) => {
                error!("NetBox get_devices failed: {:#}", e);
                Ok(Json(serde_json::json!({"error": "Failed to fetch devices — check server logs"})))
            },
        },
        None => Ok(Json(serde_json::json!({
            "error": "Orchestrator not configured (set NETBOX_URL and NETBOX_TOKEN)"
        }))),
    }
}
