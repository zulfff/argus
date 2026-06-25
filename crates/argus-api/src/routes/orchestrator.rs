use axum::{extract::State, Extension, Json};
use serde::Serialize;
use std::sync::Arc;

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
) -> Json<DriftStatusResponse> {
    if !claims.role.can_read() {
        return Json(DriftStatusResponse {
            configured: false,
            reports: vec![],
        });
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
                Json(DriftStatusResponse {
                    configured: true,
                    reports: reports_json,
                })
            }
            Err(e) => Json(DriftStatusResponse {
                configured: true,
                reports: vec![serde_json::json!({"error": e.to_string()})],
            }),
        },
        None => Json(DriftStatusResponse {
            configured: false,
            reports: vec![],
        }),
    }
}

pub async fn trigger_reconciliation(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Json<ReconciliationResponse> {
    if !claims.role.can_write() {
        return Json(ReconciliationResponse {
            triggered: false,
            message: "Insufficient permissions".into(),
        });
    }

    match &state.drift_detector {
        Some(dd) => match dd.check_all_devices().await {
            Ok(reports) => {
                let needs_fix: Vec<_> = reports.iter().filter(|r| r.needs_remediation).collect();
                Json(ReconciliationResponse {
                    triggered: true,
                    message: format!(
                        "Reconciliation complete: {} devices checked, {} need remediation",
                        reports.len(),
                        needs_fix.len()
                    ),
                })
            }
            Err(e) => Json(ReconciliationResponse {
                triggered: true,
                message: format!("Reconciliation failed: {}", e),
            }),
        },
        None => Json(ReconciliationResponse {
            triggered: false,
            message: "Orchestrator not configured (set NETBOX_URL and NETBOX_TOKEN)".into(),
        }),
    }
}

pub async fn get_netbox_devices(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Json<serde_json::Value> {
    if !claims.role.can_read() {
        return Json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    match &state.netbox_client {
        Some(nb) => match nb.get_devices(None).await {
            Ok(devices) => Json(serde_json::json!({
                "devices": devices,
                "count": devices.len()
            })),
            Err(e) => Json(serde_json::json!({"error": e.to_string()})),
        },
        None => Json(serde_json::json!({
            "error": "Orchestrator not configured (set NETBOX_URL and NETBOX_TOKEN)"
        })),
    }
}
