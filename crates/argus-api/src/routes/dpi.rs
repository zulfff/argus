use axum::{extract::State, Extension, Json};
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_common::types::Direction;
use argus_core::dpi::Layer7Protocol;

#[derive(Deserialize)]
pub struct IdentifyRequest {
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: Option<String>,
    pub payload_heuristic: Option<bool>,
    pub data: Option<String>,
}

pub async fn identify(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<IdentifyRequest>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    if !claims.role.can_read() {
        return Err(Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        ));
    }

    let direction = match payload.direction.as_deref() {
        Some("inbound") => Direction::Inbound,
        Some("outbound") => Direction::Outbound,
        Some("forward") => Direction::Forward,
        _ => Direction::Inbound,
    };

    let mut result = state
        .dpi
        .identify(payload.dst_port, payload.protocol, direction);

    if payload.payload_heuristic.unwrap_or(false) {
        if let Some(data_b64) = &payload.data {
            if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(data_b64.as_bytes())
            {
                let heuristic_proto = state.dpi.identify_by_payload_heuristic(&data);
                if heuristic_proto != Layer7Protocol::Unknown && heuristic_proto != result.protocol
                {
                    result.protocol = heuristic_proto.clone();
                    result.confidence = (result.confidence + 0.8) / 2.0;
                    result.description =
                        format!("{} (port + payload heuristic)", heuristic_proto.clone());
                }
            }
        }
    }

    Ok(Json(serde_json::json!({
        "protocol": result.protocol,
        "confidence": result.confidence,
        "description": result.description,
    })))
}
