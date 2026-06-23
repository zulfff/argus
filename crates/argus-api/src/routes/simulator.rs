use axum::http::StatusCode;
use axum::{extract::State, Extension, Json};
use std::sync::Arc;

use crate::auth::Claims;
use crate::AppState;
use argus_core::simulator::{SimulationRequest, Simulator};

pub async fn simulate_rule(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<SimulationRequest>,
) -> Result<Json<argus_core::simulator::SimulationResponse>, (StatusCode, Json<serde_json::Value>)>
{
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let simulator = Simulator::new(state.rule_engine.store().clone());

    match simulator.simulate(&req).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e, "code": 400})),
        )),
    }
}
