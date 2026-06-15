use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::Arc;

use crate::AppState;
use crate::auth::{JwtAuth, LoginRequest, RefreshRequest, TokenResponse};

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let user = state
        .auth_config
        .user_store
        .verify_password(&req.username, &req.password)
        .await
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid username or password",
                    "code": 401
                })),
            )
        })?;

    let jwt = JwtAuth::new(&state.auth_config.jwt_secret);
    let tokens = jwt.generate_tokens(&user).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e,
                "code": 500
            })),
        )
    })?;

    Ok(Json(tokens))
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let jwt = JwtAuth::new(&state.auth_config.jwt_secret);
    let tokens = jwt.refresh_access_token(&req.refresh_token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": format!("refresh failed: {}", e),
                "code": 401
            })),
        )
    })?;

    Ok(Json(tokens))
}
