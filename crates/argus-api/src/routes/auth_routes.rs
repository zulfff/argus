use axum::{extract::State, http::StatusCode, Json};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;

use crate::auth::{JwtAuth, LoginRequest, RefreshRequest, TokenResponse};
use crate::AppState;

pub async fn login(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let user = state
        .auth_config
        .user_store
        .verify_password(&req.username, &req.password)
        .await
        .ok_or_else(|| {
            warn!(
                username = %req.username,
                ip = %addr.ip(),
                "Failed login attempt"
            );
            state.audit_log.log(
                &req.username,
                "login.failed",
                "auth",
                &format!("Failed login from {}", addr.ip()),
                Some(&addr.ip().to_string()),
                false,
            );
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Invalid username or password",
                    "code": 401
                })),
            )
        })?;

    let jwt = JwtAuth::new(&state.auth_config.jwt_secret);
    let tokens = jwt.generate_tokens(&user).map_err(|_e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Authentication failed",
                "code": 500
            })),
        )
    })?;

    state.audit_log.log(
        &user.username,
        "login.success",
        "auth",
        "Successful login",
        Some(&addr.ip().to_string()),
        true,
    );

    Ok(Json(tokens))
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let jwt = JwtAuth::new(&state.auth_config.jwt_secret);
    let tokens = jwt.refresh_access_token(&req.refresh_token).map_err(|_e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Token refresh failed",
                "code": 401
            })),
        )
    })?;

    Ok(Json(tokens))
}
