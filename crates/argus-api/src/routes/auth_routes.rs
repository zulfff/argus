use axum::http::StatusCode;
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;

use crate::auth::{Claims, JwtAuth, LoginRequest, RefreshRequest, Role, TokenResponse, User};
use crate::AppState;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub enabled: bool,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        UserResponse {
            id: u.id.to_string(),
            username: u.username,
            role: u.role.to_string(),
            enabled: u.enabled,
        }
    }
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<UserResponse>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let users = state.auth_config.user_store.list_users().await;
    Ok(Json(users.into_iter().map(UserResponse::from).collect()))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let role = match req.role.as_deref() {
        Some("operator") => Role::Operator,
        Some("viewer") => Role::Viewer,
        _ => Role::Viewer,
    };

    let user = state
        .auth_config
        .user_store
        .add_user(&req.username, &req.password, role)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e, "code": 400})),
            )
        })?;

    state.audit_log.log(
        &claims.username,
        "user.create",
        "auth",
        &format!("Created user '{}'", req.username),
        None,
        true,
    );

    Ok(Json(UserResponse::from(user)))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    if state.auth_config.user_store.delete_user(&username).await {
        state.audit_log.log(
            &claims.username,
            "user.delete",
            "auth",
            &format!("Deleted user '{}'", username),
            None,
            true,
        );
        Ok(Json(serde_json::json!({"deleted": username})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "User not found", "code": 404})),
        ))
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub password: String,
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(username): Path<String>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() && claims.username != username {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    state
        .auth_config
        .user_store
        .change_password(&username, &req.password)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": e, "code": 404})),
            )
        })?;

    state.audit_log.log(
        &claims.username,
        "user.password_change",
        "auth",
        &format!("Password changed for user '{}'", username),
        None,
        true,
    );

    Ok(Json(serde_json::json!({"status": "password updated"})))
}
