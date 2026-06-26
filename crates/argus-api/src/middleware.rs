use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use axum_extra::headers::{authorization::Bearer, Authorization, HeaderMapExt};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth::AuthError;
use crate::AppState;

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let headers = request.headers();
    let authorization = headers
        .typed_get::<Authorization<Bearer>>()
        .ok_or(AuthError::MissingToken)?;

    let claims = state
        .auth_config
        .jwt_auth
        .validate_access_token(authorization.token())
        .map_err(AuthError::InvalidToken)?;

    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

pub fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    addr: Option<SocketAddr>,
) -> Option<String> {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            if let Some(first) = s.split(',').next() {
                return Some(first.trim().to_string());
            }
        }
    }
    addr.map(|a| a.ip().to_string())
}
