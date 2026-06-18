use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use axum_extra::headers::{authorization::Bearer, Authorization, HeaderMapExt};
use std::sync::Arc;

use crate::auth::{AuthError, JwtAuth};
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

    let jwt = JwtAuth::new(&state.auth_config.jwt_secret);
    let claims = jwt
        .validate_token(authorization.token())
        .map_err(AuthError::InvalidToken)?;

    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}
