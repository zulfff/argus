mod auth;
mod routes;
mod rule_store;
mod websocket;

use std::sync::Arc;

use axum::RequestPartsExt;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::signal;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tracing::{error, info, warn};

use argus_core::audit_log::AuditLog;
use argus_core::connection_tracker::ConnectionTracker;
use argus_core::rate_limiter::RateLimiter;
use argus_core::rule_engine::RuleEngine;
use argus_core::scanner::ScanDetector;
use argus_observability::metrics::ArgusMetrics;

use crate::auth::{AuthConfig, JwtAuth, Role};
use crate::websocket::LiveEventBus;

pub struct AppState {
    pub rule_engine: RuleEngine,
    pub connection_tracker: ConnectionTracker,
    pub rate_limiter: RateLimiter,
    pub scan_detector: ScanDetector,
    pub metrics: ArgusMetrics,
    pub event_bus: LiveEventBus,
    pub auth_config: AuthConfig,
    pub audit_log: AuditLog,
}

fn protected_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/rules",
            axum::routing::get(routes::rules::list_rules),
        )
        .route(
            "/api/v1/rules",
            axum::routing::post(routes::rules::create_rule),
        )
        .route(
            "/api/v1/rules/{id}",
            axum::routing::get(routes::rules::get_rule),
        )
        .route(
            "/api/v1/rules/{id}",
            axum::routing::put(routes::rules::update_rule),
        )
        .route(
            "/api/v1/rules/{id}",
            axum::routing::delete(routes::rules::delete_rule),
        )
        .route(
            "/api/v1/stats",
            axum::routing::get(routes::stats::get_stats),
        )
        .route(
            "/api/v1/connections",
            axum::routing::get(routes::connections::list_connections),
        )
        .route(
            "/api/v1/block",
            axum::routing::post(routes::block::block_ip),
        )
        .route(
            "/api/v1/block/{ip}",
            axum::routing::delete(routes::block::unblock_ip),
        )
        .route("/api/v1/ws", axum::routing::get(websocket::ws_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
}

fn public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", axum::routing::get(|| async { "OK" }))
        .route(
            "/api/v1/auth/login",
            axum::routing::post(routes::auth_routes::login),
        )
        .route(
            "/api/v1/auth/refresh",
            axum::routing::post(routes::auth_routes::refresh),
        )
        .route(
            "/metrics",
            axum::routing::get(routes::metrics::metrics_handler),
        )
}

pub fn app(state: Arc<AppState>) -> Router {
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(100)
            .burst_size(200)
            .finish()
            .expect("failed to build rate limiter config"),
    );

    let login_limiter = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .finish()
            .expect("failed to build login rate limiter"),
    );

    let login_layer = GovernorLayer {
        config: login_limiter,
    };

    public_routes()
        .route_layer(login_layer)
        .merge(protected_routes(state.clone()))
        .layer(GovernorLayer {
            config: governor_config,
        })
        .with_state(state)
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();

    let result = extract_auth(&mut parts, &state).await;

    req = Request::from_parts(parts, body);

    match result {
        Ok(user) => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        Err(err) => {
            let (status, msg) = auth_error_response(&err);
            let body = serde_json::json!({"error": msg, "code": status.as_u16()});
            (status, Json(body)).into_response()
        }
    }
}

async fn extract_auth(
    parts: &mut axum::http::request::Parts,
    state: &AppState,
) -> Result<crate::auth::AuthenticatedUser, crate::auth::AuthError> {
    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await
        .map_err(|_| crate::auth::AuthError::MissingToken)?;

    let jwt = JwtAuth::new(&state.auth_config.jwt_secret);
    let claims = jwt
        .validate_token(bearer.token())
        .map_err(|e| crate::auth::AuthError::InvalidToken(e))?;

    Ok(crate::auth::AuthenticatedUser { claims })
}

fn auth_error_response(err: &crate::auth::AuthError) -> (StatusCode, String) {
    match err {
        crate::auth::AuthError::MissingToken => (
            StatusCode::UNAUTHORIZED,
            "Missing authorization token".into(),
        ),
        crate::auth::AuthError::InvalidToken(_) => {
            (StatusCode::UNAUTHORIZED, "Invalid or expired token".into())
        }
        crate::auth::AuthError::Forbidden => {
            (StatusCode::FORBIDDEN, "Insufficient permissions".into())
        }
        crate::auth::AuthError::InternalError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Authentication error".into(),
        ),
    }
}

fn generate_secret() -> Vec<u8> {
    let mut buf = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.to_vec()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let store = Arc::new(rule_store::InMemoryRuleStore::new());
    let rule_engine = RuleEngine::new(store);
    let connection_tracker = ConnectionTracker::new(65536, 30);
    let rate_limiter = RateLimiter::new(100.0, 10.0);
    let scan_detector = ScanDetector::new();
    let metrics = ArgusMetrics::new();
    let event_bus = LiveEventBus::new(1024);
    let audit_log = AuditLog::new();

    let jwt_secret = match std::env::var("ARGUS_JWT_SECRET") {
        Ok(s) if s.len() >= 32 => {
            info!("Using JWT secret from ARGUS_JWT_SECRET env var");
            s.into_bytes()
        }
        Ok(s) => {
            error!(
                "ARGUS_JWT_SECRET must be at least 32 bytes (got {}). Refusing to start.",
                s.len()
            );
            anyhow::bail!("ARGUS_JWT_SECRET too short: {} bytes, need >= 32", s.len());
        }
        Err(_) => {
            warn!("ARGUS_JWT_SECRET not set — generating random secret for this session. Users will need to re-login on restart.");
            generate_secret()
        }
    };

    let mut auth_config = AuthConfig::new(jwt_secret);

    let admin_user = std::env::var("ARGUS_ADMIN_USER").unwrap_or_else(|_| "admin".into());
    let admin_pass = std::env::var("ARGUS_ADMIN_PASS").unwrap_or_else(|_| {
        warn!("ARGUS_ADMIN_PASS not set — generating random admin password");
        let pass = hex::encode({
            let mut buf = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        });
        info!("Generated admin password (change immediately): {}", pass);
        pass
    });

    let existing = auth_config.user_store.list_users().await;
    if existing.is_empty() {
        auth_config
            .user_store
            .add_user(&admin_user, &admin_pass, Role::Admin)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create admin user: {}", e))?;
        info!("Initial admin user '{}' created", admin_user);
    } else {
        info!("Users already exist — skipping admin creation");
    }

    let state = Arc::new(AppState {
        rule_engine,
        connection_tracker,
        rate_limiter,
        scan_detector,
        metrics,
        event_bus,
        auth_config,
        audit_log,
    });

    let app = app(state);

    let listener = TcpListener::bind("0.0.0.0:8443").await?;
    info!("argus-api listening on 0.0.0.0:8443");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("signal received, starting graceful shutdown");
}
