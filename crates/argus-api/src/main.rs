mod routes;
mod rule_store;
mod auth;
mod websocket;

use std::sync::Arc;

use argus_core::connection_tracker::ConnectionTracker;
use argus_core::rate_limiter::RateLimiter;
use argus_core::rule_engine::RuleEngine;
use argus_core::scanner::ScanDetector;
use argus_observability::metrics::ArgusMetrics;

use crate::auth::AuthConfig;
use crate::websocket::LiveEventBus;

use axum::Router;
use tokio::net::TcpListener;
use tokio::signal;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tracing::info;

pub struct AppState {
    pub rule_engine: RuleEngine,
    pub connection_tracker: ConnectionTracker,
    pub rate_limiter: RateLimiter,
    pub scan_detector: ScanDetector,
    pub metrics: ArgusMetrics,
    pub event_bus: LiveEventBus,
    pub auth_config: AuthConfig,
}

pub fn app(state: Arc<AppState>) -> Router {
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(100)
            .burst_size(200)
            .finish()
            .expect("failed to build rate limiter config"),
    );

    Router::new()
        .route("/health", axum::routing::get(|| async { "OK" }))
        .route("/api/v1/auth/login", axum::routing::post(routes::auth_routes::login))
        .route("/api/v1/auth/refresh", axum::routing::post(routes::auth_routes::refresh))
        .route("/api/v1/rules", axum::routing::get(routes::rules::list_rules))
        .route("/api/v1/rules", axum::routing::post(routes::rules::create_rule))
        .route("/api/v1/rules/{id}", axum::routing::get(routes::rules::get_rule))
        .route("/api/v1/rules/{id}", axum::routing::put(routes::rules::update_rule))
        .route("/api/v1/rules/{id}", axum::routing::delete(routes::rules::delete_rule))
        .route("/api/v1/stats", axum::routing::get(routes::stats::get_stats))
        .route("/api/v1/connections", axum::routing::get(routes::connections::list_connections))
        .route("/api/v1/block", axum::routing::post(routes::block::block_ip))
        .route("/api/v1/block/{ip}", axum::routing::delete(routes::block::unblock_ip))
        .route("/api/v1/ws", axum::routing::get(websocket::ws_handler))
        .route("/metrics", axum::routing::get(routes::metrics::metrics_handler))
        .layer(GovernorLayer { config: governor_config })
        .with_state(state)
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

    let jwt_secret = std::env::var("ARGUS_JWT_SECRET")
        .unwrap_or_else(|_| "argus-dev-secret-change-me-in-production!!!".to_string());
    let mut auth_config = AuthConfig::new(jwt_secret.into_bytes());

    let _ = auth_config
        .user_store
        .add_user("admin", "argus-admin", auth::Role::Admin)
        .await;

    let state = Arc::new(AppState {
        rule_engine,
        connection_tracker,
        rate_limiter,
        scan_detector,
        metrics,
        event_bus,
        auth_config,
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
