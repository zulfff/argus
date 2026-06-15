mod auth;
mod routes;
mod rule_store;
mod websocket;

use std::sync::Arc;

use axum::Router;
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

use crate::auth::{AuthConfig, Role};
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

pub fn app(state: Arc<AppState>) -> Router {
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(100)
            .burst_size(200)
            .finish()
            .expect("governor config builder failed"),
    );

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
        .layer(GovernorLayer {
            config: governor_config,
        })
        .with_state(state)
}

fn generate_secret() -> Vec<u8> {
    let mut buf = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.to_vec()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_target(false).init();
    info!("ARGUS v0.1.1 starting...");

    if let Err(e) = try_main().await {
        error!("Fatal startup error: {:#}", e);
        eprintln!("\n  Failed to start: {}\n", e);
        std::process::exit(1);
    }
}

async fn try_main() -> anyhow::Result<()> {
    info!("Initializing engines...");
    let store = Arc::new(rule_store::InMemoryRuleStore::new());
    let rule_engine = RuleEngine::new(store);
    let connection_tracker = ConnectionTracker::new(65536, 30);
    let rate_limiter = RateLimiter::new(100.0, 10.0);
    let scan_detector = ScanDetector::new();
    let metrics = ArgusMetrics::new();
    let event_bus = LiveEventBus::new(1024);
    let audit_log = AuditLog::new();
    info!("Engines initialized");

    info!("Setting up JWT secret...");
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
            warn!("ARGUS_JWT_SECRET not set — generating random secret for this session.");
            generate_secret()
        }
    };

    let auth_config = AuthConfig::new(jwt_secret);

    let admin_user = std::env::var("ARGUS_ADMIN_USER").unwrap_or_else(|_| "admin".into());
    let admin_pass = std::env::var("ARGUS_ADMIN_PASS").unwrap_or_else(|_| {
        let pass = hex::encode({
            let mut buf = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        });
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
    info!("Ready. Listening on http://0.0.0.0:8443");
    eprintln!();
    eprintln!("  ========================================");
    eprintln!("  ARGUS API — http://127.0.0.1:8443");
    eprintln!("  Health:     http://127.0.0.1:8443/health");
    eprintln!("  Admin user: {}", admin_user);
    eprintln!("  Password:   set via ARGUS_ADMIN_PASS env");
    eprintln!("  ========================================");
    eprintln!();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => info!("Ctrl+C received"),
            Err(e) => {
                warn!("Cannot install Ctrl+C handler (container?): {e}. Using SIGTERM only.");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                info!("SIGTERM received");
            }
            Err(e) => {
                warn!("Cannot install SIGTERM handler (container?): {e}. Use Ctrl+C.");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal received, starting graceful shutdown");
}
