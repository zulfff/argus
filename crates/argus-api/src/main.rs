mod auth;
mod db_audit_store;
mod db_connection_store;
mod db_rule_store;
mod middleware;
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

use argus_core::alerting::AlertManager;
use argus_core::audit_log::AuditLog;
use argus_core::backup::BackupManager;
use argus_core::cluster::ClusterManager;
use argus_core::compliance::ComplianceEngine;
use argus_core::connection_tracker::ConnectionTracker;
use argus_core::dpi::DpiEngine;
use argus_core::qos::QosManager;
use argus_core::rate_limiter::RateLimiter;
use argus_core::reputation::ReputationManager;
use argus_core::rule_engine::RuleEngine;
use argus_core::scanner::ScanDetector;
use argus_core::scheduler::SchedulerEngine;
use argus_core::syslog::SyslogForwarder;
use argus_core::tenancy::TenantManager;
use argus_core::vpn_portal::VpnPortalManager;
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
    pub alert_manager: AlertManager,
    pub tenant_manager: TenantManager,
    pub cluster_manager: ClusterManager,
    pub reputation_manager: ReputationManager,
    pub scheduler_engine: SchedulerEngine,
    pub vpn_portal: VpnPortalManager,
    pub dpi: DpiEngine,
    pub qos: QosManager,
    pub compliance: ComplianceEngine,
    pub syslog: SyslogForwarder,
    pub db_pool: Option<sqlx::PgPool>,
    pub backup_manager: BackupManager,
}

pub fn app(state: Arc<AppState>) -> Router {
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(100)
            .burst_size(200)
            .finish()
            .expect("governor config builder failed"),
    );

    let protected_routes = Router::new()
        .route(
            "/api/v1/auth/users",
            axum::routing::get(routes::auth_routes::list_users),
        )
        .route(
            "/api/v1/auth/users",
            axum::routing::post(routes::auth_routes::create_user),
        )
        .route(
            "/api/v1/auth/users/{username}",
            axum::routing::delete(routes::auth_routes::delete_user),
        )
        .route(
            "/api/v1/auth/users/{username}/password",
            axum::routing::put(routes::auth_routes::change_password),
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
        .route(
            "/api/v1/audit",
            axum::routing::get(routes::audit::list_audit),
        )
        .route(
            "/api/v1/audit/verify",
            axum::routing::get(routes::audit::verify_audit),
        )
        .route(
            "/api/v1/audit/export",
            axum::routing::get(routes::audit::export_audit),
        )
        .route(
            "/api/v1/alerts/rules",
            axum::routing::get(routes::alerting::list_alert_rules),
        )
        .route(
            "/api/v1/alerts/rules",
            axum::routing::post(routes::alerting::create_alert_rule),
        )
        .route(
            "/api/v1/alerts/rules/{id}",
            axum::routing::delete(routes::alerting::delete_alert_rule),
        )
        .route(
            "/api/v1/alerts/history",
            axum::routing::get(routes::alerting::list_alert_history),
        )
        .route(
            "/api/v1/alerts/history/{id}/ack",
            axum::routing::post(routes::alerting::acknowledge_alert),
        )
        .route(
            "/api/v1/tenants",
            axum::routing::get(routes::tenants::list_tenants),
        )
        .route(
            "/api/v1/tenants",
            axum::routing::post(routes::tenants::create_tenant),
        )
        .route(
            "/api/v1/tenants/{id}",
            axum::routing::delete(routes::tenants::delete_tenant),
        )
        .route(
            "/api/v1/cluster/nodes",
            axum::routing::get(routes::cluster::list_nodes),
        )
        .route(
            "/api/v1/cluster/nodes",
            axum::routing::post(routes::cluster::register_node),
        )
        .route(
            "/api/v1/cluster/nodes/{id}",
            axum::routing::delete(routes::cluster::remove_node),
        )
        .route(
            "/api/v1/cluster/status",
            axum::routing::get(routes::cluster::cluster_status),
        )
        .route(
            "/api/v1/reputation",
            axum::routing::get(routes::reputation::list_reputations),
        )
        .route(
            "/api/v1/reputation/{ip}",
            axum::routing::get(routes::reputation::get_reputation),
        )
        .route(
            "/api/v1/schedules",
            axum::routing::get(routes::scheduler::list_schedules),
        )
        .route(
            "/api/v1/schedules",
            axum::routing::post(routes::scheduler::create_schedule),
        )
        .route(
            "/api/v1/schedules/{id}",
            axum::routing::delete(routes::scheduler::delete_schedule),
        )
        .route(
            "/api/v1/rules/export/json",
            axum::routing::get(routes::import_export::export_json),
        )
        .route(
            "/api/v1/rules/export/yaml",
            axum::routing::get(routes::import_export::export_yaml),
        )
        .route(
            "/api/v1/rules/export/csv",
            axum::routing::get(routes::import_export::export_csv),
        )
        .route(
            "/api/v1/rules/import",
            axum::routing::post(routes::import_export::import_rules),
        )
        .route(
            "/api/v1/rules/simulate",
            axum::routing::post(routes::simulator::simulate_rule),
        )
        .route(
            "/api/v1/vpn/request",
            axum::routing::post(routes::vpn_portal::submit_request),
        )
        .route(
            "/api/v1/vpn/requests",
            axum::routing::get(routes::vpn_portal::list_requests),
        )
        .route(
            "/api/v1/vpn/requests/{id}/approve",
            axum::routing::post(routes::vpn_portal::approve_request),
        )
        .route(
            "/api/v1/vpn/requests/{id}/deny",
            axum::routing::post(routes::vpn_portal::deny_request),
        )
        .route(
            "/api/v1/vpn/requests/{id}/revoke",
            axum::routing::post(routes::vpn_portal::revoke_request),
        )
        .route(
            "/api/v1/vpn/requests/{id}/config",
            axum::routing::get(routes::vpn_portal::download_config),
        )
        .route(
            "/api/v1/dpi/identify",
            axum::routing::post(routes::dpi::identify),
        )
        .route(
            "/api/v1/qos/policies",
            axum::routing::get(routes::qos::list_policies),
        )
        .route(
            "/api/v1/qos/policies",
            axum::routing::post(routes::qos::create_policy),
        )
        .route(
            "/api/v1/qos/policies/{id}",
            axum::routing::delete(routes::qos::delete_policy),
        )
        .route(
            "/api/v1/compliance/reports",
            axum::routing::post(routes::compliance::generate_report),
        )
        .route(
            "/api/v1/compliance/reports",
            axum::routing::get(routes::compliance::list_reports),
        )
        .route(
            "/api/v1/compliance/reports/{id}",
            axum::routing::get(routes::compliance::get_report),
        )
        .route(
            "/api/v1/syslog/configs",
            axum::routing::get(routes::syslog::list_configs),
        )
        .route(
            "/api/v1/syslog/configs",
            axum::routing::post(routes::syslog::add_config),
        )
        .route(
            "/api/v1/syslog/configs/{id}",
            axum::routing::delete(routes::syslog::remove_config),
        )
        .route(
            "/api/v1/backup",
            axum::routing::post(routes::backup::create_backup),
        )
        .route(
            "/api/v1/backup",
            axum::routing::get(routes::backup::list_backups),
        )
        .route(
            "/api/v1/backup/restore",
            axum::routing::post(routes::backup::restore_backup),
        )
        .route(
            "/api/v1/backup/download",
            axum::routing::get(routes::backup::download_backup),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

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
        .route("/api/v1/ws", axum::routing::get(websocket::ws_handler))
        .route("/api/v1/openapi.yaml", axum::routing::get(serve_api_spec))
        .route("/docs", axum::routing::get(serve_docs))
        .merge(protected_routes)
        .layer(GovernorLayer {
            config: governor_config,
        })
        .with_state(state)
}

async fn serve_api_spec() -> impl axum::response::IntoResponse {
    let yaml = include_str!("../../../docs/api-spec.yaml");
    (
        [(axum::http::header::CONTENT_TYPE, "application/x-yaml")],
        yaml,
    )
}

async fn serve_docs() -> impl axum::response::IntoResponse {
    let html = r##"<!DOCTYPE html>
<html>
<head>
  <title>ARGUS API Docs</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>body{margin:0;background:#0a0c0f;}</style>
</head>
<body>
  <script id="api-reference" data-url="/api/v1/openapi.yaml"></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>"##;
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
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
    let alert_manager = AlertManager::new();
    let tenant_manager = TenantManager::new();
    let cluster_manager = ClusterManager::new(uuid::Uuid::new_v4());
    let reputation_manager = ReputationManager::new();
    let scheduler_engine = SchedulerEngine::new(rule_engine.store().clone());
    let vpn_portal = VpnPortalManager::new();
    let dpi = DpiEngine::new();
    let qos = QosManager::new();
    let compliance = ComplianceEngine::new();
    let syslog = SyslogForwarder::new();
    let backup_manager = BackupManager::new();
    info!("Engines initialized");

    let db_pool = if let Ok(db_url) = std::env::var("DATABASE_URL") {
        info!("DATABASE_URL set, connecting to PostgreSQL...");
        match sqlx::PgPool::connect(&db_url).await {
            Ok(pool) => {
                info!("PostgreSQL connected");
                Some(pool)
            }
            Err(e) => {
                warn!(
                    "PostgreSQL connection failed: {}. Using in-memory stores.",
                    e
                );
                None
            }
        }
    } else {
        info!("No DATABASE_URL set, using in-memory stores");
        None
    };

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
        hex::encode({
            let mut buf = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        })
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
        alert_manager,
        tenant_manager,
        cluster_manager,
        reputation_manager,
        scheduler_engine,
        vpn_portal,
        dpi,
        qos,
        compliance,
        syslog,
        db_pool,
        backup_manager,
    });

    let scheduler_engine = state.scheduler_engine.clone();
    tokio::spawn(async move {
        argus_core::scheduler::start_scheduler(scheduler_engine.into()).await;
    });
    info!("Scheduler background task started");

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
