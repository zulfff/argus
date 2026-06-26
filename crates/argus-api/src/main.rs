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
use tokio::signal;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tracing::{error, info, warn};

use argus_core::alerting::AlertManager;
use argus_core::anomaly::AnomalyDetector;
use argus_core::audit_log::AuditLog;
use argus_core::backup::BackupManager;
use argus_core::cluster::ClusterManager;
use argus_core::compliance::ComplianceEngine;
use argus_core::connection_tracker::ConnectionTracker;
use argus_core::dpi::DpiEngine;
use argus_core::ebpf::EbpfController;
use argus_core::qos::QosManager;
use argus_core::rate_limiter::RateLimiter;
use argus_core::reputation::ReputationManager;
use argus_core::rule_engine::RuleEngine;
use argus_core::scanner::ScanDetector;
use argus_core::scheduler::SchedulerEngine;
use argus_core::syslog::SyslogForwarder;
use argus_core::tenancy::TenantManager;
use argus_core::vpn_portal::VpnPortalManager;
use argus_core::ztna::ZtnaMesh;
use argus_observability::metrics::ArgusMetrics;
use argus_orchestrator::drift::DriftDetector;
use argus_orchestrator::netbox::NetboxClient;

use crate::auth::{AuthConfig, Role};
use crate::db_audit_store::PostgresAuditStore;
use crate::db_connection_store::PostgresConnectionStore;
use crate::websocket::LiveEventBus;

pub struct AppState {
    pub rule_engine: RuleEngine,
    pub connection_tracker: Arc<ConnectionTracker>,
    pub rate_limiter: Arc<RateLimiter>,
    pub scan_detector: Arc<ScanDetector>,
    pub metrics: ArgusMetrics,
    pub event_bus: LiveEventBus,
    pub auth_config: AuthConfig,
    pub audit_log: Arc<AuditLog>,
    pub alert_manager: Arc<AlertManager>,
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
    pub db_audit_store: Option<Arc<PostgresAuditStore>>,
    pub db_connection_store: Option<Arc<PostgresConnectionStore>>,
    pub backup_manager: BackupManager,
    pub ebpf_controller: EbpfController,
    pub netbox_client: Option<Arc<NetboxClient>>,
    pub drift_detector: Option<Arc<DriftDetector>>,
    pub ztna_mesh: Arc<ZtnaMesh>,
    pub anomaly_detector: Arc<AnomalyDetector>,
    pub wasm_plugin_engine: Arc<argus_core::wasm_plugin::WasmPluginEngine>,
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
        .route(
            "/api/v1/orchestrator/drift",
            axum::routing::get(routes::orchestrator::get_drift_status),
        )
        .route(
            "/api/v1/orchestrator/reconcile",
            axum::routing::post(routes::orchestrator::trigger_reconciliation),
        )
        .route(
            "/api/v1/orchestrator/devices",
            axum::routing::get(routes::orchestrator::get_netbox_devices),
        )
        .route(
            "/api/v1/anomaly/baseline",
            axum::routing::get(routes::anomaly::get_baseline),
        )
        .route(
            "/api/v1/anomaly/alerts",
            axum::routing::get(routes::anomaly::get_anomaly_alerts),
        )
        .route(
            "/api/v1/ztna/peers",
            axum::routing::get(routes::ztna::list_ztna_peers),
        )
        .route(
            "/api/v1/ztna/config/{iface}",
            axum::routing::get(routes::ztna::download_wg_config),
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

    let store: Arc<dyn argus_core::rule_engine::RuleStore> =
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            info!("DATABASE_URL set, using PostgresRuleStore");
            Arc::new(db_rule_store::PostgresRuleStore::new(&db_url).await?)
        } else {
            info!("No DATABASE_URL set, using InMemoryRuleStore");
            Arc::new(rule_store::InMemoryRuleStore::new())
        };

    let rule_engine = RuleEngine::new(store);
    let mut connection_tracker = Arc::new(ConnectionTracker::new(65536, 30));
    let rate_limiter = Arc::new(RateLimiter::new(100.0, 10.0));
    let scan_detector = Arc::new(ScanDetector::new());
    let metrics = ArgusMetrics::new();
    let event_bus = LiveEventBus::new(1024);
    let audit_log = Arc::new(AuditLog::new());
    let alert_manager = Arc::new(AlertManager::new());
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
    let ztna_mesh = Arc::new(ZtnaMesh::new("default"));
    let anomaly_detector = Arc::new(AnomalyDetector::new());
    let wasm_plugin_engine = Arc::new(argus_core::wasm_plugin::WasmPluginEngine::new());

    if let Some(ct) = Arc::get_mut(&mut connection_tracker) {
        let wasm_engine = wasm_plugin_engine.clone();
        ct.set_on_new_connection(move |key| {
            let metadata = argus_core::wasm_plugin::FlowMetadata {
                src_ip: key.src_ip.to_string(),
                dst_ip: key.dst_ip.to_string(),
                src_port: key.src_port,
                dst_port: key.dst_port,
                protocol: key.protocol,
                direction: "unknown".into(),
                interface: "unknown".into(),
                rule_action: None,
                rule_id: None,
                timestamp: chrono::Utc::now(),
                tags: std::collections::HashMap::new(),
            };
            wasm_engine.run_hook(
                argus_core::wasm_plugin::HookPoint::OnConnectionNew,
                &metadata,
            );
        });
    }

    let mut ebpf_controller = EbpfController::new();
    let ebf_obj_path =
        std::env::var("ARGUS_EBPF_OBJECT").unwrap_or_else(|_| "/var/lib/argus/argus-ebpf.o".into());
    if let Ok(wan_iface) = std::env::var("ARGUS_WAN_IFACE") {
        if let Err(e) = ebpf_controller.init(&ebf_obj_path, &wan_iface) {
            warn!("eBPF init failed: {} — eBPF data plane disabled", e);
        }
    } else {
        info!("ARGUS_WAN_IFACE not set — eBPF data plane not loaded (set ARGUS_WAN_IFACE and ARGUS_EBPF_OBJECT to enable)");
    }

    let (netbox_client, drift_detector) =
        match (std::env::var("NETBOX_URL"), std::env::var("NETBOX_TOKEN")) {
            (Ok(url), Ok(token)) if !url.is_empty() && !token.is_empty() => {
                info!("NETBOX_URL and NETBOX_TOKEN set, initializing orchestrator");
                let nb = Arc::new(NetboxClient::new(url, token));
                let dd = Arc::new(DriftDetector::new(nb.clone(), 300));
                if let Ok(vyos_addr) = std::env::var("VYOS_ADDRESS") {
                    let addr_clone = vyos_addr.clone();
                    dd.register_device(
                        "vyos-primary".into(),
                        vyos_addr,
                        std::env::var("VYOS_PORT").ok().and_then(|p| p.parse().ok()),
                    )
                    .await;
                    info!("VyOS device registered: {}", addr_clone);
                }
                (Some(nb), Some(dd))
            }
            _ => {
                info!("NETBOX_URL/NETBOX_TOKEN not both set — orchestrator disabled");
                (None, None)
            }
        };

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

    // Wire Postgres-backed stores when available
    let db_audit_store: Option<Arc<PostgresAuditStore>> = if db_pool.is_some() {
        match std::env::var("DATABASE_URL") {
            Ok(ref db_url) => match PostgresAuditStore::new(db_url).await {
                Ok(store) => {
                    info!("PostgresAuditStore wired");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    warn!("PostgresAuditStore init failed: {}. Skipping.", e);
                    None
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };

    let db_connection_store: Option<Arc<PostgresConnectionStore>> = if db_pool.is_some() {
        match std::env::var("DATABASE_URL") {
            Ok(ref db_url) => match PostgresConnectionStore::new(db_url).await {
                Ok(store) => {
                    info!("PostgresConnectionStore wired");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    warn!("PostgresConnectionStore init failed: {}. Skipping.", e);
                    None
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };

    let state = Arc::new(AppState {
        rule_engine,
        connection_tracker,
        rate_limiter,
        scan_detector,
        metrics,
        event_bus,
        auth_config,
        audit_log: audit_log.clone(),
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
        db_audit_store: db_audit_store.clone(),
        db_connection_store: db_connection_store.clone(),
        backup_manager,
        ebpf_controller,
        netbox_client,
        drift_detector,
        ztna_mesh,
        anomaly_detector: anomaly_detector.clone(),
        wasm_plugin_engine,
    });

    let scheduler_engine = state.scheduler_engine.clone();
    tokio::spawn(async move {
        argus_core::scheduler::start_scheduler(scheduler_engine.into()).await;
    });
    info!("Scheduler background task started");

    // Background GC tasks for engine memory cleanup
    let conn_tracker = state.connection_tracker.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            conn_tracker.gc();
        }
    });
    let rate_limiter = state.rate_limiter.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            rate_limiter.gc();
        }
    });
    let scan_detector = state.scan_detector.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            scan_detector.gc();
        }
    });
    info!("GC background tasks started");

    let anomaly_detector_bg = anomaly_detector.clone();
    let conn_tracker_bg = state.connection_tracker.clone();
    let alert_manager_bg = state.alert_manager.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let conn_count = conn_tracker_bg.active_count();
            let sample = argus_core::anomaly::TrafficSample {
                timestamp: chrono::Utc::now(),
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
                connection_count: conn_count as u64,
                unique_ports: 0,
            };
            anomaly_detector_bg.record_sample("all-interfaces", sample);
            anomaly_detector_bg.compute_baseline("all-interfaces");
            let current = argus_core::anomaly::TrafficSample {
                timestamp: chrono::Utc::now(),
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
                connection_count: conn_count as u64,
                unique_ports: 0,
            };
            let alerts = anomaly_detector_bg.check_anomalies("all-interfaces", &current);
            if !alerts.is_empty() {
                let mut snapshot = argus_core::alerting::SystemSnapshot {
                    blocked_ips: 0,
                    active_connections: conn_count,
                    packets_per_second: 0,
                    anomaly_score: alerts.first().map(|a| a.deviation_multiple).unwrap_or(0.0),
                    cpu_usage_percent: 0.0,
                    memory_usage_percent: 0.0,
                    audit_tampered: false,
                    wan_failed_over: false,
                    rule_match_counts: std::collections::HashMap::new(),
                };
                snapshot.anomaly_score = alerts
                    .iter()
                    .map(|a| a.deviation_multiple)
                    .fold(0.0, f64::max);
                alert_manager_bg.evaluate(&snapshot).await;
            }
            anomaly_detector_bg.gc();
        }
    });
    info!("Anomaly detection background task started");

    // Background Postgres audit log sync
    if let Some(ref pg_audit) = db_audit_store {
        let audit_log_pg = state.audit_log.clone();
        let pg_audit = pg_audit.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let entries = audit_log_pg.query(None, None, 50);
                for entry in entries {
                    let _ = pg_audit
                        .log(
                            &entry.actor,
                            &entry.action,
                            &entry.resource,
                            &entry.details,
                            entry.ip_address.as_deref(),
                            entry.success,
                        )
                        .await;
                }
            }
        });
        info!("Postgres audit log sync started");
    }

    // Background Postgres connection store sync
    if let Some(ref pg_conn) = db_connection_store {
        let conn_tracker_pg = state.connection_tracker.clone();
        let pg_conn = pg_conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let entries = conn_tracker_pg.list_all();
                for entry in entries {
                    let _ = pg_conn.insert_connection(&entry).await;
                }
                let _ = pg_conn.gc().await;
            }
        });
        info!("Postgres connection store sync started");
    }

    let app = app(state.clone());

    let tls_cert = std::env::var("ARGUS_TLS_CERT").ok();
    let tls_key = std::env::var("ARGUS_TLS_KEY").ok();

    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "TLS config error: {}. cert={}, key={}",
                            e,
                            cert_path,
                            key_path
                        )
                    })?;

            let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
            info!("Ready. Listening on https://0.0.0.0:8443 (TLS)");
            eprintln!();
            eprintln!("  ========================================");
            eprintln!("  ARGUS API — https://127.0.0.1:8443");
            eprintln!("  Health:     https://127.0.0.1:8443/health");
            eprintln!("  Admin user: {}", admin_user);
            eprintln!("  TLS cert:   {}", cert_path);
            eprintln!("  ========================================");
            eprintln!();

            let handle = axum_server::Handle::new();
            let server_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                info!("Shutdown signal received — draining TLS connections...");
                server_handle.shutdown();
            });

            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(app.clone().into_make_service())
                .await
                .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;
        }
        _ => {
            warn!("ARGUS_TLS_CERT and ARGUS_TLS_KEY not both set — using plain HTTP (insecure)");
            let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
            info!("Ready. Listening on http://0.0.0.0:8443 (plain HTTP)");
            eprintln!();
            eprintln!("  ========================================");
            eprintln!("  ARGUS API — http://127.0.0.1:8443");
            eprintln!("  Health:     http://127.0.0.1:8443/health");
            eprintln!("  Admin user: {}", admin_user);
            eprintln!("  Password:   set via ARGUS_ADMIN_PASS env");
            eprintln!("  ========================================");
            eprintln!("  WARNING: No TLS configured — all traffic in cleartext");
            eprintln!("  Set ARGUS_TLS_CERT and ARGUS_TLS_KEY env vars for TLS");
            eprintln!("  ========================================");
            eprintln!();
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }

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
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    info!("Shutdown complete");
}
