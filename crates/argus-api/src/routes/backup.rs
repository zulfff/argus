use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::AppState;
use argus_common::types::CidrRule;
use argus_core::backup::BackupSnapshot;

#[derive(serde::Deserialize)]
pub struct DownloadParams {
    pub id: Option<Uuid>,
}

#[derive(serde::Serialize)]
pub struct SnapshotResponse {
    pub id: Uuid,
    pub version: String,
    pub created_at: String,
    pub checksum: String,
    pub data: serde_json::Value,
}

impl From<BackupSnapshot> for SnapshotResponse {
    fn from(s: BackupSnapshot) -> Self {
        SnapshotResponse {
            id: s.id,
            version: s.version,
            created_at: s.created_at.to_rfc3339(),
            checksum: s.checksum,
            data: s.data,
        }
    }
}

pub async fn create_backup(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<SnapshotResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let rules = state
        .rule_engine
        .store()
        .list_rules()
        .await
        .unwrap_or_default();
    let alert_rules = state.alert_manager.list_rules();
    let schedules = state.scheduler_engine.list_schedules().await;
    let qos_policies = state.qos.list_policies();
    let tenants = state.tenant_manager.list_tenants();
    let syslog_configs = state.syslog.list_configs();
    let users = state.auth_config.user_store.list_users().await;
    let users_json: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            serde_json::json!({
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "enabled": u.enabled,
            })
        })
        .collect();
    let vpn_peers = state.vpn_portal.list(None);

    let data = serde_json::json!({
        "rules": rules,
        "alert_rules": alert_rules,
        "schedules": schedules,
        "qos_policies": qos_policies,
        "tenants": tenants,
        "syslog_configs": syslog_configs,
        "users": users_json,
        "vpn_peers": vpn_peers,
    });

    let snapshot = state.backup_manager.create_snapshot(data);

    state.audit_log.log(
        &claims.username,
        "backup.create",
        "backup",
        &format!("Created backup snapshot {}", snapshot.id),
        None,
        true,
    );

    Ok(Json(SnapshotResponse::from(snapshot)))
}

pub async fn list_backups(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<SnapshotResponse>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let snapshots = state.backup_manager.list_snapshots();
    Ok(Json(
        snapshots.into_iter().map(SnapshotResponse::from).collect(),
    ))
}

#[derive(serde::Deserialize)]
pub struct RestoreRequest {
    pub id: Option<Uuid>,
    pub data: Option<serde_json::Value>,
}

pub async fn restore_backup(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let snapshot = if let Some(id) = req.id {
        state.backup_manager.get_snapshot(&id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Backup snapshot not found", "code": 404})),
            )
        })?
    } else if let Some(data) = req.data {
        let parsed: BackupSnapshot = serde_json::from_value(data).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid backup data: {}", e), "code": 400})),
            )
        })?;
        if !parsed.verify_integrity() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": "Backup checksum verification failed — data may be tampered", "code": 400}),
                ),
            ));
        }
        parsed
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Provide either 'id' or 'data'", "code": 400})),
        ));
    };

    let restore_result = restore_from_snapshot(&state, &snapshot).await;

    match restore_result {
        Ok(summary) => {
            state.audit_log.log(
                &claims.username,
                "backup.restore",
                "backup",
                &format!("Restored from snapshot {}: {}", snapshot.id, summary),
                None,
                true,
            );

            Ok(Json(serde_json::json!({
                "status": "restored",
                "snapshot_id": snapshot.id.to_string(),
                "summary": summary,
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Restore failed: {}", e), "code": 500})),
        )),
    }
}

pub async fn download_backup(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<DownloadParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }

    let snapshot = if let Some(id) = params.id {
        state.backup_manager.get_snapshot(&id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Backup snapshot not found", "code": 404})),
            )
        })?
    } else {
        state.backup_manager.latest_snapshot().ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "No backups available", "code": 404})),
            )
        })?
    };

    let json = serde_json::to_string_pretty(&snapshot).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Serialization error: {}", e), "code": 500})),
        )
    })?;

    let filename = format!("argus-backup-{}.json", snapshot.id);
    let disposition = format!("attachment; filename=\"{}\"", filename);

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE.to_string(),
                "application/json".to_string(),
            ),
            (header::CONTENT_DISPOSITION.to_string(), disposition),
        ],
        json,
    ))
}

async fn restore_from_snapshot(
    state: &AppState,
    snapshot: &BackupSnapshot,
) -> Result<String, String> {
    let data = &snapshot.data;
    let mut counts: Vec<String> = Vec::new();

    state
        .rule_engine
        .store()
        .clear_rules()
        .await
        .map_err(|e| e.to_string())?;

    if let Some(rules) = data.get("rules").and_then(|v| v.as_array()) {
        for rule_val in rules {
            let rule: CidrRule = serde_json::from_value(rule_val.clone())
                .map_err(|e| format!("Invalid rule: {}", e))?;
            state
                .rule_engine
                .store()
                .create_rule(rule)
                .await
                .map_err(|e| e.to_string())?;
        }
        counts.push(format!("{} rules", rules.len()));
    }

    let alert_rules_list = state.alert_manager.list_rules();
    for rule in alert_rules_list {
        state.alert_manager.remove_rule(&rule.id);
    }
    if let Some(alert_rules) = data.get("alert_rules").and_then(|v| v.as_array()) {
        for rule_val in alert_rules {
            let alert_rule: argus_core::alerting::AlertRule =
                serde_json::from_value(rule_val.clone())
                    .map_err(|e| format!("Invalid alert rule: {}", e))?;
            state.alert_manager.add_rule(alert_rule);
        }
        counts.push(format!("{} alert rules", alert_rules.len()));
    }

    let existing_schedules = state.scheduler_engine.list_schedules().await;
    for s in existing_schedules {
        state.scheduler_engine.remove_schedule(&s.id).await;
    }
    if let Some(schedules) = data.get("schedules").and_then(|v| v.as_array()) {
        for sched_val in schedules {
            let schedule: argus_core::scheduler::RuleSchedule =
                serde_json::from_value(sched_val.clone())
                    .map_err(|e| format!("Invalid schedule: {}", e))?;
            state.scheduler_engine.add_schedule(schedule).await;
        }
        counts.push(format!("{} schedules", schedules.len()));
    }

    let existing_qos = state.qos.list_policies();
    for p in existing_qos {
        state.qos.remove_policy(&p.id);
    }
    if let Some(policies) = data.get("qos_policies").and_then(|v| v.as_array()) {
        for pol_val in policies {
            let mut policy: argus_core::qos::QosPolicy = serde_json::from_value(pol_val.clone())
                .map_err(|e| format!("Invalid QoS policy: {}", e))?;
            policy.id = Uuid::new_v4();
            state.qos.add_policy(policy);
        }
        counts.push(format!("{} QoS policies", policies.len()));
    }

    state.tenant_manager.clear_tenants();
    if let Some(tenants) = data.get("tenants").and_then(|v| v.as_array()) {
        for ten_val in tenants {
            let tenant: argus_core::tenancy::Tenant = serde_json::from_value(ten_val.clone())
                .map_err(|e| format!("Invalid tenant: {}", e))?;
            let _ = state
                .tenant_manager
                .create_tenant(&tenant.name, &tenant.description);
        }
        counts.push(format!("{} tenants", tenants.len()));
    }

    let existing_syslog = state.syslog.list_configs();
    for c in existing_syslog {
        state.syslog.remove_config(&c.id);
    }
    if let Some(configs) = data.get("syslog_configs").and_then(|v| v.as_array()) {
        for cfg_val in configs {
            let mut config: argus_core::syslog::SyslogConfig =
                serde_json::from_value(cfg_val.clone())
                    .map_err(|e| format!("Invalid syslog config: {}", e))?;
            config.id = Uuid::nil();
            state.syslog.add_config(config);
        }
        counts.push(format!("{} syslog configs", configs.len()));
    }

    if let Some(users) = data.get("users").and_then(|v| v.as_array()) {
        let mut parsed_users = Vec::new();
        for user_val in users {
            let username = user_val
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or("Missing username in backup")?;
            let role_str = user_val
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("viewer");
            let role = match role_str {
                "admin" => crate::auth::Role::Admin,
                "operator" => crate::auth::Role::Operator,
                _ => crate::auth::Role::Viewer,
            };
            let password_hash = user_val
                .get("password_hash")
                .and_then(|v| v.as_str());
            if let Some(hash) = password_hash {
                if !hash.is_empty() {
                    parsed_users.push((username.to_string(), hash.to_string(), role));
                } else {
                    return Err(format!(
                        "User '{}' in backup has empty password_hash — cannot restore. Regenerate backup or manually set passwords.",
                        username
                    ));
                }
            } else {
                return Err(format!(
                    "User '{}' in backup is missing password_hash — this backup was created after password hashes were excluded for security. Cannot restore users from this backup. Use the last backup that includes password hashes, or manually recreate users.",
                    username
                ));
            }
        }
        state.auth_config.user_store.clear_users().await;
        for (username, password_hash, role) in &parsed_users {
            state
                .auth_config
                .user_store
                .restore_user(username, password_hash, role.clone())
                .await
                .map_err(|e| format!("Failed to restore user '{}': {}", username, e))?;
        }
        counts.push(format!("{} users", parsed_users.len()));
    }

    state.vpn_portal.clear_peers();
    if let Some(peers) = data.get("vpn_peers").and_then(|v| v.as_array()) {
        for peer_val in peers {
            let user_id = peer_val
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let public_key = peer_val
                .get("public_key")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let allowed_ips = peer_val
                .get("allowed_ips")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            state
                .vpn_portal
                .submit_request(user_id, public_key, allowed_ips);
        }
        counts.push(format!("{} VPN peers", peers.len()));
    }

    Ok(counts.join(", "))
}
