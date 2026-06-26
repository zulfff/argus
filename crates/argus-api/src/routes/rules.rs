use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::auth::Claims;
use crate::AppState;
use argus_common::types::{Action, CidrRule, Direction};

#[derive(Serialize)]
pub struct RuleResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub action: String,
    pub direction: String,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub priority: u32,
    pub enabled: bool,
}

impl From<CidrRule> for RuleResponse {
    fn from(r: CidrRule) -> Self {
        let action_str = match r.action {
            Action::Allow => "allow".into(),
            Action::Deny => "deny".into(),
            Action::RateLimit { packets_per_second } => {
                format!("rate-limit:{}pps", packets_per_second)
            }
        };
        let direction_str = match r.direction {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
            Direction::Forward => "forward",
        };
        RuleResponse {
            id: r.id,
            name: r.name,
            description: r.description,
            action: action_str,
            direction: direction_str.into(),
            src_cidr: r.src_cidr,
            dst_cidr: r.dst_cidr,
            src_port: r.src_port,
            dst_port: r.dst_port,
            protocol: r.protocol,
            priority: r.priority,
            enabled: r.enabled,
        }
    }
}

pub async fn list_rules(
    State(state): State<Arc<AppState>>,
    Extension(_claims): Extension<Claims>,
) -> Json<Vec<RuleResponse>> {
    let rules = state
        .rule_engine
        .store()
        .list_rules()
        .await
        .unwrap_or_default();
    Json(rules.into_iter().map(RuleResponse::from).collect())
}

pub async fn get_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Extension(_claims): Extension<Claims>,
) -> Result<Json<RuleResponse>, (StatusCode, Json<serde_json::Value>)> {
    match state.rule_engine.store().get_rule(&id).await {
        Ok(rule) => Ok(Json(RuleResponse::from(rule))),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e.to_string()})))),
    }
}

#[derive(Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub action: String,
    pub direction: String,
    #[serde(default)]
    pub src_cidr: Option<String>,
    #[serde(default)]
    pub dst_cidr: Option<String>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_priority() -> u32 {
    100
}
fn default_enabled() -> bool {
    true
}

fn validate_create_request(req: &CreateRuleRequest) -> Result<(), String> {
    if req.name.is_empty() || req.name.len() > 256 {
        return Err("Rule name must be 1–256 characters".into());
    }
    if let Some(ref desc) = req.description {
        if desc.len() > 1024 {
            return Err("Description must be ≤ 1024 characters".into());
        }
    }
    if let Some(ref cidr) = req.src_cidr {
        validate_cidr(cidr)?;
    }
    if let Some(ref cidr) = req.dst_cidr {
        validate_cidr(cidr)?;
    }
    if let Some(ref proto) = req.protocol {
        if !matches!(
            proto.to_lowercase().as_str(),
            "tcp" | "udp" | "icmp" | "icmpv6" | "any"
        ) && proto.parse::<u8>().is_err()
        {
            return Err(format!("Invalid protocol: {}", proto));
        }
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<(), String> {
    argus_common::net::validate_cidr(cidr)
}

pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((StatusCode::FORBIDDEN, Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        )));
    }

    validate_create_request(&req).map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))))?;

    let action = parse_action(&req.action).map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))))?;
    let direction =
        parse_direction(&req.direction).map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))))?;

    let now = chrono::Utc::now();
    let rule = CidrRule {
        id: Uuid::new_v4(),
        name: req.name,
        description: req.description,
        action,
        direction,
        src_cidr: req.src_cidr,
        dst_cidr: req.dst_cidr,
        src_port: req.src_port,
        dst_port: req.dst_port,
        protocol: req.protocol,
        priority: req.priority,
        enabled: req.enabled,
        created_at: now,
        updated_at: now,
    };

    let created = state
        .rule_engine
        .store()
        .create_rule(rule)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    if let Err(e) = state.ebpf_controller.sync_rule_create(&created) {
        error!(
            "eBPF sync failed for rule {} ({}): {}",
            created.id, created.name, e
        );
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Rule created in store but eBPF sync failed: {}", e),
            "rule_id": created.id.to_string(),
            "code": 500
        }))));
    }

    Ok(Json(RuleResponse::from(created)))
}

pub async fn update_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((StatusCode::FORBIDDEN, Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        )));
    }

    validate_create_request(&req).map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))))?;

    let existing = state
        .rule_engine
        .store()
        .get_rule(&id)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e.to_string()}))))?;

    let action = parse_action(&req.action).map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))))?;
    let direction =
        parse_direction(&req.direction).map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))))?;

    let updated = CidrRule {
        id: existing.id,
        name: req.name,
        description: req.description,
        action,
        direction,
        src_cidr: req.src_cidr,
        dst_cidr: req.dst_cidr,
        src_port: req.src_port,
        dst_port: req.dst_port,
        protocol: req.protocol,
        priority: req.priority,
        enabled: req.enabled,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    let rule = state
        .rule_engine
        .store()
        .update_rule(updated)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    if let Err(e) = state.ebpf_controller.sync_rule_update(&existing, &rule) {
        error!(
            "eBPF sync failed for rule update {} ({}): {}",
            rule.id, rule.name, e
        );
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Rule updated in store but eBPF sync failed: {}", e),
            "rule_id": rule.id.to_string(),
            "code": 500
        }))));
    }

    Ok(Json(RuleResponse::from(rule)))
}

pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    if !claims.role.can_delete() {
        return Err(Json(
            serde_json::json!({"error": "Insufficient permissions", "code": 403}),
        ));
    }

    let rule_to_delete = state.rule_engine.store().get_rule(&id).await.ok();

    state
        .rule_engine
        .store()
        .delete_rule(&id)
        .await
        .map_err(|e| Json(serde_json::json!({"error": e.to_string()})))?;

    if let Some(ref rule) = rule_to_delete {
        if let Err(e) = state.ebpf_controller.sync_rule_delete(rule) {
            error!("eBPF sync failed for rule deletion {}: {}", id, e);
        }
    }

    Ok(Json(serde_json::json!({"deleted": id.to_string()})))
}

fn parse_action(s: &str) -> Result<Action, String> {
    match s.to_lowercase().as_str() {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        s if s.starts_with("rate-limit:") => {
            let pps = s
                .trim_start_matches("rate-limit:")
                .trim_end_matches("pps")
                .parse::<u64>()
                .map_err(|_| "invalid rate-limit value".to_string())?;
            Ok(Action::RateLimit {
                packets_per_second: pps,
            })
        }
        _ => Err(format!("unknown action: {}", s)),
    }
}

fn parse_direction(s: &str) -> Result<Direction, String> {
    match s.to_lowercase().as_str() {
        "inbound" => Ok(Direction::Inbound),
        "outbound" => Ok(Direction::Outbound),
        "forward" => Ok(Direction::Forward),
        _ => Err(format!("unknown direction: {}", s)),
    }
}
