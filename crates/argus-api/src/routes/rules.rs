use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

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

pub async fn list_rules(State(state): State<Arc<AppState>>) -> Json<Vec<RuleResponse>> {
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
) -> Result<Json<RuleResponse>, Json<serde_json::Value>> {
    match state.rule_engine.store().get_rule(&id).await {
        Ok(rule) => Ok(Json(RuleResponse::from(rule))),
        Err(e) => Err(Json(serde_json::json!({"error": e.to_string()}))),
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
        ) {
            if proto.parse::<u8>().is_err() {
                return Err(format!("Invalid protocol: {}", proto));
            }
        }
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<(), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr));
    }
    let _ip: std::net::IpAddr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid IP in CIDR: {}", cidr))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix in CIDR: {}", cidr))?;
    match _ip {
        std::net::IpAddr::V4(_) if prefix > 32 => {
            return Err(format!("IPv4 prefix must be ≤ 32, got {}", prefix));
        }
        std::net::IpAddr::V6(_) if prefix > 128 => {
            return Err(format!("IPv6 prefix must be ≤ 128, got {}", prefix));
        }
        _ => {}
    }
    Ok(())
}

pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>, Json<serde_json::Value>> {
    validate_create_request(&req).map_err(|e| Json(serde_json::json!({"error": e})))?;

    let action = parse_action(&req.action).map_err(|e| Json(serde_json::json!({"error": e})))?;
    let direction =
        parse_direction(&req.direction).map_err(|e| Json(serde_json::json!({"error": e})))?;

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
        .map_err(|e| Json(serde_json::json!({"error": e.to_string()})))?;

    Ok(Json(RuleResponse::from(created)))
}

pub async fn update_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>, Json<serde_json::Value>> {
    let existing = state
        .rule_engine
        .store()
        .get_rule(&id)
        .await
        .map_err(|e| Json(serde_json::json!({"error": e.to_string()})))?;

    let action = parse_action(&req.action).map_err(|e| Json(serde_json::json!({"error": e})))?;
    let direction =
        parse_direction(&req.direction).map_err(|e| Json(serde_json::json!({"error": e})))?;

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
        .map_err(|e| Json(serde_json::json!({"error": e.to_string()})))?;

    Ok(Json(RuleResponse::from(rule)))
}

pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    state
        .rule_engine
        .store()
        .delete_rule(&id)
        .await
        .map_err(|e| Json(serde_json::json!({"error": e.to_string()})))?;

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
