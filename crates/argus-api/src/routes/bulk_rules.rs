use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::AppState;
use argus_common::types::{Action, CidrRule, Direction};

#[derive(Deserialize)]
pub struct BulkCreateRequest {
    pub rules: Vec<BulkRuleItem>,
}

#[derive(Deserialize)]
pub struct BulkRuleItem {
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
    #[serde(default)]
    pub rate_limit_pps: Option<u64>,
}

fn default_priority() -> u32 {
    100
}

fn default_enabled() -> bool {
    true
}

#[derive(Serialize)]
pub struct BulkCreateResponse {
    pub created: usize,
    pub failed: usize,
    pub errors: Vec<BulkError>,
}

#[derive(Serialize)]
pub struct BulkError {
    pub index: usize,
    pub name: String,
    pub error: String,
}

#[derive(Deserialize)]
pub struct BulkDeleteRequest {
    pub rule_ids: Vec<Uuid>,
}

#[derive(Serialize)]
pub struct BulkDeleteResponse {
    pub deleted: usize,
    pub failed: usize,
    pub errors: Vec<BulkError>,
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
                .map_err(|_| "Invalid rate-limit format")?;
            Ok(Action::RateLimit {
                packets_per_second: pps,
            })
        }
        _ => Err(format!("Unknown action: {}", s)),
    }
}

fn parse_direction(s: &str) -> Result<Direction, String> {
    match s.to_lowercase().as_str() {
        "inbound" => Ok(Direction::Inbound),
        "outbound" => Ok(Direction::Outbound),
        "forward" => Ok(Direction::Forward),
        _ => Err(format!("Unknown direction: {}", s)),
    }
}

fn validate_rule_item(item: &BulkRuleItem) -> Result<(), String> {
    if item.name.is_empty() || item.name.len() > 256 {
        return Err("Rule name must be 1–256 characters".into());
    }
    if let Some(ref desc) = item.description {
        if desc.len() > 1024 {
            return Err("Description must be ≤ 1024 characters".into());
        }
    }
    if let Some(ref cidr) = item.src_cidr {
        argus_common::net::validate_cidr(cidr)?;
    }
    if let Some(ref cidr) = item.dst_cidr {
        argus_common::net::validate_cidr(cidr)?;
    }
    if let Some(ref proto) = item.protocol {
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

pub async fn bulk_create_rules(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<BulkCreateRequest>,
) -> Result<Json<BulkCreateResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions"})),
        ));
    }

    if req.rules.len() > 1000 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Bulk create limited to 1000 rules per request"})),
        ));
    }

    let mut created = 0;
    let mut errors = Vec::new();

    for (idx, item) in req.rules.iter().enumerate() {
        if let Err(e) = validate_rule_item(item) {
            errors.push(BulkError {
                index: idx,
                name: item.name.clone(),
                error: e,
            });
            continue;
        }

        let action = match parse_action(&item.action) {
            Ok(a) => a,
            Err(e) => {
                errors.push(BulkError {
                    index: idx,
                    name: item.name.clone(),
                    error: e,
                });
                continue;
            }
        };

        let direction = match parse_direction(&item.direction) {
            Ok(d) => d,
            Err(e) => {
                errors.push(BulkError {
                    index: idx,
                    name: item.name.clone(),
                    error: e,
                });
                continue;
            }
        };

        let now = chrono::Utc::now();
        let rule = CidrRule {
            id: Uuid::new_v4(),
            name: item.name.clone(),
            description: item.description.clone(),
            action,
            direction,
            src_cidr: item.src_cidr.clone(),
            dst_cidr: item.dst_cidr.clone(),
            src_port: item.src_port,
            dst_port: item.dst_port,
            protocol: item.protocol.clone(),
            priority: item.priority,
            enabled: item.enabled,
            created_at: now,
            updated_at: now,
            rate_limit_pps: item.rate_limit_pps,
            hit_count: 0,
            last_hit: None,
        };

        match state.rule_engine.store().create_rule(rule.clone()).await {
            Ok(_) => {
                if let Err(e) = state.ebpf_controller.sync_rule_create(&rule) {
                    tracing::warn!("eBPF sync failed for rule {}: {}", rule.id, e);
                }
                created += 1;
            }
            Err(e) => {
                errors.push(BulkError {
                    index: idx,
                    name: item.name.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    Ok(Json(BulkCreateResponse {
        created,
        failed: errors.len(),
        errors,
    }))
}

pub async fn bulk_delete_rules(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<BulkDeleteRequest>,
) -> Result<Json<BulkDeleteResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_delete() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions"})),
        ));
    }

    if req.rule_ids.len() > 1000 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Bulk delete limited to 1000 rules per request"})),
        ));
    }

    let mut deleted = 0;
    let mut errors = Vec::new();

    for (idx, rule_id) in req.rule_ids.iter().enumerate() {
        let rule = match state.rule_engine.store().get_rule(rule_id).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(BulkError {
                    index: idx,
                    name: rule_id.to_string(),
                    error: e.to_string(),
                });
                continue;
            }
        };

        match state.rule_engine.store().delete_rule(rule_id).await {
            Ok(_) => {
                if let Err(e) = state.ebpf_controller.sync_rule_delete(&rule) {
                    tracing::warn!("eBPF sync failed for rule delete {}: {}", rule_id, e);
                }
                deleted += 1;
            }
            Err(e) => {
                errors.push(BulkError {
                    index: idx,
                    name: rule_id.to_string(),
                    error: e.to_string(),
                });
            }
        }
    }

    Ok(Json(BulkDeleteResponse {
        deleted,
        failed: errors.len(),
        errors,
    }))
}
