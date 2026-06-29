use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::AppState;

#[derive(Serialize)]
pub struct RuleStatsResponse {
    pub rule_id: Uuid,
    pub rule_name: Option<String>,
    pub hit_count: u64,
    pub last_hit: Option<chrono::DateTime<chrono::Utc>>,
    pub bytes_matched: u64,
}

#[derive(Serialize)]
pub struct DeadRulesResponse {
    pub dead_rules: Vec<Uuid>,
    pub total_rules: usize,
    pub min_age_days: u32,
}

pub async fn get_rule_stats(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<RuleStatsResponse>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let stats = state.rule_stats_tracker.list_all();
    let rules = state
        .rule_engine
        .store()
        .list_rules()
        .await
        .unwrap_or_default();

    let response: Vec<RuleStatsResponse> = stats
        .into_iter()
        .map(|s| {
            let rule_name = rules
                .iter()
                .find(|r| r.id == s.rule_id)
                .map(|r| r.name.clone());
            RuleStatsResponse {
                rule_id: s.rule_id,
                rule_name,
                hit_count: s.hit_count,
                last_hit: s.last_hit,
                bytes_matched: s.bytes_matched,
            }
        })
        .collect();

    Ok(Json(response))
}

pub async fn get_top_rules(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<RuleStatsResponse>>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient permissions", "code": 403})),
        ));
    }
    let stats = state.rule_stats_tracker.top_rules(10);
    let rules = state
        .rule_engine
        .store()
        .list_rules()
        .await
        .unwrap_or_default();

    let response: Vec<RuleStatsResponse> = stats
        .into_iter()
        .map(|s| {
            let rule_name = rules
                .iter()
                .find(|r| r.id == s.rule_id)
                .map(|r| r.name.clone());
            RuleStatsResponse {
                rule_id: s.rule_id,
                rule_name,
                hit_count: s.hit_count,
                last_hit: s.last_hit,
                bytes_matched: s.bytes_matched,
            }
        })
        .collect();

    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct DeadRulesQuery {
    #[serde(default = "default_min_age_days")]
    pub min_age_days: u32,
}

fn default_min_age_days() -> u32 {
    30
}

pub async fn get_dead_rules(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    axum::extract::Query(query): axum::extract::Query<DeadRulesQuery>,
) -> Result<Json<DeadRulesResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !claims.role.can_read() {
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
    let rule_ids: Vec<Uuid> = rules.iter().map(|r| r.id).collect();
    let min_age_secs = (query.min_age_days as i64) * 86400;
    let dead = state.rule_stats_tracker.dead_rules(&rule_ids, min_age_secs);

    Ok(Json(DeadRulesResponse {
        dead_rules: dead,
        total_rules: rule_ids.len(),
        min_age_days: query.min_age_days,
    }))
}
