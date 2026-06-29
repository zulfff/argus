use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::rule_engine::RuleStore;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScheduleAction {
    Enable,
    Disable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSchedule {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub cron_expression: String,
    pub action: ScheduleAction,
    pub enabled: bool,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub last_run: Option<DateTime<Utc>>,
}

pub struct SchedulerEngine {
    schedules: Arc<RwLock<HashMap<Uuid, RuleSchedule>>>,
    store: Arc<dyn RuleStore>,
}

impl Clone for SchedulerEngine {
    fn clone(&self) -> Self {
        Self {
            schedules: self.schedules.clone(),
            store: self.store.clone(),
        }
    }
}

impl SchedulerEngine {
    pub fn new(store: Arc<dyn RuleStore>) -> Self {
        Self {
            schedules: Arc::new(RwLock::new(HashMap::new())),
            store,
        }
    }

    pub async fn add_schedule(&self, schedule: RuleSchedule) -> RuleSchedule {
        let mut schedules = self.schedules.write().await;
        schedules.insert(schedule.id, schedule.clone());
        schedule
    }

    pub async fn remove_schedule(&self, id: &Uuid) -> bool {
        let mut schedules = self.schedules.write().await;
        schedules.remove(id).is_some()
    }

    pub async fn list_schedules(&self) -> Vec<RuleSchedule> {
        let schedules = self.schedules.read().await;
        let mut list: Vec<RuleSchedule> = schedules.values().cloned().collect();
        list.sort_by_key(|s| s.created_at);
        list
    }

    pub async fn get_schedule(&self, id: &Uuid) -> Option<RuleSchedule> {
        let schedules = self.schedules.read().await;
        schedules.get(id).cloned()
    }

    pub async fn tick(&self) {
        let now = Utc::now();
        let schedules = self.schedules.read().await;
        let to_process: Vec<RuleSchedule> =
            schedules.values().filter(|s| s.enabled).cloned().collect();
        drop(schedules);

        for schedule in to_process {
            if !cron_matches(&schedule.cron_expression, now) {
                continue;
            }

            let last_run = self
                .get_schedule(&schedule.id)
                .await
                .and_then(|s| s.last_run);
            if let Some(last) = last_run {
                if (now - last).num_seconds() < 60 {
                    continue;
                }
            }

            match self.apply_schedule(&schedule).await {
                Ok(_) => {
                    let mut schedules = self.schedules.write().await;
                    if let Some(s) = schedules.get_mut(&schedule.id) {
                        s.last_run = Some(now);
                    }
                    info!(
                        schedule_id = %schedule.id,
                        rule_id = %schedule.rule_id,
                        action = ?schedule.action,
                        "Schedule applied"
                    );
                }
                Err(e) => {
                    error!(
                        schedule_id = %schedule.id,
                        rule_id = %schedule.rule_id,
                        error = %e,
                        "Failed to apply schedule"
                    );
                }
            }
        }
    }

    async fn apply_schedule(&self, schedule: &RuleSchedule) -> Result<(), String> {
        let mut rule = self
            .store
            .get_rule(&schedule.rule_id)
            .await
            .map_err(|e| format!("Rule not found: {}", e))?;

        match schedule.action {
            ScheduleAction::Enable => {
                if !rule.enabled {
                    rule.enabled = true;
                    self.store
                        .update_rule(rule)
                        .await
                        .map_err(|e| format!("Failed to enable rule: {}", e))?;
                    info!(rule_id = %schedule.rule_id, "Rule enabled by schedule");
                }
            }
            ScheduleAction::Disable => {
                if rule.enabled {
                    rule.enabled = false;
                    self.store
                        .update_rule(rule)
                        .await
                        .map_err(|e| format!("Failed to disable rule: {}", e))?;
                    info!(rule_id = %schedule.rule_id, "Rule disabled by schedule");
                }
            }
        }
        Ok(())
    }
}

pub fn validate_cron(expression: &str) -> Result<(), String> {
    let parts: Vec<&str> = expression.split_whitespace().collect();
    if parts.len() != 5 {
        return Err("Cron expression must have exactly 5 fields".to_string());
    }

    let limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];
    for (i, &field) in parts.iter().enumerate() {
        let (min, max) = limits[i];
        if field == "*" {
            continue;
        }

        // Validate multiple comma-separated entries
        for p in field.split(',') {
            if p.contains('/') {
                let s: Vec<&str> = p.split('/').collect();
                if s.len() != 2 {
                    return Err(format!("Invalid step expression: {}", p));
                }
                let base = s[0];
                let step = s[1]
                    .parse::<i32>()
                    .map_err(|_| format!("Invalid step value: {}", s[1]))?;
                if step <= 0 {
                    return Err("Step value must be positive".to_string());
                }
                if base != "*" {
                    let b = base
                        .parse::<i32>()
                        .map_err(|_| format!("Invalid step base: {}", base))?;
                    if b < min || b > max {
                        return Err(format!("Base value {} out of range", b));
                    }
                }
            } else if p.contains('-') {
                let s: Vec<&str> = p.split('-').collect();
                if s.len() != 2 {
                    return Err(format!("Invalid range expression: {}", p));
                }
                let low = s[0]
                    .parse::<i32>()
                    .map_err(|_| format!("Invalid range start: {}", s[0]))?;
                let high = s[1]
                    .parse::<i32>()
                    .map_err(|_| format!("Invalid range end: {}", s[1]))?;
                if low < min || low > max || high < min || high > max || low > high {
                    return Err(format!(
                        "Range {}-{} is invalid or out of limits",
                        low, high
                    ));
                }
            } else {
                let val = p
                    .parse::<i32>()
                    .map_err(|_| format!("Invalid numeric value: {}", p))?;
                if val < min || val > max {
                    return Err(format!("Value {} out of range ({}-{})", val, min, max));
                }
            }
        }
    }
    Ok(())
}

fn cron_matches(expression: &str, now: DateTime<Utc>) -> bool {
    let parts: Vec<&str> = expression.split_whitespace().collect();
    if parts.len() != 5 {
        warn!(expression = %expression, "Invalid cron expression: expected 5 fields");
        return false;
    }

    let minute = now.minute() as i32;
    let hour = now.hour() as i32;
    let day = now.day() as i32;
    let month = now.month() as i32;
    let weekday = now.weekday().num_days_from_sunday() as i32;

    field_matches(parts[0], minute)
        && field_matches(parts[1], hour)
        && field_matches(parts[2], day)
        && field_matches(parts[3], month)
        && field_matches(parts[4], weekday)
}

fn field_matches(field: &str, value: i32) -> bool {
    if field == "*" {
        return true;
    }

    if let Ok(n) = field.parse::<i32>() {
        return n == value;
    }

    if field.contains('/') {
        let parts: Vec<&str> = field.split('/').collect();
        if parts.len() == 2 {
            let base = if parts[0] == "*" {
                0
            } else {
                parts[0].parse::<i32>().unwrap_or(0)
            };
            let step = parts[1].parse::<i32>().unwrap_or(1);
            if step == 0 {
                return false;
            }
            return value >= base && (value - base) % step == 0;
        }
    }

    if field.contains('-') {
        let parts: Vec<&str> = field.split('-').collect();
        if parts.len() == 2 {
            let low = parts[0].parse::<i32>().unwrap_or(i32::MIN);
            let high = parts[1].parse::<i32>().unwrap_or(i32::MAX);
            return value >= low && value <= high;
        }
    }

    if field.contains(',') {
        return field.split(',').any(|p| field_matches(p, value));
    }

    false
}

pub async fn start_scheduler(engine: Arc<SchedulerEngine>) {
    info!("Starting rule scheduler (check interval: 60s)");
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        engine.tick().await;
    }
}
