use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    pub rule_id: Uuid,
    pub hit_count: u64,
    pub last_hit: Option<DateTime<Utc>>,
    pub bytes_matched: u64,
}

pub struct RuleStatsTracker {
    stats: Mutex<HashMap<Uuid, RuleStats>>,
}

impl Default for RuleStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleStatsTracker {
    pub fn new() -> Self {
        Self {
            stats: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_hit(&self, rule_id: Uuid, bytes: u64) {
        if let Ok(mut stats) = self.stats.lock() {
            let entry = stats.entry(rule_id).or_insert(RuleStats {
                rule_id,
                hit_count: 0,
                last_hit: None,
                bytes_matched: 0,
            });
            entry.hit_count += 1;
            entry.last_hit = Some(Utc::now());
            entry.bytes_matched += bytes;
        }
    }

    pub fn get_stats(&self, rule_id: &Uuid) -> Option<RuleStats> {
        self.stats.lock().ok()?.get(rule_id).cloned()
    }

    pub fn list_all(&self) -> Vec<RuleStats> {
        self.stats
            .lock()
            .ok()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn dead_rules(&self, rule_ids: &[Uuid], min_age_secs: i64) -> Vec<Uuid> {
        let stats = match self.stats.lock() {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        let now = Utc::now();
        rule_ids
            .iter()
            .filter(|id| {
                if let Some(stat) = stats.get(id) {
                    stat.hit_count == 0
                        || stat
                            .last_hit
                            .map(|t| (now - t).num_seconds() > min_age_secs)
                            .unwrap_or(true)
                } else {
                    true
                }
            })
            .copied()
            .collect()
    }

    pub fn top_rules(&self, limit: usize) -> Vec<RuleStats> {
        let mut all = self.list_all();
        all.sort_by_key(|s| std::cmp::Reverse(s.hit_count));
        all.truncate(limit);
        all
    }

    pub fn reset(&self, rule_id: &Uuid) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.remove(rule_id);
        }
    }
}
