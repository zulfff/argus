use std::collections::HashMap;
use std::sync::Mutex;

use argus_common::error::{ArgusError, Result};
use argus_common::types::{CidrRule, Direction};
use argus_core::rule_engine::RuleStore;
use async_trait::async_trait;

pub struct InMemoryRuleStore {
    rules: Mutex<HashMap<uuid::Uuid, CidrRule>>,
}

impl InMemoryRuleStore {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl RuleStore for InMemoryRuleStore {
    async fn list_rules(&self) -> Result<Vec<CidrRule>> {
        let rules = self
            .rules
            .lock()
            .map_err(|e| ArgusError::Internal(e.to_string()))?;
        let mut list: Vec<CidrRule> = rules.values().cloned().collect();
        list.sort_by_key(|r| r.priority);
        Ok(list)
    }

    async fn get_rule(&self, id: &uuid::Uuid) -> Result<CidrRule> {
        let rules = self
            .rules
            .lock()
            .map_err(|e| ArgusError::Internal(e.to_string()))?;
        rules
            .get(id)
            .cloned()
            .ok_or_else(|| ArgusError::NotFound(format!("rule {} not found", id)))
    }

    async fn create_rule(&self, rule: CidrRule) -> Result<CidrRule> {
        let mut rules = self
            .rules
            .lock()
            .map_err(|e| ArgusError::Internal(e.to_string()))?;
        rules.insert(rule.id, rule.clone());
        Ok(rule)
    }

    async fn update_rule(&self, rule: CidrRule) -> Result<CidrRule> {
        let mut rules = self
            .rules
            .lock()
            .map_err(|e| ArgusError::Internal(e.to_string()))?;
        if !rules.contains_key(&rule.id) {
            return Err(ArgusError::NotFound(format!("rule {} not found", rule.id)));
        }
        rules.insert(rule.id, rule.clone());
        Ok(rule)
    }

    async fn delete_rule(&self, id: &uuid::Uuid) -> Result<()> {
        let mut rules = self
            .rules
            .lock()
            .map_err(|e| ArgusError::Internal(e.to_string()))?;
        rules
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| ArgusError::NotFound(format!("rule {} not found", id)))
    }

    async fn rules_by_direction(&self, direction: Direction) -> Result<Vec<CidrRule>> {
        let rules = self
            .rules
            .lock()
            .map_err(|e| ArgusError::Internal(e.to_string()))?;
        let mut list: Vec<CidrRule> = rules
            .values()
            .filter(|r| r.direction == direction)
            .cloned()
            .collect();
        list.sort_by_key(|r| r.priority);
        Ok(list)
    }
}
