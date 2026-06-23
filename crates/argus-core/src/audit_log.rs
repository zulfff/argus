use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Mutex;
use uuid::Uuid;

use argus_common::audit::compute_audit_hash;

const MAX_LOG_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub details: String,
    pub ip_address: Option<String>,
    pub success: bool,
    pub hash: String,
    pub previous_hash: String,
}

pub struct AuditLog {
    entries: Mutex<VecDeque<AuditEntry>>,
    max_entries: usize,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES)),
            max_entries: MAX_LOG_ENTRIES,
        }
    }

    pub fn log(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        details: &str,
        ip_address: Option<&str>,
        success: bool,
    ) -> AuditEntry {
        let now = Utc::now();
        let id = Uuid::new_v4();

        let previous_hash = self
            .entries
            .lock()
            .ok()
            .and_then(|e| e.back().map(|prev| prev.hash.clone()))
            .unwrap_or_else(|| {
                let mut hasher = Sha256::new();
                hasher.update(b"genesis");
                hex::encode(hasher.finalize())
            });

        let hash = Self::compute_hash(&id, now, actor, action, resource, details, &previous_hash);

        let entry = AuditEntry {
            id,
            timestamp: now,
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            details: details.to_string(),
            ip_address: ip_address.map(String::from),
            success,
            hash: hash.clone(),
            previous_hash,
        };

        if let Ok(mut entries) = self.entries.lock() {
            entries.push_back(entry.clone());
            while entries.len() > self.max_entries {
                entries.pop_front();
            }
        }

        entry
    }

    fn compute_hash(
        id: &Uuid,
        timestamp: DateTime<Utc>,
        actor: &str,
        action: &str,
        resource: &str,
        details: &str,
        previous_hash: &str,
    ) -> String {
        compute_audit_hash(
            id,
            timestamp,
            actor,
            action,
            resource,
            details,
            previous_hash,
        )
    }

    pub fn verify_integrity(&self) -> VerificationResult {
        let entries = match self.entries.lock() {
            Ok(e) => e,
            Err(_) => {
                return VerificationResult {
                    valid: false,
                    tampered_count: 0,
                    total_entries: 0,
                    first_broken_at: None,
                }
            }
        };

        if entries.is_empty() {
            return VerificationResult {
                valid: true,
                tampered_count: 0,
                total_entries: 0,
                first_broken_at: None,
            };
        }

        let mut expected_previous = String::new();
        let mut first = true;
        let mut tampered = 0;
        let mut first_broken = None;

        for (i, entry) in entries.iter().enumerate() {
            if first {
                let mut gen_hasher = Sha256::new();
                gen_hasher.update(b"genesis");
                expected_previous = hex::encode(gen_hasher.finalize());
                first = false;
            }

            let computed = Self::compute_hash(
                &entry.id,
                entry.timestamp,
                &entry.actor,
                &entry.action,
                &entry.resource,
                &entry.details,
                &expected_previous,
            );

            if computed != entry.hash {
                tampered += 1;
                if first_broken.is_none() {
                    first_broken = Some(i);
                }
            }

            expected_previous = entry.hash.clone();
        }

        VerificationResult {
            valid: tampered == 0,
            tampered_count: tampered,
            total_entries: entries.len(),
            first_broken_at: first_broken,
        }
    }

    pub fn query(
        &self,
        actor: Option<&str>,
        action: Option<&str>,
        limit: usize,
    ) -> Vec<AuditEntry> {
        self.entries
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .rev()
                    .filter(|e| {
                        actor.is_none_or(|a| e.actor == a) && action.is_none_or(|a| e.action == a)
                    })
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn export_json(&self) -> String {
        let entries = self
            .entries
            .lock()
            .map(|e| e.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into())
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub tampered_count: usize,
    pub total_entries: usize,
    pub first_broken_at: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_chain() {
        let log = AuditLog::new();

        let e1 = log.log(
            "admin",
            "rule.create",
            "firewall",
            "Created rule block-ssh",
            None,
            true,
        );
        let e2 = log.log(
            "admin",
            "rule.apply",
            "firewall",
            "Applied ruleset v2",
            None,
            true,
        );

        assert_eq!(e2.previous_hash, e1.hash);
        assert_ne!(e1.hash, e2.hash);
    }

    #[test]
    fn test_integrity_verification() {
        let log = AuditLog::new();
        log.log("admin", "login", "auth", "Login attempt", None, true);
        log.log("admin", "rule.create", "firewall", "New rule", None, true);

        let result = log.verify_integrity();
        assert!(result.valid);
        assert_eq!(result.tampered_count, 0);
        assert_eq!(result.total_entries, 2);
    }

    #[test]
    fn test_tamper_detection() {
        let log = AuditLog::new();
        log.log("admin", "login", "auth", "Login attempt", None, true);

        if let Ok(mut entries) = log.entries.lock() {
            if let Some(entry) = entries.back_mut() {
                entry.action = "hacker.action".to_string();
            }
        }

        let result = log.verify_integrity();
        assert!(!result.valid);
        assert_eq!(result.tampered_count, 1);
    }

    #[test]
    fn test_query_by_actor() {
        let log = AuditLog::new();
        log.log("admin", "rule.create", "fw", "rule A", None, true);
        log.log("operator", "rule.read", "fw", "view rules", None, true);
        log.log("admin", "rule.delete", "fw", "rule B", None, true);

        let admin_logs = log.query(Some("admin"), None, 10);
        assert_eq!(admin_logs.len(), 2);
    }

    #[test]
    fn test_export_json() {
        let log = AuditLog::new();
        log.log("admin", "login", "auth", "test", None, true);
        let json = log.export_json();
        assert!(json.contains("admin"));
        assert!(json.contains("login"));
    }
}
