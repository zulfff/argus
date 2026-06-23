use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn compute_audit_hash(
    id: &Uuid,
    timestamp: DateTime<Utc>,
    actor: &str,
    action: &str,
    resource: &str,
    details: &str,
    previous_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(timestamp.to_rfc3339().as_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(resource.as_bytes());
    hasher.update(details.as_bytes());
    hasher.update(previous_hash.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_audit_hash_deterministic() {
        let id = Uuid::nil();
        let ts = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let h1 = compute_audit_hash(&id, ts, "admin", "create", "rule", "{}", "0");
        let h2 = compute_audit_hash(&id, ts, "admin", "create", "rule", "{}", "0");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_compute_audit_hash_changes_on_input() {
        let id = Uuid::nil();
        let ts = Utc::now();
        let h1 = compute_audit_hash(&id, ts, "admin", "create", "rule", "{}", "0");
        let h2 = compute_audit_hash(&id, ts, "admin", "delete", "rule", "{}", "0");
        assert_ne!(h1, h2);
    }
}
