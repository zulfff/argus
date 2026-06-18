use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSnapshot {
    pub id: Uuid,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub checksum: String,
    pub data: serde_json::Value,
}

impl BackupSnapshot {
    pub fn new(data: serde_json::Value) -> Self {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let version = env!("CARGO_PKG_VERSION").to_string();

        let mut snapshot = Self {
            id,
            version,
            created_at: now,
            checksum: String::new(),
            data,
        };

        snapshot.checksum = snapshot.compute_checksum();
        snapshot
    }

    fn compute_checksum(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.version.as_bytes());
        hasher.update(self.created_at.to_rfc3339().as_bytes());
        hasher.update(
            serde_json::to_string(&self.data)
                .unwrap_or_default()
                .as_bytes(),
        );
        hex::encode(hasher.finalize())
    }

    pub fn verify_integrity(&self) -> bool {
        let expected = self.compute_checksum();
        expected == self.checksum
    }
}

pub struct BackupManager {
    snapshots: Mutex<Vec<BackupSnapshot>>,
}

impl BackupManager {
    pub fn new() -> Self {
        Self {
            snapshots: Mutex::new(Vec::new()),
        }
    }

    pub fn create_snapshot(&self, data: serde_json::Value) -> BackupSnapshot {
        let snapshot = BackupSnapshot::new(data);
        if let Ok(mut snapshots) = self.snapshots.lock() {
            snapshots.push(snapshot.clone());
        }
        snapshot
    }

    pub fn list_snapshots(&self) -> Vec<BackupSnapshot> {
        self.snapshots.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn get_snapshot(&self, id: &Uuid) -> Option<BackupSnapshot> {
        self.snapshots
            .lock()
            .ok()
            .and_then(|s| s.iter().find(|snap| &snap.id == id).cloned())
    }

    pub fn latest_snapshot(&self) -> Option<BackupSnapshot> {
        self.snapshots.lock().ok().and_then(|s| s.last().cloned())
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_snapshot() {
        let data = serde_json::json!({"test": "value"});
        let snapshot = BackupSnapshot::new(data);
        assert!(snapshot.verify_integrity());
        assert_eq!(snapshot.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_tampered_snapshot() {
        let data = serde_json::json!({"rules": []});
        let mut snapshot = BackupSnapshot::new(data);
        assert!(snapshot.verify_integrity());
        snapshot.data = serde_json::json!({"rules": [{"bad": "data"}]});
        assert!(!snapshot.verify_integrity());
    }

    #[test]
    fn test_backup_manager() {
        let manager = BackupManager::new();
        let snap1 = manager.create_snapshot(serde_json::json!({"v": 1}));
        let snap2 = manager.create_snapshot(serde_json::json!({"v": 2}));
        assert_eq!(manager.list_snapshots().len(), 2);
        let latest = manager.latest_snapshot().unwrap();
        assert_eq!(latest.id, snap2.id);
        let found = manager.get_snapshot(&snap1.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, snap1.id);
    }
}
