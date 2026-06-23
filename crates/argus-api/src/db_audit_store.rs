use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use argus_common::audit::compute_audit_hash;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditRow {
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

impl From<AuditRow> for argus_core::audit_log::AuditEntry {
    fn from(row: AuditRow) -> Self {
        argus_core::audit_log::AuditEntry {
            id: row.id,
            timestamp: row.timestamp,
            actor: row.actor,
            action: row.action,
            resource: row.resource,
            details: row.details,
            ip_address: row.ip_address,
            success: row.success,
            hash: row.hash,
            previous_hash: row.previous_hash,
        }
    }
}

#[allow(dead_code)]
pub struct PostgresAuditStore {
    pool: PgPool,
}

#[allow(dead_code)]
impl PostgresAuditStore {
    pub async fn new(database_url: &str) -> std::result::Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id UUID PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                ip_address TEXT,
                success BOOLEAN NOT NULL DEFAULT true,
                hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log (actor);
             CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);
             CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp DESC)",
        )
        .execute(&pool)
        .await?;

        info!("PostgresAuditStore: audit_log table ready");
        Ok(Self { pool })
    }

    pub async fn log(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        details: &str,
        ip_address: Option<&str>,
        success: bool,
    ) -> argus_core::audit_log::AuditEntry {
        let now = Utc::now();
        let id = Uuid::new_v4();

        let previous_hash = match sqlx::query_as::<_, (String,)>(
            "SELECT hash FROM audit_log ORDER BY timestamp DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
        {
            Some((prev_hash,)) => prev_hash,
            None => {
                let mut hasher = Sha256::new();
                hasher.update(b"genesis");
                hex::encode(hasher.finalize())
            }
        };

        let hash = Self::compute_hash(&id, now, actor, action, resource, details, &previous_hash);

        let entry = argus_core::audit_log::AuditEntry {
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

        let _ = sqlx::query(
            "INSERT INTO audit_log (id, timestamp, actor, action, resource, details, ip_address, success, hash, previous_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(entry.id)
        .bind(entry.timestamp)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.resource)
        .bind(&entry.details)
        .bind(&entry.ip_address)
        .bind(entry.success)
        .bind(&entry.hash)
        .bind(&entry.previous_hash)
        .execute(&self.pool)
        .await;

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

    pub async fn query(
        &self,
        actor: Option<&str>,
        action: Option<&str>,
        limit: usize,
    ) -> Vec<argus_core::audit_log::AuditEntry> {
        if let (Some(actor), Some(action)) = (actor, action) {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, timestamp, actor, action, resource, details, ip_address, success, hash, previous_hash FROM audit_log WHERE actor = $1 AND action = $2 ORDER BY timestamp DESC LIMIT $3",
            )
            .bind(actor)
            .bind(action)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(AuditRow::into).collect())
            .unwrap_or_default()
        } else if let Some(actor) = actor {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, timestamp, actor, action, resource, details, ip_address, success, hash, previous_hash FROM audit_log WHERE actor = $1 ORDER BY timestamp DESC LIMIT $2",
            )
            .bind(actor)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(AuditRow::into).collect())
            .unwrap_or_default()
        } else if let Some(action) = action {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, timestamp, actor, action, resource, details, ip_address, success, hash, previous_hash FROM audit_log WHERE action = $1 ORDER BY timestamp DESC LIMIT $2",
            )
            .bind(action)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(AuditRow::into).collect())
            .unwrap_or_default()
        } else {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, timestamp, actor, action, resource, details, ip_address, success, hash, previous_hash FROM audit_log ORDER BY timestamp DESC LIMIT $1",
            )
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(AuditRow::into).collect())
            .unwrap_or_default()
        }
    }

    pub async fn verify_integrity(&self) -> argus_core::audit_log::VerificationResult {
        let rows: Vec<AuditRow> = match sqlx::query_as::<_, AuditRow>(
            "SELECT id, timestamp, actor, action, resource, details, ip_address, success, hash, previous_hash FROM audit_log ORDER BY timestamp ASC",
        )
        .fetch_all(&self.pool)
        .await
        {
            Ok(r) => r,
            Err(_) => {
                return argus_core::audit_log::VerificationResult {
                    valid: false,
                    tampered_count: 0,
                    total_entries: 0,
                    first_broken_at: None,
                }
            }
        };

        if rows.is_empty() {
            return argus_core::audit_log::VerificationResult {
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

        for (i, entry) in rows.iter().enumerate() {
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

        argus_core::audit_log::VerificationResult {
            valid: tampered == 0,
            tampered_count: tampered,
            total_entries: rows.len(),
            first_broken_at: first_broken,
        }
    }

    pub async fn export_json(&self) -> String {
        let rows: Vec<AuditRow> = sqlx::query_as::<_, AuditRow>(
            "SELECT id, timestamp, actor, action, resource, details, ip_address, success, hash, previous_hash FROM audit_log ORDER BY timestamp ASC",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let entries: Vec<argus_core::audit_log::AuditEntry> =
            rows.into_iter().map(AuditRow::into).collect();
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into())
    }
}
