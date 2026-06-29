use async_trait::async_trait;
use sqlx::PgPool;
use tracing::info;

use argus_common::error::Result;
use argus_common::types::{Action, CidrRule, Direction};

use argus_core::rule_engine::RuleStore;

#[allow(dead_code)]
pub struct PostgresRuleStore {
    pool: PgPool,
}

#[allow(dead_code)]
impl PostgresRuleStore {
    pub async fn new(database_url: &str) -> std::result::Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS rules (
                id UUID PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                action TEXT NOT NULL,
                direction TEXT NOT NULL,
                src_cidr TEXT,
                dst_cidr TEXT,
                src_port SMALLINT,
                dst_port SMALLINT,
                protocol TEXT,
                priority INT NOT NULL DEFAULT 100,
                enabled BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS threat_entries (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                ip_address INET,
                cidr CIDR,
                source TEXT NOT NULL,
                reason TEXT,
                added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL,
                last_seen TIMESTAMPTZ,
                metadata JSONB,
                CONSTRAINT chk_ip_or_cidr_present CHECK (ip_address IS NOT NULL OR cidr IS NOT NULL)
            );
            CREATE INDEX IF NOT EXISTS idx_threats_expires ON threat_entries(expires_at);"
        )
        .execute(&pool)
        .await?;

        info!("PostgresRuleStore: rules and threat_entries tables ready");
        Ok(Self { pool })
    }
}

#[allow(dead_code)]
fn action_to_str(action: &Action) -> String {
    match action {
        Action::Allow => "allow".to_string(),
        Action::Deny => "deny".to_string(),
        Action::RateLimit { packets_per_second } => format!("rate-limit:{}pps", packets_per_second),
    }
}

fn str_to_action(s: &str) -> Result<Action> {
    match s {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        s if s.starts_with("rate-limit:") => {
            let pps = s
                .trim_start_matches("rate-limit:")
                .trim_end_matches("pps")
                .parse::<u64>()
                .map_err(|_| {
                    argus_common::error::ArgusError::Validation("invalid rate-limit format".into())
                })?;
            Ok(Action::RateLimit {
                packets_per_second: pps,
            })
        }
        _ => Err(argus_common::error::ArgusError::Validation(format!(
            "unknown action: {}",
            s
        ))),
    }
}

#[allow(dead_code)]
fn direction_to_str(dir: &Direction) -> &'static str {
    match dir {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
        Direction::Forward => "forward",
    }
}

fn str_to_direction(s: &str) -> Result<Direction> {
    match s {
        "inbound" => Ok(Direction::Inbound),
        "outbound" => Ok(Direction::Outbound),
        "forward" => Ok(Direction::Forward),
        _ => Err(argus_common::error::ArgusError::Validation(format!(
            "unknown direction: {}",
            s
        ))),
    }
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: uuid::Uuid,
    name: String,
    description: Option<String>,
    action: String,
    direction: String,
    src_cidr: Option<String>,
    dst_cidr: Option<String>,
    src_port: Option<i16>,
    dst_port: Option<i16>,
    protocol: Option<String>,
    priority: i32,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<RuleRow> for CidrRule {
    type Error = argus_common::error::ArgusError;

    fn try_from(row: RuleRow) -> std::result::Result<Self, Self::Error> {
        Ok(CidrRule {
            id: row.id,
            name: row.name,
            description: row.description,
            action: str_to_action(&row.action)?,
            direction: str_to_direction(&row.direction)?,
            src_cidr: row.src_cidr,
            dst_cidr: row.dst_cidr,
            src_port: row.src_port.map(|p| p as u16),
            dst_port: row.dst_port.map(|p| p as u16),
            protocol: row.protocol,
            priority: row.priority as u32,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            rate_limit_pps: None,
            hit_count: 0,
            last_hit: None,
        })
    }
}

#[async_trait]
impl RuleStore for PostgresRuleStore {
    async fn list_rules(&self) -> Result<Vec<CidrRule>> {
        let rows = sqlx::query_as::<_, RuleRow>(
            "SELECT id, name, description, action, direction, src_cidr, dst_cidr, src_port, dst_port, protocol, priority, enabled, created_at, updated_at FROM rules ORDER BY priority ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(argus_common::error::ArgusError::Database)?;

        rows.into_iter().map(CidrRule::try_from).collect()
    }

    async fn get_rule(&self, id: &uuid::Uuid) -> Result<CidrRule> {
        let row = sqlx::query_as::<_, RuleRow>(
            "SELECT id, name, description, action, direction, src_cidr, dst_cidr, src_port, dst_port, protocol, priority, enabled, created_at, updated_at FROM rules WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(argus_common::error::ArgusError::Database)?
        .ok_or_else(|| argus_common::error::ArgusError::NotFound(format!("rule {} not found", id)))?;

        CidrRule::try_from(row)
    }

    async fn create_rule(&self, rule: CidrRule) -> Result<CidrRule> {
        sqlx::query(
            "INSERT INTO rules (id, name, description, action, direction, src_cidr, dst_cidr, src_port, dst_port, protocol, priority, enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(rule.id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(action_to_str(&rule.action))
        .bind(direction_to_str(&rule.direction))
        .bind(&rule.src_cidr)
        .bind(&rule.dst_cidr)
        .bind(rule.src_port.map(|p| p as i16))
        .bind(rule.dst_port.map(|p| p as i16))
        .bind(&rule.protocol)
        .bind(rule.priority as i32)
        .bind(rule.enabled)
        .bind(rule.created_at)
        .bind(rule.updated_at)
        .execute(&self.pool)
        .await
        .map_err(argus_common::error::ArgusError::Database)?;

        Ok(rule)
    }

    async fn update_rule(&self, rule: CidrRule) -> Result<CidrRule> {
        let rows = sqlx::query(
            "UPDATE rules SET name=$1, description=$2, action=$3, direction=$4, src_cidr=$5, dst_cidr=$6, src_port=$7, dst_port=$8, protocol=$9, priority=$10, enabled=$11, updated_at=$12 WHERE id=$13",
        )
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(action_to_str(&rule.action))
        .bind(direction_to_str(&rule.direction))
        .bind(&rule.src_cidr)
        .bind(&rule.dst_cidr)
        .bind(rule.src_port.map(|p| p as i16))
        .bind(rule.dst_port.map(|p| p as i16))
        .bind(&rule.protocol)
        .bind(rule.priority as i32)
        .bind(rule.enabled)
        .bind(rule.updated_at)
        .bind(rule.id)
        .execute(&self.pool)
        .await
        .map_err(argus_common::error::ArgusError::Database)?;

        if rows.rows_affected() == 0 {
            return Err(argus_common::error::ArgusError::NotFound(format!(
                "rule {} not found",
                rule.id
            )));
        }

        Ok(rule)
    }

    async fn delete_rule(&self, id: &uuid::Uuid) -> Result<()> {
        let rows = sqlx::query("DELETE FROM rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(argus_common::error::ArgusError::Database)?;

        if rows.rows_affected() == 0 {
            return Err(argus_common::error::ArgusError::NotFound(format!(
                "rule {} not found",
                id
            )));
        }

        Ok(())
    }

    async fn rules_by_direction(&self, direction: Direction) -> Result<Vec<CidrRule>> {
        let dir_str = direction_to_str(&direction);
        let rows = sqlx::query_as::<_, RuleRow>(
            "SELECT id, name, description, action, direction, src_cidr, dst_cidr, src_port, dst_port, protocol, priority, enabled, created_at, updated_at FROM rules WHERE direction = $1 AND enabled = true ORDER BY priority ASC",
        )
        .bind(dir_str)
        .fetch_all(&self.pool)
        .await
        .map_err(argus_common::error::ArgusError::Database)?;

        rows.into_iter().map(CidrRule::try_from).collect()
    }

    async fn clear_rules(&self) -> Result<()> {
        sqlx::query("DELETE FROM rules")
            .execute(&self.pool)
            .await
            .map_err(argus_common::error::ArgusError::Database)?;
        Ok(())
    }
}
