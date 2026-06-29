use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::net::IpAddr;
use tracing::info;

use argus_common::types::{ConnectionEntry, ConnectionState};

#[allow(dead_code)]
pub struct PostgresConnectionStore {
    pool: PgPool,
}

#[allow(dead_code)]
impl PostgresConnectionStore {
    pub async fn new(database_url: &str) -> std::result::Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS connections (
                id UUID PRIMARY KEY,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port SMALLINT NOT NULL,
                dst_port SMALLINT NOT NULL,
                protocol SMALLINT NOT NULL,
                state TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                packets_in BIGINT NOT NULL DEFAULT 0,
                packets_out BIGINT NOT NULL DEFAULT 0,
                bytes_in BIGINT NOT NULL DEFAULT 0,
                bytes_out BIGINT NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_connections_last_seen ON connections (last_seen DESC)",
        )
        .execute(&pool)
        .await?;

        info!("PostgresConnectionStore: connections table ready");
        Ok(Self { pool })
    }

    #[allow(dead_code)]
    pub async fn insert_connection(
        &self,
        entry: &ConnectionEntry,
    ) -> std::result::Result<(), sqlx::Error> {
        let state_str = connection_state_to_str(entry.state);
        // Generate a deterministic or persistent UUID for ON CONFLICT (id) to work properly
        let mut uuid_bytes = [0u8; 16];
        let src_bytes = match entry.src_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let dst_bytes = match entry.dst_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        
        let mut hasher = sha2::Sha256::default();
        use sha2::Digest;
        hasher.update(&src_bytes);
        hasher.update(&dst_bytes);
        hasher.update(&entry.src_port.to_be_bytes());
        hasher.update(&entry.dst_port.to_be_bytes());
        hasher.update(&[entry.protocol]);
        let hash = hasher.finalize();
        uuid_bytes.copy_from_slice(&hash[..16]);
        let entry_id = uuid::Uuid::from_bytes(uuid_bytes);

        sqlx::query(
            "INSERT INTO connections (id, src_ip, dst_ip, src_port, dst_port, protocol, state, created_at, last_seen, packets_in, packets_out, bytes_in, bytes_out)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (id) DO UPDATE SET last_seen=$9, packets_in=$10, packets_out=$11, bytes_in=$12, bytes_out=$13, state=$7",
        )
        .bind(entry_id)
        .bind(entry.src_ip.to_string())
        .bind(entry.dst_ip.to_string())
        .bind(entry.src_port as i16)
        .bind(entry.dst_port as i16)
        .bind(entry.protocol as i16)
        .bind(state_str)
        .bind(entry.created_at)
        .bind(entry.last_seen)
        .bind(entry.packets_in as i64)
        .bind(entry.packets_out as i64)
        .bind(entry.bytes_in as i64)
        .bind(entry.bytes_out as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn list_active(&self) -> Vec<ConnectionEntry> {
        #[derive(sqlx::FromRow)]
        struct ConnRow {
            src_ip: String,
            dst_ip: String,
            src_port: i16,
            dst_port: i16,
            protocol: i16,
            state: String,
            created_at: DateTime<Utc>,
            last_seen: DateTime<Utc>,
            packets_in: i64,
            packets_out: i64,
            bytes_in: i64,
            bytes_out: i64,
        }

        match sqlx::query_as::<_, ConnRow>(
            "SELECT src_ip, dst_ip, src_port, dst_port, protocol, state, created_at, last_seen, packets_in, packets_out, bytes_in, bytes_out FROM connections WHERE state IN ('new', 'established', 'closing') ORDER BY last_seen DESC",
        )
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|row| {
                    let src_ip = row.src_ip.parse().ok()?;
                    let dst_ip = row.dst_ip.parse().ok()?;
                    let state = str_to_connection_state(&row.state);
                    Some(ConnectionEntry {
                        src_ip,
                        dst_ip,
                        src_port: row.src_port as u16,
                        dst_port: row.dst_port as u16,
                        protocol: row.protocol as u8,
                        state,
                        created_at: row.created_at,
                        last_seen: row.last_seen,
                        packets_in: row.packets_in as u64,
                        packets_out: row.packets_out as u64,
                        bytes_in: row.bytes_in as u64,
                        bytes_out: row.bytes_out as u64,
                        draining: false,
                    })
                })
                .collect(),
            Err(e) => {
                tracing::error!("PostgresConnectionStore: list_active failed: {}", e);
                Vec::new()
            }
        }
    }

    #[allow(dead_code)]
    pub async fn gc(&self) -> std::result::Result<(), sqlx::Error> {
        let now = Utc::now();
        sqlx::query("DELETE FROM connections WHERE state = 'closed' AND last_seen < $1")
            .bind(now - chrono::Duration::seconds(120))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn connection_state_to_str(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::New => "new",
        ConnectionState::Established => "established",
        ConnectionState::Closing => "closing",
        ConnectionState::Closed => "closed",
    }
}

fn str_to_connection_state(s: &str) -> ConnectionState {
    match s {
        "new" => ConnectionState::New,
        "established" => ConnectionState::Established,
        "closing" => ConnectionState::Closing,
        _ => ConnectionState::Closed,
    }
}
