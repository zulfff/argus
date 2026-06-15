use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    RateLimit { packets_per_second: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Forward,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub action: Action,
    pub direction: Direction,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub priority: u32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EbpfStatsKind {
    PacketsAllowed,
    PacketsDropped,
    PacketsRateLimited,
    ActiveConnections,
    ConnectionsPerSecond,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfStats {
    pub kind: EbpfStatsKind,
    pub value: u64,
    pub interface: String,
    pub cpu: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub state: ConnectionState,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Established,
    Closing,
    Closed,
}

impl ConnectionEntry {
    pub fn ttl_seconds(&self, now: DateTime<Utc>) -> i64 {
        let elapsed = (now - self.last_seen).num_seconds();
        let ttl = match self.state {
            ConnectionState::New => 30,
            ConnectionState::Established => 3600,
            ConnectionState::Closing => 60,
            ConnectionState::Closed => 10,
        };
        (ttl - elapsed).max(0)
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.ttl_seconds(now) <= 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitBucket {
    pub ip: IpAddr,
    pub tokens: u64,
    pub last_refill: DateTime<Utc>,
    pub max_tokens: u64,
    pub refill_rate: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAlert {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ports_scanned: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub severity: ScanSeverity,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanSeverity {
    Low,
    Medium,
    High,
    Critical,
}
