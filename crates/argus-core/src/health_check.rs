use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub checked_at: DateTime<Utc>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub overall_status: HealthStatus,
    pub components: Vec<ComponentHealth>,
    pub timestamp: DateTime<Utc>,
}

pub struct HealthChecker;

impl HealthChecker {
    pub async fn check_database(_pool: &Option<()>) -> ComponentHealth {
        ComponentHealth {
            name: "database".into(),
            status: HealthStatus::Degraded,
            message: Some("Not configured".into()),
            checked_at: Utc::now(),
            response_time_ms: Some(0),
        }
    }

    pub async fn check_redis(_url: &Option<String>) -> ComponentHealth {
        ComponentHealth {
            name: "redis".into(),
            status: HealthStatus::Degraded,
            message: Some("Not configured".into()),
            checked_at: Utc::now(),
            response_time_ms: Some(0),
        }
    }

    pub fn check_ebpf(controller: &crate::ebpf::EbpfController) -> ComponentHealth {
        let (status, message) = if controller.is_loaded() {
            (HealthStatus::Healthy, None)
        } else {
            (HealthStatus::Degraded, Some("Not loaded".into()))
        };
        ComponentHealth {
            name: "ebpf".into(),
            status,
            message,
            checked_at: Utc::now(),
            response_time_ms: Some(0),
        }
    }

    pub async fn check_netbox<T>(_client: &Option<T>) -> ComponentHealth {
        ComponentHealth {
            name: "netbox".into(),
            status: HealthStatus::Degraded,
            message: Some("Not configured".into()),
            checked_at: Utc::now(),
            response_time_ms: Some(0),
        }
    }

    pub async fn check_all<P, N>(
        _db_pool: &Option<P>,
        redis_url: &Option<String>,
        ebpf: &crate::ebpf::EbpfController,
        _netbox: &Option<N>,
    ) -> SystemHealth {
        let mut components = Vec::new();

        components.push(Self::check_database(&None).await);
        components.push(Self::check_redis(redis_url).await);
        components.push(Self::check_ebpf(ebpf));
        components.push(Self::check_netbox(&None::<()>).await);

        let overall_status = if components
            .iter()
            .any(|c| c.status == HealthStatus::Unhealthy)
        {
            HealthStatus::Unhealthy
        } else if components
            .iter()
            .any(|c| c.status == HealthStatus::Degraded)
        {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        SystemHealth {
            overall_status,
            components,
            timestamp: Utc::now(),
        }
    }
}
