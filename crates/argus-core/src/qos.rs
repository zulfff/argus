use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QosTarget {
    SourceIp(IpAddr),
    DestIp(IpAddr),
    Subnet(String),
    Vlan(u16),
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosPolicy {
    pub id: Uuid,
    pub name: String,
    pub target: QosTarget,
    pub bandwidth_limit_bps: u64,
    pub priority: u8,
    pub dscp_mark: Option<u8>,
    pub enabled: bool,
}

pub struct QosManager {
    policies: Mutex<Vec<QosPolicy>>,
}

impl QosManager {
    pub fn new() -> Self {
        Self {
            policies: Mutex::new(Vec::new()),
        }
    }

    pub fn add_policy(&self, mut policy: QosPolicy) -> Uuid {
        policy.id = Uuid::new_v4();
        if let Ok(mut policies) = self.policies.lock() {
            policies.push(policy.clone());
        }
        policy.id
    }

    pub fn remove_policy(&self, id: &Uuid) -> bool {
        if let Ok(mut policies) = self.policies.lock() {
            let len = policies.len();
            policies.retain(|p| &p.id != id);
            policies.len() < len
        } else {
            false
        }
    }

    pub fn list_policies(&self) -> Vec<QosPolicy> {
        self.policies.lock().map(|p| p.clone()).unwrap_or_default()
    }

    pub fn get_effective_policy(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        vlan: Option<u16>,
    ) -> Option<QosPolicy> {
        let policies = self.policies.lock().ok()?;
        policies
            .iter()
            .filter(|p| p.enabled)
            .find(|p| match &p.target {
                QosTarget::SourceIp(ip) => *ip == src_ip,
                QosTarget::DestIp(ip) => *ip == dst_ip,
                QosTarget::Subnet(cidr) => {
                    if let Ok(prefix) = cidr.parse::<ipnetwork::IpNetwork>() {
                        prefix.contains(src_ip) || prefix.contains(dst_ip)
                    } else {
                        false
                    }
                }
                QosTarget::Vlan(v) => vlan == Some(*v),
                QosTarget::All => true,
            })
            .cloned()
    }
}

impl Default for QosManager {
    fn default() -> Self {
        Self::new()
    }
}
