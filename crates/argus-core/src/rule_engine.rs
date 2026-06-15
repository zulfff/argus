use argus_common::error::Result;
use argus_common::types::{Action, CidrRule, Direction};
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::instrument;

#[async_trait]
pub trait RuleStore: Send + Sync {
    async fn list_rules(&self) -> Result<Vec<CidrRule>>;
    async fn get_rule(&self, id: &uuid::Uuid) -> Result<CidrRule>;
    async fn create_rule(&self, rule: CidrRule) -> Result<CidrRule>;
    async fn update_rule(&self, rule: CidrRule) -> Result<CidrRule>;
    async fn delete_rule(&self, id: &uuid::Uuid) -> Result<()>;
    async fn rules_by_direction(&self, direction: Direction) -> Result<Vec<CidrRule>>;
}

pub struct RuleEngine {
    store: Arc<dyn RuleStore>,
}

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub action: Action,
    pub rule_id: uuid::Uuid,
    pub rule_name: String,
}

impl RuleEngine {
    pub fn new(store: Arc<dyn RuleStore>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &Arc<dyn RuleStore> {
        &self.store
    }

    #[instrument(skip(self))]
    pub async fn evaluate(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Option<u8>,
        direction: Direction,
    ) -> Result<Option<MatchResult>> {
        let mut rules = self.store.rules_by_direction(direction).await?;
        rules.sort_by_key(|r| r.priority);
        let mut matched: Option<MatchResult> = None;

        for rule in rules.iter().filter(|r| r.enabled) {
            if Self::rule_matches(rule, src_ip, dst_ip, src_port, dst_port, protocol) {
                matched = Some(MatchResult {
                    action: rule.action.clone(),
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                });
                break;
            }
        }

        Ok(matched)
    }

    fn rule_matches(
        rule: &CidrRule,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Option<u8>,
    ) -> bool {
        if let Some(ref cidr) = rule.src_cidr {
            if !ip_in_cidr(src_ip, cidr) {
                return false;
            }
        }
        if let Some(ref cidr) = rule.dst_cidr {
            if !ip_in_cidr(dst_ip, cidr) {
                return false;
            }
        }
        if let Some(rp) = rule.src_port {
            if src_port != Some(rp) {
                return false;
            }
        }
        if let Some(rp) = rule.dst_port {
            if dst_port != Some(rp) {
                return false;
            }
        }
        if let Some(ref proto) = rule.protocol {
            if let Some(p) = protocol {
                if !proto_matches(p, proto) {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix_len: u32 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let net_ip: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match (ip, net_ip) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            let ip_bits = u32::from(ip);
            let net_bits = u32::from(net);
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX.wrapping_shl(32u32.saturating_sub(prefix_len))
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            let ip_bits = u128::from(ip);
            let net_bits = u128::from(net);
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX.wrapping_shl(128u32.saturating_sub(prefix_len))
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
    }
}

fn proto_matches(protocol: u8, proto_str: &str) -> bool {
    match proto_str.to_lowercase().as_str() {
        "tcp" => protocol == 6,
        "udp" => protocol == 17,
        "icmp" => protocol == 1,
        "icmpv6" => protocol == 58,
        "any" => true,
        _ => {
            if let Ok(n) = proto_str.parse::<u8>() {
                protocol == n
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::error::ArgusError;
    use argus_common::types::Action;
    use std::net::Ipv4Addr;

    struct MockStore;

    #[async_trait]
    impl RuleStore for MockStore {
        async fn list_rules(&self) -> Result<Vec<CidrRule>> {
            Ok(vec![])
        }
        async fn get_rule(&self, _id: &uuid::Uuid) -> Result<CidrRule> {
            Err(ArgusError::NotFound("rule not found".into()))
        }
        async fn create_rule(&self, rule: CidrRule) -> Result<CidrRule> {
            Ok(rule)
        }
        async fn update_rule(&self, rule: CidrRule) -> Result<CidrRule> {
            Ok(rule)
        }
        async fn delete_rule(&self, _id: &uuid::Uuid) -> Result<()> {
            Ok(())
        }
        async fn rules_by_direction(&self, _direction: Direction) -> Result<Vec<CidrRule>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_ip_in_cidr_v4() {
        assert!(ip_in_cidr(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "10.0.0.0/8"
        ));
        assert!(!ip_in_cidr(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "10.0.0.0/8"
        ));
    }

    #[test]
    fn test_proto_matches() {
        assert!(proto_matches(6, "tcp"));
        assert!(proto_matches(17, "udp"));
        assert!(proto_matches(1, "icmp"));
        assert!(proto_matches(6, "6"));
        assert!(!proto_matches(6, "udp"));
    }

    #[test]
    fn test_rule_matches_src_cidr_only() {
        let rule = CidrRule {
            id: uuid::Uuid::new_v4(),
            name: "test".into(),
            description: None,
            action: Action::Deny,
            direction: Direction::Inbound,
            src_cidr: Some("10.0.0.0/8".into()),
            dst_cidr: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            priority: 100,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(RuleEngine::rule_matches(
            &rule,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            None,
            None,
            None
        ));
        assert!(!RuleEngine::rule_matches(
            &rule,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            None,
            None,
            None
        ));
    }
}
