use argus_common::error::Result;
use argus_common::net::{ip_in_cidr, proto_matches};
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
    async fn clear_rules(&self) -> Result<()>;
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
        async fn clear_rules(&self) -> Result<()> {
            Ok(())
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
            rate_limit_pps: None,
            hit_count: 0,
            last_hit: None,
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
