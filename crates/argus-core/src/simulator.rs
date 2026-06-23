use std::net::IpAddr;
use std::sync::Arc;

use tracing::instrument;
use uuid::Uuid;

use crate::rule_engine::RuleStore;
use argus_common::net::{ip_in_cidr, proto_matches};
use argus_common::types::{Action, CidrRule, Direction};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SimulationRequest {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub direction: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SimulationResponse {
    pub matched: bool,
    pub rule_id: Option<Uuid>,
    pub rule_name: Option<String>,
    pub action: Option<String>,
    pub match_path: Vec<String>,
}

pub struct Simulator {
    store: Arc<dyn RuleStore>,
}

impl Simulator {
    pub fn new(store: Arc<dyn RuleStore>) -> Self {
        Self { store }
    }

    #[instrument(skip(self))]
    pub async fn simulate(&self, req: &SimulationRequest) -> Result<SimulationResponse, String> {
        let src_ip: IpAddr = req
            .src_ip
            .parse()
            .map_err(|_| format!("Invalid src_ip: {}", req.src_ip))?;
        let dst_ip: IpAddr = req
            .dst_ip
            .parse()
            .map_err(|_| format!("Invalid dst_ip: {}", req.dst_ip))?;

        let direction = match req.direction.to_lowercase().as_str() {
            "inbound" => Direction::Inbound,
            "outbound" => Direction::Outbound,
            "forward" => Direction::Forward,
            _ => return Err(format!("Invalid direction: {}", req.direction)),
        };

        let protocol_num = match req.protocol.as_deref() {
            Some(p) => Some(proto_to_number(p)?),
            None => None,
        };

        let mut rules = self
            .store
            .rules_by_direction(direction)
            .await
            .map_err(|e| format!("Failed to fetch rules: {}", e))?;
        rules.sort_by_key(|r| r.priority);

        let mut match_path: Vec<String> = Vec::new();

        for rule in rules.iter().filter(|r| r.enabled) {
            match_path.push(format!(
                "Evaluating rule '{}' (priority {})",
                rule.name, rule.priority
            ));

            if rule_matches(
                rule,
                src_ip,
                dst_ip,
                req.src_port,
                req.dst_port,
                protocol_num,
            ) {
                let action_str = match &rule.action {
                    Action::Allow => "allow".to_string(),
                    Action::Deny => "deny".to_string(),
                    Action::RateLimit { packets_per_second } => {
                        format!("rate-limit:{}pps", packets_per_second)
                    }
                };

                return Ok(SimulationResponse {
                    matched: true,
                    rule_id: Some(rule.id),
                    rule_name: Some(rule.name.clone()),
                    action: Some(action_str),
                    match_path,
                });
            } else {
                match_path.push("  -> No match".to_string());
            }
        }

        match_path.push("No matching rule found (implicit default action)".to_string());

        Ok(SimulationResponse {
            matched: false,
            rule_id: None,
            rule_name: None,
            action: None,
            match_path,
        })
    }
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

fn proto_to_number(proto: &str) -> Result<u8, String> {
    match proto.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" => Ok(58),
        "any" => Ok(255),
        _ => proto
            .parse::<u8>()
            .map_err(|_| format!("Unknown protocol: {}", proto)),
    }
}
