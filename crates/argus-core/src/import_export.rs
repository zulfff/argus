use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use argus_common::types::CidrRule;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExport {
    pub version: String,
    pub exported_at: DateTime<Utc>,
    pub rules: Vec<CidrRule>,
}

impl RuleExport {
    pub fn new(rules: Vec<CidrRule>) -> Self {
        Self {
            version: "1.0".to_string(),
            exported_at: Utc::now(),
            rules,
        }
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("JSON serialization error: {}", e))
    }

    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| format!("YAML serialization error: {}", e))
    }

    pub fn to_csv(&self) -> Result<String, String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            "id",
            "name",
            "description",
            "action",
            "direction",
            "src_cidr",
            "dst_cidr",
            "src_port",
            "dst_port",
            "protocol",
            "priority",
            "enabled",
            "created_at",
            "updated_at",
        ])
        .map_err(|e| format!("CSV header error: {}", e))?;

        for rule in &self.rules {
            let action_str = match &rule.action {
                argus_common::types::Action::Allow => "allow".to_string(),
                argus_common::types::Action::Deny => "deny".to_string(),
                argus_common::types::Action::RateLimit { packets_per_second } => {
                    format!("rate-limit:{}pps", packets_per_second)
                }
            };
            let direction_str = match rule.direction {
                argus_common::types::Direction::Inbound => "inbound",
                argus_common::types::Direction::Outbound => "outbound",
                argus_common::types::Direction::Forward => "forward",
            };
            wtr.write_record(&[
                rule.id.to_string(),
                rule.name.clone(),
                rule.description.clone().unwrap_or_default(),
                action_str,
                direction_str.to_string(),
                rule.src_cidr.clone().unwrap_or_default(),
                rule.dst_cidr.clone().unwrap_or_default(),
                rule.src_port.map(|p| p.to_string()).unwrap_or_default(),
                rule.dst_port.map(|p| p.to_string()).unwrap_or_default(),
                rule.protocol.clone().unwrap_or_default(),
                rule.priority.to_string(),
                rule.enabled.to_string(),
                rule.created_at.to_rfc3339(),
                rule.updated_at.to_rfc3339(),
            ])
            .map_err(|e| format!("CSV record error: {}", e))?;
        }

        wtr.flush().map_err(|e| format!("CSV flush error: {}", e))?;
        let data = wtr
            .into_inner()
            .map_err(|e| format!("CSV inner error: {}", e))?;
        String::from_utf8(data).map_err(|e| format!("CSV UTF-8 error: {}", e))
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str::<RuleExport>(json)
            .map_err(|e| format!("JSON deserialization error: {}", e))
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.name.is_empty() || rule.name.len() > 256 {
                errors.push(format!("Rule[{}]: name must be 1-256 characters", i));
            }
            if let Some(ref desc) = rule.description {
                if desc.len() > 1024 {
                    errors.push(format!(
                        "Rule[{}]: description must be <= 1024 characters",
                        i
                    ));
                }
            }
            if let Some(ref cidr) = rule.src_cidr {
                if let Err(e) = validate_cidr(cidr) {
                    errors.push(format!("Rule[{}] src_cidr: {}", i, e));
                }
            }
            if let Some(ref cidr) = rule.dst_cidr {
                if let Err(e) = validate_cidr(cidr) {
                    errors.push(format!("Rule[{}] dst_cidr: {}", i, e));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn validate_cidr(cidr: &str) -> Result<(), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr));
    }
    let ip: std::net::IpAddr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid IP in CIDR: {}", cidr))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix in CIDR: {}", cidr))?;
    match ip {
        std::net::IpAddr::V4(_) if prefix > 32 => {
            return Err(format!("IPv4 prefix must be <= 32, got {}", prefix));
        }
        std::net::IpAddr::V6(_) if prefix > 128 => {
            return Err(format!("IPv6 prefix must be <= 128, got {}", prefix));
        }
        _ => {}
    }
    Ok(())
}
