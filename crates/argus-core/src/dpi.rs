use serde::{Deserialize, Serialize};

use argus_common::types::Direction;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Layer7Protocol {
    Http,
    Https,
    Dns,
    Ssh,
    Smtp,
    Ftp,
    Sftp,
    Mysql,
    Postgresql,
    Redis,
    Mqtt,
    Dhcp,
    Ntp,
    Snmp,
    Rdp,
    Vnc,
    Unknown,
}

impl std::fmt::Display for Layer7Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer7Protocol::Http => write!(f, "HTTP"),
            Layer7Protocol::Https => write!(f, "HTTPS"),
            Layer7Protocol::Dns => write!(f, "DNS"),
            Layer7Protocol::Ssh => write!(f, "SSH"),
            Layer7Protocol::Smtp => write!(f, "SMTP"),
            Layer7Protocol::Ftp => write!(f, "FTP"),
            Layer7Protocol::Sftp => write!(f, "SFTP"),
            Layer7Protocol::Mysql => write!(f, "MySQL"),
            Layer7Protocol::Postgresql => write!(f, "PostgreSQL"),
            Layer7Protocol::Redis => write!(f, "Redis"),
            Layer7Protocol::Mqtt => write!(f, "MQTT"),
            Layer7Protocol::Dhcp => write!(f, "DHCP"),
            Layer7Protocol::Ntp => write!(f, "NTP"),
            Layer7Protocol::Snmp => write!(f, "SNMP"),
            Layer7Protocol::Rdp => write!(f, "RDP"),
            Layer7Protocol::Vnc => write!(f, "VNC"),
            Layer7Protocol::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiResult {
    pub protocol: Layer7Protocol,
    pub confidence: f64,
    pub description: String,
}

pub struct DpiEngine;

impl DpiEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn identify(&self, dst_port: u16, protocol: u8, _direction: Direction) -> DpiResult {
        let proto_name = if protocol == 6 {
            "TCP"
        } else if protocol == 17 {
            "UDP"
        } else {
            "OTHER"
        };

        match (dst_port, protocol) {
            (80, 6) => DpiResult {
                protocol: Layer7Protocol::Http,
                confidence: 0.95,
                description: format!(
                    "HTTP (port {}/{}), direction: {:?}",
                    dst_port, proto_name, _direction
                ),
            },
            (443, 6) => DpiResult {
                protocol: Layer7Protocol::Https,
                confidence: 0.95,
                description: format!("HTTPS (port {}/{})", dst_port, proto_name),
            },
            (53, 17) | (53, 6) => DpiResult {
                protocol: Layer7Protocol::Dns,
                confidence: 0.90,
                description: format!("DNS (port {}/{})", dst_port, proto_name),
            },
            (22, 6) => DpiResult {
                protocol: Layer7Protocol::Ssh,
                confidence: 0.95,
                description: format!("SSH (port {}/{})", dst_port, proto_name),
            },
            (25, 6) | (587, 6) | (465, 6) => DpiResult {
                protocol: Layer7Protocol::Smtp,
                confidence: 0.90,
                description: format!("SMTP (port {}/{})", dst_port, proto_name),
            },
            (20, 6) | (21, 6) => DpiResult {
                protocol: Layer7Protocol::Ftp,
                confidence: 0.90,
                description: format!("FTP (port {}/{})", dst_port, proto_name),
            },
            (115, 6) => DpiResult {
                protocol: Layer7Protocol::Sftp,
                confidence: 0.85,
                description: format!("SFTP (port {}/{})", dst_port, proto_name),
            },
            (3306, 6) => DpiResult {
                protocol: Layer7Protocol::Mysql,
                confidence: 0.95,
                description: format!("MySQL (port {}/{})", dst_port, proto_name),
            },
            (5432, 6) => DpiResult {
                protocol: Layer7Protocol::Postgresql,
                confidence: 0.95,
                description: format!("PostgreSQL (port {}/{})", dst_port, proto_name),
            },
            (6379, 6) => DpiResult {
                protocol: Layer7Protocol::Redis,
                confidence: 0.90,
                description: format!("Redis (port {}/{})", dst_port, proto_name),
            },
            (1883, 6) | (8883, 6) => DpiResult {
                protocol: Layer7Protocol::Mqtt,
                confidence: 0.85,
                description: format!("MQTT (port {}/{})", dst_port, proto_name),
            },
            (67, 17) | (68, 17) => DpiResult {
                protocol: Layer7Protocol::Dhcp,
                confidence: 0.95,
                description: format!("DHCP (port {}/{})", dst_port, proto_name),
            },
            (123, 17) => DpiResult {
                protocol: Layer7Protocol::Ntp,
                confidence: 0.95,
                description: format!("NTP (port {}/{})", dst_port, proto_name),
            },
            (161, 17) | (162, 17) => DpiResult {
                protocol: Layer7Protocol::Snmp,
                confidence: 0.90,
                description: format!("SNMP (port {}/{})", dst_port, proto_name),
            },
            (3389, 6) => DpiResult {
                protocol: Layer7Protocol::Rdp,
                confidence: 0.95,
                description: format!("RDP (port {}/{})", dst_port, proto_name),
            },
            (5900..=5903, 6) => DpiResult {
                protocol: Layer7Protocol::Vnc,
                confidence: 0.85,
                description: format!("VNC (port {}/{})", dst_port, proto_name),
            },
            _ => DpiResult {
                protocol: Layer7Protocol::Unknown,
                confidence: 0.0,
                description: format!("Unknown protocol (port {}/{})", dst_port, proto_name),
            },
        }
    }

    pub fn identify_by_payload_heuristic(&self, data: &[u8]) -> Layer7Protocol {
        if data.starts_with(b"GET ")
            || data.starts_with(b"POST ")
            || data.starts_with(b"PUT ")
            || data.starts_with(b"DELETE ")
            || data.starts_with(b"HEAD ")
            || data.starts_with(b"OPTIONS ")
            || data.starts_with(b"PATCH ")
        {
            return Layer7Protocol::Http;
        }
        if data.starts_with(b"\x16\x03") && data.len() > 5 {
            return Layer7Protocol::Https;
        }
        if data.starts_with(b"SSH-") {
            return Layer7Protocol::Ssh;
        }
        if data.starts_with(b"EHLO")
            || data.starts_with(b"HELO")
            || data.starts_with(b"MAIL FROM")
            || data.starts_with(b"RCPT TO")
        {
            return Layer7Protocol::Smtp;
        }
        if data.starts_with(b"220 ") || data.starts_with(b"USER ") || data.starts_with(b"PASS ") {
            return Layer7Protocol::Ftp;
        }
        if data.len() >= 12 {
            let id = data[0];
            let flags = data[2] >> 7 & 1;
            if id == 0 && flags == 0 {
                return Layer7Protocol::Dns;
            }
        }
        Layer7Protocol::Unknown
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}
