use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyslogProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    pub id: Uuid,
    pub server: String,
    pub port: u16,
    pub protocol: SyslogProtocol,
    pub min_severity: String,
    pub enabled: bool,
}

pub struct SyslogForwarder {
    configs: Mutex<Vec<SyslogConfig>>,
    #[allow(dead_code)]
    client: reqwest::Client,
}

impl SyslogForwarder {
    pub fn new() -> Self {
        Self {
            configs: Mutex::new(Vec::new()),
            client: reqwest::Client::new(),
        }
    }

    pub fn add_config(&self, mut config: SyslogConfig) -> Uuid {
        config.id = Uuid::new_v4();
        if let Ok(mut configs) = self.configs.lock() {
            configs.push(config.clone());
        }
        config.id
    }

    pub fn remove_config(&self, id: &Uuid) -> bool {
        if let Ok(mut configs) = self.configs.lock() {
            let len = configs.len();
            configs.retain(|c| &c.id != id);
            configs.len() < len
        } else {
            false
        }
    }

    pub fn list_configs(&self) -> Vec<SyslogConfig> {
        self.configs.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub async fn send_log(
        &self,
        facility: u8,
        severity: u8,
        hostname: &str,
        app_name: &str,
        msg: &str,
    ) {
        let configs = match self.configs.lock() {
            Ok(c) => c.clone(),
            Err(_) => return,
        };

        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let priority = facility * 8 + severity;

        for config in &configs {
            if !config.enabled {
                continue;
            }
            let severity_num = match config.min_severity.to_lowercase().as_str() {
                "emerg" => 0,
                "alert" => 1,
                "crit" => 2,
                "err" => 3,
                "warning" => 4,
                "notice" => 5,
                "info" => 6,
                "debug" => 7,
                _ => 6,
            };
            if severity > severity_num {
                continue;
            }

            let syslog_msg = format!(
                "<{}>1 {} {} {} - - - {}",
                priority, timestamp, hostname, app_name, msg
            );

            match config.protocol {
                SyslogProtocol::Tcp => {
                    let addr = format!("{}:{}", config.server, config.port);
                    if let Ok(mut stream) = tokio::net::TcpStream::connect(&addr).await {
                        let _ =
                            tokio::io::AsyncWriteExt::write_all(&mut stream, syslog_msg.as_bytes())
                                .await;
                    }
                }
                SyslogProtocol::Udp => {
                    let addr = format!("{}:{}", config.server, config.port);
                    if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                        let _ = socket.send_to(syslog_msg.as_bytes(), &addr).await;
                    }
                }
            }
        }
    }
}

impl Default for SyslogForwarder {
    fn default() -> Self {
        Self::new()
    }
}
