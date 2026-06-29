use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use uuid::Uuid;

use argus_common::error::{ArgusError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaPeer {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
    #[serde(skip)]
    pub private_key: Option<String>,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
    pub last_handshake: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub enabled: bool,
    pub role: PeerRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerRole {
    Edge,
    Hub,
    Spoke,
    Gateway,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardInterface {
    pub name: String,
    pub listen_port: u16,
    #[serde(skip)]
    pub private_key: String,
    pub address: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub fwmark: Option<u32>,
    pub table: Option<String>,
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtnaPolicy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub source_peers: Vec<Uuid>,
    pub destination_peers: Vec<Uuid>,
    pub allowed_ports: Vec<u16>,
    pub allowed_protocols: Vec<String>,
    pub action: PolicyAction,
    pub priority: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
    Proxy { backend: String },
}

pub struct ZtnaMesh {
    pub interfaces: Mutex<HashMap<String, WireGuardInterface>>,
    pub peers: Mutex<HashMap<Uuid, ZtnaPeer>>,
    pub policies: Mutex<HashMap<Uuid, ZtnaPolicy>>,
    pub mesh_name: String,
}

impl ZtnaMesh {
    pub fn new(mesh_name: &str) -> Self {
        Self {
            interfaces: Mutex::new(HashMap::new()),
            peers: Mutex::new(HashMap::new()),
            policies: Mutex::new(HashMap::new()),
            mesh_name: mesh_name.to_string(),
        }
    }

    pub fn add_interface(&self, iface: WireGuardInterface) -> Result<()> {
        let mut interfaces = self
            .interfaces
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        if interfaces.contains_key(&iface.name) {
            return Err(ArgusError::Validation(format!(
                "interface {} already exists",
                iface.name
            )));
        }

        interfaces.insert(iface.name.clone(), iface);
        Ok(())
    }

    pub fn remove_interface(&self, name: &str) -> Result<()> {
        let removed = self
            .interfaces
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?
            .remove(name);
        removed
            .map(|_| ())
            .ok_or_else(|| ArgusError::NotFound(format!("interface {} not found", name)))
    }

    pub fn generate_wg_config(&self, iface_name: &str) -> Result<String> {
        let interfaces = self
            .interfaces
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        let iface = interfaces
            .get(iface_name)
            .ok_or_else(|| ArgusError::NotFound(format!("interface {} not found", iface_name)))?;

        let peers = self
            .peers
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        let mut config = String::new();

        config.push_str(&format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             ListenPort = {}\n",
            iface.private_key, iface.listen_port
        ));

        for addr in &iface.address {
            config.push_str(&format!("Address = {}\n", addr));
        }

        if let Some(table) = &iface.table {
            config.push_str(&format!("Table = {}\n", table));
        }
        if let Some(fwmark) = iface.fwmark {
            config.push_str(&format!("FwMark = {}\n", fwmark));
        }
        config.push_str(&format!("MTU = {}\n", iface.mtu));

        for dns in &iface.dns {
            config.push_str(&format!("DNS = {}\n", dns));
        }

        config.push('\n');

        for peer in peers.values() {
            if !peer.enabled {
                continue;
            }

            config.push_str(&format!(
                "[Peer]\n\
                 # {}\n\
                 PublicKey = {}\n\
                 Endpoint = {}\n\
                 AllowedIPs = {}\n\
                 PersistentKeepalive = {}\n\n",
                peer.name,
                peer.public_key,
                peer.endpoint,
                peer.allowed_ips.join(", "),
                peer.persistent_keepalive,
            ));
        }

        Ok(config)
    }

    pub fn add_peer(&self, peer: ZtnaPeer) -> Result<()> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;
        peers.insert(peer.id, peer);
        Ok(())
    }

    pub fn remove_peer(&self, peer_id: Uuid) -> Result<()> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        peers.remove(&peer_id);
        Ok(())
    }

    pub fn get_peer(&self, peer_id: Uuid) -> Option<ZtnaPeer> {
        self.peers.lock().ok()?.get(&peer_id).cloned()
    }

    pub fn list_peers(&self) -> Vec<ZtnaPeer> {
        self.peers
            .lock()
            .map(|p| p.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn add_policy(&self, policy: ZtnaPolicy) -> Result<()> {
        self.policies
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?
            .insert(policy.id, policy);
        Ok(())
    }

    pub fn evaluate_policy(
        &self,
        source_peer: Uuid,
        dest_peer: Uuid,
        dest_port: u16,
        protocol: &str,
    ) -> Option<PolicyAction> {
        let policies = self.policies.lock().ok()?;
        let mut matched: Option<&ZtnaPolicy> = None;
        let mut highest_prio = 0u32;

        for policy in policies.values().filter(|p| p.enabled) {
            if !policy.source_peers.contains(&source_peer)
                || !policy.destination_peers.contains(&dest_peer)
            {
                continue;
            }

            if !policy.allowed_ports.is_empty() && !policy.allowed_ports.contains(&dest_port) {
                continue;
            }

            if !policy.allowed_protocols.is_empty()
                && !policy
                    .allowed_protocols
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(protocol))
            {
                continue;
            }

            if policy.priority > highest_prio {
                highest_prio = policy.priority;
                matched = Some(policy);
            }
        }

        matched.map(|p| p.action.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_wg_config() {
        let mesh = ZtnaMesh::new("default");

        let iface = WireGuardInterface {
            name: "wg0".into(),
            listen_port: 51820,
            private_key: "PRIVATE_KEY_BASE64==".into(),
            address: vec!["10.99.0.1/24".into()],
            dns: vec!["1.1.1.1".into()],
            mtu: 1420,
            fwmark: None,
            table: None,
            pre_up: vec![],
            post_up: vec!["iptables -A FORWARD -i wg0 -j ACCEPT".into()],
            pre_down: vec![],
            post_down: vec![],
        };
        mesh.add_interface(iface).unwrap();

        let peer = ZtnaPeer {
            id: Uuid::new_v4(),
            name: "edge-01".into(),
            public_key: "PEER_PUBLIC_KEY_BASE64==".into(),
            private_key: None,
            endpoint: "192.168.1.10:51820".parse().unwrap(),
            allowed_ips: vec!["10.99.0.2/32".into()],
            persistent_keepalive: 25,
            last_handshake: None,
            rx_bytes: 0,
            tx_bytes: 0,
            enabled: true,
            role: PeerRole::Edge,
        };
        mesh.add_peer(peer).unwrap();

        let config = mesh.generate_wg_config("wg0").unwrap();
        assert!(config.contains("PrivateKey = PRIVATE_KEY_BASE64=="));
        assert!(config.contains("PublicKey = PEER_PUBLIC_KEY_BASE64=="));
        assert!(config.contains("Endpoint = 192.168.1.10:51820"));
        assert!(
            !config.contains("iptables"),
            "hooks should not be included in client config (security: command injection prevention)"
        );
        assert!(
            !config.contains("PostUp"),
            "PostUp hooks should not be in client config"
        );
    }

    #[test]
    fn test_policy_evaluation() {
        let mesh = ZtnaMesh::new("test");
        let peer_a = Uuid::new_v4();
        let peer_b = Uuid::new_v4();

        let policy = ZtnaPolicy {
            id: Uuid::new_v4(),
            name: "allow-ssh".into(),
            description: "Allow SSH between A and B".into(),
            source_peers: vec![peer_a],
            destination_peers: vec![peer_b],
            allowed_ports: vec![22],
            allowed_protocols: vec!["tcp".into()],
            action: PolicyAction::Allow,
            priority: 100,
            enabled: true,
        };
        mesh.add_policy(policy).unwrap();

        let result = mesh.evaluate_policy(peer_a, peer_b, 22, "tcp");
        assert!(matches!(result, Some(PolicyAction::Allow)));

        let denied = mesh.evaluate_policy(peer_a, peer_b, 80, "tcp");
        assert!(denied.is_none());
    }
}
