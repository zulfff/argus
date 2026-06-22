use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NodeRole {
    Leader,
    Follower,
    Candidate,
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeRole::Leader => write!(f, "leader"),
            NodeRole::Follower => write!(f, "follower"),
            NodeRole::Candidate => write!(f, "candidate"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterNode {
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub role: NodeRole,
    pub last_heartbeat: DateTime<Utc>,
    pub healthy: bool,
}

pub struct ClusterManager {
    local_id: Uuid,
    nodes: Mutex<HashMap<Uuid, ClusterNode>>,
    pub heartbeat_interval_secs: u64,
}

impl ClusterManager {
    pub fn new(local_id: Uuid) -> Self {
        let now = Utc::now();
        let local_node = ClusterNode {
            id: local_id,
            name: "local".to_string(),
            address: "127.0.0.1".to_string(),
            port: 8443,
            role: NodeRole::Leader,
            last_heartbeat: now,
            healthy: true,
        };
        let mut nodes = HashMap::new();
        nodes.insert(local_id, local_node);
        Self {
            local_id,
            nodes: Mutex::new(nodes),
            heartbeat_interval_secs: 5,
        }
    }

    pub fn register_node(&self, name: &str, address: &str, port: u16) -> Uuid {
        let id = Uuid::new_v4();
        let node = ClusterNode {
            id,
            name: name.to_string(),
            address: address.to_string(),
            port,
            role: NodeRole::Follower,
            last_heartbeat: Utc::now(),
            healthy: true,
        };
        if let Ok(mut nodes) = self.nodes.lock() {
            nodes.insert(id, node);
        }
        id
    }

    pub fn list_nodes(&self) -> Vec<ClusterNode> {
        self.nodes.lock().ok().map_or(Vec::new(), |nodes| {
            let mut list: Vec<ClusterNode> = nodes.values().cloned().collect();
            list.sort_by(|a, b| a.name.cmp(&b.name));
            list
        })
    }

    pub fn remove_node(&self, id: &Uuid) -> bool {
        if *id == self.local_id {
            return false;
        }
        self.nodes
            .lock()
            .ok()
            .map(|mut n| n.remove(id).is_some())
            .unwrap_or(false)
    }

    pub fn heartbeat(&self, node_id: &Uuid) -> bool {
        let Ok(mut nodes) = self.nodes.lock() else {
            return false;
        };
        if let Some(node) = nodes.get_mut(node_id) {
            node.last_heartbeat = Utc::now();
            node.healthy = true;
            true
        } else {
            false
        }
    }

    pub fn elect_leader(&self) -> Option<Uuid> {
        let mut nodes = self.nodes.lock().ok()?;
        let now = Utc::now();
        let timeout = chrono::Duration::seconds(self.heartbeat_interval_secs as i64 * 3);

        for node in nodes.values_mut() {
            if now - node.last_heartbeat > timeout {
                node.healthy = false;
                if node.role == NodeRole::Leader {
                    node.role = NodeRole::Candidate;
                }
            }
        }

        let current_leader = nodes
            .values()
            .find(|n| n.role == NodeRole::Leader && n.healthy);
        if let Some(leader) = current_leader {
            return Some(leader.id);
        }

        let healthy_followers: Vec<Uuid> =
            nodes.values().filter(|n| n.healthy).map(|n| n.id).collect();

        if healthy_followers.is_empty() {
            return None;
        }

        let new_leader_id = healthy_followers[0];
        if let Some(leader) = nodes.get_mut(&new_leader_id) {
            leader.role = NodeRole::Leader;
        }

        Some(new_leader_id)
    }
}
