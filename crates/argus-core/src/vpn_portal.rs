use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VpnPeerStatus {
    Pending,
    Approved,
    Denied,
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnPeerRequest {
    pub id: Uuid,
    pub user_id: String,
    pub public_key: String,
    pub allowed_ips: String,
    pub status: VpnPeerStatus,
    pub created_at: DateTime<Utc>,
}

pub struct VpnPortalManager {
    requests: Mutex<Vec<VpnPeerRequest>>,
}

impl VpnPortalManager {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn submit_request(
        &self,
        user_id: &str,
        public_key: &str,
        allowed_ips: &str,
    ) -> VpnPeerRequest {
        let request = VpnPeerRequest {
            id: Uuid::new_v4(),
            user_id: user_id.to_string(),
            public_key: public_key.to_string(),
            allowed_ips: allowed_ips.to_string(),
            status: VpnPeerStatus::Pending,
            created_at: Utc::now(),
        };
        if let Ok(mut reqs) = self.requests.lock() {
            reqs.push(request.clone());
        }
        request
    }

    pub fn approve(&self, id: &Uuid, approver_username: &str) -> Result<(), String> {
        if let Ok(mut reqs) = self.requests.lock() {
            if let Some(req) = reqs.iter_mut().find(|r| &r.id == id) {
                if req.status != VpnPeerStatus::Pending {
                    return Err("Request is not in pending state".to_string());
                }
                if req.user_id == approver_username {
                    return Err("Cannot approve your own request".to_string());
                }
                req.status = VpnPeerStatus::Approved;
                return Ok(());
            }
        }
        Err("Request not found".to_string())
    }

    pub fn deny(&self, id: &Uuid) -> bool {
        if let Ok(mut reqs) = self.requests.lock() {
            if let Some(req) = reqs.iter_mut().find(|r| &r.id == id) {
                if req.status == VpnPeerStatus::Pending {
                    req.status = VpnPeerStatus::Denied;
                    return true;
                }
            }
        }
        false
    }

    pub fn revoke(&self, id: &Uuid) -> bool {
        if let Ok(mut reqs) = self.requests.lock() {
            if let Some(req) = reqs.iter_mut().find(|r| &r.id == id) {
                if matches!(req.status, VpnPeerStatus::Approved | VpnPeerStatus::Active) {
                    req.status = VpnPeerStatus::Revoked;
                    return true;
                }
            }
        }
        false
    }

    pub fn list(&self, status: Option<VpnPeerStatus>) -> Vec<VpnPeerRequest> {
        if let Ok(reqs) = self.requests.lock() {
            if let Some(s) = status {
                reqs.iter().filter(|r| r.status == s).cloned().collect()
            } else {
                reqs.clone()
            }
        } else {
            Vec::new()
        }
    }

    pub fn clear_peers(&self) {
        if let Ok(mut reqs) = self.requests.lock() {
            reqs.clear();
        }
    }

    pub fn generate_client_config(
        &self,
        id: &Uuid,
        server_public_key: &str,
        endpoint: &str,
    ) -> Option<String> {
        let reqs = self.requests.lock().ok()?;
        let req = reqs.iter().find(|r| &r.id == id)?;
        if req.status != VpnPeerStatus::Approved && req.status != VpnPeerStatus::Active {
            return None;
        }
        let config = format!(
            "[Interface]\n\
             PrivateKey = <client-private-key>\n\
             Address = {}\n\
             DNS = 1.1.1.1\n\n\
             [Peer]\n\
             PublicKey = {}\n\
             Endpoint = {}\n\
             AllowedIPs = 0.0.0.0/0\n\
             PersistentKeepalive = 25\n",
            req.allowed_ips, server_public_key, endpoint
        );
        Some(config)
    }
}

impl Default for VpnPortalManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_approval_prevention() {
        let portal = VpnPortalManager::new();

        let req = portal.submit_request(
            "alice",
            "ABCD1234567890ABCD1234567890ABCD1234567890AB",
            "10.0.0.2/32",
        );
        assert_eq!(req.status, VpnPeerStatus::Pending);
        assert_eq!(req.user_id, "alice");

        let result = portal.approve(&req.id, "alice");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Cannot approve your own request");

        let requests = portal.list(Some(VpnPeerStatus::Pending));
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].status, VpnPeerStatus::Pending);
    }

    #[test]
    fn test_cross_user_approval_allowed() {
        let portal = VpnPortalManager::new();

        let req = portal.submit_request(
            "alice",
            "ABCD1234567890ABCD1234567890ABCD1234567890AB",
            "10.0.0.2/32",
        );

        let result = portal.approve(&req.id, "bob");
        assert!(result.is_ok());

        let requests = portal.list(Some(VpnPeerStatus::Approved));
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].status, VpnPeerStatus::Approved);
    }

    #[test]
    fn test_approve_nonexistent_request() {
        let portal = VpnPortalManager::new();
        let fake_id = Uuid::new_v4();

        let result = portal.approve(&fake_id, "admin");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Request not found");
    }
}
