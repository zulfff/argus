use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}

pub struct TenantManager {
    tenants: Mutex<HashMap<Uuid, Tenant>>,
    default_tenant_id: Mutex<Option<Uuid>>,
}

impl TenantManager {
    pub fn new() -> Self {
        Self {
            tenants: Mutex::new(HashMap::new()),
            default_tenant_id: Mutex::new(None),
        }
    }

    pub fn create_tenant(&self, name: &str, description: &str) -> Tenant {
        let tenant = Tenant {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.to_string(),
            created_at: Utc::now(),
            enabled: true,
        };
        if let Ok(mut tenants) = self.tenants.lock() {
            tenants.insert(tenant.id, tenant.clone());
        }
        tenant
    }

    pub fn list_tenants(&self) -> Vec<Tenant> {
        self.tenants.lock().ok().map_or(Vec::new(), |tenants| {
            let mut list: Vec<Tenant> = tenants.values().cloned().collect();
            list.sort_by(|a, b| a.name.cmp(&b.name));
            list
        })
    }

    pub fn get_tenant(&self, id: &Uuid) -> Option<Tenant> {
        self.tenants.lock().ok()?.get(id).cloned()
    }

    pub fn delete_tenant(&self, id: &Uuid) -> bool {
        self.tenants
            .lock()
            .ok()
            .map(|mut t| t.remove(id).is_some())
            .unwrap_or(false)
    }

    pub fn set_default_tenant_id(&self, id: Uuid) {
        if let Ok(mut default) = self.default_tenant_id.lock() {
            *default = Some(id);
        }
    }

    pub fn clear_tenants(&self) {
        if let Ok(mut tenants) = self.tenants.lock() {
            tenants.clear();
        }
    }
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}
