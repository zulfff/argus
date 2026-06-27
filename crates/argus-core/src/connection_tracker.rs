use argus_common::types::{ConnectionEntry, ConnectionState};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::instrument;

pub type NewConnectionCallback = Box<dyn Fn(&ConnectionKey) + Send + Sync>;

pub struct ConnectionTracker {
    connections: Mutex<HashMap<ConnectionKey, ConnectionEntry>>,
    max_entries: usize,
    gc_interval_secs: u64,
    on_new_connection: Option<NewConnectionCallback>,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct ConnectionKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl ConnectionTracker {
    pub fn new(max_entries: usize, gc_interval_secs: u64) -> Self {
        Self {
            connections: Mutex::new(HashMap::with_capacity(max_entries.min(65536))),
            max_entries,
            gc_interval_secs,
            on_new_connection: None,
        }
    }

    pub fn set_on_new_connection<F>(&mut self, callback: F)
    where
        F: Fn(&ConnectionKey) + Send + Sync + 'static,
    {
        self.on_new_connection = Some(Box::new(callback));
    }

    #[instrument(skip(self))]
    pub fn lookup(&self, key: &ConnectionKey) -> Option<ConnectionEntry> {
        let conns = self.connections.lock().ok()?;
        conns.get(key).cloned()
    }

    #[instrument(skip(self))]
    pub fn upsert(&self, key: ConnectionKey, now: DateTime<Utc>) {
        if let Ok(mut conns) = self.connections.lock() {
            if let Some(entry) = conns.get_mut(&key) {
                entry.last_seen = now;
                return;
            }
            if conns.len() >= self.max_entries {
                self.evict_lru(&mut conns);
            }
            conns.insert(
                key.clone(),
                ConnectionEntry {
                    src_ip: key.src_ip,
                    dst_ip: key.dst_ip,
                    src_port: key.src_port,
                    dst_port: key.dst_port,
                    protocol: key.protocol,
                    state: ConnectionState::New,
                    created_at: now,
                    last_seen: now,
                    packets_in: 0,
                    packets_out: 0,
                    bytes_in: 0,
                    bytes_out: 0,
                    draining: false,
                },
            );
            drop(conns);
            if let Some(ref callback) = self.on_new_connection {
                callback(&key);
            }
        }
    }

    #[instrument(skip(self))]
    pub fn update_state(&self, key: &ConnectionKey, state: ConnectionState) {
        if let Ok(mut conns) = self.connections.lock() {
            if let Some(entry) = conns.get_mut(key) {
                entry.state = state;
                entry.last_seen = Utc::now();
            }
        }
    }

    #[instrument(skip(self))]
    pub fn remove(&self, key: &ConnectionKey) {
        if let Ok(mut conns) = self.connections.lock() {
            conns.remove(key);
        }
    }

    pub fn active_count(&self) -> usize {
        self.connections.lock().map(|c| c.len()).unwrap_or(0)
    }

    pub fn gc(&self) {
        let now = Utc::now();
        if let Ok(mut conns) = self.connections.lock() {
            conns.retain(|_, entry| !entry.is_expired(now));
        }
    }

    fn evict_lru(&self, conns: &mut HashMap<ConnectionKey, ConnectionEntry>) {
        if let Some(oldest_key) = conns
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(k, _)| k.clone())
        {
            conns.remove(&oldest_key);
        }
    }

    pub fn list_all(&self) -> Vec<ConnectionEntry> {
        self.connections
            .lock()
            .map(|c| c.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn gc_interval(&self) -> u64 {
        self.gc_interval_secs
    }

    pub fn mark_draining(&self, ip: IpAddr) {
        if let Ok(mut conns) = self.connections.lock() {
            for (key, entry) in conns.iter_mut() {
                if key.src_ip == ip || key.dst_ip == ip {
                    entry.draining = true;
                }
            }
        }
    }

    pub fn count_for_ip(&self, ip: IpAddr) -> usize {
        self.connections
            .lock()
            .map(|c| {
                c.iter()
                    .filter(|(k, _)| k.src_ip == ip || k.dst_ip == ip)
                    .count()
            })
            .unwrap_or(0)
    }

    pub fn close_all_for_ip(&self, ip: IpAddr) {
        if let Ok(mut conns) = self.connections.lock() {
            conns.retain(|k, _| k.src_ip != ip && k.dst_ip != ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_upsert_and_lookup() {
        let tracker = ConnectionTracker::new(1000, 60);
        let key = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };
        let now = Utc::now();

        tracker.upsert(key.clone(), now);
        let entry = tracker.lookup(&key);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().state, ConnectionState::New);

        tracker.upsert(key.clone(), now);
        tracker.update_state(&key, ConnectionState::Established);
        let entry = tracker.lookup(&key).unwrap();
        assert_eq!(entry.state, ConnectionState::Established);
    }

    #[test]
    fn test_eviction_when_full() {
        let tracker = ConnectionTracker::new(2, 60);
        let now = Utc::now();

        let key1 = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 1,
            dst_port: 80,
            protocol: 6,
        };
        let key2 = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 2,
            dst_port: 80,
            protocol: 6,
        };
        let key3 = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 3,
            dst_port: 80,
            protocol: 6,
        };

        tracker.upsert(key1.clone(), now);
        tracker.upsert(key2.clone(), now);
        tracker.upsert(key3.clone(), now);

        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn test_remove_connection() {
        let tracker = ConnectionTracker::new(1000, 60);
        let now = Utc::now();
        let key = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        tracker.upsert(key.clone(), now);
        assert!(tracker.lookup(&key).is_some());

        tracker.update_state(&key, ConnectionState::Closed);
        tracker.remove(&key);
        assert!(tracker.lookup(&key).is_none());
    }
}
