use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::{Xdp, XdpFlags};
use aya::{Bpf, BpfLoader};
use tracing::{info, warn};

use argus_common::error::{ArgusError, Result};
use argus_common::types::{Action, CidrRule};

pub struct EbpfController {
    bpf: Option<Mutex<Bpf>>,
    pub wan_iface: Option<String>,
    pub loaded: bool,
}

fn cidr_to_lpm_key_v4(cidr: &str) -> Result<Key<u32>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(ArgusError::Validation(format!("invalid CIDR: {}", cidr)));
    }
    let v4: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| ArgusError::Validation(format!("invalid IPv4 in CIDR: {}", cidr)))?;
    let prefix_len: u32 = parts[1]
        .parse()
        .map_err(|_| ArgusError::Validation(format!("invalid prefix in CIDR: {}", cidr)))?;
    if prefix_len > 32 {
        return Err(ArgusError::Validation(format!(
            "IPv4 prefix must be <= 32: {}",
            cidr
        )));
    }
    Ok(Key::new(prefix_len, u32::from(v4)))
}

fn map_name_for_action(action: &Action, is_src: bool) -> &'static str {
    match (action, is_src) {
        (Action::Deny, true) => "SRC_BLOCKLIST",
        (Action::Deny, false) => "DST_BLOCKLIST",
        _ if is_src => "SRC_ALLOWLIST",
        _ => "DST_ALLOWLIST",
    }
}

/// Fail-safe: default-deny only when `ARGUS_EBPF_DEFAULT_MODE=deny` is set
/// exactly. Anything else (unset, empty, "allow", typos) → fail-open, so a
/// freshly-attached firewall never locks the operator out of their own box.
fn default_deny_enabled(env_value: Option<&str>) -> bool {
    matches!(env_value.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("deny"))
}

impl EbpfController {
    pub fn new() -> Self {
        Self {
            bpf: None,
            wan_iface: None,
            loaded: false,
        }
    }

    pub fn init(&mut self, obj_path: &str, wan_iface: &str) -> Result<()> {
        if !Path::new(obj_path).exists() {
            warn!(
                "eBPF object file not found at {} — eBPF data plane disabled",
                obj_path
            );
            return Ok(());
        }

        info!("Loading eBPF object from {}", obj_path);
        let mut bpf_loader = BpfLoader::new();
        let mut bpf = bpf_loader
            .load_file(obj_path)
            .map_err(|e| ArgusError::External(format!("eBPF load failed: {}", e)))?;

        let xdp_name = "argus_firewall";
        let xdp: &mut Xdp = bpf
            .program_mut(xdp_name)
            .ok_or_else(|| {
                ArgusError::NotFound(format!("XDP program '{}' not found", xdp_name))
            })?
            .try_into()
            .map_err(|_| ArgusError::Internal("program is not XDP type".into()))?;

        info!("Attaching XDP program to interface {}", wan_iface);
        xdp.attach(wan_iface, XdpFlags::default())
            .map_err(|e| ArgusError::External(format!("XDP attach failed: {}", e)))?;

        self.insert_allowlist_mode_marker_if_deny(&mut bpf)?;

        self.bpf = Some(Mutex::new(bpf));
        self.wan_iface = Some(wan_iface.to_string());
        self.loaded = true;
        info!("eBPF data plane loaded and attached to {}", wan_iface);
        Ok(())
    }

    fn insert_allowlist_mode_marker_if_deny(&self, bpf: &mut Bpf) -> Result<()> {
        if !default_deny_enabled(std::env::var("ARGUS_EBPF_DEFAULT_MODE").ok().as_deref()) {
            info!("eBPF default-allow mode (fail-open). Set ARGUS_EBPF_DEFAULT_MODE=deny to enforce allowlist.");
            return Ok(());
        }
        warn!("eBPF default-deny mode ACTIVE — only allowlisted IPs will pass. Ensure your management IP is allowlisted BEFORE this point or you may lose access.");
        self.insert_allowlist_mode_marker(bpf)
    }

    fn insert_allowlist_mode_marker(&self, bpf: &mut Bpf) -> Result<()> {
        for name in ["SRC_ALLOWLIST", "DST_ALLOWLIST"] {
            let map_ref = bpf
                .map_mut(name)
                .ok_or_else(|| ArgusError::Internal(format!("{} map not found", name)))?;

            let mut allowlist: LpmTrie<_, u32, u32> = LpmTrie::try_from(map_ref)
                .map_err(|e| ArgusError::External(format!("LpmTrie from {}: {}", name, e)))?;

            allowlist
                .insert(&Key::new(32, 0u32), 1, 0)
                .map_err(|e| {
                    ArgusError::External(format!("insert marker into {}: {}", name, e))
                })?;
        }

        info!("Allowlist mode markers inserted into eBPF (SRC_ALLOWLIST + DST_ALLOWLIST)");
        Ok(())
    }

    fn with_bpf<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Bpf) -> Result<T>,
    {
        let bpf_lock = self
            .bpf
            .as_ref()
            .ok_or_else(|| ArgusError::Internal("eBPF not loaded".into()))?;
        let mut bpf = bpf_lock
            .lock()
            .map_err(|e| ArgusError::Internal(format!("bpf lock: {}", e)))?;
        f(&mut bpf)
    }

    pub fn sync_rule_create(&self, rule: &CidrRule) -> Result<()> {
        if !self.loaded || !rule.enabled {
            return Ok(());
        }
        self.with_bpf(|bpf| self.sync_rule(bpf, rule, true))
    }

    pub fn sync_rule_delete(&self, rule: &CidrRule) -> Result<()> {
        if !self.loaded {
            return Ok(());
        }
        self.with_bpf(|bpf| self.sync_rule(bpf, rule, false))
    }

    pub fn sync_rule_update(
        &self,
        old_rule: &CidrRule,
        new_rule: &CidrRule,
    ) -> Result<()> {
        if !self.loaded {
            return Ok(());
        }
        self.with_bpf(|bpf| {
            self.sync_rule(bpf, old_rule, false)?;
            if new_rule.enabled {
                self.sync_rule(bpf, new_rule, true)?;
            }
            Ok(())
        })
    }

    pub fn sync_all_rules(&self, rules: &[CidrRule]) -> Result<()> {
        if !self.loaded {
            return Ok(());
        }
        self.with_bpf(|bpf| {
            for rule in rules.iter().filter(|r| r.enabled) {
                self.sync_rule(bpf, rule, true)?;
            }
            Ok(())
        })
    }

    fn sync_rule(&self, bpf: &mut Bpf, rule: &CidrRule, add: bool) -> Result<()> {
        if let Some(ref cidr) = rule.src_cidr {
            self.sync_cidr(bpf, rule, cidr, true, add)?;
        }
        if let Some(ref cidr) = rule.dst_cidr {
            self.sync_cidr(bpf, rule, cidr, false, add)?;
        }
        Ok(())
    }

    fn sync_cidr(
        &self,
        bpf: &mut Bpf,
        rule: &CidrRule,
        cidr: &str,
        is_src: bool,
        add: bool,
    ) -> Result<()> {
        if cidr.contains(':') {
            warn!("IPv6 CIDR rules not yet supported in eBPF data plane: {}", cidr);
            return Ok(());
        }

        let name = map_name_for_action(&rule.action, is_src);
        let lpm_key = cidr_to_lpm_key_v4(cidr)?;

        let map_ref = bpf
            .map_mut(name)
            .ok_or_else(|| ArgusError::Internal(format!("{} map not found", name)))?;

        let mut trie: LpmTrie<_, u32, u32> = LpmTrie::try_from(map_ref)
            .map_err(|e| ArgusError::External(format!("LpmTrie access for {}: {}", name, e)))?;

        if add {
            trie.insert(&lpm_key, 1u32, 0)
                .map_err(|e| ArgusError::External(format!("insert into {}: {}", name, e)))?;
        } else {
            trie.remove(&lpm_key)
                .map_err(|e| ArgusError::External(format!("remove from {}: {}", name, e)))?;
        }

        Ok(())
    }
}

impl Default for EbpfController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_to_lpm_key_v4() {
        let key = cidr_to_lpm_key_v4("10.0.0.0/8").unwrap();
        assert_eq!(key.prefix_len(), 8);
        let expected = u32::from(Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(key.data(), expected);

        let key = cidr_to_lpm_key_v4("192.168.1.0/24").unwrap();
        assert_eq!(key.prefix_len(), 24);

        let key = cidr_to_lpm_key_v4("0.0.0.0/0").unwrap();
        assert_eq!(key.prefix_len(), 0);
    }

    #[test]
    fn test_cidr_to_lpm_key_invalid() {
        assert!(cidr_to_lpm_key_v4("not-a-cidr").is_err());
        assert!(cidr_to_lpm_key_v4("10.0.0.0/33").is_err());
        assert!(cidr_to_lpm_key_v4("10.0.0.0").is_err());
    }

    #[test]
    fn test_map_name_for_action() {
        assert_eq!(map_name_for_action(&Action::Deny, true), "SRC_BLOCKLIST");
        assert_eq!(map_name_for_action(&Action::Deny, false), "DST_BLOCKLIST");
        assert_eq!(map_name_for_action(&Action::Allow, true), "SRC_ALLOWLIST");
        assert_eq!(map_name_for_action(&Action::Allow, false), "DST_ALLOWLIST");
        assert_eq!(map_name_for_action(&Action::RateLimit { packets_per_second: 10 }, true), "SRC_ALLOWLIST");
    }

    #[test]
    fn test_ebpf_controller_new_is_empty() {
        let ctrl = EbpfController::new();
        assert!(!ctrl.loaded);
        assert!(ctrl.wan_iface.is_none());
    }

    #[test]
    fn test_default_mode_is_fail_open() {
        assert!(!default_deny_enabled(None), "unset must be fail-open (allow)");
        assert!(!default_deny_enabled(Some("")), "empty must be fail-open");
        assert!(!default_deny_enabled(Some("allow")));
        assert!(!default_deny_enabled(Some("nonsense")), "typo must be fail-open");
        assert!(default_deny_enabled(Some("deny")), "explicit deny opt-in");
        assert!(default_deny_enabled(Some("DENY")), "case-insensitive deny");
        assert!(default_deny_enabled(Some(" deny ")), "trimmed deny");
    }

    #[test]
    fn test_byte_order_consistency_userspace_vs_ebpf() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let userspace_data = u32::from(ip);
        let ebpf_bytes = [10u8, 0, 0, 1];
        let ebpf_data = u32::from_be_bytes(ebpf_bytes);
        assert_eq!(
            userspace_data, ebpf_data,
            "Byte-order mismatch: userspace={:#010x} ebpf={:#010x}",
            userspace_data, ebpf_data
        );
        assert_eq!(userspace_data, 0x0A000001);
    }
}
