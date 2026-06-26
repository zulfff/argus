//! Pure arithmetic helpers with no BPF intrinsics.
//! Compiles for both the BPF target (production) and the host (so `cargo test`
//! can verify the logic without a kernel). Keep this module free of
//! `aya_ebpf` map I/O — only packing/hashing math belongs here.

/// FNV-1a hash of the full 5-tuple into a `u64` connection key.
///
/// ponytail: hash collision possible (~negligible for 262144-entry map) — upgrade
/// to a `#[repr(C)]` 16-byte struct key when a userspace consumer needs to
/// reconstruct the tuple from the key. No consumer reads CONNTRACK today.
#[inline(always)]
pub fn pack_conn_key(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut h = FNV_OFFSET;
    let mut feed = |b: u8| {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    };
    for b in src_ip.to_be_bytes() {
        feed(b);
    }
    for b in dst_ip.to_be_bytes() {
        feed(b);
    }
    for b in src_port.to_be_bytes() {
        feed(b);
    }
    for b in dst_port.to_be_bytes() {
        feed(b);
    }
    feed(protocol);
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_pack_conn_key_no_collision_for_different_ports() {
        let mut keys = HashSet::new();
        for port in 8080u16..8080 + 256 {
            let k = pack_conn_key(0x0A000001, 0x0A000002, 12345, port, 6);
            assert!(keys.insert(k), "collision at port {}", port);
        }
        assert_eq!(keys.len(), 256);
    }

    #[test]
    fn test_pack_conn_key_distinguishes_high_octet_of_dst_ip() {
        // 10.0.0.2 vs 10.1.0.2 — old bit-packing masked dst_ip to low 16 bits.
        let a = pack_conn_key(0x0A000001, 0x0A000002, 12345, 80, 6);
        let b = pack_conn_key(0x0A000001, 0x0A010002, 12345, 80, 6);
        assert_ne!(a, b);
    }

    #[test]
    fn test_pack_conn_key_distinguishes_full_src_ip() {
        // old layout overwrote high 8 bits of src_ip with protocol.
        let a = pack_conn_key(0x0A000001, 0x0A000002, 12345, 80, 6);
        let b = pack_conn_key(0xFA000001, 0x0A000002, 12345, 80, 6);
        assert_ne!(a, b);
    }

    #[test]
    fn test_pack_conn_key_distinguishes_low_byte_of_dst_port() {
        // old layout did `dst_port >> 8`, discarding the low byte entirely.
        let a = pack_conn_key(0x0A000001, 0x0A000002, 12345, 0x1F00, 6);
        let b = pack_conn_key(0x0A000001, 0x0A000002, 12345, 0x1F01, 6);
        assert_ne!(a, b);
    }

    #[test]
    fn test_pack_conn_key_distinguishes_protocol() {
        let tcp = pack_conn_key(0x0A000001, 0x0A000002, 12345, 80, 6);
        let udp = pack_conn_key(0x0A000001, 0x0A000002, 12345, 80, 17);
        assert_ne!(tcp, udp);
    }

    #[test]
    fn test_old_layout_collides_to_prove_regression() {
        // The previous bit-packing implementation, preserved to prove the bug.
        fn old(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u64 {
            ((src_ip as u64) << 32)
                | ((dst_ip as u64 & 0xFFFF) << 16)
                | ((src_port as u64) << 8)
                | (dst_port as u64 >> 8)
                | ((protocol as u64) << 56)
        }
        let mut keys = HashSet::new();
        for port in 8080u16..8080 + 256 {
            keys.insert(old(0x0A000001, 0x0A000002, 12345, port, 6));
        }
        assert_eq!(
            keys.len(),
            2,
            "old layout should collide 256 ports into 2 keys"
        );
    }
}
