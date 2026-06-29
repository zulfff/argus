use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::xdp;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::XdpContext;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::maps::{
    CONNTRACK, DST_ALLOWLIST, DST_ALLOWLIST_V6, DST_BLOCKLIST, DST_BLOCKLIST_V6, PER_CPU_PACKETS,
    RATE_LIMIT_BUCKETS, SRC_ALLOWLIST, SRC_ALLOWLIST_V6, SRC_BLOCKLIST, SRC_BLOCKLIST_V6,
    IP_REPUTATION_V4, IP_REPUTATION_V6, THREAT_STATS, EVENTS, ThreatCounter,
};

const ETH_HDR_LEN: usize = core::mem::size_of::<EthHdr>();
const IPV4_HDR_LEN: usize = core::mem::size_of::<Ipv4Hdr>();
const IPV6_HDR_LEN: usize = core::mem::size_of::<Ipv6Hdr>();

#[xdp]
pub fn argus_firewall(ctx: XdpContext) -> u32 {
    match unsafe { try_argus_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn try_argus_firewall(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + (ETH_HDR_LEN + IPV4_HDR_LEN) > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_hdr = data as *const EthHdr;
    let ether_type =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_hdr).ether_type)) };

    match ether_type {
        EtherType::Ipv4 => handle_ipv4(ctx, data, data_end),
        EtherType::Ipv6 => handle_ipv6(ctx, data, data_end),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
unsafe fn handle_ipv4(_ctx: XdpContext, data: usize, data_end: usize) -> Result<u32, u32> {
    if data + ETH_HDR_LEN + IPV4_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = &*((data + ETH_HDR_LEN) as *const Ipv4Hdr);

    let version_ihl = unsafe { *(data as *const u8).add(ETH_HDR_LEN) };
    let ihl = (version_ihl & 0x0F) as usize;
    let ip_hdr_len = ihl * 4;

    if ip_hdr_len < 20 || data + ETH_HDR_LEN + ip_hdr_len > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = u32::from_be_bytes(ip_hdr.src_addr);
    let dst_ip = u32::from_be_bytes(ip_hdr.dst_addr);
    let protocol_byte = unsafe { *(data as *const u8).add(ETH_HDR_LEN + 9) };

    let frag_off_bytes = unsafe {
        [
            *(data as *const u8).add(ETH_HDR_LEN + 6),
            *(data as *const u8).add(ETH_HDR_LEN + 7),
        ]
    };
    let frag_off = u16::from_be_bytes(frag_off_bytes);
    let more_fragments = (frag_off & 0x2000) != 0;
    let fragment_offset = (frag_off & 0x1FFF) * 8;
    let is_fragment = more_fragments || fragment_offset > 0;

    if let Some(packets_ptr) = PER_CPU_PACKETS.get_ptr_mut(0) {
        *packets_ptr = (*packets_ptr).wrapping_add(1);
    }

    let src_key = Key::new(32, src_ip);
    let dst_key = Key::new(32, dst_ip);

    // Dynamic IP Reputation Checks (v4)
    if let Some(rep) = IP_REPUTATION_V4.get(&src_key) {
        if rep.score <= -50 {
            // Update THREAT_STATS drops count
            if let Some(counter) = THREAT_STATS.get_ptr_mut(&src_ip) {
                unsafe {
                    (*counter).drops = (*counter).drops.wrapping_add(1);
                    (*counter).last_seen = aya_ebpf::helpers::bpf_ktime_get_ns();
                }
            } else {
                let init_counter = ThreatCounter {
                    drops: 1,
                    last_seen: aya_ebpf::helpers::bpf_ktime_get_ns(),
                };
                let _ = THREAT_STATS.insert(&src_ip, &init_counter, 0);
            }

            // Emit Event using EVENTS channel
            let mut buf = [0u8; 256];
            buf[0] = 1; // event type: 1 = reputation block
            buf[1..5].copy_from_slice(&src_ip.to_be_bytes());
            buf[5..9].copy_from_slice(&rep.score.to_be_bytes());
            let _ = EVENTS.output(&_ctx, &buf, 0);

            return Ok(xdp_action::XDP_DROP);
        }
    }

    if SRC_BLOCKLIST.get(&src_key).is_some() || DST_BLOCKLIST.get(&dst_key).is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    let marker = Key::new(32, 0);
    if SRC_ALLOWLIST.get(&marker).is_some()
        && SRC_ALLOWLIST.get(&src_key).is_none()
        && SRC_BLOCKLIST.get(&src_key).is_none()
    {
        return Ok(xdp_action::XDP_DROP);
    }
    if DST_ALLOWLIST.get(&marker).is_some()
        && DST_ALLOWLIST.get(&dst_key).is_none()
        && DST_BLOCKLIST.get(&dst_key).is_none()
    {
        return Ok(xdp_action::XDP_DROP);
    }

    if !check_rate_limit(src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    if !is_fragment {
        match protocol_byte {
            6 => {
                let tcp_off = ETH_HDR_LEN + ip_hdr_len;
                if data + tcp_off + core::mem::size_of::<TcpHdr>() > data_end {
                    return Ok(xdp_action::XDP_PASS);
                }
                let tcp_hdr = &*((data + tcp_off) as *const TcpHdr);
                let src_port = u16::from_be(tcp_hdr.source);
                let dst_port = u16::from_be(tcp_hdr.dest);
                track_connection(src_ip, dst_ip, src_port, dst_port, protocol_byte);
            }
            17 => {
                let udp_off = ETH_HDR_LEN + ip_hdr_len;
                if data + udp_off + core::mem::size_of::<UdpHdr>() > data_end {
                    return Ok(xdp_action::XDP_PASS);
                }
                let udp_hdr = &*((data + udp_off) as *const UdpHdr);
                let src_port = u16::from_be_bytes(udp_hdr.source);
                let dst_port = u16::from_be_bytes(udp_hdr.dest);
                track_connection(src_ip, dst_ip, src_port, dst_port, protocol_byte);
            }
            _ => {}
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn handle_ipv6(_ctx: XdpContext, data: usize, data_end: usize) -> Result<u32, u32> {
    if data + ETH_HDR_LEN + IPV6_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = &*((data + ETH_HDR_LEN) as *const Ipv6Hdr);

    let src_addr = u128::from_be_bytes(ip_hdr.src_addr);
    let dst_addr = u128::from_be_bytes(ip_hdr.dst_addr);
    let protocol_byte = unsafe { *(data as *const u8).add(ETH_HDR_LEN + 6) };

    if let Some(packets_ptr) = PER_CPU_PACKETS.get_ptr_mut(1) {
        *packets_ptr = (*packets_ptr).wrapping_add(1);
    }

    let src_key = Key::new(128, src_addr);
    let dst_key = Key::new(128, dst_addr);

    // Dynamic IP Reputation Checks (v6)
    if let Some(rep) = IP_REPUTATION_V6.get(&src_key) {
        if rep.score <= -50 {
            // Update THREAT_STATS drops count (use lower 32-bits hash of v6 src_addr as key)
            let src_ip_hash = (src_addr as u32) ^ ((src_addr >> 32) as u32);
            if let Some(counter) = THREAT_STATS.get_ptr_mut(&src_ip_hash) {
                unsafe {
                    (*counter).drops = (*counter).drops.wrapping_add(1);
                    (*counter).last_seen = aya_ebpf::helpers::bpf_ktime_get_ns();
                }
            } else {
                let init_counter = ThreatCounter {
                    drops: 1,
                    last_seen: aya_ebpf::helpers::bpf_ktime_get_ns(),
                };
                let _ = THREAT_STATS.insert(&src_ip_hash, &init_counter, 0);
            }

            // Emit Event using EVENTS channel
            let mut buf = [0u8; 256];
            buf[0] = 2; // event type: 2 = reputation block v6
            buf[1..17].copy_from_slice(&src_addr.to_be_bytes());
            buf[17..21].copy_from_slice(&rep.score.to_be_bytes());
            let _ = EVENTS.output(&_ctx, &buf, 0);

            return Ok(xdp_action::XDP_DROP);
        }
    }

    if SRC_BLOCKLIST_V6.get(&src_key).is_some() || DST_BLOCKLIST_V6.get(&dst_key).is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    let marker: u128 = 0;
    let marker_key = Key::new(0, marker);
    if SRC_ALLOWLIST_V6.get(&marker_key).is_some()
        && SRC_ALLOWLIST_V6.get(&src_key).is_none()
        && SRC_BLOCKLIST_V6.get(&src_key).is_none()
    {
        return Ok(xdp_action::XDP_DROP);
    }
    if DST_ALLOWLIST_V6.get(&marker_key).is_some()
        && DST_ALLOWLIST_V6.get(&dst_key).is_none()
        && DST_BLOCKLIST_V6.get(&dst_key).is_none()
    {
        return Ok(xdp_action::XDP_DROP);
    }

    match protocol_byte {
        6 => {
            let tcp_off = ETH_HDR_LEN + IPV6_HDR_LEN;
            if data + tcp_off + core::mem::size_of::<TcpHdr>() > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            let tcp_hdr = &*((data + tcp_off) as *const TcpHdr);
            let src_port = u16::from_be(tcp_hdr.source);
            let dst_port = u16::from_be(tcp_hdr.dest);
            let src_ip_hash = (src_addr as u32) ^ ((src_addr >> 32) as u32);
            let dst_ip_hash = (dst_addr as u32) ^ ((dst_addr >> 32) as u32);
            track_connection(src_ip_hash, dst_ip_hash, src_port, dst_port, protocol_byte);
        }
        17 => {
            let udp_off = ETH_HDR_LEN + IPV6_HDR_LEN;
            if data + udp_off + core::mem::size_of::<UdpHdr>() > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            let udp_hdr = &*((data + udp_off) as *const UdpHdr);
            let src_port = u16::from_be_bytes(udp_hdr.source);
            let dst_port = u16::from_be_bytes(udp_hdr.dest);
            let src_ip_hash = (src_addr as u32) ^ ((src_addr >> 32) as u32);
            let dst_ip_hash = (dst_addr as u32) ^ ((dst_addr >> 32) as u32);
            track_connection(src_ip_hash, dst_ip_hash, src_port, dst_port, protocol_byte);
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn check_rate_limit(src_ip: u32) -> bool {
    const MAX_TOKENS: u64 = 100;
    const REFILL_INTERVAL_NS: u64 = 1_000_000_000;

    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let bucket = match RATE_LIMIT_BUCKETS.get_ptr_mut(&src_ip) {
        Some(ptr) => ptr,
        None => {
            let new_val = ((now_ns as u64) << 32) | MAX_TOKENS;
            let _ = RATE_LIMIT_BUCKETS.insert(&src_ip, &new_val, 0);
            return true;
        }
    };

    let value = unsafe { *bucket };
    let tokens = (value & 0xFFFFFFFF) as u32;
    let last_refill = (value >> 32) as u64;

    let elapsed = now_ns.saturating_sub(last_refill);
    if elapsed >= REFILL_INTERVAL_NS {
        let new_val = ((now_ns as u64) << 32) | MAX_TOKENS;
        unsafe { *bucket = new_val };
        return true;
    }

    if tokens == 0 {
        return false;
    }

    let new_val = ((last_refill as u64) << 32) | ((tokens - 1) as u64);
    unsafe { *bucket = new_val };
    true
}

#[inline(always)]
fn track_connection(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) {
    let key: u64 = crate::pure::pack_conn_key(src_ip, dst_ip, src_port, dst_port, protocol);
    let value: u32 = ((protocol as u32) << 24) | (dst_ip & 0x00FF_FFFF);
    let _ = CONNTRACK.insert(&key, &value, 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
