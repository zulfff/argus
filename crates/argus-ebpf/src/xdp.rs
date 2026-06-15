#![no_std]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::maps::{ALLOWLIST, BLOCKLIST, CONNTRACK, PER_CPU_PACKETS, RATE_LIMIT_BUCKETS};

const ETH_HDR_LEN: usize = core::mem::size_of::<EthHdr>();
const IPV4_HDR_LEN: usize = core::mem::size_of::<Ipv4Hdr>();

#[xdp]
pub fn argus_firewall(ctx: XdpContext) -> u32 {
    match unsafe { try_argus_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn try_argus_firewall(ctx: XdpContext) -> Result<u32, u32> {
    // SAFETY: data/end pointers are set by the kernel's XDP dispatcher and
    // are valid for the duration of the program. Bounds checks below ensure
    // we never read past data_end.
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + (ETH_HDR_LEN + IPV4_HDR_LEN) > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: pointer is within [data, data_end) bounds verified above.
    // Ethernet header is 14 bytes, always valid in any XDP packet.
    let eth_hdr = &*(data as *const EthHdr);
    if eth_hdr.ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // SAFETY: pointer is within verified bounds — offset is ETH_HDR_LEN,
    // and we checked data + ETH_HDR_LEN + IPV4_HDR_LEN <= data_end above.
    let ip_hdr = &*((data + ETH_HDR_LEN) as *const Ipv4Hdr);

    let src_ip = u32::from_be(ip_hdr.src_addr);
    let dst_ip = u32::from_be(ip_hdr.dst_addr);
    let protocol = ip_hdr.proto;

    // SAFETY: PerCpuArray access from XDP runs in NAPI softirq with
    // preemption disabled — no concurrent access on the same CPU.
    if let Ok(Some(packets_ptr)) = PER_CPU_PACKETS.get_ptr_mut(0) {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Relaxed);
        *packets_ptr = (*packets_ptr).wrapping_add(1);
    }

    if BLOCKLIST.get(&src_ip).is_ok_and(|v| v.is_some()) {
        return Ok(xdp_action::XDP_DROP);
    }

    let allowlist_reserved = ALLOWLIST.get(&0u32);
    if allowlist_reserved.is_ok_and(|v| v.is_some()) {
        let in_allowlist = ALLOWLIST.get(&src_ip).is_ok_and(|v| v.is_some());
        let in_blocklist = BLOCKLIST.get(&src_ip).is_ok_and(|v| v.is_some());
        if !in_allowlist && !in_blocklist {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    if !check_rate_limit(src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    match protocol {
        IpProto::Tcp => {
            let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
            if data + tcp_off + core::mem::size_of::<TcpHdr>() > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            // SAFETY: bounds checked above.
            let tcp_hdr = &*((data + tcp_off) as *const TcpHdr);
            let src_port = u16::from_be(tcp_hdr.source);
            let dst_port = u16::from_be(tcp_hdr.dest);
            track_connection(src_ip, dst_ip, src_port, dst_port, protocol as u8);
        }
        IpProto::Udp => {
            let udp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
            if data + udp_off + core::mem::size_of::<UdpHdr>() > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            // SAFETY: bounds checked above.
            let udp_hdr = &*((data + udp_off) as *const UdpHdr);
            let src_port = u16::from_be(udp_hdr.source);
            let dst_port = u16::from_be(udp_hdr.dest);
            track_connection(src_ip, dst_ip, src_port, dst_port, protocol as u8);
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

    let bucket = unsafe {
        match RATE_LIMIT_BUCKETS.get_ptr_mut(&src_ip) {
            Ok(Some(ptr)) => ptr,
            _ => {
                let _ = RATE_LIMIT_BUCKETS.insert(&src_ip, &MAX_TOKENS, 0);
                return true;
            }
        }
    };

    // SAFETY: the bucket pointer is valid as long as this BPF program
    // holds the reference. XDP programs on the same CPU are serialized.
    let mut value = unsafe { *bucket };
    let tokens = value & 0xFFFFFFFF;
    let last_refill = value >> 32;

    if now_ns >= last_refill + REFILL_INTERVAL_NS {
        let new_val = (now_ns << 32) | MAX_TOKENS;
        // SAFETY: valid mutable pointer to BPF map value.
        unsafe { *bucket = new_val };
        return true;
    }

    if tokens == 0 {
        return false;
    }

    let new_val = (last_refill << 32) | (tokens.saturating_sub(1));
    // SAFETY: valid mutable pointer to BPF map value.
    unsafe { *bucket = new_val };
    true
}

#[inline(always)]
fn track_connection(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) {
    let key: u64 = pack_conn_key(src_ip, dst_ip, src_port, dst_port, protocol);
    let value: u32 = ((protocol as u32) << 24) | (dst_ip & 0x00FF_FFFF);
    let _ = CONNTRACK.insert(&key, &value, 0);
}

#[inline(always)]
fn pack_conn_key(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u64 {
    ((src_ip as u64) << 32)
        | ((dst_ip as u64 & 0xFFFF) << 16)
        | ((src_port as u64) << 8)
        | (dst_port as u64 >> 8)
        | ((protocol as u64) << 56)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
