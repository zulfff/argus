use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::xdp;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::XdpContext;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::maps::{
    CONNTRACK, DST_ALLOWLIST, DST_BLOCKLIST, PER_CPU_PACKETS, RATE_LIMIT_BUCKETS, SRC_ALLOWLIST,
    SRC_BLOCKLIST,
};

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
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + (ETH_HDR_LEN + IPV4_HDR_LEN) > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_hdr = data as *const EthHdr;
    let ether_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_hdr).ether_type)) };
    if ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = &*((data + ETH_HDR_LEN) as *const Ipv4Hdr);

    let src_ip = u32::from_be_bytes(ip_hdr.src_addr);
    let dst_ip = u32::from_be_bytes(ip_hdr.dst_addr);
    let protocol = ip_hdr.proto;

    if let Some(packets_ptr) = PER_CPU_PACKETS.get_ptr_mut(0) {
        *packets_ptr = (*packets_ptr).wrapping_add(1);
    }

    let src_key = Key::new(32, src_ip);
    let dst_key = Key::new(32, dst_ip);

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

    match protocol {
        IpProto::Tcp => {
            let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
            if data + tcp_off + core::mem::size_of::<TcpHdr>() > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
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
            let udp_hdr = &*((data + udp_off) as *const UdpHdr);
            let src_port = u16::from_be_bytes(udp_hdr.source);
            let dst_port = u16::from_be_bytes(udp_hdr.dest);
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

    let bucket = match RATE_LIMIT_BUCKETS.get_ptr_mut(&src_ip) {
            Some(ptr) => ptr,
            None => {
                let _ = RATE_LIMIT_BUCKETS.insert(&src_ip, &MAX_TOKENS, 0);
                return true;
            }
        };

    let value = unsafe { *bucket };
    let tokens = value & 0xFFFFFFFF;
    let last_refill = value >> 32;

    if now_ns >= last_refill + REFILL_INTERVAL_NS {
        let new_val = (now_ns << 32) | MAX_TOKENS;
        unsafe { *bucket = new_val };
        return true;
    }

    if tokens == 0 {
        return false;
    }

    let new_val = (last_refill << 32) | (tokens.saturating_sub(1));
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
