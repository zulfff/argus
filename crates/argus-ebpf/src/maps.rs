#![no_std]

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, PerCpuArray, PerfEventArray};

#[map]
pub static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(65536, 0);

#[map]
pub static ALLOWLIST: HashMap<u32, u32> = HashMap::with_max_entries(65536, 0);

#[map]
pub static CONNTRACK: HashMap<u64, u32> = HashMap::with_max_entries(262144, 0);

#[map]
pub static RATE_LIMIT_BUCKETS: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

#[map]
pub static PER_CPU_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

#[map]
pub static EVENTS: PerfEventArray<[u8; 256]> = PerfEventArray::with_max_entries(4096, 0);
