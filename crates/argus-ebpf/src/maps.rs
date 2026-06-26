use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LpmTrie, PerCpuArray, PerfEventArray};

#[map]
pub static SRC_BLOCKLIST: LpmTrie<u32, u32> = LpmTrie::with_max_entries(65536, 0);

#[map]
pub static SRC_ALLOWLIST: LpmTrie<u32, u32> = LpmTrie::with_max_entries(65536, 0);

#[map]
pub static DST_BLOCKLIST: LpmTrie<u32, u32> = LpmTrie::with_max_entries(65536, 0);

#[map]
pub static DST_ALLOWLIST: LpmTrie<u32, u32> = LpmTrie::with_max_entries(65536, 0);

#[map]
pub static SRC_BLOCKLIST_V6: LpmTrie<u128, u32> = LpmTrie::with_max_entries(32768, 0);

#[map]
pub static SRC_ALLOWLIST_V6: LpmTrie<u128, u32> = LpmTrie::with_max_entries(32768, 0);

#[map]
pub static DST_BLOCKLIST_V6: LpmTrie<u128, u32> = LpmTrie::with_max_entries(32768, 0);

#[map]
pub static DST_ALLOWLIST_V6: LpmTrie<u128, u32> = LpmTrie::with_max_entries(32768, 0);

#[map]
pub static CONNTRACK: HashMap<u64, u32> = HashMap::with_max_entries(262144, 0);

#[map]
pub static RATE_LIMIT_BUCKETS: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

#[map]
pub static PER_CPU_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

#[map]
pub static EVENTS: PerfEventArray<[u8; 256]> = PerfEventArray::new(0);
