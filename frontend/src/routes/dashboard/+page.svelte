<script>
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/stores/auth';

  let stats = $state({ packets_allowed: 0, packets_dropped: 0, active_connections: 0, blocked_ips: 0, rate_limit_buckets: 0 });
  let rules = $state([]);
  let conns = $state([]);
  let loading = $state(true);

  onMount(async () => {
    try {
      const [s, r, c] = await Promise.all([
        apiFetch('/stats'),
        apiFetch('/rules'),
        apiFetch('/connections'),
      ]);
      stats = s;
      rules = r;
      conns = c;
    } catch (e) {
      console.error('Failed to fetch dashboard data:', e);
    } finally {
      loading = false;
    }
  });

  const statCards = [
    { label: 'Packets Allowed', value: stats.packets_allowed, color: 'text-green-400' },
    { label: 'Packets Dropped', value: stats.packets_dropped, color: 'text-red-400' },
    { label: 'Active Connections', value: stats.active_connections, color: 'text-cyan-400' },
    { label: 'Blocked IPs', value: stats.blocked_ips, color: 'text-yellow-400' },
    { label: 'Rate Limit Buckets', value: stats.rate_limit_buckets, color: 'text-purple-400' },
  ];
</script>

{#if loading}
  <p class="text-gray-500">Loading...</p>
{:else}
  <div class="grid grid-cols-5 gap-4 mb-6">
    {#each statCards as card}
      <div class="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
        <p class="text-2xl font-mono {card.color}">{card.value.toLocaleString()}</p>
        <p class="text-xs text-gray-500 mt-1">{card.label}</p>
      </div>
    {/each}
  </div>

  <div class="grid grid-cols-2 gap-6">
    <div class="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h2 class="text-sm font-bold text-gray-400 mb-2">Firewall Rules ({rules.length})</h2>
      <div class="space-y-1 max-h-64 overflow-y-auto text-xs font-mono">
        {#each rules.slice(0, 20) as rule}
          <div class="flex justify-between py-1 border-b border-gray-800">
            <span class={rule.action === 'deny' ? 'text-red-400' : 'text-green-400'}>
              {rule.action}
            </span>
            <span class="text-gray-400">{rule.name}</span>
            <span class="text-gray-600">{rule.direction}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h2 class="text-sm font-bold text-gray-400 mb-2">Active Connections ({conns.length})</h2>
      <div class="space-y-1 max-h-64 overflow-y-auto text-xs font-mono">
        {#each conns.slice(0, 20) as conn}
          <div class="flex justify-between py-1 border-b border-gray-800">
            <span class="text-gray-300">{conn.src_ip}:{conn.src_port}</span>
            <span class="text-gray-600">→</span>
            <span class="text-gray-300">{conn.dst_ip}:{conn.dst_port}</span>
            <span class="text-cyan-400">{conn.state}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
{/if}
