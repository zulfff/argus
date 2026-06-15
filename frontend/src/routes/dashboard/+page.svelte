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
      stats = s; rules = r; conns = c;
    } catch (e) {
      console.error('Dashboard fetch failed:', e);
    } finally {
      loading = false;
    }

    const interval = setInterval(async () => {
      try { stats = await apiFetch('/stats'); } catch {}
      try { conns = await apiFetch('/connections'); } catch {}
    }, 5000);
    return () => clearInterval(interval);
  });
</script>

{#if loading}
  <div style="display:flex;align-items:center;justify-content:center;height:60vh;color:var(--text-muted);">
    <span style="animation:pulse 2s infinite;">▌&nbsp;INITIALIZING...</span>
  </div>
{:else}
  <div class="stat-grid animate-in">
    <div class="stat-card green">
      <div class="stat-value">{stats.packets_allowed.toLocaleString()}</div>
      <div class="stat-label">Packets Allowed</div>
    </div>
    <div class="stat-card red">
      <div class="stat-value">{stats.packets_dropped.toLocaleString()}</div>
      <div class="stat-label">Packets Dropped</div>
    </div>
    <div class="stat-card cyan">
      <div class="stat-value">{stats.active_connections}</div>
      <div class="stat-label">Active Connections</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-value">{stats.blocked_ips}</div>
      <div class="stat-label">Blocked IPs</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-value">{stats.rate_limit_buckets}</div>
      <div class="stat-label">Rate Limit Buckets</div>
    </div>
  </div>

  <div class="grid grid-cols-2 gap-4 animate-in" style="animation-delay: 0.1s;">
    <div class="card">
      <div class="card-header">
        <div class="indicator"></div>
        <h2>Firewall Rules ({rules.length})</h2>
      </div>
      <div style="max-height: 300px; overflow-y: auto;">
        {#if rules.length === 0}
          <p style="color:var(--text-muted);font-size:12px;padding:16px 0;text-align:center;">NO RULES CONFIGURED</p>
        {:else}
          {#each rules.slice(0, 15) as rule}
            <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-dim);font-size:12px;" class="animate-in">
              <span style="font-family:var(--font-mono);">
                {#if rule.action === 'deny'}
                  <span class="badge deny">DENY</span>
                {:else if rule.action.startsWith('rate-limit')}
                  <span class="badge warn">LIMIT</span>
                {:else}
                  <span class="badge allow">ALLOW</span>
                {/if}
              </span>
              <span style="color:var(--text-body);flex:1;margin-left:12px;">{rule.name}</span>
              <span style="color:var(--text-muted);font-size:11px;">{rule.direction}</span>
              <span class="badge" class:on={rule.enabled} class:off={!rule.enabled}>
                {rule.enabled ? 'ON' : 'OFF'}
              </span>
            </div>
          {/each}
        {/if}
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="indicator" style="background:var(--green);box-shadow:0 0 8px var(--green),0 0 16px rgba(63,185,80,0.3);"></div>
        <h2>Active Connections ({conns.length})</h2>
      </div>
      <div style="max-height: 300px; overflow-y: auto;">
        {#if conns.length === 0}
          <p style="color:var(--text-muted);font-size:12px;padding:16px 0;text-align:center;">NO ACTIVE CONNECTIONS</p>
        {:else}
          {#each conns.slice(0, 15) as conn}
            <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border-dim);font-size:11px;font-family:var(--font-mono);">
              <span style="color:var(--text-body);">{conn.src_ip}:{conn.src_port}</span>
              <span style="color:var(--text-muted);">→</span>
              <span style="color:var(--text-body);">{conn.dst_ip}:{conn.dst_port}</span>
              <span style="margin-left:auto;color:var(--cyan);">{conn.state.toUpperCase()}</span>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </div>
{/if}
