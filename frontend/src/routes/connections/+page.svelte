<script>
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/stores/auth';

  let conns = $state([]);
  let refresh = $state(0);

  onMount(async () => {
    const load = async () => {
      try { conns = await apiFetch('/connections'); refresh = Date.now(); } catch {}
    };
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  });
</script>

<div class="flex justify-between items-center mb-6 animate-in">
  <div>
    <h1 style="font-family:var(--font-display);font-size:18px;color:var(--text-heading);letter-spacing:2px;text-transform:uppercase;">
      ⇄ Active Connections
    </h1>
    <span style="font-size:10px;color:var(--text-muted);letter-spacing:1px;">
      {conns.length} FLOWS TRACKED · REFRESH 3s · LAST: {new Date(refresh).toLocaleTimeString()}
    </span>
  </div>
  <div style="display:flex;align-items:center;gap:8px;font-size:11px;color:var(--text-muted);">
    <span class="status-dot online" style="display:inline-block;"></span>
    LIVE
  </div>
</div>

<div class="card animate-in">
  <table class="data-table">
    <thead>
      <tr>
        <th>Source IP</th>
        <th>Port</th>
        <th>→</th>
        <th>Destination IP</th>
        <th>Port</th>
        <th>Proto</th>
        <th>State</th>
      </tr>
    </thead>
    <tbody>
      {#each conns as conn}
        <tr>
          <td style="font-family:var(--font-mono);color:var(--text-bright);">{conn.src_ip}</td>
          <td style="color:var(--text-muted);">{conn.src_port}</td>
          <td style="color:var(--cyan);">→</td>
          <td style="font-family:var(--font-mono);color:var(--text-bright);">{conn.dst_ip}</td>
          <td style="color:var(--text-muted);">{conn.dst_port}</td>
          <td style="color:var(--text-muted);">{conn.protocol}</td>
          <td>
            {#if conn.state === 'established'}
              <span class="badge allow">{conn.state.toUpperCase()}</span>
            {:else if conn.state === 'new'}
              <span class="badge info">{conn.state.toUpperCase()}</span>
            {:else if conn.state === 'closed' || conn.state === 'closing'}
              <span class="badge off">{conn.state.toUpperCase()}</span>
            {:else}
              <span class="badge warn">{conn.state.toUpperCase()}</span>
            {/if}
          </td>
        </tr>
      {:else}
        <tr>
          <td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted);">
            <div style="font-size:24px;margin-bottom:8px;">∅</div>
            NO ACTIVE CONNECTIONS — waiting for traffic...
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
