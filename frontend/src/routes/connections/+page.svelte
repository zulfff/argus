<script>
  import { onMount } from 'svelte';
  import { apiFetch, authToken } from '$lib/stores/auth';
  import { liveConnections, wsConnected, connectWebSocket, disconnectWebSocket } from '$lib/stores/live';

  let conns = $state([]);
  let refresh = $state(0);
  let search = $state('');
  let currentPage = $state(1);
  const pageSize = 30;
  let wsFailed = $state(false);

  let showKillConfirm = $state(false);
  let killTarget = $state(null);

  function geoFlag(ip) {
    if (!ip) return '🌐';
    const parts = ip.split('.');
    const a = parseInt(parts[0]);
    if (a === 10) return '🏠';
    if (a === 172 && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) return '🏠';
    if (a === 192 && parseInt(parts[1]) === 168) return '🏠';
    if (a === 127) return '🏠';
    return '🌐';
  }

  let filtered = $derived.by(() => {
    const q = search.toLowerCase().trim();
    if (!q) return conns;
    return conns.filter((c) =>
      (c.src_ip || '').toLowerCase().includes(q) ||
      (c.dst_ip || '').toLowerCase().includes(q)
    );
  });

  let sorted = $derived.by(() => {
    const order = { established: 0, new: 1, closing: 3, closed: 4 };
    return [...filtered].sort((a, b) => {
      const sa = order[a.state] ?? 2;
      const sb = order[b.state] ?? 2;
      return sa - sb;
    });
  });

  let totalPages = $derived(Math.max(1, Math.ceil(sorted.length / pageSize)));
  let paged = $derived(sorted.slice((currentPage - 1) * pageSize, currentPage * pageSize));

  $effect(() => {
    if (currentPage > totalPages) currentPage = totalPages || 1;
  });

  function killConnection(conn) {
    killTarget = conn;
    showKillConfirm = true;
  }

  async function confirmKill() {
    if (!killTarget) return;
    try {
      await apiFetch('/connections/' + killTarget.id, { method: 'DELETE' });
    } catch (e) {
      console.error('Kill failed:', e);
    }
    showKillConfirm = false;
    killTarget = null;
  }

  function cancelKill() {
    showKillConfirm = false;
    killTarget = null;
  }

  async function pollData() {
    try {
      conns = await apiFetch('/connections');
      refresh = Date.now();
    } catch {}
  }

  onMount(() => {
    let token;
    authToken.subscribe((v) => { token = v; })();

    pollData();

    if (token) {
      connectWebSocket(token);

      const unsub = liveConnections.subscribe((c) => {
        if (c && c.length) {
          conns = c;
          refresh = Date.now();
        }
      });

      setTimeout(() => {
        if (!$wsConnected) wsFailed = true;
      }, 4000);

      const interval = setInterval(() => {
        if (wsFailed) pollData();
      }, 3000);

      return () => {
        disconnectWebSocket();
        clearInterval(interval);
        unsub();
      };
    } else {
      const interval = setInterval(pollData, 3000);
      return () => clearInterval(interval);
    }
  });
</script>

<div class="flex justify-between items-center mb-4 animate-in">
  <div>
    <h1 style="font-family:var(--font-display);font-size:18px;color:var(--text-heading);letter-spacing:2px;text-transform:uppercase;">
      ⇄ Active Connections
    </h1>
    <span style="font-size:10px;color:var(--text-muted);letter-spacing:1px;">
      {sorted.length} FLOWS TRACKED · LAST: {new Date(refresh).toLocaleTimeString()}
    </span>
  </div>
  <div style="display:flex;align-items:center;gap:8px;font-size:11px;color:var(--text-muted);">
    {#if $wsConnected}
      <span class="status-dot online" style="display:inline-block;"></span> WS LIVE
    {:else if wsFailed}
      <span class="status-dot warn" style="display:inline-block;"></span> POLLING
    {/if}
  </div>
</div>

<div class="flex gap-4 mb-4 animate-in flex-wrap items-center">
  <div style="flex:1;max-width:400px;">
    <input class="input" bind:value={search} placeholder="Search by IP address (src or dst)...">
  </div>
  {#if totalPages > 1}
    <div class="pagination">
      <button disabled={currentPage <= 1} onclick={() => currentPage = 1}>«</button>
      <button disabled={currentPage <= 1} onclick={() => currentPage--}>‹</button>
      {#each Array(totalPages) as _, i}
        {#if i < 3 || i >= totalPages - 3 || Math.abs(i + 1 - currentPage) <= 1}
          <button class:active={currentPage === i + 1} onclick={() => currentPage = i + 1}>{i + 1}</button>
        {:else if i === 3 || i === totalPages - 4}
          <span>…</span>
        {/if}
      {/each}
      <button disabled={currentPage >= totalPages} onclick={() => currentPage++}>›</button>
      <button disabled={currentPage >= totalPages} onclick={() => currentPage = totalPages}>»</button>
    </div>
  {/if}
</div>

<div class="card animate-in">
  <table class="data-table">
    <thead>
      <tr>
        <th></th>
        <th>Source IP</th>
        <th>Port</th>
        <th>→</th>
        <th>Destination IP</th>
        <th>Port</th>
        <th>Proto</th>
        <th>State</th>
        <th class="text-right">Ops</th>
      </tr>
    </thead>
    <tbody>
      {#each paged as conn}
        <tr>
          <td style="font-size:14px;">{geoFlag(conn.src_ip)}</td>
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
          <td class="text-right">
            <button class="btn btn-danger" style="padding:2px 8px;font-size:10px;" onclick={() => killConnection(conn)}>
              KILL
            </button>
          </td>
        </tr>
      {:else}
        <tr>
          <td colspan="9" style="text-align:center;padding:32px;color:var(--text-muted);">
            <div style="font-size:24px;margin-bottom:8px;">∅</div>
            {search ? 'NO CONNECTIONS MATCH YOUR SEARCH' : 'NO ACTIVE CONNECTIONS — waiting for traffic...'}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

{#if showKillConfirm}
  <div class="confirm-overlay" onclick={cancelKill}>
    <div class="confirm-dialog" onclick={(e) => e.stopPropagation()}>
      <h3 style="font-family:var(--font-display);color:var(--text-heading);margin-bottom:12px;text-transform:uppercase;letter-spacing:1px;">⚠ Kill Connection</h3>
      <p style="color:var(--text-body);font-size:12px;margin-bottom:16px;">
        Are you sure you want to terminate<br>
        <strong style="color:var(--text-bright);">{killTarget?.src_ip}:{killTarget?.src_port}</strong> → <strong style="color:var(--text-bright);">{killTarget?.dst_ip}:{killTarget?.dst_port}</strong>?
      </p>
      <div class="flex gap-2 justify-between">
        <button class="btn btn-primary" onclick={confirmKill}>CONFIRM KILL</button>
        <button class="btn btn-ghost" onclick={cancelKill}>CANCEL</button>
      </div>
    </div>
  </div>
{/if}