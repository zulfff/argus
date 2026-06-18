<script>
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/stores/auth';

  let entries = $state([]);
  let loading = $state(true);
  let error = $state('');
  let filterActor = $state('');
  let filterAction = $state('');
  let chainStatus = $state(null);

  onMount(async () => {
    try {
      const [data, chain] = await Promise.all([
        apiFetch('/audit').catch(() => []),
        apiFetch('/audit/chain').catch(() => null),
      ]);
      entries = Array.isArray(data) ? data : [];
      chainStatus = chain;
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  });

  let filtered = $derived.by(() => {
    let result = entries;
    if (filterActor) {
      const q = filterActor.toLowerCase();
      result = result.filter((e) => (e.actor || '').toLowerCase().includes(q));
    }
    if (filterAction) {
      const q = filterAction.toLowerCase();
      result = result.filter((e) => (e.action || '').toLowerCase().includes(q));
    }
    return result;
  });

  function exportAudit() {
    const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'argus-audit-export.json'; a.click();
    URL.revokeObjectURL(url);
  }
</script>

<div class="flex justify-between items-center mb-4 animate-in">
  <div>
    <h1 style="font-family:var(--font-display);font-size:18px;color:var(--text-heading);letter-spacing:2px;text-transform:uppercase;">
      📋 Audit Log
    </h1>
    <span style="font-size:10px;color:var(--text-muted);letter-spacing:1px;">
      {entries.length} ENTRIES
      {#if chainStatus}
        · CHAIN:
        <span class="badge" style={chainStatus.valid ? '' : 'background:var(--red-dim);color:var(--red);'}>
          {chainStatus.valid ? 'VALID' : 'BROKEN'}
        </span>
      {/if}
    </span>
  </div>
  <div class="flex gap-2">
    <button class="btn btn-ghost" onclick={exportAudit}>📥 EXPORT JSON</button>
  </div>
</div>

{#if loading}
  <div style="text-align:center;padding:40px;color:var(--text-muted);">LOADING...</div>
{:else if error}
  <div class="card mb-4">
    <p style="color:var(--red);">⚠ {error}</p>
  </div>
{:else}
  <div class="flex gap-4 mb-4 animate-in">
    <div style="flex:1;max-width:300px;">
      <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Filter Actor</label>
      <input class="input" bind:value={filterActor} placeholder="e.g. admin, system...">
    </div>
    <div style="flex:1;max-width:300px;">
      <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Filter Action</label>
      <input class="input" bind:value={filterAction} placeholder="e.g. create, delete...">
    </div>
  </div>

  {#if chainStatus}
    <div class="card mb-4 animate-in">
      <div class="card-header">
        <div class="indicator" style={chainStatus.valid ? 'background:var(--green);box-shadow:0 0 8px var(--green);' : 'background:var(--red);box-shadow:0 0 8px var(--red);'}></div>
        <h2>Chain Verification</h2>
      </div>
      <div style="display:flex;gap:16px;font-family:var(--font-mono);font-size:11px;">
        <div>
          <span style="color:var(--text-muted);">Status:</span>
          <span style="color:{chainStatus.valid ? 'var(--green)' : 'var(--red)'};margin-left:8px;">
            {chainStatus.valid ? '✓ INTACT' : '✗ BROKEN'}
          </span>
        </div>
        <div>
          <span style="color:var(--text-muted);">Entries:</span>
          <span style="color:var(--text-bright);margin-left:8px;">{chainStatus.count || chainStatus.entries || '—'}</span>
        </div>
        {#if chainStatus.last_hash}
          <div>
            <span style="color:var(--text-muted);">Last Hash:</span>
            <span style="color:var(--text-bright);margin-left:8px;font-size:10px;">{chainStatus.last_hash.slice(0, 16)}…</span>
          </div>
        {/if}
      </div>
    </div>
  {/if}

  <div class="card animate-in">
    <table class="data-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Actor</th>
          <th>Action</th>
          <th>Resource</th>
          <th>Details</th>
          <th>Integrity</th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as entry}
          <tr>
            <td style="color:var(--text-muted);font-size:11px;">
              {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '—'}
            </td>
            <td style="color:var(--text-bright);">{entry.actor || 'system'}</td>
            <td>
              {#if entry.action === 'create' || entry.action === 'allow'}
                <span class="badge allow">{entry.action}</span>
              {:else if entry.action === 'delete' || entry.action === 'deny'}
                <span class="badge deny">{entry.action}</span>
              {:else}
                <span class="badge info">{entry.action || '—'}</span>
              {/if}
            </td>
            <td style="color:var(--text-body);">{entry.resource || '—'}</td>
            <td style="color:var(--text-body);font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
              {entry.details || '—'}
            </td>
            <td>
              {#if entry.integrity_ok === false}
                <span class="badge deny">INVALID</span>
              {:else}
                <span class="badge on">OK</span>
              {/if}
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted);">
              {filterActor || filterAction ? 'NO ENTRIES MATCH YOUR FILTERS' : 'NO AUDIT ENTRIES'}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}