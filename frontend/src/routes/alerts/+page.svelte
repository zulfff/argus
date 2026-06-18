<script>
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/stores/auth';

  let alertHistory = $state([]);
  let alertRules = $state([]);
  let loading = $state(true);
  let error = $state('');

  onMount(async () => {
    try {
      const [history, rules] = await Promise.all([
        apiFetch('/alerts/history').catch(() => []),
        apiFetch('/alerts/rules').catch(() => []),
      ]);
      alertHistory = Array.isArray(history) ? history : [];
      alertRules = Array.isArray(rules) ? rules : [];
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  });

  async function acknowledge(alertId) {
    try {
      await apiFetch('/alerts/history/' + alertId + '/ack', { method: 'POST' });
      alertHistory = alertHistory.map((a) => a.id === alertId ? { ...a, acknowledged: true } : a);
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  function severityBadge(sev) {
    if (sev === 'critical' || sev === 'high') return 'deny';
    if (sev === 'warning' || sev === 'medium') return 'warn';
    return 'info';
  }
</script>

<div class="flex justify-between items-center mb-4 animate-in">
  <div>
    <h1 style="font-family:var(--font-display);font-size:18px;color:var(--text-heading);letter-spacing:2px;text-transform:uppercase;">
      🔔 Alerts
    </h1>
    <span style="font-size:10px;color:var(--text-muted);letter-spacing:1px;">
      {alertHistory.length} ALERTS · {alertRules.length} RULES
    </span>
  </div>
</div>

{#if loading}
  <div style="text-align:center;padding:40px;color:var(--text-muted);">LOADING...</div>
{:else if error}
  <div class="card mb-4">
    <p style="color:var(--red);">⚠ {error}</p>
  </div>
{:else}
  <div class="grid grid-cols-2 gap-4 mb-4 animate-in">
    <div class="card">
      <div class="card-header">
        <div class="indicator" style="background:var(--red);box-shadow:0 0 8px var(--red);"></div>
        <h2>Alert Rules ({alertRules.length})</h2>
      </div>
      <div style="max-height: 400px; overflow-y: auto;">
        {#if alertRules.length === 0}
          <p style="color:var(--text-muted);font-size:12px;padding:16px 0;text-align:center;">NO ALERT RULES CONFIGURED</p>
        {:else}
          {#each alertRules as rule}
            <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-dim);font-size:12px;">
              <span style="color:var(--text-bright);font-family:var(--font-mono);">{rule.name || rule.id}</span>
              <span class="badge {severityBadge(rule.severity)}">{rule.severity || 'info'}</span>
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
        <div class="indicator" style="background:var(--yellow);box-shadow:0 0 8px var(--yellow);"></div>
        <h2>Alert History ({alertHistory.length})</h2>
      </div>
      <div style="max-height: 400px; overflow-y: auto;">
        {#if alertHistory.length === 0}
          <p style="color:var(--text-muted);font-size:12px;padding:16px 0;text-align:center;">NO ALERTS — all clear</p>
        {:else}
          {#each alertHistory.slice(0, 50) as al}
            <div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border-dim);font-size:11px;">
              <span class="badge {severityBadge(al.severity)}">{al.severity || 'info'}</span>
              <span style="color:var(--text-bright);flex:1;font-family:var(--font-mono);">{al.message || al.rule_name || al.id}</span>
              <span style="color:var(--text-muted);font-size:10px;">{al.timestamp ? new Date(al.timestamp).toLocaleTimeString() : ''}</span>
              {#if !al.acknowledged}
                <button class="btn btn-primary" style="padding:2px 8px;font-size:10px;" onclick={() => acknowledge(al.id)}>
                  ACK
                </button>
              {:else}
                <span class="badge on">ACKED</span>
              {/if}
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </div>

  <div class="card animate-in">
    <table class="data-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Message</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {#each alertHistory as al}
          <tr>
            <td style="color:var(--text-muted);font-size:11px;">
              {al.timestamp ? new Date(al.timestamp).toLocaleString() : '—'}
            </td>
            <td>
              <span class="badge {severityBadge(al.severity)}">{al.severity || 'info'}</span>
            </td>
            <td style="color:var(--text-bright);">{al.message || al.rule_name || '—'}</td>
            <td>
              {#if al.acknowledged}
                <span class="badge on">ACKED</span>
              {:else}
                <span class="badge warn">PENDING</span>
              {/if}
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="4" style="text-align:center;padding:32px;color:var(--text-muted);">
              No alert history
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}