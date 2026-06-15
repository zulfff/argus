<script>
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/stores/auth';

  let rules = $state([]);
  let showForm = $state(false);
  let form = $state({ name: '', action: 'deny', direction: 'inbound', src_cidr: '', dst_cidr: '', protocol: '', src_port: '', dst_port: '', priority: 100, enabled: true });

  onMount(async () => {
    try { rules = await apiFetch('/rules'); } catch (e) { console.error(e); }
  });

  async function createRule() {
    try {
      const payload = {
        name: form.name,
        action: form.action,
        direction: form.direction,
        src_cidr: form.src_cidr || null,
        dst_cidr: form.dst_cidr || null,
        src_port: form.src_port ? parseInt(form.src_port) : null,
        dst_port: form.dst_port ? parseInt(form.dst_port) : null,
        protocol: form.protocol || null,
        priority: form.priority,
        enabled: form.enabled,
      };
      await apiFetch('/rules', { method: 'POST', body: JSON.stringify(payload) });
      rules = await apiFetch('/rules');
      showForm = false;
      form = { name: '', action: 'deny', direction: 'inbound', src_cidr: '', dst_cidr: '', protocol: '', src_port: '', dst_port: '', priority: 100, enabled: true };
    } catch (e) { alert('Error: ' + e.message); }
  }

  async function deleteRule(id) {
    if (!confirm('DROP rule ' + id + '?')) return;
    try {
      await apiFetch('/rules/' + id, { method: 'DELETE' });
      rules = await apiFetch('/rules');
    } catch (e) { alert('Error: ' + e.message); }
  }
</script>

<div class="flex justify-between items-center mb-6 animate-in">
  <div>
    <h1 style="font-family:var(--font-display);font-size:18px;color:var(--text-heading);letter-spacing:2px;text-transform:uppercase;">
      ⚙ Firewall Rules
    </h1>
    <span style="font-size:10px;color:var(--text-muted);letter-spacing:1px;">{rules.length} RULES LOADED</span>
  </div>
  <button class="btn btn-primary" onclick={() => showForm = !showForm}>
    {showForm ? '✕ CANCEL' : '+ ADD RULE'}
  </button>
</div>

{#if showForm}
  <div class="card mb-4 animate-in">
    <div class="card-header">
      <div class="indicator" style="background:var(--yellow);"></div>
      <h2>New Rule — Configuration</h2>
    </div>
    <div class="grid grid-cols-4 gap-4">
      <div class="col-span-2">
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Rule Name</label>
        <input class="input" bind:value={form.name} placeholder="e.g. block-ssh-from-wan">
      </div>
      <div>
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Action</label>
        <select class="select" bind:value={form.action}>
          <option value="deny">DENY</option>
          <option value="allow">ALLOW</option>
        </select>
      </div>
      <div>
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Direction</label>
        <select class="select" bind:value={form.direction}>
          <option value="inbound">INBOUND</option>
          <option value="outbound">OUTBOUND</option>
          <option value="forward">FORWARD</option>
        </select>
      </div>
      <div>
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Source CIDR</label>
        <input class="input" bind:value={form.src_cidr} placeholder="0.0.0.0/0">
      </div>
      <div>
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Dest CIDR</label>
        <input class="input" bind:value={form.dst_cidr} placeholder="10.0.0.0/8">
      </div>
      <div>
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Protocol</label>
        <input class="input" bind:value={form.protocol} placeholder="tcp/udp/icmp">
      </div>
      <div>
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Port</label>
        <input class="input" bind:value={form.dst_port} placeholder="e.g. 22 or 443">
      </div>
      <div class="col-span-4 flex gap-4" style="padding-top:12px;">
        <button class="btn btn-primary" onclick={createRule}>DEPLOY RULE</button>
        <button class="btn btn-ghost" onclick={() => showForm = false}>DISCARD</button>
      </div>
    </div>
  </div>
{/if}

<div class="card animate-in">
  <table class="data-table">
    <thead>
      <tr>
        <th>#</th>
        <th>Name</th>
        <th>Action</th>
        <th>Source</th>
        <th>Dest</th>
        <th>Proto</th>
        <th>Dir</th>
        <th>Status</th>
        <th class="text-right">Ops</th>
      </tr>
    </thead>
    <tbody>
      {#each rules as rule, i}
        <tr>
          <td style="color:var(--text-muted);">{rule.priority}</td>
          <td style="color:var(--text-bright);">{rule.name}</td>
          <td>
            {#if rule.action === 'deny'}
              <span class="badge deny">DENY</span>
            {:else if rule.action.startsWith('rate-limit')}
              <span class="badge warn">LIMIT</span>
            {:else}
              <span class="badge allow">ALLOW</span>
            {/if}
          </td>
          <td style="color:var(--text-body);">{rule.src_cidr || '*'}</td>
          <td style="color:var(--text-body);">{rule.dst_cidr || '*'}</td>
          <td style="color:var(--text-muted);">{rule.protocol || 'any'}</td>
          <td style="color:var(--text-muted);">{rule.direction}</td>
          <td>
            <span class="badge" class:on={rule.enabled} class:off={!rule.enabled}>
              {rule.enabled ? 'ON' : 'OFF'}
            </span>
          </td>
          <td class="text-right">
            <button class="btn btn-danger" style="padding:2px 8px;font-size:10px;" onclick={() => deleteRule(rule.id)}>
              DEL
            </button>
          </td>
        </tr>
      {:else}
        <tr>
          <td colspan="9" style="text-align:center;padding:32px;color:var(--text-muted);">
            NO RULES DEFINED — Press '+ ADD RULE' to create your first firewall rule
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
