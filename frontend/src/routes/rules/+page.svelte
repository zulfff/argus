<script>
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/stores/auth';

  let rules = $state([]);
  let showForm = $state(false);
  let form = $state({ name: '', action: 'deny', direction: 'inbound', src_cidr: '', dst_cidr: '', protocol: '', src_port: '', dst_port: '', priority: 100, enabled: true });

  let search = $state('');
  let selected = $state(new Set());
  let currentPage = $state(1);
  const pageSize = 20;

  const ruleTemplates = [
    { name: 'Block SSH from WAN', action: 'deny', direction: 'inbound', src_cidr: '', dst_cidr: '', protocol: 'tcp', dst_port: '22', priority: 100 },
    { name: 'Allow HTTPS', action: 'allow', direction: 'inbound', src_cidr: '', dst_cidr: '', protocol: 'tcp', dst_port: '443', priority: 100 },
    { name: 'Block All Inbound', action: 'deny', direction: 'inbound', src_cidr: '0.0.0.0/0', dst_cidr: '', protocol: '', dst_port: '', priority: 100 },
    { name: 'Allow LAN', action: 'allow', direction: 'inbound', src_cidr: '10.0.0.0/8', dst_cidr: '', protocol: '', dst_port: '', priority: 100 },
    { name: 'Rate Limit DNS', action: 'rate-limit:100pps', direction: 'outbound', src_cidr: '', dst_cidr: '', protocol: 'udp', dst_port: '53', priority: 100 },
  ];

  let filtered = $derived(() => {
    const q = search.toLowerCase();
    if (!q) return rules;
    return rules.filter((r) =>
      (r.name || '').toLowerCase().includes(q) ||
      (r.src_cidr || '').toLowerCase().includes(q) ||
      (r.dst_cidr || '').toLowerCase().includes(q) ||
      (r.action || '').toLowerCase().includes(q) ||
      (r.protocol || '').toLowerCase().includes(q)
    );
  })();

  let totalPages = $derived(Math.max(1, Math.ceil(filtered.length / pageSize)));
  let paged = $derived(filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize));

  $effect(() => {
    if (currentPage > totalPages) currentPage = totalPages;
  });

  let allSelected = $derived(paged.length > 0 && paged.every((r) => selected.has(r.id)));
  let anySelected = $derived(selected.size > 0);

  function toggleAll() {
    if (allSelected) {
      for (const r of paged) selected.delete(r.id);
    } else {
      for (const r of paged) selected.add(r.id);
    }
    selected = new Set(selected);
  }

  function toggleOne(id) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    selected = next;
  }

  function applyTemplate(e) {
    const key = e.target.value;
    if (!key) return;
    const t = ruleTemplates[parseInt(key)];
    if (t) form = { ...t };
    e.target.value = '';
  }

  async function loadRules() {
    try { rules = await apiFetch('/rules'); selected = new Set(); } catch (e) { console.error(e); }
  }

  onMount(loadRules);

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
      form = { name: '', action: 'deny', direction: 'inbound', src_cidr: '', dst_cidr: '', protocol: '', src_port: '', dst_port: '', priority: 100, enabled: true };
      showForm = false;
      await loadRules();
    } catch (e) { alert('Error: ' + e.message); }
  }

  async function deleteRule(id) {
    if (!confirm('DROP rule ' + id + '?')) return;
    try {
      await apiFetch('/rules/' + id, { method: 'DELETE' });
      selected.delete(id); selected = new Set(selected);
      await loadRules();
    } catch (e) { alert('Error: ' + e.message); }
  }

  async function deleteSelected() {
    if (selected.size === 0) return;
    if (!confirm('DROP ' + selected.size + ' selected rules?')) return;
    try {
      await Promise.all([...selected].map((id) => apiFetch('/rules/' + id, { method: 'DELETE' })));
      await loadRules();
    } catch (e) { alert('Error: ' + e.message); }
  }

  async function toggleRule(id, enabled) {
    try {
      const rule = rules.find((r) => r.id === id);
      if (!rule) return;
      await apiFetch('/rules/' + id, { method: 'PUT', body: JSON.stringify({ ...rule, enabled }) });
      await loadRules();
    } catch (e) { alert('Error: ' + e.message); }
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify(rules, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'argus-rules-export.json'; a.click();
    URL.revokeObjectURL(url);
  }

  function importJSON() {
    const input = document.createElement('input');
    input.type = 'file'; input.accept = '.json';
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        const items = Array.isArray(data) ? data : [data];
        let imported = 0;
        for (const item of items) {
          await apiFetch('/rules', { method: 'POST', body: JSON.stringify(item) });
          imported++;
        }
        alert('Imported ' + imported + ' rules.');
        await loadRules();
      } catch (e) { alert('Import error: ' + e.message); }
    };
    input.click();
  }
</script>

<div class="flex justify-between items-center mb-4 animate-in">
  <div>
    <h1 style="font-family:var(--font-display);font-size:18px;color:var(--text-heading);letter-spacing:2px;text-transform:uppercase;">
      ⚙ Firewall Rules
    </h1>
    <span style="font-size:10px;color:var(--text-muted);letter-spacing:1px;">{rules.length} RULES LOADED</span>
  </div>
  <div class="flex gap-2">
    <button class="btn btn-ghost" onclick={exportJSON}>📥 EXPORT JSON</button>
    <button class="btn btn-ghost" onclick={importJSON}>📤 IMPORT JSON</button>
    <button class="btn btn-primary" onclick={() => showForm = !showForm}>
      {showForm ? '✕ CANCEL' : '+ ADD RULE'}
    </button>
  </div>
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
          <option value="rate-limit:100pps">RATE-LIMIT 100pps</option>
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
        <label style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);display:block;margin-bottom:4px;">Template</label>
        <select class="select" onchange={applyTemplate}>
          <option value="">— select template —</option>
          {#each ruleTemplates as t, i}
            <option value={i}>{t.name}</option>
          {/each}
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

<div class="flex gap-4 mb-4 animate-in flex-wrap items-center">
  <div style="flex:1;max-width:400px;">
    <input class="input" bind:value={search} placeholder="Search rules by name, CIDR, action, protocol...">
  </div>
  {#if anySelected}
    <button class="btn btn-danger" onclick={deleteSelected}>
      DELETE {selected.size} SELECTED
    </button>
  {/if}
  {#if totalPages > 1}
    <div class="pagination ml-2">
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
        <th style="width:30px;"><input class="checkbox" type="checkbox" checked={allSelected} onchange={toggleAll}></th>
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
      {#each paged as rule}
        <tr>
          <td><input class="checkbox" type="checkbox" checked={selected.has(rule.id)} onchange={() => toggleOne(rule.id)}></td>
          <td style="color:var(--text-muted);">{rule.priority}</td>
          <td style="color:var(--text-bright);">{rule.name}</td>
          <td>
            {#if rule.action === 'deny'}
              <span class="badge deny">DENY</span>
            {:else if rule.action && rule.action.startsWith('rate-limit')}
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
            <button
              class="badge"
              class:on={rule.enabled}
              class:off={!rule.enabled}
              style="cursor:pointer;border:none;"
              onclick={() => toggleRule(rule.id, !rule.enabled)}
              title="Toggle enable/disable"
            >
              {rule.enabled ? 'ON' : 'OFF'}
            </button>
          </td>
          <td class="text-right">
            <button class="btn btn-danger" style="padding:2px 8px;font-size:10px;" onclick={() => deleteRule(rule.id)}>
              DEL
            </button>
          </td>
        </tr>
      {:else}
        <tr>
          <td colspan="10" style="text-align:center;padding:32px;color:var(--text-muted);">
            {search ? 'NO RULES MATCH YOUR SEARCH' : "NO RULES DEFINED — Press '+ ADD RULE' to create your first firewall rule"}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>