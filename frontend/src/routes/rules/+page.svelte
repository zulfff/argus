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
    } catch (e) { alert('Failed: ' + e.message); }
  }

  async function deleteRule(id) {
    if (!confirm('Delete rule?')) return;
    try {
      await apiFetch(`/rules/${id}`, { method: 'DELETE' });
      rules = await apiFetch('/rules');
    } catch (e) { alert('Failed: ' + e.message); }
  }
</script>

<div class="flex justify-between items-center mb-4">
  <h1 class="text-lg font-bold text-gray-200">Firewall Rules ({rules.length})</h1>
  <button onclick={() => (showForm = !showForm)} class="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-1.5 rounded text-sm">
    + Add Rule
  </button>
</div>

{#if showForm}
  <div class="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4 grid grid-cols-4 gap-3 text-sm">
    <input bind:value={form.name} placeholder="Rule name" class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-gray-200 col-span-2">
    <select bind:value={form.action} class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-gray-200">
      <option value="deny">deny</option>
      <option value="allow">allow</option>
    </select>
    <select bind:value={form.direction} class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-gray-200">
      <option value="inbound">inbound</option>
      <option value="outbound">outbound</option>
      <option value="forward">forward</option>
    </select>
    <input bind:value={form.src_cidr} placeholder="Source CIDR (optional)" class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-gray-200">
    <input bind:value={form.dst_cidr} placeholder="Dest CIDR (optional)" class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-gray-200">
    <input bind:value={form.protocol} placeholder="Protocol (tcp/udp/icmp)" class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-gray-200">
    <input bind:value={form.src_port} placeholder="Src port" class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-gray-200">
    <div class="col-span-4 flex gap-3">
      <button onclick={createRule} class="bg-green-600 hover:bg-green-500 text-white px-4 py-1.5 rounded">Save</button>
      <button onclick={() => (showForm = false)} class="bg-gray-700 hover:bg-gray-600 text-white px-4 py-1.5 rounded">Cancel</button>
    </div>
  </div>
{/if}

<div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden text-xs font-mono">
  <table class="w-full">
    <thead>
      <tr class="bg-gray-800 text-gray-400 text-left">
        <th class="px-4 py-2">Pri</th>
        <th class="px-4 py-2">Name</th>
        <th class="px-4 py-2">Action</th>
        <th class="px-4 py-2">Source</th>
        <th class="px-4 py-2">Dest</th>
        <th class="px-4 py-2">Proto</th>
        <th class="px-4 py-2">Dir</th>
        <th class="px-4 py-2">Status</th>
        <th class="px-4 py-2"></th>
      </tr>
    </thead>
    <tbody>
      {#each rules as rule}
        <tr class="border-t border-gray-800 hover:bg-gray-800/50">
          <td class="px-4 py-1.5 text-gray-500">{rule.priority}</td>
          <td class="px-4 py-1.5 text-gray-300">{rule.name}</td>
          <td class="px-4 py-1.5"><span class={rule.action === 'deny' ? 'text-red-400' : 'text-green-400'}>{rule.action}</span></td>
          <td class="px-4 py-1.5 text-gray-400">{rule.src_cidr || '*'}</td>
          <td class="px-4 py-1.5 text-gray-400">{rule.dst_cidr || '*'}</td>
          <td class="px-4 py-1.5 text-gray-400">{rule.protocol || 'any'}</td>
          <td class="px-4 py-1.5 text-gray-500">{rule.direction}</td>
          <td class="px-4 py-1.5"><span class={rule.enabled ? 'text-green-400' : 'text-red-400'}>{rule.enabled ? 'ON' : 'OFF'}</span></td>
          <td class="px-4 py-1.5">
            <button onclick={() => deleteRule(rule.id)} class="text-red-500 hover:text-red-300">del</button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
