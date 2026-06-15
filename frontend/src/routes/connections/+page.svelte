<script>
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/stores/auth';

  let conns = $state([]);
  onMount(async () => {
    try { conns = await apiFetch('/connections'); } catch (e) { console.error(e); }
  });
</script>

<h1 class="text-lg font-bold text-gray-200 mb-4">Active Connections ({conns.length})</h1>
<div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden text-xs font-mono">
  <table class="w-full">
    <thead><tr class="bg-gray-800 text-gray-400 text-left">
      <th class="px-4 py-2">Source IP</th><th class="px-4 py-2">Port</th>
      <th class="px-4 py-2">Dest IP</th><th class="px-4 py-2">Port</th>
      <th class="px-4 py-2">Proto</th><th class="px-4 py-2">State</th>
    </tr></thead>
    <tbody>
      {#each conns as c}
        <tr class="border-t border-gray-800 hover:bg-gray-800/50">
          <td class="px-4 py-1.5 text-gray-300">{c.src_ip}</td>
          <td class="px-4 py-1.5 text-gray-400">{c.src_port}</td>
          <td class="px-4 py-1.5 text-gray-300">{c.dst_ip}</td>
          <td class="px-4 py-1.5 text-gray-400">{c.dst_port}</td>
          <td class="px-4 py-1.5 text-gray-500">{c.protocol}</td>
          <td class="px-4 py-1.5 text-cyan-400">{c.state}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
