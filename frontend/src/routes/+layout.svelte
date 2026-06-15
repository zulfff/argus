<script>
  import '../app.css';
  import { authToken } from '$lib/stores/auth';

  let { children } = $props();
</script>

<div class="min-h-screen bg-gray-950 text-gray-100">
  <nav class="border-b border-gray-800 bg-gray-900 px-6 py-3">
    <div class="flex items-center gap-6">
      <a href="/dashboard" class="text-cyan-400 font-bold text-lg hover:text-cyan-300">ARGUS</a>
      <a href="/dashboard" class="text-sm hover:text-cyan-400">Dashboard</a>
      <a href="/rules" class="text-sm hover:text-cyan-400">Rules</a>
      <a href="/connections" class="text-sm hover:text-cyan-400">Connections</a>
      <div class="ml-auto text-xs text-gray-500">
        {#if $authToken}
          <span class="text-green-500 mr-2">authenticated</span>
          <button onclick={() => $authToken = null} class="text-red-400 hover:text-red-300">logout</button>
        {:else}
          <a href="/login" class="text-yellow-400 hover:text-yellow-300">login</a>
        {/if}
      </div>
    </div>
  </nav>
  <main class="p-6">
    {@render children()}
  </main>
</div>
