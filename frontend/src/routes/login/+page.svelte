<script>
  import { authToken, authRole } from '$lib/stores/auth';
  import { goto } from '$app/navigation';

  let username = $state('');
  let password = $state('');
  let error = $state('');

  async function login() {
    error = '';
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const err = await res.json();
        error = err.error || 'Login failed';
        return;
      }
      const data = await res.json();
      $authToken = data.access_token;
      $authRole = data.role;
      goto('/dashboard');
    } catch (e) {
      error = 'Connection failed';
    }
  }
</script>

<div class="max-w-sm mx-auto mt-20">
  <h1 class="text-2xl font-bold text-cyan-400 mb-6 text-center">ARGUS Login</h1>
  <div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
    <input bind:value={username} placeholder="Username" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-200 mb-3 text-sm">
    <input bind:value={password} type="password" placeholder="Password" class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-200 mb-4 text-sm">
    {#if error}
      <p class="text-red-400 text-xs mb-3">{error}</p>
    {/if}
    <button onclick={login} class="w-full bg-cyan-600 hover:bg-cyan-500 text-white py-2 rounded text-sm font-bold">
      Sign In
    </button>
  </div>
</div>
