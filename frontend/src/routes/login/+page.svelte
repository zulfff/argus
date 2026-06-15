<script>
  import { authToken, authRole } from '$lib/stores/auth';
  import { goto } from '$app/navigation';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);

  async function login() {
    error = ''; loading = true;
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        error = data.error || 'Authentication failed';
        return;
      }
      $authToken = data.access_token;
      $authRole = data.role;
      goto('/dashboard');
    } catch (e) {
      error = 'Connection refused — is argus-api running?';
    } finally {
      loading = false;
    }
  }
</script>

<div class="login-container">
  <div class="login-card animate-in">
    <div class="login-logo">
      <h1>λRGUS</h1>
      <div class="subtitle">Firewall Control Interface</div>
    </div>

    <div style="display:flex;flex-direction:column;gap:16px;">
      <div>
        <label style="display:block;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text-muted);margin-bottom:6px;">Username</label>
        <input class="input" bind:value={username} placeholder="root@argus" autocomplete="username"
          onkeydown={(e) => e.key === 'Enter' && login()} />
      </div>

      <div>
        <label style="display:block;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text-muted);margin-bottom:6px;">Passphrase</label>
        <input class="input" bind:value={password} type="password" placeholder="••••••••••••" autocomplete="current-password"
          onkeydown={(e) => e.key === 'Enter' && login()} />
      </div>

      {#if error}
        <div style="padding:10px 14px;background:var(--red-dim);border:1px solid rgba(248,81,73,0.2);border-radius:var(--radius-sm);font-size:11px;color:var(--red);">
          ⚠ {error}
        </div>
      {/if}

      <button class="btn btn-primary" style="width:100%;justify-content:center;padding:12px;" onclick={login} disabled={loading}>
        {loading ? 'AUTHENTICATING...' : '>_ ESTABLISH CONNECTION'}
      </button>

      <p style="text-align:center;font-size:10px;color:var(--text-muted);margin-top:8px;">
        Default: admin / argus-admin &nbsp;|&nbsp; Change on first login
      </p>
    </div>
  </div>
</div>
