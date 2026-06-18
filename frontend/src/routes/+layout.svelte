<script>
  import '../app.css';
  import { page } from '$app/stores';
  import { authToken, apiFetch } from '$lib/stores/auth';
  import { theme } from '$lib/stores/theme';

  let { children } = $props();

  let apiStatus = $state(true);

  function toggleTheme() {
    $theme = $theme === 'dark' ? 'light' : 'dark';
  }

  $effect(() => {
    document.documentElement.setAttribute('data-theme', $theme);
  });

  $effect(() => {
    const check = async () => {
      try {
        const res = await fetch('/health');
        apiStatus = res.ok;
      } catch {
        apiStatus = false;
      }
    };
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  });
</script>

<header class="shell">
  <div class="shell-dots">
    <div class="shell-dot red"></div>
    <div class="shell-dot yellow"></div>
    <div class="shell-dot green"></div>
  </div>

  <span class="shell-path">
    <span class="prompt">❯</span>
    <span class="tilda">~/argus</span>
    /{$page.url.pathname.replace('/', '') || 'dashboard'}
  </span>

  <span style="margin-left: 16px; font-size: 11px; color: var(--text-muted);" class="shell-path">
    <span class="status-dot online" style="display:inline-block;margin-right:6px;"></span>
    {apiStatus ? 'API ONLINE' : 'API OFFLINE'}
  </span>

  <nav class="nav-links">
    <a href="/dashboard"   class="nav-link" class:active={$page.url.pathname.startsWith('/dashboard')}>   ⚡ DASH</a>
    <a href="/rules"       class="nav-link" class:active={$page.url.pathname.startsWith('/rules')}>       ⚙ RULES</a>
    <a href="/connections" class="nav-link" class:active={$page.url.pathname.startsWith('/connections')}> ⇄ CONN</a>
    <a href="/alerts"      class="nav-link" class:active={$page.url.pathname.startsWith('/alerts')}>      🔔 ALERTS</a>
    <a href="/audit"       class="nav-link" class:active={$page.url.pathname.startsWith('/audit')}>       📋 AUDIT</a>
    <a href="/docs"        class="nav-link" class:active={$page.url.pathname.startsWith('/docs')}>        📖 DOCS</a>
    {#if $authToken}
      <a href="/login" class="nav-link" onclick={() => $authToken = null}>⏻ LOGOUT</a>
    {:else}
      <a href="/login" class="nav-link">🔐 LOGIN</a>
    {/if}
    <button class="theme-toggle" onclick={toggleTheme} title="Toggle theme">
      {$theme === 'dark' ? '☀' : '🌙'}
    </button>
  </nav>
</header>

<main style="padding: 24px; position: relative; z-index: 1; max-width: 1400px; margin: 0 auto;">
  {@render children()}
</main>

<footer class="status-bar">
  <div class="status-item">
    <span class="status-dot" class:online={apiStatus} class:warn={!apiStatus}></span>
    <span>argus-api v0.1.0</span>
  </div>
  <div class="status-item">
    <span>kernel 5.15+</span>
  </div>
  <div class="status-item">
    <span>eBPF</span>
    <span class="status-dot online"></span>
  </div>
  <div class="status-item">
    <span>{new Date().toLocaleTimeString()}</span>
  </div>
</footer>