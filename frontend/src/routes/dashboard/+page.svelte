<script>
  import { onMount } from 'svelte';
  import { apiFetch, authToken } from '$lib/stores/auth';
  import { liveStats, liveConnections, wsConnected, connectWebSocket, disconnectWebSocket } from '$lib/stores/live';
  import { Line, Bar, Doughnut } from 'svelte-chartjs';
  import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    BarElement,
    ArcElement,
    Title,
    Tooltip,
    Legend,
    Filler
  } from 'chart.js';

  ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Title, Tooltip, Legend, Filler);

  let stats = $state({ packets_allowed: 0, packets_dropped: 0, active_connections: 0, blocked_ips: 0, rate_limit_buckets: 0 });
  let rules = $state([]);
  let conns = $state([]);
  let loading = $state(true);

  let trafficHistory = $state({ allowed: Array(20).fill(0), dropped: Array(20).fill(0), labels: Array(20).fill('') });
  let blockedIPs = $state({ labels: [], data: [] });
  let protoDistribution = $state({ labels: ['TCP', 'UDP', 'ICMP', 'Other'], data: [0, 0, 0, 0] });

  let wsFailed = $state(false);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#8b949e', font: { family: "'JetBrains Mono', monospace", size: 10 } } } },
    scales: { x: { ticks: { color: '#5c6370', maxTicksLimit: 10 }, grid: { color: 'rgba(30,37,51,0.5)' } }, y: { ticks: { color: '#5c6370' }, grid: { color: 'rgba(30,37,51,0.5)' }, beginAtZero: true } }
  };

  function updateTrafficHistory(allowed, dropped) {
    trafficHistory.allowed = [...trafficHistory.allowed.slice(1), allowed];
    trafficHistory.dropped = [...trafficHistory.dropped.slice(1), dropped];
    const now = new Date();
    trafficHistory.labels = [...trafficHistory.labels.slice(1), now.toLocaleTimeString('en-US', { hour12: false })];
  }

  function computeBlockedIPs(connections) {
    const ipCounts = {};
    for (const c of connections) {
      if (c.state === 'closed' || c.state === 'closing') {
        ipCounts[c.src_ip] = (ipCounts[c.src_ip] || 0) + 1;
      }
    }
    const sorted = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    blockedIPs = { labels: sorted.map(([ip]) => ip), data: sorted.map(([, n]) => n) };
  }

  function computeProtoDistribution(connections) {
    let tcp = 0, udp = 0, icmp = 0, other = 0;
    for (const c of connections) {
      const p = (c.protocol || '').toLowerCase();
      if (p === 'tcp') tcp++;
      else if (p === 'udp') udp++;
      else if (p === 'icmp') icmp++;
      else other++;
    }
    protoDistribution = { labels: ['TCP', 'UDP', 'ICMP', 'Other'], data: [tcp, udp, icmp, other] };
  }

  async function pollData() {
    try {
      const [s, r, c] = await Promise.all([
        apiFetch('/stats'),
        apiFetch('/rules'),
        apiFetch('/connections'),
      ]);
      stats = s;
      rules = r;
      conns = c;
      updateTrafficHistory(s.packets_allowed, s.packets_dropped);
      computeBlockedIPs(c);
      computeProtoDistribution(c);
    } catch (e) {
      console.error('Dashboard fetch failed:', e);
    }
  }

  onMount(() => {
    let token;
    authToken.subscribe((v) => { token = v; })();

    pollData().then(() => { loading = false; });

    if (token) {
      connectWebSocket(token);
      const unsubWs = wsConnected.subscribe((connected) => {
        if (connected) wsFailed = false;
      });

      const unsubStats = liveStats.subscribe((s) => {
        if (s) {
          stats = s;
          updateTrafficHistory(s.packets_allowed, s.packets_dropped);
        }
      });

      const unsubConns = liveConnections.subscribe((c) => {
        if (c && c.length) {
          conns = c;
          computeBlockedIPs(c);
          computeProtoDistribution(c);
        }
      });

      setTimeout(() => {
        if (!$wsConnected) wsFailed = true;
      }, 4000);

      const interval = setInterval(() => {
        if (wsFailed) pollData();
      }, 5000);

      return () => {
        disconnectWebSocket();
        clearInterval(interval);
        unsubWs();
        unsubStats();
        unsubConns();
      };
    } else {
      const interval = setInterval(pollData, 5000);
      return () => clearInterval(interval);
    }
  });
</script>

{#if loading}
  <div style="display:flex;align-items:center;justify-content:center;height:60vh;color:var(--text-muted);">
    <span style="animation:pulse 2s infinite;">▌&nbsp;INITIALIZING...</span>
  </div>
{:else}
  <div class="flex items-center justify-between mb-4 animate-in">
    <div>
      <h1 style="font-family:var(--font-display);font-size:18px;color:var(--text-heading);letter-spacing:2px;text-transform:uppercase;">
        ⚡ Dashboard
      </h1>
      <span style="font-size:10px;color:var(--text-muted);letter-spacing:1px;">
        LIVE MONITORING
        {#if $wsConnected}
          <span class="status-dot online" style="display:inline-block;margin-left:8px;"></span> WS
        {:else if wsFailed}
          <span class="status-dot warn" style="display:inline-block;margin-left:8px;"></span> POLLING
        {/if}
      </span>
    </div>
  </div>

  <div class="stat-grid animate-in">
    <div class="stat-card green">
      <div class="stat-value">{stats.packets_allowed.toLocaleString()}</div>
      <div class="stat-label">Packets Allowed</div>
    </div>
    <div class="stat-card red">
      <div class="stat-value">{stats.packets_dropped.toLocaleString()}</div>
      <div class="stat-label">Packets Dropped</div>
    </div>
    <div class="stat-card cyan">
      <div class="stat-value">{stats.active_connections}</div>
      <div class="stat-label">Active Connections</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-value">{stats.blocked_ips}</div>
      <div class="stat-label">Blocked IPs</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-value">{stats.rate_limit_buckets}</div>
      <div class="stat-label">Rate Limit Buckets</div>
    </div>
  </div>

  <div class="grid grid-cols-2 gap-4 mb-4 animate-in" style="animation-delay:0.1s;">
    <div class="card col-span-2">
      <div class="card-header">
        <div class="indicator"></div>
        <h2>Traffic — Packets Allowed vs Dropped</h2>
      </div>
      <div style="height: 240px;">
        <Line
          data={{
            labels: trafficHistory.labels,
            datasets: [
              { label: 'Allowed', data: trafficHistory.allowed, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0.3, pointRadius: 0 },
              { label: 'Dropped', data: trafficHistory.dropped, borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.1)', fill: true, tension: 0.3, pointRadius: 0 }
            ]
          }}
          options={chartOptions}
        />
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="indicator" style="background:var(--purple);box-shadow:0 0 8px var(--purple);"></div>
        <h2>Protocol Distribution</h2>
      </div>
      <div style="height: 240px;">
        <Doughnut
          data={{
            labels: protoDistribution.labels,
            datasets: [{ data: protoDistribution.data, backgroundColor: ['#39d0ff', '#a371f7', '#f0883e', '#5c6370'], borderColor: 'var(--bg-card)', borderWidth: 2 }]
          }}
          options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font: { family: "'JetBrains Mono', monospace", size: 10 }, padding: 12 } } } }}
        />
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="indicator" style="background:var(--red);box-shadow:0 0 8px var(--red);"></div>
        <h2>Top Blocked IPs</h2>
      </div>
      <div style="height: 240px;">
        {#if blockedIPs.labels.length > 0}
          <Bar
            data={{
              labels: blockedIPs.labels,
              datasets: [{ label: 'Blocks', data: blockedIPs.data, backgroundColor: 'rgba(248,81,73,0.6)', borderColor: '#f85149', borderWidth: 1, borderRadius: 2 }]
            }}
            options={{
              indexAxis: 'y',
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { display: false } },
              scales: { x: { ticks: { color: '#5c6370' }, grid: { color: 'rgba(30,37,51,0.5)' } }, y: { ticks: { color: '#8b949e', font: { family: "'JetBrains Mono', monospace", size: 9 } }, grid: { display: false } } }
            }}
          />
        {:else}
          <div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:11px;">
            NO BLOCKED IPs YET
          </div>
        {/if}
      </div>
    </div>
  </div>

  <div class="grid grid-cols-2 gap-4 animate-in" style="animation-delay: 0.15s;">
    <div class="card">
      <div class="card-header">
        <div class="indicator"></div>
        <h2>Firewall Rules ({rules.length})</h2>
      </div>
      <div style="max-height: 300px; overflow-y: auto;">
        {#if rules.length === 0}
          <p style="color:var(--text-muted);font-size:12px;padding:16px 0;text-align:center;">NO RULES CONFIGURED</p>
        {:else}
          {#each rules.slice(0, 15) as rule}
            <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-dim);font-size:12px;" class="animate-in">
              <span style="font-family:var(--font-mono);">
                {#if rule.action === 'deny'}
                  <span class="badge deny">DENY</span>
                {:else if rule.action && rule.action.startsWith('rate-limit')}
                  <span class="badge warn">LIMIT</span>
                {:else}
                  <span class="badge allow">ALLOW</span>
                {/if}
              </span>
              <span style="color:var(--text-body);flex:1;margin-left:12px;">{rule.name}</span>
              <span style="color:var(--text-muted);font-size:11px;">{rule.direction}</span>
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
        <div class="indicator" style="background:var(--green);box-shadow:0 0 8px var(--green),0 0 16px rgba(63,185,80,0.3);"></div>
        <h2>Active Connections ({conns.length})</h2>
      </div>
      <div style="max-height: 300px; overflow-y: auto;">
        {#if conns.length === 0}
          <p style="color:var(--text-muted);font-size:12px;padding:16px 0;text-align:center;">NO ACTIVE CONNECTIONS</p>
        {:else}
          {#each conns.slice(0, 15) as conn}
            <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border-dim);font-size:11px;font-family:var(--font-mono);">
              <span style="color:var(--text-body);">{conn.src_ip}:{conn.src_port}</span>
              <span style="color:var(--text-muted);">→</span>
              <span style="color:var(--text-body);">{conn.dst_ip}:{conn.dst_port}</span>
              <span style="margin-left:auto;color:var(--cyan);">{conn.state ? conn.state.toUpperCase() : '?'}</span>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </div>
{/if}