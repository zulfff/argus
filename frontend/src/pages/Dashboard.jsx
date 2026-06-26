import { useState, useEffect, useRef, useCallback } from 'react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import * as api from '../api.js';
import { PageHeader, LoadingError } from '../components/Shared.jsx';

const cardCls = "bg-white border border-[var(--color-bg-border)] rounded-lg p-5 shadow-[var(--shadow-sm)] hover:shadow-[var(--shadow-md)] transition-shadow";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);
  const [liveEvents, setLiveEvents] = useState([]);
  const [packetWindow, setPacketWindow] = useState([]);
  const windowRef = useRef([]);

  const fetchStats = useCallback(async () => {
    try {
      const s = await api.stats.get();
      setStats(s);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  useEffect(() => {
    const cleanup = api.connectWebSocket((msg) => {
      setLiveEvents((prev) => [...prev, msg].slice(-20));
      if (msg.event_type === 'packet' && msg.data?.action) {
        const now = Date.now();
        windowRef.current.push({ t: now, action: msg.data.action });
        windowRef.current = windowRef.current.filter((e) => now - e.t < 10000);
        
        const counts = windowRef.current.reduce((acc, e) => {
          acc[e.action] = (acc[e.action] || 0) + 1;
          return acc;
        }, {});
        setPacketWindow([
          { label: 'Allowed', value: counts.allow || 0 },
          { label: 'Denied', value: counts.deny || 0 },
          { label: 'Limited', value: counts['rate-limit'] || 0 },
        ]);
      }
    });
    return () => { if (cleanup && typeof cleanup === 'function') cleanup(); };
  }, []);

  if (error) return <LoadingError message={error} onRetry={fetchStats} />;
  if (!stats) return <div className="flex items-center justify-center py-20"><div className="animate-shimmer w-32 h-8 rounded"></div></div>;

  const chartData = [
    { name: 'Allowed', value: stats.packets_allowed || 0, color: 'var(--color-success)' },
    { name: 'Denied', value: stats.packets_dropped || 0, color: 'var(--color-danger)' },
    { name: 'Limited', value: stats.packets_rate_limited || 0, color: 'var(--color-warning)' },
  ];

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Real-time network monitoring and statistics" />

      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Active Connections" value={stats.active_connections?.toLocaleString() || '0'} icon="🔗" color="primary" />
        <StatCard label="Packets Allowed" value={stats.packets_allowed?.toLocaleString() || '0'} icon="✓" color="success" />
        <StatCard label="Packets Denied" value={stats.packets_dropped?.toLocaleString() || '0'} icon="✗" color="danger" />
        <StatCard label="Rate Limited" value={stats.packets_rate_limited?.toLocaleString() || '0'} icon="⚠" color="warning" />
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className={cardCls}>
          <div className="text-[var(--color-text)] text-sm font-semibold mb-4">Packet Distribution</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2}>
                {chartData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: 'white', border: '1px solid var(--color-bg-border)', borderRadius: 8, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className={cardCls}>
          <div className="text-[var(--color-text)] text-sm font-semibold mb-4">Live Traffic (10s window)</div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={packetWindow}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-bg-border)" />
              <XAxis dataKey="label" tick={{ fontSize: 11, fill: 'var(--color-text-sec)' }} />
              <YAxis tick={{ fontSize: 11, fill: 'var(--color-text-sec)' }} />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid var(--color-bg-border)', borderRadius: 8, fontSize: 12 }} />
              <Line type="monotone" dataKey="value" stroke="var(--color-primary)" strokeWidth={2} dot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className={cardCls}>
        <div className="text-[var(--color-text)] text-sm font-semibold mb-4">Live Event Feed</div>
        <div className="max-h-80 overflow-y-auto space-y-2">
          {liveEvents.length === 0 ? (
            <div className="text-[var(--color-text-sec)] text-center py-8 text-sm">Waiting for events...</div>
          ) : (
            liveEvents.slice(-15).reverse().map((e, i) => (
              <div key={i} className="flex gap-3 py-2.5 px-3 border-b border-[var(--color-bg-border)] last:border-0 items-center hover:bg-[var(--color-bg-hover)] transition-colors rounded-lg">
                <EventIcon type={e.event_type} />
                <span className="text-xs text-[var(--color-text-sec)] text-mono min-w-[70px]">{new Date(e.timestamp).toLocaleTimeString()}</span>
                <span className="text-sm text-[var(--color-text)] flex-1">{e.message || e.event_type}</span>
                {e.data?.action && <EventBadge action={e.data.action} />}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, icon, color }) {
  const colors = {
    primary: 'text-[var(--color-primary)]',
    success: 'text-[var(--color-success)]',
    danger: 'text-[var(--color-danger)]',
    warning: 'text-[var(--color-warning)]',
  };
  return (
    <div className={cardCls}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[var(--color-text-sec)] text-xs font-medium uppercase tracking-wide mb-1">{label}</div>
          <div className={`text-2xl font-bold ${colors[color]}`}>{value}</div>
        </div>
        <div className="text-3xl opacity-40">{icon}</div>
      </div>
    </div>
  );
}

function EventIcon({ type }) {
  const icons = { packet: '📦', alert: '🚨', rule: '📋', connection: '🔗', user: '👤' };
  return <span className="text-xl opacity-60">{icons[type] || '•'}</span>;
}

function EventBadge({ action }) {
  const colors = {
    allow: 'bg-[var(--color-success-light)] text-[var(--color-success)]',
    deny: 'bg-[var(--color-danger-light)] text-[var(--color-danger)]',
    'rate-limit': 'bg-[var(--color-warning-light)] text-[var(--color-warning)]',
  };
  return <span className={`px-2 py-1 rounded-md text-xs font-medium ${colors[action] || ''}`}>{action}</span>;
}
