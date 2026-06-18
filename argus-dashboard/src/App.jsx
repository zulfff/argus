/* ================================================================
   ARGUS — Next-Gen eBPF Firewall Dashboard
   Single-file React JSX · Production Quality · 2026
   ================================================================ */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  Area, AreaChart
} from 'recharts';
import * as api from './api';

/* ─── CONSTANTS & STYLES ────────────────────────────────────────── */

const S = {
  root: { background: '#080b10', color: '#e8edf3', fontFamily: '"Inter","Segoe UI",system-ui,sans-serif', minHeight: '100vh', display: 'flex', fontSize: 14 },
  sidebar: { width: 220, background: '#0d1117', borderRight: '1px solid #1e2a38', display: 'flex', flexDirection: 'column', position: 'fixed', top: 0, left: 0, height: '100vh', zIndex: 100 },
  main: { marginLeft: 220, flex: 1, padding: 24, minHeight: '100vh', animation: 'fadeSlideIn 0.3s ease-out' },
  logo: { padding: '20px 20px 16px', borderBottom: '1px solid #1e2a38', display: 'flex', alignItems: 'center', gap: 10, fontSize: 18, fontWeight: 700, fontFamily: '"JetBrains Mono",monospace', color: '#00d4ff' },
  nav: { flex: 1, padding: '12px 0' },
  navItem: (active) => ({ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 20px', cursor: 'pointer', fontSize: 13, color: active ? '#00d4ff' : '#7a8fa8', borderLeft: active ? '3px solid #00d4ff' : '3px solid transparent', background: active ? 'rgba(0,212,255,0.06)' : 'transparent', transition: 'all 0.2s cubic-bezier(0.4,0,0.2,1)' }),
  navBadge: { background: '#ff3b5c', color: '#fff', fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 9999, marginLeft: 'auto' },
  userSection: { padding: '12px 20px', borderTop: '1px solid #1e2a38', fontSize: 12, color: '#7a8fa8' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 },
  headerTitle: { fontFamily: '"JetBrains Mono",monospace', fontSize: 20, fontWeight: 600, color: '#e8edf3', letterSpacing: -0.5 },
  headerBadge: { fontSize: 11, color: '#7a8fa8', fontFamily: '"JetBrains Mono",monospace' },
  card: { background: '#0d1117', borderRadius: 8, border: '1px solid #1e2a38', boxShadow: '0 4px 16px rgba(0,0,0,0.4),0 0 0 1px #1e2a38', padding: 20 },
  statCard: (color) => ({ background: '#0d1117', borderRadius: 8, border: '1px solid #1e2a38', padding: '16px 20px', boxShadow: '0 4px 16px rgba(0,0,0,0.4)', position: 'relative', overflow: 'hidden' }),
  statValue: { fontFamily: '"JetBrains Mono",monospace', fontSize: 28, fontWeight: 700, lineHeight: 1.1 },
  statLabel: { fontSize: 11, color: '#7a8fa8', marginTop: 4, letterSpacing: 0.5, textTransform: 'uppercase' },
  badge: (bg, color) => ({ display: 'inline-flex', alignItems: 'center', padding: '2px 8px', borderRadius: 9999, fontSize: 10, fontWeight: 600, background: bg, color, letterSpacing: 0.3 }),
  btn: (bg, color, w) => ({ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 600, background: bg || 'transparent', color: color || '#e8edf3', transition: 'all 0.2s cubic-bezier(0.4,0,0.2,1)', width: w || 'auto', justifyContent: 'center', fontFamily: '"Inter",system-ui,sans-serif' }),
  input: { width: '100%', padding: '8px 12px', background: '#141923', border: '1px solid #1e2a38', borderRadius: 6, color: '#e8edf3', fontSize: 13, fontFamily: '"JetBrains Mono",monospace', outline: 'none', transition: 'border-color 0.15s' },
  select: { width: '100%', padding: '8px 12px', background: '#141923', border: '1px solid #1e2a38', borderRadius: 6, color: '#e8edf3', fontSize: 13, fontFamily: '"Inter",system-ui,sans-serif', outline: 'none', cursor: 'pointer' },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 12 },
  th: { textAlign: 'left', padding: '10px 12px', fontSize: 10, fontWeight: 600, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, borderBottom: '2px solid #1e2a38' },
  td: { padding: '10px 12px', borderBottom: '1px solid rgba(30,42,56,0.5)', fontFamily: '"JetBrains Mono",monospace', fontSize: 11 },
  rowHover: { background: '#141923', transition: 'background 0.15s' },
  checkbox: { width: 16, height: 16, accentColor: '#00d4ff', cursor: 'pointer' },
  toggle: (on) => ({ width: 36, height: 20, borderRadius: 10, background: on ? '#00ff88' : '#3d5068', cursor: 'pointer', position: 'relative', transition: 'background 0.2s', border: 'none', padding: 0 }),
  toggleDot: (on) => ({ width: 16, height: 16, borderRadius: '50%', background: '#fff', position: 'absolute', top: 2, left: on ? 18 : 2, transition: 'left 0.2s cubic-bezier(0.4,0,0.2,1)' }),
  modal: { position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, animation: 'modalIn 0.25s ease-out' },
  modalContent: { background: '#0d1117', borderRadius: 12, border: '1px solid #1e2a38', padding: 32, width: 520, maxHeight: '80vh', overflowY: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.6)' },
  toast: { position: 'fixed', top: 20, right: 20, zIndex: 2000, display: 'flex', flexDirection: 'column', gap: 8 },
  toastItem: (sev) => ({ padding: '12px 16px', borderRadius: 8, border: `1px solid ${sev === 'critical' ? '#ff3b5c' : '#ffb800'}`, background: sev === 'critical' ? 'rgba(255,59,92,0.1)' : 'rgba(255,184,0,0.1)', color: '#e8edf3', fontSize: 12, minWidth: 300, boxShadow: '0 8px 24px rgba(0,0,0,0.4)', animation: 'slideInRow 0.3s ease-out' }),
  progressBar: (w) => ({ height: 2, background: '#1e2a38', borderRadius: 1, marginTop: 8, overflow: 'hidden', position: 'relative' }),
  progressFill: (w) => ({ height: '100%', background: '#ff3b5c', width: `${w}%`, transition: 'width 1s linear', borderRadius: 1 }),
  pill: (bg, color) => ({ display: 'inline-flex', alignItems: 'center', padding: '1px 8px', borderRadius: 9999, fontSize: 10, fontWeight: 600, background: bg, color }),
  statusDot: (color, animate) => ({ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block', boxShadow: animate ? `0 0 8px ${color}` : 'none', animation: animate ? 'livePulse 2s ease-in-out infinite' : 'none' }),
};

const COLORS = { cyan: '#00d4ff', green: '#00ff88', red: '#ff3b5c', yellow: '#ffb800', purple: '#b06bff', muted: '#3d5068' };
const BADGE = { allow: ['rgba(0,255,136,0.12)','#00ff88'], deny: ['rgba(255,59,92,0.12)','#ff3b5c'], warn: ['rgba(255,184,0,0.12)','#ffb800'], info: ['rgba(0,212,255,0.12)','#00d4ff'], purple: ['rgba(176,107,255,0.12)','#b06bff'], off: ['rgba(61,80,104,0.2)','#3d5068'] };

/* ─── UTILITY HOOKS ───────────────────────────────────────────── */

function useApiData() {
  const [stats, setStats] = useState({ packets_allowed: 0, packets_dropped: 0, active_connections: 0, blocked_ips: 0, rate_limit_buckets: 0 });
  const [conns, setConns] = useState([]);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [packetHistory, setPacketHistory] = useState([]);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const s = await api.getStats();
        setStats(s);
        setPacketHistory(prev => {
          const next = [...prev, { time: new Date().toLocaleTimeString(), allowed: s.packets_allowed, dropped: s.packets_dropped }];
          return next.length > 30 ? next.slice(-30) : next;
        });
      } catch {}
    };
    const fetchConns = async () => { try { const c = await api.listConnections(); setConns(c); } catch {} };
    const fetchAlerts = async () => { try { const a = await api.listAlertHistory(); setAlerts(a); } catch {} };
    
    fetchStats(); fetchConns(); fetchAlerts();
    const interval = setInterval(() => { fetchStats(); fetchConns(); }, 3000);
    
    api.connectWebSocket((ev) => {
      if (ev.event_type === 'stats') {
        setStats(prev => ({ ...prev, ...ev.data }));
        setPacketHistory(prev => {
          const next = [...prev, { time: new Date().toLocaleTimeString(), allowed: ev.data.packets_allowed || 0, dropped: ev.data.packets_dropped || 0 }];
          return next.length > 30 ? next.slice(-30) : next;
        });
      }
      if (ev.event_type === 'connection') setConns(prev => [ev.data, ...prev].slice(0, 50));
      if (ev.event_type === 'alert') setAlerts(prev => [{ ...ev.data, id: Date.now() }, ...prev].slice(0, 50));
    });
    
    return () => clearInterval(interval);
  }, []);
  
  return { stats, conns, events, alerts, packetHistory };
}

function usePage() {
  const [page, setPage] = useState(() => {
    try { return window.location.hash.replace('#', '') || 'dashboard'; } catch { return 'dashboard'; }
  });
  const setPageAndHash = useCallback((p) => {
    setPage(p);
    try { window.location.hash = p; } catch {}
  }, []);
  return [page, setPageAndHash];
}

/* ─── LOGIN PAGE ───────────────────────────────────────────────── */

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.login(username, password);
      onLogin();
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#080b10' }}>
      <div style={{ background: '#0d1117', borderRadius: 12, border: '1px solid #1e2a38', padding: 40, width: 400, boxShadow: '0 20px 60px rgba(0,0,0,0.6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 32, justifyContent: 'center' }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <ellipse cx="12" cy="12" rx="10" ry="8" stroke="#00d4ff" strokeWidth="1.5" fill="none" />
            <circle cx="12" cy="12" r="4" fill="#00d4ff" opacity="0.8" />
          </svg>
          <span style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 24, fontWeight: 700, color: '#00d4ff' }}>ARGUS</span>
        </div>
        <h1 style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 18, color: '#e8edf3', textAlign: 'center', marginBottom: 24 }}>Firewall Dashboard</h1>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 6 }}>Username</label>
            <input style={S.input} value={username} onChange={e => setUsername(e.target.value)} placeholder="admin" autoFocus />
          </div>
          <div style={{ marginBottom: 20 }}>
            <label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 6 }}>Password</label>
            <input style={S.input} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" />
          </div>
          {error && <div style={{ color: '#ff3b5c', fontSize: 12, marginBottom: 16, textAlign: 'center' }}>{error}</div>}
          <button type="submit" disabled={loading} style={{ ...S.btn('#00d4ff', '#080b10'), width: '100%', padding: '12px 16px', fontSize: 14, opacity: loading ? 0.6 : 1 }}>
            {loading ? 'AUTHENTICATING...' : 'SIGN IN'}
          </button>
        </form>
      </div>
    </div>
  );
}

/* ─── SHARED COMPONENTS ────────────────────────────────────────── */

function StatCard({ label, value, prefix, color, trend }) {
  return (
    <div style={S.statCard(color)} onMouseEnter={e => { e.currentTarget.style.borderColor = '#1e2a38'; }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: color, opacity: 0.6 }} />
      <div style={{ ...S.statValue, color }}>{prefix || ''}{typeof value === 'number' ? value.toLocaleString() : value}</div>
      <div style={S.statLabel}>{label}</div>
      {trend !== undefined && (
        <div style={{ fontSize: 11, color: trend >= 0 ? COLORS.green : COLORS.red, marginTop: 4 }}>
          {trend >= 0 ? '↑' : '↓'} {Math.abs(trend).toFixed(1)}%
        </div>
      )}
    </div>
  );
}

function Badge({ type, label }) {
  const [bg, color] = BADGE[type] || BADGE.off;
  return <span style={S.badge(bg, color)}>{label || type.toUpperCase()}</span>;
}

function Toggle({ on, onChange }) {
  return (
    <button style={S.toggle(on)} onClick={onChange} aria-label={on ? 'Disable' : 'Enable'}>
      <div style={S.toggleDot(on)} />
    </button>
  );
}

function Modal({ children, onClose }) {
  const ref = useRef();
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    document.body.style.overflow = 'hidden';
    return () => { window.removeEventListener('keydown', handler); document.body.style.overflow = ''; };
  }, [onClose]);
  return (
    <div style={S.modal} onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={S.modalContent} ref={ref}>{children}</div>
    </div>
  );
}

function Input({ value, onChange, placeholder, error, type, ...rest }) {
  return (
    <div>
      <input style={{ ...S.input, borderColor: error ? '#ff3b5c' : S.input.borderColor }} value={value} onChange={onChange} placeholder={placeholder} type={type || 'text'} {...rest} />
      {error && <div style={{ fontSize: 10, color: '#ff3b5c', marginTop: 4 }}>{error}</div>}
    </div>
  );
}

function Table({ cols, rows, renderRow, emptyMsg, onSelect, selected, checkable }) {
  if (!rows.length) return <div style={{ textAlign: 'center', padding: 40, color: '#3d5068', fontSize: 13 }}>{emptyMsg || 'No data'}</div>;
  return (
    <table style={S.table}>
      <thead><tr>{cols.map((c, i) => <th key={i} style={S.th}>{c}</th>)}</tr></thead>
      <tbody>{rows.map((row, i) => renderRow(row, i))}</tbody>
    </table>
  );
}

function Toast({ alerts, onDismiss }) {
  return (
    <div style={S.toast}>
      {alerts.map(a => (
        <div key={a.id} style={S.toastItem(a.sev)}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontWeight: 600, color: a.sev === 'critical' ? '#ff3b5c' : '#ffb800' }}>
              {a.sev === 'critical' ? '🔴' : '🟡'} {a.sev.toUpperCase()}
            </span>
            <button onClick={() => onDismiss(a.id)} style={{ background: 'none', border: 'none', color: '#3d5068', cursor: 'pointer', fontSize: 14 }}>✕</button>
          </div>
          <div style={{ marginTop: 4 }}>{a.msg}</div>
          <ToastProgress duration={8} />
        </div>
      ))}
    </div>
  );
}

function ToastProgress({ duration }) {
  const [w, setW] = useState(100);
  useEffect(() => { const t = setInterval(() => setW(p => Math.max(0, p - 1.25)), duration * 10); return () => clearInterval(t); }, [duration]);
  return <div style={S.progressBar()}><div style={S.progressFill(w)} /></div>;
}

function Tabs({ tabs, active, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 2, borderBottom: '1px solid #1e2a38', marginBottom: 20 }}>
      {tabs.map(t => (
        <button key={t} onClick={() => onChange(t)} style={{ padding: '10px 16px', background: active === t ? '#141923' : 'transparent', border: 'none', color: active === t ? '#00d4ff' : '#7a8fa8', cursor: 'pointer', fontSize: 12, fontWeight: 600, borderBottom: active === t ? '2px solid #00d4ff' : '2px solid transparent', transition: 'all 0.2s' }}>
          {t}
        </button>
      ))}
    </div>
  );
}

function ArgusEye({ pulse }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ filter: pulse ? 'drop-shadow(0 0 8px #00d4ff)' : 'none', transition: 'filter 0.3s' }}>
      <ellipse cx="12" cy="12" rx="10" ry="8" stroke="#00d4ff" strokeWidth="1.5" fill="none" />
      <circle cx="12" cy="12" r="4" fill="#00d4ff" opacity="0.8">
        <animate attributeName="cx" values="12;14;12;10;12" dur="4s" repeatCount="indefinite" />
      </circle>
    </svg>
  );
}

function FilterBar({ filters, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center', marginBottom: 16 }}>
      {filters.map((f, i) =>
        f.type === 'search' ? (
          <input key={i} style={{ ...S.input, width: 200 }} value={f.value} onChange={e => onChange(f.key, e.target.value)} placeholder={f.placeholder || 'Search...'} />
        ) : f.type === 'select' ? (
          <select key={i} style={S.select} value={f.value} onChange={e => onChange(f.key, e.target.value)}>
            {f.options.map(o => <option key={o} value={o === f.allLabel ? '' : o}>{o}</option>)}
          </select>
        ) : null
      )}
    </div>
  );
}

/* ─── PAGE COMPONENTS ──────────────────────────────────────────── */

function Dashboard({ data }) {
  const { packetHistory, stats, events } = data;
  const [paused, setPaused] = useState(false);
  const displayEvents = paused ? events.slice(0, 5) : events;
  const trendAllowed = packetHistory.length >= 2 ? ((packetHistory[packetHistory.length - 1]?.allowed || 0) - (packetHistory[0]?.allowed || 0)) / (packetHistory[0]?.allowed || 1) * 100 : 0;
  const trendDropped = packetHistory.length >= 2 ? ((packetHistory[packetHistory.length - 1]?.dropped || 0) - (packetHistory[0]?.dropped || 0)) / (packetHistory[0]?.dropped || 1) * 100 : 0;

  const protoData = useMemo(() => [
    { name: 'TCP', value: 65 }, { name: 'UDP', value: 25 }, { name: 'ICMP', value: 8 }, { name: 'Other', value: 2 }
  ], []);

  const connStateData = useMemo(() => [
    { name: 'Established', value: 34 }, { name: 'New', value: 8 }, { name: 'Closing', value: 5 }
  ], []);

  return (
    <div style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h1 style={S.headerTitle}>◈ Dashboard</h1>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={S.headerBadge}>Updated: {new Date().toLocaleTimeString()}</span>
          <button onClick={() => setPaused(!paused)} style={S.btn('#141923', paused ? '#ffb800' : '#00ff88')}>
            {paused ? '▶ RESUME' : '⏸ PAUSE'}
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 20 }}>
        <StatCard label="Packets Allowed" value={stats.packets_allowed || 0} color={COLORS.green} trend={trendAllowed} />
        <StatCard label="Packets Dropped" value={stats.packets_dropped || 0} color={COLORS.red} trend={trendDropped} />
        <StatCard label="Active Connections" value={stats.active_connections || 0} color={COLORS.cyan} />
        <StatCard label="Blocked IPs" value={stats.blocked_ips || 0} color={COLORS.yellow} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 20 }}>
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>📊 Packet Rate (60s rolling)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={packetHistory}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a38" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#3d5068' }} stroke="#1e2a38" />
              <YAxis tick={{ fontSize: 10, fill: '#3d5068' }} stroke="#1e2a38" />
              <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1e2a38', borderRadius: 6, fontSize: 12 }} />
              <Line type="monotone" dataKey="allowed" stroke="#00ff88" strokeWidth={2} dot={false} isAnimationActive animationDuration={800} />
              <Line type="monotone" dataKey="dropped" stroke="#ff3b5c" strokeWidth={2} dot={false} isAnimationActive animationDuration={800} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={S.card}>
            <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>📊 Protocol Distribution</h3>
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={protoData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a38" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10, fill: '#3d5068' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#7a8fa8' }} width={50} />
                <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1e2a38', borderRadius: 6 }} />
                <Bar dataKey="value" fill="#00d4ff" radius={[0, 4, 4, 0]} isAnimationActive animationDuration={800} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div style={S.card}>
            <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>📊 Connection State</h3>
            <ResponsiveContainer width="100%" height={120}>
              <PieChart>
                <Pie data={connStateData} dataKey="value" cx="50%" cy="50%" outerRadius={40} innerRadius={25} isAnimationActive animationDuration={800}>
                  {connStateData.map((e, i) => <Cell key={i} fill={[COLORS.green, COLORS.cyan, COLORS.yellow][i]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1e2a38', borderRadius: 6 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: 16 }}>
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>🔔 Live Event Feed</h3>
          <div style={{ maxHeight: 260, overflowY: 'auto' }}>
            {displayEvents.slice(0, 8).map(ev => (
              <div key={ev.id} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '6px 0', borderBottom: '1px solid rgba(30,42,56,0.4)', animation: 'slideInRow 0.3s ease-out', fontSize: 11, fontFamily: '"JetBrains Mono",monospace' }}>
                <span style={{ color: '#3d5068', minWidth: 60 }}>{ev.time}</span>
                <Badge type={ev.sev === 'critical' ? 'deny' : ev.sev === 'warning' ? 'warn' : 'info'} label={ev.sev === 'critical' ? 'BLOCK' : ev.sev === 'warning' ? 'WARN' : 'INFO'} />
                <span style={{ color: '#7a8fa8' }}>{ev.msg}</span>
              </div>
            ))}
          </div>
        </div>
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>💡 System Health</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              ['API', COLORS.green], ['eBPF', COLORS.green], ['WebSocket', COLORS.green],
              ['DB', stats.active_connections > 0 ? COLORS.green : COLORS.yellow],
            ].map(([label, color]) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11 }}>
                <div style={S.statusDot(color, true)} />
                <span style={{ color: '#7a8fa8' }}>{label}</span>
                <span style={{ marginLeft: 'auto', color }}>{color === COLORS.green ? '● ONLINE' : '● IN-MEMORY'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Rules({ rules, onToggle, onDelete, onDuplicate }) {
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [selected, setSelected] = useState([]);
  const [showNewModal, setShowNewModal] = useState(false);
  const [showSimulator, setShowSimulator] = useState(false);
  const [simResult, setSimResult] = useState(null);
  const [form, setForm] = useState({ name: '', action: 'deny', direction: 'inbound', srcCidr: '', dstCidr: '', protocol: 'any', port: '', priority: 100, enabled: true });
  const [formErrors, setFormErrors] = useState({});
  const [simForm, setSimForm] = useState({ srcIp: '10.0.0.1', dstIp: '8.8.8.8', sport: '', dport: '443', protocol: 'tcp', direction: 'outbound' });
  const [creating, setCreating] = useState(false);
  const [simLoading, setSimLoading] = useState(false);

  const filtered = useMemo(() => {
    return rules.filter(r => {
      if (search && !r.name.toLowerCase().includes(search.toLowerCase()) && !r.srcCidr?.includes(search) && !r.dstCidr?.includes(search)) return false;
      if (filterAction && r.action !== filterAction) return false;
      if (filterStatus === 'enabled' && !r.enabled) return false;
      if (filterStatus === 'disabled' && r.enabled) return false;
      return true;
    });
  }, [rules, search, filterAction, filterStatus]);

  const toggleSelect = (id) => setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  const toggleAll = () => setSelected(selected.length === filtered.length ? [] : filtered.map(r => r.id));

  const validateForm = () => {
    const e = {};
    if (!form.name) e.name = 'Required';
    if (form.port && (isNaN(form.port) || form.port < 0 || form.port > 65535)) e.port = '0-65535';
    setFormErrors(e);
    return !Object.keys(e).length;
  };

  const handleSimulate = async () => {
    setSimLoading(true);
    setSimResult(null);
    try {
      const result = await api.simulateRule(simForm);
      setSimResult(result);
    } catch {
      setSimResult({ matched: false, rule: null, action: 'allow (default)' });
    } finally {
      setSimLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!validateForm()) return;
    setCreating(true);
    try {
      await api.createRule(form);
      setShowNewModal(false);
      onDuplicate(null);
    } catch {
      setFormErrors({ name: 'Failed to create rule' });
    } finally {
      setCreating(false);
    }
  };

  return (
    <div style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div><h1 style={S.headerTitle}>⊞ Firewall Rules</h1><span style={S.headerBadge}>{rules.length} RULES · {rules.filter(r => r.enabled).length} ACTIVE</span></div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={() => setShowSimulator(!showSimulator)} style={S.btn('#141923', '#00d4ff')}>🔬 Simulate</button>
          <button onClick={() => { setForm({ name:'',action:'deny',direction:'inbound',srcCidr:'',dstCidr:'',protocol:'any',port:'',priority:100,enabled:true }); setFormErrors({}); setShowNewModal(true); }} style={S.btn('#00d4ff','#080b10')}>+ NEW RULE</button>
        </div>
      </div>

      <FilterBar filters={[
        { key:'search', type:'search', value:search, placeholder:'Search name, CIDR...', onChange: (k,v) => setSearch(v) },
        { key:'action', type:'select', value:filterAction, options:['All','allow','deny','rate-limit'], allLabel:'All', onChange: (k,v) => setFilterAction(v) },
        { key:'status', type:'select', value:filterStatus, options:['All','enabled','disabled'], allLabel:'All', onChange: (k,v) => setFilterStatus(v) },
      ]} onChange={(k,v) => { if(k==='search') setSearch(v); if(k==='action') setFilterAction(v); if(k==='status') setFilterStatus(v); }} />

      {selected.length > 0 && (
        <div style={{ display: 'flex', gap: 8, padding: '8px 12px', background: '#141923', border: '1px solid #1e2a38', borderRadius: 6, marginBottom: 12, alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: '#7a8fa8' }}>{selected.length} selected</span>
          <button style={S.btn('rgba(0,255,136,0.12)','#00ff88')}>✓ Enable</button>
          <button style={S.btn('rgba(255,184,0,0.12)','#ffb800')}>✕ Disable</button>
          <button style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>🗑 Delete</button>
        </div>
      )}

      <div style={S.card}>
        <table style={S.table}>
          <thead><tr>
            <th style={S.th}><input type="checkbox" style={S.checkbox} checked={selected.length === filtered.length && filtered.length > 0} onChange={toggleAll} /></th>
            <th style={S.th}>Priority</th><th style={S.th}>Name</th><th style={S.th}>Action</th><th style={S.th}>Direction</th>
            <th style={S.th}>Source</th><th style={S.th}>Dest</th><th style={S.th}>Proto</th><th style={S.th}>Port</th><th style={S.th}>Status</th><th style={S.th}>Actions</th>
          </tr></thead>
          <tbody>
            {filtered.map(r => (
              <tr key={r.id} style={{ animation: 'slideInRow 0.3s ease-out' }}
                onMouseEnter={e => e.currentTarget.style.background = '#141923'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <td style={S.td}><input type="checkbox" style={S.checkbox} checked={selected.includes(r.id)} onChange={() => toggleSelect(r.id)} /></td>
                <td style={S.td}>{r.priority}</td>
                <td style={{ ...S.td, color: '#e8edf3', fontFamily: '"Inter",system-ui,sans-serif' }}>{r.name}</td>
                <td style={S.td}><Badge type={r.action === 'deny' ? 'deny' : r.action === 'rate-limit' ? 'warn' : 'allow'} label={r.action.toUpperCase()} /></td>
                <td style={S.td}><span style={{ color: '#7a8fa8' }}>{r.direction.toUpperCase()}</span></td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{r.srcCidr || '*'}</td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{r.dstCidr || '*'}</td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{r.protocol}</td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{r.port || '*'}</td>
                <td style={S.td}><Toggle on={r.enabled} onChange={() => onToggle(r.id)} /></td>
                <td style={S.td}>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <button style={S.btn('#141923','#7a8fa8',32)} aria-label="Edit" onMouseEnter={e => e.currentTarget.style.color='#00d4ff'} onMouseLeave={e => e.currentTarget.style.color='#7a8fa8'}>✏️</button>
                    <button style={S.btn('#141923','#7a8fa8',32)} onClick={() => onDuplicate(r.id)} aria-label="Duplicate" onMouseEnter={e => e.currentTarget.style.color='#b06bff'} onMouseLeave={e => e.currentTarget.style.color='#7a8fa8'}>📋</button>
                    <button style={S.btn('#141923','#7a8fa8',32)} onClick={() => onDelete(r.id)} aria-label="Delete" onMouseEnter={e => e.currentTarget.style.color='#ff3b5c'} onMouseLeave={e => e.currentTarget.style.color='#7a8fa8'}>🗑️</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length && <div style={{ textAlign:'center', padding: 40, color: '#3d5068', fontSize: 13 }}>No rules match your filters</div>}
      </div>

      {showSimulator && (
        <div style={{ ...S.card, marginTop: 16 }}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>🔬 Packet Simulator</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 12, marginBottom: 16 }}>
            <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Src IP</label><input style={S.input} value={simForm.srcIp} onChange={e => setSimForm({...simForm,srcIp:e.target.value})} /></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Dst IP</label><input style={S.input} value={simForm.dstIp} onChange={e => setSimForm({...simForm,dstIp:e.target.value})} /></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Sport</label><input style={S.input} value={simForm.sport} onChange={e => setSimForm({...simForm,sport:e.target.value})} /></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Dport</label><input style={S.input} value={simForm.dport} onChange={e => setSimForm({...simForm,dport:e.target.value})} /></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Proto</label><select style={S.select} value={simForm.protocol} onChange={e => setSimForm({...simForm,protocol:e.target.value})}><option>tcp</option><option>udp</option><option>icmp</option></select></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Dir</label><select style={S.select} value={simForm.direction} onChange={e => setSimForm({...simForm,direction:e.target.value})}><option>inbound</option><option>outbound</option></select></div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={handleSimulate} disabled={simLoading} style={S.btn('#00d4ff','#080b10')}>{simLoading ? 'SIMULATING...' : '▶ SIMULATE'}</button>
            {simResult && (
              <div style={{ padding: '8px 16px', borderRadius: 6, background: simResult.matched ? 'rgba(0,212,255,0.08)' : 'rgba(255,184,0,0.08)', border: `1px solid ${simResult.matched ? COLORS.cyan : COLORS.yellow}`, fontSize: 12 }}>
                {simResult.matched
                  ? <>Matched: <strong>{simResult.rule?.name || 'unknown'}</strong> → Action: <Badge type={simResult.action === 'deny' ? 'deny' : 'allow'} label={(simResult.action || 'allow').toUpperCase()} /></>
                  : <>No rule matched → Default action: <Badge type="allow" label="ALLOW (default)" /></>}
              </div>
            )}
          </div>
        </div>
      )}

      {showNewModal && (
        <Modal onClose={() => setShowNewModal(false)}>
          <h2 style={{ fontSize: 16, fontFamily: '"JetBrains Mono",monospace', color: '#e8edf3', marginBottom: 24 }}>+ New Firewall Rule</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ gridColumn: 'span 2' }}>
              <label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Name</label>
              <Input value={form.name} onChange={e => setForm({...form,name:e.target.value})} error={formErrors.name} placeholder="e.g. block-ssh-from-wan" />
            </div>
            <div><label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Action</label><select style={S.select} value={form.action} onChange={e => setForm({...form,action:e.target.value})}><option value="allow">ALLOW</option><option value="deny">DENY</option><option value="rate-limit">RATE-LIMIT</option></select></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Direction</label><select style={S.select} value={form.direction} onChange={e => setForm({...form,direction:e.target.value})}><option value="inbound">INBOUND</option><option value="outbound">OUTBOUND</option></select></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Src CIDR</label><input style={S.input} value={form.srcCidr} onChange={e => setForm({...form,srcCidr:e.target.value})} placeholder="10.0.0.0/8" /></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Dst CIDR</label><input style={S.input} value={form.dstCidr} onChange={e => setForm({...form,dstCidr:e.target.value})} placeholder="0.0.0.0/0" /></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Protocol</label><select style={S.select} value={form.protocol} onChange={e => setForm({...form,protocol:e.target.value})}><option value="any">ANY</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Port</label><Input value={form.port} onChange={e => setForm({...form,port:e.target.value})} error={formErrors.port} placeholder="0-65535" /></div>
            <div><label style={{ fontSize: 10, color: '#3d5068', textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 4 }}>Priority</label><input style={S.input} type="number" value={form.priority} onChange={e => setForm({...form,priority:parseInt(e.target.value)||0})} /></div>
            <div style={{ gridColumn: 'span 2', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 12, color: '#7a8fa8' }}>Enabled</span>
              <Toggle on={form.enabled} onChange={() => setForm({...form,enabled:!form.enabled})} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 24 }}>
            <button onClick={() => setShowNewModal(false)} style={S.btn('transparent','#7a8fa8')}>Cancel</button>
            <button onClick={handleCreate} disabled={creating} style={S.btn('#00d4ff','#080b10')}>{creating ? 'DEPLOYING...' : '▶ DEPLOY RULE'}</button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function Connections({ conns }) {
  const [search, setSearch] = useState('');
  const [filterState, setFilterState] = useState('');
  const [selected, setSelected] = useState(null);

  const filtered = useMemo(() => {
    return conns.filter(c => {
      if (search && !c.src.includes(search) && !c.dst.includes(search) && !`${c.sp}`.includes(search)) return false;
      if (filterState && c.state !== filterState) return false;
      return true;
    });
  }, [conns, search, filterState]);

  const formatDur = (s) => {
    const h = Math.floor(s / 3600); const m = Math.floor((s % 3600) / 60); const sec = s % 60;
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  };

  const stateBadge = (s) => ({ 'new': 'info', 'established': 'allow', 'closing': 'warn', 'closed': 'off' })[s] || 'off';

  return (
    <div style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div><h1 style={S.headerTitle}>⊷ Active Connections</h1><span style={S.headerBadge}>{conns.length} FLOWS · <span style={S.statusDot(COLORS.green, true)} /> LIVE</span></div>
      </div>

      <div style={{ display: 'flex', gap: 16, marginBottom: 12 }}>
        <div style={{ fontSize: 11, color: '#7a8fa8' }}>Total Active: <strong style={{ color: '#e8edf3' }}>{conns.length}</strong></div>
        <div style={{ fontSize: 11, color: '#7a8fa8' }}>New/s: <strong style={{ color: COLORS.cyan }}>3.2</strong></div>
        <div style={{ fontSize: 11, color: '#7a8fa8' }}>TCP:UDP: <strong style={{ color: COLORS.green }}>72%</strong>:<strong style={{ color: COLORS.cyan }}>28%</strong></div>
      </div>

      <FilterBar filters={[
        { key:'search', type:'search', value:search, placeholder:'Search IP or port...', onChange: (k,v) => setSearch(v) },
        { key:'state', type:'select', value:filterState, options:['All','new','established','closing','closed'], allLabel:'All', onChange: (k,v) => setFilterState(v) },
      ]} onChange={(k,v) => { if(k==='search') setSearch(v); if(k==='state') setFilterState(v); }} />

      <div style={S.card}>
        <table style={S.table}>
          <thead><tr><th style={S.th}>Source</th><th style={S.th}></th><th style={S.th}>Destination</th><th style={S.th}>Proto</th><th style={S.th}>State</th><th style={S.th}>Duration</th><th style={S.th}>Packets</th><th style={S.th}></th></tr></thead>
          <tbody>
            {filtered.map(c => (
              <tr key={c.id} style={{ animation: c.state === 'new' ? 'slideInRow 0.3s ease-out' : 'none' }}
                onClick={() => setSelected(selected === c.id ? null : c.id)}
                onMouseEnter={e => e.currentTarget.style.background = '#141923'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                style={{ cursor: 'pointer', animation: c.state === 'new' ? 'slideInRow 0.3s ease-out' : 'none' }}>
                <td style={{ ...S.td, color: '#e8edf3' }}>{c.src}:{c.sp}</td>
                <td style={{ ...S.td, color: COLORS.cyan, textAlign: 'center' }}>→</td>
                <td style={{ ...S.td, color: '#e8edf3' }}>{c.dst}:{c.dp}</td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{c.proto}</td>
                <td style={S.td}><Badge type={stateBadge(c.state)} label={c.state.toUpperCase()} /></td>
                <td style={{ ...S.td, color: '#7a8fa8', fontVariantNumeric: 'tabular-nums' }}>{formatDur(c.dur)}</td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{c.pkts}</td>
                <td style={S.td}>{c.state !== 'closed' && <button style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>🔴 Kill</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {selected && (() => {
          const c = conns.find(x => x.id === selected);
          if (!c) return null;
          return (
            <div style={{ padding: 12, background: '#141923', borderTop: '1px solid #1e2a38', marginTop: 8, fontSize: 11 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
                <div><span style={{ color: '#3d5068' }}>SRC:</span> <span style={{ color: '#e8edf3' }}>{c.src}:{c.sp}</span></div>
                <div><span style={{ color: '#3d5068' }}>DST:</span> <span style={{ color: '#e8edf3' }}>{c.dst}:{c.dp}</span></div>
                <div><span style={{ color: '#3d5068' }}>Proto:</span> <span style={{ color: '#e8edf3' }}>{c.proto}</span></div>
                <div><span style={{ color: '#3d5068' }}>State:</span> <span style={{ color: COLORS.green }}>{c.state.toUpperCase()}</span></div>
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}

function Alerts({ alerts, alertRules, onAck }) {
  return (
    <div style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
      <h1 style={S.headerTitle}>⚡ Alerts</h1>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>🔔 Alert Rules</h3>
          {alertRules.map(r => (
            <div key={r.id} style={{ padding: '10px 0', borderBottom: '1px solid rgba(30,42,56,0.4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 13, color: '#e8edf3' }}>{r.name}</span>
                <Toggle on={r.enabled} onChange={() => {}} />
              </div>
              <div style={{ fontSize: 11, color: '#7a8fa8', marginTop: 4 }}>{r.condition}</div>
              <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>{(r.channels || []).map(ch => <Badge key={ch} type="info" label={ch} />)}</div>
            </div>
          ))}
          <button style={{ ...S.btn('#141923','#00d4ff'), marginTop: 12, width: '100%', justifyContent: 'center' }}>+ CREATE RULE</button>
        </div>

        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>📜 Alert History</h3>
          <div style={{ maxHeight: 400, overflowY: 'auto' }}>
            {alerts.map(a => (
              <div key={a.id} style={{ padding: '8px 0', borderBottom: '1px solid rgba(30,42,56,0.4)', borderLeft: `3px solid ${a.sev === 'critical' ? COLORS.red : COLORS.yellow}`, paddingLeft: 10, marginBottom: 4, animation: 'slideInRow 0.3s ease-out' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 11, color: a.sev === 'critical' ? '#ff3b5c' : '#ffb800', fontWeight: 600 }}>{a.sev.toUpperCase()}</span>
                  <button onClick={() => onAck(a.id)} style={S.btn('transparent','#7a8fa8')}>✓ Acknowledge</button>
                </div>
                <div style={{ fontSize: 12, color: '#e8edf3', marginTop: 2 }}>{a.msg}</div>
                <div style={{ fontSize: 10, color: '#3d5068', marginTop: 2, fontFamily: '"JetBrains Mono",monospace' }}>{new Date(a.time).toLocaleTimeString()}</div>
              </div>
            ))}
            {!alerts.length && <div style={{ textAlign: 'center', color: '#3d5068', padding: 20 }}>No alerts</div>}
          </div>
          <button style={{ ...S.btn('transparent','#7a8fa8'), marginTop: 8 }}>✓ Acknowledge All</button>
        </div>
      </div>
    </div>
  );
}

function Audit() {
  const [auditLog, setAuditLog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterActor, setFilterActor] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [verified, setVerified] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const fetchAudit = async () => {
      try {
        const data = await api.listAudit({ actor: filterActor || undefined, action: filterAction || undefined });
        if (!cancelled) setAuditLog(data);
      } catch {} finally { if (!cancelled) setLoading(false); }
    };
    fetchAudit();
    return () => { cancelled = true; };
  }, [filterActor, filterAction]);

  const filtered = useMemo(() => auditLog, [auditLog]);

  const actionColor = (a) => a.startsWith('login') ? COLORS.purple : a.startsWith('rule') ? COLORS.cyan : a.startsWith('block') ? COLORS.red : '#7a8fa8';

  const handleVerify = async () => {
    setVerified('loading');
    try {
      const res = await api.verifyAudit();
      setVerified(res?.verified !== false);
    } catch { setVerified(false); }
  };

  const handleExport = () => {
    api.exportAudit();
  };

  if (loading) return <div style={{ textAlign: 'center', padding: 40, color: '#3d5068', fontSize: 13 }}>Loading audit log...</div>;

  return (
    <div style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div><h1 style={S.headerTitle}>⊟ Audit Log</h1><span style={S.headerBadge}>{auditLog.length} ENTRIES</span></div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={handleExport} style={S.btn('#141923','#7a8fa8')}>📥 Export JSON</button>
          <button onClick={handleVerify} style={S.btn('#b06bff','#fff')}>✓ Verify Integrity</button>
        </div>
      </div>

      <FilterBar filters={[
        { key:'actor', type:'search', value:filterActor, placeholder:'Filter by actor...', onChange: (k,v) => setFilterActor(v) },
        { key:'action', type:'select', value:filterAction, options:['All','login.success','login.failed','rule.create','rule.delete','block.add','block.remove','backup.create','user.create'], allLabel:'All', onChange: (k,v) => setFilterAction(v) },
      ]} onChange={(k,v) => { if(k==='actor') setFilterActor(v); if(k==='action') setFilterAction(v); }} />

      {verified === 'loading' && <div style={{ padding: '16px 20px', background: '#141923', borderRadius: 8, marginBottom: 12, fontSize: 12, color: '#7a8fa8' }}>⏳ Verifying hash chain integrity...</div>}
      {verified === true && (
        <div style={{ padding: '16px 20px', background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.2)', borderRadius: 8, marginBottom: 12, fontSize: 12 }}>
          ✓ Hash chain intact — All {auditLog.length} entries verified
        </div>
      )}
      {verified === false && (
        <div style={{ padding: '16px 20px', background: 'rgba(255,59,92,0.06)', border: '1px solid rgba(255,59,92,0.2)', borderRadius: 8, marginBottom: 12, fontSize: 12, color: '#ff3b5c' }}>
          ✗ Hash chain verification failed
        </div>
      )}

      <div style={S.card}>
        <table style={S.table}>
          <thead><tr><th style={S.th}>Timestamp</th><th style={S.th}>Actor</th><th style={S.th}>Action</th><th style={S.th}>Resource</th><th style={S.th}>IP</th><th style={S.th}>Status</th><th style={S.th}>Hash</th></tr></thead>
          <tbody>
            {filtered.map(a => (
              <tr key={a.id} onMouseEnter={e => e.currentTarget.style.background = '#141923'} onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <td style={{ ...S.td, color: '#3d5068' }}>{a.ts}</td>
                <td style={{ ...S.td, color: '#e8edf3', fontFamily: '"Inter",system-ui,sans-serif' }}>{a.actor}</td>
                <td style={{ ...S.td, color: actionColor(a.action) }}>{a.action}</td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{a.resource}</td>
                <td style={{ ...S.td, color: '#7a8fa8' }}>{a.ip}</td>
                <td style={S.td}><Badge type={a.success ? 'allow' : 'deny'} label={a.success ? '✓ SUCCESS' : '✗ FAILED'} /></td>
                <td style={{ ...S.td, color: '#3d5068' }} title={a.hash}>{a.hash?.slice(0, 12) || ''}...</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filtered.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, padding: '8px 12px', background: '#0d1117', borderRadius: 6, border: '1px solid #1e2a38', fontSize: 10, fontFamily: '"JetBrains Mono",monospace', color: '#3d5068', overflow: 'hidden' }}>
          {filtered.slice(0, 5).map((a, i) => (
            <React.Fragment key={a.id}>
              <span title={a.hash}>{(a.hash || '').slice(0, 8)}</span>
              {i < 4 && <span style={{ color: COLORS.cyan }}> → </span>}
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  );
}

function Reputation() {
  const [reputations, setReputations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchIp, setSearchIp] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupError, setLookupError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const fetch = async () => {
      try {
        const data = await api.listReputations();
        if (!cancelled) setReputations(data);
      } catch {} finally { if (!cancelled) setLoading(false); }
    };
    fetch();
    return () => { cancelled = true; };
  }, []);

  const handleLookup = async () => {
    setLookupResult(null);
    setLookupError(null);
    try {
      const result = await api.getReputation(searchIp);
      setLookupResult(result);
    } catch (err) {
      setLookupError(err.message || 'Lookup failed');
    }
  };

  const handleBlock = async (ip) => {
    try { await api.blockIp(ip); } catch {}
  };

  if (loading) return <div style={{ textAlign: 'center', padding: 40, color: '#3d5068', fontSize: 13 }}>Loading reputations...</div>;

  return (
    <div style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
      <h1 style={S.headerTitle}>◉ IP Reputation</h1>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>🔍 IP Lookup</h3>
          <div style={{ display: 'flex', gap: 8 }}>
            <input style={{ ...S.input, flex: 1 }} value={searchIp} onChange={e => setSearchIp(e.target.value)} placeholder="Enter IP address..." onKeyDown={e => e.key === 'Enter' && handleLookup()} />
            <button onClick={handleLookup} style={S.btn('#00d4ff','#080b10')}>CHECK</button>
          </div>
          {lookupError && <div style={{ marginTop: 12, fontSize: 12, color: '#ff3b5c' }}>{lookupError}</div>}
          {lookupResult && (
            <div style={{ marginTop: 16, padding: 16, background: '#141923', borderRadius: 8, border: '1px solid #1e2a38', animation: 'fadeSlideIn 0.3s ease-out' }}>
              <div style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 16, color: '#e8edf3' }}>{lookupResult.ip}</div>
              <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 120, height: 120, borderRadius: '50%', border: `4px solid ${lookupResult.score < -50 ? COLORS.red : lookupResult.score < 0 ? COLORS.yellow : COLORS.green}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column' }}>
                  <span style={{ fontFamily: '"JetBrains Mono",monospace', fontSize: 28, fontWeight: 700, color: lookupResult.score < -50 ? COLORS.red : lookupResult.score < 0 ? COLORS.yellow : COLORS.green }}>{lookupResult.score}</span>
                  <span style={{ fontSize: 9, color: '#3d5068' }}>/100</span>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: '#7a8fa8' }}>Source: <strong style={{ color: '#e8edf3' }}>{lookupResult.source}</strong></div>
                  <div style={{ fontSize: 11, color: '#7a8fa8', marginTop: 4 }}>Last Seen: <strong style={{ color: '#e8edf3' }}>{lookupResult.lastSeen}</strong></div>
                  <div style={{ fontSize: 11, color: '#7a8fa8', marginTop: 4 }}>Category: <Badge type={lookupResult.score < -50 ? 'deny' : lookupResult.score < 0 ? 'warn' : 'allow'} label={lookupResult.score < -50 ? 'MALICIOUS' : lookupResult.score < 0 ? 'SUSPICIOUS' : 'CLEAN'} /></div>
                </div>
              </div>
              {lookupResult.score < 0 && <button onClick={() => handleBlock(lookupResult.ip)} style={{ ...S.btn('rgba(255,59,92,0.12)','#ff3b5c'), marginTop: 12 }}>🚫 Block This IP</button>}
            </div>
          )}
        </div>

        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>🏆 Top Offenders</h3>
          <table style={S.table}>
            <thead><tr><th style={S.th}>IP</th><th style={S.th}>Score</th><th style={S.th}>Source</th><th style={S.th}>Action</th></tr></thead>
            <tbody>
              {reputations.map(r => (
                <tr key={r.ip} onMouseEnter={e => e.currentTarget.style.background='#141923'} onMouseLeave={e => e.currentTarget.style.background='transparent'}>
                  <td style={{ ...S.td, color: '#e8edf3' }}>{r.ip}</td>
                  <td style={S.td}><Badge type={r.score < -50 ? 'deny' : r.score < 0 ? 'warn' : 'allow'} label={`${r.score}`} /></td>
                  <td style={{ ...S.td, color: '#7a8fa8', fontFamily: '"Inter",system-ui,sans-serif' }}>{r.source}</td>
                  <td style={S.td}><button onClick={() => handleBlock(r.ip)} style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>🚫 Block</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Settings() {
  const [tab, setTab] = useState('General');
  const tabsList = ['General', 'Users', 'VPN Portal', 'Backup', 'Cluster', 'Syslog', 'QoS'];
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'Viewer' });
  const [users, setUsers] = useState([]);
  const [backups, setBackups] = useState([]);
  const [vpnRequests, setVpnRequests] = useState([]);
  const [clusterNodes, setClusterNodes] = useState([]);
  const [syslogConfigs, setSyslogConfigs] = useState([]);
  const [qosPolicies, setQosPolicies] = useState([]);
  const [creatingBackup, setCreatingBackup] = useState(false);
  const [userErrors, setUserErrors] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const fetchAll = async () => {
      try {
        const [u, b, v, c, s, q] = await Promise.allSettled([
          api.listUsers(), api.listBackups(), api.listVpnRequests(),
          api.listClusterNodes(), api.listSyslogConfigs(), api.listQosPolicies()
        ]);
        if (!cancelled) {
          if (u.status === 'fulfilled') setUsers(u.value);
          if (b.status === 'fulfilled') setBackups(b.value);
          if (v.status === 'fulfilled') setVpnRequests(v.value);
          if (c.status === 'fulfilled') setClusterNodes(c.value);
          if (s.status === 'fulfilled') setSyslogConfigs(s.value);
          if (q.status === 'fulfilled') setQosPolicies(q.value);
        }
      } catch {} finally { if (!cancelled) setLoading(false); }
    };
    fetchAll();
    return () => { cancelled = true; };
  }, []);

  const validateNewUser = () => {
    const e = {};
    if (!newUser.username) e.username = 'Required';
    if (!newUser.password || newUser.password.length < 6) e.password = 'Min 6 characters';
    if (users.find(u => u.username === newUser.username)) e.username = 'Already exists';
    setUserErrors(e);
    return !Object.keys(e).length;
  };

  const handleCreateBackup = async () => {
    setCreatingBackup(true);
    try {
      await api.createBackup();
      const b = await api.listBackups();
      setBackups(b);
    } catch {} finally { setCreatingBackup(false); }
  };

  const handleAddUser = async () => {
    if (!validateNewUser()) return;
    try {
      await api.createUser(newUser);
      const u = await api.listUsers();
      setUsers(u);
      setNewUser({ username: '', password: '', role: 'Viewer' });
      setShowAddUser(false);
    } catch {
      setUserErrors({ username: 'Failed to create user' });
    }
  };

  const handleDeleteUser = async (username) => {
    if (!window.confirm(`Delete user '${username}'?`)) return;
    try {
      await api.deleteUser(username);
      setUsers(prev => prev.filter(u => u.username !== username));
    } catch {}
  };

  const handleApproveVpn = async (id) => {
    try {
      await api.approveVpnRequest(id);
      const v = await api.listVpnRequests();
      setVpnRequests(v);
    } catch {}
  };

  const handleDenyVpn = async (id) => {
    try {
      await api.denyVpnRequest(id);
      const v = await api.listVpnRequests();
      setVpnRequests(v);
    } catch {}
  };

  const handleDownloadConfig = (id) => {
    api.downloadBackup(id);
  };

  const handleRestoreBackup = async (id) => {
    try { await api.restoreBackup({ id }); } catch {}
  };

  const handleDownloadBackup = (id) => {
    api.downloadBackup(id);
  };

  const roleBadge = (role) => {
    if (role === 'Admin') return 'purple';
    if (role === 'Operator') return 'info';
    return 'off';
  };

  if (loading) return <div style={{ textAlign: 'center', padding: 40, color: '#3d5068', fontSize: 13 }}>Loading settings...</div>;

  return (
    <div style={{ animation: 'fadeSlideIn 0.3s ease-out' }}>
      <h1 style={S.headerTitle}>⚙ Settings</h1>
      <Tabs tabs={tabsList} active={tab} onChange={setTab} />

      {tab === 'General' && (
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>System Configuration</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>API Endpoint</label>
              <input style={S.input} value="http://localhost:8443" readOnly />
            </div>
            <div>
              <label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>JWT Secret (masked)</label>
              <input style={S.input} type="password" value="••••••••••••••••••" readOnly />
            </div>
            <div>
              <label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Database</label>
              <div style={{ padding: '8px 12px', background: '#141923', borderRadius: 6, fontSize: 12, color: '#7a8fa8', border: '1px solid #1e2a38' }}>
                <span style={S.statusDot(COLORS.green, true)} /> In-Memory (PostgreSQL optional)
              </div>
            </div>
            <div>
              <label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Log Level</label>
              <select style={S.select} defaultValue="info">
                <option value="error">ERROR</option>
                <option value="warn">WARN</option>
                <option value="info">INFO</option>
                <option value="debug">DEBUG</option>
                <option value="trace">TRACE</option>
              </select>
            </div>
          </div>
          <div style={{ marginTop: 20, padding: 12, background: '#141923', borderRadius: 6, fontSize: 11, color: '#7a8fa8', border: '1px solid #1e2a38' }}>
            Environment variables: <code style={{ color: COLORS.cyan }}>ARGUS_JWT_SECRET</code>, <code style={{ color: COLORS.cyan }}>DATABASE_URL</code>, <code style={{ color: COLORS.cyan }}>ARGUS_ADMIN_USER</code>, <code style={{ color: COLORS.cyan }}>ARGUS_ADMIN_PASS</code>
          </div>
        </div>
      )}

      {tab === 'Users' && (
        <div style={S.card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1 }}>User Management — {users.length} users</h3>
            <button onClick={() => { setShowAddUser(!showAddUser); setUserErrors({}); }} style={S.btn('#00d4ff','#080b10')}>+ ADD USER</button>
          </div>
          {showAddUser && (
            <div style={{ padding: 16, background: '#141923', borderRadius: 8, marginBottom: 16, border: '1px solid #1e2a38', animation: 'fadeSlideIn 0.3s ease-out' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 12, alignItems: 'end' }}>
                <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Username</label>
                  <Input value={newUser.username} onChange={e => setNewUser({...newUser,username:e.target.value})} error={userErrors.username} placeholder="username" /></div>
                <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Password</label>
                  <Input value={newUser.password} onChange={e => setNewUser({...newUser,password:e.target.value})} error={userErrors.password} type="password" placeholder="min 6 chars" /></div>
                <div><label style={{ fontSize: 10, color: '#3d5068', display: 'block', marginBottom: 4 }}>Role</label>
                  <select style={S.select} value={newUser.role} onChange={e => setNewUser({...newUser,role:e.target.value})}><option>Admin</option><option>Operator</option><option>Viewer</option></select></div>
                <button onClick={handleAddUser} style={S.btn('#00d4ff','#080b10')}>CREATE</button>
              </div>
            </div>
          )}
          <table style={S.table}>
            <thead><tr><th style={S.th}>Username</th><th style={S.th}>Role</th><th style={S.th}>Status</th><th style={S.th}>Last Login</th><th style={S.th}>Actions</th></tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.username} onMouseEnter={e => e.currentTarget.style.background='#141923'} onMouseLeave={e => e.currentTarget.style.background='transparent'}>
                  <td style={{ ...S.td, color: '#e8edf3', fontFamily: '"Inter",system-ui,sans-serif' }}>{u.username}</td>
                  <td style={S.td}><Badge type={roleBadge(u.role)} label={u.role} /></td>
                  <td style={S.td}><Toggle on={u.enabled !== false} onChange={() => {}} /></td>
                  <td style={{ ...S.td, color: '#7a8fa8' }}>{(u.last_login || u.lastLogin) ? 'Recently' : 'Never'}</td>
                  <td style={S.td}>{u.username !== 'admin' && <button onClick={() => handleDeleteUser(u.username)} style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>🗑 Delete</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'VPN Portal' && (
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>WireGuard Peer Requests — {vpnRequests.filter(r => r.status === 'pending').length} pending</h3>
          <table style={S.table}>
            <thead><tr><th style={S.th}>Requester</th><th style={S.th}>Submitted</th><th style={S.th}>Public Key</th><th style={S.th}>Status</th><th style={S.th}>Actions</th></tr></thead>
            <tbody>
              {vpnRequests.map((r, i) => (
                <tr key={r.id || r.requester + i}>
                  <td style={{ ...S.td, color: '#e8edf3', fontFamily: '"Inter",system-ui,sans-serif' }}>{r.requester}</td>
                  <td style={{ ...S.td, color: '#7a8fa8' }}>{r.submitted}</td>
                  <td style={{ ...S.td, color: '#3d5068' }}>{(r.key || r.public_key || '').slice(0, 16)}...</td>
                  <td style={S.td}><Badge type={r.status === 'pending' ? 'warn' : r.status === 'approved' ? 'allow' : 'deny'} label={r.status.toUpperCase()} /></td>
                  <td style={S.td}>
                    {r.status === 'pending' && <div style={{ display: 'flex', gap: 4 }}>
                      <button onClick={() => handleApproveVpn(r.id)} style={S.btn('rgba(0,255,136,0.12)','#00ff88')}>✓ Approve</button>
                      <button onClick={() => handleDenyVpn(r.id)} style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>✕ Deny</button>
                    </div>}
                    {r.status === 'approved' && <button onClick={() => handleDownloadConfig(r.id)} style={S.btn('#00d4ff','#080b10')}>📥 Download Config</button>}
                  </td>
                </tr>
              ))}
              {!vpnRequests.length && <tr><td colSpan={5} style={{ textAlign: 'center', padding: 32, color: '#3d5068' }}>No pending VPN requests</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'Backup' && (
        <div style={S.card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1 }}>Backup Management — {backups.length} snapshots</h3>
            <button onClick={handleCreateBackup} disabled={creatingBackup} style={S.btn(creatingBackup ? '#3d5068' : '#00d4ff', creatingBackup ? '#7a8fa8' : '#080b10')}>
              {creatingBackup ? '⏳ CREATING...' : '📦 CREATE BACKUP'}
            </button>
          </div>
          {backups.length > 0 ? (
            <table style={S.table}>
              <thead><tr><th style={S.th}>Name</th><th style={S.th}>Created</th><th style={S.th}>Size</th><th style={S.th}>Checksum</th><th style={S.th}>Actions</th></tr></thead>
              <tbody>
                {backups.map(b => (
                  <tr key={b.id}>
                    <td style={{ ...S.td, color: '#e8edf3', fontFamily: '"Inter",system-ui,sans-serif' }}>{b.name}</td>
                    <td style={{ ...S.td, color: '#7a8fa8' }}>{b.timestamp}</td>
                    <td style={{ ...S.td, color: '#7a8fa8' }}>{b.size}</td>
                    <td style={{ ...S.td, color: '#3d5068' }} title={b.checksum}>{b.checksum}</td>
                    <td style={S.td}><div style={{ display: 'flex', gap: 4 }}>
                      <button onClick={() => handleDownloadBackup(b.id)} style={S.btn('#141923','#00d4ff')}>📥 Download</button>
                      <button onClick={() => handleRestoreBackup(b.id)} style={S.btn('rgba(255,184,0,0.12)','#ffb800')}>↺ Restore</button>
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ padding: 32, textAlign: 'center', color: '#3d5068', fontSize: 12, border: '1px dashed #1e2a38', borderRadius: 8 }}>
              No backups created yet. Snapshot includes rules, alert configs, users, VPN peers, and more.
            </div>
          )}
        </div>
      )}

      {tab === 'Cluster' && (
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>Cluster Nodes — {clusterNodes.length} nodes</h3>
          <table style={S.table}>
            <thead><tr><th style={S.th}>Node ID</th><th style={S.th}>Address</th><th style={S.th}>Role</th><th style={S.th}>Status</th><th style={S.th}>Last Heartbeat</th><th style={S.th}>Actions</th></tr></thead>
            <tbody>
              {clusterNodes.map(n => (
                <tr key={n.id}>
                  <td style={{ ...S.td, color: '#e8edf3', fontFamily: '"JetBrains Mono",monospace' }}>{n.id}</td>
                  <td style={{ ...S.td, color: '#7a8fa8' }}>{n.ip}</td>
                  <td style={S.td}><Badge type={n.role === 'Leader' ? 'purple' : 'info'} label={n.role} /></td>
                  <td style={S.td}><span style={S.statusDot(n.healthy ? COLORS.green : COLORS.red, true)} /> {n.healthy ? 'ONLINE' : 'OFFLINE'}</td>
                  <td style={{ ...S.td, color: '#7a8fa8' }}>{n.lastHearbeat}</td>
                  <td style={S.td}><button style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>✕ Remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <button style={{ ...S.btn('#141923','#00d4ff'), marginTop: 12 }}>+ REGISTER NODE</button>
        </div>
      )}

      {tab === 'Syslog' && (
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>Syslog Forwarding — {syslogConfigs.length} configs</h3>
          {syslogConfigs.length > 0 ? (
            <table style={S.table}>
              <thead><tr><th style={S.th}>Server</th><th style={S.th}>Port</th><th style={S.th}>Protocol</th><th style={S.th}>Severity</th><th style={S.th}>Actions</th></tr></thead>
              <tbody>{syslogConfigs.map(c => <tr key={c.id}><td style={S.td}>{c.server}</td><td style={S.td}>{c.port}</td><td style={S.td}>{c.protocol}</td><td style={S.td}>{c.minSeverity}</td><td style={S.td}><button style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>🗑 Delete</button></td></tr>)}</tbody>
            </table>
          ) : (
            <div style={{ padding: 32, textAlign: 'center', color: '#3d5068', fontSize: 12, border: '1px dashed #1e2a38', borderRadius: 8 }}>
              No syslog targets configured. Add SIEM endpoints to forward audit logs via RFC 5424.
            </div>
          )}
          <button style={{ ...S.btn('#141923','#00d4ff'), marginTop: 12 }}>+ ADD TARGET</button>
        </div>
      )}

      {tab === 'QoS' && (
        <div style={S.card}>
          <h3 style={{ fontSize: 12, color: '#7a8fa8', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>Traffic Shaping Policies — {qosPolicies.length} policies</h3>
          <table style={S.table}>
            <thead><tr><th style={S.th}>Name</th><th style={S.th}>Target</th><th style={S.th}>Bandwidth</th><th style={S.th}>Priority</th><th style={S.th}>Enabled</th><th style={S.th}>Actions</th></tr></thead>
            <tbody>
              {qosPolicies.map(q => (
                <tr key={q.id}>
                  <td style={{ ...S.td, color: '#e8edf3', fontFamily: '"Inter",system-ui,sans-serif' }}>{q.name}</td>
                  <td style={{ ...S.td, color: '#7a8fa8' }}>{q.target}</td>
                  <td style={{ ...S.td, color: '#7a8fa8' }}>{q.bandwidth}</td>
                  <td style={S.td}>{q.priority}</td>
                  <td style={S.td}><Toggle on={q.enabled} onChange={() => {}} /></td>
                  <td style={S.td}><button style={S.btn('rgba(255,59,92,0.12)','#ff3b5c')}>🗑 Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <button style={{ ...S.btn('#141923','#00d4ff'), marginTop: 12 }}>+ ADD POLICY</button>
        </div>
      )}
    </div>
  );
}

/* ─── SIDEBAR NAVIGATION ───────────────────────────────────────── */

const NAV_ITEMS = [
  { id: 'dashboard', icon: '◈', label: 'Dashboard' },
  { id: 'rules', icon: '⊞', label: 'Rules' },
  { id: 'connections', icon: '⊷', label: 'Connections' },
  { id: 'alerts', icon: '⚡', label: 'Alerts' },
  { id: 'audit', icon: '⊟', label: 'Audit Log' },
  { id: 'reputation', icon: '◉', label: 'Reputation' },
  { id: 'settings', icon: '⚙', label: 'Settings' },
];

function Sidebar({ page, onNavigate, unreadAlerts, username, role, onLogout }) {
  const [pulseEye, setPulseEye] = useState(false);
  useEffect(() => {
    if (unreadAlerts > 0) { setPulseEye(true); const t = setTimeout(() => setPulseEye(false), 3000); return () => clearTimeout(t); }
  }, [unreadAlerts]);

  return (
    <div style={S.sidebar}>
      <div style={S.logo}>
        <ArgusEye pulse={pulseEye} />
        <span>ARGUS</span>
      </div>
      <nav style={S.nav}>
        {NAV_ITEMS.map(item => (
          <div key={item.id} style={S.navItem(page === item.id)} onClick={() => onNavigate(item.id)}
            onMouseEnter={e => { e.currentTarget.style.background = page === item.id ? '' : 'rgba(255,255,255,0.03)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = page === item.id ? 'rgba(0,212,255,0.06)' : 'transparent'; }}>
            <span>{item.icon}</span>
            <span>{item.label}</span>
            {item.id === 'alerts' && unreadAlerts > 0 && <span style={S.navBadge}>{unreadAlerts}</span>}
          </div>
        ))}
      </nav>
      <div style={S.userSection}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div style={S.statusDot(COLORS.green, true)} />
          <span style={{ color: '#e8edf3', fontFamily: '"Inter",system-ui,sans-serif' }}>{username || 'admin'}</span>
          <Badge type="purple" label={(role || 'ADMIN').toUpperCase()} />
        </div>
        <button onClick={onLogout} style={{ ...S.btn('transparent','#7a8fa8'), fontSize: 11, padding: 0, width: '100%', justifyContent: 'flex-start' }}>⏻ Logout</button>
      </div>
    </div>
  );
}

/* ─── CSS-IN-JS STYLESHEET INJECTION ──────────────────────────── */

const stylesheet = `
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#080b10;color:#e8edf3;font-family:'Inter','Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
::selection{background:rgba(0,212,255,0.3)}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:#080b10}
::-webkit-scrollbar-thumb{background:#1e2a38;border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:#3d5068}
input:focus,select:focus{outline:none;border-color:#00d4ff!important;box-shadow:0 0 0 2px rgba(0,212,255,0.1)}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes slideInRow{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
@keyframes fadeSlideIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes modalIn{from{opacity:0;transform:scale(0.96) translateY(-8px)}to{opacity:1;transform:scale(1) translateY(0)}}
@keyframes livePulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.6;transform:scale(1.3)}}
@keyframes alertPulse{0%,100%{box-shadow:0 0 0 0 rgba(255,59,92,0.4)}50%{box-shadow:0 0 0 8px rgba(255,59,92,0)}}
button:hover{filter:brightness(1.1)}
`;

/* ─── ROOT APP COMPONENT ──────────────────────────────────────── */

export default function ArgusDashboard() {
  const [authenticated, setAuthenticated] = useState(() => api.isAuthenticated());
  const [page, setPage] = usePage();
  const data = useApiData();
  const [localAlerts, setLocalAlerts] = useState([]);
  const [rules, setRules] = useState([]);
  const [alertRules, setAlertRules] = useState([]);
  const [rulesLoading, setRulesLoading] = useState(true);
  const [username, setUsername] = useState('');
  const [role, setRole] = useState('');

  useEffect(() => {
    const style = document.createElement('style');
    style.textContent = stylesheet;
    document.head.appendChild(style);
    return () => style.remove();
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    let cancelled = false;
    (async () => {
      try {
        const [r, ar] = await Promise.all([api.listRules(), api.listAlertRules()]);
        if (!cancelled) { setRules(r); setAlertRules(ar); }
      } catch {} finally { if (!cancelled) setRulesLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [authenticated]);

  useEffect(() => {
    if (data.alerts.length > 0) {
      setLocalAlerts(prev => {
        const newAlerts = data.alerts.filter(a => !prev.find(p => p.id === a.id));
        return [...newAlerts, ...prev].slice(0, 5);
      });
    }
  }, [data.alerts]);

  const dismissAlert = useCallback((id) => setLocalAlerts(prev => prev.filter(a => a.id !== id)), []);

  useEffect(() => {
    if (localAlerts.length > 0) {
      const timer = setTimeout(() => setLocalAlerts(prev => prev.slice(0, -1)), 8000);
      return () => clearTimeout(timer);
    }
  }, [localAlerts.length]);

  const handleToggle = useCallback(async (id) => {
    const rule = rules.find(r => r.id === id);
    if (!rule) return;
    try {
      await api.updateRule(id, { enabled: !rule.enabled });
      setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
    } catch {}
  }, [rules]);

  const handleDelete = useCallback(async (id) => {
    try {
      await api.deleteRule(id);
      setRules(prev => prev.filter(r => r.id !== id));
    } catch {}
  }, []);

  const handleDuplicate = useCallback(async (id) => {
    if (!id) {
      try { const r = await api.listRules(); setRules(r); } catch {}
      return;
    }
    const rule = rules.find(r => r.id === id);
    if (!rule) return;
    try {
      const { id: _, ...rest } = rule;
      await api.createRule({ ...rest, name: `${rest.name} (copy)` });
      const updated = await api.listRules();
      setRules(updated);
    } catch {}
  }, [rules]);

  const handleAck = useCallback(async (id) => {
    try { await api.acknowledgeAlert(id); } catch {}
    setLocalAlerts(prev => prev.filter(a => a.id !== id));
  }, []);

  const handleLogin = useCallback(() => {
    setAuthenticated(true);
    setUsername(localStorage.getItem('argus_username') || 'admin');
    setRole(api.getRole() || 'Admin');
    try { window.location.hash = 'dashboard'; } catch {}
  }, []);

  const handleLogout = useCallback(() => {
    api.logout();
    setAuthenticated(false);
    setUsername('');
    setRole('');
  }, []);

  if (!authenticated) {
    return <LoginPage onLogin={handleLogin} />;
  }

  const renderPage = () => {
    try {
      switch (page) {
        case 'dashboard': return <Dashboard data={data} />;
        case 'rules': return <Rules rules={rules} onToggle={handleToggle} onDelete={handleDelete} onDuplicate={handleDuplicate} />;
        case 'connections': return <Connections conns={data.conns} />;
        case 'alerts': return <Alerts alerts={localAlerts} alertRules={alertRules} onAck={handleAck} />;
        case 'audit': return <Audit />;
        case 'reputation': return <Reputation />;
        case 'settings': return <Settings />;
        default: return <Dashboard data={data} />;
      }
    } catch (e) {
      return (
        <div style={{ padding: 40, textAlign: 'center', border: '1px solid #1e2a38', borderRadius: 8, background: '#0d1117' }}>
          <div style={{ color: '#ff3b5c', fontSize: 16, marginBottom: 8 }}>⚠ Error</div>
          <div style={{ color: '#7a8fa8', fontSize: 12 }}>Something went wrong loading this page.</div>
        </div>
      );
    }
  };

  return (
    <div style={S.root}>
      <Sidebar page={page} onNavigate={setPage} unreadAlerts={localAlerts.length} username={username} role={role} onLogout={handleLogout} />
      <main style={S.main}>
        {renderPage()}
      </main>
      <Toast alerts={localAlerts} onDismiss={dismissAlert} />
    </div>
  );
}