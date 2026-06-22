import { useState, useEffect, useRef, useCallback } from 'react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import * as api from '../api.js';
import { PageHeader, LoadingError } from '../components/Shared.jsx';

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
      const now = new Date().toLocaleTimeString();
      windowRef.current = [...windowRef.current.slice(-59), { time: now, allowed: s.packets_allowed || 0, dropped: s.packets_dropped || 0 }];
      setPacketWindow([...windowRef.current]);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);

    const wsCleanup = api.connectWebSocket((msg) => {
      const addEvent = (severity, text) => setLiveEvents((prev) => [...prev.slice(-49), { time: new Date().toLocaleTimeString(), msg: text, severity }]);

      if (msg.event_type === 'stats' && msg.data) {
        setStats(msg.data);
      } else if (msg.event_type === 'connection' && msg.data) {
        addEvent('info', `Connection: ${msg.data.src_ip} → ${msg.data.dst_ip} (${msg.data.state})`);
      } else if (msg.event_type === 'alert' && msg.data) {
        addEvent(msg.data.severity || 'warning', msg.data.message || 'Alert fired');
      }
    });

    return () => {
      clearInterval(interval);
      if (wsCleanup) wsCleanup();
    };
  }, [fetchStats]);

  const protoData = [
    { name: 'TCP', value: 45 },
    { name: 'UDP', value: 22 },
    { name: 'ICMP', value: 8 },
  ];

  return (
    <div className="fade-in">
      <PageHeader title="Dashboard" subtitle="Real-time network overview" />

      {error && <LoadingError message={error} onRetry={fetchStats} />}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Packets Allowed', value: stats?.packets_allowed?.toLocaleString() || '—', color: 'var(--green)', icon: '📦' },
          { label: 'Packets Dropped', value: stats?.packets_dropped?.toLocaleString() || '—', color: 'var(--red)', icon: '🚫' },
          { label: 'Active Connections', value: stats?.active_connections || '—', color: 'var(--cyan)', icon: '🔗' },
          { label: 'Blocked IPs', value: stats?.blocked_ips || '—', color: 'var(--yellow)', icon: '🌐' },
        ].map((c) => (
          <div key={c.label} className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ color: 'var(--text-sec)', fontSize: 12 }}>{c.icon} {c.label}</span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 28, fontWeight: 700 }}>{c.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>📈 Packet Rate</div>
          {packetWindow.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={packetWindow}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--bg-border)" />
                <XAxis dataKey="time" stroke="var(--text-muted)" tick={{ fontSize: 10 }} />
                <YAxis stroke="var(--text-muted)" tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ background: 'var(--bg-panel)', border: '1px solid var(--bg-border)', borderRadius: 8, color: 'var(--text)' }} />
                <Line type="monotone" dataKey="allowed" stroke="var(--green)" strokeWidth={2} dot={false} isAnimationActive animationDuration={800} />
                <Line type="monotone" dataKey="dropped" stroke="var(--red)" strokeWidth={2} dot={false} isAnimationActive animationDuration={800} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 13 }}>Collecting data...</div>
          )}
        </div>

        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>🍩 Protocol Distribution</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={protoData} dataKey="value" cx="50%" cy="50%" outerRadius={70} innerRadius={35} isAnimationActive animationDuration={800}>
                {protoData.map((e, i) => <Cell key={e.name} fill={['var(--cyan)', 'var(--purple)', 'var(--yellow)'][i]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--bg-panel)', border: '1px solid var(--bg-border)', borderRadius: 8, color: 'var(--text)' }} />
              <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-sec)' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>⚡ Live Event Feed</div>
        <div style={{ maxHeight: 240, overflowY: 'auto' }}>
          {liveEvents.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 24 }}>Waiting for events...</div>
          ) : (
            liveEvents.slice(-15).map((e, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--bg-border)', alignItems: 'center' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)', minWidth: 70 }}>{e.time}</span>
                <span className="badge" style={{ background: e.severity === 'critical' ? 'var(--red)' : e.severity === 'warning' ? 'var(--yellow)' : 'var(--cyan)', color: e.severity === 'critical' ? '#fff' : '#000' }}>{e.severity || 'info'}</span>
                <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)' }}>{e.msg}</span>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="card">
        <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>🔋 System Health</div>
        {[
          { label: 'API', status: stats ? 'ONLINE' : '—', color: stats ? 'var(--green)' : 'var(--red)' },
          { label: 'eBPF', status: stats?.packets_allowed != null ? 'ACTIVE' : '—', color: stats?.packets_allowed != null ? 'var(--green)' : 'var(--red)' },
          { label: 'DB', status: 'IN-MEMORY', color: 'var(--cyan)' },
          { label: 'WebSocket', status: 'CONNECTED', color: 'var(--green)' },
        ].map((s) => (
          <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 0', borderBottom: '1px solid var(--bg-border)' }}>
            <span className="live-dot" style={{ background: s.color, animation: 'livePulse 2s infinite' }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{s.label}</span>
            <span style={{ color: 'var(--text-sec)', fontSize: 12, marginLeft: 'auto' }}>● {s.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
