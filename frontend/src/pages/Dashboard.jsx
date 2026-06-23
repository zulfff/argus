import { useState, useEffect, useRef, useCallback } from 'react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import * as api from '../api.js';
import { PageHeader, LoadingError } from '../components/Shared.jsx';

const cardCls = "bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5 transition-colors hover:border-[var(--color-text-muted)]";

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
      if (msg.event_type === 'stats' && msg.data) setStats(msg.data);
      else if (msg.event_type === 'connection' && msg.data) addEvent('info', `Connection: ${msg.data.src_ip} → ${msg.data.dst_ip} (${msg.data.state})`);
      else if (msg.event_type === 'alert' && msg.data) addEvent(msg.data.severity || 'warning', msg.data.message || 'Alert fired');
    });
    return () => { clearInterval(interval); if (wsCleanup) wsCleanup(); };
  }, [fetchStats]);

  const protoData = [{ name: 'TCP', value: 45 }, { name: 'UDP', value: 22 }, { name: 'ICMP', value: 8 }];

  return (
    <div className="animate-fade">
      <PageHeader title="Dashboard" subtitle="Real-time network overview" />

      {error && <LoadingError message={error} onRetry={fetchStats} />}

      <div className="grid grid-cols-4 gap-2.5 mb-4">
        {[
          [stats?.packets_allowed?.toLocaleString() || '—', 'PACKETS ALLOWED', 'var(--color-green-400)'],
          [stats?.packets_dropped?.toLocaleString() || '—', 'PACKETS DROPPED', 'var(--color-red-400)'],
          [stats?.active_connections || '—', 'ACTIVE CONNS', 'var(--color-green-400)'],
          [stats?.blocked_ips || '—', 'BLOCKED IPS', 'var(--color-yellow-400)'],
        ].map(([val, label, color]) => (
          <div key={label} className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3 transition-colors hover:border-[var(--color-text-muted)]">
            <div className="text-[var(--color-text-sec)] text-[10px] font-medium uppercase tracking-wider mb-1">{label}</div>
            <div className="text-mono text-[26px] font-bold text-[var(--color-text)]">{val}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-2.5 mb-4">
        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-[10px] font-medium uppercase tracking-wider mb-2.5">Packet Rate</div>
          {packetWindow.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={packetWindow}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-bg-border)" />
                <XAxis dataKey="time" stroke="var(--color-text-muted)" tick={{ fontSize: 10 }} />
                <YAxis stroke="var(--color-text-muted)" tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ background: 'var(--color-bg-panel)', border: '1px solid var(--color-bg-border)', borderRadius: 4, color: 'var(--color-text)', fontSize: 12 }} />
                <Line type="monotone" dataKey="allowed" stroke="var(--color-green-400)" strokeWidth={2} dot={false} isAnimationActive animationDuration={800} />
                <Line type="monotone" dataKey="dropped" stroke="var(--color-red-400)" strokeWidth={2} dot={false} isAnimationActive animationDuration={800} />
              </LineChart>
            </ResponsiveContainer>
          ) : <div className="h-[200px] flex items-center justify-center text-[var(--color-text-muted)] text-xs">Collecting data...</div>}
        </div>

        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-[10px] font-medium uppercase tracking-wider mb-2.5">Protocol Distribution</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={protoData} dataKey="value" cx="50%" cy="50%" outerRadius={70} innerRadius={35} isAnimationActive animationDuration={800}>
                {protoData.map((e, i) => <Cell key={e.name} fill={['var(--color-green-400)', 'var(--color-blue-400)', 'var(--color-yellow-400)'][i]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--color-bg-panel)', border: '1px solid var(--color-bg-border)', borderRadius: 4, color: 'var(--color-text)', fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11, color: 'var(--color-text-sec)' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className={cardCls + ' mb-4'}>
        <div className="text-[var(--color-text-sec)] text-[10px] font-medium uppercase tracking-wider mb-2.5">Live Event Feed</div>
        <div className="max-h-60 overflow-y-auto">
          {liveEvents.length === 0 ? (
            <div className="text-[var(--color-text-muted)] text-center py-6">Waiting for events...</div>
          ) : (
            liveEvents.slice(-15).map((e, i) => (
              <div key={i} className="flex gap-2 py-1.5 border-b border-[var(--color-bg-border)] items-center">
                <span className="text-[var(--color-text-muted)] text-[11px] font-mono min-w-[70px]">{e.time}</span>
                <span className={`inline-flex items-center rounded-[3px] px-2 py-0.5 text-[10px] font-semibold text-mono ${e.severity === 'critical' ? 'bg-[var(--color-red-400)] text-white' : e.severity === 'warning' ? 'bg-[var(--color-yellow-400)] text-black' : 'bg-[var(--color-green-400)] text-black'}`}>{e.severity || 'info'}</span>
                <span className="text-xs text-mono">{e.msg}</span>
              </div>
            ))
          )}
        </div>
      </div>

      <div className={cardCls}>
        <div className="text-[var(--color-text-sec)] text-[10px] font-medium uppercase tracking-wider mb-2.5">System Health</div>
        {[
          { label: 'API', status: stats ? 'ONLINE' : '—', color: stats ? 'var(--color-green-400)' : 'var(--color-red-400)' },
          { label: 'eBPF', status: stats?.packets_allowed != null ? 'ACTIVE' : '—', color: stats?.packets_allowed != null ? 'var(--color-green-400)' : 'var(--color-red-400)' },
          { label: 'DB', status: 'IN-MEMORY', color: 'var(--color-green-400)' },
          { label: 'WebSocket', status: 'CONNECTED', color: 'var(--color-green-400)' },
        ].map((s) => (
          <div key={s.label} className="flex items-center gap-2 py-2.5 border-b border-[var(--color-bg-border)] last:border-none">
            <span className="w-[7px] h-[7px] rounded-full animate-live shrink-0" style={{ background: s.color }} />
            <span className="text-mono text-[11px] flex-1">{s.label}</span>
            <span className="text-[var(--color-text-sec)] text-[10px] text-mono ml-auto">● {s.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
