import { useState, useEffect, useRef } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { Toggle, PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';

export default function Alerts() {
  const [rules, setRules] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toasts, setToasts] = useState([]);
  const prevLen = useRef(0);

  const fetch = async () => { try { const [r, h] = await Promise.all([api.alerts.rules.list(), api.alerts.history.list()]); setRules(r); setHistory(h); setError(null); } catch (e) { setError(e.message); } finally { setLoading(false); } };
  useEffect(() => { fetch(); }, []);

  useEffect(() => {
    if (history.length > prevLen.current && history.length > 0 && !history[0].acknowledged) {
      const a = history[0];
      setToasts((p) => [...p, { id: a.id, msg: a.message || a.condition, sever: a.severity }]);
      setTimeout(() => setToasts((p) => p.filter((t) => t.id !== a.id)), 8000);
    }
    prevLen.current = history.length;
  }, [history]);

  const acknowledge = async (id) => { try { await api.alerts.history.acknowledge(id); setHistory((p) => p.map((a) => a.id === id ? { ...a, acknowledged: true } : a)); } catch {} };
  const toggleRule = async (r) => { try { const updated = { ...r, enabled: !r.enabled }; await api.alerts.rules.create(updated); setRules((p) => p.map((x) => x.id === r.id ? updated : x)); } catch {} };

  const unread = history.filter((a) => !a.acknowledged).length;

  return (
    <div className="fade-in">
      <PageHeader title="Alerts" subtitle={`${unread} unacknowledged`}>
        <button className="btn btn-primary" onClick={() => history.forEach((a) => acknowledge(a.id))}>Acknowledge All</button>
      </PageHeader>

      {toasts.map((t) => (
        <div key={t.id} className="toast">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ color: 'var(--red)', fontWeight: 700, fontSize: 12 }}>🚨 {t.sever?.toUpperCase()} ALERT</span>
            <button onClick={() => setToasts((p) => p.filter((x) => x.id !== t.id))} style={{ background: 'none', border: 'none', color: 'var(--text-sec)', cursor: 'pointer', padding: 0 }}>✕</button>
          </div>
          <div style={{ fontSize: 13, marginBottom: 4 }}>{t.msg}</div>
          <div className="progress"><div className="progress-bar" /></div>
        </div>
      ))}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>📋 Alert Rules</div>
          {loading ? <SkeletonRows count={3} cols={4} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
            rules.map((r) => (
              <div key={r.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--bg-border)' }}>
                <div>
                  <div style={{ fontSize: 13 }}>{r.name}</div>
                  <div className="cell-mono cell-dim" style={{ fontSize: 11 }}>{r.condition?.BlockedIpThreshold ? `≥${r.condition.BlockedIpThreshold.count} IPs in ${r.condition.BlockedIpThreshold.window_secs}s` : r.condition?.ConnectionFlood ? `≥${r.condition.ConnectionFlood.rate_per_second} conn/s` : JSON.stringify(r.condition)}</div>
                </div>
                <Toggle checked={r.enabled} onChange={() => toggleRule(r)} />
              </div>
            ))
          )}
        </div>

        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>📜 Alert History</div>
          {history.length === 0 ? <EmptyState msg="No alerts fired yet." /> : (
            history.slice(0, 20).map((a) => (
              <div key={a.id} style={{ display: 'flex', gap: 8, padding: '8px 0', borderBottom: '1px solid var(--bg-border)', alignItems: 'center', borderLeft: `3px solid ${a.acknowledged ? 'var(--text-muted)' : 'var(--red)'}`, paddingLeft: 8 }}>
                <span>{a.severity === 'critical' ? '🔴' : a.severity === 'warning' ? '🟡' : '🟢'}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12 }}>{a.message || a.condition}</div>
                  <div className="cell-mono cell-dim" style={{ fontSize: 11 }}>{new Date(a.timestamp).toLocaleString()} — {a.rule_name}</div>
                </div>
                {!a.acknowledged ? (
                  <button className="btn" style={{ padding: '4px 8px', fontSize: 11 }} onClick={() => acknowledge(a.id)}>✓ Ack</button>
                ) : <span style={{ color: 'var(--green)', fontSize: 16 }}>✓</span>}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
