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
    <div>
      <PageHeader title="Alerts" subtitle={`${unread} unacknowledged`}>
        <button className="inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded bg-[var(--color-green-400)] text-black hover:bg-[var(--color-green-500)] hover:shadow-[0_0_16px_var(--color-green-glow)] transition-all" onClick={() => history.forEach((a) => acknowledge(a.id))}>Acknowledge All</button>
      </PageHeader>

      {toasts.map((t) => (
        <div key={t.id} className="fixed top-3.5 right-3.5 z-[2000] min-w-[300px] bg-[var(--color-bg-panel)] border border-[var(--color-red-400)] rounded p-2.5 px-3.5 shadow-[0_0_24px_var(--color-red-glow)] animate-[modalIn_.15s_ease]">
          <div className="flex justify-between mb-1">
            <span className="text-[var(--color-red-400)] font-bold text-xs">🚨 {t.sever?.toUpperCase()} ALERT</span>
            <button onClick={() => setToasts((p) => p.filter((x) => x.id !== t.id))} className="bg-none border-none text-[var(--color-text-sec)] cursor-pointer p-0">✕</button>
          </div>
          <div className="text-[13px] mb-1">{t.msg}</div>
          <div className="h-0.5 bg-[var(--color-bg-border)] rounded-sm overflow-hidden mt-1.5"><div className="h-full bg-[var(--color-red-400)] animate-[toastProgress_8s_linear]" /></div>
        </div>
      ))}

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5">
          <div className="text-[var(--color-text-sec)] text-[10px] font-medium uppercase tracking-wider mb-3">📋 Alert Rules</div>
          {loading ? <SkeletonRows count={3} cols={4} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
            rules.map((r) => (
              <div key={r.id} className="flex justify-between items-center py-2 border-b border-[var(--color-bg-border)]">
                <div>
                  <div className="text-[13px]">{r.name}</div>
                  <div className="text-mono text-[var(--color-text-sec)] text-[11px]">{r.condition?.BlockedIpThreshold ? `≥${r.condition.BlockedIpThreshold.count} IPs in ${r.condition.BlockedIpThreshold.window_secs}s` : r.condition?.ConnectionFlood ? `≥${r.condition.ConnectionFlood.rate_per_second} conn/s` : JSON.stringify(r.condition)}</div>
                </div>
                <Toggle checked={r.enabled} onChange={() => toggleRule(r)} />
              </div>
            ))
          )}
        </div>

        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5">
          <div className="text-[var(--color-text-sec)] text-[10px] font-medium uppercase tracking-wider mb-3">📜 Alert History</div>
          {history.length === 0 ? <EmptyState msg="No alerts fired yet." /> : (
            history.slice(0, 20).map((a) => (
              <div key={a.id} className={`flex gap-2 py-2 border-b border-[var(--color-bg-border)] items-center pl-2 ${!a.acknowledged ? '!border-l-2 !border-l-[var(--color-red-400)]' : '!border-l-2 !border-l-transparent'}`}>
                <span>{a.severity === 'critical' ? '🔴' : a.severity === 'warning' ? '🟡' : '🟢'}</span>
                <div className="flex-1">
                  <div className="text-xs">{a.message || a.condition}</div>
                  <div className="text-mono text-[var(--color-text-sec)] text-[11px]">{new Date(a.timestamp).toLocaleString()} — {a.rule_name}</div>
                </div>
                {!a.acknowledged ? (
                  <button className="inline-flex items-center justify-center gap-1.5 px-2 py-1 text-[11px] rounded bg-[var(--color-bg-elevated)] text-[var(--color-text-sec)] border border-[var(--color-bg-border)] hover:bg-[var(--color-bg-hover)] transition-all" onClick={() => acknowledge(a.id)}>✓ Ack</button>
                ) : <span className="text-[var(--color-green-400)] text-base">✓</span>}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
