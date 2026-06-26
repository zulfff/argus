import { useState, useEffect, useRef } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { Toggle, PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';
import { primaryCls, btnCls, cardCls } from '../styles.js';

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
      <PageHeader title="Alerts" subtitle={`${unread} unacknowledged alerts`}>
        <button className={primaryCls} onClick={() => history.forEach((a) => acknowledge(a.id))}>
          ✓ Acknowledge All
        </button>
      </PageHeader>

      {toasts.map((t) => (
        <div key={t.id} className="fixed top-5 right-5 z-[2000] min-w-[340px] bg-white border-2 border-[var(--color-danger)] rounded-xl p-4 shadow-2xl shadow-red-500/30 animate-[modalIn_.2s_ease]">
          <div className="flex justify-between mb-2">
            <span className="text-[var(--color-danger)] font-bold text-sm">🚨 {t.sever?.toUpperCase()} ALERT</span>
            <button onClick={() => setToasts((p) => p.filter((x) => x.id !== t.id))} className="bg-none border-none text-[var(--color-text-muted)] hover:text-[var(--color-text)] cursor-pointer p-0 text-xl leading-none">×</button>
          </div>
          <div className="text-sm mb-3 text-[var(--color-text)]">{t.msg}</div>
          <div className="h-1 bg-gray-200 rounded-full overflow-hidden">
            <div className="h-full bg-[var(--color-danger)] animate-[toastProgress_8s_linear]" />
          </div>
        </div>
      ))}

      <div className="grid grid-cols-2 gap-6">
        <div className={cardCls}>
          <div className="text-[var(--color-text)] text-sm font-semibold mb-4 flex items-center gap-2">
            <span>📋</span>
            <span>Alert Rules</span>
          </div>
          {loading ? <SkeletonRows count={3} cols={4} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
            <div className="space-y-3">
              {rules.map((r) => (
                <div key={r.id} className="flex justify-between items-start py-3 border-b border-[var(--color-bg-border)] last:border-0">
                  <div className="flex-1">
                    <div className="text-sm font-medium text-[var(--color-text)] mb-1">{r.name}</div>
                    <div className="text-mono text-[var(--color-text-sec)] text-xs">
                      {r.condition?.BlockedIpThreshold 
                        ? `≥${r.condition.BlockedIpThreshold.count} IPs in ${r.condition.BlockedIpThreshold.window_secs}s` 
                        : r.condition?.ConnectionFlood 
                        ? `≥${r.condition.ConnectionFlood.rate_per_second} conn/s` 
                        : JSON.stringify(r.condition)}
                    </div>
                  </div>
                  <Toggle checked={r.enabled} onChange={() => toggleRule(r)} />
                </div>
              ))}
            </div>
          )}
        </div>

        <div className={cardCls}>
          <div className="text-[var(--color-text)] text-sm font-semibold mb-4 flex items-center gap-2">
            <span>📜</span>
            <span>Alert History</span>
          </div>
          {history.length === 0 ? <EmptyState msg="No alerts fired yet." /> : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto">
              {history.slice(0, 20).map((a) => (
                <div 
                  key={a.id} 
                  className={`flex gap-3 py-3 px-3 rounded-lg items-start transition-all ${
                    !a.acknowledged 
                      ? 'bg-[var(--color-danger-light)] border-l-4 border-l-[var(--color-danger)]' 
                      : 'bg-[var(--color-bg-hover)] border-l-4 border-l-transparent'
                  }`}
                >
                  <span className="text-xl">{a.severity === 'critical' ? '🔴' : a.severity === 'warning' ? '🟡' : '🟢'}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-[var(--color-text)] mb-1">{a.message || a.condition}</div>
                    <div className="text-mono text-[var(--color-text-sec)] text-xs">
                      {new Date(a.timestamp).toLocaleString()} · {a.rule_name}
                    </div>
                  </div>
                  {!a.acknowledged ? (
                    <button className={btnCls + ' !py-1 !px-3 !text-xs'} onClick={() => acknowledge(a.id)}>
                      ✓ Ack
                    </button>
                  ) : (
                    <span className="text-[var(--color-success)] text-xl">✓</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
