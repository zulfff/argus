import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';

const actionGroup = (a) => a?.split('.')[0] || '';
const colors = { login: 'var(--color-purple-400)', rule: 'var(--color-green-400)', block: 'var(--color-red-400)', backup: 'var(--color-yellow-400)', user: 'var(--color-green-400)' };

export default function Audit() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actorFilter, setActorFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [selected, setSelected] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifying, setVerifying] = useState(false);

  const fetch = async () => { setLoading(true); try { setEntries(await api.audit.list({ limit: 100 })); setError(null); } catch (e) { setError(e.message); } finally { setLoading(false); } };
  useEffect(() => { fetch(); }, []);

  const filtered = useMemo(() => entries.filter((e) => {
    const a = actionFilter === 'all' || e.action?.startsWith(actionFilter);
    const ac = !actorFilter || e.actor?.toLowerCase().includes(actorFilter.toLowerCase());
    return a && ac;
  }), [entries, actionFilter, actorFilter]);

  const verify = async () => { setVerifying(true); try { setVerifyResult(await api.audit.verify()); } catch (e) { setVerifyResult({ valid: false, error: e.message }); } finally { setVerifying(false); } };

  const btnCls = "inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs rounded bg-[var(--color-bg-elevated)] text-[var(--color-text-sec)] border border-[var(--color-bg-border)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text)] transition-all";
  const primaryCls = "inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded bg-[var(--color-green-400)] text-black hover:bg-[var(--color-green-500)] hover:shadow-[0_0_16px_var(--color-green-glow)] transition-all";

  return (
    <div>
      <PageHeader title="Audit Log" subtitle={`${entries.length} entries — hash-chained`}>
        <a href="/api/v1/audit/export" className={btnCls}>Export</a>
        <button className={primaryCls} onClick={verify} disabled={verifying}>{verifying ? '⏳ Verifying...' : '✓ Verify Integrity'}</button>
      </PageHeader>

      {verifyResult && (
        <div className="bg-[var(--color-bg-panel)] border rounded p-3.5 mb-3 animate-fade" style={{ borderColor: verifyResult.valid ? 'var(--color-green-400)' : 'var(--color-red-400)' }}>
          <div className="flex items-center gap-2">
            <span style={{ color: verifyResult.valid ? 'var(--color-green-400)' : 'var(--color-red-400)' }} className="text-xl">{verifyResult.valid ? '✓' : '⚠'}</span>
            <div>
              <div style={{ color: verifyResult.valid ? 'var(--color-green-400)' : 'var(--color-red-400)' }} className="font-bold text-[13px]">{verifyResult.valid ? 'Hash chain intact' : `Integrity violation — ${verifyResult.tampered_count} entries tampered`}</div>
              <div className="text-[var(--color-text-sec)] text-xs">{verifyResult.valid ? `All ${verifyResult.total_entries} entries verified` : `First broken at entry #${verifyResult.first_broken_at}`}</div>
            </div>
            <button className={btnCls + ' ml-auto'} onClick={() => setVerifyResult(null)}>✕</button>
          </div>
        </div>
      )}

      <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3 mb-3">
        <div className="flex gap-2">
          <input className="w-[160px] bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)] transition-colors" placeholder="Filter by actor..." value={actorFilter} onChange={(e) => setActorFilter(e.target.value)} />
          <select className="bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none cursor-pointer hover:border-[var(--color-text-muted)] transition-colors" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
            <option value="all">All Actions</option><option value="login">Login</option><option value="rule">Rule</option><option value="block">Block</option><option value="backup">Backup</option><option value="user">User</option>
          </select>
        </div>
      </div>

      <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded overflow-hidden mb-3">
        {loading ? <SkeletonRows count={5} cols={7} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
          <table className="w-full border-collapse">
            <thead><tr className="border-b border-[var(--color-bg-border)]">{['Timestamp','Actor','Action','Resource','IP','Status','Hash'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={7}><EmptyState msg="No audit entries match filters." /></td></tr> : (
                filtered.slice(0, 50).map((e) => (
                  <tr key={e.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors cursor-pointer" onClick={() => setSelected(selected?.id === e.id ? null : e)}>
                    <td className="px-2.5 py-2 text-mono text-[var(--color-text-sec)] text-[11px]" title={new Date(e.timestamp).toLocaleString()}>{new Date(e.timestamp).toLocaleString()}</td>
                    <td className="px-2.5 py-2 text-xs">{e.actor}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px]" style={{ color: colors[actionGroup(e.action)] || 'var(--color-text)' }}>{e.action}</td>
                    <td className="px-2.5 py-2 text-xs text-[var(--color-text-sec)]">{e.resource}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{e.ip_address || '—'}</td>
                    <td className="px-2.5 py-2"><Badge variant={e.success ? 'success' : 'failed'}>{e.success ? '✓' : '✗'}</Badge></td>
                    <td className="px-2.5 py-2 text-mono text-[var(--color-text-muted)] text-[11px]" title={e.hash}>{(e.hash || '').slice(0, 12)}...</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {entries.length > 0 && (
        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5">
          <div className="text-[var(--color-text-sec)] text-xs mb-2">🔗 Hash Chain (last 5)</div>
          <div className="flex items-center gap-1 flex-wrap">
            {entries.slice(0, 5).map((e, i) => (
              <span key={e.id} className="flex items-center gap-1">
                <div className="px-2 py-1 bg-[var(--color-bg-elevated)] rounded border border-[var(--color-bg-border)] text-mono text-[10px] text-[var(--color-text-muted)]">{(e.hash || '').slice(0, 8)}</div>
                {i < 4 && <span className="text-[var(--color-text-muted)] text-[10px]">→</span>}
              </span>
            ))}
          </div>
        </div>
      )}

      {selected && (
        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5 mt-3 animate-fade">
          <div className="flex justify-between mb-3">
            <span className="text-[var(--color-green-400)] text-xs text-mono">Audit Entry #{selected.id}</span>
            <button onClick={() => setSelected(null)} className="bg-none border-none text-[var(--color-text-sec)] cursor-pointer">✕</button>
          </div>
          <div className="grid grid-cols-3 gap-2">
            {[['Timestamp', new Date(selected.timestamp).toLocaleString()], ['Actor', selected.actor], ['Action', selected.action], ['Resource', selected.resource], ['IP', selected.ip_address || '—'], ['Status', selected.success ? 'Success' : 'Failed'], ['Hash', selected.hash], ['Previous Hash', selected.previous_hash]].map(([l, v]) => (
              <div key={l} className="p-2 bg-[var(--color-bg-elevated)] rounded border border-[var(--color-bg-border)]">
                <div className="text-[var(--color-text-sec)] text-[11px]">{l}</div>
                <div className="text-mono text-xs break-all">{v}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
