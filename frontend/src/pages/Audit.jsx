import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';
import { inputCls, selectCls, btnCls, primaryCls, successCls, cardCls, tableCls, tableRowCls, tableHeaderCls, tableCellCls } from '../styles.js';

const actionGroup = (a) => a?.split('.')[0] || '';
const colors = { 
  login: 'var(--color-primary)', 
  rule: 'var(--color-success)', 
  block: 'var(--color-danger)', 
  backup: 'var(--color-warning)', 
  user: 'var(--color-info)' 
};

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

  return (
    <div>
      <PageHeader title="Audit Log" subtitle={`${entries.length} entries — cryptographically hash-chained`}>
        <a href="/api/v1/audit/export" className={btnCls}>📥 Export</a>
        <button className={successCls} onClick={verify} disabled={verifying}>
          {verifying ? '⏳ Verifying...' : '✓ Verify Integrity'}
        </button>
      </PageHeader>

      {verifyResult && (
        <div 
          className={`${cardCls} mb-6 border-2 animate-fade`} 
          style={{ 
            borderColor: verifyResult.valid ? 'var(--color-success)' : 'var(--color-danger)',
            background: verifyResult.valid ? 'var(--color-success-light)' : 'var(--color-danger-light)'
          }}
        >
          <div className="flex items-center gap-3">
            <span 
              style={{ color: verifyResult.valid ? 'var(--color-success)' : 'var(--color-danger)' }} 
              className="text-3xl"
            >
              {verifyResult.valid ? '✓' : '⚠'}
            </span>
            <div className="flex-1">
              <div 
                style={{ color: verifyResult.valid ? 'var(--color-success)' : 'var(--color-danger)' }} 
                className="font-bold text-sm mb-1"
              >
                {verifyResult.valid ? 'Hash chain intact' : `Integrity violation — ${verifyResult.tampered_count} entries tampered`}
              </div>
              <div className="text-[var(--color-text-sec)] text-xs">
                {verifyResult.valid ? `All ${verifyResult.total_entries} entries verified` : `First broken at entry #${verifyResult.first_broken_at}`}
              </div>
            </div>
            <button className={btnCls} onClick={() => setVerifyResult(null)}>×</button>
          </div>
        </div>
      )}

      <div className={cardCls + ' mb-6'}>
        <div className="flex gap-2">
          <input className={inputCls + ' !w-[200px]'} placeholder="Filter by actor..." value={actorFilter} onChange={(e) => setActorFilter(e.target.value)} />
          <select className={selectCls} value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
            <option value="all">All Actions</option>
            <option value="login">Login</option>
            <option value="rule">Rule</option>
            <option value="block">Block</option>
            <option value="backup">Backup</option>
            <option value="user">User</option>
          </select>
        </div>
      </div>

      <div className={tableCls}>
        {loading ? <SkeletonRows count={8} cols={7} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
          <table className="w-full border-collapse">
            <thead>
              <tr>
                {['Timestamp','Actor','Action','Resource','IP Address','Status','Hash'].map((h) => (
                  <th key={h} className={tableHeaderCls}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={7}><EmptyState msg="No audit entries match your filters." /></td></tr>
              ) : (
                filtered.slice(0, 100).map((e) => (
                  <tr 
                    key={e.id} 
                    className={tableRowCls + ' cursor-pointer'} 
                    onClick={() => setSelected(selected?.id === e.id ? null : e)}
                  >
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'} title={new Date(e.timestamp).toISOString()}>
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className={tableCellCls + ' font-medium'}>{e.actor}</td>
                    <td className={tableCellCls + ' text-mono'} style={{ color: colors[actionGroup(e.action)] || 'var(--color-text)' }}>
                      {e.action}
                    </td>
                    <td className={tableCellCls + ' text-[var(--color-text-sec)]'}>{e.resource}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{e.ip_address || '—'}</td>
                    <td className={tableCellCls}>
                      <Badge variant={e.success ? 'success' : 'failed'}>{e.success ? '✓' : '✗'}</Badge>
                    </td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-muted)] text-xs'} title={e.hash}>
                      {(e.hash || '').slice(0, 16)}...
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {entries.length > 0 && (
        <div className={cardCls + ' mt-6'}>
          <div className="text-[var(--color-text)] text-sm font-semibold mb-4 flex items-center gap-2">
            <span>🔗</span>
            <span>Hash Chain (last 5 entries)</span>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {entries.slice(0, 5).map((e, i) => (
              <span key={e.id} className="flex items-center gap-2">
                <div className="px-3 py-2 bg-[var(--color-bg-hover)] rounded-lg border border-[var(--color-bg-border)] text-mono text-xs text-[var(--color-text-muted)]">
                  {(e.hash || '').slice(0, 12)}
                </div>
                {i < 4 && <span className="text-[var(--color-text-muted)] text-lg">→</span>}
              </span>
            ))}
          </div>
        </div>
      )}

      {selected && (
        <div className={cardCls + ' mt-6 animate-fade'}>
          <div className="flex justify-between items-start mb-4">
            <h3 className="text-sm font-semibold text-[var(--color-text)]">Audit Entry #{selected.id}</h3>
            <button onClick={() => setSelected(null)} className="text-[var(--color-text-muted)] hover:text-[var(--color-text)] text-xl leading-none">×</button>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            {[
              ['Timestamp', new Date(selected.timestamp).toLocaleString()], 
              ['Actor', selected.actor], 
              ['Action', selected.action], 
              ['Resource', selected.resource], 
              ['IP Address', selected.ip_address || '—'], 
              ['Status', selected.success ? '✓ Success' : '✗ Failed'], 
              ['Hash', selected.hash], 
              ['Previous Hash', selected.previous_hash]
            ].map(([l, v]) => (
              <div key={l}>
                <div className="text-[var(--color-text-sec)] text-xs font-medium mb-1">{l}</div>
                <div className="text-[var(--color-text)] font-mono text-xs break-all">{v}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
