import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';

const actionGroup = (a) => a?.split('.')[0] || '';

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

  const colors = { login: 'var(--purple)', rule: 'var(--cyan)', block: 'var(--red)', backup: 'var(--yellow)', user: 'var(--green)' };

  return (
    <div className="fade-in">
      <PageHeader title="Audit Log" subtitle={`${entries.length} entries — hash-chained`}>
        <a href="/api/v1/audit/export" className="btn">Export JSON</a>
        <button className="btn btn-primary" onClick={verify} disabled={verifying}>{verifying ? '⏳ Verifying...' : '✓ Verify Integrity'}</button>
      </PageHeader>

      {verifyResult && (
        <div className="card" style={{ marginBottom: 12, borderColor: verifyResult.valid ? 'var(--green)' : 'var(--red)', animation: 'fadeSlideIn 0.3s ease' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: verifyResult.valid ? 'var(--green)' : 'var(--red)', fontSize: 20 }}>{verifyResult.valid ? '✓' : '⚠'}</span>
            <div>
              <div style={{ color: verifyResult.valid ? 'var(--green)' : 'var(--red)', fontWeight: 700, fontSize: 13 }}>{verifyResult.valid ? 'Hash chain intact' : `Integrity violation — ${verifyResult.tampered_count} entries tampered`}</div>
              <div className="cell-dim" style={{ fontSize: 12 }}>{verifyResult.valid ? `All ${verifyResult.total_entries} entries verified` : `First broken at entry #${verifyResult.first_broken_at}`}</div>
            </div>
            <button className="btn" style={{ marginLeft: 'auto' }} onClick={() => setVerifyResult(null)}>✕</button>
          </div>
        </div>
      )}

      <div className="panel" style={{ padding: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="input-box" style={{ width: 160 }} placeholder="Filter by actor..." value={actorFilter} onChange={(e) => setActorFilter(e.target.value)} />
          <select className="select-box" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
            <option value="all">All Actions</option><option value="login">Login</option><option value="rule">Rule</option><option value="block">Block</option><option value="backup">Backup</option><option value="user">User</option>
          </select>
        </div>
      </div>

      <div className="panel" style={{ overflow: 'hidden', marginBottom: 12 }}>
        {loading ? <SkeletonRows count={5} cols={7} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
          <table>
            <thead><tr>{['Timestamp','Actor','Action','Resource','IP','Status','Hash'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={7}><EmptyState msg="No audit entries match filters." /></td></tr> : (
                filtered.slice(0, 50).map((e) => (
                  <tr key={e.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(selected?.id === e.id ? null : e)}>
                    <td className="cell-mono cell-dim" style={{ fontSize: 11 }} title={new Date(e.timestamp).toLocaleString()}>{new Date(e.timestamp).toLocaleString()}</td>
                    <td>{e.actor}</td>
                    <td className="cell-mono" style={{ color: colors[actionGroup(e.action)] || 'var(--text)' }}>{e.action}</td>
                    <td className="cell-dim">{e.resource}</td>
                    <td className="cell-mono cell-dim">{e.ip_address || '—'}</td>
                    <td><Badge variant={e.success ? 'success' : 'failed'}>{e.success ? '✓' : '✗'}</Badge></td>
                    <td className="cell-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }} title={e.hash}>{(e.hash || '').slice(0, 12)}...</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {entries.length > 0 && (
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 8 }}>🔗 Hash Chain (last 5)</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
            {entries.slice(0, 5).map((e) => (
              <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ padding: '4px 8px', background: 'var(--bg-elevated)', borderRadius: 4, border: '1px solid var(--bg-border)', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{(e.hash || '').slice(0, 8)}</div>
                <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>→</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {selected && (
        <div className="card" style={{ marginTop: 12, animation: 'fadeSlideIn 0.2s ease' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ color: 'var(--cyan)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>Audit Entry #{selected.id}</span>
            <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--text-sec)', cursor: 'pointer' }}>✕</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            {[['Timestamp', new Date(selected.timestamp).toLocaleString()], ['Actor', selected.actor], ['Action', selected.action], ['Resource', selected.resource], ['IP', selected.ip_address || '—'], ['Status', selected.success ? 'Success' : 'Failed'], ['Hash', selected.hash], ['Previous Hash', selected.previous_hash]].map(([l, v]) => (
              <div key={l} style={{ padding: 8, background: 'var(--bg-elevated)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-sec)', fontSize: 11 }}>{l}</div>
                <div className="cell-mono" style={{ wordBreak: 'break-all' }}>{v}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
