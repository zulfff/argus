import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, LoadingError } from '../components/Shared.jsx';

const scoreColor = (s) => s <= -50 ? 'var(--red)' : s <= 0 ? 'var(--yellow)' : 'var(--green)';
const scoreLabel = (s) => s <= -50 ? 'MALICIOUS' : s <= 0 ? 'SUSPICIOUS' : 'CLEAN';

export default function Reputation() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchIp, setSearchIp] = useState('');
  const [lookedUp, setLookedUp] = useState(null);
  const [lookingUp, setLookingUp] = useState(false);
  const [filter, setFilter] = useState('all');

  const fetch = async () => { setLoading(true); try { setEntries(await api.reputation.list()); setError(null); } catch (e) { setError(e.message); } finally { setLoading(false); } };
  useEffect(() => { fetch(); }, []);

  const lookup = async () => {
    if (!searchIp) return;
    setLookingUp(true);
    try { setLookedUp(await api.reputation.get(searchIp)); } catch (e) { setLookedUp({ ip: searchIp, error: e.message }); }
    finally { setLookingUp(false); }
  };

  const filtered = useMemo(() => {
    if (filter === 'blocklisted') return entries.filter((e) => e.score <= -50);
    if (filter === 'suspicious') return entries.filter((e) => e.score > -50 && e.score <= 0);
    return entries;
  }, [entries, filter]);

  const malicious = entries.filter((e) => e.score <= -50).length;
  const suspicious = entries.filter((e) => e.score > -50 && e.score <= 0).length;
  const clean = entries.filter((e) => e.score > 0).length;

  return (
    <div className="fade-in">
      <PageHeader title="IP Reputation" subtitle="Threat intelligence & reputation scoring" />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>🔍 IP Lookup</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input-box" style={{ fontFamily: 'var(--font-mono)', flex: 1 }} placeholder="Enter IP address..." value={searchIp} onChange={(e) => setSearchIp(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && lookup()} />
            <button className="btn btn-primary" onClick={lookup} disabled={lookingUp}>{lookingUp ? '...' : 'Check'}</button>
          </div>
          {lookedUp && (
            <div style={{ marginTop: 12, padding: 16, background: 'var(--bg-elevated)', borderRadius: 8, animation: 'fadeSlideIn 0.3s ease' }}>
              {lookedUp.error ? (
                <div style={{ color: 'var(--red)', fontSize: 13 }}>{lookedUp.error}</div>
              ) : (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 16 }}>{lookedUp.ip}</span>
                    <span className="badge" style={{ background: scoreColor(lookedUp.score), color: '#000', padding: '4px 12px', fontSize: 12 }}>{scoreLabel(lookedUp.score)}</span>
                  </div>
                  <div style={{ height: 10, background: 'var(--bg-border)', borderRadius: 5, overflow: 'hidden', marginBottom: 12 }}>
                    <div style={{ height: '100%', width: `${((lookedUp.score + 100) / 200) * 100}%`, background: scoreColor(lookedUp.score), borderRadius: 5, transition: 'width 0.5s ease' }} />
                  </div>
                  <div style={{ display: 'flex', gap: 16, color: 'var(--text-sec)', fontSize: 12 }}>
                    <span>Score: <strong style={{ color: scoreColor(lookedUp.score), fontFamily: 'var(--font-mono)' }}>{lookedUp.score}</strong></span>
                    <span>Last updated: {new Date(lookedUp.last_updated).toLocaleString()}</span>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>📊 Score Distribution</div>
          <div style={{ display: 'flex', gap: 8 }}>
            {[{ label: 'Malicious', count: malicious, color: 'var(--red)' }, { label: 'Suspicious', count: suspicious, color: 'var(--yellow)' }, { label: 'Clean', count: clean, color: 'var(--green)' }].map((s) => (
              <div key={s.label} style={{ flex: 1, padding: 12, background: 'var(--bg-elevated)', borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 24, color: s.color }}>{s.count}</div>
                <div className="cell-dim" style={{ fontSize: 11, marginTop: 4 }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
          <span style={{ color: 'var(--text-sec)', fontSize: 12 }}>🏆 Top Offenders</span>
          <div style={{ display: 'flex', gap: 4 }}>
            {[{ v: 'all', l: 'All' }, { v: 'suspicious', l: 'Suspicious' }, { v: 'blocklisted', l: 'Blocklisted' }].map((o) => (
              <button key={o.v} className={`btn ${filter === o.v ? 'btn-primary' : ''}`} style={{ padding: '4px 8px', fontSize: 11 }} onClick={() => setFilter(o.v)}>{o.l}</button>
            ))}
          </div>
        </div>
        {loading ? <SkeletonRows count={5} cols={5} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
          <table>
            <thead><tr>{['IP','Score','Threat Intel','Scans','Anomaly','Last Updated'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={6}><div className="empty-state"><div className="msg">No IP entries found.</div></div></td></tr> : (
                filtered.slice(0, 20).map((e, i) => (
                  <tr key={i}>
                    <td className="cell-mono">{e.ip}</td>
                    <td><span className="badge" style={{ background: scoreColor(e.score), color: '#000' }}>{e.score}</span></td>
                    <td className="cell-mono cell-dim">{e.threat_intel_hits}</td>
                    <td className="cell-mono cell-dim">{e.scan_attempts}</td>
                    <td className="cell-mono cell-dim">{e.anomaly_hits}</td>
                    <td className="cell-mono cell-dim" style={{ fontSize: 11 }}>{new Date(e.last_updated).toLocaleString()}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
