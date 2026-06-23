import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, LoadingError } from '../components/Shared.jsx';

const scoreColor = (s) => s <= -50 ? 'var(--color-red-400)' : s <= 0 ? 'var(--color-yellow-400)' : 'var(--color-green-400)';
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

  const inputCls = "bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)] transition-colors";
  const btnCls = "inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs rounded bg-[var(--color-bg-elevated)] text-[var(--color-text-sec)] border border-[var(--color-bg-border)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text)] transition-all";
  const primaryCls = "inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded bg-[var(--color-green-400)] text-black hover:bg-[var(--color-green-500)] hover:shadow-[0_0_16px_var(--color-green-glow)] transition-all";

  return (
    <div>
      <PageHeader title="IP Reputation" subtitle="Threat intelligence & reputation scoring" />

      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5">
          <div className="text-[var(--color-text-sec)] text-xs mb-3">🔍 IP Lookup</div>
          <div className="flex gap-2">
            <input className={inputCls + ' text-mono flex-1'} placeholder="Enter IP address..." value={searchIp} onChange={(e) => setSearchIp(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && lookup()} />
            <button className={primaryCls} onClick={lookup} disabled={lookingUp}>{lookingUp ? '...' : 'Check'}</button>
          </div>
          {lookedUp && (
            <div className="mt-3 p-4 bg-[var(--color-bg-elevated)] rounded animate-fade">
              {lookedUp.error ? (
                <div className="text-[var(--color-red-400)] text-[13px]">{lookedUp.error}</div>
              ) : (
                <>
                  <div className="flex justify-between mb-3">
                    <span className="text-mono text-base">{lookedUp.ip}</span>
                    <span className="inline-flex items-center rounded-[3px] px-3 py-1 text-xs font-semibold text-mono text-black" style={{ background: scoreColor(lookedUp.score) }}>{scoreLabel(lookedUp.score)}</span>
                  </div>
                  <div className="h-2.5 bg-[var(--color-bg-border)] rounded overflow-hidden mb-3">
                    <div className="h-full rounded transition-all duration-500" style={{ width: `${((lookedUp.score + 100) / 200) * 100}%`, background: scoreColor(lookedUp.score) }} />
                  </div>
                  <div className="flex gap-4 text-[var(--color-text-sec)] text-xs">
                    <span>Score: <strong className="text-mono" style={{ color: scoreColor(lookedUp.score) }}>{lookedUp.score}</strong></span>
                    <span>Last updated: {new Date(lookedUp.last_updated).toLocaleString()}</span>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5">
          <div className="text-[var(--color-text-sec)] text-xs mb-3">📊 Score Distribution</div>
          <div className="flex gap-2">
            {[{ label: 'Malicious', count: malicious, color: 'var(--color-red-400)' }, { label: 'Suspicious', count: suspicious, color: 'var(--color-yellow-400)' }, { label: 'Clean', count: clean, color: 'var(--color-green-400)' }].map((s) => (
              <div key={s.label} className="flex-1 p-3 bg-[var(--color-bg-elevated)] rounded text-center">
                <div className="text-mono text-2xl" style={{ color: s.color }}>{s.count}</div>
                <div className="text-[var(--color-text-sec)] text-[11px] mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5">
        <div className="flex justify-between mb-3">
          <span className="text-[var(--color-text-sec)] text-xs">🏆 Top Offenders</span>
          <div className="flex gap-1">
            {[{ v: 'all', l: 'All' }, { v: 'suspicious', l: 'Suspicious' }, { v: 'blocklisted', l: 'Blocklisted' }].map((o) => (
              <button key={o.v} className={`px-2 py-1 text-[11px] rounded transition-all ${filter === o.v ? 'bg-[var(--color-green-400)] text-black font-medium' : 'bg-[var(--color-bg-elevated)] text-[var(--color-text-sec)] border border-[var(--color-bg-border)] hover:bg-[var(--color-bg-hover)]'}`} onClick={() => setFilter(o.v)}>{o.l}</button>
            ))}
          </div>
        </div>
        {loading ? <SkeletonRows count={5} cols={5} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
          <table className="w-full border-collapse">
            <thead><tr className="border-b border-[var(--color-bg-border)]">{['IP','Score','Threat Intel','Scans','Anomaly','Last Updated'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={6}><div className="text-center py-10 px-6 text-[var(--color-text-sec)]"><div className="text-[13px]">No IP entries found.</div></div></td></tr> : (
                filtered.slice(0, 20).map((e, i) => (
                  <tr key={i} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors">
                    <td className="px-2.5 py-2 text-mono text-[11px]">{e.ip}</td>
                    <td className="px-2.5 py-2"><span className="inline-flex items-center rounded-[3px] px-2 py-0.5 text-[10px] font-semibold text-mono text-black" style={{ background: scoreColor(e.score) }}>{e.score}</span></td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{e.threat_intel_hits}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{e.scan_attempts}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{e.anomaly_hits}</td>
                    <td className="px-2.5 py-2 text-mono text-[var(--color-text-sec)] text-[11px]">{new Date(e.last_updated).toLocaleString()}</td>
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
