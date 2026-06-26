import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, LoadingError } from '../components/Shared.jsx';
import { inputCls, selectCls, primaryCls, cardCls, tableCls, tableRowCls, tableHeaderCls, tableCellCls } from '../styles.js';

const scoreColor = (s) => s <= -50 ? 'var(--color-danger)' : s <= 0 ? 'var(--color-warning)' : 'var(--color-success)';
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
    <div>
      <PageHeader title="IP Reputation" subtitle="Threat intelligence & reputation scoring" />

      <div className="grid grid-cols-3 gap-4 mb-6">
        <StatCard label="Malicious" value={malicious} color="var(--color-danger)" />
        <StatCard label="Suspicious" value={suspicious} color="var(--color-warning)" />
        <StatCard label="Clean" value={clean} color="var(--color-success)" />
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        <div className={cardCls}>
          <div className="text-sm font-semibold text-[var(--color-text)] mb-4 flex items-center gap-2">
            <span>🔍</span>
            <span>IP Lookup</span>
          </div>
          <div className="flex gap-2 mb-4">
            <input 
              className={inputCls + ' text-mono flex-1'} 
              placeholder="Enter IP address (e.g. 1.2.3.4)..." 
              value={searchIp} 
              onChange={(e) => setSearchIp(e.target.value)} 
              onKeyDown={(e) => e.key === 'Enter' && lookup()} 
            />
            <button className={primaryCls} onClick={lookup} disabled={lookingUp}>
              {lookingUp ? '⏳ Checking...' : '🔍 Check'}
            </button>
          </div>
          {lookedUp && (
            <div className="p-4 rounded-lg border-2 animate-fade" style={{ 
              borderColor: lookedUp.error ? 'var(--color-danger)' : scoreColor(lookedUp.score),
              background: lookedUp.error ? 'var(--color-danger-light)' : 'var(--color-bg-hover)'
            }}>
              {lookedUp.error ? (
                <div className="text-[var(--color-danger)] text-sm font-medium">{lookedUp.error}</div>
              ) : (
                <>
                  <div className="flex justify-between items-center mb-4">
                    <span className="text-mono text-lg font-bold text-[var(--color-text)]">{lookedUp.ip}</span>
                    <span 
                      className="inline-flex items-center rounded-lg px-4 py-2 text-sm font-bold text-white shadow-sm" 
                      style={{ background: scoreColor(lookedUp.score) }}
                    >
                      {scoreLabel(lookedUp.score)}
                    </span>
                  </div>
                  <div className="h-3 bg-gray-200 rounded-full overflow-hidden mb-4">
                    <div 
                      className="h-full rounded-full transition-all duration-500" 
                      style={{ 
                        width: `${((lookedUp.score + 100) / 200) * 100}%`, 
                        background: scoreColor(lookedUp.score) 
                      }} 
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <div className="text-[var(--color-text-sec)] text-xs mb-1">Score</div>
                      <div className="text-mono text-lg font-bold" style={{ color: scoreColor(lookedUp.score) }}>
                        {lookedUp.score}
                      </div>
                    </div>
                    <div>
                      <div className="text-[var(--color-text-sec)] text-xs mb-1">Last Updated</div>
                      <div className="text-[var(--color-text)] text-sm">
                        {new Date(lookedUp.last_updated).toLocaleString()}
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        <div className={cardCls}>
          <div className="text-sm font-semibold text-[var(--color-text)] mb-4 flex items-center gap-2">
            <span>📊</span>
            <span>Score Distribution</span>
          </div>
          <div className="space-y-3">
            {[
              { label: 'Malicious (≤ -50)', count: malicious, color: 'var(--color-danger)', percent: (malicious / (entries.length || 1)) * 100 }, 
              { label: 'Suspicious (-50 to 0)', count: suspicious, color: 'var(--color-warning)', percent: (suspicious / (entries.length || 1)) * 100 }, 
              { label: 'Clean (> 0)', count: clean, color: 'var(--color-success)', percent: (clean / (entries.length || 1)) * 100 }
            ].map((s) => (
              <div key={s.label}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-[var(--color-text)]">{s.label}</span>
                  <span className="font-bold text-mono" style={{ color: s.color }}>{s.count}</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div 
                    className="h-full rounded-full transition-all duration-500" 
                    style={{ width: `${s.percent}%`, background: s.color }} 
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className={cardCls + ' mb-4'}>
        <div className="flex gap-2">
          <select className={selectCls} value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All IPs ({entries.length})</option>
            <option value="blocklisted">Malicious ({malicious})</option>
            <option value="suspicious">Suspicious ({suspicious})</option>
          </select>
        </div>
      </div>

      <div className={tableCls}>
        {loading ? <SkeletonRows count={8} cols={6} /> : error ? <LoadingError message={error} onRetry={fetch} /> : (
          <table className="w-full border-collapse">
            <thead>
              <tr>
                {['IP Address','Score','Threat Intel','Port Scans','Anomalies','Last Updated'].map((h) => (
                  <th key={h} className={tableHeaderCls}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={6} className="text-center py-10 text-[var(--color-text-sec)]">No IP entries found.</td></tr>
              ) : (
                filtered.slice(0, 50).map((e, i) => (
                  <tr key={i} className={tableRowCls}>
                    <td className={tableCellCls + ' text-mono font-medium'}>{e.ip}</td>
                    <td className={tableCellCls}>
                      <span 
                        className="inline-flex items-center rounded-lg px-3 py-1 text-xs font-bold text-white shadow-sm" 
                        style={{ background: scoreColor(e.score) }}
                      >
                        {e.score}
                      </span>
                    </td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{e.threat_intel_hits || 0}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{e.scan_attempts || 0}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{e.anomaly_hits || 0}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{new Date(e.last_updated).toLocaleString()}</td>
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

function StatCard({ label, value, color }) {
  return (
    <div className="bg-white border border-[var(--color-bg-border)] rounded-lg p-4 shadow-[var(--shadow-sm)]">
      <div className="text-[var(--color-text-sec)] text-xs font-medium uppercase tracking-wide mb-2">{label}</div>
      <div className="text-3xl font-bold text-mono" style={{ color }}>{value}</div>
    </div>
  );
}
