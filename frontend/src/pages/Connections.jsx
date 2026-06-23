import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';
import { protoName } from '../components/Shared.jsx';

const inputCls = "bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)] transition-colors";
const selectCls = "bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none cursor-pointer hover:border-[var(--color-text-muted)] transition-colors";

export default function Connections() {
  const [conns, setConns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [filterState, setFilterState] = useState('all');
  const [filterProto, setFilterProto] = useState('all');
  const [selected, setSelected] = useState(null);

  const fetchConns = async () => { try { setConns(await api.connections.list()); setError(null); } catch (e) { setError(e.message); } finally { setLoading(false); } };
  useEffect(() => { fetchConns(); const iv = setInterval(fetchConns, 5000); return () => clearInterval(iv); }, []);

  const filtered = useMemo(() => conns.filter((c) => {
    const m = !search || c.src_ip?.includes(search) || c.dst_ip?.includes(search);
    const s = filterState === 'all' || c.state === filterState;
    const p = filterProto === 'all' || String(c.protocol) === filterProto;
    return m && s && p;
  }), [conns, search, filterState, filterProto]);

  const active = conns.filter((c) => c.state !== 'closed' && c.state !== 'closing').length;
  const tcp = conns.filter((c) => String(c.protocol) === '6').length;
  const udp = conns.filter((c) => String(c.protocol) === '17').length;
  const icmp = conns.filter((c) => String(c.protocol) === '1').length;
  const totalP = tcp + udp + icmp || 1;

  return (
    <div>
      <PageHeader title="Connections" subtitle={<span><span className="w-[7px] h-[7px] rounded-full bg-[var(--color-green-400)] inline-block animate-live shrink-0 mr-1.5 align-middle shadow-[0_0_6px_var(--color-green-glow)]" />LIVE — {active} active</span>} />

      <div className="flex gap-3 mb-3">
        {[{ label: 'Total Active', value: active }, { label: 'New', value: conns.filter((c) => c.state === 'new').length }, { label: 'Closed', value: conns.filter((c) => c.state === 'closed').length }].map((s) => (
          <div key={s.label} className="flex-1 bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-2 px-4">
            <div className="text-[var(--color-text-sec)] text-[11px]">{s.label}</div>
            <div className="text-mono text-xl">{s.value}</div>
          </div>
        ))}
        <div className="flex-[2] bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-2 px-4">
          <div className="text-[var(--color-text-sec)] text-[11px] mb-1">TCP:UDP:ICMP = {tcp}:{udp}:{icmp}</div>
          <div className="flex h-[5px] rounded-sm overflow-hidden bg-[var(--color-bg-border)]">
            <div className="bg-[var(--color-green-400)] transition-all duration-500" style={{ width: `${(tcp / totalP) * 100}%` }} />
            <div className="bg-[var(--color-blue-400)] transition-all duration-500" style={{ width: `${(udp / totalP) * 100}%` }} />
            <div className="bg-[var(--color-yellow-400)] transition-all duration-500" style={{ width: `${(icmp / totalP) * 100}%` }} />
          </div>
        </div>
      </div>

      <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3 mb-3">
        <div className="flex gap-2">
          <input className={inputCls + ' w-[220px]'} placeholder="Search IP or port..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className={selectCls} value={filterState} onChange={(e) => setFilterState(e.target.value)}>
            <option value="all">All States</option><option value="new">New</option><option value="established">Established</option><option value="closing">Closing</option><option value="closed">Closed</option>
          </select>
          <select className={selectCls} value={filterProto} onChange={(e) => setFilterProto(e.target.value)}>
            <option value="all">All Protocols</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option>
          </select>
        </div>
      </div>

      <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded overflow-hidden">
        {loading ? <SkeletonRows count={5} cols={8} /> : error ? <LoadingError message={error} onRetry={fetchConns} /> : (
          <table className="w-full border-collapse">
            <thead><tr className="border-b border-[var(--color-bg-border)]">{['Src IP:Port','→','Dst IP:Port','Proto','State','Duration','Packets'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={7}><EmptyState msg={search ? 'No connections match filter.' : 'No active connections.'} /></td></tr> : (
                filtered.slice(0, 50).map((c, i) => (
                  <tr key={i} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors cursor-pointer" style={{ opacity: c.state === 'closing' ? 0.5 : 1 }} onClick={() => setSelected(selected?.src_ip === c.src_ip && selected?.src_port === c.src_port ? null : c)}>
                    <td className="px-2.5 py-2 text-mono text-[11px]">{c.src_ip}:{c.src_port}</td>
                    <td className="px-2.5 py-2 text-[var(--color-text-sec)]">→</td>
                    <td className="px-2.5 py-2 text-mono text-[11px]">{c.dst_ip}:{c.dst_port}</td>
                    <td className="px-2.5 py-2"><Badge variant={protoName(c.protocol)?.toLowerCase()}>{protoName(c.protocol)}</Badge></td>
                    <td className="px-2.5 py-2"><Badge variant={c.state}>{c.state}</Badge></td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{c.duration || '—'}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{c.packets || '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5 mt-3 animate-fade">
          <div className="text-[var(--color-green-400)] text-xs text-mono mb-3">Connection Details</div>
          <div className="grid grid-cols-3 gap-2">
            {[['Src IP', selected.src_ip], ['Dst IP', selected.dst_ip], ['Src Port', selected.src_port], ['Dst Port', selected.dst_port], ['Protocol', protoName(selected.protocol)], ['State', selected.state]].map(([l, v]) => (
              <div key={l} className="p-2 bg-[var(--color-bg-elevated)] rounded border border-[var(--color-bg-border)]">
                <div className="text-[var(--color-text-sec)] text-[10px]">{l}</div>
                <div className="text-mono text-xs text-[var(--color-text)] mt-0.5">{v}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
