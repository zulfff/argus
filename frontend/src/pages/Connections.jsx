import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';
import { protoName } from '../components/Shared.jsx';
import { inputCls, selectCls, cardCls, tableCls, tableRowCls, tableHeaderCls, tableCellCls } from '../styles.js';

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
      <PageHeader 
        title="Active Connections" 
        subtitle={
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[var(--color-success)] inline-block animate-live shadow-sm" />
            <span>LIVE — {active} active connections</span>
          </span>
        } 
      />

      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Active" value={active} />
        <StatCard label="New" value={conns.filter((c) => c.state === 'new').length} />
        <StatCard label="Established" value={conns.filter((c) => c.state === 'established').length} />
        <StatCard label="Closed" value={conns.filter((c) => c.state === 'closed').length} />
      </div>

      <div className={cardCls + " mb-6"}>
        <div className="text-sm font-semibold text-[var(--color-text)] mb-3">Protocol Distribution</div>
        <div className="flex gap-4 items-center">
          <div className="flex-1">
            <div className="flex h-3 rounded-full overflow-hidden bg-[var(--color-bg-border)]">
              <div className="bg-[var(--color-success)] transition-all duration-500" style={{ width: `${(tcp / totalP) * 100}%` }} title={`TCP: ${tcp}`} />
              <div className="bg-[var(--color-primary)] transition-all duration-500" style={{ width: `${(udp / totalP) * 100}%` }} title={`UDP: ${udp}`} />
              <div className="bg-[var(--color-warning)] transition-all duration-500" style={{ width: `${(icmp / totalP) * 100}%` }} title={`ICMP: ${icmp}`} />
            </div>
          </div>
          <div className="text-xs text-[var(--color-text-sec)] font-mono">
            TCP:{tcp} · UDP:{udp} · ICMP:{icmp}
          </div>
        </div>
      </div>

      <div className={cardCls + " mb-4"}>
        <div className="flex gap-2 flex-wrap">
          <input className={inputCls + ' !w-[220px]'} placeholder="Search by IP address..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className={selectCls} value={filterState} onChange={(e) => setFilterState(e.target.value)}>
            <option value="all">All States</option>
            {['new','established','closing','closed'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className={selectCls} value={filterProto} onChange={(e) => setFilterProto(e.target.value)}>
            <option value="all">All Protocols</option>
            <option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option>
          </select>
        </div>
      </div>

      <div className={tableCls}>
        {loading ? <SkeletonRows count={8} cols={7} /> : error ? <LoadingError message={error} onRetry={fetchConns} /> : (
          <table className="w-full border-collapse">
            <thead>
              <tr>
                {['Source','','Destination','Protocol','State','Duration','Packets'].map((h) => (
                  <th key={h} className={tableHeaderCls}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={7}><EmptyState msg={search ? 'No connections match your filters.' : 'No active connections.'} /></td></tr>
              ) : (
                filtered.slice(0, 100).map((c, i) => (
                  <tr 
                    key={i} 
                    className={tableRowCls + ' cursor-pointer'} 
                    style={{ opacity: c.state === 'closing' || c.state === 'closed' ? 0.6 : 1 }} 
                    onClick={() => setSelected(selected?.src_ip === c.src_ip && selected?.src_port === c.src_port ? null : c)}
                  >
                    <td className={tableCellCls + ' text-mono font-medium'}>{c.src_ip}:{c.src_port}</td>
                    <td className={tableCellCls + ' text-[var(--color-text-muted)] text-center'}>→</td>
                    <td className={tableCellCls + ' text-mono font-medium'}>{c.dst_ip}:{c.dst_port}</td>
                    <td className={tableCellCls}><Badge variant={protoName(c.protocol)?.toLowerCase()}>{protoName(c.protocol)}</Badge></td>
                    <td className={tableCellCls}><Badge variant={c.state}>{c.state}</Badge></td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{c.duration || '—'}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{(c.packets_sent || 0) + (c.packets_recv || 0)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <div className={cardCls + " mt-6"}>
          <div className="flex justify-between items-start mb-4">
            <h3 className="text-sm font-semibold text-[var(--color-text)]">Connection Details</h3>
            <button onClick={() => setSelected(null)} className="text-[var(--color-text-muted)] hover:text-[var(--color-text)] text-xl leading-none">×</button>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <DetailRow label="Source IP" value={selected.src_ip} />
            <DetailRow label="Destination IP" value={selected.dst_ip} />
            <DetailRow label="Source Port" value={selected.src_port} />
            <DetailRow label="Destination Port" value={selected.dst_port} />
            <DetailRow label="Protocol" value={protoName(selected.protocol)} />
            <DetailRow label="State" value={<Badge variant={selected.state}>{selected.state}</Badge>} />
            <DetailRow label="Packets Sent" value={selected.packets_sent || 0} />
            <DetailRow label="Packets Received" value={selected.packets_recv || 0} />
            <DetailRow label="Bytes Sent" value={(selected.bytes_sent || 0).toLocaleString()} />
            <DetailRow label="Bytes Received" value={(selected.bytes_recv || 0).toLocaleString()} />
            <DetailRow label="Duration" value={selected.duration || 'Unknown'} />
            <DetailRow label="Last Seen" value={selected.last_seen ? new Date(selected.last_seen).toLocaleString() : 'Unknown'} />
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value }) {
  return (
    <div className="bg-white border border-[var(--color-bg-border)] rounded-lg p-4 shadow-[var(--shadow-sm)]">
      <div className="text-[var(--color-text-sec)] text-xs font-medium uppercase tracking-wide mb-1">{label}</div>
      <div className="text-2xl font-bold text-[var(--color-text)] text-mono">{value}</div>
    </div>
  );
}

function DetailRow({ label, value }) {
  return (
    <div>
      <div className="text-[var(--color-text-sec)] text-xs font-medium mb-1">{label}</div>
      <div className="text-[var(--color-text)] font-mono text-sm">{value}</div>
    </div>
  );
}
