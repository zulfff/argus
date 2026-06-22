import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { PageHeader, SkeletonRows, EmptyState, LoadingError } from '../components/Shared.jsx';
import { protoName } from '../components/Shared.jsx';

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
    <div className="fade-in">
      <PageHeader title="Connections" subtitle={<span><span className="live-dot on" style={{ marginRight: 6 }} />LIVE — {active} active</span>} />

      <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
        {[{ label: 'Total Active', value: active }, { label: 'New', value: conns.filter((c) => c.state === 'new').length }, { label: 'Closed', value: conns.filter((c) => c.state === 'closed').length }].map((s) => (
          <div key={s.label} className="card" style={{ flex: 1, padding: '8px 16px' }}>
            <div style={{ color: 'var(--text-sec)', fontSize: 11 }}>{s.label}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 20 }}>{s.value}</div>
          </div>
        ))}
        <div className="card" style={{ flex: 2, padding: '8px 16px' }}>
          <div style={{ color: 'var(--text-sec)', fontSize: 11, marginBottom: 4 }}>TCP:UDP:ICMP = {tcp}:{udp}:{icmp}</div>
          <div style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', background: 'var(--bg-border)' }}>
            <div style={{ width: `${(tcp / totalP) * 100}%`, background: 'var(--cyan)', transition: 'width 0.5s' }} />
            <div style={{ width: `${(udp / totalP) * 100}%`, background: 'var(--purple)', transition: 'width 0.5s' }} />
            <div style={{ width: `${(icmp / totalP) * 100}%`, background: 'var(--yellow)', transition: 'width 0.5s' }} />
          </div>
        </div>
      </div>

      <div className="panel" style={{ padding: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="input-box" style={{ width: 220 }} placeholder="Search IP or port..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className="select-box" value={filterState} onChange={(e) => setFilterState(e.target.value)}>
            <option value="all">All States</option><option value="new">New</option><option value="established">Established</option><option value="closing">Closing</option><option value="closed">Closed</option>
          </select>
          <select className="select-box" value={filterProto} onChange={(e) => setFilterProto(e.target.value)}>
            <option value="all">All Protocols</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option>
          </select>
        </div>
      </div>

      <div className="panel" style={{ overflow: 'hidden' }}>
        {loading ? <SkeletonRows count={5} cols={8} /> : error ? <LoadingError message={error} onRetry={fetchConns} /> : (
          <table>
            <thead><tr>{['Src IP:Port','→','Dst IP:Port','Proto','State','Duration','Packets'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={7}><EmptyState msg={search ? 'No connections match filter.' : 'No active connections.'} /></td></tr> : (
                filtered.slice(0, 50).map((c, i) => (
                  <tr key={i} style={{ cursor: 'pointer', opacity: c.state === 'closing' ? 0.5 : 1 }}
                      onClick={() => setSelected(selected?.src_ip === c.src_ip && selected?.src_port === c.src_port ? null : c)}>
                    <td className="cell-mono">{c.src_ip}:{c.src_port}</td>
                    <td className="cell-dim">→</td>
                    <td className="cell-mono">{c.dst_ip}:{c.dst_port}</td>
                    <td><Badge variant={protoName(c.protocol)?.toLowerCase()}>{protoName(c.protocol)}</Badge></td>
                    <td><Badge variant={c.state}>{c.state}</Badge></td>
                    <td className="cell-mono cell-dim">{c.duration || '—'}</td>
                    <td className="cell-mono cell-dim">{c.packets || '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <div className="card" style={{ marginTop: 12, animation: 'fadeSlideIn 0.2s ease' }}>
          <div style={{ color: 'var(--cyan)', fontSize: 12, fontFamily: 'var(--font-mono)', marginBottom: 12 }}>Connection Details</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            {[['Src IP', selected.src_ip], ['Dst IP', selected.dst_ip], ['Src Port', selected.src_port], ['Dst Port', selected.dst_port], ['Protocol', protoName(selected.protocol)], ['State', selected.state]].map(([l, v]) => (
              <div key={l} style={{ padding: 8, background: 'var(--bg-elevated)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-sec)', fontSize: 11 }}>{l}</div>
                <div className="cell-mono">{v}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
