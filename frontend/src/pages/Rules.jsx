import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { Toggle, Modal, PageHeader, SkeletonRows, EmptyState, LoadingError, Field } from '../components/Shared.jsx';

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('all');
  const [filterDir, setFilterDir] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [selected, setSelected] = useState(new Set());
  const [modal, setModal] = useState(false);
  const [simOpen, setSimOpen] = useState(false);
  const [simResult, setSimResult] = useState(null);
  const [form, setForm] = useState({ name: '', action: 'allow', direction: 'inbound', src_cidr: '', dst_cidr: '', src_port: '', dst_port: '', protocol: 'any', priority: 100, enabled: true, description: '' });
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);

  const fetchRules = async () => { setLoading(true); try { setRules(await api.rules.list()); setError(null); } catch (e) { setError(e.message); } finally { setLoading(false); } };
  useEffect(() => { fetchRules(); }, []);

  const filtered = useMemo(() => rules.filter((r) => {
    const m = !search || r.name?.toLowerCase().includes(search.toLowerCase()) || r.src_cidr?.includes(search) || r.dst_cidr?.includes(search);
    const a = filterAction === 'all' || r.action === filterAction || r.action?.startsWith(filterAction);
    const d = filterDir === 'all' || r.direction === filterDir;
    const s = filterStatus === 'all' || (filterStatus === 'enabled' ? r.enabled : !r.enabled);
    return m && a && d && s;
  }), [rules, search, filterAction, filterDir, filterStatus]);

  const validate = () => {
    const e = {};
    if (!form.name.trim()) e.name = 'Required';
    if (form.src_cidr && !/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(form.src_cidr)) e.src_cidr = 'Invalid CIDR';
    if (form.dst_cidr && !/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(form.dst_cidr)) e.dst_cidr = 'Invalid CIDR';
    const sp = Number(form.src_port);
    if (form.src_port && (isNaN(sp) || sp < 0 || sp > 65535)) e.src_port = '0–65535';
    const dp = Number(form.dst_port);
    if (form.dst_port && (isNaN(dp) || dp < 0 || dp > 65535)) e.dst_port = '0–65535';
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleCreate = async () => {
    if (!validate()) return;
    setSubmitting(true);
    try { await api.rules.create(form); fetchRules(); setModal(false); setForm({ name: '', action: 'allow', direction: 'inbound', src_cidr: '', dst_cidr: '', src_port: '', dst_port: '', protocol: 'any', priority: 100, enabled: true, description: '' }); }
    catch (e) { setErrors({ form: e.message }); }
    finally { setSubmitting(false); }
  };

  const handleDelete = async (id) => { try { await api.rules.delete(id); fetchRules(); } catch (e) { /* silent */ } };
  const handleToggle = async (r) => { try { await api.rules.update(r.id, { ...r, enabled: !r.enabled }); fetchRules(); } catch (e) { /* silent */ } };

  const toggleAll = () => setSelected((p) => p.size === filtered.length ? new Set() : new Set(filtered.map((r) => r.id)));
  const toggleSelect = (id) => setSelected((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const handleSimulate = async (e) => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target));
    try { setSimResult(await api.rules.simulate(fd)); } catch (err) { setSimResult({ matched: false, rule_name: null, action: null }); }
  };

  return (
    <div className="fade-in">
      <PageHeader title="Firewall Rules" subtitle={`${rules.length} rule${rules.length !== 1 ? 's' : ''}`}>
        <button className="btn" onClick={() => setSimOpen(!simOpen)}>🔬 Simulator</button>
        <button className="btn btn-primary" onClick={() => setModal(true)}>+ New Rule</button>
      </PageHeader>

      <div className="panel" style={{ padding: 12 }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <input className="input-box" style={{ width: 200 }} placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className="select-box" value={filterAction} onChange={(e) => setFilterAction(e.target.value)}>
            {['all','allow','deny','rate-limit'].map((v) => <option key={v} value={v}>{v === 'all' ? 'All Actions' : v}</option>)}
          </select>
          <select className="select-box" value={filterDir} onChange={(e) => setFilterDir(e.target.value)}>
            {['all','inbound','outbound','forward'].map((v) => <option key={v} value={v}>{v === 'all' ? 'All Directions' : v}</option>)}
          </select>
          <select className="select-box" value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="all">All Status</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
          {selected.size > 0 && (
            <span style={{ padding: '4px 8px', background: 'var(--bg-elevated)', borderRadius: 6, color: 'var(--text-sec)', fontSize: 11 }}>{selected.size} selected</span>
          )}
          <a href="/api/v1/rules/export/json" className="btn" style={{ marginLeft: 'auto' }}>Export JSON</a>
        </div>
      </div>

      {simOpen && (
        <div className="card" style={{ marginBottom: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ color: 'var(--text-sec)', fontSize: 12 }}>🔬 Packet Simulator</span>
            <button onClick={() => setSimOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-sec)', cursor: 'pointer' }}>✕</button>
          </div>
          <form onSubmit={handleSimulate} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <Field label="Src IP"><input name="src_ip" className="input-box" style={{ width: 140, fontFamily: 'var(--font-mono)' }} required /></Field>
            <Field label="Dst IP"><input name="dst_ip" className="input-box" style={{ width: 140, fontFamily: 'var(--font-mono)' }} required /></Field>
            <Field label="Src Port"><input name="src_port" className="input-box" style={{ width: 80, fontFamily: 'var(--font-mono)' }} /></Field>
            <Field label="Dst Port"><input name="dst_port" className="input-box" style={{ width: 80, fontFamily: 'var(--font-mono)' }} /></Field>
            <Field label="Protocol"><select name="protocol" className="select-box"><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>
            <Field label="Direction"><select name="direction" className="select-box" required><option value="inbound">Inbound</option><option value="outbound">Outbound</option><option value="forward">Forward</option></select></Field>
            <button type="submit" className="btn btn-primary">Simulate</button>
          </form>
          {simResult && (
            <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: 'var(--bg-elevated)', border: `1px solid ${simResult.matched ? (simResult.action?.startsWith('allow') ? 'var(--green)' : simResult.action?.startsWith('deny') ? 'var(--red)' : 'var(--yellow)') : 'var(--text-muted)'}` }}>
              <div style={{ fontSize: 13 }}>
                {simResult.matched ? <>Matched: <strong>{simResult.rule_name}</strong> → <strong>{simResult.action}</strong></> : 'No rule matched — packet would PASS'}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="panel" style={{ overflow: 'hidden' }}>
        {loading ? <SkeletonRows count={4} cols={11} /> : error ? <LoadingError message={error} onRetry={fetchRules} /> : (
          <table>
            <thead><tr>{['','#','Name','Action','Dir','Src CIDR','Dst CIDR','Proto','Port','Status',''].map((h) => <th key={h}>{h === '' ? <input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0} onChange={toggleAll} style={{ accentColor: 'var(--cyan)' }} /> : h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={11}><EmptyState msg="No rules found." /></td></tr> : (
                filtered.map((r) => (
                  <tr key={r.id} style={{ background: simResult?.matched && simResult.rule_id === r.id ? 'rgba(0,212,255,0.08)' : undefined }}>
                    <td><input type="checkbox" checked={selected.has(r.id)} onChange={() => toggleSelect(r.id)} style={{ accentColor: 'var(--cyan)' }} /></td>
                    <td className="cell-mono" style={{ color: 'var(--text-muted)' }}>{r.priority}</td>
                    <td>{r.name}</td>
                    <td><Badge variant={r.action?.split(':')[0] || r.action}>{r.action}</Badge></td>
                    <td><Badge variant={r.direction}>{r.direction}</Badge></td>
                    <td className="cell-mono cell-dim">{r.src_cidr || '*'}</td>
                    <td className="cell-mono cell-dim">{r.dst_cidr || '*'}</td>
                    <td className="cell-mono cell-dim">{r.protocol || 'any'}</td>
                    <td className="cell-mono cell-dim">{r.dst_port || r.src_port || '*'}</td>
                    <td><Toggle checked={r.enabled} onChange={() => handleToggle(r)} /></td>
                    <td><button className="btn" style={{ padding: '4px 8px', fontSize: 11, color: 'var(--red)' }} onClick={() => handleDelete(r.id)}>🗑️</button></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      <Modal open={modal} onClose={() => setModal(false)} title="New Firewall Rule">
        <div className="form-row">
          <Field label="Name *" error={errors.name}><input className="input-box" value={form.name} onChange={(e) => { setForm({ ...form, name: e.target.value }); setErrors({}); }} /></Field>
          <Field label="Action *"><select className="select-box" value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })} style={{ width: '100%' }}><option value="allow">Allow</option><option value="deny">Deny</option><option value="rate-limit">Rate-Limit</option></select></Field>
          <Field label="Direction *"><select className="select-box" value={form.direction} onChange={(e) => setForm({ ...form, direction: e.target.value })} style={{ width: '100%' }}><option value="inbound">Inbound</option><option value="outbound">Outbound</option><option value="forward">Forward</option></select></Field>
          <Field label="Protocol"><select className="select-box" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })} style={{ width: '100%' }}><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>
          <Field label="Src CIDR" error={errors.src_cidr}><input className="input-box" value={form.src_cidr} onChange={(e) => { setForm({ ...form, src_cidr: e.target.value }); setErrors({}); }} placeholder="10.0.0.0/8" style={{ fontFamily: 'var(--font-mono)' }} /></Field>
          <Field label="Dst CIDR" error={errors.dst_cidr}><input className="input-box" value={form.dst_cidr} onChange={(e) => { setForm({ ...form, dst_cidr: e.target.value }); setErrors({}); }} placeholder="0.0.0.0/0" style={{ fontFamily: 'var(--font-mono)' }} /></Field>
          <Field label="Src Port" error={errors.src_port}><input className="input-box" value={form.src_port} onChange={(e) => { setForm({ ...form, src_port: e.target.value }); setErrors({}); }} style={{ fontFamily: 'var(--font-mono)' }} /></Field>
          <Field label="Dst Port" error={errors.dst_port}><input className="input-box" value={form.dst_port} onChange={(e) => { setForm({ ...form, dst_port: e.target.value }); setErrors({}); }} style={{ fontFamily: 'var(--font-mono)' }} /></Field>
          <Field label="Priority"><input className="input-box" type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) || 0 })} /></Field>
          <Field label="Enabled"><Toggle checked={form.enabled} onChange={() => setForm({ ...form, enabled: !form.enabled })} /></Field>
          <div className="full"><Field label="Description"><input className="input-box" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field></div>
        </div>
        {errors.form && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 8 }}>{errors.form}</div>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button className="btn" onClick={() => setModal(false)}>Cancel</button>
          <button className="btn btn-primary" onClick={handleCreate} disabled={submitting}>{submitting ? 'Creating...' : 'Create Rule'}</button>
        </div>
      </Modal>
    </div>
  );
}
