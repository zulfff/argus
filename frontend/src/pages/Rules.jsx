import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { Toggle, Modal, PageHeader, SkeletonRows, EmptyState, LoadingError, Field } from '../components/Shared.jsx';

const inputCls = "w-full bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)] transition-colors";
const selectCls = "bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none cursor-pointer hover:border-[var(--color-text-muted)] transition-colors";
const btnCls = "inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs rounded bg-[var(--color-bg-elevated)] text-[var(--color-text-sec)] border border-[var(--color-bg-border)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text)] hover:border-[var(--color-text-muted)] transition-all";
const primaryCls = "inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded bg-[var(--color-green-400)] text-black hover:bg-[var(--color-green-500)] hover:shadow-[0_0_16px_var(--color-green-glow)] transition-all";

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

  const handleCreate = async () => { if (!validate()) return; setSubmitting(true); try { await api.rules.create(form); fetchRules(); setModal(false); setForm({ name: '', action: 'allow', direction: 'inbound', src_cidr: '', dst_cidr: '', src_port: '', dst_port: '', protocol: 'any', priority: 100, enabled: true, description: '' }); } catch (e) { setErrors({ form: e.message }); } finally { setSubmitting(false); } };
  const handleDelete = async (id) => { try { await api.rules.delete(id); fetchRules(); } catch {} };
  const handleToggle = async (r) => { try { await api.rules.update(r.id, { ...r, enabled: !r.enabled }); fetchRules(); } catch {} };
  const toggleAll = () => setSelected((p) => p.size === filtered.length ? new Set() : new Set(filtered.map((r) => r.id)));
  const toggleSelect = (id) => setSelected((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const handleSimulate = async (e) => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target));
    try { setSimResult(await api.rules.simulate(fd)); } catch { setSimResult({ matched: false, rule_name: null, action: null }); }
  };

  return (
    <div>
      <PageHeader title="Firewall Rules" subtitle={`${rules.length} rule${rules.length !== 1 ? 's' : ''}`}>
        <button className={btnCls} onClick={() => setSimOpen(!simOpen)}>🔬 Simulator</button>
        <button className={primaryCls} onClick={() => setModal(true)}>+ New Rule</button>
      </PageHeader>

      <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3 mb-2.5">
        <div className="flex gap-2 flex-wrap items-center">
          <input className={inputCls + ' !w-[200px]'} placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className={selectCls} value={filterAction} onChange={(e) => setFilterAction(e.target.value)}>
            {['all','allow','deny','rate-limit'].map((v) => <option key={v} value={v}>{v === 'all' ? 'All Actions' : v}</option>)}
          </select>
          <select className={selectCls} value={filterDir} onChange={(e) => setFilterDir(e.target.value)}>
            {['all','inbound','outbound','forward'].map((v) => <option key={v} value={v}>{v === 'all' ? 'All Directions' : v}</option>)}
          </select>
          <select className={selectCls} value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="all">All Status</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option>
          </select>
          {selected.size > 0 && <span className="px-2 py-1 bg-[var(--color-bg-elevated)] rounded text-[var(--color-text-sec)] text-[11px]">{selected.size} selected</span>}
          <a href="/api/v1/rules/export/json" className={btnCls + ' !ml-auto'}>Export</a>
        </div>
      </div>

      {simOpen && (
        <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded p-3.5 mb-2.5">
          <div className="flex justify-between mb-3">
            <span className="text-[var(--color-text-sec)] text-xs">🔬 Packet Simulator</span>
            <button onClick={() => setSimOpen(false)} className="bg-none border-none text-[var(--color-text-sec)] cursor-pointer">✕</button>
          </div>
          <form onSubmit={handleSimulate} className="flex gap-2 flex-wrap items-end">
            <Field label="Src IP"><input name="src_ip" className={inputCls + ' !w-[120px] text-mono'} required /></Field>
            <Field label="Dst IP"><input name="dst_ip" className={inputCls + ' !w-[120px] text-mono'} required /></Field>
            <Field label="Src Port"><input name="src_port" className={inputCls + ' !w-[70px] text-mono'} /></Field>
            <Field label="Dst Port"><input name="dst_port" className={inputCls + ' !w-[70px] text-mono'} /></Field>
            <Field label="Protocol"><select name="protocol" className={selectCls}><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>
            <Field label="Direction"><select name="direction" className={selectCls} required><option value="inbound">Inbound</option><option value="outbound">Outbound</option><option value="forward">Forward</option></select></Field>
            <button type="submit" className={primaryCls}>Simulate</button>
          </form>
          {simResult && (
            <div className="mt-3 p-3 rounded bg-[var(--color-bg-elevated)] border" style={{ borderColor: simResult.matched ? (simResult.action?.startsWith('allow') ? 'var(--color-green-400)' : simResult.action?.startsWith('deny') ? 'var(--color-red-400)' : 'var(--color-yellow-400)') : 'var(--color-text-muted)' }}>
              <div className="text-[13px]">{simResult.matched ? <>Matched: <strong>{simResult.rule_name}</strong> → <strong>{simResult.action}</strong></> : 'No rule matched — packet would PASS'}</div>
            </div>
          )}
        </div>
      )}

      <div className="bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded overflow-hidden">
        {loading ? <SkeletonRows count={4} cols={11} /> : error ? <LoadingError message={error} onRetry={fetchRules} /> : (
          <table className="w-full border-collapse">
            <thead><tr className="border-b border-[var(--color-bg-border)]">{['','#','Name','Action','Dir','Src CIDR','Dst CIDR','Proto','Port','Status',''].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h === '' ? <input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0} onChange={toggleAll} style={{ accentColor: 'var(--color-green-400)' }} /> : h}</th>)}</tr></thead>
            <tbody>
              {filtered.length === 0 ? <tr><td colSpan={11}><EmptyState msg="No rules found." /></td></tr> : (
                filtered.map((r) => (
                  <tr key={r.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors" style={{ background: simResult?.matched && simResult.rule_id === r.id ? 'rgba(0,171,68,0.08)' : undefined }}>
                    <td className="px-2.5 py-2"><input type="checkbox" checked={selected.has(r.id)} onChange={() => toggleSelect(r.id)} style={{ accentColor: 'var(--color-green-400)' }} /></td>
                    <td className="px-2.5 py-2 text-mono text-[var(--color-text-muted)] text-[11px]">{r.priority}</td>
                    <td className="px-2.5 py-2 text-xs">{r.name}</td>
                    <td className="px-2.5 py-2"><Badge variant={r.action?.split(':')[0] || r.action}>{r.action}</Badge></td>
                    <td className="px-2.5 py-2"><Badge variant={r.direction}>{r.direction}</Badge></td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{r.src_cidr || '*'}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{r.dst_cidr || '*'}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{r.protocol || 'any'}</td>
                    <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{r.dst_port || r.src_port || '*'}</td>
                    <td className="px-2.5 py-2"><Toggle checked={r.enabled} onChange={() => handleToggle(r)} /></td>
                    <td className="px-2.5 py-2"><button className={btnCls + ' !p-1 !px-2 !text-[11px] !text-[var(--color-red-400)]'} onClick={() => handleDelete(r.id)}>🗑️</button></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      <Modal open={modal} onClose={() => setModal(false)} title="New Firewall Rule">
        <div className="grid grid-cols-2 gap-x-2.5">
          <Field label="Name *" error={errors.name}><input className={inputCls} value={form.name} onChange={(e) => { setForm({ ...form, name: e.target.value }); setErrors({}); }} /></Field>
          <Field label="Action *"><select className={selectCls + ' w-full'} value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}><option value="allow">Allow</option><option value="deny">Deny</option><option value="rate-limit">Rate-Limit</option></select></Field>
          <Field label="Direction *"><select className={selectCls + ' w-full'} value={form.direction} onChange={(e) => setForm({ ...form, direction: e.target.value })}><option value="inbound">Inbound</option><option value="outbound">Outbound</option><option value="forward">Forward</option></select></Field>
          <Field label="Protocol"><select className={selectCls + ' w-full'} value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>
          <Field label="Src CIDR" error={errors.src_cidr}><input className={inputCls + ' text-mono'} value={form.src_cidr} onChange={(e) => { setForm({ ...form, src_cidr: e.target.value }); setErrors({}); }} placeholder="10.0.0.0/8" /></Field>
          <Field label="Dst CIDR" error={errors.dst_cidr}><input className={inputCls + ' text-mono'} value={form.dst_cidr} onChange={(e) => { setForm({ ...form, dst_cidr: e.target.value }); setErrors({}); }} placeholder="0.0.0.0/0" /></Field>
          <Field label="Src Port" error={errors.src_port}><input className={inputCls + ' text-mono'} value={form.src_port} onChange={(e) => { setForm({ ...form, src_port: e.target.value }); setErrors({}); }} /></Field>
          <Field label="Dst Port" error={errors.dst_port}><input className={inputCls + ' text-mono'} value={form.dst_port} onChange={(e) => { setForm({ ...form, dst_port: e.target.value }); setErrors({}); }} /></Field>
          <Field label="Priority"><input className={inputCls} type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) || 0 })} /></Field>
          <Field label="Enabled"><Toggle checked={form.enabled} onChange={() => setForm({ ...form, enabled: !form.enabled })} /></Field>
          <div className="col-span-2"><Field label="Description"><input className={inputCls} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field></div>
        </div>
        {errors.form && <div className="text-[var(--color-red-400)] text-xs mt-2">{errors.form}</div>}
        <div className="flex justify-end gap-2 mt-4">
          <button className={btnCls} onClick={() => setModal(false)}>Cancel</button>
          <button className={primaryCls} onClick={handleCreate} disabled={submitting}>{submitting ? 'Creating...' : 'Create Rule'}</button>
        </div>
      </Modal>
    </div>
  );
}
