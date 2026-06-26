import { useState, useEffect, useMemo } from 'react';
import * as api from '../api.js';
import Badge from '../components/Badge.jsx';
import { Toggle, Modal, PageHeader, SkeletonRows, EmptyState, LoadingError, Field } from '../components/Shared.jsx';
import { inputCls, selectCls, btnCls, primaryCls, dangerCls, cardCls, tableCls, tableRowCls, tableHeaderCls, tableCellCls } from '../styles.js';

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

      <div className={cardCls + " mb-4"}>
        <div className="flex gap-2 flex-wrap items-center">
          <input className={inputCls + ' !w-[200px]'} placeholder="Search rules..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className={selectCls} value={filterAction} onChange={(e) => setFilterAction(e.target.value)}>
            {['all','allow','deny','rate-limit'].map((v) => <option key={v} value={v}>{v === 'all' ? 'All Actions' : v}</option>)}
          </select>
          <select className={selectCls} value={filterDir} onChange={(e) => setFilterDir(e.target.value)}>
            {['all','inbound','outbound','forward'].map((v) => <option key={v} value={v}>{v === 'all' ? 'All Directions' : v}</option>)}
          </select>
          <select className={selectCls} value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="all">All Status</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option>
          </select>
          {selected.size > 0 && <span className="px-2 py-1 bg-[var(--color-primary-light)] text-[var(--color-primary)] rounded-md text-xs font-medium">{selected.size} selected</span>}
          <a href="/api/v1/rules/export/json" className={btnCls + ' !ml-auto'}>Export JSON</a>
        </div>
      </div>

      {simOpen && (
        <div className={cardCls + " mb-4"}>
          <div className="flex justify-between mb-4">
            <span className="text-[var(--color-text)] text-sm font-semibold">🔬 Packet Simulator</span>
            <button onClick={() => setSimOpen(false)} className="bg-none border-none text-[var(--color-text-muted)] cursor-pointer hover:text-[var(--color-text)] text-xl leading-none">×</button>
          </div>
          <form onSubmit={handleSimulate} className="flex gap-3 flex-wrap items-end">
            <Field label="Src IP"><input name="src_ip" className={inputCls + ' !w-[140px] text-mono'} placeholder="192.168.1.1" required /></Field>
            <Field label="Dst IP"><input name="dst_ip" className={inputCls + ' !w-[140px] text-mono'} placeholder="8.8.8.8" required /></Field>
            <Field label="Src Port"><input name="src_port" className={inputCls + ' !w-[90px] text-mono'} placeholder="12345" /></Field>
            <Field label="Dst Port"><input name="dst_port" className={inputCls + ' !w-[90px] text-mono'} placeholder="80" /></Field>
            <Field label="Protocol"><select name="protocol" className={selectCls}><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>
            <Field label="Direction"><select name="direction" className={selectCls} required><option value="inbound">Inbound</option><option value="outbound">Outbound</option><option value="forward">Forward</option></select></Field>
            <button type="submit" className={primaryCls}>Simulate</button>
          </form>
          {simResult && (
            <div className="mt-4 p-4 rounded-lg border-2" style={{ 
              borderColor: simResult.matched 
                ? (simResult.action?.startsWith('allow') ? 'var(--color-success)' : simResult.action?.startsWith('deny') ? 'var(--color-danger)' : 'var(--color-warning)') 
                : 'var(--color-bg-border)',
              background: simResult.matched
                ? (simResult.action?.startsWith('allow') ? 'var(--color-success-light)' : simResult.action?.startsWith('deny') ? 'var(--color-danger-light)' : 'var(--color-warning-light)')
                : 'var(--color-bg-hover)'
            }}>
              <div className="text-sm font-medium">
                {simResult.matched ? (
                  <>
                    <span className="text-[var(--color-text)]">Matched: </span>
                    <strong className="text-[var(--color-text)]">{simResult.rule_name}</strong>
                    <span className="text-[var(--color-text-sec)]"> → </span>
                    <strong>{simResult.action}</strong>
                  </>
                ) : (
                  <span className="text-[var(--color-text-sec)]">No rule matched — packet would PASS</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      <div className={tableCls}>
        {loading ? <SkeletonRows count={5} cols={11} /> : error ? <LoadingError message={error} onRetry={fetchRules} /> : (
          <table className="w-full border-collapse">
            <thead>
              <tr>
                {['','Priority','Name','Action','Direction','Src CIDR','Dst CIDR','Protocol','Port','Status',''].map((h) => (
                  <th key={h} className={tableHeaderCls}>
                    {h === '' ? <input type="checkbox" checked={selected.size === filtered.length && filtered.length > 0} onChange={toggleAll} className="cursor-pointer" style={{ accentColor: 'var(--color-primary)' }} /> : h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={11}><EmptyState msg="No rules found." /></td></tr>
              ) : (
                filtered.map((r) => (
                  <tr 
                    key={r.id} 
                    className={tableRowCls} 
                    style={{ 
                      background: simResult?.matched && simResult.rule_id === r.id 
                        ? 'var(--color-success-light)' 
                        : undefined 
                    }}
                  >
                    <td className={tableCellCls}><input type="checkbox" checked={selected.has(r.id)} onChange={() => toggleSelect(r.id)} className="cursor-pointer" style={{ accentColor: 'var(--color-primary)' }} /></td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-muted)]'}>{r.priority}</td>
                    <td className={tableCellCls + ' font-medium'}>{r.name}</td>
                    <td className={tableCellCls}><Badge variant={r.action?.split(':')[0] || r.action}>{r.action}</Badge></td>
                    <td className={tableCellCls}><Badge variant={r.direction}>{r.direction}</Badge></td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{r.src_cidr || '*'}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{r.dst_cidr || '*'}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{r.protocol || 'any'}</td>
                    <td className={tableCellCls + ' text-mono text-[var(--color-text-sec)]'}>{r.dst_port || r.src_port || '*'}</td>
                    <td className={tableCellCls}><Toggle checked={r.enabled} onChange={() => handleToggle(r)} /></td>
                    <td className={tableCellCls}>
                      <button className={dangerCls + ' !p-1.5 !text-xs'} onClick={() => handleDelete(r.id)} title="Delete rule">
                        🗑️
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      <Modal open={modal} onClose={() => setModal(false)} title="New Firewall Rule">
        <div className="grid grid-cols-2 gap-4">
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
        {errors.form && <div className="text-[var(--color-danger)] text-sm mt-3 p-3 bg-[var(--color-danger-light)] border border-[var(--color-danger)] rounded-lg">{errors.form}</div>}
        <div className="flex justify-end gap-2 mt-6">
          <button className={btnCls} onClick={() => setModal(false)}>Cancel</button>
          <button className={primaryCls} onClick={handleCreate} disabled={submitting}>{submitting ? 'Creating...' : 'Create Rule'}</button>
        </div>
      </Modal>
    </div>
  );
}
