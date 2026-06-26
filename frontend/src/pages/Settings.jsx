import { useState, useEffect, useContext } from 'react';
import * as api from '../api.js';
import { AuthContext } from '../App.jsx';
import Badge from '../components/Badge.jsx';
import { Toggle, PageHeader, SkeletonRows, EmptyState, LoadingError, Field } from '../components/Shared.jsx';
import { inputCls, selectCls, btnCls, primaryCls, dangerCls, cardCls } from '../styles.js';

const TABS = ['general', 'users', 'vpn', 'backup', 'cluster', 'syslog', 'qos'];

export default function Settings() {
  const auth = useContext(AuthContext);
  const [tab, setTab] = useState('general');
  const [users, setUsers] = useState([]);
  const [vpnReqs, setVpnReqs] = useState([]);
  const [backups, setBackups] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [syslogCfgs, setSyslogCfgs] = useState([]);
  const [qosPolicies, setQosPolicies] = useState([]);
  const [loading, setLoading] = useState({ users: false, vpn: false, backup: false, cluster: false, syslog: false, qos: false });
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'viewer' });
  const [backupMsg, setBackupMsg] = useState('');

  useEffect(() => {
    if (tab === 'users') fetchUsers();
    else if (tab === 'vpn') fetchVpn();
    else if (tab === 'backup') fetchBackups();
    else if (tab === 'cluster') fetchCluster();
    else if (tab === 'syslog') fetchSyslog();
    else if (tab === 'qos') fetchQos();
  }, [tab]);

  const fetchUsers = async () => { setLoading((p) => ({ ...p, users: true })); try { setUsers(await api.auth.listUsers()); } catch {} finally { setLoading((p) => ({ ...p, users: false })); } };
  const fetchVpn = async () => { setLoading((p) => ({ ...p, vpn: true })); try { setVpnReqs(await api.vpn.requests()); } catch {} finally { setLoading((p) => ({ ...p, vpn: false })); } };
  const fetchBackups = async () => { setLoading((p) => ({ ...p, backup: true })); try { setBackups(await api.backup.list()); } catch {} finally { setLoading((p) => ({ ...p, backup: false })); } };
  const fetchCluster = async () => { setLoading((p) => ({ ...p, cluster: true })); try { const status = await api.cluster.status(); setNodes(status.nodes || []); } catch {} finally { setLoading((p) => ({ ...p, cluster: false })); } };
  const fetchSyslog = async () => { setLoading((p) => ({ ...p, syslog: true })); try { setSyslogCfgs(await api.syslog.list()); } catch {} finally { setLoading((p) => ({ ...p, syslog: false })); } };
  const fetchQos = async () => { setLoading((p) => ({ ...p, qos: true })); try { setQosPolicies(await api.qos.list()); } catch {} finally { setLoading((p) => ({ ...p, qos: false })); } };
  const addUser = async () => { if (!newUser.username.trim() || !newUser.password.trim()) return; try { await api.auth.createUser(newUser.username, newUser.password, newUser.role); fetchUsers(); setNewUser({ username: '', password: '', role: 'viewer' }); } catch {} };
  const deleteUser = async (u) => { try { await api.auth.deleteUser(u.username); fetchUsers(); } catch {} };
  const createBackup = async () => { setBackupMsg(''); try { const res = await api.backup.create(); setBackupMsg(`✓ ${res.id}`); fetchBackups(); } catch (e) { setBackupMsg(`Error: ${e.message}`); } };
  const handleVpnAction = async (r, action) => { try { action === 'approve' ? await api.vpn.approve(r.id) : await api.vpn.deny(r.id); fetchVpn(); } catch {} };

  return (
    <div>
      <PageHeader title="Settings" subtitle="System administration" />

      <div className="flex mb-4 border-b border-[var(--color-bg-border)]">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 border-b-2 text-xs capitalize transition-all cursor-pointer font-body ${tab === t ? 'border-[var(--color-green-400)] text-[var(--color-green-500)] font-semibold' : 'border-transparent text-[var(--color-text-sec)] hover:text-[var(--color-text)]'}`}>{t}</button>
        ))}
      </div>

      {tab === 'general' && (
        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-xs mb-4">⚙️ General Settings</div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Hostname"><input className={inputCls} defaultValue="argus-01" readOnly /></Field>
            <Field label="Listen Port"><input className={inputCls + ' text-mono'} defaultValue="8443" readOnly /></Field>
            <Field label="Log Level"><select className={selectCls} defaultValue="info"><option value="debug">Debug</option><option value="info">Info</option><option value="warn">Warn</option><option value="error">Error</option></select></Field>
            <Field label="Default Rule Action"><select className={selectCls} defaultValue="deny"><option value="deny">Deny</option><option value="allow">Allow</option></select></Field>
          </div>
          <button className={primaryCls + ' mt-3'} disabled>Save Settings</button>
        </div>
      )}

      {tab === 'users' && (
        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-xs mb-3">👥 Users</div>
          <div className="flex gap-2 items-end mb-3 p-3 bg-[var(--color-bg-elevated)] rounded">
            <Field label="Username" style={{ flex: 1 }}><input className={inputCls} value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} /></Field>
            <Field label="Password" style={{ flex: 1 }}><input className={inputCls} type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} /></Field>
            <Field label="Role" style={{ width: 120 }}><select className={selectCls} value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}><option value="admin">Admin</option><option value="operator">Operator</option><option value="viewer">Viewer</option></select></Field>
            <button className={primaryCls} onClick={addUser}>Create</button>
          </div>
          {loading.users ? <SkeletonRows count={3} cols={4} /> : (
            <table className="w-full border-collapse">
              <thead><tr className="border-b border-[var(--color-bg-border)]">{['Username','Role','Status',''].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors">
                    <td className="px-2.5 py-2 text-mono text-[11px]">{u.username}</td>
                    <td className="px-2.5 py-2"><Badge variant={u.role}>{u.role}</Badge></td>
                    <td className="px-2.5 py-2"><Badge variant={u.enabled ? 'active' : 'inactive'}>{u.enabled ? 'active' : 'inactive'}</Badge></td>
                    <td className="px-2.5 py-2"><button className={dangerCls + ' !p-1 !px-2 !text-[11px]'} onClick={() => deleteUser(u)}>Delete</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'vpn' && (
        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-xs mb-3">🔒 VPN Portal — WireGuard Requests</div>
          {loading.vpn ? <SkeletonRows count={3} cols={4} /> : (
            <table className="w-full border-collapse">
              <thead><tr className="border-b border-[var(--color-bg-border)]">{['Requester','Requested At','Status','Actions'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
              <tbody>
                {vpnReqs.length === 0 ? <tr><td colSpan={4}><EmptyState msg="No VPN requests." /></td></tr> : (
                  vpnReqs.map((r) => (
                    <tr key={r.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors">
                      <td className="px-2.5 py-2 text-mono text-[11px]">{r.user_id}</td>
                      <td className="px-2.5 py-2 text-xs text-[var(--color-text-sec)]">{new Date(r.created_at).toLocaleString()}</td>
                      <td className="px-2.5 py-2"><Badge variant={r.status}>{r.status}</Badge></td>
                      <td className="px-2.5 py-2">
                        {r.status === 'Pending' ? (
                          <div className="flex gap-1">
                            <button className="inline-flex items-center justify-center gap-1.5 px-2 py-1 text-[11px] rounded bg-[var(--color-green-400)] text-black font-medium hover:bg-[var(--color-green-500)] transition-all" onClick={() => handleVpnAction(r, 'approve')}>Approve</button>
                            <button className="inline-flex items-center justify-center gap-1.5 px-2 py-1 text-[11px] rounded bg-[var(--color-red-400)] text-white hover:bg-[#f44336] transition-all" onClick={() => handleVpnAction(r, 'deny')}>Deny</button>
                          </div>
                        ) : r.status === 'Approved' ? (
                          <button className={btnCls + ' !p-1 !px-2 !text-[11px]'}>Download Config</button>
                        ) : null}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'backup' && (
        <div className={cardCls}>
          <div className="flex justify-between mb-3">
            <span className="text-[var(--color-text-sec)] text-xs">💾 Backups</span>
            <button className={primaryCls} onClick={createBackup}>Create Backup</button>
          </div>
          {backupMsg && <div className="p-2 bg-[var(--color-bg-elevated)] rounded text-[var(--color-green-400)] text-xs mb-3 text-mono">{backupMsg}</div>}
          {loading.backup ? <SkeletonRows count={3} cols={5} /> : (
            <table className="w-full border-collapse">
              <thead><tr className="border-b border-[var(--color-bg-border)]">{['ID','Timestamp','Size','Checksum','Actions'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
              <tbody>
                {backups.length === 0 ? <tr><td colSpan={5}><EmptyState msg="No backups yet." /></td></tr> : (
                  backups.map((b) => (
                    <tr key={b.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors">
                      <td className="px-2.5 py-2 text-mono text-[var(--color-text-muted)] text-[11px]">{String(b.id).slice(0, 8)}</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{new Date(b.created_at).toLocaleString()}</td>
                      <td className="px-2.5 py-2 text-xs text-[var(--color-text-sec)]">{b.size || '—'}</td>
                      <td className="px-2.5 py-2 text-mono text-[var(--color-text-muted)] text-[11px]">{(b.checksum || '').slice(0, 12)}...</td>
                      <td className="px-2.5 py-2"><button className={btnCls + ' !p-1 !px-2 !text-[11px]'}>Restore</button></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'cluster' && (
        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-xs mb-3">🌐 Cluster Nodes</div>
          {loading.cluster ? <SkeletonRows count={3} cols={5} /> : (
            <table className="w-full border-collapse">
              <thead><tr className="border-b border-[var(--color-bg-border)]">{['Node','IP','Role','Status','Last Heartbeat'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
              <tbody>
                {nodes.length === 0 ? <tr><td colSpan={5}><EmptyState msg="No cluster nodes registered." /></td></tr> : (
                  nodes.map((n) => (
                    <tr key={n.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors" style={{ borderLeft: n.role === 'leader' ? '3px solid var(--color-green-400)' : '3px solid transparent' }}>
                      <td className="px-2.5 py-2 text-mono text-[11px]">{n.name}</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{n.address}</td>
                      <td className="px-2.5 py-2"><Badge variant={n.role}>{n.role}</Badge></td>
                      <td className="px-2.5 py-2">
                        <div className="flex items-center gap-1.5">
                          <span className="w-[7px] h-[7px] rounded-full shrink-0 shadow-[0_0_6px_var(--color-green-glow)]" style={{ background: n.healthy ? 'var(--color-green-400)' : 'var(--color-red-400)', animation: n.healthy ? 'livePulse 2s infinite' : 'none' }} />
                          <Badge variant={n.healthy ? 'online' : 'offline'}>{n.healthy ? 'online' : 'offline'}</Badge>
                        </div>
                      </td>
                      <td className="px-2.5 py-2 text-mono text-[var(--color-text-sec)] text-[11px]">{new Date(n.last_heartbeat).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'syslog' && (
        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-xs mb-3">📋 Syslog</div>
          {loading.syslog ? <SkeletonRows count={2} cols={5} /> : (
            <table className="w-full border-collapse">
              <thead><tr className="border-b border-[var(--color-bg-border)]">{['Server','Port','Protocol','Severity','Enabled'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
              <tbody>
                {syslogCfgs.length === 0 ? <tr><td colSpan={5}><EmptyState msg="No syslog configs." /></td></tr> : (
                  syslogCfgs.map((c) => (
                    <tr key={c.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors">
                      <td className="px-2.5 py-2 text-mono text-[11px]">{c.server}</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{c.port}</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{c.protocol}</td>
                      <td className="px-2.5 py-2"><Badge variant="info">{c.min_severity}</Badge></td>
                      <td className="px-2.5 py-2"><Badge variant={c.enabled ? 'active' : 'inactive'}>{c.enabled ? 'enabled' : 'disabled'}</Badge></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'qos' && (
        <div className={cardCls}>
          <div className="text-[var(--color-text-sec)] text-xs mb-3">⚡ QoS Policies</div>
          {loading.qos ? <SkeletonRows count={2} cols={5} /> : (
            <table className="w-full border-collapse">
              <thead><tr className="border-b border-[var(--color-bg-border)]">{['Name','Target','Bandwidth','Priority','DSCP','Enabled'].map((h) => <th key={h} className="px-2.5 py-2 text-left text-[var(--color-text-sec)] text-[10px] font-semibold uppercase tracking-wider">{h}</th>)}</tr></thead>
              <tbody>
                {qosPolicies.length === 0 ? <tr><td colSpan={6}><EmptyState msg="No QoS policies configured." /></td></tr> : (
                  qosPolicies.map((p) => (
                    <tr key={p.id} className="border-b border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] transition-colors">
                      <td className="px-2.5 py-2 text-xs">{p.name}</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{typeof p.target === 'object' ? JSON.stringify(p.target) : String(p.target)}</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{(p.bandwidth_limit_bps / 1e6).toFixed(1)} Mbps</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{p.priority}</td>
                      <td className="px-2.5 py-2 text-mono text-[11px] text-[var(--color-text-sec)]">{p.dscp_mark ?? '—'}</td>
                      <td className="px-2.5 py-2"><Badge variant={p.enabled ? 'active' : 'inactive'}>{p.enabled ? 'yes' : 'no'}</Badge></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
