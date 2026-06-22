import { useState, useEffect, useContext } from 'react';
import * as api from '../api.js';
import { AuthContext } from '../App.jsx';
import Badge from '../components/Badge.jsx';
import { Toggle, PageHeader, SkeletonRows, EmptyState, LoadingError, Field } from '../components/Shared.jsx';

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

  const addUser = async () => {
    if (!newUser.username.trim() || !newUser.password.trim()) return;
    try { await api.auth.createUser(newUser.username, newUser.password, newUser.role); fetchUsers(); setNewUser({ username: '', password: '', role: 'viewer' }); } catch {}
  };

  const deleteUser = async (u) => { try { await api.auth.deleteUser(u.username); fetchUsers(); } catch {} };

  const createBackup = async () => {
    setBackupMsg('');
    try { const res = await api.backup.create(); setBackupMsg(`✓ ${res.id}`); fetchBackups(); } catch (e) { setBackupMsg(`Error: ${e.message}`); }
  };

  const handleVpnAction = async (r, action) => { try { action === 'approve' ? await api.vpn.approve(r.id) : await api.vpn.deny(r.id); fetchVpn(); } catch {} };

  return (
    <div className="fade-in">
      <PageHeader title="Settings" subtitle="System administration" />

      <div style={{ display: 'flex', marginBottom: 20 }}>
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: '8px 16px', border: 'none', borderBottom: tab === t ? '2px solid var(--cyan)' : '2px solid transparent',
            background: 'transparent', color: tab === t ? 'var(--cyan)' : 'var(--text-sec)', cursor: 'pointer',
            fontFamily: 'var(--font-body)', fontSize: 13, textTransform: 'capitalize', fontWeight: tab === t ? 600 : 400
          }}>{t}</button>
        ))}
      </div>

      {tab === 'general' && (
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 16 }}>⚙️ General Settings</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <Field label="Hostname"><input className="input-box" defaultValue="argus-01" readOnly /></Field>
            <Field label="Listen Port"><input className="input-box" defaultValue="8443" readOnly style={{ fontFamily: 'var(--font-mono)' }} /></Field>
            <Field label="Log Level"><select className="select-box" defaultValue="info"><option value="debug">Debug</option><option value="info">Info</option><option value="warn">Warn</option><option value="error">Error</option></select></Field>
            <Field label="Default Rule Action"><select className="select-box" defaultValue="deny"><option value="deny">Deny</option><option value="allow">Allow</option></select></Field>
          </div>
          <button className="btn btn-primary" style={{ marginTop: 12 }} disabled>Save Settings</button>
        </div>
      )}

      {tab === 'users' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ color: 'var(--text-sec)', fontSize: 12 }}>👥 Users</span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', marginBottom: 12, padding: 12, background: 'var(--bg-elevated)', borderRadius: 8 }}>
            <Field label="Username" style={{ flex: 1 }}><input className="input-box" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} /></Field>
            <Field label="Password" style={{ flex: 1 }}><input className="input-box" type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} /></Field>
            <Field label="Role" style={{ width: 120 }}><select className="select-box" value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}><option value="admin">Admin</option><option value="operator">Operator</option><option value="viewer">Viewer</option></select></Field>
            <button className="btn btn-primary" onClick={addUser}>Create</button>
          </div>
          {loading.users ? <SkeletonRows count={3} cols={4} /> : (
            <table>
              <thead><tr>{['Username','Role','Status',''].map((h) => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="cell-mono">{u.username}</td>
                    <td><Badge variant={u.role}>{u.role}</Badge></td>
                    <td><Badge variant={u.enabled ? 'active' : 'inactive'}>{u.enabled ? 'active' : 'inactive'}</Badge></td>
                    <td><button className="btn btn-danger" style={{ padding: '4px 8px', fontSize: 11 }} onClick={() => deleteUser(u)}>Delete</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'vpn' && (
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>🔒 VPN Portal — WireGuard Requests</div>
          {loading.vpn ? <SkeletonRows count={3} cols={4} /> : (
            <table>
              <thead><tr>{['Requester','Requested At','Status','Actions'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {vpnReqs.length === 0 ? <tr><td colSpan={4}><EmptyState msg="No VPN requests." /></td></tr> : (
                  vpnReqs.map((r) => (
                    <tr key={r.id}>
                      <td className="cell-mono">{r.user_id}</td>
                      <td className="cell-dim">{new Date(r.created_at).toLocaleString()}</td>
                      <td><Badge variant={r.status}>{r.status}</Badge></td>
                      <td>
                        {r.status === 'Pending' ? (
                          <div style={{ display: 'flex', gap: 4 }}>
                            <button className="btn" style={{ padding: '4px 8px', fontSize: 11, background: 'var(--green)', color: '#000', border: 'none' }} onClick={() => handleVpnAction(r, 'approve')}>Approve</button>
                            <button className="btn" style={{ padding: '4px 8px', fontSize: 11, background: 'var(--red)', color: '#fff', border: 'none' }} onClick={() => handleVpnAction(r, 'deny')}>Deny</button>
                          </div>
                        ) : r.status === 'Approved' ? (
                          <button className="btn" style={{ padding: '4px 8px', fontSize: 11 }}>Download Config</button>
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
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ color: 'var(--text-sec)', fontSize: 12 }}>💾 Backups</span>
            <button className="btn btn-primary" onClick={createBackup}>Create Backup</button>
          </div>
          {backupMsg && <div style={{ padding: 8, background: 'var(--bg-elevated)', borderRadius: 6, color: 'var(--green)', fontSize: 12, marginBottom: 12, fontFamily: 'var(--font-mono)' }}>{backupMsg}</div>}
          {loading.backup ? <SkeletonRows count={3} cols={5} /> : (
            <table>
              <thead><tr>{['ID','Timestamp','Size','Checksum','Actions'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {backups.length === 0 ? <tr><td colSpan={5}><EmptyState msg="No backups yet." /></td></tr> : (
                  backups.map((b) => (
                    <tr key={b.id}>
                      <td className="cell-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>{String(b.id).slice(0, 8)}</td>
                      <td className="cell-mono cell-dim">{new Date(b.created_at).toLocaleString()}</td>
                      <td className="cell-dim">{b.size || '—'}</td>
                      <td className="cell-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>{(b.checksum || '').slice(0, 12)}...</td>
                      <td><button className="btn" style={{ padding: '4px 8px', fontSize: 11 }}>Restore</button></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'cluster' && (
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>🌐 Cluster Nodes</div>
          {loading.cluster ? <SkeletonRows count={3} cols={5} /> : (
            <table>
              <thead><tr>{['Node','IP','Role','Status','Last Heartbeat'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {nodes.length === 0 ? <tr><td colSpan={5}><EmptyState msg="No cluster nodes registered." /></td></tr> : (
                  nodes.map((n) => (
                    <tr key={n.id} style={{ borderLeft: n.role === 'leader' ? '3px solid var(--cyan)' : '3px solid transparent' }}>
                      <td className="cell-mono">{n.name}</td>
                      <td className="cell-mono cell-dim">{n.address}</td>
                      <td><Badge variant={n.role}>{n.role}</Badge></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="live-dot" style={{ background: n.healthy ? 'var(--green)' : 'var(--red)', animation: n.healthy ? 'livePulse 2s infinite' : 'none' }} />
                          <Badge variant={n.healthy ? 'online' : 'offline'}>{n.healthy ? 'online' : 'offline'}</Badge>
                        </div>
                      </td>
                      <td className="cell-mono cell-dim" style={{ fontSize: 11 }}>{new Date(n.last_heartbeat).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'syslog' && (
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>📋 Syslog</div>
          {loading.syslog ? <SkeletonRows count={2} cols={4} /> : (
            <table>
              <thead><tr>{['Server','Port','Protocol','Severity','Enabled'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {syslogCfgs.length === 0 ? <tr><td colSpan={5}><EmptyState msg="No syslog configs." /></td></tr> : (
                  syslogCfgs.map((c) => (
                    <tr key={c.id}>
                      <td className="cell-mono">{c.server}</td>
                      <td className="cell-mono cell-dim">{c.port}</td>
                      <td className="cell-mono cell-dim">{c.protocol}</td>
                      <td><Badge variant="info">{c.min_severity}</Badge></td>
                      <td><Badge variant={c.enabled ? 'active' : 'inactive'}>{c.enabled ? 'enabled' : 'disabled'}</Badge></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'qos' && (
        <div className="card">
          <div style={{ color: 'var(--text-sec)', fontSize: 12, marginBottom: 12 }}>⚡ QoS Policies</div>
          {loading.qos ? <SkeletonRows count={2} cols={5} /> : (
            <table>
              <thead><tr>{['Name','Target','Bandwidth','Priority','DSCP','Enabled'].map((h) => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {qosPolicies.length === 0 ? <tr><td colSpan={6}><EmptyState msg="No QoS policies configured." /></td></tr> : (
                  qosPolicies.map((p) => (
                    <tr key={p.id}>
                      <td>{p.name}</td>
                      <td className="cell-mono cell-dim">{typeof p.target === 'object' ? JSON.stringify(p.target) : String(p.target)}</td>
                      <td className="cell-mono cell-dim">{(p.bandwidth_limit_bps / 1e6).toFixed(1)} Mbps</td>
                      <td className="cell-mono cell-dim">{p.priority}</td>
                      <td className="cell-mono cell-dim">{p.dscp_mark ?? '—'}</td>
                      <td><Badge variant={p.enabled ? 'active' : 'inactive'}>{p.enabled ? 'yes' : 'no'}</Badge></td>
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
