const API_BASE = '/api/v1';

let token = typeof localStorage !== 'undefined' ? localStorage.getItem('argus_token') : null;
let authRole = null;

export function isAuthenticated() { return !!token; }
export function getRole() { return authRole; }
export function getToken() { return token; }

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Login failed' }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  const data = await res.json();
  token = data.access_token;
  authRole = data.role;
  localStorage.setItem('argus_token', token);
  return data;
}

export function logout() {
  token = null;
  authRole = null;
  localStorage.removeItem('argus_token');
}

async function apiFetch(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401 && path !== '/auth/login') {
    logout();
    window.location.hash = 'login';
    throw new Error('Session expired');
  }
  return res;
}

export async function apiGet(path) {
  const res = await apiFetch(path);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function apiPost(path, body) {
  const res = await apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function apiPut(path, body) {
  const res = await apiFetch(path, { method: 'PUT', body: JSON.stringify(body) });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function apiDelete(path) {
  const res = await apiFetch(path, { method: 'DELETE' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function apiPostForm(path, body) {
  const headers = { ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const res = await fetch(`${API_BASE}${path}`, { method: 'POST', headers, body });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function apiDownload(path, filename) {
  const headers = { ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const res = await fetch(`${API_BASE}${path}`, { headers });
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename || 'download';
  a.click();
  URL.revokeObjectURL(url);
}

// ===== Auth (Admin) =====
export const listUsers = () => apiGet('/auth/users');
export const createUser = (u) => apiPost('/auth/users', u);
export const deleteUser = (username) => apiDelete(`/auth/users/${username}`);
export const changePassword = (username, password) => apiPut(`/auth/users/${username}/password`, { password });

// ===== Rules =====
export const listRules = () => apiGet('/rules');
export const getRule = (id) => apiGet(`/rules/${id}`);
export const createRule = (r) => apiPost('/rules', r);
export const updateRule = (id, r) => apiPut(`/rules/${id}`, r);
export const deleteRule = (id) => apiDelete(`/rules/${id}`);
export const simulateRule = (req) => apiPost('/rules/simulate', req);
export const exportRulesJson = () => apiDownload('/rules/export/json', 'rules.json');
export const exportRulesYaml = () => apiDownload('/rules/export/yaml', 'rules.yaml');
export const exportRulesCsv = () => apiDownload('/rules/export/csv', 'rules.csv');
export const importRules = (data) => apiPost('/rules/import', data);

// ===== Stats & Connections =====
export const getStats = () => apiGet('/stats');
export const listConnections = () => apiGet('/connections');
export const blockIp = (ip) => apiPost('/block', { ip });
export const unblockIp = (ip) => apiDelete(`/block/${ip}`);

// ===== Audit =====
export const listAudit = (params) => {
  const q = new URLSearchParams();
  if (params?.actor) q.set('actor', params.actor);
  if (params?.action) q.set('action', params.action);
  if (params?.limit) q.set('limit', params.limit);
  const qs = q.toString();
  return apiGet(`/audit${qs ? '?' + qs : ''}`);
};
export const verifyAudit = () => apiGet('/audit/verify');
export const exportAudit = () => apiDownload('/audit/export', `audit-export-${new Date().toISOString().slice(0,10)}.json`);

// ===== Alerts =====
export const listAlertRules = () => apiGet('/alerts/rules');
export const createAlertRule = (r) => apiPost('/alerts/rules', r);
export const deleteAlertRule = (id) => apiDelete(`/alerts/rules/${id}`);
export const listAlertHistory = () => apiGet('/alerts/history');
export const acknowledgeAlert = (id) => apiPost(`/alerts/history/${id}/ack`);

// ===== Tenants =====
export const listTenants = () => apiGet('/tenants');
export const createTenant = (t) => apiPost('/tenants', t);
export const deleteTenant = (id) => apiDelete(`/tenants/${id}`);

// ===== Cluster =====
export const listClusterNodes = () => apiGet('/cluster/nodes');
export const registerNode = (n) => apiPost('/cluster/nodes', n);
export const removeNode = (id) => apiDelete(`/cluster/nodes/${id}`);
export const clusterStatus = () => apiGet('/cluster/status');

// ===== Reputation =====
export const listReputations = () => apiGet('/reputation');
export const getReputation = (ip) => apiGet(`/reputation/${encodeURIComponent(ip)}`);

// ===== Schedules =====
export const listSchedules = () => apiGet('/schedules');
export const createSchedule = (s) => apiPost('/schedules', s);
export const deleteSchedule = (id) => apiDelete(`/schedules/${id}`);

// ===== VPN =====
export const submitVpnRequest = (r) => apiPost('/vpn/request', r);
export const listVpnRequests = (status) => apiGet(`/vpn/requests${status ? '?status=' + status : ''}`);
export const approveVpnRequest = (id) => apiPost(`/vpn/requests/${id}/approve`);
export const denyVpnRequest = (id) => apiPost(`/vpn/requests/${id}/deny`);
export const revokeVpnRequest = (id) => apiPost(`/vpn/requests/${id}/revoke`);
export const downloadVpnConfig = (id) => apiGet(`/vpn/requests/${id}/config`);

// ===== DPI =====
export const dpiIdentify = (req) => apiPost('/dpi/identify', req);

// ===== QoS =====
export const listQosPolicies = () => apiGet('/qos/policies');
export const createQosPolicy = (p) => apiPost('/qos/policies', p);
export const deleteQosPolicy = (id) => apiDelete(`/qos/policies/${id}`);

// ===== Compliance =====
export const generateComplianceReport = (r) => apiPost('/compliance/reports', r);
export const listComplianceReports = () => apiGet('/compliance/reports');
export const getComplianceReport = (id) => apiGet(`/compliance/reports/${id}`);

// ===== Syslog =====
export const listSyslogConfigs = () => apiGet('/syslog/configs');
export const addSyslogConfig = (c) => apiPost('/syslog/configs', c);
export const removeSyslogConfig = (id) => apiDelete(`/syslog/configs/${id}`);

// ===== Backup =====
export const createBackup = () => apiPost('/backup');
export const listBackups = () => apiGet('/backup');
export const restoreBackup = (data) => apiPost('/backup/restore', data);
export const downloadBackup = (id) => apiDownload(`/backup/download${id ? '?id=' + id : ''}`, 'argus-backup.json');

// ===== WebSocket =====
let ws = null;
let reconnectTimer = null;
let wsListeners = [];

export function connectWebSocket(onEvent) {
  if (!token) return;
  wsListeners.push(onEvent);
  if (ws) return;

  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${window.location.host}/api/v1/ws?token=${token}`;

  function connect() {
    try {
      ws = new WebSocket(url);
    } catch { return; }

    ws.onopen = () => { if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; } };
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        wsListeners.forEach(fn => fn(data));
      } catch {}
    };
    ws.onclose = () => {
      ws = null;
      if (!reconnectTimer) reconnectTimer = setTimeout(connect, 3000);
    };
    ws.onerror = () => { if (ws) ws.close(); };
  }
  connect();

  return () => {
    wsListeners = wsListeners.filter(fn => fn !== onEvent);
    if (wsListeners.length === 0 && ws) { ws.close(); ws = null; }
  };
}

export function disconnectWebSocket() {
  if (ws) { ws.close(); ws = null; }
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  wsListeners = [];
}