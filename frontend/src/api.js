const BASE = '/api/v1';

let accessToken = null;
let refreshToken = null;
let onAuthChange = null;

export function setTokens(access, refresh) {
  accessToken = access;
  refreshToken = refresh;
}

export function clearTokens() {
  accessToken = null;
  refreshToken = null;
  if (onAuthChange) onAuthChange(false);
}

export function getAccessToken() { return accessToken; }

export function onAuthStateChange(fn) { onAuthChange = fn; }

async function request(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

  let res = await fetch(`${BASE}${path}`, { ...opts, headers });

  if (res.status === 401 && refreshToken) {
    const refRes = await fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (refRes.ok) {
      const { access_token, refresh_token } = await refRes.json();
      setTokens(access_token, refresh_token);
      headers['Authorization'] = `Bearer ${accessToken}`;
      res = await fetch(`${BASE}${path}`, { ...opts, headers });
    } else {
      clearTokens();
      throw new Error('Session expired');
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }

  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

// ─── Auth ──────────────────────────────────────────
export const auth = {
  login: (username, password) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  listUsers: () => request('/auth/users'),
  createUser: (username, password, role) =>
    request('/auth/users', { method: 'POST', body: JSON.stringify({ username, password, role }) }),
  deleteUser: (username) =>
    request(`/auth/users/${encodeURIComponent(username)}`, { method: 'DELETE' }),
  changePassword: (username, password) =>
    request(`/auth/users/${encodeURIComponent(username)}/password`, { method: 'PUT', body: JSON.stringify({ password }) }),
};

// ─── Rules ─────────────────────────────────────────
export const rules = {
  list: () => request('/rules'),
  create: (data) => request('/rules', { method: 'POST', body: JSON.stringify(data) }),
  get: (id) => request(`/rules/${id}`),
  update: (id, data) => request(`/rules/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id) => request(`/rules/${id}`, { method: 'DELETE' }),
  export: (fmt) => request(`/rules/export/${fmt}`),
  import: (data) => request('/rules/import', { method: 'POST', body: JSON.stringify({ data }) }),
  simulate: (data) => request('/rules/simulate', { method: 'POST', body: JSON.stringify(data) }),
};

// ─── Stats ─────────────────────────────────────────
export const stats = {
  get: () => request('/stats'),
};

// ─── Connections ───────────────────────────────────
export const connections = {
  list: () => request('/connections'),
};

// ─── Block ─────────────────────────────────────────
export const block = {
  add: (ip) => request('/block', { method: 'POST', body: JSON.stringify({ ip }) }),
  remove: (ip) => request(`/block/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
};

// ─── Audit ─────────────────────────────────────────
export const audit = {
  list: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/audit${qs ? '?' + qs : ''}`);
  },
  verify: () => request('/audit/verify'),
  export: () => request('/audit/export'),
};

// ─── Alerts ────────────────────────────────────────
export const alerts = {
  rules: {
    list: () => request('/alerts/rules'),
    create: (data) => request('/alerts/rules', { method: 'POST', body: JSON.stringify(data) }),
    delete: (id) => request(`/alerts/rules/${id}`, { method: 'DELETE' }),
  },
  history: {
    list: () => request('/alerts/history'),
    acknowledge: (id) => request(`/alerts/history/${id}/ack`, { method: 'POST' }),
  },
};

// ─── Reputation ────────────────────────────────────
export const reputation = {
  list: () => request('/reputation'),
  get: (ip) => request(`/reputation/${encodeURIComponent(ip)}`),
};

// ─── Cluster ──────────────────────────────────────
export const cluster = {
  nodes: () => request('/cluster/nodes'),
  register: (name, address, port) =>
    request('/cluster/nodes', { method: 'POST', body: JSON.stringify({ name, address, port }) }),
  remove: (id) => request(`/cluster/nodes/${id}`, { method: 'DELETE' }),
  status: () => request('/cluster/status'),
};

// ─── VPN ──────────────────────────────────────────
export const vpn = {
  requests: (status) => {
    const qs = status ? `?status=${status}` : '';
    return request(`/vpn/requests${qs}`);
  },
  submit: (data) => request('/vpn/request', { method: 'POST', body: JSON.stringify(data) }),
  approve: (id) => request(`/vpn/requests/${id}/approve`, { method: 'POST' }),
  deny: (id) => request(`/vpn/requests/${id}/deny`, { method: 'POST' }),
  revoke: (id) => request(`/vpn/requests/${id}/revoke`, { method: 'POST' }),
  config: (id) => request(`/vpn/requests/${id}/config`),
};

// ─── Backup ───────────────────────────────────────
export const backup = {
  create: () => request('/backup', { method: 'POST' }),
  list: () => request('/backup'),
  restore: (id) => request('/backup/restore', { method: 'POST', body: JSON.stringify({ id }) }),
};

// ─── QoS ──────────────────────────────────────────
export const qos = {
  list: () => request('/qos/policies'),
  create: (data) => request('/qos/policies', { method: 'POST', body: JSON.stringify(data) }),
  delete: (id) => request(`/qos/policies/${id}`, { method: 'DELETE' }),
};

// ─── Syslog ───────────────────────────────────────
export const syslog = {
  list: () => request('/syslog/configs'),
  add: (data) => request('/syslog/configs', { method: 'POST', body: JSON.stringify(data) }),
  remove: (id) => request(`/syslog/configs/${id}`, { method: 'DELETE' }),
};

// ─── Tenants ──────────────────────────────────────
export const tenants = {
  list: () => request('/tenants'),
  create: (name, description) =>
    request('/tenants', { method: 'POST', body: JSON.stringify({ name, description }) }),
  delete: (id) => request(`/tenants/${id}`, { method: 'DELETE' }),
};

// ─── Scheduler ────────────────────────────────────
export const scheduler = {
  list: () => request('/schedules'),
  create: (data) => request('/schedules', { method: 'POST', body: JSON.stringify(data) }),
  delete: (id) => request(`/schedules/${id}`, { method: 'DELETE' }),
};

// ─── WebSocket ────────────────────────────────────
let ws = null;
let wsHandler = null;
let wsReconnectTimer = null;

export function connectWebSocket(handler) {
  wsHandler = handler;
  if (!accessToken) return () => {};

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${window.location.host}/api/v1/ws`;

  ws = new WebSocket(url, ['bearer', accessToken]);

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (wsHandler) wsHandler(msg);
    } catch {}
  };

  ws.onclose = () => {
    if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
    wsReconnectTimer = setTimeout(() => connectWebSocket(wsHandler), 5000);
  };

  ws.onerror = () => ws?.close();

  return () => {
    if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
    ws?.close();
  };
}
