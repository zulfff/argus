import { writable } from 'svelte/store';

const stored = typeof localStorage !== 'undefined' ? localStorage.getItem('argus_token') : null;
export const authToken = writable(stored);
export const authRole = writable(null);

authToken.subscribe((val) => {
  if (typeof localStorage !== 'undefined') {
    if (val) localStorage.setItem('argus_token', val);
    else localStorage.removeItem('argus_token');
  }
});

const API_BASE = '/api/v1';

export async function apiFetch(path, options = {}) {
  let token;
  authToken.subscribe((v) => (token = v))();

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    authToken.set(null);
    authRole.set(null);
    throw new Error('Session expired — please login again');
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }

  return res.json();
}
