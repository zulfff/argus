import { writable } from 'svelte/store';

const stored = typeof localStorage !== 'undefined' ? localStorage.getItem('argus_token') : null;
export const authToken = writable(stored);

authToken.subscribe((val) => {
  if (typeof localStorage !== 'undefined') {
    if (val) {
      localStorage.setItem('argus_token', val);
    } else {
      localStorage.removeItem('argus_token');
    }
  }
});

export const authRole = writable(null);

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
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Request failed');
  }
  return res.json();
}
