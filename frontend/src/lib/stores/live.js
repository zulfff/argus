import { writable } from 'svelte/store';

let ws = null;
let reconnectTimer = null;

export const liveStats = writable(null);
export const liveConnections = writable([]);
export const liveAlerts = writable([]);
export const wsConnected = writable(false);

export function connectWebSocket(token) {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  if (reconnectTimer) clearTimeout(reconnectTimer);

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${window.location.host}/api/v1/ws?token=${token}`;

  try {
    ws = new WebSocket(url);

    ws.onopen = () => {
      wsConnected.set(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event_type === 'stats') {
          liveStats.set(data.data);
        } else if (data.event_type === 'connection') {
          liveConnections.update((conns) => {
            const idx = conns.findIndex((c) => c.id === data.data.id);
            if (idx >= 0) {
              conns[idx] = data.data;
              return [...conns];
            }
            return [data.data, ...conns];
          });
        } else if (data.event_type === 'alert') {
          liveAlerts.update((alerts) => [data.data, ...alerts].slice(0, 50));
        }
      } catch (e) {
        /* ignore parse errors */
      }
    };

    ws.onerror = () => {
      wsConnected.set(false);
    };

    ws.onclose = () => {
      wsConnected.set(false);
      ws = null;
      reconnectTimer = setTimeout(() => connectWebSocket(token), 3000);
    };
  } catch {
    wsConnected.set(false);
    reconnectTimer = setTimeout(() => connectWebSocket(token), 3000);
  }
}

export function disconnectWebSocket() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (ws) {
    ws.onclose = null;
    ws.close();
    ws = null;
  }
  wsConnected.set(false);
}
