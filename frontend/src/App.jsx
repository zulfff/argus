import { useState, useEffect, createContext, useContext, useCallback } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation, Outlet } from 'react-router-dom';
import * as api from './api.js';
import Badge from './components/Badge.jsx';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Rules from './pages/Rules.jsx';
import Connections from './pages/Connections.jsx';
import Alerts from './pages/Alerts.jsx';
import Audit from './pages/Audit.jsx';
import Reputation from './pages/Reputation.jsx';
import Settings from './pages/Settings.jsx';

export const AuthContext = createContext(null);

const NAV_ITEMS = [
  { path: '/dashboard', icon: '◈', label: 'Dashboard' },
  { path: '/rules', icon: '⊞', label: 'Rules' },
  { path: '/connections', icon: '⊷', label: 'Connections' },
  { path: '/alerts', icon: '⚡', label: 'Alerts' },
  { path: '/audit', icon: '⊟', label: 'Audit Log' },
  { path: '/reputation', icon: '◉', label: 'Reputation' },
  { path: '/settings', icon: '⚙', label: 'Settings' },
];

const ARGUS_EYE = (
  <svg width="28" height="28" viewBox="0 0 40 40" style={{ flexShrink: 0 }}>
    <circle cx="20" cy="20" r="18" fill="none" stroke="var(--cyan)" strokeWidth="2" />
    <circle cx="20" cy="20" r="10" fill="var(--cyan-glow)" />
    <ellipse cx="20" cy="20" rx="5" ry="7" fill="var(--cyan)" style={{ animation: 'eyeScan 4s ease-in-out infinite' }} />
    <circle cx="20" cy="20" r="2" fill="var(--bg-root)" />
  </svg>
);

function Sidebar({ alertCount }) {
  const location = useLocation();
  const navigate = useNavigate();
  const auth = useContext(AuthContext);

  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        {ARGUS_EYE}
        <span>ARGUS</span>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={`sidebar-nav-item ${location.pathname === item.path ? 'active' : ''}`}
          >
            <span className="icon">{item.icon}</span>
            <span>{item.label}</span>
            {item.path === '/alerts' && alertCount > 0 && (
              <span className="badge" style={{ background: 'var(--red)', color: '#fff' }}>{alertCount}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="sidebar-avatar">{auth.user?.username?.[0]?.toUpperCase() || '?'}</div>
          <div>
            <div className="sidebar-user-name">{auth.user?.username || '...'}</div>
            {auth.user?.role && <Badge variant={auth.user.role}>{auth.user.role}</Badge>}
          </div>
        </div>
        <button className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center' }} onClick={auth.logout}>
          Logout
        </button>
      </div>
    </div>
  );
}

function ProtectedLayout() {
  const auth = useContext(AuthContext);
  const [alertCount, setAlertCount] = useState(0);
  const [wsCleanup, setWsCleanup] = useState(null);

  useEffect(() => {
    const cleanup = api.connectWebSocket((msg) => {
      if (msg.event_type === 'alert') setAlertCount((c) => c + 1);
    });
    setWsCleanup(() => cleanup);
    return () => { if (cleanup && typeof cleanup === 'function') cleanup(); };
  }, []);

  if (!auth.user) return <Navigate to="/login" replace />;

  return (
    <div className="layout">
      <Sidebar alertCount={alertCount} />
      <div className="main-content fade-in" key={location.pathname}>
        <Outlet />
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const stored = localStorage.getItem('argus_user');
    const tokens = localStorage.getItem('argus_tokens');
    if (stored && tokens) {
      try {
        const { access, refresh } = JSON.parse(tokens);
        api.setTokens(access, refresh);
        setUser(JSON.parse(stored));
      } catch {}
    }
    setLoading(false);
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await api.auth.login(username, password);
    const { access_token, refresh_token, role } = res;
    api.setTokens(access_token, refresh_token);
    const u = { username, role };
    localStorage.setItem('argus_user', JSON.stringify(u));
    localStorage.setItem('argus_tokens', JSON.stringify({ access: access_token, refresh: refresh_token }));
    setUser(u);
    navigate('/dashboard');
  }, [navigate]);

  const logout = useCallback(() => {
    api.clearTokens();
    localStorage.removeItem('argus_user');
    localStorage.removeItem('argus_tokens');
    setUser(null);
    navigate('/login');
  }, [navigate]);

  if (loading) return null;

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/dashboard" replace /> : <Login />} />
        <Route element={<ProtectedLayout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/connections" element={<Connections />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/reputation" element={<Reputation />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AuthContext.Provider>
  );
}
