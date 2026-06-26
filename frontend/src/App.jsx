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
  { path: '/audit', icon: '⊟', label: 'Audit' },
  { path: '/reputation', icon: '◉', label: 'Reputation' },
  { path: '/settings', icon: '⚙', label: 'Settings' },
];

const ARGUS_ICON = (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="shrink-0">
    <rect x="3" y="3" width="18" height="18" rx="4" stroke="currentColor" strokeWidth="2"/>
    <path d="M8 12L11 15L16 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

function btnClass(active) {
  return `flex items-center gap-3 w-full px-4 py-2.5 text-sm transition-all cursor-pointer text-left rounded-lg mx-2 ${
    active 
      ? 'bg-[var(--color-primary)] text-white font-medium shadow-sm' 
      : 'text-[var(--color-text-sec)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text)]'
  }`;
}

function Sidebar({ alertCount }) {
  const location = useLocation();
  const navigate = useNavigate();
  const auth = useContext(AuthContext);

  return (
    <div className="w-[240px] bg-[var(--color-bg-panel)] border-r border-[var(--color-bg-border)] flex flex-col shrink-0">
      <div className="flex items-center gap-3 px-6 py-5 border-b border-[var(--color-bg-border)]">
        <div className="text-[var(--color-primary)]">{ARGUS_ICON}</div>
        <span className="text-lg font-semibold text-[var(--color-text)]">Argus</span>
      </div>
      <nav className="flex-1 py-4 space-y-1">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={btnClass(location.pathname === item.path)}
          >
            <span className="text-base w-5 text-center">{item.icon}</span>
            <span className="flex-1">{item.label}</span>
            {item.path === '/alerts' && alertCount > 0 && (
              <span className="inline-flex items-center justify-center min-w-[20px] h-5 rounded-full px-1.5 text-[11px] font-semibold bg-[var(--color-danger)] text-white">{alertCount}</span>
            )}
          </button>
        ))}
      </nav>
      <div className="px-4 py-4 border-t border-[var(--color-bg-border)] space-y-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-[var(--color-primary-light)] flex items-center justify-center text-[var(--color-primary)] text-sm font-semibold">
            {auth.user?.username?.[0]?.toUpperCase() || '?'}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[var(--color-text)] text-sm font-medium truncate">{auth.user?.username || '...'}</div>
            {auth.user?.role && <Badge variant={auth.user.role}>{auth.user.role}</Badge>}
          </div>
        </div>
        <button 
          className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 text-sm rounded-lg bg-transparent text-[var(--color-text-sec)] border border-[var(--color-bg-border)] hover:bg-[var(--color-bg-hover)] hover:border-[var(--color-text-muted)] transition-all font-medium" 
          onClick={auth.logout}
        >
          Logout
        </button>
      </div>
    </div>
  );
}

function ProtectedLayout() {
  const auth = useContext(AuthContext);
  const location = useLocation();
  const [alertCount, setAlertCount] = useState(0);

  useEffect(() => {
    const cleanup = api.connectWebSocket((msg) => {
      if (msg.event_type === 'alert') setAlertCount((c) => c + 1);
    });
    return () => { if (cleanup && typeof cleanup === 'function') cleanup(); };
  }, []);

  if (!auth.user) return <Navigate to="/login" replace />;

  return (
    <div className="flex h-screen bg-[var(--color-bg-root)]">
      <Sidebar alertCount={alertCount} />
      <div className="flex-1 p-6 overflow-auto" key={location.pathname}>
        <div className="animate-fade max-w-[1600px] mx-auto">
          <Outlet />
        </div>
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
