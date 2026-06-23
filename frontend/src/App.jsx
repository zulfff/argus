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

const ARGUS_EYE = (
  <svg width="22" height="22" viewBox="0 0 40 40" className="shrink-0">
    <circle cx="20" cy="20" r="18" fill="none" stroke="var(--color-green-500)" strokeWidth="2" />
    <circle cx="20" cy="20" r="10" fill="var(--color-green-dim)" />
    <ellipse cx="20" cy="20" rx="5" ry="7" fill="var(--color-green-400)" style={{ animation: 'eyeScan 4s ease-in-out infinite' }} />
    <circle cx="20" cy="20" r="2" fill="var(--color-bg-root)" />
  </svg>
);

function btnClass(active) {
  return `flex items-center gap-2 w-full px-3.5 py-2 border-l-2 text-xs transition-all cursor-pointer text-left font-body border-transparent text-[var(--color-text-sec)] hover:bg-[#001a12] hover:text-[var(--color-text)] ${active ? '!border-[var(--color-green-400)] !text-[var(--color-green-500)] !bg-[#001a12]' : ''}`;
}

function Sidebar({ alertCount }) {
  const location = useLocation();
  const navigate = useNavigate();
  const auth = useContext(AuthContext);

  return (
    <div className="w-[200px] bg-[#000a06] border-r border-[var(--color-bg-border)] flex flex-col shrink-0">
      <div className="flex items-center gap-2 px-3.5 py-4 border-b border-[var(--color-bg-border)] text-[15px] font-bold text-mono tracking-wider">
        {ARGUS_EYE}
        <span>ARGUS</span>
      </div>
      <nav className="flex-1 py-1">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={btnClass(location.pathname === item.path)}
          >
            <span className="text-sm w-[18px] text-center">{item.icon}</span>
            <span>{item.label}</span>
            {item.path === '/alerts' && alertCount > 0 && (
              <span className="inline-flex items-center rounded-[3px] px-2 py-0.5 text-[10px] font-semibold text-mono bg-[var(--color-red-400)] text-white ml-auto">{alertCount}</span>
            )}
          </button>
        ))}
      </nav>
      <div className="px-3.5 py-2.5 border-t border-[var(--color-bg-border)]">
        <div className="flex items-center gap-2 mb-2">
          <div className="w-[26px] h-[26px] rounded-full bg-[var(--color-green-400)] flex items-center justify-center text-black text-[11px] font-bold">
            {auth.user?.username?.[0]?.toUpperCase() || '?'}
          </div>
          <div>
            <div className="text-[var(--color-text)] text-[11px]">{auth.user?.username || '...'}</div>
            {auth.user?.role && <Badge variant={auth.user.role}>{auth.user.role}</Badge>}
          </div>
        </div>
        <button className="w-full inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs rounded bg-transparent text-[var(--color-text-sec)] border border-[var(--color-bg-border)] hover:bg-[var(--color-bg-elevated)] hover:border-[var(--color-text-muted)] transition-all" onClick={auth.logout}>
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
      <div className="flex-1 p-5 overflow-auto bg-[var(--color-bg-root)]" key={location.pathname}>
        <div className="animate-fade">
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
