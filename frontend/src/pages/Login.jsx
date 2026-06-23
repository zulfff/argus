import { useState, useContext } from 'react';
import { AuthContext } from '../App.jsx';

export default function Login() {
  const { login } = useContext(AuthContext);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try { await login(username, password); }
    catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="h-screen flex items-center justify-center bg-[var(--color-bg-root)]">
      <div className="w-[380px] p-7 bg-[var(--color-bg-panel)] border border-[var(--color-bg-border)] rounded-xl shadow-[0_4px_24px_rgba(0,0,0,0.5)]">
        <div className="flex items-center gap-2 justify-center mb-1.5 text-lg font-bold text-mono tracking-wider">
          <svg width="28" height="28" viewBox="0 0 40 40">
            <circle cx="20" cy="20" r="18" fill="none" stroke="var(--color-green-500)" strokeWidth="2" />
            <circle cx="20" cy="20" r="10" fill="var(--color-green-dim)" />
            <ellipse cx="20" cy="20" rx="5" ry="7" fill="var(--color-green-400)" style={{ animation: 'eyeScan 4s ease-in-out infinite' }} />
            <circle cx="20" cy="20" r="2" fill="var(--color-bg-root)" />
          </svg>
          ARGUS
        </div>
        <div className="text-center text-[var(--color-text-sec)] text-xs mb-5">eBPF Firewall & Router Dashboard</div>
        {error && <div className="bg-[var(--color-red-dim)] border border-[var(--color-red-400)] rounded px-2.5 py-2 text-[var(--color-red-400)] text-xs mb-2.5">{error}</div>}
        <form onSubmit={onSubmit}>
          <div className="mb-2.5">
            <label className="text-[var(--color-text-sec)] text-[11px] font-medium mb-[3px] block">Username</label>
            <input className="w-full bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)] transition-colors" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoFocus required />
          </div>
          <div className="mb-2.5">
            <label className="text-[var(--color-text-sec)] text-[11px] font-medium mb-[3px] block">Password</label>
            <input className="w-full bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded px-2.5 py-1.5 text-xs text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] hover:border-[var(--color-text-muted)] transition-colors" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <button type="submit" className="w-full inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded bg-[var(--color-green-400)] text-black hover:bg-[var(--color-green-500)] hover:shadow-[0_0_16px_var(--color-green-glow)] transition-all mt-2" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
