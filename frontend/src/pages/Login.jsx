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
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand" style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center', marginBottom: 8, fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
          <svg width="32" height="32" viewBox="0 0 40 40"><circle cx="20" cy="20" r="18" fill="none" stroke="var(--cyan)" strokeWidth="2"/><circle cx="20" cy="20" r="10" fill="var(--cyan-glow)"/><ellipse cx="20" cy="20" rx="5" ry="7" fill="var(--cyan)" style={{animation:'eyeScan 4s ease-in-out infinite'}}/><circle cx="20" cy="20" r="2" fill="var(--bg-root)"/></svg>
          ARGUS
        </div>
        <div className="login-subtitle">eBPF Firewall & Router Dashboard</div>
        {error && <div className="login-error">{error}</div>}
        <form onSubmit={onSubmit}>
          <div className="field">
            <label>Username</label>
            <input className="input-box" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoFocus required />
          </div>
          <div className="field">
            <label>Password</label>
            <input className="input-box" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <button type="submit" className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: 8 }} disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
