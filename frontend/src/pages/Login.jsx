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
    <div className="h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100">
      <div className="w-[420px] p-8 bg-white border border-[var(--color-bg-border)] rounded-2xl shadow-[var(--shadow-lg)]">
        <div className="flex items-center gap-3 justify-center mb-2">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" className="text-[var(--color-primary)]">
            <rect x="3" y="3" width="18" height="18" rx="4" stroke="currentColor" strokeWidth="2"/>
            <path d="M8 12L11 15L16 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <span className="text-2xl font-bold text-[var(--color-text)]">Argus</span>
        </div>
        <div className="text-center text-[var(--color-text-sec)] text-sm mb-8">Network Security Platform</div>
        
        {error && (
          <div className="bg-[var(--color-danger-light)] border border-[var(--color-danger)] rounded-lg px-4 py-3 text-[var(--color-danger)] text-sm mb-4 flex items-start gap-2">
            <span>⚠️</span>
            <span className="flex-1">{error}</span>
          </div>
        )}
        
        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label className="text-[var(--color-text)] text-sm font-medium mb-1.5 block">Username</label>
            <input 
              className="w-full bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded-lg px-4 py-2.5 text-sm text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] focus:border-[var(--color-primary)] focus:ring-2 focus:ring-[var(--color-primary-light)] transition-all" 
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
              placeholder="Enter username" 
              autoFocus 
              required 
            />
          </div>
          
          <div>
            <label className="text-[var(--color-text)] text-sm font-medium mb-1.5 block">Password</label>
            <input 
              className="w-full bg-[var(--color-bg-root)] border border-[var(--color-bg-border)] rounded-lg px-4 py-2.5 text-sm text-[var(--color-text)] outline-none placeholder:text-[var(--color-text-muted)] focus:border-[var(--color-primary)] focus:ring-2 focus:ring-[var(--color-primary-light)] transition-all" 
              type="password" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              placeholder="Enter password"
              required 
            />
          </div>
          
          <button 
            type="submit" 
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-semibold rounded-lg bg-[var(--color-primary)] text-white hover:bg-[var(--color-primary-hover)] shadow-[var(--shadow-sm)] hover:shadow-[var(--shadow-md)] transition-all mt-6 disabled:opacity-50 disabled:cursor-not-allowed" 
            disabled={loading}
          >
            {loading ? '⏳ Signing in...' : 'Sign In'}
          </button>
        </form>
        
        <div className="mt-6 pt-6 border-t border-[var(--color-bg-border)] text-center text-xs text-[var(--color-text-muted)]">
          Default credentials: admin / check console logs
        </div>
      </div>
    </div>
  );
}
