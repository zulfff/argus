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
    <div className="h-screen flex items-center justify-center relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50"></div>
      
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-80 h-80 bg-blue-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-blob"></div>
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-blob animation-delay-2000"></div>
        <div className="absolute -bottom-40 left-20 w-80 h-80 bg-indigo-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-blob animation-delay-4000"></div>
      </div>

      <div className="relative w-[440px] backdrop-blur-xl bg-white/70 border border-white/20 rounded-3xl shadow-2xl shadow-indigo-500/10 p-10">
        <div className="absolute inset-0 bg-gradient-to-br from-white/40 to-white/10 rounded-3xl"></div>
        
        <div className="relative">
          <div className="flex items-center gap-3 justify-center mb-3">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/50">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-white">
                <rect x="3" y="3" width="18" height="18" rx="4" stroke="currentColor" strokeWidth="2"/>
                <path d="M8 12L11 15L16 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
          </div>
          
          <h1 className="text-3xl font-bold text-center mb-1 bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 bg-clip-text text-transparent">Welcome to Argus</h1>
          <p className="text-center text-gray-600 text-sm mb-8">Network Security Platform</p>
          
          {error && (
            <div className="backdrop-blur-sm bg-red-50/80 border border-red-200/50 rounded-2xl px-4 py-3 text-red-700 text-sm mb-6 flex items-start gap-3 shadow-sm">
              <span className="text-lg">⚠️</span>
              <span className="flex-1 mt-0.5">{error}</span>
            </div>
          )}
          
          <form onSubmit={onSubmit} className="space-y-5">
            <div>
              <label className="text-gray-700 text-sm font-semibold mb-2 block">Username</label>
              <input 
                className="w-full backdrop-blur-sm bg-white/50 border border-white/40 rounded-xl px-4 py-3 text-sm text-gray-900 placeholder:text-gray-400 outline-none focus:bg-white/80 focus:border-blue-400 focus:ring-4 focus:ring-blue-500/10 transition-all shadow-sm" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                placeholder="Enter your username" 
                autoFocus 
                required 
              />
            </div>
            
            <div>
              <label className="text-gray-700 text-sm font-semibold mb-2 block">Password</label>
              <input 
                className="w-full backdrop-blur-sm bg-white/50 border border-white/40 rounded-xl px-4 py-3 text-sm text-gray-900 placeholder:text-gray-400 outline-none focus:bg-white/80 focus:border-blue-400 focus:ring-4 focus:ring-blue-500/10 transition-all shadow-sm" 
                type="password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                placeholder="Enter your password"
                required 
              />
            </div>
            
            <button 
              type="submit" 
              className="w-full mt-6 inline-flex items-center justify-center gap-2 px-6 py-3.5 text-sm font-semibold rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white hover:from-blue-700 hover:to-indigo-700 shadow-lg shadow-blue-500/30 hover:shadow-xl hover:shadow-blue-500/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:shadow-lg" 
              disabled={loading}
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                  </svg>
                  <span>Signing in...</span>
                </>
              ) : (
                <>
                  <span>Sign In</span>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M5 12h14M12 5l7 7-7 7"/>
                  </svg>
                </>
              )}
            </button>
          </form>
          
          <div className="mt-8 pt-6 border-t border-gray-200/50 text-center">
            <p className="text-xs text-gray-500">
              Default: <span className="font-mono font-medium text-gray-700">admin</span> / Check server logs for password
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
