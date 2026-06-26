const VARIANTS = {
  allow: 'bg-[var(--color-green-400)] text-black',
  deny: 'bg-[var(--color-red-400)] text-white',
  'rate-limit': 'bg-[var(--color-yellow-400)] text-black',
  success: 'bg-[var(--color-green-400)] text-black',
  failed: 'bg-[var(--color-red-400)] text-white',
  info: 'bg-[var(--color-green-400)] text-black',
  warn: 'bg-[var(--color-yellow-400)] text-black',
  warning: 'bg-[var(--color-yellow-400)] text-black',
  critical: 'bg-[var(--color-red-400)] text-white',
  admin: 'bg-[var(--color-purple-400)] text-white',
  operator: 'bg-[var(--color-green-400)] text-black',
  viewer: 'bg-[var(--color-text-muted)] text-white',
  online: 'bg-[var(--color-green-400)] text-black',
  offline: 'bg-[var(--color-red-400)] text-white',
  active: 'bg-[var(--color-green-400)] text-black',
  inactive: 'bg-[var(--color-text-muted)] text-white',
  leader: 'bg-[var(--color-green-400)] text-black',
  follower: 'bg-[var(--color-text-sec)] text-white',
  new: 'bg-[var(--color-green-400)] text-black',
  established: 'bg-[var(--color-green-400)] text-black',
  closing: 'bg-[var(--color-yellow-400)] text-black',
  closed: 'bg-[var(--color-text-muted)] text-white',
  pending: 'bg-[var(--color-yellow-400)] text-black',
  approved: 'bg-[var(--color-green-400)] text-black',
  denied: 'bg-[var(--color-red-400)] text-white',
  revoked: 'bg-[var(--color-text-muted)] text-white',
  inbound: 'bg-[var(--color-green-400)] text-black',
  outbound: 'bg-[var(--color-purple-400)] text-white',
  forward: 'bg-[var(--color-yellow-400)] text-black',
};

export default function Badge({ variant, children }) {
  const cls = VARIANTS[variant] || 'bg-[var(--color-text-muted)] text-white';
  return <span className={`inline-flex items-center rounded-[3px] px-2 py-0.5 text-[10px] font-semibold text-mono tracking-wide ${cls}`}>{children}</span>;
}

export function Toggle({ checked, onChange }) {
  return (
    <div
      className={`w-11 h-6 rounded-full cursor-pointer relative shrink-0 transition-colors ${checked ? 'bg-[var(--color-primary)]' : 'bg-gray-200'}`}
      onClick={onChange} role="switch" aria-checked={checked} tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onChange?.()}
    >
      <div className={`absolute top-0.5 w-5 h-5 rounded-full bg-white shadow-sm transition-all ${checked ? 'left-5' : 'left-0.5'}`} />
    </div>
  );
}

export function Modal({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/40 backdrop-blur-sm animate-[modalFadeIn_.2s_ease]" onClick={onClose}>
      <div className="bg-white rounded-xl border border-[var(--color-bg-border)] p-6 min-w-[500px] max-w-[600px] max-h-[85vh] overflow-y-auto shadow-[var(--shadow-lg)] animate-[modalIn_.2s_ease]" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-5">
          <h2 className="text-lg font-semibold text-[var(--color-text)]">{title}</h2>
          <button className="bg-none border-none text-[var(--color-text-muted)] cursor-pointer text-xl p-1 leading-none hover:text-[var(--color-text)] transition-colors rounded-lg hover:bg-[var(--color-bg-hover)]" onClick={onClose} aria-label="Close">×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="flex justify-between items-start mb-6 animate-fade">
      <div>
        <h1 className="text-2xl font-semibold text-[var(--color-text)]">{title}</h1>
        {subtitle && <div className="text-[var(--color-text-sec)] text-sm mt-1">{subtitle}</div>}
      </div>
      {children && <div className="flex gap-2 items-center">{children}</div>}
    </div>
  );
}

export function SkeletonRows({ count = 3, cols = 6 }) {
  return Array.from({ length: count }).map((_, i) => (
    <div key={i} className="flex gap-4 px-4 py-3 border-b border-[var(--color-bg-border)]">
      {Array.from({ length: cols }).map((_, j) => (
        <div key={j} className="h-4 rounded animate-shimmer" style={{ width: [60, 140, 100, 100, 80, 60][j % 6] }} />
      ))}
    </div>
  ));
}

export function EmptyState({ msg, action, onAction }) {
  return (
    <div className="text-center py-16 px-6 text-[var(--color-text-sec)]">
      <div className="text-5xl mb-4 opacity-40">📭</div>
      <div className="text-sm mb-4">{msg}</div>
      {action && <button className="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[var(--color-primary)] text-white hover:bg-[var(--color-primary-hover)] shadow-[var(--shadow-sm)] transition-all" onClick={onAction}>{action}</button>}
    </div>
  );
}

export function LoadingError({ message, onRetry }) {
  return (
    <div className="text-center py-16 px-6">
      <div className="text-5xl mb-4 opacity-40">⚠️</div>
      <div className="text-sm mb-4 text-[var(--color-danger)]">{message || 'Failed to load data'}</div>
      {onRetry && <button className="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[var(--color-primary)] text-white hover:bg-[var(--color-primary-hover)] shadow-[var(--shadow-sm)] transition-all" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Field({ label, error, children, style }) {
  return (
    <div className="mb-4" style={style}>
      {label && <label className="text-[var(--color-text)] text-sm font-medium mb-1.5 block">{label}</label>}
      {children}
      {error && <div className="text-[var(--color-danger)] text-xs mt-1">{error}</div>}
    </div>
  );
}

const PROTO_MAP = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };
export function protoName(p) {
  if (!p) return 'Unknown';
  const n = Number(p);
  return PROTO_MAP[n] || `IP/${n}`;
}
