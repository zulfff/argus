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
      className={`w-[34px] h-[18px] rounded-full cursor-pointer relative shrink-0 transition-colors ${checked ? 'bg-[var(--color-green-400)]' : 'bg-[var(--color-bg-border)]'}`}
      onClick={onChange} role="switch" aria-checked={checked} tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onChange?.()}
    >
      <div className={`absolute top-[2px] w-[14px] h-[14px] rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-[2px]'}`} />
    </div>
  );
}

export function Modal({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-[rgba(0,8,4,0.75)] backdrop-blur-sm animate-[modalFadeIn_.15s_ease]" onClick={onClose}>
      <div className="bg-[var(--color-bg-panel)] rounded-lg border border-[var(--color-bg-border)] p-5 min-w-[460px] max-w-[600px] max-h-[80vh] overflow-y-auto shadow-[0_8px_40px_rgba(0,0,0,0.6)] animate-[modalIn_.15s_ease]" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-[15px] font-semibold text-[var(--color-text)] m-0">{title}</h2>
          <button className="bg-none border-none text-[var(--color-text-sec)] cursor-pointer text-base p-1 leading-none hover:text-[var(--color-text)]" onClick={onClose} aria-label="Close">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="flex justify-between items-start mb-4 animate-fade">
      <div>
        <h1 className="text-lg font-semibold text-[var(--color-text)] m-0">{title}</h1>
        {subtitle && <div className="text-[var(--color-text-sec)] text-[11px] mt-0.5">{subtitle}</div>}
      </div>
      {children && <div className="flex gap-1.5 items-center">{children}</div>}
    </div>
  );
}

export function SkeletonRows({ count = 3, cols = 6 }) {
  return Array.from({ length: count }).map((_, i) => (
    <div key={i} className="flex gap-3 px-3.5 py-2.5 border-b border-[var(--color-bg-border)]">
      {Array.from({ length: cols }).map((_, j) => (
        <div key={j} className="h-2.5 rounded-[3px] animate-shimmer" style={{ width: [40, 120, 80, 80, 60, 50][j % 6] }} />
      ))}
    </div>
  ));
}

export function EmptyState({ msg, action, onAction }) {
  return (
    <div className="text-center py-10 px-6 text-[var(--color-text-sec)]">
      <div className="text-[28px] mb-2.5 opacity-50">📭</div>
      <div className="text-[13px] mb-3.5">{msg}</div>
      {action && <button className="inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded bg-[var(--color-green-400)] text-black hover:bg-[var(--color-green-500)] hover:shadow-[0_0_16px_var(--color-green-glow)] transition-all" onClick={onAction}>{action}</button>}
    </div>
  );
}

export function LoadingError({ message, onRetry }) {
  return (
    <div className="text-center py-10 px-6 text-[var(--color-text-sec)]">
      <div className="text-[28px] mb-2.5 opacity-50">⚠️</div>
      <div className="text-[13px] mb-3.5 text-[var(--color-red-400)]">{message || 'Failed to load data'}</div>
      {onRetry && <button className="inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded bg-[var(--color-green-400)] text-black hover:bg-[var(--color-green-500)] hover:shadow-[0_0_16px_var(--color-green-glow)] transition-all" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Field({ label, error, children, style }) {
  return (
    <div className="mb-2.5" style={style}>
      {label && <label className="text-[var(--color-text-sec)] text-[11px] font-medium mb-[3px] block">{label}</label>}
      {children}
      {error && <div className="text-[var(--color-red-400)] text-[10px] mt-0.5">{error}</div>}
    </div>
  );
}

const PROTO_MAP = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };
export function protoName(p) {
  if (!p) return 'Unknown';
  const n = Number(p);
  return PROTO_MAP[n] || `IP/${n}`;
}
