const VARIANTS = {
  allow: ['var(--green)', '#000'],
  deny: ['var(--red)', '#fff'],
  'rate-limit': ['var(--yellow)', '#000'],
  success: ['var(--green)', '#000'],
  failed: ['var(--red)', '#fff'],
  info: ['var(--cyan)', '#000'],
  warn: ['var(--yellow)', '#000'],
  warning: ['var(--yellow)', '#000'],
  critical: ['var(--red)', '#fff'],
  admin: ['var(--purple)', '#fff'],
  operator: ['var(--cyan)', '#000'],
  viewer: ['var(--text-muted)', '#fff'],
  online: ['var(--green)', '#000'],
  offline: ['var(--red)', '#fff'],
  active: ['var(--green)', '#000'],
  inactive: ['var(--text-muted)', '#fff'],
  leader: ['var(--cyan)', '#000'],
  follower: ['var(--text-sec)', '#fff'],
  new: ['var(--cyan)', '#000'],
  established: ['var(--green)', '#000'],
  closing: ['var(--yellow)', '#000'],
  closed: ['var(--text-muted)', '#fff'],
  pending: ['var(--yellow)', '#000'],
  approved: ['var(--green)', '#000'],
  denied: ['var(--red)', '#fff'],
  revoked: ['var(--text-muted)', '#fff'],
  inbound: ['var(--cyan)', '#000'],
  outbound: ['var(--purple)', '#fff'],
  forward: ['var(--yellow)', '#000'],
};

export default function Badge({ variant, children }) {
  const [bg, fg] = VARIANTS[variant] || ['var(--text-muted)', '#fff'];
  return <span className="badge" style={{ background: bg, color: fg }}>{children}</span>;
}

export function Toggle({ checked, onChange }) {
  return (
    <div className={`toggle ${checked ? 'on' : 'off'}`} onClick={onChange} role="switch" aria-checked={checked} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && onChange?.()} />
  );
}

export function Modal({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{title}</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <div className="sub">{subtitle}</div>}
      </div>
      {children && <div className="page-actions">{children}</div>}
    </div>
  );
}

export function SkeletonRows({ count = 3, cols = 6 }) {
  return Array.from({ length: count }).map((_, i) => (
    <div key={i} className="skeleton-row">
      {Array.from({ length: cols }).map((_, j) => (
        <div key={j} className="skeleton-bar" style={{ width: [40, 120, 80, 80, 60, 50][j % 6] }} />
      ))}
    </div>
  ));
}

export function EmptyState({ msg, action, onAction }) {
  return (
    <div className="empty-state">
      <div className="icon">📭</div>
      <div className="msg">{msg}</div>
      {action && <button className="btn btn-primary" onClick={onAction}>{action}</button>}
    </div>
  );
}

export function LoadingError({ message, onRetry }) {
  return (
    <div className="empty-state">
      <div className="icon">⚠️</div>
      <div className="msg" style={{ color: 'var(--red)' }}>{message || 'Failed to load data'}</div>
      {onRetry && <button className="btn btn-primary" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Field({ label, error, children }) {
  return (
    <div className="field">
      {label && <label>{label}</label>}
      {children}
      {error && <div className="err">{error}</div>}
    </div>
  );
}

const PROTO_MAP = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };
export function protoName(p) {
  if (!p) return 'Unknown';
  const n = Number(p);
  return PROTO_MAP[n] || `IP/${n}`;
}
