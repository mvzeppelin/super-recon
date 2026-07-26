const STATUS_CLASS = {
  ok: 'badge--good',
  error: 'badge--critical',
  queued: 'badge--muted',
  running: 'badge--warning',
  cancelled: 'badge--muted',
}

export default function StatusBadge({ status }) {
  if (!status) return <span className="muted">–</span>
  const cls = STATUS_CLASS[String(status).toLowerCase()] ?? 'badge--muted'
  return <span className={`badge ${cls}`}>{status}</span>
}
