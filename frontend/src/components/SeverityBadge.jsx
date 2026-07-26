const STATUS_CLASS = {
  critical: 'badge--critical',
  high: 'badge--serious',
  medium: 'badge--warning',
  low: 'badge--good',
  info: 'badge--muted',
}

export default function SeverityBadge({ severity }) {
  if (!severity) return <span className="muted">–</span>
  const cls = STATUS_CLASS[String(severity).toLowerCase()] ?? 'badge--muted'
  return <span className={`badge ${cls}`}>{severity}</span>
}
