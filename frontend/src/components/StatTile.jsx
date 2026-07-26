// accent usa a mesma paleta de status dos badges (StatusBadge/SeverityBadge):
// 'good' | 'warning' | 'critical' | 'muted' | undefined (neutro)
export default function StatTile({ label, value, onClick, accent }) {
  const Tag = onClick ? 'button' : 'div'
  const cls = accent ? `stat-tile stat-tile--${accent}` : 'stat-tile'
  return (
    <Tag className={cls} onClick={onClick}>
      <span className="stat-tile__value">{value}</span>
      <span className="stat-tile__label">{label}</span>
    </Tag>
  )
}
