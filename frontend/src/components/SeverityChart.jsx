import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'

// Mesma paleta/vocabulário de SeverityBadge.jsx (lookup por
// .toLowerCase(), já que nuclei grava minúsculo e dalfox capitalizado) —
// mantém as duas representações (badge por linha, gráfico agregado)
// visualmente consistentes em vez de inventar uma paleta nova.
const COLORS = {
  critical: 'var(--status-critical)',
  high: 'var(--status-serious)',
  medium: 'var(--status-warning)',
  low: 'var(--status-good)',
  info: 'var(--status-muted)',
}

const ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function SeverityChart({ counts }) {
  const data = Object.entries(counts)
    .map(([key, value]) => ({ key, value, rank: ORDER.indexOf(key.toLowerCase()) }))
    .sort((a, b) => (a.rank === -1 ? 99 : a.rank) - (b.rank === -1 ? 99 : b.rank))

  if (!data.length) return null

  return (
    <div className="chart-card">
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="key" innerRadius={50} outerRadius={80} paddingAngle={2}>
            {data.map((d) => (
              <Cell key={d.key} fill={COLORS[d.key.toLowerCase()] ?? 'var(--status-muted)'} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: 'var(--surface-1)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="severity-chart__legend">
        {data.map((d) => (
          <span key={d.key} className="severity-chart__legend-item">
            <span className="severity-chart__swatch" style={{ background: COLORS[d.key.toLowerCase()] ?? 'var(--status-muted)' }} />
            {d.key} ({d.value})
          </span>
        ))}
      </div>
    </div>
  )
}
