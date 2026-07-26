import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useTranslation } from '../i18n/LanguageContext.jsx'
import { suffixLabel } from '../toolSchemas.js'

// Barra horizontal com a contagem de achados por ferramenta — mesmo dado já
// usado no grid de StatTile logo abaixo (indices/findingsIndices), só numa
// forma que dá pra comparar o volume entre ferramentas de relance.
export default function FindingsByToolChart({ indices }) {
  const { t } = useTranslation()
  if (!indices.length) return null

  const data = [...indices]
    .sort((a, b) => b.doc_count - a.doc_count)
    .map((idx) => ({ suffix: idx.suffix, label: t(suffixLabel(idx.suffix)), count: idx.doc_count }))

  return (
    <div className="chart-card">
      <ResponsiveContainer width="100%" height={Math.max(120, data.length * 28)}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, bottom: 4, left: 4 }}>
          <CartesianGrid horizontal={false} stroke="var(--gridline)" />
          <XAxis type="number" allowDecimals={false} tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} />
          <YAxis
            type="category"
            dataKey="label"
            width={160}
            tick={{ fill: 'var(--text-secondary)', fontSize: 12 }}
          />
          <Tooltip
            contentStyle={{ background: 'var(--surface-1)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
            formatter={(value) => [value, t('Achados')]}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {data.map((d) => (
              <Cell key={d.suffix} fill="var(--series-1)" />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
