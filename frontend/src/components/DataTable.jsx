import AssetLink from './AssetLink.jsx'
import IpProvenance from './IpProvenance.jsx'
import JobDocsLink from './JobDocsLink.jsx'
import SeverityBadge from './SeverityBadge.jsx'
import StatusBadge from './StatusBadge.jsx'
import { useTranslation } from '../i18n/LanguageContext.jsx'

// Colunas que identificam "o host/IP/URL que esse achado é sobre" — ganham
// o atalho "🔍" pra página de detalhe do ativo (ver AssetLink.jsx).
const ASSET_KEYS = new Set(['subdomain', 'host', 'ip', 'url', 'domain', 'hostname'])

function renderCell(col, row, locale, client, t) {
  const value = row[col.key]

  if (col.key === 'severity') return <SeverityBadge severity={value} />
  if (col.key === 'status') return <StatusBadge status={value} />
  if (col.key === 'doc_count' && client) return <JobDocsLink client={client} row={row} />
  // Achado "por IP" (nmap/masscan/shodan/censys) — o IP pode parecer solto
  // sem contexto (ex: PTR não bate com o domínio do cliente), então ganha
  // um botão "ⓘ" que explica de onde ele veio (ver IpProvenance.jsx).
  if (col.key === 'ip' && value && client && row.scan_id) {
    return (
      <>
        <IpProvenance client={client} ip={value} scanId={row.scan_id} />
        <AssetLink client={client} value={value} />
      </>
    )
  }
  if (ASSET_KEYS.has(col.key) && value && client && typeof value === 'string') {
    return (
      <>
        {value}
        <AssetLink client={client} value={value} />
      </>
    )
  }
  // wpscan grava só o username puro em "title" (dado bruto) — a frase é
  // composta aqui, no idioma selecionado, em vez de fixa no backend.
  if (col.key === 'title' && row.finding_type === 'user' && value) {
    return t('Usuário enumerado: {{username}}', { username: value })
  }
  if (Array.isArray(value)) return value.length ? value.join(', ') : <span className="muted">–</span>
  if (typeof value === 'boolean') return value ? '✓' : '–'
  if (value === null || value === undefined || value === '') return <span className="muted">–</span>
  if (col.key === '@timestamp' || col.key === 'started_at' || col.key === 'finished_at') {
    return new Date(value).toLocaleString(locale)
  }
  if (col.key === 'description' || col.key === 'error' || col.key === 'references') {
    const text = String(value)
    return <span title={text}>{text.length > 100 ? `${text.slice(0, 100)}…` : text}</span>
  }
  return String(value)
}

function HeaderCell({ col, sort, onSort, t }) {
  if (!onSort || col.sortable === false) return t(col.label)

  const active = sort && sort.replace(/^-/, '') === col.key
  const desc = active && sort.startsWith('-')

  return (
    <button type="button" className="th-sort" onClick={() => onSort(col.key)}>
      {t(col.label)}
      <span className={`th-sort__arrow${active ? ' th-sort__arrow--active' : ''}`}>
        {active ? (desc ? '▼' : '▲') : '↕'}
      </span>
    </button>
  )
}

export default function DataTable({
  columns,
  rows,
  loading,
  sort,
  onSort,
  renderActions,
  selectable = false,
  selectedIds,
  onToggleRow,
  onToggleAll,
  client,
}) {
  const { t, lang } = useTranslation()
  const locale = lang === 'en' ? 'en-US' : 'pt-BR'

  if (loading) return <div className="empty-state">{t('Carregando…')}</div>
  if (!rows.length) return <div className="empty-state">{t('Nenhum resultado encontrado.')}</div>

  const allSelected = selectable && rows.every((r) => selectedIds.has(r._id))

  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {selectable && (
              <th className="data-table__checkbox-col">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={() => onToggleAll(rows)}
                  aria-label={t('Selecionar todos')}
                />
              </th>
            )}
            {columns.map((c) => (
              <th key={c.key}>
                <HeaderCell col={c} sort={sort} onSort={onSort} t={t} />
              </th>
            ))}
            {renderActions && <th></th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row._id}>
              {selectable && (
                <td className="data-table__checkbox-col">
                  <input
                    type="checkbox"
                    checked={selectedIds.has(row._id)}
                    onChange={() => onToggleRow(row._id)}
                    aria-label={t('Selecionar linha')}
                  />
                </td>
              )}
              {columns.map((c) => (
                <td key={c.key}>{renderCell(c, row, locale, client, t)}</td>
              ))}
              {renderActions && <td>{renderActions(row)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
