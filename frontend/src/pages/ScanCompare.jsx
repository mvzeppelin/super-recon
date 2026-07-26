import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import DataTable from '../components/DataTable.jsx'
import StatTile from '../components/StatTile.jsx'
import { useTranslation } from '../i18n/LanguageContext.jsx'
import { columnsFor, suffixLabel } from '../toolSchemas.js'

const NON_FINDINGS_SUFFIXES = new Set(['jobs', 'scans', 'wordlists'])

function formatScan(scan, locale) {
  if (!scan) return ''
  const when = new Date(scan['@timestamp']).toLocaleString(locale)
  const targets = (scan.targets || []).join(', ')
  return targets ? `${when} — ${targets}` : when
}

export default function ScanCompare() {
  const { t, lang } = useTranslation()
  const locale = lang === 'en' ? 'en-US' : 'pt-BR'
  const { client } = useParams()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const fromId = searchParams.get('from')
  const toId = searchParams.get('to')

  const [suffixes, setSuffixes] = useState([])
  const [suffix, setSuffix] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showUnchanged, setShowUnchanged] = useState(false)

  useEffect(() => {
    api
      .listClientIndices(client)
      .then((indices) => {
        const findings = indices.filter((i) => !NON_FINDINGS_SUFFIXES.has(i.suffix)).map((i) => i.suffix)
        setSuffixes(findings)
        setSuffix((prev) => (findings.includes(prev) ? prev : findings[0] || ''))
      })
      .catch((e) => setError(e.message))
  }, [client])

  useEffect(() => {
    if (!suffix || !fromId || !toId) return
    setLoading(true)
    setError(null)
    setShowUnchanged(false)
    api
      .compareScans(client, suffix, fromId, toId)
      .then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [client, suffix, fromId, toId])

  if (!fromId || !toId) {
    return (
      <div className="page">
        <div className="empty-state empty-state--error">
          {t('Selecione dois scans no painel do cliente para comparar.')}
        </div>
      </div>
    )
  }

  const columns = suffix ? columnsFor(suffix) : []

  return (
    <div className="page">
      <div className="page-header">
        <h1>{t('Comparar scans')} <span className="muted">· {client}</span></h1>
        <div className="page-header__actions">
          <button className="link-button" onClick={() => navigate(`/clients/${encodeURIComponent(client)}`)}>
            ← {client}
          </button>
        </div>
      </div>

      {result && (
        <div className="empty-state">
          <strong>{formatScan(result.from_scan, locale)}</strong> → <strong>{formatScan(result.to_scan, locale)}</strong>
        </div>
      )}

      <div className="filters-bar">
        {suffixes.length > 1 && (
          <select value={suffix} onChange={(e) => setSuffix(e.target.value)}>
            {suffixes.map((s) => (
              <option key={s} value={s}>
                {t(suffixLabel(s))}
              </option>
            ))}
          </select>
        )}
      </div>

      {error && <div className="empty-state empty-state--error">{error}</div>}
      {loading && <div className="empty-state">{t('Carregando…')}</div>}

      {!loading && result && (
        <>
          <div className="stat-grid">
            <div className="stat-tile stat-tile--good">
              <span className="stat-tile__value">{result.new.length}</span>
              <span className="stat-tile__label">{t('Novos')}</span>
            </div>
            <div className="stat-tile stat-tile--critical">
              <span className="stat-tile__value">{result.resolved.length}</span>
              <span className="stat-tile__label">{t('Resolvidos')}</span>
            </div>
            <StatTile
              label={t('Inalterados')}
              value={result.unchanged.length}
              accent="muted"
              onClick={() => setShowUnchanged((v) => !v)}
            />
          </div>

          <section>
            <h2>{t('Novos ({{total}})', { total: result.new.length })}</h2>
            <DataTable columns={columns} rows={result.new} loading={false} client={client} />
          </section>

          <section>
            <h2>{t('Resolvidos ({{total}})', { total: result.resolved.length })}</h2>
            <DataTable columns={columns} rows={result.resolved} loading={false} client={client} />
          </section>

          {showUnchanged && (
            <section>
              <h2>{t('Inalterados ({{total}})', { total: result.unchanged.length })}</h2>
              <DataTable columns={columns} rows={result.unchanged} loading={false} client={client} />
            </section>
          )}
        </>
      )}
    </div>
  )
}
