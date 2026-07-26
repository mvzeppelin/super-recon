import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { getUser } from '../auth.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

const PAGE_SIZE = 50

export default function AuditLogPage() {
  const { t, lang } = useTranslation()
  const locale = lang === 'en' ? 'en-US' : 'pt-BR'
  const me = getUser()

  const [result, setResult] = useState({ total: 0, items: [] })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (me?.role !== 'admin') return
    setLoading(true)
    api
      .getAuditLog({ page, size: PAGE_SIZE })
      .then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page])

  if (me?.role !== 'admin') {
    return (
      <div className="page">
        <div className="empty-state empty-state--error">{t('Você não tem permissão pra ver esta página.')}</div>
      </div>
    )
  }

  const totalPages = Math.max(1, Math.ceil(result.total / PAGE_SIZE))

  return (
    <div className="page">
      <div className="page-header">
        <h1>{t('Log de auditoria ({{total}})', { total: result.total })}</h1>
      </div>

      {error && <div className="empty-state empty-state--error">{error}</div>}
      {loading && <div className="empty-state">{t('Carregando…')}</div>}

      {!loading && !result.items.length && <div className="empty-state">{t('Nenhum registro ainda.')}</div>}

      {!loading && result.items.length > 0 && (
        <>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('Quando')}</th>
                  <th>{t('Usuário')}</th>
                  <th>{t('Papel')}</th>
                  <th>{t('Método')}</th>
                  <th>{t('Rota')}</th>
                  <th>{t('Status')}</th>
                </tr>
              </thead>
              <tbody>
                {result.items.map((entry) => (
                  <tr key={entry._id}>
                    <td>{new Date(entry['@timestamp']).toLocaleString(locale)}</td>
                    <td>{entry.username}</td>
                    <td>{entry.role}</td>
                    <td>{entry.method}</td>
                    <td>{entry.path}</td>
                    <td>{entry.status_code}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              {t('← anterior')}
            </button>
            <span>{t('página {{page}} de {{totalPages}} · {{total}} resultados', { page, totalPages, total: result.total })}</span>
            <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              {t('próxima →')}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
