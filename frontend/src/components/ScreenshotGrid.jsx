import { api } from '../api.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

// Galeria de miniaturas do gowitness — triagem visual rápida de vários
// hosts de uma vez, diferente da DataTable (densa, uma linha por vez), que
// não faz sentido pra um achado cujo valor principal é uma imagem.
export default function ScreenshotGrid({ rows, loading, client }) {
  const { t } = useTranslation()

  if (loading) return <div className="empty-state">{t('Carregando…')}</div>
  if (!rows.length) return <div className="empty-state">{t('Nenhum resultado encontrado.')}</div>

  return (
    <div className="screenshot-grid">
      {rows.map((row) => (
        <a
          key={row._id}
          className="screenshot-card"
          href={row.screenshot_id ? api.screenshotUrl(client, row.screenshot_id) : undefined}
          target="_blank"
          rel="noreferrer"
          onClick={(e) => {
            if (!row.screenshot_id) e.preventDefault()
          }}
        >
          <div className="screenshot-card__thumb">
            {row.screenshot_id ? (
              <img src={api.screenshotUrl(client, row.screenshot_id)} alt={row.title || row.url} loading="lazy" />
            ) : (
              <span className="screenshot-card__placeholder">
                {row.failed ? t('Falhou') : t('Sem screenshot')}
              </span>
            )}
          </div>
          <div className="screenshot-card__caption">
            <strong className="screenshot-card__title">{row.title || t('(sem título)')}</strong>
            <span className="screenshot-card__url" title={row.url}>
              {row.status_code ? `${row.status_code} · ` : ''}
              {row.final_url || row.url}
            </span>
          </div>
        </a>
      ))}
    </div>
  )
}
