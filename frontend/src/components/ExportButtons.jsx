import { useTranslation } from '../i18n/LanguageContext.jsx'

// Links simples de download (não fetch/blob): o browser já trata a resposta
// com Content-Disposition: attachment como download nativo.
export default function ExportButtons({ urls }) {
  const { t } = useTranslation()
  return (
    <div className="export-buttons">
      <span className="export-buttons__label">{t('exportar')}</span>
      <a href={urls.json} className="export-buttons__link">
        JSON
      </a>
      <a href={urls.csv} className="export-buttons__link">
        CSV
      </a>
      <a href={urls.pdf} className="export-buttons__link">
        PDF
      </a>
    </div>
  )
}
