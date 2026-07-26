import { Link } from 'react-router-dom'
import { useTranslation } from '../i18n/LanguageContext.jsx'

// Atalho "🔍" ao lado de valores de host/IP/URL/subdomínio nas tabelas —
// navega pra página de detalhe do ativo (AssetDetail.jsx), que junta tudo
// que qualquer ferramenta achou sobre esse mesmo valor exato.
export default function AssetLink({ client, value }) {
  const { t } = useTranslation()
  if (!client || !value) return null
  return (
    <Link
      to={`/clients/${encodeURIComponent(client)}/asset?value=${encodeURIComponent(value)}`}
      className="asset-link"
      title={t('Ver tudo sobre este ativo')}
      onClick={(e) => e.stopPropagation()}
    >
      🔍
    </Link>
  )
}
