import { useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

// Mensagem curta explicando de onde um IP "solto" na tabela veio (ex: um
// achado de nmap/shodan/censys cujo PTR não bate com o domínio do cliente).
// Busca sob demanda (só ao abrir), cacheado no state — reabrir não refaz a
// chamada.
function summaryFor(t, data) {
  switch (data.kind) {
    case 'root_domain':
      return t('IP do domínio raiz {{target}}', { target: data.target })
    case 'subdomain':
      return t('Resolvido do subdomínio {{subdomains}} (dnsx)', { subdomains: data.subdomains.join(', ') })
    case 'direct_ip':
      return t('IP informado diretamente no alvo do scan ({{target}})', { target: data.target })
    default:
      return t('Não foi possível determinar a origem desse IP.')
  }
}

export default function IpProvenance({ client, ip, scanId }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [state, setState] = useState({ status: 'idle' })
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    function onClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [open])

  function handleToggle() {
    setOpen((prev) => !prev)
    if (state.status === 'idle') {
      setState({ status: 'loading' })
      api
        .ipProvenance(client, ip, scanId)
        .then((data) => setState({ status: 'ok', data }))
        .catch(() => setState({ status: 'error' }))
    }
  }

  return (
    <span className="ip-provenance" ref={ref}>
      {ip}
      <button
        type="button"
        className="ip-provenance__trigger"
        onClick={handleToggle}
        title={t('Como esse IP foi descoberto')}
        aria-label={t('Como esse IP foi descoberto')}
      >
        ⓘ
      </button>
      {open && (
        <div className="ip-provenance__popover">
          {state.status === 'loading' && t('Carregando…')}
          {state.status === 'error' && t('Erro ao buscar origem.')}
          {state.status === 'ok' && summaryFor(t, state.data)}
        </div>
      )}
    </span>
  )
}
