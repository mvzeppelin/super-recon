import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import DataTable from '../components/DataTable.jsx'
import { useTranslation } from '../i18n/LanguageContext.jsx'
import { columnsFor, suffixLabel } from '../toolSchemas.js'

// Consolida tudo que qualquer ferramenta achou sobre um valor exato
// (subdomínio, IP ou URL) — sem isso, ver o quadro completo de um mesmo
// host exige abrir cada tela de achados por ferramenta e buscar o valor à
// mão em cada uma (ver GET /clients/{client}/asset no backend).
export default function AssetDetail() {
  const { t } = useTranslation()
  const { client } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const value = searchParams.get('value') || ''
  const [input, setInput] = useState(value)

  const [result, setResult] = useState({})
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    setInput(value)
    if (!value) {
      setResult({})
      return
    }
    setLoading(true)
    setError(null)
    api
      .getAsset(client, value)
      .then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [client, value])

  function handleSearch(e) {
    e.preventDefault()
    const v = input.trim()
    if (!v) return
    setSearchParams({ value: v })
  }

  const suffixes = Object.keys(result).sort()

  return (
    <div className="page">
      <div className="page-header">
        <h1>{t('Detalhe do ativo')}</h1>
        <div className="page-header__actions">
          <button className="link-button" onClick={() => navigate(`/clients/${encodeURIComponent(client)}`)}>
            ← {client}
          </button>
        </div>
      </div>

      <form className="scan-form scan-form--inline" onSubmit={handleSearch}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={t('subdomínio, IP ou URL exata')}
        />
        <button type="submit">{t('Buscar')}</button>
      </form>

      {!value && <div className="empty-state">{t('Digite um valor pra ver tudo que as ferramentas acharam sobre ele.')}</div>}
      {loading && <div className="empty-state">{t('Carregando…')}</div>}
      {error && <div className="empty-state empty-state--error">{error}</div>}
      {value && !loading && !error && suffixes.length === 0 && (
        <div className="empty-state">{t('Nada encontrado para "{{value}}".', { value })}</div>
      )}

      {suffixes.map((suffix) => (
        <section key={suffix}>
          <div className="section-header">
            <h2>{t(suffixLabel(suffix))} ({result[suffix].length})</h2>
            <button
              type="button"
              className="link-button"
              onClick={() => navigate(`/clients/${encodeURIComponent(client)}/${suffix}`)}
            >
              {t('ver tabela completa')}
            </button>
          </div>
          <DataTable columns={columnsFor(suffix)} rows={result[suffix]} loading={false} client={client} />
        </section>
      ))}
    </div>
  )
}
