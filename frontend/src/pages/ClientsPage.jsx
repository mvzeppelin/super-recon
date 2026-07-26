import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import WordlistSelector from '../components/WordlistSelector.jsx'
import { getUser } from '../auth.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

export default function ClientsPage() {
  const { t } = useTranslation()
  const role = getUser()?.role
  const canOperate = role === 'admin' || role === 'operator'
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const [clientName, setClientName] = useState('')
  const [targets, setTargets] = useState('')
  const [gobusterWordlist, setGobusterWordlist] = useState('common')
  const [customWordlistId, setCustomWordlistId] = useState('')
  const [wordlists, setWordlists] = useState([])
  const [uploadFile, setUploadFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    api
      .listClients()
      .then(setClients)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  // wordlists já enviadas para esse nome de cliente — funciona mesmo antes do
  // primeiro scan, já que o índice de metadados é criado no primeiro upload,
  // não exige o cliente "existir" ainda. Com debounce pra não bater na API a
  // cada tecla digitada.
  useEffect(() => {
    const name = clientName.trim()
    setCustomWordlistId('') // nome mudou — a wordlist marcada era de outro cliente
    if (!name) {
      setWordlists([])
      return
    }
    const timer = setTimeout(() => {
      api
        .listWordlists(name)
        .then(setWordlists)
        .catch(() => setWordlists([]))
    }, 300)
    return () => clearTimeout(timer)
  }, [clientName])

  async function handleDelete(name) {
    if (!window.confirm(t('Excluir todos os dados de "{{name}}"? Essa ação não pode ser desfeita.', { name }))) return
    try {
      await api.deleteClient(name)
      setClients((prev) => prev.filter((c) => c !== name))
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    const targetList = targets
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
    if (!clientName.trim() || !targetList.length) return
    if (gobusterWordlist === 'custom' && !customWordlistId) return

    setSubmitting(true)
    try {
      await api.createScan(
        clientName.trim(), targetList, gobusterWordlist, gobusterWordlist === 'custom' ? customWordlistId : null,
      )
      navigate(`/clients/${encodeURIComponent(clientName.trim())}`)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  async function handleUploadWordlist(e) {
    e.preventDefault()
    const name = clientName.trim()
    if (!uploadFile || !name) return
    setUploading(true)
    setError(null)
    try {
      const doc = await api.uploadWordlist(name, uploadFile)
      setUploadFile(null)
      setCustomWordlistId(doc.wordlist_id)
      const list = await api.listWordlists(name)
      setWordlists(list)
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="page">
      {canOperate && (
      <section className="card">
        <h2>{t('Novo recon')}</h2>
        <form className="scan-form" onSubmit={handleSubmit}>
          <label>
            {t('Cliente')}
            <input value={clientName} onChange={(e) => setClientName(e.target.value)} placeholder="acme-corp" required />
          </label>
          <label>
            {t('Domínios / IPs (um por linha)')}
            <textarea
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder={'acme.com\n192.168.1.10'}
              rows={4}
              required
            />
          </label>
          <WordlistSelector
            value={gobusterWordlist}
            onChange={setGobusterWordlist}
            customWordlistId={customWordlistId}
            onCustomWordlistIdChange={setCustomWordlistId}
            wordlists={wordlists}
            uploadFile={uploadFile}
            onUploadFileChange={setUploadFile}
            onUpload={handleUploadWordlist}
            uploading={uploading}
            disabledReason={!clientName.trim() ? t('Preencha o nome do cliente acima para enviar/selecionar uma wordlist.') : null}
          />
          <button
            type="submit"
            disabled={submitting || (gobusterWordlist === 'custom' && !customWordlistId)}
          >
            {submitting ? t('Disparando…') : t('Iniciar recon')}
          </button>
        </form>
      </section>
      )}

      <section className="card">
        <h2>{t('Clientes')}</h2>
        {loading && <div className="empty-state">{t('Carregando…')}</div>}
        {error && <div className="empty-state empty-state--error">{error}</div>}
        {!loading && !clients.length && <div className="empty-state">{t('Nenhum cliente com dados ainda.')}</div>}
        <div className="client-grid">
          {clients.map((c) => (
            <div key={c} className="client-card">
              <Link to={`/clients/${encodeURIComponent(c)}`} className="client-card__link">
                {c}
              </Link>
              {role === 'admin' && (
                <button
                  type="button"
                  className="client-card__delete"
                  title={t('Excluir {{name}}', { name: c })}
                  onClick={() => handleDelete(c)}
                >
                  ×
                </button>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
