import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { clearSession, getSession, setSession } from '../auth.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

export default function LoginGate({ children }) {
  const { t } = useTranslation()
  const [status, setStatus] = useState('checking') // checking | ok | needed
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    // Sessão salva de uma visita anterior pode ter expirado ou sido
    // revogada (usuário desativado/excluído) — confirma com o backend antes
    // de confiar nela, em vez de só checar se existe no localStorage.
    if (!getSession()) {
      setStatus('needed')
      return
    }
    api
      .getMe()
      .then(() => setStatus('ok'))
      .catch(() => {
        clearSession()
        setStatus('needed')
      })
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const { token, username: loggedUsername, role, must_change_password: mustChangePassword } = await api.login(username.trim(), password)
      setSession({ token, username: loggedUsername, role, mustChangePassword })
      setStatus('ok')
    } catch (err) {
      setError(err.message || t('Usuário ou senha inválidos.'))
    } finally {
      setSubmitting(false)
    }
  }

  if (status === 'checking') return <div className="empty-state">{t('Carregando…')}</div>
  if (status === 'ok') return children

  return (
    <div className="login-gate">
      <form className="login-gate__form" onSubmit={handleSubmit}>
        <h1>super-recon</h1>
        <label>
          {t('Usuário')}
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus required />
        </label>
        <label>
          {t('Senha')}
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <div className="empty-state empty-state--error">{error}</div>}
        <button type="submit" disabled={submitting || !username.trim() || !password}>
          {submitting ? t('Verificando…') : t('Entrar')}
        </button>
      </form>
    </div>
  )
}
