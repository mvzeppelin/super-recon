import { useState } from 'react'
import { api } from '../api.js'
import { clearMustChangePassword, getUser } from '../auth.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

const ROLE_LABELS = { admin: 'Administrador', operator: 'Operador', viewer: 'Leitor' }

export default function MyAccountPage() {
  const { t } = useTranslation()
  const user = getUser()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setSuccess(false)
    if (newPassword !== confirmPassword) {
      setError(t('A confirmação não bate com a nova senha.'))
      return
    }
    setSubmitting(true)
    try {
      await api.changePassword(currentPassword, newPassword)
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setSuccess(true)
      clearMustChangePassword()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1>{t('Minha conta')}</h1>
      </div>

      <section className="card">
        <h2>{t('Usuário')}</h2>
        <p>
          <strong>{user?.username}</strong> — {t(ROLE_LABELS[user?.role] || user?.role)}
        </p>
      </section>

      <section className="card">
        <h2>{t('Trocar minha senha')}</h2>
        <form className="scan-form" onSubmit={handleSubmit}>
          <label>
            {t('Senha atual')}
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </label>
          <label>
            {t('Nova senha')}
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              minLength={8}
              required
            />
          </label>
          <label>
            {t('Confirmar nova senha')}
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              minLength={8}
              required
            />
          </label>
          {error && <div className="empty-state empty-state--error">{error}</div>}
          {success && <div className="empty-state">{t('Senha alterada com sucesso.')}</div>}
          <button type="submit" disabled={submitting}>
            {submitting ? t('Salvando…') : t('Salvar')}
          </button>
        </form>
      </section>
    </div>
  )
}
