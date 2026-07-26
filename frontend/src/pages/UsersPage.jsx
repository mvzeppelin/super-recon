import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { getUser } from '../auth.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

const ROLES = ['admin', 'operator', 'viewer']
const ROLE_LABELS = { admin: 'Administrador', operator: 'Operador', viewer: 'Leitor' }

export default function UsersPage() {
  const { t, lang } = useTranslation()
  const locale = lang === 'en' ? 'en-US' : 'pt-BR'
  const me = getUser()

  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('viewer')
  const [submitting, setSubmitting] = useState(false)
  const [resettingUserId, setResettingUserId] = useState(null)
  const [resetPassword, setResetPassword] = useState('')

  function load() {
    setLoading(true)
    api
      .listUsers()
      .then(setUsers)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    if (me?.role === 'admin') load()
  }, [])

  if (me?.role !== 'admin') {
    return (
      <div className="page">
        <div className="empty-state empty-state--error">{t('Você não tem permissão pra ver esta página.')}</div>
      </div>
    )
  }

  async function handleCreate(e) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await api.createUser(newUsername.trim(), newPassword, newRole)
      setNewUsername('')
      setNewPassword('')
      setNewRole('viewer')
      load()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  async function handleRoleChange(user, role) {
    try {
      await api.updateUser(user.user_id, { role })
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleToggleDisabled(user) {
    try {
      await api.updateUser(user.user_id, { disabled: !user.disabled })
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleResetPassword(userId) {
    if (resetPassword.length < 8) return
    try {
      await api.resetUserPassword(userId, resetPassword)
      setResettingUserId(null)
      setResetPassword('')
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleDelete(user) {
    if (!window.confirm(t('Excluir o usuário "{{username}}"? Essa ação não pode ser desfeita.', { username: user.username })))
      return
    try {
      await api.deleteUser(user.user_id)
      load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1>{t('Usuários ({{total}})', { total: users.length })}</h1>
      </div>

      <section className="card">
        <h2>{t('Novo usuário')}</h2>
        <form className="scan-form scan-form--inline" onSubmit={handleCreate}>
          <input
            type="text"
            placeholder={t('usuário')}
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder={t('senha (mín. 8 caracteres)')}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            minLength={8}
            required
          />
          <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
            {ROLES.map((role) => (
              <option key={role} value={role}>
                {t(ROLE_LABELS[role])}
              </option>
            ))}
          </select>
          <button type="submit" disabled={submitting}>
            {submitting ? t('Criando…') : t('Criar usuário')}
          </button>
        </form>
      </section>

      {error && <div className="empty-state empty-state--error">{error}</div>}
      {loading && <div className="empty-state">{t('Carregando…')}</div>}

      {!loading && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('Usuário')}</th>
                <th>{t('Papel')}</th>
                <th>{t('Status')}</th>
                <th>{t('Criado em')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.user_id}>
                  <td>{u.username}</td>
                  <td>
                    <select value={u.role} onChange={(e) => handleRoleChange(u, e.target.value)}>
                      {ROLES.map((role) => (
                        <option key={role} value={role}>
                          {t(ROLE_LABELS[role])}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <button type="button" className="link-button" onClick={() => handleToggleDisabled(u)}>
                      {u.disabled ? t('desativado — ativar') : t('ativo — desativar')}
                    </button>
                  </td>
                  <td>{new Date(u.created_at).toLocaleString(locale)}</td>
                  <td>
                    {resettingUserId === u.user_id ? (
                      <span className="custom-wordlist-picker">
                        <input
                          type="password"
                          placeholder={t('nova senha')}
                          value={resetPassword}
                          onChange={(e) => setResetPassword(e.target.value)}
                          minLength={8}
                          autoFocus
                        />
                        <button type="button" onClick={() => handleResetPassword(u.user_id)} disabled={resetPassword.length < 8}>
                          {t('confirmar')}
                        </button>
                        <button
                          type="button"
                          className="link-button"
                          onClick={() => {
                            setResettingUserId(null)
                            setResetPassword('')
                          }}
                        >
                          {t('cancelar')}
                        </button>
                      </span>
                    ) : (
                      <span className="user-row__actions">
                        <button type="button" className="link-button" onClick={() => setResettingUserId(u.user_id)}>
                          {t('resetar senha')}
                        </button>
                        {u.username !== me.username && (
                          <button type="button" className="link-button link-button--danger" onClick={() => handleDelete(u)}>
                            {t('excluir')}
                          </button>
                        )}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
