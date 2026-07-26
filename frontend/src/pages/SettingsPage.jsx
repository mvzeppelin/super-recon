import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { getUser } from '../auth.js'
import Tabs from '../components/Tabs.jsx'
import { useTranslation } from '../i18n/LanguageContext.jsx'
import { SETTINGS_GROUPS, SETTINGS_META } from '../settingsMeta.js'

// Valor de edição local por campo — string pra int/str/csv_set (facilita o
// <input>, convertido de volta no save), booleano pra bool, sempre vazio
// pra secret (write-only: em branco no PUT = "não mexer", ver README
// "Configurações" — evita ecoar o segredo de volta do backend a cada load).
function draftValueFor(entry) {
  if (entry.secret) return ''
  if (entry.type === 'bool') return entry.value
  if (entry.type === 'int') return String(entry.value)
  if (entry.type === 'csv_set') return entry.value.join(', ')
  return entry.value
}

function draftsFromFields(list) {
  const drafts = {}
  for (const entry of list) drafts[entry.key] = draftValueFor(entry)
  return drafts
}

export default function SettingsPage() {
  const { t } = useTranslation()
  const me = getUser()

  const [fields, setFields] = useState([])
  const [drafts, setDrafts] = useState({})
  const [group, setGroup] = useState(SETTINGS_GROUPS[0].id)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const [savedGroup, setSavedGroup] = useState(null)

  function load() {
    setLoading(true)
    api
      .getSettings()
      .then((data) => {
        setFields(data)
        setDrafts(draftsFromFields(data))
      })
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

  function updateDraft(key, value) {
    setDrafts((prev) => ({ ...prev, [key]: value }))
  }

  function overridesForGroup(groupId) {
    const overrides = {}
    for (const entry of fields.filter((f) => f.group === groupId)) {
      const draft = drafts[entry.key]
      if (entry.secret) {
        if (typeof draft === 'string' && draft.trim() !== '') overrides[entry.key] = draft.trim()
        continue
      }
      if (entry.type === 'bool') overrides[entry.key] = Boolean(draft)
      else if (entry.type === 'int') overrides[entry.key] = Number(draft)
      else if (entry.type === 'csv_set') {
        overrides[entry.key] = String(draft)
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      } else overrides[entry.key] = draft
    }
    return overrides
  }

  async function handleSaveGroup(groupId) {
    setSaving(true)
    setError(null)
    setSavedGroup(null)
    try {
      const updated = await api.updateSettings(overridesForGroup(groupId))
      setFields(updated)
      setDrafts((prev) => ({ ...prev, ...draftsFromFields(updated.filter((f) => f.group === groupId)) }))
      setSavedGroup(groupId)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  async function handleResetField(key) {
    setError(null)
    try {
      const updated = await api.updateSettings({ [key]: null })
      setFields(updated)
      const resetEntry = updated.find((f) => f.key === key)
      setDrafts((prev) => ({ ...prev, [key]: draftValueFor(resetEntry) }))
    } catch (err) {
      setError(err.message)
    }
  }

  const groupsWithFields = SETTINGS_GROUPS.map((g) => ({
    ...g,
    label: t(g.label),
    fields: fields.filter((f) => f.group === g.id),
  }))
  const activeGroup = groupsWithFields.find((g) => g.id === group) || groupsWithFields[0]

  return (
    <div className="page">
      <div className="page-header">
        <h1>{t('Configurações')}</h1>
      </div>

      {error && <div className="empty-state empty-state--error">{error}</div>}
      {loading && <div className="empty-state">{t('Carregando…')}</div>}

      {!loading && (
        <>
          <Tabs
            tabs={groupsWithFields.map((g) => ({ id: g.id, label: g.label }))}
            active={activeGroup?.id}
            onChange={(id) => {
              setGroup(id)
              setSavedGroup(null)
            }}
          />

          <section className="card">
            {activeGroup?.fields.map((entry) => {
              const meta = SETTINGS_META[entry.key] || { label: entry.key, tip: '' }
              return (
                <div key={entry.key} className="settings-field">
                  <label className="settings-field__label">{t(meta.label)}</label>
                  <div className="settings-field__control">
                    {entry.type === 'bool' && (
                      <input
                        type="checkbox"
                        checked={Boolean(drafts[entry.key])}
                        onChange={(e) => updateDraft(entry.key, e.target.checked)}
                      />
                    )}
                    {entry.type === 'int' && (
                      <input
                        type="number"
                        value={drafts[entry.key] ?? ''}
                        onChange={(e) => updateDraft(entry.key, e.target.value)}
                      />
                    )}
                    {(entry.type === 'str' || entry.type === 'csv_set') && !entry.secret && (
                      <input
                        type="text"
                        value={drafts[entry.key] ?? ''}
                        onChange={(e) => updateDraft(entry.key, e.target.value)}
                      />
                    )}
                    {entry.secret && (
                      <input
                        type="password"
                        value={drafts[entry.key] ?? ''}
                        placeholder={entry.is_set ? t('•••• (definido — deixe em branco pra não mexer)') : t('(não definido)')}
                        onChange={(e) => updateDraft(entry.key, e.target.value)}
                      />
                    )}
                    {entry.overridden && (
                      <button type="button" className="link-button" onClick={() => handleResetField(entry.key)}>
                        {t('restaurar padrão')}
                      </button>
                    )}
                  </div>
                  <p className="settings-field__tip">{t(meta.tip)}</p>
                </div>
              )
            })}

            <div className="settings-field__actions">
              <button type="button" disabled={saving} onClick={() => handleSaveGroup(activeGroup?.id)}>
                {saving ? t('Salvando…') : t('Salvar')}
              </button>
              {savedGroup === activeGroup?.id && <span className="settings-field__saved">{t('Salvo com sucesso.')}</span>}
            </div>
          </section>
        </>
      )}
    </div>
  )
}
