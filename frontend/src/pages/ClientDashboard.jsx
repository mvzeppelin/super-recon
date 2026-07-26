import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import ExportButtons from '../components/ExportButtons.jsx'
import FindingsByToolChart from '../components/FindingsByToolChart.jsx'
import RiskScoreCard from '../components/RiskScoreCard.jsx'
import StatTile from '../components/StatTile.jsx'
import Tabs from '../components/Tabs.jsx'
import ToolChecklist from '../components/ToolChecklist.jsx'
import WordlistSelector from '../components/WordlistSelector.jsx'
import { getUser } from '../auth.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'
import { suffixLabel } from '../toolSchemas.js'

const DEFAULT_TAB = 'overview'

const REFRESH_MS = 4000

const EMPTY_SUMMARY = { total: 0, ok: 0, error: 0, cancelled: 0, running: 0, queued: 0 }

// suffix "jobs" tem seu próprio quadro (execuções) — não entra na grade de achados
const EXCLUDED_FROM_FINDINGS = new Set(['jobs', 'scans', 'wordlists', 'scan-schedules'])

const WEEKDAY_LABELS = [
  'Segunda-feira', 'Terça-feira', 'Quarta-feira', 'Quinta-feira', 'Sexta-feira', 'Sábado', 'Domingo',
]

function formatDuration(seconds) {
  const total = Math.floor(seconds)
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (h > 0) return `${h}h${String(m).padStart(2, '0')}m`
  if (m > 0) return `${m}m${String(s).padStart(2, '0')}s`
  return `${s}s`
}

const EMPTY_RECURRING_FORM = {
  targets: '',
  gobusterWordlist: 'common',
  customWordlistId: '',
  // null = usa o default resolvido a cada disparo (ver GET /scan-defaults),
  // não fixado na criação do alvo salvo — lista explícita só depois que o
  // usuário mexer no checklist.
  enabledTools: null,
  enabled: false,
  periodicity: 'daily',
  weekday: 0,
  dayOfMonth: 1,
  runTime: '09:00',
}

export default function ClientDashboard() {
  const { t, lang } = useTranslation()
  const locale = lang === 'en' ? 'en-US' : 'pt-BR'
  const role = getUser()?.role
  const isAdmin = role === 'admin'
  const canOperate = isAdmin || role === 'operator'
  const { client } = useParams()
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = searchParams.get('tab') || DEFAULT_TAB
  function setTab(id) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (id === DEFAULT_TAB) next.delete('tab')
      else next.set('tab', id)
      return next
    })
  }
  const [indices, setIndices] = useState([])
  const [summary, setSummary] = useState(EMPTY_SUMMARY)
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [targets, setTargets] = useState('')
  // { tools, enabled_by_default } — mesmo pro cliente inteiro, não muda com
  // targets/scan; buscado uma vez só (ver efeito abaixo), independente do
  // efeito de load() por cliente.
  const [scanDefaults, setScanDefaults] = useState({ tools: [], enabled_by_default: [] })
  // null = ainda não mexeu no checklist -> usa scanDefaults.enabled_by_default
  // na hora de renderizar/enviar (ver <ToolChecklist> abaixo e handleNewScan).
  const [enabledTools, setEnabledTools] = useState(null)
  const [gobusterWordlist, setGobusterWordlist] = useState('common')
  const [customWordlistId, setCustomWordlistId] = useState('')
  const [wordlists, setWordlists] = useState([])
  const [uploadFile, setUploadFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [selectedScans, setSelectedScans] = useState(new Set())
  const [recurringScans, setRecurringScans] = useState([])
  const [recurringForm, setRecurringForm] = useState(EMPTY_RECURRING_FORM)
  const [editingScheduleId, setEditingScheduleId] = useState(null)
  const [recurringSubmitting, setRecurringSubmitting] = useState(false)
  const navigate = useNavigate()

  function load({ showLoading = false } = {}) {
    if (showLoading) setLoading(true)
    // client sem nenhum índice de achados ainda (ex: scan recém-disparado,
    // só a fase 1 gravou jobs) não é erro — só uma lista vazia.
    const indicesPromise = api.listClientIndices(client).catch(() => [])
    const summaryPromise = api.getJobsSummary(client).catch(() => EMPTY_SUMMARY)
    const scansPromise = api.listScans(client).catch(() => [])
    const wordlistsPromise = api.listWordlists(client).catch(() => [])
    const recurringPromise = api.listRecurringScans(client).catch(() => [])
    return Promise.all([indicesPromise, summaryPromise, scansPromise, wordlistsPromise, recurringPromise])
      .then(([indicesData, summaryData, scansData, wordlistsData, recurringData]) => {
        setIndices(indicesData)
        setSummary(summaryData)
        setScans(scansData)
        setWordlists(wordlistsData)
        setRecurringScans(recurringData)
        setError(null)
      })
      .finally(() => {
        if (showLoading) setLoading(false)
      })
  }

  // Recarrega os dados sozinho, sem precisar de F5 — útil para acompanhar um
  // scan em andamento vendo os tiles subirem em tempo real.
  useEffect(() => {
    load({ showLoading: true })
    const id = setInterval(() => load(), REFRESH_MS)
    return () => clearInterval(id)
  }, [client])

  // Ferramentas da Fase 4 + quais entram marcadas por padrão — não muda por
  // cliente, busca uma vez só.
  useEffect(() => {
    api.getScanDefaults().then(setScanDefaults).catch(() => {})
  }, [])

  async function handleDeleteClient() {
    if (!window.confirm(t('Excluir todos os dados de "{{name}}"? Essa ação não pode ser desfeita.', { name: client }))) return
    try {
      await api.deleteClient(client)
      navigate('/')
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleClearData() {
    if (
      !window.confirm(
        t(
          'Limpar todos os dados de "{{client}}"? O cliente continua existindo, mas achados e histórico de execuções serão apagados (como se fosse recém-criado). Essa ação não pode ser desfeita.',
          { client },
        ),
      )
    )
      return
    try {
      await api.clearClientData(client)
      load({ showLoading: true })
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleCancelAll() {
    if (!window.confirm(t('Cancelar todas as execuções em andamento de "{{client}}"?', { client }))) return
    try {
      const { cancelled } = await api.cancelAllJobs(client)
      if (!cancelled.length) {
        window.alert(t('Nenhuma execução em andamento para esse cliente.'))
      }
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleNewScan(e) {
    e.preventDefault()
    const targetList = targets
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
    if (!targetList.length) return
    if (gobusterWordlist === 'custom' && !customWordlistId) return

    setSubmitting(true)
    try {
      await api.createScan(
        client, targetList, gobusterWordlist, gobusterWordlist === 'custom' ? customWordlistId : null, enabledTools,
      )
      setTargets('')
      setEnabledTools(null)
      setTimeout(load, 2000)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  async function handleUploadWordlist(e) {
    e.preventDefault()
    if (!uploadFile) return
    setUploading(true)
    setError(null)
    try {
      const doc = await api.uploadWordlist(client, uploadFile)
      setUploadFile(null)
      setCustomWordlistId(doc.wordlist_id)
      load({ showLoading: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
    }
  }

  async function handleDeleteWordlist(wordlistId) {
    if (
      !window.confirm(
        t(
          'Excluir esta wordlist? Se algum scan em andamento ainda for usá-la no gobuster, ele cai para o perfil "common" em vez de falhar.',
        ),
      )
    )
      return
    try {
      await api.deleteWordlist(client, wordlistId)
      if (customWordlistId === wordlistId) setCustomWordlistId('')
      load({ showLoading: true })
    } catch (err) {
      setError(err.message)
    }
  }

  function recurringFormToBody(form) {
    return {
      targets: form.targets.split('\n').map((line) => line.trim()).filter(Boolean),
      gobuster_wordlist: form.gobusterWordlist,
      gobuster_custom_wordlist_id: form.gobusterWordlist === 'custom' ? form.customWordlistId : null,
      enabled_tools: form.enabledTools,
      enabled: form.enabled,
      periodicity: form.enabled ? form.periodicity : null,
      run_time: form.enabled ? form.runTime : null,
      weekday: form.enabled && form.periodicity === 'weekly' ? Number(form.weekday) : null,
      day_of_month: form.enabled && form.periodicity === 'monthly' ? Number(form.dayOfMonth) : null,
    }
  }

  function resetRecurringForm() {
    setRecurringForm(EMPTY_RECURRING_FORM)
    setEditingScheduleId(null)
  }

  async function handleRecurringSubmit(e) {
    e.preventDefault()
    const body = recurringFormToBody(recurringForm)
    if (!body.targets.length) return
    if (recurringForm.gobusterWordlist === 'custom' && !recurringForm.customWordlistId) return

    setRecurringSubmitting(true)
    setError(null)
    try {
      if (editingScheduleId) {
        await api.updateRecurringScan(client, editingScheduleId, body)
      } else {
        await api.createRecurringScan(client, body)
      }
      resetRecurringForm()
      load({ showLoading: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setRecurringSubmitting(false)
    }
  }

  function handleEditRecurring(sched) {
    setEditingScheduleId(sched.schedule_id)
    setRecurringForm({
      targets: (sched.targets || []).join('\n'),
      gobusterWordlist: sched.gobuster_wordlist,
      customWordlistId: sched.gobuster_custom_wordlist_id || '',
      enabledTools: sched.enabled_tools ?? null,
      enabled: sched.enabled,
      periodicity: sched.periodicity || 'daily',
      weekday: sched.weekday ?? 0,
      dayOfMonth: sched.day_of_month ?? 1,
      runTime: sched.run_time || '09:00',
    })
  }

  async function handleToggleRecurringEnabled(sched) {
    setError(null)
    try {
      await api.updateRecurringScan(client, sched.schedule_id, {
        targets: sched.targets,
        gobuster_wordlist: sched.gobuster_wordlist,
        gobuster_custom_wordlist_id: sched.gobuster_custom_wordlist_id,
        enabled: !sched.enabled,
        periodicity: sched.periodicity,
        run_time: sched.run_time,
        weekday: sched.weekday,
        day_of_month: sched.day_of_month,
      })
      load({ showLoading: true })
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleDeleteRecurring(scheduleId) {
    if (!window.confirm(t('Excluir este alvo salvo? A recorrência automática (se ativa) para de disparar. Essa ação não pode ser desfeita.')))
      return
    try {
      await api.deleteRecurringScan(client, scheduleId)
      if (editingScheduleId === scheduleId) resetRecurringForm()
      load({ showLoading: true })
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleRunRecurringNow(scheduleId) {
    try {
      await api.runRecurringScanNow(client, scheduleId)
      setTimeout(load, 2000)
    } catch (err) {
      setError(err.message)
    }
  }

  function formatPeriodicity(sched) {
    if (sched.periodicity === 'daily') return t('Diário')
    if (sched.periodicity === 'weekly') return t('Toda {{weekday}}', { weekday: t(WEEKDAY_LABELS[sched.weekday]) })
    if (sched.periodicity === 'monthly') return t('Dia {{day}} do mês', { day: sched.day_of_month })
    return t('Não configurado')
  }

  const findingsIndices = indices.filter((i) => !EXCLUDED_FROM_FINDINGS.has(i.suffix))
  const findingsTotal = findingsIndices.reduce((acc, i) => acc + i.doc_count, 0)

  function goToJobs(status) {
    const qs = status ? `?status=${encodeURIComponent(status)}` : ''
    navigate(`/clients/${encodeURIComponent(client)}/jobs${qs}`)
  }

  function goToScanJobs(scanId) {
    navigate(`/clients/${encodeURIComponent(client)}/jobs?scan_id=${encodeURIComponent(scanId)}`)
  }

  function goToCompare(fromId, toId) {
    navigate(`/clients/${encodeURIComponent(client)}/compare?from=${encodeURIComponent(fromId)}&to=${encodeURIComponent(toId)}`)
  }

  function toggleScanSelection(scanId) {
    setSelectedScans((prev) => {
      const next = new Set(prev)
      if (next.has(scanId)) next.delete(scanId)
      else next.add(scanId)
      return next
    })
  }

  function handleCompareSelected() {
    const [a, b] = [...selectedScans]
    const scanA = scans.find((s) => s.scan_id === a)
    const scanB = scans.find((s) => s.scan_id === b)
    if (!scanA || !scanB) return
    // "from" é sempre o mais antigo dos dois, independente da ordem em que
    // foram marcados — comparar sempre no sentido cronológico.
    const [older, newer] = scanA['@timestamp'] <= scanB['@timestamp'] ? [scanA, scanB] : [scanB, scanA]
    goToCompare(older.scan_id, newer.scan_id)
  }

  async function handleDeleteScan() {
    const [scanId] = [...selectedScans]
    if (!scanId) return
    if (
      !window.confirm(
        t('Excluir este scan? Todos os achados e execuções desse scan serão apagados. Essa ação não pode ser desfeita.'),
      )
    )
      return
    try {
      await api.deleteScan(client, scanId)
      setSelectedScans(new Set())
      load({ showLoading: true })
    } catch (err) {
      setError(err.message)
    }
  }

  const TABS = [
    { id: 'overview', label: t('Visão geral') },
    { id: 'scans', label: t('Scans') },
    { id: 'wordlists', label: t('Wordlists') },
    { id: 'recurring', label: t('Recorrência') },
  ]

  return (
    <div className="page">
      <div className="page-header">
        <h1>{client}</h1>
        <div className="page-header__actions">
          {canOperate && (
            <button className="action-pill action-pill--warning" onClick={handleCancelAll}>
              {t('■ cancelar scans em andamento')}
            </button>
          )}
          {isAdmin && (
            <button className="action-pill action-pill--info" onClick={handleClearData}>
              {t('↺ limpar dados')}
            </button>
          )}
          {isAdmin && (
            <button className="action-pill action-pill--critical" onClick={handleDeleteClient}>
              {t('⚠ excluir cliente')}
            </button>
          )}
          <span className="page-header__divider" />
          <button className="link-button" onClick={() => navigate('/')}>
            {t('← clientes')}
          </button>
        </div>
      </div>

      <Tabs tabs={TABS} active={tab} onChange={setTab} />

      {tab === 'overview' && canOperate && (
        <section className="card">
          <h2>{t('Novo recon para {{client}}', { client })}</h2>
          <form className="scan-form scan-form--inline" onSubmit={handleNewScan}>
            <textarea
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder={'novo-dominio.com\n1.2.3.4'}
              rows={3}
            />
            <WordlistSelector
              showLabel={false}
              value={gobusterWordlist}
              onChange={setGobusterWordlist}
              customWordlistId={customWordlistId}
              onCustomWordlistIdChange={setCustomWordlistId}
              wordlists={wordlists}
              uploadFile={uploadFile}
              onUploadFileChange={setUploadFile}
              onUpload={handleUploadWordlist}
              uploading={uploading}
            />
            <div>
              <label>{t('Ferramentas (Fase 4)')}</label>
              <ToolChecklist
                value={enabledTools ?? scanDefaults.enabled_by_default}
                onChange={setEnabledTools}
                tools={scanDefaults.tools}
              />
            </div>
            <button type="submit" disabled={submitting || (gobusterWordlist === 'custom' && !customWordlistId)}>
              {submitting ? t('Disparando…') : t('Rodar recon')}
            </button>
          </form>
        </section>
      )}

      {loading && <div className="empty-state">{t('Carregando…')}</div>}
      {error && <div className="empty-state empty-state--error">{error}</div>}

      {!loading && !error && (
        <>
          {tab === 'scans' && (
            <section>
              <div className="section-header">
                <h2>{t('Scans ({{total}})', { total: scans.length })}</h2>
                {selectedScans.size === 1 && canOperate && (
                  <button type="button" className="action-pill action-pill--critical" onClick={handleDeleteScan}>
                    {t('excluir scan selecionado')}
                  </button>
                )}
                {selectedScans.size === 2 && (
                  <button type="button" className="action-pill action-pill--info" onClick={handleCompareSelected}>
                    {t('comparar selecionados')}
                  </button>
                )}
              </div>
              {scans.length === 0 && <div className="empty-state">{t('Nenhum scan registrado ainda.')}</div>}
              {scans.length > 0 && (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th className="data-table__checkbox-col"></th>
                        <th>{t('Quando')}</th>
                        <th>{t('Alvos')}</th>
                        <th>{t('Wordlist')}</th>
                        <th>{t('Ferramentas')}</th>
                        <th>{t('Duração')}</th>
                        <th></th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map((s, i) => (
                        <tr key={s.scan_id}>
                          <td className="data-table__checkbox-col">
                            <input
                              type="checkbox"
                              checked={selectedScans.has(s.scan_id)}
                              disabled={!selectedScans.has(s.scan_id) && selectedScans.size >= 2}
                              onChange={() => toggleScanSelection(s.scan_id)}
                              aria-label={t('Selecionar linha')}
                            />
                          </td>
                          <td>{new Date(s['@timestamp']).toLocaleString(locale)}</td>
                          <td>{(s.targets || []).join(', ')}</td>
                          <td>{s.gobuster_wordlist}</td>
                          <td title={(s.enabled_tools || []).join(', ')}>
                            {s.enabled_tools ? t('{{count}}/8', { count: s.enabled_tools.length }) : '–'}
                          </td>
                          <td>{s.duration_seconds != null ? formatDuration(s.duration_seconds) : t('em andamento')}</td>
                          <td>
                            <button type="button" className="link-button" onClick={() => goToScanJobs(s.scan_id)}>
                              {t('ver execuções')}
                            </button>
                          </td>
                          <td>
                            {i < scans.length - 1 && (
                              <button
                                type="button"
                                className="link-button"
                                onClick={() => goToCompare(scans[i + 1].scan_id, s.scan_id)}
                              >
                                {t('ver mudanças desde a anterior')}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {tab === 'wordlists' && (
            <section>
              <h2>{t('Wordlists customizadas ({{total}})', { total: wordlists.length })}</h2>
              {wordlists.length === 0 && <div className="empty-state">{t('Nenhuma wordlist enviada ainda.')}</div>}
              {wordlists.length > 0 && (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>{t('Arquivo')}</th>
                        <th>{t('Linhas')}</th>
                        <th>{t('Tamanho (bytes)')}</th>
                        <th>{t('Quando')}</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {wordlists.map((w) => (
                        <tr key={w.wordlist_id}>
                          <td>{w.filename}</td>
                          <td>{w.line_count}</td>
                          <td>{w.size_bytes}</td>
                          <td>{new Date(w['@timestamp']).toLocaleString(locale)}</td>
                          <td>
                            {canOperate && (
                              <button
                                type="button"
                                className="worker-status__cancel"
                                onClick={() => handleDeleteWordlist(w.wordlist_id)}
                              >
                                {t('excluir')}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {tab === 'recurring' && (
            <>
              {canOperate && (
              <section className="card">
                <h2>{editingScheduleId ? t('Editar alvo salvo') : t('Novo alvo salvo / recorrência')}</h2>
                <form className="scan-form" onSubmit={handleRecurringSubmit}>
                  <label>
                    {t('Domínios / IPs (um por linha)')}
                    <textarea
                      value={recurringForm.targets}
                      onChange={(e) => setRecurringForm((f) => ({ ...f, targets: e.target.value }))}
                      placeholder={'acme.com\n192.168.1.10'}
                      rows={3}
                      required
                    />
                  </label>
                  <WordlistSelector
                    showUpload={false}
                    value={recurringForm.gobusterWordlist}
                    onChange={(v) => setRecurringForm((f) => ({ ...f, gobusterWordlist: v }))}
                    customWordlistId={recurringForm.customWordlistId}
                    onCustomWordlistIdChange={(v) => setRecurringForm((f) => ({ ...f, customWordlistId: v }))}
                    wordlists={wordlists}
                  />

                  <div>
                    <label>{t('Ferramentas (Fase 4)')}</label>
                    <ToolChecklist
                      value={recurringForm.enabledTools ?? scanDefaults.enabled_by_default}
                      onChange={(v) => setRecurringForm((f) => ({ ...f, enabledTools: v }))}
                      tools={scanDefaults.tools}
                    />
                  </div>

                  <label className="recurring-form__checkbox">
                    <input
                      type="checkbox"
                      checked={recurringForm.enabled}
                      onChange={(e) => setRecurringForm((f) => ({ ...f, enabled: e.target.checked }))}
                    />
                    {t('Ativar recorrência automática')}
                  </label>

                  {recurringForm.enabled && (
                    <div className="recurring-form__row">
                      <label>
                        {t('Periodicidade')}
                        <select
                          value={recurringForm.periodicity}
                          onChange={(e) => setRecurringForm((f) => ({ ...f, periodicity: e.target.value }))}
                        >
                          <option value="daily">{t('Diário')}</option>
                          <option value="weekly">{t('Semanal')}</option>
                          <option value="monthly">{t('Mensal')}</option>
                        </select>
                      </label>

                      {recurringForm.periodicity === 'weekly' && (
                        <label>
                          {t('Dia da semana')}
                          <select
                            value={recurringForm.weekday}
                            onChange={(e) => setRecurringForm((f) => ({ ...f, weekday: e.target.value }))}
                          >
                            {WEEKDAY_LABELS.map((label, idx) => (
                              <option key={label} value={idx}>
                                {t(label)}
                              </option>
                            ))}
                          </select>
                        </label>
                      )}

                      {recurringForm.periodicity === 'monthly' && (
                        <label>
                          {t('Dia do mês')}
                          <select
                            value={recurringForm.dayOfMonth}
                            onChange={(e) => setRecurringForm((f) => ({ ...f, dayOfMonth: e.target.value }))}
                          >
                            {Array.from({ length: 31 }, (_, i) => i + 1).map((day) => (
                              <option key={day} value={day}>
                                {day}
                              </option>
                            ))}
                          </select>
                        </label>
                      )}

                      <label>
                        {t('Horário (UTC)')}
                        <input
                          type="time"
                          value={recurringForm.runTime}
                          onChange={(e) => setRecurringForm((f) => ({ ...f, runTime: e.target.value }))}
                          required
                        />
                      </label>
                    </div>
                  )}

                  <div className="recurring-form__actions">
                    <button
                      type="submit"
                      disabled={
                        recurringSubmitting || (recurringForm.gobusterWordlist === 'custom' && !recurringForm.customWordlistId)
                      }
                    >
                      {recurringSubmitting ? t('Salvando…') : editingScheduleId ? t('Salvar alterações') : t('Salvar alvo')}
                    </button>
                    {editingScheduleId && (
                      <button type="button" className="link-button" onClick={resetRecurringForm}>
                        {t('cancelar edição')}
                      </button>
                    )}
                  </div>
                </form>
              </section>
              )}

              <section>
                <h2>{t('Recorrência ({{total}})', { total: recurringScans.length })}</h2>
                {recurringScans.length === 0 && <div className="empty-state">{t('Nenhum alvo salvo ainda.')}</div>}
                {recurringScans.length > 0 && (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>{t('Alvos')}</th>
                          <th>{t('Periodicidade')}</th>
                          <th>{t('Horário (UTC)')}</th>
                          <th>{t('Próxima execução')}</th>
                          <th>{t('Última execução')}</th>
                          <th>{t('Ativo')}</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {recurringScans.map((sched) => (
                          <tr key={sched.schedule_id}>
                            <td>{(sched.targets || []).join(', ')}</td>
                            <td>{sched.enabled ? formatPeriodicity(sched) : t('—')}</td>
                            <td>{sched.enabled ? sched.run_time : t('—')}</td>
                            <td>{sched.enabled && sched.next_run_at ? new Date(sched.next_run_at).toLocaleString(locale) : t('—')}</td>
                            <td>{sched.last_run_at ? new Date(sched.last_run_at).toLocaleString(locale) : t('—')}</td>
                            <td>
                              <input
                                type="checkbox"
                                checked={sched.enabled}
                                onChange={() => handleToggleRecurringEnabled(sched)}
                                disabled={!canOperate}
                                aria-label={t('Ativar/desativar recorrência')}
                              />
                            </td>
                            <td className="recurring-form__actions">
                              {canOperate && (
                                <>
                                  <button type="button" className="link-button" onClick={() => handleRunRecurringNow(sched.schedule_id)}>
                                    {t('rodar agora')}
                                  </button>
                                  <button type="button" className="link-button" onClick={() => handleEditRecurring(sched)}>
                                    {t('editar')}
                                  </button>
                                  <button
                                    type="button"
                                    className="worker-status__cancel"
                                    onClick={() => handleDeleteRecurring(sched.schedule_id)}
                                  >
                                    {t('excluir')}
                                  </button>
                                </>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </>
          )}

          {tab === 'overview' && (
            <>
              <RiskScoreCard client={client} />

              <section>
                <h2>{t('Execuções ({{total}})', { total: summary.total })}</h2>
                <div className="stat-grid">
                  <StatTile label={t('Total')} value={summary.total} onClick={() => goToJobs()} />
                  <StatTile label={t('Concluídas')} value={summary.ok} onClick={() => goToJobs('ok')} accent="good" />
                  <StatTile label={t('Em execução')} value={summary.running} onClick={() => goToJobs('running')} accent="warning" />
                  <StatTile label={t('Pendentes')} value={summary.queued} onClick={() => goToJobs('queued')} accent="muted" />
                  <StatTile label={t('Canceladas')} value={summary.cancelled} onClick={() => goToJobs('cancelled')} accent="muted" />
                  <StatTile label={t('Erros')} value={summary.error} onClick={() => goToJobs('error')} accent="critical" />
                </div>
              </section>

              <section>
                <div className="section-header">
                  <h2>{t('Achados por ferramenta ({{total}} documentos)', { total: findingsTotal })}</h2>
                  {findingsIndices.length > 0 && (
                    <ExportButtons
                      urls={{
                        json: api.exportClientUrl(client, 'json'),
                        csv: api.exportClientUrl(client, 'csv'),
                        pdf: api.exportClientUrl(client, 'pdf'),
                      }}
                    />
                  )}
                </div>
                {findingsIndices.length === 0 && <div className="empty-state">{t('Nenhum achado ainda.')}</div>}
                <FindingsByToolChart indices={findingsIndices} />
                <div className="stat-grid">
                  {findingsIndices.map((idx) => (
                    <StatTile
                      key={idx.suffix}
                      label={t(suffixLabel(idx.suffix))}
                      value={idx.doc_count}
                      onClick={() => navigate(`/clients/${encodeURIComponent(client)}/${idx.suffix}`)}
                    />
                  ))}
                </div>
              </section>
            </>
          )}
        </>
      )}
    </div>
  )
}
