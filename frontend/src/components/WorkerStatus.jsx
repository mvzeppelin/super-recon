import { useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'

const POLL_MS = 3000

function elapsed(startedAt) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000))
  if (seconds < 60) return `${seconds}s`
  return `${Math.floor(seconds / 60)}m${String(seconds % 60).padStart(2, '0')}s`
}

export default function WorkerStatus() {
  const { t } = useTranslation()
  const [data, setData] = useState({ recon_cpus: 0, active: [] })
  const [open, setOpen] = useState(false)
  const mountedRef = useRef(true)

  function refresh() {
    api
      .activeJobs()
      .then((d) => {
        if (mountedRef.current) setData(d)
      })
      .catch(() => {
        // silencioso: não interrompe a navegação por causa do widget de status
      })
  }

  useEffect(() => {
    mountedRef.current = true
    refresh()
    const id = setInterval(refresh, POLL_MS)
    return () => {
      mountedRef.current = false
      clearInterval(id)
    }
  }, [])

  function handleCancel(job) {
    if (!window.confirm(t('Cancelar {{tool}} em {{target}} (cliente {{client}})?', job))) return
    api
      .cancelJob(job.client, job.job_id)
      .then(refresh)
      .catch(() => {
        // se falhar, o próximo poll (3s) já corrige o estado mostrado
      })
  }

  const busy = data.active.length
  const total = data.recon_cpus || busy

  return (
    <div className="worker-status">
      <button
        type="button"
        className="worker-status__summary"
        onClick={() => setOpen((o) => !o)}
        disabled={busy === 0}
      >
        <span className={`worker-status__dot${busy ? ' worker-status__dot--active' : ''}`} />
        {busy > 0
          ? t('{{busy}}/{{total}} execuções em andamento', { busy, total })
          : t('ocioso · {{total}} workers', { total })}
      </button>

      {open && busy > 0 && (
        <ul className="worker-status__list">
          {data.active.map((j) => (
            <li key={j.job_id}>
              <span className="worker-status__tool">{j.tool}</span>
              <span className="muted">
                {' '}
                {j.target} · {j.client}
              </span>
              <span className="worker-status__elapsed">{elapsed(j.started_at)}</span>
              <button type="button" className="worker-status__cancel" onClick={() => handleCancel(j)}>
                {t('cancelar')}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
