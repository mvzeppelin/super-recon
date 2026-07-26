import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import DataTable from '../components/DataTable.jsx'
import ExportButtons from '../components/ExportButtons.jsx'
import FiltersBar from '../components/FiltersBar.jsx'
import ScreenshotGrid from '../components/ScreenshotGrid.jsx'
import SeverityChart from '../components/SeverityChart.jsx'
import { getUser } from '../auth.js'
import { useTranslation } from '../i18n/LanguageContext.jsx'
import { columnsFor, suffixLabel, suffixTools } from '../toolSchemas.js'

const PAGE_SIZE = 25
const REFRESH_MS = 4000

// Só nuclei/dalfox gravam campo "severity" — o gráfico de distribuição só
// faz sentido pra esses dois (ver SeverityBadge.jsx pra mesma checagem).
const SEVERITY_SUFFIXES = new Set(['nuclei', 'dalfox'])

// "jobs"/"scans" são metadados de execução, não achados — não fazem sentido
// selecionar/excluir aqui (job em andamento tem seu próprio cancelamento).
const NON_FINDINGS_SUFFIXES = new Set(['jobs', 'scans', 'wordlists'])

// Filtros com campo de estado próprio (têm UI dedicada ou lógica especial
// abaixo) — qualquer outro parâmetro na URL (ex: ?alive=true, vindo de um
// link externo como o card de risco do dashboard) não tem UI própria aqui,
// mas ainda precisa virar filtro de verdade: o backend já aceita qualquer
// campo via query string (ver _filters_from_query em main.py), então repassar
// os desconhecidos como estão é o que faz um link tipo
// "/clients/x/httpx?alive=true" realmente filtrar em vez de ser descartado
// pelos efeitos abaixo que só conhecem os campos com estado próprio.
const KNOWN_FILTER_PARAMS = new Set(['q', 'tool', 'severity', 'status', 'scan_id', 'page', 'sort'])

function extraFiltersFromSearch(sp) {
  const extra = {}
  for (const key of sp.keys()) {
    if (KNOWN_FILTER_PARAMS.has(key) || key in extra) continue
    const values = sp.getAll(key)
    extra[key] = values.length > 1 ? values : values[0]
  }
  return extra
}

// "04/07/2026 14:32 — acme.com" — dá identidade legível ao scan_id (hex
// opaco) para o seletor de filtro, já que o mesmo alvo pode ter sido
// escaneado de novo em outro dia.
function formatScanLabel(scan, locale) {
  const dt = new Date(scan['@timestamp'])
  const when = Number.isNaN(dt.getTime())
    ? scan.scan_id.slice(0, 8)
    : dt.toLocaleString(locale, { dateStyle: 'short', timeStyle: 'short' })
  const targets = (scan.targets || []).join(', ')
  const label = targets ? `${when} — ${targets}` : when
  return label.length > 60 ? `${label.slice(0, 57)}…` : label
}

export default function ToolFindings() {
  const { t, lang } = useTranslation()
  const locale = lang === 'en' ? 'en-US' : 'pt-BR'
  const role = getUser()?.role
  const canOperate = role === 'admin' || role === 'operator'
  const { client, suffix } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  // Estado inicial vem da URL — dá refresh/link compartilhável sem perder
  // busca/filtros ativos (ver useEffect de sincronização mais abaixo, que
  // escreve de volta pra URL a cada mudança).
  const [qInput, setQInput] = useState(searchParams.get('q') || '')
  const [q, setQ] = useState(searchParams.get('q') || '')
  const [tool, setTool] = useState(searchParams.get('tool') || '')
  const [severity, setSeverity] = useState(searchParams.get('severity') || '')
  const [statuses, setStatuses] = useState(searchParams.getAll('status'))
  const [scanId, setScanId] = useState(searchParams.get('scan_id') || '')
  const [scans, setScans] = useState([])
  const [page, setPage] = useState(Number(searchParams.get('page')) || 1)
  const [sort, setSort] = useState(searchParams.get('sort') || '-@timestamp')
  // Filtros sem campo próprio (ver KNOWN_FILTER_PARAMS acima) — só entram e
  // saem pela URL, não têm controle de UI dedicado.
  const [extraFilters, setExtraFilters] = useState(() => extraFiltersFromSearch(searchParams))

  const [result, setResult] = useState({ total: 0, items: [] })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(new Set())
  const [uniqueExport, setUniqueExport] = useState(false)
  const [severityCounts, setSeverityCounts] = useState({})

  // histórico de scans do cliente, para o seletor de filtro por execução
  useEffect(() => {
    api
      .listScans(client)
      .then(setScans)
      .catch(() => setScans([]))
  }, [client])

  // debounce da busca livre
  useEffect(() => {
    const timer = setTimeout(() => {
      setPage(1)
      setQ(qInput)
    }, 300)
    return () => clearTimeout(timer)
  }, [qInput])

  // Ao trocar de suffix (ex: link "Docs" da aba Execuções, que manda pra
  // outra tabela já com tool/scan/busca definidos), o React Router reaproveita
  // essa mesma instância — sem isso, os filtros da tabela anterior (scan,
  // tool, severidade, status, página, ordenação) vazam pra tabela nova em
  // vez de vir da URL de destino, e o efeito de sincronização de URL logo
  // abaixo reescreve por cima dos parâmetros que o link acabou de mandar.
  // Não roda na primeira montagem — os useState iniciais já leram a URL.
  const firstSuffixRender = useRef(true)
  useEffect(() => {
    if (firstSuffixRender.current) {
      firstSuffixRender.current = false
      return
    }
    setQInput(searchParams.get('q') || '')
    setQ(searchParams.get('q') || '')
    setTool(searchParams.get('tool') || '')
    setSeverity(searchParams.get('severity') || '')
    setStatuses(searchParams.getAll('status'))
    setScanId(searchParams.get('scan_id') || '')
    setPage(Number(searchParams.get('page')) || 1)
    setSort(searchParams.get('sort') || '-@timestamp')
    setExtraFilters(extraFiltersFromSearch(searchParams))
  }, [suffix])

  function fetchFindings({ showLoading = false } = {}) {
    if (showLoading) setLoading(true)
    setError(null)
    const params = { q, page, size: PAGE_SIZE, sort, ...extraFilters }
    if (tool) params.tool = tool
    if (severity) params.severity = severity
    if (statuses.length) params.status = statuses
    if (scanId) params.scan_id = scanId

    return api
      .getFindings(client, suffix, params)
      .then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => {
        if (showLoading) setLoading(false)
      })
  }

  // Recarrega sozinho a cada REFRESH_MS, sem precisar de F5 — útil para
  // acompanhar um scan em andamento vendo achados/execuções chegarem. Não
  // passar fetchFindings direto pro useEffect: ela retorna uma Promise (para
  // o botão de cancelar poder encadear nela), e o useEffect trataria esse
  // retorno como função de cleanup, quebrando ao desmontar/trocar de
  // dependências.
  useEffect(() => {
    setSelected(new Set())
    fetchFindings({ showLoading: true })
    const id = setInterval(() => fetchFindings(), REFRESH_MS)
    return () => clearInterval(id)
  }, [client, suffix, q, tool, severity, statuses, scanId, page, sort, extraFilters])

  // Espelha os filtros ativos na URL — dá refresh/link compartilhável sem
  // perder o recorte atual (replace: true pra não empilhar histórico a
  // cada tecla/clique de filtro).
  useEffect(() => {
    const next = new URLSearchParams()
    if (q) next.set('q', q)
    if (tool) next.set('tool', tool)
    if (severity) next.set('severity', severity)
    statuses.forEach((s) => next.append('status', s))
    if (scanId) next.set('scan_id', scanId)
    if (page > 1) next.set('page', String(page))
    if (sort && sort !== '-@timestamp') next.set('sort', sort)
    Object.entries(extraFilters).forEach(([key, value]) => {
      if (Array.isArray(value)) value.forEach((v) => next.append(key, v))
      else next.set(key, value)
    })
    setSearchParams(next, { replace: true })
  }, [q, tool, severity, statuses, scanId, page, sort, extraFilters, setSearchParams])

  // Distribuição de severidade — reflete os mesmos filtros da tabela (tool/
  // scan/q), mas de propósito NÃO o filtro de severidade em si: senão o
  // gráfico sempre colapsaria numa fatia só quando o usuário já filtrou por
  // uma severidade, o que não ajuda em nada.
  useEffect(() => {
    if (!SEVERITY_SUFFIXES.has(suffix)) {
      setSeverityCounts({})
      return
    }
    const params = { q, ...extraFilters }
    if (tool) params.tool = tool
    if (statuses.length) params.status = statuses
    if (scanId) params.scan_id = scanId
    api
      .getSeveritySummary(client, suffix, params)
      .then(setSeverityCounts)
      .catch(() => setSeverityCounts({}))
  }, [client, suffix, q, tool, statuses, scanId, extraFilters])

  function handleSort(field) {
    setPage(1)
    setSort((prev) => {
      const prevField = prev.replace(/^-/, '')
      if (prevField !== field) return field
      return prev.startsWith('-') ? field : `-${field}`
    })
  }

  function handleCancelJob(row) {
    if (!window.confirm(t('Cancelar {{tool}} em {{target}}?', row))) return
    api
      .cancelJob(client, row._id)
      .then(() => fetchFindings())
      .catch((e) => setError(e.message))
  }

  function toggleRow(id) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleAll(rows) {
    setSelected((prev) => {
      const allSelected = rows.every((r) => prev.has(r._id))
      const next = new Set(prev)
      rows.forEach((r) => (allSelected ? next.delete(r._id) : next.add(r._id)))
      return next
    })
  }

  function handleDeleteSelected() {
    if (!selected.size) return
    if (!window.confirm(t('Excluir {{count}} achado(s) selecionado(s)? Essa ação não pode ser desfeita.', { count: selected.size })))
      return
    api
      .deleteFindings(client, suffix, Array.from(selected))
      .then(() => {
        setSelected(new Set())
        return fetchFindings()
      })
      .catch((e) => setError(e.message))
  }

  // Galeria (gowitness) não tem UI de seleção por checkbox — é uma grade de
  // imagens, não uma tabela de linhas. viewer não pode excluir achado nem
  // cancelar job, então a seleção em si não serve pra nada nesse papel.
  const selectable = !NON_FINDINGS_SUFFIXES.has(suffix) && suffix !== 'gowitness' && canOperate
  const columns = columnsFor(suffix)
  const toolOptions = suffixTools(suffix)
  const scanOptions = scans.map((s) => ({ scan_id: s.scan_id, label: formatScanLabel(s, locale) }))
  const totalPages = Math.max(1, Math.ceil(result.total / PAGE_SIZE))

  // Mesmos filtros aplicados na tela (não a paginação/ordenação — exportar
  // sempre traz todo o recorte filtrado, não só a página atual).
  const exportParams = { q, ...extraFilters }
  if (tool) exportParams.tool = tool
  if (severity) exportParams.severity = severity
  if (statuses.length) exportParams.status = statuses
  if (scanId) exportParams.scan_id = scanId
  if (uniqueExport) exportParams.unique = 'true'

  return (
    <div className="page">
      <div className="page-header">
        <h1>
          {t(suffixLabel(suffix))} <span className="muted">({result.total}) · {client}</span>
        </h1>
        <div className="page-header__actions">
          {selectable && (
            <label className="unique-toggle" title={t('Agrupa achados idênticos vindos de tools/scans diferentes numa linha só')}>
              <input type="checkbox" checked={uniqueExport} onChange={(e) => setUniqueExport(e.target.checked)} />
              {t('exportar únicos')}
            </label>
          )}
          <ExportButtons
            urls={{
              json: api.exportSuffixUrl(client, suffix, 'json', exportParams),
              csv: api.exportSuffixUrl(client, suffix, 'csv', exportParams),
              pdf: api.exportSuffixUrl(client, suffix, 'pdf', exportParams),
            }}
          />
          <span className="page-header__divider" />
          <button className="link-button" onClick={() => navigate(`/clients/${encodeURIComponent(client)}`)}>
            ← {client}
          </button>
        </div>
      </div>

      <FiltersBar
        q={qInput}
        onQChange={setQInput}
        toolOptions={toolOptions}
        toolValue={tool}
        onToolChange={(v) => {
          setTool(v)
          setPage(1)
        }}
        scanOptions={scanOptions}
        scanValue={scanId}
        onScanChange={(v) => {
          setScanId(v)
          setPage(1)
        }}
        showSeverity={SEVERITY_SUFFIXES.has(suffix)}
        severityValue={severity}
        onSeverityChange={(v) => {
          setSeverity(v)
          setPage(1)
        }}
        showStatus={suffix === 'jobs'}
        statusValues={statuses}
        onStatusChange={(v) => {
          setStatuses(v)
          setPage(1)
        }}
      />

      {error && <div className="empty-state empty-state--error">{error}</div>}

      {SEVERITY_SUFFIXES.has(suffix) && <SeverityChart counts={severityCounts} />}

      {selectable && selected.size > 0 && (
        <div className="selection-bar">
          <span>{t('{{count}} selecionado(s)', { count: selected.size })}</span>
          <button type="button" className="action-pill action-pill--critical" onClick={handleDeleteSelected}>
            {t('✕ excluir selecionados')}
          </button>
          <button type="button" className="link-button" onClick={() => setSelected(new Set())}>
            {t('limpar seleção')}
          </button>
        </div>
      )}

      {suffix === 'gowitness' ? (
        <ScreenshotGrid rows={result.items} loading={loading} client={client} />
      ) : (
        <DataTable
          columns={columns}
          rows={result.items}
          loading={loading}
          sort={sort}
          onSort={handleSort}
          client={client}
          selectable={selectable}
          selectedIds={selected}
          onToggleRow={toggleRow}
          onToggleAll={toggleAll}
          renderActions={
            suffix === 'jobs' && canOperate
              ? (row) =>
                  (row.status === 'running' || row.status === 'queued') && (
                    <button type="button" className="worker-status__cancel" onClick={() => handleCancelJob(row)}>
                      {t('cancelar')}
                    </button>
                  )
              : undefined
          }
        />
      )}

      {!loading && result.total > 0 && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            {t('← anterior')}
          </button>
          <span>{t('página {{page}} de {{totalPages}} · {{total}} resultados', { page, totalPages, total: result.total })}</span>
          <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
            {t('próxima →')}
          </button>
        </div>
      )}
    </div>
  )
}
