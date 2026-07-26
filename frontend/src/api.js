import { clearSession, getToken } from './auth.js'

const BASE = '/api'

async function request(path, opts = {}) {
  const token = getToken()
  const headers = { ...(opts.headers || {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) }
  const res = await fetch(`${BASE}${path}`, { ...opts, headers })
  if (res.status === 401) {
    // A sessão guardada não vale mais (expirou, foi desativada, ou nunca
    // foi válida) — limpa e recarrega pra cair de volta na tela de login
    // (LoginGate), em vez de espalhar erro 401 por cada tela da aplicação.
    clearSession()
    window.location.reload()
    throw new Error('Sessão expirada — recarregando…')
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || detail
    } catch {
      // resposta sem corpo JSON
    }
    throw new Error(detail)
  }
  return res.json()
}

// Anexa o token de sessão (se houver) na query string — usado só pelos
// links de exportação/screenshot, que são <a href>/<img src> simples e não
// mandam header customizado como as chamadas via fetch acima.
function withToken(params) {
  const token = getToken()
  return token ? { ...params, token } : params
}

// Valor pode ser string (filtro único, como sempre foi) ou array (múltiplos
// valores pro mesmo campo, ex: vários status marcados de uma vez) — nesse
// caso vira múltiplas entradas "chave=valor" repetidas (?status=ok&status=error),
// não uma string ficando "ok,error" (que o backend não entenderia como duas).
function toQueryString(params) {
  const usp = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === '' || value == null) continue
    if (Array.isArray(value)) {
      value.forEach((item) => usp.append(key, item))
    } else {
      usp.append(key, value)
    }
  }
  return usp.toString()
}

export const api = {
  health: () => request('/health'),
  login: (username, password) =>
    request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  getMe: () => request('/auth/me'),
  changePassword: (currentPassword, newPassword) =>
    request('/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  listUsers: () => request('/users'),
  createUser: (username, password, role) =>
    request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role }),
    }),
  updateUser: (userId, body) =>
    request(`/users/${encodeURIComponent(userId)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  resetUserPassword: (userId, newPassword) =>
    request(`/users/${encodeURIComponent(userId)}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_password: newPassword }),
    }),
  deleteUser: (userId) => request(`/users/${encodeURIComponent(userId)}`, { method: 'DELETE' }),
  getAuditLog: (params = {}) => {
    const qs = toQueryString(params)
    return request(`/audit-log${qs ? `?${qs}` : ''}`)
  },
  getSettings: () => request('/settings'),
  updateSettings: (overrides) =>
    request('/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ overrides }),
    }),
  activeJobs: () => request('/jobs/active'),
  listClients: () => request('/clients'),
  listClientIndices: (client) => request(`/clients/${encodeURIComponent(client)}/indices`),
  getJobsSummary: (client) => request(`/clients/${encodeURIComponent(client)}/jobs/summary`),
  listScans: (client) => request(`/clients/${encodeURIComponent(client)}/scans`),
  getScanDefaults: () => request('/scan-defaults'),
  ipProvenance: (client, ip, scanId) => {
    const qs = new URLSearchParams({ ip, scan_id: scanId }).toString()
    return request(`/clients/${encodeURIComponent(client)}/ip-provenance?${qs}`)
  },
  getAsset: (client, value) => {
    const qs = new URLSearchParams({ value }).toString()
    return request(`/clients/${encodeURIComponent(client)}/asset?${qs}`)
  },
  getRiskSummary: (client) => request(`/clients/${encodeURIComponent(client)}/risk-report?format=json`),
  exportRiskReportUrl: (client) => {
    const qs = new URLSearchParams(withToken({ format: 'pdf' })).toString()
    return `${BASE}/clients/${encodeURIComponent(client)}/risk-report?${qs}`
  },
  deleteScan: (client, scanId) =>
    request(`/clients/${encodeURIComponent(client)}/scans/${encodeURIComponent(scanId)}`, { method: 'DELETE' }),
  deleteClient: (client) => request(`/clients/${encodeURIComponent(client)}`, { method: 'DELETE' }),
  clearClientData: (client) => request(`/clients/${encodeURIComponent(client)}/clear`, { method: 'POST' }),
  cancelJob: (client, jobId) =>
    request(`/clients/${encodeURIComponent(client)}/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' }),
  cancelAllJobs: (client) => request(`/clients/${encodeURIComponent(client)}/jobs/cancel-all`, { method: 'POST' }),
  exportClientUrl: (client, format) => {
    const qs = new URLSearchParams(withToken({ format })).toString()
    return `${BASE}/clients/${encodeURIComponent(client)}/export?${qs}`
  },
  exportSuffixUrl: (client, suffix, format, params = {}) => {
    const qs = toQueryString(withToken({ format, ...params }))
    return `${BASE}/clients/${encodeURIComponent(client)}/${encodeURIComponent(suffix)}/export?${qs}`
  },
  screenshotUrl: (client, screenshotId) => {
    const qs = new URLSearchParams(withToken({})).toString()
    return `${BASE}/clients/${encodeURIComponent(client)}/screenshots/${encodeURIComponent(screenshotId)}${qs ? `?${qs}` : ''}`
  },
  getFindings: (client, suffix, params = {}) => {
    const qs = toQueryString(params)
    return request(`/clients/${encodeURIComponent(client)}/${encodeURIComponent(suffix)}${qs ? `?${qs}` : ''}`)
  },
  getSeveritySummary: (client, suffix, params = {}) => {
    const qs = toQueryString(params)
    return request(`/clients/${encodeURIComponent(client)}/${encodeURIComponent(suffix)}/severity-summary${qs ? `?${qs}` : ''}`)
  },
  deleteFindings: (client, suffix, ids) =>
    request(`/clients/${encodeURIComponent(client)}/${encodeURIComponent(suffix)}/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    }),
  createScan: (clientName, targets, gobusterWordlist = 'common', gobusterCustomWordlistId = null, enabledTools = null) =>
    request('/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: clientName,
        targets,
        gobuster_wordlist: gobusterWordlist,
        gobuster_custom_wordlist_id: gobusterCustomWordlistId,
        enabled_tools: enabledTools,
      }),
    }),
  getScan: (scanId, clientName) => request(`/scans/${scanId}?client=${encodeURIComponent(clientName)}`),
  compareScans: (client, suffix, fromScan, toScan) => {
    const qs = new URLSearchParams({ from_scan: fromScan, to_scan: toScan }).toString()
    return request(`/clients/${encodeURIComponent(client)}/${encodeURIComponent(suffix)}/compare?${qs}`)
  },
  listWordlists: (client) => request(`/clients/${encodeURIComponent(client)}/wordlists`),
  uploadWordlist: (client, file) => {
    const formData = new FormData()
    formData.append('file', file)
    return request(`/clients/${encodeURIComponent(client)}/wordlists`, { method: 'POST', body: formData })
  },
  deleteWordlist: (client, wordlistId) =>
    request(`/clients/${encodeURIComponent(client)}/wordlists/${encodeURIComponent(wordlistId)}`, {
      method: 'DELETE',
    }),
  listRecurringScans: (client) => request(`/clients/${encodeURIComponent(client)}/recurring-scans`),
  createRecurringScan: (client, body) =>
    request(`/clients/${encodeURIComponent(client)}/recurring-scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  updateRecurringScan: (client, scheduleId, body) =>
    request(`/clients/${encodeURIComponent(client)}/recurring-scans/${encodeURIComponent(scheduleId)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  deleteRecurringScan: (client, scheduleId) =>
    request(`/clients/${encodeURIComponent(client)}/recurring-scans/${encodeURIComponent(scheduleId)}`, {
      method: 'DELETE',
    }),
  runRecurringScanNow: (client, scheduleId) =>
    request(`/clients/${encodeURIComponent(client)}/recurring-scans/${encodeURIComponent(scheduleId)}/run-now`, {
      method: 'POST',
    }),
}
