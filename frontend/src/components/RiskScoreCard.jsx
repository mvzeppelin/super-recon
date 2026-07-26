import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import StatTile from './StatTile.jsx'
import { useTranslation } from '../i18n/LanguageContext.jsx'

// finding_type do wpscan que conta como vulnerabilidade (ver
// backend/app/opensearch_client.py: _WPSCAN_VULN_TYPES) — mesmo filtro,
// espelhado aqui pro link do StatTile levar exatamente pro mesmo recorte
// que o número reflete.
const WPSCAN_VULN_TYPES = ['core_vulnerability', 'theme_vulnerability', 'plugin_vulnerability']

// Tier (string em português, vem fixo do backend — ver risk_score.py) ->
// classe de badge já existente (mesma paleta do SeverityBadge/StatusBadge).
const TIER_CLASS = {
  Nenhum: 'badge--muted',
  Baixo: 'badge--good',
  Médio: 'badge--warning',
  Alto: 'badge--serious',
  Crítico: 'badge--critical',
}

const SEVERITY_META = {
  critical: { label: 'Crítico', accent: 'critical' },
  high: { label: 'Alto', accent: 'serious' },
  medium: { label: 'Médio', accent: 'warning' },
  low: { label: 'Baixo', accent: 'good' },
  info: { label: 'Informativo', accent: 'muted' },
}
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

// Resumo agregado (score de risco) do cliente pro relatório executivo — o
// mesmo dado que vira o PDF (ver GET /clients/{client}/risk-report), aqui
// como card no topo da aba "Visão geral" pra dar visibilidade contínua sem
// precisar gerar o PDF toda vez.
export default function RiskScoreCard({ client }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [summary, setSummary] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    setSummary(null)
    setError(null)
    api
      .getRiskSummary(client)
      .then(setSummary)
      .catch((e) => setError(e.message))
  }, [client])

  // Seção opcional — uma falha aqui não pode derrubar o resto do dashboard.
  if (error) return null
  if (!summary) return null

  const { tier, score, severity_counts: severityCounts, wpscan_vulnerabilities: wpscanVulns, surface } = summary
  const criticalCount = severityCounts.critical || 0
  const hasSeverityFindings = SEVERITY_ORDER.some((sev) => severityCounts[sev]) || wpscanVulns > 0

  function goTo(suffix, params) {
    const qs = params ? `?${params.toString()}` : ''
    navigate(`/clients/${encodeURIComponent(client)}/${suffix}${qs}`)
  }

  return (
    <section className="risk-score-card">
      <div className="section-header">
        <h2>{t('Nível de risco')}</h2>
        <a href={api.exportRiskReportUrl(client)} className="link-button">
          {t('baixar relatório executivo (PDF)')}
        </a>
      </div>

      <div className="risk-score-card__headline">
        <span className={`badge risk-score-card__badge ${TIER_CLASS[tier] || 'badge--muted'}`}>{t(tier)}</span>
        <span className="risk-score-card__score">{t('pontuação: {{score}}', { score })}</span>
      </div>
      {criticalCount > 0 && (
        <p className="risk-score-card__reason">
          {t('{{count}} achado(s) crítico(s) identificado(s)', { count: criticalCount })}
        </p>
      )}

      {hasSeverityFindings && (
        <div className="stat-grid">
          {/* Origem sempre nuclei: é a fonte dominante de achados com
              severidade (dalfox é opt-in e rende pouco, ver README "Dados
              do Dalfox") — quando um achado vier só do dalfox, o link ainda
              leva pra uma tabela real de achados, só não necessariamente a
              exata (dalfox tem sua própria página em /clients/{client}/dalfox). */}
          {SEVERITY_ORDER.filter((sev) => severityCounts[sev]).map((sev) => (
            <StatTile
              key={sev}
              label={t(SEVERITY_META[sev].label)}
              value={severityCounts[sev]}
              accent={SEVERITY_META[sev].accent}
              onClick={() => goTo('nuclei', new URLSearchParams({ severity: sev }))}
            />
          ))}
          {wpscanVulns > 0 && (
            <StatTile
              label={t('Vulnerabilidades WordPress')}
              value={wpscanVulns}
              accent="serious"
              onClick={() => {
                const params = new URLSearchParams()
                WPSCAN_VULN_TYPES.forEach((ft) => params.append('finding_type', ft))
                goTo('wpscan', params)
              }}
            />
          )}
        </div>
      )}
      {!hasSeverityFindings && <div className="empty-state">{t('Nenhum achado com severidade identificado ainda.')}</div>}

      <div className="risk-score-card__surface-label muted">{t('Superfície de ataque (contexto — não entra na pontuação)')}</div>
      <div className="stat-grid">
        <StatTile label={t('Subdomínios')} value={surface.subdomains} onClick={() => goTo('subdomains')} />
        <StatTile
          label={t('Hosts vivos (HTTP)')}
          value={surface.live_hosts}
          onClick={() => goTo('httpx', new URLSearchParams({ alive: 'true' }))}
        />
        <StatTile label={t('Portas abertas')} value={surface.open_ports} onClick={() => goTo('masscan')} />
      </div>
    </section>
  )
}
