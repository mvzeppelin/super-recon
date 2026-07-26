// Labels/tips das configurações da tela "Configurações" (admin) — fonte em
// português, cada string passa por t() pra tradução (mesmo padrão de
// ROLE_LABELS em UsersPage.jsx). Uma entrada por chave devolvida por
// GET /settings (ver backend/app/settings_registry.py — essa lista de
// grupos/ordem espelha o registro de lá).

export const SETTINGS_GROUPS = [
  { id: 'session', label: 'Sessão' },
  { id: 'wordlists', label: 'Upload de wordlists' },
  { id: 'notifications', label: 'Notificações' },
  { id: 'monitoring', label: 'Monitor & recorrência' },
  { id: 'phase4_optional', label: 'Ferramentas opcionais (Fase 4)' },
  { id: 'integrations', label: 'Integrações externas' },
  { id: 'timeouts', label: 'Timeouts por ferramenta' },
]

const GENERIC_TIMEOUT_TIP =
  'Tempo máximo (segundos) que a ferramenta pode rodar antes de ser interrompida. Um job com erro "Read timed out" estourou esse valor — não é falha real da ferramenta, só precisa de mais tempo pro alvo em questão.'

const LARGE_TARGET_TIMEOUT_TIP =
  'Tempo máximo (segundos) que a ferramenta pode rodar antes de ser interrompida. Busca dados arquivados/históricos, por isso costuma ser a mais sensível a esse timeout em domínios grandes ou antigos — aumente se o job terminar com erro "Read timed out".'

function timeoutMeta(tool, { tip = GENERIC_TIMEOUT_TIP } = {}) {
  return { label: `Timeout do ${tool} (segundos)`, tip, unit: 's' }
}

export const SETTINGS_META = {
  // ---- sessão ----
  SESSION_TTL_DAYS: {
    label: 'Validade do token de sessão (dias)',
    tip: 'Depois de logar, por quantos dias o token continua valendo sem precisar logar de novo.',
    unit: 'dias',
  },

  // ---- upload de wordlists customizadas ----
  MAX_WORDLIST_BYTES: {
    label: 'Tamanho máximo de wordlist (bytes)',
    tip: 'Limite de tamanho de arquivo aceito no upload de wordlist customizada do gobuster.',
    unit: 'bytes',
  },
  MAX_WORDLIST_LINES: {
    label: 'Máximo de linhas por wordlist',
    tip: 'Wordlists com mais linhas que isso são rejeitadas no upload.',
  },
  MAX_WORDLIST_LINE_CHARS: {
    label: 'Máximo de caracteres por linha',
    tip: 'Linhas mais longas que isso na wordlist são rejeitadas no upload.',
  },
  MAX_WORDLISTS_PER_CLIENT: {
    label: 'Máximo de wordlists por cliente',
    tip: 'Quantas wordlists customizadas um mesmo cliente pode ter salvas ao mesmo tempo.',
  },
  GOBUSTER_CUSTOM_TIMEOUT: {
    label: 'Timeout do gobuster com wordlist customizada (segundos)',
    tip: 'Wordlist customizada pode ser bem maior que os perfis padrão ("common"/"big"), por isso tem um timeout próprio, mais generoso.',
    unit: 's',
  },

  // ---- notificação em achado crítico ----
  NOTIFY_SEVERITIES: {
    label: 'Severidades que disparam notificação',
    tip: 'Um achado com uma dessas severidades dispara Slack/webhook (hoje gravado por nuclei e dalfox).',
  },
  SLACK_BOT_TOKEN: {
    label: 'Token do bot do Slack',
    tip: 'Token de bot (xoxb-...) com escopo chat:write. Vazio = notificação por Slack desligada.',
  },
  SLACK_CHANNEL: {
    label: 'Canal do Slack',
    tip: 'ID do canal onde o bot foi adicionado (não o nome — pegue em "Copiar link do canal" no Slack).',
  },
  NOTIFY_WEBHOOK_URL: {
    label: 'URL de webhook genérico',
    tip: 'Qualquer URL que aceite POST de JSON — funciona com um Incoming Webhook do Slack, Discord com adaptador, ou um endpoint seu. Pode ser usado junto com o Slack, não é um ou-outro.',
  },
  PUBLIC_BASE_URL: {
    label: 'URL pública do dashboard',
    tip: 'Opcional — usada só para montar um link clicável na notificação (ex: http://minha-vps.example.com:3000).',
  },

  // ---- monitor de saúde / recorrência ----
  HEALTH_CHECK_INTERVAL_SECONDS: {
    label: 'Intervalo do monitor de saúde (segundos)',
    tip: 'De quanto em quanto tempo o backend confere cluster OpenSearch, worker Celery, fila e jobs travados. 0 ou negativo desliga o monitor inteiro — nesse caso, religar exige reiniciar o backend (ajustar o intervalo com o monitor já ligado funciona na hora).',
    unit: 's',
  },
  HEALTH_QUEUE_BACKLOG_THRESHOLD: {
    label: 'Limite de fila represada',
    tip: 'Número de tarefas pendentes na fila do Celery acima do qual soa alarme de fila represada.',
  },
  HEALTH_STUCK_JOB_MINUTES: {
    label: 'Minutos até considerar um job travado',
    tip: 'Quanto tempo um job pode ficar "em execução" antes de ser considerado travado (ex: o worker morreu no meio sem atualizar o status).',
    unit: 'min',
  },
  RECURRENCE_CHECK_INTERVAL_SECONDS: {
    label: 'Intervalo do agendador de recorrência (segundos)',
    tip: 'De quanto em quanto tempo o backend confere se algum alvo salvo com recorrência está na hora de rodar. 0 ou negativo desliga o agendador inteiro — religar exige reiniciar o backend.',
    unit: 's',
  },

  // ---- ferramentas opt-in da Fase 4 ----
  GOWITNESS_ENABLED: {
    label: 'Gowitness ligado por padrão',
    tip: 'Se marcado, um novo scan já sai com o screenshot de cada URL viva marcado no checklist (dá pra mudar por execução — isso só define o estado inicial).',
  },
  DALFOX_ENABLED: {
    label: 'Dalfox ligado por padrão',
    tip: 'Se marcado, um novo scan já sai com o scanner de XSS marcado no checklist (dá pra mudar por execução).',
  },
  KITERUNNER_ENABLED: {
    label: 'Kiterunner ligado por padrão',
    tip: 'Se marcado, um novo scan já sai com a descoberta de rotas de API marcada no checklist (dá pra mudar por execução).',
  },
  KITERUNNER_WORDLIST_LINES: {
    label: 'Linhas da wordlist do kiterunner',
    tip: 'Quantas linhas da wordlist de rotas de API são usadas — menos é mais rápido, mais é mais completo.',
  },

  // ---- integrações externas ----
  SHODAN_API_KEY: {
    label: 'Chave de API do Shodan',
    tip: 'Habilita consulta à Shodan Host API pro IP do domínio raiz, de cada subdomínio e de alvo IP puro. Vazio = desligado, nenhuma chamada é feita. Gere em account.shodan.io (o plano free funciona).',
  },
  CENSYS_API_KEY: {
    label: 'Token de API do Censys',
    tip: 'Habilita consulta à Censys Platform API nos mesmos pontos da Shodan — cobertura diferente (um acha o que o outro não acha), os dois podem ficar ligados ao mesmo tempo. Gere em platform.censys.io.',
  },
  WPSCAN_API_TOKEN: {
    label: 'Token da WPVulnDB (WPScan)',
    tip: 'O WPScan roda sempre em toda URL viva, com ou sem token; esse token só habilita cruzar o plugin/tema encontrado com a base de vulnerabilidades (dado de CVE). Gere em wpscan.com/api.',
  },

  // ---- timeout de cada ferramenta ----
  ASSETFINDER_TIMEOUT: timeoutMeta('assetfinder'),
  SUBFINDER_TIMEOUT: timeoutMeta('subfinder'),
  SUBLIST3R_TIMEOUT: timeoutMeta('sublist3r'),
  AMASS_TIMEOUT: timeoutMeta('amass'),
  DNSENUM_TIMEOUT: timeoutMeta('dnsenum'),
  DNSRECON_TIMEOUT: timeoutMeta('dnsrecon'),
  RDAP_TIMEOUT: timeoutMeta('rdap'),
  WAYBACK_TIMEOUT: timeoutMeta('wayback', { tip: LARGE_TARGET_TIMEOUT_TIP }),
  WAYBACK_MAX_RECORDS: {
    label: 'Teto de URLs coletadas pelo wayback',
    tip: 'Limita quantas URLs o wayback coleta por execução, além do timeout acima — evita que um domínio com histórico gigantesco nunca termine. O que já foi coletado não se perde mesmo se parar no teto.',
  },
  GAU_TIMEOUT: timeoutMeta('gau', { tip: LARGE_TARGET_TIMEOUT_TIP }),
  THEHARVESTER_TIMEOUT: timeoutMeta('theharvester'),
  KATANA_TIMEOUT: timeoutMeta('katana'),
  HTTPX_TIMEOUT: timeoutMeta('httpx'),
  DNSX_TIMEOUT: timeoutMeta('dnsx'),
  MASSCAN_TIMEOUT: timeoutMeta('masscan'),
  NMAP_TIMEOUT: timeoutMeta('nmap'),
  NUCLEI_TIMEOUT: timeoutMeta('nuclei'),
  NIKTO_TIMEOUT: timeoutMeta('nikto'),
  WPSCAN_TIMEOUT: timeoutMeta('wpscan'),
  GOWITNESS_TIMEOUT: timeoutMeta('gowitness'),
  DALFOX_TIMEOUT: timeoutMeta('dalfox'),
  KITERUNNER_TIMEOUT: timeoutMeta('kiterunner'),
}
