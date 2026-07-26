import multiprocessing
import os

RECON_CPUS = int(os.environ["RECON_CPUS"]) if os.environ.get("RECON_CPUS") else multiprocessing.cpu_count()

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ["REDIS_PASSWORD"]

OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", "9200"))
OPENSEARCH_USER = os.environ["OPENSEARCH_ADMIN_USER"]
OPENSEARCH_PASSWORD = os.environ["OPENSEARCH_ADMIN_PASSWORD"]

KALI_IMAGE = os.environ.get("KALI_IMAGE", "kali-tools:1.0")

# Autenticação (usuários/papéis, ver README "Autenticação e usuários") —
# sempre exigida, sem opção de desligar (diferente da antiga API_KEY, que
# era opcional). Tempo de validade de um token de sessão (dias) desde o
# login; expirado, precisa logar de novo. Token mandado via header
# "Authorization: Bearer <token>" ou ?token= (query string, usado pelos
# links de download do ExportButtons e pelas imagens do gowitness — <a
# href>/<img src> simples, sem como mandar header customizado).
SESSION_TTL_DAYS = int(os.environ.get("SESSION_TTL_DAYS", "30"))

# Diretório de troca de arquivos com os containers efêmeros do Kali (para
# ferramentas que não sabem escrever a saída em stdout, ex: nikto).
# EXCHANGE_DIR é o path visto de dentro do worker; HOST_EXCHANGE_DIR é o
# mesmo diretório visto pelo host (necessário pois os containers do Kali são
# "irmãos", criados via docker.sock, não filhos do worker).
EXCHANGE_DIR = os.environ.get("EXCHANGE_DIR", "/exchange")
HOST_EXCHANGE_DIR = os.environ["HOST_EXCHANGE_DIR"]

# Dois perfis de wordlist selecionáveis por scan (ver ScanRequest.gobuster_wordlist):
# "common" (dirb/common.txt, ~4.6k palavras) é rápido; "big" (dirb/big.txt,
# ~20k palavras) é mais completo mas demora bem mais — daí o timeout maior.
GOBUSTER_WORDLISTS = {
    "common": os.environ.get("GOBUSTER_WORDLIST_COMMON", "/usr/share/dirb/wordlists/common.txt"),
    "big": os.environ.get("GOBUSTER_WORDLIST_BIG", "/usr/share/dirb/wordlists/big.txt"),
}
GOBUSTER_TIMEOUTS = {"common": 300, "big": 900}
NUCLEI_TEMPLATE_DIRS = os.environ.get(
    "NUCLEI_TEMPLATE_DIRS",
    "/root/nuclei-templates/http/technologies,/root/nuclei-templates/http/exposures,/root/nuclei-templates/http/misconfiguration",
)

# Kiterunner (Fase 4, opt-in — ver KITERUNNER_ENABLED abaixo): tamanho fixo
# de wordlist via .env, mesmo padrão do NUCLEI_TEMPLATE_DIRS acima — sem
# seletor por scan (perfil common/big/custom é exclusividade do gobuster).
# KITERUNNER_WORDLIST é o nome cacheado no build da imagem (ver Dockerfile);
# KITERUNNER_WORDLIST_LINES trunca às N primeiras linhas em tempo de scan via
# "-A nome:N" (mesmo arquivo em cache, sem nova chamada de rede).
KITERUNNER_WORDLIST = os.environ.get("KITERUNNER_WORDLIST", "apiroutes-260227")
KITERUNNER_WORDLIST_LINES = int(os.environ.get("KITERUNNER_WORDLIST_LINES", "5000"))

# Wordlists customizadas enviadas pelo usuário para o gobuster (ver
# backend/app/wordlists.py para a validação). WORDLISTS_DIR é o path visto de
# dentro do backend (onde o upload é gravado); HOST_WORDLISTS_DIR é o mesmo
# diretório visto pelo host — necessário pra montar o arquivo específico
# (read-only) no container efêmero do gobuster via docker.sock, mesmo padrão
# de EXCHANGE_DIR/HOST_EXCHANGE_DIR acima.
WORDLISTS_DIR = os.environ.get("WORDLISTS_DIR", "/wordlists")
HOST_WORDLISTS_DIR = os.environ["HOST_WORDLISTS_DIR"]

# Screenshots do gowitness (ver backend/app/screenshots.py) — diferente de
# WORDLISTS_DIR acima, não precisa de um HOST_SCREENSHOTS_DIR: o worker
# grava aqui diretamente (move do diretório de troca efêmero), não repassa
# esse path pra montar em outro container via docker.sock.
SCREENSHOTS_DIR = os.environ.get("SCREENSHOTS_DIR", "/screenshots")

# Limites de upload — recurso propositalmente conservador: uma wordlist é uma
# lista de palavras curtas, não um arquivo genérico. Tudo configurável via
# .env caso o padrão seja baixo demais para o seu caso de uso.
MAX_WORDLIST_BYTES = int(os.environ.get("MAX_WORDLIST_BYTES", str(5 * 1024 * 1024)))  # 5 MiB
MAX_WORDLIST_LINES = int(os.environ.get("MAX_WORDLIST_LINES", "200000"))
MAX_WORDLIST_LINE_CHARS = int(os.environ.get("MAX_WORDLIST_LINE_CHARS", "512"))
MAX_WORDLISTS_PER_CLIENT = int(os.environ.get("MAX_WORDLISTS_PER_CLIENT", "5"))
# Wordlist customizada pode ter até 200k linhas (10x o perfil "big") — timeout
# fixo e generoso em vez de calcular em cima do line_count, por simplicidade.
GOBUSTER_CUSTOM_TIMEOUT = int(os.environ.get("GOBUSTER_CUSTOM_TIMEOUT_SECONDS", "1200"))

# Timeout de cada ferramenta (segundos). Os valores abaixo são os mesmos
# usados como padrão desde sempre (hardcoded em commands.py antes de virarem
# configuráveis) — ficam comentados no .env(.example) de propósito: não
# especificar = usa esse padrão, só precisa descomentar/ajustar a ferramenta
# que realmente estiver estourando pro alvo em questão (ex: wayback/gau
# buscam URLs arquivadas e podem demorar bem mais que o padrão em domínios
# grandes/antigos — visto na prática, job terminou em erro "Read timed out"
# por estourar o timeout, não por falha real da ferramenta).
ASSETFINDER_TIMEOUT = int(os.environ.get("ASSETFINDER_TIMEOUT_SECONDS", "120"))
SUBFINDER_TIMEOUT = int(os.environ.get("SUBFINDER_TIMEOUT_SECONDS", "180"))
SUBLIST3R_TIMEOUT = int(os.environ.get("SUBLIST3R_TIMEOUT_SECONDS", "180"))
AMASS_TIMEOUT = int(os.environ.get("AMASS_TIMEOUT_SECONDS", "150"))
DNSENUM_TIMEOUT = int(os.environ.get("DNSENUM_TIMEOUT_SECONDS", "120"))
DNSRECON_TIMEOUT = int(os.environ.get("DNSRECON_TIMEOUT_SECONDS", "240"))
RDAP_TIMEOUT = int(os.environ.get("RDAP_TIMEOUT_SECONDS", "60"))
WAYBACK_TIMEOUT = int(os.environ.get("WAYBACK_TIMEOUT_SECONDS", "180"))
# Teto de URLs coletadas por execução do wayback (ver wayback_fetch.py) —
# limita o runtime por volume de dados em vez de depender só do timeout
# acima, que sempre pode ser insuficiente pra um domínio ainda maior.
WAYBACK_MAX_RECORDS = int(os.environ.get("WAYBACK_MAX_RECORDS", "200000"))
GAU_TIMEOUT = int(os.environ.get("GAU_TIMEOUT_SECONDS", "120"))
THEHARVESTER_TIMEOUT = int(os.environ.get("THEHARVESTER_TIMEOUT_SECONDS", "180"))
KATANA_TIMEOUT = int(os.environ.get("KATANA_TIMEOUT_SECONDS", "120"))
HTTPX_TIMEOUT = int(os.environ.get("HTTPX_TIMEOUT_SECONDS", "180"))
DNSX_TIMEOUT = int(os.environ.get("DNSX_TIMEOUT_SECONDS", "120"))
MASSCAN_TIMEOUT = int(os.environ.get("MASSCAN_TIMEOUT_SECONDS", "300"))
NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT_SECONDS", "300"))
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT_SECONDS", "300"))
NIKTO_TIMEOUT = int(os.environ.get("NIKTO_TIMEOUT_SECONDS", "240"))
WPSCAN_TIMEOUT = int(os.environ.get("WPSCAN_TIMEOUT_SECONDS", "600"))
GOWITNESS_TIMEOUT = int(os.environ.get("GOWITNESS_TIMEOUT_SECONDS", "120"))
DALFOX_TIMEOUT = int(os.environ.get("DALFOX_TIMEOUT_SECONDS", "300"))
KITERUNNER_TIMEOUT = int(os.environ.get("KITERUNNER_TIMEOUT_SECONDS", "300"))

# Notificação em achado crítico (Slack e/ou webhook genérico) — "fecha o
# loop" sem precisar ficar olhando a tela. Vazio nos dois = desligado
# (padrão). Basta configurar um dos dois canais (ou os dois). Severidade
# existe hoje no nuclei e no dalfox, mas o filtro é genérico por campo
# "severity" — uma ferramenta futura que grave esse campo já é coberta
# automaticamente.
NOTIFY_SEVERITIES = {
    s.strip().lower() for s in os.environ.get("NOTIFY_SEVERITIES", "critical").split(",") if s.strip()
}
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL", "")
NOTIFY_WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "")
# Só para montar um link clicável na notificação (ex: "http://vps.example.com:3000").
# Vazio = notificação sem link — o backend não sabe sua URL pública sozinho
# (pode estar atrás de proxy reverso, IP de VPS etc.), por isso é explícito.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

# Monitor básico de saúde da plataforma (cluster OpenSearch, worker Celery,
# fila, jobs travados) — roda em background dentro do próprio processo do
# backend (sem container/serviço novo) e reaproveita o mesmo Slack/webhook
# de achado crítico acima. <= 0 desliga o monitor inteiramente (loop nem
# inicia). Notifica só na transição de estado, não a cada checagem — ver
# health_monitor.py.
HEALTH_CHECK_INTERVAL_SECONDS = int(os.environ.get("HEALTH_CHECK_INTERVAL_SECONDS", "60"))
# Nº de tarefas esperando na fila do Celery (Redis) acima do qual soa alarme
# de fila represada (worker não dá conta / travou).
HEALTH_QUEUE_BACKLOG_THRESHOLD = int(os.environ.get("HEALTH_QUEUE_BACKLOG_THRESHOLD", "50"))
# Minutos que um job pode ficar "running" antes de ser considerado travado
# (ex: worker morreu no meio da execução sem atualizar o status).
HEALTH_STUCK_JOB_MINUTES = int(os.environ.get("HEALTH_STUCK_JOB_MINUTES", "60"))

# Recorrência de scans (alvos salvos com agendamento diário/semanal/mensal) —
# mesmo esquema do monitor de saúde acima: loop em background dentro do
# próprio processo do backend, sem serviço/container novo. <= 0 desliga o
# scheduler inteiramente. Precisão de disparo é de ~1 intervalo (não é cron
# de precisão de segundo) — ver README "Recorrência de scans".
RECURRENCE_CHECK_INTERVAL_SECONDS = int(os.environ.get("RECURRENCE_CHECK_INTERVAL_SECONDS", "60"))

# Shodan (dados passivos por IP: org/ISP, portas/banners já indexados pela
# Shodan, CVEs conhecidos) — enriquece sem gastar tempo de scan ativo. Vazio
# (padrão) = desligado inteiramente; nenhuma chamada à API é feita e nenhum
# job "shodan" é criado. Precisa de uma API key (mesmo do plano free) em
# https://account.shodan.io/.
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

# Censys (mesma ideia do Shodan acima: dado passivo por IP — ASN/org, WHOIS,
# software identificado por serviço) — outro motor de varredura, cobertura
# diferente da Shodan (um acha o que o outro não acha). Vazio (padrão) =
# desligado inteiramente. Token de acesso da Platform API em
# https://platform.censys.io/.
CENSYS_API_KEY = os.environ.get("CENSYS_API_KEY", "")

# WPScan (enumeração de plugins/temas/usuários do WordPress cruzada com a
# WPVulnDB) — diferente do Shodan/Censys acima, roda sempre (Fase 4, em toda
# URL viva); o próprio WPScan detecta se o alvo é WordPress ou não, e sai
# rápido quando não é. O token só habilita o cruzamento com a base de
# vulnerabilidades (sem ele, a enumeração de plugin/tema/usuário continua
# funcionando, só sem dado de CVE). Gere em https://wpscan.com/api/.
WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN", "")

# Gowitness (screenshot de cada URL viva, Fase 4) — desligado por padrão,
# diferente de Shodan/Censys o motivo aqui não é falta de API key: precisa
# de Chromium na imagem kali-tools (~300MB a mais) e da capability
# SYS_ADMIN no container efêmero (sandbox do Chrome não inicializa rodando
# como root sem ela) — nenhuma outra ferramenta do projeto pede isso. Ver
# README "Screenshots (Gowitness)" antes de ligar. Desde os "Perfis de scan
# por execução" (ver resolve_enabled_tools abaixo), isso só define o estado
# inicial do checklist de ferramentas — o usuário ainda pode ligar/desligar
# por scan independente deste valor.
GOWITNESS_ENABLED = bool(os.environ.get("GOWITNESS_ENABLED", "").strip())

# Dalfox (scanner de XSS, Fase 4) — desligado por padrão: na prática rende
# poucos achados (às vezes nenhum) pro custo de rodar em toda URL viva de
# todo scan; ative se quiser essa cobertura. Ver README "Dados do Dalfox".
# Mesma ressalva do Gowitness acima: só o default do checklist por scan.
DALFOX_ENABLED = bool(os.environ.get("DALFOX_ENABLED", "").strip())

# Kiterunner (content-discovery focado em API, Fase 4) — desligado por
# padrão, mesmo motivo do dalfox acima: custo de rodar em toda URL viva de
# todo scan pro achado que rende. Diferente do dalfox, não precisa de
# Chrome/capability nenhuma — é "gobuster com uma wordlist orientada a rotas
# de API" (só GET; o modo multi-método do kiterunner exige um schema
# kitebuilder .kite, não usado aqui). Ver README "Dados do Kiterunner".
# Mesma ressalva do Gowitness acima: só o default do checklist por scan.
KITERUNNER_ENABLED = bool(os.environ.get("KITERUNNER_ENABLED", "").strip())

# Ferramentas da Fase 4 sempre marcadas por padrão no checklist de "Perfis
# de scan por execução" (ver README) — as 3 opt-in acima entram também
# quando o *_ENABLED correspondente estiver ligado.
PHASE4_DEFAULT_TOOLS = ["gobuster", "nikto", "nuclei", "katana", "wpscan"]


def resolve_enabled_tools(enabled_tools: list[str] | None) -> list[str]:
    """None (campo enabled_tools omitido no request) reproduz o
    comportamento de sempre: as 5 sempre-ligadas + as opt-in que estiverem
    marcadas acima. Uma lista explícita (o checklist do formulário de scan)
    vale como está — os *_ENABLED só definem o default, não são mais um
    hard-gate; dá pra ligar dalfox numa execução mesmo com DALFOX_ENABLED
    vazio, e vice-versa."""
    if enabled_tools is not None:
        return list(enabled_tools)
    tools = list(PHASE4_DEFAULT_TOOLS)
    if DALFOX_ENABLED:
        tools.append("dalfox")
    if GOWITNESS_ENABLED:
        tools.append("gowitness")
    if KITERUNNER_ENABLED:
        tools.append("kiterunner")
    return tools
