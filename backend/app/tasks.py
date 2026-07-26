import ipaddress
import logging
import os
from datetime import datetime, timezone

import redis
from celery import chord, group

import parsers as parsers_module

from . import censys_client, commands, config, docker_runner, notifications, opensearch_client, shodan_client, util
from . import screenshots as screenshots_mod
from . import wordlists as wordlists_mod
from .celery_app import celery_app

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

_redis = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, password=config.REDIS_PASSWORD, db=1)

# Ferramentas de recon passivo disparadas direto do domínio informado (Fase 1).
# Várias delas fazem a mesma coisa (enumeração de subdomínio) por fontes
# diferentes — a soma é positiva, cada uma tende a achar algo que as outras
# não acham (ver decisão do usuário sobre isso).
DOMAIN_PHASE1_TOOLS = [
    "assetfinder", "subfinder", "sublist3r", "amass", "dnsenum", "dnsrecon",
    "rdap_domain", "wayback", "gau", "theharvester",
]


def _pick_core() -> int:
    if config.RECON_CPUS <= 1:
        return 0
    return _redis.incr("recon:core_rr") % config.RECON_CPUS


def _scan_cancelled(job_ctx: dict) -> bool:
    """True se o scan desse job_ctx foi marcado como cancelado (ver
    mark_scan_cancelled em opensearch_client.py, chamado por
    POST /clients/{client}/jobs/cancel-all). Checado no início de toda
    função que despacha a fase seguinte do pipeline — sem isso, o chord
    callback da fase atual ainda dispara a próxima mesmo com os jobs
    anteriores mortos à força (o Celery conta uma tarefa revogada como
    "concluída" pro chord), fazendo "cancelar tudo" não impedir processos
    novos de continuarem subindo (visto na prática)."""
    return opensearch_client.is_scan_cancelled(job_ctx["client"], job_ctx["scan_id"])


def _queue_job(job_ctx: dict, tool: str, target: str) -> str:
    """Registra a task como "queued" no momento em que é despachada para o
    Celery — antes de rodar, e possivelmente antes até de existir um worker
    livre para pegá-la. É isso que dá visibilidade real de "pendente" no
    painel do cliente, e permite cancelar algo que ainda nem começou."""
    return opensearch_client.queue_job(job_ctx["client"], job_ctx["scan_id"], tool, target)


def _resolved_enabled_tools(job_ctx: dict) -> list[str]:
    """job_ctx["enabled_tools"] já vem resolvido (nunca None) desde
    main.py/recurrence_scheduler.py — o fallback aqui é só uma rede de
    segurança pra job_ctx antigo/malformado (ex: scan disparado por um
    worker de versão anterior a "Perfis de scan por execução"). Checa
    "is None" e não truthiness: [] é um valor válido e intencional ("nenhuma
    ferramenta da Fase 4 nesse scan"), não pode cair no fallback como se
    fosse um job_ctx malformado."""
    enabled_tools = job_ctx.get("enabled_tools")
    return enabled_tools if enabled_tools is not None else config.PHASE4_DEFAULT_TOOLS


def _run_and_index(
    job_ctx: dict, tool: str, target: str, spec: dict, job_id: str,
    *, on_finished: "callable | None" = None, doc_transform: "callable | None" = None,
) -> dict:
    """Executa a spec de comando, parseia e indexa. Usado por todas as tasks.

    `job_id` é o id da própria task do Celery — usado como _id do documento
    em {client}-jobs, o que permite cancelar essa execução específica depois
    (POST /clients/{client}/jobs/{job_id}/cancel faz celery.control.revoke
    nesse mesmo id). Grava o job em etapas ("running" ao iniciar, de novo
    quando o container sobe com o container_id, "ok"/"error" ao terminar) —
    é isso que alimenta o indicador de execuções em andamento (GET
    /jobs/active) e a coluna de status na aba "jobs".

    `on_finished`/`doc_transform` são ganchos opcionais usados só pelo
    gowitness hoje (ver run_gowitness_task): `on_finished(local_dir)` repassa
    pro docker_runner.run() (salva o screenshot antes do diretório de troca
    ser apagado); `doc_transform(docs)` roda depois do parse, antes de
    indexar (anexa o screenshot_id nos docs — o parser não sabe de disco)."""
    client_name = job_ctx["client"]
    scan_id = job_ctx["scan_id"]
    core = _pick_core()
    started_at = _now_iso()

    opensearch_client.record_job(
        client_name=client_name, job_id=job_id, scan_id=scan_id, tool=tool, target=target,
        status="running", cpu_core=core, started_at=started_at,
    )

    def on_started(container_id: str) -> None:
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool=tool, target=target,
            status="running", container_id=container_id,
        )

    try:
        raw = docker_runner.run(
            spec["cmd"],
            cpuset=core,
            cap_add=spec.get("cap_add"),
            output_file=spec.get("output_file"),
            extra_ro_mounts=spec.get("extra_ro_mounts"),
            timeout=spec.get("timeout", 300),
            on_started=on_started,
            on_finished=on_finished,
        )
        docs = parsers_module.parse(tool, raw, client=client_name, scan_id=scan_id, target=target)
        if doc_transform:
            doc_transform(docs)
        count = opensearch_client.bulk_index(parsers_module.index_name(client_name, tool), docs)
        notifications.notify_findings(client_name, tool, target, docs)
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool=tool, target=target,
            status="ok", cpu_core=core, doc_count=count, finished_at=_now_iso(),
        )
        return {"tool": tool, "target": target, "count": count, "status": "ok"}
    except Exception as exc:  # noqa: BLE001 - queremos capturar qualquer falha de ferramenta/parser
        logger.exception("falha ao rodar %s em %s", tool, target)
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool=tool, target=target,
            status="error", cpu_core=core, error=str(exc), finished_at=_now_iso(),
        )
        return {"tool": tool, "target": target, "count": 0, "status": "error", "error": str(exc)}


@celery_app.task(name="recon.run_tool", bind=True)
def run_tool_task(self, job_ctx: dict, tool: str, target: str, job_id: str | None = None, **kwargs) -> dict:
    spec = commands.build(tool, target, **kwargs)
    return _run_and_index(job_ctx, tool, target, spec, job_id or self.request.id)


@celery_app.task(name="recon.run_httpx", bind=True)
def run_httpx_task(self, job_ctx: dict, hosts: list[str], target: str, job_id: str | None = None) -> dict:
    spec = commands.httpx_batch(hosts)
    return _run_and_index(job_ctx, "httpx", target, spec, job_id or self.request.id)


@celery_app.task(name="recon.run_dnsx", bind=True)
def run_dnsx_task(self, job_ctx: dict, hosts: list[str], target: str, job_id: str | None = None) -> dict:
    spec = commands.dnsx_batch(hosts)
    return _run_and_index(job_ctx, "dnsx", target, spec, job_id or self.request.id)


@celery_app.task(name="recon.run_nikto", bind=True)
def run_nikto_task(self, job_ctx: dict, url: str, job_id: str | None = None) -> dict:
    spec = commands.nikto(url)
    return _run_and_index(job_ctx, "nikto", url, spec, job_id or self.request.id)


@celery_app.task(name="recon.run_gowitness", bind=True)
def run_gowitness_task(self, job_ctx: dict, url: str, job_id: str | None = None) -> dict:
    """Screenshot de uma URL viva. O screenshot em si (arquivo binário) não
    passa pelo parser normal (raw_text) — sai do diretório de troca efêmero
    via on_finished (screenshots.persist) e é anexado ao doc já parseado via
    doc_transform, antes de indexar (ver _run_and_index)."""
    client_name = job_ctx["client"]
    spec = commands.gowitness(url)
    holder: dict = {}

    def on_finished(local_dir: str) -> None:
        src_dir = os.path.join(local_dir, "screenshots")
        files = os.listdir(src_dir) if os.path.isdir(src_dir) else []
        if files:
            holder["screenshot_id"] = screenshots_mod.persist(client_name, os.path.join(src_dir, files[0]))

    def doc_transform(docs: list[dict]) -> None:
        if docs and holder.get("screenshot_id"):
            docs[0]["screenshot_id"] = holder["screenshot_id"]

    return _run_and_index(
        job_ctx, "gowitness", url, spec, job_id or self.request.id,
        on_finished=on_finished, doc_transform=doc_transform,
    )


@celery_app.task(name="recon.run_shodan", bind=True)
def run_shodan_task(self, job_ctx: dict, ip: str, job_id: str | None = None) -> dict:
    """Consulta a Shodan Host API pra esse IP — dado passivo (org/ISP,
    portas/banners que a Shodan já tinha indexado, CVEs conhecidos), sem
    gastar tempo de scan ativo. Diferente das demais ferramentas, não sobe
    container Kali: é só uma chamada HTTPS direta (ver shodan_client.py).

    Três resultados possíveis, confirmados testando contra IPs reais (não
    só pela documentação): "ok" com achados = dado normal; "ok" sem achados
    = Shodan não tem esse IP indexado (404, não é erro); "error" = Shodan
    TEM dado sobre o IP mas o plano da API key não dá acesso a ele (403
    "Requires membership or higher" — visto no plano free: funciona pra
    alguns IPs, falha pra outros, sem padrão previsível). Esse último é
    registrado como erro de propósito, não como "sem achado" — senão
    passaria a impressão enganosa de "verificamos e não tinha nada"."""
    client_name = job_ctx["client"]
    scan_id = job_ctx["scan_id"]
    job_id = job_id or self.request.id
    opensearch_client.record_job(
        client_name=client_name, job_id=job_id, scan_id=scan_id, tool="shodan", target=ip,
        status="running", started_at=_now_iso(),
    )
    try:
        raw = shodan_client.lookup(ip)
    except shodan_client.NotFoundError:
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool="shodan", target=ip,
            status="ok", doc_count=0, finished_at=_now_iso(),
        )
        return {"tool": "shodan", "target": ip, "count": 0, "status": "ok"}
    except shodan_client.PlanRequiredError as exc:
        logger.warning("shodan: plano da API key não dá acesso a %s: %s", ip, exc)
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool="shodan", target=ip,
            status="error", error=str(exc), finished_at=_now_iso(),
        )
        return {"tool": "shodan", "target": ip, "count": 0, "status": "error", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - queremos capturar qualquer falha de rede/parser
        logger.exception("falha ao consultar shodan em %s", ip)
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool="shodan", target=ip,
            status="error", error=str(exc), finished_at=_now_iso(),
        )
        return {"tool": "shodan", "target": ip, "count": 0, "status": "error", "error": str(exc)}

    docs = parsers_module.parse("shodan", raw, client=client_name, scan_id=scan_id, target=ip)
    count = opensearch_client.bulk_index(parsers_module.index_name(client_name, "shodan"), docs)
    notifications.notify_findings(client_name, "shodan", ip, docs)
    opensearch_client.record_job(
        client_name=client_name, job_id=job_id, scan_id=scan_id, tool="shodan", target=ip,
        status="ok", doc_count=count, finished_at=_now_iso(),
    )
    return {"tool": "shodan", "target": ip, "count": count, "status": "ok"}


@celery_app.task(name="recon.run_censys", bind=True)
def run_censys_task(self, job_ctx: dict, ip: str, job_id: str | None = None) -> dict:
    """Consulta a Censys Platform API pra esse IP — mesma ideia do
    run_shodan_task (dado passivo por IP, sem container Kali), mas mais
    simples: diferente da Shodan, a Censys sempre responde 200 (testado na
    prática), então não existe distinção "sem dado" vs "erro de plano" —
    IP sem serviço encontrado só gera 0 docs, igual ao nmap sem portas."""
    client_name = job_ctx["client"]
    scan_id = job_ctx["scan_id"]
    job_id = job_id or self.request.id
    opensearch_client.record_job(
        client_name=client_name, job_id=job_id, scan_id=scan_id, tool="censys", target=ip,
        status="running", started_at=_now_iso(),
    )
    try:
        raw = censys_client.lookup(ip)
        docs = parsers_module.parse("censys", raw, client=client_name, scan_id=scan_id, target=ip)
        count = opensearch_client.bulk_index(parsers_module.index_name(client_name, "censys"), docs)
        notifications.notify_findings(client_name, "censys", ip, docs)
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool="censys", target=ip,
            status="ok", doc_count=count, finished_at=_now_iso(),
        )
        return {"tool": "censys", "target": ip, "count": count, "status": "ok"}
    except Exception as exc:  # noqa: BLE001 - queremos capturar qualquer falha de rede/parser
        logger.exception("falha ao consultar censys em %s", ip)
        opensearch_client.record_job(
            client_name=client_name, job_id=job_id, scan_id=scan_id, tool="censys", target=ip,
            status="error", error=str(exc), finished_at=_now_iso(),
        )
        return {"tool": "censys", "target": ip, "count": 0, "status": "error", "error": str(exc)}


@celery_app.task(name="recon.subdomain_ip_recon")
def subdomain_ip_recon_task(_results, job_ctx: dict, ip: str) -> dict:
    """Callback do chord [rdap_network, masscan] disparado por
    _dispatch_subdomain_ip_recon — mesma lógica do phase2_ip_task (masscan
    descobre as portas abertas, nmap escaneia só elas em vez do top-1000
    padrão), sem repetir o httpx: o hostname que resolve pra esse IP já foi
    testado na Fase 3, rodar de novo no IP puro seria trabalho duplicado."""
    if _scan_cancelled(job_ctx):
        return {"ip": ip, "status": "cancelled"}
    client_name = job_ctx["client"]
    ports = opensearch_client.query_masscan_ports(client_name, ip)
    ports_str = ",".join(str(p) for p in ports) if ports else None
    run_tool_task.delay(job_ctx, "nmap", ip, job_id=_queue_job(job_ctx, "nmap", ip), ports=ports_str)
    return {"ip": ip}


def _is_scannable_ip(ip: str) -> bool:
    """Descarta IP privado/loopback/link-local — visto na prática com um
    alvo real (vulnweb.com): um subdomínio ("localhost.vulnweb.com") resolve
    de propósito para 127.0.0.1. Sem esse filtro, masscan/nmap escaneariam a
    própria infra de scanning (o container do Kali, ou outros containers na
    mesma rede docker) em vez do alvo do cliente — um subdomínio malicioso/
    mal-configurado apontando pra dentro não deve virar porta de entrada
    pra escanear rede interna."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast)


def _dispatch_subdomain_ip_recon(job_ctx: dict, target: str) -> None:
    """Estende nmap/masscan/rdap_network pros IPs dos subdomínios, não só o
    IP do domínio raiz — sem isso, um subdomínio hospedado num IP diferente
    (outro provedor/CDN) nunca era escaneado por porta, só o host raiz do
    domínio. dnsx (Fase 3) é o primeiro ponto em que sabemos o IP de cada
    subdomínio, por isso só dá pra disparar isso na Fase 4. Dedup pelo IP
    (não pelo hostname) evita escanear a mesma máquina várias vezes — comum
    vários subdomínios resolverem pro mesmo host/CDN. Exclui o IP do domínio
    raiz (já coberto pelo nmap/rdap_network da Fase 3) e qualquer IP não
    roteável publicamente (ver _is_scannable_ip); no-op para alvo IP puro
    (esse fluxo não roda dnsx, então query_dnsx_ips já devolve vazio)."""
    client_name = job_ctx["client"]
    ips = opensearch_client.query_dnsx_ips(client_name, target)
    if not util.is_ip_or_cidr(target):
        ips.discard(util.resolve_ip(target))

    skipped = {ip for ip in ips if not _is_scannable_ip(ip)}
    if skipped:
        logger.warning(
            "ignorando IP(s) não-públicos resolvidos por subdomínio de %s (cliente=%s): %s",
            target, client_name, sorted(skipped),
        )
    for ip in sorted(ips - skipped):
        phase1_tasks = [
            run_tool_task.s(job_ctx, "rdap_network", ip, job_id=_queue_job(job_ctx, "rdap_network", ip)),
            run_tool_task.s(job_ctx, "masscan", ip, job_id=_queue_job(job_ctx, "masscan", ip)),
        ]
        if config.SHODAN_API_KEY:
            phase1_tasks.append(run_shodan_task.s(job_ctx, ip, job_id=_queue_job(job_ctx, "shodan", ip)))
        if config.CENSYS_API_KEY:
            phase1_tasks.append(run_censys_task.s(job_ctx, ip, job_id=_queue_job(job_ctx, "censys", ip)))
        chord(group(phase1_tasks))(subdomain_ip_recon_task.s(job_ctx, ip))


# Teto de subcaminhos por URL que disparam wpscan a mais (ver
# gobuster_wpscan_followup_task) — um gobuster com muitos hits não pode virar
# dezenas de execuções de wpscan (cada uma pode levar minutos).
_GOBUSTER_WPSCAN_MAX_SUBPATHS = 5


def _looks_like_directory(path: str) -> bool:
    """Sem extensão de arquivo no último segmento do caminho (ex: "/blog",
    não "/robots.txt" ou "/config.php") — heurística pra separar candidatos
    reais a uma raiz de aplicação (onde um WordPress à parte poderia estar
    instalado) de arquivos soltos que o gobuster também encontra."""
    last_segment = path.rstrip("/").rsplit("/", 1)[-1]
    return "." not in last_segment


@celery_app.task(name="recon.gobuster_wpscan_followup")
def gobuster_wpscan_followup_task(_result, job_ctx: dict, url: str) -> dict:
    """Depois que o gobuster termina numa URL, roda wpscan também nos
    subcaminhos que parecem diretório — cobre o caso de um WordPress
    instalado numa subpasta (ex: http://site.com/blog) em vez da raiz, que a
    Fase 4 sozinha não alcançaria (ela só roda no que o httpx achou vivo,
    tipicamente a raiz de cada host)."""
    if _scan_cancelled(job_ctx):
        return {"url": url, "status": "cancelled"}
    if "wpscan" not in _resolved_enabled_tools(job_ctx):
        # Esse scan desligou wpscan explicitamente (ver "Perfis de scan por
        # execução") — o follow-up não pode rodá-lo por baixo dos panos.
        return {"url": url, "status": "wpscan_disabled"}
    client_name = job_ctx["client"]
    scan_id = job_ctx["scan_id"]
    hits = opensearch_client.query_gobuster_hits(client_name, scan_id, url)

    subpath_urls = []
    seen = {url}
    for hit in hits:
        hit_url = hit.get("url")
        path = hit.get("path") or ""
        if not hit_url or hit_url in seen or not _looks_like_directory(path):
            continue
        seen.add(hit_url)
        subpath_urls.append(hit_url)
        if len(subpath_urls) >= _GOBUSTER_WPSCAN_MAX_SUBPATHS:
            break

    subtasks = [
        run_tool_task.s(job_ctx, "wpscan", subpath_url, job_id=_queue_job(job_ctx, "wpscan", subpath_url))
        for subpath_url in subpath_urls
    ]
    if subtasks:
        group(subtasks).apply_async()
    return {"url": url, "subpaths_checked": len(subtasks)}


@celery_app.task(name="recon.phase4_dispatch")
def phase4_dispatch_task(_results, job_ctx: dict, target: str) -> dict:
    """Fase 4: para cada URL viva (status 200) encontrada na Fase 3 (httpx),
    dispara em paralelo o subconjunto de gobuster/nikto/nuclei/katana/wpscan/
    dalfox/gowitness/kiterunner marcado em job_ctx["enabled_tools"] — ver
    "Perfis de scan por execução" no README: a lista já vem resolvida desde
    main.py/recurrence_scheduler.py (config.resolve_enabled_tools), sempre as
    5 "tradicionais" mais as opt-in que estiverem no checklist daquele scan
    (não mais um hard-gate global via *_ENABLED). O próprio wpscan detecta se
    a URL é WordPress ou não (sem gate por tech-detection aqui) — se estiver
    no checklist, roda em toda URL viva, igual às demais. Quando o gobuster
    termina, um follow-up (gobuster_wpscan_followup_task) roda wpscan de novo
    nos subcaminhos que parecem diretório — cobre um WordPress instalado numa
    subpasta (ex: /blog) que essa fase sozinha não alcançaria (só dispara se
    wpscan também estiver habilitado nesse scan). Também estende nmap/
    masscan/rdap_network pros IPs dos subdomínios (ver
    _dispatch_subdomain_ip_recon). É o fim automático do pipeline
    (fire-and-forget: não há Fase 5 automática)."""
    if _scan_cancelled(job_ctx):
        return {"target": target, "status": "cancelled"}
    client_name = job_ctx["client"]
    _dispatch_subdomain_ip_recon(job_ctx, target)
    urls = opensearch_client.query_alive_urls(client_name, target)
    wordlist_profile = job_ctx.get("gobuster_wordlist", "common")
    gobuster_kwargs = {"wordlist_profile": wordlist_profile}

    if wordlist_profile == "custom":
        custom_id = job_ctx.get("gobuster_custom_wordlist_id")
        resolved = wordlists_mod.resolve_for_run(client_name, custom_id) if custom_id else None
        if resolved:
            host_path, container_path = resolved
            gobuster_kwargs = {
                "wordlist_path": container_path,
                "extra_ro_mounts": {host_path: container_path},
            }
        else:
            # Wordlist removida (ou nunca existiu) entre o disparo do scan e
            # a Fase 4 — não trava o pipeline inteiro, cai pro perfil padrão.
            logger.warning(
                "wordlist customizada %s não encontrada para %s — usando perfil 'common'", custom_id, client_name,
            )
            gobuster_kwargs = {"wordlist_profile": "common"}

    enabled_tools = _resolved_enabled_tools(job_ctx)

    tasks = []
    for url in urls:
        if "gobuster" in enabled_tools:
            gobuster_sig = run_tool_task.s(
                job_ctx, "gobuster", url, job_id=_queue_job(job_ctx, "gobuster", url), **gobuster_kwargs,
            )
            gobuster_sig.link(gobuster_wpscan_followup_task.s(job_ctx, url))
            tasks.append(gobuster_sig)
        if "nikto" in enabled_tools:
            tasks.append(run_nikto_task.s(job_ctx, url, job_id=_queue_job(job_ctx, "nikto", url)))
        if "nuclei" in enabled_tools:
            tasks.append(run_tool_task.s(job_ctx, "nuclei", url, job_id=_queue_job(job_ctx, "nuclei", url)))
        if "katana" in enabled_tools:
            tasks.append(run_tool_task.s(job_ctx, "katana", url, job_id=_queue_job(job_ctx, "katana", url)))
        if "wpscan" in enabled_tools:
            tasks.append(run_tool_task.s(job_ctx, "wpscan", url, job_id=_queue_job(job_ctx, "wpscan", url)))
        if "dalfox" in enabled_tools:
            tasks.append(run_tool_task.s(job_ctx, "dalfox", url, job_id=_queue_job(job_ctx, "dalfox", url)))
        if "gowitness" in enabled_tools:
            tasks.append(run_gowitness_task.s(job_ctx, url, job_id=_queue_job(job_ctx, "gowitness", url)))
        if "kiterunner" in enabled_tools:
            tasks.append(
                run_tool_task.s(job_ctx, "kiterunner", url, job_id=_queue_job(job_ctx, "kiterunner", url))
            )

    if tasks:
        group(tasks).apply_async()

    return {"target": target, "alive_urls": len(urls)}


@celery_app.task(name="recon.phase2_domain")
def phase2_domain_task(_results, job_ctx: dict, domain: str) -> dict:
    """Fase 2 (domínio): consolida subdomínios encontrados na Fase 1 e dispara
    a Fase 3 (httpx + dnsx nos subdomínios; nmap + rdap do bloco de IP no IP
    resolvido do domínio raiz). O rdap num IP já devolve o bloco (CIDR) que
    contém esse IP — não precisamos calcular o /16 manualmente, o RIR resolve
    isso pra gente (ver rdap_bloco.json de exemplo)."""
    if _scan_cancelled(job_ctx):
        return {"domain": domain, "status": "cancelled"}
    client_name = job_ctx["client"]
    subdomains = opensearch_client.query_subdomains(client_name, domain)
    hosts = sorted({domain, *subdomains})

    phase3 = [
        run_httpx_task.s(job_ctx, hosts, domain, job_id=_queue_job(job_ctx, "httpx", domain)),
        run_dnsx_task.s(job_ctx, hosts, domain, job_id=_queue_job(job_ctx, "dnsx", domain)),
    ]

    ip = util.resolve_ip(domain)
    if ip:
        phase3.append(run_tool_task.s(job_ctx, "nmap", ip, job_id=_queue_job(job_ctx, "nmap", ip)))
        phase3.append(
            run_tool_task.s(job_ctx, "rdap_network", ip, job_id=_queue_job(job_ctx, "rdap_network", ip))
        )
        if config.SHODAN_API_KEY:
            phase3.append(run_shodan_task.s(job_ctx, ip, job_id=_queue_job(job_ctx, "shodan", ip)))
        if config.CENSYS_API_KEY:
            phase3.append(run_censys_task.s(job_ctx, ip, job_id=_queue_job(job_ctx, "censys", ip)))

    chord(group(phase3))(phase4_dispatch_task.s(job_ctx, domain))
    return {"domain": domain, "hosts": len(hosts), "resolved_ip": ip}


@celery_app.task(name="recon.phase2_ip")
def phase2_ip_task(_results, job_ctx: dict, ip: str) -> dict:
    """Fase 2 (IP): usa as portas abertas do masscan para direcionar o nmap,
    e dispara httpx diretamente no IP (Fase 3)."""
    if _scan_cancelled(job_ctx):
        return {"ip": ip, "status": "cancelled"}
    client_name = job_ctx["client"]
    ports = opensearch_client.query_masscan_ports(client_name, ip)
    ports_str = ",".join(str(p) for p in ports) if ports else None

    phase3 = [
        run_tool_task.s(job_ctx, "nmap", ip, job_id=_queue_job(job_ctx, "nmap", ip), ports=ports_str),
        run_httpx_task.s(job_ctx, [ip], ip, job_id=_queue_job(job_ctx, "httpx", ip)),
    ]

    chord(group(phase3))(phase4_dispatch_task.s(job_ctx, ip))
    return {"ip": ip, "ports_found": len(ports)}


@celery_app.task(name="recon.orchestrate_scan")
def orchestrate_scan_task(job_ctx: dict, targets: list[str]) -> dict:
    dispatched = {"domains": [], "ips": []}
    for target in targets:
        if util.is_ip_or_cidr(target):
            phase1_tasks = [
                run_tool_task.s(job_ctx, "rdap_network", target, job_id=_queue_job(job_ctx, "rdap_network", target)),
                run_tool_task.s(job_ctx, "masscan", target, job_id=_queue_job(job_ctx, "masscan", target)),
            ]
            if config.SHODAN_API_KEY:
                phase1_tasks.append(run_shodan_task.s(job_ctx, target, job_id=_queue_job(job_ctx, "shodan", target)))
            if config.CENSYS_API_KEY:
                phase1_tasks.append(run_censys_task.s(job_ctx, target, job_id=_queue_job(job_ctx, "censys", target)))
            chord(group(phase1_tasks))(phase2_ip_task.s(job_ctx, target))
            dispatched["ips"].append(target)
        else:
            phase1 = group(
                run_tool_task.s(job_ctx, tool, target, job_id=_queue_job(job_ctx, tool, target))
                for tool in DOMAIN_PHASE1_TOOLS
            )
            chord(phase1)(phase2_domain_task.s(job_ctx, target))
            dispatched["domains"].append(target)

    return dispatched
