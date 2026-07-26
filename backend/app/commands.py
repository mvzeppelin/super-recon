import pathlib
import shlex

from . import config

_WAYBACK_FETCH_SRC = (pathlib.Path(__file__).parent / "wayback_fetch.py").read_text()


def _quote_list(items: list[str]) -> str:
    return " ".join(shlex.quote(i) for i in items)


def build(tool: str, target: str, **kwargs) -> dict:
    """Monta a especificação de execução (cmd + flags do docker) para um tool
    simples de alvo único. Ferramentas com necessidades especiais (httpx em
    lote, nikto com arquivo) têm construção própria em tasks.py."""
    if tool == "assetfinder":
        return {"cmd": ["assetfinder", "-subs-only", target], "timeout": config.ASSETFINDER_TIMEOUT}

    if tool == "subfinder":
        return {"cmd": ["subfinder", "-d", target, "-oJ", "-silent"], "timeout": config.SUBFINDER_TIMEOUT}

    if tool == "sublist3r":
        return {"cmd": ["sublist3r", "-d", target, "-n"], "timeout": config.SUBLIST3R_TIMEOUT}

    if tool == "wayback":
        # Busca paginada própria em vez do waybackurls (ver wayback_fetch.py):
        # domínios com histórico gigantesco no Wayback Machine baixavam tudo
        # de uma vez só e estouravam o timeout sem devolver nada (visto na
        # prática com acme.com). Aqui o teto de registros limita o runtime
        # por volume de dados, e o resultado vai sendo escrito por página —
        # se o timeout ainda assim estourar, o parcial já coletado sobrevive
        # (ver docker_runner.run()).
        cmd = (
            f"python3 -c {shlex.quote(_WAYBACK_FETCH_SRC)} "
            f"{shlex.quote(target)} {config.WAYBACK_MAX_RECORDS} > urls.txt"
        )
        return {
            "cmd": ["bash", "-c", cmd],
            "output_file": "urls.txt",
            "timeout": config.WAYBACK_TIMEOUT,
        }

    if tool == "rdap_domain" or tool == "rdap_network":
        return {"cmd": ["rdap", target, "--json"], "timeout": config.RDAP_TIMEOUT}

    if tool == "masscan":
        ports = kwargs.get("ports", "1-1000")
        return {
            "cmd": ["masscan", target, "-p", ports, "--rate", "1000"],
            "cap_add": ["NET_RAW", "NET_ADMIN"],
            "timeout": config.MASSCAN_TIMEOUT,
        }

    if tool == "nmap":
        args = ["nmap", "-Pn", "-sV", "-oX", "-"]
        ports = kwargs.get("ports")
        if ports:
            args += ["-p", ports]
        args.append(target)
        return {"cmd": args, "timeout": config.NMAP_TIMEOUT}

    if tool == "gobuster":
        # wordlist_path (já resolvido por tasks.py, montado read-only no
        # container efêmero) tem prioridade — usado para wordlist customizada;
        # sem ele, cai no perfil common/big embutido na imagem do Kali.
        custom_path = kwargs.get("wordlist_path")
        profile = kwargs.get("wordlist_profile", "common")
        wordlist = custom_path or config.GOBUSTER_WORDLISTS.get(profile, config.GOBUSTER_WORDLISTS["common"])
        timeout = config.GOBUSTER_CUSTOM_TIMEOUT if custom_path else config.GOBUSTER_TIMEOUTS.get(profile, 300)
        spec = {
            "cmd": ["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "-r", "-t", "20"],
            "timeout": timeout,
        }
        if kwargs.get("extra_ro_mounts"):
            spec["extra_ro_mounts"] = kwargs["extra_ro_mounts"]
        return spec

    if tool == "nuclei":
        template_dirs = config.NUCLEI_TEMPLATE_DIRS.split(",")
        cmd = ["nuclei", "-u", target, "-j", "-silent"]
        for t in template_dirs:
            cmd += ["-t", t]
        return {"cmd": cmd, "timeout": config.NUCLEI_TIMEOUT}

    if tool == "amass":
        # -r com resolvers explícitos evita a fase de qualificação de
        # resolvers do amass v4, que trava com frequência em rede de container.
        return {
            "cmd": ["amass", "enum", "-d", target, "-r", "1.1.1.1,8.8.8.8", "-timeout", "2"],
            "timeout": config.AMASS_TIMEOUT,
        }

    if tool == "dnsenum":
        return {"cmd": ["dnsenum", "--noreverse", "--threads", "10", target], "timeout": config.DNSENUM_TIMEOUT}

    if tool == "dnsrecon":
        # "echo n |" responde automaticamente ao prompt interativo que o
        # dnsrecon faz quando detecta wildcard DNS durante o brute-force
        # (senão o processo trava esperando entrada no stdin); "n" = não
        # continuar o brute-force sob wildcard, evitando uma enxurrada de
        # falsos positivos (tudo "resolve" para o mesmo IP do wildcard).
        # O módulo de busca no Bing foi removido do comando: em teste real
        # contra um domínio real, ele devolveu subdomínios inventados
        # (fragmentos de URL mal interpretados, ex: "3ascanme.nmap.org" —
        # resíduo de "%3a" de um link nos resultados do Bing) — dado real
        # encontrado ao validar a ferramenta, não uma suposição.
        cmd = (
            f"echo n | dnsrecon -d {shlex.quote(target)} -t std,brt "
            f"-D /usr/share/dnsenum/dns.txt -j result.json"
        )
        return {
            "cmd": ["bash", "-c", cmd],
            "output_file": "result.json",
            "timeout": config.DNSRECON_TIMEOUT,
        }

    if tool == "gau":
        return {"cmd": ["bash", "-c", f"echo {shlex.quote(target)} | gau"], "timeout": config.GAU_TIMEOUT}

    if tool == "theharvester":
        return {
            "cmd": [
                "theHarvester", "-d", target, "-b", "crtsh,otx,urlscan,rapiddns,hackertarget", "-f", "result",
            ],
            "output_file": "result.json",
            "timeout": config.THEHARVESTER_TIMEOUT,
        }

    if tool == "katana":
        return {"cmd": ["katana", "-u", target, "-silent", "-depth", "2"], "timeout": config.KATANA_TIMEOUT}

    if tool == "wpscan":
        # -e vp,vt,u: só plugins/temas já sinalizados vulneráveis + usuários
        # (não é inventário completo — perfil rápido, focado em achado
        # acionável). Sem --force: se não for WordPress, sai sozinho (visto
        # na prática — nunca prompta interativamente em --format json, só
        # grava {"scan_aborted": "..."} no output_file e sai com exit != 0,
        # que o docker_runner ignora como sempre).
        cmd = [
            "wpscan", "--url", target, "--format", "json", "--output", "result.json",
            "--no-banner", "--random-user-agent", "--disable-tls-checks", "-e", "vp,vt,u",
        ]
        if config.WPSCAN_API_TOKEN:
            cmd += ["--api-token", config.WPSCAN_API_TOKEN]
        return {"cmd": cmd, "output_file": "result.json", "timeout": config.WPSCAN_TIMEOUT}

    if tool == "dalfox":
        # --skip-headless: evita depender de um Chrome/Chromium real (dalfox
        # usa chromedp internamente só para DOM XSS profundo) — testado ao
        # vivo, XSS refletido/verificado (o caso de uso principal) continua
        # funcionando sem headless, sem precisar da mesma capability SYS_ADMIN
        # que o gowitness paga.
        cmd = [
            "dalfox", "url", target, "--format", "json", "-o", "result.json",
            "--skip-headless", "--no-spinner", "--no-color",
        ]
        return {"cmd": cmd, "output_file": "result.json", "timeout": config.DALFOX_TIMEOUT}

    if tool == "kiterunner":
        # -A <wordlist>:<N>: usa a wordlist nomeada pré-baixada no build da
        # imagem (ver Dockerfile), truncada às N primeiras linhas — tamanho
        # fixo via .env (KITERUNNER_WORDLIST/KITERUNNER_WORDLIST_LINES), sem
        # seletor por scan (diferente do gobuster acima). --disable-precheck
        # pula o preflight de wildcard/host-discovery do kiterunner,
        # desnecessário aqui: o httpx da Fase 3 já confirmou que a URL está
        # viva antes da Fase 4 disparar qualquer ferramenta. Só GET: o modo
        # multi-método do kiterunner exige um schema kitebuilder (.kite via
        # -w), não usado aqui. --success-status-codes filtra a saída JSONL só
        # pros hits — sem isso, uma linha por caminho tentado (364k+ linhas
        # de ruído pra wordlist completa).
        wordlist_arg = f"{config.KITERUNNER_WORDLIST}:{config.KITERUNNER_WORDLIST_LINES}"
        cmd = [
            "kiterunner", "scan", target, "-A", wordlist_arg, "-o", "json",
            "-x", "5", "-j", "1",
            "--success-status-codes", "200,201,204,301,302,307,401,403",
            "--disable-precheck",
        ]
        return {"cmd": cmd, "timeout": config.KITERUNNER_TIMEOUT}

    raise ValueError(f"comando não definido para a ferramenta: {tool}")


def httpx_batch(hosts: list[str]) -> dict:
    payload = _quote_list(hosts)
    # -fr: segue redirects, então status_code reflete o destino final (uma
    # raiz que só redireciona 301->200 aparece como 200, não como 301).
    return {
        "cmd": ["bash", "-c", f"printf '%s\\n' {payload} | httpx -json -silent -fr"],
        "timeout": config.HTTPX_TIMEOUT,
    }


def dnsx_batch(hosts: list[str]) -> dict:
    payload = _quote_list(hosts)
    return {
        "cmd": ["bash", "-c", f"printf '%s\\n' {payload} | dnsx -silent -json -a"],
        "timeout": config.DNSX_TIMEOUT,
    }


def nikto(url: str) -> dict:
    return {
        "cmd": ["nikto", "-h", url, "-output", "result", "-Format", "xml", "-maxtime", "180s"],
        "output_file": "result.xml",
        "timeout": config.NIKTO_TIMEOUT,
    }


def gowitness(url: str) -> dict:
    # --chrome-path: sem isso o gowitness tenta baixar um Chrome sozinho
    # (sem rede de saída pro objetivo, e desperdiçaria isso em todo scan) —
    # usa o chromium já instalado na imagem. cap_add SYS_ADMIN é obrigatório:
    # sem ela o sandbox do Chrome não inicializa rodando como root (erro
    # "websocket url timeout reached"), única ferramenta do projeto que
    # precisa dessa capability.
    # --driver gorod: o driver padrão (chromedp) trava indefinidamente na
    # captura do screenshot dentro do container (a página carrega e os
    # metadados saem certos, só o Page.captureScreenshot via CDP nunca
    # retorna, até estourar o --timeout) — testado ao vivo, reproduzível.
    # O driver gorod (baseado na lib go-rod) não tem esse problema.
    cmd = [
        "gowitness", "scan", "single", "-u", url,
        "--write-jsonl", "--write-jsonl-file", "result.jsonl",
        "-s", "screenshots", "--screenshot-format", "jpeg",
        "--chrome-path", "/usr/bin/chromium",
        "--driver", "gorod",
    ]
    return {
        "cmd": cmd,
        "output_file": "result.jsonl",
        "cap_add": ["SYS_ADMIN"],
        "timeout": config.GOWITNESS_TIMEOUT,
    }
