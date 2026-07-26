import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import NotFoundError, RequestError

from . import config, risk_score

# Caracteres com significado especial na sintaxe do query_string (Lucene) —
# escapados para tratar a busca livre como texto literal, não como uma
# expressão de busca (senão "a (b)" ou "c:d" quebram a query ou mudam de
# comportamento de forma surpreendente para quem só queria buscar um texto).
_QS_SPECIAL_CHARS = re.compile(r'([+\-=&|><!(){}\[\]^"~*?:\\/])')


def _contains_query(q: str) -> dict:
    """Busca livre como "contém a string" em qualquer parte do valor, não só
    match exato — campos keyword (subdomain, url, host, ip...) só batiam com
    o valor inteiro (buscar "xxx" não achava "xxx.acme.com", só o valor
    completo achava). Envolver em wildcards nas duas pontas resolve isso;
    analyze_wildcard mantém o comportamento correto em campos "text"
    analisados (description, registrant etc.), casando contra os tokens."""
    escaped = _QS_SPECIAL_CHARS.sub(r"\\\1", q)
    return {"query_string": {"query": f"*{escaped}*", "analyze_wildcard": True}}

_client = None


def client() -> OpenSearch:
    global _client
    if _client is None:
        _client = OpenSearch(
            hosts=[{"host": config.OPENSEARCH_HOST, "port": config.OPENSEARCH_PORT}],
            http_auth=(config.OPENSEARCH_USER, config.OPENSEARCH_PASSWORD),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
        )
    return _client


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def bulk_index(index: str, docs: list[dict]) -> int:
    if not docs:
        return 0
    actions = ({"_index": index, "_source": doc} for doc in docs)
    success, _errors = helpers.bulk(client(), actions, raise_on_error=False)
    return success


def delete_findings(client_name: str, suffix: str, ids: list[str]) -> int:
    """Remove documentos específicos de um índice pelo _id (ex: descartar um
    achado que é falso positivo, sem afetar o resto dos achados). ids que não
    existem (mais) são ignorados silenciosamente — raise_on_error=False evita
    que um id já removido por outra chamada derrube a operação inteira."""
    index = f"{client_name}-{suffix}"
    actions = ({"_op_type": "delete", "_index": index, "_id": doc_id} for doc_id in ids)
    success, _errors = helpers.bulk(client(), actions, raise_on_error=False)
    return success


def _safe_search_with_id(index: str, body: dict) -> list[dict]:
    """Igual _safe_search, mas mantém o _id de cada doc — necessário pra
    telas que renderizam achados de índices variados junto (ex: DataTable
    usa row._id como key/seleção), diferente da maioria dos usos de
    _safe_search, que só extrai um campo específico do _source."""
    try:
        resp = client().search(index=index, body=body)
    except NotFoundError:
        return []
    return [{**hit["_source"], "_id": hit["_id"]} for hit in resp["hits"]["hits"]]


def _safe_search(index: str, body: dict) -> list[dict]:
    try:
        resp = client().search(index=index, body=body)
    except NotFoundError:
        return []
    return [hit["_source"] for hit in resp["hits"]["hits"]]


def query_subdomains(client_name: str, domain: str) -> list[str]:
    hits = _safe_search(
        f"{client_name}-subdomains",
        {"query": {"term": {"domain": domain}}, "size": 10000, "_source": ["subdomain"]},
    )
    return sorted({h["subdomain"] for h in hits if h.get("subdomain")})


def query_masscan_ports(client_name: str, ip: str) -> list[int]:
    _refresh_index(f"{client_name}-masscan")
    hits = _safe_search(
        f"{client_name}-masscan",
        {"query": {"term": {"ip": ip}}, "size": 10000, "_source": ["port"]},
    )
    return sorted({h["port"] for h in hits if h.get("port")})


def _refresh_index(index: str) -> None:
    """Força o índice a ficar imediatamente pesquisável. bulk_index() não usa
    refresh=True por padrão (o refresh automático do OpenSearch não é
    instantâneo) — sem isso, uma consulta que roda logo depois do callback
    de uma fase anterior (chord/link) pode não ver documentos gravados
    milissegundos antes, mesmo já existindo. Usado só nos pontos em que uma
    fase de dispatch decide o que fazer a seguir com base num resultado
    indexado por outra tarefa da mesma fase."""
    try:
        client().indices.refresh(index=index)
    except NotFoundError:
        pass


def query_dnsx_ips(client_name: str, target: str) -> set[str]:
    """IPs de todos os hosts resolvidos pelo dnsx para esse domínio (domínio
    raiz + subdomínios, já que dnsx roda em lote sobre os dois — ver
    phase2_domain_task). Alimenta a extensão de nmap/masscan/rdap_network
    pros IPs dos subdomínios, não só o do domínio raiz (ver
    _dispatch_subdomain_ip_recon em tasks.py). Como target aqui é sempre um
    domínio (dnsx não roda no fluxo de alvo IP puro), um IP puro devolve
    conjunto vazio naturalmente — nada a estender nesse caso."""
    _refresh_index(f"{client_name}-dns")
    hits = _safe_search(
        f"{client_name}-dns",
        {"query": {"term": {"target": target}}, "size": 10000, "_source": ["ips"]},
    )
    ips: set[str] = set()
    for hit in hits:
        ips.update(hit.get("ips") or [])
    return ips


def find_subdomains_for_ip(client_name: str, domain: str, ip: str) -> list[str]:
    """Quais subdomínios de `domain` (resolvidos pelo dnsx) apontam pra esse
    IP — usado pra explicar a origem de um achado por IP (ex: nmap/shodan/
    censys) que não é o IP do domínio raiz: "veio do subdomínio X" em vez de
    aparecer solto sem explicação (ver GET /clients/{client}/ip-provenance)."""
    hits = _safe_search(
        f"{client_name}-dns",
        {"query": {"term": {"target": domain}}, "size": 500, "_source": ["subdomain", "ips"]},
    )
    return sorted({h["subdomain"] for h in hits if h.get("subdomain") and ip in (h.get("ips") or [])})


def query_gobuster_hits(client_name: str, scan_id: str, target: str) -> list[dict]:
    """Achados do gobuster (status 200) para uma URL específica de um scan —
    usado pra decidir se algum subcaminho merece ferramentas adicionais (ver
    gobuster_wpscan_followup_task em tasks.py: um WordPress pode estar numa
    subpasta, ex: /blog, em vez da raiz que a Fase 4 já cobre)."""
    _refresh_index(f"{client_name}-gobuster")
    return _safe_search(
        f"{client_name}-gobuster",
        {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"scan_id": scan_id}},
                        {"term": {"target": target}},
                        {"term": {"status_code": 200}},
                    ]
                }
            },
            "size": 500,
            "_source": ["url", "path"],
        },
    )


def query_alive_urls(client_name: str, target: str) -> list[str]:
    """URLs que valem a pena investigar mais a fundo (gobuster/nikto/nuclei/
    katana): qualquer host que o httpx conseguiu obter resposta (código
    200/301/403/404/500...), não só quem responde 200 na raiz.

    Um 404 na raiz não significa "morto" — só que não tem index; é
    exatamente esse tipo de host que o gobuster existe pra investigar (acha
    caminho vivo que não está linkado em lugar nenhum). Filtrar por 200 aqui
    descartaria esse caso e boa parte do valor do gobuster/nikto/nuclei."""
    _refresh_index(f"{client_name}-httpx")
    hits = _safe_search(
        f"{client_name}-httpx",
        {
            "query": {"bool": {"filter": [{"term": {"target": target}}, {"term": {"alive": True}}]}},
            "size": 10000,
            "_source": ["url"],
        },
    )
    return sorted({h["url"] for h in hits if h.get("url")})


def delete_client(client_name: str) -> bool:
    """Remove todos os índices do cliente ({client_name}-*). Retorna False se
    o cliente não tinha nenhum índice (nada para apagar)."""
    if not list_client_indices(client_name):
        return False
    try:
        client().indices.delete(index=f"{client_name}-*")
    except NotFoundError:
        return False
    return True


def clear_client_data(client_name: str) -> bool:
    """Apaga todos os índices do cliente (achados + histórico de execuções),
    igual a delete_client, mas recria na sequência um índice {client_name}-jobs
    vazio — o suficiente para o cliente continuar aparecendo em list_clients()
    (que enumera clientes por essa convenção), só que zerado, como se fosse
    recém-criado. Retorna False se o cliente não tinha nenhum índice."""
    if not list_client_indices(client_name):
        return False
    try:
        client().indices.delete(index=f"{client_name}-*")
    except NotFoundError:
        return False
    # index_patterns "*-jobs" do template é aplicado automaticamente na criação.
    client().indices.create(index=f"{client_name}-jobs")
    return True


def list_clients() -> list[str]:
    try:
        indices = client().cat.indices(index="*-jobs", format="json")
    except NotFoundError:
        return []
    suffix = "-jobs"
    names = {idx["index"][: -len(suffix)] for idx in indices if idx["index"].endswith(suffix)}
    return sorted(names)


def list_client_indices(client_name: str) -> list[dict]:
    try:
        indices = client().cat.indices(index=f"{client_name}-*", format="json")
    except NotFoundError:
        return []
    prefix = f"{client_name}-"
    items = [
        {"suffix": idx["index"][len(prefix):], "doc_count": int(idx.get("docs.count") or 0)}
        for idx in indices
        if idx["index"].startswith(prefix)
    ]
    return sorted(items, key=lambda i: i["suffix"])


# suffix -> campo(s) que identificam "o host/IP/URL que esse achado é sobre"
# — nomenclatura inconsistente entre ferramentas (host vs url vs ip vs
# subdomain vs hostname), sem convenção compartilhada no projeto; mapa fixo
# construído na mão. "rdap-network" fica de fora (faixa CIDR, não campo
# exato — tratado à parte em find_asset). Índices de metadado (jobs, scans,
# scan-schedules, wordlists) também ficam de fora: não são achados sobre um
# host/IP.
_ASSET_MATCH_FIELDS = {
    "subdomains": ["subdomain"],
    "dns": ["subdomain", "ips"],
    "httpx": ["host", "url"],
    "gobuster": ["url"],
    "kiterunner": ["url"],
    "dalfox": ["url"],
    "nuclei": ["host"],
    "nikto": ["host"],
    "wpscan": ["url"],
    "gowitness": ["url", "final_url"],
    "katana": ["url", "domain"],
    "wayback": ["url", "domain"],
    "nmap": ["ip", "hostname"],
    "masscan": ["ip"],
    "shodan": ["ip", "hostnames"],
    "censys": ["ip"],
    "rdap-domain": ["domain"],
    "harvester": ["value"],
}

# Campos mapeados como tipo "ip" no OpenSearch (não "keyword") — um "term"
# contra um deles rejeita a busca inteira com erro 400 se o valor não for um
# IP válido (diferente de um mismatch silencioso de tipo, que é o comum).
# Só entram no "should" quando o valor buscado já é um IP.
_IP_TYPED_FIELDS = {"ip", "ips"}


def find_asset(client_name: str, value: str) -> dict[str, list[dict]]:
    """Tudo que qualquer ferramenta achou sobre um valor exato (subdomínio,
    IP ou URL) — varre cada índice populado do cliente com o(s) campo(s)
    certo(s) pra esse índice (ver _ASSET_MATCH_FIELDS), mesmo padrão de loop
    por índice já usado em delete_scan. "rdap-network" é tratado à parte
    (faixa CIDR: o valor cai entre start_address e end_address, não um
    campo exato)."""
    populated = {i["suffix"] for i in list_client_indices(client_name)}
    results: dict[str, list[dict]] = {}

    is_ip = True
    try:
        ipaddress.ip_address(value)
    except ValueError:
        is_ip = False

    for suffix, fields in _ASSET_MATCH_FIELDS.items():
        if suffix not in populated:
            continue
        usable_fields = [f for f in fields if f not in _IP_TYPED_FIELDS or is_ip]
        if not usable_fields:
            continue
        should = [{"term": {f: value}} for f in usable_fields]
        hits = _safe_search_with_id(
            f"{client_name}-{suffix}",
            {"query": {"bool": {"should": should, "minimum_should_match": 1}}, "size": 200},
        )
        if hits:
            results[suffix] = hits

    if "rdap-network" in populated and is_ip:
        hits = _safe_search_with_id(
            f"{client_name}-rdap-network",
            {
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"start_address": {"lte": value}}},
                            {"range": {"end_address": {"gte": value}}},
                        ]
                    }
                },
                "size": 200,
            },
        )
        if hits:
            results["rdap-network"] = hits

    return results


def search_findings(
    client_name: str,
    suffix: str,
    *,
    q: str | None = None,
    filters: dict | None = None,
    page: int = 1,
    size: int = 25,
    sort_field: str = "@timestamp",
    sort_order: str = "desc",
) -> dict:
    index = f"{client_name}-{suffix}"
    must = [_contains_query(q)] if q else []
    # Cada valor pode ser uma string (filtro de valor único, como sempre foi)
    # ou uma lista (múltiplos valores pro mesmo campo, ex: status=queued OU
    # status=running) — "terms" cobre os dois casos: com lista de 1 item se
    # comporta exatamente igual ao "term" de antes, sem mudar nada pra quem
    # já passava valor único.
    filter_clauses = [
        {"terms": {k: v if isinstance(v, list) else [v]}} for k, v in (filters or {}).items()
    ]

    query = {"bool": {"must": must, "filter": filter_clauses}} if (must or filter_clauses) else {"match_all": {}}
    body = {
        "query": query,
        "from": max(page - 1, 0) * size,
        "size": size,
        "sort": [{sort_field: {"order": sort_order}}],
    }
    try:
        resp = client().search(index=index, body=body)
    except NotFoundError:
        return {"total": 0, "page": page, "size": size, "items": []}
    except RequestError:
        # Provavelmente ordenação por um campo "text" (não indexado para
        # sort, ex: description/registrant/org/error) — refaz sem ordenar em
        # vez de devolver erro para o usuário.
        body.pop("sort", None)
        resp = client().search(index=index, body=body)

    total = resp["hits"]["total"]["value"]
    items = [{**hit["_source"], "_id": hit["_id"]} for hit in resp["hits"]["hits"]]
    return {"total": total, "page": page, "size": size, "items": items}


def severity_summary(client_name: str, suffix: str, *, q: str | None = None, filters: dict | None = None) -> dict:
    """Contagem de achados por severidade (nuclei/dalfox, os únicos índices
    com esse campo) — mesmo padrão de jobs_summary, mas respeitando os
    mesmos filtros (tool/scan/status/q) já aplicados na tabela de achados,
    pra o gráfico sempre bater com o que está sendo visto."""
    index = f"{client_name}-{suffix}"
    must = [_contains_query(q)] if q else []
    filter_clauses = [
        {"terms": {k: v if isinstance(v, list) else [v]}} for k, v in (filters or {}).items()
    ]
    query = {"bool": {"must": must, "filter": filter_clauses}} if (must or filter_clauses) else {"match_all": {}}
    try:
        resp = client().search(
            index=index,
            body={"size": 0, "query": query, "aggs": {"by_severity": {"terms": {"field": "severity", "size": 10}}}},
        )
    except NotFoundError:
        return {}
    return {b["key"]: b["doc_count"] for b in resp["aggregations"]["by_severity"]["buckets"]}


# finding_type do wpscan que representa uma vulnerabilidade confirmada
# contra a WPVulnDB (ver backend/parsers/wpscan.py) — exclui
# "interesting"/"core_version"/"user", que não são vulnerabilidades em si.
_WPSCAN_VULN_TYPES = ["core_vulnerability", "theme_vulnerability", "plugin_vulnerability"]


def top_findings(client_name: str, limit: int = 15) -> list[dict]:
    """Os achados mais graves (nuclei/dalfox, critical antes de high, entre
    os dois índices) pra nomear no relatório executivo — o score sozinho não
    diz o que foi encontrado. search_findings já tolera índice inexistente
    (devolve items=[]), então um cliente sem nuclei/dalfox não quebra aqui."""
    results: list[dict] = []
    for severity in ("critical", "high"):
        for suffix in ("nuclei", "dalfox"):
            if len(results) >= limit:
                return results[:limit]
            page = search_findings(client_name, suffix, filters={"severity": [severity]}, size=limit - len(results))
            for item in page["items"]:
                item["_suffix"] = suffix
            results.extend(page["items"])
    return results[:limit]


def risk_summary(client_name: str) -> dict:
    """Agregação por trás do relatório executivo (card no dashboard + PDF,
    ver risk_score.py para a matemática) — nuclei+dalfox (severidade) e
    wpscan (vulnerabilidades confirmadas) entram no score; superfície de
    ataque (subdomínios/hosts vivos/portas abertas) é só contexto no
    relatório, não pontua. Cliente sem dado nenhum cai nos mesmos
    tratamentos de índice inexistente já usados no resto do arquivo —
    score 0, tier "Nenhum", sem exceção."""
    severity_counts: dict[str, int] = {}
    for suffix in ("nuclei", "dalfox"):
        for sev, count in severity_summary(client_name, suffix).items():
            severity_counts[sev] = severity_counts.get(sev, 0) + count

    try:
        wpscan_vuln_count = client().count(
            index=f"{client_name}-wpscan",
            body={"query": {"terms": {"finding_type": _WPSCAN_VULN_TYPES}}},
        )["count"]
    except NotFoundError:
        wpscan_vuln_count = 0

    try:
        live_hosts = client().count(index=f"{client_name}-httpx", body={"query": {"term": {"alive": True}}})["count"]
    except NotFoundError:
        live_hosts = 0

    indices = {i["suffix"]: i["doc_count"] for i in list_client_indices(client_name)}

    result = risk_score.compute(severity_counts, wpscan_vuln_count)
    result.update({
        "severity_counts": severity_counts,
        "wpscan_vulnerabilities": wpscan_vuln_count,
        "surface": {
            "subdomains": indices.get("subdomains", 0),
            "live_hosts": live_hosts,
            "open_ports": indices.get("masscan", 0),
        },
        "top_findings": top_findings(client_name),
    })
    return result


def record_scan(client_name: str, scan_id: str, targets: list[str], **extra) -> None:
    """Registra a submissão do scan assim que ele é disparado — alvos
    originais + data/hora. `scan_id` sozinho é um hex opaco; é este registro
    que dá a ele uma identidade "por data de execução" (o pedido original:
    escanear o mesmo alvo em dias seguidos deve continuar distinguível nos
    filtros). Indexado com _id=scan_id para permitir upsert caso a mesma
    chamada seja repetida (idempotente)."""
    doc = {"client": client_name, "scan_id": scan_id, "targets": targets, "@timestamp": _now_iso(), **extra}
    client().index(index=f"{client_name}-scans", id=scan_id, body=doc)


def get_scan(client_name: str, scan_id: str) -> dict | None:
    try:
        resp = client().get(index=f"{client_name}-scans", id=scan_id)
    except NotFoundError:
        return None
    return resp["_source"]


def mark_scan_cancelled(client_name: str, scan_id: str) -> None:
    """Marca um scan como cancelado — checado em todo ponto do pipeline que
    dispara mais trabalho (ver tasks.py), pra "cancelar scans em andamento"
    de fato impedir fases futuras de rodar, não só matar os jobs que já
    existiam no momento do clique. Sem isso, o chord callback da fase atual
    ainda dispara a fase seguinte mesmo com os jobs mortos à força (o Celery
    conta a tarefa morta/revogada como "concluída" pro chord) — visto na
    prática: cancelar só os jobs visíveis não impedia processos novos de
    continuarem subindo."""
    client().update(
        index=f"{client_name}-scans", id=scan_id,
        body={"doc": {"cancelled": True, "cancelled_at": _now_iso()}, "doc_as_upsert": True},
    )


def is_scan_cancelled(client_name: str, scan_id: str) -> bool:
    scan = get_scan(client_name, scan_id)
    return bool(scan and scan.get("cancelled"))


def list_scans(client_name: str) -> list[dict]:
    """Histórico de scans do cliente, do mais recente para o mais antigo —
    alimenta o seletor "scan" nos filtros de achados/execuções. Cada item
    ganha duration_seconds (do disparo até a última ferramenta terminar),
    via uma agregação max(finished_at) por scan_id sobre {client}-jobs —
    None enquanto nenhuma ferramenta desse scan tiver terminado ainda."""
    scans = _safe_search(
        f"{client_name}-scans",
        {"query": {"match_all": {}}, "size": 500, "sort": [{"@timestamp": "desc"}]},
    )
    if not scans:
        return scans
    try:
        resp = client().search(
            index=f"{client_name}-jobs",
            body={
                "size": 0,
                "aggs": {
                    "by_scan": {
                        "terms": {"field": "scan_id", "size": 500},
                        "aggs": {"last_finish": {"max": {"field": "finished_at"}}},
                    }
                },
            },
        )
        buckets = resp["aggregations"]["by_scan"]["buckets"]
    except NotFoundError:
        buckets = []
    last_finish_by_scan = {
        b["key"]: b["last_finish"]["value_as_string"]
        for b in buckets
        if b["last_finish"]["value"] is not None
    }
    for scan in scans:
        last_finish = last_finish_by_scan.get(scan["scan_id"])
        if last_finish:
            started = datetime.fromisoformat(scan["@timestamp"])
            finished = datetime.fromisoformat(last_finish.replace("Z", "+00:00"))
            scan["duration_seconds"] = max(0.0, (finished - started).total_seconds())
        else:
            scan["duration_seconds"] = None
    return scans


def delete_scan(client_name: str, scan_id: str) -> dict:
    """Remove um scan inteiro: achados e jobs desse scan_id em todos os
    índices do cliente (incluindo o próprio registro em {client}-scans, que
    também tem esse campo), via delete_by_query. Diferente de
    delete_findings (que apaga achados específicos por _id de um índice só)
    — aqui não dá pra saber de antemão quais índices esse scan tocou (depende
    de quais fases/tools rodaram), então varremos todos os índices existentes
    do cliente pelo scan_id."""
    deleted_by_suffix: dict[str, int] = {}
    for info in list_client_indices(client_name):
        suffix = info["suffix"]
        index = f"{client_name}-{suffix}"
        try:
            resp = client().delete_by_query(
                index=index, body={"query": {"term": {"scan_id": scan_id}}}, conflicts="proceed",
            )
        except NotFoundError:
            continue
        count = resp.get("deleted", 0)
        if count:
            deleted_by_suffix[suffix] = count
    return {"deleted_by_suffix": deleted_by_suffix}


def query_jobs(client_name: str, scan_id: str) -> list[dict]:
    return _safe_search(
        f"{client_name}-jobs",
        {"query": {"term": {"scan_id": scan_id}}, "size": 500, "sort": [{"@timestamp": "asc"}]},
    )


def record_wordlist(client_name: str, wordlist_id: str, doc: dict) -> None:
    """Metadados da wordlist customizada (nome original, tamanho, linhas) —
    o conteúdo em si vive só no disco (ver wordlists.py), nunca aqui.
    refresh=True: save_wordlist() checa o limite por cliente contando
    resultado de busca logo antes de gravar; sem forçar refresh aqui, um
    upload em sequência rápida poderia contar um total desatualizado (o
    índice do OpenSearch não fica visível pra busca instantaneamente) e
    passar do limite — visto na prática ao testar."""
    client().index(index=f"{client_name}-wordlists", id=wordlist_id, body=doc, refresh=True)


def get_wordlist(client_name: str, wordlist_id: str) -> dict | None:
    """None tanto se a wordlist não existe quanto se existe mas pertence a
    outro cliente — usado para checar posse antes de referenciar um
    wordlist_id num scan (um cliente não pode usar a wordlist de outro)."""
    try:
        resp = client().get(index=f"{client_name}-wordlists", id=wordlist_id)
    except NotFoundError:
        return None
    return resp["_source"]


def list_wordlists(client_name: str) -> list[dict]:
    hits = _safe_search(
        f"{client_name}-wordlists",
        {"query": {"match_all": {}}, "size": 500, "sort": [{"@timestamp": "desc"}]},
    )
    return hits


def delete_wordlist_doc(client_name: str, wordlist_id: str) -> bool:
    try:
        client().delete(index=f"{client_name}-wordlists", id=wordlist_id, refresh=True)
    except NotFoundError:
        return False
    return True


def record_recurring_scan(client_name: str, schedule_id: str, doc: dict) -> None:
    """Grava/atualiza um alvo salvo (com ou sem recorrência ativa) — mesmo
    idioma de record_wordlist: index com id=schedule_id (upsert), refresh=True
    porque o scheduler (recurrence_scheduler.py) pode ler esse mesmo registro
    poucos segundos depois de criado/editado."""
    client().index(index=f"{client_name}-scan-schedules", id=schedule_id, body=doc, refresh=True)


def get_recurring_scan(client_name: str, schedule_id: str) -> dict | None:
    try:
        resp = client().get(index=f"{client_name}-scan-schedules", id=schedule_id)
    except NotFoundError:
        return None
    return resp["_source"]


def list_recurring_scans(client_name: str) -> list[dict]:
    return _safe_search(
        f"{client_name}-scan-schedules",
        {"query": {"match_all": {}}, "size": 500, "sort": [{"created_at": "desc"}]},
    )


def delete_recurring_scan_doc(client_name: str, schedule_id: str) -> bool:
    try:
        client().delete(index=f"{client_name}-scan-schedules", id=schedule_id, refresh=True)
    except NotFoundError:
        return False
    return True


def list_due_recurring_scans(now_iso: str) -> list[dict]:
    """Alvos salvos com recorrência ativa cuja próxima execução já chegou, em
    qualquer cliente — usado pelo loop do recurrence_scheduler.py. Mesmo
    padrão cross-cliente de list_active_jobs()."""
    try:
        resp = client().search(
            index="*-scan-schedules",
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"enabled": True}},
                            {"range": {"next_run_at": {"lte": now_iso}}},
                        ]
                    }
                },
                "size": 200,
            },
        )
    except NotFoundError:
        return []
    return [hit["_source"] for hit in resp["hits"]["hits"]]


def update_recurring_scan_after_run(
    client_name: str, schedule_id: str, *, last_run_at: str, last_scan_id: str, next_run_at: str,
) -> None:
    client().update(
        index=f"{client_name}-scan-schedules", id=schedule_id,
        body={"doc": {"last_run_at": last_run_at, "last_scan_id": last_scan_id, "next_run_at": next_run_at}},
    )


def record_job(
    *,
    client_name: str,
    job_id: str,
    scan_id: str,
    tool: str,
    target: str,
    status: str,
    cpu_core: int | None = None,
    doc_count: int | None = None,
    error: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    container_id: str | None = None,
) -> None:
    """Grava/atualiza o registro de um job pelo seu job_id (= id da task do
    Celery) — chamado com status="running" ao iniciar (de novo quando o
    container sobe, para gravar o container_id), e por fim com
    "ok"/"error"/"cancelled". Usa update+upsert (não index()) para um write
    não apagar os campos gravados nos anteriores (ex: started_at)."""
    doc = {
        "client": client_name,
        "scan_id": scan_id,
        "tool": tool,
        "target": target,
        "status": status,
        "@timestamp": _now_iso(),
    }
    if cpu_core is not None:
        doc["cpu_core"] = cpu_core
    if doc_count is not None:
        doc["doc_count"] = doc_count
    if error:
        doc["error"] = error
    if started_at:
        doc["started_at"] = started_at
    if finished_at:
        doc["finished_at"] = finished_at
    if container_id:
        doc["container_id"] = container_id
    client().update(
        index=f"{client_name}-jobs",
        id=job_id,
        body={"doc": doc, "doc_as_upsert": True},
    )


def queue_job(client_name: str, scan_id: str, tool: str, target: str) -> str:
    """Gera um job_id e grava o registro como status="queued" — chamado no
    momento em que a task é despachada para o Celery (antes de rodar), não
    quando ela de fato começa a executar. É isso que permite mostrar
    "pendente" e cancelar uma tarefa que ainda nem começou."""
    job_id = uuid.uuid4().hex
    record_job(client_name=client_name, job_id=job_id, scan_id=scan_id, tool=tool, target=target, status="queued")
    return job_id


def get_job(client_name: str, job_id: str) -> dict | None:
    try:
        resp = client().get(index=f"{client_name}-jobs", id=job_id)
    except NotFoundError:
        return None
    return {**resp["_source"], "job_id": resp["_id"]}


def list_cancelable_jobs(client_name: str) -> list[dict]:
    """Jobs que ainda podem ser cancelados: rodando agora ou esperando na
    fila (ainda não começaram)."""
    try:
        resp = client().search(
            index=f"{client_name}-jobs",
            body={"query": {"terms": {"status": ["running", "queued"]}}, "size": 500},
        )
    except NotFoundError:
        return []
    return [{**hit["_source"], "job_id": hit["_id"]} for hit in resp["hits"]["hits"]]


def jobs_summary(client_name: str) -> dict:
    """Contagem de execuções por status — usado no painel do cliente."""
    try:
        resp = client().search(
            index=f"{client_name}-jobs",
            body={"size": 0, "aggs": {"by_status": {"terms": {"field": "status", "size": 10}}}},
        )
    except NotFoundError:
        return {"total": 0, "ok": 0, "error": 0, "cancelled": 0, "running": 0, "queued": 0}
    counts = {b["key"]: b["doc_count"] for b in resp["aggregations"]["by_status"]["buckets"]}
    return {
        "total": sum(counts.values()),
        "ok": counts.get("ok", 0),
        "error": counts.get("error", 0),
        "cancelled": counts.get("cancelled", 0),
        "running": counts.get("running", 0),
        "queued": counts.get("queued", 0),
    }


def list_active_jobs() -> list[dict]:
    """Jobs com status="running" em qualquer cliente — visão global do que
    está rodando agora nos workers."""
    try:
        resp = client().search(
            index="*-jobs",
            body={
                "query": {"term": {"status": "running"}},
                "size": 200,
                "sort": [{"started_at": {"order": "asc"}}],
            },
        )
    except NotFoundError:
        return []
    return [{**hit["_source"], "job_id": hit["_id"]} for hit in resp["hits"]["hits"]]


# --------------------------------------------------------------------------
# Autenticação e configurações — usuários/sessões/log de auditoria/settings.
# Únicos índices globais do projeto (todo o resto é por-cliente,
# "{cliente}-{suffix}") — nomeados com "_" em vez de "-" de propósito: a
# política de retenção longa (ver opensearch/ism-policies/long-retention.json,
# index_patterns: ["*-*"]) pega qualquer índice com hífen; um
# "super-recon-users" cairia nela e expiraria sozinho com
# ILM_LONG_RETENTION_DAYS configurado — apagando usuários/sessões/settings
# sem aviso. Sem hífen no nome, esses quatro índices nunca batem esse glob.
# --------------------------------------------------------------------------

_USERS_INDEX = "super_recon_users"
_SESSIONS_INDEX = "super_recon_sessions"
_AUDIT_LOG_INDEX = "super_recon_audit_log"
_SETTINGS_INDEX = "super_recon_settings"
_SETTINGS_DOC_ID = "settings"


def create_user(user_id: str, username: str, password_hash: str, role: str) -> None:
    now = _now_iso()
    doc = {
        "user_id": user_id, "username": username, "password_hash": password_hash,
        "role": role, "disabled": False, "created_at": now, "updated_at": now,
    }
    # refresh=True: diferente dos writes de achado (alto volume, refresh
    # forçado sairia caro), criar usuário é raro — e sem isso, logar como
    # esse usuário logo em seguida (dentro do mesmo ~1s de refresh interval,
    # bem plausível ao testar) não acharia ele via get_user_by_username
    # (busca, diferente de get-by-id, que é sempre near-real-time).
    client().index(index=_USERS_INDEX, id=user_id, body=doc, refresh=True)


def get_user(user_id: str) -> dict | None:
    try:
        resp = client().get(index=_USERS_INDEX, id=user_id)
    except NotFoundError:
        return None
    return {**resp["_source"], "user_id": resp["_id"]}


def get_user_by_username(username: str) -> dict | None:
    try:
        resp = client().search(index=_USERS_INDEX, body={"query": {"term": {"username": username}}, "size": 1})
    except NotFoundError:
        return None
    hits = resp["hits"]["hits"]
    if not hits:
        return None
    return {**hits[0]["_source"], "user_id": hits[0]["_id"]}


def list_users() -> list[dict]:
    try:
        resp = client().search(
            index=_USERS_INDEX,
            body={"query": {"match_all": {}}, "size": 1000, "sort": [{"created_at": {"order": "asc"}}]},
        )
    except NotFoundError:
        return []
    return [{**hit["_source"], "user_id": hit["_id"]} for hit in resp["hits"]["hits"]]


def update_user(user_id: str, **fields) -> None:
    fields["updated_at"] = _now_iso()
    client().update(index=_USERS_INDEX, id=user_id, body={"doc": fields}, refresh=True)


def delete_user(user_id: str) -> bool:
    try:
        client().delete(index=_USERS_INDEX, id=user_id, refresh=True)
        return True
    except NotFoundError:
        return False


def count_active_admins() -> int:
    """Usado pra impedir excluir/rebaixar/desativar o último admin restante
    (ver rotas de usuário em main.py) — sem essa checagem dá pra trancar
    todo mundo fora do sistema sem querer."""
    try:
        resp = client().count(
            index=_USERS_INDEX,
            body={"query": {"bool": {"filter": [{"term": {"role": "admin"}}, {"term": {"disabled": False}}]}}},
        )
    except NotFoundError:
        return 0
    return resp["count"]


def create_session(token: str, user: dict, ttl_days: int) -> None:
    now = datetime.now(timezone.utc)
    doc = {
        "token": token, "user_id": user["user_id"], "username": user["username"], "role": user["role"],
        "created_at": now.isoformat(), "expires_at": (now + timedelta(days=ttl_days)).isoformat(),
    }
    # refresh=True: sessão criada agora (ex: login numa segunda aba, ou de um
    # atacante com um token roubado) precisa aparecer imediatamente pra
    # delete_sessions_for_user() (search-based, delete_by_query) — sem isso,
    # uma sessão criada dentro da mesma janela de refresh (~1s) de uma troca
    # de senha logo em seguida escaparia da varredura e continuaria válida
    # (mesmo raciocínio de create_user/get_user_by_username, ver ali).
    client().index(index=_SESSIONS_INDEX, id=token, body=doc, refresh=True)


def get_session(token: str) -> dict | None:
    """None tanto pra token inexistente quanto expirado — quem chama (o
    middleware de auth) trata os dois casos do mesmo jeito (401), não
    precisa distinguir."""
    try:
        resp = client().get(index=_SESSIONS_INDEX, id=token)
    except NotFoundError:
        return None
    doc = resp["_source"]
    if datetime.fromisoformat(doc["expires_at"]) < datetime.now(timezone.utc):
        return None
    return doc


def delete_session(token: str) -> None:
    try:
        client().delete(index=_SESSIONS_INDEX, id=token)
    except NotFoundError:
        pass


def delete_sessions_for_user(user_id: str, *, except_token: str | None = None) -> None:
    """Derruba as sessões ativas de um usuário — chamado depois de trocar a
    senha (self-service ou reset por admin): sem isso, um token que já
    tivesse vazado continuaria válido normalmente até expirar sozinho
    (SESSION_TTL_DAYS, até 30 dias), mesmo com a senha já trocada.
    except_token preserva a sessão que fez a própria troca (self-service):
    sem isso, trocar a própria senha te deslogaria também. No reset feito
    por um admin em outro usuário não há sessão "própria" a preservar."""
    query: dict = {"bool": {"filter": [{"term": {"user_id": user_id}}]}}
    if except_token:
        query["bool"]["must_not"] = [{"ids": {"values": [except_token]}}]
    try:
        client().delete_by_query(index=_SESSIONS_INDEX, body={"query": query}, conflicts="proceed", refresh=True)
    except NotFoundError:
        pass


def record_audit(user: dict, method: str, path: str, status_code: int) -> None:
    doc = {
        "@timestamp": _now_iso(),
        "user_id": user["user_id"], "username": user["username"], "role": user["role"],
        "method": method, "path": path, "status_code": status_code,
    }
    client().index(index=_AUDIT_LOG_INDEX, body=doc)


def list_audit_log(page: int = 1, size: int = 50) -> dict:
    try:
        resp = client().search(
            index=_AUDIT_LOG_INDEX,
            body={
                "query": {"match_all": {}},
                "from": max(page - 1, 0) * size, "size": size,
                "sort": [{"@timestamp": {"order": "desc"}}],
            },
        )
    except NotFoundError:
        return {"total": 0, "page": page, "size": size, "items": []}
    total = resp["hits"]["total"]["value"]
    items = [{**hit["_source"], "_id": hit["_id"]} for hit in resp["hits"]["hits"]]
    return {"total": total, "page": page, "size": size, "items": items}


def get_settings_overrides() -> dict:
    """Overrides salvos pela tela "Configurações" (admin) — {} numa
    instalação nova, antes de qualquer alteração. Aplicados por cima dos
    defaults do .env no startup do backend (ver main.py:
    _load_settings_overrides) e a cada PUT /settings bem-sucedido."""
    try:
        resp = client().get(index=_SETTINGS_INDEX, id=_SETTINGS_DOC_ID)
    except NotFoundError:
        return {}
    return resp["_source"].get("overrides", {})


def save_settings_overrides(overrides: dict) -> None:
    """Substitui o documento inteiro de overrides (não é um merge parcial
    do OpenSearch: PUT /settings em main.py já monta o dict completo — as
    chaves mantidas + as alteradas - as resetadas — antes de chamar aqui,
    já que um update parcial (`doc`) do OpenSearch nunca remove campo, só
    sobrescreve/adiciona, o que impediria "restaurar padrão" de fato tirar
    o override salvo)."""
    doc = {"overrides": overrides, "updated_at": _now_iso()}
    client().index(index=_SETTINGS_INDEX, id=_SETTINGS_DOC_ID, body=doc, refresh=True)
