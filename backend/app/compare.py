from . import opensearch_client
from .export import MAX_ROWS, dedup_key


def _fetch_scan_docs(client_name: str, suffix: str, scan_id: str) -> list[dict]:
    result = opensearch_client.search_findings(
        client_name, suffix, filters={"scan_id": scan_id}, size=MAX_ROWS,
    )
    return result["items"]


def compare_scans(client_name: str, suffix: str, from_scan_id: str, to_scan_id: str) -> dict:
    """"O que mudou desde a última vez": acha achados novos (só no scan mais
    recente), resolvidos (só no mais antigo — ex: vulnerabilidade corrigida,
    subdomínio desativado) e quantos continuam iguais nos dois. Reaproveita a
    mesma noção de identidade de achado do recurso "exportar únicos"
    (dedup_key) — o que faz um achado "ser o mesmo" independente de tool/scan
    é exatamente o que faz sentido usar aqui para saber se ele persistiu."""
    from_docs = _fetch_scan_docs(client_name, suffix, from_scan_id)
    to_docs = _fetch_scan_docs(client_name, suffix, to_scan_id)

    from_by_key = {dedup_key(d): d for d in from_docs}
    to_by_key = {dedup_key(d): d for d in to_docs}

    new_keys = to_by_key.keys() - from_by_key.keys()
    resolved_keys = from_by_key.keys() - to_by_key.keys()
    unchanged_keys = to_by_key.keys() & from_by_key.keys()

    return {
        "new": [to_by_key[k] for k in new_keys],
        "resolved": [from_by_key[k] for k in resolved_keys],
        "unchanged": [to_by_key[k] for k in unchanged_keys],
    }
