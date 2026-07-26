import re
from datetime import datetime, timezone
from urllib.parse import urlparse

# Hostname válido (rfc1123), sem espaços — usado para filtrar ruído
# (banners, linhas de log, eco do comando) dos outputs em texto puro.
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def base_doc(client: str, scan_id: str, target: str, tool: str) -> dict:
    return {
        "client": client,
        "scan_id": scan_id,
        "target": target,
        "tool": tool,
        "@timestamp": now_iso(),
    }


def clean_lines(raw_text: str) -> list[str]:
    return [line.strip() for line in raw_text.splitlines() if line.strip()]


def is_hostname(line: str) -> bool:
    return bool(HOSTNAME_RE.match(line))


def parse_subdomain_list(raw_text: str, *, client: str, scan_id: str, target: str, tool: str) -> list[dict]:
    """Comum a assetfinder/sublist3r: uma lista em texto puro, um host por linha,
    misturada com ruído (banners, logs, eco do comando) que não é hostname válido."""
    docs = []
    for line in clean_lines(raw_text):
        if not is_hostname(line):
            continue
        doc = base_doc(client, scan_id, target, tool)
        doc.update({
            "subdomain": line.lower(),
            "domain": target,
            "sources": [tool],
            "first_seen": now_iso(),
        })
        docs.append(doc)
    return docs


def parse_url_list(raw_text: str, *, client: str, scan_id: str, target: str, tool: str) -> list[dict]:
    """Comum a waybackurls/gau: lista de URLs históricas em texto puro, uma
    por linha, misturada com ruído (eco do comando, linha em branco)."""
    docs = []
    for line in clean_lines(raw_text):
        if not line.startswith(("http://", "https://")):
            continue
        parsed = urlparse(line)
        doc = base_doc(client, scan_id, target, tool)
        doc.update({
            "url": line,
            "domain": parsed.hostname or target,
            "path": parsed.path or "/",
            "has_params": bool(parsed.query),
        })
        docs.append(doc)
    return docs


def extract_json_block(raw_text: str) -> str:
    """Descarta ruído (ex: eco do comando) antes do primeiro '{' de um JSON."""
    idx = raw_text.find("{")
    if idx == -1:
        raise ValueError("Nenhum JSON encontrado na saída")
    return raw_text[idx:]


def extract_xml_block(raw_text: str) -> str:
    """Descarta ruído (saída de console) antes do início do XML."""
    idx = raw_text.find("<?xml")
    if idx == -1:
        idx = raw_text.find("<")
    if idx == -1:
        raise ValueError("Nenhum XML encontrado na saída")
    return raw_text[idx:]
