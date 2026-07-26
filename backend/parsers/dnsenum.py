import re

from .common import base_doc, now_iso

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Linhas de registro no formato "nome.dominio.   TTL   IN   TIPO   valor"
RECORD_RE = re.compile(r"^(?P<name>[\w.-]+)\.\s+\d+\s+IN\s+(?:A|AAAA|CNAME|NS|MX)\s+\S+")


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    docs = []
    seen = set()
    target_lower = target.lower().rstrip(".")

    for raw_line in raw_text.splitlines():
        line = ANSI_RE.sub("", raw_line).strip()
        match = RECORD_RE.match(line)
        if not match:
            continue
        name = match.group("name").lower()
        if name != target_lower and not name.endswith(f".{target_lower}"):
            continue  # NS/MX de terceiros (ex: provedor de e-mail/hosting)
        if name in seen:
            continue
        seen.add(name)

        doc = base_doc(client, scan_id, target, "dnsenum")
        doc.update({
            "subdomain": name,
            "domain": target,
            "sources": ["dnsenum"],
            "first_seen": now_iso(),
        })
        docs.append(doc)
    return docs
