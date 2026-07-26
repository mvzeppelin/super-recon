import re

from .common import base_doc, now_iso

# amass imprime um grafo de relações, uma por linha:
# "sujeito (Tipo) --> predicado --> objeto (Tipo)"
# Só nos interessam linhas cujo sujeito é um FQDN dentro do domínio alvo.
LINE_RE = re.compile(r"^(?P<name>\S+)\s+\(FQDN\)\s+-->")


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    docs = []
    seen = set()
    target_lower = target.lower().rstrip(".")

    for line in raw_text.splitlines():
        match = LINE_RE.match(line.strip())
        if not match:
            continue
        name = match.group("name").lower().rstrip(".")
        if name != target_lower and not name.endswith(f".{target_lower}"):
            continue  # FQDN de outra organização (ex: nameserver do provedor)
        if name in seen:
            continue
        seen.add(name)

        doc = base_doc(client, scan_id, target, "amass")
        doc.update({
            "subdomain": name,
            "domain": target,
            "sources": ["amass"],
            "first_seen": now_iso(),
        })
        docs.append(doc)
    return docs
