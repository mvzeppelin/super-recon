import json

from .common import base_doc


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    """dnsx aqui roda em modo resolução/validação (não brute-force): recebe
    a lista de subdomínios já consolidados e só devolve os que resolvem de
    verdade, com os IPs. Hosts que não resolvem simplesmente não aparecem
    na saída — por isso não existe um "resolved: false" aqui."""
    docs = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        doc = base_doc(client, scan_id, target, "dnsx")
        doc.update({
            "subdomain": obj.get("host"),
            "ips": obj.get("a", []),
            "resolved": True,
        })
        docs.append(doc)
    return docs
