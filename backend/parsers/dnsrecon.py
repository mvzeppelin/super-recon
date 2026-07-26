import json

from .common import base_doc, now_iso


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    # Vem de um output_file (arquivo -j do dnsrecon): JSON puro, sem ruído de
    # console antes — diferente das ferramentas que imprimem no stdout.
    records = json.loads(raw_text)
    docs = []
    seen = set()

    for rec in records:
        if rec.get("type") not in ("A", "AAAA"):
            continue
        # Registros do domínio raiz usam a chave "domain"; hosts achados via
        # brute-force/bing usam "name".
        name = rec.get("name") or rec.get("domain")
        if not name:
            continue
        name = name.lower().rstrip(".")
        if name in seen:
            continue
        seen.add(name)

        doc = base_doc(client, scan_id, target, "dnsrecon")
        doc.update({
            "subdomain": name,
            "domain": target,
            "sources": ["dnsrecon"],
            "first_seen": now_iso(),
        })
        docs.append(doc)
    return docs
