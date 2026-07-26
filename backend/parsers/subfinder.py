import json

from .common import base_doc, now_iso


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    docs = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        doc = base_doc(client, scan_id, target, "subfinder")
        doc.update({
            "subdomain": obj.get("host", "").lower(),
            "domain": obj.get("input", target),
            "sources": [obj.get("source", "subfinder")],
            "first_seen": now_iso(),
        })
        docs.append(doc)
    return docs
