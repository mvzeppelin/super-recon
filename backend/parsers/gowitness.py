import json

from .common import base_doc


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    """gowitness --write-jsonl: uma linha JSON por URL (aqui sempre uma só,
    já que cada job roda "scan single" pra uma URL). Não indexa html/headers/
    network/cookies do JSONL — grandes e de baixo valor de busca; o
    screenshot_id (referência ao arquivo persistido, ver screenshots.py) é
    anexado depois, em tasks.py, não aqui (parser não sabe de disco)."""
    docs = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        tls = obj.get("tls") or {}
        technologies = [t.get("value") for t in (obj.get("technologies") or []) if t.get("value")]

        doc = base_doc(client, scan_id, target, "gowitness")
        doc.update({
            "url": obj.get("url"),
            "final_url": obj.get("final_url"),
            "status_code": obj.get("response_code"),
            "title": obj.get("title") or None,
            "perception_hash": obj.get("perception_hash") or None,
            "tls_protocol": tls.get("protocol") or None,
            "tls_issuer": tls.get("issuer") or None,
            "technologies": technologies,
            "failed": obj.get("failed", False),
            "failed_reason": obj.get("failed_reason") or None,
        })
        docs.append(doc)
    return docs
