import json

from .common import base_doc


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    try:
        items = json.loads(raw_text)
    except json.JSONDecodeError:
        return []

    docs = []
    for item in items:
        if not item:
            continue
        doc = base_doc(client, scan_id, target, "dalfox")
        doc.update({
            "type": item.get("type"),
            "inject_type": item.get("inject_type"),
            "poc_type": item.get("poc_type"),
            "method": item.get("method"),
            "url": item.get("data"),
            "param": item.get("param"),
            "payload": item.get("payload"),
            "evidence": item.get("evidence"),
            "cwe": item.get("cwe"),
            "severity": item.get("severity"),
            "message": item.get("message_str"),
        })
        docs.append(doc)
    return docs
