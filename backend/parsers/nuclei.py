import json

from .common import base_doc


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

        info = obj.get("info", {})
        classification = info.get("classification") or {}

        doc = base_doc(client, scan_id, target, "nuclei")
        doc.update({
            "template_id": obj.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "host": obj.get("host"),
            "matched_at": obj.get("matched-at"),
            "tags": info.get("tags", []),
            "cve": classification.get("cve-id"),
        })
        docs.append(doc)
    return docs
