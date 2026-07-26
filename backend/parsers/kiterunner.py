import json
from urllib.parse import urljoin

from .common import base_doc


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    base_url = target if target.endswith("/") else target + "/"
    docs = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Linhas de log/status ("level":"info", ex: "scan options"/"scan
        # complete") também são JSON válido começando com "{", mas não são
        # achados — só as linhas de hit real têm "method"/"responses".
        if "method" not in obj or not obj.get("responses"):
            continue

        path = obj.get("path", "")
        responses = obj["responses"]
        resp = responses[0] if responses else {}

        doc = base_doc(client, scan_id, target, "kiterunner")
        doc.update({
            "url": urljoin(base_url, path.lstrip("/")),
            "path": path,
            "method": obj.get("method"),
            "status_code": resp.get("sc"),
            "size": resp.get("len"),
        })
        docs.append(doc)
    return docs
