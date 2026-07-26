import json
from urllib.parse import urlparse

from .common import base_doc, clean_lines


def parse_httprobe(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    """httprobe só confirma que a URL está viva (sem status code)."""
    docs = []
    for line in clean_lines(raw_text):
        if not line.startswith(("http://", "https://")):
            continue
        parsed = urlparse(line)
        doc = base_doc(client, scan_id, target, "httprobe")
        doc.update({
            "url": line,
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "status_code": None,
            "alive": True,
        })
        docs.append(doc)
    return docs


def parse_httpx(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    """httpx (-json/-jsonl): uma linha JSON por URL, com status code."""
    docs = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url", "")
        parsed = urlparse(url)
        doc = base_doc(client, scan_id, target, "httpx")
        doc.update({
            "url": url,
            "scheme": obj.get("scheme") or parsed.scheme,
            "host": obj.get("host") or parsed.hostname,
            "status_code": obj.get("status_code"),
            "alive": True,
        })
        docs.append(doc)
    return docs
