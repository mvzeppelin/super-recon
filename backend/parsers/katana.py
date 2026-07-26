from urllib.parse import urlparse

from .common import base_doc, clean_lines


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    docs = []
    for line in clean_lines(raw_text):
        if not line.startswith(("http://", "https://")):
            continue
        parsed = urlparse(line)
        doc = base_doc(client, scan_id, target, "katana")
        doc.update({
            "url": line,
            "domain": parsed.hostname or target,
        })
        docs.append(doc)
    return docs
