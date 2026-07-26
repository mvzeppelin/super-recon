import re

from .common import base_doc

LINE_RE = re.compile(r"Discovered open port (\d+)/(\w+) on ([\d.]+)")


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    docs = []
    for port, proto, ip in LINE_RE.findall(raw_text):
        doc = base_doc(client, scan_id, target, "masscan")
        doc.update({
            "ip": ip,
            "port": int(port),
            "proto": proto,
            "state": "open",
        })
        docs.append(doc)
    return docs
