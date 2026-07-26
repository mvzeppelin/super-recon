import re
from urllib.parse import urljoin

from .common import base_doc

# Formato padrão de linha do gobuster (modo dir): "/caminho (Status: 200) [Size: 1234]"
LINE_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]")


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    base_url = target if target.endswith("/") else target + "/"
    docs = []
    for line in raw_text.splitlines():
        match = LINE_RE.match(line.strip())
        if not match:
            continue
        path, status_code, size = match.groups()
        doc = base_doc(client, scan_id, target, "gobuster")
        doc.update({
            "url": urljoin(base_url, path.lstrip("/")),
            "path": path,
            "status_code": int(status_code),
            "size": int(size),
        })
        docs.append(doc)
    return docs
