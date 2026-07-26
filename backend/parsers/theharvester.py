import json

from .common import base_doc

# chave do JSON do theHarvester -> tipo normalizado no índice "harvester"
FIELD_TYPES = {
    "emails": "email",
    "hosts": "host",
    "ips": "ip",
    "asns": "asn",
    "interesting_urls": "url",
    "people": "person",
    "vhosts": "vhost",
}


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    # Vem de um output_file (-f do theHarvester): JSON puro.
    obj = json.loads(raw_text)
    docs = []

    for key, item_type in FIELD_TYPES.items():
        for value in obj.get(key, []):
            if item_type == "host":
                value = value.split(":", 1)[0]  # remove o ":cname_alvo" quando presente
            doc = base_doc(client, scan_id, target, "theharvester")
            doc.update({"type": item_type, "value": value})
            docs.append(doc)
    return docs
