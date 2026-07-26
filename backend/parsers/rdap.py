import json

from .common import base_doc, extract_json_block


def _vcard_fn(vcard_array) -> str | None:
    """Extrai o campo 'fn' (nome formatado) de um vcardArray RDAP."""
    try:
        properties = vcard_array[1]
    except (IndexError, TypeError):
        return None
    for prop in properties:
        if prop and prop[0] == "fn":
            return prop[3]
    return None


def _find_entity_by_role(entities, role: str) -> dict | None:
    for entity in entities or []:
        if role in entity.get("roles", []):
            return entity
    return None


def parse_domain(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    obj = json.loads(extract_json_block(raw_text))
    registrant_entity = _find_entity_by_role(obj.get("entities"), "registrant")
    registrant = _vcard_fn(registrant_entity["vcardArray"]) if registrant_entity else None

    doc = base_doc(client, scan_id, target, "rdap")
    doc.update({
        "domain": obj.get("ldhName", target).lower(),
        "handle": obj.get("handle"),
        "nameservers": [ns["ldhName"] for ns in obj.get("nameservers", []) if ns.get("ldhName")],
        "registrant": registrant,
        "events": [
            {"eventAction": e.get("eventAction"), "eventDate": e.get("eventDate")}
            for e in obj.get("events", [])
        ],
    })
    return [doc]


def parse_network(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    obj = json.loads(extract_json_block(raw_text))
    cidrs = obj.get("cidr0_cidrs") or []
    cidr = f"{cidrs[0]['v4prefix']}/{cidrs[0]['length']}" if cidrs else None
    registrant_entity = _find_entity_by_role(obj.get("entities"), "registrant")
    org = _vcard_fn(registrant_entity["vcardArray"]) if registrant_entity else None

    doc = base_doc(client, scan_id, target, "rdap")
    doc.update({
        "handle": obj.get("handle"),
        "start_address": obj.get("startAddress"),
        "end_address": obj.get("endAddress"),
        "cidr": cidr,
        "country": obj.get("country"),
        "org": org,
    })
    return [doc]
