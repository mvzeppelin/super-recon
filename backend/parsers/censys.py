import json

from .common import base_doc


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    """raw_text é o corpo JSON cru da Censys Platform API (chamada HTTPS
    direta, sem ruído de shell). Um doc por serviço encontrado — mesmo
    padrão do nmap/shodan; IP sem nenhum serviço (comum, não é exceção:
    "services": [] pra qualquer IP que a Censys não tenha achado porta
    aberta) simplesmente não gera documento, igual ao nmap sem portas."""
    obj = json.loads(raw_text)
    resource = (obj.get("result") or {}).get("resource") or {}
    ip = resource.get("ip", target)

    asn_info = resource.get("autonomous_system") or {}
    whois_org = ((resource.get("whois") or {}).get("organization") or {}).get("name")
    org = whois_org or asn_info.get("description")
    location = resource.get("location") or {}

    docs = []
    for svc in resource.get("services") or []:
        # Cada entrada de "software" é {"vendor", "product"} (identificação
        # real) ou só {"type": [...]} (categoria, sem vendor/product) — filtra
        # só as que têm identificação de verdade.
        software = [
            f"{s['vendor']}:{s['product']}"
            for s in (svc.get("software") or [])
            if s.get("vendor") and s.get("product")
        ]
        labels = [label.get("value") for label in (svc.get("labels") or []) if label.get("value")]

        doc = base_doc(client, scan_id, target, "censys")
        doc.update({
            "ip": ip,
            "port": svc.get("port"),
            "protocol": svc.get("protocol"),
            "transport": svc.get("transport_protocol"),
            "software": software,
            "labels": labels,
            "asn": asn_info.get("asn"),
            "org": org,
            "country": location.get("country"),
            "city": location.get("city"),
        })
        docs.append(doc)

    return docs
