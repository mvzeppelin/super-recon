import json

from .common import base_doc


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    """raw_text é o corpo JSON cru da Shodan Host API (chamada HTTPS direta,
    sem passar por container/shell — diferente das demais ferramentas, não
    tem ruído de echo de comando antes do JSON)."""
    obj = json.loads(raw_text)
    ip = obj.get("ip_str", target)
    org = obj.get("org")
    isp = obj.get("isp")
    country = obj.get("country_name")
    city = obj.get("city")
    hostnames = obj.get("hostnames") or []

    # O campo "vulns" varia de formato entre respostas: às vezes dict
    # (CVE -> detalhes), às vezes lista simples de CVE-ids — visto na
    # prática consultando IPs reais, não documentado de forma consistente.
    vulns_raw = obj.get("vulns")
    if isinstance(vulns_raw, dict):
        vulns = sorted(vulns_raw.keys())
    elif isinstance(vulns_raw, list):
        vulns = sorted(vulns_raw)
    else:
        vulns = []

    common_fields = {
        "org": org, "isp": isp, "country": country, "city": city,
        "hostnames": hostnames, "vulns": vulns,
    }

    docs = []
    for item in obj.get("data") or []:
        doc = base_doc(client, scan_id, target, "shodan")
        doc.update({
            "ip": ip,
            "port": item.get("port"),
            "transport": item.get("transport"),
            "product": item.get("product"),
            "version": item.get("version"),
            "cpe": item.get("cpe") or [],
            **common_fields,
        })
        docs.append(doc)

    if not docs:
        # Sem portas em "data" mas o host existe (raro) — ainda assim
        # registra org/isp/vulns num doc sem porta, em vez de descartar.
        doc = base_doc(client, scan_id, target, "shodan")
        doc.update({"ip": ip, "port": None, "transport": None, "product": None, "version": None, "cpe": [], **common_fields})
        docs.append(doc)

    return docs
