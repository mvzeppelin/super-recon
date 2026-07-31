import defusedxml.ElementTree as ET

from .common import base_doc, extract_xml_block


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    root = ET.fromstring(extract_xml_block(raw_text))
    docs = []
    for host_el in root.findall("host"):
        ip = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break

        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            cpes = [cpe.text for cpe in port_el.findall("service/cpe")]

            doc = base_doc(client, scan_id, target, "nmap")
            doc.update({
                "ip": ip,
                "hostname": hostname,
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol"),
                "state": state_el.get("state") if state_el is not None else None,
                "service": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
                "cpe": cpes,
            })
            docs.append(doc)
    return docs
