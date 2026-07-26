import xml.etree.ElementTree as ET

from .common import base_doc, extract_xml_block


def _text(el) -> str | None:
    return el.text.strip() if el is not None and el.text else None


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    root = ET.fromstring(extract_xml_block(raw_text))
    docs = []
    for scandetails in root.findall(".//scandetails"):
        host = scandetails.get("targethostname") or scandetails.get("targetip")
        port = scandetails.get("targetport")
        for item in scandetails.findall("item"):
            doc = base_doc(client, scan_id, target, "nikto")
            doc.update({
                "host": host,
                "port": int(port) if port else None,
                "finding_id": item.get("id"),
                "description": _text(item.find("description")),
                "uri": _text(item.find("uri")),
                "references": _text(item.find("references")),
            })
            docs.append(doc)
    return docs
