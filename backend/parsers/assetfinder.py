from .common import parse_subdomain_list


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    return parse_subdomain_list(raw_text, client=client, scan_id=scan_id, target=target, tool="assetfinder")
