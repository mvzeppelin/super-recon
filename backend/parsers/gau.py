from .common import parse_url_list


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    # gau agrega AlienVault OTX, Wayback, URLScan e Common Crawl — grava no
    # mesmo índice "wayback" (é o mesmo conceito: histórico de URLs), só com
    # tool="gau" para diferenciar a origem.
    return parse_url_list(raw_text, client=client, scan_id=scan_id, target=target, tool="gau")
