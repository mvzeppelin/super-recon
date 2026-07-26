from . import (
    amass,
    assetfinder,
    censys,
    dalfox,
    dnsenum,
    dnsrecon,
    dnsx,
    gau,
    gobuster,
    gowitness,
    httpx,
    katana,
    kiterunner,
    masscan,
    nikto,
    nmap,
    nuclei,
    rdap,
    shodan,
    subfinder,
    sublist3r,
    theharvester,
    wayback,
    wpscan,
)

# tool -> função de parsing. "tool" é o nome usado pelo orquestrador para
# identificar qual ferramenta gerou a saída bruta.
PARSERS = {
    "assetfinder": assetfinder.parse,
    "subfinder": subfinder.parse,
    "sublist3r": sublist3r.parse,
    "amass": amass.parse,
    "dnsenum": dnsenum.parse,
    "dnsrecon": dnsrecon.parse,
    "httprobe": httpx.parse_httprobe,
    "httpx": httpx.parse_httpx,
    "dnsx": dnsx.parse,
    "wayback": wayback.parse,
    "gau": gau.parse,
    "katana": katana.parse,
    "rdap_domain": rdap.parse_domain,
    "rdap_network": rdap.parse_network,
    "masscan": masscan.parse,
    "nmap": nmap.parse,
    "nikto": nikto.parse,
    "nuclei": nuclei.parse,
    "gobuster": gobuster.parse,
    "theharvester": theharvester.parse,
    "shodan": shodan.parse,
    "censys": censys.parse,
    "wpscan": wpscan.parse,
    "gowitness": gowitness.parse,
    "dalfox": dalfox.parse,
    "kiterunner": kiterunner.parse,
}

# tool -> sufixo de índice no OpenSearch (ver Etapa 2: "{cliente}-{sufixo}")
INDEX_SUFFIX = {
    "assetfinder": "subdomains",
    "subfinder": "subdomains",
    "sublist3r": "subdomains",
    "amass": "subdomains",
    "dnsenum": "subdomains",
    "dnsrecon": "subdomains",
    "httprobe": "httpx",
    "httpx": "httpx",
    "dnsx": "dns",
    "wayback": "wayback",
    "gau": "wayback",
    "katana": "katana",
    "rdap_domain": "rdap-domain",
    "rdap_network": "rdap-network",
    "masscan": "masscan",
    "nmap": "nmap",
    "nikto": "nikto",
    "nuclei": "nuclei",
    "gobuster": "gobuster",
    "theharvester": "harvester",
    "shodan": "shodan",
    "censys": "censys",
    "wpscan": "wpscan",
    "gowitness": "gowitness",
    "dalfox": "dalfox",
    "kiterunner": "kiterunner",
}


def parse(tool: str, raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    return PARSERS[tool](raw_text, client=client, scan_id=scan_id, target=target)


def index_name(client: str, tool: str) -> str:
    return f"{client}-{INDEX_SUFFIX[tool]}"
