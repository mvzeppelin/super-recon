import defusedxml.common
import pytest

from parsers import (
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

CLIENT = "teste"
SCAN_ID = "scan-001"
DOMAIN = "businesscorp.com.br"


def test_assetfinder():
    # amostra real (businesscorp.com.br, alvo fictício de treinamento da Desec Security)
    raw = """businesscorp.com.br
rh.businesscorp.com.br
mail.businesscorp.com.br
www.businesscorp.com.br
intranet.businesscorp.com.br
parsingok.businesscorp.com.br
srvkey.businesscorp.com.br
dev.businesscorp.com.br
ftp.businesscorp.com.br
piloto.businesscorp.com.br
ns1.businesscorp.com.br
ns2.businesscorp.com.br
"""
    docs = assetfinder.parse(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) == 12
    assert {d["subdomain"] for d in docs} >= {"businesscorp.com.br", "ns2.businesscorp.com.br"}
    assert all(d["tool"] == "assetfinder" and d["sources"] == ["assetfinder"] for d in docs)


def test_subfinder():
    raw = """{"host":"parsingok.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"rh.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"srvkey.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"twww.businesscorp.com.br","input":"businesscorp.com.br","source":"submd"}
{"host":"intranet.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"mail.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"ns1.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"ns2.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"piloto.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
{"host":"www.businesscorp.com.br","input":"businesscorp.com.br","source":"hackertarget"}
"""
    docs = subfinder.parse(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) == 10
    assert {d["subdomain"] for d in docs} >= {"parsingok.businesscorp.com.br", "ns2.businesscorp.com.br"}
    assert all(d["domain"] == DOMAIN for d in docs)


def test_sublist3r():
    # amostra real reduzida: banner/ruído do sublist3r + só os hosts que ele
    # de fato encontrou (o parser ignora tudo que não é um hostname válido).
    raw = """[-] Searching now in Baidu..
[!] Error: Virustotal probably now is blocking our requests
[-] Total Unique Subdomains Found: 2
www.businesscorp.com.br
rh.businesscorp.com.br
"""
    docs = sublist3r.parse(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) == 2
    assert {d["subdomain"] for d in docs} == {"www.businesscorp.com.br", "rh.businesscorp.com.br"}


def test_httprobe():
    raw = """https://dev.businesscorp.com.br
http://dev.businesscorp.com.br
http://mail.businesscorp.com.br
http://intranet.businesscorp.com.br
http://www.businesscorp.com.br
http://ns1.businesscorp.com.br
http://parsingok.businesscorp.com.br
http://businesscorp.com.br
http://rh.businesscorp.com.br
http://ftp.businesscorp.com.br
"""
    docs = httpx.parse_httprobe(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) == 10
    assert all(d["alive"] is True and d["status_code"] is None for d in docs)
    https_doc = next(d for d in docs if d["url"] == "https://dev.businesscorp.com.br")
    assert https_doc["scheme"] == "https"
    assert https_doc["host"] == "dev.businesscorp.com.br"


def test_wayback():
    # amostra real (waybackurls contra businesscorp.com.br), reduzida a ~130
    # URLs — mais que suficiente pra exercitar o parser (>100 e com query params).
    raw = """http://businesscorp.com.br/
http://businesscorp.com.br/%C3%A3dimi/
http://businesscorp.com.br//_docs
http://businesscorp.com.br/_docs/senhas.txt
http://businesscorp.com.br/_docs/?C=D;O=A
http://businesscorp.com.br/_docs/?C=M;O=A
http://businesscorp.com.br/_docs/?C=N;O=D
http://businesscorp.com.br/_docs/?C=S;O=A
http://businesscorp.com.br///_restrito
http://businesscorp.com.br/_restrito/?C=M%3BO=A
http://www.businesscorp.com.br/access.log
http://businesscorp.com.br/AcessoRestrito/
http://www.businesscorp.com.br/admin/
http://www.businesscorp.com.br/apiClients
http://www.businesscorp.com.br/apiClients/showNames.txt
http://www.businesscorp.com.br/apiClients/showNames.xml
http://businesscorp.com.br/app
http://businesscorp.com.br/app/index.php
http://businesscorp.com.br/bkp/
http://businesscorp.com.br/bkp/script.sh
http://businesscorp.com.br/blog/robots-txt/
http://businesscorp.com.br:80/cadastro.php
http://businesscorp.com.br/cgi-bin/
http://www.businesscorp.com.br/comunicacao/projeto.txt
http://businesscorp.com.br/config
http://businesscorp.com.br/config.txt
http://businesscorp.com.br/configuracoes/
http://businesscorp.com.br/configuracoes/comunicacao/
http://www.businesscorp.com.br/configuracoes/comunicacao/prjeto.txt
http://businesscorp.com.br/configuracoes/comunicacao/projeto.txt
http://www.businesscorp.com.br/configuracoes/comunicacao/?C=D;O=A
http://www.businesscorp.com.br/configuracoes/comunicacao/?C=M;O=A
http://www.businesscorp.com.br/configuracoes/comunicacao/?C=N;O=D
http://www.businesscorp.com.br/configuracoes/comunicacao/?C=S;O=A
http://businesscorp.com.br/configuracoes/db.sql
http://businesscorp.com.br/css
http://businesscorp.com.br/css/default.css
http://www.businesscorp.com.br/css/font-awesome/
http://businesscorp.com.br/css/font-awesome/css/font-awesome.min.css
http://businesscorp.com.br/css/font-awesome/fonts/fontawesome-webfont.eot
http://businesscorp.com.br/css/font-awesome/fonts/fontawesome-webfont.eot?v=4.0.3
http://businesscorp.com.br/css/font-awesome/fonts/fontawesome-webfont.svg?v=4.0.3
http://businesscorp.com.br/css/font-awesome/fonts/fontawesome-webfont.ttf?v=4.0.3
http://businesscorp.com.br/css/font-awesome/fonts/fontawesome-webfont.woff?v=4.0.3
http://www.businesscorp.com.br/css/fontello/
http://businesscorp.com.br/css/fontello/css/fontello.css
http://businesscorp.com.br/css/fontello/font/fontello.eot?13439518
http://businesscorp.com.br/css/fontello/font/fontello.svg?13439518
http://businesscorp.com.br/css/fontello/font/fontello.ttf?13439518
http://businesscorp.com.br/css/fontello/font/fontello.woff?13439518
http://www.businesscorp.com.br/css/fonts/
http://businesscorp.com.br/css/fonts.css
http://businesscorp.com.br/css/fonts/merriweather/merriweather-black-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-black-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-black-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-black-webfont.woff
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bold-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bold-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bold-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bold-webfont.woff
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bolditalic-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bolditalic-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bolditalic-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-bolditalic-webfont.woff
http://businesscorp.com.br/css/fonts/merriweather/merriweather-heavyitalic-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-heavyitalic-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-heavyitalic-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-heavyitalic-webfont.woff
http://businesscorp.com.br/css/fonts/merriweather/merriweather-italic-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-italic-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-italic-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-italic-webfont.woff
http://businesscorp.com.br/css/fonts/merriweather/merriweather-light-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-light-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-light-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-light-webfont.woff
http://businesscorp.com.br/css/fonts/merriweather/merriweather-lightitalic-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-lightitalic-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-lightitalic-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-lightitalic-webfont.woff
http://businesscorp.com.br/css/fonts/merriweather/merriweather-regular-webfont.eot
http://businesscorp.com.br/css/fonts/merriweather/merriweather-regular-webfont.svg
http://businesscorp.com.br/css/fonts/merriweather/merriweather-regular-webfont.ttf
http://businesscorp.com.br/css/fonts/merriweather/merriweather-regular-webfont.woff
http://www.businesscorp.com.br/css/fonts/montserrat/
http://businesscorp.com.br/css/fonts/montserrat/montserrat-bold-webfont.eot
http://businesscorp.com.br/css/fonts/montserrat/montserrat-bold-webfont.svg
http://businesscorp.com.br/css/fonts/montserrat/montserrat-bold-webfont.ttf
http://businesscorp.com.br/css/fonts/montserrat/montserrat-bold-webfont.woff
http://businesscorp.com.br/css/fonts/montserrat/montserrat-regular-webfont.eot
http://businesscorp.com.br/css/fonts/montserrat/montserrat-regular-webfont.svg
http://businesscorp.com.br/css/fonts/montserrat/montserrat-regular-webfont.ttf
http://businesscorp.com.br/css/fonts/montserrat/montserrat-regular-webfont.woff
http://businesscorp.com.br/css/layout.css
http://businesscorp.com.br/css/media-queries.css
http://www.businesscorp.com.br/db/
http://businesscorp.com.br/db/index
http://businesscorp.com.br/db/update.sql
http://businesscorp.com.br/demo
http://businesscorp.com.br/favicon.ico
http://businesscorp.com.br/favicon.png
http://businesscorp.com.br/icons/back.gif
http://businesscorp.com.br/icons/blank.gif
http://businesscorp.com.br/icons/folder.gif
http://businesscorp.com.br/icons/image2.gif
http://businesscorp.com.br/icons/text.gif
http://businesscorp.com.br/icons/unknown.gif
http://businesscorp.com.br/images/
http://businesscorp.com.br/images/header-background.jpg
http://businesscorp.com.br/images/logo.png
http://businesscorp.com.br/images/preloader.gif
http://businesscorp.com.br/images/sample-image.jpg
http://businesscorp.com.br/images/Sem%20T%C3%ADtulo-1.psd
http://businesscorp.com.br/index
http://businesscorp.com.br/index.html
http://businesscorp.com.br/info
http://businesscorp.com.br/info.php
http://businesscorp.com.br/info.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000
http://businesscorp.com.br/info.php?=PHPE9568F34-D428-11d2-A769-00AA001ACF42
http://businesscorp.com.br/info.php?=PHPE9568F35-D428-11d2-A769-00AA001ACF42
http://businesscorp.com.br/intranet
http://www.businesscorp.com.br/intranet/home.php
http://businesscorp.com.br/js/
http://businesscorp.com.br/js/backstretch.js
http://businesscorp.com.br/js/getClient.js
http://businesscorp.com.br/js/getClient.js//apiClients/showNames.xml
http://businesscorp.com.br/js/gmaps.js
http://businesscorp.com.br/js/init.js
"""
    docs = wayback.parse(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) > 100
    assert all(d["url"].startswith(("http://", "https://")) for d in docs)
    with_params = next(d for d in docs if "?" in d["url"])
    assert with_params["has_params"] is True


def test_rdap_domain():
    # campos reduzidos ao que o parser lê — a resposta RDAP real tem muito
    # mais ruído (notices, links, entidades sem role de registrant etc.).
    raw = """{
  "handle": "businesscorp.com.br",
  "ldhName": "businesscorp.com.br",
  "nameservers": [
    {"ldhName": "ns1.businesscorp.com.br"},
    {"ldhName": "ns2.businesscorp.com.br"}
  ],
  "entities": [
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard", [["fn", {}, "text", "DESEC SECURITY SEGURANCA DA INFORMACAO LTDA"]]]
    }
  ],
  "events": [
    {"eventAction": "registration", "eventDate": "2017-09-04T16:38:02Z"},
    {"eventAction": "last changed", "eventDate": "2025-09-05T08:20:31Z"},
    {"eventAction": "expiration", "eventDate": "2027-09-04T16:38:02Z"}
  ]
}"""
    docs = rdap.parse_domain(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) == 1
    doc = docs[0]
    assert doc["domain"] == "businesscorp.com.br"
    assert doc["handle"] == "businesscorp.com.br"
    assert doc["nameservers"] == ["ns1.businesscorp.com.br", "ns2.businesscorp.com.br"]
    assert "DESEC SECURITY" in doc["registrant"]
    assert len(doc["events"]) == 3
    assert {e["eventAction"] for e in doc["events"]} == {"registration", "last changed", "expiration"}


def test_rdap_network():
    raw = """{
  "handle": "37.59.174.224 - 37.59.174.239",
  "startAddress": "37.59.174.224",
  "endAddress": "37.59.174.239",
  "country": "PT",
  "cidr0_cidrs": [{"v4prefix": "37.59.174.224", "length": 28}],
  "entities": [
    {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "OVH Hosting LDA"]]]}
  ]
}"""
    docs = rdap.parse_network(raw, client=CLIENT, scan_id=SCAN_ID, target="37.59.174.224/28")
    assert len(docs) == 1
    doc = docs[0]
    assert doc["handle"] == "37.59.174.224 - 37.59.174.239"
    assert doc["start_address"] == "37.59.174.224"
    assert doc["end_address"] == "37.59.174.239"
    assert doc["cidr"] == "37.59.174.224/28"
    assert doc["country"] == "PT"
    assert doc["org"] == "OVH Hosting LDA"


def test_masscan():
    raw = "Starting masscan 1.3.2\nDiscovered open port 80/tcp on 192.168.15.1\n"
    docs = masscan.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="192.168.15.1")
    assert len(docs) == 1
    doc = docs[0]
    assert doc == {**doc, "ip": "192.168.15.1", "port": 80, "proto": "tcp", "state": "open"}


def test_nmap():
    # XML reduzido ao que o parser lê (o nmap real inclui um <scaninfo> e
    # <hosthint> enormes, irrelevantes pro parsing) — mesmos 5 hosts/portas
    # de uma varredura real contra 192.168.15.1.
    raw = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.15.1" addrtype="ipv4"/>
<hostnames><hostname name="_gateway" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="Dropbear sshd" version="2020.81"><cpe>cpe:/a:matt_johnston:dropbear_ssh_server:2020.81</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="53"><state state="open"/><service name="domain" product="dnsmasq" version="2.84rc2"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="mini_httpd" version="1.30 26Oct2018"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port>
<port protocol="tcp" portid="3517"><state state="open"/><service name="802-11-iapp"/></port>
</ports>
</host>
</nmaprun>
"""
    docs = nmap.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="192.168.15.1")
    assert len(docs) == 5
    by_port = {d["port"]: d for d in docs}
    assert by_port[22]["service"] == "ssh"
    assert by_port[22]["product"] == "Dropbear sshd"
    assert "cpe:/o:linux:linux_kernel" in by_port[22]["cpe"]
    assert by_port[443]["state"] == "filtered"
    assert all(d["ip"] == "192.168.15.1" and d["hostname"] == "_gateway" for d in docs)


def test_shodan():
    # amostra real reduzida (consulta contra 45.33.32.156 / scanme.nmap.org)
    raw = """{
  "ip_str": "45.33.32.156",
  "org": "Linode",
  "isp": "Akamai Connected Cloud",
  "country_name": "United States",
  "city": "Fremont",
  "hostnames": ["scanme.nmap.org"],
  "vulns": ["CVE-2007-4723", "CVE-2009-0796"],
  "data": [
    {
      "port": 22, "transport": "tcp", "product": "OpenSSH", "version": "6.6.1p1",
      "cpe": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:canonical:ubuntu_linux"]
    },
    {
      "port": 80, "transport": "tcp", "product": "Apache httpd", "version": "2.4.7",
      "cpe": ["cpe:/a:apache:http_server:2.4.7"]
    }
  ]
}"""
    docs = shodan.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="45.33.32.156")
    assert len(docs) == 2
    by_port = {d["port"]: d for d in docs}
    assert by_port[22]["product"] == "OpenSSH"
    assert "cpe:/o:canonical:ubuntu_linux" in by_port[22]["cpe"]
    assert by_port[80]["product"] == "Apache httpd"
    assert all(d["ip"] == "45.33.32.156" for d in docs)
    assert all(d["hostnames"] == ["scanme.nmap.org"] for d in docs)
    assert all(set(d["vulns"]) == {"CVE-2007-4723", "CVE-2009-0796"} for d in docs)
    assert all(d["org"] == "Linode" and d["isp"] == "Akamai Connected Cloud" for d in docs)


def test_shodan_vulns_as_dict():
    # "vulns" às vezes vem como dict (CVE -> detalhes) em vez de lista —
    # visto na prática consultando IPs reais com respostas diferentes.
    raw = '{"ip_str": "1.2.3.4", "vulns": {"CVE-2021-1234": {}, "CVE-2020-0001": {}}, "data": []}'
    docs = shodan.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="1.2.3.4")
    assert len(docs) == 1
    assert docs[0]["port"] is None
    assert set(docs[0]["vulns"]) == {"CVE-2021-1234", "CVE-2020-0001"}


def test_censys():
    # amostra real reduzida (consulta contra 45.33.32.156 / scanme.nmap.org)
    raw = """{
  "result": {
    "resource": {
      "ip": "45.33.32.156",
      "autonomous_system": {"asn": 63949, "description": "Linode"},
      "whois": {"organization": {"name": "Linode"}},
      "location": {"country": "United States", "city": "Fremont"},
      "services": [
        {
          "port": 22, "protocol": "SSH", "transport_protocol": "tcp",
          "software": [{"type": ["REMOTE_ACCESS"]}, {"vendor": "openbsd", "product": "openssh"}],
          "labels": [{"value": "REMOTE_ACCESS"}]
        },
        {
          "port": 80, "protocol": "HTTP", "transport_protocol": "tcp",
          "software": [{"vendor": "apache", "product": "http_server"}],
          "labels": [{"value": "WEB_UI"}]
        }
      ]
    }
  }
}"""
    docs = censys.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="45.33.32.156")
    assert len(docs) == 2
    by_port = {d["port"]: d for d in docs}
    assert by_port[22]["protocol"] == "SSH"
    assert by_port[22]["software"] == ["openbsd:openssh"]
    assert by_port[80]["software"] == ["apache:http_server"]
    assert all(d["ip"] == "45.33.32.156" and d["asn"] == 63949 for d in docs)
    assert all(d["org"] == "Linode" and d["city"] == "Fremont" for d in docs)


def test_censys_no_services_yields_no_docs():
    # Comum, não é exceção: qualquer IP sem porta encontrada pela Censys
    # devolve "services": [] — visto na prática inclusive contra faixas
    # reservadas (TEST-NET). Mesmo comportamento do nmap sem portas abertas.
    raw = '{"result": {"resource": {"ip": "203.0.113.1", "services": []}}}'
    docs = censys.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="203.0.113.1")
    assert docs == []


def test_nikto():
    # amostra real (nikto -Format xml contra businesscorp.com.br)
    raw = """<?xml version="1.0" ?>
<niktoscans>
<niktoscan version="2.5.0">
<scandetails targetip="37.59.174.225" targethostname="businesscorp.com.br" targetport="80">
<item id="999984" method="GET">
<description><![CDATA[/: Server may leak inodes via ETags.]]></description>
<uri><![CDATA[/]]></uri>
<references><![CDATA[CVE-2003-1418]]></references>
</item>
<item id="999957" method="GET">
<description><![CDATA[/: The anti-clickjacking X-Frame-Options header is not present.]]></description>
<uri><![CDATA[/]]></uri>
<references><![CDATA[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options]]></references>
</item>
<item id="999103" method="GET">
<description><![CDATA[/: The X-Content-Type-Options header is not set.]]></description>
<uri><![CDATA[/]]></uri>
<references><![CDATA[https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/]]></references>
</item>
</scandetails>
</niktoscan>
</niktoscans>
"""
    docs = nikto.parse(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) == 3
    assert docs[0]["finding_id"] == "999984"
    assert docs[0]["host"] == "businesscorp.com.br"
    assert docs[0]["port"] == 80
    assert docs[0]["uri"] == "/"


def test_nmap_rejects_xml_entity_expansion_dos():
    # Auditoria de segurança: defusedxml.ElementTree (troca do
    # xml.etree.ElementTree stdlib) recusa a expansão de entidades ("billion
    # laughs") em vez de consumir memória sem limite — um alvo malicioso
    # controlando a resposta de banner/serviço não deve conseguir derrubar o
    # worker via XML forjado. Rejeita com exceção, não silenciosamente.
    raw = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<nmaprun scanner="nmap">
<host><address addr="&lol2;" addrtype="ipv4"/></host>
</nmaprun>
"""
    with pytest.raises(defusedxml.common.EntitiesForbidden):
        nmap.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="192.168.15.1")


def test_nuclei():
    # campos reduzidos ao que o parser lê — a saída real do nuclei tem
    # request/response completos, curl-command etc., tudo ignorado aqui.
    raw = (
        '{"template-id":"apache-mod-negotiation-listing","host":"businesscorp.com.br",'
        '"matched-at":"http://businesscorp.com.br/config","info":{"name":"Apache mod_negotiation - '
        'Pseudo Directory Listing","severity":"low","tags":["apache","misconfig"],'
        '"classification":{"cve-id":null}}}\n'
        '{"template-id":"apache-mod-negotiation-listing","host":"businesscorp.com.br",'
        '"matched-at":"http://businesscorp.com.br/index","info":{"name":"Apache mod_negotiation - '
        'Pseudo Directory Listing","severity":"low","tags":["apache","misconfig"],'
        '"classification":{"cve-id":null}}}\n'
        '{"template-id":"waf-detect","host":"businesscorp.com.br",'
        '"matched-at":"http://businesscorp.com.br","info":{"name":"WAF Detection","severity":"info",'
        '"tags":["waf","tech"],"classification":{"cve-id":null}}}\n'
    )
    docs = nuclei.parse(raw, client=CLIENT, scan_id=SCAN_ID, target=DOMAIN)
    assert len(docs) == 3
    ids = [d["template_id"] for d in docs]
    assert ids == ["apache-mod-negotiation-listing", "apache-mod-negotiation-listing", "waf-detect"]
    waf_doc = docs[2]
    assert waf_doc["severity"] == "info"
    assert "waf" in waf_doc["tags"]
    assert all(d["cve"] is None for d in docs)


def test_dalfox():
    # amostra real (achado único, XSS verificado capturado ao vivo contra
    # uma página de teste local) — formato real do dalfox -o result.json: um
    # array JSON (não JSONL, diferente do nuclei), sempre terminado por um
    # objeto vazio sentinela mesmo com zero achados.
    raw = (
        '[\n'
        '{"type":"V","inject_type":"inHTML-URL","poc_type":"plain","method":"GET",'
        '"data":"http://businesscorp.com.br/search?q=hello%27%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60+class%3Ddalfox%3E",'
        '"param":"q","payload":"\'><img/src/onerror=.1|alert`` class=dalfox>",'
        '"evidence":"1 line:  >You searched: hello\'><img/src/onerror=.1|alert`` class=dalfox></p></body></html",'
        '"cwe":"CWE-79","severity":"High","message_id":209,'
        '"message_str":"Triggered XSS Payload (found DOM Object): q=\'><img/src/onerror=.1|alert`` class=dalfox>"},\n'
        '{}]'
    )
    docs = dalfox.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="http://businesscorp.com.br")
    assert len(docs) == 1
    doc = docs[0]
    assert doc["type"] == "V"
    assert doc["param"] == "q"
    assert doc["severity"] == "High"
    assert doc["cwe"] == "CWE-79"
    assert doc["url"].startswith("http://businesscorp.com.br/search?q=")
    assert "onerror" in doc["payload"]


def test_dalfox_no_findings_yields_no_docs():
    # dalfox sem achado ainda grava o sentinela "{}" — não deve virar um doc.
    docs = dalfox.parse("[\n{}]", client=CLIENT, scan_id=SCAN_ID, target="http://businesscorp.com.br")
    assert docs == []


def test_dalfox_invalid_json_yields_no_docs():
    docs = dalfox.parse("not json", client=CLIENT, scan_id=SCAN_ID, target="http://businesscorp.com.br")
    assert docs == []


def test_amass():
    # amostra real (nmap.org), reduzida: grafo de relações do amass v4
    raw = """nmap.org (FQDN) --> ns_record --> ns3.linode.com (FQDN)
ns3.linode.com (FQDN) --> a_record --> 92.123.95.3 (IPAddress)
chat.nmap.org (FQDN) --> a_record --> 45.33.32.156 (IPAddress)
scanme.nmap.org (FQDN) --> a_record --> 45.33.32.156 (IPAddress)
scanme.nmap.org (FQDN) --> aaaa_record --> 2600:3c01::f03c:91ff:fe18:bb2f (IPAddress)
21342 (ASN) --> managed_by --> AKAMAI-ASN2 (RIROrganization)
"""
    docs = amass.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="nmap.org")
    subdomains = {d["subdomain"] for d in docs}
    # ns3.linode.com não é do domínio alvo — não deve aparecer
    assert subdomains == {"nmap.org", "chat.nmap.org", "scanme.nmap.org"}
    assert all(d["tool"] == "amass" for d in docs)


def test_dnsenum():
    # amostra real (nmap.org) com códigos ANSI de cor, como o dnsenum imprime
    raw = "\x1b[0mnmap.org.                                566      IN    A        50.116.1.184\n" \
          "\x1b[0mns1.linode.com.                          150      IN    A        92.123.94.2\n" \
          "\x1b[0mwww.nmap.org.                            3600     IN    A        50.116.1.184\n"
    docs = dnsenum.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="nmap.org")
    subdomains = {d["subdomain"] for d in docs}
    # ns1.linode.com é infraestrutura de terceiros — não deve aparecer
    assert subdomains == {"nmap.org", "www.nmap.org"}


def test_dnsrecon():
    raw = """[
    {"arguments": "...", "date": "...", "type": "ScanInfo"},
    {"address": "50.116.1.184", "domain": "nmap.org", "type": "A"},
    {"address": "50.116.1.184", "name": "www.nmap.org", "type": "A"},
    {"address": "192.178.223.26", "exchange": "ALT1.ASPMX.L.GOOGLE.COM", "type": "MX"}
]"""
    docs = dnsrecon.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="nmap.org")
    subdomains = {d["subdomain"] for d in docs}
    assert subdomains == {"nmap.org", "www.nmap.org"}


def test_dnsx():
    raw = (
        '{"host":"scanme.nmap.org","a":["45.33.32.156"],"status_code":"NOERROR"}\n'
        '{"host":"chat.nmap.org","a":["45.33.32.156"],"status_code":"NOERROR"}\n'
    )
    docs = dnsx.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="nmap.org")
    assert len(docs) == 2
    assert docs[0]["subdomain"] == "scanme.nmap.org"
    assert docs[0]["ips"] == ["45.33.32.156"]
    assert docs[0]["resolved"] is True


def test_gau():
    raw = 'time="..." level=warning msg="config not found"\nhttps://nmap.org/\nhttp://nmap.org/book/toc.html\n'
    docs = gau.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="nmap.org")
    assert len(docs) == 2
    assert all(d["tool"] == "gau" for d in docs)


def test_katana():
    raw = "https://nmap.org\nhttps://nmap.org/book/man.html\nhttps://npcap.com/\n"
    docs = katana.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="https://nmap.org")
    assert len(docs) == 3
    assert {d["domain"] for d in docs} == {"nmap.org", "npcap.com"}


def test_theharvester():
    raw = (
        '{"cmd": "-d tesla.com", "hosts": ["auth.tesla.com", '
        '"repair.tesla.com:repair.tesla.com.edgekey.net"], '
        '"ips": ["1.2.3.4"], "asns": ["AS1234"]}'
    )
    docs = theharvester.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="tesla.com")
    by_type = {}
    for d in docs:
        by_type.setdefault(d["type"], []).append(d["value"])
    assert set(by_type["host"]) == {"auth.tesla.com", "repair.tesla.com"}
    assert by_type["ip"] == ["1.2.3.4"]
    assert by_type["asn"] == ["AS1234"]


def test_gobuster_synthetic():
    # Não há amostra real de gobuster; simula o formato padrão do modo "dir"
    # (mesmo formato usado pelo -o em texto puro).
    raw = """===============================================================
Gobuster v3.8.2
===============================================================
/admin                (Status: 301) [Size: 178]
/login.php            (Status: 200) [Size: 1024]
===============================================================
"""
    docs = gobuster.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="http://businesscorp.com.br")
    assert len(docs) == 2
    assert docs[0]["path"] == "/admin"
    assert docs[0]["status_code"] == 301
    assert docs[0]["size"] == 178
    assert docs[0]["url"] == "http://businesscorp.com.br/admin"
    assert docs[1]["url"] == "http://businesscorp.com.br/login.php"


def test_kiterunner():
    # amostra real (achado único, capturado ao vivo contra um servidor local
    # respondendo 200 em /v1/profile).
    raw = (
        '{"method":"GET","target":"http://127.0.0.1:8899","path":"/v1/profile",'
        '"responses":[{"uri":"","sc":200,"len":17}],"time":"2026-07-18T12:56:29Z"}\n'
    )
    docs = kiterunner.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="http://127.0.0.1:8899")
    assert len(docs) == 1
    doc = docs[0]
    assert doc["path"] == "/v1/profile"
    assert doc["status_code"] == 200
    assert doc["size"] == 17
    assert doc["method"] == "GET"
    assert doc["url"] == "http://127.0.0.1:8899/v1/profile"


def test_kiterunner_no_hits_yields_no_docs():
    docs = kiterunner.parse("", client=CLIENT, scan_id=SCAN_ID, target="http://127.0.0.1:8899")
    assert docs == []


def test_kiterunner_invalid_json_yields_no_docs():
    docs = kiterunner.parse("not json\n{broken", client=CLIENT, scan_id=SCAN_ID, target="http://127.0.0.1:8899")
    assert docs == []


def test_kiterunner_ignores_log_lines_mixed_with_hits():
    # Bug real encontrado ao validar ao vivo: linhas de log ("level":"info",
    # ex: "scan options"/"scan complete") também são JSON válido começando
    # com "{", mas não têm "method"/"responses" — sem o filtro, viravam doc
    # lixo (path vazio, campos None) misturado com os achados reais.
    raw = (
        '{"level":"info","wordlist":"httparchive_apiroutes_2026_02_27.txt","message":"already cached"}\n'
        '{"method":"GET","target":"http://127.0.0.1:8899","path":"/v1/profile",'
        '"responses":[{"uri":"","sc":200,"len":17}],"time":"2026-07-18T12:56:29Z"}\n'
        '{"level":"info","results":1,"duration":123.45,"message":"scan complete"}\n'
    )
    docs = kiterunner.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="http://127.0.0.1:8899")
    assert len(docs) == 1
    assert docs[0]["path"] == "/v1/profile"


def test_wpscan_not_wordpress_yields_no_docs():
    # amostra real (rodado ao vivo contra https://example.com, que não é
    # WordPress) — wpscan sai com scan_aborted, sem prompt interativo.
    raw = """{
  "db_update_started": true,
  "scan_aborted": "The remote website is up, but does not seem to be running WordPress.",
  "target_url": "https://example.com/"
}"""
    docs = wpscan.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="https://example.com")
    assert docs == []


def test_wpscan_real_site_no_vulnerabilities():
    # amostra real reduzida (rodado ao vivo contra uma instância WordPress
    # local descartável, versão 7.0.1 sem plugins/temas vulneráveis).
    raw = """{
  "target_url": "http://127.0.0.1:8899/",
  "interesting_findings": [
    {
      "url": "http://127.0.0.1:8899/xmlrpc.php",
      "to_s": "XML-RPC seems to be enabled: http://127.0.0.1:8899/xmlrpc.php",
      "type": "xmlrpc",
      "confidence": 100,
      "references": {"url": ["http://codex.wordpress.org/XML-RPC_Pingback_API"]}
    }
  ],
  "version": {
    "number": "7.0.1",
    "status": "latest",
    "confidence": 100,
    "vulnerabilities": []
  },
  "main_theme": {
    "slug": "twentytwentyfive",
    "vulnerabilities": [],
    "version": {"number": "1.5"}
  },
  "plugins": {},
  "themes": {},
  "users": {
    "admin": {"id": null, "confidence": 100}
  }
}"""
    docs = wpscan.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="http://127.0.0.1:8899")
    by_type = {}
    for d in docs:
        by_type.setdefault(d["finding_type"], []).append(d)

    assert len(by_type["interesting"]) == 1
    assert by_type["interesting"][0]["url"] == "http://127.0.0.1:8899/xmlrpc.php"

    assert len(by_type["core_version"]) == 1
    assert by_type["core_version"][0]["component_version"] == "7.0.1"
    assert by_type["core_version"][0]["title"] == "WordPress 7.0.1 (latest)"

    assert len(by_type["user"]) == 1
    # title = username puro (sem frase) — a tradução é composta no frontend
    # (ver DataTable.jsx), pra respeitar o idioma selecionado na UI.
    assert by_type["user"][0]["title"] == "admin"

    assert "core_vulnerability" not in by_type
    assert "theme_vulnerability" not in by_type
    assert "plugin_vulnerability" not in by_type


def test_wpscan_synthetic_vulnerabilities():
    # Schema documentado do wpscan (não reproduzido ao vivo — precisaria de
    # um plugin genuinamente desatualizado instalado) para o caminho de
    # plugin/tema/core vulnerável.
    raw = """{
  "target_url": "http://vulnerable.example/",
  "version": {
    "number": "5.0",
    "status": "insecure",
    "vulnerabilities": [
      {"title": "WordPress < 5.1 - Comment Cross-Site Scripting (XSS)",
       "fixed_in": "5.1",
       "references": {"url": ["https://wpscan.com/vulnerability/abc"], "cve": ["2019-9787"]}}
    ]
  },
  "main_theme": {"slug": "twentyseventeen", "vulnerabilities": [], "version": {"number": "1.0"}},
  "plugins": {
    "akismet": {
      "version": {"number": "3.0"},
      "vulnerabilities": [
        {"title": "Akismet < 3.1.5 - SQL Injection", "fixed_in": "3.1.5",
         "references": {"wpvulndb": ["1234"]}}
      ]
    }
  },
  "themes": {},
  "users": {}
}"""
    docs = wpscan.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="http://vulnerable.example")
    by_type = {d["finding_type"]: d for d in docs}

    core_vuln = by_type["core_vulnerability"]
    assert core_vuln["component"] == "wordpress core"
    assert core_vuln["fixed_in"] == "5.1"
    assert "https://nvd.nist.gov/vuln/detail/2019-9787" in core_vuln["references"]

    plugin_vuln = by_type["plugin_vulnerability"]
    assert plugin_vuln["component"] == "akismet"
    assert plugin_vuln["component_version"] == "3.0"
    assert "https://wpscan.com/vulnerability/1234" in plugin_vuln["references"]


def test_wpscan_invalid_json_yields_no_docs():
    docs = wpscan.parse("not json", client=CLIENT, scan_id=SCAN_ID, target="http://x.com")
    assert docs == []


def test_wpscan_core_version_without_status_omits_parenthetical():
    # "status" ausente não deve inventar palavra em nenhum idioma — só
    # some o parêntese, em vez de um fallback hardcoded.
    raw = '{"version": {"number": "6.0"}, "users": {}}'
    docs = wpscan.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="http://x.com")
    core_version = next(d for d in docs if d["finding_type"] == "core_version")
    assert core_version["title"] == "WordPress 6.0"


def test_gowitness():
    # amostra real reduzida (gowitness scan single -u https://example.com
    # --write-jsonl, uma linha JSON só — formato real do --write-jsonl) —
    # html/headers/network/cookies/console omitidos de propósito, o parser
    # não indexa esses campos.
    raw = (
        '{"id": 0, "url": "https://example.com", "final_url": "https://example.com/", '
        '"response_code": 200, "title": "Example Domain", "perception_hash": "p:bc3c38c1c3c3c367", '
        '"file_name": "https---example.com.png", "is_pdf": false, "failed": false, "failed_reason": "", '
        '"tls": {"protocol": "TLS 1.3", "cipher": "AES_128_GCM", "subject_name": "example.com", '
        '"issuer": "Cloudflare TLS Issuing ECC CA 3"}, "technologies": [{"value": "Cloudflare"}]}'
    )
    docs = gowitness.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="https://example.com")
    assert len(docs) == 1
    doc = docs[0]
    assert doc["url"] == "https://example.com"
    assert doc["final_url"] == "https://example.com/"
    assert doc["status_code"] == 200
    assert doc["title"] == "Example Domain"
    assert doc["perception_hash"] == "p:bc3c38c1c3c3c367"
    assert doc["tls_protocol"] == "TLS 1.3"
    assert doc["tls_issuer"] == "Cloudflare TLS Issuing ECC CA 3"
    assert doc["technologies"] == ["Cloudflare"]
    assert doc["failed"] is False
    assert "screenshot_id" not in doc  # anexado depois, em tasks.py — não no parser


def test_gowitness_failed_scan():
    raw = '{"url": "https://down.example", "failed": true, "failed_reason": "net::ERR_CONNECTION_REFUSED"}'
    docs = gowitness.parse(raw, client=CLIENT, scan_id=SCAN_ID, target="https://down.example")
    assert len(docs) == 1
    assert docs[0]["failed"] is True
    assert docs[0]["failed_reason"] == "net::ERR_CONNECTION_REFUSED"


def test_gowitness_invalid_json_yields_no_docs():
    docs = gowitness.parse("not json", client=CLIENT, scan_id=SCAN_ID, target="http://x.com")
    assert docs == []
