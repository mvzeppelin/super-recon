import ipaddress
import socket
import urllib.parse


def is_ip_or_cidr(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def is_safe_webhook_url(url: str) -> bool:
    """Recusa um destino de webhook (notificação de achado crítico/saúde da
    plataforma, ver notifications.py) que resolva pra rede interna/privada —
    defesa contra SSRF (auditoria de segurança): sem isso, um admin (ou
    alguém que sequestre uma sessão de admin) podia apontar
    NOTIFY_WEBHOOK_URL pra 127.0.0.1, pro endereço de metadados de nuvem
    (169.254.169.254), ou pra outro serviço da rede docker (opensearch,
    redis, backend) e fazer o worker/backend disparar requisições HTTP
    contra eles a cada achado crítico. Resolve TODOS os IPs do hostname
    (getaddrinfo cobre IPv4 e IPv6) e recusa se qualquer um cair em faixa
    privada/loopback/link-local/reservada/multicast — não basta olhar só o
    primeiro resultado, um DNS malicioso pode devolver um público primeiro e
    um interno depois. Chamada tanto ao salvar a configuração
    (settings_registry.py, evita salvar algo já obviamente ruim) quanto
    imediatamente antes de cada disparo (notifications.py, contra
    DNS/TOCTOU: o host podia resolver pra um IP público quando salvo e pra
    um IP interno depois, se o admin não controlar o domínio)."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except OSError:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return False
    return True
