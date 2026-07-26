import ipaddress
import socket


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
