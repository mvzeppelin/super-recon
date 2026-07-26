import requests

from . import config

_API_URL = "https://api.shodan.io/shodan/host/{ip}"
_HTTP_TIMEOUT = 15


class NotFoundError(Exception):
    """Shodan não tem esse IP indexado (HTTP 404) — não é falha, é ausência
    de dado."""


class PlanRequiredError(Exception):
    """Shodan tem dado sobre o IP, mas o plano da API key não dá acesso ao
    Host Lookup para ele (HTTP 403 "Requires membership or higher to
    access"). Visto na prática com o plano free ("Membership"): funciona
    para alguns IPs (aparentemente já em cache/liberados) e falha para
    outros com dado real, sem um padrão previsível de antemão. Diferente de
    NotFoundError: aqui a Shodan sabe algo sobre o IP, só não deixa a gente
    ver com essa key."""


def lookup(ip: str) -> str:
    resp = requests.get(_API_URL.format(ip=ip), params={"key": config.SHODAN_API_KEY}, timeout=_HTTP_TIMEOUT)
    if resp.status_code == 404:
        raise NotFoundError(ip)
    if resp.status_code == 403:
        raise PlanRequiredError(resp.text)
    resp.raise_for_status()
    return resp.text
