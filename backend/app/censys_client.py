import requests

from . import config

_API_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"
_HTTP_TIMEOUT = 15


def lookup(ip: str) -> str:
    """Diferente da Shodan, a Platform API da Censys sempre responde 200 pra
    IP válido (mesmo sem nenhum serviço encontrado — "services": [] nesse
    caso, testado na prática inclusive contra faixas reservadas tipo
    TEST-NET) — não existe um "404 sem dado" equivalente ao da Shodan aqui;
    quem decide se há achado é o parser, olhando o array "services"."""
    resp = requests.get(
        _API_URL.format(ip=ip),
        headers={"Authorization": f"Bearer {config.CENSYS_API_KEY}"},
        timeout=_HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.text
