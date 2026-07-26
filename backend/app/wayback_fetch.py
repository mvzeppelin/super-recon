"""Busca paginada na API CDX do Wayback Machine, com teto de registros.

Roda dentro do container efêmero do Kali (`python3 -c "<conteúdo deste
arquivo>" <domínio> <max_records>`) — não usa o binário `waybackurls` porque
ele faz uma única chamada HTTP bloqueante que baixa a resposta inteira antes
de imprimir qualquer coisa. Em domínios com histórico arquivado gigantesco
(ex: acme.com — mais de 15MB baixados em 300s e ainda incompleto, visto na
prática) isso é tudo-ou-nada: se o timeout do container estourar no meio do
download, o resultado inteiro se perde, e não tem valor de timeout que resolva
isso de forma confiável pra qualquer domínio (sempre existe um maior).

Aqui a busca é paginada via resumeKey da própria API CDX e para sozinha ao
atingir `max_records` — o tempo de execução fica limitado por volume de
dados (previsível), não pela sorte da rede/tamanho do domínio. Cada página é
escrita e flushada assim que chega, então mesmo se o container for morto no
meio (timeout batendo antes do teto), o que já foi coletado sobrevive (ver
docker_runner.run(), que lê o arquivo de saída parcial nesse caso).
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

PAGE_SIZE = 10000
PER_PAGE_TIMEOUT = 60
MAX_PAGE_RETRIES = 3
CDX_BASE = "http://web.archive.org/cdx/search/cdx"


def build_page_url(domain: str, resume_key: str | None) -> str:
    q = urllib.parse.quote(f"*.{domain}/*", safe="*./")
    url = f"{CDX_BASE}?url={q}&output=json&fl=original&collapse=urlkey&limit={PAGE_SIZE}&showResumeKey=true"
    if resume_key:
        url += f"&resumeKey={urllib.parse.quote(resume_key)}"
    return url


def split_page(data: list) -> tuple[list[str], str | None]:
    """Separa uma resposta da CDX API em (urls, resume_key).

    Formato observado: [header, *dados, [], [resume_key]] quando há próxima
    página, ou [header, *dados] quando é a última."""
    rows = data[1:]
    if len(rows) >= 2 and rows[-2] == []:
        return [r[0] for r in rows[:-2]], rows[-1][0]
    return [r[0] for r in rows], None


def fetch(
    domain: str,
    max_records: int,
    *,
    urlopen=urllib.request.urlopen,
    out=sys.stdout,
    err=sys.stderr,
) -> int:
    resume_key = None
    seen = 0
    while seen < max_records:
        url = build_page_url(domain, resume_key)
        data = None
        for attempt in range(1, MAX_PAGE_RETRIES + 1):
            try:
                with urlopen(url, timeout=PER_PAGE_TIMEOUT) as resp:
                    data = json.load(resp)
                break
            except Exception as exc:  # noqa: BLE001 - qualquer falha de rede/parse tenta de novo
                print(f"[wayback] tentativa {attempt} falhou: {exc}", file=err)
        if data is None:
            print("[wayback] desistindo após falhas repetidas na página atual", file=err)
            break
        if not data:
            break

        urls, resume_key = split_page(data)
        for u in urls:
            if seen >= max_records:
                break
            print(u, file=out)
            seen += 1
        out.flush()  # garante que a página já está em disco antes de seguir/morrer

        if not resume_key:
            break

    print(f"[wayback] {seen} URLs coletadas (teto: {max_records})", file=err)
    return seen


if __name__ == "__main__":
    fetch(sys.argv[1], int(sys.argv[2]))
