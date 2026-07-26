import os
import re
import uuid
from datetime import datetime, timezone

from fastapi import UploadFile

from . import config, opensearch_client

# Qualquer caractere de controle exceto tab/LF/CR — sinal forte de que o
# arquivo não é texto puro (binário, ou algo diferente de uma wordlist).
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class WordlistError(Exception):
    """Erro de validação do upload — sempre com uma mensagem segura para
    devolver direto ao usuário (nunca expõe path interno/detalhe de sistema)."""


async def read_capped(upload: UploadFile, max_bytes: int) -> bytes:
    """Lê o upload em blocos, parando assim que passar do limite — nunca
    materializa o arquivo inteiro em memória antes de checar o tamanho (um
    upload de alguns GB não deve ser lido até o fim só para ser rejeitado
    depois)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise WordlistError(f"arquivo maior que o limite de {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_lines(raw: bytes) -> list[str]:
    if not raw:
        raise WordlistError("arquivo vazio")
    if b"\x00" in raw:
        raise WordlistError("arquivo não é texto (contém byte nulo) — envie uma wordlist em texto puro")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise WordlistError("arquivo precisa ser texto UTF-8 (uma palavra/caminho por linha)")

    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > config.MAX_WORDLIST_LINE_CHARS:
            raise WordlistError(
                f"linha com mais de {config.MAX_WORDLIST_LINE_CHARS} caracteres — não parece uma wordlist"
            )
        if _CONTROL_CHARS_RE.search(line):
            raise WordlistError("arquivo contém caracteres de controle inválidos")
        lines.append(line)

    if not lines:
        raise WordlistError("wordlist vazia (nenhuma linha válida depois de remover vazias/comentários)")
    if len(lines) > config.MAX_WORDLIST_LINES:
        raise WordlistError(f"mais de {config.MAX_WORDLIST_LINES} linhas — acima do limite permitido")
    return lines


def _sanitize_filename(filename: str | None) -> str:
    """Só para exibição — o arquivo em disco nunca usa esse nome (sempre um
    wordlist_id gerado pelo servidor), então isso não é uma superfície de
    path traversal, só cosmético."""
    base = os.path.basename(filename or "wordlist.txt")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base[:100] or "wordlist.txt"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_wordlist(client_name: str, filename: str | None, raw: bytes) -> dict:
    """Valida o conteúdo e grava em disco com um nome opaco gerado aqui
    (nunca o filename enviado) — evita qualquer forma de path traversal via
    nome de arquivo. Levanta WordlistError com uma mensagem segura em
    qualquer falha de validação."""
    if len(raw) > config.MAX_WORDLIST_BYTES:
        raise WordlistError(f"arquivo maior que o limite de {config.MAX_WORDLIST_BYTES} bytes")

    existing = opensearch_client.list_wordlists(client_name)
    if len(existing) >= config.MAX_WORDLISTS_PER_CLIENT:
        raise WordlistError(
            f"limite de {config.MAX_WORDLISTS_PER_CLIENT} wordlists customizadas por cliente atingido — "
            "remova alguma antes de enviar outra"
        )

    lines = _validate_lines(raw)
    normalized = ("\n".join(lines) + "\n").encode("utf-8")

    wordlist_id = uuid.uuid4().hex
    os.makedirs(config.WORDLISTS_DIR, exist_ok=True)
    path = os.path.join(config.WORDLISTS_DIR, f"{wordlist_id}.txt")
    with open(path, "wb") as fh:
        fh.write(normalized)

    doc = {
        "client": client_name,
        "wordlist_id": wordlist_id,
        "filename": _sanitize_filename(filename),
        "line_count": len(lines),
        "size_bytes": len(normalized),
        "@timestamp": _now_iso(),
    }
    opensearch_client.record_wordlist(client_name, wordlist_id, doc)
    return doc


def list_wordlists(client_name: str) -> list[dict]:
    return opensearch_client.list_wordlists(client_name)


def delete_wordlist(client_name: str, wordlist_id: str) -> bool:
    """Remove o arquivo em disco e o registro — nessa ordem não importa muito,
    mas apagar o registro primeiro e o arquivo depois evitaria um _get_ ver o
    registro sem arquivo; preferimos o inverso (arquivo primeiro) só para não
    deixar um arquivo órfão em disco se a chamada ao OpenSearch falhar."""
    if not opensearch_client.get_wordlist(client_name, wordlist_id):
        return False
    path = os.path.join(config.WORDLISTS_DIR, f"{wordlist_id}.txt")
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    opensearch_client.delete_wordlist_doc(client_name, wordlist_id)
    return True


def delete_client_wordlists(client_name: str) -> int:
    """Usado por delete_client/clear_client_data — sem isso, os arquivos em
    disco ficariam órfãos (o índice {client}-wordlists some, mas o conteúdo
    persistiria no volume indefinidamente)."""
    count = 0
    for doc in list_wordlists(client_name):
        if delete_wordlist(client_name, doc["wordlist_id"]):
            count += 1
    return count


def resolve_for_run(client_name: str, wordlist_id: str) -> tuple[str, str] | None:
    """(host_path, container_path) para montar a wordlist (read-only) no
    container efêmero do gobuster — None se a wordlist não existe ou não
    pertence a esse cliente (não deixa um scan referenciar o wordlist_id de
    outro cliente por engano ou de propósito)."""
    if not opensearch_client.get_wordlist(client_name, wordlist_id):
        return None
    filename = f"{wordlist_id}.txt"
    host_path = os.path.join(config.HOST_WORDLISTS_DIR, filename)
    container_path = f"/custom-wordlist/{filename}"
    return host_path, container_path
