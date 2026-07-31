import os
import re
import shutil
import uuid

from . import config

# Mesmo formato de wordlist_id (uuid4 hex) — validado antes de virar path,
# defesa contra path traversal (mesmo raciocínio de wordlists.py: nunca
# aceita um id que não seja exatamente esse formato).
_SCREENSHOT_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# client_name já é validado na borda da API (ver CLIENT_NAME_RE em
# models.py/main.py) — checagem repetida aqui de propósito (defesa em
# profundidade, auditoria de segurança): este módulo nunca deve confiar
# cegamente em quem chamou já ter validado, já que um client_name tipo
# "../../etc" ou começando com "/" (que descarta SCREENSHOTS_DIR inteiro
# via os.path.join) resultaria em escrever/ler fora do diretório esperado.
_CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _client_dir(client_name: str) -> str:
    if not _CLIENT_NAME_RE.match(client_name):
        raise ValueError(f"nome de cliente inválido: {client_name!r}")
    return os.path.join(config.SCREENSHOTS_DIR, client_name)


def persist(client_name: str, source_path: str) -> str | None:
    """Move um screenshot do diretório de troca efêmero (que será apagado
    assim que o container do gowitness terminar) pra um local persistente,
    com um id opaco gerado aqui. None se source_path não existir (ex:
    gowitness falhou antes de conseguir tirar o screenshot)."""
    if not os.path.exists(source_path):
        return None
    screenshot_id = uuid.uuid4().hex
    dest_dir = _client_dir(client_name)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, f"{screenshot_id}.jpeg")
    shutil.move(source_path, dest_path)
    return screenshot_id


def resolve(client_name: str, screenshot_id: str) -> str | None:
    """Path absoluto do screenshot, ou None se o client/id não bate com o
    formato esperado (path traversal) ou o arquivo não existe."""
    if not _SCREENSHOT_ID_RE.match(screenshot_id):
        return None
    try:
        client_dir = _client_dir(client_name)
    except ValueError:
        return None
    path = os.path.join(client_dir, f"{screenshot_id}.jpeg")
    return path if os.path.exists(path) else None


def delete_client_screenshots(client_name: str) -> None:
    """Usado por delete_client/clear_client_data — sem isso, os arquivos em
    disco ficariam órfãos (mesmo raciocínio de delete_client_wordlists)."""
    shutil.rmtree(_client_dir(client_name), ignore_errors=True)
