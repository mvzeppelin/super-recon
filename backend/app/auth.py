"""Lógica pura de autenticação (hash de senha, geração de token) — sem
I/O, testável sem OpenSearch. Quem busca/grava usuário e sessão é
opensearch_client.py; quem decide se uma requisição pode passar é o
middleware em main.py."""

import secrets

import bcrypt

# Papéis do sistema — inglês/keyword, mesmo padrão já usado em todo o
# resto do projeto pra campos de dado (status de job, severidade, nome de
# ferramenta); a tradução pro rótulo em português/inglês acontece só na UI.
ROLES = ["admin", "operator", "viewer"]

# Nº de bytes do token de sessão (ver generate_token) — 32 bytes = 64
# caracteres hex, mesma ordem de grandeza de uma API key gerada com
# "openssl rand -hex 32" (já era a recomendação deste projeto pra API_KEY).
_TOKEN_BYTES = 32


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # hash malformado/vazio (ex: doc de usuário corrompido) — trata
        # como senha errada, não deixa a exceção subir e virar 500.
        return False


# Hash de custo idêntico ao de hash_password(), mas de uma senha que nunca é
# usada de verdade — existe só pra dar ao login() um verify_password() pra
# rodar quando o usuário não existe. Sem isso, checar "usuário existe?" antes
# de chamar verify_password() faz login com usuário inexistente responder
# bem mais rápido (pula o bcrypt.checkpw, que sozinho custa ~100-300ms) do
# que login com usuário existente e senha errada — um timing side-channel
# clássico pra enumerar quais usernames existem, sem precisar acertar senha
# nenhuma. Calculado uma vez, na subida do processo.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(16))


def generate_token() -> str:
    return secrets.token_hex(_TOKEN_BYTES)
