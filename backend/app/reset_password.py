"""Reset de senha via banco, pra quando um usuário (inclusive o próprio
admin) perde a senha e não tem outro admin logado pra resetar pela UI (ver
README "Autenticação e usuários").

Uso (de dentro do container do backend):
    docker compose exec backend python -m app.reset_password <username> <nova_senha>
"""

import sys

from . import auth, opensearch_client


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("uso: python -m app.reset_password <username> <nova_senha>", file=sys.stderr)
        return 1

    username, new_password = argv[1], argv[2]
    if len(new_password) < 8:
        print("a nova senha precisa ter pelo menos 8 caracteres", file=sys.stderr)
        return 1

    user = opensearch_client.get_user_by_username(username)
    if not user:
        print(f"usuário '{username}' não encontrado", file=sys.stderr)
        return 1

    opensearch_client.update_user(user["user_id"], password_hash=auth.hash_password(new_password))
    print(f"senha de '{username}' redefinida com sucesso.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
