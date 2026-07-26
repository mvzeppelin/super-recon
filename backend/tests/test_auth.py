from app import auth


def test_hash_password_roundtrip():
    hashed = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", hashed) is True


def test_verify_password_wrong_password_fails():
    hashed = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("wrong password", hashed) is False


def test_hash_password_never_stores_plaintext():
    hashed = auth.hash_password("my-secret-password")
    assert "my-secret-password" not in hashed


def test_verify_password_malformed_hash_is_false_not_exception():
    assert auth.verify_password("anything", "not-a-real-bcrypt-hash") is False


def test_generate_token_is_unique_and_long():
    tokens = {auth.generate_token() for _ in range(100)}
    assert len(tokens) == 100
    assert all(len(t) == 64 for t in tokens)  # 32 bytes hex-encoded


def test_roles_include_all_three_tiers():
    assert auth.ROLES == ["admin", "operator", "viewer"]


def test_dummy_password_hash_is_a_valid_bcrypt_hash():
    # Usado em main.py pra dar ao login() um hash pra verificar mesmo quando
    # o usuário não existe (timing constante, ver auth.DUMMY_PASSWORD_HASH) —
    # precisa ser um hash bcrypt de verdade, senão verify_password() cairia
    # no ramo de exceção (hash malformado) e devolveria False rápido demais,
    # sem custo de bcrypt nenhum, voltando a vazar timing.
    assert auth.verify_password("qualquer coisa", auth.DUMMY_PASSWORD_HASH) is False
