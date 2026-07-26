"""Trava de força bruta em POST /auth/login — sem isso, nada nesse projeto
impede tentar senha ilimitadamente contra um username (nem o admin semeado
na instalação, cuja senha padrão é pública no README). Contador por
username (não por IP: um IP só protege contra um atacante de fonte única,
username protege a conta mesmo com tentativas distribuídas) guardado no
Redis (já usado pelo projeto, ver tasks.py) — db diferente do db=1 usado
pelo round-robin de cores, pra não misturar namespace."""

import redis

from . import config

_redis = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, password=config.REDIS_PASSWORD, db=2)

_MAX_ATTEMPTS = 10
_WINDOW_SECONDS = 15 * 60


def _key(username: str) -> str:
    return f"login_fail:{username}"


def is_locked_out(username: str) -> bool:
    raw = _redis.get(_key(username))
    return raw is not None and int(raw) >= _MAX_ATTEMPTS


def record_failure(username: str) -> None:
    key = _key(username)
    count = _redis.incr(key)
    if count == 1:
        _redis.expire(key, _WINDOW_SECONDS)


def reset(username: str) -> None:
    _redis.delete(_key(username))
