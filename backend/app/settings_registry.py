"""Registro único das configurações editáveis pela tela "Configurações"
(admin) — sem I/O, testável isolado (mesmo padrão de auth.py). Cada
entrada descreve uma constante de config.py que é lida direto do módulo
(config.NOME) toda vez que é usada em qualquer lugar do backend — não há
cópia em variável de outro módulo, closure ou default de função — então
sobrescrever o atributo aqui (apply_overrides) já vale pro processo
inteiro no próximo uso, sem precisar tocar nenhum dos pontos de leitura
espalhados em commands.py/notifications.py/wordlists.py/main.py.

Ficam de fora de propósito (só .env, ver README "Configurações"):
RECON_CPUS, REDIS_*, OPENSEARCH_ADMIN_*, *_HOST_BIND, *_PORT, KALI_IMAGE,
EXCHANGE_DIR/HOST_EXCHANGE_DIR/WORDLISTS_DIR/HOST_WORDLISTS_DIR/
SCREENSHOTS_DIR, GOBUSTER_WORDLIST_COMMON/BIG, NUCLEI_TEMPLATE_DIRS,
KITERUNNER_WORDLIST, ILM_*_RETENTION_DAYS — infra de bootstrap (credencial,
bind/porta, path de volume Docker) ou presos a um client/processo já
criado no boot (OpenSearch/Celery), mudar exigiria restart de qualquer
forma.
"""

from typing import Any

from . import config

# type: "int" | "bool" | "str" | "csv_set"
# secret=True: nunca devolvido em texto por effective_view() — só
# "is_set": bool. Ver main.py (PUT /settings) para a semântica de
# "campo em branco não mexe" desses.
SETTINGS = [
    # ---- sessão ----
    {"key": "SESSION_TTL_DAYS", "group": "session", "type": "int", "min": 1},
    # ---- upload de wordlists customizadas ----
    {"key": "MAX_WORDLIST_BYTES", "group": "wordlists", "type": "int", "min": 1024},
    {"key": "MAX_WORDLIST_LINES", "group": "wordlists", "type": "int", "min": 1},
    {"key": "MAX_WORDLIST_LINE_CHARS", "group": "wordlists", "type": "int", "min": 1},
    {"key": "MAX_WORDLISTS_PER_CLIENT", "group": "wordlists", "type": "int", "min": 1},
    {"key": "GOBUSTER_CUSTOM_TIMEOUT", "group": "wordlists", "type": "int", "min": 1},
    # ---- notificação em achado crítico ----
    {"key": "NOTIFY_SEVERITIES", "group": "notifications", "type": "csv_set"},
    {"key": "SLACK_BOT_TOKEN", "group": "notifications", "type": "str", "secret": True},
    {"key": "SLACK_CHANNEL", "group": "notifications", "type": "str"},
    {"key": "NOTIFY_WEBHOOK_URL", "group": "notifications", "type": "str"},
    {"key": "PUBLIC_BASE_URL", "group": "notifications", "type": "str"},
    # ---- monitor de saúde / recorrência (<=0 desliga o loop, sem min) ----
    {"key": "HEALTH_CHECK_INTERVAL_SECONDS", "group": "monitoring", "type": "int"},
    {"key": "HEALTH_QUEUE_BACKLOG_THRESHOLD", "group": "monitoring", "type": "int", "min": 0},
    {"key": "HEALTH_STUCK_JOB_MINUTES", "group": "monitoring", "type": "int", "min": 1},
    {"key": "RECURRENCE_CHECK_INTERVAL_SECONDS", "group": "monitoring", "type": "int"},
    # ---- ferramentas opt-in da Fase 4 ----
    {"key": "GOWITNESS_ENABLED", "group": "phase4_optional", "type": "bool"},
    {"key": "DALFOX_ENABLED", "group": "phase4_optional", "type": "bool"},
    {"key": "KITERUNNER_ENABLED", "group": "phase4_optional", "type": "bool"},
    {"key": "KITERUNNER_WORDLIST_LINES", "group": "phase4_optional", "type": "int", "min": 1},
    # ---- integrações externas (dados passivos) ----
    {"key": "SHODAN_API_KEY", "group": "integrations", "type": "str", "secret": True},
    {"key": "CENSYS_API_KEY", "group": "integrations", "type": "str", "secret": True},
    {"key": "WPSCAN_API_TOKEN", "group": "integrations", "type": "str", "secret": True},
    # ---- timeout de cada ferramenta (segundos) ----
    {"key": "ASSETFINDER_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "SUBFINDER_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "SUBLIST3R_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "AMASS_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "DNSENUM_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "DNSRECON_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "RDAP_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "WAYBACK_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "WAYBACK_MAX_RECORDS", "group": "timeouts", "type": "int", "min": 1},
    {"key": "GAU_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "THEHARVESTER_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "KATANA_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "HTTPX_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "DNSX_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "MASSCAN_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "NMAP_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "NUCLEI_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "NIKTO_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "WPSCAN_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "GOWITNESS_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "DALFOX_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
    {"key": "KITERUNNER_TIMEOUT", "group": "timeouts", "type": "int", "min": 1},
]

_BY_KEY = {entry["key"]: entry for entry in SETTINGS}

# Snapshot dos valores vindos do .env, tirado na importação — antes de
# qualquer override ser aplicado (ver main.py: _load_settings_overrides,
# que roda depois, no startup). É o "valor de fábrica" que a tela usa pra
# mostrar "esse campo foi alterado?" e pro botão "restaurar padrão".
_DEFAULTS: dict[str, Any] = {entry["key"]: getattr(config, entry["key"]) for entry in SETTINGS}


def is_known(key: str) -> bool:
    return key in _BY_KEY


def is_secret(key: str) -> bool:
    return bool(_BY_KEY[key].get("secret"))


def default_value(key: str) -> Any:
    return _DEFAULTS[key]


def validate(key: str, value: Any) -> Any:
    """Confere tipo (e min, quando aplicável) e devolve o valor já no
    formato pronto pra setattr(config, key, ...). Levanta ValueError com
    mensagem clara (vira 400 na rota) se o valor não bater com o tipo
    esperado."""
    entry = _BY_KEY[key]
    kind = entry["type"]

    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{key}: esperado true/false")
        return value

    if kind == "int":
        # bool é subclasse de int em Python — sem essa checagem, True/False
        # passariam como 1/0 sem avisar que o tipo está errado.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key}: esperado um número inteiro")
        min_value = entry.get("min")
        if min_value is not None and value < min_value:
            raise ValueError(f"{key}: valor mínimo é {min_value}")
        return value

    if kind == "str":
        if not isinstance(value, str):
            raise ValueError(f"{key}: esperado texto")
        return value

    if kind == "csv_set":
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{key}: esperada uma lista de textos")
        return {item.strip().lower() for item in value if item.strip()}

    raise AssertionError(f"tipo desconhecido no registro: {kind}")  # pragma: no cover


def apply_overrides(overrides: dict[str, Any]) -> None:
    """Sobrescreve config.<KEY> pra cada chave presente — reflete
    imediatamente em todo o resto do backend (ver docstring do módulo)."""
    for key, value in overrides.items():
        if is_known(key):
            setattr(config, key, validate(key, value))


def effective_view(overrides: dict[str, Any]) -> list[dict[str, Any]]:
    """Monta a resposta de GET /settings: uma entrada por configuração,
    com o valor atual (já refletindo overrides persistidos), o default de
    fábrica, e se está sobrescrito. Campo secreto nunca devolve o valor —
    só se está definido (is_set) — ver README "Configurações"."""
    result = []
    for entry in SETTINGS:
        key = entry["key"]
        overridden = key in overrides
        current = getattr(config, key)
        item: dict[str, Any] = {
            "key": key,
            "group": entry["group"],
            "type": entry["type"],
            "overridden": overridden,
            "secret": bool(entry.get("secret")),
        }
        if entry.get("secret"):
            item["is_set"] = bool(current)
        else:
            item["value"] = sorted(current) if entry["type"] == "csv_set" else current
            item["default"] = sorted(_DEFAULTS[key]) if entry["type"] == "csv_set" else _DEFAULTS[key]
        result.append(item)
    return result
