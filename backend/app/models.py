import re
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

_RUN_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
# Mínimo pragmático — não é uma política de complexidade de senha completa,
# só evita o caso óbvio de senha vazia/de poucos caracteres. Vale pro admin
# semeado também (ver README "Autenticação e usuários": "admin@superRecon"
# tem mais que isso).
_MIN_PASSWORD_LENGTH = 8

# Ferramentas selecionáveis por scan (Fase 4 — ver README "Perfis de scan
# por execução"). A Fase 1 (recon passivo) continua sempre rodando junto,
# fora do escopo desse checklist.
PHASE4_TOOLS = ["gobuster", "nikto", "nuclei", "katana", "wpscan", "dalfox", "gowitness", "kiterunner"]


def _validate_enabled_tools(value: list[str] | None) -> None:
    if value is not None and (unknown := set(value) - set(PHASE4_TOOLS)):
        raise ValueError(f"ferramentas desconhecidas em enabled_tools: {sorted(unknown)}")


class ScanRequest(BaseModel):
    client: str = Field(min_length=1)
    targets: list[str] = Field(min_length=1)
    # "common" (dirb/common.txt, ~4.6k palavras) é o padrão rápido; "big"
    # (dirb/big.txt, ~20k) é mais completo mas bem mais lento no gobuster;
    # "custom" usa uma wordlist enviada pelo usuário (gobuster_custom_wordlist_id).
    gobuster_wordlist: Literal["common", "big", "custom"] = "common"
    gobuster_custom_wordlist_id: str | None = None
    # None = usa o default (5 sempre-ligadas + opt-in conforme .env, ver
    # config.resolve_enabled_tools) — lista explícita substitui por completo.
    enabled_tools: list[str] | None = None

    @model_validator(mode="after")
    def _check_custom_wordlist_id(self):
        if self.gobuster_wordlist == "custom" and not self.gobuster_custom_wordlist_id:
            raise ValueError("gobuster_custom_wordlist_id é obrigatório quando gobuster_wordlist='custom'")
        _validate_enabled_tools(self.enabled_tools)
        return self


class ScanResponse(BaseModel):
    scan_id: str
    client: str
    targets: list[str]
    status: str


class DeleteFindingsRequest(BaseModel):
    ids: list[str] = Field(min_length=1)


class RecurringScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1)
    gobuster_wordlist: Literal["common", "big", "custom"] = "common"
    gobuster_custom_wordlist_id: str | None = None
    # None = usa o default no momento de cada disparo (ver
    # config.resolve_enabled_tools) — não fixado na criação do alvo salvo,
    # pra acompanhar mudanças de *_ENABLED no .env entre uma execução e outra.
    enabled_tools: list[str] | None = None
    # Desativado por padrão — o registro em si já serve como "alvos salvos"
    # reutilizáveis (via run-now) mesmo sem a recorrência automática ligada.
    enabled: bool = False
    periodicity: Literal["daily", "weekly", "monthly"] | None = None
    # "HH:MM", sempre UTC (ver README "Recorrência de scans").
    run_time: str | None = None
    weekday: int | None = None  # 0=segunda .. 6=domingo, obrigatório se weekly
    day_of_month: int | None = None  # 1-31, obrigatório se monthly (clampado em meses curtos)

    @model_validator(mode="after")
    def _check_schedule_fields(self):
        if self.gobuster_wordlist == "custom" and not self.gobuster_custom_wordlist_id:
            raise ValueError("gobuster_custom_wordlist_id é obrigatório quando gobuster_wordlist='custom'")
        _validate_enabled_tools(self.enabled_tools)

        if not self.enabled:
            return self

        if not self.periodicity:
            raise ValueError("periodicity é obrigatório quando enabled=True")
        if not self.run_time or not _RUN_TIME_RE.match(self.run_time):
            raise ValueError("run_time é obrigatório e deve estar no formato HH:MM (UTC) quando enabled=True")
        if self.periodicity == "weekly" and (self.weekday is None or not (0 <= self.weekday <= 6)):
            raise ValueError("weekday (0=segunda..6=domingo) é obrigatório quando periodicity='weekly'")
        if self.periodicity == "monthly" and (self.day_of_month is None or not (1 <= self.day_of_month <= 31)):
            raise ValueError("day_of_month (1-31) é obrigatório quando periodicity='monthly'")
        return self


class RecurringScanResponse(BaseModel):
    schedule_id: str
    client: str
    targets: list[str]
    gobuster_wordlist: str
    gobuster_custom_wordlist_id: str | None = None
    enabled_tools: list[str] | None = None
    enabled: bool
    periodicity: str | None = None
    run_time: str | None = None
    weekday: int | None = None
    day_of_month: int | None = None
    next_run_at: str | None = None
    last_run_at: str | None = None
    last_scan_id: str | None = None
    created_at: str
    updated_at: str


# ---- Autenticação (ver README "Autenticação e usuários") ----


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str
    # True só quando esse login usou a senha padrão semeada na instalação
    # (ver README "Autenticação e usuários") — o frontend usa isso pra
    # avisar que ela precisa ser trocada, já que é uma credencial pública.
    must_change_password: bool = False


class MeResponse(BaseModel):
    username: str
    role: str


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=_MIN_PASSWORD_LENGTH)
    role: Literal["admin", "operator", "viewer"]


class UpdateUserRequest(BaseModel):
    # Só os dois campos editáveis depois de criado — trocar username
    # trocaria a identidade do usuário sem trocar o histórico de auditoria
    # já gravado com o nome antigo, então não é suportado aqui.
    role: Literal["admin", "operator", "viewer"] | None = None
    disabled: bool | None = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=_MIN_PASSWORD_LENGTH)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=_MIN_PASSWORD_LENGTH)


class UserResponse(BaseModel):
    user_id: str
    username: str
    role: str
    disabled: bool
    created_at: str
    updated_at: str


class AuditLogEntry(BaseModel):
    user_id: str
    username: str
    role: str
    method: str
    path: str
    status_code: int


class UpdateSettingsRequest(BaseModel):
    # Heterogêneo de propósito (int/bool/str/lista, uma por chave do
    # registro em settings_registry.py) — não dá pra tipar campo a campo
    # num único modelo estático; a validação fina (tipo certo, mínimo)
    # acontece em settings_registry.validate(), não aqui. Valor None numa
    # chave = "restaurar essa configuração pro padrão de fábrica".
    overrides: dict[str, Any]
