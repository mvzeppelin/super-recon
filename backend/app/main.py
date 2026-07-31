import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, Path, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from . import auth, compare as compare_mod, config, docker_runner, export as export_mod, login_throttle, opensearch_client, recurrence, settings_registry, tasks, util
from . import health_monitor, recurrence_scheduler, screenshots as screenshots_mod, wordlists as wordlists_mod
from .models import (
    CLIENT_NAME_RE,
    PHASE4_TOOLS,
    ChangePasswordRequest,
    CreateUserRequest,
    DeleteFindingsRequest,
    LoginRequest,
    LoginResponse,
    MeResponse,
    RecurringScanRequest,
    ResetPasswordRequest,
    ScanRequest,
    ScanResponse,
    UpdateSettingsRequest,
    UpdateUserRequest,
    UserResponse,
)

# `client`/`suffix` viram nome de índice no OpenSearch e path de arquivo em
# vários lugares — charset restrito aqui, na borda da API, fecha de uma vez
# (pra toda rota que os recebe como parâmetro de URL) o que um valor tipo
# "*" ou "../../etc" conseguiria fazer rio abaixo (ler/apagar dados de
# outro cliente via glob no índice, ou escapar do diretório esperado — ver
# CHANGELOG). Mesmo regex de ScanRequest.client (models.py), reusado aqui
# pros parâmetros de rota. "suffix" é sempre minúsculo na prática (nome de
# ferramenta/índice), mas aceita o mesmo charset por simplicidade.
ClientPath = Annotated[str, Path(pattern=CLIENT_NAME_RE.pattern)]
ClientQuery = Annotated[str, Query(pattern=CLIENT_NAME_RE.pattern)]
SuffixPath = Annotated[str, Path(pattern=CLIENT_NAME_RE.pattern)]

app = FastAPI(title="super-recon orchestrator", version="1.1.1")

# ?token= (usado pelos links de export/screenshot, ver _extract_token) é uma
# credencial de sessão em texto puro — sem isso, ela vai inteira pro log de
# acesso do uvicorn a cada request (docker compose logs backend), plaintext,
# válida por até SESSION_TTL_DAYS. Redige só o valor, mantém o resto do log
# útil pra debug (método/rota/status).
_TOKEN_LOG_RE = re.compile(r"(token=)[0-9a-f]{10,}")


class _RedactTokenFilter(logging.Filter):
    """uvicorn.logging.AccessFormatter monta a linha de log direto de
    record.args — uma tupla (client_addr, method, full_path, http_version,
    status_code), não de record.msg/getMessage() (esse é só o template
    "%s..."). Por isso redige o elemento full_path (índice 2) na tupla, sem
    trocar o formato dela — trocá-la por outra coisa (ex: um record.msg já
    formatado com args=()) quebra o unpacking de 5 valores que o formatter
    faz, e derruba o próprio logging."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            full_path = args[2]
            redacted = _TOKEN_LOG_RE.sub(r"\1***", full_path)
            if redacted != full_path:
                record.args = (*args[:2], redacted, *args[3:])
        return True


logging.getLogger("uvicorn.access").addFilter(_RedactTokenFilter())

_EXPORT_MEDIA_TYPES = {"json": "application/json", "csv": "text/csv", "pdf": "application/pdf"}

# "jobs"/"scans"/"wordlists"/"scan-schedules" são metadados, não achados —
# têm ciclo de vida e endpoints próprios, então ficam fora do "excluir
# achados específicos" e do "comparar scans".
_NON_FINDINGS_SUFFIXES = {"jobs", "scans", "wordlists", "scan-schedules"}

# /health fica de fora porque é chamado pelo HEALTHCHECK do próprio
# container (dentro da rede docker, sem passar pela porta exposta ao host)
# e usado pelo frontend/gate pra uma checagem sem custo; /auth/login fica de
# fora porque é o próprio ato de se autenticar — exigir sessão pra logar
# seria uma trava sem saída.
_AUTH_EXEMPT_PATHS = {"/health", "/auth/login"}
_TOKEN_HEADER_PREFIX = "Bearer "
_TOKEN_QUERY_PARAM = "token"
_AUDITED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

_DEFAULT_ADMIN_USERNAME = "admin"
_DEFAULT_ADMIN_PASSWORD = "admin@superRecon"  # noqa: S105 — credencial pública de instalação, ver README


@app.on_event("startup")
def _start_health_monitor() -> None:
    health_monitor.start()


@app.on_event("startup")
def _start_recurrence_scheduler() -> None:
    recurrence_scheduler.start()


@app.on_event("startup")
def _seed_admin_user() -> None:
    """Cria o usuário admin padrão na primeira subida (ver README
    "Autenticação e usuários") — idempotente, roda toda subida do backend
    mas só cria se ainda não existir nenhum usuário "admin" (ex: alguém já
    renomeou/excluiu o padrão)."""
    if opensearch_client.get_user_by_username(_DEFAULT_ADMIN_USERNAME):
        return
    opensearch_client.create_user(
        user_id=uuid.uuid4().hex, username=_DEFAULT_ADMIN_USERNAME,
        password_hash=auth.hash_password(_DEFAULT_ADMIN_PASSWORD), role="admin",
    )


@app.on_event("startup")
def _load_settings_overrides() -> None:
    """Aplica por cima dos defaults do .env qualquer configuração já salva
    pela tela "Configurações" (ver README) — roda toda subida do backend,
    senão um override feito ontem se perderia no próximo restart."""
    settings_registry.apply_overrides(opensearch_client.get_settings_overrides())


def _extract_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith(_TOKEN_HEADER_PREFIX):
        return auth_header[len(_TOKEN_HEADER_PREFIX):]
    return request.query_params.get(_TOKEN_QUERY_PARAM) or None


@app.middleware("http")
async def require_auth_and_audit(request: Request, call_next):
    """Toda rota (exceto as em _AUTH_EXEMPT_PATHS) exige uma sessão válida —
    token via "Authorization: Bearer <token>" ou ?token= (query string,
    usado pelos links de download do ExportButtons e pelas imagens do
    gowitness, que são <a href>/<img src> simples, sem como mandar header
    customizado). Resolve pra request.state.user (usado pelas rotas via
    require_role, e por este mesmo middleware pra montar o log de
    auditoria). Depois da rota rodar, se for uma mutação (POST/PUT/DELETE/
    PATCH) que deu certo (2xx), grava uma entrada em audit-log — só
    /auth/login foge desse caminho genérico (grava o próprio evento no
    handler: como é isento de autenticação, request.state.user nunca chega
    a existir pra ele; /auth/logout passa por aqui normalmente, já que
    deslogar exige estar logado)."""
    if request.url.path in _AUTH_EXEMPT_PATHS:
        return await call_next(request)

    token = _extract_token(request)
    session = opensearch_client.get_session(token) if token else None
    if not session:
        return JSONResponse(status_code=401, content={"detail": "sessão ausente, inválida ou expirada"})

    user = opensearch_client.get_user(session["user_id"])
    if not user or user.get("disabled"):
        return JSONResponse(status_code=401, content={"detail": "usuário inválido ou desativado"})

    request.state.user = {"user_id": user["user_id"], "username": user["username"], "role": user["role"]}

    response = await call_next(request)

    if request.method in _AUDITED_METHODS and 200 <= response.status_code < 300:
        opensearch_client.record_audit(request.state.user, request.method, request.url.path, response.status_code)

    return response


def require_role(*roles: str):
    """Dependency factory — Depends(require_role("admin")) numa rota exige
    que request.state.user["role"] esteja entre os papéis passados (403 se
    não estiver). Só pra mutações que precisam de mais que "estar logado";
    GETs não usam isso, a autenticação genérica do middleware já basta."""

    def checker(request: Request) -> None:
        if request.state.user["role"] not in roles:
            raise HTTPException(status_code=403, detail="seu papel não tem permissão pra essa ação")

    return checker


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cancel_job(client: str, job: dict) -> None:
    """Marca o job como cancelado, mata a task no Celery (SIGKILL — garante
    que o próprio worker não sobrescreva esse status com "ok"/"error" logo
    em seguida) e para o container do Kali associado, se já tiver subido."""
    job_id = job["job_id"]
    opensearch_client.record_job(
        client_name=client, job_id=job_id, scan_id=job["scan_id"], tool=job["tool"], target=job["target"],
        status="cancelled", finished_at=_now_iso(),
    )
    tasks.celery_app.control.revoke(job_id, terminate=True, signal="SIGKILL")
    container_id = job.get("container_id")
    if container_id:
        docker_runner.stop_container(container_id)

# Parâmetros de controle reservados em /clients/{client}/{suffix} — qualquer
# outro query param vira filtro exato (term) sobre o campo de mesmo nome
# (ex: ?tool=assetfinder, ?severity=critical, ?status_code=200). token
# também é reservado aqui pelo mesmo motivo do middleware de auth: não é um
# campo de índice, viraria um filtro que nunca bate com nada.
_RESERVED_QUERY_PARAMS = {"q", "page", "size", "sort", _TOKEN_QUERY_PARAM}


def _filters_from_query(request: Request, extra_reserved: set[str] = frozenset()) -> dict[str, list[str]]:
    """Monta o dict de filtros a partir da query string, agrupando valores
    repetidos do mesmo campo numa lista (?status=queued&status=running) —
    permite selecionar múltiplos valores pro mesmo filtro (ex: múltiplos
    status na aba de execuções) em vez de só um por vez. `.keys()` de um
    QueryParams pode repetir a mesma chave; dict.fromkeys(...) desduplica
    mantendo a ordem antes de buscar todos os valores de cada uma."""
    reserved = _RESERVED_QUERY_PARAMS | extra_reserved
    return {
        k: request.query_params.getlist(k)
        for k in dict.fromkeys(request.query_params.keys())
        if k not in reserved
    }


@app.get("/health")
def health():
    try:
        opensearch_client.client().cluster.health()
        opensearch_ok = True
    except Exception:
        opensearch_ok = False
    # "platform_problems": lê o resultado do último ciclo do monitor de
    # saúde (health_monitor.py) — não dispara um check novo, então não
    # deixa /health mais lento. None = monitor desligado ou ainda não rodou.
    return {
        "opensearch": opensearch_ok,
        "recon_cpus": config.RECON_CPUS,
        "platform_problems": health_monitor.last_problems(),
    }


# ---- Autenticação (ver README "Autenticação e usuários") ----


@app.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    if login_throttle.is_locked_out(req.username):
        raise HTTPException(status_code=429, detail="muitas tentativas de login — tente novamente em alguns minutos")

    user = opensearch_client.get_user_by_username(req.username)
    # Roda verify_password() sempre, mesmo sem usuário — contra um hash
    # dummy de custo idêntico, pra login com username inexistente não
    # responder mais rápido que username existente + senha errada (ver
    # auth.DUMMY_PASSWORD_HASH: sem isso, dava pra enumerar username por
    # timing, sem precisar acertar senha nenhuma).
    password_hash = user["password_hash"] if user else auth.DUMMY_PASSWORD_HASH
    password_ok = auth.verify_password(req.password, password_hash)
    if not user or user.get("disabled") or not password_ok:
        login_throttle.record_failure(req.username)
        raise HTTPException(status_code=401, detail="usuário ou senha inválidos")
    login_throttle.reset(req.username)

    token = auth.generate_token()
    opensearch_client.create_session(token, user, config.SESSION_TTL_DAYS)
    # Isento do log genérico do middleware (login não passa por
    # request.state.user) — grava aqui, agora que a identidade é conhecida.
    opensearch_client.record_audit(
        {"user_id": user["user_id"], "username": user["username"], "role": user["role"]},
        "POST", "/auth/login", 200,
    )
    must_change_password = user["username"] == _DEFAULT_ADMIN_USERNAME and req.password == _DEFAULT_ADMIN_PASSWORD
    return LoginResponse(token=token, username=user["username"], role=user["role"], must_change_password=must_change_password)


@app.post("/auth/logout")
def logout(request: Request):
    token = _extract_token(request)
    if token:
        opensearch_client.delete_session(token)
    return {"status": "logged_out"}


@app.get("/auth/me", response_model=MeResponse)
def me(request: Request):
    user = request.state.user
    return MeResponse(username=user["username"], role=user["role"])


@app.post("/auth/change-password")
def change_password(req: ChangePasswordRequest, request: Request):
    """Qualquer usuário logado troca a própria senha, confirmando a senha
    atual — diferente do reset feito por um admin (POST
    /users/{id}/reset-password), que não pede a senha antiga."""
    user = opensearch_client.get_user(request.state.user["user_id"])
    if not user or not auth.verify_password(req.current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="senha atual incorreta")
    opensearch_client.update_user(user["user_id"], password_hash=auth.hash_password(req.new_password))
    # Derruba qualquer outra sessão desse usuário (ex: um token que tivesse
    # vazado antes da troca) — preserva só a que fez essa própria troca, pra
    # não deslogar quem acabou de trocar a senha.
    opensearch_client.delete_sessions_for_user(user["user_id"], except_token=_extract_token(request))
    return {"status": "password_changed"}


def _guard_last_admin(existing: dict, fields: dict) -> None:
    """Impede desativar ou rebaixar o último admin ativo restante — sem
    isso dá pra trancar todo mundo fora do sistema, sem ninguém com papel
    admin sobrando pra desfazer."""
    was_active_admin = existing["role"] == "admin" and not existing.get("disabled")
    if not was_active_admin:
        return
    becoming_disabled = fields.get("disabled") is True
    becoming_non_admin = "role" in fields and fields["role"] != "admin"
    if (becoming_disabled or becoming_non_admin) and opensearch_client.count_active_admins() <= 1:
        raise HTTPException(status_code=400, detail="não é possível desativar/rebaixar o último admin ativo")


@app.get("/users", response_model=list[UserResponse], dependencies=[Depends(require_role("admin"))])
def list_users():
    return opensearch_client.list_users()


@app.post("/users", response_model=UserResponse, dependencies=[Depends(require_role("admin"))])
def create_user_route(req: CreateUserRequest):
    if opensearch_client.get_user_by_username(req.username):
        raise HTTPException(status_code=409, detail="já existe um usuário com esse nome")
    user_id = uuid.uuid4().hex
    opensearch_client.create_user(user_id, req.username, auth.hash_password(req.password), req.role)
    return opensearch_client.get_user(user_id)


@app.put("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(require_role("admin"))])
def update_user_route(user_id: str, req: UpdateUserRequest):
    existing = opensearch_client.get_user(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="usuário não encontrado")
    fields = req.model_dump(exclude_unset=True)
    _guard_last_admin(existing, fields)
    if fields:
        opensearch_client.update_user(user_id, **fields)
    return opensearch_client.get_user(user_id)


@app.post("/users/{user_id}/reset-password", dependencies=[Depends(require_role("admin"))])
def reset_user_password(user_id: str, req: ResetPasswordRequest):
    """Reset feito por um admin em outro usuário — diferente de
    POST /auth/change-password (self-service, exige a senha atual)."""
    if not opensearch_client.get_user(user_id):
        raise HTTPException(status_code=404, detail="usuário não encontrado")
    opensearch_client.update_user(user_id, password_hash=auth.hash_password(req.new_password))
    # Diferente do self-service acima, aqui não há sessão "própria" do admin
    # que fez o reset a preservar — derruba todas as sessões do usuário alvo.
    opensearch_client.delete_sessions_for_user(user_id)
    return {"user_id": user_id, "status": "password_reset"}


@app.delete("/users/{user_id}", dependencies=[Depends(require_role("admin"))])
def delete_user_route(user_id: str, request: Request):
    existing = opensearch_client.get_user(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="usuário não encontrado")
    if user_id == request.state.user["user_id"]:
        raise HTTPException(status_code=400, detail="não é possível excluir o próprio usuário logado")
    _guard_last_admin(existing, {"disabled": True})
    opensearch_client.delete_user(user_id)
    return {"user_id": user_id, "status": "deleted"}


@app.get("/audit-log", dependencies=[Depends(require_role("admin"))])
def audit_log(page: int = 1, size: int = 50):
    return opensearch_client.list_audit_log(page=page, size=size)


@app.get("/settings", dependencies=[Depends(require_role("admin"))])
def get_settings():
    return settings_registry.effective_view(opensearch_client.get_settings_overrides())


@app.put("/settings", dependencies=[Depends(require_role("admin"))])
def update_settings(req: UpdateSettingsRequest):
    """Valor null numa chave restaura o padrão de fábrica (tira o override
    salvo); qualquer outro valor sobrescreve. Aplica ao vivo (setattr no
    módulo config — ver settings_registry.py) e persiste, pra sobreviver a
    um restart do backend (ver _load_settings_overrides)."""
    current = opensearch_client.get_settings_overrides()
    to_apply: dict = {}
    for key, value in req.overrides.items():
        if not settings_registry.is_known(key):
            raise HTTPException(status_code=400, detail=f"configuração desconhecida: {key}")
        if value is None:
            current.pop(key, None)
            setattr(config, key, settings_registry.default_value(key))
            continue
        try:
            settings_registry.validate(key, value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        current[key] = value
        to_apply[key] = value

    opensearch_client.save_settings_overrides(current)
    settings_registry.apply_overrides(to_apply)
    return settings_registry.effective_view(current)


@app.post("/scans", response_model=ScanResponse, dependencies=[Depends(require_role("admin", "operator"))])
def create_scan(req: ScanRequest):
    if req.gobuster_wordlist == "custom":
        # Confere posse aqui (falha rápido e claro), e de novo na Fase 4 (a
        # wordlist pode ser removida entre o disparo e o gobuster rodar de
        # fato) — um cliente não pode usar o wordlist_id de outro.
        if not opensearch_client.get_wordlist(req.client, req.gobuster_custom_wordlist_id):
            raise HTTPException(status_code=404, detail="wordlist customizada não encontrada para esse cliente")

    scan_id = uuid.uuid4().hex
    enabled_tools = config.resolve_enabled_tools(req.enabled_tools)
    job_ctx = {
        "client": req.client, "scan_id": scan_id, "gobuster_wordlist": req.gobuster_wordlist,
        "gobuster_custom_wordlist_id": req.gobuster_custom_wordlist_id, "enabled_tools": enabled_tools,
    }
    opensearch_client.record_scan(
        req.client, scan_id, req.targets,
        gobuster_wordlist=req.gobuster_wordlist, gobuster_custom_wordlist_id=req.gobuster_custom_wordlist_id,
        enabled_tools=enabled_tools,
    )
    tasks.orchestrate_scan_task.delay(job_ctx, req.targets)
    return ScanResponse(scan_id=scan_id, client=req.client, targets=req.targets, status="queued")


@app.get("/scan-defaults")
def scan_defaults():
    """Ferramentas da Fase 4 selecionáveis por scan (ver "Perfis de scan por
    execução" no README) e quais entram marcadas por padrão — o frontend usa
    isso pra desenhar o checklist do formulário de novo scan já pré-marcado
    igual ao comportamento de hoje, sem duplicar a lógica de resolução dos
    *_ENABLED aqui (ver config.resolve_enabled_tools)."""
    return {"tools": PHASE4_TOOLS, "enabled_by_default": config.resolve_enabled_tools(None)}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str, client: ClientQuery):
    jobs = opensearch_client.query_jobs(client, scan_id)
    if not jobs:
        raise HTTPException(status_code=404, detail="scan não encontrado (ou ainda não gerou nenhum resultado)")
    return {"scan_id": scan_id, "client": client, "jobs": jobs}


@app.get("/clients")
def list_clients():
    return opensearch_client.list_clients()


@app.get("/clients/{client}/scans")
def list_scans(client: ClientPath):
    """Histórico de scans do cliente (scan_id + alvos + data de disparo +
    duration_seconds) — usado para popular o seletor "scan" nas telas de
    achados/execuções, já que o mesmo alvo pode ser escaneado de novo em
    outro dia e os dados de ambas as execuções convivem nos mesmos índices."""
    return opensearch_client.list_scans(client)


@app.delete("/clients/{client}/scans/{scan_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_scan(client: ClientPath, scan_id: str):
    """Remove um scan inteiro: o registro do scan e todos os achados/jobs
    desse scan_id, em todos os índices do cliente. Diferente de
    /clients/{client}/{suffix}/delete (que apaga achados específicos de um
    índice só, pelo _id)."""
    if not opensearch_client.get_scan(client, scan_id):
        raise HTTPException(status_code=404, detail="scan não encontrado")
    result = opensearch_client.delete_scan(client, scan_id)
    return {"client": client, "scan_id": scan_id, **result}


@app.post("/clients/{client}/wordlists", dependencies=[Depends(require_role("admin", "operator"))])
async def upload_wordlist(client: ClientPath, file: UploadFile = File(...)):
    """Upload de wordlist customizada para o gobuster. Sempre validado antes
    de gravar (tamanho, quantidade de linhas, conteúdo texto puro, limite de
    wordlists por cliente) — ver wordlists.py para o detalhe de cada limite e
    o porquê. O nome do arquivo enviado nunca vira um path no disco (só é
    usado, sanitizado, para exibição); o arquivo em si é salvo com um id
    opaco gerado no servidor."""
    try:
        raw = await wordlists_mod.read_capped(file, config.MAX_WORDLIST_BYTES)
        doc = wordlists_mod.save_wordlist(client, file.filename, raw)
    except wordlists_mod.WordlistError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return doc


@app.get("/clients/{client}/wordlists")
def list_wordlists(client: ClientPath):
    return wordlists_mod.list_wordlists(client)


@app.delete("/clients/{client}/wordlists/{wordlist_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_wordlist(client: ClientPath, wordlist_id: str):
    if not wordlists_mod.delete_wordlist(client, wordlist_id):
        raise HTTPException(status_code=404, detail="wordlist não encontrada")
    return {"client": client, "wordlist_id": wordlist_id, "status": "deleted"}


@app.get("/clients/{client}/screenshots/{screenshot_id}")
def get_screenshot(client: ClientPath, screenshot_id: str):
    """Serve o screenshot do gowitness (ver screenshots.py) — escopado ao
    cliente na própria estrutura de diretório (nunca lê o id de outro
    cliente, mesmo que o id seja válido)."""
    path = screenshots_mod.resolve(client, screenshot_id)
    if not path:
        raise HTTPException(status_code=404, detail="screenshot não encontrado")
    with open(path, "rb") as fh:
        data = fh.read()
    return Response(content=data, media_type="image/jpeg")


def _build_recurring_scan_doc(
    client: str, schedule_id: str, req: RecurringScanRequest, *,
    created_at: str, last_run_at: str | None = None, last_scan_id: str | None = None,
) -> dict:
    """Monta o documento completo do alvo salvo/recorrência — usado tanto na
    criação quanto na edição (que faz um index() de substituição inteira, não
    um update parcial, então created_at/last_run_at/last_scan_id precisam ser
    passados explicitamente para não se perderem numa edição)."""
    next_run_at = None
    if req.enabled:
        next_run = recurrence.compute_next_run(
            req.periodicity, req.run_time, weekday=req.weekday, day_of_month=req.day_of_month,
            now=datetime.now(timezone.utc),
        )
        next_run_at = next_run.isoformat()
    return {
        "schedule_id": schedule_id,
        "client": client,
        "targets": req.targets,
        "gobuster_wordlist": req.gobuster_wordlist,
        "gobuster_custom_wordlist_id": req.gobuster_custom_wordlist_id,
        "enabled_tools": req.enabled_tools,
        "enabled": req.enabled,
        "periodicity": req.periodicity,
        "run_time": req.run_time,
        "weekday": req.weekday,
        "day_of_month": req.day_of_month,
        "next_run_at": next_run_at,
        "last_run_at": last_run_at,
        "last_scan_id": last_scan_id,
        "created_at": created_at,
        "updated_at": _now_iso(),
    }


@app.post("/clients/{client}/recurring-scans", dependencies=[Depends(require_role("admin", "operator"))])
def create_recurring_scan(client: ClientPath, req: RecurringScanRequest):
    if req.gobuster_wordlist == "custom" and not opensearch_client.get_wordlist(client, req.gobuster_custom_wordlist_id):
        raise HTTPException(status_code=404, detail="wordlist customizada não encontrada para esse cliente")
    schedule_id = uuid.uuid4().hex
    doc = _build_recurring_scan_doc(client, schedule_id, req, created_at=_now_iso())
    opensearch_client.record_recurring_scan(client, schedule_id, doc)
    return doc


@app.get("/clients/{client}/recurring-scans")
def list_recurring_scans(client: ClientPath):
    return opensearch_client.list_recurring_scans(client)


@app.put("/clients/{client}/recurring-scans/{schedule_id}", dependencies=[Depends(require_role("admin", "operator"))])
def update_recurring_scan(client: ClientPath, schedule_id: str, req: RecurringScanRequest):
    existing = opensearch_client.get_recurring_scan(client, schedule_id)
    if not existing:
        raise HTTPException(status_code=404, detail="alvo salvo não encontrado")
    if req.gobuster_wordlist == "custom" and not opensearch_client.get_wordlist(client, req.gobuster_custom_wordlist_id):
        raise HTTPException(status_code=404, detail="wordlist customizada não encontrada para esse cliente")
    doc = _build_recurring_scan_doc(
        client, schedule_id, req,
        created_at=existing["created_at"], last_run_at=existing.get("last_run_at"), last_scan_id=existing.get("last_scan_id"),
    )
    opensearch_client.record_recurring_scan(client, schedule_id, doc)
    return doc


@app.delete("/clients/{client}/recurring-scans/{schedule_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_recurring_scan(client: ClientPath, schedule_id: str):
    if not opensearch_client.delete_recurring_scan_doc(client, schedule_id):
        raise HTTPException(status_code=404, detail="alvo salvo não encontrado")
    return {"client": client, "schedule_id": schedule_id, "status": "deleted"}


@app.post(
    "/clients/{client}/recurring-scans/{schedule_id}/run-now",
    dependencies=[Depends(require_role("admin", "operator"))],
)
def run_recurring_scan_now(client: ClientPath, schedule_id: str):
    """Dispara imediatamente os alvos salvos, sem tocar no agendamento —
    idêntico ao create_scan(), só que reaproveitando um alvo já salvo em vez
    de vir do formulário de "novo recon"."""
    sched = opensearch_client.get_recurring_scan(client, schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="alvo salvo não encontrado")

    scan_id = uuid.uuid4().hex
    enabled_tools = config.resolve_enabled_tools(sched.get("enabled_tools"))
    job_ctx = {
        "client": client, "scan_id": scan_id, "gobuster_wordlist": sched["gobuster_wordlist"],
        "gobuster_custom_wordlist_id": sched.get("gobuster_custom_wordlist_id"), "enabled_tools": enabled_tools,
    }
    opensearch_client.record_scan(
        client, scan_id, sched["targets"],
        gobuster_wordlist=sched["gobuster_wordlist"], gobuster_custom_wordlist_id=sched.get("gobuster_custom_wordlist_id"),
        enabled_tools=enabled_tools, triggered_by="manual_from_saved", schedule_id=schedule_id,
    )
    tasks.orchestrate_scan_task.delay(job_ctx, sched["targets"])
    return ScanResponse(scan_id=scan_id, client=client, targets=sched["targets"], status="queued")


@app.get("/jobs/active")
def active_jobs():
    """Execuções em andamento agora, em todos os clientes — alimenta o
    indicador de ocupação dos workers no frontend."""
    active = opensearch_client.list_active_jobs()
    return {"recon_cpus": config.RECON_CPUS, "active": active}


@app.get("/clients/{client}/indices")
def list_client_indices(client: ClientPath):
    indices = opensearch_client.list_client_indices(client)
    if not indices:
        raise HTTPException(status_code=404, detail="cliente sem dados indexados")
    return indices


def _export_response(
    fmt: str, filename_base: str, client: str, suffix: str | None = None,
    *, q: str | None = None, filters: dict | None = None, unique: bool = False,
) -> Response:
    if fmt not in _EXPORT_MEDIA_TYPES:
        raise HTTPException(status_code=400, detail="format deve ser json, csv ou pdf")

    if fmt == "json":
        content = export_mod.export_json(client, suffix, q=q, filters=filters, unique=unique)
        media_type = _EXPORT_MEDIA_TYPES["json"]
        ext = "json"
    elif fmt == "csv":
        content, media_type = export_mod.export_csv(client, suffix, q=q, filters=filters, unique=unique)
        ext = "zip" if media_type == "application/zip" else "csv"
    else:
        content = export_mod.export_pdf(client, suffix, q=q, filters=filters, unique=unique)
        media_type = _EXPORT_MEDIA_TYPES["pdf"]
        ext = "pdf"

    if unique:
        filename_base += "-unicos"

    headers = {"Content-Disposition": f'attachment; filename="{filename_base}.{ext}"'}
    return Response(content=content, media_type=media_type, headers=headers)


@app.get("/clients/{client}/export")
def export_client(client: ClientPath, format: str = "json"):
    """Exporta TODOS os achados do cliente (todas as ferramentas/índices).
    CSV nesse nível vem como um .zip (um CSV por índice — schemas diferentes
    não cabem num CSV só). PDF tem um teto de linhas por seção; use JSON/CSV
    para o dado completo. Sem filtros — cada índice tem seu próprio schema."""
    if not opensearch_client.list_client_indices(client):
        raise HTTPException(status_code=404, detail="cliente sem dados indexados")
    return _export_response(format, f"{client}-export", client)


@app.get("/clients/{client}/{suffix}/export")
def export_suffix(
    client: ClientPath, suffix: SuffixPath, request: Request, format: str = "json", q: str | None = None, unique: bool = False,
):
    """Exporta os achados de uma única ferramenta/índice do cliente — aceita
    os mesmos filtros de GET /clients/{client}/{suffix} (q + qualquer outro
    parâmetro vira filtro exato), para exportar exatamente o recorte que
    está sendo visto na tela, não a tabela inteira. `unique=true` agrupa
    achados idênticos vindos de tools/scans diferentes numa linha só (ver
    export.py: _dedupe) — resolve pedir "só os subdomínios sem duplicar"."""
    filters = _filters_from_query(request, {"format", "unique"})
    return _export_response(format, f"{client}-{suffix}", client, suffix, q=q, filters=filters, unique=unique)


@app.delete("/clients/{client}", dependencies=[Depends(require_role("admin"))])
def delete_client(client: ClientPath):
    """Apaga todos os índices do cliente ({client}-*) no OpenSearch. Não
    cancela scans em andamento na fila — só remove os dados já indexados."""
    # Antes de apagar o índice de metadados: sem isso, os arquivos de
    # wordlist customizada/screenshot ficariam órfãos no disco pra sempre (o
    # registro que diz "isso pertence a esse cliente" já teria sumido).
    wordlists_mod.delete_client_wordlists(client)
    screenshots_mod.delete_client_screenshots(client)
    deleted = opensearch_client.delete_client(client)
    if not deleted:
        raise HTTPException(status_code=404, detail="cliente sem dados indexados")
    return {"client": client, "status": "deleted"}


@app.post("/clients/{client}/clear", dependencies=[Depends(require_role("admin"))])
def clear_client_data(client: ClientPath):
    """Apaga achados e histórico de execuções do cliente, mas o cliente
    continua existindo (some do dashboard só o que já foi indexado; o nome
    continua na lista de clientes, zerado, como se fosse recém-criado). Não
    cancela scans em andamento na fila — mesma ressalva de DELETE /clients/{client}."""
    wordlists_mod.delete_client_wordlists(client)
    screenshots_mod.delete_client_screenshots(client)
    cleared = opensearch_client.clear_client_data(client)
    if not cleared:
        raise HTTPException(status_code=404, detail="cliente sem dados indexados")
    return {"client": client, "status": "cleared"}


@app.get("/clients/{client}/jobs/summary")
def jobs_summary(client: ClientPath):
    """Contagem de execuções por status (total, ok, error, cancelled,
    running, queued) — alimenta o quadro de execuções do painel do cliente."""
    return opensearch_client.jobs_summary(client)


@app.post("/clients/{client}/jobs/{job_id}/cancel", dependencies=[Depends(require_role("admin", "operator"))])
def cancel_job(client: ClientPath, job_id: str):
    """Cancela uma execução específica: em andamento (mata o container) ou
    ainda esperando na fila (nunca chega a rodar)."""
    job = opensearch_client.get_job(client, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job não encontrado")
    if job.get("status") not in ("running", "queued"):
        raise HTTPException(
            status_code=409, detail=f"job não está em execução nem pendente (status atual: {job.get('status')})",
        )
    _cancel_job(client, job)
    return {"client": client, "job_id": job_id, "status": "cancelled"}


@app.post("/clients/{client}/jobs/cancel-all", dependencies=[Depends(require_role("admin", "operator"))])
def cancel_all_jobs(client: ClientPath):
    """Cancela todas as execuções em andamento ou pendentes desse cliente.

    Matar só os jobs já visíveis nesse instante não basta: o pipeline é
    encadeado em fases (cada fase dispara a próxima via chord callback
    quando a fase anterior "termina" — e o Celery conta uma tarefa morta à
    força como "terminada" pra esse efeito), então o callback da fase atual
    ainda dispara a fase seguinte mesmo depois de tudo cancelado, fazendo
    parecer que sempre sobe processo novo (visto na prática). Por isso,
    além de matar os jobs pendentes, marca cada scan_id envolvido como
    cancelado — toda função de despacho de fase (tasks.py) confere essa
    marca antes de disparar a próxima e desiste cedo se estiver marcada."""
    pending = opensearch_client.list_cancelable_jobs(client)
    for job in pending:
        _cancel_job(client, job)

    scan_ids = {job["scan_id"] for job in pending if job.get("scan_id")}
    for scan_id in scan_ids:
        opensearch_client.mark_scan_cancelled(client, scan_id)

    return {"client": client, "cancelled": [j["job_id"] for j in pending], "scans_cancelled": sorted(scan_ids)}


@app.get("/clients/{client}/ip-provenance")
def ip_provenance(client: ClientPath, ip: str, scan_id: str):
    """De onde veio esse IP dentro do scan — pra achados por IP (nmap,
    masscan, rdap-network, shodan, censys) não aparecerem soltos sem
    explicação (ex: um IP cujo PTR não bate com o domínio do cliente).
    Declarado ANTES de GET /clients/{client}/{suffix} de propósito: como os
    dois batem o mesmo formato de path (2 segmentos), o FastAPI casa pela
    ordem de registro — se "get_findings" viesse primeiro, "ip-provenance"
    seria capturado ali como se fosse um suffix de índice.

    Confere, na ordem, contra cada alvo original do scan (`scan.targets`):
    1. o próprio alvo é esse IP (ou um bloco CIDR que o contém) — scan de IP puro;
    2. o alvo é um domínio cujo IP raiz (resolvido agora) bate com esse IP;
    3. o alvo é um domínio e algum subdomínio dele (resolvido pelo dnsx
       durante o scan) aponta pra esse IP.
    "unknown" se nenhum desses bater (ex: scan antigo, dado reprocessado)."""
    scan = opensearch_client.get_scan(client, scan_id)
    if not scan:
        return {"kind": "unknown"}

    for target in scan.get("targets", []):
        if util.is_ip_or_cidr(target):
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(target, strict=False):
                    return {"kind": "direct_ip", "target": target}
            except ValueError:
                continue
            continue

        if util.resolve_ip(target) == ip:
            return {"kind": "root_domain", "target": target}

        subdomains = opensearch_client.find_subdomains_for_ip(client, target, ip)
        if subdomains:
            return {"kind": "subdomain", "target": target, "subdomains": subdomains}

    return {"kind": "unknown"}


@app.get("/clients/{client}/risk-report")
def get_risk_report(client: ClientPath, format: str = "json"):
    """Relatório executivo (score de risco agregado — ver risk_score.py para
    a metodologia). Declarado ANTES de GET /clients/{client}/{suffix} pelo
    mesmo motivo do ip-provenance/asset acima (mesmo formato de path de 2
    segmentos, FastAPI casa por ordem de registro).

    format=json (padrão) é a mesma agregação que alimenta o card de risco no
    dashboard; format=pdf devolve o relatório pronto pra apresentar a um
    cliente não-técnico."""
    if format == "pdf":
        content = export_mod.export_risk_report(client)
        headers = {"Content-Disposition": f'attachment; filename="{client}-relatorio-executivo.pdf"'}
        return Response(content=content, media_type=_EXPORT_MEDIA_TYPES["pdf"], headers=headers)
    if format != "json":
        raise HTTPException(status_code=400, detail="format deve ser json ou pdf")
    return opensearch_client.risk_summary(client)


@app.get("/clients/{client}/asset")
def get_asset(client: ClientPath, value: str):
    """Tudo que qualquer ferramenta achou sobre um valor exato (subdomínio,
    IP ou URL), consolidado num só lugar — sem isso, ver tudo sobre um
    mesmo host exige abrir cada tela de achados por ferramenta e buscar o
    valor manualmente em cada uma. Declarado ANTES de GET
    /clients/{client}/{suffix} pelo mesmo motivo do ip-provenance acima
    (mesmo formato de path de 2 segmentos, FastAPI casa por ordem de
    registro)."""
    return opensearch_client.find_asset(client, value)


@app.get("/clients/{client}/{suffix}")
def get_findings(client: ClientPath, suffix: SuffixPath, request: Request, q: str | None = None, page: int = 1, size: int = 25, sort: str = "-@timestamp"):
    sort_field = sort.lstrip("-")
    sort_order = "desc" if sort.startswith("-") else "asc"
    filters = _filters_from_query(request)
    return opensearch_client.search_findings(
        client, suffix, q=q, filters=filters, page=page, size=size, sort_field=sort_field, sort_order=sort_order,
    )


@app.get("/clients/{client}/{suffix}/severity-summary")
def get_severity_summary(client: ClientPath, suffix: SuffixPath, request: Request, q: str | None = None):
    """Contagem de achados por severidade (nuclei/dalfox) — alimenta o
    gráfico de distribuição na tela de achados, respeitando os mesmos
    filtros já ativos na tabela (tool/scan/status)."""
    filters = _filters_from_query(request)
    return opensearch_client.severity_summary(client, suffix, q=q, filters=filters)


@app.post("/clients/{client}/{suffix}/delete", dependencies=[Depends(require_role("admin", "operator"))])
def delete_findings(client: ClientPath, suffix: SuffixPath, req: DeleteFindingsRequest):
    """Remove achados específicos pelo _id (ex: descartar um falso positivo),
    sem afetar o resto do índice. Não vale para "jobs"/"scans": um job em
    andamento precisa ser cancelado (POST .../jobs/{job_id}/cancel), não
    apagado direto — senão o container/task fica órfão, sem registro para
    parar."""
    if suffix in _NON_FINDINGS_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"não é possível excluir achados de '{suffix}' por aqui")
    deleted = opensearch_client.delete_findings(client, suffix, req.ids)
    return {"client": client, "suffix": suffix, "requested": len(req.ids), "deleted": deleted}


@app.get("/clients/{client}/{suffix}/compare")
def compare_scans(client: ClientPath, suffix: SuffixPath, from_scan: str, to_scan: str):
    """"O que mudou desde a última vez": compara os achados de dois scans do
    mesmo índice — o que é novo (só no scan mais recente), o que "sumiu" (só
    no mais antigo — ex: vulnerabilidade corrigida, subdomínio desativado) e
    quantos achados continuam iguais nos dois."""
    if suffix in _NON_FINDINGS_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"não é possível comparar achados de '{suffix}' por aqui")
    from_info = opensearch_client.get_scan(client, from_scan)
    to_info = opensearch_client.get_scan(client, to_scan)
    if not from_info or not to_info:
        raise HTTPException(status_code=404, detail="scan não encontrado")
    result = compare_mod.compare_scans(client, suffix, from_scan, to_scan)
    return {"client": client, "suffix": suffix, "from_scan": from_info, "to_scan": to_info, **result}
