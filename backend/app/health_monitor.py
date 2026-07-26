import logging
import queue
import threading
import time
from datetime import datetime, timedelta, timezone

import redis
from redis.backoff import NoBackoff
from redis.retry import Retry

from . import config, notifications, opensearch_client
from .celery_app import celery_app

logger = logging.getLogger(__name__)

# Nome da fila padrão do Celery no transporte Redis (kombu) — "celery" a
# menos que task_default_queue seja customizado, o que não é o caso aqui
# (ver celery_app.py). É a mesma chave que "redis-cli LLEN celery" mostraria.
_QUEUE_KEY = "celery"

# socket_timeout sozinho NÃO basta: testado na prática com "docker pause
# redis", um LLEN ainda demorou ~26-60s pra desistir mesmo com
# socket_timeout=2/5 — o redis-py 8.x tem retry automático embutido por
# padrão (várias tentativas com backoff) mesmo em timeout de leitura.
# retry=Retry(NoBackoff(), 0) desliga esse retry; só então o timeout de fato
# vira o teto real de espera (confirmado: 2.0s cravado no teste). db=0: mesmo
# banco do broker (ver celery_app.py) — só leitura (LLEN), não interfere na
# fila. Distinto do db=1 usado por tasks.py para o round-robin de cores, que é
# um dado da aplicação, não do broker em si.
_redis = redis.Redis(
    host=config.REDIS_HOST, port=config.REDIS_PORT, password=config.REDIS_PASSWORD, db=0,
    socket_timeout=5, socket_connect_timeout=5, retry=Retry(NoBackoff(), 0),
)

# Índices internos do próprio OpenSearch/plugins (security-auditlog,
# top_queries, .opendistro-*) costumam ficar "yellow" para sempre num
# cluster single-node (esperam réplica que nunca vai ser alocada) — sem
# excluí-los, o monitor acusaria "problema" o tempo todo mesmo com o
# cluster/dados do projeto 100% saudáveis. Mesmo padrão de exclusão do
# opensearch/backup.sh.
_HEALTH_INDEX_PATTERN = "*,-.*,-security-auditlog-*,-top_queries-*"

_last_problems: list[str] | None = None  # None = ainda não rodou nenhum check


def _check_opensearch() -> str | None:
    try:
        health = opensearch_client.client().cluster.health(index=_HEALTH_INDEX_PATTERN)
    except Exception as exc:
        return f"OpenSearch inacessível: {exc}"
    status = health.get("status")
    if status != "green":
        return f"Cluster OpenSearch em estado '{status}' (índices do projeto)"
    return None


def _check_worker() -> str | None:
    """`inspect(timeout=...)` só bound quanto tempo espera por uma resposta —
    não bound a conexão em si; contra um broker congelado/particionado (não
    simplesmente recusando conexão) fica preso indefinidamente, visto na
    prática testando com "docker pause redis". Por isso o ping roda numa
    thread solta com um limite de espera aplicado aqui fora: se estourar,
    reporta o problema e segue em frente (a thread presa vaza até o socket
    dar timeout sozinho — aceitável para um monitor "básico"; a alternativa,
    travar o loop de checagem inteiro para sempre, é bem pior)."""
    result: queue.Queue = queue.Queue(maxsize=1)

    def _target():
        try:
            result.put(("ok", celery_app.control.inspect(timeout=5).ping()))
        except Exception as exc:  # noqa: BLE001 - repassado como problema, não propagado
            result.put(("error", exc))

    threading.Thread(target=_target, daemon=True, name="health-worker-ping").start()
    try:
        kind, value = result.get(timeout=10)
    except queue.Empty:
        return "Timeout ao checar workers Celery (broker sem resposta em 10s)"

    if kind == "error":
        return f"Falha ao checar workers Celery: {value}"
    if not value:
        return "Nenhum worker Celery respondendo"
    return None


def _check_queue_backlog() -> str | None:
    try:
        depth = _redis.llen(_QUEUE_KEY)
    except Exception as exc:
        return f"Falha ao checar fila no Redis: {exc}"
    if depth > config.HEALTH_QUEUE_BACKLOG_THRESHOLD:
        return f"Fila com {depth} tarefa(s) pendente(s) (limite: {config.HEALTH_QUEUE_BACKLOG_THRESHOLD})"
    return None


def _check_stuck_jobs() -> str | None:
    try:
        active = opensearch_client.list_active_jobs()
    except Exception as exc:
        return f"Falha ao checar jobs em execução: {exc}"

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=config.HEALTH_STUCK_JOB_MINUTES)
    stuck = []
    for job in active:
        started_at = job.get("started_at")
        if not started_at:
            continue
        try:
            started = datetime.fromisoformat(started_at)
        except ValueError:
            continue
        if started < cutoff:
            stuck.append(job)

    if stuck:
        oldest = stuck[0]
        return (
            f"{len(stuck)} job(s) rodando há mais de {config.HEALTH_STUCK_JOB_MINUTES}min "
            f"(mais antigo: {oldest.get('tool')} em {oldest.get('target')}, cliente {oldest.get('client')})"
        )
    return None


_CHECKS = (_check_opensearch, _check_worker, _check_queue_backlog, _check_stuck_jobs)


def check_health() -> list[str]:
    """Roda todos os checks e devolve a lista de problemas atuais (vazia =
    tudo ok). Cada check é isolado: uma exceção num deles vira uma mensagem
    de problema, nunca derruba os outros checks."""
    return [msg for check in _CHECKS if (msg := check())]


def run_check_and_notify() -> list[str]:
    """Notifica só na transição de estado (problemas novos/diferentes, ou
    recuperação) — nunca a cada checagem, senão um problema persistente
    inundaria o canal de Slack/webhook."""
    global _last_problems
    problems = check_health()

    if problems != _last_problems and (problems or _last_problems):
        try:
            notifications.notify_health(problems)
        except Exception:
            logger.exception("falha ao notificar mudança de estado de saúde")

    _last_problems = problems
    return problems


def _loop() -> None:
    while True:
        try:
            run_check_and_notify()
        except Exception:
            logger.exception("falha inesperada no monitor de saúde")
        time.sleep(config.HEALTH_CHECK_INTERVAL_SECONDS)


def last_problems() -> list[str] | None:
    """Resultado do último check (None = monitor ainda não rodou nenhum, ex:
    logo após subir com HEALTH_CHECK_INTERVAL_SECONDS <= 0). Leitura O(1), não
    dispara um check novo — usado só para expor o estado atual em /health."""
    return _last_problems


def start() -> None:
    """Chamado uma vez no startup do backend (ver main.py). <= 0 desliga o
    monitor inteiramente — thread nem chega a subir."""
    if config.HEALTH_CHECK_INTERVAL_SECONDS <= 0:
        logger.info("monitor de saúde desligado (HEALTH_CHECK_INTERVAL_SECONDS <= 0)")
        return
    threading.Thread(target=_loop, daemon=True, name="health-monitor").start()
    logger.info("monitor de saúde iniciado (intervalo: %ss)", config.HEALTH_CHECK_INTERVAL_SECONDS)
