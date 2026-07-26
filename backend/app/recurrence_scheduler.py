import logging
import threading
import time
import uuid
from datetime import datetime, timezone

from . import config, opensearch_client, recurrence, tasks

logger = logging.getLogger(__name__)


def _trigger(sched: dict, now: datetime) -> None:
    client_name = sched["client"]
    schedule_id = sched["schedule_id"]
    scan_id = uuid.uuid4().hex
    enabled_tools = config.resolve_enabled_tools(sched.get("enabled_tools"))
    job_ctx = {
        "client": client_name, "scan_id": scan_id, "gobuster_wordlist": sched["gobuster_wordlist"],
        "gobuster_custom_wordlist_id": sched.get("gobuster_custom_wordlist_id"), "enabled_tools": enabled_tools,
    }
    opensearch_client.record_scan(
        client_name, scan_id, sched["targets"],
        gobuster_wordlist=sched["gobuster_wordlist"], gobuster_custom_wordlist_id=sched.get("gobuster_custom_wordlist_id"),
        enabled_tools=enabled_tools, triggered_by="recurrence", schedule_id=schedule_id,
    )
    tasks.orchestrate_scan_task.delay(job_ctx, sched["targets"])

    next_run = recurrence.compute_next_run(
        sched["periodicity"], sched["run_time"],
        weekday=sched.get("weekday"), day_of_month=sched.get("day_of_month"), now=now,
    )
    opensearch_client.update_recurring_scan_after_run(
        client_name, schedule_id, last_run_at=now.isoformat(), last_scan_id=scan_id, next_run_at=next_run.isoformat(),
    )
    logger.info(
        "recorrência disparada: cliente=%s schedule_id=%s scan_id=%s próxima execução=%s",
        client_name, schedule_id, scan_id, next_run.isoformat(),
    )


def run_due_schedules() -> int:
    """Dispara todo alvo salvo com recorrência ativa cuja next_run_at já
    chegou. Cada disparo é isolado: uma falha num não impede os outros
    (mesmo espírito de health_monitor._CHECKS)."""
    now = datetime.now(timezone.utc)
    due = opensearch_client.list_due_recurring_scans(now.isoformat())
    for sched in due:
        try:
            _trigger(sched, now)
        except Exception:
            logger.exception(
                "falha ao disparar recorrência (cliente=%s schedule_id=%s)",
                sched.get("client"), sched.get("schedule_id"),
            )
    return len(due)


def _loop() -> None:
    while True:
        try:
            run_due_schedules()
        except Exception:
            logger.exception("falha inesperada no scheduler de recorrência")
        time.sleep(config.RECURRENCE_CHECK_INTERVAL_SECONDS)


def start() -> None:
    """Chamado uma vez no startup do backend (ver main.py). <= 0 desliga o
    scheduler inteiramente — thread nem chega a subir. Precisão de disparo é
    de ~1 intervalo de checagem (não é cron de precisão de segundo)."""
    if config.RECURRENCE_CHECK_INTERVAL_SECONDS <= 0:
        logger.info("scheduler de recorrência desligado (RECURRENCE_CHECK_INTERVAL_SECONDS <= 0)")
        return
    threading.Thread(target=_loop, daemon=True, name="recurrence-scheduler").start()
    logger.info("scheduler de recorrência iniciado (intervalo: %ss)", config.RECURRENCE_CHECK_INTERVAL_SECONDS)
