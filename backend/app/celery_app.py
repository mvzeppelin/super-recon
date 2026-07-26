from celery import Celery

from . import config

_broker_url = f"redis://:{config.REDIS_PASSWORD}@{config.REDIS_HOST}:{config.REDIS_PORT}/0"

celery_app = Celery("recon", broker=_broker_url, backend=_broker_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Cada tarefa roda no máximo 1 container Kali por vez; --concurrency do
    # worker (ver entrypoint-worker.sh) já limita a paralelismo = RECON_CPUS.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    imports=("app.tasks",),
)
