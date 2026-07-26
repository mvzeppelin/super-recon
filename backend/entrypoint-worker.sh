#!/bin/sh
set -eu

CONCURRENCY="${RECON_CPUS:-$(nproc)}"
echo "[worker] concorrência = ${CONCURRENCY} cores"

exec celery -A app.celery_app.celery_app worker --loglevel=info --concurrency="${CONCURRENCY}"
