#!/bin/sh
set -eu

# HTTPS opcional (ver README "HTTPS") — desligado por padrão (HTTPS_ENABLED
# vazio), comportamento idêntico a sempre. Ligado, o backend passa a
# responder só em HTTPS, na mesma porta de sempre (BACKEND_PORT no host,
# 8000 dentro do container) — sem redirect automático de HTTP: diferente
# do frontend, aqui é uma API consumida por curl/scripts, não uma página
# pra "visitar" no navegador.
#
# Se vier algum argumento (ex: "docker compose run backend pytest -q" ou
# "... backend bash"), roda exatamente esse comando em vez de subir o
# uvicorn — mesmo comportamento que existia com CMD antes de virar
# ENTRYPOINT, necessário pra continuar rodando a suite de testes/shell
# manual no container sem precisar de HTTPS/certificado nenhum.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

if [ -n "${HTTPS_ENABLED:-}" ]; then
  if [ ! -f /certs/fullchain.pem ] || [ ! -f /certs/privkey.pem ]; then
    echo "[backend] ERRO: HTTPS_ENABLED está ligado mas /certs/fullchain.pem ou /certs/privkey.pem não existe (montados de ./certs no host). Gere um autoassinado com certs/generate-self-signed-cert.sh ou instale um certificado de verdade — ver README \"HTTPS\"." >&2
    exit 1
  fi
  echo "[backend] HTTPS ligado, usando certificado em /certs"
  exec uvicorn app.main:app --host 0.0.0.0 --port 8000 \
    --ssl-keyfile /certs/privkey.pem --ssl-certfile /certs/fullchain.pem
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
