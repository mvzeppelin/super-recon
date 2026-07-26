#!/bin/sh
set -eu

# Hook do entrypoint oficial da imagem nginx (roda todo script executável
# em /docker-entrypoint.d/ antes do nginx subir — não precisa sobrescrever
# o ENTRYPOINT da imagem). Ver README "HTTPS".

if [ -z "${HTTPS_ENABLED:-}" ]; then
  # Desligado (padrão) — a config HTTP simples que o Dockerfile já copiou
  # pra /etc/nginx/conf.d/default.conf continua valendo, sem tocar em nada.
  exit 0
fi

if [ ! -f /certs/fullchain.pem ] || [ ! -f /certs/privkey.pem ]; then
  echo "[frontend] ERRO: HTTPS_ENABLED está ligado mas /certs/fullchain.pem ou /certs/privkey.pem não existe (montados de ./certs no host). Gere um autoassinado com certs/generate-self-signed-cert.sh ou instale um certificado de verdade — ver README \"HTTPS\"." >&2
  exit 1
fi

echo "[frontend] HTTPS ligado — porta 80 passa a só redirecionar pra HTTPS (porta ${FRONTEND_HTTPS_PORT:-3443})"
FRONTEND_HTTPS_PORT="${FRONTEND_HTTPS_PORT:-3443}" envsubst '${FRONTEND_HTTPS_PORT}' \
  < /etc/nginx/nginx-https.conf.template \
  > /etc/nginx/conf.d/default.conf
