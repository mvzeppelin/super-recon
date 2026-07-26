#!/bin/sh
# Restaura um snapshot tirado por backup.sh.
#
# Uso:
#   ./opensearch/restore.sh                                # lista os snapshots disponíveis
#   ./opensearch/restore.sh <nome-do-snapshot>              # restaura todos os índices do snapshot
#   ./opensearch/restore.sh <nome-do-snapshot> "acme-*"     # restaura só os índices que baterem o padrão
#
# O OpenSearch recusa restaurar um índice que já existe (ex: "acme-nuclei" já
# existe, mesmo que com dado ruim/incompleto) — apague ou fixe manualmente o
# índice em questão antes de restaurar por cima dele:
#   curl -sk -u admin:<senha> -X DELETE "https://localhost:9200/acme-nuclei"
# Isso é intencional: o script não apaga nada por conta própria.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

set -a
. ./.env
set +a

BASE_URL="https://${OPENSEARCH_HOST_BIND:-127.0.0.1}:9200"
AUTH="${OPENSEARCH_ADMIN_USER}:${OPENSEARCH_ADMIN_PASSWORD}"

if [ "$#" -lt 1 ]; then
  echo "[restore] snapshots disponíveis em 'recon-backups':"
  curl -sk -u "$AUTH" "${BASE_URL}/_snapshot/recon-backups/_all" \
    -H "Content-Type: application/json" --fail-with-body
  echo
  echo "[restore] uso: $0 <nome-do-snapshot> [padrão-de-índices]"
  exit 0
fi

SNAPSHOT_NAME="$1"
INDICES_PATTERN="${2:-*}"

printf '[restore] restaurar o snapshot "%s" (índices: %s) em %s? Isso NÃO apaga nada primeiro — índices já existentes causam erro. [y/N] ' \
  "$SNAPSHOT_NAME" "$INDICES_PATTERN" "$BASE_URL"
read -r confirm
case "$confirm" in
  y|Y|yes|s|S|sim) ;;
  *) echo "[restore] cancelado."; exit 1 ;;
esac

curl -sk -u "$AUTH" -X POST "${BASE_URL}/_snapshot/recon-backups/${SNAPSHOT_NAME}/_restore?wait_for_completion=true" \
  -H "Content-Type: application/json" \
  -d "{\"indices\": \"${INDICES_PATTERN}\"}" \
  --fail-with-body
echo
echo "[restore] concluído."
