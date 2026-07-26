#!/bin/sh
# Tira um snapshot de todos os índices de dados do projeto (achados, jobs,
# scans, wordlists — exclui índices internos do OpenSearch/plugins, tipo
# .opendistro-*, security-auditlog-*, top_queries-*).
#
# Uso:
#   ./opensearch/backup.sh              # nome automático (backup-AAAAMMDD-HHMMSS)
#   ./opensearch/backup.sh meu-backup   # nome escolhido
#
# Roda do host (fora de qualquer container) — depende só de curl e do
# OpenSearch estar acessível em OPENSEARCH_HOST_BIND:9200 (ver .env).
# Os arquivos ficam em data/opensearch-snapshots/; copie essa pasta pra fora
# do host (outro disco, outra máquina, S3 etc.) — um backup que só existe no
# mesmo disco dos dados originais não protege contra falha de disco/host.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

set -a
. ./.env
set +a

BASE_URL="https://${OPENSEARCH_HOST_BIND:-127.0.0.1}:9200"
AUTH="${OPENSEARCH_ADMIN_USER}:${OPENSEARCH_ADMIN_PASSWORD}"
SNAPSHOT_NAME="${1:-backup-$(date +%Y%m%d-%H%M%S)}"

echo "[backup] tirando snapshot '${SNAPSHOT_NAME}'..."
curl -sk -u "$AUTH" -X PUT "${BASE_URL}/_snapshot/recon-backups/${SNAPSHOT_NAME}?wait_for_completion=true" \
  -H "Content-Type: application/json" \
  -d '{"indices": "*,-.*,-security-auditlog-*,-top_queries-*", "include_global_state": false}' \
  --fail-with-body
echo
echo "[backup] concluído: ${SNAPSHOT_NAME}"
echo "[backup] arquivos em data/opensearch-snapshots/ — copie essa pasta pra fora do host."
