#!/bin/sh
set -eu

BASE_URL="https://opensearch:9200"
AUTH="${OPENSEARCH_ADMIN_USER}:${OPENSEARCH_ADMIN_PASSWORD}"
TEMPLATES_DIR="/templates"
ISM_DIR="/ism-policies"

echo "[init] aplicando component template comum..."
curl -sk -u "$AUTH" -X PUT "$BASE_URL/_component_template/recon-common-mappings" \
  -H "Content-Type: application/json" \
  --data-binary "@${TEMPLATES_DIR}/_component-common.json" \
  --fail-with-body
echo

for file in "$TEMPLATES_DIR"/*.json; do
  name=$(basename "$file" .json)
  [ "$name" = "_component-common" ] && continue

  echo "[init] aplicando index template: recon-${name}..."
  curl -sk -u "$AUTH" -X PUT "$BASE_URL/_index_template/recon-${name}" \
    -H "Content-Type: application/json" \
    --data-binary "@${file}" \
    --fail-with-body
  echo
done

echo "[init] templates aplicados com sucesso."

# ---------------------------------------------------------------------------
# ILM básico (via ISM, o plugin de lifecycle já incluso no OpenSearch): cada
# policy abaixo só é criada/atualizada se a variável de retenção correspondente
# estiver definida (dias) — vazio/ausente = sem expiração automática pra esse
# grupo, mantendo o comportamento de sempre (guardar tudo indefinidamente) até
# o usuário optar explicitamente por configurar. `ism_template` no corpo da
# policy faz o attach automático em índices *novos* que casarem o pattern; a
# chamada extra em _plugins/_ism/add cobre índices *já existentes* antes da
# policy existir (retroativo).
# ---------------------------------------------------------------------------

apply_ism_policy() {
  policy_id="$1"
  policy_file="$2"
  retention_days="$3"
  index_pattern="$4"

  if [ -z "$retention_days" ]; then
    echo "[init] ${policy_id}: sem dias de retenção configurados, pulando (esse grupo não expira automaticamente)."
    return
  fi

  tmp_file="/tmp/${policy_id}.json"
  sed "s/__RETENTION_DAYS__/${retention_days}/g" "$policy_file" > "$tmp_file"

  echo "[init] aplicando política ISM: ${policy_id} (retenção: ${retention_days} dias)..."
  existing=$(curl -sk -u "$AUTH" "$BASE_URL/_plugins/_ism/policies/${policy_id}")
  seq_no=$(echo "$existing" | grep -o '"_seq_no":[0-9]*' | head -1 | cut -d: -f2)
  primary_term=$(echo "$existing" | grep -o '"_primary_term":[0-9]*' | head -1 | cut -d: -f2)

  if [ -n "$seq_no" ] && [ -n "$primary_term" ]; then
    # já existe de um boot anterior — precisa do seq_no/primary_term atuais,
    # senão o PUT falha com 409 (controle de concorrência otimista do ISM).
    curl -sk -u "$AUTH" -X PUT "$BASE_URL/_plugins/_ism/policies/${policy_id}?if_seq_no=${seq_no}&if_primary_term=${primary_term}" \
      -H "Content-Type: application/json" --data-binary "@${tmp_file}" --fail-with-body
  else
    curl -sk -u "$AUTH" -X PUT "$BASE_URL/_plugins/_ism/policies/${policy_id}" \
      -H "Content-Type: application/json" --data-binary "@${tmp_file}" --fail-with-body
  fi
  echo

  echo "[init] aplicando ${policy_id} retroativamente a índices já existentes (${index_pattern})..."
  curl -sk -u "$AUTH" -X POST "$BASE_URL/_plugins/_ism/add/${index_pattern}" \
    -H "Content-Type: application/json" -d "{\"policy_id\": \"${policy_id}\"}" \
    --fail-with-body
  echo
}

apply_ism_policy "recon-short-retention" "${ISM_DIR}/short-retention.json" "${ILM_SHORT_RETENTION_DAYS:-}" "*-wayback,*-katana"
apply_ism_policy "recon-long-retention" "${ISM_DIR}/long-retention.json" "${ILM_LONG_RETENTION_DAYS:-}" "*-*"

echo "[init] ILM configurado."

# ---------------------------------------------------------------------------
# Repositório de snapshot (backup) — só registra o repositório em si (deixa
# pronto pra usar); tirar o snapshot é uma ação explícita do usuário (ver
# README "Backup do OpenSearch"), não algo automático a cada boot. PUT
# _snapshot/<repo> não é versionado como as policies de ISM (não tem
# seq_no/primary_term) — reaplicar com a mesma config é sempre idempotente.
# ---------------------------------------------------------------------------

echo "[init] registrando repositório de snapshot: recon-backups..."
curl -sk -u "$AUTH" -X PUT "$BASE_URL/_snapshot/recon-backups" \
  -H "Content-Type: application/json" \
  -d '{"type": "fs", "settings": {"location": "/usr/share/opensearch/snapshots", "compress": true}}' \
  --fail-with-body
echo
echo "[init] repositório de snapshot pronto."
