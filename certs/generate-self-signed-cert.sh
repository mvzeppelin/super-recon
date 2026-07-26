#!/bin/sh
set -eu

# Gera um par autoassinado pra desenvolvimento/teste local — não é um
# certificado confiável por navegador nenhum, é só o suficiente pra ligar
# HTTPS_ENABLED e testar o fluxo (ver README "HTTPS"). Pra produção de
# verdade, instale um certificado real (Let's Encrypt, comprado, ou emitido
# por uma CA interna) nos mesmos dois arquivos.

DIR="$(cd "$(dirname "$0")" && pwd)"
DAYS="${1:-825}"

if [ -f "$DIR/fullchain.pem" ] || [ -f "$DIR/privkey.pem" ]; then
  echo "Já existe um certificado em $DIR — remova fullchain.pem/privkey.pem antes de gerar um novo." >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/privkey.pem" -out "$DIR/fullchain.pem" \
  -days "$DAYS" -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$DIR/privkey.pem"

echo
echo "Certificado autoassinado gerado:"
echo "  $DIR/fullchain.pem"
echo "  $DIR/privkey.pem"
echo "(válido por $DAYS dias)"
echo
echo "Pra ligar: defina HTTPS_ENABLED=true no .env e reinicie backend/frontend:"
echo "  docker compose up -d backend frontend"
