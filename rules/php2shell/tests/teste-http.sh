#!/usr/bin/env bash
set -euo pipefail
# Teste inofensivo da regra PHP2Shell. Não explora as CVEs: envia apenas o
# Nome do campo com valor inocente e confere se o WAF responde 403.
# Use somente contra servidores que voce administra ou esta autorizado a testar.
if [[ $# -ne 1 ]]; then
  echo "Uso: $0 https://seu-dominio.example/" >&2
  exit 2
fi
URL="$1"
case "$URL" in http://*|https://*) ;; *) echo "Informe URL HTTP(S)" >&2; exit 2;; esac

req() { # $1=descricao ; demais args: parametros do curl
  local desc="$1"; shift
  local code
  code=$(curl --silent --show-error --max-time 15 --output /dev/null \
    --write-out '%{http_code}' --request POST "$@" "$URL") || code="erro"
  printf '  %-42s HTTP %s\n' "$desc" "$code"
}

echo "Testando $URL"
echo "Esperado: 403 em cada caso quando a regra esta ativa."
echo

# 1) Caso basico: nome exato do campo (regra 1005001 / 1005005)
req "campo PHP_SESSION_UPLOAD_PROGRESS" --form 'PHP_SESSION_UPLOAD_PROGRESS=teste_waf'

# 2) Campo escondido apos preenchimento grande (testa SecRequestBodyLimitAction
#    Reject + regra de limite). Com ProcessPartial sem Reject isto poderia passar.
PADFILE=$(mktemp)
trap 'rm -f "$PADFILE"' EXIT
head -c 200000 /dev/zero | tr '\0' 'A' > "$PADFILE"
req "campo apos 200KB de padding" \
  --form "pad=<$PADFILE" --form 'PHP_SESSION_UPLOAD_PROGRESS=teste_waf'

# 3) Multipart malformado: boundary ausente (regra 1005002/1005003)
req "multipart sem boundary" \
  -H 'Content-Type: multipart/form-data' \
  --data-binary 'PHP_SESSION_UPLOAD_PROGRESS=teste_waf'

echo
echo 'Observacoes:'
echo '- Um 403 isolado pode vir de outro mecanismo; confirme o ID no log do ModSecurity.'
echo '- 400/413 nos casos 2 e 3 tambem indicam bloqueio (corpo rejeitado).'
echo '- Qualquer resultado aqui NAO prova que o servidor esta seguro: atualize o PHP.'
