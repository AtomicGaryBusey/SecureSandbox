#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Gateway." >&2; exit 1; }
csr="${1:-/tmp/research-conversation.csr}"; output="${2:-/tmp/research-conversation.crt}"
extensions="$(mktemp)"; trap 'rm -f "$extensions"' EXIT
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=clientAuth' > "$extensions"
openssl x509 -req -in "$csr" -CA /etc/secure-sandbox/pki/ca.crt -CAkey /etc/secure-sandbox/pki/ca.key -CAcreateserial -out "$output" -days 7 -extfile "$extensions"
chmod 644 "$output"; rm -f /etc/secure-sandbox/pki/ca.srl
echo conversation-transport:certificate-signed
