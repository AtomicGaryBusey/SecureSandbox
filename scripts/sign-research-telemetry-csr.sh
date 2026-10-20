#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi

csr="${1:-/tmp/research-telemetry.csr}"
output="${2:-/tmp/research-telemetry.crt}"
[[ -f "$csr" ]] || { echo "Missing CSR: $csr" >&2; exit 2; }
[[ -f /etc/secure-sandbox/pki/ca.key ]] || {
  echo "Gateway CA has not been initialized." >&2
  exit 2
}

extension_file="$(mktemp)"
trap 'rm -f "$extension_file"' EXIT
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  > "$extension_file"
openssl x509 -req -in "$csr" \
  -CA /etc/secure-sandbox/pki/ca.crt \
  -CAkey /etc/secure-sandbox/pki/ca.key \
  -CAcreateserial -out "$output" -days 7 -extfile "$extension_file"
chmod 644 "$output"
rm -f /etc/secure-sandbox/pki/ca.srl

echo "research-telemetry-identity:certificate-signed"
