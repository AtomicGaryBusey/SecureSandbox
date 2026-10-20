#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi

if ! getent group model-broker >/dev/null; then
  groupadd --system model-broker
fi
install -d -o root -g model-broker -m 750 /etc/secure-sandbox/pki

if [[ -e /etc/secure-sandbox/pki/ca.key ]]; then
  echo "Refusing to replace existing Gateway CA." >&2
  exit 2
fi

openssl genpkey -algorithm ED25519 -out /etc/secure-sandbox/pki/ca.key
openssl req -x509 -new -key /etc/secure-sandbox/pki/ca.key \
  -out /etc/secure-sandbox/pki/ca.crt -days 30 \
  -subj '/CN=SecureSandbox Broker CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl genpkey -algorithm ED25519 -out /etc/secure-sandbox/pki/server.key
openssl req -new -key /etc/secure-sandbox/pki/server.key \
  -out /etc/secure-sandbox/pki/server.csr \
  -subj '/CN=secure-sandbox-gateway'
extension_file="$(mktemp)"
trap 'rm -f "$extension_file"' EXIT
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=IP:172.30.10.1,DNS:secure-sandbox-gateway' \
  > "$extension_file"
openssl x509 -req -in /etc/secure-sandbox/pki/server.csr \
  -CA /etc/secure-sandbox/pki/ca.crt \
  -CAkey /etc/secure-sandbox/pki/ca.key \
  -CAcreateserial -out /etc/secure-sandbox/pki/server.crt \
  -days 14 -extfile "$extension_file"

chown root:model-broker \
  /etc/secure-sandbox/pki/ca.crt \
  /etc/secure-sandbox/pki/server.crt \
  /etc/secure-sandbox/pki/server.key
chmod 640 \
  /etc/secure-sandbox/pki/ca.crt \
  /etc/secure-sandbox/pki/server.crt \
  /etc/secure-sandbox/pki/server.key
chmod 600 /etc/secure-sandbox/pki/ca.key
rm -f /etc/secure-sandbox/pki/server.csr /etc/secure-sandbox/pki/ca.srl

echo "gateway-broker-pki:initialized"
