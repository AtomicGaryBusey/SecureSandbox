#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi

if ! getent group model-broker >/dev/null; then
  groupadd --system model-broker
fi
pki_dir=/etc/secure-sandbox/pki
[[ ! -L /etc/secure-sandbox && -d /etc/secure-sandbox ]] || {
  echo "SecureSandbox configuration root is invalid." >&2
  exit 2
}
if [[ -e "$pki_dir" || -L "$pki_dir" ]]; then
  [[ -d "$pki_dir" && ! -L "$pki_dir" ]] || {
    echo "Gateway PKI directory is invalid." >&2
    exit 2
  }
fi
install -d -o root -g model-broker -m 750 "$pki_dir"
[[ "$(stat -c '%U:%G:%a' "$pki_dir")" == root:model-broker:750 ]] || {
  echo "Gateway PKI directory metadata is invalid." >&2
  exit 2
}

require_regular() {
  [[ -f "$1" && ! -L "$1" && "$(stat -c %h "$1")" == 1 ]] || {
    echo "Invalid PKI object: $1" >&2
    exit 2
  }
}

same_public_key() {
  local key="$1"
  local certificate="$2"
  local key_public certificate_public
  key_public="$(mktemp "$pki_dir/.key-public.XXXXXX")"
  certificate_public="$(mktemp "$pki_dir/.certificate-public.XXXXXX")"
  local result=0
  openssl pkey -in "$key" -pubout -out "$key_public" >/dev/null 2>&1 \
    && openssl x509 -in "$certificate" -pubkey -noout > "$certificate_public" \
    && cmp -s "$key_public" "$certificate_public" || result=$?
  rm -f -- "$key_public" "$certificate_public"
  return "$result"
}

[[ ! -L "$pki_dir/ca.key" ]] || { echo "Gateway CA key path is invalid." >&2; exit 2; }
if [[ ! -e "$pki_dir/ca.key" ]]; then
  if [[ -e "$pki_dir/ca.crt" || -e "$pki_dir/server.key" || -e "$pki_dir/server.crt" ]]; then
    echo "Gateway PKI has descendants but no CA key; refusing identity replacement." >&2
    exit 2
  fi
  temporary_ca_key="$(mktemp "$pki_dir/.ca.key.XXXXXX")"
  openssl genpkey -algorithm ED25519 -out "$temporary_ca_key"
  chmod 600 "$temporary_ca_key"
  mv -f -- "$temporary_ca_key" "$pki_dir/ca.key"
fi
require_regular "$pki_dir/ca.key"
openssl pkey -in "$pki_dir/ca.key" -noout >/dev/null 2>&1 || {
  echo "Gateway CA key is invalid." >&2
  exit 2
}

[[ ! -L "$pki_dir/ca.crt" ]] || { echo "Gateway CA certificate path is invalid." >&2; exit 2; }
if [[ ! -e "$pki_dir/ca.crt" ]]; then
  if [[ -e "$pki_dir/server.crt" ]]; then
    echo "Gateway server certificate exists without its issuing CA certificate." >&2
    exit 2
  fi
  temporary_ca_certificate="$(mktemp "$pki_dir/.ca.crt.XXXXXX")"
  openssl req -x509 -new -key "$pki_dir/ca.key" \
    -out "$temporary_ca_certificate" -days 30 \
    -subj '/CN=SecureSandbox Broker CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'
  chmod 640 "$temporary_ca_certificate"
  mv -f -- "$temporary_ca_certificate" "$pki_dir/ca.crt"
fi
require_regular "$pki_dir/ca.crt"
openssl x509 -in "$pki_dir/ca.crt" -noout -checkend 1 >/dev/null 2>&1 \
  && same_public_key "$pki_dir/ca.key" "$pki_dir/ca.crt" || {
    echo "Gateway CA certificate does not match its existing key." >&2
    exit 2
  }

[[ ! -L "$pki_dir/server.key" ]] || { echo "Gateway server key path is invalid." >&2; exit 2; }
if [[ ! -e "$pki_dir/server.key" ]]; then
  if [[ -e "$pki_dir/server.crt" ]]; then
    echo "Gateway server certificate exists without its private key." >&2
    exit 2
  fi
  temporary_server_key="$(mktemp "$pki_dir/.server.key.XXXXXX")"
  openssl genpkey -algorithm ED25519 -out "$temporary_server_key"
  chmod 640 "$temporary_server_key"
  mv -f -- "$temporary_server_key" "$pki_dir/server.key"
fi
require_regular "$pki_dir/server.key"
openssl pkey -in "$pki_dir/server.key" -noout >/dev/null 2>&1 || {
  echo "Gateway server key is invalid." >&2
  exit 2
}

[[ ! -L "$pki_dir/server.crt" ]] || { echo "Gateway server certificate path is invalid." >&2; exit 2; }
if [[ ! -e "$pki_dir/server.crt" ]]; then
  temporary_server_request="$(mktemp "$pki_dir/.server.csr.XXXXXX")"
  temporary_server_certificate="$(mktemp "$pki_dir/.server.crt.XXXXXX")"
  openssl req -new -key "$pki_dir/server.key" \
    -out "$temporary_server_request" -subj '/CN=secure-sandbox-gateway'
  extension_file="$(mktemp "$pki_dir/.server-extensions.XXXXXX")"
  trap 'rm -f -- "${temporary_server_request:-}" "${temporary_server_certificate:-}" "${extension_file:-}"' EXIT
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=IP:172.30.10.1,DNS:secure-sandbox-gateway' \
    > "$extension_file"
  openssl x509 -req -in "$temporary_server_request" \
    -CA "$pki_dir/ca.crt" -CAkey "$pki_dir/ca.key" \
    -CAcreateserial -out "$temporary_server_certificate" \
    -days 14 -extfile "$extension_file"
  chmod 640 "$temporary_server_certificate"
  mv -f -- "$temporary_server_certificate" "$pki_dir/server.crt"
  rm -f -- "$temporary_server_request" "$extension_file" "$pki_dir/ca.srl"
  trap - EXIT
fi
require_regular "$pki_dir/server.crt"
openssl verify -purpose sslserver -CAfile "$pki_dir/ca.crt" "$pki_dir/server.crt" >/dev/null 2>&1 \
  && [[ "$(openssl x509 -in "$pki_dir/server.crt" -noout -subject -nameopt RFC2253)" == "subject=CN=secure-sandbox-gateway" ]] \
  && openssl x509 -in "$pki_dir/server.crt" -checkhost secure-sandbox-gateway -noout >/dev/null 2>&1 \
  && openssl x509 -in "$pki_dir/server.crt" -checkip 172.30.10.1 -noout >/dev/null 2>&1 \
  && same_public_key "$pki_dir/server.key" "$pki_dir/server.crt" || {
    echo "Gateway server certificate is invalid or does not match its existing key." >&2
    exit 2
  }

chown root:model-broker \
  "$pki_dir/ca.crt" \
  "$pki_dir/server.crt" \
  "$pki_dir/server.key"
chmod 640 \
  "$pki_dir/ca.crt" \
  "$pki_dir/server.crt" \
  "$pki_dir/server.key"
chown root:root "$pki_dir/ca.key"
chmod 600 "$pki_dir/ca.key"
rm -f "$pki_dir/server.csr" "$pki_dir/ca.srl"

echo "gateway-broker-pki:initialized"
