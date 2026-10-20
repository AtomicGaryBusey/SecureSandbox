#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Research." >&2
  exit 1
fi

identity_dir=/home/agent/.config/secure-sandbox
if [[ -e "$identity_dir/client.key" ]]; then
  echo "Refusing to replace existing broker client key." >&2
  exit 2
fi

install -d -o agent -g agent -m 700 "$identity_dir"
runuser -u agent -- openssl genpkey -algorithm ED25519 \
  -out "$identity_dir/client.key"
runuser -u agent -- openssl req -new -key "$identity_dir/client.key" \
  -out "$identity_dir/client.csr" \
  -subj '/CN=secure-sandbox-research'
chmod 600 "$identity_dir/client.key" "$identity_dir/client.csr"

echo "research-broker-identity:csr-ready"
