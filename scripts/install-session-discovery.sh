#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This installer must run as root on Research." >&2
  exit 1
fi

registry_source="${1:-/tmp/session_registry.py}"
[[ -f "$registry_source" && ! -L "$registry_source" ]] \
  || { echo "Missing trusted session registry source." >&2; exit 2; }
/usr/bin/python3 -m py_compile "$registry_source"

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox /var/lib/secure-sandbox
install -o root -g root -m 755 "$registry_source" \
  /usr/local/libexec/secure-sandbox/session_registry.py
/usr/local/libexec/secure-sandbox/session_registry.py refresh

registry_sha256="$(sha256sum /usr/local/libexec/secure-sandbox/session_registry.py | cut -d' ' -f1)"
registry_rows="$(wc -l </var/lib/secure-sandbox/claude-sessions.txt | tr -d ' ')"
/usr/bin/jq -ncS --arg registry_sha256 "$registry_sha256" --argjson registry_rows "$registry_rows" \
  '{registry_rows:$registry_rows,registry_sha256:$registry_sha256,
    schema:"secure-sandbox-session-discovery-install-v1",status:"installed"}'
