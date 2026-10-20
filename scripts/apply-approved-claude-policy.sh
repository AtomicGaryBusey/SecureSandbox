#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Research." >&2
  exit 1
fi

settings_source="${1:-/tmp/managed-settings.proposed.json}"
launcher_source="${2:-/tmp/research-claude.proposed}"
registry_source="${3:-/tmp/session_registry.py}"
[[ -f "$settings_source" ]] || { echo "Missing managed settings." >&2; exit 2; }
[[ -f "$launcher_source" ]] || { echo "Missing launcher." >&2; exit 2; }
[[ -f "$registry_source" ]] || { echo "Missing session registry manager." >&2; exit 2; }
python3 -m json.tool "$settings_source" >/dev/null
bash -n "$launcher_source"
python3 -m py_compile "$registry_source"

install -d -o root -g root -m 755 /etc/claude-code
install -o root -g root -m 644 "$settings_source" \
  /etc/claude-code/managed-settings.json
install -o root -g root -m 755 "$launcher_source" \
  /usr/local/bin/research-claude
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox \
  /var/lib/secure-sandbox
install -o root -g root -m 755 "$registry_source" \
  /usr/local/libexec/secure-sandbox/session_registry.py
install -d -o agent -g agent -m 700 /home/agent/research-workspace
/usr/local/libexec/secure-sandbox/session_registry.py refresh

echo "claude-policy:installed; run the post-install safety audit before use"
