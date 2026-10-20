#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Research." >&2
  exit 1
fi

auditor_source="${1:-/tmp/claude_tool_auditor.py}"
unit_source="${2:-/tmp/claude-tool-auditor.service}"

for source in "$auditor_source" "$unit_source"; do
  [[ -f "$source" ]] || { echo "Missing required file: $source" >&2; exit 2; }
done

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g root -m 700 /var/lib/secure-sandbox/tool-auditor
install -o root -g root -m 755 "$auditor_source" \
  /usr/local/libexec/secure-sandbox/claude_tool_auditor.py
install -o root -g root -m 644 "$unit_source" \
  /etc/systemd/system/claude-tool-auditor.service

python3 -m py_compile /usr/local/libexec/secure-sandbox/claude_tool_auditor.py
systemd-analyze security claude-tool-auditor.service --offline=yes >/dev/null
systemctl daemon-reload
systemctl enable --now claude-tool-auditor.service
systemctl is-active --quiet claude-tool-auditor.service

echo "claude-tool-auditor:active"
