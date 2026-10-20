#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "root required" >&2; exit 1; }
backup_id="${1:-}"
[[ "$backup_id" =~ ^corpus-intelligence-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "invalid backup id" >&2; exit 2; }
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" && ! -L "$backup" ]] || { echo "backup not found" >&2; exit 1; }

for item in managed-settings.json managed-mcp.json corpus_intelligence.py corpus_intelligence_mcp.py telemetry_exporter.py; do
  case "$item" in
    managed-settings.json) destination="/etc/claude-code/managed-settings.json"; mode=644 ;;
    managed-mcp.json) destination="/etc/claude-code/managed-mcp.json"; mode=644 ;;
    *) destination="/usr/local/libexec/secure-sandbox/$item"; mode=755 ;;
  esac
  if [[ -f "$backup/$item" ]]; then
    install -o root -g root -m "$mode" "$backup/$item" "$destination"
  elif [[ -f "$backup/$item.absent" ]]; then
    rm -f -- "$destination"
  else
    echo "incomplete backup: $item" >&2
    exit 1
  fi
done
systemctl restart telemetry-exporter.service
systemctl is-active --quiet telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
fi
echo "corpus-intelligence:rolled-back:$backup_id"
