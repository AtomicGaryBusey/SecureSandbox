#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "root required" >&2; exit 1; }
backup_id="${1:-}"
[[ "$backup_id" =~ ^source-integrity-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "invalid backup id" >&2; exit 2; }
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" && ! -L "$backup" ]] || { echo "backup not found" >&2; exit 1; }

install -o root -g root -m 644 "$backup/managed-settings.json" /etc/claude-code/managed-settings.json
install -o root -g root -m 755 "$backup/research-claude" /usr/local/bin/research-claude
for item in managed-mcp.json source_integrity.py source_integrity_mcp.py source_importer.py telemetry_exporter.py source_import_wrapper.py; do
  case "$item" in
    managed-mcp.json) destination="/etc/claude-code/$item" ;;
    source_import_wrapper.py) destination="/usr/local/sbin/secure-sandbox-source-import" ;;
    *) destination="/usr/local/libexec/secure-sandbox/$item" ;;
  esac
  if [[ -f "$backup/$item" ]]; then
    mode=755; [[ "$item" == managed-mcp.json ]] && mode=644
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
echo "source-integrity:rolled-back:$backup_id"
