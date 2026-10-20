#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
settings="${1:-/tmp/managed-settings.proposed.json}"
launcher="${2:-/tmp/research-claude.proposed}"
managed_mcp="${3:-/tmp/managed-mcp.json}"
core="${4:-/tmp/source_integrity.py}"
server="${5:-/tmp/source_integrity_mcp.py}"
rollback="${6:-/tmp/rollback_source_integrity.sh}"
importer="${7:-/tmp/source_importer.py}"
telemetry="${8:-/tmp/telemetry_exporter.py}"
wrapper="${9:-/tmp/source_import_wrapper.py}"
for source in "$settings" "$launcher" "$managed_mcp" "$core" "$server" "$rollback" "$importer" "$telemetry" "$wrapper"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact: $source" >&2; exit 2; }
done
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m json.tool "$settings" >/dev/null
python3 -m json.tool "$managed_mcp" >/dev/null
bash -n "$launcher" "$rollback"
python3 -m py_compile "$core" "$server" "$importer" "$telemetry" "$wrapper"

backup_id="source-integrity-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
cp --no-dereference /etc/claude-code/managed-settings.json "$backup/managed-settings.json"
cp --no-dereference /usr/local/bin/research-claude "$backup/research-claude"
for item in managed-mcp.json source_integrity.py source_integrity_mcp.py source_importer.py telemetry_exporter.py source_import_wrapper.py; do
  case "$item" in
    managed-mcp.json) current="/etc/claude-code/$item" ;;
    source_import_wrapper.py) current="/usr/local/sbin/secure-sandbox-source-import" ;;
    *) current="/usr/local/libexec/secure-sandbox/$item" ;;
  esac
  if [[ -f "$current" && ! -L "$current" ]]; then
    cp --no-dereference "$current" "$backup/$item"
  else
    : > "$backup/$item.absent"
  fi
done
chmod -R go-rwx "$backup"

rollback_on_error() {
  trap - ERR
  bash "$rollback" "$backup_id" >/dev/null || true
}
trap rollback_on_error ERR

install -d -o root -g root -m 755 /etc/claude-code /usr/local/libexec/secure-sandbox /home/agent/research-workspace/source-manifests
install -o root -g root -m 644 "$settings" /etc/claude-code/managed-settings.json
install -o root -g root -m 644 "$managed_mcp" /etc/claude-code/managed-mcp.json
install -o root -g root -m 755 "$launcher" /usr/local/bin/research-claude
install -o root -g root -m 755 "$core" /usr/local/libexec/secure-sandbox/source_integrity.py
install -o root -g root -m 755 "$server" /usr/local/libexec/secure-sandbox/source_integrity_mcp.py
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback_source_integrity.sh
install -o root -g root -m 755 "$importer" /usr/local/libexec/secure-sandbox/source_importer.py
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 755 "$wrapper" /usr/local/sbin/secure-sandbox-source-import
python3 -m py_compile /usr/local/libexec/secure-sandbox/source_integrity.py /usr/local/libexec/secure-sandbox/source_integrity_mcp.py /usr/local/libexec/secure-sandbox/source_importer.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py /usr/local/sbin/secure-sandbox-source-import
systemctl restart telemetry-exporter.service
systemctl is-active --quiet telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/source-integrity-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/source-integrity-latest
trap - ERR
echo "source-integrity:installed:$backup_id"
