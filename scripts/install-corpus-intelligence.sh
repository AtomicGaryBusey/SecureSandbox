#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
settings="${1:-/tmp/managed-settings.proposed.json}"
managed_mcp="${2:-/tmp/managed-mcp.json}"
core="${3:-/tmp/corpus_intelligence.py}"
server="${4:-/tmp/corpus_intelligence_mcp.py}"
telemetry="${5:-/tmp/telemetry_exporter.py}"
rollback="${6:-/tmp/rollback_corpus_intelligence.sh}"
for source in "$settings" "$managed_mcp" "$core" "$server" "$telemetry" "$rollback"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact: $source" >&2; exit 2; }
done
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m json.tool "$settings" >/dev/null
python3 -m json.tool "$managed_mcp" >/dev/null
bash -n "$rollback"
python3 -m py_compile "$core" "$server" "$telemetry"

backup_id="corpus-intelligence-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
for item in managed-settings.json managed-mcp.json corpus_intelligence.py corpus_intelligence_mcp.py telemetry_exporter.py; do
  case "$item" in
    managed-settings.json) current="/etc/claude-code/managed-settings.json" ;;
    managed-mcp.json) current="/etc/claude-code/managed-mcp.json" ;;
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

install -d -o agent -g agent -m 750 /home/agent/research-workspace
install -d -o root -g root -m 755 /etc/claude-code /usr/local/libexec/secure-sandbox \
  /home/agent/research-workspace/corpus-indexes
install -o root -g root -m 644 "$settings" /etc/claude-code/managed-settings.json
install -o root -g root -m 644 "$managed_mcp" /etc/claude-code/managed-mcp.json
install -o root -g root -m 755 "$core" /usr/local/libexec/secure-sandbox/corpus_intelligence.py
install -o root -g root -m 755 "$server" /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback_corpus_intelligence.sh
python3 -m py_compile /usr/local/libexec/secure-sandbox/corpus_intelligence.py \
  /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py \
  /usr/local/libexec/secure-sandbox/telemetry_exporter.py
systemctl restart telemetry-exporter.service
systemctl is-active --quiet telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/corpus-intelligence-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/corpus-intelligence-latest
trap - ERR
echo "corpus-intelligence:installed:$backup_id"
