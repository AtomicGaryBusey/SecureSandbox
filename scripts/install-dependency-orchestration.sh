#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
orchestrator="${1:-/tmp/dependency_orchestrator.py}"
telemetry="${2:-/tmp/telemetry_exporter.py}"
rollback="${3:-/tmp/rollback_dependency_orchestration.sh}"
for source in "$orchestrator" "$telemetry" "$rollback"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact: $source" >&2; exit 2; }
done
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m py_compile "$orchestrator" "$telemetry"
bash -n "$rollback"

backup_id="dependency-orchestration-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
for current in \
  /usr/local/libexec/secure-sandbox/dependency_orchestrator.py \
  /usr/local/libexec/secure-sandbox/telemetry_exporter.py \
  /usr/local/libexec/secure-sandbox/rollback_dependency_orchestration.sh \
  /etc/sudoers.d/secure-sandbox-dependency-orchestration; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"

rollback_on_error() {
  trap - ERR
  bash "$rollback" "$backup_id" >/dev/null || true
}
trap rollback_on_error ERR

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g root -m 700 /var/lib/secure-sandbox/dependency-orchestration \
  /var/lib/secure-sandbox/dependency-orchestration/plans \
  /var/lib/secure-sandbox/dependency-orchestration/transactions
install -d -o agent -g agent -m 750 /home/agent/research-workspace
install -d -o root -g root -m 755 /home/agent/research-workspace/dependency-bundles
install -o root -g root -m 755 "$orchestrator" /usr/local/libexec/secure-sandbox/dependency_orchestrator.py
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback_dependency_orchestration.sh
if [[ ! -e /home/agent/research-workspace/dependency-bundles/INDEX.json ]]; then
  printf '%s\n' '{"bundles":[],"schema":"secure-sandbox-dependency-bundle-index-v1"}' \
    > /home/agent/research-workspace/dependency-bundles/INDEX.json
fi
chown root:root /home/agent/research-workspace/dependency-bundles/INDEX.json
chmod 444 /home/agent/research-workspace/dependency-bundles/INDEX.json
rm -f -- /etc/sudoers.d/secure-sandbox-dependency-orchestration
visudo -c >/dev/null
python3 -m py_compile /usr/local/libexec/secure-sandbox/dependency_orchestrator.py \
  /usr/local/libexec/secure-sandbox/telemetry_exporter.py
systemctl restart telemetry-exporter.service
systemctl is-active --quiet telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/dependency-orchestration-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/dependency-orchestration-latest
trap - ERR
echo "dependency-orchestration:installed:$backup_id"
