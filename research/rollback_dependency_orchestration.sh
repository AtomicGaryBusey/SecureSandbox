#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/dependency-orchestration-latest)}"
[[ "$backup_id" =~ ^dependency-orchestration-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid backup ID" >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" && ! -L "$backup" ]] || { echo "Backup not found" >&2; exit 2; }

restore() {
  local name="$1" destination="$2" mode="$3"
  if [[ -f "$backup/$name" ]]; then
    install -o root -g root -m "$mode" "$backup/$name" "$destination"
  elif [[ -f "$backup/$name.absent" ]]; then
    rm -f "$destination"
  else
    echo "Incomplete backup: $name" >&2
    exit 2
  fi
}

restore dependency_orchestrator.py /usr/local/libexec/secure-sandbox/dependency_orchestrator.py 755
restore telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py 755
restore rollback_dependency_orchestration.sh /usr/local/libexec/secure-sandbox/rollback_dependency_orchestration.sh 755
# Security migrations are monotonic: rollback may restore application bytes,
# but it must never resurrect the retired labadmin automation grant.
rm -f -- /etc/sudoers.d/secure-sandbox-dependency-orchestration
visudo -c >/dev/null
systemctl restart telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
fi
echo "dependency-orchestration:rolled-back:$backup_id"
