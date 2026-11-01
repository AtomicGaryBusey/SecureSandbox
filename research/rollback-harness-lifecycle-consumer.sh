#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || {
  echo "active or unreconciled agent run" >&2; exit 1;
}
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/harness-lifecycle-consumer-latest)}"
[[ "$backup_id" =~ ^harness-lifecycle-consumer-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid backup ID." >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" && ! -L "$backup" ]] || { echo "Backup not found." >&2; exit 2; }
restore() {
  local name="$1" destination="$2" mode="$3"
  if [[ -f "$backup/$name" && ! -L "$backup/$name" ]]; then
    install -o root -g root -m "$mode" "$backup/$name" "$destination"
  elif [[ -f "$backup/$name.absent" && ! -L "$backup/$name.absent" ]]; then
    rm -f -- "$destination"
  else
    echo "Incomplete backup: $name" >&2; exit 2
  fi
}
# Never remove lifecycle code underneath a published generation.  An older
# code backup may be restored, but an absence marker is valid only for an empty store.
if [[ -f "$backup/harness_generation_store.py.absent" \
   && -f /var/lib/secure-sandbox/harnesses/selector.json ]] \
   && ! grep -q '"active_generation_id":null' /var/lib/secure-sandbox/harnesses/selector.json; then
  echo "Refusing to remove lifecycle consumer with a published generation." >&2; exit 1
fi
restore harness-generation-manager.py /usr/local/libexec/secure-sandbox/harness-generation-manager.py 755
restore harness-generation.py /usr/local/libexec/secure-sandbox/harness-generation.py 755
restore harness_generation_store.py /usr/local/libexec/secure-sandbox/shared/harness_generation_store.py 644
restore privileged_workflow.py /usr/local/libexec/secure-sandbox/shared/privileged_workflow.py 644
restore harness_runtime_binding.py /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py 644
restore rollback-harness-lifecycle-consumer.sh /usr/local/libexec/secure-sandbox/rollback-harness-lifecycle-consumer.sh 755
echo "harness-lifecycle-consumer:rolled-back:$backup_id"
