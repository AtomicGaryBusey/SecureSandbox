#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
manager="${1:-/tmp/harness_generation_manager.py}"
inspector="${2:-/tmp/harness-generation.py}"
store="${3:-/tmp/harness_generation_store.py}"
workflow="${4:-/tmp/privileged_workflow.py}"
binding="${5:-/tmp/harness_runtime_binding.py}"
rollback="${6:-/tmp/rollback-harness-lifecycle-consumer.sh}"
backup_id="${7:-harness-lifecycle-consumer-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
for source in "$manager" "$inspector" "$store" "$workflow" "$binding" "$rollback"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing regular deployment source." >&2; exit 2; }
done
[[ "$backup_id" =~ ^harness-lifecycle-consumer-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid backup identity." >&2; exit 2; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || {
  echo "active or unreconciled agent run" >&2; exit 1;
}
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m py_compile "$manager" "$inspector" "$store" "$workflow" "$binding"
bash -n "$rollback"

backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ ! -e "$backup" && ! -L "$backup" ]] || { echo "Backup identity already exists." >&2; exit 1; }
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
declare -a names=(harness-generation-manager.py harness-generation.py harness_generation_store.py privileged_workflow.py harness_runtime_binding.py rollback-harness-lifecycle-consumer.sh)
declare -a destinations=(
  /usr/local/libexec/secure-sandbox/harness-generation-manager.py
  /usr/local/libexec/secure-sandbox/harness-generation.py
  /usr/local/libexec/secure-sandbox/shared/harness_generation_store.py
  /usr/local/libexec/secure-sandbox/shared/privileged_workflow.py
  /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py
  /usr/local/libexec/secure-sandbox/rollback-harness-lifecycle-consumer.sh
)
for index in "${!names[@]}"; do
  current="${destinations[$index]}"; name="${names[$index]}"
  if [[ -f "$current" && ! -L "$current" ]]; then
    cp --no-dereference "$current" "$backup/$name"
  else
    : > "$backup/$name.absent"
  fi
done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash "$rollback" "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox/shared
install -o root -g root -m 755 "$manager" "${destinations[0]}"
install -o root -g root -m 755 "$inspector" "${destinations[1]}"
install -o root -g root -m 644 "$store" "${destinations[2]}"
install -o root -g root -m 644 "$workflow" "${destinations[3]}"
install -o root -g root -m 644 "$binding" "${destinations[4]}"
install -o root -g root -m 755 "$rollback" "${destinations[5]}"
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox-harnesses
install -d -o root -g root -m 700 /var/lib/secure-sandbox/harnesses
status="$(/usr/local/libexec/secure-sandbox/harness-generation.py status)"
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["schema"] == "secure-sandbox-harness-generation-status-v1"' <<<"$status"
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/harness-lifecycle-consumer-latest
chown root:root /var/lib/secure-sandbox/policy-backups/harness-lifecycle-consumer-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/harness-lifecycle-consumer-latest
sync -d /var/lib/secure-sandbox/policy-backups
trap - ERR
echo "harness-lifecycle-consumer:installed:$backup_id"
