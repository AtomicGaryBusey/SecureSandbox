#!/bin/bash
set -euo pipefail

role="${1:-}"
engine="${2:-/tmp/privileged_workflow.py}"
verifier="${3:-/tmp/privileged_workflow_live_verifier.py}"
case "$role" in gateway|research|target) ;; *) echo "Usage: install-privileged-workflow-engine.sh gateway|research|target" >&2; exit 2;; esac
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root in the guest." >&2; exit 1; }
for source in "$engine" "$verifier" /tmp/update-policy-hash.sh; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact." >&2; exit 2; }
done
python3 -m py_compile "$engine" "$verifier"

backup_id="privileged-workflow-$role-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
destinations=(
  /usr/local/libexec/secure-sandbox/shared/privileged_workflow.py
  /usr/local/libexec/secure-sandbox/privileged_workflow_live_verifier.py
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh
)
for destination in "${destinations[@]}"; do
  name="$(basename "$destination")"
  if [[ -f "$destination" && ! -L "$destination" ]]; then
    cp --no-dereference "$destination" "$backup/$name"
  else
    : > "$backup/$name.absent"
  fi
done
chmod -R go-rwx "$backup"
rollback_on_error() {
  trap - ERR
  for destination in "${destinations[@]}"; do
    name="$(basename "$destination")"
    if [[ -f "$backup/$name" ]]; then
      cp --no-dereference "$backup/$name" "$destination"
    elif [[ -f "$backup/$name.absent" ]]; then
      rm -f -- "$destination"
    fi
  done
}
trap rollback_on_error ERR

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox/shared
install -o root -g root -m 755 "$engine" /usr/local/libexec/secure-sandbox/shared/privileged_workflow.py
install -o root -g root -m 755 "$verifier" /usr/local/libexec/secure-sandbox/privileged_workflow_live_verifier.py
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh
PYTHONPATH=/usr/local/libexec/secure-sandbox \
  /usr/local/libexec/secure-sandbox/privileged_workflow_live_verifier.py "$role"
/usr/local/libexec/secure-sandbox/update-policy-hash.sh "$role" >/dev/null
trap - ERR
echo "privileged-workflow-$role:installed:$backup_id"
