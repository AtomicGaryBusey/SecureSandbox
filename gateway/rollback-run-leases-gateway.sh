#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/run-leases-gateway-latest)}"
[[ "$backup_id" =~ ^run-leases-gateway-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid rollback generation." >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" ]] || { echo "Unknown rollback generation." >&2; exit 2; }
self_destination=/usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh
for destination in \
  /usr/local/libexec/secure-sandbox/run_lease.py \
  /usr/local/libexec/secure-sandbox/model_broker.py \
  /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py \
  /usr/local/libexec/secure-sandbox/telemetry_receiver.py \
  /usr/local/libexec/secure-sandbox/conversation_receiver.py \
  /usr/local/libexec/secure-sandbox/update_client_fingerprints.py \
  /usr/local/libexec/secure-sandbox/shared/__init__.py \
  /usr/local/libexec/secure-sandbox/shared/bounded_http.py \
  /usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh \
  /etc/secure-sandbox/run-lease-profiles.json \
  /etc/systemd/system/model-broker.service \
  /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh \
  /etc/systemd/system/run-leases-install-recovery.service \
  /etc/secure-sandbox/broker.json; do
  [[ "$destination" != "$self_destination" ]] || continue
  name="$(basename "$destination")"
  if [[ -f "$backup/$name" ]]; then cp --no-dereference "$backup/$name" "$destination"; elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"; fi
done
systemctl daemon-reload
if [[ -f /etc/systemd/system/run-leases-install-recovery.service ]]; then
  systemctl enable run-leases-install-recovery.service >/dev/null
else
  systemctl disable run-leases-install-recovery.service >/dev/null 2>&1 || true
fi
for service in model-broker.service telemetry-receiver.service conversation-receiver.service local-telemetry-exporter.service; do
  if systemctl is-active --quiet "$service"; then systemctl restart "$service"; fi
done
# Never truncate the script Bash is currently reading.  Publish its predecessor
# through a new inode so this invocation can finish on its already-open inode.
self_name="$(basename "$self_destination")"
if [[ -f "$backup/$self_name" ]]; then
  self_tmp="${self_destination}.rollback.$$"
  install -o root -g root -m 755 "$backup/$self_name" "$self_tmp"
  mv -f -- "$self_tmp" "$self_destination"
elif [[ -f "$backup/$self_name.absent" ]]; then
  rm -f -- "$self_destination"
fi
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh gateway >/dev/null; fi
rm -f /var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending
sync -d /var/lib/secure-sandbox/policy-backups
echo "run-leases-gateway:rolled-back:$backup_id"

