#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/run-leases-gateway-latest)}"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" ]] || { echo "Unknown rollback generation." >&2; exit 2; }
for destination in \
  /usr/local/libexec/secure-sandbox/run_lease.py \
  /usr/local/libexec/secure-sandbox/model_broker.py \
  /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py \
  /usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh \
  /etc/secure-sandbox/run-lease-profiles.json \
  /etc/systemd/system/model-broker.service \
  /etc/secure-sandbox/broker.json; do
  name="$(basename "$destination")"
  if [[ -f "$backup/$name" ]]; then cp --no-dereference "$backup/$name" "$destination"; elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"; fi
done
systemctl daemon-reload
systemctl restart model-broker.service local-telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh gateway >/dev/null; fi
echo "run-leases-gateway:rolled-back:$backup_id"

