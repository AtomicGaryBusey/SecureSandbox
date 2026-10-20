#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Gateway." >&2; exit 1; }
manager="${1:-/tmp/run_lease.py}"
broker="${2:-/tmp/model_broker.py}"
telemetry="${3:-/tmp/local_telemetry_exporter.py}"
profiles="${4:-/tmp/run-lease-profiles.json}"
rollback="${5:-/tmp/rollback-run-leases-gateway.sh}"
unit="${6:-/tmp/model-broker.service}"
for source in "$manager" "$broker" "$telemetry" "$profiles" "$rollback" "$unit"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact: $source" >&2; exit 2; }
done
python3 -m py_compile "$manager" "$broker" "$telemetry"
python3 -m json.tool "$profiles" >/dev/null
bash -n "$rollback"

backup_id="run-leases-gateway-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
for current in \
  /usr/local/libexec/secure-sandbox/run_lease.py \
  /usr/local/libexec/secure-sandbox/model_broker.py \
  /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py \
  /usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh \
  /etc/secure-sandbox/run-lease-profiles.json \
  /etc/systemd/system/model-broker.service \
  /etc/secure-sandbox/broker.json; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"

rollback_on_error() { trap - ERR; bash "$rollback" "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g model-broker -m 750 /var/lib/secure-sandbox/run-leases
install -d -o root -g model-broker -m 2750 /var/lib/secure-sandbox/run-leases/leases
install -d -o model-broker -g model-broker -m 700 /var/lib/secure-sandbox/run-leases/counters
install -d -o root -g model-broker -m 750 /var/lib/secure-sandbox/run-leases/summaries
install -o root -g root -m 755 "$manager" /usr/local/libexec/secure-sandbox/run_lease.py
install -o root -g root -m 755 "$broker" /usr/local/libexec/secure-sandbox/model_broker.py
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh
install -o root -g root -m 644 "$profiles" /etc/secure-sandbox/run-lease-profiles.json
install -o root -g root -m 644 "$unit" /etc/systemd/system/model-broker.service
python3 - /etc/secure-sandbox/broker.json <<'PY'
import json, os, sys
path=sys.argv[1]
with open(path, encoding="utf-8") as handle: value=json.load(handle)
value["lease_state_directory"]="/var/lib/secure-sandbox/run-leases"
temporary=path+".new"
with open(temporary,"w",encoding="utf-8") as handle:
    json.dump(value,handle,separators=(",",":"),sort_keys=True); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.chown(temporary,0,__import__("grp").getgrnam("model-broker").gr_gid); os.chmod(temporary,0o640); os.replace(temporary,path)
PY
touch /var/lib/secure-sandbox/run-leases/counters/.lock
chown model-broker:model-broker /var/lib/secure-sandbox/run-leases/counters/.lock
chmod 600 /var/lib/secure-sandbox/run-leases/counters/.lock
python3 /usr/local/libexec/secure-sandbox/model_broker.py --config /etc/secure-sandbox/broker.json --validate
systemd-analyze verify /etc/systemd/system/model-broker.service >/dev/null
python3 -m py_compile /usr/local/libexec/secure-sandbox/run_lease.py /usr/local/libexec/secure-sandbox/model_broker.py
/usr/local/libexec/secure-sandbox/run_lease.py recover >/dev/null
systemctl daemon-reload
systemctl restart model-broker.service local-telemetry-exporter.service
systemctl is-active --quiet model-broker.service local-telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh gateway >/dev/null; fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/run-leases-gateway-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/run-leases-gateway-latest
trap - ERR
echo "run-leases-gateway:installed:$backup_id"

