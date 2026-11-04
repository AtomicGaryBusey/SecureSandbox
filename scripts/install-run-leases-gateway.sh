#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Gateway." >&2; exit 1; }
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh
manager="${1:-/tmp/run_lease.py}"
broker="${2:-/tmp/model_broker.py}"
telemetry="${3:-/tmp/local_telemetry_exporter.py}"
profiles="${4:-/tmp/run-lease-profiles.json}"
rollback="${5:-/tmp/rollback-run-leases-gateway.sh}"
unit="${6:-/tmp/model-broker.service}"
install_recovery="${7:-/tmp/run-leases-install-recovery.sh}"
install_recovery_unit="${8:-/tmp/run-leases-install-recovery.service}"
shared_init=/tmp/shared_init.py
bounded_http=/tmp/bounded_http.py
harness_runtime_binding=/tmp/harness_runtime_binding.py
native_vendor_stack=/tmp/native_vendor_stack.py
native_stack_runtime_binding=/tmp/native_stack_runtime_binding.py
model_stack_runtime_binding=/tmp/model_stack_runtime_binding.py
session_context_binding=/tmp/session_context_binding.py
runtime_authority=/tmp/runtime_authority.py
telemetry_receiver=/tmp/telemetry_receiver.py
conversation_receiver=/tmp/conversation_receiver.py
fingerprints=/tmp/update_client_fingerprints.py
adapter=/tmp/model_adapters.py
profile_status=/tmp/model_profile_status.py
profile_activator=/tmp/model_profile_activate.py
for source in "$manager" "$broker" "$telemetry" "$profiles" "$rollback" "$unit" "$install_recovery" "$install_recovery_unit" "$shared_init" "$bounded_http" "$harness_runtime_binding" "$native_vendor_stack" "$native_stack_runtime_binding" "$model_stack_runtime_binding" "$session_context_binding" "$runtime_authority" "$telemetry_receiver" "$conversation_receiver" "$fingerprints" "$adapter" "$profile_status" "$profile_activator"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact: $source" >&2; exit 2; }
done
if [[ -e /var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending ]]; then
  /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh
fi
python3 -m py_compile "$manager" "$broker" "$adapter" "$profile_status" "$profile_activator" "$telemetry" "$bounded_http" "$harness_runtime_binding" "$native_vendor_stack" "$native_stack_runtime_binding" "$model_stack_runtime_binding" "$session_context_binding" "$runtime_authority" "$telemetry_receiver" "$conversation_receiver" "$fingerprints"
python3 -m json.tool "$profiles" >/dev/null
bash -n "$rollback" "$install_recovery"
for directory in /var/lib/secure-sandbox/run-leases/leases /var/lib/secure-sandbox/run-leases/counters; do
  if [[ -d "$directory" ]] && find "$directory" -maxdepth 1 -type f -name '*.json' -print -quit | grep -q .; then
    echo "Active Gateway lease state blocks schema deployment." >&2
    exit 1
  fi
done

backup_id="${9:-run-leases-gateway-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
[[ "$backup_id" =~ ^run-leases-gateway-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid Gateway backup identity." >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ ! -e "$backup" && ! -L "$backup" ]] || { echo "Gateway backup identity already exists." >&2; exit 1; }
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
for current in \
  /usr/local/libexec/secure-sandbox/run_lease.py \
  /usr/local/libexec/secure-sandbox/model_broker.py \
  /usr/local/libexec/secure-sandbox/model_adapters.py \
  /usr/local/libexec/secure-sandbox/model_profile_status.py \
  /usr/local/libexec/secure-sandbox/model_profile_activate.py \
  /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py \
  /usr/local/libexec/secure-sandbox/telemetry_receiver.py \
  /usr/local/libexec/secure-sandbox/conversation_receiver.py \
  /usr/local/libexec/secure-sandbox/update_client_fingerprints.py \
  /usr/local/libexec/secure-sandbox/shared/__init__.py \
  /usr/local/libexec/secure-sandbox/shared/bounded_http.py \
  /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py \
  /usr/local/libexec/secure-sandbox/shared/native_vendor_stack.py \
  /usr/local/libexec/secure-sandbox/shared/native_stack_runtime_binding.py \
  /usr/local/libexec/secure-sandbox/shared/model_stack_runtime_binding.py \
  /usr/local/libexec/secure-sandbox/shared/session_context_binding.py \
  /usr/local/libexec/secure-sandbox/shared/runtime_authority.py \
  /usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh \
  /etc/secure-sandbox/run-lease-profiles.json \
  /etc/systemd/system/model-broker.service \
  /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh \
  /etc/systemd/system/run-leases-install-recovery.service \
  /etc/secure-sandbox/broker.json; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash "$rollback" "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR
install -o root -g root -m 755 "$install_recovery" /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh
install -o root -g root -m 644 "$install_recovery_unit" /etc/systemd/system/run-leases-install-recovery.service
systemctl daemon-reload
systemctl enable run-leases-install-recovery.service >/dev/null
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending
chown root:root /var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending
chmod 600 /var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending
sync -d /var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox/shared
install -d -o root -g model-broker -m 750 /var/lib/secure-sandbox/run-leases
install -d -o root -g model-broker -m 2750 /var/lib/secure-sandbox/run-leases/leases
install -d -o model-broker -g model-broker -m 700 /var/lib/secure-sandbox/run-leases/counters
install -d -o root -g model-broker -m 750 /var/lib/secure-sandbox/run-leases/summaries
install -o root -g root -m 755 "$manager" /usr/local/libexec/secure-sandbox/run_lease.py
install -o root -g root -m 755 "$broker" /usr/local/libexec/secure-sandbox/model_broker.py
install -o root -g root -m 755 "$adapter" /usr/local/libexec/secure-sandbox/model_adapters.py
install -o root -g root -m 755 "$profile_status" /usr/local/libexec/secure-sandbox/model_profile_status.py
install -o root -g root -m 755 "$profile_activator" /usr/local/libexec/secure-sandbox/model_profile_activate.py
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py
install -o root -g root -m 755 "$telemetry_receiver" /usr/local/libexec/secure-sandbox/telemetry_receiver.py
install -o root -g root -m 755 "$conversation_receiver" /usr/local/libexec/secure-sandbox/conversation_receiver.py
install -o root -g root -m 755 "$fingerprints" /usr/local/libexec/secure-sandbox/update_client_fingerprints.py
install -o root -g root -m 644 "$shared_init" /usr/local/libexec/secure-sandbox/shared/__init__.py
install -o root -g root -m 755 "$bounded_http" /usr/local/libexec/secure-sandbox/shared/bounded_http.py
install -o root -g root -m 755 "$harness_runtime_binding" /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py
install -o root -g root -m 755 "$native_vendor_stack" /usr/local/libexec/secure-sandbox/shared/native_vendor_stack.py
install -o root -g root -m 755 "$native_stack_runtime_binding" /usr/local/libexec/secure-sandbox/shared/native_stack_runtime_binding.py
install -o root -g root -m 755 "$model_stack_runtime_binding" /usr/local/libexec/secure-sandbox/shared/model_stack_runtime_binding.py
install -o root -g root -m 755 "$session_context_binding" /usr/local/libexec/secure-sandbox/shared/session_context_binding.py
install -o root -g root -m 755 "$runtime_authority" /usr/local/libexec/secure-sandbox/shared/runtime_authority.py
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh
install -o root -g root -m 644 "$profiles" /etc/secure-sandbox/run-lease-profiles.json
install -o root -g root -m 644 "$unit" /etc/systemd/system/model-broker.service
python3 - /etc/secure-sandbox/broker.json <<'PY'
import json, os, sys
path=sys.argv[1]
with open(path, encoding="utf-8") as handle: value=json.load(handle)
value["lease_state_directory"]="/var/lib/secure-sandbox/run-leases"
value.setdefault("adapter", "anthropic-messages-v1")
value.setdefault("credential_scheme", "bearer")
value.setdefault("deployment", {})
value.setdefault("oauth_ipv4", [])
value.setdefault("profile_id", "abliterated-glm")
value.setdefault("profile_sha256", "f1470ba4d7c3c17e2ac15ed249cf59019f33ed085f65d07f984fd4c700520502")
value.setdefault("settings", {"anthropic_version":"2023-06-01",
                              "maximum_output_tokens":32768,
                              "temperature_milli":None})
value.setdefault("vendor_id", "abliteration")
temporary=path+".new"
with open(temporary,"w",encoding="utf-8") as handle:
    json.dump(value,handle,separators=(",",":"),sort_keys=True); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.chown(temporary,0,__import__("grp").getgrnam("model-broker").gr_gid); os.chmod(temporary,0o640); os.replace(temporary,path)
PY
touch /var/lib/secure-sandbox/run-leases/counters/.lock
chown model-broker:model-broker /var/lib/secure-sandbox/run-leases/counters/.lock
chmod 600 /var/lib/secure-sandbox/run-leases/counters/.lock
python3 /usr/local/libexec/secure-sandbox/model_broker.py --config /etc/secure-sandbox/broker.json --validate
systemd-analyze verify /etc/systemd/system/model-broker.service /etc/systemd/system/run-leases-install-recovery.service >/dev/null
python3 -m py_compile /usr/local/libexec/secure-sandbox/run_lease.py /usr/local/libexec/secure-sandbox/model_broker.py /usr/local/libexec/secure-sandbox/model_adapters.py /usr/local/libexec/secure-sandbox/model_profile_status.py /usr/local/libexec/secure-sandbox/model_profile_activate.py /usr/local/libexec/secure-sandbox/telemetry_receiver.py /usr/local/libexec/secure-sandbox/conversation_receiver.py /usr/local/libexec/secure-sandbox/update_client_fingerprints.py /usr/local/libexec/secure-sandbox/shared/bounded_http.py /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py /usr/local/libexec/secure-sandbox/shared/native_vendor_stack.py /usr/local/libexec/secure-sandbox/shared/native_stack_runtime_binding.py /usr/local/libexec/secure-sandbox/shared/model_stack_runtime_binding.py /usr/local/libexec/secure-sandbox/shared/session_context_binding.py /usr/local/libexec/secure-sandbox/shared/runtime_authority.py
/usr/local/libexec/secure-sandbox/run_lease.py recover >/dev/null
systemctl daemon-reload
systemctl restart model-broker.service telemetry-receiver.service conversation-receiver.service local-telemetry-exporter.service
systemctl is-active --quiet model-broker.service telemetry-receiver.service conversation-receiver.service local-telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh gateway >/dev/null; fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/run-leases-gateway-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/run-leases-gateway-latest
trap - ERR
rm -f /var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending
sync -d /var/lib/secure-sandbox/policy-backups
echo "run-leases-gateway:installed:$backup_id"

