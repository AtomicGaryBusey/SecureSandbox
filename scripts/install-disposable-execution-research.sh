#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
broker="${1:-/tmp/execution_broker.py}"; mcp="${2:-/tmp/execution_mcp.py}"
unit="${3:-/tmp/execution-broker.service}"; token_file="${4:-/tmp/execution-token}"
settings="${5:-/tmp/managed-settings.proposed.json}"; managed_mcp="${6:-/tmp/managed-mcp.json}"
firewall="${7:-/tmp/render_research_firewall.py}"; telemetry="${8:-/tmp/telemetry_exporter.py}"
approval_identity="${9:-/tmp/execution-approval-identity.json}"; runtime_image_file="${10:-/tmp/execution-runtime-image}"
for path in "$broker" "$mcp" "$unit" "$token_file" "$settings" "$managed_mcp" "$firewall" "$telemetry" "$approval_identity" "$runtime_image_file"; do
  [[ -f "$path" && ! -L "$path" ]] || { echo "Missing artifact: $path" >&2; exit 2; }
done
python3 -m py_compile "$broker" "$mcp" "$firewall" "$telemetry"
python3 -m json.tool "$settings" >/dev/null; python3 -m json.tool "$managed_mcp" >/dev/null
token="$(tr -d '\r\n' < "$token_file")"; [[ "$token" =~ ^[A-Za-z0-9]{64}$ ]] || { echo "Invalid execution token." >&2; exit 2; }
approval_schema="$(jq -er '.schema' "$approval_identity")"
runtime_image="$(tr -d '\r\n' < "$runtime_image_file")"
[[ "$runtime_image" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Invalid execution runtime image." >&2; exit 2; }
approval_floor=/etc/secure-sandbox/execution-approval-floor.json
if [[ -e "$approval_floor" ]]; then
  [[ -f "$approval_floor" && ! -L "$approval_floor" && "$(stat -c '%u:%a' "$approval_floor")" == "0:640" ]] \
    || { echo "Untrusted execution approval floor." >&2; exit 2; }
  jq -e '.schema == "secure-sandbox-execution-approval-floor-v2" and .minimum_protocol == 2 and (.minimum_epoch | type == "number") and (.generation_id | type == "string") and (.algorithm == "ecdsa-p256-sha256-x962-low-s") and (.public_key_sha256 | test("^[0-9a-f]{64}$"))' "$approval_floor" >/dev/null \
    || { echo "Invalid execution approval floor." >&2; exit 2; }
  [[ "$approval_schema" == secure-sandbox-execution-approval-key-v2 ]] \
    || { echo "Execution approval v1 is below the protected floor." >&2; exit 2; }
  jq -e --slurpfile floor "$approval_floor" '(.generation_epoch >= $floor[0].minimum_epoch) and (.generation_id == $floor[0].generation_id) and (.algorithm == $floor[0].algorithm) and (.public_key_sha256 == $floor[0].public_key_sha256)' "$approval_identity" >/dev/null \
    || { echo "Execution approval identity conflicts with the protected floor." >&2; exit 2; }
fi
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh
getent passwd execution-broker >/dev/null || useradd --system --home /nonexistent --shell /usr/sbin/nologin execution-broker
usermod -a -G agent execution-broker
broker_uid="$(id -u execution-broker)"
chown agent:agent /home/agent/research-workspace
chmod 750 /home/agent/research-workspace

backup_id="disposable-execution-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 "$backup"
for current in /etc/claude-code/managed-settings.json /etc/claude-code/managed-mcp.json /etc/nftables.conf /usr/local/libexec/secure-sandbox/telemetry_exporter.py; do
  cp --no-dereference "$current" "$backup/$(basename "$current")"
done

install -d -o root -g root -m 755 /etc/secure-sandbox /usr/local/libexec/secure-sandbox
install -d -o root -g execution-broker -m 750 /var/lib/secure-sandbox/execution-approvals
install -d -o execution-broker -g execution-broker -m 700 \
  /var/lib/secure-sandbox/execution-approvals/pending \
  /var/lib/secure-sandbox/execution-approvals/consumed
install -d -o root -g execution-broker -m 750 \
  /var/lib/secure-sandbox/execution-approvals/claims \
  /var/lib/secure-sandbox/execution-approvals/responses
install -o root -g root -m 755 "$broker" /usr/local/libexec/secure-sandbox/execution_broker.py
install -o root -g root -m 755 "$mcp" /usr/local/libexec/secure-sandbox/execution_mcp.py
install -o root -g root -m 755 "$firewall" /usr/local/libexec/secure-sandbox/render_research_firewall.py
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 644 "$unit" /etc/systemd/system/execution-broker.service
install -o root -g root -m 644 "$settings" /etc/claude-code/managed-settings.json
install -o root -g root -m 644 "$managed_mcp" /etc/claude-code/managed-mcp.json
config_tmp="$(mktemp /tmp/secure-sandbox-execution-broker-config.XXXXXX)"
trap 'rm -f -- "$config_tmp"' EXIT
if [[ "$approval_schema" == secure-sandbox-execution-approval-key-v1 ]]; then
  public_key="$(jq -er '.public_key | select(type == "string")' "$approval_identity")"
  [[ "$public_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]] || { echo "Invalid execution approval public key." >&2; exit 2; }
  jq -n --arg token "$token" --arg image "$runtime_image" \
    '{schema:"secure-sandbox-execution-broker-v2",token:$token,runtime_image_id:$image,allowed_signers:"/etc/secure-sandbox/execution-approval.allowed_signers"}' \
    > "$config_tmp"
  printf 'secure-sandbox-host %s\n' "$public_key" > /etc/secure-sandbox/execution-approval.allowed_signers
  chown root:execution-broker /etc/secure-sandbox/execution-approval.allowed_signers
  chmod 640 /etc/secure-sandbox/execution-approval.allowed_signers
elif [[ "$approval_schema" == secure-sandbox-execution-approval-key-v2 ]]; then
  jq -e '(.status == "active") and (.algorithm == "ecdsa-p256-sha256-x962-low-s") and (.generation_id | test("^[0-9a-f-]{36}$")) and (.generation_epoch | type == "number" and . >= 1) and (.public_key_sha256 | test("^[0-9a-f]{64}$")) and (.public_key_spki_der_b64 | type == "string")' "$approval_identity" >/dev/null
  jq -n --arg token "$token" --arg image "$runtime_image" --slurpfile identity "$approval_identity" \
    '{schema:"secure-sandbox-execution-broker-v3",token:$token,runtime_image_id:$image,approval:{mode:"active-v2",minimum_protocol:2,minimum_epoch:$identity[0].generation_epoch,generation_id:$identity[0].generation_id,generation_epoch:$identity[0].generation_epoch,algorithm:$identity[0].algorithm,public_key_spki_der_b64:$identity[0].public_key_spki_der_b64,public_key_sha256:$identity[0].public_key_sha256}}' \
    > "$config_tmp"
  rm -f /etc/secure-sandbox/execution-approval.allowed_signers
else
  echo "Invalid execution approval identity." >&2; exit 2
fi
install -o root -g execution-broker -m 640 "$config_tmp" /etc/secure-sandbox/execution-broker.json
rm -f "$token_file" "$approval_identity" "$runtime_image_file"
printf '%s\n' "-a always,exit -F arch=b64 -S connect,sendto,sendmsg,sendmmsg -F uid=$broker_uid -k execution-network" \
  > /etc/audit/rules.d/51-secure-sandbox-execution.rules
chmod 600 /etc/audit/rules.d/51-secure-sandbox-execution.rules
/usr/local/libexec/secure-sandbox/render_research_firewall.py --output /etc/nftables.conf
nft -c -f /etc/nftables.conf; nft -f /etc/nftables.conf
augenrules --load >/dev/null
systemctl daemon-reload
systemctl enable execution-broker.service
systemctl restart execution-broker.service
systemctl restart telemetry-exporter.service
systemctl is-active --quiet execution-broker.service telemetry-exporter.service
echo "disposable-execution-research:installed:$backup_id"
