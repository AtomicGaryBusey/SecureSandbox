#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
authorization_broker="/usr/local/libexec/secure-sandbox-host/current/authorization_broker"
requesting_agent="${SECURE_SANDBOX_REQUESTING_AGENT:-Codex}"
requesting_session="${SECURE_SANDBOX_REQUESTING_SESSION:-disposable-execution-approval-ddd}"
[[ "$(ssh -F "$ssh_config" sandbox-research-admin 'test -e /run/secure-sandbox/run-id; echo $?')" == 1 ]] || { echo "Refusing deployment during an active run." >&2; exit 1; }

if ! key_json="$($authorization_broker execution-approval-public-key 2>/dev/null)"; then
  "$authorization_broker" request \
    --agent "$requesting_agent" --session "$requesting_session" \
    --purpose "Create the protected disposable-execution approval signing key" \
    --resource "/usr/local/var/lib/secure-sandbox/execution-approval" \
    --operation execution-approval-key-init --parameters-json '{}'
  key_json="$($authorization_broker execution-approval-public-key)"
fi
approval_schema="$(jq -er '.schema' <<<"$key_json")"
if [[ "$approval_schema" == secure-sandbox-execution-approval-key-v1 ]]; then
  jq -e '(.status == "ready") and (.public_key | type == "string")' <<<"$key_json" >/dev/null
elif [[ "$approval_schema" == secure-sandbox-execution-approval-key-v2 ]]; then
  jq -e '(.status == "active") and (.generation_id | type == "string") and (.generation_epoch | type == "number") and (.public_key_spki_der_b64 | type == "string") and (.public_key_sha256 | type == "string") and (.algorithm == "ecdsa-p256-sha256-x962-low-s")' <<<"$key_json" >/dev/null
else
  echo "Invalid execution approval identity." >&2; exit 1
fi
temporary="$(mktemp -d /tmp/secure-sandbox-execution-approval.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
printf '%s\n' "$key_json" > "$temporary/execution-approval-identity.json"

target_result="$(op-agents read 'op://Agents/SecureSandbox-Execution-Broker/password' \
  | "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-target-control \
    deploy install-disposable-execution-target.sh --stdin-file execution-token \
    --file "$root_dir/target/execution_service.py" --file "$root_dir/target/build-python-runtime.sh" \
    --file "$root_dir/target/secure-sandbox-execution.service" --file "$root_dir/scripts/install-disposable-execution-target.sh" \
    --file "$root_dir/shared/__init__.py:shared_init.py" --file "$root_dir/shared/bounded_http.py" \
    --file "$root_dir/scripts/update-policy-hash.sh")"
printf '%s\n' "$target_result"
runtime_image="$(printf '%s\n' "$target_result" | sed -n 's/^disposable-execution-target:installed:\(sha256:[0-9a-f]\{64\}\)$/\1/p' | tail -1)"
[[ "$runtime_image" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Target runtime identity unavailable." >&2; exit 1; }
printf '%s\n' "$runtime_image" > "$temporary/execution-runtime-image"

op-agents read 'op://Agents/SecureSandbox-Execution-Broker/password' \
  | "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
    deploy install-disposable-execution-research.sh --stdin-file execution-token \
    --file "$root_dir/research/execution_broker.py" --file "$root_dir/research/execution_mcp.py" \
    --file "$root_dir/research/execution-broker.service" --file "$root_dir/research/managed-settings.proposed.json" \
    --file "$root_dir/research/managed-mcp.json" --file "$root_dir/research/render_research_firewall.py" \
    --file "$root_dir/research/telemetry_exporter.py" --file "$root_dir/scripts/install-disposable-execution-research.sh" \
    --file "$root_dir/scripts/update-policy-hash.sh" \
    --file "$temporary/execution-approval-identity.json" --file "$temporary/execution-runtime-image"

"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-target-control run policy-hash target >/dev/null
"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control run policy-hash research >/dev/null
echo disposable-execution:deployed
