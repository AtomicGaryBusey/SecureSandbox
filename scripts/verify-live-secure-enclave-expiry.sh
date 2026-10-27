#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
state_dir="$root_dir/.private/secure-enclave-execution-approval-ddd"
state="$state_dir/state.json"
jq -e '.stage == "complete" and .software_retirement.status == "software_retired"' "$state" >/dev/null
temporary="$(mktemp -d /tmp/secure-sandbox-live-expiry.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
created_at="$(date +%s)"; expires_at="$((created_at + 90))"
approval="$(jq -ncS --arg approval_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  --arg run_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  --arg session_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  --arg source_id "$(jq -er .acceptance.source_id "$state")" \
  --arg runtime_image_id "$(jq -er .acceptance_record.runtime_image_id "$state")" \
  --argjson created_at "$created_at" --argjson expires_at "$expires_at" \
  '{schema:"secure-sandbox-execution-approval-request-v1",approval_id:$approval_id,
    created_at:$created_at,expires_at:$expires_at,run_id:$run_id,session_id:$session_id,
    source_id:$source_id,source_manifest_sha256:("5"*64),code_sha256:("6"*64),
    fixture_manifest:[],fixture_manifest_sha256:"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    timeout_seconds:5,runtime_image_id:$runtime_image_id}')"
echo "LIVE EXPIRY 1/3  Approve promptly; this signature will be held until it expires"
envelope="$(python3 scripts/operator-authorization.py request \
  --agent Codex --session secure-enclave-execution-approval-ddd-expiry \
  --purpose "Approve one short-lived signature for the live expiry/no-consumption gate" \
  --resource "Disposable execution in SecureSandbox-Target" \
  --operation execution-approval-sign --parameters-json "$approval")"
jq -e --argjson approval "$approval" '
  .schema == "secure-sandbox-execution-approval-envelope-v2"
  and .attestation.approval == $approval
' <<<"$envelope" >/dev/null || { echo live_expiry_envelope_invalid >&2; exit 1; }
printf '%s\n' "$approval" > "$temporary/expired-approval.json"
printf '%s\n' "$envelope" > "$temporary/expired-envelope.json"
echo "LIVE EXPIRY 2/3  Wait about 90 seconds for the exact signed request to expire"
while [[ "$(date +%s)" -le "$expires_at" ]]; do sleep 1; done
echo "LIVE EXPIRY 3/3  Prove deployed Research rejects it without consumption or Target entry"
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
set +e
result="$("$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-audit-expired-execution-approval.sh /tmp/audit_expired_execution_approval.py \
  /tmp/expired-approval.json /tmp/expired-envelope.json \
  --file scripts/audit-expired-execution-approval.sh:install-audit-expired-execution-approval.sh \
  --file scripts/audit_expired_execution_approval.py \
  --file "$temporary/expired-approval.json" --file "$temporary/expired-envelope.json")"
control_status=$?
set -e
if [[ "$control_status" -ne 0 ]]; then
  printf '%s\n' "$result" >&2
  exit "$control_status"
fi
jq -e --arg generation_id "$(jq -er .prepared.generation_id "$state")" \
  --argjson generation_epoch "$(jq -er .prepared.generation_epoch "$state")" \
  --arg public_key_sha256 "$(jq -er .prepared.public_key_sha256 "$state")" '
  .schema == "secure-sandbox-live-expiry-evidence-v1" and .status == "verified"
  and .generation_id == $generation_id and .generation_epoch == $generation_epoch
  and .public_key_sha256 == $public_key_sha256 and .rejection == "approval_expired"
  and .signature_algorithm == "ecdsa-p256-sha256-x962-low-s"
  and (.observed_at > .expires_at)
  and .approval_id == .approval.approval_id
  and .verified_attestation_generation_id == $generation_id
  and .verified_attestation_generation_epoch == $generation_epoch
  and .consumed_marker_absent == true
  and .rejection_precedes_target_dispatch == true
' <<<"$result" >/dev/null || { echo live_expiry_evidence_invalid >&2; exit 1; }
evidence="$state_dir/live-expiry-evidence.json"
staged="$(mktemp "$state_dir/.live-expiry.XXXXXX")"
jq -cS . <<<"$result" > "$staged"; chmod 600 "$staged"
/usr/bin/python3 -c 'import os,sys; s,t=sys.argv[1:]; f=os.open(s,os.O_RDONLY); os.fsync(f); os.close(f); os.replace(s,t); d=os.open(os.path.dirname(t),os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)' "$staged" "$evidence"
python3 scripts/verify-secure-enclave-execution-approval-ddd.py \
  --repo "$root_dir" --state-dir "$state_dir" \
  --history-root "$root_dir/.private/secure-enclave-execution-approval-ddd-history" \
  --install-root /usr/local/libexec/secure-sandbox-host \
  --require-live-expiry --require-live-peer-isolation \
  --require-live-keychain-isolation
echo secure-enclave-execution-approval-ddd:live-expiry-verified
