#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
bridge_to_rotation=false
while (($#)); do
  case "$1" in
    --bridge-to-rotation) bridge_to_rotation=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
state_dir="$root_dir/.private/secure-enclave-execution-approval-ddd"
state="$state_dir/state.json"
legacy_ui_bundle="$(python3 scripts/secure_enclave_ddd_support.py local-config-field \
  --path "$root_dir/.private/secure-enclave-ddd.json" \
  --field legacy_launchservices_ui_bundle_sha256)"
[[ -f "$state" && ! -L "$state" && "$(stat -f '%Su:%Sp' "$state")" == "$(id -un):-rw-------" ]] \
  || { echo secure_enclave_ddd_checkpoint_untrusted >&2; exit 1; }
jq -e '.schema == "secure-sandbox-secure-enclave-ddd-checkpoint-v1" and .stage == "research_acceptance_verified"' "$state" >/dev/null
durable_replace() {
  /usr/bin/python3 -c 'import os,sys; source,target=sys.argv[1:]; fd=os.open(source,os.O_RDONLY); os.fsync(fd); os.close(fd); os.replace(source,target); directory=os.open(os.path.dirname(target),os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)' "$1" "$2"
}
temporary="$(mktemp -d /tmp/secure-sandbox-se-finalize.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
requesting_agent="$(jq -er .requesting_agent "$state")"
requesting_session="$(jq -er .requesting_session "$state")"
transaction_id="$(jq -er .prepared.transaction_id "$state")"
if [[ "$bridge_to_rotation" == true ]] \
    && jq -e '
      .cold_boot_evidence != null
      and .host_acceptance_verifier != null
      and .negative_gates != null
      and .committed_record != null
    ' "$state" >/dev/null; then
  exec "$root_dir/scripts/commit-secure-enclave-bridge-successor.sh"
fi
source_execution_broker_sha256="$(shasum -a 256 research/execution_broker.py | awk '{print $1}')"
source_transition_sha256="$(shasum -a 256 research/execution_approval_transition.py | awk '{print $1}')"
source_watchdog_sha256="$(shasum -a 256 research/run_lease_watchdog.py | awk '{print $1}')"
source_receipts_sha256="$(shasum -a 256 research/evidence_receipts.py | awk '{print $1}')"
source_corpus_broker_sha256="$(shasum -a 256 research/corpus_broker.py | awk '{print $1}')"
source_corpus_unit_sha256="$(shasum -a 256 research/corpus-broker.service | awk '{print $1}')"
source_corpus_mcp_sha256="$(shasum -a 256 research/corpus_intelligence_mcp.py | awk '{print $1}')"
source_execution_unit_sha256="$(shasum -a 256 research/execution-broker.service | awk '{print $1}')"
request_broker() {
  # Launch the exact protected signed app through LaunchServices. The pinned
  # predecessor is accepted only for schema-checked successful responses;
  # cancellation is never inferred from absent output.
  python3 "$root_dir/scripts/operator-authorization.py" request "$@"
}
verify_checkpoint_research_boundary() {
  "$control_client" client --timeout-seconds 75 --ssh-config "$ssh_config" \
    sandbox-research-control deploy install-boundary-audit.sh \
    "$(jq -er .prepared.research_release_id "$state")" \
    "$source_execution_broker_sha256" "$source_transition_sha256" \
    "$source_watchdog_sha256" "$source_receipts_sha256" \
    "$source_corpus_broker_sha256" "$source_corpus_unit_sha256" \
    "$source_corpus_mcp_sha256" "$source_execution_unit_sha256" \
    --file "$root_dir/scripts/verify-checkpoint-research-boundary.sh:install-boundary-audit.sh"
}

if jq -e '.host_acceptance_verifier != null' "$state" >/dev/null; then
  echo "FINALIZE 1/7  Reuse the durable Host-correlation checkpoint"
  verifier="$(jq -cS .host_acceptance_verifier "$state")"
  verifier_sha256="$(python3 scripts/validate_secure_enclave_finalization.py verifier \
    --state "$state" --current-boot "$(sysctl -n kern.boottime)")"
else
  echo "FINALIZE 1/7  Correlate the real Target execution across Research and Host receipts"
  research_evidence="$(jq -cS .research_evidence "$state")"
  verifier="$(request_broker --agent "$requesting_agent" --session "$requesting_session" \
    --purpose "Correlate the exact Secure Enclave acceptance execution and content-free receipts" \
    --resource /usr/local/var/lib/secure-sandbox/execution-approval \
    --operation execution-approval-migration-verify-acceptance \
    --parameters-json "$(jq -ncS --argjson research_evidence "$research_evidence" '{research_evidence:$research_evidence}')")"
  verifier_sha256="$(jq -er .verifier_sha256 <<<"$verifier")"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson verifier "$verifier" '.host_acceptance_verifier=$verifier' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
fi

echo "FINALIZE 2/7  Approve one fresh post-reboot signature for live negative verification"
  created_at="$(date +%s)"
  approval="$(jq -ncS --arg approval_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg run_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg session_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg source_id "$(jq -er .acceptance.source_id "$state")" \
    --argjson created_at "$created_at" --argjson expires_at "$((created_at + 90))" \
    --arg runtime_image_id "$(jq -er .acceptance_record.runtime_image_id "$state")" \
    '{schema:"secure-sandbox-execution-approval-request-v1",approval_id:$approval_id,created_at:$created_at,expires_at:$expires_at,run_id:$run_id,session_id:$session_id,source_id:$source_id,source_manifest_sha256:("1"*64),code_sha256:("2"*64),fixture_manifest:[],fixture_manifest_sha256:"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",timeout_seconds:5,runtime_image_id:$runtime_image_id}')"
  envelope="$(request_broker --agent "$requesting_agent" --session "$requesting_session" \
    --purpose "Approve one post-reboot signature for replay and wrong-key rejection tests" \
    --resource "Disposable execution in SecureSandbox-Target" \
    --operation execution-approval-sign --parameters-json "$approval")"
  printf '%s\n' "$approval" > "$temporary/approval.json"
  printf '%s\n' "$envelope" > "$temporary/envelope.json"

  echo "FINALIZE 3/7  Prove wrong-key and replay rejection in the deployed Research verifier"
  "$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
    deploy install-execution-approval-transition.sh verify-negative \
    /tmp/execution_approval_transition.py /tmp/approval.json /tmp/envelope.json \
    --file "$root_dir/scripts/install-execution-approval-transition.sh" \
    --file "$root_dir/research/execution_approval_transition.py" \
    --file "$temporary/approval.json" --file "$temporary/envelope.json" \
    > "$temporary/negative-gates.json"
python3 scripts/validate_secure_enclave_finalization.py negative \
  --evidence "$temporary/negative-gates.json" \
  --approval-id "$(jq -er .approval_id <<<"$approval")"

if [[ "$bridge_to_rotation" == true ]]; then
  echo "FINALIZE 4/7  Defer cancellation to the fixed forward-rotation generation"
  bridge_exception="$(jq -ncS \
    --arg predecessor_ui_bundle "$legacy_ui_bundle" \
    --argjson recorded_at "$(date +%s)" \
    '{schema:"secure-sandbox-execution-approval-bridge-exception-v1",reason:"predecessor_ui_has_no_authenticated_result_sidecar",predecessor_ui_bundle_sha256:$predecessor_ui_bundle,cancellation_gate:"mandatory_on_immediate_forward_rotation",software_key_retirement:"deferred",recorded_at:$recorded_at}')"
else
  echo "FINALIZE 4/7  Prove every second signature needs fresh biometrics (CANCEL this window)"
  second_created_at="$(date +%s)"
  second_approval="$(jq -ncS --arg approval_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg run_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg session_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg source_id "$(jq -er .acceptance.source_id "$state")" \
    --argjson created_at "$second_created_at" --argjson expires_at "$((second_created_at + 90))" \
    --arg runtime_image_id "$(jq -er .acceptance_record.runtime_image_id "$state")" \
    '{schema:"secure-sandbox-execution-approval-request-v1",approval_id:$approval_id,created_at:$created_at,expires_at:$expires_at,run_id:$run_id,session_id:$session_id,source_id:$source_id,source_manifest_sha256:("3"*64),code_sha256:("4"*64),fixture_manifest:[],fixture_manifest_sha256:"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",timeout_seconds:5,runtime_image_id:$runtime_image_id}')"
  set +e
  request_broker --agent "$requesting_agent" --session "$requesting_session" \
    --purpose "CANCEL THIS WINDOW: prove a second signature cannot reuse biometric authorization" \
    --resource "Disposable execution in SecureSandbox-Target" \
    --operation execution-approval-sign --parameters-json "$second_approval" \
    > "$temporary/second-sign.stdout" 2> "$temporary/second-sign.stderr"
  second_status=$?
  set -e
  if [[ "$second_status" -eq 0 ]]; then
    echo second_signature_was_approved_expected_operator_cancellation >&2
    exit 1
  fi
  [[ ! -s "$temporary/second-sign.stdout" ]] \
    || { echo second_sign_unexpected_stdout >&2; exit 1; }
  python3 scripts/validate_secure_enclave_finalization.py cancellation \
    --stderr "$temporary/second-sign.stderr"
  cancellation_evidence="$(jq -ncS --argjson request "$second_approval" \
    --arg request_sha256 "$(printf '%s\n' "$second_approval" | shasum -a 256 | awk '{print $1}')" \
    --arg stderr_sha256 "$(shasum -a 256 "$temporary/second-sign.stderr" | awk '{print $1}')" \
    --arg generation_id "$(jq -er .prepared.generation_id "$state")" \
    --argjson generation_epoch "$(jq -er .prepared.generation_epoch "$state")" \
    --arg public_key_sha256 "$(jq -er .prepared.public_key_sha256 "$state")" \
    --argjson observed_at "$(date +%s)" \
    '{schema:"secure-sandbox-execution-approval-cancellation-evidence-v1",status:"cancelled",approval_id:$request.approval_id,run_id:$request.run_id,session_id:$request.session_id,request_sha256:$request_sha256,generation_id:$generation_id,generation_epoch:$generation_epoch,public_key_sha256:$public_key_sha256,stderr_sha256:$stderr_sha256,stdout_empty:true,observed_at:$observed_at}')"
fi

echo "FINALIZE 5/7  Commit the rebooted, correlated, negatively-tested Host authority"
set +e
scripts/verify-boundaries.sh > "$temporary/post-reboot-boundary.log"
boundary_status=$?
set -e
checkpoint_host_verification=null
checkpoint_research_verification=null
bridge_successor_deployment=null
bridge_successor_release_id=null
bridge_successor_deployment_sha256=null
bridge_exception=null
if [[ "$bridge_to_rotation" == true ]]; then
  expected_bridge_failures=$'FAIL  Host Claude controller is an immutable release matching approved source\nFAIL  Evidence receipts are producer-minted and hidden from the agent'
  if [[ "$boundary_status" -eq 0 \
      || "$(grep -c '^FAIL  ' "$temporary/post-reboot-boundary.log")" -ne 2 \
      || "$(grep '^FAIL  ' "$temporary/post-reboot-boundary.log")" \
         != "$expected_bridge_failures" \
      || "$(tail -n 1 "$temporary/post-reboot-boundary.log")" \
         != 'BOUNDARY VERIFICATION FAILED: 2 check(s)' ]]; then
    cat "$temporary/post-reboot-boundary.log" >&2
    echo unexpected_finalize_boundary_failure >&2
    exit 1
  fi
  jq -e --arg transaction_id "$(jq -er .transaction_id <<<"$verifier")" \
    --arg generation_id "$(jq -er .generation_id <<<"$verifier")" \
    --argjson generation_epoch "$(jq -er .generation_epoch <<<"$verifier")" \
    --arg host_release_id "$(jq -er .host_release_id <<<"$verifier")" \
    --arg research_release_id "$(jq -er .research_release_id <<<"$verifier")" '
    .prepared.transaction_id == $transaction_id
    and .prepared.generation_id == $generation_id
    and .prepared.generation_epoch == $generation_epoch
    and .prepared.host_release_id == $host_release_id
    and .prepared.research_release_id == $research_release_id
  ' "$state" >/dev/null || { echo bridge_checkpoint_verifier_identity_mismatch >&2; exit 1; }
  python3 scripts/secure_enclave_ddd_support.py verify-checkpoint-host-release \
    --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
    --launcher /usr/local/bin/secure-sandbox-claude \
    --expected-release-id "$(jq -er .host_release_id <<<"$verifier")" \
    --expected-generation-id "$(jq -er .generation_id <<<"$verifier")" \
    --expected-generation-epoch "$(jq -er .generation_epoch <<<"$verifier")" \
    --expected-public-key-sha256 "$(jq -er .prepared.public_key_sha256 "$state")" \
    --expected-ui-bundle-sha256 "$legacy_ui_bundle" \
    | jq -cS . > "$temporary/checkpoint-host-verification.json"
  checkpoint_host_verification="$(jq -cS . "$temporary/checkpoint-host-verification.json")"
  verify_checkpoint_research_boundary \
    | jq -cS . > "$temporary/checkpoint-research-verification.json"
  jq -e --arg research_release_id "$(jq -er .research_release_id <<<"$verifier")" '
    .schema == "secure-sandbox-checkpoint-research-boundary-verification-v1"
    and .status == "verified"
    and .release_id == $research_release_id
    and .receipt_boundary_verified == true
  ' "$temporary/checkpoint-research-verification.json" >/dev/null \
    || { echo bridge_checkpoint_research_verification_invalid >&2; exit 1; }
  checkpoint_research_verification="$(jq -cS . "$temporary/checkpoint-research-verification.json")"
  printf '%s\n' 'PASS  Live Host is the exact immutable checkpoint predecessor; source advancement is mandatory on immediate forward rotation' \
    >> "$temporary/post-reboot-boundary.log"
  printf '%s\n' 'PASS  Live Research is the exact checkpoint release and its receipt boundary remains intact; broker source advancement is mandatory on immediate forward rotation' \
    >> "$temporary/post-reboot-boundary.log"
elif [[ "$boundary_status" -ne 0 ]]; then
  cat "$temporary/post-reboot-boundary.log" >&2
  echo unexpected_finalize_boundary_failure >&2
  exit 1
fi
boundary_sha256="$(shasum -a 256 "$temporary/post-reboot-boundary.log" | awk '{print $1}')"
checkpoint_host_verification_sha256=null
checkpoint_research_verification_sha256=null
if [[ -f "$temporary/checkpoint-host-verification.json" ]]; then
  checkpoint_host_verification_sha256="$(shasum -a 256 "$temporary/checkpoint-host-verification.json" | awk '{print $1}')"
fi
if [[ -f "$temporary/checkpoint-research-verification.json" ]]; then
  checkpoint_research_verification_sha256="$(shasum -a 256 "$temporary/checkpoint-research-verification.json" | awk '{print $1}')"
fi
cold_boot_evidence="$(jq -ncS --arg prior_boot "$(jq -er .host_boot "$state")" \
  --arg rebooted_boot "$(jq -er .rebooted_boot "$state")" --arg boundary_sha256 "$boundary_sha256" \
  --argjson bridge "$bridge_to_rotation" \
  --argjson checkpoint_host_verification "$checkpoint_host_verification" \
  --arg checkpoint_host_verification_sha256 "$checkpoint_host_verification_sha256" \
  --argjson checkpoint_research_verification "$checkpoint_research_verification" \
  --arg checkpoint_research_verification_sha256 "$checkpoint_research_verification_sha256" \
  --argjson bridge_successor_deployment "$bridge_successor_deployment" \
  --arg bridge_successor_release_id "$bridge_successor_release_id" \
  --arg bridge_successor_deployment_sha256 "$bridge_successor_deployment_sha256" \
  '{schema:"secure-sandbox-host-reboot-acceptance-v1",prior_boot:$prior_boot,rebooted_boot:$rebooted_boot,boundary_sha256:$boundary_sha256,bridge_predecessor_exception:$bridge,checkpoint_host_verification:$checkpoint_host_verification,checkpoint_host_verification_sha256:(if $checkpoint_host_verification_sha256 == "null" then null else $checkpoint_host_verification_sha256 end),checkpoint_research_verification:$checkpoint_research_verification,checkpoint_research_verification_sha256:(if $checkpoint_research_verification_sha256 == "null" then null else $checkpoint_research_verification_sha256 end),bridge_successor_deployment:$bridge_successor_deployment,bridge_successor_release_id:(if $bridge_successor_release_id == "null" then null else $bridge_successor_release_id end),bridge_successor_deployment_sha256:(if $bridge_successor_deployment_sha256 == "null" then null else $bridge_successor_deployment_sha256 end)}')"
cold_boot_sha256="$(printf '%s' "$cold_boot_evidence" | shasum -a 256 | awk '{print $1}')"
if jq -e '.committed_record != null' "$state" >/dev/null; then
  committed_record="$(jq -cS .committed_record "$state")"
else
  committed_record="$(jq -ncS --argjson prepared "$(jq -cS .prepared "$state")" \
    --arg host_release_id "$(jq -er .prepared.host_release_id "$state")" \
    --arg research_release_id "$(jq -er .prepared.research_release_id "$state")" \
    --argjson recorded_at "$(date +%s)" \
    '{schema:"secure-sandbox-execution-approval-transition-v2",phase:"committed",transaction_id:$prepared.transaction_id,generation_id:$prepared.generation_id,generation_epoch:$prepared.generation_epoch,previous_generation_id:$prepared.previous_generation_id,previous_generation_epoch:$prepared.previous_generation_epoch,operator_uid:$prepared.operator_uid,algorithm:$prepared.algorithm,public_key_spki_der_b64:$prepared.public_key_spki_der_b64,public_key_sha256:$prepared.public_key_sha256,host_release_id:$host_release_id,research_release_id:$research_release_id,expected_prior_phase:"acceptance",recorded_at:$recorded_at}')"
fi
state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
jq -S --argjson evidence "$cold_boot_evidence" --arg evidence_sha256 "$cold_boot_sha256" \
  --arg boundary_sha256 "$boundary_sha256" --argjson committed_record "$committed_record" \
  --argjson verifier "$verifier" --argjson negative_gates "$(jq -cS . "$temporary/negative-gates.json")" \
  --argjson bridge_successor_deployment "$bridge_successor_deployment" \
  --arg bridge_successor_release_id "$bridge_successor_release_id" \
  --argjson bridge_exception "$bridge_exception" \
  '.cold_boot_evidence=$evidence | .cold_boot_acceptance_sha256=$evidence_sha256 | .post_reboot_boundary_sha256=$boundary_sha256 | .committed_record=$committed_record | .host_acceptance_verifier=$verifier | .negative_gates=$negative_gates | .bridge_successor_deployment=$bridge_successor_deployment | .bridge_successor_release_id=(if $bridge_successor_release_id == "null" then null else $bridge_successor_release_id end) | .bridge_exception=$bridge_exception' \
  "$state" > "$state_tmp"
chmod 600 "$state_tmp"
durable_replace "$state_tmp" "$state"
if [[ "$bridge_to_rotation" == true ]]; then
  exec "$root_dir/scripts/commit-secure-enclave-bridge-successor.sh"
fi
research_acceptance="$(jq -cS .research_acceptance "$state")"
request_broker --agent "$requesting_agent" --session "$requesting_session" \
  --purpose "Commit the rebooted and end-to-end verified Secure Enclave approval generation" \
  --resource /usr/local/var/lib/secure-sandbox/execution-approval \
  --operation execution-approval-migration-commit \
  --parameters-json "$(jq -ncS --arg transaction_id "$transaction_id" \
    --argjson research_activation "$research_acceptance" --arg cold_boot_acceptance_sha256 "$cold_boot_sha256" \
    --arg acceptance_verifier_sha256 "$verifier_sha256" \
    '{transaction_id:$transaction_id,research_activation:$research_activation,cold_boot_acceptance_sha256:$cold_boot_acceptance_sha256,acceptance_verifier_sha256:$acceptance_verifier_sha256}')"

echo "FINALIZE 6/7  Commit Research, consume the bounded permit, and reopen normal admission"
jq -cS .committed_record "$state" > "$temporary/transition-committed.json"
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-execution-approval-transition.sh apply \
  /tmp/execution_approval_transition.py /tmp/transition-committed.json \
  --file "$root_dir/scripts/install-execution-approval-transition.sh" \
  --file "$root_dir/research/execution_approval_transition.py" \
  --file "$temporary/transition-committed.json"

if [[ "$bridge_to_rotation" == true ]]; then
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson bridge_exception "$bridge_exception" --argjson completed_at "$(date +%s)" \
    '.stage="bridge_committed" | .bridge_exception=$bridge_exception | .bridge_committed_at=$completed_at' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
  echo secure-enclave-execution-approval-ddd:bridge-committed-for-immediate-forward-rotation
  echo "The software key remains cryptographically revoked but undeleted until the fixed rotation completes."
  exit 0
fi

echo "FINALIZE 7/7  Retire the revoked software key and verify the complete boundary"
retirement="$(request_broker --agent "$requesting_agent" --session "$requesting_session" \
  --purpose "Retire the permanently revoked software execution-approval key" \
  --resource /usr/local/var/lib/secure-sandbox/execution-approval \
  --operation execution-approval-software-retire \
  --parameters-json "$(jq -ncS --arg transaction_id "$transaction_id" '{transaction_id:$transaction_id}')")"
jq -e --arg transaction_id "$transaction_id" \
  --arg generation_id "$(jq -er .prepared.generation_id "$state")" \
  --argjson generation_epoch "$(jq -er .prepared.generation_epoch "$state")" \
  '.schema == "secure-sandbox-execution-approval-migration-result-v2"
   and .status == "software_retired" and .transaction_id == $transaction_id
   and .generation_id == $generation_id and .generation_epoch == $generation_epoch' \
  <<<"$retirement" >/dev/null
scripts/verify-boundaries.sh | tee "$temporary/final-boundary.log"
final_boundary_sha256="$(shasum -a 256 "$temporary/final-boundary.log" | awk '{print $1}')"
state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
jq -S --argjson cancellation_evidence "$cancellation_evidence" \
  --argjson retirement "$retirement" --arg final_boundary_sha256 "$final_boundary_sha256" \
  --argjson completed_at "$(date +%s)" \
  '.stage="complete" | .cancellation_evidence=$cancellation_evidence
   | .software_retirement=$retirement | .final_boundary_sha256=$final_boundary_sha256
   | .completed_at=$completed_at' "$state" > "$state_tmp"
chmod 600 "$state_tmp"
durable_replace "$state_tmp" "$state"
echo secure-enclave-execution-approval-ddd:deployed-and-boundary-verified
