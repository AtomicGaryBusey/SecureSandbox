#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
state_dir="$root_dir/.private/secure-enclave-execution-approval-ddd"
state="$state_dir/state.json"
legacy_ui_bundle="$(python3 scripts/secure_enclave_ddd_support.py local-config-field \
  --path "$root_dir/.private/secure-enclave-ddd.json" \
  --field legacy_launchservices_ui_bundle_sha256)"
durable_replace() {
  /usr/bin/python3 -c 'import os,sys; source,target=sys.argv[1:]; fd=os.open(source,os.O_RDONLY); os.fsync(fd); os.close(fd); os.replace(source,target); directory=os.open(os.path.dirname(target),os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)' "$1" "$2"
}
[[ -f "$state" && ! -L "$state" && "$(stat -f '%Su:%Sp' "$state")" == "$(id -un):-rw-------" ]] \
  || { echo secure_enclave_ddd_checkpoint_untrusted >&2; exit 1; }
jq -e '.schema == "secure-sandbox-secure-enclave-ddd-checkpoint-v1" and .stage == "awaiting_host_reboot"' "$state" >/dev/null
prior_boot="$(jq -er .host_boot "$state")"
current_boot="$(sysctl -n kern.boottime)"
[[ "$current_boot" != "$prior_boot" ]] || { echo actual_mac_reboot_required >&2; exit 1; }
expires_at="$(jq -er .acceptance.expires_at "$state")"

agent_matches() {
  local socket="$1" public_key="$2" expected actual
  [[ -S "$socket" && -f "$public_key" && ! -L "$public_key" ]] || return 1
  expected="$(/usr/bin/ssh-keygen -lf "$public_key" -E sha256 2>/dev/null \
    | /usr/bin/awk 'NR == 1 {print $2}')"
  actual="$(SSH_AUTH_SOCK="$socket" /usr/bin/ssh-add -l -E sha256 2>/dev/null \
    | /usr/bin/awk '{print $2}')"
  [[ -n "$expected" && "$actual" == "$expected" ]]
}
provisioning_socket=/tmp/secure-sandbox-ssh-agent.sock
control_socket=/tmp/secure-sandbox-control-ssh-agent.sock
provisioning_public="$root_dir/runs/provisioning_key.pub"
control_public="$root_dir/runs/control_key.pub"
if ! agent_matches "$provisioning_socket" "$provisioning_public" \
    || ! agent_matches "$control_socket" "$control_public"; then
  echo "COLD BOOT 0/2  Restore the exact ephemeral SSH identities from the Agents vault"
  scripts/labctl key-load
fi
agent_matches "$provisioning_socket" "$provisioning_public" \
  && agent_matches "$control_socket" "$control_public" \
  || { echo cold_boot_ssh_identity_restore_failed >&2; exit 1; }

prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
[[ -x "$prlctl" ]] || { echo parallels_prlctl_unavailable >&2; exit 1; }
vm_status() {
  local vm_name="$1"
  "$prlctl" list --all --json "$vm_name" 2>/dev/null \
    | /usr/bin/jq -er --arg name "$vm_name" '
        if type == "array" and length == 1 and .[0].name == $name
           and (.[0].status | type) == "string"
        then .[0].status else error("invalid VM status") end
      '
}
gateway_state="$(vm_status SecureSandbox-Gateway)"
research_state="$(vm_status SecureSandbox-Research)"
target_state="$(vm_status SecureSandbox-Target)"
if /usr/bin/pgrep -x prl_client_app >/dev/null; then
  echo parallels_gui_must_be_closed_before_vm_start >&2
  exit 1
fi
case "$gateway_state:$research_state:$target_state" in
  stopped:stopped:stopped)
    echo "COLD BOOT 1/2  Start the verified VM stack with the Parallels GUI closed"
    scripts/labctl start
    ;;
  running:running:running)
    echo "COLD BOOT 1/2  Reuse the already-running VM stack without retrying lifecycle startup"
    ;;
  *)
    jq -nc --arg gateway "$gateway_state" --arg research "$research_state" \
      --arg target "$target_state" \
      '{schema:"secure-sandbox-host-lifecycle-v1",operation:"resume-readback",
        status:"rejected",observed:{gateway:$gateway,research:$research,target:$target,
        gateway_net0:"unknown"},action_failures:["mixed_or_unknown_vm_state"]}' >&2
    exit 1
    ;;
esac

temporary="$(mktemp -d /tmp/secure-sandbox-se-acceptance.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
echo "COLD BOOT 2/2  Verify the complete live boundary after controlled startup"
set +e
scripts/verify-boundaries.sh | tee "$temporary/pre-resume-boundary.log"
boundary_status="${PIPESTATUS[0]}"
set -e
if [[ "$boundary_status" -ne 0 ]]; then
  [[ "$(grep -c '^FAIL  ' "$temporary/pre-resume-boundary.log")" -eq 1 \
      && "$(grep '^FAIL  ' "$temporary/pre-resume-boundary.log")" \
         == 'FAIL  Host Claude controller is an immutable release matching approved source' \
      && "$(tail -n 1 "$temporary/pre-resume-boundary.log")" \
         == 'BOUNDARY VERIFICATION FAILED: 1 check(s)' ]] \
    || { echo unexpected_pre_resume_boundary_failure >&2; exit 1; }
  python3 scripts/secure_enclave_ddd_support.py verify-checkpoint-host-release \
    --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
    --launcher /usr/local/bin/secure-sandbox-claude \
    --expected-release-id "$(jq -er .prepared.host_release_id "$state")" \
    --expected-generation-id "$(jq -er .prepared.generation_id "$state")" \
    --expected-generation-epoch "$(jq -er .prepared.generation_epoch "$state")" \
    --expected-public-key-sha256 "$(jq -er .prepared.public_key_sha256 "$state")" \
    --expected-ui-bundle-sha256 "$legacy_ui_bundle" \
    > "$temporary/checkpoint-host-verification.json"
  echo "PASS  Live Host is the exact immutable checkpoint predecessor; source advancement is deferred to forward rotation"
fi
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
request_broker() {
  # The deployed pre-recovery UI has no result sidecar and cannot be launched
  # as a foreground app by its old request wrapper on macOS 27.  The reviewed
  # source wrapper uses LaunchServices and accepts only the exact predecessor's
  # schema-checked successful acceptance response.  Root execution remains in
  # the protected broker service and its signed UI peer.
  python3 "$root_dir/scripts/operator-authorization.py" request "$@"
}
requesting_agent="$(jq -er .requesting_agent "$state")"
requesting_session="$(jq -er .requesting_session "$state")"
deploy_transition() {
  local record="$1"
  "$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
    deploy install-execution-approval-transition.sh apply \
    /tmp/execution_approval_transition.py "/tmp/$(basename "$record")" \
    --file "$root_dir/scripts/install-execution-approval-transition.sh" \
    --file "$root_dir/research/execution_approval_transition.py" \
    --file "$record"
}
verify_acceptance() {
  jq -cS .acceptance_record "$state" > "$temporary/acceptance-record.json"
  "$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
    deploy install-execution-approval-transition.sh verify-acceptance \
    /tmp/execution_approval_transition.py /tmp/acceptance-record.json \
    --file "$root_dir/scripts/install-execution-approval-transition.sh" \
    --file "$root_dir/research/execution_approval_transition.py" \
    --file "$temporary/acceptance-record.json"
}
archive_predecessor_acceptance_evidence() {
  local transaction result
  transaction="$(jq -er .prepared.transaction_id "$state")"
  result="$("$control_client" client --ssh-config "$ssh_config" \
    sandbox-research-control deploy install-acceptance-evidence-archive.sh \
    "$transaction" /tmp/archive_execution_approval_acceptance_evidence.py \
    --file "$root_dir/scripts/archive-execution-approval-acceptance-evidence.sh:install-acceptance-evidence-archive.sh" \
    --file "$root_dir/scripts/archive_execution_approval_acceptance_evidence.py")"
  jq -e --arg transaction "$transaction" '
    .schema == "secure-sandbox-execution-approval-evidence-archive-v1"
    and .current_transaction_id == $transaction
    and .archived_transaction_id != $transaction
    and (.status == "absent" or .status == "current" or .status == "archived")
  ' <<<"$result" >/dev/null || { echo acceptance_evidence_archive_invalid >&2; return 1; }
  if [[ "$(jq -er .status <<<"$result")" == archived ]]; then
    echo "Archived the predecessor generation acceptance evidence before current correlation."
  fi
}
gateway_control() {
  "$control_client" client --ssh-config "$ssh_config" sandbox-gateway-control run "$@"
}
verified_live_runtime_image() {
  local research target research_image target_image
  research="$("$control_client" client --ssh-config "$ssh_config" \
    sandbox-research-control deploy install-boundary-audit.sh research \
    --file "$root_dir/scripts/audit-execution-runtime-identity.sh:install-boundary-audit.sh")"
  target="$("$control_client" client --ssh-config "$ssh_config" \
    sandbox-target-control deploy install-boundary-audit.sh target \
    --file "$root_dir/scripts/audit-execution-runtime-identity.sh:install-boundary-audit.sh")"
  jq -e --arg generation_id "$(jq -er .prepared.generation_id "$state")" \
    --argjson generation_epoch "$(jq -er .prepared.generation_epoch "$state")" \
    --arg public_key_sha256 "$(jq -er .prepared.public_key_sha256 "$state")" '
      .schema == "secure-sandbox-execution-runtime-identity-v1"
      and .role == "research" and .generation_id == $generation_id
      and .generation_epoch == $generation_epoch
      and .public_key_sha256 == $public_key_sha256
      and (.runtime_image_id | test("^sha256:[0-9a-f]{64}$"))
    ' <<<"$research" >/dev/null || { echo research_execution_runtime_identity_invalid >&2; return 1; }
  jq -e '
      .schema == "secure-sandbox-execution-runtime-identity-v1"
      and .role == "target"
      and (.runtime_image_id | test("^sha256:[0-9a-f]{64}$"))
    ' <<<"$target" >/dev/null || { echo target_execution_runtime_identity_invalid >&2; return 1; }
  research_image="$(jq -er .runtime_image_id <<<"$research")"
  target_image="$(jq -er .runtime_image_id <<<"$target")"
  [[ "$research_image" == "$target_image" ]] \
    || { echo execution_runtime_identity_mismatch >&2; return 1; }
  printf '%s\n' "$research_image"
}
issue_gateway_lease() {
  local run_id="$1" expires_at="${2:-}" issued
  issued="$(gateway_control lease-issue "$run_id" short)"
  jq -e --arg run_id "$run_id" '
    .schema == "secure-sandbox-run-lease-v1"
    and .run_id == $run_id and .profile == "short"
    and (.lease_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
    and (.issued_at | type == "number")
    and (.expires_at | type == "number")
    and .issued_at < .expires_at
  ' <<<"$issued" >/dev/null || { echo acceptance_gateway_lease_invalid >&2; return 1; }
  if [[ -n "$expires_at" ]]; then
    jq -e --argjson expires_at "$expires_at" '.expires_at <= $expires_at' <<<"$issued" >/dev/null \
      || { echo acceptance_gateway_lease_exceeds_acceptance >&2; return 1; }
  fi
  jq -cS . <<<"$issued"
}
ensure_preissued_gateway_lease() {
  local core="$1" run_id expires_at issued saved state_tmp
  run_id="$(jq -er .run_id <<<"$core")"
  expires_at="$(jq -er .expires_at <<<"$core")"
  issued="$(issue_gateway_lease "$run_id" "$expires_at")"
  if jq -e '.planned_acceptance_gateway_lease != null' "$state" >/dev/null; then
    saved="$(jq -cS .planned_acceptance_gateway_lease "$state")"
    [[ "$(jq -cS . <<<"$issued")" == "$saved" ]] \
      || { echo acceptance_gateway_lease_conflict >&2; return 1; }
  else
    state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
    jq -S --argjson lease "$issued" '.planned_acceptance_gateway_lease=$lease' \
      "$state" > "$state_tmp"
    chmod 600 "$state_tmp"
    durable_replace "$state_tmp" "$state"
  fi
  jq -cS . <<<"$issued"
}
finalize_unissued_gateway_lease() {
  local core="$1" reason="${2:-launch_failed}" run_id status summary
  [[ "$reason" == launch_failed || "$reason" == expired ]] \
    || { echo acceptance_gateway_lease_finalization_reason_invalid >&2; return 1; }
  run_id="$(jq -er .run_id <<<"$core")"
  status="$(gateway_control lease-status "$run_id")"
  jq -e --arg run_id "$run_id" --arg reason "$reason" '
    .lease.run_id == $run_id and .counters.run_id == $run_id
    and .counters.requests == 0
    and .counters.input_tokens == 0
    and .counters.output_tokens == 0
    and .counters.cost_microusd == 0
    and (.summary == null or .summary.reason == $reason
         or .summary.reason == "launch_failed" or .summary.reason == "expired")
  ' <<<"$status" >/dev/null \
    || { echo acceptance_gateway_lease_not_unissued >&2; return 1; }
  if jq -e '.summary == null' <<<"$status" >/dev/null; then
    summary="$(gateway_control lease-finalize "$run_id" "$reason")"
  else
    summary="$(jq -cS .summary <<<"$status")"
  fi
  jq -e --arg run_id "$run_id" --arg reason "$reason" '
    .schema == "secure-sandbox-run-lease-summary-v1"
    and (.reason == $reason or .reason == "launch_failed" or .reason == "expired")
    and .lease.run_id == $run_id
    and .final_counters.run_id == $run_id
    and .final_counters.requests == 0
    and .final_counters.input_tokens == 0
    and .final_counters.output_tokens == 0
    and .final_counters.cost_microusd == 0
  ' <<<"$summary" >/dev/null || { echo acceptance_gateway_lease_finalization_invalid >&2; return 1; }
}
materialize_acceptance_draft() {
  local draft run_id state_tmp issue_status status replacement
  draft="$(jq -ceS '.planned_acceptance_retry_draft | select(type == "object")' "$state")"
  run_id="$(jq -er .run_id <<<"$draft")"
  set +e
  gateway_lease="$(issue_gateway_lease "$run_id")"
  issue_status=$?
  set -e
  if [[ "$issue_status" -ne 0 ]]; then
    status="$(gateway_control lease-status "$run_id")"
    jq -e --arg run_id "$run_id" '
      .lease.run_id == $run_id and .counters.run_id == $run_id
      and .summary != null
      and (.summary.reason == "expired" or .summary.reason == "launch_failed")
      and .counters.requests == 0
      and .counters.input_tokens == 0
      and .counters.output_tokens == 0
      and .counters.cost_microusd == 0
    ' <<<"$status" >/dev/null \
      || { echo acceptance_draft_lease_recovery_invalid >&2; return "$issue_status"; }
    replacement="$(jq -cS \
      --arg acceptance_attempt_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
      --arg run_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
      --arg session_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
      '.acceptance_attempt_id=$acceptance_attempt_id | .run_id=$run_id | .session_id=$session_id' \
      <<<"$draft")"
    state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
    jq -S --argjson draft "$replacement" '.planned_acceptance_retry_draft=$draft' \
      "$state" > "$state_tmp"
    chmod 600 "$state_tmp"
    durable_replace "$state_tmp" "$state"
    materialize_acceptance_draft
    return
  fi
  recorded_at="$(jq -er .issued_at <<<"$gateway_lease")"
  expires_at="$(jq -er .expires_at <<<"$gateway_lease")"
  acceptance_core="$(jq -cS --argjson expires_at "$expires_at" '. + {expires_at:$expires_at}' <<<"$draft")"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson plan "$acceptance_core" --argjson recorded_at "$recorded_at" \
    --argjson gateway_lease "$gateway_lease" \
    '.planned_acceptance_retry=$plan | .planned_acceptance_retry_recorded_at=$recorded_at | .planned_acceptance_gateway_lease=$gateway_lease | del(.planned_acceptance_retry_draft,.planned_acceptance_host_authorization)' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
}
persist_initial_acceptance_draft() {
  local prepared="$1" runtime_image_id="$2" state_tmp draft prior_binding attempt_number attempt_id run_id session_id source_id
  if jq -e '.planned_acceptance_retry_draft != null' "$state" >/dev/null; then
    return
  fi
  prior_binding="$(jq -er .research_acceptance.acceptance_binding_sha256 "$state")"
  attempt_number="$(( $(jq -er .acceptance.acceptance_attempt_number "$state") + 1 ))"
  attempt_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  run_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  session_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  source_id="$(jq -er .acceptance.source_id "$state")"
  draft="$(jq -ncS --argjson prepared "$prepared" \
    --arg acceptance_attempt_id "$attempt_id" --argjson acceptance_attempt_number "$attempt_number" \
    --arg previous_acceptance_binding_sha256 "$prior_binding" --arg run_id "$run_id" \
    --arg session_id "$session_id" --arg source_id "$source_id" \
    --arg code_sha256 "$(jq -er .acceptance_record.code_sha256 "$state")" \
    --arg fixture_manifest_sha256 "$(jq -er .acceptance_record.fixture_manifest_sha256 "$state")" \
    --arg runtime_image_id "$runtime_image_id" \
    '{transaction_id:$prepared.transaction_id,generation_id:$prepared.generation_id,generation_epoch:$prepared.generation_epoch,acceptance_attempt_id:$acceptance_attempt_id,acceptance_attempt_number:$acceptance_attempt_number,previous_acceptance_binding_sha256:$previous_acceptance_binding_sha256,run_id:$run_id,session_id:$session_id,source_id:$source_id,code_sha256:$code_sha256,fixture_manifest_sha256:$fixture_manifest_sha256,timeout_seconds:5,runtime_image_id:$runtime_image_id}')"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson draft "$draft" '.planned_acceptance_retry_draft=$draft' "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
}
replace_unissued_acceptance_plan() {
  local prior="$1" reason="$2" state_tmp draft
  finalize_unissued_gateway_lease "$prior" "$reason"
  draft="$(jq -cS --arg acceptance_attempt_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg run_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    --arg session_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
    'del(.expires_at) | .acceptance_attempt_id=$acceptance_attempt_id | .run_id=$run_id | .session_id=$session_id' <<<"$prior")"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson draft "$draft" \
    '.planned_acceptance_retry_draft=$draft | del(.planned_acceptance_retry,.planned_acceptance_retry_recorded_at,.planned_acceptance_gateway_lease,.planned_acceptance_host_authorization)' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
  materialize_acceptance_draft
}
persist_host_authorization() {
  local core="$1" authorization="$2" binding state_tmp
  binding="$(printf '%s\n' "$(jq -cS . <<<"$core")" | shasum -a 256 | awk '{print $1}')"
  jq -e --arg binding "$binding" --arg attempt_id "$(jq -er .acceptance_attempt_id <<<"$core")" \
    --argjson attempt_number "$(jq -er .acceptance_attempt_number <<<"$core")" '
    .schema == "secure-sandbox-execution-approval-acceptance-authorization-v1"
    and .status == "authorized"
    and .acceptance_attempt_id == $attempt_id
    and .acceptance_attempt_number == $attempt_number
    and .acceptance_binding_sha256 == $binding
  ' <<<"$authorization" >/dev/null || { echo acceptance_host_authorization_invalid >&2; return 1; }
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson authorization "$authorization" '.planned_acceptance_host_authorization=$authorization' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
}
if jq -e '
    .prepared.previous_generation_id != null
    and .prepared.previous_generation_epoch != null
  ' "$state" >/dev/null; then
  archive_predecessor_acceptance_evidence
elif ! jq -e '
    .prepared.previous_generation_id == null
    and .prepared.previous_generation_epoch == null
  ' "$state" >/dev/null; then
  echo acceptance_predecessor_identity_invalid >&2
  exit 1
fi
set +e
verify_acceptance > "$temporary/research-evidence.json" 2> "$temporary/preflight-verification.stderr"
verification_status=$?
set -e
if [[ "$verification_status" -ne 0 ]]; then
  deferred_until="$(jq -r '.acceptance_launch_deferred_until // 0' "$state")"
  if [[ "$deferred_until" =~ ^[0-9]+$ && "$deferred_until" -gt "$(date +%s)" ]]; then
    printf 'The prior exact acceptance permit was not consumed because Research admission rejected the launch.\n' >&2
    printf 'It remains non-replaceable until %s (%s); no new authorization was requested.\n' \
      "$deferred_until" "$(date -r "$deferred_until" '+%Y-%m-%d %H:%M:%S %Z')" >&2
    exit 1
  fi
  if [[ "$(jq -r '.acceptance_attempt_started // false' "$state")" == true \
        || "$(date +%s)" -gt "$expires_at" ]]; then
    echo "The prior acceptance attempt is terminal or expired; authorizing a new append-only attempt."
    prepared="$(jq -cS .prepared "$state")"
    live_runtime_image="$(verified_live_runtime_image)"
    if [[ "$live_runtime_image" != "$(jq -er .acceptance_record.runtime_image_id "$state")" ]]; then
      echo "The prior acceptance record used a superseded Target runtime; the new append-only attempt will bind the verified live runtime."
    fi
    if jq -e '.planned_acceptance_retry_draft != null' "$state" >/dev/null; then
      materialize_acceptance_draft
    elif ! jq -e '.planned_acceptance_retry != null' "$state" >/dev/null; then
      persist_initial_acceptance_draft "$prepared" "$live_runtime_image"
      materialize_acceptance_draft
    fi
    while true; do
      acceptance_core="$(jq -cS .planned_acceptance_retry "$state")"
      recorded_at="$(jq -er .planned_acceptance_retry_recorded_at "$state")"
      gateway_lease="$(jq -cS .planned_acceptance_gateway_lease "$state")"
      attempt_number="$(jq -er .acceptance_attempt_number <<<"$acceptance_core")"
      attempt_id="$(jq -er .acceptance_attempt_id <<<"$acceptance_core")"
      run_id="$(jq -er .run_id <<<"$acceptance_core")"
      session_id="$(jq -er .session_id <<<"$acceptance_core")"
      source_id="$(jq -er .source_id <<<"$acceptance_core")"
      expires_at="$(jq -er .expires_at <<<"$acceptance_core")"
      if jq -e '.planned_acceptance_host_authorization != null' "$state" >/dev/null; then
        host_authorization="$(jq -cS .planned_acceptance_host_authorization "$state")"
        persist_host_authorization "$acceptance_core" "$host_authorization"
      else
        if [[ "$(date +%s)" -lt "$expires_at" ]]; then
          gateway_lease="$(ensure_preissued_gateway_lease "$acceptance_core")"
        fi
        host_authorization="$(request_broker --agent "$requesting_agent" --session "$requesting_session" \
          --purpose "Authorize replacement migration acceptance attempt $attempt_number" \
          --resource /usr/local/var/lib/secure-sandbox/execution-approval \
          --operation execution-approval-migration-authorize-acceptance \
          --parameters-json "$(jq -ncS --arg transaction_id "$(jq -er .transaction_id <<<"$prepared")" --argjson acceptance "$acceptance_core" '{transaction_id:$transaction_id,acceptance:$acceptance}')")"
        if [[ "$(jq -er .status <<<"$host_authorization")" == not_issued_expired ]]; then
          echo "The checkpointed retry expired before Host issuance; replacing that unissued plan."
          replace_unissued_acceptance_plan "$acceptance_core" expired
          continue
        fi
        persist_host_authorization "$acceptance_core" "$host_authorization"
      fi
      if [[ "$(date +%s)" -lt "$expires_at" ]]; then
        gateway_lease="$(ensure_preissued_gateway_lease "$acceptance_core")"
      else
        finalize_unissued_gateway_lease "$acceptance_core" expired
      fi
      break
    done
    jq -e '.schema == "secure-sandbox-execution-approval-acceptance-authorization-v1" and .status == "authorized"' \
      <<<"$host_authorization" >/dev/null
    jq -nS --argjson prior "$(jq -cS .acceptance_record "$state")" \
      --argjson core "$acceptance_core" --argjson authorization "$host_authorization" \
      --argjson recorded_at "$recorded_at" \
      '$prior | .expected_prior_phase="acceptance" | .recorded_at=$recorded_at
       | .run_id=$core.run_id | .session_id=$core.session_id | .source_id=$core.source_id
       | .code_sha256=$core.code_sha256
       | .fixture_manifest_sha256=$core.fixture_manifest_sha256
       | .timeout_seconds=$core.timeout_seconds | .runtime_image_id=$core.runtime_image_id
       | .expires_at=$core.expires_at | .acceptance_attempt_id=$core.acceptance_attempt_id
       | .acceptance_attempt_number=$core.acceptance_attempt_number
       | .previous_acceptance_binding_sha256=$core.previous_acceptance_binding_sha256
       | .host_acceptance_authorization=$authorization' \
      > "$temporary/acceptance-record.json"
    research_acceptance="$(deploy_transition "$temporary/acceptance-record.json")"
    acceptance="$(jq -ncS --argjson prior "$(jq -cS .acceptance "$state")" \
      --arg run_id "$run_id" --arg session_id "$session_id" --arg attempt_id "$attempt_id" \
      --argjson attempt_number "$attempt_number" --argjson expires_at "$expires_at" \
      '$prior | .run_id=$run_id | .session_id=$session_id | .expires_at=$expires_at | .acceptance_attempt_id=$attempt_id | .acceptance_attempt_number=$attempt_number')"
    state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
    jq -S --argjson record "$(jq -cS . "$temporary/acceptance-record.json")" \
      --argjson acceptance "$acceptance" --argjson research_acceptance "$(jq -cS . <<<"$research_acceptance")" \
      --argjson gateway_lease "$gateway_lease" \
      '.acceptance_record=$record | .acceptance=$acceptance | .research_acceptance=$research_acceptance | .acceptance_gateway_lease=$gateway_lease | .acceptance_attempt_started=false | del(.planned_acceptance_retry,.planned_acceptance_retry_recorded_at,.planned_acceptance_gateway_lease,.planned_acceptance_retry_draft,.planned_acceptance_host_authorization,.acceptance_launch_deferred_until,.acceptance_launch_failed_at,.acceptance_launch_status)' \
      "$state" > "$state_tmp"
    chmod 600 "$state_tmp"
    durable_replace "$state_tmp" "$state"
    if [[ "$(date +%s)" -ge "$expires_at" ]]; then
      state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
      jq -S --argjson started_at "$(date +%s)" \
        '.acceptance_attempt_started=true | .acceptance_attempt_started_at=$started_at | .acceptance_launch_deferred_until=.acceptance.expires_at' \
        "$state" > "$state_tmp"
      chmod 600 "$state_tmp"
      durable_replace "$state_tmp" "$state"
      echo "The Host-authorized acceptance was recovered in Research after expiry; advancing through a fresh append-only attempt."
      trap - EXIT
      rm -rf -- "$temporary"
      exec "$root_dir/scripts/resume-secure-enclave-execution-approval-ddd.sh"
    fi
  fi
  run_id="$(jq -er .acceptance.run_id "$state")"
  session_id="$(jq -er .acceptance.session_id "$state")"
  source_id="$(jq -er .acceptance.source_id "$state")"
  code="$(jq -er .acceptance.code "$state")"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson started_at "$(date +%s)" \
    '.acceptance_attempt_started=true | .acceptance_attempt_started_at=$started_at' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
  echo "A single exact acceptance run will open in THIS terminal."
  echo "Ask it to call run_python_fixture exactly once with:"
  printf '  source_id: %s\n  fixture_paths: []\n  timeout_seconds: 5\n  code: %s\n' "$source_id" "$code"
  echo "Approve the SecureSandbox Touch ID window, wait for the complete structured result, then close GLM."
  set +e
  SECURE_SANDBOX_ACCEPTANCE_RUN_ID="$run_id" \
  SECURE_SANDBOX_ACCEPTANCE_SESSION_ID="$session_id" \
    ./scripts/labctl claude --lease-profile short
  launch_status=$?
  set -e
  if [[ "$launch_status" -ne 0 ]]; then
    if finalize_unissued_gateway_lease "$(jq -cS .acceptance "$state")"; then
      state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
      jq -S --argjson deferred_until "$(jq -er .acceptance.expires_at "$state")" \
        --argjson failed_at "$(date +%s)" --argjson launch_status "$launch_status" \
        '.acceptance_launch_deferred_until=$deferred_until | .acceptance_launch_failed_at=$failed_at | .acceptance_launch_status=$launch_status' \
        "$state" > "$state_tmp"
      chmod 600 "$state_tmp"
      durable_replace "$state_tmp" "$state"
      echo "acceptance_launch_failed; the exact unconsumed permit remains fenced until expiry" >&2
      exit "$launch_status"
    fi
    echo "The launcher failed after Gateway lease use; checking protected acceptance evidence before deciding recovery." >&2
  fi
  set +e
  verify_acceptance > "$temporary/research-evidence.json" 2> "$temporary/postrun-verification.stderr"
  verification_status=$?
  set -e
  if [[ "$verification_status" -ne 0 ]]; then
    echo "acceptance_attempt_incomplete; rerun this same resume command for an explicitly authorized new attempt" >&2
    exit 1
  fi
else
  echo "The exact acceptance execution was already durably recorded; skipping relaunch."
fi
jq -e '.schema == "secure-sandbox-execution-approval-acceptance-evidence-v1" and .status == "verified"' \
  "$temporary/research-evidence.json" >/dev/null
state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
jq -S --argjson evidence "$(jq -cS . "$temporary/research-evidence.json")" \
  --arg rebooted_boot "$current_boot" --argjson verified_at "$(date +%s)" \
  '.stage="research_acceptance_verified" | .research_evidence=$evidence | .rebooted_boot=$rebooted_boot | .research_verified_at=$verified_at' \
  "$state" > "$state_tmp"
chmod 600 "$state_tmp"
durable_replace "$state_tmp" "$state"
echo secure-enclave-execution-approval-ddd:research-acceptance-verified
echo "The authority remains uncommitted and the software key remains undeleted pending Host correlation and negative gates."
