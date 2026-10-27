#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
requesting_agent="Codex"
requesting_session="secure-enclave-execution-approval-ddd-live"
acceptance_source_id=""
acceptance_runtime_image=""
ddd_config="${SECURE_SANDBOX_DDD_CONFIG:-$root_dir/.private/secure-enclave-ddd.json}"
expected_acceptance_source_id="$(python3 "$root_dir/scripts/secure_enclave_ddd_support.py" \
  local-config-field --path "$ddd_config" --field acceptance_source_id)"
while (($#)); do
  case "$1" in
    --requesting-agent) requesting_agent="$2"; shift 2 ;;
    --requesting-session) requesting_session="$2"; shift 2 ;;
    --acceptance-source-id) acceptance_source_id="$2"; shift 2 ;;
    --acceptance-runtime-image) acceptance_runtime_image="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

cd "$root_dir"
temporary="$(mktemp -d /tmp/secure-sandbox-se-approval.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
state_dir="$root_dir/.private/secure-enclave-execution-approval-ddd"
state="$state_dir/state.json"
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
durable_replace() {
  /usr/bin/python3 -c 'import os,sys; source,target=sys.argv[1:]; fd=os.open(source,os.O_RDONLY); os.fsync(fd); os.close(fd); os.replace(source,target); directory=os.open(os.path.dirname(target),os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)' "$1" "$2"
}

stage_rank() {
  case "$1" in
    none) echo 0 ;;
    records_ready) echo 1 ;;
    research_prepared) echo 2 ;;
    research_fenced) echo 3 ;;
    host_activated) echo 4 ;;
    research_active) echo 5 ;;
    acceptance_record_ready) echo 6 ;;
    awaiting_host_reboot) echo 7 ;;
    research_acceptance_verified) echo 8 ;;
    complete) echo 9 ;;
    *) echo secure_enclave_ddd_checkpoint_invalid >&2; exit 1 ;;
  esac
}

checkpoint_merge() {
  local next_stage="$1" field="$2" value="$3" state_tmp
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --arg stage "$next_stage" --arg field "$field" --argjson value "$value" \
    '.stage=$stage | .[$field]=$value' "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
}

deploy_transition() {
  local record="$1"
  "$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
    deploy install-execution-approval-transition.sh apply \
    /tmp/execution_approval_transition.py "/tmp/$(basename "$record")" \
    --file "$root_dir/scripts/install-execution-approval-transition.sh" \
    --file "$root_dir/research/execution_approval_transition.py" \
    --file "$record"
}

gateway_control() {
  "$control_client" client --ssh-config "$ssh_config" sandbox-gateway-control run "$@"
}

issue_acceptance_gateway_lease() {
  local run_id="$1" issued
  issued="$(gateway_control lease-issue "$run_id" short)"
  jq -e --arg run_id "$run_id" '
    .schema == "secure-sandbox-run-lease-v1"
    and .run_id == $run_id and .profile == "short"
    and (.lease_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
    and (.issued_at | type == "number") and (.expires_at | type == "number")
    and .issued_at < .expires_at
  ' <<<"$issued" >/dev/null || { echo acceptance_gateway_lease_invalid >&2; return 1; }
  jq -cS . <<<"$issued"
}

finalize_draft_gateway_lease() {
  local run_id="$1" status summary
  status="$(gateway_control lease-status "$run_id")"
  jq -e --arg run_id "$run_id" '
    .lease.run_id == $run_id and .counters.run_id == $run_id
    and .summary != null
    and (.summary.reason == "expired" or .summary.reason == "launch_failed")
    and .counters.requests == 0 and .counters.input_tokens == 0
    and .counters.output_tokens == 0 and .counters.cost_microusd == 0
  ' <<<"$status" >/dev/null || { echo acceptance_draft_lease_recovery_invalid >&2; return 1; }
  summary="$(jq -cS .summary <<<"$status")"
  jq -e --arg run_id "$run_id" '
    .lease.run_id == $run_id and .final_counters.run_id == $run_id
    and .final_counters.requests == 0 and .final_counters.input_tokens == 0
    and .final_counters.output_tokens == 0 and .final_counters.cost_microusd == 0
  ' <<<"$summary" >/dev/null
}

materialize_initial_acceptance_draft() {
  local draft run_id issue_status status replacement state_tmp
  draft="$(jq -ceS '.planned_acceptance_draft | select(type == "object")' "$state")"
  run_id="$(jq -er .run_id <<<"$draft")"
  set +e
  acceptance_gateway_lease="$(issue_acceptance_gateway_lease "$run_id")"
  issue_status=$?
  set -e
  if [[ "$issue_status" -ne 0 ]]; then
    finalize_draft_gateway_lease "$run_id"
    replacement="$(jq -cS \
      --arg acceptance_attempt_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
      --arg run_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
      --arg session_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
      '.acceptance_attempt_id=$acceptance_attempt_id | .run_id=$run_id | .session_id=$session_id' \
      <<<"$draft")"
    state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
    jq -S --argjson draft "$replacement" '.planned_acceptance_draft=$draft' "$state" > "$state_tmp"
    chmod 600 "$state_tmp"
    durable_replace "$state_tmp" "$state"
    materialize_initial_acceptance_draft
    return
  fi
  acceptance_recorded_at="$(jq -er .issued_at <<<"$acceptance_gateway_lease")"
  acceptance_expires_at="$(jq -er .expires_at <<<"$acceptance_gateway_lease")"
  acceptance_core="$(jq -cS --argjson expires_at "$acceptance_expires_at" \
    '. + {expires_at:$expires_at}' <<<"$draft")"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson plan "$acceptance_core" --argjson recorded_at "$acceptance_recorded_at" \
    --argjson lease "$acceptance_gateway_lease" \
    '.planned_acceptance=$plan | .planned_acceptance_recorded_at=$recorded_at
     | .planned_acceptance_gateway_lease=$lease
     | del(.planned_acceptance_draft,.planned_acceptance_host_authorization)' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
}

persist_initial_host_authorization() {
  local core="$1" authorization="$2" binding state_tmp
  binding="$(printf '%s\n' "$(jq -cS . <<<"$core")" | shasum -a 256 | awk '{print $1}')"
  jq -e --arg binding "$binding" \
    --arg transaction_id "$(jq -er .transaction_id <<<"$core")" \
    --arg generation_id "$(jq -er .generation_id <<<"$core")" \
    --argjson generation_epoch "$(jq -er .generation_epoch <<<"$core")" \
    --arg attempt_id "$(jq -er .acceptance_attempt_id <<<"$core")" \
    --argjson attempt_number "$(jq -er .acceptance_attempt_number <<<"$core")" '
    .schema == "secure-sandbox-execution-approval-acceptance-authorization-v1"
    and .status == "authorized"
    and .transaction_id == $transaction_id
    and .generation_id == $generation_id
    and .generation_epoch == $generation_epoch
    and .acceptance_attempt_id == $attempt_id
    and .acceptance_attempt_number == $attempt_number
    and .acceptance_binding_sha256 == $binding
  ' <<<"$authorization" >/dev/null \
    || { echo acceptance_host_authorization_invalid >&2; return 1; }
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson authorization "$authorization" \
    '.planned_acceptance_host_authorization=$authorization' "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
}

make_record() {
  local phase="$1" expected_prior_phase="$2" destination="$3"
  jq -nS --arg phase "$phase" --argjson prepared "$prepared" \
    --arg expected_prior_phase "$expected_prior_phase" \
    --arg host_release_id "$host_release_id" --arg research_release_id "$research_release_id" \
    --argjson recorded_at "$(date +%s)" \
    '{schema:"secure-sandbox-execution-approval-transition-v2",phase:$phase,transaction_id:$prepared.transaction_id,generation_id:$prepared.generation_id,generation_epoch:$prepared.generation_epoch,previous_generation_id:$prepared.previous_generation_id,previous_generation_epoch:$prepared.previous_generation_epoch,operator_uid:$prepared.operator_uid,algorithm:$prepared.algorithm,public_key_spki_der_b64:$prepared.public_key_spki_der_b64,public_key_sha256:$prepared.public_key_sha256,host_release_id:$host_release_id,research_release_id:$research_release_id,expected_prior_phase:$expected_prior_phase,recorded_at:$recorded_at}' \
    > "$destination"
}

current_stage=none
if [[ -e "$state" || -L "$state" ]]; then
  [[ -f "$state" && ! -L "$state" && "$(stat -f '%Su:%Sp' "$state")" == "$(id -un):-rw-------" ]] \
    || { echo secure_enclave_ddd_checkpoint_untrusted >&2; exit 1; }
  jq -e '.schema == "secure-sandbox-secure-enclave-ddd-checkpoint-v1"' "$state" >/dev/null
  current_stage="$(jq -er .stage "$state")"
  stage_rank "$current_stage" >/dev/null
  [[ "$(jq -er .requesting_agent "$state")" == "$requesting_agent" \
     && "$(jq -er .requesting_session "$state")" == "$requesting_session" ]] \
    || { echo secure_enclave_ddd_request_identity_conflict >&2; exit 1; }
  if (( $(stage_rank "$current_stage") >= 7 )); then
    echo "secure-enclave-execution-approval-ddd:$current_stage"
    [[ "$current_stage" == awaiting_host_reboot ]] \
      && { echo "Before restarting: quit the Parallels Desktop GUI, keep it closed, then run:"; \
           printf '  cd %q\n' "$root_dir"; \
           echo "  ./scripts/labctl stop"; \
           echo "Restart only after its final verified record reports gateway, research, and target all stopped."; \
           echo "After restart, run the reviewed resume command supplied by Codex."; }
    exit 0
  fi
  prepared="$(jq -cS .prepared "$state")"
  host_release_id="$(jq -er .host_release_id "$state")"
  research_release_id="$(jq -er .research_release_id "$state")"
else
  source_host_release_id="$(python3 scripts/secure_enclave_ddd_support.py \
    source-host-release-id --repo "$root_dir")"
  live_host_release_id="$(basename "$(readlink /usr/local/libexec/secure-sandbox-host/current)")"
  live_approval_identity=""
  if [[ "$live_host_release_id" == "$source_host_release_id" ]]; then
    live_approval_identity="$(/usr/local/libexec/secure-sandbox-host/current/authorization_broker \
      execution-approval-public-key 2>/dev/null || true)"
  fi
  if [[ "$live_host_release_id" == "$source_host_release_id" ]] \
      && jq -e '.schema == "secure-sandbox-execution-approval-key-v2" and .status == "active"' \
        <<<"$live_approval_identity" >/dev/null 2>&1; then
    echo "DDD 1/9  Reuse the exact verified Secure Enclave-capable protected host release"
    python3 scripts/secure_enclave_ddd_support.py verify-postactivation-host-release \
      --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
      --launcher /usr/local/bin/secure-sandbox-claude >/dev/null
  else
    echo "DDD 1/9  Deploy the reviewed Secure Enclave-capable protected host release"
    python3 scripts/deploy-host-controller.py deploy \
      --requesting-agent "$requesting_agent" \
      --requesting-session "$requesting_session" \
      --purpose "Deploy Secure Enclave-backed disposable-execution approval"
  fi

  echo "DDD 2/9  Republish the exact typed control plane and admission fence"
  python3 scripts/privileged-control-operation.py deploy
  scripts/deploy-run-leases.sh

  broker=/usr/local/libexec/secure-sandbox-host/current/authorization_broker
  host_release_id="$(basename "$(readlink /usr/local/libexec/secure-sandbox-host/current)")"
  [[ "$host_release_id" =~ ^[0-9a-f]{64}$ ]] || { echo protected_release_identity_invalid >&2; exit 1; }

  echo "DDD 3/9  Predeploy the v2-capable Research broker before irreversible activation"
  disposable_deployment="$(scripts/deploy-disposable-execution.sh)"
  printf '%s\n' "$disposable_deployment"
  deployed_runtime_image="$(printf '%s\n' "$disposable_deployment" \
    | sed -n 's/^disposable-execution-target:installed:\(sha256:[0-9a-f]\{64\}\)$/\1/p' \
    | tail -1)"
  [[ "$deployed_runtime_image" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || { echo deployed_execution_runtime_identity_invalid >&2; exit 1; }
  if [[ -n "$acceptance_runtime_image" ]]; then
    [[ "$acceptance_runtime_image" == "$deployed_runtime_image" ]] \
      || { echo secure_enclave_acceptance_runtime_identity_mismatch >&2; exit 1; }
  fi
  acceptance_runtime_image="$deployed_runtime_image"
  research_release_id="$(for artifact in research/execution_broker.py research/execution_approval_transition.py research/run_lease_watchdog.py; do shasum -a 256 "$artifact" | awk '{print $1}'; done | xxd -r -p | shasum -a 256 | awk '{print $1}')"
  [[ "$research_release_id" =~ ^[0-9a-f]{64}$ ]] || { echo research_release_identity_invalid >&2; exit 1; }

  echo "DDD 4/9  Create and prove possession of the non-exportable Secure Enclave key"
  prepared="$($broker request \
    --agent "$requesting_agent" --session "$requesting_session" \
    --purpose "Create and prove the non-exportable Secure Enclave execution-approval identity" \
    --resource /usr/local/var/lib/secure-sandbox/execution-approval \
    --operation execution-approval-key-init \
    --parameters-json "$(jq -ncS --arg research_release_id "$research_release_id" '{research_release_id:$research_release_id}')")"
  jq -e '.schema == "secure-sandbox-execution-approval-key-v2" and .status == "prepared" and (.generation_epoch >= 1)' <<<"$prepared" >/dev/null

  previous_phase="$(jq -r 'if .previous_generation_id == null then "none" else "committed" end' <<<"$prepared")"
  make_record prepared "$previous_phase" "$temporary/transition-prepared.json"
  make_record fenced prepared "$temporary/transition-fenced.json"
  make_record active fenced "$temporary/transition-active.json"
  mkdir -p "$state_dir"
  chmod 700 "$state_dir"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -ncS --argjson prepared "$prepared" \
    --argjson prepared_record "$(jq -cS . "$temporary/transition-prepared.json")" \
    --argjson fenced_record "$(jq -cS . "$temporary/transition-fenced.json")" \
    --argjson active_record "$(jq -cS . "$temporary/transition-active.json")" \
    --arg host_release_id "$host_release_id" --arg research_release_id "$research_release_id" \
    --arg deployed_runtime_image "$deployed_runtime_image" \
    --arg host_boot "$(sysctl -n kern.boottime)" --arg requesting_agent "$requesting_agent" \
    --arg requesting_session "$requesting_session" --argjson checkpointed_at "$(date +%s)" \
    '{schema:"secure-sandbox-secure-enclave-ddd-checkpoint-v1",stage:"records_ready",prepared:$prepared,host_release_id:$host_release_id,research_release_id:$research_release_id,deployed_runtime_image:$deployed_runtime_image,phase_records:{prepared:$prepared_record,fenced:$fenced_record,active:$active_record},host_boot:$host_boot,requesting_agent:$requesting_agent,requesting_session:$requesting_session,checkpointed_at:$checkpointed_at}' \
    > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
  current_stage=records_ready
fi

broker=/usr/local/libexec/secure-sandbox-host/current/authorization_broker
if (( $(stage_rank "$current_stage") >= 4 )); then
  live_host_release_id="$(basename "$(readlink /usr/local/libexec/secure-sandbox-host/current)")"
  [[ "$live_host_release_id" == "$host_release_id" ]] \
    || { echo post_activation_host_release_identity_mismatch >&2; exit 1; }
  active_identity="$($broker execution-approval-public-key)"
  jq -e --argjson prepared "$prepared" \
    '.schema == "secure-sandbox-execution-approval-key-v2" and .status == "active"
     and .generation_id == $prepared.generation_id
     and .generation_epoch == $prepared.generation_epoch
     and .algorithm == $prepared.algorithm
     and .public_key_sha256 == $prepared.public_key_sha256
     and .public_key_spki_der_b64 == $prepared.public_key_spki_der_b64' \
    <<<"$active_identity" >/dev/null
else
source_host_release_id="$(python3 scripts/secure_enclave_ddd_support.py \
  source-host-release-id --repo "$root_dir")"
protected_selectors="$(python3 scripts/secure_enclave_ddd_support.py \
  protected-selector-identities --repo "$root_dir" \
  --install-root /usr/local/libexec/secure-sandbox-host)"
live_host_release_id="$(jq -er .current <<<"$protected_selectors")"
previous_host_release_id="$(jq -er .previous <<<"$protected_selectors")"
source_research_release_id="$(for artifact in research/execution_broker.py research/execution_approval_transition.py research/run_lease_watchdog.py; do shasum -a 256 "$artifact" | awk '{print $1}'; done | xxd -r -p | shasum -a 256 | awk '{print $1}')"
[[ "$source_host_release_id" =~ ^[0-9a-f]{64}$ ]] || { echo source_host_release_identity_invalid >&2; exit 1; }
[[ "$live_host_release_id" =~ ^[0-9a-f]{64}$ ]] || { echo protected_release_identity_invalid >&2; exit 1; }
[[ "$source_research_release_id" =~ ^[0-9a-f]{64}$ ]] || { echo research_release_identity_invalid >&2; exit 1; }
repair_required="$(python3 scripts/secure_enclave_ddd_support.py repair-required \
  --checkpoint-host "$host_release_id" --source-host "$source_host_release_id" \
  --live-host "$live_host_release_id" --checkpoint-research "$research_release_id" \
  --source-research "$source_research_release_id")"
if [[ "$repair_required" == true ]]; then
  [[ "$current_stage" == research_prepared ]] \
    || { echo secure_enclave_pre_activation_repair_stage_invalid >&2; exit 1; }
  [[ "$previous_host_release_id" =~ ^[0-9a-f]{64}$ ]] \
    || { echo protected_previous_release_identity_invalid >&2; exit 1; }
  reusable_deployed_host="$(python3 scripts/secure_enclave_ddd_support.py \
    reusable-deployed-host --checkpoint-host "$host_release_id" \
    --source-host "$source_host_release_id" --live-host "$live_host_release_id" \
    --previous-host "$previous_host_release_id")"
  selector_restore_required="$(python3 scripts/secure_enclave_ddd_support.py \
    selector-restore-required --checkpoint-host "$host_release_id" \
    --source-host "$source_host_release_id" --live-host "$live_host_release_id" \
    --previous-host "$previous_host_release_id")"
  if [[ "$reusable_deployed_host" == true ]]; then
    echo "DDD recovery 1/4  Reuse the exact already-deployed Host repair"
    repaired_host_release_id="$live_host_release_id"
  else
    if [[ "$selector_restore_required" == true ]]; then
      echo "DDD recovery 1/4  Restore the checkpoint-pinned Host selector before repair"
      python3 scripts/deploy-host-controller.py rollback "$host_release_id" \
        --requesting-agent "$requesting_agent" \
        --requesting-session "$requesting_session" \
        --purpose "Restore the checkpoint-pinned Host release before Secure Enclave rebind"
      restored_selectors="$(python3 scripts/secure_enclave_ddd_support.py \
        protected-selector-identities --repo "$root_dir" \
        --install-root /usr/local/libexec/secure-sandbox-host)"
      restored_host_release_id="$(jq -er .current <<<"$restored_selectors")"
      [[ "$restored_host_release_id" == "$host_release_id" ]] \
        || { echo protected_checkpoint_release_restore_failed >&2; exit 1; }
    fi
    echo "DDD recovery 2/4  Deploy the immutable Host half of the pre-activation repair"
    python3 scripts/deploy-host-controller.py deploy \
      --requesting-agent "$requesting_agent" \
      --requesting-session "$requesting_session" \
      --purpose "Bind the prepared Secure Enclave generation to the repaired Research release"
    broker=/usr/local/libexec/secure-sandbox-host/current/authorization_broker
    repaired_selectors="$(python3 scripts/secure_enclave_ddd_support.py \
      protected-selector-identities --repo "$root_dir" \
      --install-root /usr/local/libexec/secure-sandbox-host)"
    repaired_host_release_id="$(jq -er .current <<<"$repaired_selectors")"
    deployed_source_host_release_id="$(python3 scripts/secure_enclave_ddd_support.py \
      source-host-release-id --repo "$root_dir")"
    [[ "$repaired_host_release_id" == "$deployed_source_host_release_id" ]] \
      || { echo protected_release_identity_mismatch >&2; exit 1; }
  fi
  broker=/usr/local/libexec/secure-sandbox-host/current/authorization_broker
  echo "DDD recovery 3/4  Reauthorize the exact repaired Host and Research measurements"
  repaired_prepared="$($broker request \
    --agent "$requesting_agent" --session "$requesting_session" \
    --purpose "Rebind the prepared non-exportable Secure Enclave identity to repaired measured code" \
    --resource /usr/local/var/lib/secure-sandbox/execution-approval \
    --operation execution-approval-key-init \
    --parameters-json "$(jq -ncS --arg research_release_id "$source_research_release_id" '{research_release_id:$research_release_id}')")"
  jq -e --argjson old "$prepared" --arg host "$repaired_host_release_id" \
    --arg research "$source_research_release_id" \
    '.schema == "secure-sandbox-execution-approval-key-v2" and .status == "prepared"
     and .transaction_id == $old.transaction_id and .generation_id == $old.generation_id
     and .generation_epoch == $old.generation_epoch and .operator_uid == $old.operator_uid
     and .algorithm == $old.algorithm and .public_key_sha256 == $old.public_key_sha256
     and .public_key_spki_der_b64 == $old.public_key_spki_der_b64
     and .previous_generation_id == $old.previous_generation_id
     and .previous_generation_epoch == $old.previous_generation_epoch
     and .host_release_id == $host and .research_release_id == $research' \
    <<<"$repaired_prepared" >/dev/null
  prepared="$repaired_prepared"
  host_release_id="$repaired_host_release_id"
  research_release_id="$source_research_release_id"
  make_record prepared prepared "$temporary/transition-prepared.json"
  make_record fenced prepared "$temporary/transition-fenced.json"
  make_record active fenced "$temporary/transition-active.json"
  echo "DDD recovery 4/4  Checkpoint the signed repair before Research compare-and-swap"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson prepared "$prepared" \
    --argjson prepared_record "$(jq -cS . "$temporary/transition-prepared.json")" \
    --argjson fenced_record "$(jq -cS . "$temporary/transition-fenced.json")" \
    --argjson active_record "$(jq -cS . "$temporary/transition-active.json")" \
    --arg host_release_id "$host_release_id" --arg research_release_id "$research_release_id" \
    --argjson checkpointed_at "$(date +%s)" \
    '.stage="records_ready" | .prepared=$prepared | .host_release_id=$host_release_id
     | .research_release_id=$research_release_id
     | .phase_records={prepared:$prepared_record,fenced:$fenced_record,active:$active_record}
     | .checkpointed_at=$checkpointed_at
     | del(.research_prepared,.research_fence,.host_activation,.research_active)' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
  current_stage=records_ready
fi
fi
transaction_id="$(jq -er .transaction_id <<<"$prepared")"
for phase in prepared fenced active; do
  jq -cS ".phase_records.$phase" "$state" > "$temporary/transition-$phase.json"
done

if (( $(stage_rank "$current_stage") < 2 )); then
  echo "DDD 5/9  Prepare Research using the precommitted exact record"
  research_prepared="$(deploy_transition "$temporary/transition-prepared.json")"
  checkpoint_merge research_prepared research_prepared "$(jq -cS . <<<"$research_prepared")"
  current_stage=research_prepared
fi

if (( $(stage_rank "$current_stage") < 3 )); then
  echo "DDD 5/9  Fence Research before Host activation"
  research_fence="$(deploy_transition "$temporary/transition-fenced.json")"
  checkpoint_merge research_fenced research_fence "$(jq -cS . <<<"$research_fence")"
  current_stage=research_fenced
else
  research_fence="$(jq -cS .research_fence "$state")"
fi

if (( $(stage_rank "$current_stage") < 4 )); then
  echo "DDD 6/9  Irreversibly activate protocol v2 on the Host"
  activation="$($broker request \
    --agent "$requesting_agent" --session "$requesting_session" \
    --purpose "Activate the fenced Secure Enclave execution-approval generation" \
    --resource /usr/local/var/lib/secure-sandbox/execution-approval \
    --operation execution-approval-migration-activate \
    --parameters-json "$(jq -ncS --arg transaction_id "$transaction_id" --argjson research_fence "$research_fence" '{transaction_id:$transaction_id,research_fence:$research_fence}')")"
  jq -e '.status == "host_activated"' <<<"$activation" >/dev/null
  checkpoint_merge host_activated host_activation "$(jq -cS . <<<"$activation")"
  current_stage=host_activated
fi

if (( $(stage_rank "$current_stage") < 5 )); then
  echo "DDD 7/9  Activate the exact pinned generation in Research while admission stays closed"
  research_active="$(deploy_transition "$temporary/transition-active.json")"
  checkpoint_merge research_active research_active "$(jq -cS . <<<"$research_active")"
  current_stage=research_active
fi

if (( $(stage_rank "$current_stage") < 6 )); then
  echo "DDD 8/9  Precommit one TTL-bound exact-run acceptance record"
  acceptance_code='print("secure-sandbox-secure-enclave-acceptance")'
  if jq -e '.planned_acceptance_draft != null' "$state" >/dev/null; then
    materialize_initial_acceptance_draft
    acceptance_core="$(jq -cS .planned_acceptance "$state")"
    acceptance_recorded_at="$(jq -er .planned_acceptance_recorded_at "$state")"
  elif jq -e '.planned_acceptance != null' "$state" >/dev/null; then
    acceptance_core="$(jq -cS .planned_acceptance "$state")"
    acceptance_recorded_at="$(jq -er .planned_acceptance_recorded_at "$state")"
  else
    [[ "$acceptance_source_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
      || { echo "Step 8 requires --acceptance-source-id with a registered source UUID." >&2; exit 2; }
    if [[ -z "$acceptance_runtime_image" ]]; then
      acceptance_runtime_image="$(jq -er .deployed_runtime_image "$state")"
    fi
    [[ "$acceptance_runtime_image" =~ ^sha256:[0-9a-f]{64}$ ]] \
      || { echo deployed_execution_runtime_identity_invalid >&2; exit 1; }
    [[ "$acceptance_source_id" == "$expected_acceptance_source_id" ]] \
      || { echo secure_enclave_acceptance_source_identity_mismatch >&2; exit 1; }
    [[ "$acceptance_runtime_image" == "$(jq -er .deployed_runtime_image "$state")" ]] \
      || { echo secure_enclave_acceptance_runtime_identity_mismatch >&2; exit 1; }
    acceptance_run_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    acceptance_session_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    acceptance_attempt_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    acceptance_code_sha256="$(printf '%s' "$acceptance_code" | shasum -a 256 | awk '{print $1}')"
    acceptance_fixture_sha256=4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945
    acceptance_draft="$(jq -ncS --argjson prepared "$prepared" \
      --arg acceptance_attempt_id "$acceptance_attempt_id" \
      --arg run_id "$acceptance_run_id" --arg session_id "$acceptance_session_id" \
      --arg source_id "$acceptance_source_id" --arg code_sha256 "$acceptance_code_sha256" \
      --arg fixture_manifest_sha256 "$acceptance_fixture_sha256" \
      --arg runtime_image_id "$acceptance_runtime_image" \
      '{transaction_id:$prepared.transaction_id,generation_id:$prepared.generation_id,generation_epoch:$prepared.generation_epoch,acceptance_attempt_id:$acceptance_attempt_id,acceptance_attempt_number:1,previous_acceptance_binding_sha256:null,run_id:$run_id,session_id:$session_id,source_id:$source_id,code_sha256:$code_sha256,fixture_manifest_sha256:$fixture_manifest_sha256,timeout_seconds:5,runtime_image_id:$runtime_image_id}')"
    state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
    jq -S --argjson draft "$acceptance_draft" '.planned_acceptance_draft=$draft' \
      "$state" > "$state_tmp"
    chmod 600 "$state_tmp"
    durable_replace "$state_tmp" "$state"
    materialize_initial_acceptance_draft
    acceptance_core="$(jq -cS .planned_acceptance "$state")"
    acceptance_recorded_at="$(jq -er .planned_acceptance_recorded_at "$state")"
  fi
  acceptance_run_id="$(jq -er .run_id <<<"$acceptance_core")"
  acceptance_session_id="$(jq -er .session_id <<<"$acceptance_core")"
  acceptance_attempt_id="$(jq -er .acceptance_attempt_id <<<"$acceptance_core")"
  acceptance_source_id="$(jq -er .source_id <<<"$acceptance_core")"
  acceptance_code_sha256="$(jq -er .code_sha256 <<<"$acceptance_core")"
  acceptance_fixture_sha256="$(jq -er .fixture_manifest_sha256 <<<"$acceptance_core")"
  acceptance_runtime_image="$(jq -er .runtime_image_id <<<"$acceptance_core")"
  acceptance_expires_at="$(jq -er .expires_at <<<"$acceptance_core")"
  while true; do
    if jq -e '.planned_acceptance_host_authorization != null' "$state" >/dev/null; then
      host_acceptance_authorization="$(jq -cS .planned_acceptance_host_authorization "$state")"
      persist_initial_host_authorization "$acceptance_core" "$host_acceptance_authorization"
      break
    fi
    host_acceptance_authorization="$($broker request \
      --agent "$requesting_agent" --session "$requesting_session" \
      --purpose "Authorize the first exact migration acceptance attempt" \
      --resource /usr/local/var/lib/secure-sandbox/execution-approval \
      --operation execution-approval-migration-authorize-acceptance \
      --parameters-json "$(jq -ncS --arg transaction_id "$transaction_id" --argjson acceptance "$acceptance_core" '{transaction_id:$transaction_id,acceptance:$acceptance}')")"
    if [[ "$(jq -er .status <<<"$host_acceptance_authorization")" == not_issued_expired ]]; then
      echo "The checkpointed attempt expired before Host issuance; replacing that unissued plan."
      finalize_draft_gateway_lease "$acceptance_run_id"
      acceptance_draft="$(jq -ncS --argjson prior "$acceptance_core" \
        --arg acceptance_attempt_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
        --arg run_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
        --arg session_id "$(uuidgen | tr '[:upper:]' '[:lower:]')" \
        '$prior | del(.expires_at) | .acceptance_attempt_id=$acceptance_attempt_id | .run_id=$run_id | .session_id=$session_id')"
      state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
      jq -S --argjson draft "$acceptance_draft" \
        '.planned_acceptance_draft=$draft
         | del(.planned_acceptance,.planned_acceptance_recorded_at,.planned_acceptance_gateway_lease,.planned_acceptance_host_authorization)' \
        "$state" > "$state_tmp"
      chmod 600 "$state_tmp"
      durable_replace "$state_tmp" "$state"
      materialize_initial_acceptance_draft
      acceptance_core="$(jq -cS .planned_acceptance "$state")"
      acceptance_recorded_at="$(jq -er .planned_acceptance_recorded_at "$state")"
      acceptance_run_id="$(jq -er .run_id <<<"$acceptance_core")"
      acceptance_session_id="$(jq -er .session_id <<<"$acceptance_core")"
      acceptance_attempt_id="$(jq -er .acceptance_attempt_id <<<"$acceptance_core")"
      acceptance_source_id="$(jq -er .source_id <<<"$acceptance_core")"
      acceptance_code_sha256="$(jq -er .code_sha256 <<<"$acceptance_core")"
      acceptance_fixture_sha256="$(jq -er .fixture_manifest_sha256 <<<"$acceptance_core")"
      acceptance_runtime_image="$(jq -er .runtime_image_id <<<"$acceptance_core")"
      acceptance_expires_at="$(jq -er .expires_at <<<"$acceptance_core")"
      continue
    fi
    persist_initial_host_authorization "$acceptance_core" "$host_acceptance_authorization"
    break
  done
  jq -nS --argjson prepared "$prepared" --arg host_release_id "$host_release_id" \
    --arg research_release_id "$research_release_id" --arg run_id "$acceptance_run_id" \
    --arg session_id "$acceptance_session_id" --arg source_id "$acceptance_source_id" \
    --arg code_sha256 "$acceptance_code_sha256" \
    --arg fixture_manifest_sha256 "$acceptance_fixture_sha256" \
    --arg runtime_image_id "$acceptance_runtime_image" \
    --arg acceptance_attempt_id "$acceptance_attempt_id" \
    --argjson host_acceptance_authorization "$host_acceptance_authorization" \
    --argjson recorded_at "$acceptance_recorded_at" --argjson expires_at "$acceptance_expires_at" \
    '{schema:"secure-sandbox-execution-approval-transition-v2",phase:"acceptance",transaction_id:$prepared.transaction_id,generation_id:$prepared.generation_id,generation_epoch:$prepared.generation_epoch,previous_generation_id:$prepared.previous_generation_id,previous_generation_epoch:$prepared.previous_generation_epoch,operator_uid:$prepared.operator_uid,algorithm:$prepared.algorithm,public_key_spki_der_b64:$prepared.public_key_spki_der_b64,public_key_sha256:$prepared.public_key_sha256,host_release_id:$host_release_id,research_release_id:$research_release_id,expected_prior_phase:"active",recorded_at:$recorded_at,run_id:$run_id,session_id:$session_id,source_id:$source_id,code_sha256:$code_sha256,fixture_manifest_sha256:$fixture_manifest_sha256,timeout_seconds:5,runtime_image_id:$runtime_image_id,expires_at:$expires_at,acceptance_attempt_id:$acceptance_attempt_id,acceptance_attempt_number:1,previous_acceptance_binding_sha256:null,host_acceptance_authorization:$host_acceptance_authorization}' \
    > "$temporary/transition-acceptance.json"
  acceptance="$(jq -ncS --arg run_id "$acceptance_run_id" --arg session_id "$acceptance_session_id" \
    --arg source_id "$acceptance_source_id" --arg code "$acceptance_code" \
    --arg acceptance_attempt_id "$acceptance_attempt_id" --argjson expires_at "$acceptance_expires_at" \
    '{run_id:$run_id,session_id:$session_id,source_id:$source_id,code:$code,fixture_paths:[],timeout_seconds:5,expires_at:$expires_at,acceptance_attempt_id:$acceptance_attempt_id,acceptance_attempt_number:1}')"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson record "$(jq -cS . "$temporary/transition-acceptance.json")" \
    --argjson acceptance "$acceptance" \
    '.stage="acceptance_record_ready" | .acceptance_record=$record | .acceptance=$acceptance
     | .acceptance_gateway_lease=.planned_acceptance_gateway_lease
     | del(.planned_acceptance,.planned_acceptance_recorded_at,.planned_acceptance_draft,.planned_acceptance_gateway_lease,.planned_acceptance_host_authorization)' \
    "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
  current_stage=acceptance_record_ready
else
  jq -cS .acceptance_record "$state" > "$temporary/transition-acceptance.json"
fi

if (( $(stage_rank "$current_stage") < 7 )); then
  echo "DDD 8/9  Issue the exact permit while general admission stays fenced"
  research_acceptance="$(deploy_transition "$temporary/transition-acceptance.json")"
  checkpoint_merge awaiting_host_reboot research_acceptance "$(jq -cS . <<<"$research_acceptance")"
fi

echo "DDD 9/9  Verify and stop at the restart-safe checkpoint"
scripts/verify-boundaries.sh
echo "secure-enclave-execution-approval-ddd:awaiting-real-host-reboot"
echo "The migration is active but uncommitted; the revoked software key has NOT been deleted."
echo "Before restarting: quit the Parallels Desktop GUI, keep it closed, then run:"
printf '  cd %q\n' "$root_dir"
echo "  ./scripts/labctl stop"
echo "Restart only after its final verified record reports gateway, research, and target all stopped."
echo "After restart, run the reviewed resume command supplied by Codex."
