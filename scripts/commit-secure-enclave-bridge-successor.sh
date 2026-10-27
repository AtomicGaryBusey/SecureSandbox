#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
state="$root_dir/.private/secure-enclave-execution-approval-ddd/state.json"
legacy_ui_bundle="$(python3 scripts/secure_enclave_ddd_support.py local-config-field \
  --path "$root_dir/.private/secure-enclave-ddd.json" \
  --field legacy_launchservices_ui_bundle_sha256)"
[[ -f "$state" && ! -L "$state" \
    && "$(stat -f '%Su:%Sp' "$state")" == "$(id -un):-rw-------" ]] \
  || { echo secure_enclave_ddd_checkpoint_untrusted >&2; exit 1; }
jq -e '
  .schema == "secure-sandbox-secure-enclave-ddd-checkpoint-v1"
  and .stage == "research_acceptance_verified"
  and .cold_boot_evidence != null
  and .host_acceptance_verifier != null
  and .negative_gates != null
  and .committed_record != null
' "$state" >/dev/null || { echo bridge_successor_checkpoint_invalid >&2; exit 1; }

durable_replace() {
  /usr/bin/python3 -c 'import os,sys; source,target=sys.argv[1:]; fd=os.open(source,os.O_RDONLY); os.fsync(fd); os.close(fd); os.replace(source,target); directory=os.open(os.path.dirname(target),os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)' "$1" "$2"
}

source_release="$(python3 scripts/secure_enclave_ddd_support.py \
  source-host-release-id --repo "$root_dir")"
current_release="$(basename "$(readlink /usr/local/libexec/secure-sandbox-host/current)")"
verifier="$(jq -cS .host_acceptance_verifier "$state")"
verifier_unsigned="$(jq -cS 'del(.verifier_sha256)' <<<"$verifier")"
verifier_sha256="$(printf '%s' "$verifier_unsigned" | shasum -a 256 | awk '{print $1}')"
[[ "$verifier_sha256" == "$(jq -er .verifier_sha256 <<<"$verifier")" ]] \
  || { echo bridge_successor_verifier_digest_mismatch >&2; exit 1; }
jq -e '.status == "verified" and .wrong_key_rejected and .replay_rejected' \
  <<<"$(jq -cS .negative_gates "$state")" >/dev/null \
  || { echo bridge_successor_negative_gates_invalid >&2; exit 1; }
if jq -e '.bridge_successor_deployment == null' "$state" >/dev/null; then
  predecessor_release="$(jq -er .prepared.host_release_id "$state")"
  evidence="$(jq -cS .cold_boot_evidence "$state")"
  jq -e --arg predecessor "$predecessor_release" '
    .schema == "secure-sandbox-host-reboot-acceptance-v1"
    and .bridge_predecessor_exception == true
    and .checkpoint_host_verification.status == "verified"
    and .checkpoint_host_verification.release_id == $predecessor
    and .checkpoint_research_verification.status == "verified"
    and .checkpoint_research_verification.receipt_boundary_verified == true
    and .bridge_successor_deployment == null
    and .bridge_successor_release_id == null
    and .bridge_successor_deployment_sha256 == null
  ' <<<"$evidence" >/dev/null \
    || { echo bridge_predecessor_evidence_invalid >&2; exit 1; }
  [[ "$(printf '%s' "$evidence" | shasum -a 256 | awk '{print $1}')" \
      == "$(jq -er .cold_boot_acceptance_sha256 "$state")" ]] \
    || { echo bridge_predecessor_evidence_digest_mismatch >&2; exit 1; }

  if [[ "$current_release" == "$predecessor_release" ]]; then
    python3 scripts/secure_enclave_ddd_support.py verify-checkpoint-host-release \
      --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
      --launcher /usr/local/bin/secure-sandbox-claude \
      --expected-release-id "$predecessor_release" \
      --expected-generation-id "$(jq -er .prepared.generation_id "$state")" \
      --expected-generation-epoch "$(jq -er .prepared.generation_epoch "$state")" \
      --expected-public-key-sha256 "$(jq -er .prepared.public_key_sha256 "$state")" \
      --expected-ui-bundle-sha256 "$legacy_ui_bundle" \
      >/dev/null
    echo "BRIDGE PREPARE 1/2  Deploy the reviewed retry-aware Host successor"
    requesting_agent="$(jq -er .requesting_agent "$state")"
    requesting_session="$(jq -er .requesting_session "$state")"
    deployment="$(python3 scripts/operator-authorization.py request \
      --agent "$requesting_agent" --session "$requesting_session" \
      --purpose "Advance the verified checkpoint predecessor to the retry-aware bridge successor" \
      --resource /usr/local/libexec/secure-sandbox-host \
      --operation host-controller-install \
      --parameters-json "$(jq -ncS --arg repo "$root_dir" \
        --arg state_root "$HOME/Library/Application Support/SecureSandbox/controller-state" \
        --arg expected "$source_release" \
        '{repo:$repo,state_root:$state_root,expected_source_release_id:$expected}')")"
  elif [[ "$current_release" == "$source_release" ]]; then
    echo "BRIDGE PREPARE 1/2  Recover the already-deployed exact Host successor"
    installed_verification="$(python3 scripts/secure_enclave_ddd_support.py verify-postactivation-host-release \
      --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
      --launcher /usr/local/bin/secure-sandbox-claude)"
    deployment="$(jq -cS '
      {schema:"secure-sandbox-host-controller-release-v1",status:"already_deployed",release_id:.release_id,launcher_sha256:.launcher_sha256,payloads:.payloads}
    ' <<<"$installed_verification")"
  else
    echo bridge_predecessor_release_mismatch >&2
    exit 1
  fi
  jq -e --arg expected "$source_release" '
    .schema == "secure-sandbox-host-controller-release-v1"
    and (.status == "deployed" or .status == "already_deployed")
    and .release_id == $expected
  ' <<<"$deployment" >/dev/null \
    || { echo bridge_successor_deployment_invalid >&2; exit 1; }
  python3 scripts/secure_enclave_ddd_support.py verify-postactivation-host-release \
    --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
    --launcher /usr/local/bin/secure-sandbox-claude >/dev/null

  deployment="$(jq -cS . <<<"$deployment")"
  deployment_sha256="$(printf '%s\n' "$deployment" | shasum -a 256 | awk '{print $1}')"
  evidence="$(jq -cS --argjson deployment "$deployment" \
    --arg release_id "$source_release" --arg digest "$deployment_sha256" '
    .bridge_successor_deployment=$deployment
    | .bridge_successor_release_id=$release_id
    | .bridge_successor_deployment_sha256=$digest
  ' <<<"$evidence")"
  evidence_sha256="$(printf '%s' "$evidence" | shasum -a 256 | awk '{print $1}')"
  bridge_exception="$(jq -ncS \
    --arg predecessor_ui_bundle "$legacy_ui_bundle" \
    --argjson recorded_at "$(date +%s)" \
    '{schema:"secure-sandbox-execution-approval-bridge-exception-v1",reason:"predecessor_ui_has_no_authenticated_result_sidecar",predecessor_ui_bundle_sha256:$predecessor_ui_bundle,cancellation_gate:"mandatory_on_immediate_forward_rotation",software_key_retirement:"deferred",recorded_at:$recorded_at}')"
  state_dir="$(dirname "$state")"
  state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
  jq -S --argjson deployment "$deployment" --arg release_id "$source_release" \
    --argjson evidence "$evidence" --arg evidence_sha256 "$evidence_sha256" \
    --argjson bridge_exception "$bridge_exception" '
    .bridge_successor_deployment=$deployment
    | .bridge_successor_release_id=$release_id
    | .cold_boot_evidence=$evidence
    | .cold_boot_acceptance_sha256=$evidence_sha256
    | .bridge_exception=$bridge_exception
  ' "$state" > "$state_tmp"
  chmod 600 "$state_tmp"
  durable_replace "$state_tmp" "$state"
  echo "BRIDGE PREPARE 2/2  Successor checkpoint durably recorded"
else
  recorded_successor="$(jq -er .bridge_successor_release_id "$state")"
  recorded_live="$recorded_successor"
  repairs_count="$(jq -er '(.bridge_commit_repairs // []) | length' "$state")"
  [[ "$repairs_count" =~ ^[0-9]+$ && "$repairs_count" -le 3 ]] \
    || { echo bridge_commit_repair_chain_invalid >&2; exit 1; }
  for ((index=0; index<repairs_count; index++)); do
    repair="$(jq -cS --argjson index "$index" '.bridge_commit_repairs[$index]' "$state")"
    jq -e --arg from "$recorded_live" \
      --arg cold_boot_sha256 "$(jq -er .cold_boot_acceptance_sha256 "$state")" '
      type == "object"
      and (keys | sort) == (["deployment","deployment_sha256","from_release_id","reason","recorded_at","schema","to_release_id","protected_cold_boot_acceptance_sha256"] | sort)
      and .schema == "secure-sandbox-execution-approval-bridge-commit-repair-v1"
      and .reason == "empty_legacy_completion_directory_mode_migration"
      and .from_release_id == $from
      and .to_release_id == .deployment.release_id
      and .from_release_id != .to_release_id
      and .protected_cold_boot_acceptance_sha256 == $cold_boot_sha256
      and .deployment.schema == "secure-sandbox-host-controller-release-v1"
      and (.deployment.status == "deployed" or .deployment.status == "already_deployed")
      and (.deployment_sha256 | test("^[0-9a-f]{64}$"))
      and (.recorded_at | type == "number" and floor == . and . >= 1)
    ' <<<"$repair" >/dev/null \
      || { echo bridge_commit_repair_chain_invalid >&2; exit 1; }
    repair_deployment="$(jq -cS .deployment <<<"$repair")"
    [[ "$(printf '%s\n' "$repair_deployment" | shasum -a 256 | awk '{print $1}')" \
        == "$(jq -er .deployment_sha256 <<<"$repair")" ]] \
      || { echo bridge_commit_repair_chain_invalid >&2; exit 1; }
    recorded_live="$(jq -er .to_release_id <<<"$repair")"
  done
  if [[ "$source_release" == "$recorded_live" ]]; then
    [[ "$current_release" == "$source_release" ]] \
      || { echo bridge_successor_release_mismatch >&2; exit 1; }
  else
    [[ "$repairs_count" -lt 3 ]] \
      || { echo bridge_commit_repair_limit_exceeded >&2; exit 1; }
    if [[ "$current_release" == "$recorded_live" ]]; then
      if [[ "$repairs_count" -eq 0 ]]; then
        recorded_deployment="$(jq -cS .bridge_successor_deployment "$state")"
      else
        recorded_deployment="$(jq -cS '.bridge_commit_repairs[-1].deployment' "$state")"
      fi
      installed_verification="$(python3 scripts/secure_enclave_ddd_support.py \
        verify-installed-host-release --repo "$root_dir" \
        --install-root /usr/local/libexec/secure-sandbox-host \
        --launcher /usr/local/bin/secure-sandbox-claude \
        --expected-release-id "$recorded_live" \
        --expected-generation-id "$(jq -er .prepared.generation_id "$state")" \
        --expected-generation-epoch "$(jq -er .prepared.generation_epoch "$state")" \
        --expected-public-key-sha256 "$(jq -er .prepared.public_key_sha256 "$state")")"
      jq -e --argjson installed "$installed_verification" '
        .payloads == $installed.payloads
        and .launcher_sha256 == $installed.launcher_sha256
      ' <<<"$recorded_deployment" >/dev/null \
        || { echo bridge_recorded_successor_verification_mismatch >&2; exit 1; }
      echo "BRIDGE REPAIR 1/2  Deploy the bounded completion-directory repair release"
      requesting_agent="$(jq -er .requesting_agent "$state")"
      requesting_session="$(jq -er .requesting_session "$state")"
      deployment="$(python3 scripts/operator-authorization.py request \
        --agent "$requesting_agent" --session "$requesting_session" \
        --purpose "Install the bounded empty completion-directory mode migration" \
        --resource /usr/local/libexec/secure-sandbox-host \
        --operation host-controller-install \
        --parameters-json "$(jq -ncS --arg repo "$root_dir" \
          --arg state_root "$HOME/Library/Application Support/SecureSandbox/controller-state" \
          --arg expected "$source_release" \
          '{repo:$repo,state_root:$state_root,expected_source_release_id:$expected}')")"
    elif [[ "$current_release" == "$source_release" ]]; then
      echo "BRIDGE REPAIR 1/2  Recover the already-deployed exact repair release"
      installed_verification="$(python3 scripts/secure_enclave_ddd_support.py \
        verify-postactivation-host-release --repo "$root_dir" \
        --install-root /usr/local/libexec/secure-sandbox-host \
        --launcher /usr/local/bin/secure-sandbox-claude)"
      deployment="$(jq -cS '
        {schema:"secure-sandbox-host-controller-release-v1",status:"already_deployed",release_id:.release_id,launcher_sha256:.launcher_sha256,payloads:.payloads}
      ' <<<"$installed_verification")"
    else
      echo bridge_commit_repair_selector_mismatch >&2
      exit 1
    fi
    jq -e --arg expected "$source_release" '
      .schema == "secure-sandbox-host-controller-release-v1"
      and (.status == "deployed" or .status == "already_deployed")
      and .release_id == $expected
    ' <<<"$deployment" >/dev/null \
      || { echo bridge_commit_repair_deployment_invalid >&2; exit 1; }
    python3 scripts/secure_enclave_ddd_support.py verify-postactivation-host-release \
      --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
      --launcher /usr/local/bin/secure-sandbox-claude >/dev/null
    deployment="$(jq -cS . <<<"$deployment")"
    repair="$(jq -ncS --arg from_release_id "$recorded_live" \
      --arg to_release_id "$source_release" --argjson deployment "$deployment" \
      --arg deployment_sha256 "$(printf '%s\n' "$deployment" | shasum -a 256 | awk '{print $1}')" \
      --arg protected_cold_boot_acceptance_sha256 "$(jq -er .cold_boot_acceptance_sha256 "$state")" \
      --argjson recorded_at "$(date +%s)" \
      '{schema:"secure-sandbox-execution-approval-bridge-commit-repair-v1",reason:"empty_legacy_completion_directory_mode_migration",from_release_id:$from_release_id,to_release_id:$to_release_id,deployment:$deployment,deployment_sha256:$deployment_sha256,protected_cold_boot_acceptance_sha256:$protected_cold_boot_acceptance_sha256,recorded_at:$recorded_at}')"
    state_dir="$(dirname "$state")"
    state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
    jq -S --argjson repair "$repair" \
      '.bridge_commit_repairs=((.bridge_commit_repairs // []) + [$repair])' \
      "$state" > "$state_tmp"
    chmod 600 "$state_tmp"
    durable_replace "$state_tmp" "$state"
    echo "BRIDGE REPAIR 2/2  Repair release checkpoint durably recorded"
  fi
fi
python3 scripts/secure_enclave_ddd_support.py verify-postactivation-host-release \
  --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
  --launcher /usr/local/bin/secure-sandbox-claude >/dev/null

cold_boot_evidence="$(jq -cS .cold_boot_evidence "$state")"
cold_boot_sha256="$(printf '%s' "$cold_boot_evidence" | shasum -a 256 | awk '{print $1}')"
[[ "$cold_boot_sha256" == "$(jq -er .cold_boot_acceptance_sha256 "$state")" ]] \
  || { echo bridge_successor_cold_boot_digest_mismatch >&2; exit 1; }
requesting_agent="$(jq -er .requesting_agent "$state")"
requesting_session="$(jq -er .requesting_session "$state")"
transaction_id="$(jq -er .prepared.transaction_id "$state")"
research_acceptance="$(jq -cS .research_acceptance "$state")"

echo "BRIDGE COMMIT 1/2  Commit the successor-validated Host authority"
commit="$(python3 scripts/operator-authorization.py request \
  --agent "$requesting_agent" --session "$requesting_session" \
  --purpose "Commit the retry-aware, rebooted, end-to-end verified Secure Enclave authority" \
  --resource /usr/local/var/lib/secure-sandbox/execution-approval \
  --operation execution-approval-migration-commit \
  --parameters-json "$(jq -ncS --arg transaction_id "$transaction_id" \
    --argjson research_activation "$research_acceptance" \
    --arg cold_boot_acceptance_sha256 "$cold_boot_sha256" \
    --arg acceptance_verifier_sha256 "$verifier_sha256" \
    '{transaction_id:$transaction_id,research_activation:$research_activation,cold_boot_acceptance_sha256:$cold_boot_acceptance_sha256,acceptance_verifier_sha256:$acceptance_verifier_sha256}')")"
jq -e --arg transaction_id "$transaction_id" \
  --arg generation_id "$(jq -er .prepared.generation_id "$state")" \
  --argjson generation_epoch "$(jq -er .prepared.generation_epoch "$state")" \
  --arg cold_boot_sha256 "$cold_boot_sha256" \
  --arg verifier_sha256 "$verifier_sha256" '
  .schema == "secure-sandbox-execution-approval-migration-result-v2"
  and .status == "committed" and .transaction_id == $transaction_id
  and .generation_id == $generation_id and .generation_epoch == $generation_epoch
  and .cold_boot_acceptance_sha256 == $cold_boot_sha256
  and .acceptance_verifier_sha256 == $verifier_sha256
' <<<"$commit" >/dev/null || { echo bridge_successor_commit_invalid >&2; exit 1; }

echo "BRIDGE COMMIT 2/2  Commit Research and reopen normal admission"
temporary="$(mktemp -d /tmp/secure-sandbox-se-bridge-commit.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
jq -cS .committed_record "$state" > "$temporary/transition-committed.json"
/usr/local/libexec/secure-sandbox-host/current/control_client client \
  --ssh-config /usr/local/libexec/secure-sandbox-host/current/ssh_config \
  sandbox-research-control deploy install-execution-approval-transition.sh apply \
  /tmp/execution_approval_transition.py /tmp/transition-committed.json \
  --file "$root_dir/scripts/install-execution-approval-transition.sh" \
  --file "$root_dir/research/execution_approval_transition.py" \
  --file "$temporary/transition-committed.json"

state_dir="$(dirname "$state")"
state_tmp="$(mktemp "$state_dir/.state.XXXXXX")"
jq -S --argjson host_commit "$commit" --argjson completed_at "$(date +%s)" '
  .stage="bridge_committed"
  | .bridge_host_commit=$host_commit
  | .bridge_committed_at=$completed_at
' "$state" > "$state_tmp"
chmod 600 "$state_tmp"
durable_replace "$state_tmp" "$state"
echo secure-enclave-execution-approval-ddd:bridge-committed-for-immediate-forward-rotation
echo "The software key remains cryptographically revoked but undeleted until the fixed rotation completes."
