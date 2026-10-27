#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
requesting_agent="Codex"
requesting_session="secure-enclave-execution-approval-ddd-forward-rotation"
ddd_config="${SECURE_SANDBOX_DDD_CONFIG:-$root_dir/.private/secure-enclave-ddd.json}"
acceptance_source_id="$(python3 scripts/secure_enclave_ddd_support.py \
  local-config-field --path "$ddd_config" --field acceptance_source_id)"
while (($#)); do
  case "$1" in
    --requesting-agent) requesting_agent="$2"; shift 2 ;;
    --requesting-session) requesting_session="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

state_dir="$root_dir/.private/secure-enclave-execution-approval-ddd"
state="$state_dir/state.json"
history_root="$root_dir/.private/secure-enclave-execution-approval-ddd-history"
handoff="$history_root/forward-rotation-handoff.json"
source_release="$(python3 scripts/secure_enclave_ddd_support.py \
  source-host-release-id --repo "$root_dir")"
[[ "$source_release" =~ ^[0-9a-f]{64}$ ]] \
  || { echo source_host_release_identity_invalid >&2; exit 1; }

durable_replace() {
  /usr/bin/python3 -c 'import os,sys; source,target=sys.argv[1:]; fd=os.open(source,os.O_RDONLY); os.fsync(fd); os.close(fd); os.replace(source,target); directory=os.open(os.path.dirname(target),os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)' "$1" "$2"
}

if [[ -e "$state" || -L "$state" ]]; then
  [[ -f "$state" && ! -L "$state" \
      && "$(stat -f '%Su:%Sp' "$state")" == "$(id -un):-rw-------" ]] \
    || { echo secure_enclave_ddd_checkpoint_untrusted >&2; exit 1; }
fi

if [[ -f "$state" ]] \
    && [[ "$(jq -r .stage "$state")" == bridge_committed ]]; then
  echo "ROTATION 1/3  Publish the fixed LaunchServices/result-channel Host release"
  current_release="$(basename "$(readlink /usr/local/libexec/secure-sandbox-host/current)")"
  if [[ "$current_release" != "$source_release" ]]; then
    deployment="$(python3 scripts/operator-authorization.py request \
      --agent "$requesting_agent" --session "$requesting_session" \
      --purpose "Deploy the fixed authorization UI before forward key rotation" \
      --resource /usr/local/libexec/secure-sandbox-host \
      --operation host-controller-install \
      --parameters-json "$(jq -ncS --arg repo "$root_dir" \
        --arg state_root "$HOME/Library/Application Support/SecureSandbox/controller-state" \
        --arg expected "$source_release" \
        '{repo:$repo,state_root:$state_root,expected_source_release_id:$expected}')")"
    jq -e --arg expected "$source_release" \
      '.schema == "secure-sandbox-host-controller-release-v1" and .status == "deployed" and .release_id == $expected' \
      <<<"$deployment" >/dev/null
  fi
  python3 scripts/secure_enclave_ddd_support.py verify-postactivation-host-release \
    --repo "$root_dir" --install-root /usr/local/libexec/secure-sandbox-host \
    --launcher /usr/local/bin/secure-sandbox-claude >/dev/null

  echo "ROTATION 2/3  Archive the committed bridge checkpoint without deleting it"
  mkdir -p "$history_root"
  chmod 700 "$history_root"
  transaction_id="$(jq -er .prepared.transaction_id "$state")"
  generation_id="$(jq -er .prepared.generation_id "$state")"
  archive="$history_root/$transaction_id.bridge"
  handoff_tmp="$(mktemp "$history_root/.handoff.XXXXXX")"
  jq -nS --arg transaction_id "$transaction_id" --arg generation_id "$generation_id" \
    --arg source_release "$source_release" --arg requesting_agent "$requesting_agent" \
    --arg requesting_session "$requesting_session" --argjson recorded_at "$(date +%s)" \
    '{schema:"secure-sandbox-secure-enclave-forward-rotation-handoff-v1",bridge_transaction_id:$transaction_id,bridge_generation_id:$generation_id,source_host_release_id:$source_release,requesting_agent:$requesting_agent,requesting_session:$requesting_session,recorded_at:$recorded_at}' \
    > "$handoff_tmp"
  chmod 600 "$handoff_tmp"
  durable_replace "$handoff_tmp" "$handoff"
  python3 scripts/secure_enclave_ddd_support.py archive-bridge-checkpoint \
    --state-dir "$state_dir" --archive "$archive" >/dev/null
elif [[ -f "$state" && ! -L "$state" ]]; then
  jq -e --arg session "$requesting_session" \
    '.schema == "secure-sandbox-secure-enclave-ddd-checkpoint-v1" and .requesting_session == $session and .prepared.previous_generation_id != null' \
    "$state" >/dev/null \
    || { echo secure_enclave_rotation_checkpoint_conflict >&2; exit 1; }
else
  [[ -f "$handoff" && ! -L "$handoff" \
      && "$(stat -f '%Su:%Sp' "$handoff")" == "$(id -un):-rw-------" ]] \
    || { echo secure_enclave_rotation_handoff_missing >&2; exit 1; }
  jq -e --arg source "$source_release" --arg agent "$requesting_agent" \
    --arg session "$requesting_session" \
    '.schema == "secure-sandbox-secure-enclave-forward-rotation-handoff-v1"
     and .source_host_release_id == $source and .requesting_agent == $agent
     and .requesting_session == $session' "$handoff" >/dev/null \
    || { echo secure_enclave_rotation_handoff_conflict >&2; exit 1; }
fi

echo "ROTATION 3/3  Begin or resume the explicit forward key-rotation transaction"
exec "$root_dir/scripts/deploy-secure-enclave-execution-approval-ddd.sh" \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --acceptance-source-id "$acceptance_source_id"
