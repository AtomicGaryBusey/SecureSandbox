#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
client=/usr/local/libexec/secure-sandbox-host/current/control_client
control_public_key="$root_dir/runs/control_key.pub"
for path in "$control_public_key" "$root_dir/scripts/install-privileged-control.sh" \
  "$root_dir/scripts/privileged_control.py" "$root_dir/scripts/privileged_control_entry.py" \
  "$root_dir/config/privileged-control.sudoers" "$root_dir/config/sshd-control.conf"; do
  [[ -f "$path" && ! -L "$path" ]] || { echo "control deployment source invalid: $path" >&2; exit 2; }
done
# Install the exact dispatcher revision first; the predecessor dispatcher does
# not and must not recognize the new lifecycle operations.
control_result="$("$client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-privileged-control.sh research /tmp/control_key.pub \
  --file "$root_dir/scripts/install-privileged-control.sh" \
  --file "$root_dir/scripts/privileged_control.py" \
  --file "$root_dir/scripts/privileged_control_entry.py" \
  --file "$root_dir/config/privileged-control.sudoers" \
  --file "$root_dir/config/sshd-control.conf" --file "$control_public_key")"
[[ "$control_result" == "privileged-control:installed:research" ]] || exit 1
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_id="harness-lifecycle-consumer-$stamp-$$"
result="$("$client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-harness-lifecycle-consumer.sh \
  /tmp/harness_generation_manager.py /tmp/harness-generation.py \
  /tmp/harness_generation_store.py /tmp/privileged_workflow.py \
  /tmp/harness_runtime_binding.py /tmp/rollback-harness-lifecycle-consumer.sh "$backup_id" \
  --file "$root_dir/research/harness_generation_manager.py" \
  --file "$root_dir/scripts/harness-generation.py" \
  --file "$root_dir/shared/harness_generation_store.py" \
  --file "$root_dir/shared/privileged_workflow.py" \
  --file "$root_dir/shared/harness_runtime_binding.py" \
  --file "$root_dir/research/rollback-harness-lifecycle-consumer.sh" \
  --file "$root_dir/scripts/install-harness-lifecycle-consumer.sh")"
[[ "$result" == "harness-lifecycle-consumer:installed:$backup_id" ]] || exit 1
printf '%s\n' "$result"
