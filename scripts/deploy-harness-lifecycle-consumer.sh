#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
client=/usr/local/libexec/secure-sandbox-host/current/control_client
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
