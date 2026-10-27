#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
requesting_agent="Codex"
requesting_session="privileged-workflow-transaction-engine-ddd-live"
while (($#)); do
  case "$1" in
    --requesting-agent) (($# >= 2)) || exit 2; requesting_agent="$2"; shift 2 ;;
    --requesting-session) (($# >= 2)) || exit 2; requesting_session="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
cd "$root_dir"

echo "DDD 1/5  Deploy the reviewed immutable Host release"
python3 scripts/deploy-host-controller.py deploy \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --purpose "Deploy the reusable privileged workflow transaction engine"

echo "DDD 2/5  Republish the exact typed control plane"
python3 scripts/privileged-control-operation.py deploy

echo "DDD 3/5  Install the engine and run isolated role-local recovery gates"
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
for role in gateway research target; do
  "$control_client" client --ssh-config "$ssh_config" "sandbox-$role-control" \
    deploy install-privileged-workflow-engine.sh "$role" \
    --file "$root_dir/shared/privileged_workflow.py" \
    --file "$root_dir/scripts/privileged_workflow_live_verifier.py" \
    --file "$root_dir/scripts/update-policy-hash.sh" \
    --file "$root_dir/scripts/install-privileged-workflow-engine.sh"
done

echo "DDD 4/5  Synchronize isolated guest clocks"
scripts/sync-lab-time.sh --apply

echo "DDD 5/5  Verify the complete live boundary"
scripts/verify-boundaries.sh
echo "privileged-workflow-transaction-engine-ddd:deployed-and-boundary-verified"
