#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
requesting_agent="Codex"
requesting_session="request-bound-execution-ddd-live"

while (($#)); do
  case "$1" in
    --requesting-agent)
      (($# >= 2)) || { echo "--requesting-agent requires a value" >&2; exit 2; }
      requesting_agent="$2"; shift 2 ;;
    --requesting-session)
      (($# >= 2)) || { echo "--requesting-session requires a value" >&2; exit 2; }
      requesting_session="$2"; shift 2 ;;
    *)
      echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

export SECURE_SANDBOX_REQUESTING_AGENT="$requesting_agent"
export SECURE_SANDBOX_REQUESTING_SESSION="$requesting_session"

cd "$root_dir"
echo "DDD 1/7  Deploy protected host approval authority and signed Touch ID UI"
python3 scripts/deploy-host-controller.py deploy \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --purpose "Deploy request-bound disposable-execution approval"

echo "DDD 2/7  Republish the exact typed control plane to every guest"
python3 scripts/privileged-control-operation.py deploy

echo "DDD 3/7  Losslessly archive aged control receipts while preserving replay detection"
control_client="/usr/local/libexec/secure-sandbox-host/current/control_client"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
for destination in sandbox-gateway-control sandbox-research-control sandbox-target-control; do
  "$control_client" client --ssh-config "$ssh_config" "$destination" run control-receipts-archive
done

echo "DDD 4/7  Deploy exact run/session lifecycle binding"
scripts/deploy-run-leases.sh

echo "DDD 5/7  Deploy pinned approval verifier and independently contained Target runtime"
scripts/deploy-disposable-execution.sh

echo "DDD 6/7  Synchronize isolated guest clocks before freshness verification"
scripts/sync-lab-time.sh --apply

echo "DDD 7/7  Verify the complete live boundary"
scripts/verify-boundaries.sh

echo "request-bound-execution-approval-ddd:deployed-and-boundary-verified"
