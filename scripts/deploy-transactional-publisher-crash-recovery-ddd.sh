#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
requesting_agent="Codex"
requesting_session="transactional-publisher-crash-recovery-ddd-live"
while (($#)); do
  case "$1" in
    --requesting-agent) (($# >= 2)) || exit 2; requesting_agent="$2"; shift 2 ;;
    --requesting-session) (($# >= 2)) || exit 2; requesting_session="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
export SECURE_SANDBOX_REQUESTING_AGENT="$requesting_agent"
export SECURE_SANDBOX_REQUESTING_SESSION="$requesting_session"
cd "$root_dir"

echo "DDD 1/6  Deploy the reviewed immutable Host release"
python3 scripts/deploy-host-controller.py deploy \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --purpose "Deploy crash-recoverable transactional publishers"

echo "DDD 2/6  Republish the exact typed control plane"
python3 scripts/privileged-control-operation.py deploy

echo "DDD 3/6  Deploy Gateway and Research publishers transactionally"
scripts/deploy-run-leases.sh

echo "DDD 4/6  Synchronize isolated guest clocks"
scripts/sync-lab-time.sh --apply

echo "DDD 5/6  Exercise content-free live crash recovery"
control_client="/usr/local/libexec/secure-sandbox-host/current/control_client"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
for role in gateway research; do
  "$control_client" client --ssh-config "$ssh_config" "sandbox-$role-control" \
    deploy install-transactional-publisher-live-verifier.sh "$role" \
    --file "$root_dir/scripts/transactional_publisher_live_verifier.py" \
    --file "$root_dir/scripts/install-transactional-publisher-live-verifier.sh"
done

echo "DDD 6/6  Verify the complete live boundary"
scripts/verify-boundaries.sh
echo "transactional-publisher-crash-recovery-ddd:deployed-and-boundary-verified"
