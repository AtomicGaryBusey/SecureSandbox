#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
requesting_agent="Codex"
requesting_session="local-broker-protocol-hardening-ddd-live"
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

echo "DDD 1/7  Deploy the reviewed immutable Host release"
python3 scripts/deploy-host-controller.py deploy \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --purpose "Deploy bounded local broker protocols"

echo "DDD 2/7  Republish the exact typed control plane"
python3 scripts/privileged-control-operation.py deploy

echo "DDD 3/7  Deploy Gateway and Research brokers transactionally"
scripts/deploy-run-leases.sh

echo "DDD 4/7  Deploy the bounded Target execution listener"
scripts/deploy-disposable-execution.sh

echo "DDD 5/7  Synchronize isolated guest clocks"
scripts/sync-lab-time.sh --apply

echo "DDD 6/7  Exercise live slow-peer fairness without retaining content"
control_client="/usr/local/libexec/secure-sandbox-host/current/control_client"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-local-broker-protocol-live-verifier.sh \
  --file "$root_dir/scripts/local_broker_protocol_live_verifier.py" \
  --file "$root_dir/scripts/install-local-broker-protocol-live-verifier.sh"

echo "DDD 7/7  Verify the complete live boundary"
scripts/verify-boundaries.sh
echo "local-broker-protocol-hardening-ddd:deployed-and-boundary-verified"
