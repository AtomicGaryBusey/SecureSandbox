#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo root_required >&2; exit 1; }
[[ "$#" -eq 6 ]] || { echo "usage: source-id entrypoint-symbol entrypoint-file target-symbol target-file max-depth" >&2; exit 2; }
[[ -f /tmp/verify-codegraph-findings-ergonomics-live.py \
   && ! -L /tmp/verify-codegraph-findings-ergonomics-live.py ]] \
  || { echo verifier_invalid >&2; exit 2; }
[[ ! -e /run/secure-sandbox/run-id \
   && ! -e /run/secure-sandbox/evidence-run-id \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] \
  || { echo agent_lifecycle_not_idle >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo claude_process_active >&2; exit 1; }
env PYTHONPATH=/usr/local/libexec/secure-sandbox \
  /usr/bin/python3 /tmp/verify-codegraph-findings-ergonomics-live.py analyze "$@"
