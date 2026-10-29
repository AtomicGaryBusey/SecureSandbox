#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo root_required >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] \
  || { echo agent_lifecycle_not_idle >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo claude_process_active >&2; exit 1; }
[[ -f /tmp/verify-receipt-pointer-findings-live.py \
   && ! -L /tmp/verify-receipt-pointer-findings-live.py ]] \
  || { echo verifier_payload_invalid >&2; exit 1; }

PYTHONPATH=/usr/local/libexec/secure-sandbox \
  /usr/bin/python3 /tmp/verify-receipt-pointer-findings-live.py
