#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id ]] \
  || { echo "active agent run or boundary verification" >&2; exit 1; }
[[ ! -e /var/lib/secure-sandbox/run-lifecycle/active.json \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] \
  || { echo "unreconciled run lifecycle" >&2; exit 1; }
verifier="${1:-/tmp/local_broker_protocol_live_verifier.py}"
[[ -f "$verifier" && ! -L "$verifier" ]] || { echo "Invalid verifier." >&2; exit 2; }
python3 -m py_compile "$verifier"
exec python3 "$verifier"
