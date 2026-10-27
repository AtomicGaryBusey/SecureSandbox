#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo root_required >&2; exit 1; }
action="${1:-}"
manager="${2:-/tmp/execution_approval_transition.py}"
[[ "$action" == apply || "$action" == verify || "$action" == verify-acceptance || "$action" == verify-negative ]] || { echo transition_action_invalid >&2; exit 2; }
[[ -f "$manager" && ! -L "$manager" ]] || { echo transition_artifact_missing >&2; exit 2; }
python3 -m py_compile "$manager"
install -o root -g root -m 755 "$manager" /usr/local/libexec/secure-sandbox/execution_approval_transition.py
if [[ "$action" == apply || "$action" == verify-acceptance ]]; then
  record="${3:-/tmp/execution-approval-transition.json}"
  [[ -f "$record" && ! -L "$record" ]] || { echo transition_record_missing >&2; exit 2; }
  /usr/local/libexec/secure-sandbox/execution_approval_transition.py "$action" --record "$record"
  rm -f -- "$record"
else
  approval="${3:-/tmp/execution-approval-test-request.json}"
  envelope="${4:-/tmp/execution-approval-test-envelope.json}"
  [[ -f "$approval" && ! -L "$approval" && -f "$envelope" && ! -L "$envelope" ]] \
    || { echo transition_verification_input_missing >&2; exit 2; }
  /usr/local/libexec/secure-sandbox/execution_approval_transition.py "$action" \
    --approval "$approval" --envelope "$envelope"
  rm -f -- "$approval" "$envelope"
fi
