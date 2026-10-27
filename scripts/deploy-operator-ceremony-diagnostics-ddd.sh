#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
requesting_agent="Codex"
requesting_session="operator-ceremony-diagnostics-ddd-live"
while (($#)); do
  case "$1" in
    --requesting-agent) (($# >= 2)) || exit 2; requesting_agent="$2"; shift 2 ;;
    --requesting-session) (($# >= 2)) || exit 2; requesting_session="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
cd "$root_dir"
temporary="$(mktemp -d /tmp/secure-sandbox-operator-ceremony.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT

echo "DDD 1/5  Deploy the reviewed ceremony-bound Host release"
python3 scripts/deploy-host-controller.py deploy \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --purpose "Deploy unambiguous operator ceremonies and content-free diagnostics"

echo "DDD 2/5  Approve the explicit side-effect-free approval ceremony"
python3 scripts/touchid-authorization-probe.py \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --purpose "APPROVE: verify the explicit approval ceremony" \
  --ceremony approve

echo "DDD 3/5  Cancel the explicit cancellation ceremony"
set +e
python3 scripts/touchid-authorization-probe.py \
  --requesting-agent "$requesting_agent" \
  --requesting-session "$requesting_session" \
  --purpose "CANCEL: verify the cancellation-only ceremony" \
  --ceremony cancel-test \
  > "$temporary/cancel.stdout" 2> "$temporary/cancel.stderr"
cancel_status=$?
set -e
[[ "$cancel_status" -eq 1 && ! -s "$temporary/cancel.stdout" ]] \
  || { echo cancellation_ceremony_result_invalid >&2; exit 1; }
python3 scripts/validate-operator-diagnostic.py \
  --path "$temporary/cancel.stderr" \
  --code operator_cancelled \
  --operation authorization-probe \
  --outcome cancelled \
  --retry new-request \
  --action start_new_request_when_ready

echo "DDD 4/5  Verify automated ceremony and diagnostic contracts"
python3 -m unittest \
  scripts.test_operator_authorization \
  scripts.test_validate_operator_diagnostic \
  scripts.test_validate_secure_enclave_finalization \
  scripts.test_verify_secure_enclave_execution_approval_ddd

echo "DDD 5/5  Verify the complete live boundary"
scripts/verify-boundaries.sh
echo "operator-ceremony-diagnostics-ddd:deployed-and-boundary-verified"
