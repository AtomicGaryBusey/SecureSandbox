#!/bin/bash
set -euo pipefail

if (( $# != 2 )); then
  echo "Usage: verify-azure-evidence.sh SUBSCRIPTION_ID WORKSPACE_CUSTOMER_ID" >&2
  exit 2
fi

subscription_id="$1"
workspace_id="$2"
query='let Recent = SecureSandbox_CL | extend ObservedAt=coalesce(ingestion_time(), TimeGenerated) | where ObservedAt > ago(30m); union (Recent | where VmId == "gateway" and EventType == "heartbeat" | summarize Count=count() | extend Check="gateway_heartbeat"), (Recent | where VmId == "research" and EventType == "heartbeat" | summarize Count=count() | extend Check="research_heartbeat"), (Recent | where VmId == "research" and Decision == "deny" | summarize Count=count() | extend Check="research_deny") | project Check, Count'
# Azure can cache identical Log Analytics queries briefly. A comment-only nonce
# keeps each acceptance check fresh without changing query semantics.
query+=" // verification $(date -u +%s)"

result="$(az monitor log-analytics query \
  --subscription "$subscription_id" \
  --workspace "$workspace_id" \
  --analytics-query "$query" \
  --output json)"

for expected in gateway_heartbeat research_heartbeat research_deny; do
  if jq -e --arg expected "$expected" \
    'any(.[]; .Check == $expected and (.Count | tonumber) > 0)' \
    <<<"$result" >/dev/null; then
    echo "PASS  Azure contains recent $expected evidence"
  else
    echo "FAIL  Azure does not yet contain recent $expected evidence" >&2
    exit 1
  fi
done

echo "AZURE EVIDENCE VERIFICATION PASSED"
