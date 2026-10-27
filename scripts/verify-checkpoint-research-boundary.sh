#!/bin/bash
set -euo pipefail

[[ "$#" -eq 9 ]] || { echo checkpoint_research_arguments_invalid >&2; exit 64; }
expected_release_id="$1"
source_execution_broker_sha256="$2"
source_transition_sha256="$3"
source_watchdog_sha256="$4"
source_receipts_sha256="$5"
source_corpus_broker_sha256="$6"
source_corpus_unit_sha256="$7"
source_corpus_mcp_sha256="$8"
source_execution_unit_sha256="$9"

for digest in "$expected_release_id" "$source_execution_broker_sha256" \
  "$source_transition_sha256" "$source_watchdog_sha256" \
  "$source_receipts_sha256" "$source_corpus_broker_sha256" \
  "$source_corpus_unit_sha256" "$source_corpus_mcp_sha256" \
  "$source_execution_unit_sha256"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
    || { echo checkpoint_research_digest_invalid >&2; exit 64; }
done

execution_broker=/usr/local/libexec/secure-sandbox/execution_broker.py
transition=/usr/local/libexec/secure-sandbox/execution_approval_transition.py
watchdog=/usr/local/libexec/secure-sandbox/run_lease_watchdog.py
live_execution_broker_sha256="$(sha256sum "$execution_broker" | awk '{print $1}')"
live_transition_sha256="$(sha256sum "$transition" | awk '{print $1}')"
live_watchdog_sha256="$(sha256sum "$watchdog" | awk '{print $1}')"
live_release_id="$(printf '%s\n' "$live_execution_broker_sha256" \
  "$live_transition_sha256" "$live_watchdog_sha256" | xxd -r -p | \
  sha256sum | awk '{print $1}')"

[[ "$live_release_id" == "$expected_release_id" ]] \
  || { echo checkpoint_research_release_mismatch >&2; exit 1; }
[[ "$live_transition_sha256" == "$source_transition_sha256" \
    && "$live_watchdog_sha256" == "$source_watchdog_sha256" ]] \
  || { echo checkpoint_research_nonbroker_source_mismatch >&2; exit 1; }
[[ "$live_execution_broker_sha256" != "$source_execution_broker_sha256" ]] \
  || { echo checkpoint_research_bridge_exception_not_required >&2; exit 1; }
for artifact in "$execution_broker" "$transition" "$watchdog"; do
  [[ "$(stat -c %U:%G:%a "$artifact")" == root:root:755 ]] \
    || { echo checkpoint_research_artifact_untrusted >&2; exit 1; }
done

[[ "$(sha256sum /usr/local/libexec/secure-sandbox/evidence_receipts.py | awk '{print $1}')" \
      == "$source_receipts_sha256" ]]
[[ "$(sha256sum /usr/local/libexec/secure-sandbox/corpus_broker.py | awk '{print $1}')" \
      == "$source_corpus_broker_sha256" ]]
[[ "$(sha256sum /etc/systemd/system/corpus-broker.service | awk '{print $1}')" \
      == "$source_corpus_unit_sha256" ]]
[[ "$(sha256sum /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py | awk '{print $1}')" \
      == "$source_corpus_mcp_sha256" ]]
[[ "$(sha256sum /etc/systemd/system/execution-broker.service | awk '{print $1}')" \
      == "$source_execution_unit_sha256" ]]
[[ "$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts)" \
      == root:evidence-receipts:750 ]]
[[ "$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts/corpus)" \
      == corpus-broker:evidence-receipts:2750 ]]
[[ "$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts/execution)" \
      == execution-broker:evidence-receipts:2750 ]]
[[ "$(stat -c %U:%G:%a /run/secure-sandbox-corpus/corpus.sock)" \
      == corpus-broker:agent:660 ]]
runuser -u agent -- test -w /run/secure-sandbox-corpus/corpus.sock
! runuser -u agent -- test -r /var/lib/secure-sandbox/evidence-receipts
runuser -u corpus-broker -- test -w /var/lib/secure-sandbox/evidence-receipts/corpus
! runuser -u corpus-broker -- test -w /var/lib/secure-sandbox/evidence-receipts/execution
runuser -u execution-broker -- test -w /var/lib/secure-sandbox/evidence-receipts/execution
! runuser -u execution-broker -- test -w /var/lib/secure-sandbox/evidence-receipts/corpus

jq -ncS --arg release_id "$live_release_id" \
  --arg execution_broker_sha256 "$live_execution_broker_sha256" \
  --arg source_execution_broker_sha256 "$source_execution_broker_sha256" \
  --arg transition_sha256 "$live_transition_sha256" \
  --arg watchdog_sha256 "$live_watchdog_sha256" \
  '{schema:"secure-sandbox-checkpoint-research-boundary-verification-v1",status:"verified",release_id:$release_id,execution_broker_sha256:$execution_broker_sha256,source_execution_broker_sha256:$source_execution_broker_sha256,transition_sha256:$transition_sha256,watchdog_sha256:$watchdog_sha256,receipt_boundary_verified:true}'
