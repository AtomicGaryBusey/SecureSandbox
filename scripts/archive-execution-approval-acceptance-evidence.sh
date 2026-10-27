#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo root_required >&2; exit 1; }
current_transaction="${1:-}"
helper="${2:-/tmp/archive_execution_approval_acceptance_evidence.py}"
[[ "$current_transaction" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
  || { echo current_transaction_invalid >&2; exit 2; }
[[ -f "$helper" && ! -L "$helper" ]] || { echo acceptance_evidence_archiver_missing >&2; exit 2; }
/usr/bin/python3 "$helper" "$current_transaction"
rm -f -- "$helper"
