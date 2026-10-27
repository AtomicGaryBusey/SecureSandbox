#!/bin/bash
set -euo pipefail
cleanup() { rm -f -- "${helper:-}" "${approval:-}" "${envelope:-}"; }
trap cleanup EXIT
[[ "$(id -u)" -eq 0 ]] || { echo root_required >&2; exit 1; }
helper="${1:-/tmp/audit_expired_execution_approval.py}"
approval="${2:-/tmp/expired-approval.json}"
envelope="${3:-/tmp/expired-envelope.json}"
[[ -f "$helper" && ! -L "$helper" && -f "$approval" && ! -L "$approval" \
    && -f "$envelope" && ! -L "$envelope" ]] || { echo expiry_audit_input_missing >&2; exit 2; }
python3 "$helper" "$approval" "$envelope"
