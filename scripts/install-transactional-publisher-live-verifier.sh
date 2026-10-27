#!/bin/bash
set -euo pipefail
role="${1:-}"
verifier="${2:-/tmp/transactional_publisher_live_verifier.py}"
[[ "$role" == gateway || "$role" == research ]] || exit 2
[[ -f "$verifier" && ! -L "$verifier" ]] || exit 2
python3 "$verifier" "$role"
