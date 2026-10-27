#!/bin/bash
set -euo pipefail
request=/tmp/request.json
[[ -f "$request" && ! -L "$request" && "$(stat -c '%U:%G:%a:%h' "$request")" == root:root:*:1 ]] \
  || { echo "finding_action_payload_invalid" >&2; exit 2; }
size="$(stat -c %s "$request")"
(( size > 0 && size <= 16384 )) || { echo "finding_action_size_invalid" >&2; exit 2; }
python3 -m json.tool "$request" >/dev/null
exec /usr/local/libexec/secure-sandbox/finding_admin.py apply "$request"
