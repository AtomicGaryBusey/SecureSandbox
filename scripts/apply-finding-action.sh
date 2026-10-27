#!/bin/bash
set -euo pipefail
[[ $# -eq 1 ]] || { echo "Usage: apply-finding-action.sh REQUEST.json" >&2; exit 2; }
request="$1"
[[ -f "$request" && ! -L "$request" ]] || { echo "Request must be a regular non-symlink file." >&2; exit 2; }
size="$(stat -f '%z' "$request")"
(( size > 0 && size <= 16384 )) || { echo "Request must be between 1 and 16384 bytes." >&2; exit 2; }
python3 -m json.tool "$request" >/dev/null
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
  sandbox-research-control deploy install-finding-action.sh \
  --file "$root_dir/scripts/install-finding-action.sh" --file "$request:request.json"
