#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
control_client="/usr/local/libexec/secure-sandbox-host/current/control_client"

"$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  run lifecycle-idle >/dev/null

python3 "$root_dir/scripts/deploy-host-controller.py" deploy \
  --requesting-agent Codex \
  --requesting-session session-discovery-labels-ddd \
  --purpose "Deploy trusted host-side session run accounting"

result="$("$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-session-discovery.sh \
  --file "$root_dir/research/session_registry.py" \
  --file "$root_dir/scripts/install-session-discovery.sh")"
printf '%s\n' "$result"

expected="$(shasum -a 256 "$root_dir/research/session_registry.py" | awk '{print $1}')"
jq -e --arg expected "$expected" '
  .schema == "secure-sandbox-session-discovery-install-v1"
  and .status == "installed"
  and .registry_sha256 == $expected
  and (.registry_rows | type == "number" and . >= 1 and . <= 10000)
' <<<"$result" >/dev/null || { echo session_registry_live_receipt_invalid >&2; exit 1; }

"$root_dir/scripts/labctl" sessions
