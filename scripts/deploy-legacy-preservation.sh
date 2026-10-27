#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
client=/usr/local/libexec/secure-sandbox-host/current/control_client
"$client" client --ssh-config "$ssh_config" sandbox-research-control run lifecycle-idle >/dev/null
exec "$client" client --ssh-config "$ssh_config" sandbox-research-control deploy \
  install-legacy-preservation.sh \
  "$root_dir/scripts/install-legacy-preservation.sh" \
  "$root_dir/scripts/privileged_control.py" \
  "$root_dir/scripts/legacy-guest-export.py" \
  "$root_dir/scripts/legacy_guest_preserver.py" \
  "$root_dir/scripts/verify-legacy-archive.py" \
  "$root_dir/scripts/plan-legacy-continuity-import.py" \
  "$root_dir/scripts/import-legacy-continuity.py" \
  "$root_dir/scripts/legacy_continuity_control.py"
