#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
settings_hash="$(shasum -a 256 "$root_dir/research/managed-settings.proposed.json" | awk '{print $1}')"
launcher_hash="$(shasum -a 256 "$root_dir/research/research-claude.proposed" | awk '{print $1}')"

"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  run rollback-approved-claude-policy "$settings_hash" "$launcher_hash"

echo "Approved Claude policy and launcher removed; workspace contents preserved."
