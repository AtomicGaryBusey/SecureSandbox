#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
ssh_config="$root_dir/config/ssh_config"
settings_hash="$(shasum -a 256 "$root_dir/research/managed-settings.proposed.json" | awk '{print $1}')"
launcher_hash="$(shasum -a 256 "$root_dir/research/research-claude.proposed" | awk '{print $1}')"

# Refuse to erase files that have evolved since the approved baseline.
ssh -F "$ssh_config" sandbox-research-admin \
  "test \"\$(sha256sum /etc/claude-code/managed-settings.json | cut -d' ' -f1)\" = '$settings_hash' && test \"\$(sha256sum /usr/local/bin/research-claude | cut -d' ' -f1)\" = '$launcher_hash'"

op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
      "sudo -S -p '' rm -f /etc/claude-code/managed-settings.json /usr/local/bin/research-claude"

echo "Approved Claude policy and launcher removed; workspace contents preserved."
