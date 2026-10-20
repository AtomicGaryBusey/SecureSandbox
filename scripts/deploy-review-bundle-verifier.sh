#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
scp -q -F "$ssh_config" \
 "$root_dir/research/managed-settings.proposed.json" "$root_dir/research/source_integrity_mcp.py" \
 "$root_dir/research/review_bundle.py" "$root_dir/research/review_bundle_publisher.py" \
 "$root_dir/research/review-bundle-mount.service" \
 "$root_dir/research/telemetry_exporter.py" "$root_dir/research/glm-persona.md" \
 "$root_dir/research/rollback_review_bundle_verifier.sh" \
 "$root_dir/scripts/install-review-bundle-verifier.sh" "$root_dir/scripts/update-policy-hash.sh" \
 sandbox-research-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Research/password' | ssh -F "$ssh_config" sandbox-research-admin \
 "sudo -S -p '' bash /tmp/install-review-bundle-verifier.sh"
