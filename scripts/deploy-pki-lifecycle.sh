#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
state_root="${SECURE_SANDBOX_STATE_ROOT:-}"
coordination_parent="${SECURE_SANDBOX_COORDINATION_PARENT_PID:-}"
coordination_holder="${SECURE_SANDBOX_COORDINATION_HOLDER_PID:-}"
expected_state_root="$HOME/Library/Application Support/SecureSandbox/controller-state"
pid_file="$state_root/coordination.lock/pid"
[[ "$state_root" = "$expected_state_root" && "$coordination_parent" = "$PPID" \
    && "$coordination_holder" == <-> && -f "$pid_file" && ! -L "$pid_file" \
    && "$(< "$pid_file")" = "$coordination_holder" ]] || {
  print -u2 'Run through: python3 scripts/pki-operation.py deploy'
  exit 1
}
"$root_dir/scripts/sync-lab-time.sh" --check
"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
  sandbox-research-control run lifecycle-idle >/dev/null

gateway_manifest="$(mktemp /tmp/pki-gateway-manifest.XXXXXX)"
research_manifest="$(mktemp /tmp/pki-research-manifest.XXXXXX)"
trap 'rm -f -- "$gateway_manifest" "$research_manifest"' EXIT HUP INT TERM
for item in \
  "$root_dir/scripts/pki_lifecycle.py:pki_lifecycle.py" \
  "$root_dir/gateway/pki_generation.py:pki_generation.py" \
  "$root_dir/scripts/pki-expiry-check.service:pki-expiry-check.service" \
  "$root_dir/scripts/pki-expiry-check.timer:pki-expiry-check.timer" \
  "$root_dir/scripts/update-policy-hash.sh:update-policy-hash.sh" \
  "$root_dir/gateway/local_telemetry_exporter.py:telemetry_exporter.py"; do
  source="${item%%:*}"; target="${item##*:}"
  print "$(/usr/bin/shasum -a 256 "$source" | /usr/bin/awk '{print $1}')  $target" >> "$gateway_manifest"
done
for item in \
  "$root_dir/scripts/pki_lifecycle.py:pki_lifecycle.py" \
  "$root_dir/scripts/pki_guest_helpers.py:pki_guest_helpers.py" \
  "$root_dir/research/pki_generation.py:pki_generation.py" \
  "$root_dir/scripts/pki-expiry-check.service:pki-expiry-check.service" \
  "$root_dir/scripts/pki-expiry-check.timer:pki-expiry-check.timer" \
  "$root_dir/scripts/update-policy-hash.sh:update-policy-hash.sh" \
  "$root_dir/research/telemetry_exporter.py:telemetry_exporter.py"; do
  source="${item%%:*}"; target="${item##*:}"
  print "$(/usr/bin/shasum -a 256 "$source" | /usr/bin/awk '{print $1}')  $target" >> "$research_manifest"
done
gateway_manifest_sha="$(/usr/bin/shasum -a 256 "$gateway_manifest" | /usr/bin/awk '{print $1}')"
research_manifest_sha="$(/usr/bin/shasum -a 256 "$research_manifest" | /usr/bin/awk '{print $1}')"
"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-gateway-control \
  deploy install-pki-lifecycle.sh gateway "$gateway_manifest_sha" \
  --file "$root_dir/scripts/pki_lifecycle.py" --file "$root_dir/gateway/pki_generation.py:pki_generation.py" \
  --file "$root_dir/scripts/pki-expiry-check.service" --file "$root_dir/scripts/pki-expiry-check.timer" \
  --file "$root_dir/scripts/update-policy-hash.sh" --file "$root_dir/gateway/local_telemetry_exporter.py:telemetry_exporter.py" \
  --file "$root_dir/scripts/install-pki-lifecycle.sh" --file "$gateway_manifest:SHA256SUMS"
"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-pki-lifecycle.sh research "$research_manifest_sha" \
  --file "$root_dir/scripts/pki_lifecycle.py" --file "$root_dir/scripts/pki_guest_helpers.py" \
  --file "$root_dir/research/pki_generation.py:pki_generation.py" --file "$root_dir/scripts/pki-expiry-check.service" \
  --file "$root_dir/scripts/pki-expiry-check.timer" --file "$root_dir/scripts/update-policy-hash.sh" \
  --file "$root_dir/research/telemetry_exporter.py:telemetry_exporter.py" --file "$root_dir/scripts/install-pki-lifecycle.sh" \
  --file "$research_manifest:SHA256SUMS"
