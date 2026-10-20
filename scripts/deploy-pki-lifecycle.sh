#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
ssh_config="$root_dir/config/ssh_config"
[[ "${SECURE_SANDBOX_COORDINATION_LOCK_HELD:-}" = 1 ]] || {
  print -u2 'Run through: python3 scripts/pki-operation.py deploy'
  exit 1
}
"$root_dir/scripts/sync-lab-time.sh" --check
active_run="$(ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin 'if test -f /run/secure-sandbox/run-id; then cat /run/secure-sandbox/run-id; fi')"
[[ -z "$active_run" ]] || { print -u2 "Refusing PKI deployment while Claude run $active_run is active."; exit 1; }

ssh -F "$ssh_config" sandbox-gateway 'rm -rf /tmp/pki-lifecycle-gateway && install -d -m 700 /tmp/pki-lifecycle-gateway'
ssh -F "$ssh_config" sandbox-research-admin 'rm -rf /tmp/pki-lifecycle-research && install -d -m 700 /tmp/pki-lifecycle-research'
scp -F "$ssh_config" \
  "$root_dir/scripts/pki_lifecycle.py" "$root_dir/gateway/pki_generation.py" \
  "$root_dir/scripts/pki-expiry-check.service" "$root_dir/scripts/pki-expiry-check.timer" \
  "$root_dir/scripts/update-policy-hash.sh" "$root_dir/gateway/local_telemetry_exporter.py" \
  sandbox-gateway:/tmp/pki-lifecycle-gateway/
scp -F "$ssh_config" \
  "$root_dir/scripts/pki_lifecycle.py" "$root_dir/scripts/pki_guest_helpers.py" "$root_dir/research/pki_generation.py" \
  "$root_dir/scripts/pki-expiry-check.service" "$root_dir/scripts/pki-expiry-check.timer" \
  "$root_dir/scripts/update-policy-hash.sh" "$root_dir/research/telemetry_exporter.py" \
  sandbox-research-admin:/tmp/pki-lifecycle-research/
ssh -F "$ssh_config" sandbox-gateway 'mv /tmp/pki-lifecycle-gateway/local_telemetry_exporter.py /tmp/pki-lifecycle-gateway/telemetry_exporter.py'
scp -F "$ssh_config" "$root_dir/scripts/install-pki-lifecycle.sh" sandbox-gateway:/tmp/pki-lifecycle-gateway/
scp -F "$ssh_config" "$root_dir/scripts/install-pki-lifecycle.sh" sandbox-research-admin:/tmp/pki-lifecycle-research/
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
scp -F "$ssh_config" "$gateway_manifest" sandbox-gateway:/tmp/pki-lifecycle-gateway/SHA256SUMS
scp -F "$ssh_config" "$research_manifest" sandbox-research-admin:/tmp/pki-lifecycle-research/SHA256SUMS
gateway_manifest_sha="$(/usr/bin/shasum -a 256 "$gateway_manifest" | /usr/bin/awk '{print $1}')"
research_manifest_sha="$(/usr/bin/shasum -a 256 "$research_manifest" | /usr/bin/awk '{print $1}')"
installer_sha="$(/usr/bin/shasum -a 256 "$root_dir/scripts/install-pki-lifecycle.sh" | /usr/bin/awk '{print $1}')"
op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
  | ssh -F "$ssh_config" sandbox-gateway "sudo -S -p '' /bin/sh -c 'install -o root -g root -m 700 /tmp/pki-lifecycle-gateway/install-pki-lifecycle.sh /var/lib/secure-sandbox/pki-installer; printf \"$installer_sha  /var/lib/secure-sandbox/pki-installer\\n\" | sha256sum -c - >/dev/null; exec /bin/bash /var/lib/secure-sandbox/pki-installer gateway $gateway_manifest_sha'"
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin "sudo -S -p '' /bin/sh -c 'install -o root -g root -m 700 /tmp/pki-lifecycle-research/install-pki-lifecycle.sh /var/lib/secure-sandbox/pki-installer; printf \"$installer_sha  /var/lib/secure-sandbox/pki-installer\\n\" | sha256sum -c - >/dev/null; exec /bin/bash /var/lib/secure-sandbox/pki-installer research $research_manifest_sha'"
ssh -F "$ssh_config" sandbox-gateway 'rm -rf /tmp/pki-lifecycle-gateway'
ssh -F "$ssh_config" sandbox-research-admin 'rm -rf /tmp/pki-lifecycle-research'
