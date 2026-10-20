#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
names=(managed-settings.proposed.json source_integrity_mcp.py review_bundle.py review_bundle_publisher.py review-bundle-mount.service telemetry_exporter.py glm-persona.md rollback_review_bundle_verifier.sh update-policy-hash.sh)
for name in "${names[@]}"; do [[ -f "/tmp/$name" && ! -L "/tmp/$name" ]] || { echo "Invalid artifact: $name" >&2; exit 2; }; done
python3 -m json.tool /tmp/managed-settings.proposed.json >/dev/null
python3 -m py_compile /tmp/source_integrity_mcp.py /tmp/review_bundle.py /tmp/review_bundle_publisher.py /tmp/telemetry_exporter.py
bash -n /tmp/rollback_review_bundle_verifier.sh
bash -n /tmp/update-policy-hash.sh
systemd-analyze verify /tmp/review-bundle-mount.service >/dev/null
backup_id="review-bundle-verifier-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
destinations=(
 /etc/claude-code/managed-settings.json
 /usr/local/libexec/secure-sandbox/source_integrity_mcp.py
 /usr/local/libexec/secure-sandbox/review_bundle.py
 /usr/local/libexec/secure-sandbox/review_bundle_publisher.py
 /etc/systemd/system/review-bundle-mount.service
 /usr/local/libexec/secure-sandbox/telemetry_exporter.py
 /etc/claude-code/secure-sandbox-persona.md
 /usr/local/libexec/secure-sandbox/rollback_review_bundle_verifier.sh
 /usr/local/libexec/secure-sandbox/update-policy-hash.sh)
for current in "${destinations[@]}"; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash /tmp/rollback_review_bundle_verifier.sh "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR
view=/home/agent/research-workspace/review-bundles
canonical=/var/lib/secure-sandbox/review-bundles
if mountpoint -q "$view"; then
  systemctl stop review-bundle-mount.service
  : > "$backup/mount.was-active"
else
  [[ -d "$view" && ! -L "$view" && "$(stat -c %U:%G:%a "$view")" == root:root:755 ]] \
    || { echo "Untrusted review-bundles directory" >&2; exit 2; }
  mv -- "$view" "$backup/review-bundles.workspace"
fi
if [[ ! -e "$canonical" ]]; then
  install -d -o root -g root -m 755 "$canonical"
  : > "$backup/canonical.absent"
  if [[ -d "$backup/review-bundles.workspace" ]]; then cp -a "$backup/review-bundles.workspace/." "$canonical/"; fi
fi
[[ -d "$canonical" && ! -L "$canonical" && "$(stat -c %U:%G:%a "$canonical")" == root:root:755 ]] \
  || { echo "Untrusted canonical review-bundles directory" >&2; exit 2; }
install -d -o root -g root -m 755 "$view"
install -o root -g root -m 644 /tmp/managed-settings.proposed.json /etc/claude-code/managed-settings.json
install -o root -g root -m 755 /tmp/source_integrity_mcp.py /usr/local/libexec/secure-sandbox/source_integrity_mcp.py
install -o root -g root -m 755 /tmp/review_bundle.py /usr/local/libexec/secure-sandbox/review_bundle.py
install -o root -g root -m 755 /tmp/review_bundle_publisher.py /usr/local/libexec/secure-sandbox/review_bundle_publisher.py
install -o root -g root -m 644 /tmp/review-bundle-mount.service /etc/systemd/system/review-bundle-mount.service
install -o root -g root -m 755 /tmp/telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 444 /tmp/glm-persona.md /etc/claude-code/secure-sandbox-persona.md
install -o root -g root -m 755 /tmp/rollback_review_bundle_verifier.sh /usr/local/libexec/secure-sandbox/rollback_review_bundle_verifier.sh
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh
python3 -m py_compile /usr/local/libexec/secure-sandbox/source_integrity_mcp.py /usr/local/libexec/secure-sandbox/review_bundle.py /usr/local/libexec/secure-sandbox/review_bundle_publisher.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py
systemctl daemon-reload
systemctl enable --now review-bundle-mount.service >/dev/null
mountpoint -q "$view"
test "$(stat -c %d:%i "$canonical")" = "$(stat -c %d:%i "$view")"
findmnt -n -o OPTIONS --target "$view" | tr ',' '\n' | grep -qx ro
for option in nosuid nodev noexec; do findmnt -n -o OPTIONS --target "$view" | tr ',' '\n' | grep -qx "$option"; done
systemctl restart telemetry-exporter.service
systemctl is-active --quiet review-bundle-mount.service telemetry-exporter.service
/usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/review-bundle-verifier-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/review-bundle-verifier-latest
trap - ERR
echo "review-bundle-verifier:installed:$backup_id"
