#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/review-bundle-verifier-latest)}"
[[ "$backup_id" =~ ^review-bundle-verifier-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid backup ID" >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" && ! -L "$backup" ]] || { echo "Backup not found" >&2; exit 2; }
systemctl disable --now review-bundle-mount.service >/dev/null 2>&1 || true
restore() {
  local name="$1" destination="$2" mode="$3"
  if [[ -f "$backup/$name" ]]; then install -o root -g root -m "$mode" "$backup/$name" "$destination"
  elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"
  else echo "Incomplete backup: $name" >&2; exit 2; fi
}
restore managed-settings.json /etc/claude-code/managed-settings.json 644
restore source_integrity_mcp.py /usr/local/libexec/secure-sandbox/source_integrity_mcp.py 755
restore review_bundle.py /usr/local/libexec/secure-sandbox/review_bundle.py 755
restore review_bundle_publisher.py /usr/local/libexec/secure-sandbox/review_bundle_publisher.py 755
restore review-bundle-mount.service /etc/systemd/system/review-bundle-mount.service 644
restore telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py 755
restore secure-sandbox-persona.md /etc/claude-code/secure-sandbox-persona.md 444
restore rollback_review_bundle_verifier.sh /usr/local/libexec/secure-sandbox/rollback_review_bundle_verifier.sh 755
restore update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh 755
view=/home/agent/research-workspace/review-bundles
canonical=/var/lib/secure-sandbox/review-bundles
host_mount_namespace() {
  /usr/bin/nsenter --mount=/proc/1/ns/mnt -- "$@"
}
remove_unmounted_view_if_present() {
  if host_mount_namespace /usr/bin/mountpoint -q "$view"; then
    echo "Refusing rollback while the review-bundle view remains mounted" >&2
    return 1
  fi
  if host_mount_namespace /usr/bin/test -L "$view"; then
    echo "Refusing untrusted review-bundle view symlink during rollback" >&2
    return 1
  fi
  if host_mount_namespace /usr/bin/test -e "$view"; then
    host_mount_namespace /usr/bin/test -d "$view" \
      || { echo "Refusing non-directory review-bundle view during rollback" >&2; return 1; }
    host_mount_namespace /usr/bin/rmdir "$view"
  fi
}
if [[ -d "$backup/review-bundles.workspace" ]]; then
  remove_unmounted_view_if_present
  if [[ -f "$backup/canonical.absent" ]] \
      && host_mount_namespace /usr/bin/test -d "$canonical"; then
    host_mount_namespace /usr/bin/mv -- "$canonical" "$backup/review-bundles.canonical-after-rollback"
  fi
  host_mount_namespace /usr/bin/mv -- "$backup/review-bundles.workspace" "$view"
elif [[ -f "$backup/review-bundles.workspace.absent" ]]; then
  remove_unmounted_view_if_present
  if [[ -f "$backup/canonical.absent" ]] \
      && host_mount_namespace /usr/bin/test -d "$canonical"; then
    host_mount_namespace /usr/bin/mv -- "$canonical" "$backup/review-bundles.canonical-after-rollback"
  fi
elif [[ ! -f "$backup/mount.was-active" ]]; then
  echo "Incomplete backup: review-bundles workspace state" >&2
  exit 2
fi
systemctl daemon-reload
if [[ -f "$backup/mount.was-active" && -f /etc/systemd/system/review-bundle-mount.service ]]; then
  systemctl enable --now review-bundle-mount.service >/dev/null
fi
systemctl restart telemetry-exporter.service
/usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
echo "review-bundle-verifier:rolled-back:$backup_id"
