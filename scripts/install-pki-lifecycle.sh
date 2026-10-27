#!/bin/bash
set -euo pipefail

role="${1:-}"
expected_manifest_sha256="${2:-}"
case "$role" in gateway|research) ;; *) echo "Usage: install-pki-lifecycle.sh gateway|research" >&2; exit 2;; esac
[[ "$expected_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid expected manifest digest." >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root in the guest." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }

untrusted_root="/tmp"
trusted_root="$(mktemp -d /var/lib/secure-sandbox/.pki-deploy.XXXXXX)"
chmod 700 "$trusted_root"
trap 'rm -rf -- "$trusted_root"' EXIT
for source in "$untrusted_root"/*; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Untrusted deployment artifact." >&2; exit 2; }
  install -o root -g root -m 600 "$source" "$trusted_root/$(basename "$source")"
done
actual_manifest_sha256="$(sha256sum "$trusted_root/SHA256SUMS" | awk '{print $1}')"
[[ "$actual_manifest_sha256" = "$expected_manifest_sha256" ]] || { echo "Deployment manifest digest mismatch." >&2; exit 2; }
(cd "$trusted_root" && sha256sum -c SHA256SUMS >/dev/null)
source_root="$trusted_root"
for source in \
  "$source_root/pki_lifecycle.py" \
  "$source_root/pki_generation.py" \
  "$source_root/pki-expiry-check.service" \
  "$source_root/pki-expiry-check.timer" \
  "$source_root/update-policy-hash.sh" \
  "$source_root/telemetry_exporter.py"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact: $source" >&2; exit 2; }
done
if [[ "$role" = research ]]; then
  [[ -f "$source_root/pki_guest_helpers.py" && ! -L "$source_root/pki_guest_helpers.py" ]] || exit 2
fi
python3 -m py_compile "$source_root/pki_lifecycle.py" "$source_root/pki_generation.py" "$source_root/telemetry_exporter.py"
[[ "$role" = gateway ]] || python3 -m py_compile "$source_root/pki_guest_helpers.py"
bash -n "$source_root/update-policy-hash.sh"

backup_id="pki-lifecycle-$role-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
for current in \
  /usr/local/libexec/secure-sandbox/pki_lifecycle.py \
  /usr/local/libexec/secure-sandbox/pki_generation.py \
  /usr/local/libexec/secure-sandbox/pki_guest_helpers.py \
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh \
  /etc/systemd/system/pki-expiry-check.service \
  /etc/systemd/system/pki-expiry-check.timer; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
if [[ "$role" = gateway ]]; then
  telemetry=/usr/local/libexec/secure-sandbox/local_telemetry_exporter.py
else
  telemetry=/usr/local/libexec/secure-sandbox/telemetry_exporter.py
fi
if [[ -f "$telemetry" && ! -L "$telemetry" ]]; then cp --no-dereference "$telemetry" "$backup/$(basename "$telemetry")"; fi
chmod -R go-rwx "$backup"

installed_paths=(
  /usr/local/libexec/secure-sandbox/pki_lifecycle.py
  /usr/local/libexec/secure-sandbox/pki_generation.py
  /usr/local/libexec/secure-sandbox/pki_guest_helpers.py
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh
  /etc/systemd/system/pki-expiry-check.service
  /etc/systemd/system/pki-expiry-check.timer
  "$telemetry"
)
rollback_on_error() {
  trap - ERR
  for current in "${installed_paths[@]}"; do
    name="$(basename "$current")"
    if [[ -f "$backup/$name" ]]; then
      cp --no-dereference "$backup/$name" "$current"
    elif [[ -f "$backup/$name.absent" ]]; then
      rm -f -- "$current"
    fi
  done
  if [[ -f "$backup/pki-expiry-check.timer.absent" ]]; then
    systemctl disable --now pki-expiry-check.timer >/dev/null 2>&1 || true
  fi
  systemctl daemon-reload || true
  if [[ "$role" = gateway ]]; then
    systemctl restart local-telemetry-exporter.service || true
  else
    systemctl restart telemetry-exporter.service || true
  fi
}
trap rollback_on_error ERR

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g root -m 700 /var/lib/secure-sandbox/pki-lifecycle
install -o root -g root -m 755 "$source_root/pki_lifecycle.py" /usr/local/libexec/secure-sandbox/pki_lifecycle.py
install -o root -g root -m 755 "$source_root/pki_generation.py" /usr/local/libexec/secure-sandbox/pki_generation.py
if [[ "$role" = research ]]; then
  install -o root -g root -m 755 "$source_root/pki_guest_helpers.py" /usr/local/libexec/secure-sandbox/pki_guest_helpers.py
fi
install -o root -g root -m 755 "$source_root/update-policy-hash.sh" /usr/local/libexec/secure-sandbox/update-policy-hash.sh
install -o root -g root -m 644 "$source_root/pki-expiry-check.service" /etc/systemd/system/pki-expiry-check.service
install -o root -g root -m 644 "$source_root/pki-expiry-check.timer" /etc/systemd/system/pki-expiry-check.timer
install -o root -g root -m 755 "$source_root/telemetry_exporter.py" "$telemetry"
python3 -m py_compile /usr/local/libexec/secure-sandbox/pki_lifecycle.py /usr/local/libexec/secure-sandbox/pki_generation.py "$telemetry"
systemd-analyze verify /etc/systemd/system/pki-expiry-check.service /etc/systemd/system/pki-expiry-check.timer >/dev/null
systemctl daemon-reload
systemctl enable pki-expiry-check.timer >/dev/null
generation_manifest=/var/lib/secure-sandbox/pki-lifecycle/current/manifest.json
if [[ -f "$generation_manifest" && ! -L "$generation_manifest" ]]; then
  systemctl start pki-expiry-check.timer
else
  systemctl stop pki-expiry-check.timer >/dev/null 2>&1 || true
fi
if [[ "$role" = gateway ]]; then systemctl restart local-telemetry-exporter.service; else systemctl restart telemetry-exporter.service; fi
if [[ -f "$generation_manifest" && ! -L "$generation_manifest" ]]; then
  systemctl is-active --quiet pki-expiry-check.timer
else
  ! systemctl is-active --quiet pki-expiry-check.timer
fi
systemctl is-active --quiet "$(basename "$telemetry" .py | tr _ -).service" 2>/dev/null || {
  [[ "$role" = gateway ]] && systemctl is-active --quiet local-telemetry-exporter.service || systemctl is-active --quiet telemetry-exporter.service
}
/usr/local/libexec/secure-sandbox/update-policy-hash.sh "$role" >/dev/null
printf '%s\n' "$backup_id" > "/var/lib/secure-sandbox/policy-backups/pki-lifecycle-$role-latest"
chmod 600 "/var/lib/secure-sandbox/policy-backups/pki-lifecycle-$role-latest"
trap - ERR
echo "pki-lifecycle-$role:installed:$backup_id"
