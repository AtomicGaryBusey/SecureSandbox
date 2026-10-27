#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo root_required >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] \
  || { echo agent_lifecycle_not_idle >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo claude_running >&2; exit 1; }
names=(privileged_control.py legacy-guest-export.py legacy_guest_preserver.py verify-legacy-archive.py plan-legacy-continuity-import.py import-legacy-continuity.py legacy_continuity_control.py session_registry.py)
all_names=(install-legacy-preservation.sh "${names[@]}")
[[ "$#" -eq "${#all_names[@]}" ]] || { echo expected_hashes_required >&2; exit 2; }
for index in "${!all_names[@]}"; do
  position=$((index + 1))
  expected="${!position}"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "expected_hash_invalid:${all_names[$index]}" >&2; exit 2; }
  actual="$(sha256sum "/tmp/${all_names[$index]}" | cut -d' ' -f1)"
  [[ "$actual" = "$expected" ]] || { echo "deployment_hash_mismatch:${all_names[$index]}" >&2; exit 2; }
done
for name in "${names[@]}"; do
  [[ -f "/tmp/$name" && ! -L "/tmp/$name" ]] || { echo "artifact_invalid:$name" >&2; exit 2; }
done
for name in "${names[@]}"; do python3 -m py_compile "/tmp/$name"; done
backup="$(mktemp -d /var/lib/secure-sandbox/policy-backups/legacy-preservation-XXXXXXXX)"
chmod 700 "$backup"
dest=/usr/local/libexec/secure-sandbox
for name in "${names[@]}"; do
  [[ -f "$dest/$name" && ! -L "$dest/$name" ]] && cp --no-dereference "$dest/$name" "$backup/$name" || : > "$backup/$name.absent"
done
rollback() {
  trap - ERR
  for name in "${names[@]}"; do
    if [[ -f "$backup/$name.absent" ]]; then rm -f -- "$dest/$name"; else install -o root -g root -m 755 "$backup/$name" "$dest/$name"; fi
  done
  "$dest/update-policy-hash.sh" research >/dev/null 2>&1 || true
}
trap rollback ERR
for name in "${names[@]}"; do install -o root -g root -m 755 "/tmp/$name" "$dest/$name"; done
for name in "${names[@]}"; do python3 -m py_compile "$dest/$name"; done
"$dest/privileged_control.py" internal control-self-check >/dev/null
"$dest/update-policy-hash.sh" research >/dev/null
trap - ERR
echo legacy-preservation:installed
