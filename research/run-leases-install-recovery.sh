#!/bin/bash
set -euo pipefail
pending=/var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending
[[ -e "$pending" ]] || exit 0
[[ -f "$pending" && ! -L "$pending" && "$(stat -c %U:%G:%a "$pending")" = root:root:600 ]] || {
  echo "invalid Research run-lease install transaction" >&2; exit 1;
}
backup_id="$(cat "$pending")"
[[ "$backup_id" =~ ^run-leases-research-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
  echo "invalid Research rollback generation" >&2; exit 1;
}
exec /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh "$backup_id"
