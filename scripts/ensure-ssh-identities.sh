#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
provisioning_socket=/tmp/secure-sandbox-ssh-agent.sock
control_socket=/tmp/secure-sandbox-control-ssh-agent.sock
provisioning_public="$root_dir/runs/provisioning_key.pub"
control_public="$root_dir/runs/control_key.pub"

identity_matches() {
  local socket="$1" public_key="$2" expected actual count
  [[ -S "$socket" && -f "$public_key" && ! -L "$public_key" ]] || return 1
  expected="$(/usr/bin/ssh-keygen -lf "$public_key" -E sha256 2>/dev/null \
    | /usr/bin/awk 'NR == 1 {print $2}')"
  [[ -n "$expected" ]] || return 1
  actual="$(SSH_AUTH_SOCK="$socket" /usr/bin/ssh-add -l -E sha256 2>/dev/null \
    | /usr/bin/awk '{print $2}')"
  count="$(/usr/bin/awk 'NF {count++} END {print count + 0}' <<<"$actual")"
  [[ "$count" == 1 && "$actual" == "$expected" ]]
}

identities_ready() {
  identity_matches "$provisioning_socket" "$provisioning_public" \
    && identity_matches "$control_socket" "$control_public"
}

if identities_ready; then
  exit 0
fi

echo "SecureSandbox ephemeral SSH identities are unavailable; restoring them from the Agents vault." >&2
"$root_dir/scripts/labctl" key-load >/dev/null

if ! identities_ready; then
  echo secure_sandbox_ssh_identity_restore_failed >&2
  exit 1
fi

echo "SecureSandbox ephemeral SSH identities restored." >&2
