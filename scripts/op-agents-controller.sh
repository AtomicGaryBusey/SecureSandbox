#!/bin/bash
# Release-local credential bridge. The service-account token remains in the
# login Keychain and is exposed only to the exec'd 1Password process.
set -euo pipefail
op_path=__OP_PATH_SHELL__
expected_op_sha256=__OP_SHA256_SHELL__
actual_op_sha256="$(/usr/bin/shasum -a 256 "$op_path" | /usr/bin/awk '{print $1}')"
[[ "$actual_op_sha256" == "$expected_op_sha256" ]] || {
  echo "op-agents: op_binary_hash_mismatch" >&2
  exit 1
}
OP_SERVICE_ACCOUNT_TOKEN="$(/usr/bin/security find-generic-password -s op-service-account-agents -w)" || {
  echo "op-agents: no token in the Keychain (service op-service-account-agents)" >&2
  exit 1
}
export OP_SERVICE_ACCOUNT_TOKEN
exec "$op_path" "$@"

