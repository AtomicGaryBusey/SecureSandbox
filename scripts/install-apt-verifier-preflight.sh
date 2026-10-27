#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
role="$(cat /etc/secure-sandbox/control-role 2>/dev/null)"
[[ "$role" == research || "$role" == target ]] || { echo "Unsupported role." >&2; exit 2; }

command -v gpgv >/dev/null
gpgv --version >/dev/null
getent passwd _apt >/dev/null
runuser -u _apt -- /usr/bin/gpgv --version >/dev/null
test -x /usr/lib/apt/methods/gpgv
runuser -u _apt -- /usr/lib/apt/methods/gpgv </dev/null >/dev/null 2>&1 || {
  status=$?
  [[ "$status" -eq 100 ]] || exit "$status"
}

echo "apt-verifier-preflight:$role:passed"
