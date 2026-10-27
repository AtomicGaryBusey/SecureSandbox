#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ -f /etc/secure-sandbox/control-role ]] || { echo "Control role is missing." >&2; exit 2; }
[[ "$(cat /etc/secure-sandbox/control-role)" == research ]] || {
  echo "This installer is restricted to Research." >&2
  exit 2
}

# The Research firewall is rendered before the disposable-execution service is
# installed.  Create its stable service identity first so UID-bound rules can
# be generated without relaxing the renderer's fail-closed account lookup.
if ! getent passwd execution-broker >/dev/null; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin execution-broker
fi

account="$(getent passwd execution-broker)"
IFS=: read -r name _ uid _ _ home shell <<< "$account"
[[ "$name" == execution-broker && "$uid" -ne 0 && "$home" == /nonexistent \
  && "$shell" == /usr/sbin/nologin ]] || {
  echo "Execution broker identity is untrusted." >&2
  exit 2
}

echo "research-service-principals:installed"
