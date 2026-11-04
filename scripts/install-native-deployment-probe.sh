#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 && "$(id -g)" -eq 0 ]] || {
  echo native_deployment_probe_root_required >&2
  exit 1
}
[[ "$#" -eq 1 ]] || { echo native_deployment_probe_arguments_invalid >&2; exit 64; }
case "$1" in gateway|research) role="$1";;
  *) echo native_deployment_probe_role_invalid >&2; exit 64;;
esac
release="/tmp/native_${role}_release.py"
for path in /tmp/native_deployment_probe.py /tmp/native_deployment.py "$release"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    echo native_deployment_probe_payload_invalid >&2
    exit 2
  }
done
exec /usr/bin/python3 -I /tmp/native_deployment_probe.py \
  "$role" "$release" /tmp/native_deployment.py
