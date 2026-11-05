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
for path in /tmp/native_deployment_probe.py /tmp/native_deployment.py \
  /tmp/native_vendor_stack.py "$release"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    echo native_deployment_probe_payload_invalid >&2
    exit 2
  }
done
if [[ "$role" == research ]]; then
  [[ -f /tmp/native-vendor-stacks.json && ! -L /tmp/native-vendor-stacks.json ]] || {
    echo native_deployment_probe_catalog_authority_missing >&2
    exit 2
  }
  exec /usr/bin/python3 -I /tmp/native_deployment_probe.py \
    "$role" "$release" /tmp/native_deployment.py /tmp/native_vendor_stack.py \
    /tmp/native-vendor-stacks.json
fi
exec /usr/bin/python3 -I /tmp/native_deployment_probe.py \
  "$role" "$release" /tmp/native_deployment.py /tmp/native_vendor_stack.py
