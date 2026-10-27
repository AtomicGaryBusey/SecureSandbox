#!/bin/bash
set -euo pipefail

role="${1:-}"
shift || true
[[ "$(id -u)" -eq 0 ]] || { echo "root_required" >&2; exit 1; }
[[ -f /tmp/configure-guest.sh && ! -L /tmp/configure-guest.sh \
    && -x /tmp/install-privileged-control.sh ]] \
  || { echo "base_installer_payload_missing" >&2; exit 2; }
[[ -f /tmp/control_key.pub && ! -L /tmp/control_key.pub ]] \
  || { echo "control_key_payload_invalid" >&2; exit 2; }

export SECURE_SANDBOX_CONTROL_PUBLIC_KEY_FILE=/tmp/control_key.pub
case "$role" in
  gateway)
    (( $# == 3 )) || { echo "gateway_arguments_invalid" >&2; exit 2; }
    export SECURE_SANDBOX_UPLINK_MAC="$1"
    export SECURE_SANDBOX_CONTROL_MAC="$2"
    export SECURE_SANDBOX_ADMIN_SOURCE_IPV4="$3"
    ;;
  research)
    (( $# == 2 )) || { echo "research_arguments_invalid" >&2; exit 2; }
    export SECURE_SANDBOX_CONTROL_MAC="$1"
    export SECURE_SANDBOX_LAB_MAC="$2"
    ;;
  target)
    (( $# == 1 )) || { echo "target_arguments_invalid" >&2; exit 2; }
    export SECURE_SANDBOX_LAB_MAC="$1"
    ;;
  *)
    echo "role_invalid" >&2
    exit 2
    ;;
esac

exec /bin/bash /tmp/configure-guest.sh "$role"
