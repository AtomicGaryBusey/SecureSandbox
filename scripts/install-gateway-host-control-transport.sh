#!/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[[ "$(id -u)" -eq 0 ]] || {
  echo "Gateway Host-control transport installation requires root." >&2
  exit 1
}
source=/tmp/gateway-host-control-transport.py
[[ -f "$source" && ! -L "$source" ]] || {
  echo "Gateway Host-control transport payload is unavailable." >&2
  exit 1
}
exec /usr/bin/python3 -I "$source" install
