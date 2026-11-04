#!/bin/bash
set -euo pipefail

[[ $# -eq 0 ]] || { echo native_deployment_bootstrap_arguments_forbidden >&2; exit 64; }
[[ "$(id -u)" == 0 && "$(id -g)" == 0 ]] || {
  echo native_deployment_bootstrap_root_required >&2
  exit 1
}

exec /usr/bin/python3 -I /tmp/native_deployment_fence_bootstrap.py release
