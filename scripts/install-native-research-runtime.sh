#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX=/tmp/native-research-pycache

[[ "$(id -u)" -eq 0 ]] || {
  echo native_research_install_root_required >&2
  exit 1
}
[[ "$#" -eq 0 ]] || {
  echo native_research_install_arguments_forbidden >&2
  exit 64
}

exec /usr/bin/python3 /tmp/native_research_installer.py
