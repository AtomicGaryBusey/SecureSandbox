#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
exec /usr/bin/python3 "$root_dir/scripts/vm-operation.py" reprovision "$@"
