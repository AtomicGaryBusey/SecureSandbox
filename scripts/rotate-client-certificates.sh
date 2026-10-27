#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
print -u2 'Legacy leaf-certificate rotation is disabled; using transactional PKI generation rotation.'
exec /usr/bin/python3 "$root_dir/scripts/pki-operation.py" rotate
