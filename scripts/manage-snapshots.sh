#!/bin/bash
set -euo pipefail
(( $# <= 1 )) || { echo "Usage: manage-snapshots.sh [--dry-run|--apply]" >&2; exit 2; }
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec /usr/bin/python3 "$root_dir/scripts/snapshot_retention.py" "${1:---dry-run}"
