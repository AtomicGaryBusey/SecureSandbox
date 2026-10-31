#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$root_dir/scripts/deploy-codegraph-adapter.sh"
"$root_dir/scripts/deploy-findings-adjudication.sh"
echo "codegraph-findings-ergonomics:installed"
