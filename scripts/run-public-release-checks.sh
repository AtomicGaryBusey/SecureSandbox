#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
candidate="${1:-HEAD}"
cd "$root_dir"

resolved="$(git rev-parse --verify "${candidate}^{commit}")"
head="$(git rev-parse --verify HEAD)"
[[ "$resolved" == "$head" ]] || {
  echo "public release candidate must be the exact checked-out HEAD" >&2
  exit 1
}
git diff --quiet
git diff --cached --quiet

python3 scripts/check-public-identifiers.py --worktree-only
python3 scripts/check-public-identifiers.py --history-only --ref "$resolved"

temporary="$(mktemp -d "${TMPDIR:-/tmp}/secure-sandbox-public-release.XXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
export PYTHONPYCACHEPREFIX="$temporary/pycache"

git ls-files -z '*.py' | xargs -0 python3 -m py_compile

while IFS= read -r -d '' script; do
  case "$(head -n 1 "$script")" in
    *zsh) zsh -n "$script" ;;
    *bash) bash -n "$script" ;;
    *) echo "unsupported shell interpreter: $script" >&2; exit 1 ;;
  esac
done < <(git ls-files -z '*.sh')

test_path="$root_dir/scripts:$root_dir/gateway:$root_dir/research:$root_dir/target:$root_dir/shared:$root_dir"
for suite in scripts gateway research target shared; do
  PYTHONPATH="$test_path" python3 -m unittest discover -s "$suite" -p 'test_*.py'
done

python3 scripts/build-public-release.py --ref "$resolved" --output-dir "$temporary/first" >/dev/null
python3 scripts/build-public-release.py --ref "$resolved" --output-dir "$temporary/second" >/dev/null
for artifact in SecureSandbox-source.tar.gz SecureSandbox-source.provenance.json SHA256SUMS; do
  cmp "$temporary/first/$artifact" "$temporary/second/$artifact"
done

printf '{"commit":"%s","schema":"secure-sandbox-public-release-check-v1","status":"verified"}\n' "$resolved"
