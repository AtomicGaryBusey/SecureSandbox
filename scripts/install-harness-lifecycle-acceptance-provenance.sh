#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on the disposable Mac." >&2; exit 1; }
source_commit="${1:-}"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "Invalid source commit." >&2; exit 2; }
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ "$(git -C "$repo" rev-parse HEAD)" == "$source_commit" ]] \
  || { echo "Checkout commit does not match requested installation." >&2; exit 2; }
git -C "$repo" diff --quiet --ignore-submodules --
git -C "$repo" diff --cached --quiet --ignore-submodules --
[[ -z "$(git -C "$repo" status --porcelain=v1 --untracked-files=all)" ]] \
  || { echo "Checkout must be clean before protected installation." >&2; exit 2; }

payloads=(
  scripts/harness-lifecycle-acceptance-provenance.py
  scripts/harness-lifecycle-acceptance-observe.py
  scripts/harness-lifecycle-acceptance-supervisor.py
  scripts/harness-lifecycle-acceptance.py
  shared/harness_lifecycle.py
  shared/harness_lifecycle_acceptance.py
  shared/harness_lifecycle_provenance_fixture.py
)
for relative in "${payloads[@]}"; do
  source="$repo/$relative"
  [[ -f "$source" && ! -L "$source" ]] \
    || { echo "Missing regular protected-driver source: $relative" >&2; exit 2; }
done
python3 - "$repo" "${payloads[@]}" <<'PY'
import pathlib, sys

root = pathlib.Path(sys.argv[1])
for relative in sys.argv[2:]:
    source = root / relative
    compile(source.read_bytes(), str(source), "exec", dont_inherit=True)
PY

base=/usr/local/libexec/secure-sandbox-harness-acceptance
releases="$base/releases"
release="$releases/$source_commit"
state=/var/db/SecureSandbox/harness-lifecycle-acceptance
install -d -o root -g wheel -m 755 "$base" "$releases"
install -d -o root -g wheel -m 700 /var/db/SecureSandbox "$state"
[[ ! -e "$release" && ! -L "$release" ]] \
  || { echo "Protected driver release already exists; refusing overwrite." >&2; exit 1; }
temporary="$(mktemp -d "$releases/.${source_commit}.new.XXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT
for relative in "${payloads[@]}"; do
  install -d -o root -g wheel -m 755 "$temporary/$(dirname "$relative")"
  mode=444
  [[ "$relative" == scripts/* ]] && mode=555
  install -o root -g wheel -m "$mode" "$repo/$relative" "$temporary/$relative"
done

PYTHONDONTWRITEBYTECODE=1 python3 - "$temporary" "$source_commit" <<'PY'
import hashlib, importlib.util, json, pathlib, sys

release = pathlib.Path(sys.argv[1])
source_commit = sys.argv[2]
shared = release / "shared"
sys.path.insert(0, str(shared))
spec = importlib.util.spec_from_file_location(
    "installed_acceptance_cli", release / "scripts/harness-lifecycle-acceptance.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
payloads = list(module.PROTECTED_DRIVER_PAYLOADS["host-provenance-fixture"])
records = []
for relative in payloads:
    path = release / relative
    raw = path.read_bytes()
    records.append({
        "mode": path.stat().st_mode & 0o777,
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    })
manifest = {
    "schema": module.PROTECTED_DRIVER_MANIFEST_SCHEMA,
    "suite_id": module.SUITE_ID,
    "suite_sha256": module.suite_sha256(),
    "source_commit": source_commit,
    "drivers": {"host-provenance-fixture": payloads},
    "files": sorted(records, key=lambda item: item["path"]),
}
manifest["manifest_sha256"] = module.digest(manifest)
(release / "manifest.json").write_bytes(module.canonical(manifest))
PY
chown root:wheel "$temporary/manifest.json"
chmod 444 "$temporary/manifest.json"
find "$temporary" -type d -exec chmod 555 {} +
mv "$temporary" "$release"
trap - EXIT
sync
echo "harness-lifecycle-acceptance-provenance:installed:$source_commit"
