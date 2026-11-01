#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on the disposable Mac." >&2; exit 1; }
source_commit="${1:-}"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "Invalid source commit." >&2; exit 2; }
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
git=/usr/bin/git
export GIT_NO_REPLACE_OBJECTS=1
resolved_commit="$("$git" -C "$repo" rev-parse --verify "$source_commit^{commit}")" \
  || { echo "Requested commit is unavailable." >&2; exit 2; }
[[ "$resolved_commit" == "$source_commit" ]] \
  || { echo "Requested commit did not resolve exactly." >&2; exit 2; }
head_commit="$("$git" -C "$repo" rev-parse --verify HEAD)" \
  || { echo "Checkout HEAD is unavailable." >&2; exit 2; }
[[ "$head_commit" == "$source_commit" ]] \
  || { echo "Checkout commit does not match requested installation." >&2; exit 2; }
"$git" -C "$repo" diff --quiet --ignore-submodules -- \
  || { echo "Checkout has unstaged changes." >&2; exit 2; }
"$git" -C "$repo" diff --cached --quiet --ignore-submodules -- \
  || { echo "Checkout has staged changes." >&2; exit 2; }
checkout_status="$("$git" -C "$repo" status --porcelain=v1 --untracked-files=all)" \
  || { echo "Checkout status is unavailable." >&2; exit 2; }
[[ -z "$checkout_status" ]] \
  || { echo "Checkout must be clean before protected installation." >&2; exit 2; }

# Install the complete production-bound Host acceptance inventory from the
# exact requested commit.
payloads=(
  scripts/harness-lifecycle-acceptance-archive.py
  scripts/harness-lifecycle-acceptance-qualification.py
  scripts/harness-lifecycle-acceptance-qualification-supervisor.py
  scripts/harness-lifecycle-acceptance-qualification-observe.py
  scripts/install-harness-lifecycle-acceptance-qualification.sh
  scripts/harness-lifecycle-acceptance-provenance.py
  scripts/harness-lifecycle-acceptance-observe.py
  scripts/harness-lifecycle-acceptance-supervisor.py
  scripts/harness-lifecycle-acceptance.py
  scripts/enroll-disposable-mac-harness-lifecycle.py
  shared/harness_lifecycle.py
  shared/harness_lifecycle_acceptance.py
  shared/harness_lifecycle_archive_fixture.py
  shared/harness_lifecycle_qualification_fixture.py
  shared/harness_lifecycle_provenance_fixture.py
  shared/harness_qualification.py
  shared/harness_qualification_fixture.py
  shared/claude_core_adapter.py
  shared/harness_archive_preflight.py
  fixtures/harness-qualification/malicious_harness.py
)

base=/usr/local/libexec/secure-sandbox-harness-acceptance
releases="$base/releases"
release="$releases/$source_commit"
state=/var/db/SecureSandbox/harness-lifecycle-acceptance
install -d -o root -g wheel -m 755 "$base" "$releases"
install -d -o root -g wheel -m 700 /var/db/SecureSandbox "$state"

lock="$base/.install.lock"
if ! /bin/mkdir -m 700 "$lock"; then
  echo "Another protected Host installation is in progress." >&2
  exit 1
fi
temporary=""
cleanup() {
  if [[ -n "$temporary" && -d "$temporary" ]]; then
    /bin/rm -rf -- "$temporary"
  fi
  /bin/rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT

[[ ! -e "$release" && ! -L "$release" ]] \
  || { echo "Protected driver release already exists; refusing overwrite." >&2; exit 1; }
temporary="$(mktemp -d "$releases/.${source_commit}.new.XXXXXX")"

# Resolve modes and bytes from immutable Git objects. No payload pathname in
# the operator-writable checkout is reopened after authorization.
for relative in "${payloads[@]}"; do
  tree_record="$("$git" -C "$repo" ls-tree "$source_commit" -- "$relative")" \
    || { echo "Unable to inspect protected-driver object: $relative" >&2; exit 2; }
  read -r object_mode object_type object_id object_path <<<"$tree_record"
  [[ "$object_type" == "blob" && "$object_path" == "$relative" \
      && ( "$object_mode" == "100644" || "$object_mode" == "100755" ) \
      && "$object_id" =~ ^[0-9a-f]{40,64}$ ]] \
    || { echo "Invalid protected-driver Git object: $relative" >&2; exit 2; }
  install -d -o root -g wheel -m 755 "$temporary/$(dirname "$relative")"
  destination="$temporary/$relative"
  "$git" -C "$repo" cat-file blob "$object_id" >"$destination" \
    || { echo "Unable to read protected-driver object: $relative" >&2; exit 2; }
  mode=444
  [[ "$relative" == scripts/* ]] && mode=555
  chown root:wheel "$destination"
  chmod "$mode" "$destination"
done

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 - "$temporary" "${payloads[@]}" <<'PY'
import pathlib, sys

root = pathlib.Path(sys.argv[1])
for relative in sys.argv[2:]:
    source = root / relative
    if source.suffix == ".py":
        compile(source.read_bytes(), str(source), "exec", dont_inherit=True)
PY
bash -n "$temporary/scripts/install-harness-lifecycle-acceptance-qualification.sh"

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 - "$temporary" "$source_commit" <<'PY'
import hashlib, importlib.util, pathlib, sys

release = pathlib.Path(sys.argv[1])
source_commit = sys.argv[2]
sys.path.insert(0, str(release / "shared"))
spec = importlib.util.spec_from_file_location(
    "installed_acceptance_cli", release / "scripts/harness-lifecycle-acceptance.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
driver_names = (
    "host-provenance-fixture", "host-archive-fixture",
    "research-qualification-fixture",
)
drivers = {
    name: list(module.PROTECTED_DRIVER_PAYLOADS[name]) for name in driver_names
}
payloads = sorted({relative for values in drivers.values() for relative in values})
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
    "drivers": drivers,
    "files": records,
}
manifest["manifest_sha256"] = module.digest(manifest)
(release / "manifest.json").write_bytes(module.canonical(manifest))
PY
chown root:wheel "$temporary/manifest.json"
chmod 444 "$temporary/manifest.json"
find "$temporary" -type d -exec chmod 555 {} +

# The root-only lock serializes the absence check and rename, so a concurrent
# installer cannot turn mv into directory nesting.
mv "$temporary" "$release"
temporary=""

# Success is emitted only after the installed verifier rereads the published
# root-owned release and its complete manifest.
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 - "$release" "$source_commit" <<'PY'
import importlib.util, pathlib, sys

release = pathlib.Path(sys.argv[1])
source_commit = sys.argv[2]
sys.path.insert(0, str(release / "shared"))
spec = importlib.util.spec_from_file_location(
    "published_acceptance_cli", release / "scripts/harness-lifecycle-acceptance.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
for driver in (
    "host-provenance-fixture", "host-archive-fixture",
    "research-qualification-fixture",
):
    module.verify_protected_driver(
        release.parent.parent, source_commit, driver, 0,
    )
PY
sync
echo "harness-lifecycle-acceptance-host:installed:$source_commit"
