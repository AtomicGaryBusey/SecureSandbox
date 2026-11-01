#!/bin/bash
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on the disposable Mac." >&2; exit 1; }
source_commit="${1:-}"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "Invalid source commit." >&2; exit 2; }
bootstrap_base=/usr/local/libexec/secure-sandbox-harness-acceptance-bootstrap
expected_installer="$bootstrap_base/$source_commit/scripts/$(basename "${BASH_SOURCE[0]}")"
/usr/bin/python3 -I - "$expected_installer" "${BASH_SOURCE[0]}" "$bootstrap_base" \
    "$bootstrap_base/$source_commit" <<'PY'
import pathlib, stat, sys

expected = pathlib.Path(sys.argv[1])
source = pathlib.Path(sys.argv[2])
paths = [pathlib.Path(value) for value in sys.argv[3:]] + [expected.parent, expected]
if source.resolve(strict=True) != expected:
    raise SystemExit("Protected installer must run from the root-owned bootstrap checkout.")
for path in paths:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise SystemExit("Protected installer bootstrap path is not trusted.")
    if path == expected:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("Protected installer bootstrap file is not trusted.")
    elif not stat.S_ISDIR(info.st_mode):
        raise SystemExit("Protected installer bootstrap directory is not trusted.")
PY
git=/usr/bin/git
public_ref=refs/heads/public-release
authorized_remote=https://github.com/AtomicGaryBusey/SecureSandbox.git
trusted_git() {
  /usr/bin/env -i \
    PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    "$git" "$@"
}
remote_tip="$(cd / && trusted_git ls-remote --exit-code \
  "$authorized_remote" "$public_ref")" \
  || { echo "Authorized publication tip is unavailable." >&2; exit 2; }
[[ "$remote_tip" == "$source_commit"$'\t'"$public_ref" ]] \
  || { echo "Requested commit is not the authorized publication tip." >&2; exit 2; }

# Install the complete production-bound Host acceptance inventory from the
# exact requested commit.
payloads=(
  scripts/harness-lifecycle-acceptance-bootstrap.py
  scripts/harness-lifecycle-acceptance-archive.py
  scripts/harness-lifecycle-acceptance-authorization.py
  scripts/harness-lifecycle-acceptance-authorization-observe.py
  scripts/harness-lifecycle-acceptance-runtime.py
  scripts/harness-lifecycle-acceptance-management.py
  scripts/harness-lifecycle-acceptance-scenario-cli.py
  scripts/harness-lifecycle-acceptance-scenario-supervisor.py
  scripts/harness-lifecycle-acceptance-scenario-observe.py
  scripts/harness-lifecycle-acceptance-scenario-research.py
  scripts/install-harness-lifecycle-acceptance-scenarios.sh
  scripts/harness-lifecycle-acceptance-qualification.py
  scripts/harness-lifecycle-acceptance-qualification-supervisor.py
  scripts/harness-lifecycle-acceptance-qualification-observe.py
  scripts/harness-lifecycle-acceptance-cold-boot.py
  scripts/harness-lifecycle-acceptance-export.py
  scripts/install-harness-lifecycle-acceptance-qualification.sh
  scripts/harness-lifecycle-acceptance-provenance.py
  scripts/harness-lifecycle-acceptance-observe.py
  scripts/harness-lifecycle-acceptance-supervisor.py
  scripts/harness-lifecycle-acceptance-recovery.py
  scripts/harness-lifecycle-acceptance-recovery-observe.py
  scripts/install-harness-lifecycle-acceptance-recovery.sh
  scripts/harness-lifecycle-acceptance.py
  scripts/host-controller-release.py
  scripts/enroll-disposable-mac-harness-lifecycle.py
  shared/harness_lifecycle.py
  shared/harness_lifecycle_acceptance.py
  shared/harness_lifecycle_acceptance_interactive.py
  shared/harness_lifecycle_acceptance_scenarios.py
  shared/harness_lifecycle_acceptance_fixture.py
  shared/harness_runtime_binding.py
  shared/harness_generation_store.py
  shared/privileged_workflow.py
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
trusted_repository=""
cleanup() {
  if [[ -n "$temporary" && -d "$temporary" ]]; then
    /bin/rm -rf -- "$temporary"
  fi
  if [[ -n "$trusted_repository" && -d "$trusted_repository" ]]; then
    /bin/rm -rf -- "$trusted_repository"
  fi
  /bin/rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT

[[ ! -e "$release" && ! -L "$release" ]] \
  || { echo "Protected driver release already exists; refusing overwrite." >&2; exit 1; }
trusted_repository="$(mktemp -d "$state/.source.${source_commit}.XXXXXX")"
trusted_git init --quiet --bare --template= "$trusted_repository"
trusted_git -C "$trusted_repository" fetch --quiet --no-tags --depth=1 \
  "$authorized_remote" "$public_ref:refs/heads/accepted"
resolved_commit="$(trusted_git -C "$trusted_repository" rev-parse --verify \
  "refs/heads/accepted^{commit}")" \
  || { echo "Requested commit is unavailable from the authority." >&2; exit 2; }
[[ "$resolved_commit" == "$source_commit" ]] \
  || { echo "Authorized publication changed during installation." >&2; exit 2; }
temporary="$(mktemp -d "$releases/.${source_commit}.new.XXXXXX")"

# Resolve modes and bytes only from the fresh root-owned object store. No Git
# configuration, object, index, hook, or payload from the operator-writable
# checkout is consumed after authorization.
for relative in "${payloads[@]}"; do
  tree_record="$(trusted_git -C "$trusted_repository" \
    ls-tree "$source_commit" -- "$relative")" \
    || { echo "Unable to inspect protected-driver object: $relative" >&2; exit 2; }
  read -r object_mode object_type object_id object_path <<<"$tree_record"
  [[ "$object_type" == "blob" && "$object_path" == "$relative" \
      && ( "$object_mode" == "100644" || "$object_mode" == "100755" ) \
      && "$object_id" =~ ^[0-9a-f]{40,64}$ ]] \
    || { echo "Invalid protected-driver Git object: $relative" >&2; exit 2; }
  install -d -o root -g wheel -m 755 "$temporary/$(dirname "$relative")"
  destination="$temporary/$relative"
  trusted_git -C "$trusted_repository" cat-file blob "$object_id" >"$destination" \
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
bash -n "$temporary/scripts/install-harness-lifecycle-acceptance-recovery.sh"
bash -n "$temporary/scripts/install-harness-lifecycle-acceptance-scenarios.sh"

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
    "clean-machine-bootstrap",
    "host-provenance-fixture", "host-archive-fixture",
    "research-qualification-fixture", "touchid-authorization-fixture",
    "bound-session-runtime-fixture", "protected-management-fixture",
    "research-recovery-fixture",
    "cold-boot-readback-fixture", "independent-export-fixture",
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
    "clean-machine-bootstrap",
    "host-provenance-fixture", "host-archive-fixture",
    "research-qualification-fixture", "touchid-authorization-fixture",
    "bound-session-runtime-fixture", "protected-management-fixture",
    "research-recovery-fixture",
    "cold-boot-readback-fixture", "independent-export-fixture",
):
    module.verify_protected_driver(
        release.parent.parent, source_commit, driver, 0,
    )
PY
sync
echo "harness-lifecycle-acceptance-host:installed:$source_commit"
