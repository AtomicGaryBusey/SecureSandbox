#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || exit 1
campaign_id="${1:-}"
source_commit="${2:-}"
case_id="${3:-}"
[[ "$campaign_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || exit 2
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || exit 2
[[ "$case_id" == qualification-zero-production-authority ]] || exit 2

/usr/bin/python3 -I - "$campaign_id" "$source_commit" "$case_id" <<'PY'
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

campaign_id, source_commit, case_id = sys.argv[1:]
release = Path(
    "/usr/local/libexec/secure-sandbox/"
    "harness-lifecycle-acceptance-qualification"
) / source_commit
root = Path(
    "/var/lib/secure-sandbox/harness-lifecycle-acceptance"
) / campaign_id
output_root = root / "qualification-fixtures"
case = output_root / case_id


def directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise SystemExit("qualification_diagnostic_directory_untrusted")


for path in (root, output_root):
    directory(path)
release_info = release.lstat()
if (not stat.S_ISDIR(release_info.st_mode) or stat.S_ISLNK(release_info.st_mode)
        or release_info.st_uid != 0
        or stat.S_IMODE(release_info.st_mode) != 0o755):
    raise SystemExit("qualification_diagnostic_release_untrusted")

guard_paths = (
    "/run/secure-sandbox/run-id",
    "/run/secure-sandbox/evidence-run-id",
    "/var/lib/secure-sandbox/run-lifecycle/active.json",
    "/var/lib/secure-sandbox/run-lifecycle/failure-latched.json",
)
guard_presence = {path: os.path.lexists(path) for path in guard_paths}
try:
    process = subprocess.run(
        ["/usr/bin/pgrep", "-x", "claude"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        timeout=5,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
except (OSError, subprocess.SubprocessError):
    raise SystemExit("qualification_diagnostic_process_readback_failed")
if process.returncode not in {0, 1}:
    raise SystemExit("qualification_diagnostic_process_readback_failed")

fixture_inventory = sorted(item.name for item in output_root.iterdir())
if any("/" in name or name in {"", ".", ".."}
       for name in fixture_inventory):
    raise SystemExit("qualification_diagnostic_inventory_untrusted")
entries = {item.name: item for item in case.iterdir()} if case.exists() else {}
if not set(entries) <= {"worker.json", "worker.stderr", "result.json"}:
    raise SystemExit("qualification_diagnostic_inventory_untrusted")
files = {}
for name, path in sorted(entries.items()):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 1024 * 1024):
        raise SystemExit("qualification_diagnostic_file_untrusted")
    raw = path.read_bytes()
    files[name] = {
        "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
    }

staged = {
    "harness-lifecycle-acceptance-qualification.py":
        release / "scripts/harness-lifecycle-acceptance-qualification.py",
    "harness_lifecycle_acceptance.py":
        release / "shared/harness_lifecycle_acceptance.py",
    "harness_lifecycle_qualification_fixture.py":
        release / "shared/harness_lifecycle_qualification_fixture.py",
    "harness_qualification.py": release / "shared/harness_qualification.py",
    "harness_qualification_fixture.py":
        release / "shared/harness_qualification_fixture.py",
    "claude_core_adapter.py": release / "shared/claude_core_adapter.py",
    "malicious_harness.py":
        release / "fixtures/harness-qualification/malicious_harness.py",
}
mismatches = []
for name, destination in staged.items():
    source = Path("/tmp") / name
    if (not source.is_file() or source.is_symlink()
            or not destination.is_file() or destination.is_symlink()
            or source.read_bytes() != destination.read_bytes()):
        mismatches.append(name)
campaign_source = Path("/tmp/campaign.json")
campaign_match = (
    campaign_source.is_file()
    and not campaign_source.is_symlink()
    and campaign_source.read_bytes() == (root / "campaign.json").read_bytes()
)

audit_path = Path("/var/lib/secure-sandbox/control/audit.jsonl")
audit_info = audit_path.lstat()
if (not stat.S_ISREG(audit_info.st_mode) or stat.S_ISLNK(audit_info.st_mode)
        or audit_info.st_uid != 0 or audit_info.st_nlink != 1
        or stat.S_IMODE(audit_info.st_mode) != 0o600
        or audit_info.st_size > 8 * 1024 * 1024):
    raise SystemExit("qualification_diagnostic_audit_untrusted")
audit_tail = []
for raw_line in audit_path.read_bytes().splitlines()[-24:]:
    value = json.loads(raw_line)
    if value.get("schema") != "secure-sandbox-privileged-control-audit-v1":
        raise SystemExit("qualification_diagnostic_audit_invalid")
    audit_tail.append({key: value.get(key) for key in (
        "timestamp", "outcome", "kind", "operation", "error", "request_id",
    )})

print(json.dumps({
    "authority": "diagnostic-only",
    "control_audit_tail": audit_tail,
    "campaign_id": campaign_id,
    "case_id": case_id,
    "claude_process_present": process.returncode == 0,
    "files": files,
    "fixture_inventory": fixture_inventory,
    "guard_path_presence": guard_presence,
    "installed_release_mismatches": mismatches,
    "research_campaign_match": campaign_match,
    "release": source_commit,
    "schema": "secure-sandbox-qualification-research-diagnostic-v1",
    "status": "observed",
}, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
PY
