#!/usr/bin/env python3
"""Activate verified legacy Research continuity from the root-owned archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = Path("/usr/local/libexec/secure-sandbox")
ARCHIVE = Path("/var/lib/secure-sandbox/legacy-migration/research.tar.gz")
STATE = Path("/var/lib/secure-sandbox/legacy-migration")
PLAN = STATE / "continuity-plan.json"
RECEIPT = STATE / "continuity-import.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TOOLS = {
    "importer": ROOT / "import-legacy-continuity.py",
    "planner": ROOT / "plan-legacy-continuity-import.py",
    "session_registry": ROOT / "session_registry.py",
    "verifier": ROOT / "verify-legacy-archive.py",
}


class ContinuityError(RuntimeError):
    pass


def trusted_regular(path: Path, mode: int, maximum: int) -> os.stat_result:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_gid != 0
                or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != mode
                or opened.st_size > maximum
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ContinuityError(f"file_untrusted:{path.name}")
        return opened
    finally:
        os.close(descriptor)


def require_idle() -> None:
    blocked = (
        Path("/run/secure-sandbox/run-id"), Path("/run/secure-sandbox/evidence-run-id"),
        Path("/var/lib/secure-sandbox/run-lifecycle/active.json"),
        Path("/var/lib/secure-sandbox/run-lifecycle/failure-latched.json"),
    )
    if any(path.exists() for path in blocked):
        raise ContinuityError("agent_lifecycle_not_idle")
    result = subprocess.run(
        ["/usr/bin/pgrep", "-x", "claude"], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode != 1:
        raise ContinuityError("agent_lifecycle_not_idle")


def run(command: list[str], *, stdout=None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command, check=False, stdin=subprocess.DEVNULL,
        stdout=stdout if stdout is not None else subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    if result.returncode:
        raise ContinuityError(
            f"command_failed:{Path(command[0]).name}:{result.stderr.decode('utf-8', 'replace')[:400]}"
        )
    return result


def json_output(command: list[str]) -> dict[str, object]:
    result = run(command)
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContinuityError("command_output_invalid") from error
    if not isinstance(value, dict):
        raise ContinuityError("command_output_invalid")
    return value


def atomic_plan(archive: Path) -> None:
    temporary = PLAN.with_name(f".{PLAN.name}.new-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            run(["/usr/bin/python3", "-I", str(TOOLS["planner"]), str(archive)], stdout=output)
            output.flush()
            os.fsync(output.fileno())
        value = json.loads(temporary.read_bytes())
        if value.get("status") != "ready" or value.get("blocking_conflicts") != 0:
            raise ContinuityError("continuity_plan_blocked")
        os.replace(temporary, PLAN)
        directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def activate(expected_archive_sha256: str) -> dict[str, object]:
    if os.geteuid() != 0:
        raise ContinuityError("root_required")
    if not SHA256.fullmatch(expected_archive_sha256):
        raise ContinuityError("archive_sha256_invalid")
    require_idle()
    for path in TOOLS.values():
        trusted_regular(path, 0o755, 64 * 1024 * 1024)
    trusted_regular(ARCHIVE, 0o600, 64 * 1024 * 1024 * 1024)
    verification = json_output([
        "/usr/bin/python3", "-I", str(TOOLS["verifier"]), str(ARCHIVE),
    ])
    if (verification.get("status") != "verified" or verification.get("role") != "research"
            or verification.get("archive_sha256") != expected_archive_sha256):
        raise ContinuityError("research_archive_verification_failed")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_info = STATE.lstat()
    if (not stat.S_ISDIR(state_info.st_mode) or STATE.is_symlink() or state_info.st_uid != 0
            or state_info.st_gid != 0 or stat.S_IMODE(state_info.st_mode) != 0o700):
        raise ContinuityError("continuity_state_untrusted")
    if RECEIPT.exists():
        trusted_regular(RECEIPT, 0o600, 1024 * 1024)
        receipt = json.loads(RECEIPT.read_bytes())
        if (receipt.get("status") != "imported"
                or receipt.get("archive_sha256") != expected_archive_sha256):
            raise ContinuityError("continuity_receipt_conflict")
    else:
        atomic_plan(ARCHIVE)
        receipt = json_output([
            "/usr/bin/python3", "-I", str(TOOLS["importer"]), str(ARCHIVE),
            "--destination-prefix", "/", "--owner-user", "agent", "--receipt", str(RECEIPT),
        ])
        if receipt.get("status") != "imported" or receipt.get("archive_sha256") != expected_archive_sha256:
            raise ContinuityError("continuity_import_failed")
        trusted_regular(RECEIPT, 0o600, 1024 * 1024)
        trusted_regular(PLAN, 0o600, 1024 * 1024 * 1024)
        plan_sha256 = hashlib.sha256(PLAN.read_bytes()).hexdigest()
        if receipt.get("plan_sha256") != plan_sha256:
            raise ContinuityError("continuity_plan_receipt_mismatch")
    run([
        "/usr/bin/python3", "-I", str(TOOLS["session_registry"]), "refresh",
    ])
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive_sha256")
    args = parser.parse_args()
    print(json.dumps(activate(args.archive_sha256), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContinuityError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"legacy_continuity_rejected:{type(error).__name__}:{error}", file=sys.stderr)
        raise SystemExit(1)
