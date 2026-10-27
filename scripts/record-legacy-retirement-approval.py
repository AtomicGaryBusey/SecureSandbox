#!/usr/bin/env python3
"""Record explicit legacy-generation retirement approval; never deletes data."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "scripts/legacy-migration-status.py"
GENERATION = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ROLES = ("gateway", "research", "target")
MAX_RECEIPT = 16 * 1024 * 1024


class ApprovalError(RuntimeError):
    pass


def load_status():
    spec = importlib.util.spec_from_file_location("legacy_migration_status_for_approval", STATUS_PATH)
    if spec is None or spec.loader is None:
        raise ApprovalError("status_evaluator_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def secure_directory(path: Path, uid: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ApprovalError(f"directory_untrusted:{path.name}")


def read_json(path: Path, uid: int) -> dict[str, object]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or opened.st_size > MAX_RECEIPT
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ApprovalError(f"record_untrusted:{path.name}")
        data = bytearray()
        while chunk := os.read(descriptor, MAX_RECEIPT + 1 - len(data)):
            data.extend(chunk)
            if len(data) > MAX_RECEIPT:
                raise ApprovalError(f"record_untrusted:{path.name}")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ApprovalError(f"record_changed:{path.name}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApprovalError(f"record_invalid:{path.name}") from error
    if not isinstance(value, dict):
        raise ApprovalError(f"record_invalid:{path.name}")
    return value


def atomic_json(path: Path, value: dict[str, object], uid: int) -> None:
    if path.exists() or path.is_symlink():
        raise ApprovalError("retirement_approval_exists")
    temporary = path.with_name(f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}")
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            data = canonical(value)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise ApprovalError("short_write")
                offset += written
            os.fchmod(descriptor, 0o600)
            if os.fstat(descriptor).st_uid != uid:
                raise ApprovalError("retirement_approval_owner_invalid")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        parent = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def record(repo: Path, generation: str, *, confirmations: tuple[bool, bool, bool],
           approved_at: int | None = None, status_module=None) -> dict[str, object]:
    if not GENERATION.fullmatch(generation):
        raise ApprovalError("generation_invalid")
    if confirmations != (True, True, True):
        raise ApprovalError("retirement_confirmation_incomplete")
    uid = os.geteuid()
    repo = repo.resolve(strict=True)
    generation_root = repo / ".private/legacy-migration" / generation
    archives = generation_root / "archives"
    receipts = generation_root / "receipts"
    for directory in (
        repo / ".private", repo / ".private/legacy-migration",
        generation_root, archives, receipts,
    ):
        secure_directory(directory, uid)
    status_module = load_status() if status_module is None else status_module
    evaluation = status_module.evaluate(repo, generation)
    failed = evaluation.get("failed_gates")
    if failed != ["operator_retirement_approved"]:
        raise ApprovalError("technical_gates_incomplete")

    hashes: dict[str, str] = {}
    for role in ROLES:
        receipt = read_json(receipts / f"preservation-{role}.json", uid)
        digest = status_module.sha256_regular(archives / f"{role}.tar.gz")
        if (not isinstance(digest, str) or not SHA256.fullmatch(digest)
                or receipt.get("schema") != "secure-sandbox-legacy-preservation-receipt-v1"
                or receipt.get("status") != "verified"
                or receipt.get("role") != role or receipt.get("generation") != generation
                or receipt.get("archive_sha256") != digest):
            raise ApprovalError(f"preservation_evidence_invalid:{role}")
        hashes[role] = digest
    timestamp = int(time.time()) if approved_at is None else approved_at
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp <= 0:
        raise ApprovalError("approval_time_invalid")
    result = {
        "approved_at": timestamp,
        "archive_sha256": hashes,
        "evidence_class": "operator-explicit-after-all-technical-gates",
        "generation": generation,
        "glm_continuity_confirmed": True,
        "independent_backup_confirmed": True,
        "retirement_understood": True,
        "schema": "secure-sandbox-legacy-retirement-approval-v1",
        "status": "approved",
    }
    atomic_json(receipts / "operator-retirement-approval.json", result, uid)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(ROOT))
    parser.add_argument("--generation", required=True)
    parser.add_argument("--confirm-glm-continuity", action="store_true")
    parser.add_argument("--confirm-independent-backup", action="store_true")
    parser.add_argument("--confirm-retirement-understood", action="store_true")
    args = parser.parse_args()
    confirmations = (
        args.confirm_glm_continuity,
        args.confirm_independent_backup,
        args.confirm_retirement_understood,
    )
    if confirmations != (True, True, True) or not sys.stdin.isatty():
        raise ApprovalError("interactive_retirement_confirmation_required")
    expected = f"AUTHORIZE RETIREMENT {args.generation}"
    entered = input(
        "This records eligibility to retire the named quarantined generation. It does not delete it.\n"
        "Continue only after personally verifying GLM continuity and the independent backup.\n"
        f"Type exactly: {expected}\n> "
    )
    if entered != expected:
        raise ApprovalError("retirement_confirmation_mismatch")
    print(json.dumps(record(
        Path(args.repo), args.generation, confirmations=confirmations,
    ), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ApprovalError, OSError, ValueError) as error:
        print(f"legacy_retirement_approval_rejected:{type(error).__name__}:{error}", file=sys.stderr)
        raise SystemExit(1)
