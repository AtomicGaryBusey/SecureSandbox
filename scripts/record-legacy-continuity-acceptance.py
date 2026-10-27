#!/usr/bin/env python3
"""Record an operator-observed GLM continuity check. Never deletes VM data."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid


GENERATION = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
SESSION_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_RECEIPT = 16 * 1024 * 1024
SCOPE_CATEGORIES = {
    "claude_conversations", "conversation_capture", "evidence_receipts", "findings",
    "memory_proposals", "native_memory", "related_agent_state", "reports",
    "review_materials", "scripts", "workspace_materials",
}


class AcceptanceError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def read_json(path: Path, *, uid: int) -> dict[str, object]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or opened.st_size > MAX_RECEIPT
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise AcceptanceError(f"record_untrusted:{path.name}")
        data = bytearray()
        while chunk := os.read(descriptor, MAX_RECEIPT + 1 - len(data)):
            data.extend(chunk)
            if len(data) > MAX_RECEIPT:
                raise AcceptanceError(f"record_untrusted:{path.name}")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise AcceptanceError(f"record_changed:{path.name}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError(f"record_invalid:{path.name}") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"record_invalid:{path.name}")
    return value


def sha256_regular(path: Path, *, uid: int) -> str:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise AcceptanceError("research_archive_untrusted")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise AcceptanceError("research_archive_changed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def secure_directory(path: Path, uid: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise AcceptanceError(f"directory_untrusted:{path.name}")


def atomic_json(path: Path, value: dict[str, object], uid: int) -> None:
    if path.exists() or path.is_symlink():
        raise AcceptanceError("continuity_acceptance_exists")
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
                    raise AcceptanceError("short_write")
                offset += written
            os.fchmod(descriptor, 0o600)
            if os.fstat(descriptor).st_uid != uid:
                raise AcceptanceError("continuity_acceptance_owner_invalid")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def record(repo: Path, generation: str, session_id: str, *, observed_at: int | None = None,
           confirmations: tuple[bool, bool, bool] = (True, True, True)) -> dict[str, object]:
    if not GENERATION.fullmatch(generation) or not SESSION_UUID.fullmatch(session_id):
        raise AcceptanceError("acceptance_identity_invalid")
    if confirmations != (True, True, True):
        raise AcceptanceError("acceptance_confirmation_incomplete")
    uid = os.geteuid()
    repo = repo.resolve(strict=True)
    private = repo / ".private"
    migration = private / "legacy-migration"
    generation_root = migration / generation
    receipts = generation_root / "receipts"
    archives = generation_root / "archives"
    for directory in (private, migration, generation_root, receipts, archives):
        secure_directory(directory, uid)

    preservation = read_json(receipts / "preservation-research.json", uid=uid)
    imported = read_json(receipts / "continuity-import.json", uid=uid)
    archive_digest = sha256_regular(archives / "research.tar.gz", uid=uid)
    imported_sessions = imported.get("imported_session_ids")
    preserved_scope = imported.get("preserved_scope")
    scope_valid = bool(
        isinstance(preserved_scope, dict) and set(preserved_scope) == SCOPE_CATEGORIES
        and all(
            isinstance(value, dict) and set(value) == {"records", "regular_bytes", "sha256"}
            and isinstance(value["records"], int) and not isinstance(value["records"], bool)
            and value["records"] >= 0
            and isinstance(value["regular_bytes"], int)
            and not isinstance(value["regular_bytes"], bool) and value["regular_bytes"] >= 0
            and isinstance(value["sha256"], str) and SHA256.fullmatch(value["sha256"])
            for value in preserved_scope.values()
        )
        and isinstance(imported.get("preserved_scope_sha256"), str)
        and SHA256.fullmatch(imported["preserved_scope_sha256"])
        and hashlib.sha256(canonical(preserved_scope)).hexdigest()
        == imported["preserved_scope_sha256"]
    )
    if (preservation.get("schema") != "secure-sandbox-legacy-preservation-receipt-v1"
            or preservation.get("verification_schema")
            != "secure-sandbox-legacy-preservation-verification-v1"
            or preservation.get("status") != "verified"
            or preservation.get("generation") != generation
            or preservation.get("archive_sha256") != archive_digest
            or imported.get("schema") != "secure-sandbox-legacy-continuity-receipt-v1"
            or imported.get("status") != "imported"
            or imported.get("archive_sha256") != archive_digest
            or imported.get("blocking_conflicts") != 0 or imported.get("rejected") != 0
            or not scope_valid
            or not isinstance(imported_sessions, list) or session_id not in imported_sessions
            or not isinstance(imported.get("report_evidence_sha256"), str)
            or not SHA256.fullmatch(imported["report_evidence_sha256"])
            or not isinstance(imported.get("report_evidence_count"), int)
            or isinstance(imported.get("report_evidence_count"), bool)
            or imported.get("report_evidence_count", 0) <= 0):
        raise AcceptanceError("continuity_evidence_incomplete")

    timestamp = int(time.time()) if observed_at is None else observed_at
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp <= 0:
        raise AcceptanceError("observation_time_invalid")
    result = {
        "archive_sha256": archive_digest,
        "context_verified": True,
        "evidence_class": "operator-observed-first-person-glm",
        "generation": generation,
        "observed_at": timestamp,
        "report_evidence_sha256": imported["report_evidence_sha256"],
        "preserved_scope_sha256": imported["preserved_scope_sha256"],
        "reports_verified": True,
        "schema": "secure-sandbox-glm-continuity-acceptance-v1",
        "session_id": session_id,
        "session_resume_verified": True,
        "status": "continuous",
    }
    atomic_json(receipts / "glm-continuity.json", result, uid)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--generation", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--confirm-session-resumed", action="store_true")
    parser.add_argument("--confirm-reports-verified", action="store_true")
    parser.add_argument("--confirm-context-verified", action="store_true")
    args = parser.parse_args()
    confirmations = (
        args.confirm_session_resumed, args.confirm_reports_verified, args.confirm_context_verified,
    )
    if confirmations != (True, True, True) or not sys.stdin.isatty():
        raise AcceptanceError("interactive_operator_confirmation_required")
    expected = f"ACCEPT {args.session_id}"
    entered = input(
        "After personally observing GLM resume this session and verify its reports/context,\n"
        f"type exactly: {expected}\n> "
    )
    if entered != expected:
        raise AcceptanceError("operator_confirmation_mismatch")
    print(json.dumps(record(
        Path(args.repo), args.generation, args.session_id, confirmations=confirmations,
    ), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, ValueError) as error:
        print(f"legacy_continuity_acceptance_rejected:{type(error).__name__}:{error}", file=sys.stderr)
        raise SystemExit(1)
