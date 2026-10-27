#!/usr/bin/env python3
"""Import selected legacy Research continuity data without overwriting live state."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import tarfile
import uuid


ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / "plan-legacy-continuity-import.py"
MAX_JSONL_LINE = 16 * 1024 * 1024
MAX_IMPORT_FILE = 8 * 1024 * 1024 * 1024
IMPORT_CATEGORIES = {"claude_journal", "workspace_file"}
DIRECTORY_CATEGORIES = {"claude_journal_directory", "workspace_directory"}
SAFE_COMPONENT = re.compile(r"^[^/\x00]+$")
SESSION_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
WORKSPACE = "/home/agent/research-workspace"
CLAUDE_PROJECTS = Path("/home/agent/.claude/projects")
CLAUDE_JOURNAL_IDENTITIES = {
    "-home-agent": ("/home/agent", frozenset({"sdk-cli"})),
    "-home-agent-research-workspace": (WORKSPACE, frozenset({"cli", "sdk-cli"})),
}
SCOPE_ROOTS = {
    "conversation_capture": (
        Path("/var/lib/secure-sandbox/conversation-capture"),
        Path("/var/lib/secure-sandbox/conversation-outbox"),
    ),
    "evidence_receipts": (Path("/var/lib/secure-sandbox/evidence-receipts"),),
    "findings": (Path("/var/lib/secure-sandbox/findings"),),
    "memory_proposals": (Path("/var/lib/secure-sandbox/memory-proposals"),),
    "related_agent_state": (Path("/var/lib/secure-sandbox"),),
    "reports": (Path(f"{WORKSPACE}/reports"),),
    "review_materials": (
        Path(f"{WORKSPACE}/reports"), Path(f"{WORKSPACE}/review-bundles"),
    ),
    "scripts": (Path(f"{WORKSPACE}/scripts"),),
    "workspace_materials": (Path(WORKSPACE),),
}
SCOPE_CATEGORIES = (
    "claude_conversations", "conversation_capture", "evidence_receipts", "findings",
    "memory_proposals", "native_memory", "related_agent_state", "reports",
    "review_materials", "scripts", "workspace_materials",
)


class ImportError(RuntimeError):
    pass


def load_planner():
    spec = importlib.util.spec_from_file_location("legacy_continuity_planner", PLAN_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise ImportError("short_write")
        offset += written


def logical_parts(source_hex: str) -> tuple[str, ...]:
    try:
        value = os.fsdecode(bytes.fromhex(source_hex))
    except (TypeError, ValueError) as error:
        raise ImportError("source_path_invalid") from error
    path = Path(value)
    if not path.is_absolute() or any(not SAFE_COMPONENT.fullmatch(part) for part in path.parts[1:]):
        raise ImportError("source_path_invalid")
    return path.parts[1:]


def open_root(prefix: Path) -> int:
    descriptor = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        os.close(descriptor)
        raise ImportError("destination_root_untrusted")
    return descriptor


def open_directory(parent: int, component: str, *, create: bool) -> tuple[int, bool]:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(component, flags, dir_fd=parent), False
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(component, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            created = False
        descriptor = os.open(component, flags, dir_fd=parent)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            os.close(descriptor)
            raise ImportError("destination_parent_untrusted")
        return descriptor, created


def walk_directory(root: int, parts: tuple[str, ...], *, create: bool,
                   owner_uid: int, owner_gid: int) -> tuple[int, int]:
    current = os.dup(root)
    created = 0
    try:
        for component in parts:
            next_descriptor, was_created = open_directory(current, component, create=create)
            os.close(current)
            current = next_descriptor
            info = os.fstat(current)
            if info.st_uid not in {0, owner_uid} or stat.S_IMODE(info.st_mode) & 0o022:
                raise ImportError("destination_parent_untrusted")
            if was_created:
                os.fchmod(current, 0o700)
                if os.geteuid() == 0:
                    os.fchown(current, owner_uid, owner_gid)
                os.fsync(current)
            created += int(was_created)
        return current, created
    except BaseException:
        os.close(current)
        raise


def existing_digest(parent: int, name: str) -> str | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ImportError("destination_type_conflict")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ImportError("destination_changed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


class JournalValidator:
    def __init__(self, expected_session_id: str, expected_cwd: str,
                 expected_entrypoints: frozenset[str]) -> None:
        if not SESSION_UUID.fullmatch(expected_session_id):
            raise ImportError("claude_journal_invalid")
        if expected_cwd not in {value[0] for value in CLAUDE_JOURNAL_IDENTITIES.values()}:
            raise ImportError("claude_journal_invalid")
        if not expected_entrypoints:
            raise ImportError("claude_journal_invalid")
        self.expected_session_id = expected_session_id
        self.expected_cwd = expected_cwd
        self.expected_entrypoints = expected_entrypoints
        self.buffer = bytearray()
        self.lines = 0
        self.resume_record_seen = False

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        if len(self.buffer) > MAX_JSONL_LINE and b"\n" not in self.buffer:
            raise ImportError("claude_journal_invalid")
        while True:
            newline = self.buffer.find(b"\n")
            if newline < 0:
                break
            line = bytes(self.buffer[:newline])
            del self.buffer[:newline + 1]
            self.validate_line(line)

    def validate_line(self, line: bytes) -> None:
        if not line or len(line) > MAX_JSONL_LINE:
            raise ImportError("claude_journal_invalid")
        # Claude journals can retain an all-NUL crash gap from an interrupted
        # append.  It carries no JSON or executable content; preserve it
        # byte-for-byte for source fidelity while rejecting every other
        # malformed line.
        if not line.strip(b"\x00"):
            self.lines += 1
            return
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ImportError("claude_journal_invalid") from error
        if not isinstance(value, dict):
            raise ImportError("claude_journal_invalid")
        session_id = value.get("sessionId") or value.get("session_id")
        if (session_id == self.expected_session_id and value.get("cwd") == self.expected_cwd
                and value.get("entrypoint") in self.expected_entrypoints):
            self.resume_record_seen = True
        self.lines += 1

    def finish(self) -> None:
        if self.buffer or self.lines == 0 or not self.resume_record_seen:
            raise ImportError("claude_journal_invalid")


def create_file(parent: int, name: str, stream, size: int, expected: str,
                owner_uid: int, owner_gid: int, *,
                journal_identity: tuple[str, str, frozenset[str]] | None) -> str:
    if size < 0 or size > MAX_IMPORT_FILE:
        raise ImportError("archive_member_invalid")
    current = existing_digest(parent, name)
    if current is not None:
        if current != expected:
            raise ImportError("destination_conflict")
    temporary = None if current is not None else f".{name}.legacy-import-{uuid.uuid4()}"
    descriptor = None if temporary is None else os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600, dir_fd=parent,
    )
    digest = hashlib.sha256()
    validator = (JournalValidator(*journal_identity)
                 if journal_identity is not None else None)
    try:
        remaining = size
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ImportError("archive_member_invalid")
            remaining -= len(chunk)
            digest.update(chunk)
            if validator is not None:
                validator.feed(chunk)
            if descriptor is not None:
                write_all(descriptor, chunk)
        if validator is not None:
            validator.finish()
        if digest.hexdigest() != expected:
            raise ImportError("archive_payload_changed")
        if descriptor is not None:
            # Imported legacy content is data, never executable state. Do not
            # activate source-controlled mode bits from the old guest.
            os.fchmod(descriptor, 0o600)
            if os.geteuid() == 0:
                os.fchown(descriptor, owner_uid, owner_gid)
            os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if temporary is None:
        return "identical"
    try:
        # Hard-link publication is atomic and refuses to replace a concurrent file.
        os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    except FileExistsError:
        if existing_digest(parent, name) != expected:
            raise ImportError("destination_conflict")
        result = "identical"
    else:
        result = "created"
    finally:
        os.unlink(temporary, dir_fd=parent)
    os.fsync(parent)
    return result


def manifest_records(archive_path: Path) -> tuple[dict[str, dict[str, object]], str]:
    planner = load_planner()
    verifier = planner.load_verifier()
    verification = verifier.verify(archive_path, include_manifest=True)
    value = verification["_manifest"]
    return ({record["archive_path"]: record for record in value["records"]},
            verification["archive_sha256"])


def journal_identity(source_hex: str) -> tuple[str, str, frozenset[str]]:
    path = Path(os.fsdecode(bytes.fromhex(source_hex)))
    try:
        relative = path.relative_to(CLAUDE_PROJECTS)
    except ValueError as error:
        raise ImportError("claude_journal_invalid") from error
    if len(relative.parts) != 2 or not SESSION_UUID.fullmatch(path.stem):
        raise ImportError("claude_journal_invalid")
    identity = CLAUDE_JOURNAL_IDENTITIES.get(relative.parts[0])
    if identity is None:
        raise ImportError("claude_journal_invalid")
    return path.stem, identity[0], identity[1]


def open_bound_archive(path: Path, expected_sha256: str) -> tuple[int, os.stat_result]:
    before_path = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    opened = os.fstat(descriptor)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or (before_path.st_dev, before_path.st_ino) != (opened.st_dev, opened.st_ino)):
        os.close(descriptor)
        raise ImportError("archive_file_untrusted")
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        os.close(descriptor)
        raise ImportError("archive_identity_changed")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor, opened


def preserved_scope(records: dict[str, dict[str, object]]) -> tuple[dict[str, object], str]:
    evidence: dict[str, list[dict[str, object]]] = {name: [] for name in SCOPE_CATEGORIES}
    projects = Path("/home/agent/.claude/projects")
    for record in records.values():
        try:
            path = Path(os.fsdecode(bytes.fromhex(str(record["source_path_hex"]))))
        except (KeyError, TypeError, ValueError) as error:
            raise ImportError("scope_evidence_path_invalid") from error
        categories = set()
        if path.is_relative_to(projects) and path.suffix == ".jsonl":
            categories.add("claude_conversations")
        if path.is_relative_to(projects) and "memory" in path.relative_to(projects).parts:
            categories.add("native_memory")
        for category, roots in SCOPE_ROOTS.items():
            if any(path.is_relative_to(root) for root in roots):
                categories.add(category)
        item = {
            "kind": record.get("kind"),
            "omitted": record.get("omitted") is True,
            "sha256": record.get("sha256"),
            "size": record.get("size"),
            "source_path_hex": record["source_path_hex"],
        }
        for category in categories:
            evidence[category].append(item)
    result: dict[str, object] = {}
    for category in SCOPE_CATEGORIES:
        items = sorted(evidence[category], key=lambda item: str(item["source_path_hex"]))
        result[category] = {
            "records": len(items),
            "regular_bytes": sum(
                int(item["size"]) for item in items
                if item["kind"] == "regular" and isinstance(item["size"], int)
                and not isinstance(item["size"], bool)
            ),
            "sha256": hashlib.sha256(canonical(items)).hexdigest(),
        }
    return result, hashlib.sha256(canonical(result)).hexdigest()


def apply(archive_path: Path, prefix: Path, owner_user: str) -> dict[str, object]:
    planner = load_planner()
    plan = planner.plan(archive_path, prefix)
    if plan["blocking_conflicts"] or plan["status"] != "ready":
        raise ImportError("continuity_plan_blocked")
    account = pwd.getpwnam(owner_user)
    selected = {
        item["source_path_hex"]: item for item in plan["dispositions"]
        if item["category"] in IMPORT_CATEGORIES | DIRECTORY_CATEGORIES
    }
    imported_session_ids = sorted({
        Path(os.fsdecode(bytes.fromhex(item["source_path_hex"]))).stem
        for item in plan["dispositions"] if item["category"] == "claude_journal"
    })
    report_evidence = sorted(
        (
            {"source_path_hex": item["source_path_hex"], "sha256": item["sha256"]}
            for item in plan["dispositions"]
            if (item["category"] == "workspace_file"
                and Path(os.fsdecode(bytes.fromhex(item["source_path_hex"]))).is_relative_to(
                    "/home/agent/research-workspace/reports"
                ))
        ),
        key=lambda item: item["source_path_hex"],
    )
    records, manifest_archive_sha256 = manifest_records(archive_path)
    if manifest_archive_sha256 != plan["archive_sha256"]:
        raise ImportError("archive_identity_changed")
    by_member = {
        record["archive_path"]: (record, selected[record["source_path_hex"]])
        for record in records.values() if record["source_path_hex"] in selected
    }
    scope, scope_sha256 = preserved_scope(records)
    counts = {"created": 0, "identical": 0, "directories": 0}
    root = open_root(prefix)
    try:
        archive_descriptor, archive_opened = open_bound_archive(
            archive_path, str(plan["archive_sha256"])
        )
        try:
            with os.fdopen(archive_descriptor, "rb", closefd=False) as raw:
                with gzip.GzipFile(fileobj=raw, mode="rb") as compressed:
                    with tarfile.open(fileobj=compressed, mode="r|") as archive:
                        seen: set[str] = set()
                        for member in archive:
                            if member.name not in by_member:
                                continue
                            record, disposition = by_member[member.name]
                            parts = logical_parts(record["source_path_hex"])
                            category = disposition["category"]
                            if category in DIRECTORY_CATEGORIES:
                                directory, made = walk_directory(
                                    root, parts, create=True,
                                    owner_uid=account.pw_uid, owner_gid=account.pw_gid,
                                )
                                try:
                                    os.fsync(directory)
                                finally:
                                    os.close(directory)
                                counts["directories"] += made
                            else:
                                parent, made = walk_directory(
                                    root, parts[:-1], create=True,
                                    owner_uid=account.pw_uid, owner_gid=account.pw_gid,
                                )
                                counts["directories"] += made
                                try:
                                    stream = archive.extractfile(member)
                                    if stream is None:
                                        raise ImportError("archive_member_invalid")
                                    action = create_file(
                                        parent, parts[-1], stream, member.size, str(record["sha256"]),
                                        account.pw_uid, account.pw_gid,
                                        journal_identity=(
                                            journal_identity(str(record["source_path_hex"]))
                                            if category == "claude_journal" else None
                                        ),
                                    )
                                    counts[action] += 1
                                finally:
                                    os.close(parent)
                            seen.add(member.name)
                        if seen != set(by_member):
                            raise ImportError("selected_archive_members_missing")
            archive_after = os.fstat(archive_descriptor)
            if (archive_opened.st_size, archive_opened.st_mtime_ns, archive_opened.st_ctime_ns) != (
                    archive_after.st_size, archive_after.st_mtime_ns, archive_after.st_ctime_ns):
                raise ImportError("archive_changed_during_import")
        finally:
            os.close(archive_descriptor)
    finally:
        os.close(root)
    receipt = {
        "archive_sha256": plan["archive_sha256"],
        "blocking_conflicts": 0,
        "created": counts["created"],
        "directories_created": counts["directories"],
        "identical": counts["identical"],
        "manifest_sha256": plan["manifest_sha256"],
        "plan_sha256": hashlib.sha256(canonical(plan)).hexdigest(),
        "preserved_scope": scope,
        "preserved_scope_sha256": scope_sha256,
        "dispositions": len(plan["dispositions"]),
        "dispositions_sha256": hashlib.sha256(canonical(plan["dispositions"])).hexdigest(),
        "imported_session_ids": imported_session_ids,
        "report_evidence_count": len(report_evidence),
        "report_evidence_sha256": hashlib.sha256(canonical(report_evidence)).hexdigest(),
        "rejected": 0,
        "schema": "secure-sandbox-legacy-continuity-receipt-v1",
        "status": "imported",
    }
    return receipt


def atomic_receipt(path: Path, value: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise ImportError("receipt_exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        write_all(descriptor, canonical(value))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("--destination-prefix", default="/")
    parser.add_argument("--owner-user", default="agent")
    parser.add_argument("--receipt")
    parser.add_argument("--allow-non-root", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0 and not args.allow_non_root:
        raise ImportError("root_required")
    result = apply(Path(args.archive), Path(args.destination_prefix), args.owner_user)
    if args.receipt:
        atomic_receipt(Path(args.receipt), result)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ImportError, OSError, KeyError, TypeError, ValueError, tarfile.TarError,
            json.JSONDecodeError) as error:
        print(f"legacy_continuity_import_rejected:{type(error).__name__}:{error}", file=os.sys.stderr)
        raise SystemExit(1)
