#!/usr/bin/env python3
"""Maintain a root-owned allowlist of Claude sessions created in Research."""

from __future__ import annotations

import json
import fcntl
import os
import pwd
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path


JOURNAL_ROOT = Path("/home/agent/.claude/projects")
REGISTRY = Path("/var/lib/secure-sandbox/claude-sessions.txt")
LOCK = Path("/var/lib/secure-sandbox/session-registry.lock")
WORKSPACE = "/home/agent/research-workspace"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_FILES = 10_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("session registry maintenance requires root")


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def discover() -> dict[str, datetime | None]:
    agent_uid = pwd.getpwnam("agent").pw_uid
    sessions: dict[str, datetime | None] = {}
    seen_files = 0
    if not JOURNAL_ROOT.is_dir():
        return sessions

    for directory, dirnames, filenames in os.walk(JOURNAL_ROOT, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for filename in filenames:
            if not filename.endswith(".jsonl"):
                continue
            seen_files += 1
            if seen_files > MAX_FILES:
                raise SystemExit("too many Claude journal files")
            path = Path(directory, filename)
            try:
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != agent_uid:
                    continue
                if metadata.st_size > MAX_FILE_BYTES:
                    continue
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            except (FileNotFoundError, OSError):
                continue
            with os.fdopen(descriptor, "rb") as journal:
                for raw in journal:
                    if len(raw) > MAX_LINE_BYTES:
                        continue
                    try:
                        record = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    session_id = record.get("sessionId") or record.get("session_id")
                    if (
                        isinstance(session_id, str)
                        and UUID.fullmatch(session_id)
                        and record.get("cwd") == WORKSPACE
                        and record.get("entrypoint") == "cli"
                    ):
                        observed = parse_timestamp(record.get("timestamp"))
                        existing = sessions.get(session_id)
                        if session_id not in sessions or (
                            observed is not None and (existing is None or observed < existing)
                        ):
                            sessions[session_id] = observed
    return sessions


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_registry(sessions: dict[str, datetime | None]) -> None:
    REGISTRY.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".claude-sessions.", dir=REGISTRY.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            ordered = sorted(
                sessions.items(),
                key=lambda item: (
                    item[1] is None,
                    item[1] or datetime.max.replace(tzinfo=timezone.utc),
                    item[0],
                ),
            )
            for session_id, created_at in ordered:
                output.write(f"{session_id}\t{format_timestamp(created_at)}\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, REGISTRY)
        directory_fd = os.open(REGISTRY.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@contextmanager
def registry_lock():
    LOCK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor = os.open(
        LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise SystemExit("untrusted session registry lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def registry_contains(session_id: str) -> bool:
    if not REGISTRY.exists():
        return False
    registered = {
        line.partition("\t")[0]
        for line in REGISTRY.read_text(encoding="ascii").splitlines()
        if "\t" in line
    }
    return session_id in registered


def main() -> int:
    require_root()
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command not in {"refresh", "refresh-list", "list", "contains", "refresh-contains"}:
        print("usage: session_registry.py refresh|refresh-list|list|contains SESSION_UUID|refresh-contains SESSION_UUID", file=sys.stderr)
        return 2
    if command in {"refresh", "refresh-list", "list"} and len(sys.argv) != 2:
        return 2
    if command in {"contains", "refresh-contains"} and (
        len(sys.argv) != 3 or UUID.fullmatch(sys.argv[2]) is None
    ):
        return 2
    with registry_lock():
        if command in {"refresh", "refresh-list", "refresh-contains"}:
            sessions = discover()
            write_registry(sessions)
            if command == "refresh-contains":
                return 0 if sys.argv[2] in sessions else 1
        if command in {"list", "refresh-list"}:
            if REGISTRY.exists():
                sys.stdout.write(REGISTRY.read_text(encoding="ascii"))
            return 0
        if command == "contains":
            return 0 if registry_contains(sys.argv[2]) else 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
