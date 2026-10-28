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
from dataclasses import dataclass
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
MAX_RECORDS = 1_000_000


@dataclass
class SessionMetadata:
    created_at: datetime | None = None
    last_activity_at: datetime | None = None
    user_turns: int = 0
    compactions: int = 0
    compaction_summaries: int = 0


def earlier(current: datetime | None, observed: datetime | None) -> datetime | None:
    if observed is None:
        return current
    if current is None or observed < current:
        return observed
    return current


def later(current: datetime | None, observed: datetime | None) -> datetime | None:
    if observed is None:
        return current
    if current is None or observed > current:
        return observed
    return current


def is_human_user_turn(record: dict) -> bool:
    if (
        record.get("type") != "user"
        or record.get("isMeta") is True
        or record.get("isCompactSummary") is True
    ):
        return False
    message = record.get("message")
    if not isinstance(message, dict):
        return False
    content = message.get("content")
    if isinstance(content, str):
        return bool(content.strip())
    if not isinstance(content, list):
        return False
    return any(
        isinstance(block, dict)
        and block.get("type") in {"text", "input_text"}
        and isinstance(block.get("text"), str)
        and bool(block["text"].strip())
        for block in content
    )


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


def discover() -> dict[str, SessionMetadata]:
    agent_uid = pwd.getpwnam("agent").pw_uid
    sessions: dict[str, SessionMetadata] = {}
    admitted: set[str] = set()
    seen_files = 0
    seen_records = 0
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
                    seen_records += 1
                    if seen_records > MAX_RECORDS:
                        raise SystemExit("too many Claude journal records")
                    if len(raw) > MAX_LINE_BYTES:
                        continue
                    try:
                        record = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    session_id = record.get("sessionId") or record.get("session_id")
                    if not isinstance(session_id, str) or UUID.fullmatch(session_id) is None:
                        continue
                    session = sessions.setdefault(session_id, SessionMetadata())
                    observed = parse_timestamp(record.get("timestamp"))
                    session.last_activity_at = later(session.last_activity_at, observed)
                    if record.get("cwd") == WORKSPACE and record.get("entrypoint") == "cli":
                        admitted.add(session_id)
                        session.created_at = earlier(session.created_at, observed)
                    if is_human_user_turn(record):
                        session.user_turns += 1
                    if record.get("subtype") == "compact_boundary":
                        session.compactions += 1
                    if record.get("isCompactSummary") is True:
                        session.compaction_summaries += 1
    return {session_id: sessions[session_id] for session_id in admitted}


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_registry(sessions: dict[str, SessionMetadata]) -> None:
    REGISTRY.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".claude-sessions.", dir=REGISTRY.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            ordered = sorted(
                sessions.items(),
                key=lambda item: (
                    item[1].created_at is None,
                    item[1].created_at or datetime.max.replace(tzinfo=timezone.utc),
                    item[0],
                ),
            )
            for session_id, metadata in ordered:
                output.write(
                    f"{session_id}\t{format_timestamp(metadata.created_at)}"
                    f"\t{format_timestamp(metadata.last_activity_at)}"
                    f"\t{metadata.user_turns}"
                    f"\t{max(metadata.compactions, metadata.compaction_summaries)}\n"
                )
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
