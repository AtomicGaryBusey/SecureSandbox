#!/usr/bin/env python3
"""Render content-free Research session metadata with host-owned labels."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path


SCHEMA = "secure-sandbox-session-labels-v1"
RUN_SCHEMA = "secure-sandbox-session-runs-v2"
LEGACY_RUN_SCHEMA = "secure-sandbox-session-runs-v1"
RUN_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TIMESTAMP = re.compile(r"^(?:unknown|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$")
MAX_INPUT = 8 * 1024 * 1024
MAX_CATALOG_BYTES = 1024 * 1024
MAX_LABEL_BYTES = 120


def default_catalog() -> Path:
    return Path.home() / "Library" / "Application Support" / "SecureSandbox" / "session-labels.json"


def default_run_catalog() -> Path:
    return Path.home() / "Library" / "Application Support" / "SecureSandbox" / "controller-state" / "session-runs.json"


def validate_label(value: str) -> str:
    if value != value.strip() or not value:
        raise ValueError("label must be nonempty without surrounding whitespace")
    if len(value.encode("utf-8")) > MAX_LABEL_BYTES:
        raise ValueError(f"label must be at most {MAX_LABEL_BYTES} UTF-8 bytes")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("label cannot contain control characters")
    return value


def load_labels(path: Path) -> dict[str, str]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {}
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise PermissionError("session label catalog ownership or mode is untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size > MAX_CATALOG_BYTES
        ):
            raise PermissionError("opened session label catalog is untrusted")
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("session label catalog schema is invalid")
    labels = value.get("labels")
    if not isinstance(labels, dict) or len(labels) > 10_000:
        raise ValueError("session label catalog entries are invalid")
    result: dict[str, str] = {}
    for session_id, label in labels.items():
        if not isinstance(session_id, str) or UUID.fullmatch(session_id) is None:
            raise ValueError("session label catalog UUID is invalid")
        if not isinstance(label, str):
            raise ValueError("session label catalog label is invalid")
        result[session_id] = validate_label(label)
    return result


def load_run_records(path: Path) -> dict[str, dict]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {}
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_CATALOG_BYTES
    ):
        raise PermissionError("session run catalog ownership or mode is untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "r", encoding="ascii") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size > MAX_CATALOG_BYTES
        ):
            raise PermissionError("opened session run catalog is untrusted")
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema") not in {RUN_SCHEMA, LEGACY_RUN_SCHEMA}:
        raise ValueError("session run catalog schema is invalid")
    legacy = value["schema"] == LEGACY_RUN_SCHEMA
    sessions = value.get("sessions")
    if not isinstance(sessions, dict) or len(sessions) > 10_000:
        raise ValueError("session run catalog entries are invalid")
    result: dict[str, dict] = {}
    for session_id, record in sessions.items():
        if UUID.fullmatch(str(session_id)) is None or not isinstance(record, dict):
            raise ValueError("session run catalog entry is invalid")
        if set(record) != ({"last_started_at", "runs"} if legacy
                          else {"last_started_at", "runs", "run_ids"}):
            raise ValueError("session run catalog fields are invalid")
        runs = record.get("runs")
        started = record.get("last_started_at")
        if (
            not isinstance(runs, int)
            or isinstance(runs, bool)
            or not 1 <= runs <= 1_000_000
            or not isinstance(started, int)
            or isinstance(started, bool)
            or started < 0
        ):
            raise ValueError("session run catalog counter is invalid")
        links = [] if legacy else record["run_ids"]
        if (not isinstance(links, list) or len(links) > 1000 or len(links) > runs
                or any(not isinstance(item, str) or RUN_UUID.fullmatch(item) is None for item in links)
                or len(set(links)) != len(links)):
            raise ValueError("session run catalog links are invalid")
        result[session_id] = {"runs": runs, "last_started_at": started, "run_ids": links}
    return result


def load_run_counts(path: Path) -> dict[str, int]:
    return {session_id: record["runs"] for session_id, record in load_run_records(path).items()}


def session_runs(path: Path, session_id: str) -> dict:
    if UUID.fullmatch(session_id) is None:
        raise ValueError("a canonical session UUID is required")
    record = load_run_records(path).get(session_id)
    return {"schema": RUN_SCHEMA, "session_id": session_id,
            "total_runs": record["runs"] if record else 0,
            "run_ids": record["run_ids"] if record else []}


def save_labels(path: Path, labels: dict[str, str]) -> None:
    if len(labels) > 10_000:
        raise ValueError("too many session labels")
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_metadata = parent.lstat()
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != os.getuid():
        raise PermissionError("session label catalog directory is untrusted")
    os.chmod(parent, 0o700)
    payload = json.dumps(
        {"labels": dict(sorted(labels.items())), "schema": SCHEMA},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".session-labels.", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_registry(raw: bytes) -> list[tuple[str, str, str, str, str]]:
    if len(raw) > MAX_INPUT:
        raise ValueError("session registry exceeds the host rendering limit")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("session registry is not ASCII") from error
    result = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) == 2:  # Pre-DDD compatibility during rolling deployment.
            fields.extend(["unknown", "unknown", "unknown"])
        elif len(fields) == 6:  # Reject the briefly deployed untrusted run estimate.
            fields = fields[:5]
        if len(fields) != 5:
            raise ValueError("session registry row has an invalid field count")
        session_id, created, last, turns, compactions = fields
        if UUID.fullmatch(session_id) is None:
            raise ValueError("session registry contains an invalid UUID")
        if TIMESTAMP.fullmatch(created) is None or TIMESTAMP.fullmatch(last) is None:
            raise ValueError("session registry contains an invalid timestamp")
        for value in (turns, compactions):
            if value != "unknown" and (not value.isdigit() or int(value) > 1_000_000):
                raise ValueError("session registry contains an invalid counter")
        result.append((session_id, created, last, turns, compactions))
    return result


def render(path: Path, run_path: Path) -> int:
    labels = load_labels(path)
    run_counts = load_run_counts(run_path)
    rows = parse_registry(sys.stdin.buffer.read(MAX_INPUT + 1))
    print("SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL")
    for row in rows:
        session_id = row[0]
        runs = str(run_counts[session_id]) if session_id in run_counts else "unknown"
        print("\t".join((*row, runs, labels.get(session_id, "-"))))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=default_catalog())
    parser.add_argument("--run-catalog", type=Path, default=default_run_catalog())
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("render")
    label_parser = subparsers.add_parser("label")
    label_parser.add_argument("session_id")
    label_parser.add_argument("label")
    unlabel_parser = subparsers.add_parser("unlabel")
    unlabel_parser.add_argument("session_id")
    runs_parser = subparsers.add_parser("runs")
    runs_parser.add_argument("session_id")
    arguments = parser.parse_args()

    if arguments.command == "render":
        return render(arguments.catalog, arguments.run_catalog)
    if UUID.fullmatch(arguments.session_id) is None:
        raise ValueError("a canonical session UUID is required")
    if arguments.command == "runs":
        print(json.dumps(session_runs(arguments.run_catalog, arguments.session_id), sort_keys=True))
        return 0
    labels = load_labels(arguments.catalog)
    if arguments.command == "label":
        labels[arguments.session_id] = validate_label(arguments.label)
        save_labels(arguments.catalog, labels)
        print(f"labeled\t{arguments.session_id}\t{labels[arguments.session_id]}")
        return 0
    if arguments.command == "unlabel":
        labels.pop(arguments.session_id, None)
        save_labels(arguments.catalog, labels)
        print(f"unlabeled\t{arguments.session_id}")
        return 0
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
