#!/usr/bin/env python3
"""Manage the root-owned SecureSandbox telemetry run marker."""

from __future__ import annotations

import os
import sys
import uuid
import fcntl
from contextlib import contextmanager
from pathlib import Path


RUN_DIRECTORY = Path("/run/secure-sandbox")
RUN_ID_FILE = RUN_DIRECTORY / "run-id"
LOCK_FILE = RUN_DIRECTORY / ".run-id.lock"
SPECIAL_RUN_IDS = {"boundary-test"}


def canonical_run_id(value: str) -> str:
    if value in SPECIAL_RUN_IDS:
        return value
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError("run ID must be a canonical UUIDv4 or boundary-test")
    return str(parsed)


@contextmanager
def marker_lock():
    RUN_DIRECTORY.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def set_run_id(value: str) -> None:
    canonical = canonical_run_id(value)
    with marker_lock():
        if RUN_ID_FILE.exists():
            raise FileExistsError("a SecureSandbox run is already active")
        temporary = RUN_DIRECTORY / f".run-id.{os.getpid()}"
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o644,
            )
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                handle.write(canonical + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chown(temporary, 0, 0)
            os.chmod(temporary, 0o644)
            os.replace(temporary, RUN_ID_FILE)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def clear_run_id(expected: str | None = None) -> None:
    with marker_lock():
        if expected is not None:
            expected = canonical_run_id(expected)
            try:
                actual = RUN_ID_FILE.read_text(encoding="ascii").strip()
            except FileNotFoundError:
                return
            if actual != expected:
                raise PermissionError("active run marker belongs to another workflow")
        try:
            RUN_ID_FILE.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if len(sys.argv) == 3 and sys.argv[1] == "set":
        set_run_id(sys.argv[2])
        return
    if len(sys.argv) in {2, 3} and sys.argv[1] == "clear":
        clear_run_id(sys.argv[2] if len(sys.argv) == 3 else None)
        return
    raise SystemExit("usage: manage_run_id.py set RUN_ID | clear [EXPECTED_RUN_ID]")


if __name__ == "__main__":
    main()
