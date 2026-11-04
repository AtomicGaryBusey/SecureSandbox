#!/usr/bin/env python3
"""Fail-closed lifetime guard for the Research native-harness compartment.

The service owns no provider credential and launches no tool. It keeps the
native network compartment eligible only while one immutable, unexpired grant
remains readable by the dedicated service identity. Native session scopes are
created separately by the root controller and are stopped before this guard.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import signal
import stat
import time
from pathlib import Path
from typing import Callable

from shared import native_egress


GRANT = Path("/var/lib/secure-sandbox/native-egress/active.json")
IDENTITY = "native-harness"
POLL_SECONDS = 0.25


class NativeHarnessSupervisorError(RuntimeError):
    """Stable supervisor failure."""


def require_identity() -> pwd.struct_passwd:
    try:
        identity = pwd.getpwnam(IDENTITY)
    except KeyError as error:
        raise NativeHarnessSupervisorError("native_harness_identity_missing") from error
    if (
        identity.pw_uid == 0
        or identity.pw_gid == 0
        or os.geteuid() != identity.pw_uid
        or os.getegid() != identity.pw_gid
        or set(os.getgroups()) - {identity.pw_gid}
        or identity.pw_dir != "/var/empty"
        or identity.pw_shell != "/usr/sbin/nologin"
    ):
        raise NativeHarnessSupervisorError("native_harness_identity_invalid")
    return identity


def observed_grant(
    path: Path,
    *,
    gid: int,
    now: int,
    expected_uid: int = 0,
) -> tuple[str, tuple[int, int, int, int, int]]:
    try:
        parent = path.parent.lstat()
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as error:
        raise NativeHarnessSupervisorError("native_harness_grant_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= native_egress.MAX_GRANT_BYTES:
            block = os.read(
                descriptor,
                min(65536, native_egress.MAX_GRANT_BYTES + 1 - len(raw)),
            )
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != expected_uid
        or parent.st_mode & 0o022
        or not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or opened.st_gid != gid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o640
        or not 2 <= opened.st_size <= native_egress.MAX_GRANT_BYTES
        or (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        ) != (
            opened.st_dev, opened.st_ino, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns,
        )
        or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or len(raw) != opened.st_size
    ):
        raise NativeHarnessSupervisorError("native_harness_grant_untrusted")
    try:
        value = json.loads(raw)
        grant = native_egress.validate_grant(value, now=now)
    except (UnicodeDecodeError, json.JSONDecodeError, native_egress.NativeEgressError) as error:
        raise NativeHarnessSupervisorError("native_harness_grant_untrusted") from error
    if bytes(raw) != native_egress.canonical_bytes(grant):
        raise NativeHarnessSupervisorError("native_harness_grant_untrusted")
    return grant["grant_sha256"], (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )


def monitor(
    path: Path,
    *,
    gid: int,
    now: Callable[[], int] = lambda: int(time.time()),
    sleep: Callable[[float], None] = time.sleep,
    stopping: Callable[[], bool] = lambda: False,
) -> None:
    try:
        expected_digest, expected_identity = observed_grant(path, gid=gid, now=now())
    except (OSError, native_egress.NativeEgressError) as error:
        raise NativeHarnessSupervisorError("native_harness_grant_invalid") from error
    while not stopping():
        sleep(POLL_SECONDS)
        try:
            digest, identity = observed_grant(path, gid=gid, now=now())
        except (OSError, native_egress.NativeEgressError) as error:
            raise NativeHarnessSupervisorError("native_harness_grant_lost") from error
        if digest != expected_digest or identity != expected_identity:
            raise NativeHarnessSupervisorError("native_harness_grant_changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--grant", type=Path, default=GRANT)
    args = parser.parse_args()
    try:
        identity = require_identity()
        observed_grant(args.grant, gid=identity.pw_gid, now=int(time.time()))
        if args.validate:
            return 0
        state = {"stopping": False}

        def stop(_signal: int, _frame: object) -> None:
            state["stopping"] = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        monitor(
            args.grant,
            gid=identity.pw_gid,
            stopping=lambda: state["stopping"],
        )
        return 0
    except (NativeHarnessSupervisorError, native_egress.NativeEgressError, OSError) as error:
        print(str(error), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
