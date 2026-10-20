#!/usr/bin/env python3
"""Terminate the exact tagged Claude process group when a run lease expires."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import pwd
import signal
import stat
import time
import uuid
from pathlib import Path
from typing import Any

RUN_DIRECTORY = Path("/run/secure-sandbox")
RUN_ID_FILE = RUN_DIRECTORY / "run-id"
LEASE_FILE = RUN_DIRECTORY / "run-lease.json"
PROCESS_FILE = RUN_DIRECTORY / "run-process.json"
LOCK_FILE = RUN_DIRECTORY / "run-lease.lock"
PROC = Path("/proc")
SCHEMA = "secure-sandbox-research-run-lease-v1"


def canonical_uuid4(value: str, name: str) -> str:
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError(f"{name} must be a canonical UUIDv4")
    return str(parsed)


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.chown(temporary, 0, 0); os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


@contextlib.contextmanager
def lease_lock():
    descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def arm(run_id: str, lease_id: str, expires_at: int) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    lease_id = canonical_uuid4(lease_id, "lease ID")
    if expires_at <= int(time.time()):
        raise ValueError("lease expiry must be in the future")
    with lease_lock():
        if RUN_ID_FILE.read_text(encoding="ascii").strip() != run_id:
            raise PermissionError("run marker mismatch")
        if LEASE_FILE.exists():
            raise FileExistsError("a Research run lease is already armed")
        value = {"schema": SCHEMA, "run_id": run_id, "lease_id": lease_id, "expires_at": expires_at}
        atomic_json(LEASE_FILE, value)
        process = {"schema": "secure-sandbox-run-process-v1", "run_id": run_id,
                   "lease_id": lease_id, "ready": False}
        try:
            atomic_json(PROCESS_FILE, process)
        except Exception:
            try: LEASE_FILE.unlink()
            except FileNotFoundError: pass
            raise
        return value


def disarm(run_id: str) -> None:
    run_id = canonical_uuid4(run_id, "run ID")
    with lease_lock():
        try: value = load_lease()
        except FileNotFoundError: return
        if value["run_id"] != run_id:
            raise PermissionError("armed lease belongs to another run")
        agent_uid = pwd.getpwnam("agent").pw_uid
        groups, supervisors = registered_targets(run_id, value["lease_id"], agent_uid)
        supervisors |= supervisor_processes(run_id)
        if not terminate(groups, supervisors, agent_uid):
            raise RuntimeError("agent processes remain during lease disarm")
        LEASE_FILE.unlink()
        try: PROCESS_FILE.unlink()
        except FileNotFoundError: pass


def renew(run_id: str, lease_id: str, expires_at: int) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    lease_id = canonical_uuid4(lease_id, "lease ID")
    with lease_lock():
        value = load_lease()
        if value["run_id"] != run_id or value["lease_id"] != lease_id:
            raise PermissionError("armed lease identity mismatch")
        if expires_at <= int(value["expires_at"]):
            raise ValueError("renewed expiry must increase")
        value["expires_at"] = expires_at
        atomic_json(LEASE_FILE, value)
        return value


def expire(run_id: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    with lease_lock():
        value = load_lease()
        if value["run_id"] != run_id:
            raise PermissionError("armed lease belongs to another run")
        value["expires_at"] = int(time.time()) + 1
        atomic_json(LEASE_FILE, value)
        return value


def load_lease() -> dict[str, Any]:
    metadata = LEASE_FILE.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError("invalid Research lease ownership or mode")
    descriptor = os.open(LEASE_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle: value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("invalid Research lease schema")
    canonical_uuid4(str(value.get("run_id", "")), "run ID")
    canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    if not isinstance(value.get("expires_at"), int):
        raise ValueError("invalid Research lease expiry")
    return value


def process_fields(pid: int) -> tuple[str, int, int, int]:
    raw = (PROC / str(pid) / "stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(")") + 2:].split()
    return fields[0], int(fields[1]), int(fields[2]), int(fields[19])


def registered_targets(run_id: str, lease_id: str, agent_uid: int) -> tuple[set[int], set[int]]:
    try:
        metadata = PROCESS_FILE.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
            raise PermissionError("invalid process registration ownership or mode")
        descriptor = os.open(PROCESS_FILE, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle: value = json.load(handle)
        if (value.get("schema") != "secure-sandbox-run-process-v1"
                or value.get("run_id") != run_id or value.get("lease_id") != lease_id):
            raise ValueError("process registration identity mismatch")
        supervisor = int(value["supervisor_pid"])
        supervisor_start = int(value["supervisor_start_time"])
        if (PROC / str(supervisor)).stat().st_uid != 0:
            raise ValueError("process supervisor is not root")
        arguments = (PROC / str(supervisor) / "cmdline").read_bytes().split(b"\0")
        if (b"/usr/local/libexec/secure-sandbox/run_lease_process.py" not in arguments
                or run_id.encode() not in arguments):
            raise ValueError("process supervisor identity mismatch")
        _, _, _, actual_supervisor_start = process_fields(supervisor)
        if actual_supervisor_start != supervisor_start:
            raise ValueError("process supervisor start mismatch")
        if value.get("ready") is not True:
            return set(), {supervisor}
        child = int(value["child_pid"])
        process_group = int(value["process_group"])
        start_time = int(value["child_start_time"])
        if (PROC / str(child)).stat().st_uid != agent_uid:
            raise ValueError("registered child owner mismatch")
        _, parent, actual_group, actual_start = process_fields(child)
        if parent != supervisor or actual_group != process_group or actual_start != start_time:
            raise ValueError("registered child identity mismatch")
        if process_group <= 1 or process_group == os.getpgrp():
            raise ValueError("invalid registered process group")
        return {process_group}, {supervisor}
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, KeyError, json.JSONDecodeError):
        return set(), set()


def process_ids_for_uid(uid: int) -> set[int]:
    result: set[int] = set()
    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            state, _, _, _ = process_fields(int(entry.name))
            if state != "Z" and entry.stat().st_uid == uid:
                result.add(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
    return result


def supervisor_processes(run_id: str) -> set[int]:
    result: set[int] = set()
    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != 0:
                continue
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
            if (b"/usr/local/libexec/secure-sandbox/run_lease_process.py" in arguments
                    and run_id.encode() in arguments):
                result.add(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return result


def terminate(groups: set[int], pids: set[int], agent_uid: int) -> bool:
    for group in groups:
        try: os.killpg(group, signal.SIGTERM)
        except ProcessLookupError: pass
    for pid in pids:
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        remaining = process_ids_for_uid(agent_uid)
        if not remaining:
            break
        time.sleep(0.1)
    for group in groups:
        try: os.killpg(group, signal.SIGKILL)
        except ProcessLookupError: pass
    for pid in pids | process_ids_for_uid(agent_uid):
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if not process_ids_for_uid(agent_uid):
            return True
        time.sleep(0.05)
    return not process_ids_for_uid(agent_uid)

def watch() -> None:
    agent_uid = pwd.getpwnam("agent").pw_uid
    while True:
        try: lease = load_lease()
        except FileNotFoundError:
            time.sleep(0.5); continue
        except Exception as error:
            print(json.dumps({"event":"lease_watchdog_failed","error":type(error).__name__}, separators=(",", ":")), flush=True)
            time.sleep(1); continue
        now = int(time.time())
        if now < lease["expires_at"]:
            time.sleep(min(1, lease["expires_at"] - now)); continue
        with lease_lock():
            try: lease = load_lease()
            except FileNotFoundError: continue
            if int(time.time()) < lease["expires_at"]:
                continue
            groups, supervisors = registered_targets(lease["run_id"], lease["lease_id"], agent_uid)
            supervisors |= supervisor_processes(lease["run_id"])
            terminated = terminate(groups, supervisors, agent_uid)
            event = "lease_watchdog_expired" if terminated else "lease_watchdog_enforcement_failed"
            print(json.dumps({"event":event,"run_id":lease["run_id"],"lease_id":lease["lease_id"],
                              "process_groups":len(groups)}, separators=(",", ":"), sort_keys=True), flush=True)
            if not terminated:
                time.sleep(1)
                continue
            try: LEASE_FILE.unlink()
            except FileNotFoundError: pass
            try: PROCESS_FILE.unlink()
            except FileNotFoundError: pass


def main() -> None:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command")
    arm_parser = sub.add_parser("arm"); arm_parser.add_argument("run_id"); arm_parser.add_argument("lease_id"); arm_parser.add_argument("expires_at", type=int)
    disarm_parser = sub.add_parser("disarm"); disarm_parser.add_argument("run_id")
    renew_parser = sub.add_parser("renew"); renew_parser.add_argument("run_id"); renew_parser.add_argument("lease_id"); renew_parser.add_argument("expires_at", type=int)
    expire_parser = sub.add_parser("expire"); expire_parser.add_argument("run_id")
    args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit("run lease watchdog requires root")
    if args.command == "arm": print(json.dumps(arm(args.run_id, args.lease_id, args.expires_at), separators=(",", ":"), sort_keys=True))
    elif args.command == "disarm": disarm(args.run_id)
    elif args.command == "renew": print(json.dumps(renew(args.run_id, args.lease_id, args.expires_at), separators=(",", ":"), sort_keys=True))
    elif args.command == "expire": print(json.dumps(expire(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command is None: watch()
    else: raise SystemExit(2)


if __name__ == "__main__": main()

