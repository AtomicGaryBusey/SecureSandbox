#!/usr/bin/env python3
"""Snapshot agent-authored reports into encrypted, append-only evidence blobs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import time
import uuid

REPORT_DIR = "/home/agent/research-workspace/reports"
RUN_MARKER = "/run/secure-sandbox/run-id"
STATE = "/var/lib/secure-sandbox/artifact-capture/state.json"
OUTBOX = "/var/lib/secure-sandbox/conversation-outbox"
FATAL = "/run/secure-sandbox/artifact-capture-fatal"
READY = "/run/secure-sandbox/artifact-capture-ready"
AGE = "/usr/local/bin/age"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FILES = 512
MAX_OUTBOX_BYTES = 256 * 1024 * 1024
SETTLE_SECONDS = 2.0
POLL_SECONDS = 0.5
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(?:md|txt|json)$")
RUN_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def atomic_json(path: str, value: object, mode: int = 0o600) -> None:
    temporary = path + ".new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.write(descriptor, (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_state() -> dict:
    try:
        with open(STATE, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def current_run() -> str:
    try:
        with open(RUN_MARKER, encoding="ascii") as handle:
            value = handle.read(64).strip()
        return value if RUN_RE.fullmatch(value) else "preflight"
    except OSError:
        return "preflight"


def outbox_size() -> int:
    total = 0
    for name in os.listdir(OUTBOX):
        path = os.path.join(OUTBOX, name)
        try:
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
        except OSError:
            pass
    return total


def candidate_names() -> list[str]:
    names = sorted(entry.name for entry in os.scandir(REPORT_DIR) if NAME_RE.fullmatch(entry.name))
    return names[: MAX_FILES + 1]


def read_report(name: str) -> tuple[bytes, tuple[int, int, int, int]]:
    if not NAME_RE.fullmatch(name):
        raise ValueError("invalid_name")
    directory = os.open(REPORT_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(descriptor)
        agent_uid = pwd.getpwnam("agent").pw_uid
        if not stat.S_ISREG(before.st_mode) or before.st_uid != agent_uid or before.st_nlink != 1:
            raise ValueError("unsafe_file")
        if before.st_size < 1 or before.st_size > MAX_FILE_BYTES:
            raise ValueError("invalid_size")
        chunks = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        signature = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if len(content) != before.st_size or signature != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise ValueError("changed_during_read")
        content.decode("utf-8")
        return content, signature
    except UnicodeDecodeError as error:
        raise ValueError("not_utf8") from error
    finally:
        os.close(descriptor)


def encrypt_snapshot(recipient: str, name: str, content: bytes, version: int) -> tuple[str, str, str]:
    artifact_id = str(uuid.uuid4())
    source_sha256 = hashlib.sha256(content).hexdigest()
    envelope = {
        "artifact_id": artifact_id,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "file_name": name,
        "media_type": {
            ".md": "text/markdown",
            ".json": "application/json",
            ".txt": "text/plain",
        }[os.path.splitext(name)[1]],
        "record_bytes": len(content),
        "run_id": current_run(),
        "schema": "secure-sandbox-artifact-v1",
        "source_sha256": source_sha256,
        "version": version,
    }
    plaintext = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode() + b"\n" + content
    temporary = os.path.join(OUTBOX, f".artifact-{artifact_id}.new")
    result = subprocess.run(
        [AGE, "-r", recipient, "-o", temporary],
        input=plaintext,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise RuntimeError("age encryption failed")
    with open(temporary, "rb") as handle:
        cipher_sha256 = hashlib.sha256(handle.read()).hexdigest()
    final = os.path.join(OUTBOX, f"artifact-{artifact_id}-{version:012d}-{cipher_sha256}.age")
    os.chmod(temporary, 0o640)
    os.replace(temporary, final)
    directory = os.open(OUTBOX, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({
        "event": "artifact_captured",
        "artifact_id": artifact_id,
        "run_id": envelope["run_id"],
        "version": version,
        "cipher_sha256": cipher_sha256,
        "source_sha256": source_sha256,
        "bytes": os.path.getsize(final),
    }, separators=(",", ":")), flush=True)
    return artifact_id, source_sha256, final


def terminate_agent() -> None:
    agent_uid = pwd.getpwnam("agent").pw_uid
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.stat(f"/proc/{entry}").st_uid != agent_uid:
                continue
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                command = handle.read().replace(b"\x00", b" ")
            if b"claude" in command:
                os.kill(int(entry), signal.SIGTERM)
        except (OSError, ValueError):
            pass


def fatal(reason: str) -> None:
    print(json.dumps({
        "event": "artifact_capture_failed",
        "run_id": current_run(),
        "error": reason[:120],
    }, separators=(",", ":")), flush=True)
    descriptor = os.open(FATAL, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, (reason + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.unlink(READY)
    except OSError:
        pass
    terminate_agent()


def scan(recipient: str, state: dict, stable: dict[str, tuple[tuple[int, int, int, int], float]]) -> bool:
    names = candidate_names()
    if len(names) > MAX_FILES:
        raise RuntimeError("artifact file count exceeded")
    if outbox_size() > MAX_OUTBOX_BYTES:
        raise RuntimeError("encrypted outbox capacity exceeded")
    changed = False
    now = time.monotonic()
    live = set(names)
    for stale in set(stable) - live:
        stable.pop(stale, None)
    files = state.setdefault("files", {})
    for name in names:
        try:
            content, signature = read_report(name)
        except (OSError, ValueError) as error:
            print(json.dumps({
                "event": "artifact_rejected",
                "run_id": current_run(),
                "reason": str(error)[:64],
            }, separators=(",", ":")), flush=True)
            stable.pop(name, None)
            continue
        previous = stable.get(name)
        if previous is None or previous[0] != signature:
            stable[name] = (signature, now)
            continue
        if now - previous[1] < SETTLE_SECONDS:
            continue
        digest = hashlib.sha256(content).hexdigest()
        old = files.get(name, {}) if isinstance(files.get(name), dict) else {}
        if old.get("source_sha256") == digest:
            continue
        version = int(old.get("version", 0)) + 1
        artifact_id, source_sha256, _ = encrypt_snapshot(recipient, name, content, version)
        files[name] = {
            "artifact_id": artifact_id,
            "source_sha256": source_sha256,
            "version": version,
        }
        atomic_json(STATE, state)
        changed = True
        if outbox_size() > MAX_OUTBOX_BYTES:
            raise RuntimeError("encrypted outbox capacity exceeded")
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipient-file", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    with open(args.recipient_file, encoding="ascii") as handle:
        recipient = handle.read().strip()
    if not recipient.startswith("age1") or len(recipient) < 50:
        raise SystemExit("invalid age recipient")
    os.makedirs(os.path.dirname(STATE), mode=0o700, exist_ok=True)
    state = load_state()
    stable: dict[str, tuple[tuple[int, int, int, int], float]] = {}
    try:
        os.unlink(FATAL)
    except OSError:
        pass
    try:
        # Permission failures must never be mistaken for an empty workspace.
        candidate_names()
        atomic_json(STATE, state)
        descriptor = os.open(READY, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        os.close(descriptor)
        while True:
            scan(recipient, state, stable)
            if args.once:
                return
            time.sleep(POLL_SECONDS)
    except Exception as error:
        fatal(f"{type(error).__name__}: {error}")
        raise


if __name__ == "__main__":
    main()
