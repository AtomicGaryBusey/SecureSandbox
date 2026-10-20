#!/usr/bin/env python3
"""Fail-closed, networkless capture of Claude Code JSONL journals."""

from __future__ import annotations

import argparse
import base64
import io
import hashlib
import json
import os
import pwd
import signal
import stat
import subprocess
import time
import uuid

JOURNAL_ROOT = "/home/agent/.claude/projects"
RUN_MARKER = "/run/secure-sandbox/run-id"
STATE = "/var/lib/secure-sandbox/conversation-capture/state.json"
OUTBOX = "/var/lib/secure-sandbox/conversation-outbox"
FATAL = "/run/secure-sandbox/conversation-capture-fatal"
READY = "/run/secure-sandbox/conversation-capture-ready"
AGE = "/usr/local/bin/age"
MAX_CHUNK = 256 * 1024
MAX_OUTBOX = 256 * 1024 * 1024
MAX_JOURNAL_ENTRIES = 8192
MAX_JOURNAL_DEPTH = 16
RUN_RE = __import__("re").compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def open_anchored_directory(path: str) -> int:
    """Open an absolute directory without following a symlink in any component."""
    if not path.startswith("/"):
        raise ValueError("Claude journal root must be absolute")
    components = path.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ValueError("Claude journal root has an unsafe component")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in components:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def atomic_json(path: str, value: object, mode: int = 0o600) -> None:
    temporary = path + ".new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.write(descriptor, (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY)
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
            value = handle.read().strip()
        return value if RUN_RE.fullmatch(value) else ""
    except OSError:
        return ""


def secure_journals():
    """Yield logical path, held file object, and stat from an anchored no-follow walk."""
    agent_uid = pwd.getpwnam("agent").pw_uid
    root = open_anchored_directory(JOURNAL_ROOT)
    root_info = os.fstat(root)
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != agent_uid:
        os.close(root)
        raise RuntimeError("invalid Claude journal root")
    visited = [0]

    def walk(directory: int, relative: str, depth: int):
        try:
            names = sorted(os.listdir(directory))
        except OSError as error:
            raise RuntimeError("Claude journal enumeration failed") from error
        for name in names:
            visited[0] += 1
            if visited[0] > MAX_JOURNAL_ENTRIES:
                raise RuntimeError("Claude journal entry limit exceeded")
            logical = os.path.join(relative, name) if relative else name
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode):
                if depth >= MAX_JOURNAL_DEPTH:
                    raise RuntimeError("Claude journal depth limit exceeded")
                try:
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                    child_info = os.fstat(child)
                    if not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != agent_uid:
                        os.close(child)
                        continue
                except OSError:
                    continue
                try:
                    yield from walk(child, logical, depth + 1)
                finally:
                    os.close(child)
                continue
            if not name.endswith(".jsonl"):
                continue
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=directory,
                )
                opened = os.fstat(descriptor)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != agent_uid
                        or opened.st_nlink != 1):
                    os.close(descriptor)
                    continue
            except OSError:
                continue
            path = os.path.join(JOURNAL_ROOT, logical)
            yield path, os.fdopen(descriptor, "rb"), opened

    try:
        yield from walk(root, "", 0)
    finally:
        os.close(root)


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


def journal_identity(path: str, info: os.stat_result) -> str:
    """Bind an offset to both the filesystem object and its journal pathname."""
    return f"{info.st_dev}:{info.st_ino}:{path}"


def encrypt_chunk(recipient: str, run_id: str, source: str, sequence: int,
                  previous: str, records: bytes) -> tuple[str, str]:
    envelope = {
        "schema": "secure-sandbox-conversation-v1",
        "run_id": run_id,
        "source": os.path.basename(source),
        "sequence": sequence,
        "previous_cipher_sha256": previous,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "record_bytes": len(records),
    }
    plaintext = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode() + b"\n" + records
    temporary = os.path.join(OUTBOX, f".{run_id}-{sequence:012d}.new")
    result = subprocess.run(
        [AGE, "-r", recipient, "-o", temporary], input=plaintext,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        timeout=30,
    )
    if result.returncode != 0:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise RuntimeError("age encryption failed")
    with open(temporary, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    final = os.path.join(OUTBOX, f"{run_id}-{sequence:012d}-{digest}.age")
    os.chmod(temporary, 0o640)
    os.replace(temporary, final)
    directory = os.open(OUTBOX, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"event":"conversation_chunk_captured","run_id":run_id,"sequence":sequence,"cipher_sha256":digest,"bytes":os.path.getsize(final)},separators=(",",":")),flush=True)
    return digest, final


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
    print(json.dumps({"event":"conversation_capture_failed","run_id":current_run(),"error":reason[:120]},separators=(",",":")),flush=True)
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


def read_complete_records(handle: io.BufferedReader) -> tuple[bytes, int, list[dict]]:
    """Return archive-safe records, consumed source bytes, and corruption evidence."""
    candidate = handle.read(MAX_CHUNK + 1)
    if not candidate:
        return b"", 0, []
    boundary = candidate.rfind(b"\n")
    if boundary < 0:
        if len(candidate) > MAX_CHUNK:
            raise RuntimeError("Claude journal record exceeds capture limit")
        return b"", 0, []
    records = candidate[: boundary + 1]
    archived = bytearray()
    corruptions = []
    for line in records.splitlines():
        if len(line) > MAX_CHUNK:
            raise RuntimeError("invalid Claude journal record")
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict):
            archived.extend(line + b"\n")
            continue
        digest = hashlib.sha256(line).hexdigest()
        wrapper = {
            "type": "secure-sandbox-corrupt-journal-record-v1",
            "raw_base64": base64.b64encode(line).decode("ascii"),
            "raw_bytes": len(line),
            "raw_sha256": digest,
        }
        archived.extend(json.dumps(wrapper, separators=(",", ":"), sort_keys=True).encode() + b"\n")
        corruptions.append({"raw_bytes": len(line), "raw_sha256": digest})
    return bytes(archived), len(records), corruptions


def scan(recipient: str, state: dict) -> bool:
    run_id = current_run()
    if not run_id:
        offsets = state.setdefault("offsets", {})
        changed = False
        for path, handle, info in secure_journals():
            with handle:
                identity = journal_identity(path, info)
                if offsets.get(identity) != info.st_size:
                    offsets[identity] = info.st_size
                    changed = True
        return changed
    if outbox_size() > MAX_OUTBOX:
        raise RuntimeError("encrypted outbox capacity exceeded")
    offsets = state.setdefault("offsets", {})
    run = state.setdefault("runs", {}).setdefault(run_id, {"sequence": 0, "previous": ""})
    changed = False
    for path, handle, info in secure_journals():
        with handle:
            identity = journal_identity(path, info)
            offset = int(offsets.get(identity, 0))
            if info.st_size < offset:
                raise RuntimeError("Claude journal was truncated")
            if info.st_size == offset:
                continue
            while True:
                handle.seek(offset)
                records, consumed, corruptions = read_complete_records(handle)
                if not records:
                    break
                sequence = int(run["sequence"])
                digest, _ = encrypt_chunk(recipient, run_id, path, sequence, str(run["previous"]), records)
                for corruption in corruptions:
                    print(json.dumps({
                        "event": "conversation_journal_record_wrapped",
                        "run_id": run_id,
                        "source": os.path.basename(path),
                        **corruption,
                    }, separators=(",", ":")), flush=True)
                run["sequence"] = sequence + 1
                run["previous"] = digest
                offset += consumed
                offsets[identity] = offset
                changed = True
                if outbox_size() > MAX_OUTBOX:
                    raise RuntimeError("encrypted outbox capacity exceeded")
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipient-file", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    with open(args.recipient_file, encoding="ascii") as handle:
        recipient = handle.read().strip()
    if not recipient.startswith("age1"):
        raise SystemExit("invalid age recipient")
    os.makedirs(OUTBOX, mode=0o750, exist_ok=True)
    state = load_state()
    while True:
        try:
            changed = scan(recipient, state)
            if changed:
                atomic_json(STATE, state)
            with open(READY, "w", encoding="ascii") as handle:
                handle.write(str(int(time.time())) + "\n")
            if args.once:
                return
            time.sleep(0.25)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
            fatal(str(error)[:200])
            raise


if __name__ == "__main__":
    main()
