#!/usr/bin/env python3
"""Fail-closed, networkless capture of Claude Code JSONL journals."""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import io
import hashlib
import json
import os
import pwd
import stat
import subprocess
import sys
import time
import uuid

JOURNAL_ROOT = "/home/agent/.claude/projects"
RUN_MARKER = "/run/secure-sandbox/run-id"
LIFECYCLE = "/var/lib/secure-sandbox/run-lifecycle/active.json"
STATE = "/var/lib/secure-sandbox/conversation-capture/state.json"
LOCK = "/var/lib/secure-sandbox/conversation-capture/capture.lock"
RECEIPT_DIR = "/var/lib/secure-sandbox/run-lifecycle/capture-receipts"
OUTBOX = "/var/lib/secure-sandbox/conversation-outbox"
FATAL = "/run/secure-sandbox/conversation-capture-fatal"
READY = "/run/secure-sandbox/conversation-capture-ready"
AGE = "/usr/local/bin/age"
MAX_CHUNK = 256 * 1024
MAX_OUTBOX = 256 * 1024 * 1024
MAX_JOURNAL_ENTRIES = 8192
MAX_JOURNAL_DEPTH = 16
RUN_RE = __import__("re").compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
PENDING_NAME_RE = __import__("re").compile(r"^\.[0-9a-f-]{36}-[0-9]{12}\.pending$")


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
        if not isinstance(value, dict):
            raise RuntimeError("invalid conversation capture state")
        return value
    except FileNotFoundError:
        return {}


@contextlib.contextmanager
def capture_lock():
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def current_run() -> str:
    try:
        with open(RUN_MARKER, encoding="ascii") as handle:
            value = handle.read().strip()
        return value if RUN_RE.fullmatch(value) else ""
    except OSError:
        pass
    try:
        with open(LIFECYCLE, encoding="utf-8") as handle:
            lifecycle = json.load(handle)
        run_id = lifecycle.get("run_id", "") if isinstance(lifecycle, dict) else ""
        phase = lifecycle.get("phase", "") if isinstance(lifecycle, dict) else ""
        return run_id if RUN_RE.fullmatch(run_id) and phase in {
            "active", "closing", "local_closed", "failure_latched"
        } else ""
    except (OSError, ValueError, json.JSONDecodeError):
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


def emit_event(value: dict) -> None:
    """Keep lifecycle CLI stdout reserved for its single response object."""
    print(json.dumps(value, separators=(",", ":"), sort_keys=True), file=sys.stderr, flush=True)


def pending_chunk_path() -> str:
    return os.path.join(os.path.dirname(STATE), "pending-chunk.json")


def remove_durable(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def encrypt_chunk(recipient: str, run_id: str, source: str, sequence: int,
                  previous: str, records: bytes) -> tuple[str, str, str]:
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
    temporary = os.path.join(OUTBOX, f".{run_id}-{sequence:012d}.pending")
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
    os.chmod(temporary, 0o640)
    final = os.path.join(OUTBOX, f"{run_id}-{sequence:012d}-{digest}.age")
    return digest, temporary, final


def publish_ready_chunk(state: dict, pending: dict) -> str:
    run_id = pending["run_id"]
    run = state["runs"][run_id]
    sequence = int(pending["sequence"])
    digest = str(pending["cipher_sha256"])
    temporary = str(pending["temporary"])
    final = str(pending["final"])
    if int(run["sequence"]) == sequence:
        if str(run["previous"]) != pending["previous_cipher_sha256"]:
            raise RuntimeError("pending chunk chain mismatch")
        run["sequence"] = sequence + 1
        run["previous"] = digest
        state.setdefault("offsets", {})[pending["journal_identity"]] = int(pending["end_offset"])
        run.setdefault("chunks", []).append({
            "sequence": sequence,
            "cipher_sha256": digest,
            "journal_identity": pending["journal_identity"],
            "start_offset": int(pending["start_offset"]),
            "end_offset": int(pending["end_offset"]),
        })
        atomic_json(STATE, state)
    elif (int(run["sequence"]) != sequence + 1 or str(run["previous"]) != digest
          or int(state.setdefault("offsets", {}).get(pending["journal_identity"], -1))
          != int(pending["end_offset"])):
        raise RuntimeError("capture state does not match pending chunk")
    if not os.path.exists(temporary):
        raise RuntimeError("pending ciphertext disappeared")
    if not os.path.exists(final):
        # Retain the hidden inode until the transaction record is removed.  If
        # the shipper consumes the public hard link during a crash window,
        # recovery republishes the identical ciphertext and the receiver's
        # create-only contract makes that idempotent.
        os.link(temporary, final)
    else:
        with open(final, "rb") as handle:
            if hashlib.sha256(handle.read()).hexdigest() != digest:
                raise RuntimeError("published ciphertext hash mismatch")
    directory = os.open(OUTBOX, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    remove_durable(pending_chunk_path())
    remove_durable(temporary)
    emit_event({"event":"conversation_chunk_captured","run_id":run_id,
                "sequence":sequence,"cipher_sha256":digest})
    return digest


def capture_chunk(recipient: str, state: dict, run_id: str, source: str,
                  identity: str, start_offset: int, records: bytes, consumed: int) -> str:
    run = state["runs"][run_id]
    base = {
        "schema":"secure-sandbox-capture-chunk-transaction-v1",
        "run_id":run_id,
        "sequence":int(run["sequence"]),
        "previous_cipher_sha256":str(run["previous"]),
        "source":source,
        "journal_identity":identity,
        "start_offset":start_offset,
        "end_offset":start_offset + consumed,
        "records_sha256":hashlib.sha256(records).hexdigest(),
    }
    try:
        with open(pending_chunk_path(), encoding="utf-8") as handle:
            pending = json.load(handle)
    except FileNotFoundError:
        pending = base
        atomic_json(pending_chunk_path(), pending)
    if any(pending.get(key) != value for key, value in base.items()):
        raise RuntimeError("unreconciled capture transaction does not match journal state")
    if "cipher_sha256" not in pending:
        digest, temporary, final = encrypt_chunk(
            recipient, run_id, source, int(base["sequence"]),
            str(base["previous_cipher_sha256"]), records,
        )
        pending.update({"cipher_sha256":digest,"temporary":temporary,"final":final})
        atomic_json(pending_chunk_path(), pending)
    return publish_ready_chunk(state, pending)


def reconcile_pending(state: dict) -> None:
    try:
        with open(pending_chunk_path(), encoding="utf-8") as handle:
            pending = json.load(handle)
    except FileNotFoundError:
        return
    if not isinstance(pending, dict) or pending.get("schema") != "secure-sandbox-capture-chunk-transaction-v1":
        raise RuntimeError("invalid pending capture transaction")
    if "cipher_sha256" not in pending:
        temporary = os.path.join(
            OUTBOX, f'.{pending.get("run_id", "")}-{int(pending.get("sequence", -1)):012d}.pending'
        )
        if not os.path.isfile(temporary):
            return
        with open(temporary, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        pending.update({
            "cipher_sha256":digest,
            "temporary":temporary,
            "final":os.path.join(OUTBOX, f'{pending["run_id"]}-{int(pending["sequence"]):012d}-{digest}.age'),
        })
        atomic_json(pending_chunk_path(), pending)
    publish_ready_chunk(state, pending)


def fatal(reason: str) -> None:
    emit_event({"event":"conversation_capture_failed","run_id":current_run(),"error":reason[:120]})
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


def wrap_corrupt_record(raw: bytes) -> tuple[bytes, dict]:
    digest = hashlib.sha256(raw).hexdigest()
    evidence = {"raw_bytes": len(raw), "raw_sha256": digest}
    wrapper = {
        "type": "secure-sandbox-corrupt-journal-record-v1",
        "raw_base64": base64.b64encode(raw).decode("ascii"),
        **evidence,
    }
    return json.dumps(wrapper, separators=(",", ":"), sort_keys=True).encode() + b"\n", evidence


def scan(recipient: str, state: dict) -> bool:
    run_id = current_run()
    if not run_id:
        return False
    if outbox_size() > MAX_OUTBOX:
        raise RuntimeError("encrypted outbox capacity exceeded")
    reconcile_pending(state)
    offsets = state.setdefault("offsets", {})
    run = state.setdefault("runs", {}).setdefault(run_id, {"sequence": 0, "previous": ""})
    changed = False
    for path, handle, info in secure_journals():
        with handle:
            identity = journal_identity(path, info)
            observed = run.setdefault("journals", {})
            if identity not in observed:
                observed[identity] = info.st_size
                changed = True
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
                digest = capture_chunk(recipient, state, run_id, path, identity,
                                       offset, records, consumed)
                for corruption in corruptions:
                    emit_event({
                        "event": "conversation_journal_record_wrapped",
                        "run_id": run_id,
                        "source": os.path.basename(path),
                        **corruption,
                    })
                offset += consumed
                changed = True
                if outbox_size() > MAX_OUTBOX:
                    raise RuntimeError("encrypted outbox capacity exceeded")
    return changed


def prepare(run_id: str) -> dict:
    if not RUN_RE.fullmatch(run_id):
        raise ValueError("invalid run ID")
    with capture_lock():
        state = load_state()
        if os.path.exists(pending_chunk_path()):
            reconcile_pending(state)
        if os.path.exists(pending_chunk_path()):
            raise RuntimeError("previous capture transaction is incomplete")
        pending_names = [name for name in os.listdir(OUTBOX) if PENDING_NAME_RE.fullmatch(name)]
        if len(pending_names) > 16:
            raise RuntimeError("orphan pending ciphertext limit exceeded")
        for name in pending_names:
            path = os.path.join(OUTBOX, name)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                raise RuntimeError("unsafe orphan pending ciphertext")
            remove_durable(path)
        offsets = state.setdefault("offsets", {})
        journals = []
        for path, handle, info in secure_journals():
            with handle:
                identity = journal_identity(path, info)
                offsets[identity] = info.st_size
                journals.append({"identity": identity, "size": info.st_size})
        prepared = {item["identity"]:item["size"] for item in journals}
        state.setdefault("runs", {})[run_id] = {"sequence": 0, "previous": "",
                                                "journals":dict(prepared),
                                                "prepared_offsets":dict(prepared),
                                                "chunks":[]}
        atomic_json(STATE, state)
        return {"schema":"secure-sandbox-capture-prepare-v1", "run_id":run_id,
                "journals":journals, "prepared_at":int(time.time())}


def finalize(recipient: str, run_id: str) -> dict:
    if not RUN_RE.fullmatch(run_id):
        raise ValueError("invalid run ID")
    with capture_lock():
        state = load_state()
        reconcile_pending(state)
        run = state.setdefault("runs", {}).get(run_id)
        if not isinstance(run, dict):
            raise RuntimeError("run capture was not prepared")
        offsets = state.setdefault("offsets", {})
        journals = []
        seen = set()
        for path, handle, info in secure_journals():
            with handle:
                identity = journal_identity(path, info)
                seen.add(identity)
                run.setdefault("journals", {}).setdefault(identity, info.st_size)
                target = info.st_size
                offset = int(offsets.get(identity, 0))
                if target < offset:
                    raise RuntimeError("Claude journal was truncated")
                while offset < target:
                    handle.seek(offset)
                    remaining = target - offset
                    candidate = handle.read(min(MAX_CHUNK + 1, remaining))
                    if not candidate:
                        raise RuntimeError("Claude journal snapshot became unreadable")
                    boundary = candidate.rfind(b"\n")
                    if boundary >= 0:
                        records, consumed, corruptions = read_complete_records(io.BytesIO(candidate))
                    else:
                        if remaining > MAX_CHUNK:
                            raise RuntimeError("unterminated Claude journal record exceeds capture limit")
                        records, corruption = wrap_corrupt_record(candidate)
                        consumed, corruptions = len(candidate), [corruption]
                    sequence = int(run["sequence"])
                    digest = capture_chunk(recipient, state, run_id, path, identity,
                                           offset, records, consumed)
                    offset += consumed
                    for corruption in corruptions:
                        emit_event({"event":"conversation_journal_record_wrapped",
                                    "run_id":run_id,"source":os.path.basename(path),
                                    **corruption})
                journals.append({"identity":identity,"snapshot_size":target,
                                 "final_offset":offset})
        missing = set(run.get("journals", {})) - seen
        if missing:
            raise RuntimeError("observed Claude journal disappeared before finalization")
        atomic_json(STATE, state)
        receipt = {"schema":"secure-sandbox-capture-final-v1", "run_id":run_id,
                   "journals":journals, "final_cipher_sha256":str(run["previous"]),
                   "final_sequence":int(run["sequence"]),
                   "prepared_offsets":dict(run.get("prepared_offsets", {})),
                   "chunks":list(run.get("chunks", [])),
                   "finalized_at":int(time.time())}
        os.makedirs(RECEIPT_DIR, mode=0o700, exist_ok=True)
        atomic_json(os.path.join(RECEIPT_DIR, run_id + ".json"), receipt)
        return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipient-file", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--prepare")
    parser.add_argument("--finalize")
    args = parser.parse_args()
    with open(args.recipient_file, encoding="ascii") as handle:
        recipient = handle.read().strip()
    if not recipient.startswith("age1"):
        raise SystemExit("invalid age recipient")
    os.makedirs(OUTBOX, mode=0o750, exist_ok=True)
    if args.prepare and args.finalize:
        raise SystemExit("choose one lifecycle operation")
    if args.prepare:
        print(json.dumps(prepare(args.prepare), separators=(",", ":"), sort_keys=True))
        return
    if args.finalize:
        print(json.dumps(finalize(recipient, args.finalize), separators=(",", ":"), sort_keys=True))
        return
    while True:
        try:
            with capture_lock():
                state = load_state()
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
