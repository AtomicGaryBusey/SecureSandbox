#!/usr/bin/env python3
"""Bounded monotonic replay authority for interactive Claude login.

Exact handles remain until a separate Touch-ID-authorized compaction projects
only finalized, consumed handles into a Bloom floor. A Bloom match is
denial-only: false positives can refuse a fresh login but cannot admit replay.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Callable, Mapping


HANDLE_SCHEMA = "secure-sandbox-native-claude-login-handle-v2"
FLOOR_SCHEMA = "secure-sandbox-native-claude-login-replay-floor-v1"
HANDLE_ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller/login-handles")
PROOF_ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller/login-proofs")
LOCK_NAME = ".replay.lock"
FLOOR_NAME = "replay-floor.json"
PENDING_FLOOR_NAME = "replay-floor.pending.json"
MAX_RETAINED_HANDLES = 32
FLOOR_BYTES = 256 * 1024
FLOOR_BITS = FLOOR_BYTES * 8
FLOOR_HASH_COUNT = 7
MAX_COMPACTIONS = 4096
MAX_INSERTED_HANDLES = MAX_COMPACTIONS * MAX_RETAINED_HANDLES
MAX_SET_BITS = FLOOR_BITS * 2 // 5
MAX_RECORD_BYTES = 4096
MAX_FLOOR_BYTES = 512 * 1024
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
HANDLE_NAME = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json")
PENDING_HANDLE_NAME = re.compile(
    r"\.pending-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json")


class NativeClaudeReplayError(RuntimeError):
    """Stable fail-closed replay-floor error."""


def canonical(value: object) -> bytes:
    try:
        return (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeClaudeReplayError("native_claude_replay_value_invalid") from error


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def keyed_evidence(key: bytes, value: object) -> str:
    if not isinstance(key, bytes) or len(key) != 32:
        raise NativeClaudeReplayError("native_claude_replay_binding_key_invalid")
    return hmac.new(
        key, b"secure-sandbox-native-claude-login-compaction-evidence-v1\0"
        + canonical(value), hashlib.sha256,
    ).hexdigest()


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise NativeClaudeReplayError("native_claude_replay_write_failed")
        view = view[count:]


def _root_descriptor(root: Path, *, trusted_uid: int, trusted_gid: int) -> int:
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        current = root.lstat()
        if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
                or stat.S_IMODE(opened.st_mode) != 0o700):
            raise NativeClaudeReplayError("native_claude_replay_root_untrusted")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _lock(root_descriptor: int, *, trusted_uid: int, trusted_gid: int) -> int:
    descriptor = os.open(
        LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=root_descriptor)
    try:
        os.fchown(descriptor, trusted_uid, trusted_gid)
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise NativeClaudeReplayError("native_claude_replay_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_exact_at(root_descriptor: int, name: str, *, maximum: int,
                   trusted_uid: int, trusted_gid: int, mode: int) -> bytes:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=root_descriptor)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != mode
                or not 1 <= info.st_size <= maximum):
            raise NativeClaudeReplayError("native_claude_replay_record_untrusted")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) != info.st_size or os.read(descriptor, 1):
            raise NativeClaudeReplayError("native_claude_replay_record_changed")
        return raw
    finally:
        os.close(descriptor)


def _parse_canonical(raw: bytes, *, maximum: int) -> dict[str, object]:
    if not 1 <= len(raw) <= maximum:
        raise NativeClaudeReplayError("native_claude_replay_record_size_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeClaudeReplayError("native_claude_replay_record_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeClaudeReplayError("native_claude_replay_record_not_canonical")
    return value


def replay_identity(*, operation_id: str, plan_sha256: str,
                    authorization_sha256: str, stack_sha256: str,
                    catalog_sha256: str) -> tuple[dict[str, str], str]:
    immutable = {
        "operation_id": operation_id, "plan_sha256": plan_sha256,
        "authorization_sha256": authorization_sha256,
        "stack_sha256": stack_sha256, "catalog_sha256": catalog_sha256,
    }
    if UUID4.fullmatch(operation_id) is None or any(
        SHA256.fullmatch(immutable[field]) is None for field in (
            "plan_sha256", "authorization_sha256", "stack_sha256",
            "catalog_sha256")
    ):
        raise NativeClaudeReplayError("native_claude_replay_identity_invalid")
    return immutable, digest(immutable)


def _handle_value(immutable: Mapping[str, str], replay_sha256: str, *,
                  state: str, finalized_evidence_sha256: str | None,
                  finalized_at: int | None) -> dict[str, object]:
    body: dict[str, object] = {
        **immutable, "state": state, "replay_sha256": replay_sha256,
        "finalized_evidence_sha256": finalized_evidence_sha256,
        "finalized_at": finalized_at,
    }
    return {"schema": HANDLE_SCHEMA, **body, "record_sha256": digest(body)}


def _validate_handle(value: object, *, expected_operation_id: str | None = None
                     ) -> dict[str, object]:
    fields = {
        "schema", "state", "operation_id", "plan_sha256",
        "authorization_sha256", "stack_sha256", "catalog_sha256",
        "replay_sha256", "finalized_evidence_sha256", "finalized_at",
        "record_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeClaudeReplayError("native_claude_replay_handle_fields_invalid")
    if value["schema"] != HANDLE_SCHEMA or value["state"] not in {
        "claimed", "finalized"
    }:
        raise NativeClaudeReplayError("native_claude_replay_handle_invalid")
    immutable, replay_sha256 = replay_identity(
        operation_id=str(value["operation_id"]),
        plan_sha256=str(value["plan_sha256"]),
        authorization_sha256=str(value["authorization_sha256"]),
        stack_sha256=str(value["stack_sha256"]),
        catalog_sha256=str(value["catalog_sha256"]),
    )
    if (expected_operation_id is not None
            and immutable["operation_id"] != expected_operation_id):
        raise NativeClaudeReplayError("native_claude_replay_handle_identity_mismatch")
    if value["replay_sha256"] != replay_sha256:
        raise NativeClaudeReplayError("native_claude_replay_handle_digest_invalid")
    if value["state"] == "claimed":
        if (value["finalized_evidence_sha256"] is not None
                or value["finalized_at"] is not None):
            raise NativeClaudeReplayError("native_claude_replay_handle_state_invalid")
    elif (not isinstance(value["finalized_at"], int)
          or value["finalized_at"] < 1
          or not isinstance(value["finalized_evidence_sha256"], str)
          or SHA256.fullmatch(value["finalized_evidence_sha256"]) is None):
        raise NativeClaudeReplayError("native_claude_replay_handle_state_invalid")
    body = {key: value[key] for key in fields - {"schema", "record_sha256"}}
    if value["record_sha256"] != digest(body):
        raise NativeClaudeReplayError("native_claude_replay_handle_record_invalid")
    return value


def _read_handle(root_descriptor: int, operation_id: str, *, trusted_uid: int,
                 trusted_gid: int) -> dict[str, object]:
    raw = _read_exact_at(
        root_descriptor, f"{operation_id}.json", maximum=MAX_RECORD_BYTES,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
    return _validate_handle(
        _parse_canonical(raw, maximum=MAX_RECORD_BYTES),
        expected_operation_id=operation_id)


def _bloom_indexes(replay_sha256: str) -> tuple[int, ...]:
    if SHA256.fullmatch(replay_sha256) is None:
        raise NativeClaudeReplayError("native_claude_replay_digest_invalid")
    raw = bytes.fromhex(replay_sha256)
    return tuple(
        int.from_bytes(hashlib.sha256(
            b"secure-sandbox-native-claude-login-replay-index-v1\0"
            + number.to_bytes(2, "big") + raw).digest()[:8], "big") % FLOOR_BITS
        for number in range(FLOOR_HASH_COUNT)
    )


def _bloom_contains(bitmap: bytes | bytearray, replay_sha256: str) -> bool:
    return all(bitmap[index // 8] & (1 << (index % 8))
               for index in _bloom_indexes(replay_sha256))


def _bloom_add(bitmap: bytearray, replay_sha256: str) -> None:
    for index in _bloom_indexes(replay_sha256):
        bitmap[index // 8] |= 1 << (index % 8)


def _empty_floor() -> dict[str, object]:
    return {
        "schema": FLOOR_SCHEMA,
        "bitmap_b64": base64.b64encode(bytes(FLOOR_BYTES)).decode("ascii"),
        "bit_count": FLOOR_BITS, "hash_count": FLOOR_HASH_COUNT,
        "set_bit_count": 0, "inserted_handle_count": 0,
        "compaction_count": 0, "previous_floor_sha256": None,
        "compacted_handle_set_sha256": None, "compacted_handle_count": 0,
        "operation_id": None, "plan_sha256": None,
        "authorization_sha256": None, "compacted_at": None,
        "floor_sha256": None,
    }


def _validate_floor(value: object, *, allow_empty: bool = False
                    ) -> tuple[dict[str, object], bytes]:
    fields = set(_empty_floor())
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeClaudeReplayError("native_claude_replay_floor_fields_invalid")
    if (value["schema"] != FLOOR_SCHEMA or value["bit_count"] != FLOOR_BITS
            or value["hash_count"] != FLOOR_HASH_COUNT):
        raise NativeClaudeReplayError("native_claude_replay_floor_invalid")
    try:
        bitmap = base64.b64decode(str(value["bitmap_b64"]), validate=True)
    except (ValueError, TypeError) as error:
        raise NativeClaudeReplayError("native_claude_replay_floor_bitmap_invalid") from error
    if len(bitmap) != FLOOR_BYTES:
        raise NativeClaudeReplayError("native_claude_replay_floor_bitmap_invalid")
    set_bits = sum(byte.bit_count() for byte in bitmap)
    if (value["set_bit_count"] != set_bits or set_bits > MAX_SET_BITS
            or not isinstance(value["inserted_handle_count"], int)
            or not 0 <= value["inserted_handle_count"] <= MAX_INSERTED_HANDLES
            or not isinstance(value["compaction_count"], int)
            or not 0 <= value["compaction_count"] <= MAX_COMPACTIONS
            or not isinstance(value["compacted_handle_count"], int)
            or not 0 <= value["compacted_handle_count"] <= MAX_RETAINED_HANDLES):
        raise NativeClaudeReplayError("native_claude_replay_floor_metadata_invalid")
    if value["floor_sha256"] is None:
        if not allow_empty or value != _empty_floor():
            raise NativeClaudeReplayError("native_claude_replay_floor_digest_invalid")
        return value, bitmap
    for field in ("previous_floor_sha256", "compacted_handle_set_sha256",
                  "plan_sha256", "authorization_sha256", "floor_sha256"):
        if value[field] is not None and (
            not isinstance(value[field], str)
            or SHA256.fullmatch(value[field]) is None
        ):
            raise NativeClaudeReplayError("native_claude_replay_floor_metadata_invalid")
    if (not isinstance(value["operation_id"], str)
            or UUID4.fullmatch(value["operation_id"]) is None
            or not isinstance(value["compacted_at"], int)
            or value["compacted_at"] < 1
            or value["compacted_handle_count"] < 1
            or value["compaction_count"] < 1
            or value["inserted_handle_count"] < value["compacted_handle_count"]
            or (value["previous_floor_sha256"] is None)
               != (value["compaction_count"] == 1)
            or value["compacted_handle_set_sha256"] is None
            or value["plan_sha256"] is None
            or value["authorization_sha256"] is None):
        raise NativeClaudeReplayError("native_claude_replay_floor_metadata_invalid")
    body = {key: value[key] for key in fields - {"schema", "floor_sha256"}}
    if value["floor_sha256"] != digest(body):
        raise NativeClaudeReplayError("native_claude_replay_floor_digest_invalid")
    return value, bitmap


def _load_floor(root_descriptor: int, *, trusted_uid: int,
                trusted_gid: int) -> tuple[dict[str, object], bytes]:
    try:
        raw = _read_exact_at(
            root_descriptor, FLOOR_NAME, maximum=MAX_FLOOR_BYTES,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
    except FileNotFoundError:
        return _validate_floor(_empty_floor(), allow_empty=True)
    return _validate_floor(_parse_canonical(raw, maximum=MAX_FLOOR_BYTES))


def _inventory(root_descriptor: int, *, trusted_uid: int,
               trusted_gid: int) -> list[dict[str, object]]:
    names = os.listdir(root_descriptor)
    permitted = {LOCK_NAME, FLOOR_NAME, PENDING_FLOOR_NAME}
    unexpected = [name for name in names
                  if name not in permitted and HANDLE_NAME.fullmatch(name) is None]
    if unexpected:
        raise NativeClaudeReplayError("native_claude_replay_store_untrusted")
    handles = []
    for name in sorted(names):
        match = HANDLE_NAME.fullmatch(name)
        if match is not None:
            handles.append(_read_handle(
                root_descriptor, match.group(1), trusted_uid=trusted_uid,
                trusted_gid=trusted_gid))
    if len(handles) > MAX_RETAINED_HANDLES:
        raise NativeClaudeReplayError("native_claude_replay_store_untrusted")
    return handles


def _recover_pending_handles(root_descriptor: int, *, trusted_uid: int,
                             trusted_gid: int,
                             checkpoint: Callable[[str], None] = (
                                 lambda _phase: None)) -> None:
    """Publish only an exact durable claimed-to-finalized transition."""
    names = os.listdir(root_descriptor)
    pending_names = sorted(
        name for name in names if PENDING_HANDLE_NAME.fullmatch(name) is not None)
    if len(pending_names) > MAX_RETAINED_HANDLES:
        raise NativeClaudeReplayError("native_claude_replay_store_untrusted")
    for pending_name in pending_names:
        match = PENDING_HANDLE_NAME.fullmatch(pending_name)
        assert match is not None
        operation_id = match.group(1)
        pending_raw = _read_exact_at(
            root_descriptor, pending_name, maximum=MAX_RECORD_BYTES,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
        pending = _validate_handle(
            _parse_canonical(pending_raw, maximum=MAX_RECORD_BYTES),
            expected_operation_id=operation_id)
        current = _read_handle(
            root_descriptor, operation_id, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        immutable_fields = (
            "operation_id", "plan_sha256", "authorization_sha256",
            "stack_sha256", "catalog_sha256", "replay_sha256")
        if (current["state"] != "claimed" or pending["state"] != "finalized"
                or any(current[field] != pending[field]
                       for field in immutable_fields)):
            raise NativeClaudeReplayError(
                "native_claude_replay_pending_handle_conflict")
        os.replace(
            pending_name, f"{operation_id}.json",
            src_dir_fd=root_descriptor, dst_dir_fd=root_descriptor)
        os.fsync(root_descriptor)
        observed = _read_exact_at(
            root_descriptor, f"{operation_id}.json", maximum=MAX_RECORD_BYTES,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
        if observed != pending_raw:
            raise NativeClaudeReplayError(
                "native_claude_replay_handle_readback_failed")
        checkpoint("handle-finalization-recovered")


def claim_handle(*, operation_id: str, plan_sha256: str,
                 authorization_sha256: str, stack_sha256: str,
                 catalog_sha256: str, root: Path = HANDLE_ROOT,
                 trusted_uid: int = 0, trusted_gid: int = 0) -> None:
    immutable, replay_sha256 = replay_identity(
        operation_id=operation_id, plan_sha256=plan_sha256,
        authorization_sha256=authorization_sha256,
        stack_sha256=stack_sha256, catalog_sha256=catalog_sha256)
    root_descriptor = _root_descriptor(
        root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    lock = -1
    try:
        lock = _lock(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        floor, bitmap = _load_floor(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        if floor["floor_sha256"] is not None and _bloom_contains(
            bitmap, replay_sha256
        ):
            raise NativeClaudeReplayError("native_claude_replay_floor_match_denied")
        _recover_pending_handles(
            root_descriptor, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        handles = _inventory(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        if len(handles) >= MAX_RETAINED_HANDLES:
            raise NativeClaudeReplayError(
                "native_claude_replay_handle_retention_limit")
        value = _handle_value(
            immutable, replay_sha256, state="claimed",
            finalized_evidence_sha256=None, finalized_at=None)
        descriptor = os.open(
            f"{operation_id}.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=root_descriptor)
        try:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, canonical(value))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(root_descriptor)
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(root_descriptor)


def _replace_record_at(root_descriptor: int, name: str,
                       value: Mapping[str, object], *, trusted_uid: int,
                       trusted_gid: int,
                       checkpoint: Callable[[str], None] = lambda _phase: None,
                       ) -> None:
    pending = f".pending-{name}"
    raw = canonical(value)
    try:
        descriptor = os.open(
            pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=root_descriptor)
    except FileExistsError:
        existing = _read_exact_at(
            root_descriptor, pending, maximum=max(MAX_RECORD_BYTES, len(raw)),
            trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
        if existing != raw:
            raise NativeClaudeReplayError("native_claude_replay_pending_conflict")
    else:
        try:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    checkpoint("handle-finalization-pending")
    os.replace(pending, name, src_dir_fd=root_descriptor,
               dst_dir_fd=root_descriptor)
    os.fsync(root_descriptor)
    if _read_exact_at(
        root_descriptor, name, maximum=max(MAX_RECORD_BYTES, len(raw)),
        trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600,
    ) != raw:
        raise NativeClaudeReplayError("native_claude_replay_readback_failed")


def finalize_handle(*, operation_id: str, plan_sha256: str,
                    authorization_sha256: str, stack_sha256: str,
                    result_evidence_sha256: str, root: Path = HANDLE_ROOT,
                    trusted_uid: int = 0, trusted_gid: int = 0,
                    now: int | None = None,
                    checkpoint: Callable[[str], None] = lambda _phase: None,
                    ) -> None:
    if SHA256.fullmatch(result_evidence_sha256) is None:
        raise NativeClaudeReplayError("native_claude_replay_result_invalid")
    root_descriptor = _root_descriptor(
        root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    lock = -1
    try:
        lock = _lock(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        current = _read_handle(
            root_descriptor, operation_id, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        if any(current[field] != expected for field, expected in {
            "plan_sha256": plan_sha256,
            "authorization_sha256": authorization_sha256,
            "stack_sha256": stack_sha256,
        }.items()):
            raise NativeClaudeReplayError(
                "native_claude_replay_handle_identity_mismatch")
        if current["state"] == "finalized":
            if current["finalized_evidence_sha256"] != result_evidence_sha256:
                raise NativeClaudeReplayError(
                    "native_claude_replay_finalization_conflict")
            return
        immutable = {field: str(current[field]) for field in (
            "operation_id", "plan_sha256", "authorization_sha256",
            "stack_sha256", "catalog_sha256")}
        value = _handle_value(
            immutable, str(current["replay_sha256"]), state="finalized",
            finalized_evidence_sha256=result_evidence_sha256,
            finalized_at=int(time.time()) if now is None else now)
        _replace_record_at(
            root_descriptor, f"{operation_id}.json", value,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            checkpoint=checkpoint)
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(root_descriptor)


def _proof_absent(operation_id: str, *, proof_root: Path, trusted_uid: int,
                  trusted_gid: int) -> bool:
    descriptor = _root_descriptor(
        proof_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        try:
            info = os.stat(
                f"{operation_id}.json", dir_fd=descriptor,
                follow_symlinks=False)
        except FileNotFoundError:
            return True
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise NativeClaudeReplayError("native_claude_replay_proof_untrusted")
        return False
    finally:
        os.close(descriptor)


def _publish_floor(root_descriptor: int, value: Mapping[str, object], *,
                   trusted_uid: int, trusted_gid: int,
                   checkpoint: Callable[[str], None] = lambda _phase: None,
                   ) -> None:
    raw = canonical(value)
    if len(raw) > MAX_FLOOR_BYTES:
        raise NativeClaudeReplayError("native_claude_replay_floor_oversized")
    try:
        descriptor = os.open(
            PENDING_FLOOR_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=root_descriptor)
    except FileExistsError:
        pending = _read_exact_at(
            root_descriptor, PENDING_FLOOR_NAME, maximum=MAX_FLOOR_BYTES,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
        if pending != raw:
            raise NativeClaudeReplayError(
                "native_claude_replay_pending_floor_conflict")
    else:
        try:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    checkpoint("floor-pending")
    os.replace(PENDING_FLOOR_NAME, FLOOR_NAME,
               src_dir_fd=root_descriptor, dst_dir_fd=root_descriptor)
    os.fsync(root_descriptor)
    if _read_exact_at(
        root_descriptor, FLOOR_NAME, maximum=MAX_FLOOR_BYTES,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600,
    ) != raw:
        raise NativeClaudeReplayError("native_claude_replay_floor_readback_failed")


def _recover_pending_floor(root_descriptor: int, *, current: Mapping[str, object],
                           trusted_uid: int, trusted_gid: int,
                           checkpoint: Callable[[str], None]) -> None:
    try:
        raw = _read_exact_at(
            root_descriptor, PENDING_FLOOR_NAME, maximum=MAX_FLOOR_BYTES,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
    except FileNotFoundError:
        return
    pending, _bitmap = _validate_floor(
        _parse_canonical(raw, maximum=MAX_FLOOR_BYTES))
    if pending["previous_floor_sha256"] != current["floor_sha256"]:
        raise NativeClaudeReplayError(
            "native_claude_replay_pending_floor_conflict")
    os.replace(PENDING_FLOOR_NAME, FLOOR_NAME,
               src_dir_fd=root_descriptor, dst_dir_fd=root_descriptor)
    os.fsync(root_descriptor)
    observed = _read_exact_at(
        root_descriptor, FLOOR_NAME, maximum=MAX_FLOOR_BYTES,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid, mode=0o600)
    if observed != raw:
        raise NativeClaudeReplayError(
            "native_claude_replay_floor_readback_failed")
    checkpoint("floor-recovered")


def compact(*, operation_id: str, plan_sha256: str,
            authorization_sha256: str, binding_key: bytes,
            root: Path = HANDLE_ROOT, proof_root: Path = PROOF_ROOT,
            trusted_uid: int = 0, trusted_gid: int = 0,
            now: Callable[[], int] = lambda: int(time.time()),
            checkpoint: Callable[[str], None] = lambda _phase: None,
            ) -> dict[str, object]:
    if (UUID4.fullmatch(operation_id) is None
            or SHA256.fullmatch(plan_sha256) is None
            or SHA256.fullmatch(authorization_sha256) is None):
        raise NativeClaudeReplayError("native_claude_replay_compaction_request_invalid")
    root_descriptor = _root_descriptor(
        root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    lock = -1
    try:
        lock = _lock(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        floor, bitmap_raw = _load_floor(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        _recover_pending_floor(
            root_descriptor, current=floor, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid, checkpoint=checkpoint)
        floor, bitmap_raw = _load_floor(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        _recover_pending_handles(
            root_descriptor, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid, checkpoint=checkpoint)
        handles = _inventory(
            root_descriptor, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        eligible = [handle for handle in handles
                    if handle["state"] == "finalized" and _proof_absent(
                        str(handle["operation_id"]), proof_root=proof_root,
                        trusted_uid=trusted_uid, trusted_gid=trusted_gid)]
        if not eligible:
            raise NativeClaudeReplayError("native_claude_replay_nothing_to_compact")
        bitmap = bytearray(bitmap_raw)
        new_handles = [handle for handle in eligible if not _bloom_contains(
            bitmap, str(handle["replay_sha256"]))]
        if new_handles:
            if (int(floor["compaction_count"]) >= MAX_COMPACTIONS
                    or int(floor["inserted_handle_count"]) + len(new_handles)
                    > MAX_INSERTED_HANDLES):
                raise NativeClaudeReplayError(
                    "native_claude_replay_floor_compaction_limit")
            for handle in new_handles:
                _bloom_add(bitmap, str(handle["replay_sha256"]))
            set_bits = sum(byte.bit_count() for byte in bitmap)
            if set_bits > MAX_SET_BITS:
                raise NativeClaudeReplayError("native_claude_replay_floor_saturated")
            compacted = sorted(str(handle["replay_sha256"])
                               for handle in new_handles)
            body: dict[str, object] = {
                "bitmap_b64": base64.b64encode(bitmap).decode("ascii"),
                "bit_count": FLOOR_BITS, "hash_count": FLOOR_HASH_COUNT,
                "set_bit_count": set_bits,
                "inserted_handle_count": (
                    int(floor["inserted_handle_count"]) + len(new_handles)),
                "compaction_count": int(floor["compaction_count"]) + 1,
                "previous_floor_sha256": floor["floor_sha256"],
                "compacted_handle_set_sha256": digest(compacted),
                "compacted_handle_count": len(new_handles),
                "operation_id": operation_id, "plan_sha256": plan_sha256,
                "authorization_sha256": authorization_sha256,
                "compacted_at": now(),
            }
            proposed = {
                "schema": FLOOR_SCHEMA, **body, "floor_sha256": digest(body)}
            _validate_floor(proposed)
            _publish_floor(
                root_descriptor, proposed, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid, checkpoint=checkpoint)
            checkpoint("floor-published")
            floor, bitmap_raw = _load_floor(
                root_descriptor, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            bitmap = bytearray(bitmap_raw)
            if floor != proposed:
                raise NativeClaudeReplayError(
                    "native_claude_replay_floor_readback_failed")
        removed = 0
        for handle in eligible:
            replay_sha256 = str(handle["replay_sha256"])
            if not _bloom_contains(bitmap, replay_sha256):
                raise NativeClaudeReplayError(
                    "native_claude_replay_floor_representation_missing")
            if not _proof_absent(
                str(handle["operation_id"]), proof_root=proof_root,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            ):
                raise NativeClaudeReplayError(
                    "native_claude_replay_proof_state_changed")
            current = _read_handle(
                root_descriptor, str(handle["operation_id"]),
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
            if current != handle:
                raise NativeClaudeReplayError("native_claude_replay_handle_changed")
            os.unlink(f"{handle['operation_id']}.json", dir_fd=root_descriptor)
            os.fsync(root_descriptor)
            removed += 1
            checkpoint("handle-removed")
        evidence_body = {
            "operation_id": operation_id, "plan_sha256": plan_sha256,
            "authorization_sha256": authorization_sha256,
            "floor_sha256": floor["floor_sha256"],
            "compaction_count": floor["compaction_count"],
            "inserted_handle_count": floor["inserted_handle_count"],
            "removed_handle_count": removed,
            "false_positive_semantics": "denial-only",
        }
        return {**evidence_body,
                "evidence_sha256": keyed_evidence(binding_key, evidence_body)}
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(root_descriptor)
