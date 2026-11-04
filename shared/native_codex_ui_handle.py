#!/usr/bin/env python3
"""Root-owned one-shot claims for the sanitized native Codex UI channel.

This authority is deliberately not a terminal handle.  It can open only the
schema-pinned command/event stream owned by the Research runtime driver; it
never names a PTY, arbitrary command, or credential-bearing descriptor.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from shared import native_stack_session


RECORD_SCHEMA = "secure-sandbox-native-codex-ui-handle-v1"
PUBLIC_SCHEMA = "secure-sandbox-native-codex-ui-handle-public-v1"
CLAIM_SCHEMA = "secure-sandbox-native-codex-ui-handle-claim-v1"
CONSUMPTION_SCHEMA = "secure-sandbox-native-codex-ui-handle-consumption-v1"
RETIREMENT_SCHEMA = "secure-sandbox-native-codex-ui-handle-retirement-v1"
KIND = "codex-typed-ui"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
MAXIMUM_RECORD_BYTES = 32 * 1024
MAXIMUM_RECORDS = 4096
MAXIMUM_LIFETIME_SECONDS = 180
LOCK_NAME = ".inventory.lock"
STALE_FD_SECONDS = 300


class NativeCodexUIHandleError(ValueError):
    """Stable fail-closed typed-UI handle error."""


def canonical_bytes(value: object) -> bytes:
    try:
        raw = (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_not_canonicalizable"
        ) from error
    if not 2 <= len(raw) <= MAXIMUM_RECORD_BYTES:
        raise NativeCodexUIHandleError("native_codex_ui_handle_size_invalid")
    return raw


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeCodexUIHandleError(
            f"native_codex_ui_handle_{label}_invalid"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeCodexUIHandleError(
            f"native_codex_ui_handle_{label}_invalid"
        )
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise NativeCodexUIHandleError(
            f"native_codex_ui_handle_{label}_invalid"
        )
    return value


def validate_record(
    value: object, *, now: int | None = None, require_fresh: bool = False,
) -> dict[str, Any]:
    fields = {
        "schema", "handle_id", "kind", "operation_id", "plan_sha256",
        "authorization_sha256", "stack_sha256", "catalog_sha256",
        "session_id", "runtime_authority_sha256", "harness_generation_id",
        "harness_executable_sha256", "session_lease", "issued_at",
        "expires_at", "record_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexUIHandleError("native_codex_ui_handle_fields_invalid")
    if value.get("schema") != RECORD_SCHEMA or value.get("kind") != KIND:
        raise NativeCodexUIHandleError("native_codex_ui_handle_identity_invalid")
    for field in ("handle_id", "operation_id", "session_id"):
        _uuid4(value.get(field), field)
    for field in (
        "plan_sha256", "authorization_sha256", "stack_sha256",
        "catalog_sha256", "runtime_authority_sha256",
        "harness_generation_id", "harness_executable_sha256",
    ):
        _digest(value.get(field), field)
    try:
        lease = native_stack_session.validate_session_lease(value.get("session_lease"))
    except native_stack_session.NativeStackSessionError as error:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_session_lease_invalid"
        ) from error
    if (lease["session_id"] != value["session_id"]
            or lease["runtime_authority_sha256"]
                != value["runtime_authority_sha256"]):
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_session_lease_mismatch"
        )
    issued = _integer(value.get("issued_at"), "issued_at")
    expires = _integer(value.get("expires_at"), "expires_at")
    if expires <= issued or expires > issued + MAXIMUM_LIFETIME_SECONDS:
        raise NativeCodexUIHandleError("native_codex_ui_handle_lifetime_invalid")
    if require_fresh and (now is None or not issued <= now < expires):
        raise NativeCodexUIHandleError("native_codex_ui_handle_expired")
    body = {key: value[key] for key in fields - {"schema", "record_sha256"}}
    supplied = _digest(value.get("record_sha256"), "record_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeCodexUIHandleError("native_codex_ui_handle_digest_mismatch")
    return {"schema": RECORD_SCHEMA, **body, "record_sha256": supplied}


def make_record(**values: object) -> dict[str, Any]:
    body = {"kind": KIND, **values}
    return validate_record({
        "schema": RECORD_SCHEMA, **body, "record_sha256": sha256(body),
    })


def public_record(value: object) -> dict[str, Any]:
    record = validate_record(value)
    lease = record["session_lease"]
    body = {
        "handle_id": record["handle_id"], "kind": KIND,
        "operation_id": record["operation_id"],
        "session_id": record["session_id"],
        "runtime_authority_sha256": record["runtime_authority_sha256"],
        "session_lease_sha256": lease["lease_sha256"],
        "session_expires_at": lease["expires_at"],
        "handle_sha256": record["record_sha256"],
        "expires_at": record["expires_at"],
    }
    return {"schema": PUBLIC_SCHEMA, **body, "reply_sha256": sha256(body)}


def validate_public(value: object) -> dict[str, Any]:
    fields = {
        "schema", "handle_id", "kind", "operation_id", "session_id",
        "runtime_authority_sha256", "session_lease_sha256",
        "session_expires_at", "handle_sha256", "expires_at", "reply_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_public_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "reply_sha256"}}
    for field in ("handle_id", "operation_id", "session_id"):
        _uuid4(body.get(field), f"public_{field}")
    for field in (
        "runtime_authority_sha256", "session_lease_sha256", "handle_sha256",
    ):
        _digest(body.get(field), f"public_{field}")
    _integer(body.get("session_expires_at"), "public_session_expires_at")
    _integer(body.get("expires_at"), "public_expires_at")
    supplied = _digest(value.get("reply_sha256"), "public_reply_sha256")
    if (value.get("schema") != PUBLIC_SCHEMA or body.get("kind") != KIND
            or not hmac.compare_digest(supplied, sha256(body))):
        raise NativeCodexUIHandleError("native_codex_ui_handle_public_invalid")
    return {"schema": PUBLIC_SCHEMA, **body, "reply_sha256": supplied}


def validate_claim(value: object) -> dict[str, str]:
    fields = {"schema", "handle_id", "handle_sha256", "request_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexUIHandleError("native_codex_ui_handle_claim_fields_invalid")
    body = {
        "handle_id": _uuid4(value.get("handle_id"), "claim_handle_id"),
        "handle_sha256": _digest(
            value.get("handle_sha256"), "claim_handle_sha256"
        ),
    }
    supplied = _digest(value.get("request_sha256"), "claim_request_sha256")
    if value.get("schema") != CLAIM_SCHEMA or not hmac.compare_digest(
        supplied, sha256(body)
    ):
        raise NativeCodexUIHandleError("native_codex_ui_handle_claim_invalid")
    return {"schema": CLAIM_SCHEMA, **body, "request_sha256": supplied}


def _root(root: Path, uid: int, gid: int) -> int:
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    info = os.fstat(descriptor)
    current = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(current.st_mode)
            or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
            or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(descriptor)
        raise NativeCodexUIHandleError("native_codex_ui_handle_root_untrusted")
    return descriptor


def _read_at(
    directory: int, name: str, uid: int, gid: int, *, mode: int = 0o600,
) -> dict[str, Any]:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
    )
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != mode
                or not 2 <= info.st_size <= MAXIMUM_RECORD_BYTES):
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_record_untrusted"
            )
        raw = os.read(descriptor, info.st_size + 1)
        if len(raw) != info.st_size or os.read(descriptor, 1):
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_record_changed"
            )
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_record_invalid"
        ) from error
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_record_not_canonical"
        )
    return value


def _lock(directory: int, uid: int, gid: int) -> int:
    descriptor = os.open(
        LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=directory,
    )
    try:
        os.fchown(descriptor, uid, gid); os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_lock_untrusted"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _inventory(
    directory: int, *, now: int, uid: int, gid: int,
    prune_expired_sources: bool = True,
    allow_incomplete_retirement: bool = False,
) -> None:
    fragment = UUID4.pattern.removeprefix("^").removesuffix("$")
    record_name = re.compile(
        rf"({fragment})(?:\.(consumed|claim|retired))?\.json"
    )
    fd_name = re.compile(rf"\.fd-({fragment})")
    names = sorted(os.listdir(directory))
    if len(names) > (MAXIMUM_RECORDS * 2) + 1:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_inventory_capacity_exceeded"
        )
    records: dict[tuple[str, str], dict[str, Any]] = {}
    changed = False
    for name in names:
        if name == LOCK_NAME:
            continue
        matched = record_name.fullmatch(name)
        if matched is not None:
            handle_id, suffix = matched.group(1), matched.group(2) or "source"
            raw = _read_at(directory, name, uid, gid)
            if suffix == "claim":
                value = _validate_consumption(raw)
                if value["handle_id"] != handle_id:
                    raise NativeCodexUIHandleError(
                        "native_codex_ui_handle_inventory_untrusted"
                    )
            elif suffix == "retired":
                value = _validate_retirement(raw)
                if value["handle_id"] != handle_id:
                    raise NativeCodexUIHandleError(
                        "native_codex_ui_handle_inventory_untrusted"
                    )
            else:
                value = validate_record(raw)
                if value["handle_id"] != handle_id:
                    raise NativeCodexUIHandleError(
                        "native_codex_ui_handle_inventory_untrusted"
                    )
            records[(handle_id, suffix)] = value
            continue
        matched_fd = fd_name.fullmatch(name)
        if matched_fd is not None:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            value = validate_record(_read_at(
                directory, name, uid, gid, mode=0o400
            ))
            if value["handle_id"] != matched_fd.group(1):
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_inventory_untrusted"
                )
            if info.st_mtime > now - STALE_FD_SECONDS:
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_claim_incomplete"
                )
            os.unlink(name, dir_fd=directory)
            changed = True
            continue
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_inventory_untrusted"
        )
    for (handle_id, suffix), value in list(records.items()):
        retired = records.get((handle_id, "retired"))
        if (suffix == "consumed" and (handle_id, "claim") not in records
                and retired is None):
            if now >= value["expires_at"] + STALE_FD_SECONDS:
                os.unlink(f"{handle_id}.consumed.json", dir_fd=directory)
                records.pop((handle_id, suffix))
                changed = True
                continue
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_claim_ambiguous"
            )
        if suffix == "claim":
            consumed = records.get((handle_id, "consumed"))
            expected = (
                consumed["record_sha256"] if consumed is not None else
                retired["handle_sha256"] if retired is not None else None
            )
            if (expected is None or value["handle_sha256"] != expected
                    or (consumed is not None and not
                        consumed["issued_at"] <= value["claimed_at"]
                        < consumed["expires_at"])):
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_inventory_untrusted"
                )
        if (suffix in {"consumed", "claim"}
                and (handle_id, "source") in records):
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_inventory_untrusted"
            )
        if retired is not None and suffix in {"source", "consumed"}:
            if value["record_sha256"] != retired["handle_sha256"]:
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_inventory_untrusted"
                )
        if (retired is not None and suffix in {"source", "consumed", "claim"}
                and not allow_incomplete_retirement):
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_retirement_incomplete"
            )
    if prune_expired_sources:
        for (handle_id, suffix), value in list(records.items()):
            if (suffix == "source" and value["expires_at"] <= now
                    and (handle_id, "retired") not in records):
                os.unlink(f"{handle_id}.json", dir_fd=directory)
                records.pop((handle_id, suffix))
                changed = True
    if changed:
        os.fsync(directory)
    if len(os.listdir(directory)) > MAXIMUM_RECORDS + 1:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_inventory_capacity_exceeded"
        )


def _write_at(directory: int, name: str, value: object, uid: int, gid: int,
              mode: int) -> None:
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        | os.O_CLOEXEC, mode, dir_fd=directory,
    )
    try:
        os.fchown(descriptor, uid, gid); os.fchmod(descriptor, mode)
        raw = canonical_bytes(value)
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            if count <= 0:
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_write_failed"
                )
            offset += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(value: object, *, root: Path, trusted_uid: int = 0,
            trusted_gid: int = 0) -> dict[str, Any]:
    record = validate_record(value)
    directory = _root(root, trusted_uid, trusted_gid)
    lock = -1
    try:
        lock = _lock(directory, trusted_uid, trusted_gid)
        _inventory(
            directory, now=record["issued_at"], uid=trusted_uid,
            gid=trusted_gid,
        )
        if len(os.listdir(directory)) >= MAXIMUM_RECORDS + 1:
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_inventory_capacity_exceeded"
            )
        name = f"{record['handle_id']}.json"
        _write_at(directory, name, record, trusted_uid, trusted_gid, 0o600)
        os.fsync(directory)
        if validate_record(_read_at(
            directory, name, trusted_uid, trusted_gid
        )) != record:
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_readback_failed"
            )
        return public_record(record)
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(directory)


def _consumption(record: Mapping[str, Any], claimed_at: int) -> dict[str, Any]:
    body = {
        "handle_id": record["handle_id"],
        "handle_sha256": record["record_sha256"], "claimed_at": claimed_at,
    }
    return {"schema": CONSUMPTION_SCHEMA, **body,
            "consumption_sha256": sha256(body)}


def _validate_consumption(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "handle_id", "handle_sha256", "claimed_at",
        "consumption_sha256",
    }:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_consumption_invalid"
        )
    body = {
        "handle_id": _uuid4(value.get("handle_id"), "consumed_handle_id"),
        "handle_sha256": _digest(
            value.get("handle_sha256"), "consumed_handle_sha256"
        ),
        "claimed_at": _integer(value.get("claimed_at"), "claimed_at"),
    }
    supplied = _digest(value.get("consumption_sha256"), "consumption_sha256")
    if (value.get("schema") != CONSUMPTION_SCHEMA
            or not hmac.compare_digest(supplied, sha256(body))):
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_consumption_invalid"
        )
    return {"schema": CONSUMPTION_SCHEMA, **body,
            "consumption_sha256": supplied}


def _retirement(
    handle_id: str, handle_sha256: str, retired_at: int,
) -> dict[str, Any]:
    body = {
        "handle_id": handle_id, "handle_sha256": handle_sha256,
        "retired_at": retired_at,
    }
    return {"schema": RETIREMENT_SCHEMA, **body,
            "retirement_sha256": sha256(body)}


def _validate_retirement(value: object) -> dict[str, Any]:
    fields = {
        "schema", "handle_id", "handle_sha256", "retired_at",
        "retirement_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_retirement_invalid"
        )
    body = {
        "handle_id": _uuid4(value.get("handle_id"), "retired_handle_id"),
        "handle_sha256": _digest(
            value.get("handle_sha256"), "retired_handle_sha256"
        ),
        "retired_at": _integer(value.get("retired_at"), "retired_at"),
    }
    supplied = _digest(value.get("retirement_sha256"), "retirement_sha256")
    if (value.get("schema") != RETIREMENT_SCHEMA
            or not hmac.compare_digest(supplied, sha256(body))):
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_retirement_invalid"
        )
    return {"schema": RETIREMENT_SCHEMA, **body,
            "retirement_sha256": supplied}


def claim_unlinked_fd(
    claim_value: object, *, root: Path, now: int, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> tuple[int, dict[str, Any]]:
    claim = validate_claim(claim_value)
    directory = _root(root, trusted_uid, trusted_gid)
    source = f"{claim['handle_id']}.json"
    consumed = f"{claim['handle_id']}.consumed.json"
    temporary = f".fd-{uuid.uuid4()}"
    reader = -1
    lock = -1
    try:
        lock = _lock(directory, trusted_uid, trusted_gid)
        for denied in (consumed, f"{claim['handle_id']}.retired.json"):
            try:
                os.stat(denied, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_replay_denied"
            )
        _inventory(
            directory, now=now, uid=trusted_uid, gid=trusted_gid,
            prune_expired_sources=False,
        )
        record = validate_record(_read_at(
            directory, source, trusted_uid, trusted_gid
        ))
        if not hmac.compare_digest(
            record["record_sha256"], claim["handle_sha256"]
        ):
            raise NativeCodexUIHandleError("native_codex_ui_handle_claim_mismatch")
        before = os.stat(source, dir_fd=directory, follow_symlinks=False)
        os.replace(source, consumed, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        after = os.stat(consumed, dir_fd=directory, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise NativeCodexUIHandleError("native_codex_ui_handle_claim_ambiguous")
        if validate_record(_read_at(
            directory, consumed, trusted_uid, trusted_gid
        )) != record:
            raise NativeCodexUIHandleError("native_codex_ui_handle_claim_ambiguous")
        validate_record(record, now=now, require_fresh=True)
        consumption = _consumption(record, now)
        claim_name = f"{claim['handle_id']}.claim.json"
        _write_at(
            directory, claim_name, consumption, trusted_uid, trusted_gid, 0o600
        )
        os.fsync(directory)
        if _validate_consumption(_read_at(
            directory, claim_name, trusted_uid, trusted_gid
        )) != consumption:
            raise NativeCodexUIHandleError("native_codex_ui_handle_claim_ambiguous")
        _write_at(directory, temporary, record, trusted_uid, trusted_gid, 0o400)
        reader = os.open(
            temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
        os.unlink(temporary, dir_fd=directory); os.fsync(directory)
        info = os.fstat(reader)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o400
                or os.lseek(reader, 0, os.SEEK_CUR) != 0):
            raise NativeCodexUIHandleError("native_codex_ui_handle_fd_untrusted")
        result, reader = reader, -1
        return result, record
    finally:
        if reader >= 0:
            os.close(reader)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        if lock >= 0:
            os.close(lock)
        os.close(directory)


def read_unlinked_fd(
    descriptor: int, *, now: int, trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    try:
        info = os.fstat(descriptor)
        access = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as error:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_fd_unavailable"
        ) from error
    if (descriptor < 3 or access != os.O_RDONLY
            or not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
            or info.st_uid != trusted_uid or info.st_gid != trusted_gid
            or stat.S_IMODE(info.st_mode) != 0o400
            or not 2 <= info.st_size <= MAXIMUM_RECORD_BYTES
            or os.lseek(descriptor, 0, os.SEEK_CUR) != 0):
        raise NativeCodexUIHandleError("native_codex_ui_handle_fd_untrusted")
    raw = os.read(descriptor, info.st_size + 1)
    if len(raw) != info.st_size or os.read(descriptor, 1):
        raise NativeCodexUIHandleError("native_codex_ui_handle_fd_changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeCodexUIHandleError("native_codex_ui_handle_fd_invalid") from error
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_fd_not_canonical"
        )
    return validate_record(value, now=now, require_fresh=True)


def read_consumed_by_id(
    *, root: Path, handle_id: str, trusted_uid: int = 0, trusted_gid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    identifier = _uuid4(handle_id, "consumed_handle_id")
    directory = _root(root, trusted_uid, trusted_gid)
    lock = -1
    try:
        lock = _lock(directory, trusted_uid, trusted_gid)
        _inventory(
            directory, now=int(time.time()), uid=trusted_uid, gid=trusted_gid,
        )
        record = validate_record(_read_at(
            directory, f"{identifier}.consumed.json", trusted_uid, trusted_gid
        ))
        consumption = _validate_consumption(_read_at(
            directory, f"{identifier}.claim.json", trusted_uid, trusted_gid
        ))
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(directory)
    if (consumption["handle_id"] != identifier
            or not hmac.compare_digest(
                consumption["handle_sha256"], record["record_sha256"]
            )
            or not record["issued_at"] <= consumption["claimed_at"]
                < record["expires_at"]):
        raise NativeCodexUIHandleError(
            "native_codex_ui_handle_consumption_mismatch"
        )
    return record, consumption


def retire_handle(
    *, root: Path, handle_id: str, handle_sha256: str, now: int,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    """Retire one exact source or consumed pair after proven run absence."""
    identifier = _uuid4(handle_id, "retire_handle_id")
    expected_sha256 = _digest(handle_sha256, "retire_handle_sha256")
    directory = _root(root, trusted_uid, trusted_gid)
    lock = -1
    try:
        lock = _lock(directory, trusted_uid, trusted_gid)
        _inventory(
            directory, now=now, uid=trusted_uid, gid=trusted_gid,
            prune_expired_sources=False, allow_incomplete_retirement=True,
        )
        source = f"{identifier}.json"
        consumed = f"{identifier}.consumed.json"
        claim = f"{identifier}.claim.json"
        retired = f"{identifier}.retired.json"
        try:
            retirement = _validate_retirement(_read_at(
                directory, retired, trusted_uid, trusted_gid
            ))
        except FileNotFoundError:
            try:
                record = validate_record(_read_at(
                    directory, source, trusted_uid, trusted_gid
                ))
            except FileNotFoundError:
                try:
                    record = validate_record(_read_at(
                        directory, consumed, trusted_uid, trusted_gid
                    ))
                except FileNotFoundError:
                    try:
                        os.stat(claim, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        return
                    raise NativeCodexUIHandleError(
                        "native_codex_ui_handle_retirement_ambiguous"
                    )
                receipt = _validate_consumption(_read_at(
                    directory, claim, trusted_uid, trusted_gid
                ))
                if receipt["handle_sha256"] != expected_sha256:
                    raise NativeCodexUIHandleError(
                        "native_codex_ui_handle_retirement_mismatch"
                    )
            if record["record_sha256"] != expected_sha256:
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_retirement_mismatch"
                )
            retirement = _retirement(identifier, expected_sha256, now)
            _write_at(
                directory, retired, retirement,
                trusted_uid, trusted_gid, 0o600,
            )
            os.fsync(directory)
        else:
            if (retirement["handle_id"] != identifier
                    or retirement["handle_sha256"] != expected_sha256):
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_retirement_mismatch"
                )
        for name, validator in (
            (source, validate_record), (consumed, validate_record),
            (claim, _validate_consumption),
        ):
            try:
                value = validator(_read_at(
                    directory, name, trusted_uid, trusted_gid
                ))
            except FileNotFoundError:
                continue
            observed = (
                value["record_sha256"] if validator is validate_record
                else value["handle_sha256"]
            )
            if observed != expected_sha256:
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_retirement_mismatch"
                )
            os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(directory)


def finalize_retirement(
    *, root: Path, handle_id: str, handle_sha256: str, now: int,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    """Remove a retirement tombstone only after durable terminal journal state."""
    identifier = _uuid4(handle_id, "finalize_handle_id")
    expected_sha256 = _digest(handle_sha256, "finalize_handle_sha256")
    directory = _root(root, trusted_uid, trusted_gid)
    lock = -1
    try:
        lock = _lock(directory, trusted_uid, trusted_gid)
        _inventory(
            directory, now=now, uid=trusted_uid, gid=trusted_gid,
            prune_expired_sources=False,
        )
        name = f"{identifier}.retired.json"
        try:
            retirement = _validate_retirement(_read_at(
                directory, name, trusted_uid, trusted_gid
            ))
        except FileNotFoundError:
            for suffix in (".json", ".consumed.json", ".claim.json"):
                try:
                    os.stat(
                        f"{identifier}{suffix}", dir_fd=directory,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                raise NativeCodexUIHandleError(
                    "native_codex_ui_handle_finalization_ambiguous"
                )
            return
        if (retirement["handle_id"] != identifier
                or retirement["handle_sha256"] != expected_sha256):
            raise NativeCodexUIHandleError(
                "native_codex_ui_handle_finalization_mismatch"
            )
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(directory)
