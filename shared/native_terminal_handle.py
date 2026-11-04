#!/usr/bin/env python3
"""Root-owned one-shot handles for native interactive terminal streams.

The Touch ID path publishes only a content-free public handle.  A separately
authenticated terminal client presents that handle over its connected Unix
socket; the root broker atomically consumes the durable record and transfers
an unlinked read-only file description to the fixed stream launcher.  Vendor
terminal bytes never enter this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import fcntl
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping


RECORD_SCHEMA = "secure-sandbox-native-terminal-handle-v1"
PUBLIC_SCHEMA = "secure-sandbox-native-terminal-handle-public-v1"
CLAIM_SCHEMA = "secure-sandbox-native-terminal-handle-claim-v1"
CONSUMPTION_SCHEMA = "secure-sandbox-native-terminal-handle-consumption-v1"
KINDS = {"claude-login", "claude-session"}
REMOTE_OPERATIONS = {
    "claude-login": "native-claude-login",
    "claude-session": "native-claude-launch",
}
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
MAXIMUM_RECORD_BYTES = 32 * 1024
MAXIMUM_RECORDS = 4096
MAXIMUM_LIFETIME_SECONDS = 180


class NativeTerminalHandleError(ValueError):
    """Stable fail-closed terminal-handle error."""


def canonical_bytes(value: object) -> bytes:
    try:
        raw = (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeTerminalHandleError(
            "native_terminal_handle_not_canonicalizable"
        ) from error
    if not 2 <= len(raw) <= MAXIMUM_RECORD_BYTES:
        raise NativeTerminalHandleError("native_terminal_handle_size_invalid")
    return raw


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeTerminalHandleError(f"native_terminal_handle_{label}_invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeTerminalHandleError(f"native_terminal_handle_{label}_invalid")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise NativeTerminalHandleError(f"native_terminal_handle_{label}_invalid")
    return value


def validate_record(value: object, *, now: int | None = None,
                    require_fresh: bool = False) -> dict[str, Any]:
    fields = {
        "schema", "handle_id", "kind", "operation_id", "plan_sha256",
        "authorization_sha256", "stack_sha256", "catalog_sha256",
        "session_id", "remote_operation", "remote_arguments", "issued_at",
        "expires_at", "record_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeTerminalHandleError("native_terminal_handle_fields_invalid")
    kind = value.get("kind")
    if (value.get("schema") != RECORD_SCHEMA or kind not in KINDS
            or value.get("remote_operation") != REMOTE_OPERATIONS[kind]):
        raise NativeTerminalHandleError("native_terminal_handle_identity_invalid")
    _uuid4(value.get("handle_id"), "handle_id")
    _uuid4(value.get("operation_id"), "operation_id")
    _uuid4(value.get("session_id"), "session_id")
    for field in (
        "plan_sha256", "authorization_sha256", "stack_sha256",
        "catalog_sha256",
    ):
        _digest(value.get(field), field)
    arguments = value.get("remote_arguments")
    expected_count = 5 if kind == "claude-login" else 2
    if (not isinstance(arguments, list) or len(arguments) != expected_count
            or any(not isinstance(item, str) or not 1 <= len(item) <= 128
                   for item in arguments)):
        raise NativeTerminalHandleError(
            "native_terminal_handle_remote_arguments_invalid"
        )
    if arguments[0] != value["operation_id"]:
        raise NativeTerminalHandleError(
            "native_terminal_handle_remote_binding_invalid"
        )
    if kind == "claude-login":
        expected = [
            value["operation_id"], value["plan_sha256"],
            value["authorization_sha256"], value["stack_sha256"],
            value["catalog_sha256"],
        ]
        if arguments != expected:
            raise NativeTerminalHandleError(
                "native_terminal_handle_remote_binding_invalid"
            )
    elif SHA256.fullmatch(arguments[1]) is None:
        # The first argument is the Touch ID action/operation ID and the second
        # is the one-time Research prepare digest.  The separately bound
        # session ID must not be conflated with the action ID.
        raise NativeTerminalHandleError(
            "native_terminal_handle_remote_binding_invalid"
        )
    issued = _integer(value.get("issued_at"), "issued_at")
    expires = _integer(value.get("expires_at"), "expires_at")
    if expires <= issued or expires > issued + MAXIMUM_LIFETIME_SECONDS:
        raise NativeTerminalHandleError("native_terminal_handle_lifetime_invalid")
    if require_fresh and (now is None or not issued <= now < expires):
        raise NativeTerminalHandleError("native_terminal_handle_expired")
    body = {key: value[key] for key in fields - {"schema", "record_sha256"}}
    supplied = _digest(value.get("record_sha256"), "record_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeTerminalHandleError("native_terminal_handle_digest_mismatch")
    return {"schema": RECORD_SCHEMA, **body, "record_sha256": supplied}


def make_record(
    *, handle_id: str, kind: str, operation_id: str, plan_sha256: str,
    authorization_sha256: str, stack_sha256: str, catalog_sha256: str,
    session_id: str, remote_arguments: list[str], issued_at: int,
    expires_at: int,
) -> dict[str, Any]:
    body = {
        "handle_id": handle_id, "kind": kind,
        "operation_id": operation_id, "plan_sha256": plan_sha256,
        "authorization_sha256": authorization_sha256,
        "stack_sha256": stack_sha256, "catalog_sha256": catalog_sha256,
        "session_id": session_id,
        "remote_operation": REMOTE_OPERATIONS.get(kind),
        "remote_arguments": remote_arguments, "issued_at": issued_at,
        "expires_at": expires_at,
    }
    return validate_record({
        "schema": RECORD_SCHEMA, **body, "record_sha256": sha256(body),
    })


def public_record(record_value: object) -> dict[str, Any]:
    record = validate_record(record_value)
    body = {
        "handle_id": record["handle_id"], "kind": record["kind"],
        "operation_id": record["operation_id"],
        "session_id": record["session_id"],
        "handle_sha256": record["record_sha256"],
        "expires_at": record["expires_at"],
    }
    return {"schema": PUBLIC_SCHEMA, **body, "reply_sha256": sha256(body)}


def validate_public(value: object) -> dict[str, Any]:
    fields = {
        "schema", "handle_id", "kind", "operation_id", "session_id",
        "handle_sha256", "expires_at", "reply_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeTerminalHandleError(
            "native_terminal_handle_public_fields_invalid"
        )
    body = {
        "handle_id": _uuid4(value.get("handle_id"), "public_handle_id"),
        "kind": value.get("kind"),
        "operation_id": _uuid4(
            value.get("operation_id"), "public_operation_id"
        ),
        "session_id": _uuid4(value.get("session_id"), "public_session_id"),
        "handle_sha256": _digest(
            value.get("handle_sha256"), "public_handle_sha256"
        ),
        "expires_at": _integer(value.get("expires_at"), "public_expires_at"),
    }
    supplied = _digest(value.get("reply_sha256"), "public_reply_sha256")
    if (value.get("schema") != PUBLIC_SCHEMA or body["kind"] not in KINDS
            or not hmac.compare_digest(str(supplied), sha256(body))):
        raise NativeTerminalHandleError(
            "native_terminal_handle_public_invalid"
        )
    return {"schema": PUBLIC_SCHEMA, **body, "reply_sha256": supplied}


def validate_claim(value: object) -> dict[str, str]:
    fields = {"schema", "handle_id", "handle_sha256", "request_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeTerminalHandleError("native_terminal_handle_claim_fields_invalid")
    body = {
        "handle_id": _uuid4(value.get("handle_id"), "claim_handle_id"),
        "handle_sha256": _digest(
            value.get("handle_sha256"), "claim_handle_sha256"
        ),
    }
    supplied = _digest(value.get("request_sha256"), "claim_request_sha256")
    if (value.get("schema") != CLAIM_SCHEMA
            or not hmac.compare_digest(str(supplied), sha256(body))):
        raise NativeTerminalHandleError("native_terminal_handle_claim_invalid")
    return {"schema": CLAIM_SCHEMA, **body,
            "request_sha256": str(supplied)}


def _root_descriptor(root: Path, *, trusted_uid: int, trusted_gid: int) -> int:
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        opened = os.fstat(descriptor)
        current = root.lstat()
        if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(current.st_mode)
                or (opened.st_dev, opened.st_ino)
                    != (current.st_dev, current.st_ino)
                or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
                or stat.S_IMODE(opened.st_mode) != 0o700):
            raise NativeTerminalHandleError(
                "native_terminal_handle_root_untrusted"
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_canonical_at(directory: int, name: str, *, trusted_uid: int,
                       trusted_gid: int) -> dict[str, Any]:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
    )
    try:
        information = os.fstat(descriptor)
        if (not stat.S_ISREG(information.st_mode) or information.st_nlink != 1
                or information.st_uid != trusted_uid
                or information.st_gid != trusted_gid
                or stat.S_IMODE(information.st_mode) != 0o600
                or not 2 <= information.st_size <= MAXIMUM_RECORD_BYTES):
            raise NativeTerminalHandleError(
                "native_terminal_handle_record_untrusted"
            )
        raw = os.read(descriptor, information.st_size + 1)
        if len(raw) != information.st_size or os.read(descriptor, 1):
            raise NativeTerminalHandleError(
                "native_terminal_handle_record_changed"
            )
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeTerminalHandleError(
            "native_terminal_handle_record_invalid"
        ) from error
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        raise NativeTerminalHandleError(
            "native_terminal_handle_record_not_canonical"
        )
    return value


def _write_new_at(
    directory: int, name: str, value: object, *, mode: int,
    trusted_uid: int, trusted_gid: int,
) -> None:
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        | os.O_CLOEXEC, mode, dir_fd=directory,
    )
    try:
        os.fchown(descriptor, trusted_uid, trusted_gid)
        os.fchmod(descriptor, mode)
        raw = canonical_bytes(value)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise NativeTerminalHandleError(
                    "native_terminal_handle_write_failed"
                )
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_consumption(value: object) -> dict[str, Any]:
    fields = {
        "schema", "handle_id", "handle_sha256", "claimed_at",
        "consumption_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeTerminalHandleError(
            "native_terminal_handle_consumption_fields_invalid"
        )
    body = {
        "handle_id": _uuid4(value.get("handle_id"), "consumption_handle_id"),
        "handle_sha256": _digest(
            value.get("handle_sha256"), "consumption_handle_sha256"
        ),
        "claimed_at": _integer(value.get("claimed_at"), "claimed_at"),
    }
    supplied = _digest(
        value.get("consumption_sha256"), "consumption_sha256"
    )
    if (value.get("schema") != CONSUMPTION_SCHEMA
            or not hmac.compare_digest(str(supplied), sha256(body))):
        raise NativeTerminalHandleError(
            "native_terminal_handle_consumption_invalid"
        )
    return {
        "schema": CONSUMPTION_SCHEMA, **body,
        "consumption_sha256": supplied,
    }


def consumption_record(
    record_value: object, *, claimed_at: int,
) -> dict[str, Any]:
    record = validate_record(record_value)
    body = {
        "handle_id": record["handle_id"],
        "handle_sha256": record["record_sha256"],
        "claimed_at": claimed_at,
    }
    return validate_consumption({
        "schema": CONSUMPTION_SCHEMA, **body,
        "consumption_sha256": sha256(body),
    })


def publish(record_value: object, *, root: Path, trusted_uid: int = 0,
            trusted_gid: int = 0) -> dict[str, Any]:
    record = validate_record(record_value)
    directory = _root_descriptor(
        root, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    name = f"{record['handle_id']}.json"
    try:
        names = os.listdir(directory)
        permitted = re.compile(
            rf"(?:{UUID4.pattern})(?:\.consumed|\.claim)?\.json|"
            rf"\.fd-(?:{UUID4.pattern})"
        )
        if (len(names) >= MAXIMUM_RECORDS
                or any(permitted.fullmatch(item) is None for item in names)):
            raise NativeTerminalHandleError(
                "native_terminal_handle_inventory_untrusted"
            )
        _write_new_at(
            directory, name, record, mode=0o600,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        )
        os.fsync(directory)
        if validate_record(_read_canonical_at(
            directory, name, trusted_uid=trusted_uid, trusted_gid=trusted_gid
        )) != record:
            raise NativeTerminalHandleError(
                "native_terminal_handle_readback_failed"
            )
        return public_record(record)
    finally:
        os.close(directory)


def claim_unlinked_fd(
    claim_value: object, *, root: Path, now: int, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> tuple[int, dict[str, Any]]:
    claim = validate_claim(claim_value)
    directory = _root_descriptor(
        root, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    source = f"{claim['handle_id']}.json"
    consumed = f"{claim['handle_id']}.consumed.json"
    reader = -1
    temporary = f".fd-{uuid.uuid4()}"
    try:
        try:
            os.stat(consumed, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise NativeTerminalHandleError(
                "native_terminal_handle_replay_denied"
            )
        record = validate_record(_read_canonical_at(
            directory, source, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ))
        if not hmac.compare_digest(
            record["record_sha256"], claim["handle_sha256"]
        ):
            raise NativeTerminalHandleError(
                "native_terminal_handle_claim_mismatch"
            )
        before = os.stat(source, dir_fd=directory, follow_symlinks=False)
        os.replace(source, consumed, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        after = os.stat(consumed, dir_fd=directory, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise NativeTerminalHandleError(
                "native_terminal_handle_claim_ambiguous"
            )
        observed = validate_record(_read_canonical_at(
            directory, consumed, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ))
        if observed != record:
            raise NativeTerminalHandleError(
                "native_terminal_handle_claim_ambiguous"
            )
        # Expiry is checked only after the durable replay tombstone exists.
        validate_record(record, now=now, require_fresh=True)
        consumption = consumption_record(record, claimed_at=now)
        claim_name = f"{claim['handle_id']}.claim.json"
        _write_new_at(
            directory, claim_name, consumption, mode=0o600,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        )
        os.fsync(directory)
        if validate_consumption(_read_canonical_at(
            directory, claim_name, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )) != consumption:
            raise NativeTerminalHandleError(
                "native_terminal_handle_claim_ambiguous"
            )
        writer = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o400, dir_fd=directory
        )
        try:
            os.fchown(writer, trusted_uid, trusted_gid)
            os.fchmod(writer, 0o400)
            raw = canonical_bytes(record)
            offset = 0
            while offset < len(raw):
                written = os.write(writer, raw[offset:])
                if written <= 0:
                    raise NativeTerminalHandleError(
                        "native_terminal_handle_write_failed"
                    )
                offset += written
            os.fsync(writer)
        finally:
            os.close(writer)
        reader = os.open(
            temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        info = os.fstat(reader)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o400
                or os.lseek(reader, 0, os.SEEK_CUR) != 0):
            raise NativeTerminalHandleError(
                "native_terminal_handle_fd_untrusted"
            )
        result, reader = reader, -1
        return result, record
    finally:
        if reader >= 0:
            os.close(reader)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def read_unlinked_fd(
    descriptor: int, *, now: int, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    try:
        information = os.fstat(descriptor)
    except OSError as error:
        raise NativeTerminalHandleError(
            "native_terminal_handle_fd_unavailable"
        ) from error
    access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    if (descriptor < 3 or access_mode != os.O_RDONLY
            or not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 0 or information.st_uid != trusted_uid
            or information.st_gid != trusted_gid
            or stat.S_IMODE(information.st_mode) != 0o400
            or not 2 <= information.st_size <= MAXIMUM_RECORD_BYTES
            or os.lseek(descriptor, 0, os.SEEK_CUR) != 0):
        raise NativeTerminalHandleError("native_terminal_handle_fd_untrusted")
    raw = os.read(descriptor, information.st_size + 1)
    if len(raw) != information.st_size or os.read(descriptor, 1):
        raise NativeTerminalHandleError("native_terminal_handle_fd_changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeTerminalHandleError(
            "native_terminal_handle_fd_invalid"
        ) from error
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        raise NativeTerminalHandleError(
            "native_terminal_handle_fd_not_canonical"
        )
    return validate_record(value, now=now, require_fresh=True)


def read_consumed(
    *, root: Path, handle_id: str, handle_sha256: str,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read a durable, timely claim after the stream has completed.

    Freshness is established by the immutable root-owned claim timestamp, not
    by requiring the original Touch ID window to remain open for the duration
    of a human browser/terminal login.
    """
    identifier = _uuid4(handle_id, "consumed_handle_id")
    expected_digest = _digest(handle_sha256, "consumed_handle_sha256")
    directory = _root_descriptor(
        root, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    try:
        record = validate_record(_read_canonical_at(
            directory, f"{identifier}.consumed.json",
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        ))
        consumption = validate_consumption(_read_canonical_at(
            directory, f"{identifier}.claim.json",
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        ))
    finally:
        os.close(directory)
    if (not hmac.compare_digest(record["record_sha256"], expected_digest)
            or consumption["handle_id"] != identifier
            or not hmac.compare_digest(
                consumption["handle_sha256"], expected_digest
            )
            or not record["issued_at"] <= consumption["claimed_at"]
                < record["expires_at"]):
        raise NativeTerminalHandleError(
            "native_terminal_handle_consumption_mismatch"
        )
    return record, consumption


def read_consumed_by_id(
    *, root: Path, handle_id: str, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read a consumed record by its root-authoritative operation identity."""
    identifier = _uuid4(handle_id, "consumed_handle_id")
    directory = _root_descriptor(
        root, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    try:
        record = validate_record(_read_canonical_at(
            directory, f"{identifier}.consumed.json",
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        ))
        consumption = validate_consumption(_read_canonical_at(
            directory, f"{identifier}.claim.json",
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        ))
    finally:
        os.close(directory)
    if (record["handle_id"] != identifier
            or consumption["handle_id"] != identifier
            or not hmac.compare_digest(
                record["record_sha256"], consumption["handle_sha256"]
            )
            or not record["issued_at"] <= consumption["claimed_at"]
                < record["expires_at"]):
        raise NativeTerminalHandleError(
            "native_terminal_handle_consumption_mismatch"
        )
    return record, consumption
