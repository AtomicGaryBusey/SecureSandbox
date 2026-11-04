#!/usr/bin/env python3
"""Crash-durable exact-file transactions for native guest installation.

The installer holds its own deployment lock while using this helper.  A
canonical pending record and independently hashed backups are fsynced before
the first destination is changed.  Recovery is idempotent and never reports
success unless every original file (including ownership and mode) or original
absence has been restored and read back.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA = "secure-sandbox-native-install-transaction-v2"
RESULT_SCHEMA = "secure-sandbox-native-install-transaction-result-v1"
ARCHIVE_SCHEMA = "secure-sandbox-native-install-transaction-archive-v1"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_BACKUP_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_ARCHIVE_BYTES = 2 * MAX_RECORD_BYTES
MAX_RETAINED_ARCHIVES = 32
SHA256 = re.compile(r"[0-9a-f]{64}")


class NativeInstallTransactionError(RuntimeError):
    """Stable fail-closed transaction error."""


def canonical(value: object, *, maximum: int = MAX_RECORD_BYTES) -> bytes:
    try:
        raw = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeInstallTransactionError("native_install_value_invalid") from error
    if len(raw) > maximum:
        raise NativeInstallTransactionError("native_install_record_oversized")
    return raw


def digest(value: object, *, maximum: int = MAX_RECORD_BYTES) -> str:
    return hashlib.sha256(canonical(value, maximum=maximum)).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _trusted_parent_fd(path: Path, *, expected_uid: int) -> int:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as error:
        raise NativeInstallTransactionError("native_install_parent_untrusted") from error
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_mode & 0o022
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        os.close(descriptor)
        raise NativeInstallTransactionError("native_install_parent_untrusted")
    return descriptor


def _trusted_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    mode: int,
    create: bool = False,
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise NativeInstallTransactionError("native_install_directory_missing")
        parent_descriptor = _trusted_parent_fd(path.parent, expected_uid=expected_uid)
        try:
            os.mkdir(path.name, mode, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise NativeInstallTransactionError("native_install_directory_untrusted")


def _read_regular(
    path: Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    expected_mode: int | None = None,
    maximum: int = MAX_FILE_BYTES,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeInstallTransactionError("native_install_file_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or len(data) != opened.st_size
        or len(data) > maximum
        or (expected_uid is not None and opened.st_uid != expected_uid)
        or (expected_gid is not None and opened.st_gid != expected_gid)
        or (expected_mode is not None and stat.S_IMODE(opened.st_mode) != expected_mode)
    ):
        raise NativeInstallTransactionError("native_install_file_untrusted")
    return bytes(data), opened


def _atomic_file(
    path: Path,
    raw: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    parent = path.parent
    parent_descriptor = _trusted_parent_fd(parent, expected_uid=os.geteuid())
    temporary_name = f".{path.name}.{uuid.uuid4()}.tmp"
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_descriptor,
        )
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), uid, gid)
            os.fchmod(handle.fileno(), mode)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(
            temporary_name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            observed = bytearray()
            while len(observed) <= len(raw):
                block = os.read(descriptor, min(65536, len(raw) + 1 - len(observed)))
                if not block:
                    break
                observed.extend(block)
        finally:
            os.close(descriptor)
        if observed != raw or metadata.st_size != len(raw):
            raise NativeInstallTransactionError("native_install_publication_readback_failed")
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise NativeInstallTransactionError("native_install_publication_readback_failed")
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)


def _validated_destinations(
    destinations: Iterable[Path], *, expected_uid: int
) -> list[Path]:
    values = sorted(destinations, key=lambda item: str(item))
    if not values or len(values) > 64 or len({str(item) for item in values}) != len(values):
        raise NativeInstallTransactionError("native_install_destination_set_invalid")
    for path in values:
        if not path.is_absolute() or ".." in path.parts or len(str(path)) > 512:
            raise NativeInstallTransactionError("native_install_destination_invalid")
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != expected_uid
            or parent.st_mode & 0o022
        ):
            raise NativeInstallTransactionError("native_install_destination_parent_untrusted")
    return values


def _enforce_retention_bound(pending: Path, *, expected_uid: int) -> None:
    """Fail closed before a transaction can exceed the retained-evidence cap."""
    descriptor = _trusted_parent_fd(pending.parent, expected_uid=expected_uid)
    try:
        expression = re.compile(
            rf"{re.escape(pending.stem)}\."
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\."
            r"(?:committed|recovered)\.json"
        )
        retained = sum(
            1 for name in os.listdir(descriptor) if expression.fullmatch(name)
        )
    finally:
        os.close(descriptor)
    if retained >= MAX_RETAINED_ARCHIVES:
        raise NativeInstallTransactionError("native_install_retention_limit")


def _transaction_body(record: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "schema", "transaction_sha256", "decision", "decided_at",
        "state_sha256",
    }
    return {key: record[key] for key in record if key not in excluded}


def _state_body(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in record if key != "state_sha256"}


def validate_record(value: object) -> dict[str, Any]:
    fields = {
        "schema",
        "transaction_id",
        "created_at",
        "backup_directory",
        "recovery_helper",
        "destinations",
        "metadata",
        "decision",
        "decided_at",
        "transaction_sha256",
        "state_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != SCHEMA:
        raise NativeInstallTransactionError("native_install_record_invalid")
    try:
        parsed = uuid.UUID(str(value["transaction_id"]))
    except (ValueError, AttributeError) as error:
        raise NativeInstallTransactionError("native_install_record_invalid") from error
    if parsed.version != 4 or str(parsed) != value["transaction_id"]:
        raise NativeInstallTransactionError("native_install_record_invalid")
    if (
        not isinstance(value["created_at"], int)
        or isinstance(value["created_at"], bool)
        or value["created_at"] < 1
        or not isinstance(value["backup_directory"], str)
        or not Path(value["backup_directory"]).is_absolute()
        or not isinstance(value["destinations"], list)
        or not 1 <= len(value["destinations"]) <= 64
        or not isinstance(value["metadata"], dict)
        or value["decision"] not in {None, "commit", "recover"}
        or (
            (value["decision"] is None and value["decided_at"] is not None)
            or (
                value["decision"] is not None
                and (
                    not isinstance(value["decided_at"], int)
                    or isinstance(value["decided_at"], bool)
                    or value["decided_at"] < value["created_at"]
                )
            )
        )
        or SHA256.fullmatch(str(value["transaction_sha256"])) is None
        or value["transaction_sha256"] != digest(_transaction_body(value))
        or SHA256.fullmatch(str(value["state_sha256"])) is None
        or value["state_sha256"] != digest(_state_body(value))
    ):
        raise NativeInstallTransactionError("native_install_record_invalid")
    helper = value["recovery_helper"]
    if (
        not isinstance(helper, dict)
        or set(helper) != {"path", "sha256"}
        or not isinstance(helper["path"], str)
        or not Path(helper["path"]).is_absolute()
        or ".." in Path(helper["path"]).parts
        or SHA256.fullmatch(str(helper["sha256"])) is None
    ):
        raise NativeInstallTransactionError("native_install_record_invalid")
    canonical(value["metadata"])
    paths: set[str] = set()
    for item in value["destinations"]:
        expected = {
            "path",
            "state",
            "backup_name",
            "sha256",
            "size",
            "uid",
            "gid",
            "mode",
        }
        if not isinstance(item, dict) or set(item) != expected:
            raise NativeInstallTransactionError("native_install_record_invalid")
        path = item["path"]
        if (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or ".." in Path(path).parts
            or path in paths
            or item["state"] not in {"absent", "file"}
        ):
            raise NativeInstallTransactionError("native_install_record_invalid")
        paths.add(path)
        if item["state"] == "absent":
            if any(item[name] is not None for name in expected - {"path", "state"}):
                raise NativeInstallTransactionError("native_install_record_invalid")
        elif (
            not isinstance(item["backup_name"], str)
            or re.fullmatch(r"file-[0-9]{2}\.bin", item["backup_name"]) is None
            or SHA256.fullmatch(str(item["sha256"])) is None
            or not all(
                isinstance(item[name], int) and not isinstance(item[name], bool)
                for name in ("size", "uid", "gid", "mode")
            )
            or not 0 <= item["size"] <= MAX_FILE_BYTES
            or not 0 <= item["mode"] <= 0o7777
        ):
            raise NativeInstallTransactionError("native_install_record_invalid")
    return value


def read_record(
    path: Path, *, expected_uid: int, expected_gid: int
) -> dict[str, Any]:
    raw, _ = _read_regular(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=0o600,
        maximum=MAX_RECORD_BYTES,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeInstallTransactionError("native_install_record_invalid") from error
    if raw != canonical(value):
        raise NativeInstallTransactionError("native_install_record_not_canonical")
    return validate_record(value)


def verify_recovery_helper(
    record: Mapping[str, Any], *, expected_uid: int
) -> Path:
    helper = record["recovery_helper"]
    path = Path(helper["path"])
    raw, _ = _read_regular(path, expected_uid=expected_uid, maximum=MAX_FILE_BYTES)
    if hashlib.sha256(raw).hexdigest() != helper["sha256"]:
        raise NativeInstallTransactionError("native_install_recovery_helper_mismatch")
    return path


def decide(
    pending: Path,
    decision: str,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    now: int | None = None,
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise NativeInstallTransactionError("native_install_root_required")
    if decision not in {"commit", "recover"}:
        raise NativeInstallTransactionError("native_install_decision_invalid")
    record = read_record(
        pending, expected_uid=expected_uid, expected_gid=expected_gid
    )
    if record["decision"] not in {None, decision}:
        raise NativeInstallTransactionError("native_install_decision_conflict")
    if record["decision"] is None:
        updated = dict(record)
        updated["decision"] = decision
        observed_time = int(time.time()) if now is None else now
        updated["decided_at"] = max(record["created_at"], observed_time)
        updated["state_sha256"] = digest(_state_body(updated))
        record = validate_record(updated)
        _atomic_file(
            pending,
            canonical(record),
            uid=expected_uid,
            gid=expected_gid,
            mode=0o600,
        )
    return record


def begin(
    pending: Path,
    backup: Path,
    destinations: Iterable[Path],
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    now: int | None = None,
    metadata: Mapping[str, Any] | None = None,
    recovery_helper: Path | None = None,
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise NativeInstallTransactionError("native_install_root_required")
    if pending.exists() or pending.is_symlink():
        raise NativeInstallTransactionError("native_install_recovery_required")
    _trusted_directory(
        pending.parent,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        mode=0o700,
        create=True,
    )
    _enforce_retention_bound(pending, expected_uid=expected_uid)
    _trusted_directory(
        backup.parent,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        mode=0o700,
        create=True,
    )
    os.mkdir(backup, 0o700)
    _trusted_directory(
        backup,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        mode=0o700,
    )
    entries: list[dict[str, Any]] = []
    backup_bytes = 0
    try:
        for index, destination in enumerate(
            _validated_destinations(destinations, expected_uid=expected_uid)
        ):
            try:
                raw, file_metadata = _read_regular(destination)
            except NativeInstallTransactionError as error:
                try:
                    destination.lstat()
                except FileNotFoundError:
                    entries.append({
                        "path": str(destination),
                        "state": "absent",
                        "backup_name": None,
                        "sha256": None,
                        "size": None,
                        "uid": None,
                        "gid": None,
                        "mode": None,
                    })
                    continue
                raise NativeInstallTransactionError(
                    "native_install_file_untrusted"
                ) from error
            name = f"file-{index:02d}.bin"
            backup_bytes += len(raw)
            if backup_bytes > MAX_BACKUP_BYTES:
                raise NativeInstallTransactionError(
                    "native_install_backup_set_oversized"
                )
            _atomic_file(
                backup / name,
                raw,
                uid=expected_uid,
                gid=expected_gid,
                mode=0o600,
            )
            entries.append({
                "path": str(destination),
                "state": "file",
                "backup_name": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "uid": file_metadata.st_uid,
                "gid": file_metadata.st_gid,
                "mode": stat.S_IMODE(file_metadata.st_mode),
            })
        helper_path = Path(__file__).resolve() if recovery_helper is None else recovery_helper
        helper_raw, _ = _read_regular(
            helper_path,
            expected_uid=expected_uid,
            maximum=MAX_FILE_BYTES,
        )
        immutable = {
            "transaction_id": str(uuid.uuid4()),
            "created_at": int(time.time()) if now is None else now,
            "backup_directory": str(backup),
            "recovery_helper": {
                "path": str(helper_path),
                "sha256": hashlib.sha256(helper_raw).hexdigest(),
            },
            "destinations": entries,
            "metadata": dict(metadata or {}),
        }
        transaction_sha256 = digest(immutable)
        state = {
            "schema": SCHEMA,
            **immutable,
            "decision": None,
            "decided_at": None,
            "transaction_sha256": transaction_sha256,
        }
        record = validate_record({**state, "state_sha256": digest(state)})
        _atomic_file(
            pending,
            canonical(record),
            uid=expected_uid,
            gid=expected_gid,
            mode=0o600,
        )
        return record
    except Exception:
        if not pending.exists():
            for child in backup.iterdir():
                child.unlink()
            backup.rmdir()
            _fsync_directory(backup.parent)
        raise


def recover(
    pending: Path, *, expected_uid: int = 0, expected_gid: int = 0
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise NativeInstallTransactionError("native_install_root_required")
    initial = read_record(
        pending, expected_uid=expected_uid, expected_gid=expected_gid
    )
    if initial["decision"] not in {None, "recover"}:
        raise NativeInstallTransactionError("native_install_decision_conflict")
    verify_recovery_helper(initial, expected_uid=expected_uid)
    record = decide(
        pending,
        "recover",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    backup = Path(record["backup_directory"])
    _trusted_directory(
        backup,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        mode=0o700,
    )
    for item in reversed(record["destinations"]):
        destination = Path(item["path"])
        if item["state"] == "absent":
            parent_descriptor = _trusted_parent_fd(
                destination.parent, expected_uid=expected_uid
            )
            try:
                try:
                    info = os.stat(
                        destination.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or info.st_nlink != 1
                ):
                    raise NativeInstallTransactionError(
                        "native_install_recovery_target_untrusted"
                    )
                os.unlink(destination.name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            continue
        raw, _ = _read_regular(
            backup / item["backup_name"],
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_mode=0o600,
            maximum=MAX_FILE_BYTES,
        )
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise NativeInstallTransactionError("native_install_backup_mismatch")
        _atomic_file(
            destination,
            raw,
            uid=item["uid"],
            gid=item["gid"],
            mode=item["mode"],
        )
    return {
        "schema": RESULT_SCHEMA,
        "status": "restored",
        "transaction_id": record["transaction_id"],
        "transaction_sha256": record["transaction_sha256"],
    }


def _finalize(
    pending: Path,
    status_value: str,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, Any]:
    if status_value not in {"committed", "recovered"}:
        raise NativeInstallTransactionError("native_install_final_status_invalid")
    record = read_record(
        pending, expected_uid=expected_uid, expected_gid=expected_gid
    )
    expected_decision = "commit" if status_value == "committed" else "recover"
    if record["decision"] != expected_decision:
        raise NativeInstallTransactionError("native_install_final_decision_mismatch")
    completion_body = {
        "status": status_value,
        "completed_at": record["decided_at"],
        "transaction": record,
    }
    completion = {
        "schema": ARCHIVE_SCHEMA,
        **completion_body,
        "archive_sha256": digest(completion_body, maximum=MAX_ARCHIVE_BYTES),
    }
    result = {
        "schema": RESULT_SCHEMA,
        "status": status_value,
        "transaction_id": record["transaction_id"],
        "transaction_sha256": record["transaction_sha256"],
    }
    archive = pending.with_name(
        f"{pending.stem}.{record['transaction_id']}.{status_value}.json"
    )
    encoded = canonical(completion, maximum=MAX_ARCHIVE_BYTES)
    try:
        observed, _ = _read_regular(
            archive,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_mode=0o600,
            maximum=MAX_ARCHIVE_BYTES,
        )
    except NativeInstallTransactionError:
        try:
            archive.lstat()
        except FileNotFoundError:
            _atomic_file(
                archive,
                encoded,
                uid=expected_uid,
                gid=expected_gid,
                mode=0o600,
            )
        else:
            raise NativeInstallTransactionError(
                "native_install_archive_untrusted"
            )
    else:
        if observed != encoded:
            raise NativeInstallTransactionError(
                "native_install_archive_collision"
            )
    parent_descriptor = _trusted_parent_fd(
        pending.parent, expected_uid=expected_uid
    )
    try:
        descriptor = os.open(
            pending.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        try:
            current = os.fstat(descriptor)
            raw = bytearray()
            while len(raw) <= MAX_RECORD_BYTES:
                block = os.read(
                    descriptor, min(65536, MAX_RECORD_BYTES + 1 - len(raw))
                )
                if not block:
                    break
                raw.extend(block)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != expected_uid
            or current.st_gid != expected_gid
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
            or bytes(raw) != canonical(record)
        ):
            raise NativeInstallTransactionError("native_install_pending_untrusted")
        os.unlink(pending.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return result


def _verify_recovered_record(record: Mapping[str, Any]) -> None:
    for item in record["destinations"]:
        destination = Path(item["path"])
        if item["state"] == "absent":
            try:
                destination.lstat()
            except FileNotFoundError:
                continue
            raise NativeInstallTransactionError(
                "native_install_recovery_readback_failed"
            )
        try:
            raw, _ = _read_regular(
                destination,
                expected_uid=item["uid"],
                expected_gid=item["gid"],
                expected_mode=item["mode"],
                maximum=MAX_FILE_BYTES,
            )
        except NativeInstallTransactionError as error:
            raise NativeInstallTransactionError(
                "native_install_recovery_readback_failed"
            ) from error
        if (
            len(raw) != item["size"]
            or hashlib.sha256(raw).hexdigest() != item["sha256"]
        ):
            raise NativeInstallTransactionError(
                "native_install_recovery_readback_failed"
            )


def finalize_recovery(
    pending: Path, *, expected_uid: int = 0, expected_gid: int = 0
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise NativeInstallTransactionError("native_install_root_required")
    record = read_record(
        pending, expected_uid=expected_uid, expected_gid=expected_gid
    )
    if record["decision"] != "recover":
        raise NativeInstallTransactionError("native_install_final_decision_mismatch")
    _verify_recovered_record(record)
    return _finalize(
        pending,
        "recovered",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def commit(
    pending: Path, *, expected_uid: int = 0, expected_gid: int = 0
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise NativeInstallTransactionError("native_install_root_required")
    decide(
        pending,
        "commit",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    return _finalize(
        pending,
        "committed",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def _main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    begin_parser = subparsers.add_parser("begin")
    begin_parser.add_argument("--pending", type=Path, required=True)
    begin_parser.add_argument("--backup", type=Path, required=True)
    begin_parser.add_argument("--recovery-helper", type=Path)
    begin_parser.add_argument("--metadata-json", default="{}")
    begin_parser.add_argument("destination", type=Path, nargs="+")
    for name in ("recover", "finalize-recovery", "commit", "inspect"):
        child = subparsers.add_parser(name)
        child.add_argument("--pending", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        if args.command == "begin":
            metadata = json.loads(args.metadata_json)
            if not isinstance(metadata, dict):
                raise NativeInstallTransactionError(
                    "native_install_metadata_invalid"
                )
            result = begin(
                args.pending,
                args.backup,
                args.destination,
                metadata=metadata,
                recovery_helper=args.recovery_helper,
            )
        elif args.command == "recover":
            result = recover(args.pending)
        elif args.command == "finalize-recovery":
            result = finalize_recovery(args.pending)
        elif args.command == "inspect":
            record = read_record(args.pending, expected_uid=0, expected_gid=0)
            verify_recovery_helper(record, expected_uid=0)
            result = {
                "schema": RESULT_SCHEMA,
                "status": "pending",
                "decision": record["decision"],
                "transaction_id": record["transaction_id"],
                "transaction_sha256": record["transaction_sha256"],
                "recovery_helper": record["recovery_helper"],
                "metadata": record["metadata"],
            }
        else:
            result = commit(args.pending)
    except (NativeInstallTransactionError, OSError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(canonical(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
