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
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA = "secure-sandbox-native-install-transaction-v1"
RESULT_SCHEMA = "secure-sandbox-native-install-transaction-result-v1"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")


class NativeInstallTransactionError(RuntimeError):
    """Stable fail-closed transaction error."""


def canonical(value: object) -> bytes:
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
    if len(raw) > MAX_RECORD_BYTES:
        raise NativeInstallTransactionError("native_install_record_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != expected_uid
            or parent.st_mode & 0o022
        ):
            raise NativeInstallTransactionError("native_install_parent_untrusted")
        os.mkdir(path, mode)
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
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), uid, gid)
            os.fchmod(handle.fileno(), mode)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(parent)
        observed, metadata = _read_regular(
            path,
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=mode,
            maximum=max(MAX_RECORD_BYTES, len(raw)),
        )
        if observed != raw or metadata.st_size != len(raw):
            raise NativeInstallTransactionError("native_install_publication_readback_failed")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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


def _record_body(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in record if key not in {"schema", "transaction_sha256"}}


def validate_record(value: object) -> dict[str, Any]:
    fields = {
        "schema",
        "transaction_id",
        "created_at",
        "backup_directory",
        "destinations",
        "transaction_sha256",
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
        or SHA256.fullmatch(str(value["transaction_sha256"])) is None
        or value["transaction_sha256"] != digest(_record_body(value))
    ):
        raise NativeInstallTransactionError("native_install_record_invalid")
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


def begin(
    pending: Path,
    backup: Path,
    destinations: Iterable[Path],
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    now: int | None = None,
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
    try:
        for index, destination in enumerate(
            _validated_destinations(destinations, expected_uid=expected_uid)
        ):
            try:
                raw, metadata = _read_regular(destination)
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
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
            })
        body = {
            "transaction_id": str(uuid.uuid4()),
            "created_at": int(time.time()) if now is None else now,
            "backup_directory": str(backup),
            "destinations": entries,
        }
        record = validate_record(
            {"schema": SCHEMA, **body, "transaction_sha256": digest(body)}
        )
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
    record = read_record(
        pending, expected_uid=expected_uid, expected_gid=expected_gid
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
            try:
                info = destination.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise NativeInstallTransactionError("native_install_recovery_target_untrusted")
            destination.unlink()
            _fsync_directory(destination.parent)
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
    completion = {
        "schema": RESULT_SCHEMA,
        "status": status_value,
        "transaction_id": record["transaction_id"],
        "transaction_sha256": record["transaction_sha256"],
    }
    archive = pending.with_name(
        f"{pending.stem}.{record['transaction_id']}.{status_value}.json"
    )
    _atomic_file(
        archive,
        canonical(completion),
        uid=expected_uid,
        gid=expected_gid,
        mode=0o600,
    )
    pending.unlink()
    _fsync_directory(pending.parent)
    return completion


def finalize_recovery(
    pending: Path, *, expected_uid: int = 0, expected_gid: int = 0
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise NativeInstallTransactionError("native_install_root_required")
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
    begin_parser.add_argument("destination", type=Path, nargs="+")
    for name in ("recover", "finalize-recovery", "commit"):
        child = subparsers.add_parser(name)
        child.add_argument("--pending", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        if args.command == "begin":
            result = begin(args.pending, args.backup, args.destination)
        elif args.command == "recover":
            result = recover(args.pending)
        elif args.command == "finalize-recovery":
            result = finalize_recovery(args.pending)
        else:
            result = commit(args.pending)
    except (NativeInstallTransactionError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(canonical(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
