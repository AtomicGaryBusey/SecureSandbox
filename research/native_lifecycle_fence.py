#!/usr/bin/env python3
"""Durable Research-side publication fence for native vendor processes.

The Host publication lock cannot be shared across the VM boundary.  Research
therefore owns a second, durable fence.  Promotion acquisition and every
native-process admission serialize on the same descriptor-held lock.  A
failed or ambiguous publication intentionally leaves admission closed until
the exact promotion triple is released after Host publication readback.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Iterator, Mapping


ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller/lifecycle")
INSTALL_PENDING = Path(
    "/var/lib/secure-sandbox/native-vendor/install/"
    "native-research-install.pending.json")
LOCK_NAME = "promotion.lock"
FENCE_NAME = "promotion-fence.json"
FENCE_SCHEMA = "secure-sandbox-native-stack-promotion-fence-v1"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_FENCE_BYTES = 4096


class NativeLifecycleFenceError(RuntimeError):
    """Stable fail-closed lifecycle-fence error."""


def _canonical(value: object) -> bytes:
    try:
        raw = (json.dumps(value, allow_nan=False, ensure_ascii=True,
                          separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeLifecycleFenceError("native_lifecycle_fence_value_invalid") from error
    if len(raw) > MAX_FENCE_BYTES:
        raise NativeLifecycleFenceError("native_lifecycle_fence_value_oversized")
    return raw


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_triple(*, promotion_id: str, plan_sha256: str,
                     catalog_sha256: str) -> dict[str, str]:
    if UUID4.fullmatch(promotion_id) is None:
        raise NativeLifecycleFenceError("native_lifecycle_promotion_id_invalid")
    if SHA256.fullmatch(plan_sha256) is None:
        raise NativeLifecycleFenceError("native_lifecycle_plan_digest_invalid")
    if SHA256.fullmatch(catalog_sha256) is None:
        raise NativeLifecycleFenceError("native_lifecycle_catalog_digest_invalid")
    return {"promotion_id": promotion_id, "plan_sha256": plan_sha256,
            "catalog_sha256": catalog_sha256}


@contextlib.contextmanager
def locked(*, root: Path = ROOT, trusted_uid: int = 0,
           trusted_gid: int = 0) -> Iterator[int]:
    """Hold the exact lock used by promotion and process admission."""
    root_fd = lock_fd = -1
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY
                          | os.O_NOFOLLOW | os.O_CLOEXEC)
        root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != trusted_uid
                or root_info.st_gid != trusted_gid
                or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise NativeLifecycleFenceError("native_lifecycle_root_untrusted")
        lock_fd = os.open(
            LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=root_fd)
        os.fchown(lock_fd, trusted_uid, trusted_gid)
        os.fchmod(lock_fd, 0o600)
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1
                or lock_info.st_uid != trusted_uid
                or lock_info.st_gid != trusted_gid
                or stat.S_IMODE(lock_info.st_mode) != 0o600):
            raise NativeLifecycleFenceError("native_lifecycle_lock_untrusted")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # Re-read the directory after blocking on the lock.  Replacement of
        # the opened directory itself is ambiguity, even though this fd is safe.
        current = root.lstat()
        if (current.st_dev, current.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise NativeLifecycleFenceError("native_lifecycle_root_changed")
        yield root_fd
    except FileNotFoundError as error:
        raise NativeLifecycleFenceError("native_lifecycle_root_missing") from error
    finally:
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _read_at(root_fd: int, *, trusted_uid: int, trusted_gid: int
             ) -> dict[str, str] | None:
    try:
        descriptor = os.open(
            FENCE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= MAX_FENCE_BYTES):
            raise NativeLifecycleFenceError("native_lifecycle_fence_untrusted")
        raw = os.read(descriptor, MAX_FENCE_BYTES + 1)
        if len(raw) != info.st_size:
            raise NativeLifecycleFenceError("native_lifecycle_fence_changed")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeLifecycleFenceError("native_lifecycle_fence_invalid") from error
    fields = {"schema", "promotion_id", "plan_sha256", "catalog_sha256",
              "fence_sha256"}
    if not isinstance(value, dict) or set(value) != fields or raw != _canonical(value):
        raise NativeLifecycleFenceError("native_lifecycle_fence_invalid")
    body = _validate_triple(
        promotion_id=value["promotion_id"], plan_sha256=value["plan_sha256"],
        catalog_sha256=value["catalog_sha256"])
    if (value["schema"] != FENCE_SCHEMA
            or value["fence_sha256"] != _digest(body)):
        raise NativeLifecycleFenceError("native_lifecycle_fence_invalid")
    return value


def _write_at(root_fd: int, body: Mapping[str, str], *,
              trusted_uid: int, trusted_gid: int) -> str:
    value = {"schema": FENCE_SCHEMA, **dict(body),
             "fence_sha256": _digest(dict(body))}
    payload = _canonical(value)
    temporary = f".{FENCE_NAME}.{os.getpid()}.{uuid.uuid4().hex}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
        os.fchown(descriptor, trusted_uid, trusted_gid)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise NativeLifecycleFenceError("native_lifecycle_fence_write_failed")
            view = view[count:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, FENCE_NAME, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
        return value["fence_sha256"]
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass


def acquire_locked(root_fd: int, *, promotion_id: str, plan_sha256: str,
                   catalog_sha256: str, trusted_uid: int = 0,
                   trusted_gid: int = 0) -> str:
    body = _validate_triple(
        promotion_id=promotion_id, plan_sha256=plan_sha256,
        catalog_sha256=catalog_sha256)
    existing = _read_at(root_fd, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if existing is not None:
        if any(existing[key] != value for key, value in body.items()):
            raise NativeLifecycleFenceError("native_lifecycle_fence_conflict")
        return existing["fence_sha256"]
    return _write_at(root_fd, body, trusted_uid=trusted_uid, trusted_gid=trusted_gid)


def release_locked(root_fd: int, *, promotion_id: str, plan_sha256: str,
                   catalog_sha256: str, trusted_uid: int = 0,
                   trusted_gid: int = 0) -> str:
    body = _validate_triple(
        promotion_id=promotion_id, plan_sha256=plan_sha256,
        catalog_sha256=catalog_sha256)
    existing = _read_at(root_fd, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if existing is None or any(existing[key] != value for key, value in body.items()):
        raise NativeLifecycleFenceError("native_lifecycle_release_mismatch")
    evidence = _digest({**body, "state": "released",
                        "fence_sha256": existing["fence_sha256"]})
    os.unlink(FENCE_NAME, dir_fd=root_fd)
    os.fsync(root_fd)
    return evidence


@contextlib.contextmanager
def admission_open(*, root: Path = ROOT,
                   install_pending: Path = INSTALL_PENDING,
                   trusted_uid: int = 0,
                   trusted_gid: int = 0) -> Iterator[None]:
    """Hold publication exclusion for one complete native process lifetime."""
    with locked(root=root, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid) as root_fd:
        try:
            install_pending.lstat()
        except FileNotFoundError:
            pass
        else:
            # Any object at the durable transaction pathname closes
            # admission. Recovery owns interpreting its exact contents.
            raise NativeLifecycleFenceError(
                "native_lifecycle_install_recovery_required")
        if _read_at(root_fd, trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid) is not None:
            raise NativeLifecycleFenceError("native_lifecycle_admission_fenced")
        yield
