#!/usr/bin/env python3
"""Crash-safe whole-generation publication for native Host build products.

The release builder constructs and verifies a complete generation outside the
public ``artifacts/host`` pathname.  This helper copies that generation into a
private same-filesystem stage and uses macOS ``renameatx_np(RENAME_SWAP)`` to
replace an existing generation as one namespace operation.  A durable journal
allows the next invocation to finish a committed swap or restore the exact
predecessor; it never repairs or path-deletes individual files.  Terminal
generations and journals are retained under versioned names so every recovery
step is idempotent after power loss.  An authority-bound persistent lock is
held across every complete reconcile or publish transaction.

macOS has no conditional rename-by-open-descriptor primitive.  Therefore a
same-UID process is not treated as a filesystem security boundary: operands
are inode-bound before and after each rename, a mismatched syscall result is
compensated before failure is reported, and the independently signed carrier
and provenance-bound admission check—not mere presence at the public path—is
the release authority.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Callable


JOURNAL_SCHEMA = "secure-sandbox-native-host-generation-publication-v2"
AUTHORITY_SCHEMA = "secure-sandbox-native-host-publication-authority-v3"
LOCK_SCHEMA = "secure-sandbox-native-host-publication-lock-v1"
REJECTED_RECORD_SCHEMA = (
    "secure-sandbox-native-host-rejected-generation-v1"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PUBLICATION_ID = re.compile(r"^[0-9a-f]{32}$")
JOURNAL_NAME = "pending.json"
AUTHORITY_NAME = ".authority.json"
LOCK_NAME = ".publication.lock"
RENAME_SWAP = 0x00000002
RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
RENAME_RESOLVE_BENEATH = 0x00000020
MAX_TREE_BYTES = 1024 * 1024 * 1024
MAX_TREE_ENTRIES = 4096
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0


_LIBC = ctypes.CDLL(None, use_errno=True)
_ACL_GET_FD_NP = getattr(_LIBC, "acl_get_fd_np", None)
_ACL_GET_ENTRY = getattr(_LIBC, "acl_get_entry", None)
_ACL_FREE = getattr(_LIBC, "acl_free", None)
if _ACL_GET_FD_NP is not None:
    _ACL_GET_FD_NP.argtypes = [ctypes.c_int, ctypes.c_int]
    _ACL_GET_FD_NP.restype = ctypes.c_void_p
if _ACL_GET_ENTRY is not None:
    _ACL_GET_ENTRY.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
    ]
    _ACL_GET_ENTRY.restype = ctypes.c_int
if _ACL_FREE is not None:
    _ACL_FREE.argtypes = [ctypes.c_void_p]
    _ACL_FREE.restype = ctypes.c_int


class PublicationError(RuntimeError):
    """The generation cannot be published or reconciled safely."""


class PublicationRolledBack(PublicationError):
    """A damaged post-swap candidate was restored to its predecessor."""


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value, allow_nan=False, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _reject_extended_acl(descriptor: int, failure: str) -> None:
    """Reject every extended ACL; mode bits are the complete authority."""
    if (_ACL_GET_FD_NP is None or _ACL_GET_ENTRY is None
            or _ACL_FREE is None):
        raise PublicationError("publication_acl_api_unavailable")
    ctypes.set_errno(0)
    acl = _ACL_GET_FD_NP(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise PublicationError(failure)
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = _ACL_GET_ENTRY(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0:
            raise PublicationError(failure)
        if ctypes.get_errno() not in {errno.ENOENT, errno.EINVAL}:
            raise PublicationError(failure)
    finally:
        if _ACL_FREE(acl) != 0:
            raise PublicationError("publication_acl_release_failed")


def _open_trusted_directory(
    path: Path, *, private: bool,
) -> tuple[int, os.stat_result]:
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise PublicationError(f"publication_directory_missing:{path}") from error
    maximum_mode = 0o700 if private else 0o755
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(named.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & ~maximum_mode
    ):
        os.close(descriptor)
        raise PublicationError(f"publication_directory_untrusted:{path}")
    try:
        _reject_extended_acl(descriptor, f"publication_directory_acl:{path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _fsync_directory(path: Path) -> None:
    descriptor, _info = _open_trusted_directory(path, private=False)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _trusted_directory(path: Path, *, private: bool) -> os.stat_result:
    descriptor, info = _open_trusted_directory(path, private=private)
    os.close(descriptor)
    return info


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        info = os.fstat(descriptor)
        current = path.lstat()
    except OSError as error:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        raise PublicationError(f"publication_file_unreadable:{path}") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise PublicationError(f"publication_file_untrusted:{path}")
    try:
        _reject_extended_acl(descriptor, f"publication_file_acl:{path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, info


def _open_directory_entry(
    parent: int, name: str, *, expected_device: int, relative: str,
) -> tuple[int, os.stat_result]:
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise PublicationError(
            f"publication_tree_entry_unreadable:{relative}"
        ) from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_dev != expected_device
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise PublicationError(f"publication_tree_entry_untrusted:{relative}")
    try:
        _reject_extended_acl(
            descriptor, f"publication_tree_entry_acl:{relative}",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _open_regular_entry(
    parent: int, name: str, *, expected_device: int, relative: str,
) -> tuple[int, os.stat_result]:
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise PublicationError(
            f"publication_tree_entry_unreadable:{relative}"
        ) from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_dev != expected_device
        or opened.st_uid != os.geteuid() or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise PublicationError(f"publication_tree_entry_untrusted:{relative}")
    try:
        _reject_extended_acl(
            descriptor, f"publication_tree_entry_acl:{relative}",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _tree_record_from_descriptor(
    root_descriptor: int, root_info: os.stat_result,
) -> dict[str, object]:
    entries: dict[str, dict[str, object]] = {}
    total = 0

    def inspect(directory: int, prefix: tuple[str, ...]) -> None:
        nonlocal total
        before = os.fstat(directory)
        try:
            names = sorted(item.name for item in os.scandir(directory))
        except OSError as error:
            raise PublicationError("publication_tree_inventory_failed") from error
        for name in names:
            if (not name or name in {".", ".."} or "/" in name
                    or "\x00" in name):
                raise PublicationError("publication_tree_path_invalid")
            parts = (*prefix, name)
            relative = "/".join(parts)
            if len(relative) > 1024 or len(entries) >= MAX_TREE_ENTRIES:
                raise PublicationError("publication_tree_path_invalid")
            try:
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except OSError as error:
                raise PublicationError(
                    f"publication_tree_entry_unreadable:{relative}"
                ) from error
            mode = stat.S_IMODE(named.st_mode)
            if stat.S_ISLNK(named.st_mode):
                raise PublicationError(f"publication_tree_symlink:{relative}")
            if stat.S_ISDIR(named.st_mode):
                child, opened = _open_directory_entry(
                    directory, name, expected_device=root_info.st_dev,
                    relative=relative,
                )
                try:
                    entries[relative] = {"kind": "directory", "mode": mode}
                    inspect(child, parts)
                    after = os.fstat(child)
                    current = os.stat(
                        name, dir_fd=directory, follow_symlinks=False,
                    )
                    if (_identity(opened) != _identity(after)
                            or _identity(after) != _identity(current)):
                        raise PublicationError(
                            f"publication_tree_entry_changed:{relative}"
                        )
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(named.st_mode):
                raise PublicationError(
                    f"publication_tree_entry_invalid:{relative}"
                )
            descriptor, opened = _open_regular_entry(
                directory, name, expected_device=root_info.st_dev,
                relative=relative,
            )
            digest = hashlib.sha256()
            size = 0
            try:
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
                    if total + size > MAX_TREE_BYTES:
                        raise PublicationError("publication_tree_too_large")
                after = os.fstat(descriptor)
                current = os.stat(
                    name, dir_fd=directory, follow_symlinks=False,
                )
            finally:
                os.close(descriptor)
            if (_identity(opened) != _identity(after)
                    or _identity(after) != _identity(current)
                    or size != opened.st_size):
                raise PublicationError(
                    f"publication_tree_entry_changed:{relative}"
                )
            total += size
            entries[relative] = {
                "kind": "file", "mode": mode,
                "sha256": digest.hexdigest(), "size": size,
            }
        after_directory = os.fstat(directory)
        if _identity(before) != _identity(after_directory):
            raise PublicationError("publication_tree_changed_during_readback")

    inspect(root_descriptor, ())
    return {
        "entries": entries,
        "root_mode": stat.S_IMODE(root_info.st_mode),
        "schema": "secure-sandbox-native-host-generation-tree-v1",
    }


def tree_record(root: Path) -> dict[str, object]:
    """Return a closed content-and-mode record for one complete generation."""
    root = Path(root)
    descriptor, root_info = _open_trusted_directory(root, private=False)
    try:
        record = _tree_record_from_descriptor(descriptor, root_info)
        after = os.fstat(descriptor)
        named = root.lstat()
        if (_identity(root_info) != _identity(after)
                or _identity(after) != _identity(named)):
            raise PublicationError("publication_tree_changed_during_readback")
        return record
    finally:
        os.close(descriptor)


def tree_digest(root: Path) -> str:
    first = tree_record(root)
    second = tree_record(root)
    if first != second:
        raise PublicationError("publication_tree_changed_during_readback")
    return hashlib.sha256(_canonical(first)).hexdigest()


def _copy_generation(
    candidate: Path, state_root: Path, stage_name: str,
) -> Path:
    """Copy one closed generation through held source/destination dirfds."""
    if re.fullmatch(r"stage\.[0-9a-f]{32}", stage_name) is None:
        raise PublicationError("publication_stage_name_invalid")
    source, source_info = _open_trusted_directory(candidate, private=False)
    state, state_info = _open_state_root(state_root)
    if source_info.st_dev != state_info.st_dev:
        os.close(source)
        os.close(state)
        raise PublicationError("publication_cross_device_forbidden")
    try:
        try:
            os.mkdir(stage_name, 0o700, dir_fd=state)
        except FileExistsError as error:
            raise PublicationError("publication_stage_already_exists") from error
        stage, _stage_info = _open_directory_entry(
            state, stage_name, expected_device=state_info.st_dev,
            relative=stage_name,
        )
        try:
            copied_bytes = 0
            copied_entries = 0

            def copy_directory(
                source_directory: int, destination_directory: int,
                prefix: tuple[str, ...],
            ) -> None:
                nonlocal copied_bytes, copied_entries
                source_before = os.fstat(source_directory)
                names = sorted(item.name for item in os.scandir(source_directory))
                for name in names:
                    parts = (*prefix, name)
                    relative = "/".join(parts)
                    copied_entries += 1
                    if (copied_entries > MAX_TREE_ENTRIES
                            or len(relative) > 1024):
                        raise PublicationError("publication_tree_path_invalid")
                    named = os.stat(
                        name, dir_fd=source_directory, follow_symlinks=False,
                    )
                    mode = stat.S_IMODE(named.st_mode)
                    if stat.S_ISDIR(named.st_mode):
                        source_child, source_child_info = _open_directory_entry(
                            source_directory, name,
                            expected_device=source_info.st_dev,
                            relative=relative,
                        )
                        try:
                            os.mkdir(name, 0o700, dir_fd=destination_directory)
                            destination_child, _destination_info = (
                                _open_directory_entry(
                                    destination_directory, name,
                                    expected_device=state_info.st_dev,
                                    relative=relative,
                                )
                            )
                            try:
                                copy_directory(
                                    source_child, destination_child, parts,
                                )
                                os.fchmod(destination_child, mode)
                                os.fsync(destination_child)
                            finally:
                                os.close(destination_child)
                            source_after = os.fstat(source_child)
                            source_named = os.stat(
                                name, dir_fd=source_directory,
                                follow_symlinks=False,
                            )
                            if (_identity(source_child_info)
                                    != _identity(source_after)
                                    or _identity(source_after)
                                    != _identity(source_named)):
                                raise PublicationError(
                                    f"publication_tree_entry_changed:{relative}"
                                )
                        finally:
                            os.close(source_child)
                        continue
                    if not stat.S_ISREG(named.st_mode):
                        if stat.S_ISLNK(named.st_mode):
                            raise PublicationError(
                                f"publication_tree_symlink:{relative}"
                            )
                        raise PublicationError(
                            f"publication_tree_entry_invalid:{relative}"
                        )
                    source_file, source_file_info = _open_regular_entry(
                        source_directory, name,
                        expected_device=source_info.st_dev,
                        relative=relative,
                    )
                    destination_file = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=destination_directory,
                    )
                    try:
                        while True:
                            block = os.read(source_file, 1024 * 1024)
                            if not block:
                                break
                            copied_bytes += len(block)
                            if copied_bytes > MAX_TREE_BYTES:
                                raise PublicationError(
                                    "publication_tree_too_large"
                                )
                            view = memoryview(block)
                            while view:
                                written = os.write(destination_file, view)
                                if written <= 0:
                                    raise PublicationError(
                                        "publication_stage_copy_failed"
                                    )
                                view = view[written:]
                        os.fchmod(destination_file, mode)
                        os.fsync(destination_file)
                        source_after = os.fstat(source_file)
                    finally:
                        os.close(destination_file)
                        os.close(source_file)
                    source_named = os.stat(
                        name, dir_fd=source_directory, follow_symlinks=False,
                    )
                    if (_identity(source_file_info) != _identity(source_after)
                            or _identity(source_after)
                            != _identity(source_named)):
                        raise PublicationError(
                            f"publication_tree_entry_changed:{relative}"
                        )
                source_after = os.fstat(source_directory)
                if _identity(source_before) != _identity(source_after):
                    raise PublicationError(
                        "publication_tree_changed_during_copy"
                    )

            copy_directory(source, stage, ())
            os.fchmod(stage, stat.S_IMODE(source_info.st_mode))
            os.fsync(stage)
        finally:
            os.close(stage)
        os.fsync(state)
    finally:
        os.close(source)
        os.close(state)
    return state_root / stage_name


def _durably_sync_tree(root: Path) -> None:
    """Fsync every file and directory bottom-up before journal authority."""
    descriptor, root_info = _open_trusted_directory(root, private=False)

    def sync_directory(directory: int, prefix: tuple[str, ...]) -> None:
        before = os.fstat(directory)
        for name in sorted(item.name for item in os.scandir(directory)):
            relative = "/".join((*prefix, name))
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(named.st_mode):
                child, child_info = _open_directory_entry(
                    directory, name, expected_device=root_info.st_dev,
                    relative=relative,
                )
                try:
                    sync_directory(child, (*prefix, name))
                    os.fsync(child)
                    after = os.fstat(child)
                finally:
                    os.close(child)
                current = os.stat(
                    name, dir_fd=directory, follow_symlinks=False,
                )
                if (_identity(child_info) != _identity(after)
                        or _identity(after) != _identity(current)):
                    raise PublicationError(
                        f"publication_tree_entry_changed:{relative}"
                    )
            elif stat.S_ISREG(named.st_mode):
                child, child_info = _open_regular_entry(
                    directory, name, expected_device=root_info.st_dev,
                    relative=relative,
                )
                try:
                    os.fsync(child)
                    after = os.fstat(child)
                finally:
                    os.close(child)
                current = os.stat(
                    name, dir_fd=directory, follow_symlinks=False,
                )
                if (_identity(child_info) != _identity(after)
                        or _identity(after) != _identity(current)):
                    raise PublicationError(
                        f"publication_tree_entry_changed:{relative}"
                    )
            elif stat.S_ISLNK(named.st_mode):
                raise PublicationError(f"publication_tree_symlink:{relative}")
            else:
                raise PublicationError(
                    f"publication_tree_entry_invalid:{relative}"
                )
        os.fsync(directory)
        if _identity(before) != _identity(os.fstat(directory)):
            raise PublicationError("publication_tree_changed_during_fsync")

    try:
        sync_directory(descriptor, ())
        after = os.fstat(descriptor)
        named = root.lstat()
        if (_identity(root_info) != _identity(after)
                or _identity(after) != _identity(named)):
            raise PublicationError("publication_tree_changed_during_fsync")
    finally:
        os.close(descriptor)


def _inode_record(info: os.stat_result) -> dict[str, int]:
    return {"device": int(info.st_dev), "inode": int(info.st_ino)}


def _valid_inode_record(value: object) -> bool:
    return (
        isinstance(value, dict) and set(value) == {"device", "inode"}
        and all(isinstance(value[key], int) and value[key] > 0
                for key in ("device", "inode"))
    )


def _matches_inode(info: os.stat_result, expected: dict[str, int]) -> bool:
    return (info.st_dev, info.st_ino) == (
        expected["device"], expected["inode"],
    )


def _authority_value(
    info: os.stat_result, lock_info: os.stat_result, lock_sha256: str,
) -> dict[str, object]:
    return {
        "device": int(info.st_dev), "gid": int(info.st_gid),
        "inode": int(info.st_ino),
        "lock_identity": _inode_record(lock_info),
        "lock_sha256": lock_sha256,
        "schema": AUTHORITY_SCHEMA,
        "uid": int(info.st_uid),
    }


def _lock_value(info: os.stat_result) -> dict[str, object]:
    return {
        "device": int(info.st_dev), "gid": int(info.st_gid),
        "inode": int(info.st_ino), "schema": LOCK_SCHEMA,
        "uid": int(info.st_uid),
    }


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise PublicationError("publication_record_write_failed")
        view = view[written:]


def _create_authority(
    state: int, state_info: os.stat_result, *,
    checkpoint: Callable[[str], None] | None = None,
) -> None:
    checkpoint = checkpoint or (lambda _name: None)
    lock_raw = _canonical(_lock_value(state_info))
    lock_descriptor = os.open(
        LOCK_NAME,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=state,
    )
    try:
        checkpoint("bootstrap-lock-created")
        os.fchmod(lock_descriptor, 0o600)
        _write_all(lock_descriptor, lock_raw)
        os.fsync(lock_descriptor)
        lock_info = os.fstat(lock_descriptor)
    finally:
        os.close(lock_descriptor)
    os.fsync(state)
    checkpoint("bootstrap-lock-durable")
    lock_sha256 = hashlib.sha256(lock_raw).hexdigest()
    raw = _canonical(_authority_value(
        state_info, lock_info, lock_sha256,
    ))
    authority_descriptor = os.open(
        AUTHORITY_NAME,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=state,
    )
    try:
        checkpoint("bootstrap-authority-created")
        os.fchmod(authority_descriptor, 0o600)
        _write_all(authority_descriptor, raw)
        os.fsync(authority_descriptor)
    finally:
        os.close(authority_descriptor)
    os.fsync(state)
    checkpoint("bootstrap-authority-durable")


def _open_lock_record(
    state: int, state_info: os.stat_result,
) -> tuple[int, os.stat_result, bytes]:
    descriptor, info = _open_regular_entry(
        state, LOCK_NAME, expected_device=state_info.st_dev,
        relative=LOCK_NAME,
    )
    try:
        if (stat.S_IMODE(info.st_mode) != 0o600
                or not 2 <= info.st_size <= 512):
            raise PublicationError("publication_state_lock_untrusted")
        raw = os.read(descriptor, 513)
        if len(raw) > 512 or os.read(descriptor, 1):
            raise PublicationError("publication_state_lock_invalid")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PublicationError("publication_state_lock_invalid") from error
        if (raw != _canonical(value) or not isinstance(value, dict)
                or value != _lock_value(state_info)):
            raise PublicationError("publication_state_lock_mismatch")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, info, raw
    except BaseException:
        os.close(descriptor)
        raise


def _open_state_root_with_lock(
    path: Path,
) -> tuple[int, os.stat_result, int, os.stat_result]:
    state, state_info = _open_trusted_directory(path, private=True)
    authority = lock_descriptor = -1
    try:
        lock_descriptor, lock_info, lock_raw = _open_lock_record(
            state, state_info,
        )
        authority, authority_info = _open_regular_entry(
            state, AUTHORITY_NAME, expected_device=state_info.st_dev,
            relative=AUTHORITY_NAME,
        )
        if (stat.S_IMODE(authority_info.st_mode) != 0o600
                or not 2 <= authority_info.st_size <= 512):
            raise PublicationError("publication_state_authority_untrusted")
        raw = os.read(authority, 513)
        if len(raw) > 512 or os.read(authority, 1):
            raise PublicationError("publication_state_authority_invalid")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PublicationError(
                "publication_state_authority_invalid"
            ) from error
        if (raw != _canonical(value) or not isinstance(value, dict)
                or value != _authority_value(
                    state_info, lock_info,
                    hashlib.sha256(lock_raw).hexdigest(),
                )):
            raise PublicationError("publication_state_authority_mismatch")
        result = state, state_info, lock_descriptor, lock_info
        lock_descriptor = -1
        return result
    except BaseException:
        os.close(state)
        raise
    finally:
        if authority >= 0:
            os.close(authority)
        if lock_descriptor >= 0:
            os.close(lock_descriptor)


def _open_state_root(path: Path) -> tuple[int, os.stat_result]:
    state, state_info, lock_descriptor, _lock_info = (
        _open_state_root_with_lock(path)
    )
    os.close(lock_descriptor)
    return state, state_info


@contextmanager
def _publication_lock(state_root: Path):
    """Hold the anchored publication lock for one complete transaction."""
    state, state_info, lock_descriptor, lock_info = (
        _open_state_root_with_lock(state_root)
    )
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        named_state = state_root.lstat()
        named_lock = os.stat(
            LOCK_NAME, dir_fd=state, follow_symlinks=False,
        )
        if ((_identity(state_info)[:2] != _identity(named_state)[:2])
                or not _matches_inode(named_lock, _inode_record(lock_info))
                or not _matches_inode(
                    os.fstat(lock_descriptor), _inode_record(lock_info),
                )):
            raise PublicationError("publication_state_lock_changed")
        yield
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)
        os.close(state)


def _generation_observation(path: Path) -> dict[str, object] | None:
    try:
        descriptor, info = _open_trusted_directory(path, private=False)
    except PublicationError:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        raise
    try:
        first = _tree_record_from_descriptor(descriptor, info)
        second = _tree_record_from_descriptor(descriptor, info)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (first != second or _identity(info) != _identity(after)
                or _identity(after) != _identity(named)):
            raise PublicationError("publication_tree_changed_during_readback")
        return {
            "tree_sha256": hashlib.sha256(_canonical(first)).hexdigest(),
            "identity": _inode_record(info),
        }
    finally:
        os.close(descriptor)


def _renameatx(
    source_parent: int, source_name: str,
    destination_parent: int, destination_name: str, flags: int,
) -> None:
    function = getattr(_LIBC, "renameatx_np", None)
    if function is None:
        raise PublicationError("publication_atomic_rename_unavailable")
    function.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(
        source_parent, os.fsencode(source_name),
        destination_parent, os.fsencode(destination_name), flags,
    )
    if result != 0:
        failure = ctypes.get_errno()
        raise PublicationError(
            "publication_atomic_rename_failed:" + os.strerror(failure)
        )


def _quarantine_public_entry(
    public_parent: int, public_name: str,
    state_parent: int, observed: os.stat_result,
) -> str:
    """Move a mismatched public directory into fresh retained evidence."""
    quarantine_name = f"quarantine.{secrets.token_hex(16)}"
    _renameatx(
        public_parent, public_name, state_parent, quarantine_name,
        RENAME_EXCL | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH,
    )
    try:
        os.stat(public_name, dir_fd=public_parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise PublicationError("publication_public_quarantine_failed")
    quarantined = os.stat(
        quarantine_name, dir_fd=state_parent, follow_symlinks=False,
    )
    if (quarantined.st_dev, quarantined.st_ino) != (
        observed.st_dev, observed.st_ino,
    ):
        raise PublicationError("publication_public_quarantine_failed")
    os.fsync(public_parent)
    os.fsync(state_parent)
    return quarantine_name


def _parent_descriptor(
    path: Path, state_root: Path,
) -> tuple[int, os.stat_result]:
    if path == state_root:
        return _open_state_root(state_root)
    return _open_trusted_directory(path, private=False)


def _rename_generation_bound(
    source: Path, destination: Path, state_root: Path,
    expected_source: dict[str, int], *,
    checkpoint: Callable[[str], None] | None = None,
    event: str = "rename-operands-opened",
) -> None:
    checkpoint = checkpoint or (lambda _name: None)
    source_parent, source_parent_info = _parent_descriptor(
        source.parent, state_root,
    )
    destination_parent, destination_parent_info = _parent_descriptor(
        destination.parent, state_root,
    )
    source_descriptor = -1
    try:
        if source_parent_info.st_dev != destination_parent_info.st_dev:
            raise PublicationError("publication_cross_device_forbidden")
        source_descriptor, source_info = _open_directory_entry(
            source_parent, source.name,
            expected_device=source_parent_info.st_dev,
            relative=source.name,
        )
        if not _matches_inode(source_info, expected_source):
            raise PublicationError("publication_rename_source_changed")
        try:
            os.stat(
                destination.name, dir_fd=destination_parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise PublicationError("publication_rename_destination_exists")
        checkpoint(event)
        named = os.stat(
            source.name, dir_fd=source_parent, follow_symlinks=False,
        )
        if not _matches_inode(named, expected_source):
            raise PublicationError("publication_rename_source_changed")
        _renameatx(
            source_parent, source.name,
            destination_parent, destination.name,
            RENAME_EXCL | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH,
        )
        published = os.stat(
            destination.name, dir_fd=destination_parent,
            follow_symlinks=False,
        )
        if not _matches_inode(published, expected_source):
            # ``renameatx_np`` is pathname-based; macOS has no conditional
            # rename-by-open-descriptor primitive.  If a non-cooperating
            # same-UID process wins the final lookup race, quarantine a public
            # mismatch before reporting failure.  The independently signed
            # carrier is still the authority; this public materialization
            # never becomes an accepted source merely because the rename
            # occurred.
            if destination.parent != state_root:
                _quarantine_public_entry(
                    destination_parent, destination.name,
                    source_parent, published,
                )
            else:
                try:
                    os.stat(
                        source.name, dir_fd=source_parent,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    _renameatx(
                        destination_parent, destination.name,
                        source_parent, source.name,
                        RENAME_EXCL | RENAME_NOFOLLOW_ANY
                        | RENAME_RESOLVE_BENEATH,
                    )
                    restored = os.stat(
                        source.name, dir_fd=source_parent,
                        follow_symlinks=False,
                    )
                    if (restored.st_dev, restored.st_ino) != (
                        published.st_dev, published.st_ino,
                    ):
                        raise PublicationError(
                            "publication_rename_compensation_failed"
                        )
                    os.fsync(source_parent)
                    os.fsync(destination_parent)
            raise PublicationError("publication_rename_identity_mismatch")
        os.fsync(source_parent)
        os.fsync(destination_parent)
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        os.close(source_parent)
        os.close(destination_parent)


def _atomic_swap_bound(
    left: Path, right: Path, state_root: Path,
    expected_left: dict[str, int], expected_right: dict[str, int], *,
    checkpoint: Callable[[str], None] | None = None,
) -> None:
    checkpoint = checkpoint or (lambda _name: None)
    left_parent, left_parent_info = _parent_descriptor(
        left.parent, state_root,
    )
    right_parent, right_parent_info = _parent_descriptor(
        right.parent, state_root,
    )
    left_descriptor = right_descriptor = -1
    try:
        if left_parent_info.st_dev != right_parent_info.st_dev:
            raise PublicationError("publication_cross_device_forbidden")
        left_descriptor, left_info = _open_directory_entry(
            left_parent, left.name, expected_device=left_parent_info.st_dev,
            relative=left.name,
        )
        right_descriptor, right_info = _open_directory_entry(
            right_parent, right.name, expected_device=right_parent_info.st_dev,
            relative=right.name,
        )
        if (not _matches_inode(left_info, expected_left)
                or not _matches_inode(right_info, expected_right)):
            raise PublicationError("publication_swap_operand_changed")
        checkpoint("swap-operands-opened")
        named_left = os.stat(
            left.name, dir_fd=left_parent, follow_symlinks=False,
        )
        named_right = os.stat(
            right.name, dir_fd=right_parent, follow_symlinks=False,
        )
        if (not _matches_inode(named_left, expected_left)
                or not _matches_inode(named_right, expected_right)):
            raise PublicationError("publication_swap_operand_changed")
        _renameatx(
            left_parent, left.name, right_parent, right.name,
            RENAME_SWAP | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH,
        )
        swapped_left = os.stat(
            left.name, dir_fd=left_parent, follow_symlinks=False,
        )
        swapped_right = os.stat(
            right.name, dir_fd=right_parent, follow_symlinks=False,
        )
        if (not _matches_inode(swapped_left, expected_right)
                or not _matches_inode(swapped_right, expected_left)):
            restored = False
            if (_matches_inode(swapped_left, expected_right)
                    and not _matches_inode(swapped_right, expected_right)):
                try:
                    _renameatx(
                        left_parent, left.name, right_parent, right.name,
                        RENAME_SWAP | RENAME_NOFOLLOW_ANY
                        | RENAME_RESOLVE_BENEATH,
                    )
                    restored_right = os.stat(
                        right.name, dir_fd=right_parent,
                        follow_symlinks=False,
                    )
                    restored = _matches_inode(
                        restored_right, expected_right,
                    )
                except (OSError, PublicationError):
                    restored = False
            if not restored:
                mismatched_public = os.stat(
                    right.name, dir_fd=right_parent,
                    follow_symlinks=False,
                )
                _quarantine_public_entry(
                    right_parent, right.name, left_parent,
                    mismatched_public,
                )
            os.fsync(left_parent)
            os.fsync(right_parent)
            raise PublicationError("publication_swap_identity_mismatch")
        os.fsync(left_parent)
        os.fsync(right_parent)
    finally:
        if left_descriptor >= 0:
            os.close(left_descriptor)
        if right_descriptor >= 0:
            os.close(right_descriptor)
        os.close(left_parent)
        os.close(right_parent)


def _rename_regular_bound(
    state_root: Path, source_name: str, destination_name: str,
    expected_source: dict[str, int],
) -> None:
    state, state_info = _open_state_root(state_root)
    descriptor = -1
    try:
        descriptor, info = _open_regular_entry(
            state, source_name, expected_device=state_info.st_dev,
            relative=source_name,
        )
        if not _matches_inode(info, expected_source):
            raise PublicationError("publication_record_changed")
        try:
            os.stat(destination_name, dir_fd=state, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PublicationError("publication_record_collision")
        named = os.stat(source_name, dir_fd=state, follow_symlinks=False)
        if not _matches_inode(named, expected_source):
            raise PublicationError("publication_record_changed")
        _renameatx(
            state, source_name, state, destination_name,
            RENAME_EXCL | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH,
        )
        moved = os.stat(
            destination_name, dir_fd=state, follow_symlinks=False,
        )
        if not _matches_inode(moved, expected_source):
            raise PublicationError("publication_record_changed")
        os.fsync(state)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(state)


def _journal_value(
    *, target: Path, publication_id: str, stage_name: str,
    candidate_digest: str, candidate_identity: dict[str, int],
    predecessor_digest: str | None,
    predecessor_identity: dict[str, int] | None,
) -> dict[str, object]:
    return {
        "candidate_identity": candidate_identity,
        "candidate_tree_sha256": candidate_digest,
        "predecessor_identity": predecessor_identity,
        "predecessor_tree_sha256": predecessor_digest,
        "publication_id": publication_id,
        "schema": JOURNAL_SCHEMA,
        "stage_name": stage_name,
        "target_path": str(target),
    }


def _write_journal(state_root: Path, value: dict[str, object]) -> None:
    publication_id = str(value["publication_id"])
    temporary_name = f".pending.{publication_id}.tmp"
    raw = _canonical(value)
    state, state_info = _open_state_root(state_root)
    descriptor = -1
    try:
        try:
            os.stat(JOURNAL_NAME, dir_fd=state, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PublicationError("publication_journal_already_exists")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=state,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        temporary_info = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = -1
        _rename_regular_bound(
            state_root, temporary_name, JOURNAL_NAME,
            _inode_record(temporary_info),
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(state)


def _read_journal(
    state_root: Path, target: Path,
) -> tuple[dict[str, object], dict[str, int]] | None:
    state, state_info = _open_state_root(state_root)
    descriptor = -1
    try:
        try:
            descriptor, info = _open_regular_entry(
                state, JOURNAL_NAME, expected_device=state_info.st_dev,
                relative=JOURNAL_NAME,
            )
        except PublicationError as error:
            try:
                os.stat(JOURNAL_NAME, dir_fd=state, follow_symlinks=False)
            except FileNotFoundError:
                return None
            raise PublicationError("publication_journal_untrusted") from error
        if stat.S_IMODE(info.st_mode) != 0o600 or not 2 <= info.st_size <= 4096:
            raise PublicationError("publication_journal_untrusted")
        raw = os.read(descriptor, 4097)
        if len(raw) > 4096 or os.read(descriptor, 1):
            raise PublicationError("publication_journal_invalid")
        journal_identity = _inode_record(info)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(state)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError("publication_journal_invalid") from error
    fields = {
        "candidate_identity", "candidate_tree_sha256",
        "predecessor_identity", "predecessor_tree_sha256",
        "publication_id", "schema", "stage_name", "target_path",
    }
    predecessor = value.get("predecessor_tree_sha256") if isinstance(value, dict) else None
    predecessor_identity = value.get("predecessor_identity") if isinstance(value, dict) else None
    publication_id = value.get("publication_id") if isinstance(value, dict) else None
    if (
        raw != _canonical(value) or not isinstance(value, dict)
        or set(value) != fields or value.get("schema") != JOURNAL_SCHEMA
        or not isinstance(value.get("candidate_tree_sha256"), str)
        or SHA256.fullmatch(value["candidate_tree_sha256"]) is None
        or not _valid_inode_record(value.get("candidate_identity"))
        or not isinstance(publication_id, str)
        or PUBLICATION_ID.fullmatch(publication_id) is None
        or value.get("stage_name") != f"stage.{publication_id}"
        or value.get("target_path") != str(target)
        or ((predecessor is None) != (predecessor_identity is None))
        or (
            predecessor is not None
            and (not isinstance(predecessor, str)
                 or SHA256.fullmatch(predecessor) is None
                 or not _valid_inode_record(predecessor_identity))
        )
    ):
        raise PublicationError("publication_journal_invalid")
    return value, journal_identity


def _read_rejected_record(
    state_root: Path, publication_id: str,
) -> dict[str, object] | None:
    name = f"rejected.{publication_id}.json"
    state, state_info = _open_state_root(state_root)
    descriptor = -1
    try:
        try:
            descriptor, info = _open_regular_entry(
                state, name, expected_device=state_info.st_dev,
                relative=name,
            )
        except PublicationError as error:
            try:
                os.stat(name, dir_fd=state, follow_symlinks=False)
            except FileNotFoundError:
                return None
            raise PublicationError(
                "publication_rejected_record_untrusted"
            ) from error
        if stat.S_IMODE(info.st_mode) != 0o600 or not 2 <= info.st_size <= 1024:
            raise PublicationError("publication_rejected_record_untrusted")
        raw = os.read(descriptor, 1025)
        if len(raw) > 1024 or os.read(descriptor, 1):
            raise PublicationError("publication_rejected_record_invalid")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(state)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError("publication_rejected_record_invalid") from error
    if (raw != _canonical(value) or not isinstance(value, dict)
            or set(value) != {
                "candidate_tree_sha256", "publication_id",
                "retained_identity", "retained_tree_sha256", "schema",
            }
            or value.get("schema") != REJECTED_RECORD_SCHEMA
            or value.get("publication_id") != publication_id
            or not _valid_inode_record(value.get("retained_identity"))
            or not isinstance(value.get("candidate_tree_sha256"), str)
            or SHA256.fullmatch(value["candidate_tree_sha256"]) is None
            or not isinstance(value.get("retained_tree_sha256"), str)
            or SHA256.fullmatch(value["retained_tree_sha256"]) is None):
        raise PublicationError("publication_rejected_record_invalid")
    return value


def _bind_rejected_generation(
    state_root: Path, publication_id: str,
    candidate_digest: str, rejected: Path,
    candidate_identity: dict[str, int], *, create: bool,
) -> None:
    observed = _generation_observation(rejected)
    if observed is None or observed["identity"] != candidate_identity:
        raise PublicationError("publication_rejected_generation_changed")
    expected = {
        "candidate_tree_sha256": candidate_digest,
        "publication_id": publication_id,
        "retained_identity": candidate_identity,
        "retained_tree_sha256": observed["tree_sha256"],
        "schema": REJECTED_RECORD_SCHEMA,
    }
    existing = _read_rejected_record(state_root, publication_id)
    if existing is None:
        if not create:
            raise PublicationError("publication_rejected_record_missing")
        temporary_name = (
            f".rejected.{publication_id}.{secrets.token_hex(16)}.tmp"
        )
        final_name = f"rejected.{publication_id}.json"
        raw = _canonical(expected)
        state, state_info = _open_state_root(state_root)
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=state,
            )
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, raw)
            os.fsync(descriptor)
            temporary_info = os.fstat(descriptor)
            os.close(descriptor)
            descriptor = -1
            _rename_regular_bound(
                state_root, temporary_name, final_name,
                _inode_record(temporary_info),
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(state)
        existing = _read_rejected_record(state_root, publication_id)
    current = _generation_observation(rejected)
    if existing != expected or current != observed:
        raise PublicationError("publication_rejected_generation_changed")


def _retained_path(
    state_root: Path, publication_id: str, role: str,
) -> Path:
    if role not in {"predecessor", "rejected"}:
        raise PublicationError("publication_retained_role_invalid")
    return state_root / f"retained.{publication_id}.{role}"


def _retain_generation(
    source: Path, retained: Path, state_root: Path,
    expected_identity: dict[str, int],
) -> None:
    source_observed = _generation_observation(source)
    retained_observed = _generation_observation(retained)
    if source_observed is not None and retained_observed is not None:
        raise PublicationError("publication_retained_generation_collision")
    if retained_observed is not None:
        if retained_observed["identity"] != expected_identity:
            raise PublicationError("publication_retained_generation_changed")
        return
    if source_observed is None or source_observed["identity"] != expected_identity:
        raise PublicationError("publication_generation_disappeared")
    _rename_generation_bound(
        source, retained, state_root, expected_identity,
        event="retain-operands-opened",
    )


def _archive_journal(
    state_root: Path, publication_id: str, status: str,
    journal_identity: dict[str, int],
) -> None:
    if status not in {"completed", "rolledback"}:
        raise PublicationError("publication_terminal_status_invalid")
    _rename_regular_bound(
        state_root, JOURNAL_NAME,
        f"{status}.{publication_id}.json", journal_identity,
    )


def _finish_committed(
    *, state_root: Path, target: Path, stage: Path,
    journal: dict[str, object], journal_identity: dict[str, int],
) -> dict[str, str]:
    candidate_digest = str(journal["candidate_tree_sha256"])
    candidate_identity = dict(journal["candidate_identity"])
    target_observed = _generation_observation(target)
    if (target_observed is None
            or target_observed["tree_sha256"] != candidate_digest
            or target_observed["identity"] != candidate_identity):
        raise PublicationError("publication_target_readback_mismatch")
    predecessor_digest = journal["predecessor_tree_sha256"]
    predecessor_identity = journal["predecessor_identity"]
    if predecessor_digest is not None:
        retained = _retained_path(
            state_root, str(journal["publication_id"]), "predecessor",
        )
        _retain_generation(
            stage, retained, state_root, dict(predecessor_identity),
        )
        retained_observed = _generation_observation(retained)
        if (retained_observed is None
                or retained_observed["tree_sha256"] != predecessor_digest):
            raise PublicationError("publication_predecessor_readback_mismatch")
    elif _generation_observation(stage) is not None:
        raise PublicationError("publication_unexpected_stage")
    target_after = _generation_observation(target)
    if target_after != target_observed:
        raise PublicationError("publication_target_changed_after_retention")
    _archive_journal(
        state_root, str(journal["publication_id"]), "completed",
        journal_identity,
    )
    return {"status": "verified", "tree_sha256": candidate_digest}


def _finish_rolled_back(
    *, state_root: Path, target: Path, stage: Path,
    journal: dict[str, object], journal_identity: dict[str, int],
) -> None:
    predecessor_digest = journal["predecessor_tree_sha256"]
    predecessor_identity = journal["predecessor_identity"]
    if predecessor_digest is None:
        if _generation_observation(target) is not None:
            raise PublicationError("publication_initial_rollback_incomplete")
    else:
        target_observed = _generation_observation(target)
        if (target_observed is None
                or target_observed["tree_sha256"] != predecessor_digest
                or target_observed["identity"] != predecessor_identity):
            raise PublicationError("publication_rollback_readback_failed")
    rejected = _retained_path(
        state_root, str(journal["publication_id"]), "rejected",
    )
    candidate_identity = dict(journal["candidate_identity"])
    publication_id = str(journal["publication_id"])
    candidate_digest = str(journal["candidate_tree_sha256"])
    rejected_observed = _generation_observation(rejected)
    if rejected_observed is None:
        stage_observed = _generation_observation(stage)
        if (stage_observed is None
                or stage_observed["identity"] != candidate_identity):
            raise PublicationError("publication_rejected_generation_changed")
        _bind_rejected_generation(
            state_root, publication_id, candidate_digest, stage,
            candidate_identity, create=True,
        )
        _retain_generation(
            stage, rejected, state_root, candidate_identity,
        )
    _bind_rejected_generation(
        state_root, publication_id, candidate_digest, rejected,
        candidate_identity, create=False,
    )
    _archive_journal(
        state_root, str(journal["publication_id"]), "rolledback",
        journal_identity,
    )
    raise PublicationRolledBack("publication_candidate_failed_readback")


def _reconcile_publication_locked(
    target: Path, state_root: Path,
) -> dict[str, str]:
    target = Path(target).absolute()
    state_root = Path(state_root).absolute()
    _trusted_directory(target.parent, private=False)
    state, _state_info = _open_state_root(state_root)
    os.close(state)
    journal_record = _read_journal(state_root, target)
    if journal_record is None:
        # Preparatory files and directories are intentionally retained.  A
        # recovery path never deletes pathname-selected evidence.
        return {"status": "no-pending-publication"}
    journal, journal_identity = journal_record
    candidate_digest = str(journal["candidate_tree_sha256"])
    candidate_identity = dict(journal["candidate_identity"])
    predecessor_digest = journal["predecessor_tree_sha256"]
    predecessor_identity = journal["predecessor_identity"]
    stage = state_root / str(journal["stage_name"])
    retained_predecessor = _retained_path(
        state_root, str(journal["publication_id"]), "predecessor",
    )
    retained_rejected = _retained_path(
        state_root, str(journal["publication_id"]), "rejected",
    )
    target_observed = _generation_observation(target)
    stage_observed = _generation_observation(stage)
    predecessor_retained = _generation_observation(retained_predecessor)
    rejected_retained = _generation_observation(retained_rejected)

    if (target_observed is not None
            and target_observed["tree_sha256"] == candidate_digest
            and target_observed["identity"] == candidate_identity):
        return _finish_committed(
            state_root=state_root, target=target, stage=stage,
            journal=journal, journal_identity=journal_identity,
        )

    if (stage_observed is not None
            and stage_observed["tree_sha256"] == candidate_digest
            and stage_observed["identity"] == candidate_identity):
        if predecessor_digest is None:
            if target_observed is not None:
                raise PublicationError("publication_unexpected_predecessor")
            _rename_generation_bound(
                stage, target, state_root, candidate_identity,
            )
        else:
            if (target_observed is None
                    or target_observed["tree_sha256"] != predecessor_digest
                    or target_observed["identity"] != predecessor_identity):
                raise PublicationError("publication_predecessor_changed")
            _atomic_swap_bound(
                stage, target, state_root, candidate_identity,
                dict(predecessor_identity),
            )
        return _finish_committed(
            state_root=state_root, target=target, stage=stage,
            journal=journal, journal_identity=journal_identity,
        )

    if predecessor_digest is not None:
        if (target_observed is not None
                and target_observed["tree_sha256"] == predecessor_digest
                and target_observed["identity"] == predecessor_identity
                and (rejected_retained is not None
                     or (stage_observed is not None
                         and stage_observed["identity"] == candidate_identity))):
            return _finish_rolled_back(
                state_root=state_root, target=target, stage=stage,
                journal=journal, journal_identity=journal_identity,
            )
        if (stage_observed is not None
                and stage_observed["tree_sha256"] == predecessor_digest
                and stage_observed["identity"] == predecessor_identity
                and target_observed is not None
                and target_observed["identity"] == candidate_identity):
            _atomic_swap_bound(
                stage, target, state_root, dict(predecessor_identity),
                candidate_identity,
            )
            return _finish_rolled_back(
                state_root=state_root, target=target, stage=stage,
                journal=journal, journal_identity=journal_identity,
            )
        if predecessor_retained is not None:
            raise PublicationError("publication_terminal_journal_stranded")
    else:
        if (target_observed is not None
                and target_observed["identity"] == candidate_identity
                and stage_observed is None):
            _bind_rejected_generation(
                state_root, str(journal["publication_id"]),
                candidate_digest, target, candidate_identity,
                create=True,
            )
            _rename_generation_bound(
                target, retained_rejected, state_root, candidate_identity,
            )
            return _finish_rolled_back(
                state_root=state_root, target=target, stage=retained_rejected,
                journal=journal, journal_identity=journal_identity,
            )
        if (target_observed is None and rejected_retained is not None
                and rejected_retained["identity"] == candidate_identity):
            return _finish_rolled_back(
                state_root=state_root, target=target, stage=retained_rejected,
                journal=journal, journal_identity=journal_identity,
            )
    raise PublicationError("publication_state_ambiguous")


def reconcile_publication(
    target: Path, state_root: Path,
) -> dict[str, str]:
    state_root = Path(state_root).absolute()
    with _publication_lock(state_root):
        return _reconcile_publication_locked(target, state_root)


def _publish_generation_locked(
    candidate: Path,
    target: Path,
    state_root: Path,
    *,
    checkpoint: Callable[[str], None] | None = None,
) -> dict[str, str]:
    candidate = Path(candidate).absolute()
    target = Path(target).absolute()
    state_root = Path(state_root).absolute()
    checkpoint = checkpoint or (lambda _name: None)
    _trusted_directory(candidate, private=False)
    _trusted_directory(candidate.parent, private=True)
    _trusted_directory(target.parent, private=False)
    state, _state_info = _open_state_root(state_root)
    os.close(state)
    prior = _reconcile_publication_locked(target, state_root)
    if prior["status"] not in {"no-pending-publication", "verified"}:
        raise PublicationError("publication_reconciliation_incomplete")
    publication_id = secrets.token_hex(16)
    stage_name = f"stage.{publication_id}"
    stage = state_root / stage_name
    candidate_digest = tree_digest(candidate)
    predecessor_observed = _generation_observation(target)
    predecessor_digest = (
        str(predecessor_observed["tree_sha256"])
        if predecessor_observed is not None else None
    )
    predecessor_identity = (
        dict(predecessor_observed["identity"])
        if predecessor_observed is not None else None
    )
    _copy_generation(candidate, state_root, stage_name)
    stage_observed = _generation_observation(stage)
    if (stage_observed is None
            or stage_observed["tree_sha256"] != candidate_digest):
        raise PublicationError("publication_stage_readback_mismatch")
    candidate_identity = dict(stage_observed["identity"])
    _durably_sync_tree(stage)
    if _generation_observation(stage) != stage_observed:
        raise PublicationError("publication_stage_changed_after_fsync")
    value = _journal_value(
        target=target, publication_id=publication_id,
        stage_name=stage_name, candidate_digest=candidate_digest,
        candidate_identity=candidate_identity,
        predecessor_digest=predecessor_digest,
        predecessor_identity=predecessor_identity,
    )
    _write_journal(state_root, value)
    checkpoint("journal-committed")
    if predecessor_observed is None:
        _rename_generation_bound(
            stage, target, state_root, candidate_identity,
            checkpoint=checkpoint,
        )
    else:
        _atomic_swap_bound(
            stage, target, state_root, candidate_identity,
            dict(predecessor_identity), checkpoint=checkpoint,
        )
    checkpoint("generation-swapped")
    journal_record = _read_journal(state_root, target)
    if journal_record is None:
        raise PublicationError("publication_journal_disappeared")
    current_journal, journal_identity = journal_record
    if current_journal != value:
        raise PublicationError("publication_journal_changed")
    return _finish_committed(
        state_root=state_root, target=target, stage=stage,
        journal=value, journal_identity=journal_identity,
    )


def publish_generation(
    candidate: Path,
    target: Path,
    state_root: Path,
    *,
    checkpoint: Callable[[str], None] | None = None,
) -> dict[str, str]:
    state_root = Path(state_root).absolute()
    checkpoint = checkpoint or (lambda _name: None)
    with _publication_lock(state_root):
        checkpoint("publication-lock-acquired")
        return _publish_generation_locked(
            candidate, target, state_root, checkpoint=checkpoint,
        )


def _existing_private_state_root(
    path: Path, *, checkpoint: Callable[[str], None] | None = None,
) -> None:
    path = Path(path).absolute()
    checkpoint = checkpoint or (lambda _name: None)
    try:
        path.lstat()
    except FileNotFoundError:
        parent, parent_info = _open_trusted_directory(
            path.parent, private=True,
        )
        bootstrap_name = (
            f".{path.name}.bootstrap.{secrets.token_hex(16)}"
        )
        bootstrap_path = path.parent / bootstrap_name
        bootstrap = -1
        try:
            os.mkdir(bootstrap_name, 0o700, dir_fd=parent)
            checkpoint("bootstrap-directory-created")
            bootstrap, bootstrap_info = _open_directory_entry(
                parent, bootstrap_name,
                expected_device=parent_info.st_dev,
                relative=bootstrap_name,
            )
            if list(os.scandir(bootstrap)):
                raise PublicationError(
                    "publication_state_root_creation_raced"
                )
            _create_authority(
                bootstrap, bootstrap_info, checkpoint=checkpoint,
            )
            os.fsync(bootstrap)
            checkpoint("bootstrap-state-durable")
            verified, verified_info = _open_state_root(bootstrap_path)
            os.close(verified)
            if _identity(verified_info)[:2] != _identity(bootstrap_info)[:2]:
                raise PublicationError(
                    "publication_state_root_creation_raced"
                )
            checkpoint("bootstrap-validated")
            _renameatx(
                parent, bootstrap_name, parent, path.name,
                RENAME_EXCL | RENAME_NOFOLLOW_ANY
                | RENAME_RESOLVE_BENEATH,
            )
            checkpoint("bootstrap-published")
            named = os.stat(
                path.name, dir_fd=parent, follow_symlinks=False,
            )
            if (named.st_dev, named.st_ino) != (
                bootstrap_info.st_dev, bootstrap_info.st_ino,
            ):
                raise PublicationError(
                    "publication_state_root_creation_raced"
                )
            os.fsync(parent)
            checkpoint("bootstrap-parent-durable")
        finally:
            if bootstrap >= 0:
                os.close(bootstrap)
            os.close(parent)
    verified, _verified_info = _open_state_root(path)
    os.close(verified)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    publish = subparsers.add_parser("publish")
    publish.add_argument("--candidate", type=Path, required=True)
    publish.add_argument("--target", type=Path, required=True)
    publish.add_argument("--state-root", type=Path, required=True)
    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--target", type=Path, required=True)
    reconcile.add_argument("--state-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        _existing_private_state_root(arguments.state_root.absolute())
        if arguments.command == "publish":
            result = publish_generation(
                arguments.candidate, arguments.target, arguments.state_root,
            )
        else:
            result = reconcile_publication(
                arguments.target, arguments.state_root,
            )
    except PublicationRolledBack as error:
        print(str(error), file=sys.stderr)
        return 3
    except (OSError, PublicationError) as error:
        if isinstance(error, OSError) and error.errno == errno.EXDEV:
            detail = "publication_cross_device_forbidden"
        else:
            detail = str(error)
        print(detail, file=sys.stderr)
        return 1
    print(_canonical(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
