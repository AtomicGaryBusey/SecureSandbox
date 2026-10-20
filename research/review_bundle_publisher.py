#!/usr/bin/env python3
"""Root-only atomic publisher for bounded white-box review bundles."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import shutil
import stat
import sys
import uuid
from pathlib import Path

from review_bundle import (
    BUNDLE_RE, MAX_ENTRIES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_TREE_ENTRIES,
    REVIEW_ROOT, safe_relative,
)

RUN_ID = Path("/run/secure-sandbox/run-id")
PROCESS_ROOT = Path("/proc")
STAGING_ROOT = Path("/tmp")
AT_FDCWD = -100
RENAME_NOREPLACE = 1
TRUSTED_UID = 0
MAX_BUNDLES = 64
MAX_TEMPORARIES = 64
TEMP_RE = re.compile(r"^\.([a-z0-9](?:[a-z0-9-]{0,55}[a-z0-9])?-review)\.([0-9a-f-]{36})\.tmp$")


class PublishError(ValueError):
    pass


def require_root_and_idle() -> None:
    if os.geteuid() != 0:
        raise PublishError("root_required")
    if RUN_ID.exists():
        raise PublishError("active_run")
    try:
        processes = list(PROCESS_ROOT.iterdir())
    except OSError as error:
        raise PublishError("process_state_unavailable") from error
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            if (process / "comm").read_text(encoding="utf-8").strip() == "claude":
                raise PublishError("active_run")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


def validate_staging(bundle_id: str, source: Path) -> list[tuple[str, Path, os.stat_result]]:
    if not BUNDLE_RE.fullmatch(bundle_id):
        raise PublishError("invalid_bundle_id")
    try:
        resolved = source.resolve(strict=True)
        staging = STAGING_ROOT.resolve(strict=True)
    except OSError as error:
        raise PublishError("staging_unavailable") from error
    if resolved.parent != staging or not resolved.name.startswith(bundle_id + "."):
        raise PublishError("invalid_staging_path")
    root_info = os.lstat(resolved)
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_mode & 0o022):
        raise PublishError("invalid_staging_tree")
    records: list[tuple[str, Path, os.stat_result]] = []
    total = 0
    tree_entries = 0
    for directory, names, files in os.walk(resolved, topdown=True, followlinks=False):
        names.sort(); files.sort()
        tree_entries += len(names) + len(files)
        if tree_entries > MAX_TREE_ENTRIES:
            raise PublishError("bundle_too_many_entries")
        for name in names:
            path = Path(directory) / name
            info = os.lstat(path)
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != root_info.st_uid or info.st_mode & 0o022):
                raise PublishError("invalid_staging_tree")
        for name in files:
            path = Path(directory) / name
            relative = safe_relative(path.relative_to(resolved).as_posix())
            if relative in {".bundle-id", "SHA256SUMS"}:
                raise PublishError("reserved_bundle_path")
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != root_info.st_uid
                    or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES):
                raise PublishError("invalid_staging_file")
            total += info.st_size
            if len(records) >= MAX_ENTRIES - 1:
                raise PublishError("bundle_too_many_entries")
            if total > MAX_TOTAL_BYTES:
                raise PublishError("bundle_too_large")
            records.append((relative, path, info))
    if not records:
        raise PublishError("empty_bundle")
    return sorted(records, key=lambda item: item[0].encode("utf-8"))


def write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short_write")
        offset += written


def copy_and_hash(source: Path, expected: os.stat_result, destination: Path) -> tuple[int, str]:
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    digest = hashlib.sha256(); total = 0
    try:
        before = os.fstat(source_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns)):
            raise PublishError("staging_changed")
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise PublishError("bundle_file_too_large")
            digest.update(chunk); write_all(destination_fd, chunk)
        after = os.fstat(source_fd)
        if ((after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (before.st_size, before.st_mtime_ns, before.st_ctime_ns)):
            raise PublishError("staging_changed")
        os.fsync(destination_fd)
    finally:
        os.close(source_fd); os.close(destination_fd)
    return total, digest.hexdigest()


def write_control(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        write_all(descriptor, data); os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.renameat2(AT_FDCWD, os.fsencode(source), AT_FDCWD, os.fsencode(destination), RENAME_NOREPLACE)
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise PublishError("bundle_already_exists")
        raise OSError(code, os.strerror(code))


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remove_temporary(path: Path) -> None:
    if not path.exists():
        return
    for directory, names, files in os.walk(path, topdown=False):
        for name in files:
            os.chmod(Path(directory) / name, 0o600, follow_symlinks=False)
        os.chmod(directory, 0o700)
    shutil.rmtree(path)


def prepare_review_root(root: Path) -> None:
    entries = list(os.scandir(root))
    if len(entries) > MAX_BUNDLES + MAX_TEMPORARIES:
        raise PublishError("review_root_capacity_exceeded")
    bundles = 0
    temporaries: list[Path] = []
    for entry in entries:
        info = entry.stat(follow_symlinks=False)
        if BUNDLE_RE.fullmatch(entry.name):
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
                raise PublishError("review_root_untrusted")
            bundles += 1
            continue
        match = TEMP_RE.fullmatch(entry.name)
        try:
            valid_uuid = bool(match and uuid.UUID(match.group(2)).version == 4 and str(uuid.UUID(match.group(2))) == match.group(2))
        except ValueError:
            valid_uuid = False
        if not valid_uuid or not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID:
            raise PublishError("review_root_untrusted")
        temporaries.append(Path(entry.path))
    if bundles >= MAX_BUNDLES:
        raise PublishError("review_root_capacity_exceeded")
    for temporary in temporaries:
        remove_temporary(temporary)
    fsync_directory(root)


def publish(bundle_id: str, source: Path) -> dict:
    require_root_and_idle()
    records = validate_staging(bundle_id, source)
    root = Path(REVIEW_ROOT)
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
        raise PublishError("review_root_untrusted")
    prepare_review_root(root)
    temporary = root / f".{bundle_id}.{uuid.uuid4()}.tmp"
    destination = root / bundle_id
    temporary.mkdir(mode=0o700)
    manifest: dict[str, tuple[int, str]] = {}
    try:
        identity = (bundle_id + "\n").encode()
        write_control(temporary / ".bundle-id", identity)
        manifest[".bundle-id"] = (len(identity), hashlib.sha256(identity).hexdigest())
        for relative, path, initial in records:
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            manifest[relative] = copy_and_hash(path, initial, target)
        manifest_data = "".join(
            f"{manifest[path][1]}  {path}\n" for path in sorted(manifest, key=lambda item: item.encode("utf-8"))
        ).encode()
        write_control(temporary / "SHA256SUMS", manifest_data)
        for directory, names, files in os.walk(temporary, topdown=False):
            for name in files:
                os.chmod(Path(directory) / name, 0o444, follow_symlinks=False)
            os.chmod(directory, 0o555)
            fsync_directory(Path(directory))
        rename_noreplace(temporary, destination)
        fsync_directory(root)
    except Exception:
        remove_temporary(temporary)
        raise
    return {
        "schema": "secure-sandbox-review-bundle-publication-v1",
        "bundle_id": bundle_id,
        "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
        "file_count": len(records),
        "total_bytes": sum(size for path, (size, _) in manifest.items() if path != ".bundle-id"),
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: review_bundle_publisher.py BUNDLE_ID /tmp/BUNDLE_ID.STAGING")
    try:
        result = publish(sys.argv[1], Path(sys.argv[2]))
    except (PublishError, OSError) as error:
        raise SystemExit(str(error)) from error
    print("review-bundle:published:" + result["bundle_id"] + ":" + result["manifest_sha256"])


if __name__ == "__main__":
    main()
