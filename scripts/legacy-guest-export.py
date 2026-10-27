#!/usr/bin/env python3
"""Create a bounded, content-addressed archive from an isolated legacy guest."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import time
from typing import BinaryIO, Iterator


SCHEMA = "secure-sandbox-legacy-preservation-v1"
MAX_PATHS = 1_000_000
MAX_PATH_BYTES = 4096
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
ROLE_ROOTS = {
    "research": ("/home/agent", "/var/lib/secure-sandbox", "/var/log/secure-sandbox"),
    "gateway": ("/var/lib/secure-sandbox", "/var/log/secure-sandbox"),
    "target": ("/var/lib/secure-sandbox", "/var/log/secure-sandbox", "/home/labadmin"),
}


class ExportError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def safe_component(value: str) -> str:
    return value.encode("utf-8", "surrogateescape").hex()


def archive_name(role: str, source: Path) -> str:
    if not source.is_absolute():
        raise ExportError("source_path_not_absolute")
    parts = [safe_component(part) for part in source.parts[1:]]
    return str(PurePosixPath("payload", role, *parts))


def record_metadata(path: Path, info: os.stat_result, kind: str) -> dict[str, object]:
    return {
        "gid": info.st_gid,
        "kind": kind,
        "mode": stat.S_IMODE(info.st_mode),
        "mtime_ns": info.st_mtime_ns,
        "nlink": info.st_nlink,
        "source_path_hex": os.fsencode(path).hex(),
        "uid": info.st_uid,
    }


def walk_roots(
    roots: tuple[str, ...], logical_roots: tuple[str, ...] | None = None,
) -> Iterator[tuple[Path, Path, os.stat_result]]:
    if logical_roots is None:
        logical_roots = roots
    if len(roots) != len(logical_roots):
        raise ExportError("root_mapping_invalid")
    count = 0
    for root_value, logical_value in zip(roots, logical_roots, strict=True):
        root = Path(root_value)
        logical_root = Path(logical_value)
        if not root.is_absolute() or not logical_root.is_absolute():
            raise ExportError("root_mapping_invalid")
        try:
            root_info = root.lstat()
        except FileNotFoundError:
            continue
        root_device = root_info.st_dev
        stack = [root]
        while stack:
            path = stack.pop()
            encoded = os.fsencode(path)
            if len(encoded) > MAX_PATH_BYTES:
                raise ExportError("path_length_limit_exceeded")
            info = path.lstat()
            count += 1
            if count > MAX_PATHS:
                raise ExportError("path_count_limit_exceeded")
            logical_path = logical_root / path.relative_to(root)
            yield path, logical_path, info
            if stat.S_ISDIR(info.st_mode):
                if info.st_dev != root_device:
                    raise ExportError(f"unexpected_mount:{os.fsdecode(encoded)}")
                with os.scandir(path) as entries:
                    children = sorted((Path(entry.path) for entry in entries), key=os.fsencode, reverse=True)
                stack.extend(children)


class HashingReader(io.RawIOBase):
    def __init__(self, descriptor: int, remaining: int) -> None:
        self.descriptor = descriptor
        self.remaining = remaining
        self.digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:
        if self.remaining == 0:
            return 0
        chunk = os.read(self.descriptor, min(len(buffer), self.remaining))
        if not chunk:
            raise ExportError("file_truncated_during_export")
        buffer[: len(chunk)] = chunk
        self.remaining -= len(chunk)
        self.digest.update(chunk)
        return len(chunk)


def tar_info(name: str, info: os.stat_result, kind: bytes, size: int = 0) -> tarfile.TarInfo:
    item = tarfile.TarInfo(name)
    item.mode = stat.S_IMODE(info.st_mode)
    item.uid = info.st_uid
    item.gid = info.st_gid
    item.mtime = info.st_mtime_ns / 1_000_000_000
    item.type = kind
    item.size = size
    item.uname = ""
    item.gname = ""
    return item


def export(
    role: str, output: BinaryIO, roots: tuple[str, ...] | None = None,
    logical_roots: tuple[str, ...] | None = None,
) -> dict[str, object]:
    selected = roots if roots is not None else ROLE_ROOTS[role]
    logical = logical_roots if logical_roots is not None else selected
    records: list[dict[str, object]] = []
    total_bytes = 0
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            for path, logical_path, before in walk_roots(selected, logical):
                name = archive_name(role, logical_path)
                if stat.S_ISREG(before.st_mode):
                    if before.st_size > MAX_FILE_BYTES:
                        raise ExportError("file_size_limit_exceeded")
                    total_bytes += before.st_size
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise ExportError("total_size_limit_exceeded")
                    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        opened = os.fstat(descriptor)
                        expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                        actual = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                        if expected != actual or not stat.S_ISREG(opened.st_mode):
                            raise ExportError("source_changed_before_read")
                        reader = HashingReader(descriptor, opened.st_size)
                        archive.addfile(tar_info(name, opened, tarfile.REGTYPE, opened.st_size), reader)
                        if reader.remaining != 0:
                            raise ExportError("file_truncated_during_export")
                        after = os.fstat(descriptor)
                        final = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                        if actual != final:
                            raise ExportError("source_changed_during_read")
                        record = record_metadata(logical_path, opened, "regular")
                        record.update({"sha256": reader.digest.hexdigest(), "size": opened.st_size})
                    finally:
                        os.close(descriptor)
                elif stat.S_ISDIR(before.st_mode):
                    archive.addfile(tar_info(name, before, tarfile.DIRTYPE))
                    record = record_metadata(logical_path, before, "directory")
                elif stat.S_ISLNK(before.st_mode):
                    target = os.readlink(path)
                    item = tar_info(name, before, tarfile.SYMTYPE)
                    item.linkname = target
                    archive.addfile(item)
                    record = record_metadata(logical_path, before, "symlink")
                    record["target_hex"] = os.fsencode(target).hex()
                else:
                    kind = (
                        "socket" if stat.S_ISSOCK(before.st_mode) else
                        "fifo" if stat.S_ISFIFO(before.st_mode) else
                        "block" if stat.S_ISBLK(before.st_mode) else
                        "character" if stat.S_ISCHR(before.st_mode) else "unsupported"
                    )
                    record = record_metadata(logical_path, before, kind)
                    record["omitted"] = True
                record["archive_path"] = name
                records.append(record)
            manifest = {
                "created_at": int(time.time()),
                "records": records,
                "role": role,
                "roots": list(logical),
                "schema": SCHEMA,
                "summary": {"paths": len(records), "regular_bytes": total_bytes},
            }
            body = canonical(manifest)
            item = tarfile.TarInfo("MANIFEST.json")
            item.mode = 0o400
            item.uid = 0
            item.gid = 0
            item.mtime = 0
            item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
    return manifest


def inventory(
    role: str, roots: tuple[str, ...] | None = None,
    logical_roots: tuple[str, ...] | None = None,
) -> dict[str, object]:
    selected = roots if roots is not None else ROLE_ROOTS[role]
    logical = logical_roots if logical_roots is not None else selected
    counts: dict[str, int] = {}
    regular_bytes = 0
    paths = 0
    for _path, _logical_path, info in walk_roots(selected, logical):
        paths += 1
        if stat.S_ISREG(info.st_mode):
            kind = "regular"
            regular_bytes += info.st_size
        elif stat.S_ISDIR(info.st_mode): kind = "directory"
        elif stat.S_ISLNK(info.st_mode): kind = "symlink"
        elif stat.S_ISSOCK(info.st_mode): kind = "socket"
        elif stat.S_ISFIFO(info.st_mode): kind = "fifo"
        elif stat.S_ISBLK(info.st_mode): kind = "block"
        elif stat.S_ISCHR(info.st_mode): kind = "character"
        else: kind = "unsupported"
        counts[kind] = counts.get(kind, 0) + 1
    return {
        "counts": counts, "regular_bytes": regular_bytes, "role": role,
        "roots": list(logical), "schema": SCHEMA, "status": "inventory", "paths": paths,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("inventory", "export"))
    parser.add_argument("--role", required=True, choices=tuple(ROLE_ROOTS))
    parser.add_argument("--output", default="-")
    parser.add_argument("--source-prefix", default="/")
    parser.add_argument("--allow-non-root", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0 and not args.allow_non_root:
        raise SystemExit("root_required")
    prefix = Path(args.source_prefix)
    if not prefix.is_absolute():
        raise SystemExit("source_prefix_invalid")
    logical_roots = ROLE_ROOTS[args.role]
    physical_roots = tuple(str(prefix / value.lstrip("/")) for value in logical_roots)
    if args.operation == "inventory":
        print(json.dumps(inventory(args.role, physical_roots, logical_roots), sort_keys=True))
        return 0
    if args.output == "-":
        export(args.role, sys.stdout.buffer, physical_roots, logical_roots)
    else:
        target = Path(args.output)
        if target.exists() or target.is_symlink():
            raise SystemExit("output_exists")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                export(args.role, output, physical_roots, logical_roots)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(descriptor)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ExportError, OSError, tarfile.TarError) as error:
        print(f"legacy_export_failed:{type(error).__name__}:{error}", file=sys.stderr)
        raise SystemExit(1)

