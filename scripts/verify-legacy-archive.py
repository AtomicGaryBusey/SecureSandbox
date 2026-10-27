#!/usr/bin/env python3
"""Verify a legacy preservation archive without extracting hostile content."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile


SCHEMA = "secure-sandbox-legacy-preservation-v1"
ROLES = {"research", "gateway", "target"}
ROLE_ROOTS = {
    "research": ("/home/agent", "/var/lib/secure-sandbox", "/var/log/secure-sandbox"),
    "gateway": ("/var/lib/secure-sandbox", "/var/log/secure-sandbox"),
    "target": ("/var/lib/secure-sandbox", "/var/log/secure-sandbox", "/home/labadmin"),
}
MAX_MANIFEST = 256 * 1024 * 1024
MAX_PATHS = 1_000_000
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SPECIAL_KINDS = {"socket", "fifo", "block", "character", "unsupported"}


class VerificationError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def safe_name(name: str) -> None:
    path = PurePosixPath(name)
    if name.startswith("/") or not name or ".." in path.parts or "." in path.parts:
        raise VerificationError("archive_path_unsafe")
    if len(name.encode("utf-8", "surrogateescape")) > 16384:
        raise VerificationError("archive_path_too_long")


def archive_name(role: str, source: Path) -> str:
    if not source.is_absolute():
        raise VerificationError("manifest_source_path_invalid")
    parts = [part.encode("utf-8", "surrogateescape").hex() for part in source.parts[1:]]
    return str(PurePosixPath("payload", role, *parts))


def verify(path: Path, *, include_manifest: bool = False) -> dict[str, object]:
    before_path = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before_path.st_dev, before_path.st_ino) != (opened.st_dev, opened.st_ino)):
            raise VerificationError("archive_file_untrusted")
        archive_digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            archive_digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)

        members: dict[str, dict[str, object]] = {}
        manifest_bytes: bytes | None = None
        manifest_seen = False
        total_bytes = 0
        with os.fdopen(descriptor, "rb", closefd=False) as raw:
            with gzip.GzipFile(fileobj=raw, mode="rb") as compressed:
                with tarfile.open(fileobj=compressed, mode="r|") as archive:
                    for item in archive:
                        safe_name(item.name)
                        if item.name in members or (item.name == "MANIFEST.json" and manifest_seen):
                            raise VerificationError("archive_member_duplicate")
                        if item.name == "MANIFEST.json":
                            if not item.isfile() or item.size > MAX_MANIFEST:
                                raise VerificationError("manifest_member_invalid")
                            stream = archive.extractfile(item)
                            if stream is None:
                                raise VerificationError("manifest_member_invalid")
                            manifest_bytes = stream.read(MAX_MANIFEST + 1)
                            manifest_seen = True
                            continue
                        if manifest_seen:
                            raise VerificationError("manifest_not_final")
                        if len(members) >= MAX_PATHS:
                            raise VerificationError("path_count_limit_exceeded")
                        if item.isfile():
                            total_bytes += item.size
                            if total_bytes > MAX_TOTAL_BYTES:
                                raise VerificationError("total_size_limit_exceeded")
                            stream = archive.extractfile(item)
                            if stream is None:
                                raise VerificationError("regular_member_unreadable")
                            digest = hashlib.sha256()
                            remaining = item.size
                            while remaining:
                                chunk = stream.read(min(1024 * 1024, remaining))
                                if not chunk:
                                    raise VerificationError("regular_member_truncated")
                                remaining -= len(chunk)
                                digest.update(chunk)
                            members[item.name] = {"kind": "regular", "sha256": digest.hexdigest(), "size": item.size}
                        elif item.isdir():
                            members[item.name] = {"kind": "directory"}
                        elif item.issym():
                            members[item.name] = {"kind": "symlink", "target_hex": os.fsencode(item.linkname).hex()}
                        else:
                            raise VerificationError("archive_member_type_invalid")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise VerificationError("archive_changed_during_verification")
    finally:
        os.close(descriptor)

    if manifest_bytes is None:
        raise VerificationError("manifest_missing")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("manifest_invalid") from error
    if canonical(manifest) != manifest_bytes or manifest.get("schema") != SCHEMA:
        raise VerificationError("manifest_noncanonical")
    role = manifest.get("role")
    if role not in ROLES:
        raise VerificationError("manifest_role_invalid")
    if (manifest.get("roots") != list(ROLE_ROOTS[role])
            or not isinstance(manifest.get("created_at"), int)
            or isinstance(manifest.get("created_at"), bool)):
        raise VerificationError("manifest_scope_invalid")
    records = manifest.get("records")
    if not isinstance(records, list) or len(records) > MAX_PATHS:
        raise VerificationError("manifest_records_invalid")
    expected: dict[str, dict[str, object]] = {}
    record_names: set[str] = set()
    omitted = 0
    for record in records:
        if not isinstance(record, dict):
            raise VerificationError("manifest_record_invalid")
        common = {
            "archive_path", "gid", "kind", "mode", "mtime_ns", "nlink",
            "source_path_hex", "uid",
        }
        name = record.get("archive_path")
        if not isinstance(name, str):
            raise VerificationError("manifest_record_invalid")
        safe_name(name)
        source_hex = record.get("source_path_hex")
        if not isinstance(source_hex, str):
            raise VerificationError("manifest_source_path_invalid")
        try:
            source_path = Path(os.fsdecode(bytes.fromhex(source_hex)))
        except (ValueError, TypeError) as error:
            raise VerificationError("manifest_source_path_invalid") from error
        if not any(source_path == Path(root) or source_path.is_relative_to(root)
                   for root in ROLE_ROOTS[role]):
            raise VerificationError("manifest_source_scope_invalid")
        if archive_name(role, source_path) != name:
            raise VerificationError("manifest_source_binding_invalid")
        if name in record_names:
            raise VerificationError("manifest_path_duplicate")
        record_names.add(name)
        kind = record.get("kind")
        if (any(not isinstance(record.get(field), int) or isinstance(record.get(field), bool)
                for field in ("gid", "mode", "mtime_ns", "nlink", "uid"))
                or record["gid"] < 0 or record["uid"] < 0
                or not 0 <= record["mode"] <= 0o7777 or record["nlink"] < 1):
            raise VerificationError("manifest_metadata_invalid")
        if kind == "regular":
            if (set(record) != common | {"sha256", "size"}
                    or not isinstance(record.get("sha256"), str)
                    or not SHA256.fullmatch(record["sha256"])
                    or not isinstance(record.get("size"), int)
                    or isinstance(record.get("size"), bool)
                    or not 0 <= record["size"] <= MAX_TOTAL_BYTES):
                raise VerificationError("manifest_record_invalid")
        elif kind == "directory":
            if set(record) != common:
                raise VerificationError("manifest_record_invalid")
        elif kind == "symlink":
            target = record.get("target_hex")
            if set(record) != common | {"target_hex"} or not isinstance(target, str):
                raise VerificationError("manifest_record_invalid")
            try:
                bytes.fromhex(target)
            except ValueError as error:
                raise VerificationError("manifest_record_invalid") from error
        elif kind in SPECIAL_KINDS:
            if set(record) != common | {"omitted"} or record.get("omitted") is not True:
                raise VerificationError("manifest_record_invalid")
            omitted += 1
            continue
        else:
            raise VerificationError("manifest_kind_invalid")
        comparable: dict[str, object] = {"kind": kind}
        if kind == "regular":
            comparable.update({"sha256": record.get("sha256"), "size": record.get("size")})
        elif kind == "symlink":
            comparable["target_hex"] = record.get("target_hex")
        elif kind != "directory":
            raise VerificationError("manifest_kind_invalid")
        expected[name] = comparable
    if expected != members:
        raise VerificationError("manifest_payload_mismatch")
    summary = manifest.get("summary")
    if summary != {"paths": len(records), "regular_bytes": total_bytes}:
        raise VerificationError("manifest_summary_invalid")
    result = {
        "archive_sha256": archive_digest.hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "omitted_special_files": omitted,
        "paths": len(records),
        "regular_bytes": total_bytes,
        "role": role,
        "schema": "secure-sandbox-legacy-preservation-verification-v1",
        "status": "verified",
    }
    if include_manifest:
        result["_manifest"] = manifest
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    args = parser.parse_args()
    print(json.dumps(verify(Path(args.archive)), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (VerificationError, OSError, tarfile.TarError) as error:
        print(f"legacy_archive_rejected:{type(error).__name__}:{error}", file=sys.stderr)
        raise SystemExit(1)

