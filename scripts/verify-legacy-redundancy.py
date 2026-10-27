#!/usr/bin/env python3
"""Verify an independent second copy of legacy archives; never copies or deletes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid


GENERATION = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ROLES = ("gateway", "research", "target")
MAX_RECEIPT = 16 * 1024 * 1024


class RedundancyError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def secure_directory(path: Path, uid: int, *, exact_private: bool) -> os.stat_result:
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != uid
            or (mode != 0o700 if exact_private else bool(mode & 0o022))):
        raise RedundancyError(f"directory_untrusted:{path.name}")
    return info


def read_json(path: Path, uid: int) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or opened.st_size > MAX_RECEIPT):
            raise RedundancyError(f"record_untrusted:{path.name}")
        data = bytearray()
        while chunk := os.read(descriptor, MAX_RECEIPT + 1 - len(data)):
            data.extend(chunk)
            if len(data) > MAX_RECEIPT:
                raise RedundancyError(f"record_untrusted:{path.name}")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RedundancyError(f"record_changed:{path.name}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RedundancyError(f"record_invalid:{path.name}") from error
    if not isinstance(value, dict):
        raise RedundancyError(f"record_invalid:{path.name}")
    return value


def hash_regular(path: Path, uid: int) -> tuple[str, int, int]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise RedundancyError(f"archive_untrusted:{path.name}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RedundancyError(f"archive_changed:{path.name}")
        return digest.hexdigest(), opened.st_size, opened.st_dev
    finally:
        os.close(descriptor)


def atomic_json(path: Path, value: dict[str, object], uid: int) -> None:
    if path.exists() or path.is_symlink():
        raise RedundancyError("redundancy_receipt_exists")
    temporary = path.with_name(f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}")
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            data = canonical(value)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise RedundancyError("short_write")
                offset += written
            os.fchmod(descriptor, 0o600)
            if os.fstat(descriptor).st_uid != uid:
                raise RedundancyError("redundancy_receipt_owner_invalid")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def verify(repo: Path, generation: str, copy_root: Path, *,
           declared_separate_failure_domain: bool,
           require_distinct_device: bool = True,
           verified_at: int | None = None) -> dict[str, object]:
    if not GENERATION.fullmatch(generation):
        raise RedundancyError("generation_invalid")
    if not declared_separate_failure_domain:
        raise RedundancyError("separate_failure_domain_not_attested")
    uid = os.geteuid()
    repo = repo.resolve(strict=True)
    private = repo / ".private"
    migration = private / "legacy-migration"
    generation_root = migration / generation
    primary = generation_root / "archives"
    receipts = generation_root / "receipts"
    for directory in (private, migration, generation_root, primary, receipts):
        secure_directory(directory, uid, exact_private=True)

    copy_root = copy_root.resolve(strict=True)
    secondary_info = secure_directory(copy_root, uid, exact_private=False)
    primary_info = primary.lstat()
    if require_distinct_device and primary_info.st_dev == secondary_info.st_dev:
        raise RedundancyError("second_copy_not_on_distinct_filesystem")

    hashes: dict[str, str] = {}
    sizes: dict[str, int] = {}
    secondary_devices: set[int] = set()
    for role in ROLES:
        receipt = read_json(receipts / f"preservation-{role}.json", uid)
        primary_digest, primary_size, primary_device = hash_regular(
            primary / f"{role}.tar.gz", uid
        )
        secondary_digest, secondary_size, secondary_device = hash_regular(
            copy_root / f"{role}.tar.gz", uid
        )
        if (receipt.get("schema") != "secure-sandbox-legacy-preservation-receipt-v1"
                or receipt.get("verification_schema")
                != "secure-sandbox-legacy-preservation-verification-v1"
                or receipt.get("status") != "verified"
                or receipt.get("generation") != generation
                or receipt.get("role") != role
                or receipt.get("archive_sha256") != primary_digest
                or not SHA256.fullmatch(primary_digest)
                or primary_digest != secondary_digest
                or primary_size != secondary_size):
            raise RedundancyError(f"archive_copy_mismatch:{role}")
        if require_distinct_device and primary_device == secondary_device:
            raise RedundancyError(f"archive_copy_not_independent:{role}")
        hashes[role] = primary_digest
        sizes[role] = primary_size
        secondary_devices.add(secondary_device)
    if len(secondary_devices) != 1:
        raise RedundancyError("second_copy_spans_filesystems")

    timestamp = int(time.time()) if verified_at is None else verified_at
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp <= 0:
        raise RedundancyError("verification_time_invalid")
    result = {
        "archive_sha256": hashes,
        "archive_sizes": sizes,
        "failure_domain_evidence": "operator-attested-separate-failure-domain-and-distinct-filesystem",
        "generation": generation,
        "independent_copies": 2,
        "primary_device": primary_info.st_dev,
        "schema": "secure-sandbox-legacy-redundancy-v1",
        "secondary_device": next(iter(secondary_devices)),
        "secondary_root": str(copy_root),
        "status": "verified",
        "verified_at": timestamp,
    }
    atomic_json(receipts / "redundancy.json", result, uid)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--generation", required=True)
    parser.add_argument("--copy-root", required=True)
    parser.add_argument("--confirm-separate-failure-domain", action="store_true")
    args = parser.parse_args()
    if not args.confirm_separate_failure_domain or not sys.stdin.isatty():
        raise RedundancyError("interactive_failure_domain_confirmation_required")
    expected = f"VERIFY {args.generation}"
    entered = input(
        "Confirm that the second-copy directory is on separately administered storage whose\n"
        "loss is independent of the Mac's internal disk, then type exactly:\n"
        f"{expected}\n> "
    )
    if entered != expected:
        raise RedundancyError("failure_domain_confirmation_mismatch")
    print(json.dumps(verify(
        Path(args.repo), args.generation, Path(args.copy_root),
        declared_separate_failure_domain=True,
    ), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RedundancyError, OSError, ValueError) as error:
        print(f"legacy_redundancy_rejected:{type(error).__name__}:{error}", file=sys.stderr)
        raise SystemExit(1)
