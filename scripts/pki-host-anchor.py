#!/usr/bin/env python3
"""Root-controlled host anchor for SecureSandbox PKI generation rollback detection."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path


DEFAULT_ROOT = Path("/usr/local/var/lib/secure-sandbox/pki")
HEX64 = re.compile(r"[0-9a-f]{64}")


class AnchorError(RuntimeError):
    pass


def canonical(value: dict) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def valid_generation(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise AnchorError("invalid_generation_id") from error
    if parsed.version != 4 or str(parsed) != value:
        raise AnchorError("invalid_generation_id")
    return value


def seal(value: dict) -> dict:
    body = dict(value)
    body.pop("record_sha256", None)
    body["record_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
    return body


def validate(value: dict) -> dict:
    expected = {
        "schema", "generation_id", "manifest_sha256", "committed_at",
        "previous_generation_id", "previous_manifest_sha256", "record_sha256",
    }
    if set(value) != expected or value["schema"] != 2:
        raise AnchorError("anchor_schema_invalid")
    valid_generation(value["generation_id"])
    if value["previous_generation_id"]:
        valid_generation(value["previous_generation_id"])
    for key in ("manifest_sha256",):
        if not isinstance(value[key], str) or not HEX64.fullmatch(value[key]):
            raise AnchorError("anchor_hash_invalid")
    previous_hash = value["previous_manifest_sha256"]
    if previous_hash and (not isinstance(previous_hash, str) or not HEX64.fullmatch(previous_hash)):
        raise AnchorError("anchor_hash_invalid")
    if bool(value["previous_generation_id"]) != bool(previous_hash):
        raise AnchorError("anchor_previous_invalid")
    if not isinstance(value["committed_at"], int) or isinstance(value["committed_at"], bool):
        raise AnchorError("anchor_time_invalid")
    supplied = value["record_sha256"]
    if not isinstance(supplied, str) or not HEX64.fullmatch(supplied):
        raise AnchorError("anchor_hash_invalid")
    body = dict(value)
    del body["record_sha256"]
    if not hmac.compare_digest(supplied, hashlib.sha256(canonical(body)).hexdigest()):
        raise AnchorError("anchor_record_mismatch")
    return value


def read_anchor(path: Path) -> dict:
    return validate(read_root_json(path, 8192, "anchor_untrusted"))


def pending_value(generation: str) -> dict:
    value = {"schema": 2, "generation_id": valid_generation(generation), "created_at": int(time.time())}
    value["record_sha256"] = hashlib.sha256(canonical(value)).hexdigest()
    return value


def read_pending(path: Path) -> dict:
    value = read_root_json(path, 4096, "pending_untrusted")
    if set(value) != {"schema", "generation_id", "created_at", "record_sha256"} or value["schema"] != 2:
        raise AnchorError("pending_schema_invalid")
    valid_generation(value["generation_id"])
    if not isinstance(value["created_at"], int) or isinstance(value["created_at"], bool):
        raise AnchorError("pending_schema_invalid")
    supplied = value["record_sha256"]
    body = dict(value)
    del body["record_sha256"]
    if not isinstance(supplied, str) or not HEX64.fullmatch(supplied) or not hmac.compare_digest(
        supplied, hashlib.sha256(canonical(body)).hexdigest()
    ):
        raise AnchorError("pending_record_mismatch")
    return value


def read_root_json(path: Path, maximum: int, error_code: str) -> dict:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o644 or not 0 < info.st_size <= maximum):
            raise AnchorError(error_code)
        data = b""
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > maximum:
            raise AnchorError(error_code)
        value = json.loads(data.decode("utf-8"))
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise AnchorError(error_code)
    return value


def atomic_write(path: Path, value: dict) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".anchor.", dir=path.parent)
    temporary: Path | None = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def prepare_root(root: Path) -> int:
    if os.geteuid() != 0:
        raise AnchorError("root_required")
    existed = root.exists() or root.is_symlink()
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not existed:
        os.chown(root, 0, 0)
        os.chmod(root, 0o755)
    root_info = root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
            or stat.S_IMODE(root_info.st_mode) != 0o755):
        raise AnchorError("anchor_root_untrusted")
    descriptor = os.open(
        root / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    lock_info = os.fstat(descriptor)
    if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0:
        os.close(descriptor)
        raise AnchorError("anchor_lock_untrusted")
    os.fchmod(descriptor, 0o600)
    os.fchown(descriptor, 0, 0)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def begin(root: Path, generation: str) -> dict:
    valid_generation(generation)
    descriptor = prepare_root(root)
    try:
        path = root / "pending-generation.json"
        if path.exists() or path.is_symlink():
            value = read_pending(path)
            if value["generation_id"] != generation:
                raise AnchorError("different_generation_pending")
            return value
        value = pending_value(generation)
        atomic_write(path, value)
        return value
    finally:
        os.close(descriptor)


def commit(root: Path, generation: str, manifest_hash: str, expected_current: str) -> dict:
    valid_generation(generation)
    if not HEX64.fullmatch(manifest_hash):
        raise AnchorError("anchor_hash_invalid")
    descriptor = prepare_root(root)
    try:
        pending_path = root / "pending-generation.json"
        pending = read_pending(pending_path)
        if pending["generation_id"] != generation:
            raise AnchorError("pending_generation_mismatch")
        path = root / "active-generation.json"
        previous = None
        if path.exists() or path.is_symlink():
            previous = read_anchor(path)
            if previous["generation_id"] == generation and previous["manifest_sha256"] == manifest_hash:
                pending_path.unlink()
                directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                return previous
            if previous["generation_id"] != expected_current:
                raise AnchorError("anchor_expected_current_mismatch")
        elif expected_current:
            raise AnchorError("anchor_expected_current_mismatch")
        value = seal({
            "schema": 2,
            "generation_id": generation,
            "manifest_sha256": manifest_hash,
            "committed_at": int(time.time()),
            "previous_generation_id": previous["generation_id"] if previous else "",
            "previous_manifest_sha256": previous["manifest_sha256"] if previous else "",
        })
        atomic_write(path, value)
        pending_path.unlink()
        directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return value
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", default=str(DEFAULT_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify")
    sub.add_parser("pending")
    start = sub.add_parser("begin")
    start.add_argument("generation_id")
    write = sub.add_parser("commit")
    write.add_argument("generation_id")
    write.add_argument("manifest_sha256")
    write.add_argument("--expected-current", default="")
    args = parser.parse_args()
    try:
        root = Path(args.state_root)
        if args.command == "verify":
            value = read_anchor(root / "active-generation.json")
        elif args.command == "pending":
            value = read_pending(root / "pending-generation.json")
        elif args.command == "begin":
            value = begin(root, args.generation_id)
        else:
            value = commit(root, args.generation_id, args.manifest_sha256, args.expected_current)
        print(json.dumps(value, separators=(",", ":"), sort_keys=True))
        return 0
    except (AnchorError, OSError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
