#!/usr/bin/env python3
"""Bounded transaction and generation verification for SecureSandbox PKI v2."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


SCHEMA = 2
MAX_JSON_BYTES = 32 * 1024
MAX_TRANSACTIONS = 16
MAX_GENERATIONS = 8
PHASES = (
    "prepared",
    "research_dual_trust",
    "gateway_dual_trust",
    "research_new_clients",
    "gateway_new_only",
    "committed",
)
IDENTITIES = ("ca", "server", "broker", "telemetry", "conversation")
HEX64 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


class LifecycleError(RuntimeError):
    """A stable fail-closed lifecycle error."""


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_generation_id(value: str) -> str:
    if not UUID4.fullmatch(value):
        raise LifecycleError("invalid_generation_id")
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise LifecycleError("invalid_generation_id")
    return value


def _bounded_regular(path: Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise LifecycleError("file_missing") from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise LifecycleError("untrusted_file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise LifecycleError("file_size_invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise LifecycleError("file_changed_during_read")
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        value = bytes(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(value) > maximum or (after.st_dev, after.st_ino, after.st_size) != (
        info.st_dev,
        info.st_ino,
        info.st_size,
    ):
        raise LifecycleError("file_changed_during_read")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_bounded_regular(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleError("invalid_json") from error
    if not isinstance(value, dict):
        raise LifecycleError("invalid_json")
    return value


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary: Path | None = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
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


def _openssl(openssl: str, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        [openssl, *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise LifecycleError("certificate_validation_failed")
    return result.stdout


def certificate_metadata(path: Path, openssl: str = "/usr/bin/openssl") -> dict[str, Any]:
    pem = _bounded_regular(path, 64 * 1024)
    der = _openssl(openssl, "x509", "-outform", "DER", input_bytes=pem)
    public_pem = _openssl(openssl, "x509", "-pubkey", "-noout", input_bytes=pem)
    public_der = _openssl(openssl, "pkey", "-pubin", "-outform", "DER", input_bytes=public_pem)
    end_line = _openssl(openssl, "x509", "-enddate", "-noout", input_bytes=pem).decode("ascii").strip()
    start_line = _openssl(openssl, "x509", "-startdate", "-noout", input_bytes=pem).decode("ascii").strip()
    serial_line = _openssl(openssl, "x509", "-serial", "-noout", input_bytes=pem).decode("ascii").strip()
    if not end_line.startswith("notAfter=") or not start_line.startswith("notBefore="):
        raise LifecycleError("certificate_expiry_invalid")
    try:
        expires = dt.datetime.strptime(end_line[9:], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        starts = dt.datetime.strptime(start_line[10:], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise LifecycleError("certificate_expiry_invalid") from error
    if not serial_line.startswith("serial=") or not re.fullmatch(r"[0-9A-Fa-f]+", serial_line[7:]):
        raise LifecycleError("certificate_serial_invalid")
    return {
        "fingerprint_sha256": sha256_bytes(der),
        "spki_sha256": sha256_bytes(public_der),
        "serial_hex": serial_line[7:].lower(),
        "not_before": int(starts.timestamp()),
        "not_after": int(expires.timestamp()),
    }


def build_manifest(generation_id: str, certificates: dict[str, Path], openssl: str) -> dict[str, Any]:
    validate_generation_id(generation_id)
    if set(certificates) != set(IDENTITIES):
        raise LifecycleError("identity_set_invalid")
    identities = {name: certificate_metadata(certificates[name], openssl) for name in IDENTITIES}
    fingerprints = [identities[name]["fingerprint_sha256"] for name in IDENTITIES]
    public_keys = [identities[name]["spki_sha256"] for name in IDENTITIES]
    serials = [identities[name]["serial_hex"] for name in IDENTITIES]
    if (len(set(fingerprints)) != len(fingerprints) or len(set(public_keys)) != len(public_keys)
            or len(set(serials)) != len(serials)):
        raise LifecycleError("identity_not_unique")
    created = int(time.time())
    if any(identities[name]["not_before"] > created + 300 for name in IDENTITIES):
        raise LifecycleError("certificate_not_yet_valid")
    if identities["ca"]["not_after"] > created + 45 * 86400 + 300:
        raise LifecycleError("ca_validity_too_long")
    if any(identities[name]["not_after"] > created + 21 * 86400 + 300 for name in IDENTITIES if name != "ca"):
        raise LifecycleError("leaf_validity_too_long")
    if min(item["not_after"] for item in identities.values()) < created + 7 * 86400:
        raise LifecycleError("certificate_validity_too_short")
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "generation_id": generation_id,
        "created_at": created,
        "minimum_not_after": min(item["not_after"] for item in identities.values()),
        "identities": identities,
    }
    body["manifest_sha256"] = sha256_bytes(canonical_bytes(body))
    return validate_manifest(body)


def validate_manifest(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {
        "schema", "generation_id", "created_at", "minimum_not_after", "identities", "manifest_sha256"
    }:
        raise LifecycleError("manifest_schema_invalid")
    if value["schema"] != SCHEMA:
        raise LifecycleError("manifest_schema_invalid")
    validate_generation_id(value["generation_id"])
    if not isinstance(value["created_at"], int) or isinstance(value["created_at"], bool):
        raise LifecycleError("manifest_time_invalid")
    if not isinstance(value["minimum_not_after"], int) or isinstance(value["minimum_not_after"], bool):
        raise LifecycleError("manifest_time_invalid")
    identities = value["identities"]
    if not isinstance(identities, dict) or set(identities) != set(IDENTITIES):
        raise LifecycleError("identity_set_invalid")
    for name in IDENTITIES:
        item = identities[name]
        if not isinstance(item, dict) or set(item) != {"fingerprint_sha256", "spki_sha256", "serial_hex", "not_before", "not_after"}:
            raise LifecycleError("identity_schema_invalid")
        if not isinstance(item["fingerprint_sha256"], str) or not HEX64.fullmatch(item["fingerprint_sha256"]):
            raise LifecycleError("identity_hash_invalid")
        if not isinstance(item["spki_sha256"], str) or not HEX64.fullmatch(item["spki_sha256"]):
            raise LifecycleError("identity_hash_invalid")
        if not isinstance(item["serial_hex"], str) or not re.fullmatch(r"[0-9a-f]+", item["serial_hex"]):
            raise LifecycleError("identity_serial_invalid")
        if (not isinstance(item["not_before"], int) or isinstance(item["not_before"], bool)
                or not isinstance(item["not_after"], int) or isinstance(item["not_after"], bool)
                or item["not_before"] >= item["not_after"]):
            raise LifecycleError("manifest_time_invalid")
    if value["minimum_not_after"] != min(identities[name]["not_after"] for name in IDENTITIES):
        raise LifecycleError("minimum_expiry_mismatch")
    if len({identities[name]["serial_hex"] for name in IDENTITIES}) != len(IDENTITIES):
        raise LifecycleError("identity_not_unique")
    supplied = value["manifest_sha256"]
    if not isinstance(supplied, str) or not HEX64.fullmatch(supplied):
        raise LifecycleError("manifest_hash_invalid")
    body = dict(value)
    del body["manifest_sha256"]
    if not __import__("hmac").compare_digest(supplied, sha256_bytes(canonical_bytes(body))):
        raise LifecycleError("manifest_hash_mismatch")
    return value


class TransactionStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.transactions = root / "transactions"
        self.generations = root / "generations"
        self.lock_path = root / ".lock"

    def prepare(self) -> None:
        old_umask = os.umask(0o077)
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            for path in (self.root, self.transactions, self.generations):
                if path != self.root:
                    path.mkdir(mode=0o700, exist_ok=True)
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    raise LifecycleError("state_directory_untrusted")
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            lock_info = os.fstat(descriptor)
            os.close(descriptor)
            if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid()
                    or stat.S_IMODE(lock_info.st_mode) != 0o600):
                raise LifecycleError("state_lock_untrusted")
            self._bounded_entries(self.transactions, MAX_TRANSACTIONS)
            self._bounded_entries(self.generations, MAX_GENERATIONS)
        finally:
            os.umask(old_umask)

    @staticmethod
    def _bounded_entries(path: Path, maximum: int) -> list[Path]:
        entries = list(path.iterdir())
        if len(entries) > maximum:
            raise LifecycleError("state_entry_limit_exceeded")
        if any(entry.is_symlink() for entry in entries):
            raise LifecycleError("state_entry_untrusted")
        return entries

    def locked(self):
        self.prepare()
        handle = self.lock_path.open("r+b")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def path(self, generation_id: str) -> Path:
        return self.transactions / f"{validate_generation_id(generation_id)}.json"

    def create(self, generation_id: str, manifest_sha256: str) -> dict[str, Any]:
        validate_generation_id(generation_id)
        if not HEX64.fullmatch(manifest_sha256):
            raise LifecycleError("manifest_hash_invalid")
        path = self.path(generation_id)
        if path.exists() or path.is_symlink():
            raise LifecycleError("transaction_exists")
        if len(self._bounded_entries(self.transactions, MAX_TRANSACTIONS)) >= MAX_TRANSACTIONS:
            raise LifecycleError("transaction_limit_exceeded")
        now = int(time.time())
        value = {
            "schema": SCHEMA,
            "generation_id": generation_id,
            "manifest_sha256": manifest_sha256,
            "phase": "prepared",
            "created_at": now,
            "updated_at": now,
        }
        value["record_sha256"] = sha256_bytes(canonical_bytes(value))
        atomic_write(path, canonical_bytes(value), 0o600)
        return value

    def load(self, generation_id: str) -> dict[str, Any]:
        value = load_json(self.path(generation_id))
        if set(value) != {"schema", "generation_id", "manifest_sha256", "phase", "created_at", "updated_at", "record_sha256"}:
            raise LifecycleError("transaction_schema_invalid")
        if value["schema"] != SCHEMA or value["generation_id"] != generation_id:
            raise LifecycleError("transaction_schema_invalid")
        if value["phase"] not in PHASES or not HEX64.fullmatch(str(value["manifest_sha256"])):
            raise LifecycleError("transaction_schema_invalid")
        if any(not isinstance(value[key], int) or isinstance(value[key], bool) for key in ("created_at", "updated_at")):
            raise LifecycleError("transaction_schema_invalid")
        supplied = value["record_sha256"]
        body = dict(value)
        del body["record_sha256"]
        if not isinstance(supplied, str) or not HEX64.fullmatch(supplied) or not __import__("hmac").compare_digest(
            supplied, sha256_bytes(canonical_bytes(body))
        ):
            raise LifecycleError("transaction_hash_mismatch")
        return value

    def advance(self, generation_id: str, expected: str, target: str) -> dict[str, Any]:
        if expected not in PHASES or target not in PHASES:
            raise LifecycleError("phase_invalid")
        current = self.load(generation_id)
        current_index = PHASES.index(current["phase"])
        target_index = PHASES.index(target)
        expected_index = PHASES.index(expected)
        if current_index >= target_index:
            return current
        if current_index != expected_index or target_index != expected_index + 1:
            raise LifecycleError("phase_transition_invalid")
        current["phase"] = target
        current["updated_at"] = max(int(time.time()), current["updated_at"])
        del current["record_sha256"]
        current["record_sha256"] = sha256_bytes(canonical_bytes(current))
        atomic_write(self.path(generation_id), canonical_bytes(current), 0o600)
        return current

    def prune_committed(self, active_generation: str, keep: int = 2) -> list[str]:
        """Remove only oldest committed, inactive generations and their journals."""
        validate_generation_id(active_generation)
        if not 2 <= keep <= MAX_GENERATIONS:
            raise LifecycleError("retention_invalid")
        entries = self._bounded_entries(self.generations, MAX_GENERATIONS)
        committed: list[tuple[int, str, Path]] = []
        for generation in entries:
            if not generation.is_dir() or generation.is_symlink():
                raise LifecycleError("state_entry_untrusted")
            generation_id = validate_generation_id(generation.name)
            transaction = self.load(generation_id)
            if transaction["phase"] == "committed" and generation_id != active_generation:
                committed.append((transaction["updated_at"], generation_id, generation))
        committed.sort()
        removable = committed[:max(0, len(entries) - keep)]
        removed: list[str] = []
        for _, generation_id, generation in removable:
            shutil.rmtree(generation)
            self.path(generation_id).unlink()
            removed.append(generation_id)
        if removed:
            for directory in (self.generations, self.transactions):
                handle = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(handle)
                finally:
                    os.close(handle)
        return removed


def expiry_event(manifest: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    validate_manifest(manifest)
    current = int(time.time()) if now is None else now
    remaining = manifest["minimum_not_after"] - current
    status = "critical" if remaining <= 172800 else "warning" if remaining <= 604800 else "ok"
    return {
        "event": "pki_expiry_status",
        "generation_id": manifest["generation_id"],
        "minimum_not_after": manifest["minimum_not_after"],
        "remaining_seconds": remaining,
        "status": status,
    }


def activation_event(manifest: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    event = expiry_event(manifest, now)
    event["event"] = "pki_generation_activated"
    return event


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", default="/var/lib/secure-sandbox/pki-lifecycle")
    parser.add_argument("--openssl", default="/usr/bin/openssl")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-manifest")
    validate.add_argument("manifest")
    expiry = sub.add_parser("expiry")
    expiry.add_argument("manifest", nargs="?", default="/etc/secure-sandbox/pki-generation.json")
    create = sub.add_parser("create-transaction")
    create.add_argument("generation_id")
    create.add_argument("manifest_sha256")
    advance = sub.add_parser("advance")
    advance.add_argument("generation_id")
    advance.add_argument("expected", choices=PHASES)
    advance.add_argument("target", choices=PHASES)
    args = parser.parse_args()
    try:
        if args.command == "validate-manifest":
            value = validate_manifest(load_json(Path(args.manifest)))
        elif args.command == "expiry":
            value = expiry_event(load_json(Path(args.manifest)))
        else:
            store = TransactionStore(Path(args.state_root))
            with store.locked():
                value = store.create(args.generation_id, args.manifest_sha256) if args.command == "create-transaction" else store.advance(args.generation_id, args.expected, args.target)
        print(json.dumps(value, separators=(",", ":"), sort_keys=True))
        return 0
    except (LifecycleError, OSError) as error:
        print(json.dumps({"error": str(error)}, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
