#!/usr/bin/env python3
"""Explicit, non-inferential legacy session-to-harness binding migration."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT))

from shared.harness_runtime_binding import (  # noqa: E402
    MIGRATION_AUTHORIZATION_SCHEMA, MIGRATION_PLAN_SCHEMA,
    MIGRATION_RECEIPT_SCHEMA, SESSION_SCHEMA, container_fields, validate_binding,
)


UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
EVIDENCE_SCHEMA = "secure-sandbox-legacy-harness-session-attestation-v1"
MAX_BYTES = 1024 * 1024
MAX_SECONDS = 300
MAX_EVIDENCE_AGE = 86400


class MigrationError(RuntimeError):
    """Stable migration rejection."""


def canonical(value: object) -> bytes:
    return (json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_catalog_parent(path: Path) -> None:
    info = path.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_nlink < 2):
        raise MigrationError("session_catalog_parent_untrusted")


def self_digest(value: dict[str, Any], field: str, label: str) -> str:
    supplied = value.get(field)
    body = dict(value); body.pop(field, None)
    if not isinstance(supplied, str) or supplied != digest(body):
        raise MigrationError(f"{label}_digest_mismatch")
    return supplied


def read_catalog(path: Path) -> tuple[dict[str, Any], bytes]:
    validate_catalog_parent(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1 or not 0 < info.st_size <= MAX_BYTES):
        raise MigrationError("session_catalog_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError("session_catalog_invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise MigrationError("session_catalog_noncanonical")
    if value.get("schema") not in {
        "secure-sandbox-session-runs-v1", "secure-sandbox-session-runs-v2",
        "secure-sandbox-session-runs-v3", SESSION_SCHEMA,
    } or not isinstance(value.get("sessions"), dict):
        raise MigrationError("session_catalog_invalid")
    return value, raw


def validate_evidence(value: object, session_id: str, record: dict[str, Any],
                      *, now: int) -> dict[str, Any]:
    expected = {"schema", "attestation_id", "session_id", "observed_run_ids",
                "legacy_executable_sha256", "observer", "observed_at", "status",
                "evidence_sha256"}
    if not isinstance(value, dict) or set(value) != expected:
        raise MigrationError("legacy_attestation_invalid")
    if (value["schema"] != EVIDENCE_SCHEMA or value["session_id"] != session_id
            or UUID4.fullmatch(str(value["attestation_id"])) is None
            or value["observer"] != "secure-sandbox-legacy-harness-attestor-v1"
            or value["status"] != "attested"
            or not integer(value["observed_at"])
            or not now - MAX_EVIDENCE_AGE <= value["observed_at"] <= now
            or SHA256.fullmatch(str(value["legacy_executable_sha256"])) is None):
        raise MigrationError("legacy_attestation_invalid")
    run_ids = record.get("run_ids", [])
    if (not isinstance(value["observed_run_ids"], list)
            or value["observed_run_ids"] != run_ids):
        raise MigrationError("legacy_attestation_run_set_mismatch")
    self_digest(value, "evidence_sha256", "legacy_attestation")
    return value


def create_plan(catalog_path: Path, session_id: str, binding_value: object,
                evidence_value: object, *, now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    catalog, raw = read_catalog(catalog_path)
    record = catalog["sessions"].get(session_id)
    if not isinstance(record, dict):
        raise MigrationError("session_not_found")
    if "harness_generation_id" in record:
        raise MigrationError("session_already_harness_bound")
    binding = validate_binding(binding_value)
    evidence = validate_evidence(evidence_value, session_id, record, now=now)
    if evidence["legacy_executable_sha256"] != binding["harness_executable_sha256"]:
        raise MigrationError("legacy_executable_binding_mismatch")
    body = {
        "schema": MIGRATION_PLAN_SCHEMA, "plan_id": str(uuid.uuid4()),
        "session_id": session_id, "catalog_sha256": hashlib.sha256(raw).hexdigest(),
        "session_record_sha256": digest(record), "binding": binding,
        "evidence_sha256": evidence["evidence_sha256"],
        "created_at": now, "expires_at": now + MAX_SECONDS,
    }
    return {**body, "plan_sha256": digest(body)}


def validate_authorization(value: object, plan: dict[str, Any], now: int) -> dict[str, Any]:
    expected = {"schema", "authorization_id", "plan_id", "plan_sha256", "method",
                "password_fallback", "authorized_at", "expires_at",
                "requesting_agent_sha256", "requesting_session_sha256",
                "authorization_sha256"}
    if not isinstance(value, dict) or set(value) != expected:
        raise MigrationError("migration_authorization_invalid")
    if (value["schema"] != MIGRATION_AUTHORIZATION_SCHEMA
            or UUID4.fullmatch(str(value["authorization_id"])) is None
            or value["plan_id"] != plan["plan_id"]
            or value["plan_sha256"] != plan["plan_sha256"]
            or value["method"] != "touch-id" or value["password_fallback"] is not False
            or not integer(value["authorized_at"])
            or not integer(value["expires_at"])
            or not value["authorized_at"] <= now < value["expires_at"] <= plan["expires_at"]
            or any(SHA256.fullmatch(str(value[name])) is None for name in (
                "requesting_agent_sha256", "requesting_session_sha256"))):
        raise MigrationError("migration_authorization_invalid")
    self_digest(value, "authorization_sha256", "migration_authorization")
    return value


def atomic_catalog(path: Path, value: dict[str, Any]) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".session-runs.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600); handle.write(canonical(value))
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def apply_plan(catalog_path: Path, plan: object, authorization: object,
               evidence: object, *, now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    expected_plan = {
        "schema", "plan_id", "session_id", "catalog_sha256",
        "session_record_sha256", "binding", "evidence_sha256", "created_at",
        "expires_at", "plan_sha256",
    }
    if (not isinstance(plan, dict) or set(plan) != expected_plan
            or plan.get("schema") != MIGRATION_PLAN_SCHEMA):
        raise MigrationError("migration_plan_invalid")
    if (UUID4.fullmatch(str(plan.get("plan_id"))) is None
            or UUID4.fullmatch(str(plan.get("session_id"))) is None
            or not integer(plan.get("created_at"))
            or not integer(plan.get("expires_at"))
            or any(SHA256.fullmatch(str(plan.get(name))) is None for name in (
                "catalog_sha256", "session_record_sha256", "evidence_sha256"))
            or not plan["created_at"] <= now < plan["expires_at"]
            or plan["expires_at"] - plan["created_at"] != MAX_SECONDS):
        raise MigrationError("migration_plan_invalid")
    self_digest(plan, "plan_sha256", "migration_plan")
    binding = validate_binding(plan.get("binding"))
    validate_authorization(authorization, plan, now)
    lock_path = catalog_path.parent / ".session-runs.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(descriptor)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid()
                or stat.S_IMODE(lock_info.st_mode) != 0o600 or lock_info.st_nlink != 1):
            raise MigrationError("session_catalog_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        catalog, raw = read_catalog(catalog_path)
        if hashlib.sha256(raw).hexdigest() != plan.get("catalog_sha256"):
            raise MigrationError("session_catalog_changed")
        record = catalog["sessions"].get(plan.get("session_id"))
        if not isinstance(record, dict) or digest(record) != plan.get("session_record_sha256"):
            raise MigrationError("session_record_changed")
        attestation = validate_evidence(evidence, plan["session_id"], record, now=now)
        if attestation["evidence_sha256"] != plan.get("evidence_sha256"):
            raise MigrationError("legacy_attestation_changed")
        if attestation["legacy_executable_sha256"] != binding["harness_executable_sha256"]:
            raise MigrationError("legacy_executable_binding_mismatch")
        if "harness_generation_id" in record:
            raise MigrationError("session_already_harness_bound")
        catalog["sessions"][plan["session_id"]] = {
            **record, **container_fields(binding),
        }
        catalog["schema"] = SESSION_SCHEMA
        atomic_catalog(catalog_path, catalog)
    finally:
        os.close(descriptor)
    body = {
        "schema": MIGRATION_RECEIPT_SCHEMA, "receipt_id": str(uuid.uuid4()),
        "plan_id": plan["plan_id"], "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "session_id": plan["session_id"],
        "harness_generation_id": binding["harness_generation_id"],
        "catalog_sha256": hashlib.sha256(canonical(catalog)).hexdigest(),
        "migrated_at": now, "status": "committed",
    }
    return {**body, "receipt_sha256": digest(body)}


def load_json(path: Path) -> object:
    with path.open("r", encoding="ascii") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan"); plan.add_argument("catalog", type=Path)
    plan.add_argument("session_id"); plan.add_argument("binding", type=Path)
    plan.add_argument("evidence", type=Path)
    args = parser.parse_args()
    result = create_plan(args.catalog, args.session_id, load_json(args.binding),
                         load_json(args.evidence))
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MigrationError, OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error), "status": "rejected"},
                         separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
