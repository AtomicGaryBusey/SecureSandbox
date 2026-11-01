#!/usr/bin/env python3
"""Protected immutable harness generations and fail-closed activation.

This module owns storage and selector integrity.  It never downloads a release,
qualifies a candidate, or grants an authorization.  Callers must provide exact
provenance, qualification, adapter, and Touch ID receipts produced by their
respective trusted components.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from privileged_workflow import WorkflowError, WorkflowStore


PLAN_SCHEMA = "secure-sandbox-harness-activation-plan-v1"
MANAGEMENT_PLAN_SCHEMA = "secure-sandbox-harness-management-plan-v1"
AUTHORIZATION_SCHEMA = "secure-sandbox-harness-touchid-authorization-v1"
QUALIFICATION_SCHEMA = "secure-sandbox-harness-disposable-qualification-v1"
ADAPTER_SCHEMA = "secure-sandbox-harness-adapter-projection-v1"
CATALOG_SCHEMA = "secure-sandbox-harness-catalog-v1"
RECORD_SCHEMA = "secure-sandbox-harness-generation-v1"
SELECTOR_SCHEMA = "secure-sandbox-active-harness-selector-v1"
FLOOR_SCHEMA = "secure-sandbox-harness-admission-floor-v1"
FENCE_SCHEMA = "secure-sandbox-harness-admission-fence-v1"
JOURNAL_SCHEMA = "secure-sandbox-harness-activation-journal-v1"
HEALTH_SCHEMA = "secure-sandbox-harness-health-receipt-v1"
RECEIPT_SCHEMA = "secure-sandbox-harness-generation-receipt-v1"
STATUS_SCHEMA = "secure-sandbox-harness-generation-status-v1"
REFERENCE_SCHEMA = "secure-sandbox-harness-session-reference-readback-v1"
WORKFLOW = "harness-activation"

MAX_JSON_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_GENERATIONS = 32
MAX_RECEIPTS = 256
MAX_PLAN_SECONDS = 300
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ID_RE = re.compile(r"[a-z][a-z0-9-]{0,62}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
PLATFORM_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
UUID4_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
RELEASE_TEMP_RE = re.compile(
    r"\.([0-9a-f]{64})\.new-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"
)
ZERO_SHA256 = "0" * 64


class GenerationStoreError(RuntimeError):
    """Stable, content-free generation-store failure."""


class HealthProbe(Protocol):
    def probe(self, plan: dict[str, Any], executable: Path) -> dict[str, Any]:
        """Run the fixed, synthetic, credential-free production adapter probe."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise GenerationStoreError("json_not_canonicalizable") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_value(value: object) -> str:
    return sha256_bytes(canonical_bytes(value))


def _exact(value: dict[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise GenerationStoreError(f"{label}_fields_invalid")


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise GenerationStoreError(f"{label}_invalid")
    return value


def _uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4_RE.fullmatch(value) is None:
        raise GenerationStoreError(f"{label}_invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise GenerationStoreError(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise GenerationStoreError(f"{label}_invalid")
    return value


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise GenerationStoreError(f"{label}_invalid")
    return value


def _integer(value: object, label: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise GenerationStoreError(f"{label}_invalid")
    return value


def _trusted_directory(path: Path, uid: int, mode: int, *, create: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise GenerationStoreError("directory_missing")
        path.mkdir(mode=mode)
        info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode):
        raise GenerationStoreError("directory_untrusted")


def _read_regular(path: Path, uid: int, maximum: int, mode: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise GenerationStoreError("file_missing") from error
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode or not 0 < before.st_size <= maximum):
        raise GenerationStoreError("file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise GenerationStoreError("file_changed")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (len(data) > maximum or (after.st_dev, after.st_ino, after.st_size)
            != (before.st_dev, before.st_ino, before.st_size)):
        raise GenerationStoreError("file_changed")
    return bytes(data)


def _read_json(path: Path, uid: int, mode: int = 0o600) -> dict[str, Any]:
    raw = _read_regular(path, uid, MAX_JSON_BYTES, mode)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GenerationStoreError("json_invalid") from error
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise GenerationStoreError("json_noncanonical")
    return value


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                         getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.parent / f".{path.name}.new-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GenerationStoreError("write_failed")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def write_new_file(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GenerationStoreError("write_failed")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _self_digest(value: dict[str, Any], field: str, label: str) -> str:
    supplied = _sha(value.get(field), field)
    body = dict(value)
    del body[field]
    if not hmac.compare_digest(supplied, sha256_value(body)):
        raise GenerationStoreError(f"{label}_digest_mismatch")
    return supplied


def validate_qualification(value: object, now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("qualification_invalid")
    _exact(value, {
        "schema", "qualification_id", "generation_id", "artifact_sha256",
        "manifest_sha256", "adapter_id", "adapter_sha256", "suite_sha256",
        "policy_sha256", "observer", "observation_set_sha256", "qualified_at",
        "expires_at", "synthetic", "status", "authority", "qualification_sha256",
    }, "qualification")
    if (value["schema"] != QUALIFICATION_SCHEMA
            or value["observer"] != "secure-sandbox-disposable-supervisor-v1"
            or value["status"] != "qualified"
            or value["authority"] != "qualification-evidence-only"
            or value["synthetic"] is not False):
        raise GenerationStoreError("qualification_not_admissible")
    _uuid(value["qualification_id"], "qualification_id")
    for name in ("generation_id", "artifact_sha256", "manifest_sha256", "adapter_sha256",
                 "suite_sha256", "policy_sha256", "observation_set_sha256"):
        _sha(value[name], name)
    _id(value["adapter_id"], "adapter_id")
    qualified = _integer(value["qualified_at"], "qualified_at", 0, 2**63 - 1)
    expires = _integer(value["expires_at"], "qualification_expires_at", 0, 2**63 - 1)
    if qualified > now + 300 or not now < expires or expires - qualified > 31 * 86400:
        raise GenerationStoreError("qualification_time_invalid")
    _self_digest(value, "qualification_sha256", "qualification")
    return value


def validate_adapter(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("adapter_invalid")
    _exact(value, {
        "schema", "adapter_id", "adapter_sha256", "projection_sha256", "harness_id",
        "executable_name", "protocol", "policy_sha256", "health_probe_sha256", "authority",
    }, "adapter")
    if (value["schema"] != ADAPTER_SCHEMA or value["authority"] != "none"
            or value["executable_name"] != "harness"
            or value["protocol"] != "secure-sandbox-neutral-harness-v1"):
        raise GenerationStoreError("adapter_invalid")
    _id(value["adapter_id"], "adapter_id")
    _id(value["harness_id"], "harness_id")
    for name in ("adapter_sha256", "policy_sha256", "health_probe_sha256"):
        _sha(value[name], name)
    _self_digest(value, "projection_sha256", "adapter")
    return value


def validate_verification(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("verification_invalid")
    required = {
        "action", "observed_at", "receipt_id", "schema", "status",
        "artifact_sha256", "envelope_sha256", "evidence_sha256", "generation_id",
        "manifest_sha256", "note", "policy_sha256",
    }
    _exact(value, required, "verification")
    if (value["schema"] != "secure-sandbox-harness-lifecycle-receipt-v1"
            or value["action"] != "verify"
            or value["status"] != "artifact_and_evidence_bindings_verified"
            or value["note"] != "not_admitted_not_executable"):
        raise GenerationStoreError("verification_invalid")
    _uuid(value["receipt_id"], "verification_receipt_id")
    _integer(value["observed_at"], "verification_observed_at", 0, 2**63 - 1)
    for name in ("artifact_sha256", "envelope_sha256", "generation_id",
                 "manifest_sha256", "policy_sha256"):
        _sha(value[name], name)
    evidence = value["evidence_sha256"]
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 32:
        raise GenerationStoreError("verification_evidence_invalid")
    for item in evidence:
        _sha(item, "verification_evidence_sha256")
    return value


def validate_plan(value: object, now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("plan_invalid")
    fields = {
        "schema", "plan_id", "transaction_id", "action_ids", "operation",
        "created_at", "expires_at", "candidate", "current", "catalog_sha256",
        "selector_sha256", "floor_sha256", "verification_sha256",
        "qualification_sha256", "adapter_projection_sha256", "plan_sha256",
    }
    _exact(value, fields, "plan")
    if value["schema"] != PLAN_SCHEMA or value["operation"] not in {"activate", "rollback"}:
        raise GenerationStoreError("plan_schema_invalid")
    _uuid(value["plan_id"], "plan_id")
    _uuid(value["transaction_id"], "transaction_id")
    actions = value["action_ids"]
    if not isinstance(actions, dict):
        raise GenerationStoreError("plan_action_ids_invalid")
    _exact(actions, {"prepared", "authorized", "activated", "verified", "committed",
                     "restored"}, "plan_action_ids")
    for name, action in actions.items():
        _uuid(action, f"{name}_action_id")
    created = _integer(value["created_at"], "created_at", 0, 2**63 - 1)
    expires = _integer(value["expires_at"], "expires_at", 0, 2**63 - 1)
    if created > now + 300 or not now < expires <= created + MAX_PLAN_SECONDS:
        raise GenerationStoreError("plan_time_invalid")
    candidate = value["candidate"]
    if not isinstance(candidate, dict):
        raise GenerationStoreError("candidate_invalid")
    _exact(candidate, {
        "generation_id", "harness_id", "vendor_id", "version", "platform",
        "release_sequence", "artifact_sha256", "artifact_size", "manifest_sha256",
        "policy_sha256", "adapter_id", "adapter_sha256", "suite_sha256",
        "health_probe_sha256", "qualification_expires_at",
    }, "candidate")
    for name in ("generation_id", "artifact_sha256", "manifest_sha256", "policy_sha256",
                 "adapter_sha256", "suite_sha256"):
        _sha(candidate[name], name)
    _sha(candidate["health_probe_sha256"], "health_probe_sha256")
    for name in ("harness_id", "vendor_id", "adapter_id"):
        _id(candidate[name], name)
    if (not isinstance(candidate["version"], str) or VERSION_RE.fullmatch(candidate["version"]) is None
            or not isinstance(candidate["platform"], str)
            or PLATFORM_RE.fullmatch(candidate["platform"]) is None):
        raise GenerationStoreError("candidate_identity_invalid")
    _integer(candidate["release_sequence"], "release_sequence", 1, 2**63 - 1)
    _integer(candidate["artifact_size"], "artifact_size", 1, MAX_ARTIFACT_BYTES)
    if _integer(candidate["qualification_expires_at"], "qualification_expires_at", 1, 2**63 - 1) < expires:
        raise GenerationStoreError("qualification_expires_before_plan")
    current = value["current"]
    if not isinstance(current, dict):
        raise GenerationStoreError("current_invalid")
    _exact(current, {"generation_id", "selector_epoch"}, "current")
    if current["generation_id"] is not None:
        _sha(current["generation_id"], "current_generation_id")
    _integer(current["selector_epoch"], "selector_epoch", 0, 2**63 - 1)
    for name in ("catalog_sha256", "selector_sha256", "floor_sha256", "verification_sha256",
                 "qualification_sha256", "adapter_projection_sha256"):
        _sha(value[name], name)
    _self_digest(value, "plan_sha256", "plan")
    if len(canonical_bytes(value)) > MAX_JSON_BYTES:
        raise GenerationStoreError("plan_too_large")
    return value


def validate_authorization(value: object, plan: dict[str, Any], now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("authorization_invalid")
    _exact(value, {
        "schema", "authorization_id", "plan_id", "plan_sha256", "transaction_id",
        "operation", "method", "password_fallback", "authorized_at", "expires_at",
        "requesting_agent_sha256", "requesting_session_sha256", "authorization_sha256",
    }, "authorization")
    if (value["schema"] != AUTHORIZATION_SCHEMA or value["plan_id"] != plan["plan_id"]
            or value["plan_sha256"] != plan["plan_sha256"]
            or value["transaction_id"] != plan["transaction_id"]
            or value["operation"] != plan["operation"]
            or value["method"] != "touch-id" or value["password_fallback"] is not False):
        raise GenerationStoreError("authorization_binding_invalid")
    _uuid(value["authorization_id"], "authorization_id")
    authorized = _integer(value["authorized_at"], "authorized_at", 0, 2**63 - 1)
    expires = _integer(value["expires_at"], "authorization_expires_at", 0, 2**63 - 1)
    if authorized > now + 300 or not now < expires <= plan["expires_at"]:
        raise GenerationStoreError("authorization_time_invalid")
    _sha(value["requesting_agent_sha256"], "requesting_agent_sha256")
    _sha(value["requesting_session_sha256"], "requesting_session_sha256")
    _self_digest(value, "authorization_sha256", "authorization")
    return value


def validate_management_plan(value: object, now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("management_plan_invalid")
    _exact(value, {
        "schema", "plan_id", "transaction_id", "action_ids", "operation",
        "generation_id", "reason_sha256", "reference_sha256", "created_at", "expires_at",
        "catalog_sha256", "selector_sha256", "floor_sha256", "plan_sha256",
    }, "management_plan")
    if value["schema"] != MANAGEMENT_PLAN_SCHEMA or value["operation"] not in {"retire", "revoke"}:
        raise GenerationStoreError("management_plan_schema_invalid")
    _uuid(value["plan_id"], "plan_id"); _uuid(value["transaction_id"], "transaction_id")
    actions = value["action_ids"]
    if not isinstance(actions, dict):
        raise GenerationStoreError("management_action_ids_invalid")
    _exact(actions, {"prepared", "authorized", "activated", "verified", "committed", "restored"},
           "management_action_ids")
    for name, action in actions.items():
        _uuid(action, f"{name}_action_id")
    _sha(value["generation_id"], "generation_id")
    for name in ("reason_sha256", "reference_sha256", "catalog_sha256", "selector_sha256",
                 "floor_sha256"):
        _sha(value[name], name)
    created = _integer(value["created_at"], "created_at", 0, 2**63 - 1)
    expires = _integer(value["expires_at"], "expires_at", 0, 2**63 - 1)
    if created > now + 300 or not now < expires <= created + MAX_PLAN_SECONDS:
        raise GenerationStoreError("management_plan_time_invalid")
    _self_digest(value, "plan_sha256", "management_plan")
    return value


def validate_reference_readback(value: object, now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("reference_readback_invalid")
    _exact(value, {"schema", "generation_id", "active_run_count", "resumable_session_count",
                   "observed_at", "observer", "reference_sha256"}, "reference_readback")
    if (value["schema"] != REFERENCE_SCHEMA
            or value["observer"] != "secure-sandbox-session-catalog-readback-v1"):
        raise GenerationStoreError("reference_readback_invalid")
    _sha(value["generation_id"], "generation_id")
    _integer(value["active_run_count"], "active_run_count", 0, 2**31 - 1)
    _integer(value["resumable_session_count"], "resumable_session_count", 0, 2**31 - 1)
    observed = _integer(value["observed_at"], "observed_at", 0, 2**63 - 1)
    if not now - 30 <= observed <= now + 5:
        raise GenerationStoreError("reference_readback_stale")
    _self_digest(value, "reference_sha256", "reference_readback")
    return value


def validate_health(value: object, plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationStoreError("health_invalid")
    _exact(value, {
        "schema", "plan_id", "plan_sha256", "generation_id", "artifact_sha256",
        "adapter_sha256", "health_probe_sha256", "observer", "synthetic",
        "production_credential_present", "network_attempts", "status", "health_sha256",
    }, "health")
    if (value["schema"] != HEALTH_SCHEMA or value["plan_id"] != plan["plan_id"]
            or value["plan_sha256"] != plan["plan_sha256"]
            or value["generation_id"] != plan["candidate"]["generation_id"]
            or value["artifact_sha256"] != plan["candidate"]["artifact_sha256"]
            or value["adapter_sha256"] != plan["candidate"]["adapter_sha256"]
            or value["health_probe_sha256"] != plan["candidate"]["health_probe_sha256"]
            or value["observer"] != "secure-sandbox-fixed-health-supervisor-v1"
            or value["synthetic"] is not True
            or value["production_credential_present"] is not False
            or value["network_attempts"] != [] or value["status"] != "passed"):
        raise GenerationStoreError("health_rejected")
    _self_digest(value, "health_sha256", "health")
    return value


class GenerationStore:
    """Root-owned immutable releases plus transactional selector state."""

    def __init__(self, release_root: Path, state_root: Path, *, uid: int | None = None,
                 now: Callable[[], int] | None = None) -> None:
        self.release_root = release_root
        self.releases = release_root / "releases"
        self.state_root = state_root
        self.receipts = state_root / "receipts"
        self.journals = state_root / "journals"
        self.catalog_path = state_root / "catalog.json"
        self.selector_path = state_root / "selector.json"
        self.floor_path = state_root / "admission-floor.json"
        self.fence_path = state_root / "activation-fence.json"
        self.lock_path = state_root / ".lock"
        self.workflow = WorkflowStore(state_root / "workflow", WORKFLOW,
                                      owner_uid=os.geteuid() if uid is None else uid)
        self.uid = os.geteuid() if uid is None else uid
        self.now = now or (lambda: int(time.time()))

    def prepare(self) -> None:
        old = os.umask(0o077)
        try:
            if not self.release_root.exists():
                self.release_root.mkdir(mode=0o755)
                self.release_root.chmod(0o755)
            _trusted_directory(self.release_root, self.uid, 0o755)
            if not self.releases.exists():
                self.releases.mkdir(mode=0o755)
                self.releases.chmod(0o755)
            _trusted_directory(self.releases, self.uid, 0o755)
            if not self.state_root.exists():
                self.state_root.mkdir(mode=0o700)
            _trusted_directory(self.state_root, self.uid, 0o700)
            for path in (self.receipts, self.journals):
                _trusted_directory(path, self.uid, 0o700, create=True)
            descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT |
                                 getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    raise GenerationStoreError("lock_untrusted")
            finally:
                os.close(descriptor)
            if not self.catalog_path.exists():
                atomic_write(self.catalog_path, canonical_bytes({
                    "schema": CATALOG_SCHEMA, "epoch": 0, "generations": [],
                }))
            if not self.selector_path.exists():
                atomic_write(self.selector_path, canonical_bytes({
                    "schema": SELECTOR_SCHEMA, "epoch": 0, "active_generation_id": None,
                    "predecessor_generation_id": None, "plan_sha256": None,
                }))
            if not self.floor_path.exists():
                atomic_write(self.floor_path, canonical_bytes({
                    "schema": FLOOR_SCHEMA, "highest_release_sequence": 0,
                    "revoked_generation_ids": [], "epoch": 0,
                }))
        finally:
            os.umask(old)

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        self.prepare()
        descriptor = os.open(self.lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextlib.contextmanager
    def inspection_locked(self) -> Iterator[None]:
        """Open existing protected state without creating or repairing anything."""
        _trusted_directory(self.release_root, self.uid, 0o755)
        _trusted_directory(self.releases, self.uid, 0o755)
        _trusted_directory(self.state_root, self.uid, 0o700)
        _trusted_directory(self.receipts, self.uid, 0o700)
        _trusted_directory(self.journals, self.uid, 0o700)
        try:
            info = self.lock_path.lstat()
        except OSError as error:
            raise GenerationStoreError("lock_missing") from error
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != self.uid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise GenerationStoreError("lock_untrusted")
        descriptor = os.open(self.lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _catalog(self) -> dict[str, Any]:
        value = _read_json(self.catalog_path, self.uid)
        _exact(value, {"schema", "epoch", "generations"}, "catalog")
        if value["schema"] != CATALOG_SCHEMA:
            raise GenerationStoreError("catalog_invalid")
        _integer(value["epoch"], "catalog_epoch", 0, 2**63 - 1)
        generations = value["generations"]
        if not isinstance(generations, list) or len(generations) > MAX_GENERATIONS:
            raise GenerationStoreError("catalog_invalid")
        seen: set[str] = set()
        for record in generations:
            self._validate_record(record)
            if record["generation_id"] in seen:
                raise GenerationStoreError("catalog_duplicate_generation")
            seen.add(record["generation_id"])
        if generations != sorted(generations, key=lambda item: item["generation_id"]):
            raise GenerationStoreError("catalog_order_invalid")
        return value

    @staticmethod
    def _validate_record(value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise GenerationStoreError("record_invalid")
        _exact(value, {
            "schema", "generation_id", "harness_id", "vendor_id", "version", "platform",
            "release_sequence", "artifact_sha256", "artifact_size", "manifest_sha256",
            "policy_sha256", "adapter_id", "adapter_sha256", "suite_sha256",
            "health_probe_sha256",
            "verification_sha256", "qualification_sha256", "inventory_sha256",
            "published_at", "status", "status_epoch", "reason_sha256",
        }, "record")
        if value["schema"] != RECORD_SCHEMA or value["status"] not in {
                "retained", "active", "rejected", "retired", "revoked"}:
            raise GenerationStoreError("record_invalid")
        for name in ("generation_id", "artifact_sha256", "manifest_sha256", "policy_sha256",
                     "adapter_sha256", "suite_sha256", "verification_sha256",
                     "qualification_sha256", "inventory_sha256"):
            _sha(value[name], name)
        _sha(value["health_probe_sha256"], "health_probe_sha256")
        for name in ("harness_id", "vendor_id", "adapter_id"):
            _id(value[name], name)
        if value["reason_sha256"] is not None:
            _sha(value["reason_sha256"], "reason_sha256")
        _integer(value["release_sequence"], "release_sequence", 1, 2**63 - 1)
        _integer(value["artifact_size"], "artifact_size", 1, MAX_ARTIFACT_BYTES)
        _integer(value["published_at"], "published_at", 0, 2**63 - 1)
        _integer(value["status_epoch"], "status_epoch", 1, 2**63 - 1)
        return value

    def _selector(self) -> dict[str, Any]:
        value = _read_json(self.selector_path, self.uid)
        _exact(value, {"schema", "epoch", "active_generation_id",
                       "predecessor_generation_id", "plan_sha256"}, "selector")
        if value["schema"] != SELECTOR_SCHEMA:
            raise GenerationStoreError("selector_invalid")
        _integer(value["epoch"], "selector_epoch", 0, 2**63 - 1)
        for name in ("active_generation_id", "predecessor_generation_id", "plan_sha256"):
            if value[name] is not None:
                _sha(value[name], name)
        return value

    def _floor(self) -> dict[str, Any]:
        value = _read_json(self.floor_path, self.uid)
        _exact(value, {"schema", "highest_release_sequence", "revoked_generation_ids", "epoch"},
               "floor")
        if value["schema"] != FLOOR_SCHEMA:
            raise GenerationStoreError("floor_invalid")
        _integer(value["highest_release_sequence"], "highest_release_sequence", 0, 2**63 - 1)
        _integer(value["epoch"], "floor_epoch", 0, 2**63 - 1)
        revoked = value["revoked_generation_ids"]
        if (not isinstance(revoked, list) or len(revoked) > MAX_GENERATIONS
                or revoked != sorted(set(revoked))):
            raise GenerationStoreError("floor_revocations_invalid")
        for generation in revoked:
            _sha(generation, "revoked_generation_id")
        return value

    def _state_digests(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]]:
        catalog = self._catalog()
        selector = self._selector()
        floor = self._floor()
        return catalog, selector, floor, {
            "catalog_sha256": sha256_value(catalog),
            "selector_sha256": sha256_value(selector),
            "floor_sha256": sha256_value(floor),
        }

    @staticmethod
    def _manifest_identity(manifest: dict[str, Any]) -> dict[str, Any]:
        expected = {"schema", "harness_id", "vendor_id", "version", "platform",
                    "release_sequence", "generation_id", "artifact", "adapter_id", "evidence",
                    "compatibility"}
        if set(manifest) != expected or manifest.get("schema") != "secure-sandbox-harness-release-manifest-v1":
            raise GenerationStoreError("manifest_invalid")
        artifact = manifest.get("artifact")
        if (not isinstance(artifact, dict)
                or set(artifact) != {"filename", "media_type", "sha256", "size", "url"}):
            raise GenerationStoreError("manifest_invalid")
        compatibility = manifest.get("compatibility")
        if (not isinstance(compatibility, dict)
                or set(compatibility) != {"adapter_sha256", "controller_schema"}):
            raise GenerationStoreError("manifest_invalid")
        body = dict(manifest); supplied_generation = body.pop("generation_id", None)
        if supplied_generation != sha256_value(body):
            raise GenerationStoreError("manifest_generation_mismatch")
        return {
            "generation_id": _sha(manifest["generation_id"], "generation_id"),
            "harness_id": _id(manifest["harness_id"], "harness_id"),
            "vendor_id": _id(manifest["vendor_id"], "vendor_id"),
            "version": manifest["version"], "platform": manifest["platform"],
            "release_sequence": manifest["release_sequence"],
            "artifact_sha256": _sha(artifact["sha256"], "artifact_sha256"),
            "artifact_size": artifact["size"], "adapter_id": _id(manifest["adapter_id"], "adapter_id"),
            "manifest_adapter_sha256": _sha(compatibility["adapter_sha256"],
                                            "manifest_adapter_sha256"),
        }

    def create_plan(self, manifest_path: Path, artifact_path: Path, verification_path: Path,
                    qualification_path: Path, adapter_path: Path, *, operation: str = "activate",
                    now: int | None = None) -> dict[str, Any]:
        current_time = self.now() if now is None else now
        with self.locked():
            catalog, selector, floor, digests = self._state_digests()
            manifest_raw = _read_regular(manifest_path, self.uid, MAX_JSON_BYTES, 0o600)
            try:
                manifest = json.loads(manifest_raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise GenerationStoreError("manifest_invalid") from error
            if canonical_bytes(manifest) != manifest_raw:
                raise GenerationStoreError("manifest_noncanonical")
            identity = self._manifest_identity(manifest)
            manifest_adapter_sha256 = identity.pop("manifest_adapter_sha256")
            verification = validate_verification(_read_json(verification_path, self.uid))
            qualification = validate_qualification(_read_json(qualification_path, self.uid), current_time)
            adapter = validate_adapter(_read_json(adapter_path, self.uid))
            artifact = _read_regular(artifact_path, self.uid, identity["artifact_size"], 0o600)
            manifest_sha256 = sha256_bytes(manifest_raw)
            bindings = {
                "generation_id": identity["generation_id"],
                "artifact_sha256": identity["artifact_sha256"],
                "manifest_sha256": manifest_sha256,
                "policy_sha256": verification["policy_sha256"],
                "adapter_id": identity["adapter_id"],
            }
            if sha256_bytes(artifact) != identity["artifact_sha256"]:
                raise GenerationStoreError("artifact_digest_mismatch")
            for receipt in (verification, qualification):
                if any(receipt.get(name) != expected for name, expected in bindings.items()
                       if name in receipt):
                    raise GenerationStoreError("evidence_binding_mismatch")
            if (adapter["adapter_id"] != identity["adapter_id"]
                    or adapter["harness_id"] != identity["harness_id"]
                    or adapter["adapter_sha256"] != manifest_adapter_sha256
                    or adapter["policy_sha256"] != verification["policy_sha256"]
                    or qualification["adapter_sha256"] != adapter["adapter_sha256"]):
                raise GenerationStoreError("adapter_binding_mismatch")
            if identity["generation_id"] in floor["revoked_generation_ids"]:
                raise GenerationStoreError("generation_revoked")
            existing = next((item for item in catalog["generations"]
                             if item["generation_id"] == identity["generation_id"]), None)
            if existing is not None and existing["status"] in {"rejected", "retired", "revoked"}:
                raise GenerationStoreError("generation_not_selectable")
            if operation == "rollback":
                if existing is None or existing["status"] != "retained":
                    raise GenerationStoreError("rollback_target_invalid")
            elif operation == "activate":
                if existing is not None:
                    raise GenerationStoreError("published_generation_requires_rollback")
            else:
                raise GenerationStoreError("operation_invalid")
            candidate = {
                **identity, "manifest_sha256": manifest_sha256,
                "policy_sha256": verification["policy_sha256"],
                "adapter_sha256": adapter["adapter_sha256"],
                "health_probe_sha256": adapter["health_probe_sha256"],
                "suite_sha256": qualification["suite_sha256"],
                "qualification_expires_at": qualification["expires_at"],
            }
            plan: dict[str, Any] = {
                "schema": PLAN_SCHEMA, "plan_id": str(uuid.uuid4()),
                "transaction_id": str(uuid.uuid4()),
                "action_ids": {name: str(uuid.uuid4()) for name in (
                    "prepared", "authorized", "activated", "verified", "committed", "restored")},
                "operation": operation, "created_at": current_time,
                "expires_at": current_time + MAX_PLAN_SECONDS, "candidate": candidate,
                "current": {"generation_id": selector["active_generation_id"],
                            "selector_epoch": selector["epoch"]},
                **digests,
                "verification_sha256": sha256_value(verification),
                "qualification_sha256": qualification["qualification_sha256"],
                "adapter_projection_sha256": adapter["projection_sha256"],
            }
            plan["plan_sha256"] = sha256_value(plan)
            return validate_plan(plan, current_time)

    def _require_plan_sources(self, plan: dict[str, Any], manifest_path: Path, artifact_path: Path,
                              verification_path: Path, qualification_path: Path,
                              adapter_path: Path, now: int) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        manifest = _read_regular(manifest_path, self.uid, MAX_JSON_BYTES, 0o600)
        artifact = _read_regular(artifact_path, self.uid, plan["candidate"]["artifact_size"], 0o600)
        verification_raw = _read_regular(verification_path, self.uid, MAX_JSON_BYTES, 0o600)
        qualification_raw = _read_regular(qualification_path, self.uid, MAX_JSON_BYTES, 0o600)
        adapter_raw = _read_regular(adapter_path, self.uid, MAX_JSON_BYTES, 0o600)
        verification = validate_verification(json.loads(verification_raw))
        qualification = validate_qualification(json.loads(qualification_raw), now)
        adapter = validate_adapter(json.loads(adapter_raw))
        expected = plan["candidate"]
        checks = {
            "generation_id": qualification["generation_id"],
            "artifact_sha256": sha256_bytes(artifact),
            "manifest_sha256": sha256_bytes(manifest),
            "policy_sha256": verification["policy_sha256"],
            "adapter_id": adapter["adapter_id"], "adapter_sha256": adapter["adapter_sha256"],
            "suite_sha256": qualification["suite_sha256"],
        }
        if any(expected[name] != observed for name, observed in checks.items()):
            raise GenerationStoreError("plan_source_changed")
        if (sha256_value(verification) != plan["verification_sha256"]
                or qualification["qualification_sha256"] != plan["qualification_sha256"]
                or adapter["projection_sha256"] != plan["adapter_projection_sha256"]):
            raise GenerationStoreError("plan_evidence_changed")
        return artifact, manifest, verification_raw, qualification_raw, adapter_raw

    def create_management_plan(self, operation: str, generation_id: str, reason_sha256: str,
                               reference_path: Path, *, now: int | None = None) -> dict[str, Any]:
        """Create a five-minute retire/revoke plan from independent reference readback."""
        current_time = self.now() if now is None else now
        with self.locked():
            catalog, selector, _floor, digests = self._state_digests()
            generation_id = _sha(generation_id, "generation_id")
            reason_sha256 = _sha(reason_sha256, "reason_sha256")
            if operation not in {"retire", "revoke"}:
                raise GenerationStoreError("management_operation_invalid")
            matches = [item for item in catalog["generations"]
                       if item["generation_id"] == generation_id]
            if len(matches) != 1:
                raise GenerationStoreError("generation_not_found")
            record = matches[0]
            if record["status"] in {"retired", "revoked", "rejected"}:
                raise GenerationStoreError("generation_not_manageable")
            if operation == "retire" and generation_id in {
                    selector["active_generation_id"], selector["predecessor_generation_id"]}:
                raise GenerationStoreError("protected_generation_not_retirable")
            reference = validate_reference_readback(_read_json(reference_path, self.uid), current_time)
            if reference["generation_id"] != generation_id:
                raise GenerationStoreError("reference_generation_mismatch")
            if operation == "retire" and (
                    reference["active_run_count"] or reference["resumable_session_count"]):
                raise GenerationStoreError("generation_still_referenced")
            plan: dict[str, Any] = {
                "schema": MANAGEMENT_PLAN_SCHEMA, "plan_id": str(uuid.uuid4()),
                "transaction_id": str(uuid.uuid4()),
                "action_ids": {name: str(uuid.uuid4()) for name in (
                    "prepared", "authorized", "activated", "verified", "committed", "restored")},
                "operation": operation, "generation_id": generation_id,
                "reason_sha256": reason_sha256,
                "reference_sha256": reference["reference_sha256"],
                "created_at": current_time, "expires_at": current_time + MAX_PLAN_SECONDS,
                **digests,
            }
            plan["plan_sha256"] = sha256_value(plan)
            return validate_management_plan(plan, current_time)

    def apply_management_plan(self, raw_plan: object, raw_authorization: object,
                              reference_path: Path, *, runtime_idle: Callable[[], bool],
                              now: int | None = None) -> dict[str, Any]:
        """Apply an exact Touch ID retire/revoke decision without deleting evidence."""
        current_time = self.now() if now is None else now
        plan = validate_management_plan(raw_plan, current_time)
        authorization = validate_authorization(raw_authorization, plan, current_time)
        reference = validate_reference_readback(_read_json(reference_path, self.uid), current_time)
        if (reference["generation_id"] != plan["generation_id"]
                or reference["reference_sha256"] != plan["reference_sha256"]):
            raise GenerationStoreError("management_reference_changed")
        if plan["operation"] == "retire" and (
                reference["active_run_count"] or reference["resumable_session_count"]):
            raise GenerationStoreError("generation_still_referenced")
        identities = {
            "generation": plan["generation_id"], "plan": plan["plan_sha256"],
            "references": plan["reference_sha256"], "reason": plan["reason_sha256"],
        }
        with self.locked():
            if any(self.journals.iterdir()):
                raise GenerationStoreError("activation_recovery_pending")
            locked_reference = validate_reference_readback(
                _read_json(reference_path, self.uid), current_time,
            )
            if locked_reference != reference:
                raise GenerationStoreError("management_reference_changed")
            catalog, selector, floor, digests = self._state_digests()
            if any(plan[name] != digests[name] for name in digests):
                raise GenerationStoreError("management_state_changed")
            matches = [item for item in catalog["generations"]
                       if item["generation_id"] == plan["generation_id"]]
            if len(matches) != 1:
                raise GenerationStoreError("generation_not_found")
            record = matches[0]
            if record["status"] in {"rejected", "retired", "revoked"}:
                raise GenerationStoreError("generation_not_manageable")
            if plan["operation"] == "retire" and plan["generation_id"] in {
                    selector["active_generation_id"], selector["predecessor_generation_id"]}:
                raise GenerationStoreError("protected_generation_not_retirable")
            self._write_fence(plan)
            if not runtime_idle():
                self._remove_fence(plan)
                raise GenerationStoreError("research_runtime_not_idle")
            journal_path = self.journals / f"{plan['transaction_id']}.json"
            journal = {
                "schema": JOURNAL_SCHEMA, "transaction_id": plan["transaction_id"],
                "plan_sha256": plan["plan_sha256"], "phase": "fenced", "plan": plan,
                "old_catalog": catalog, "old_selector": selector, "old_floor": floor,
                "health_sha256": None, "failure_sha256": None,
            }
            atomic_write(journal_path, canonical_bytes(journal))
            try:
                with self.workflow.locked():
                    self.workflow.create(plan["transaction_id"], plan["action_ids"]["prepared"],
                                         identities, plan["expires_at"], now=current_time)
                    self.workflow.advance(
                        plan["transaction_id"], "authorized", plan["action_ids"]["authorized"],
                        identities, authorization_sha256=authorization["authorization_sha256"],
                        authorization_expires_at=authorization["expires_at"], now=current_time,
                    )
                record = {**record, "status": "retired" if plan["operation"] == "retire" else "revoked",
                          "status_epoch": record["status_epoch"] + 1,
                          "reason_sha256": plan["reason_sha256"]}
                catalog = self._replace_record(catalog, record)
                if plan["operation"] == "revoke":
                    floor = {**floor,
                             "revoked_generation_ids": sorted(set(
                                 [*floor["revoked_generation_ids"], plan["generation_id"]])),
                             "epoch": floor["epoch"] + 1}
                    if selector["active_generation_id"] == plan["generation_id"]:
                        selector = {"schema": SELECTOR_SCHEMA, "epoch": selector["epoch"] + 1,
                                    "active_generation_id": None,
                                    "predecessor_generation_id": selector["predecessor_generation_id"],
                                    "plan_sha256": plan["plan_sha256"]}
                    elif selector["predecessor_generation_id"] == plan["generation_id"]:
                        selector = {"schema": SELECTOR_SCHEMA, "epoch": selector["epoch"] + 1,
                                    "active_generation_id": selector["active_generation_id"],
                                    "predecessor_generation_id": None,
                                    "plan_sha256": plan["plan_sha256"]}
                atomic_write(self.catalog_path, canonical_bytes(catalog))
                atomic_write(self.floor_path, canonical_bytes(floor))
                atomic_write(self.selector_path, canonical_bytes(selector))
                readback = self.verify_boundary()
                evidence = sha256_value(readback)
                journal["phase"] = "health_passed"; journal["health_sha256"] = evidence
                atomic_write(journal_path, canonical_bytes(journal))
                with self.workflow.locked():
                    self.workflow.advance(plan["transaction_id"], "activated",
                                          plan["action_ids"]["activated"], identities,
                                          evidence_sha256=evidence, now=current_time)
                    self.workflow.advance(plan["transaction_id"], "verified",
                                          plan["action_ids"]["verified"], identities,
                                          evidence_sha256=evidence, now=current_time)
                    head = self.workflow.advance(plan["transaction_id"], "committed",
                                                 plan["action_ids"]["committed"], identities,
                                                 evidence_sha256=evidence, now=current_time)
                self._remove_fence(plan)
                journal_path.unlink(); fsync_directory(self.journals)
                return self._receipt(
                    plan["operation"], "committed", transaction_id=plan["transaction_id"],
                    plan_sha256=plan["plan_sha256"], generation_id=plan["generation_id"],
                    authorization_sha256=authorization["authorization_sha256"],
                    reference_sha256=plan["reference_sha256"],
                    catalog_sha256=sha256_value(catalog), selector_sha256=sha256_value(selector),
                    floor_sha256=sha256_value(floor), workflow_head_sha256=head["head_sha256"],
                )
            except Exception as error:
                try:
                    with self.workflow.locked():
                        head = self.workflow.inspect(plan["transaction_id"], identities)
                except WorkflowError as workflow_error:
                    journal["phase"] = "recovery_required"
                    journal["failure_sha256"] = sha256_bytes(
                        type(error).__name__.encode("ascii")
                    )
                    atomic_write(journal_path, canonical_bytes(journal))
                    raise GenerationStoreError("management_state_ambiguous") from workflow_error
                if head["phase"] in {"activated", "verified", "committed"}:
                    journal["phase"] = "recovery_required"
                    journal["failure_sha256"] = sha256_bytes(
                        type(error).__name__.encode("ascii")
                    )
                    atomic_write(journal_path, canonical_bytes(journal))
                    raise
                journal["phase"] = "restoring"
                journal["failure_sha256"] = sha256_bytes(type(error).__name__.encode("ascii"))
                atomic_write(journal_path, canonical_bytes(journal))
                atomic_write(self.catalog_path, canonical_bytes(journal["old_catalog"]))
                atomic_write(self.selector_path, canonical_bytes(journal["old_selector"]))
                atomic_write(self.floor_path, canonical_bytes(journal["old_floor"]))
                self.verify_boundary()
                with self.workflow.locked():
                    if head["phase"] in {"prepared", "authorized"}:
                        self.workflow.advance(
                            plan["transaction_id"], "rolled_back", plan["action_ids"]["restored"], identities,
                            evidence_sha256=sha256_value(journal["old_selector"]),
                            now=current_time,
                        )
                self._remove_fence(plan)
                journal_path.unlink(); fsync_directory(self.journals)
                raise

    def _identities(self, plan: dict[str, Any]) -> dict[str, str]:
        candidate = plan["candidate"]
        return {
            "adapter": candidate["adapter_sha256"], "generation": candidate["generation_id"],
            "health_probe": candidate["health_probe_sha256"],
            "manifest": candidate["manifest_sha256"], "plan": plan["plan_sha256"],
            "policy": candidate["policy_sha256"], "qualification": plan["qualification_sha256"],
        }

    def _write_fence(self, plan: dict[str, Any]) -> None:
        expected = {
            "schema": FENCE_SCHEMA, "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"], "transaction_id": plan["transaction_id"],
            "status": "fenced",
        }
        if self.fence_path.exists() or self.fence_path.is_symlink():
            existing = _read_json(self.fence_path, self.uid)
            if existing == expected:
                return
            raise GenerationStoreError("admission_already_fenced")
        atomic_write(self.fence_path, canonical_bytes(expected))

    def _remove_fence(self, plan: dict[str, Any]) -> None:
        fence = _read_json(self.fence_path, self.uid)
        if (fence.get("schema") != FENCE_SCHEMA or fence.get("plan_id") != plan["plan_id"]
                or fence.get("plan_sha256") != plan["plan_sha256"]
                or fence.get("transaction_id") != plan["transaction_id"]
                or fence.get("status") != "fenced"):
            raise GenerationStoreError("admission_fence_mismatch")
        self.fence_path.unlink()
        fsync_directory(self.state_root)

    def _publish(self, plan: dict[str, Any], artifact: bytes, manifest: bytes,
                 verification: bytes, qualification: bytes, adapter: bytes,
                 now: int) -> dict[str, Any]:
        candidate = plan["candidate"]
        destination = self.releases / candidate["generation_id"]
        if destination.exists() or destination.is_symlink():
            observed = self._readback_release(candidate["generation_id"])
            self._require_published_sources(
                observed, artifact, manifest, verification, qualification, adapter,
            )
            return observed
        if len(list(self.releases.iterdir())) >= MAX_GENERATIONS:
            raise GenerationStoreError("generation_capacity_exceeded")
        temporary = self.releases / f".{candidate['generation_id']}.new-{uuid.uuid4()}"
        temporary.mkdir(mode=0o700)
        try:
            files = {
                "harness": (artifact, 0o555), "manifest.json": (manifest, 0o444),
                "verification.json": (verification, 0o444),
                "qualification.json": (qualification, 0o444),
                "adapter.json": (adapter, 0o444),
            }
            inventory_files: list[dict[str, Any]] = []
            for name, (content, mode) in files.items():
                path = temporary / name
                write_new_file(path, content, mode)
                inventory_files.append({"name": name, "sha256": sha256_bytes(content),
                                        "size": len(content), "mode": mode})
            inventory = {
                "schema": "secure-sandbox-harness-release-inventory-v1",
                "generation_id": candidate["generation_id"], "files": inventory_files,
            }
            inventory["inventory_sha256"] = sha256_value(inventory)
            inventory_raw = canonical_bytes(inventory)
            path = temporary / "inventory.json"
            write_new_file(path, inventory_raw, 0o444)
            fsync_directory(temporary)
            os.chmod(temporary, 0o555)
            os.rename(temporary, destination)
            fsync_directory(self.releases)
        except BaseException:
            if temporary.exists() and not temporary.is_symlink():
                os.chmod(temporary, 0o700)
                shutil.rmtree(temporary)
            raise
        observed = self._readback_release(candidate["generation_id"])
        self._require_published_sources(
            observed, artifact, manifest, verification, qualification, adapter,
        )
        return observed

    @staticmethod
    def _require_published_sources(observed: dict[str, Any], artifact: bytes, manifest: bytes,
                                   verification: bytes, qualification: bytes,
                                   adapter: bytes) -> None:
        expected = {
            "harness": sha256_bytes(artifact), "manifest.json": sha256_bytes(manifest),
            "verification.json": sha256_bytes(verification),
            "qualification.json": sha256_bytes(qualification),
            "adapter.json": sha256_bytes(adapter),
        }
        if observed.get("file_sha256") != expected:
            raise GenerationStoreError("published_source_mismatch")

    def _cleanup_interrupted_publication(self, generation_id: str) -> None:
        """Remove only structurally exact, root-owned publication temporaries."""
        _sha(generation_id, "generation_id")
        expected = {
            "harness": (0o555, MAX_ARTIFACT_BYTES),
            "manifest.json": (0o444, MAX_JSON_BYTES),
            "verification.json": (0o444, MAX_JSON_BYTES),
            "qualification.json": (0o444, MAX_JSON_BYTES),
            "adapter.json": (0o444, MAX_JSON_BYTES),
            "inventory.json": (0o444, MAX_JSON_BYTES),
        }
        for temporary in list(self.releases.iterdir()):
            match = RELEASE_TEMP_RE.fullmatch(temporary.name)
            if match is None or match.group(1) != generation_id:
                continue
            _uuid(match.group(2), "publication_temporary_id")
            info = temporary.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) not in {0o700, 0o555}):
                raise GenerationStoreError("publication_temporary_untrusted")
            children = list(temporary.iterdir())
            if len(children) > len(expected):
                raise GenerationStoreError("publication_temporary_untrusted")
            for child in children:
                if child.name not in expected:
                    raise GenerationStoreError("publication_temporary_untrusted")
                mode, maximum = expected[child.name]
                child_info = child.lstat()
                if (not stat.S_ISREG(child_info.st_mode) or stat.S_ISLNK(child_info.st_mode)
                        or child_info.st_uid != self.uid or child_info.st_nlink != 1
                        or stat.S_IMODE(child_info.st_mode) != mode
                        or child_info.st_size > maximum):
                    raise GenerationStoreError("publication_temporary_untrusted")
            os.chmod(temporary, 0o700)
            for child in children:
                child.unlink()
            fsync_directory(temporary)
            temporary.rmdir()
            fsync_directory(self.releases)

    def _readback_release(self, generation_id: str) -> dict[str, Any]:
        path = self.releases / _sha(generation_id, "generation_id")
        _trusted_directory(path, self.uid, 0o555)
        expected_names = {"harness", "manifest.json", "verification.json",
                          "qualification.json", "adapter.json", "inventory.json"}
        if {item.name for item in path.iterdir()} != expected_names:
            raise GenerationStoreError("release_inventory_invalid")
        inventory = json.loads(_read_regular(path / "inventory.json", self.uid, MAX_JSON_BYTES, 0o444))
        if not isinstance(inventory, dict) or inventory.get("generation_id") != generation_id:
            raise GenerationStoreError("release_inventory_invalid")
        supplied = _self_digest(inventory, "inventory_sha256", "inventory")
        files = inventory.get("files")
        if not isinstance(files, list) or [item.get("name") for item in files] != [
                "harness", "manifest.json", "verification.json", "qualification.json", "adapter.json"]:
            raise GenerationStoreError("release_inventory_invalid")
        observed_files: dict[str, str] = {}
        for item in files:
            if set(item) != {"name", "sha256", "size", "mode"}:
                raise GenerationStoreError("release_inventory_invalid")
            raw = _read_regular(path / item["name"], self.uid, item["size"], item["mode"])
            if sha256_bytes(raw) != item["sha256"]:
                raise GenerationStoreError("release_inventory_mismatch")
            observed_files[item["name"]] = item["sha256"]
        return {"generation_id": generation_id, "inventory_sha256": supplied,
                "file_sha256": observed_files, "executable": path / "harness"}

    def _record_for(self, plan: dict[str, Any], inventory_sha256: str, now: int,
                    status: str) -> dict[str, Any]:
        candidate = plan["candidate"]
        return {
            "schema": RECORD_SCHEMA, **{name: candidate[name] for name in (
                "generation_id", "harness_id", "vendor_id", "version", "platform",
                "release_sequence", "artifact_sha256", "artifact_size", "manifest_sha256",
                "policy_sha256", "adapter_id", "adapter_sha256", "suite_sha256")},
            "health_probe_sha256": candidate["health_probe_sha256"],
            "verification_sha256": plan["verification_sha256"],
            "qualification_sha256": plan["qualification_sha256"],
            "inventory_sha256": inventory_sha256, "published_at": now,
            "status": status, "status_epoch": 1, "reason_sha256": None,
        }

    @staticmethod
    def _replace_record(catalog: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
        records = [item for item in catalog["generations"]
                   if item["generation_id"] != record["generation_id"]]
        records.append(record)
        return {"schema": CATALOG_SCHEMA, "epoch": catalog["epoch"] + 1,
                "generations": sorted(records, key=lambda item: item["generation_id"])}

    def _receipt(self, action: str, status: str, **fields: object) -> dict[str, Any]:
        entries = list(self.receipts.iterdir())
        if len(entries) >= MAX_RECEIPTS or any(item.is_symlink() or not item.is_file() for item in entries):
            raise GenerationStoreError("receipt_store_untrusted")
        value = {"schema": RECEIPT_SCHEMA, "receipt_id": str(uuid.uuid4()),
                 "observed_at": self.now(), "action": action, "status": status, **fields}
        value["receipt_sha256"] = sha256_value(value)
        atomic_write(self.receipts / f"{value['receipt_id']}.json", canonical_bytes(value))
        return value

    def activate(self, raw_plan: object, raw_authorization: object, manifest_path: Path,
                 artifact_path: Path, verification_path: Path, qualification_path: Path,
                 adapter_path: Path, probe: HealthProbe, *, runtime_idle: Callable[[], bool],
                 now: int | None = None) -> dict[str, Any]:
        current_time = self.now() if now is None else now
        plan = validate_plan(raw_plan, current_time)
        authorization = validate_authorization(raw_authorization, plan, current_time)
        identities = self._identities(plan)
        with self.locked():
            if any(self.journals.iterdir()):
                raise GenerationStoreError("activation_recovery_pending")
            catalog, selector, floor, digests = self._state_digests()
            if any(plan[name] != digests[name] for name in digests):
                raise GenerationStoreError("activation_state_changed")
            if (plan["current"]["generation_id"] != selector["active_generation_id"]
                    or plan["current"]["selector_epoch"] != selector["epoch"]):
                raise GenerationStoreError("activation_selector_changed")
            sources = self._require_plan_sources(
                plan, manifest_path, artifact_path, verification_path,
                qualification_path, adapter_path, current_time,
            )
            self._write_fence(plan)
            if not runtime_idle():
                self._remove_fence(plan)
                raise GenerationStoreError("research_runtime_not_idle")
            journal_path = self.journals / f"{plan['transaction_id']}.json"
            old_catalog, old_selector, old_floor = catalog, selector, floor
            journal = {
                "schema": JOURNAL_SCHEMA, "transaction_id": plan["transaction_id"],
                "plan_sha256": plan["plan_sha256"], "phase": "fenced",
                "plan": plan, "old_catalog": old_catalog, "old_selector": old_selector,
                "old_floor": old_floor,
                "health_sha256": None, "failure_sha256": None,
            }
            atomic_write(journal_path, canonical_bytes(journal))
            try:
                with self.workflow.locked():
                    self.workflow.create(plan["transaction_id"], plan["action_ids"]["prepared"],
                                         identities, plan["expires_at"], now=current_time)
                    self.workflow.advance(
                        plan["transaction_id"], "authorized", plan["action_ids"]["authorized"],
                        identities, authorization_sha256=authorization["authorization_sha256"],
                        authorization_expires_at=authorization["expires_at"], now=current_time,
                    )
                published = self._publish(plan, *sources, current_time)
                current_record = next((item for item in catalog["generations"]
                                       if item["generation_id"] == selector["active_generation_id"]), None)
                if current_record is not None and current_record["status"] == "active":
                    current_record = {**current_record, "status": "retained",
                                      "status_epoch": current_record["status_epoch"] + 1}
                    catalog = self._replace_record(catalog, current_record)
                record = self._record_for(plan, published["inventory_sha256"], current_time, "active")
                existing = next((item for item in catalog["generations"]
                                 if item["generation_id"] == record["generation_id"]), None)
                if existing is not None:
                    record = {**existing, "status": "active",
                              "status_epoch": existing["status_epoch"] + 1, "reason_sha256": None}
                catalog = self._replace_record(catalog, record)
                floor = {"schema": FLOOR_SCHEMA,
                         "highest_release_sequence": max(
                             floor["highest_release_sequence"], record["release_sequence"]),
                         "revoked_generation_ids": floor["revoked_generation_ids"],
                         "epoch": floor["epoch"] + 1}
                selector = {"schema": SELECTOR_SCHEMA, "epoch": selector["epoch"] + 1,
                            "active_generation_id": record["generation_id"],
                            "predecessor_generation_id": old_selector["active_generation_id"],
                            "plan_sha256": plan["plan_sha256"]}
                atomic_write(self.catalog_path, canonical_bytes(catalog))
                atomic_write(self.floor_path, canonical_bytes(floor))
                atomic_write(self.selector_path, canonical_bytes(selector))
                journal["phase"] = "selected"
                atomic_write(journal_path, canonical_bytes(journal))
                readback = self.verify_boundary()
                health = validate_health(probe.probe(plan, published["executable"]), plan)
                journal["phase"] = "health_passed"; journal["health_sha256"] = health["health_sha256"]
                atomic_write(journal_path, canonical_bytes(journal))
                activation_evidence = sha256_value({"readback": readback,
                                                    "health_sha256": health["health_sha256"]})
                with self.workflow.locked():
                    self.workflow.advance(plan["transaction_id"], "activated",
                                          plan["action_ids"]["activated"], identities,
                                          evidence_sha256=activation_evidence, now=current_time)
                    self.workflow.advance(plan["transaction_id"], "verified",
                                          plan["action_ids"]["verified"], identities,
                                          evidence_sha256=sha256_value(readback), now=current_time)
                    head = self.workflow.advance(plan["transaction_id"], "committed",
                                                 plan["action_ids"]["committed"], identities,
                                                 evidence_sha256=health["health_sha256"], now=current_time)
                self._remove_fence(plan)
                journal_path.unlink(); fsync_directory(self.journals)
                return self._receipt(
                    plan["operation"], "committed", transaction_id=plan["transaction_id"],
                    plan_sha256=plan["plan_sha256"], authorization_sha256=authorization["authorization_sha256"],
                    old_generation_id=old_selector["active_generation_id"],
                    new_generation_id=record["generation_id"], selector_sha256=sha256_value(selector),
                    catalog_sha256=sha256_value(catalog), floor_sha256=sha256_value(floor),
                    health_sha256=health["health_sha256"], workflow_head_sha256=head["head_sha256"],
                )
            except Exception as error:
                failure = sha256_bytes(type(error).__name__.encode("ascii"))
                try:
                    with self.workflow.locked():
                        head = self.workflow.inspect(plan["transaction_id"], identities)
                except WorkflowError as workflow_error:
                    journal["phase"] = "recovery_required"; journal["failure_sha256"] = failure
                    atomic_write(journal_path, canonical_bytes(journal))
                    raise GenerationStoreError("activation_state_ambiguous") from workflow_error
                if head["phase"] in {"activated", "verified", "committed"}:
                    journal["phase"] = "recovery_required"; journal["failure_sha256"] = failure
                    atomic_write(journal_path, canonical_bytes(journal))
                    raise
                journal["phase"] = "restoring"; journal["failure_sha256"] = failure
                atomic_write(journal_path, canonical_bytes(journal))
                restored_catalog = old_catalog
                try:
                    release = self._readback_release(plan["candidate"]["generation_id"])
                except GenerationStoreError:
                    pass
                else:
                    rejected = self._record_for(
                        plan, release["inventory_sha256"], current_time, "rejected",
                    )
                    rejected["reason_sha256"] = failure
                    restored_catalog = self._replace_record(old_catalog, rejected)
                atomic_write(self.catalog_path, canonical_bytes(restored_catalog))
                atomic_write(self.selector_path, canonical_bytes(old_selector))
                atomic_write(self.floor_path, canonical_bytes(old_floor))
                self.verify_boundary()
                with self.workflow.locked():
                    if head["phase"] in {"prepared", "authorized"}:
                        self.workflow.advance(plan["transaction_id"], "rolled_back",
                                              plan["action_ids"]["restored"], identities,
                                              evidence_sha256=sha256_value(old_selector),
                                              now=current_time)
                self._remove_fence(plan)
                journal_path.unlink(); fsync_directory(self.journals)
                raise

    def recover(self, *, now: int | None = None) -> dict[str, Any]:
        """Recover one interrupted activation without choosing a generation."""
        current_time = self.now() if now is None else now
        with self.locked():
            entries = list(self.journals.iterdir())
            if len(entries) != 1 or entries[0].is_symlink() or not entries[0].is_file():
                raise GenerationStoreError("recovery_journal_ambiguous")
            journal_path = entries[0]
            journal = _read_json(journal_path, self.uid)
            expected = {"schema", "transaction_id", "plan_sha256", "phase", "plan",
                        "old_catalog", "old_selector", "old_floor", "health_sha256",
                        "failure_sha256"}
            _exact(journal, expected, "journal")
            if journal["schema"] != JOURNAL_SCHEMA:
                raise GenerationStoreError("journal_invalid")
            raw_plan = journal["plan"]
            if isinstance(raw_plan, dict) and raw_plan.get("schema") == PLAN_SCHEMA:
                plan = validate_plan(raw_plan, raw_plan["created_at"])
                identities = self._identities(plan)
            elif isinstance(raw_plan, dict) and raw_plan.get("schema") == MANAGEMENT_PLAN_SCHEMA:
                plan = validate_management_plan(raw_plan, raw_plan["created_at"])
                identities = {
                    "generation": plan["generation_id"], "plan": plan["plan_sha256"],
                    "references": plan["reference_sha256"], "reason": plan["reason_sha256"],
                }
            else:
                raise GenerationStoreError("journal_plan_invalid")
            if (journal["transaction_id"] != plan["transaction_id"]
                    or journal["plan_sha256"] != plan["plan_sha256"]):
                raise GenerationStoreError("journal_binding_invalid")
            with self.workflow.locked():
                transaction = self.workflow.transactions / plan["transaction_id"]
                if not transaction.exists() and not transaction.is_symlink():
                    if plan["schema"] == PLAN_SCHEMA:
                        self._cleanup_interrupted_publication(
                            plan["candidate"]["generation_id"]
                        )
                    atomic_write(self.catalog_path, canonical_bytes(journal["old_catalog"]))
                    atomic_write(self.selector_path, canonical_bytes(journal["old_selector"]))
                    atomic_write(self.floor_path, canonical_bytes(journal["old_floor"]))
                    self.verify_boundary()
                    outcome = "restored_predecessor"
                    head = None
                else:
                    head = self.workflow.inspect(plan["transaction_id"], identities)
                if head is not None and head["phase"] in {"activated", "verified", "committed"}:
                    self.verify_boundary()
                    if journal["health_sha256"] is None:
                        raise GenerationStoreError("activated_health_missing")
                    if head["phase"] == "activated":
                        head = self.workflow.advance(
                            plan["transaction_id"], "verified", plan["action_ids"]["verified"],
                            identities, evidence_sha256=sha256_value(self.verify_boundary()),
                            now=current_time,
                        )
                    if head["phase"] == "verified":
                        head = self.workflow.advance(
                            plan["transaction_id"], "committed", plan["action_ids"]["committed"],
                            identities, evidence_sha256=journal["health_sha256"], now=current_time,
                        )
                    outcome = "committed"
                elif head is not None:
                    if plan["schema"] == PLAN_SCHEMA:
                        self._cleanup_interrupted_publication(
                            plan["candidate"]["generation_id"]
                        )
                    restored_catalog = journal["old_catalog"]
                    if plan["schema"] == PLAN_SCHEMA:
                        try:
                            release = self._readback_release(plan["candidate"]["generation_id"])
                        except GenerationStoreError:
                            pass
                        else:
                            rejected = self._record_for(
                                plan, release["inventory_sha256"], current_time, "rejected",
                            )
                            rejected["reason_sha256"] = sha256_bytes(b"interrupted_activation")
                            restored_catalog = self._replace_record(restored_catalog, rejected)
                    atomic_write(self.catalog_path, canonical_bytes(restored_catalog))
                    atomic_write(self.selector_path, canonical_bytes(journal["old_selector"]))
                    atomic_write(self.floor_path, canonical_bytes(journal["old_floor"]))
                    self.verify_boundary()
                    if head["phase"] in {"prepared", "authorized"}:
                        self.workflow.advance(
                            plan["transaction_id"], "rolled_back",
                            plan["action_ids"]["restored"], identities,
                            evidence_sha256=sha256_value(journal["old_selector"]),
                            now=current_time,
                        )
                    outcome = "restored_predecessor"
            self._remove_fence(plan)
            journal_path.unlink(); fsync_directory(self.journals)
            return self._receipt(
                "recover", outcome, transaction_id=plan["transaction_id"],
                plan_sha256=plan["plan_sha256"],
                active_generation_id=self._selector()["active_generation_id"],
            )

    def verify_boundary(self) -> dict[str, Any]:
        catalog, selector, floor, digests = self._state_digests()
        records = {item["generation_id"]: item for item in catalog["generations"]}
        release_entries = list(self.releases.iterdir())
        if any(entry.is_symlink() or SHA256_RE.fullmatch(entry.name) is None for entry in release_entries):
            raise GenerationStoreError("release_store_untrusted")
        if {entry.name for entry in release_entries} != set(records):
            raise GenerationStoreError("release_catalog_mismatch")
        for generation, record in records.items():
            release = self._readback_release(generation)
            if release["inventory_sha256"] != record["inventory_sha256"]:
                raise GenerationStoreError("catalog_inventory_mismatch")
        active = selector["active_generation_id"]
        predecessor = selector["predecessor_generation_id"]
        if active is None:
            if any(item["status"] == "active" for item in records.values()):
                raise GenerationStoreError("selector_catalog_mismatch")
        else:
            record = records.get(active)
            if record is None or record["status"] != "active" or active in floor["revoked_generation_ids"]:
                raise GenerationStoreError("selector_catalog_mismatch")
        if sum(item["status"] == "active" for item in records.values()) > 1:
            raise GenerationStoreError("catalog_multiple_active")
        if predecessor is not None:
            predecessor_record = records.get(predecessor)
            if (predecessor == active or predecessor_record is None
                    or predecessor_record["status"] != "retained"
                    or predecessor in floor["revoked_generation_ids"]):
                raise GenerationStoreError("predecessor_catalog_mismatch")
        for generation in floor["revoked_generation_ids"]:
            record = records.get(generation)
            if record is not None and record["status"] != "revoked":
                raise GenerationStoreError("revocation_floor_mismatch")
        return {"schema": "secure-sandbox-harness-generation-boundary-v1",
                "status": "verified", "active_generation_id": active,
                "generation_count": len(records), **digests}

    def status(self) -> dict[str, Any]:
        with self.locked():
            boundary = self.verify_boundary()
            catalog = self._catalog(); selector = self._selector(); floor = self._floor()
            return {"schema": STATUS_SCHEMA, "status": "verified",
                    "admission": "fenced" if self.fence_path.exists() else "open",
                    "recovery_pending": any(self.journals.iterdir()),
                    "active_generation_id": selector["active_generation_id"],
                    "predecessor_generation_id": selector["predecessor_generation_id"],
                    "selector_epoch": selector["epoch"],
                    "highest_release_sequence": floor["highest_release_sequence"],
                    "revoked_generation_ids": floor["revoked_generation_ids"],
                    "generations": catalog["generations"], "boundary": boundary}
    def inspect_status(self) -> dict[str, Any]:
        with self.inspection_locked():
            boundary = self.verify_boundary()
            catalog = self._catalog(); selector = self._selector(); floor = self._floor()
            if self.fence_path.exists():
                fence = _read_json(self.fence_path, self.uid)
                if (set(fence) != {"schema", "plan_id", "plan_sha256", "transaction_id", "status"}
                        or fence.get("schema") != FENCE_SCHEMA or fence.get("status") != "fenced"):
                    raise GenerationStoreError("admission_fence_invalid")
            return {"schema": STATUS_SCHEMA, "status": "verified",
                    "admission": "fenced" if self.fence_path.exists() else "open",
                    "recovery_pending": any(self.journals.iterdir()),
                    "active_generation_id": selector["active_generation_id"],
                    "predecessor_generation_id": selector["predecessor_generation_id"],
                    "selector_epoch": selector["epoch"],
                    "highest_release_sequence": floor["highest_release_sequence"],
                    "revoked_generation_ids": floor["revoked_generation_ids"],
                    "generations": catalog["generations"], "boundary": boundary}
# End of module.
