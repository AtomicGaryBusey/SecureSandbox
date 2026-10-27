#!/usr/bin/env python3
"""Durable, monotonic Research-side execution-approval v2 migration."""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


STATE_ROOT = Path("/var/lib/secure-sandbox/execution-approval-transition")
JOURNAL = STATE_ROOT / "journal.json"
HISTORY = STATE_ROOT / "history"
PHASE_RECEIPTS = STATE_ROOT / "phase-receipts"
ACCEPTANCE_HISTORY = STATE_ROOT / "acceptance-history"
FLOOR = STATE_ROOT / "minimum-floor.json"
PUBLIC_FLOOR = Path("/etc/secure-sandbox/execution-approval-floor.json")
CONFIG = Path("/etc/secure-sandbox/execution-broker.json")
ADMISSION_FENCE = Path(
    "/var/lib/secure-sandbox/run-lifecycle/execution-approval-migration-fence.json"
)
RUN_LOCK = Path("/run/secure-sandbox/run-lease.lock")
QUIESCENCE_MARKERS = (
    Path("/run/secure-sandbox/run-id"),
    Path("/run/secure-sandbox/evidence-run-id"),
    Path("/run/secure-sandbox/run-lease.json"),
    Path("/run/secure-sandbox/run-process.json"),
    Path("/var/lib/secure-sandbox/run-lifecycle/active.json"),
    Path("/var/lib/secure-sandbox/run-lifecycle/failure-latched.json"),
    Path("/var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending"),
)
APPROVAL_ROOT = Path("/var/lib/secure-sandbox/execution-approvals")
ACCEPTANCE_PERMIT = Path(
    "/var/lib/secure-sandbox/run-lifecycle/execution-approval-acceptance-permit.json"
)
EVIDENCE_RECEIPTS = Path("/var/lib/secure-sandbox/evidence-receipts/execution")
ALGORITHM = "ecdsa-p256-sha256-x962-low-s"
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PHASES = {"prepared": 1, "fenced": 2, "active": 3, "acceptance": 4, "committed": 5}
RELEASE_ARTIFACTS = (
    Path("/usr/local/libexec/secure-sandbox/execution_broker.py"),
    Path("/usr/local/libexec/secure-sandbox/execution_approval_transition.py"),
    Path("/usr/local/libexec/secure-sandbox/run_lease_watchdog.py"),
)
MAX_PREACTIVATION_RELEASE_REBINDS = 3


class TransitionError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic(path: Path, value: object, mode: int = 0o600) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        data = canonical(value)
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise TransitionError("state_write_failed")
            view = view[count:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def atomic_owned(path: Path, value: object, owner: int, mode: int = 0o600) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        data = canonical(value)
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise TransitionError("state_write_failed")
            view = view[count:]
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, owner, -1)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def protected_directory(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, mode=mode, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode):
        raise TransitionError("state_directory_untrusted")


def trusted_existing_directory(path: Path, mode: int, owner: int = 0,
                               group: int = 0) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or info.st_gid != group
            or stat.S_IMODE(info.st_mode) != mode):
        raise TransitionError("state_directory_untrusted")


def read_json(path: Path, schema: str, mode: int, maximum: int = 16384) -> dict[str, Any]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransitionError("state_invalid") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != mode or len(raw) > maximum
            or not isinstance(value, dict) or value.get("schema") != schema
            or canonical(value) != raw):
        raise TransitionError("state_invalid")
    return value


def uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(value)  # type: ignore[arg-type]
    except (ValueError, TypeError, AttributeError) as error:
        raise TransitionError(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise TransitionError(f"{label}_invalid")
    return str(value)


def release_identity(paths: tuple[Path, ...] = RELEASE_ARTIFACTS) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def validate_record(value: object) -> dict[str, Any]:
    required = {
        "schema", "phase", "transaction_id", "generation_id", "generation_epoch",
        "algorithm", "public_key_spki_der_b64", "public_key_sha256", "host_release_id",
        "research_release_id", "operator_uid", "previous_generation_id",
        "previous_generation_epoch", "expected_prior_phase", "recorded_at",
    }
    acceptance_required = {
        "run_id", "session_id", "source_id", "code_sha256",
        "fixture_manifest_sha256", "timeout_seconds", "runtime_image_id", "expires_at",
        "acceptance_attempt_id", "acceptance_attempt_number",
        "previous_acceptance_binding_sha256", "host_acceptance_authorization",
    }
    supplied = set(value)
    expected = required | (acceptance_required if value.get("phase") == "acceptance" else set())
    if (not isinstance(value, dict) or supplied != expected
            or value.get("schema") != "secure-sandbox-execution-approval-transition-v2"
            or value.get("phase") not in PHASES):
        raise TransitionError("transition_record_invalid")
    if value["phase"] == "acceptance":
        for name in ("run_id", "session_id", "source_id", "acceptance_attempt_id"):
            uuid4(value[name], name)
        authorization = value.get("host_acceptance_authorization")
        previous_binding = value.get("previous_acceptance_binding_sha256")
        if (any(not isinstance(value.get(name), str) or SHA256.fullmatch(value[name]) is None
                for name in ("code_sha256", "fixture_manifest_sha256"))
                or not isinstance(value.get("acceptance_attempt_number"), int)
                or isinstance(value.get("acceptance_attempt_number"), bool)
                or value["acceptance_attempt_number"] < 1
                or (previous_binding is not None and (
                    not isinstance(previous_binding, str) or SHA256.fullmatch(previous_binding) is None
                ))
                or not isinstance(value.get("timeout_seconds"), int)
                or isinstance(value.get("timeout_seconds"), bool)
                or not 1 <= value["timeout_seconds"] <= 10
                or not isinstance(value.get("runtime_image_id"), str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", value["runtime_image_id"]) is None
                or not isinstance(value.get("expires_at"), int)
                or isinstance(value.get("expires_at"), bool)
                or value["expires_at"] <= value["recorded_at"]
                or value["expires_at"] - value["recorded_at"] > 3600):
            raise TransitionError("transition_record_invalid")
        binding = acceptance_binding(value)
        authorization_required = {
            "schema", "status", "transaction_id", "generation_id", "generation_epoch",
            "algorithm", "public_key_sha256", "operator_uid",
            "previous_generation_id", "previous_generation_epoch",
            "acceptance_attempt_id", "acceptance_attempt_number",
            "previous_acceptance_binding_sha256", "acceptance_binding_sha256",
            "host_release_id", "research_release_id", "authorized_at",
        }
        if (not isinstance(authorization, dict) or set(authorization) != authorization_required
                or authorization.get("schema")
                != "secure-sandbox-execution-approval-acceptance-authorization-v1"
                or authorization.get("status") != "authorized"
                or authorization.get("transaction_id") != value.get("transaction_id")
                or authorization.get("generation_id") != value.get("generation_id")
                or authorization.get("generation_epoch") != value.get("generation_epoch")
                or authorization.get("algorithm") != value.get("algorithm")
                or authorization.get("public_key_sha256") != value.get("public_key_sha256")
                or authorization.get("operator_uid") != value.get("operator_uid")
                or authorization.get("previous_generation_id")
                != value.get("previous_generation_id")
                or authorization.get("previous_generation_epoch")
                != value.get("previous_generation_epoch")
                or authorization.get("acceptance_attempt_id") != value["acceptance_attempt_id"]
                or authorization.get("acceptance_attempt_number")
                != value["acceptance_attempt_number"]
                or authorization.get("previous_acceptance_binding_sha256") != previous_binding
                or authorization.get("acceptance_binding_sha256") != binding
                or authorization.get("host_release_id") != value.get("host_release_id")
                or authorization.get("research_release_id") != value.get("research_release_id")
                or not isinstance(authorization.get("authorized_at"), int)
                or isinstance(authorization.get("authorized_at"), bool)
                or authorization["authorized_at"] < 1):
            raise TransitionError("transition_record_invalid")
    uuid4(value["transaction_id"], "transaction_id")
    uuid4(value["generation_id"], "generation_id")
    if (not isinstance(value.get("generation_epoch"), int)
            or isinstance(value.get("generation_epoch"), bool)
            or value["generation_epoch"] < 1
            or value.get("algorithm") != ALGORITHM
            or not isinstance(value.get("public_key_sha256"), str)
            or SHA256.fullmatch(value["public_key_sha256"]) is None
            or not isinstance(value.get("host_release_id"), str)
            or SHA256.fullmatch(value["host_release_id"]) is None
            or not isinstance(value.get("research_release_id"), str)
            or SHA256.fullmatch(value["research_release_id"]) is None
            or not isinstance(value.get("operator_uid"), int)
            or isinstance(value.get("operator_uid"), bool)
            or value["operator_uid"] < 0
            or value.get("expected_prior_phase") not in {*PHASES, "none"}
            or not isinstance(value.get("recorded_at"), int)
            or isinstance(value.get("recorded_at"), bool)
            or value["recorded_at"] < 1):
        raise TransitionError("transition_record_invalid")
    previous_id = value.get("previous_generation_id")
    previous_epoch = value.get("previous_generation_epoch")
    if ((previous_id is None) != (previous_epoch is None)
            or (previous_id is not None and (
                uuid4(previous_id, "previous_generation_id") != previous_id
                or not isinstance(previous_epoch, int) or isinstance(previous_epoch, bool)
                or previous_epoch < 1 or previous_epoch >= value["generation_epoch"]))):
        raise TransitionError("transition_record_invalid")
    try:
        encoded = value["public_key_spki_der_b64"]
        spki = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError) as error:
        raise TransitionError("transition_record_invalid") from error
    if (base64.b64encode(spki).decode("ascii") != encoded
            or len(spki) != 91 or not spki.startswith(SPKI_PREFIX)
            or hashlib.sha256(spki).hexdigest() != value["public_key_sha256"]):
        raise TransitionError("transition_record_invalid")
    return value


def acceptance_binding(value: dict[str, Any]) -> str:
    names = (
        "transaction_id", "generation_id", "generation_epoch",
        "acceptance_attempt_id", "acceptance_attempt_number",
        "previous_acceptance_binding_sha256", "run_id", "session_id", "source_id",
        "code_sha256", "fixture_manifest_sha256", "timeout_seconds",
        "runtime_image_id", "expires_at",
    )
    return hashlib.sha256(canonical({name:value[name] for name in names})).hexdigest()


def current_config() -> dict[str, Any]:
    try:
        info = CONFIG.lstat()
        value = json.loads(CONFIG.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise TransitionError("execution_broker_config_invalid") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o640
            or not isinstance(value, dict)
            or value.get("schema") not in {
                "secure-sandbox-execution-broker-v2", "secure-sandbox-execution-broker-v3"
            }
            or not isinstance(value.get("token"), str)
            or re.fullmatch(r"[A-Za-z0-9]{64}", value["token"]) is None
            or not isinstance(value.get("runtime_image_id"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value["runtime_image_id"]) is None):
        raise TransitionError("execution_broker_config_invalid")
    return value


def base_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema":"secure-sandbox-execution-broker-v3",
        "token":config["token"],
        "runtime_image_id":config["runtime_image_id"],
        "approval":{},
    }


def write_config(config: dict[str, Any]) -> None:
    temporary = CONFIG.parent / f".{CONFIG.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        data = canonical(config)
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise TransitionError("config_write_failed")
            view = view[count:]
        os.fchmod(descriptor, 0o640)
        os.fchown(descriptor, 0, __import__("grp").getgrnam("execution-broker").gr_gid)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, CONFIG)
    fsync_directory(CONFIG.parent)


def floor_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema":"secure-sandbox-execution-approval-floor-v2",
        "minimum_protocol":2,
        "minimum_epoch":record["generation_epoch"],
        "generation_id":record["generation_id"],
        "algorithm":record["algorithm"],
        "public_key_sha256":record["public_key_sha256"],
        "updated_at":record["recorded_at"],
    }


def write_public_floor(value: dict[str, Any]) -> None:
    temporary = PUBLIC_FLOOR.parent / f".{PUBLIC_FLOOR.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        data = canonical(value)
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise TransitionError("floor_write_failed")
            view = view[count:]
        os.fchmod(descriptor, 0o640)
        os.fchown(descriptor, 0, grp.getgrnam("execution-broker").gr_gid)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, PUBLIC_FLOOR)
    fsync_directory(PUBLIC_FLOOR.parent)


@contextlib.contextmanager
def admission_lock():
    descriptor = os.open(RUN_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def assert_quiescent() -> None:
    if any(path.exists() for path in QUIESCENCE_MARKERS):
        raise TransitionError("research_not_quiescent")
    agent_uid = pwd.getpwnam("agent").pw_uid
    result = subprocess.run(
        ["/usr/bin/pgrep", "-u", str(agent_uid)], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode == 0:
        raise TransitionError("research_agent_processes_present")
    if result.returncode != 1:
        raise TransitionError("research_process_check_failed")
    broker = pwd.getpwnam("execution-broker")
    broker_gid = grp.getgrnam("execution-broker").gr_gid
    for name in ("pending", "claims", "responses"):
        path = APPROVAL_ROOT / name
        trusted_existing_directory(
            path,
            0o700 if name == "pending" else 0o750,
            broker.pw_uid if name == "pending" else 0,
            broker_gid,
        )
        if any(path.iterdir()):
            raise TransitionError("execution_approvals_not_quiescent")


def same_generation(left: dict[str, Any], right: dict[str, Any]) -> bool:
    names = (
        "transaction_id", "generation_id", "generation_epoch", "algorithm",
        "public_key_spki_der_b64", "public_key_sha256", "host_release_id",
        "research_release_id", "operator_uid", "previous_generation_id",
        "previous_generation_epoch",
    )
    return all(left.get(name) == right.get(name) for name in names)


def preactivation_release_rebindings(journal: dict[str, Any]) -> list[dict[str, Any]]:
    history = journal.get("preactivation_release_rebindings", [])
    if not isinstance(history, list) or len(history) > MAX_PREACTIVATION_RELEASE_REBINDS:
        raise TransitionError("transition_release_rebinding_invalid")
    prior_host = None
    prior_research = None
    for rebinding in history:
        if (not isinstance(rebinding, dict)
                or set(rebinding) != {
                    "from_host_release_id", "to_host_release_id",
                    "from_research_release_id", "to_research_release_id",
                    "prior_journal_sha256", "rebound_at",
                }
                or any(SHA256.fullmatch(rebinding.get(name, "")) is None for name in (
                    "from_host_release_id", "to_host_release_id",
                    "from_research_release_id", "to_research_release_id",
                    "prior_journal_sha256",
                ))
                or (rebinding["from_host_release_id"] == rebinding["to_host_release_id"]
                    and rebinding["from_research_release_id"]
                    == rebinding["to_research_release_id"])
                or not isinstance(rebinding.get("rebound_at"), int)
                or isinstance(rebinding.get("rebound_at"), bool)
                or rebinding["rebound_at"] < 1
                or (prior_host is not None
                    and rebinding["from_host_release_id"] != prior_host)
                or (prior_research is not None
                    and rebinding["from_research_release_id"] != prior_research)):
            raise TransitionError("transition_release_rebinding_invalid")
        prior_host = rebinding["to_host_release_id"]
        prior_research = rebinding["to_research_release_id"]
    if history and (prior_host != journal.get("host_release_id")
                    or prior_research != journal.get("research_release_id")):
        raise TransitionError("transition_release_rebinding_invalid")
    return history


def transition_result(record: dict[str, Any], journal: dict[str, Any],
                      phase_receipt_sha256: str) -> dict[str, Any]:
    return {
        "schema":"secure-sandbox-execution-approval-transition-result-v2",
        "status":record["phase"],
        **{name:record[name] for name in (
            "transaction_id", "generation_id", "generation_epoch",
            "previous_generation_id", "previous_generation_epoch", "operator_uid",
            "algorithm", "public_key_sha256", "host_release_id", "research_release_id",
            "expected_prior_phase",
        )},
        "prior_record_sha256":journal["prior_record_sha256"],
        "journal_sha256":hashlib.sha256(canonical(journal)).hexdigest(),
        "phase_receipt_sha256":phase_receipt_sha256,
        "acceptance_binding_sha256":journal["acceptance_binding_sha256"],
    }


def phase_receipt(record: dict[str, Any], journal: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema":"secure-sandbox-execution-approval-transition-receipt-v2",
        "outcome":"succeeded", "phase":record["phase"],
        "transaction_id":record["transaction_id"],
        "generation_id":record["generation_id"],
        "generation_epoch":record["generation_epoch"],
        "record_sha256":hashlib.sha256(canonical(record)).hexdigest(),
        "prior_record_sha256":journal["prior_record_sha256"],
        "journal_sha256":hashlib.sha256(canonical(journal)).hexdigest(),
        "recorded_at":record["recorded_at"],
    }


def ensure_phase_receipt(record: dict[str, Any], journal: dict[str, Any]) -> str:
    protected_directory(PHASE_RECEIPTS)
    receipt = phase_receipt(record, journal)
    if record["phase"] == "acceptance":
        suffix = f"acceptance-{record['acceptance_attempt_number']}"
    elif record["phase"] == "prepared" and journal.get("preactivation_release_rebindings"):
        suffix = f"prepared-rebind-{len(journal['preactivation_release_rebindings'])}"
    else:
        suffix = record["phase"]
    path = PHASE_RECEIPTS / f"{record['transaction_id']}.{suffix}.json"
    if path.exists():
        if read_json(path, receipt["schema"], 0o600) != receipt:
            raise TransitionError("transition_receipt_conflict")
    else:
        atomic(path, receipt)
    return hashlib.sha256(canonical(receipt)).hexdigest()


def reconcile_acceptance_permit(record: dict[str, Any]) -> None:
    permit = {
        "schema":"secure-sandbox-execution-approval-acceptance-permit-v1",
        "status":"ready",
        **{name:record[name] for name in (
            "transaction_id", "generation_id", "generation_epoch", "run_id", "session_id",
            "source_id", "code_sha256", "fixture_manifest_sha256", "timeout_seconds",
            "runtime_image_id", "expires_at", "acceptance_attempt_id",
            "acceptance_attempt_number", "previous_acceptance_binding_sha256",
        )},
        "acceptance_binding_sha256":acceptance_binding(record),
    }
    if ACCEPTANCE_PERMIT.exists():
        existing = read_json(
            ACCEPTANCE_PERMIT,
            "secure-sandbox-execution-approval-acceptance-permit-v1", 0o600,
        )
        retry_replacement = (
            permit.get("previous_acceptance_binding_sha256")
            == existing.get("acceptance_binding_sha256")
            and permit.get("acceptance_attempt_number")
            == existing.get("acceptance_attempt_number", 0) + 1
            and (existing.get("status") == "consumed"
                 or existing.get("expires_at", 0) < int(time.time()))
        )
        if existing != permit and not retry_replacement and not (
            existing.get("status") == "consumed"
            and all(existing.get(name) == permit.get(name) for name in permit if name != "status")
        ):
            raise TransitionError("acceptance_permit_conflict")
        if retry_replacement:
            atomic(ACCEPTANCE_PERMIT, permit)
    else:
        atomic(ACCEPTANCE_PERMIT, permit)


def successful_acceptance_receipts(
    record: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    if not EVIDENCE_RECEIPTS.exists():
        return []
    broker_uid = pwd.getpwnam("execution-broker").pw_uid
    matches = []
    for path in EVIDENCE_RECEIPTS.iterdir():
        info = path.lstat()
        if (not re.fullmatch(r"[0-9a-f-]{36}\.json", path.name)
                or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != broker_uid or stat.S_IMODE(info.st_mode) != 0o640
                or info.st_nlink != 1 or info.st_size > 4096):
            raise TransitionError("acceptance_receipt_state_untrusted")
        raw = path.read_bytes()
        value = json.loads(raw)
        unsigned = dict(value)
        content_sha256 = unsigned.pop("content_sha256", None)
        content = json.dumps(
            unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if (raw != json.dumps(
                value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8") + b"\n"
                or content_sha256 != hashlib.sha256(content).hexdigest()):
            raise TransitionError("acceptance_receipt_state_untrusted")
        evidence = value.get("evidence", {})
        if (value.get("schema") == "secure-sandbox-evidence-receipt-v4"
                and value.get("producer") == "execution-broker"
                and value.get("instrument") == "run_python_fixture"
                and evidence.get("run_id") == record.get("run_id")
                and evidence.get("session_id") == record.get("session_id")):
            expected = {
                "source_id":record["source_id"], "run_id":record["run_id"],
                "session_id":record["session_id"], "code_sha256":record["code_sha256"],
                "fixture_manifest_sha256":record["fixture_manifest_sha256"],
                "timeout_seconds":record["timeout_seconds"],
                "image_digest":record["runtime_image_id"],
                "approval_key_generation_id":record["generation_id"],
                "approval_key_generation_epoch":record["generation_epoch"],
                "approval_public_key_sha256":record["public_key_sha256"],
                "approval_signature_algorithm":record["algorithm"],
                "exit_code":0, "timed_out":False, "output_limit_exceeded":False,
                "stdout_truncated":False, "stderr_truncated":False,
            }
            if any(evidence.get(name) != expected_value
                   for name, expected_value in expected.items()):
                raise TransitionError("acceptance_receipt_mismatch")
            matches.append((value, evidence))
    return matches


def receipt_is_successful_acceptance(record: dict[str, Any]) -> bool:
    return bool(successful_acceptance_receipts(record))


def read_acceptance_attempt(record: dict[str, Any]) -> tuple[Path, dict[str, Any], int]:
    broker_uid = pwd.getpwnam("execution-broker").pw_uid
    path = APPROVAL_ROOT / "consumed" / f"acceptance-{record['acceptance_attempt_id']}.json"
    try:
        info = path.lstat()
        raw = path.read_bytes()
        marker = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransitionError("acceptance_attempt_state_untrusted") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != broker_uid or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1 or len(raw) > 16 * 1024
            or not isinstance(marker, dict)
            or marker.get("schema")
            != "secure-sandbox-execution-approval-acceptance-attempt-v2"
            or canonical(marker) != raw):
        raise TransitionError("acceptance_attempt_state_untrusted")
    return path, marker, broker_uid


def reconcile_acceptance_attempt(
    record: dict[str, Any],
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], dict[str, Any]]]]:
    path, marker, broker_uid = read_acceptance_attempt(record)
    for name in (
        "transaction_id", "generation_id", "generation_epoch", "run_id", "session_id",
        "source_id", "code_sha256", "fixture_manifest_sha256", "timeout_seconds",
        "runtime_image_id", "expires_at", "acceptance_attempt_id",
        "acceptance_attempt_number", "previous_acceptance_binding_sha256",
    ):
        if marker.get(name) != record.get(name):
            raise TransitionError("acceptance_consumed_mismatch")
    if marker.get("acceptance_binding_sha256") != acceptance_binding(record):
        raise TransitionError("acceptance_consumed_mismatch")
    matches = successful_acceptance_receipts(record)
    if len(matches) > 1:
        raise TransitionError("acceptance_receipt_ambiguous")
    if matches:
        receipt, _evidence = matches[0]
        expected_receipt = {
            "research_receipt_id":receipt.get("receipt_id"),
            "research_receipt_sha256":receipt.get("content_sha256"),
        }
        if marker.get("status") == "succeeded":
            if any(marker.get(name) != value for name, value in expected_receipt.items()):
                raise TransitionError("acceptance_attempt_receipt_mismatch")
        elif marker.get("status") in {"claimed", "failed"}:
            marker = {
                **marker, "status":"succeeded", "succeeded_at":int(time.time()),
                **expected_receipt,
            }
            marker.pop("failed_at", None)
            marker.pop("failure_class", None)
            atomic_owned(path, marker, broker_uid)
        else:
            raise TransitionError("acceptance_attempt_state_untrusted")
    return marker, matches


def prepare_acceptance_retry(record: dict[str, Any], prior: dict[str, Any]) -> None:
    if (record.get("acceptance_attempt_number")
            != prior.get("acceptance_attempt_number", 0) + 1
            or record.get("previous_acceptance_binding_sha256")
            != prior.get("acceptance_binding_sha256")):
        raise TransitionError("acceptance_retry_sequence_invalid")
    assert_quiescent()
    if receipt_is_successful_acceptance(prior):
        reconcile_acceptance_attempt(prior)
        raise TransitionError("acceptance_already_succeeded")
    existing = read_json(
        ACCEPTANCE_PERMIT,
        "secure-sandbox-execution-approval-acceptance-permit-v1", 0o600,
    )
    if (existing.get("acceptance_attempt_id") != prior.get("acceptance_attempt_id")
            or existing.get("acceptance_binding_sha256")
            != prior.get("acceptance_binding_sha256")
            or (existing.get("status") != "consumed"
                and existing.get("expires_at", 0) >= int(time.time()))):
        raise TransitionError("acceptance_retry_not_terminal")
    protected_directory(ACCEPTANCE_HISTORY)
    journal_archive = ACCEPTANCE_HISTORY / (
        f"{record['transaction_id']}.{prior['acceptance_attempt_number']}.journal.json"
    )
    permit_archive = ACCEPTANCE_HISTORY / (
        f"{record['transaction_id']}.{prior['acceptance_attempt_number']}.permit.json"
    )
    if journal_archive.exists():
        if read_json(journal_archive, prior["schema"], 0o600) != prior:
            raise TransitionError("acceptance_history_conflict")
    else:
        atomic(journal_archive, prior)
    if permit_archive.exists():
        if read_json(permit_archive, existing["schema"], 0o600) != existing:
            raise TransitionError("acceptance_history_conflict")
    else:
        atomic(permit_archive, existing)


def reconcile_committed_admission(record: dict[str, Any]) -> None:
    if ACCEPTANCE_PERMIT.exists():
        permit = read_json(
            ACCEPTANCE_PERMIT,
            "secure-sandbox-execution-approval-acceptance-permit-v1", 0o600,
        )
        if (permit.get("status") != "consumed"
                or permit.get("transaction_id") != record["transaction_id"]
                or permit.get("generation_id") != record["generation_id"]):
            raise TransitionError("acceptance_permit_not_consumed")
        ACCEPTANCE_PERMIT.unlink()
    try:
        ADMISSION_FENCE.unlink()
    except FileNotFoundError:
        pass
    fsync_directory(ADMISSION_FENCE.parent)


def apply(record_path: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise TransitionError("root_required")
    protected_directory(STATE_ROOT)
    protected_directory(PHASE_RECEIPTS)
    trusted_existing_directory(ADMISSION_FENCE.parent, 0o755)
    record = validate_record(json.loads(record_path.read_bytes()))
    if record["research_release_id"] != release_identity():
        raise TransitionError("research_release_identity_mismatch")
    if FLOOR.exists():
        floor = read_json(FLOOR, "secure-sandbox-execution-approval-floor-v2", 0o600)
        if (set(floor) != {"schema", "minimum_protocol", "minimum_epoch", "generation_id",
                           "algorithm", "public_key_sha256", "updated_at"}
                or floor.get("minimum_protocol") != 2
                or not isinstance(floor.get("minimum_epoch"), int)
                or floor["minimum_epoch"] > record["generation_epoch"]
                or (floor["minimum_epoch"] == record["generation_epoch"]
                    and (floor.get("generation_id") != record["generation_id"]
                         or floor.get("algorithm") != record["algorithm"]
                         or floor.get("public_key_sha256") != record["public_key_sha256"]))):
            raise TransitionError("transition_below_minimum_floor")
    prior = None
    archived_prior_sha256 = None
    observed_prior_phase = "none"
    release_repair = False
    release_rebindings: list[dict[str, Any]] = []
    if JOURNAL.exists():
        prior = read_json(JOURNAL, "secure-sandbox-execution-approval-transition-journal-v2", 0o600)
        observed_prior_phase = prior["phase"]
        release_rebindings = preactivation_release_rebindings(prior)
        if not same_generation(prior, record):
            stable_names = (
                "transaction_id", "generation_id", "generation_epoch", "algorithm",
                "public_key_spki_der_b64", "public_key_sha256", "operator_uid",
                "previous_generation_id", "previous_generation_epoch",
            )
            release_repair = (
                prior.get("phase") == "prepared" and record["phase"] == "prepared"
                and record["expected_prior_phase"] == "prepared"
                and not FLOOR.exists()
                and len(release_rebindings) < MAX_PREACTIVATION_RELEASE_REBINDS
                and all(prior.get(name) == record.get(name) for name in stable_names)
                and (prior.get("host_release_id") != record["host_release_id"]
                     or prior.get("research_release_id") != record["research_release_id"])
            )
            if not release_repair:
                if (record["phase"] != "prepared" or prior.get("phase") != "committed"
                        or record["generation_epoch"] <= prior.get("generation_epoch", 0)):
                    raise TransitionError("transition_generation_conflict")
                protected_directory(HISTORY)
                archive = HISTORY / f"{prior['transaction_id']}.json"
                if archive.exists():
                    archived = read_json(
                        archive,
                        "secure-sandbox-execution-approval-transition-journal-v2", 0o600,
                    )
                    if archived != prior:
                        raise TransitionError("transition_history_conflict")
                else:
                    atomic(archive, prior)
                archived_prior_sha256 = hashlib.sha256(canonical(prior)).hexdigest()
                prior = None
            else:
                release_rebindings = [*release_rebindings, {
                    "from_host_release_id":prior["host_release_id"],
                    "to_host_release_id":record["host_release_id"],
                    "from_research_release_id":prior["research_release_id"],
                    "to_research_release_id":record["research_release_id"],
                    "prior_journal_sha256":hashlib.sha256(canonical(prior)).hexdigest(),
                    "rebound_at":record["recorded_at"],
                }]
    acceptance_retry = (
        prior is not None and prior["phase"] == "acceptance"
        and record["phase"] == "acceptance"
        and record.get("acceptance_attempt_id") != prior.get("acceptance_attempt_id")
    )
    if (prior is not None and prior["phase"] == record["phase"]
            and not acceptance_retry and not release_repair):
        if any(prior.get(name) != record.get(name) for name in record if name != "schema"):
            raise TransitionError("transition_redelivery_conflict")
        if record["phase"] == "acceptance":
            with admission_lock():
                reconcile_acceptance_permit(record)
        elif record["phase"] == "committed":
            with admission_lock():
                reconcile_committed_admission(record)
        return transition_result(record, prior, ensure_phase_receipt(record, prior))
    if record["expected_prior_phase"] != observed_prior_phase:
        raise TransitionError("transition_prior_phase_conflict")
    if prior is not None:
        if prior is not None and PHASES[record["phase"]] < PHASES[prior["phase"]]:
            raise TransitionError("transition_phase_rollback")
    config = current_config()
    phase = record["phase"]
    if phase == "prepared":
        if prior is not None and prior["phase"] != "prepared":
            raise TransitionError("transition_phase_rollback")
    elif phase == "fenced":
        if prior is None or prior["phase"] not in {"prepared", "fenced"}:
            raise TransitionError("transition_phase_invalid")
        fence = {
            "schema":"secure-sandbox-execution-approval-admission-fence-v1",
            "transaction_id":record["transaction_id"],
            "generation_id":record["generation_id"],
            "generation_epoch":record["generation_epoch"],
            "created_at":record["recorded_at"],
        }
        with admission_lock():
            assert_quiescent()
            atomic(ADMISSION_FENCE, fence, 0o600)
            subprocess.run(["/usr/bin/systemctl", "stop", "execution-broker.service"], check=True)
            inactive = subprocess.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", "execution-broker.service"],
                check=False,
            )
            if inactive.returncode == 0:
                raise TransitionError("execution_broker_still_active")
            fenced = base_config(config)
            fenced["approval"] = {
                "mode":"fenced", "minimum_protocol":2,
                "minimum_epoch":record["generation_epoch"],
            }
            write_config(fenced)
    elif phase in {"active", "acceptance", "committed"}:
        expected_prior = {
            "active":{"fenced", "active"},
            "acceptance":{"active", "acceptance"},
            "committed":{"acceptance", "committed"},
        }[phase]
        if prior is None or prior["phase"] not in expected_prior:
            raise TransitionError("transition_phase_invalid")
        if acceptance_retry:
            with admission_lock():
                prepare_acceptance_retry(record, prior)
        active = base_config(config)
        active["approval"] = {
            "mode":"active-v2", "minimum_protocol":2,
            "minimum_epoch":record["generation_epoch"],
            "generation_id":record["generation_id"],
            "generation_epoch":record["generation_epoch"],
            "algorithm":record["algorithm"],
            "public_key_spki_der_b64":record["public_key_spki_der_b64"],
            "public_key_sha256":record["public_key_sha256"],
        }
        floor = floor_record(record)
        atomic(FLOOR, floor)
        write_public_floor(floor)
        write_config(active)
        subprocess.run(["/usr/bin/systemctl", "restart", "execution-broker.service"], check=True)
        subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "execution-broker.service"], check=True)
    journal = {
        "schema":"secure-sandbox-execution-approval-transition-journal-v2",
        **{name: record[name] for name in (
            "phase", "transaction_id", "generation_id", "generation_epoch", "algorithm",
            "public_key_spki_der_b64", "public_key_sha256", "host_release_id",
            "research_release_id", "operator_uid", "previous_generation_id",
            "previous_generation_epoch", "expected_prior_phase", "recorded_at",
        )},
        "prior_record_sha256": (
            hashlib.sha256(canonical(prior)).hexdigest() if prior else archived_prior_sha256
        ),
        "acceptance_binding_sha256": (
            acceptance_binding(record) if phase == "acceptance" else None
        ),
    }
    if phase == "acceptance":
        journal.update({name:record[name] for name in (
            "run_id", "session_id", "source_id", "code_sha256",
            "fixture_manifest_sha256", "timeout_seconds", "runtime_image_id", "expires_at",
            "acceptance_attempt_id", "acceptance_attempt_number",
            "previous_acceptance_binding_sha256", "host_acceptance_authorization",
        )})
    if release_repair:
        journal["preactivation_release_rebindings"] = release_rebindings
    atomic(JOURNAL, journal)
    if phase == "acceptance":
        with admission_lock():
            reconcile_acceptance_permit(record)
    elif phase == "committed":
        with admission_lock():
            reconcile_committed_admission(record)
    return transition_result(record, journal, ensure_phase_receipt(record, journal))


def verify_envelope(approval_path: Path, envelope_path: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise TransitionError("root_required")
    try:
        approval = json.loads(approval_path.read_bytes())
        envelope = json.loads(envelope_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise TransitionError("verification_input_invalid") from error
    broker_path = Path("/usr/local/libexec/secure-sandbox/execution_broker.py")
    spec = importlib.util.spec_from_file_location("secure_sandbox_execution_broker", broker_path)
    if spec is None or spec.loader is None:
        raise TransitionError("execution_broker_unavailable")
    broker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(broker)
    config = broker.load_config()
    attestation, attestation_sha256 = broker.verify_v2_envelope(
        envelope, approval, config
    )
    return {
        "schema":"secure-sandbox-execution-approval-verification-v2",
        "status":"verified",
        "approval_id":approval["approval_id"],
        "authorization_request_id":attestation["authorization_request_id"],
        "generation_id":attestation["key_generation_id"],
        "generation_epoch":attestation["key_generation_epoch"],
        "public_key_sha256":attestation["public_key_sha256"],
        "attestation_sha256":attestation_sha256,
    }


def verify_acceptance(record_path: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise TransitionError("root_required")
    record = validate_record(json.loads(record_path.read_bytes()))
    if record["phase"] != "acceptance":
        raise TransitionError("acceptance_record_invalid")
    journal = read_json(JOURNAL, "secure-sandbox-execution-approval-transition-journal-v2", 0o600)
    if any(journal.get(name) != record.get(name) for name in record if name != "schema"):
        raise TransitionError("acceptance_record_mismatch")
    marker, matches = reconcile_acceptance_attempt(record)
    if marker.get("status") != "succeeded":
        raise TransitionError("acceptance_attempt_not_successful")
    broker_uid = pwd.getpwnam("execution-broker").pw_uid
    if len(matches) != 1:
        raise TransitionError("acceptance_receipt_ambiguous")
    receipt, evidence = matches[0]
    approval_id = uuid4(evidence.get("approval_id"), "approval_id")
    consumed_path = APPROVAL_ROOT / "consumed" / f"{approval_id}.json"
    consumed_info = consumed_path.lstat()
    consumed_raw = consumed_path.read_bytes()
    consumed = json.loads(consumed_raw)
    if (not stat.S_ISREG(consumed_info.st_mode) or stat.S_ISLNK(consumed_info.st_mode)
            or consumed_info.st_uid != broker_uid or stat.S_IMODE(consumed_info.st_mode) != 0o600
            or consumed_info.st_nlink != 1 or canonical(consumed) != consumed_raw
            or consumed.get("generation_id") != record["generation_id"]
            or consumed.get("generation_epoch") != record["generation_epoch"]
            or consumed.get("public_key_sha256") != record["public_key_sha256"]
            or consumed.get("signature_algorithm") != record["algorithm"]):
        raise TransitionError("acceptance_approval_consumed_mismatch")
    result = {
        "schema":"secure-sandbox-execution-approval-acceptance-evidence-v1",
        "status":"verified", "transaction_id":record["transaction_id"],
        "generation_id":record["generation_id"], "generation_epoch":record["generation_epoch"],
        "host_release_id":record["host_release_id"], "research_release_id":record["research_release_id"],
        "run_id":record["run_id"], "session_id":record["session_id"],
        "acceptance_attempt_id":record["acceptance_attempt_id"],
        "acceptance_attempt_number":record["acceptance_attempt_number"],
        "approval_id":approval_id,
        "approval_attestation_sha256":evidence["approval_attestation_sha256"],
        "research_receipt_id":receipt["receipt_id"],
        "research_receipt_sha256":receipt["content_sha256"],
        "consumed_marker_sha256":hashlib.sha256(canonical(consumed)).hexdigest(),
        "acceptance_binding_sha256":journal["acceptance_binding_sha256"],
        "verified_at":int(time.time()),
    }
    artifact = STATE_ROOT / "acceptance-evidence.json"
    if artifact.exists():
        existing = read_json(artifact, result["schema"], 0o600)
        if ({key:value for key, value in existing.items() if key != "verified_at"}
                != {key:value for key, value in result.items() if key != "verified_at"}):
            raise TransitionError("acceptance_evidence_conflict")
        return existing
    atomic(artifact, result)
    return result


def verify_negative_gates(approval_path: Path, envelope_path: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise TransitionError("root_required")
    approval = json.loads(approval_path.read_bytes())
    envelope = json.loads(envelope_path.read_bytes())
    broker_path = Path("/usr/local/libexec/secure-sandbox/execution_broker.py")
    spec = importlib.util.spec_from_file_location("secure_sandbox_execution_broker_negative", broker_path)
    if spec is None or spec.loader is None:
        raise TransitionError("execution_broker_unavailable")
    broker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(broker)
    config = broker.load_config()
    broker.verify_v2_envelope(envelope, approval, config)
    wrong = json.loads(json.dumps(config))
    wrong["approval"]["public_key_sha256"] = "0" * 64
    try:
        broker.verify_v2_envelope(envelope, approval, wrong)
    except broker.Rejected:
        pass
    else:
        raise TransitionError("wrong_key_was_accepted")
    with tempfile.TemporaryDirectory(prefix="execution-approval-replay-") as directory:
        root = Path(directory)
        for name in ("pending", "claims", "responses", "consumed"):
            (root / name).mkdir(mode=0o700)
        response = {
            "schema":"secure-sandbox-execution-approval-response-v1",
            "approval_id":approval["approval_id"], "status":"approved", "envelope":envelope,
        }
        response_path = root / "responses" / f"{approval['approval_id']}.json"
        atomic(response_path, response, 0o640)
        broker.await_operator_approval(approval, config, root=root, trusted_uid=0)
        atomic(response_path, response, 0o640)
        try:
            broker.await_operator_approval(approval, config, root=root, trusted_uid=0)
        except broker.Rejected as error:
            if str(error) != "approval_replayed":
                raise TransitionError("replay_gate_invalid") from error
        else:
            raise TransitionError("replay_was_accepted")
    return {
        "schema":"secure-sandbox-execution-approval-negative-gates-v1",
        "status":"verified", "approval_id":approval["approval_id"],
        "wrong_key_rejected":True, "replay_rejected":True,
        "verified_at":int(time.time()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    apply_parser = sub.add_parser("apply")
    apply_parser.add_argument("--record", type=Path, required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--approval", type=Path, required=True)
    verify_parser.add_argument("--envelope", type=Path, required=True)
    acceptance_parser = sub.add_parser("verify-acceptance")
    acceptance_parser.add_argument("--record", type=Path, required=True)
    negative_parser = sub.add_parser("verify-negative")
    negative_parser.add_argument("--approval", type=Path, required=True)
    negative_parser.add_argument("--envelope", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "apply":
            result = apply(args.record)
        elif args.command == "verify":
            result = verify_envelope(args.approval, args.envelope)
        elif args.command == "verify-acceptance":
            result = verify_acceptance(args.record)
        else:
            result = verify_negative_gates(args.approval, args.envelope)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (TransitionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(json.dumps({"error":str(error), "status":"rejected"}, sort_keys=True), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
