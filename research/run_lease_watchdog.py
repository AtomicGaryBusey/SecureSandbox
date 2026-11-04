#!/usr/bin/env python3
"""Terminate the exact tagged Claude process group when a run lease expires."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from shared.harness_runtime_binding import HarnessBindingError, validate_binding
from shared.model_stack_runtime_binding import BROKERED_MODE
from shared.runtime_authority import RuntimeAuthorityError, validate_binding as validate_runtime_authority
from session_policy_runtime import measure as measure_session_policy

RUN_DIRECTORY = Path("/run/secure-sandbox")
LIFECYCLE_DIRECTORY = Path("/var/lib/secure-sandbox/run-lifecycle")
LIFECYCLE_FILE = LIFECYCLE_DIRECTORY / "active.json"
FAILURE_FILE = LIFECYCLE_DIRECTORY / "failure-latched.json"
EXECUTION_APPROVAL_MIGRATION_FENCE = (
    LIFECYCLE_DIRECTORY / "execution-approval-migration-fence.json"
)
EXECUTION_APPROVAL_ACCEPTANCE_PERMIT = (
    LIFECYCLE_DIRECTORY / "execution-approval-acceptance-permit.json"
)
COMPLETED_DIRECTORY = LIFECYCLE_DIRECTORY / "completed"
CAPTURE_RECEIPTS = LIFECYCLE_DIRECTORY / "capture-receipts"
CAPTURE = "/usr/local/libexec/secure-sandbox/conversation_capture.py"
CAPTURE_RECIPIENT = "/etc/secure-sandbox/conversation-recipient.txt"
SYSTEMCTL = "/usr/bin/systemctl"
CGROUP_ROOT = Path("/sys/fs/cgroup")
RUN_ID_FILE = RUN_DIRECTORY / "run-id"
EVIDENCE_RUN_ID_FILE = RUN_DIRECTORY / "evidence-run-id"
LEASE_FILE = RUN_DIRECTORY / "run-lease.json"
PROCESS_FILE = RUN_DIRECTORY / "run-process.json"
LOCK_FILE = RUN_DIRECTORY / "run-lease.lock"
CLOSE_LOCK_FILE = RUN_DIRECTORY / "run-close.lock"
PROC = Path("/proc")
SCHEMA = "secure-sandbox-research-run-lease-v3"
PROCESS_SCHEMA = "secure-sandbox-run-process-v3"
LIFECYCLE_SCHEMA = "secure-sandbox-run-lifecycle-v3"
GATEWAY_LEASE_SCHEMA = "secure-sandbox-run-lease-v3"
GATEWAY_TRANSPORT_SCHEMA = "secure-sandbox-brokered-run-transport-v1"
ARM_SCHEMA = "secure-sandbox-research-run-arm-v3"
RENEW_SCHEMA = "secure-sandbox-research-run-renew-v3"
MAX_ARM_BYTES = 256 * 1024
MAX_STATE_BYTES = 512 * 1024
TRUSTED_UID = 0
INSTALL_PENDING = Path("/var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending")
MODEL_PROFILE_FENCE = Path("/var/lib/secure-sandbox/model-profile-activation.pending")
HARNESS_ACTIVATION_FENCE = Path("/var/lib/secure-sandbox/harnesses/activation-fence.json")
HARNESS_INSPECTOR = "/usr/local/libexec/secure-sandbox/harness-generation.py"

GATEWAY_LEASE_FIELDS = {
    "schema", "lease_id", "run_id", "profile", "issued_at", "expires_at",
    "maximum_expires_at", "runtime_authority", "brokered_transport", "limits",
    "pricing", "renewals",
}
RESEARCH_LEASE_FIELDS = {
    "schema", "run_id", "lease_id", "expires_at", "maximum_expires_at",
    "runtime_authority", "gateway_lease", "gateway_lease_sha256",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
PROFILE = re.compile(r"[a-z][a-z0-9-]{0,31}")


def canonical_uuid4(value: str, name: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a canonical UUIDv4") from error
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError(f"{name} must be a canonical UUIDv4")
    return str(parsed)


def canonical_json_line(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("control payload is not canonicalizable") from error


def parse_control_payload(raw: bytes, schema: str) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_ARM_BYTES:
        raise ValueError("control payload size is invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("control payload is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "gateway_lease"}
        or value.get("schema") != schema
    ):
        raise ValueError("control payload is invalid")
    if raw != canonical_json_line(value):
        raise ValueError("control payload is noncanonical")
    return value


def parse_arm_payload(raw: bytes) -> dict[str, Any]:
    return parse_control_payload(raw, ARM_SCHEMA)


def parse_renew_payload(raw: bytes) -> dict[str, Any]:
    return parse_control_payload(raw, RENEW_SCHEMA)


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"invalid Gateway lease {label}")
    return value


def _positive_integer(value: object, label: str) -> int:
    result = _nonnegative_integer(value, label)
    if result < 1:
        raise ValueError(f"invalid Gateway lease {label}")
    return result


def gateway_lease_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_line(value)).hexdigest()


def validate_gateway_lease(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != GATEWAY_LEASE_FIELDS
        or value.get("schema") != GATEWAY_LEASE_SCHEMA
    ):
        raise ValueError("invalid Gateway lease fields")
    run_id = canonical_uuid4(str(value.get("run_id", "")), "run ID")
    lease_id = canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    profile = value.get("profile")
    if not isinstance(profile, str) or PROFILE.fullmatch(profile) is None:
        raise ValueError("invalid Gateway lease profile")
    issued_at = _nonnegative_integer(value.get("issued_at"), "issued_at")
    expires_at = _nonnegative_integer(value.get("expires_at"), "expires_at")
    maximum_expires_at = _nonnegative_integer(
        value.get("maximum_expires_at"), "maximum_expires_at"
    )
    renewals = _nonnegative_integer(value.get("renewals"), "renewals")
    if not issued_at <= expires_at <= maximum_expires_at:
        raise ValueError("invalid Gateway lease time bounds")
    try:
        authority = validate_runtime_authority(value.get("runtime_authority"))
    except RuntimeAuthorityError as error:
        raise ValueError("invalid Gateway runtime authority") from error
    if authority["model_stack_binding"]["mode"] != BROKERED_MODE:
        raise PermissionError("native runtime transport is unavailable")
    transport = value.get("brokered_transport")
    if (
        not isinstance(transport, dict)
        or set(transport) != {"schema", "relay_sha256", "policy_sha256"}
        or transport.get("schema") != GATEWAY_TRANSPORT_SCHEMA
        or SHA256.fullmatch(str(transport.get("relay_sha256", ""))) is None
        or SHA256.fullmatch(str(transport.get("policy_sha256", ""))) is None
    ):
        raise ValueError("invalid Gateway brokered transport")
    limit_fields = {
        "max_requests", "max_input_tokens", "max_output_tokens", "max_cost_microusd"
    }
    limits = value.get("limits")
    if not isinstance(limits, dict) or set(limits) != limit_fields:
        raise ValueError("invalid Gateway lease limits")
    for field in limit_fields:
        _positive_integer(limits.get(field), field)
    price_fields = {
        "input_microusd_per_million_tokens",
        "output_microusd_per_million_tokens",
    }
    pricing = value.get("pricing")
    if not isinstance(pricing, dict) or set(pricing) != price_fields:
        raise ValueError("invalid Gateway lease pricing")
    for field in price_fields:
        _positive_integer(pricing.get(field), field)
    return {
        "schema": GATEWAY_LEASE_SCHEMA,
        "lease_id": lease_id,
        "run_id": run_id,
        "profile": profile,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "maximum_expires_at": maximum_expires_at,
        "runtime_authority": authority,
        "brokered_transport": transport,
        "limits": limits,
        "pricing": pricing,
        "renewals": renewals,
    }


def validate_current_runtime(gateway_lease: dict[str, Any]) -> dict[str, Any]:
    authority = gateway_lease["runtime_authority"]
    harness = authority["harness_binding"]
    observed_harness = read_harness_binding(harness["harness_generation_id"])
    if observed_harness != harness:
        raise PermissionError("protected harness runtime binding mismatch")
    context = authority["session_context_binding"]
    source_argument = context["source_id"] if context["source_id"] is not None else "none"
    observed_policy = measure_session_policy(source_argument)
    policy_fields = {
        "schema", "source_id", "source_manifest_sha256", "persona_sha256",
        "tool_catalog_sha256", "extension_set_sha256",
    }
    if not isinstance(observed_policy, dict) or set(observed_policy) != policy_fields:
        raise PermissionError("Research session policy measurement is invalid")
    expected_policy = {
        "schema": "secure-sandbox-session-policy-runtime-v1",
        "source_id": context["source_id"],
        "source_manifest_sha256": context["source_manifest_sha256"],
        "persona_sha256": context["persona_sha256"],
        "tool_catalog_sha256": context["tool_catalog_sha256"],
        "extension_set_sha256": context["extension_set_sha256"],
    }
    if observed_policy != expected_policy:
        raise PermissionError("Research session policy binding mismatch")
    return authority


def validate_research_lease(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != RESEARCH_LEASE_FIELDS
        or value.get("schema") != SCHEMA
    ):
        raise ValueError("invalid Research lease fields")
    run_id = canonical_uuid4(str(value.get("run_id", "")), "run ID")
    lease_id = canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    expires_at = _nonnegative_integer(value.get("expires_at"), "expires_at")
    maximum_expires_at = _nonnegative_integer(
        value.get("maximum_expires_at"), "maximum_expires_at"
    )
    try:
        authority = validate_runtime_authority(value.get("runtime_authority"))
    except RuntimeAuthorityError as error:
        raise ValueError("invalid Research runtime authority") from error
    gateway = validate_gateway_lease(value.get("gateway_lease"))
    supplied_digest = value.get("gateway_lease_sha256")
    if (
        not isinstance(supplied_digest, str)
        or SHA256.fullmatch(supplied_digest) is None
        or supplied_digest != gateway_lease_sha256(gateway)
    ):
        raise ValueError("invalid Research Gateway lease digest")
    if (
        gateway["run_id"] != run_id
        or gateway["lease_id"] != lease_id
        or gateway["runtime_authority"] != authority
        or gateway["maximum_expires_at"] != maximum_expires_at
        or expires_at > gateway["expires_at"]
        or expires_at > maximum_expires_at
    ):
        raise ValueError("Research and Gateway lease binding mismatch")
    return {
        "schema": SCHEMA,
        "run_id": run_id,
        "lease_id": lease_id,
        "expires_at": expires_at,
        "maximum_expires_at": maximum_expires_at,
        "runtime_authority": authority,
        "gateway_lease": gateway,
        "gateway_lease_sha256": supplied_digest,
    }


def read_harness_binding(generation_id: str | None) -> dict[str, str]:
    command = [HARNESS_INSPECTOR, "active-runtime"] if generation_id is None else [
        HARNESS_INSPECTOR, "generation-runtime", generation_id,
    ]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, check=False,
                            timeout=10, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 32 * 1024:
        raise PermissionError("protected harness runtime binding is unavailable")
    try:
        return validate_binding(json.loads(result.stdout))
    except (HarnessBindingError, json.JSONDecodeError) as error:
        raise PermissionError("protected harness runtime binding is invalid") from error


def atomic_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o755 if path.parent == LIFECYCLE_DIRECTORY else 0o700,
                      parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.chown(temporary, 0, 0); os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def atomic_text(path: Path, value: str, mode: int = 0o644) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(descriptor, value.encode("ascii")); os.fsync(descriptor)
        os.fchmod(descriptor, mode); os.fchown(descriptor, 0, 0)
    finally:
        os.close(descriptor)
    os.replace(temporary, path); fsync_directory(path.parent)


def load_root_json(path: Path, schema: str, mode: int = 0o600) -> dict[str, Any]:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != TRUSTED_UID
            or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_STATE_BYTES):
        raise PermissionError(f"invalid {path.name} ownership or mode")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError(f"invalid {path.name} opened identity")
        raw = handle.read(MAX_STATE_BYTES + 1)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {path.name} JSON") from error
    if raw != canonical_json_line(value):
        raise ValueError(f"noncanonical {path.name}")
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError(f"invalid {path.name} schema")
    return value


def lifecycle() -> dict[str, Any]:
    value = load_root_json(LIFECYCLE_FILE, LIFECYCLE_SCHEMA, 0o644)
    run_id = canonical_uuid4(str(value.get("run_id", "")), "run ID")
    lease_id = canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    session_id = canonical_uuid4(str(value.get("session_id", "")), "session ID")
    if value.get("phase") not in {"preparing", "active", "closing", "local_closed", "failure_latched"}:
        raise ValueError("invalid lifecycle phase")
    if value.get("unit") != unit_name(run_id):
        raise ValueError("invalid lifecycle unit")
    if (
        isinstance(value.get("expires_at"), bool)
        or not isinstance(value.get("expires_at"), int)
        or value["expires_at"] < 0
        or SHA256.fullmatch(str(value.get("runtime_authority_sha256", ""))) is None
        or SHA256.fullmatch(str(value.get("gateway_lease_sha256", ""))) is None
    ):
        raise ValueError("invalid lifecycle authority binding")
    value["run_id"] = run_id
    value["lease_id"] = lease_id
    value["session_id"] = session_id
    return value


def process_ids_for_uid_strict(uid: int) -> set[int]:
    result: set[int] = set()
    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status_text = (entry / "status").read_text(encoding="ascii")
            state_line = next(line for line in status_text.splitlines() if line.startswith("State:"))
            uid_line = next(line for line in status_text.splitlines() if line.startswith("Uid:"))
            real_uid = int(uid_line.split()[1])
            if real_uid == uid and "Z" not in state_line.split()[1]:
                result.add(int(entry.name))
        except FileNotFoundError:
            continue
        except (OSError, StopIteration, ValueError, IndexError) as error:
            raise RuntimeError("cannot prove agent process inventory") from error
    return result


def unit_name(run_id: str) -> str:
    return "secure-sandbox-run-" + canonical_uuid4(run_id, "run ID") + ".scope"


def unit_cgroup(unit: str) -> Path:
    result = subprocess.run([SYSTEMCTL, "show", "--property=ControlGroup", "--value", unit],
                            capture_output=True, text=True, check=False, timeout=10)
    value = result.stdout.strip()
    if (result.returncode != 0 or value == "/" or not value.startswith("/")
            or ".." in value.split("/") or not unit.startswith("secure-sandbox-run-")
            or not unit.endswith(".scope")):
        raise RuntimeError("cannot resolve run cgroup")
    return CGROUP_ROOT / value.lstrip("/")


def cgroup_populated(path: Path) -> bool:
    values = dict(line.split(maxsplit=1) for line in (path / "cgroup.events").read_text().splitlines())
    if values.get("populated") not in {"0", "1"}:
        raise RuntimeError("invalid cgroup events")
    return values["populated"] == "1"


def kill_run_cgroup(unit: str) -> None:
    path = unit_cgroup(unit)
    if (path / "cgroup.freeze").exists():
        (path / "cgroup.freeze").write_text("1\n", encoding="ascii")
    (path / "cgroup.kill").write_text("1\n", encoding="ascii")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not cgroup_populated(path):
            return
        time.sleep(0.05)
    raise RuntimeError("run cgroup remains populated")


def kill_agent_uid(uid: int) -> None:
    deadline = time.monotonic() + 10
    while True:
        processes = process_ids_for_uid_strict(uid)
        if not processes:
            return
        for pid in processes:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        if time.monotonic() >= deadline:
            raise RuntimeError("agent processes remain after emergency kill")
        time.sleep(0.05)


def stop_agent_user_manager(uid: int) -> None:
    unit = f"user@{uid}.service"
    stopped = subprocess.run([SYSTEMCTL, "stop", unit], capture_output=True, text=True,
                             check=False, timeout=10)
    if stopped.returncode != 0:
        raise RuntimeError("agent user manager did not stop cleanly")
    active = subprocess.run([SYSTEMCTL, "is-active", "--quiet", unit], capture_output=True,
                            text=True, check=False, timeout=5)
    if active.returncode == 0:
        raise RuntimeError("agent user manager remains active")
    subprocess.run([SYSTEMCTL, "reset-failed", unit], capture_output=True, text=True,
                   check=False, timeout=5)
    failed = subprocess.run([SYSTEMCTL, "is-failed", "--quiet", unit], capture_output=True,
                            text=True, check=False, timeout=5)
    if failed.returncode == 0:
        raise RuntimeError("agent user manager failure state could not be cleared")


def capture_operation(command: str, run_id: str) -> dict[str, Any]:
    result = subprocess.run([CAPTURE, "--recipient-file", CAPTURE_RECIPIENT,
                             f"--{command}", run_id], capture_output=True, text=True,
                            check=False, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"conversation capture {command} failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("run_id") != run_id:
        raise RuntimeError(f"invalid conversation capture {command} receipt")
    return value


PROCESS_BASE_FIELDS = {
    "schema", "run_id", "lease_id", "ready", "unit", "runtime_authority",
    "gateway_lease_sha256",
}


def validate_process_record(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != PROCESS_SCHEMA:
        raise ValueError("invalid process record schema")
    fields = set(value)
    seed = PROCESS_BASE_FIELDS
    claimed = seed | {"supervisor_pid", "supervisor_start_time"}
    ready = claimed | {"scope_pid"}
    failed = claimed | {"launch_failed", "scope_empty", "exited_at"}
    terminal = ready | {"scope_empty", "exit_status", "exited_at"}
    variants = {frozenset(item) for item in (seed, claimed, ready, failed, terminal)}
    if frozenset(fields) not in variants:
        raise ValueError("invalid process record fields")
    run_id = canonical_uuid4(str(value.get("run_id", "")), "run ID")
    lease_id = canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    if value.get("unit") != unit_name(run_id) or not isinstance(value.get("ready"), bool):
        raise ValueError("invalid process record identity")
    try:
        authority = validate_runtime_authority(value.get("runtime_authority"))
    except RuntimeAuthorityError as error:
        raise ValueError("invalid process runtime authority") from error
    gateway_digest = value.get("gateway_lease_sha256")
    if not isinstance(gateway_digest, str) or SHA256.fullmatch(gateway_digest) is None:
        raise ValueError("invalid process Gateway lease digest")
    if fields == seed:
        if value["ready"] is not False:
            raise ValueError("invalid process seed state")
    else:
        for field in ("supervisor_pid", "supervisor_start_time"):
            if (
                isinstance(value.get(field), bool)
                or not isinstance(value.get(field), int)
                or value[field] < 1
            ):
                raise ValueError("invalid process supervisor identity")
        if fields == claimed and value["ready"] is not False:
            raise ValueError("invalid claimed process state")
        if fields in (ready, terminal):
            if (
                value["ready"] is not True
                or isinstance(value.get("scope_pid"), bool)
                or not isinstance(value.get("scope_pid"), int)
                or value["scope_pid"] < 1
            ):
                raise ValueError("invalid ready process state")
        if fields == failed:
            if (
                value["ready"] is not False
                or value.get("scope_empty") is not True
                or not isinstance(value.get("launch_failed"), str)
                or not value["launch_failed"]
            ):
                raise ValueError("invalid failed process state")
        if fields == terminal:
            if (
                value.get("scope_empty") is not True
                or isinstance(value.get("exit_status"), bool)
                or not isinstance(value.get("exit_status"), int)
            ):
                raise ValueError("invalid terminal process state")
        if fields in (failed, terminal):
            if (
                isinstance(value.get("exited_at"), bool)
                or not isinstance(value.get("exited_at"), int)
                or value["exited_at"] < 0
            ):
                raise ValueError("invalid process exit time")
    return {**value, "run_id": run_id, "lease_id": lease_id,
            "runtime_authority": authority}


def recorded_scope_empty(state: dict[str, Any]) -> bool:
    registration = validate_process_record(load_root_json(PROCESS_FILE, PROCESS_SCHEMA))
    if (registration.get("run_id") != state.get("run_id")
            or registration.get("lease_id") != state.get("lease_id")
            or registration.get("unit") != state.get("unit")
            or registration["runtime_authority"]["binding_sha256"]
            != state.get("runtime_authority_sha256")
            or registration["gateway_lease_sha256"]
            != state.get("gateway_lease_sha256")):
        return False
    if registration.get("ready") is False:
        return "supervisor_pid" not in registration or registration.get("scope_empty") is True
    return (registration.get("ready") is True and registration.get("scope_empty") is True
            and isinstance(registration.get("exit_status"), int)
            and isinstance(registration.get("exited_at"), int))


def await_scope_empty_receipt(state: dict[str, Any], seconds: float = 2.0) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        try:
            if recorded_scope_empty(state):
                return True
        except (FileNotFoundError, PermissionError, ValueError, json.JSONDecodeError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def scope_is_empty(state: dict[str, Any]) -> bool:
    try:
        return not cgroup_populated(unit_cgroup(str(state["unit"])))
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return recorded_scope_empty(state)


def validate_capture_receipt(receipt: dict[str, Any], run_id: str) -> None:
    if receipt.get("run_id") != run_id:
        raise RuntimeError("capture receipt run mismatch")
    sequence = receipt.get("final_sequence")
    chunks = receipt.get("chunks")
    journals = receipt.get("journals")
    prepared = receipt.get("prepared_offsets")
    if (isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0
            or not isinstance(chunks, list) or len(chunks) != sequence
            or not isinstance(journals, list) or not isinstance(prepared, dict)):
        raise RuntimeError("invalid capture receipt structure")
    previous = ""
    for expected, chunk in enumerate(chunks):
        if (not isinstance(chunk, dict) or chunk.get("sequence") != expected
                or not isinstance(chunk.get("journal_identity"), str)
                or isinstance(chunk.get("start_offset"), bool)
                or not isinstance(chunk.get("start_offset"), int)
                or isinstance(chunk.get("end_offset"), bool)
                or not isinstance(chunk.get("end_offset"), int)
                or chunk["start_offset"] < 0 or chunk["end_offset"] <= chunk["start_offset"]
                or len(str(chunk.get("cipher_sha256", ""))) != 64
                or any(character not in "0123456789abcdef"
                       for character in str(chunk.get("cipher_sha256", "")))):
            raise RuntimeError("invalid capture receipt chunk")
        previous = str(chunk["cipher_sha256"])
    if receipt.get("final_cipher_sha256") != previous:
        raise RuntimeError("capture receipt chain head mismatch")
    for identity, offset in prepared.items():
        if not isinstance(identity, str) or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise RuntimeError("invalid prepared capture offset")
    final_identities: set[str] = set()
    for journal in journals:
        if (not isinstance(journal, dict) or not isinstance(journal.get("identity"), str)
                or isinstance(journal.get("snapshot_size"), bool)
                or not isinstance(journal.get("snapshot_size"), int)
                or journal.get("final_offset") != journal.get("snapshot_size")
                or journal["snapshot_size"] < 0):
            raise RuntimeError("capture receipt does not prove terminal offsets")
        if journal["identity"] in final_identities:
            raise RuntimeError("duplicate journal in capture receipt")
        final_identities.add(journal["identity"])
    if not set(prepared).issubset(final_identities):
        raise RuntimeError("prepared journal missing from capture receipt")
    if any(str(chunk["journal_identity"]) not in final_identities for chunk in chunks):
        raise RuntimeError("capture chunk lacks a terminal journal proof")


def validated_snapshot(lease: dict[str, Any]) -> dict[str, Any]:
    lease = validate_research_lease(lease)
    state = lifecycle()
    if (state.get("run_id") != lease.get("run_id")
            or state.get("lease_id") != lease.get("lease_id")
            or state.get("session_id")
            != lease["runtime_authority"]["session_context_binding"]["session_id"]
            or state.get("runtime_authority_sha256")
            != lease["runtime_authority"]["binding_sha256"]
            or state.get("gateway_lease_sha256") != lease["gateway_lease_sha256"]
            or state.get("expires_at") != lease["expires_at"]):
        raise RuntimeError("lease and lifecycle identity mismatch")
    phase = state.get("phase")
    if phase not in {"active", "closing", "local_closed"}:
        raise RuntimeError("lease has invalid lifecycle phase")
    if phase == "active":
        try:
            metadata = RUN_ID_FILE.lstat()
            marker = RUN_ID_FILE.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise RuntimeError("active admission marker mismatch") from error
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != TRUSTED_UID
                or stat.S_IMODE(metadata.st_mode) != 0o644 or metadata.st_nlink != 1
                or marker != lease.get("run_id")):
            raise RuntimeError("active admission marker mismatch")
    return state


def latch_failure(run_id: str, operation: str, error: BaseException) -> None:
    value = {"schema":LIFECYCLE_SCHEMA,"phase":"failure_latched","run_id":run_id,
             "operation":operation,"error":type(error).__name__,"latched_at":int(time.time())}
    atomic_json(FAILURE_FILE, value)
    try:
        current = lifecycle(); current.update(value); atomic_json(LIFECYCLE_FILE, current, 0o644)
    except Exception:
        pass


@contextlib.contextmanager
def lease_lock():
    descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextlib.contextmanager
def close_lock():
    descriptor = os.open(CLOSE_LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def arm(gateway_lease: object) -> dict[str, Any]:
    gateway = validate_gateway_lease(gateway_lease)
    run_id = gateway["run_id"]
    lease_id = gateway["lease_id"]
    expires_at = gateway["expires_at"]
    maximum_expires_at = gateway["maximum_expires_at"]
    authority = gateway["runtime_authority"]
    context = authority["session_context_binding"]
    session_id = context["session_id"]
    gateway_digest = gateway_lease_sha256(gateway)
    if expires_at <= int(time.time()):
        raise ValueError("lease expiry must be in the future")
    with lease_lock():
        acceptance = None
        permit: dict[str, Any] | None = None
        if EXECUTION_APPROVAL_MIGRATION_FENCE.exists():
            try:
                permit = load_root_json(
                    EXECUTION_APPROVAL_ACCEPTANCE_PERMIT,
                    "secure-sandbox-execution-approval-acceptance-permit-v1",
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                raise PermissionError(
                    "execution approval migration has closed Research admission"
                ) from error
            required = {
                "schema", "status", "transaction_id", "generation_id", "generation_epoch",
                "run_id", "session_id", "source_id", "code_sha256",
                "fixture_manifest_sha256", "timeout_seconds", "runtime_image_id", "expires_at",
                "acceptance_attempt_id", "acceptance_attempt_number",
                "previous_acceptance_binding_sha256", "acceptance_binding_sha256",
            }
            now = int(time.time())
            if (set(permit) != required or permit.get("status") != "ready"
                    or permit.get("run_id") != run_id or permit.get("session_id") != session_id
                    or permit.get("source_id") != context["source_id"]
                    or isinstance(permit.get("expires_at"), bool)
                    or not isinstance(permit.get("expires_at"), int)
                    or permit["expires_at"] < now or expires_at > permit["expires_at"]):
                raise PermissionError("execution approval migration has closed Research admission")
            acceptance = {name:permit[name] for name in permit if name not in {"schema", "status"}}
        if (INSTALL_PENDING.exists() or MODEL_PROFILE_FENCE.exists()
                or HARNESS_ACTIVATION_FENCE.exists()
                or LEASE_FILE.exists() or LIFECYCLE_FILE.exists() or FAILURE_FILE.exists()
                or RUN_ID_FILE.exists() or EVIDENCE_RUN_ID_FILE.exists()):
            raise FileExistsError("a Research run lease is already armed")
        agent_uid = pwd.getpwnam("agent").pw_uid
        if process_ids_for_uid_strict(agent_uid):
            raise RuntimeError("agent processes exist before run arm")
        # These are independent protected readbacks, not host-supplied claims.
        # Keep them inside the publication lock so no Research run can race a
        # second arm between measurement and durable state creation.
        validate_current_runtime(gateway)
        value = validate_research_lease({
            "schema": SCHEMA,
            "run_id": run_id,
            "lease_id": lease_id,
            "expires_at": expires_at,
            "maximum_expires_at": maximum_expires_at,
            "runtime_authority": authority,
            "gateway_lease": gateway,
            "gateway_lease_sha256": gateway_digest,
        })
        state = {"schema":LIFECYCLE_SCHEMA,"phase":"preparing","run_id":run_id,
                 "session_id":session_id,
                 "lease_id":lease_id,"expires_at":expires_at,"unit":unit_name(run_id),
                 "runtime_authority_sha256":authority["binding_sha256"],
                 "gateway_lease_sha256":gateway_digest,
                 "preparing_at":int(time.time())}
        if acceptance is not None:
            state["execution_approval_acceptance"] = acceptance
        atomic_json(LIFECYCLE_FILE, state, 0o644)
        try:
            capture_operation("prepare", run_id)
            atomic_json(LEASE_FILE, value)
            process = {"schema": PROCESS_SCHEMA, "run_id": run_id,
                       "lease_id": lease_id, "ready": False, "unit":unit_name(run_id),
                       "runtime_authority":authority,
                       "gateway_lease_sha256":gateway_digest}
            atomic_json(PROCESS_FILE, process)
            state["phase"] = "active"; state["armed_at"] = int(time.time())
            atomic_json(LIFECYCLE_FILE, state, 0o644)
            atomic_text(RUN_ID_FILE, run_id + "\n")
            if acceptance is not None and permit is not None:
                atomic_json(
                    EXECUTION_APPROVAL_ACCEPTANCE_PERMIT,
                    {**permit, "status":"consumed", "consumed_at":int(time.time())},
                )
        except Exception as error:
            try: LEASE_FILE.unlink()
            except FileNotFoundError: pass
            try: PROCESS_FILE.unlink()
            except FileNotFoundError: pass
            latch_failure(run_id, "arm", error)
            raise
        return value


def _close(run_id: str, require_expired: bool = False) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    state: dict[str, Any]
    with lease_lock():
        state = lifecycle()
        if state["run_id"] != run_id:
            raise PermissionError("lifecycle belongs to another run")
        if require_expired and int(time.time()) < int(load_lease()["expires_at"]):
            return state
        if state["phase"] == "local_closed":
            return state
        try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
        except FileNotFoundError: pass
        state["phase"] = "closing"; state["admission_revoked_at"] = int(time.time())
        atomic_json(LIFECYCLE_FILE, state, 0o644)
    # Do not hold the lifecycle lock while the scope supervisor records its
    # terminal receipt or while capture takes its independent lock.
    try:
        cgroup_error = None
        try: kill_run_cgroup(str(state["unit"]))
        except Exception as error: cgroup_error = error
        agent_uid = pwd.getpwnam("agent").pw_uid
        user_manager_error = None
        try: stop_agent_user_manager(agent_uid)
        except Exception as error: user_manager_error = error
        # A clean systemd stop is the normal path.  The strict UID sweep remains
        # the fail-closed backstop and runs even when the manager stop fails.
        kill_agent_uid(agent_uid)
        if user_manager_error is not None:
            raise RuntimeError("agent user manager cleanup failed") from user_manager_error
        if cgroup_error is not None and not await_scope_empty_receipt(state):
            raise RuntimeError("run cgroup closure was not proven") from cgroup_error
        receipt = capture_operation("finalize", run_id)
        with lease_lock():
            current = lifecycle()
            if (current.get("run_id") != run_id or current.get("lease_id") != state.get("lease_id")
                    or current.get("phase") not in {"closing", "local_closed"}):
                raise RuntimeError("lifecycle changed during close")
            current["phase"] = "local_closed"; current["local_closed_at"] = int(time.time())
            current["capture_receipt"] = str(CAPTURE_RECEIPTS / f"{run_id}.json")
            current["capture_final_sequence"] = receipt.get("final_sequence")
            atomic_json(LIFECYCLE_FILE, current, 0o644)
            return current
    except Exception as error:
        latch_failure(run_id, "close", error)
        raise


def close(run_id: str, require_expired: bool = False) -> dict[str, Any]:
    with close_lock():
        return _close(run_id, require_expired)


def disarm(run_id: str) -> None:
    close(run_id)


def _commit(run_id: str, gateway_summary_sha256: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    if len(gateway_summary_sha256) != 64 or any(c not in "0123456789abcdef" for c in gateway_summary_sha256):
        raise ValueError("invalid Gateway summary digest")
    with lease_lock():
        state = lifecycle()
        if state["run_id"] != run_id or state["phase"] != "local_closed":
            raise RuntimeError("run is not locally closed")
        lease = load_lease()
        registration = validate_process_record(load_root_json(PROCESS_FILE, PROCESS_SCHEMA))
        if (
            lease["run_id"] != run_id
            or lease["lease_id"] != state["lease_id"]
            or lease["runtime_authority"]["binding_sha256"]
            != state["runtime_authority_sha256"]
            or lease["gateway_lease_sha256"] != state["gateway_lease_sha256"]
            or registration["run_id"] != run_id
            or registration["lease_id"] != lease["lease_id"]
            or registration["runtime_authority"] != lease["runtime_authority"]
            or registration["gateway_lease_sha256"] != lease["gateway_lease_sha256"]
        ):
            raise RuntimeError("completed runtime authority mismatch")
        if not scope_is_empty(state):
            raise RuntimeError("run cgroup is not proven empty during commit")
        if process_ids_for_uid_strict(pwd.getpwnam("agent").pw_uid):
            raise RuntimeError("agent processes remain during commit")
        receipt = load_root_json(CAPTURE_RECEIPTS / f"{run_id}.json",
                                 "secure-sandbox-capture-final-v1")
        validate_capture_receipt(receipt, run_id)
        if FAILURE_FILE.exists():
            failure = load_root_json(FAILURE_FILE, LIFECYCLE_SCHEMA)
            if failure.get("run_id") != run_id:
                raise RuntimeError("failure latch belongs to another run")
        completed = {
            **state,
            "phase":"committed",
            "committed_at":int(time.time()),
            "gateway_summary_sha256":gateway_summary_sha256,
            "runtime_authority":lease["runtime_authority"],
            "gateway_lease":lease["gateway_lease"],
            "gateway_lease_sha256":lease["gateway_lease_sha256"],
        }
        atomic_json(COMPLETED_DIRECTORY / f"{run_id}.json", completed)
        for path in (LEASE_FILE, PROCESS_FILE, LIFECYCLE_FILE, FAILURE_FILE):
            try: path.unlink()
            except FileNotFoundError: pass
        fsync_directory(LIFECYCLE_DIRECTORY)
        return completed


def commit(run_id: str, gateway_summary_sha256: str) -> dict[str, Any]:
    with close_lock():
        return _commit(run_id, gateway_summary_sha256)


def status(run_id: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    with lease_lock():
        state = lifecycle()
        if state["run_id"] != run_id:
            raise PermissionError("lifecycle belongs to another run")
        return state


def completed_status(run_id: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    with lease_lock():
        value = load_root_json(COMPLETED_DIRECTORY / f"{run_id}.json", LIFECYCLE_SCHEMA)
        if (value.get("run_id") != run_id or value.get("phase") != "committed"
                or not isinstance(value.get("gateway_summary_sha256"), str)
                or len(value["gateway_summary_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in value["gateway_summary_sha256"])):
            raise ValueError("invalid completed lifecycle")
        try:
            authority = validate_runtime_authority(value.get("runtime_authority"))
            gateway = validate_gateway_lease(value.get("gateway_lease"))
        except (RuntimeAuthorityError, PermissionError, ValueError) as error:
            raise ValueError("invalid completed lifecycle") from error
        if (
            gateway["run_id"] != run_id
            or gateway["lease_id"] != value.get("lease_id")
            or gateway["runtime_authority"] != authority
            or authority["binding_sha256"] != value.get("runtime_authority_sha256")
            or gateway_lease_sha256(gateway) != value.get("gateway_lease_sha256")
        ):
            raise ValueError("invalid completed lifecycle")
        value["runtime_authority"] = authority
        value["gateway_lease"] = gateway
        return value


def emergency() -> dict[str, Any]:
    agent_uid = pwd.getpwnam("agent").pw_uid
    state: dict[str, Any] | None = None
    try:
        state = lifecycle()
        return close(str(state["run_id"]))
    except Exception as error:
        try: kill_agent_uid(agent_uid)
        finally: latch_failure(str(state["run_id"]) if state is not None else "unknown",
                               "emergency", error)
        raise


def renew(gateway_lease: object) -> dict[str, Any]:
    gateway = validate_gateway_lease(gateway_lease)
    with lease_lock():
        value = load_lease()
        run_id = value["run_id"]
        lease_id = value["lease_id"]
        if gateway["run_id"] != run_id or gateway["lease_id"] != lease_id:
            raise PermissionError("armed lease identity mismatch")
        previous_gateway = value["gateway_lease"]
        stable_fields = GATEWAY_LEASE_FIELDS - {"expires_at", "renewals"}
        if any(gateway[field] != previous_gateway[field] for field in stable_fields):
            raise PermissionError("renewed Gateway lease authority changed")
        if (
            gateway["expires_at"] <= previous_gateway["expires_at"]
            or gateway["renewals"] != previous_gateway["renewals"] + 1
        ):
            raise ValueError("renewed expiry must increase")
        state = lifecycle()
        if (state["run_id"] != run_id or state["lease_id"] != lease_id
                or state["phase"] != "active"
                or state["runtime_authority_sha256"]
                != value["runtime_authority"]["binding_sha256"]
                or state["gateway_lease_sha256"] != value["gateway_lease_sha256"]):
            raise PermissionError("active lifecycle identity mismatch")
        registration = validate_process_record(load_root_json(PROCESS_FILE, PROCESS_SCHEMA))
        if (
            registration["run_id"] != run_id
            or registration["lease_id"] != lease_id
            or registration["runtime_authority"] != value["runtime_authority"]
            or registration["gateway_lease_sha256"] != value["gateway_lease_sha256"]
        ):
            raise PermissionError("run process authority mismatch")
        validate_current_runtime(gateway)
        digest = gateway_lease_sha256(gateway)
        renewed = validate_research_lease({
            **value,
            "expires_at": gateway["expires_at"],
            "gateway_lease": gateway,
            "gateway_lease_sha256": digest,
        })
        registration["gateway_lease_sha256"] = digest
        state["expires_at"] = gateway["expires_at"]
        state["gateway_lease_sha256"] = digest
        # Readers use the same lease lock.  A crash between publications leaves
        # a closed mismatch rather than a partially renewed authority.
        atomic_json(LEASE_FILE, renewed)
        atomic_json(PROCESS_FILE, registration)
        atomic_json(LIFECYCLE_FILE, state, 0o644)
        return renewed


def expire(run_id: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    with lease_lock():
        value = load_lease()
        if value["run_id"] != run_id:
            raise PermissionError("armed lease belongs to another run")
        state = lifecycle()
        if (
            state["run_id"] != run_id
            or state["lease_id"] != value["lease_id"]
            or state["phase"] != "active"
            or state["runtime_authority_sha256"]
            != value["runtime_authority"]["binding_sha256"]
            or state["gateway_lease_sha256"] != value["gateway_lease_sha256"]
        ):
            raise PermissionError("active lifecycle identity mismatch")
        value["expires_at"] = min(value["expires_at"], int(time.time()) + 1)
        value = validate_research_lease(value)
        state["expires_at"] = value["expires_at"]
        atomic_json(LEASE_FILE, value)
        atomic_json(LIFECYCLE_FILE, state, 0o644)
        return value


def load_lease() -> dict[str, Any]:
    return validate_research_lease(load_root_json(LEASE_FILE, SCHEMA))


def watch() -> None:
    agent_uid = pwd.getpwnam("agent").pw_uid
    while True:
        lease = None
        state = None
        recovery_close = False
        state_error: BaseException | None = None
        with lease_lock():
            try:
                state = lifecycle()
            except FileNotFoundError:
                if RUN_ID_FILE.exists() or process_ids_for_uid_strict(agent_uid):
                    error = RuntimeError("durable lifecycle disappeared while admission or agent processes remained")
                    try:
                        try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
                        except FileNotFoundError: pass
                        kill_agent_uid(agent_uid)
                    finally: latch_failure("unknown", "watch", error)
                    raise error
            except Exception as error:
                print(json.dumps({"event":"lease_watchdog_failed","error":type(error).__name__}, separators=(",", ":")), flush=True)
                run_id = "unknown"
                try: run_id = lifecycle()["run_id"]
                except Exception: pass
                try:
                    try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
                    except FileNotFoundError: pass
                    kill_agent_uid(agent_uid)
                finally: latch_failure(run_id, "watch", error)
                raise
            if state is not None:
                phase = str(state["phase"])
                try:
                    lease = load_lease()
                    if (lease.get("run_id") != state.get("run_id")
                            or lease.get("lease_id") != state.get("lease_id")):
                        raise RuntimeError("lease and lifecycle identity mismatch")
                    if phase in {"active", "closing", "local_closed"}:
                        validated_snapshot(lease)
                except FileNotFoundError:
                    if phase in {"preparing", "active", "closing"}:
                        recovery_close = True
                    elif phase not in {"local_closed", "failure_latched"}:
                        raise
                except Exception as error:
                    try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
                    except FileNotFoundError: pass
                    recovery_close = True
                    lease = None
                    state_error = error
        if lease is None:
            if recovery_close and state is not None:
                close(str(state["run_id"]))
                if state_error is not None:
                    latch_failure(str(state["run_id"]), "watch_state", state_error)
                    print(json.dumps({"event":"lease_watchdog_state_latched",
                                      "run_id":state["run_id"],
                                      "error":type(state_error).__name__},
                                     separators=(",", ":"), sort_keys=True), flush=True)
            time.sleep(0.5)
            continue
        assert state is not None
        if state["phase"] == "failure_latched":
            time.sleep(0.5)
            continue
        if state["phase"] in {"closing", "local_closed"}:
            if state["phase"] == "closing":
                state = close(str(lease["run_id"]))
            while LIFECYCLE_FILE.exists():
                time.sleep(0.5)
            continue
        now = int(time.time())
        if now < lease["expires_at"]:
            time.sleep(min(1, lease["expires_at"] - now)); continue
        state = close(lease["run_id"], require_expired=True)
        if state.get("phase") == "local_closed":
            print(json.dumps({"event":"lease_watchdog_expired","run_id":lease["run_id"],
                              "lease_id":lease["lease_id"]}, separators=(",", ":"), sort_keys=True), flush=True)
            while LIFECYCLE_FILE.exists():
                time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command")
    sub.add_parser("arm-v3")
    disarm_parser = sub.add_parser("disarm"); disarm_parser.add_argument("run_id")
    close_parser = sub.add_parser("close"); close_parser.add_argument("run_id")
    commit_parser = sub.add_parser("commit"); commit_parser.add_argument("run_id"); commit_parser.add_argument("gateway_summary_sha256")
    status_parser = sub.add_parser("status"); status_parser.add_argument("run_id")
    completed_parser = sub.add_parser("completed"); completed_parser.add_argument("run_id")
    sub.add_parser("emergency")
    sub.add_parser("renew-v3")
    expire_parser = sub.add_parser("expire"); expire_parser.add_argument("run_id")
    args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit("run lease watchdog requires root")
    if args.command == "arm-v3":
        payload = parse_arm_payload(__import__("sys").stdin.buffer.read(MAX_ARM_BYTES + 1))
        print(json.dumps(arm(payload["gateway_lease"]), separators=(",", ":"), sort_keys=True))
    elif args.command == "disarm": disarm(args.run_id)
    elif args.command == "close": print(json.dumps(close(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command == "commit": print(json.dumps(commit(args.run_id, args.gateway_summary_sha256), separators=(",", ":"), sort_keys=True))
    elif args.command == "status": print(json.dumps(status(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command == "completed": print(json.dumps(completed_status(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command == "emergency": print(json.dumps(emergency(), separators=(",", ":"), sort_keys=True))
    elif args.command == "renew-v3":
        payload = parse_renew_payload(__import__("sys").stdin.buffer.read(MAX_ARM_BYTES + 1))
        print(json.dumps(renew(payload["gateway_lease"]), separators=(",", ":"), sort_keys=True))
    elif args.command == "expire": print(json.dumps(expire(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command is None: watch()
    else: raise SystemExit(2)


if __name__ == "__main__": main()

