#!/usr/bin/env python3
"""Protected Host coordinator for native vendor stack actions.

This process consumes only the content-free plans from
``shared.native_stack_operations``.  OAuth tokens, authorization codes, PKCE
material, provider response bodies, and credential paths are deliberately not
part of any accepted schema or subprocess interface.

The concrete Host credential service and guest control operations are separate
protected consumers.  If any of those consumers is absent or returns anything
other than its exact content-free acknowledgement, this manager fails closed.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

# The protected release carries the exact shared schema closure as a hashed,
# read-only zip payload. Source-tree execution uses the repository package only
# when this file is visibly in the reviewed ``scripts`` layout.
_SUPPORT = Path(__file__).with_name("native_stack_support")
if _SUPPORT.is_file():
    sys.path.insert(0, str(_SUPPORT))
elif Path(__file__).resolve().parent.name == "scripts":
    _SOURCE_ROOT = Path(__file__).resolve().parent.parent
    if (_SOURCE_ROOT / "shared/native_stack_operations.py").is_file():
        sys.path.insert(0, str(_SOURCE_ROOT))

from shared import native_egress
from shared import native_stack_operations as operations
from shared import native_vendor_stack


TRANSACTION_SCHEMA = "secure-sandbox-native-stack-host-transaction-v1"
STEP_RESULT_SCHEMA = "secure-sandbox-native-stack-step-result-v1"
PROVIDER_RESULT_SCHEMA = "secure-sandbox-native-stack-provider-result-v1"
AUTHORIZATION_SCHEMA = "secure-sandbox-native-stack-touchid-authorization-v1"
HOST_TICKET_SCHEMA = "secure-sandbox-native-stack-host-ticket-v1"
CLOSED_POLICY_SCHEMA = "secure-sandbox-native-egress-closed-v1"
MAX_JSON = 1024 * 1024
MAX_RECORDS = 64
STATE_ROOT = Path("/usr/local/var/lib/secure-sandbox/native-stack-transactions")
RECEIPT_ROOT = Path("/usr/local/var/lib/secure-sandbox/native-stack-receipts")
AUTHORIZATION_RECEIPT_ROOT = Path(
    "/usr/local/var/log/secure-sandbox/authorization-receipts"
)
CATALOG_PATH = Path(
    "/usr/local/var/lib/secure-sandbox/native-stack-catalog/catalog.json"
)
CONTROL_CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
HOST_BACKEND = Path("/usr/local/libexec/secure-sandbox-host/current/native_stack_backend")
TERMINAL_PHASES = {"committed", "rejected", "recovered-fenced"}
RECOVERY_PHASES = {"recovery-required", "recovering"}
ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}")
FORBIDDEN_SERIALIZED_NAMES = (
    b"access_token",
    b"refresh_token",
    b"authorization_code",
    b"code_verifier",
    b"pkce",
    b"provider_response",
    b"credential_path",
    b"client_secret",
)

# This is the only sequence permitted after an action becomes ambiguous. It
# stops both socket owners, installs deny-only policy in both guests, and then
# removes native conntrack state. It deliberately excludes every publication
# and start step from the full successor rotation.
CLOSE_ONLY_PROTOCOL = (
    "stop-bound-runs",
    "stop-research-native-harness",
    "stop-gateway-native-tunnel",
    "apply-research-deny-only",
    "apply-gateway-deny-only",
    "delete-research-native-conntrack",
    "delete-gateway-native-conntrack",
)


class NativeStackManagerError(RuntimeError):
    """Stable fail-closed protected-manager error."""


class SimulatedHardCrash(BaseException):
    """Test-only hard-stop signal that bypasses in-process recovery."""


def canonical(value: object) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeStackManagerError("native_stack_manager_json_invalid") from error
    if len(encoded) > MAX_JSON:
        raise NativeStackManagerError("native_stack_manager_json_oversized")
    lowered = encoded.lower()
    if any(name in lowered for name in FORBIDDEN_SERIALIZED_NAMES):
        raise NativeStackManagerError("native_stack_manager_secret_field_forbidden")
    return encoded


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _safe_error(error: BaseException | str) -> str:
    value = str(error)
    return value if ERROR_CODE.fullmatch(value) else "native_stack_operation_failed"


def _journal_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "journal_sha256"}


def validate_journal(value: object) -> dict[str, Any]:
    expected = {
        "schema", "action_id", "action", "plan", "plan_sha256",
        "authorization", "authorization_sha256", "catalog_sha256",
        "prior_status", "successor_grant", "phase", "completed_steps",
        "provider_evidence_sha256", "decided_receipt", "error_code", "created_at", "updated_at",
        "journal_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise NativeStackManagerError("native_stack_journal_fields_invalid")
    if value["schema"] != TRANSACTION_SCHEMA:
        raise NativeStackManagerError("native_stack_journal_schema_invalid")
    plan = operations.validate_plan(value["plan"])
    if (
        value["action_id"] != plan["action_id"]
        or value["action"] != plan["action"]
        or value["plan_sha256"] != plan["plan_sha256"]
    ):
        raise NativeStackManagerError("native_stack_journal_plan_mismatch")
    authorization = validate_authorization(
        value["authorization"], plan, now=value["created_at"], require_fresh=False
    )
    if (
        value["authorization_sha256"] != authorization["authorization_sha256"]
        or operations.SHA256.fullmatch(str(value["catalog_sha256"])) is None
    ):
        raise NativeStackManagerError("native_stack_journal_authority_mismatch")
    prior = operations.validate_status(value["prior_status"])
    if prior["status_sha256"] != plan["current_status_sha256"]:
        raise NativeStackManagerError("native_stack_journal_status_mismatch")
    grant = value["successor_grant"]
    if grant is not None:
        native_egress.validate_grant(grant)
    if not isinstance(value["phase"], str) or not 1 <= len(value["phase"]) <= 128:
        raise NativeStackManagerError("native_stack_journal_phase_invalid")
    steps = value["completed_steps"]
    if (
        not isinstance(steps, list)
        or len(steps) > 96
        or any(not isinstance(item, str) or len(item) > 96 for item in steps)
    ):
        raise NativeStackManagerError("native_stack_journal_steps_invalid")
    evidence = value["provider_evidence_sha256"]
    if evidence is not None and operations.SHA256.fullmatch(str(evidence)) is None:
        raise NativeStackManagerError("native_stack_journal_evidence_invalid")
    decided = value["decided_receipt"]
    if decided is not None:
        try:
            receipt = operations.validate_receipt(decided)
        except operations.NativeStackOperationError as error:
            raise NativeStackManagerError("native_stack_journal_receipt_invalid") from error
        if (
            receipt["action_id"] != plan["action_id"]
            or receipt["action"] != plan["action"]
            or receipt["plan_sha256"] != plan["plan_sha256"]
            or value["phase"] not in {"commit-decided", "receipt-published", "committed"}
        ):
            raise NativeStackManagerError("native_stack_journal_receipt_mismatch")
    error_code = value["error_code"]
    if error_code is not None and (
        not isinstance(error_code, str) or ERROR_CODE.fullmatch(error_code) is None
    ):
        raise NativeStackManagerError("native_stack_journal_error_invalid")
    for field in ("created_at", "updated_at"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] < 1:
            raise NativeStackManagerError("native_stack_journal_time_invalid")
    supplied = value["journal_sha256"]
    if (
        not isinstance(supplied, str)
        or operations.SHA256.fullmatch(supplied) is None
        or not hmac.compare_digest(supplied, digest(_journal_body(value)))
    ):
        raise NativeStackManagerError("native_stack_journal_digest_mismatch")
    canonical(value)
    return value


def _write_all(descriptor: int, data: bytes) -> None:
    cursor = 0
    while cursor < len(data):
        written = os.write(descriptor, data[cursor:])
        if written <= 0:
            raise OSError("short_write")
        cursor += written


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _trusted_directory(path: Path, uid: int) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise NativeStackManagerError("native_stack_state_root_untrusted")


def ensure_state_directory(path: Path, uid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    _trusted_directory(path, uid)


def atomic_json(path: Path, value: dict[str, Any], uid: int) -> None:
    data = canonical(value)
    _trusted_directory(path.parent, uid)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def trusted_json(path: Path, uid: int) -> dict[str, Any]:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 2 <= before.st_size <= MAX_JSON
    ):
        raise NativeStackManagerError("native_stack_state_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_JSON:
            block = os.read(descriptor, min(65536, MAX_JSON + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        or len(raw) != opened.st_size
        or len(raw) > MAX_JSON
    ):
        raise NativeStackManagerError("native_stack_state_file_changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackManagerError("native_stack_state_file_invalid") from error
    validated = validate_journal(value)
    if bytes(raw) != canonical(validated):
        raise NativeStackManagerError("native_stack_state_file_not_canonical")
    return validated


def trusted_canonical_document(path: Path, uid: int) -> dict[str, Any]:
    """Read one root-owned canonical 0600 JSON document without path races."""
    _trusted_directory(path.parent, uid)
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeStackManagerError("native_stack_authorization_receipt_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_JSON:
            block = os.read(descriptor, min(65536, MAX_JSON + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != uid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or not 2 <= opened.st_size <= MAX_JSON
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        or len(raw) != opened.st_size
        or len(raw) > MAX_JSON
    ):
        raise NativeStackManagerError("native_stack_authorization_receipt_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackManagerError("native_stack_authorization_receipt_invalid") from error
    if not isinstance(value, dict) or bytes(raw) != canonical(value):
        raise NativeStackManagerError("native_stack_authorization_receipt_not_canonical")
    return value


def validate_authorization(
    value: object,
    plan: Mapping[str, Any],
    *,
    now: int,
    require_fresh: bool = True,
    expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    expected = {
        "schema", "authorization_id", "request_sha256", "pending_receipt_sha256",
        "action_id", "action", "plan_sha256", "method", "password_fallback",
        "authorized_at", "expires_at", "host_release_id",
        "requesting_agent_sha256", "requesting_session_sha256",
        "authorization_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise NativeStackManagerError("native_stack_authorization_fields_invalid")
    if value["schema"] != AUTHORIZATION_SCHEMA:
        raise NativeStackManagerError("native_stack_authorization_schema_invalid")
    for field in (
        "request_sha256", "pending_receipt_sha256", "plan_sha256",
        "host_release_id", "requesting_agent_sha256", "requesting_session_sha256",
        "authorization_sha256",
    ):
        if operations.SHA256.fullmatch(str(value[field])) is None:
            raise NativeStackManagerError("native_stack_authorization_digest_invalid")
    if operations.UUID4.fullmatch(str(value["authorization_id"])) is None:
        raise NativeStackManagerError("native_stack_authorization_id_invalid")
    if (
        value["action_id"] != plan["action_id"]
        or value["action"] != plan["action"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or value["method"] != "touch-id"
        or value["password_fallback"] is not False
    ):
        raise NativeStackManagerError("native_stack_authorization_plan_mismatch")
    authorized_at = value["authorized_at"]
    expires_at = value["expires_at"]
    if (
        not isinstance(authorized_at, int)
        or isinstance(authorized_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not plan["created_at"] <= authorized_at < expires_at
        or expires_at > min(plan["expires_at"], authorized_at + 120)
        or (require_fresh and not authorized_at <= now < expires_at)
    ):
        raise NativeStackManagerError("native_stack_authorization_expired")
    if (
        expected_host_release_id is not None
        and value["host_release_id"] != expected_host_release_id
    ):
        raise NativeStackManagerError("native_stack_authorization_release_mismatch")
    supplied = value["authorization_sha256"]
    body = {key: item for key, item in value.items() if key != "authorization_sha256"}
    if not hmac.compare_digest(supplied, digest(body)):
        raise NativeStackManagerError("native_stack_authorization_digest_mismatch")
    canonical(value)
    return value


def verify_authorization_receipt(
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    receipt_root: Path,
    trusted_uid: int,
) -> None:
    receipt = trusted_canonical_document(
        receipt_root / f"{authorization['authorization_id']}.json", trusted_uid
    )
    expected = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "native_action_id", "native_plan_sha256", "host_release_id",
    }
    if set(receipt) != expected:
        raise NativeStackManagerError("native_stack_authorization_receipt_fields_invalid")
    if (
        digest(receipt) != authorization["pending_receipt_sha256"]
        or receipt["schema"] != "secure-sandbox-operator-authorization-receipt-v1"
        or receipt["request_id"] != authorization["authorization_id"]
        or receipt["request_sha256"] != authorization["request_sha256"]
        or receipt["status"] != "executing"
        or receipt["started_at"] != authorization["authorized_at"]
        or receipt["completed_at"] is not None
        or receipt["operation"] != f"native-stack-{plan['action']}"
        or receipt["identity_evidence"] != "operator-declared"
        or receipt["authorization_method"] != "touch-id"
        or receipt["ceremony"] != "approve"
        or receipt["exit_status"] is not None
        or receipt["stdout_sha256"] is not None
        or receipt["stderr_sha256"] is not None
        or receipt["native_action_id"] != plan["action_id"]
        or receipt["native_plan_sha256"] != plan["plan_sha256"]
        or receipt["host_release_id"] != authorization["host_release_id"]
        or hashlib.sha256(receipt["declared_agent"].encode("utf-8")).hexdigest()
        != authorization["requesting_agent_sha256"]
        or hashlib.sha256(receipt["declared_session"].encode("utf-8")).hexdigest()
        != authorization["requesting_session_sha256"]
    ):
        raise NativeStackManagerError("native_stack_authorization_receipt_mismatch")


def expected_plan_identity(stack_value: object) -> dict[str, Any]:
    stack = native_vendor_stack.validate_stack(stack_value)
    harness = stack["harness"]
    authentication = stack["authentication"]
    account = stack["account_binding"]
    model = stack["model"]
    return {
        "stack_id": stack["stack_id"],
        "stack_sha256": native_vendor_stack.stack_revision(stack),
        "vendor_id": stack["vendor_id"],
        "harness_id": harness["harness_id"],
        "harness_generation_id": harness["generation_id"],
        "harness_adapter_id": harness["adapter_id"],
        "authentication_mode": authentication["mode"],
        "credential_custody": authentication["credential_custody"],
        "account_subject_sha256": account["account_subject_sha256"],
        "workspace_sha256": account["workspace_sha256"],
        "program_id": account["program_id"],
        "program_tier": account["program_tier"],
        "program_requirements_version": account["program_requirements_version"],
        "model_id": model["model_id"],
        "model_settings_sha256": native_vendor_stack.sha256(model["settings"]),
        "network_policy_id": stack["network_policy_id"],
    }


def authoritative_stack(
    plan: Mapping[str, Any], catalog_path: Path = CATALOG_PATH
) -> tuple[dict[str, Any], str]:
    try:
        _trusted_directory(catalog_path.parent, os.geteuid())
        catalog = native_vendor_stack.load_catalog(catalog_path, private=True)
        stack = native_vendor_stack.stack_by_id(catalog, plan["identity"]["stack_id"])
    except (OSError, native_vendor_stack.NativeVendorStackError) as error:
        raise NativeStackManagerError("native_stack_catalog_untrusted") from error
    if expected_plan_identity(stack) != plan["identity"]:
        raise NativeStackManagerError("native_stack_catalog_identity_mismatch")
    return stack, hashlib.sha256(native_vendor_stack.canonical_bytes(catalog)).hexdigest()


def validate_close_only_protocol() -> tuple[str, ...]:
    protocol = tuple(native_egress.ROTATION_PROTOCOL)
    if (
        CLOSE_ONLY_PROTOCOL[1:] != protocol[: len(CLOSE_ONLY_PROTOCOL) - 1]
        or len(protocol) <= len(CLOSE_ONLY_PROTOCOL) - 1
        or any(step.startswith("start-") for step in CLOSE_ONLY_PROTOCOL)
        or any("successor-policy" in step for step in CLOSE_ONLY_PROTOCOL)
    ):
        raise NativeStackManagerError("native_stack_close_protocol_invalid")
    return CLOSE_ONLY_PROTOCOL


class Backend(Protocol):
    def status(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]: ...
    def prepare_grant(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any] | None: ...
    def rotation_step(
        self, step: str, plan: Mapping[str, Any], grant: Mapping[str, Any] | None,
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]: ...
    def provider_action(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]: ...


def _exact_step_result(
    value: object, step: str, plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    expected = {
        "schema", "action_id", "plan_sha256", "authorization_sha256",
        "step", "status", "evidence_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise NativeStackManagerError("native_stack_step_result_invalid")
    if (
        value["schema"] != STEP_RESULT_SCHEMA
        or value["action_id"] != plan["action_id"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or value["authorization_sha256"] != authorization["authorization_sha256"]
        or value["step"] != step
        or value["status"] != "verified"
        or operations.SHA256.fullmatch(str(value["evidence_sha256"])) is None
    ):
        raise NativeStackManagerError("native_stack_step_result_mismatch")
    return value


def _exact_provider_result(
    value: object, plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    expected = {
        "schema", "action_id", "action", "plan_sha256", "authorization_sha256",
        "status", "evidence_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise NativeStackManagerError("native_stack_provider_result_invalid")
    if (
        value["schema"] != PROVIDER_RESULT_SCHEMA
        or value["action_id"] != plan["action_id"]
        or value["action"] != plan["action"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or value["authorization_sha256"] != authorization["authorization_sha256"]
        or value["status"] != "verified"
        or operations.SHA256.fullmatch(str(value["evidence_sha256"])) is None
    ):
        raise NativeStackManagerError("native_stack_provider_result_mismatch")
    return value


def host_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    body = {
        "schema": HOST_TICKET_SCHEMA,
        "plan": plan,
        "authorization": authorization,
    }
    return {**body, "ticket_sha256": digest(body)}


def _grant_native_identity(grant: Mapping[str, Any]) -> Mapping[str, Any]:
    binding = grant["binding"]
    if binding["kind"] in {"stack-intent", "native-stack"}:
        return binding["value"]
    return binding["value"]["model_stack_binding"]["authority"]


def validate_grant_for_plan(
    value: object, plan: Mapping[str, Any], *, now: int
) -> dict[str, Any]:
    grant = native_egress.validate_grant(value, now=now)
    identity = plan["identity"]
    native = _grant_native_identity(grant)
    if grant["phase"] != plan["requested_network_phase"]:
        raise NativeStackManagerError("native_stack_grant_phase_mismatch")
    comparisons = {
        "stack_id": "stack_id",
        "stack_sha256": "stack_sha256",
        "vendor_id": "vendor_id",
        "harness_id": "harness_id",
        "harness_generation_id": "harness_generation_id",
        "harness_adapter_id": "harness_adapter_id",
        "authentication_mode": "authentication_mode",
        "credential_custody": "credential_custody",
        "program_id": "program_id",
        "program_tier": "program_tier",
        "program_requirements_version": "program_requirements_version",
        "model_id": "model_id",
        "model_settings_sha256": "model_settings_sha256",
        "network_policy_id": "network_policy_id",
    }
    if any(native.get(native_name) != identity.get(plan_name)
           for native_name, plan_name in comparisons.items()):
        raise NativeStackManagerError("native_stack_grant_identity_mismatch")
    for field in ("account_subject_sha256", "workspace_sha256"):
        if field in native and native.get(field) != identity.get(field):
            raise NativeStackManagerError("native_stack_grant_identity_mismatch")
    return grant


def closed_policy(plan: Mapping[str, Any]) -> dict[str, Any]:
    body = {
        "action_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "stack_id": plan["identity"]["stack_id"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "state": "closed",
    }
    return {"schema": CLOSED_POLICY_SCHEMA, **body, "policy_sha256": digest(body)}


class SubprocessBackend:
    """Exact content-free production transport.

    ``native_stack_backend`` is intentionally not implemented here: it is the
    separately signed Host credential/XPC bridge.  Its absence is a hard
    failure, never an implicit success or alternate credential path.
    """

    STEP_OPERATIONS = {
        "stop-research-native-harness": ("sandbox-research-control", "native-harness-stop"),
        "stop-gateway-native-tunnel": ("sandbox-gateway-control", "native-tunnel-stop"),
        "apply-research-deny-only": ("sandbox-research-control", "native-egress-deny-only"),
        "apply-gateway-deny-only": ("sandbox-gateway-control", "native-egress-deny-only"),
        "delete-research-native-conntrack": ("sandbox-research-control", "native-egress-conntrack-delete"),
        "delete-gateway-native-conntrack": ("sandbox-gateway-control", "native-egress-conntrack-delete"),
        "apply-gateway-successor-policy": ("sandbox-gateway-control", "native-egress-apply"),
        "apply-research-successor-policy": ("sandbox-research-control", "native-egress-apply"),
        "start-gateway-native-tunnel": ("sandbox-gateway-control", "native-tunnel-start"),
        "start-research-native-harness": ("sandbox-research-control", "native-harness-start"),
        "stop-bound-runs": ("sandbox-research-control", "native-runs-stop"),
    }

    def __init__(
        self,
        *,
        control_client: Path = CONTROL_CLIENT,
        ssh_config: Path = SSH_CONFIG,
        host_backend: Path = HOST_BACKEND,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    ) -> None:
        self.control_client = control_client
        self.ssh_config = ssh_config
        self.host_backend = host_backend
        self.runner = runner

    def _run(self, command: list[str], payload: object, timeout: int = 180) -> dict[str, Any]:
        raw = canonical(payload)
        if self.runner is not subprocess.run:
            # Test-only dependency injection. Production always takes the
            # process-group, bounded-stream path below.
            result = self.runner(
                command,
                input=raw,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
            )
        else:
            result = self._run_bounded_process_group(command, raw, timeout)
        if result.returncode != 0 or not 2 <= len(result.stdout) <= MAX_JSON:
            raise NativeStackManagerError("native_stack_control_operation_failed")
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeStackManagerError("native_stack_control_response_invalid") from error
        if not isinstance(value, dict):
            raise NativeStackManagerError("native_stack_control_response_invalid")
        if result.stdout != canonical(value):
            raise NativeStackManagerError(
                "native_stack_control_response_not_canonical"
            )
        return value

    @staticmethod
    def _terminate_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=1)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise NativeStackManagerError(
                "native_stack_control_process_unreaped"
            ) from error

    @classmethod
    def _run_bounded_process_group(
        cls, command: list[str], raw: bytes, timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
            close_fds=True,
            start_new_session=True,
        )
        if process.stdin is None or process.stdout is None:
            cls._terminate_group(process)
            raise NativeStackManagerError("native_stack_control_operation_failed")
        selector = selectors.DefaultSelector()
        output = bytearray()
        pending = memoryview(raw)
        deadline = time.monotonic() + timeout
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NativeStackManagerError("native_stack_control_timeout")
                events = selector.select(min(remaining, 0.25))
                if not events and process.poll() is not None:
                    # Drain the pipe one final time on the next iteration.
                    events = [(type("Key", (), {"fileobj": process.stdout})(), 0)]
                for key, _mask in events:
                    if key.fileobj is process.stdin:
                        if not pending:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                            continue
                        try:
                            count = os.write(process.stdin.fileno(), pending[:65536])
                        except BlockingIOError:
                            continue
                        if count <= 0:
                            raise NativeStackManagerError(
                                "native_stack_control_operation_failed"
                            )
                        pending = pending[count:]
                    elif key.fileobj is process.stdout:
                        try:
                            block = os.read(process.stdout.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not block:
                            if process.stdout in [entry.fileobj for entry in selector.get_map().values()]:
                                selector.unregister(process.stdout)
                            process.stdout.close()
                            continue
                        output.extend(block)
                        if len(output) > MAX_JSON:
                            raise NativeStackManagerError(
                                "native_stack_control_response_oversized"
                            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeStackManagerError("native_stack_control_timeout")
            returncode = process.wait(timeout=remaining)
            return subprocess.CompletedProcess(command, returncode, bytes(output), b"")
        except (NativeStackManagerError, OSError, subprocess.TimeoutExpired) as error:
            cls._terminate_group(process)
            if isinstance(error, NativeStackManagerError):
                raise
            raise NativeStackManagerError("native_stack_control_operation_failed") from error
        finally:
            selector.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            if process.stdout is not None and not process.stdout.closed:
                process.stdout.close()

    def _host(
        self, operation: str, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._run(
            [str(self.host_backend), operation],
            host_ticket(plan, authorization),
            timeout=300,
        )

    def status(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._host("status", plan, authorization)

    def prepare_grant(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        value = self._host("prepare-grant", plan, authorization)
        if value == {"schema": CLOSED_POLICY_SCHEMA, "state": "closed"}:
            return None
        return value

    def rotation_step(
        self, step: str, plan: Mapping[str, Any], grant: Mapping[str, Any] | None,
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            host, operation = self.STEP_OPERATIONS[step]
        except KeyError as error:
            raise NativeStackManagerError("native_stack_rotation_step_invalid") from error
        payload: dict[str, Any] = {
            "schema": "secure-sandbox-native-stack-step-request-v1",
            "action_id": plan["action_id"],
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "step": step,
            # The successor grant is disclosed to a guest only at the exact
            # policy-publication step, after both socket owners are stopped,
            # both guests are deny-only, and both conntrack domains are gone.
            "successor": (
                grant
                if grant is not None and step in {
                    "apply-gateway-successor-policy",
                    "apply-research-successor-policy",
                }
                else closed_policy(plan)
            ),
        }
        command = [
            str(self.control_client), "client", "--ssh-config", str(self.ssh_config),
            "--timeout-seconds", "180", host, "pipe", operation,
        ]
        return self._run(command, payload)

    def provider_action(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._host("provider-action", plan, authorization)


class NativeStackManager:
    def __init__(
        self,
        backend: Backend,
        *,
        state_root: Path = STATE_ROOT,
        receipt_root: Path = RECEIPT_ROOT,
        authorization_receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
        catalog_path: Path = CATALOG_PATH,
        trusted_uid: int = 0,
        host_release_id: str | None = None,
        now: Callable[[], int] = lambda: int(time.time()),
        crash_hook: Callable[[str], None] | None = None,
        authorization_receipt_verifier: Callable[
            [Mapping[str, Any], Mapping[str, Any]], None
        ] | None = None,
        catalog_resolver: Callable[
            [Mapping[str, Any]], tuple[dict[str, Any], str]
        ] | None = None,
    ) -> None:
        self.backend = backend
        self.state_root = state_root
        self.receipt_root = receipt_root
        self.authorization_receipt_root = authorization_receipt_root
        self.catalog_path = catalog_path
        self.trusted_uid = trusted_uid
        self.host_release_id = host_release_id
        self.now = now
        self.crash_hook = crash_hook or (lambda _phase: None)
        self.authorization_receipt_verifier = authorization_receipt_verifier
        self.catalog_resolver = catalog_resolver

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        ensure_state_directory(self.state_root, self.trusted_uid)
        ensure_state_directory(self.receipt_root, self.trusted_uid)
        ensure_state_directory(self.state_root / "archive", self.trusted_uid)
        lock_path = self.state_root / ".lock"
        try:
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(
                lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            created = False
        try:
            if created:
                os.fchmod(descriptor, 0o600)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.trusted_uid
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise NativeStackManagerError("native_stack_lock_untrusted")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _records(self) -> list[tuple[Path, dict[str, Any]]]:
        paths = sorted(self.state_root.glob("*.json"))
        records = [(path, trusted_json(path, self.trusted_uid)) for path in paths]
        if sum(value["phase"] not in TERMINAL_PHASES for _path, value in records) > MAX_RECORDS:
            raise NativeStackManagerError("native_stack_transaction_state_unbounded")
        return records

    def _archive_terminal_records(self) -> None:
        archive = self.state_root / "archive"
        _trusted_directory(archive, self.trusted_uid)
        for path, journal in self._records():
            if journal["phase"] not in TERMINAL_PHASES:
                continue
            destination = archive / path.name
            if destination.exists():
                observed = trusted_json(destination, self.trusted_uid)
                if observed != journal:
                    raise NativeStackManagerError(
                        "native_stack_transaction_archive_collision"
                    )
                path.unlink()
            else:
                os.replace(path, destination)
            _fsync_directory(self.state_root)
            _fsync_directory(archive)

    def _action_is_known(self, action_id: str) -> bool:
        name = f"{action_id}.json"
        for candidate in (
            self.state_root / name,
            self.state_root / "archive" / name,
            self.receipt_root / name,
        ):
            try:
                candidate.lstat()
                return True
            except FileNotFoundError:
                continue
        return False

    def _persist(
        self, path: Path, journal: dict[str, Any], phase: str, **fields: object
    ) -> None:
        journal.update(fields)
        journal["phase"] = phase
        journal["updated_at"] = self.now()
        journal["journal_sha256"] = digest(_journal_body(journal))
        validate_journal(journal)
        atomic_json(path, journal, self.trusted_uid)
        self.crash_hook(phase)

    def _initial_status(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        status = operations.validate_status(self.backend.status(plan, authorization))
        if (
            status["stack_id"] != plan["identity"]["stack_id"]
            or status["stack_sha256"] != plan["identity"]["stack_sha256"]
            or status["status_sha256"] != plan["current_status_sha256"]
        ):
            raise NativeStackManagerError("native_stack_current_status_changed")
        if plan["action"] == "signin-begin":
            if (
                status["activation"]["state"] not in {"inactive", "fenced"}
                or status["authentication"]["state"] != "signed-out"
                or status["live_run_count"] != 0
            ):
                # Same-account reauthentication needs a future explicit plan
                # schema; an already signed-in state is never inferred to mean
                # that the same account is being reauthorized.
                raise NativeStackManagerError("native_stack_signin_precondition_failed")
        if plan["action"] == "binding-commit":
            account = status["account_binding"]
            if (
                status["activation"]["state"] not in {"inactive", "fenced"}
                or (account["state"] == "unbound" and status["live_run_count"] != 0)
                or (
                    account["state"] == "bound"
                    and account["account_subject_sha256"]
                    == plan["observed_account_subject_sha256"]
                    and account["workspace_sha256"]
                    == plan["observed_workspace_sha256"]
                )
            ):
                raise NativeStackManagerError("native_stack_binding_precondition_failed")
        return status

    def _prepare_grant(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        phase = plan["requested_network_phase"]
        if phase == "closed":
            return None
        value = self.backend.prepare_grant(plan, authorization)
        # OpenAI SIWC login/status/logout is Host-only. No guest grant exists.
        host_only = (
            plan["identity"]["vendor_id"] == "openai"
            and plan["action"] in {"signin-begin", "status-verify", "logout"}
        )
        if value is None:
            if host_only:
                return None
            raise NativeStackManagerError("native_stack_successor_grant_missing")
        if host_only:
            raise NativeStackManagerError("native_stack_host_only_guest_grant_forbidden")
        return validate_grant_for_plan(value, plan, now=self.now())

    def _rotation(
        self,
        path: Path,
        journal: dict[str, Any],
        grant: Mapping[str, Any] | None,
        label: str,
    ) -> list[dict[str, Any]]:
        native_egress.validate_rotation_protocol(native_egress.ROTATION_PROTOCOL)
        evidence: list[dict[str, Any]] = []
        for index, step in enumerate(native_egress.ROTATION_PROTOCOL):
            phase = f"{label}-{index:02d}-{step}"
            self._persist(path, journal, phase + "-pending")
            result = _exact_step_result(
                self.backend.rotation_step(
                    step, journal["plan"], grant, journal["authorization"]
                ),
                step,
                journal["plan"],
                journal["authorization"],
            )
            evidence.append(result)
            journal["completed_steps"].append(f"{label}:{step}")
            self._persist(path, journal, phase + "-verified")
        return evidence

    def _stop_bound_runs(
        self, path: Path, journal: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not journal["plan"]["impact"]["stops_bound_runs"]:
            return None
        step = "stop-bound-runs"
        self._persist(path, journal, "stop-bound-runs-pending")
        result = _exact_step_result(
            self.backend.rotation_step(
                step, journal["plan"], None, journal["authorization"]
            ),
            step,
            journal["plan"],
            journal["authorization"],
        )
        journal["completed_steps"].append(step)
        self._persist(path, journal, "stop-bound-runs-verified")
        status = operations.validate_status(
            self.backend.status(journal["plan"], journal["authorization"])
        )
        if status["live_run_count"] != 0:
            raise NativeStackManagerError("native_stack_bound_runs_still_live")
        return result

    def _force_closed(
        self, path: Path, journal: dict[str, Any], label: str = "recovery-close"
    ) -> list[dict[str, Any]]:
        try:
            evidence: list[dict[str, Any]] = []
            for index, step in enumerate(validate_close_only_protocol()):
                phase = f"{label}-{index:02d}-{step}"
                self._persist(path, journal, phase + "-pending")
                result = _exact_step_result(
                    self.backend.rotation_step(
                        step, journal["plan"], None, journal["authorization"]
                    ),
                    step,
                    journal["plan"],
                    journal["authorization"],
                )
                evidence.append(result)
                journal["completed_steps"].append(f"{label}:{step}")
                self._persist(path, journal, phase + "-verified")
            self._persist(path, journal, f"{label}-readback-pending")
            status = operations.validate_status(
                self.backend.status(journal["plan"], journal["authorization"])
            )
            if (
                status["stack_id"] != journal["plan"]["identity"]["stack_id"]
                or status["network"]["phase"] != "closed"
                or status["live_run_count"] != 0
            ):
                raise NativeStackManagerError("native_stack_close_readback_ambiguous")
            self._persist(path, journal, f"{label}-readback-verified")
            return evidence
        except Exception as error:
            self._persist(
                path,
                journal,
                "recovery-required",
                error_code=_safe_error(error),
            )
            raise NativeStackManagerError("native_stack_recovery_required") from error

    def _emergency_close(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> None:
        """Best-effort deny closure when durable-journal I/O itself failed.

        No success is recorded here. The absence of a durable transaction
        remains ambiguous and requires operator inspection, but journal
        failure must not be allowed to suppress the network-deny attempt.
        """
        for step in validate_close_only_protocol():
            try:
                _exact_step_result(
                    self.backend.rotation_step(step, plan, None, authorization),
                    step,
                    plan,
                    authorization,
                )
            except Exception:
                # Every barrier is independent fail-safe defense. Failure of
                # either guest's stop, deny, or conntrack operation must never
                # suppress an attempt against the other guest. This method
                # records no success, so continuing cannot create a misleading
                # verified result.
                continue

    def _verify_final_status(
        self, plan: Mapping[str, Any], status: Mapping[str, Any]
    ) -> None:
        identity = plan["identity"]
        action = plan["action"]
        if status["stack_id"] != identity["stack_id"]:
            raise NativeStackManagerError("native_stack_final_stack_mismatch")
        if action != "binding-commit" and status["stack_sha256"] != identity["stack_sha256"]:
            raise NativeStackManagerError("native_stack_final_revision_mismatch")
        if (
            identity["harness_generation_id"] is not None
            and status["harness"]["generation_id"] != identity["harness_generation_id"]
        ):
            raise NativeStackManagerError("native_stack_final_harness_mismatch")
        for field in ("account_subject_sha256", "workspace_sha256"):
            if (
                action not in {"binding-commit", "logout", "credential-destroy"}
                and identity[field] is not None
                and status["account_binding"][field] != identity[field]
            ):
                raise NativeStackManagerError("native_stack_final_account_mismatch")
        if status["network"]["phase"] != "closed":
            raise NativeStackManagerError("native_stack_final_network_not_closed")
        if plan["impact"]["stops_bound_runs"] and status["live_run_count"] != 0:
            raise NativeStackManagerError("native_stack_final_runs_not_stopped")
        if action == "signin-begin" and (
            status["authentication"]["state"] != "signed-in"
            or status["activation"]["state"] not in {"inactive", "fenced"}
            or status["live_run_count"] != 0
        ):
            raise NativeStackManagerError("native_stack_signin_not_verified")
        if action == "binding-commit":
            binding = status["account_binding"]
            if (
                binding["state"] != "bound"
                or binding["account_subject_sha256"]
                != plan["observed_account_subject_sha256"]
                or binding["workspace_sha256"] != plan["observed_workspace_sha256"]
                or status["stack_sha256"] == identity["stack_sha256"]
            ):
                raise NativeStackManagerError("native_stack_binding_commit_not_verified")
        if action == "status-verify" and status["authentication"]["state"] != "signed-in":
            raise NativeStackManagerError("native_stack_status_not_verified")
        if action == "entitlement-verify" and (
            status["program_entitlement"]["state"] != "verified"
            or status["model_entitlement"]["state"] != "verified"
        ):
            raise NativeStackManagerError("native_stack_entitlement_not_verified")
        if action == "activate":
            for component in ("authentication", "program_entitlement", "model_entitlement"):
                observed_at = status[component]["observed_at"]
                if (
                    not isinstance(observed_at, int)
                    or not self.now() - 300 <= observed_at <= self.now()
                ):
                    raise NativeStackManagerError("native_stack_activation_evidence_stale")
            prerequisites = (
                status["harness"]["state"] == "admitted",
                status["authentication"]["state"] == "signed-in",
                status["account_binding"]["state"] == "bound",
                status["program_entitlement"]["state"] == "verified",
                status["model_entitlement"]["state"] == "verified",
                status["activation"]["state"] == "active",
            )
            if not all(prerequisites):
                raise NativeStackManagerError("native_stack_activation_not_verified")
        if action in {"rollback", "logout", "credential-destroy"} and status["activation"]["state"] not in {
            "inactive", "fenced"
        }:
            raise NativeStackManagerError("native_stack_deactivation_not_verified")
        if action in {"logout", "credential-destroy"} and status["authentication"]["state"] != "signed-out":
            raise NativeStackManagerError("native_stack_logout_not_verified")
        custody = status["credential_custody"]
        if action in {"logout", "recover"} and (
            custody["state"] == "session-projected"
            or custody["projection_count"] not in {0, None}
        ):
            raise NativeStackManagerError("native_stack_projection_not_revoked")
        if action == "credential-destroy" and (
            custody["state"] != "absent"
            or custody["tombstone_sha256"] is None
            or custody["projection_count"] != 0
            or status["account_binding"]["state"] != "unbound"
            or status["program_entitlement"]["state"] == "verified"
            or status["model_entitlement"]["state"] == "verified"
        ):
            raise NativeStackManagerError(
                "native_stack_credential_destroy_not_verified"
            )
        if action == "recover" and (
            status["activation"]["state"] != "fenced"
            or status["live_run_count"] != 0
            or status["fence_reason"] is None
        ):
            raise NativeStackManagerError("native_stack_recovery_not_verified")

    def _pending_records(self) -> list[tuple[Path, dict[str, Any]]]:
        return [
            (path, value)
            for path, value in self._records()
            if value["phase"] not in TERMINAL_PHASES
        ]

    def _publish_decided_receipt(
        self, path: Path, journal: dict[str, Any]
    ) -> dict[str, Any]:
        decided = journal.get("decided_receipt")
        if decided is None:
            raise NativeStackManagerError("native_stack_commit_decision_missing")
        receipt = operations.validate_receipt(decided)
        destination = self.receipt_root / f"{journal['action_id']}.json"
        if destination.exists():
            observed = trusted_canonical_document(destination, self.trusted_uid)
            try:
                observed = operations.validate_receipt(observed)
            except operations.NativeStackOperationError as error:
                raise NativeStackManagerError("native_stack_receipt_untrusted") from error
            if observed != receipt:
                raise NativeStackManagerError("native_stack_receipt_collision")
        else:
            atomic_json(destination, receipt, self.trusted_uid)
        self._persist(path, journal, "receipt-published")
        self._persist(path, journal, "committed")
        return receipt

    def _reconcile_decided_commits(self) -> None:
        for path, journal in self._records():
            if journal["phase"] in {"commit-decided", "receipt-published"}:
                self._publish_decided_receipt(path, journal)

    def apply(self, plan_value: object, authorization_value: object) -> dict[str, Any]:
        with self.locked():
            # A durable commit decision is authoritative even if the process
            # died before publication. Reconcile it before considering a new
            # action; never force-close or discard an already verified result.
            self._reconcile_decided_commits()
            self._archive_terminal_records()
            plan = operations.validate_plan(plan_value, now=self.now(), require_fresh=True)
            authorization = validate_authorization(
                authorization_value,
                plan,
                now=self.now(),
                require_fresh=True,
                expected_host_release_id=self.host_release_id,
            )
            existing = self.state_root / f"{plan['action_id']}.json"
            if self._action_is_known(plan["action_id"]):
                raise NativeStackManagerError("native_stack_action_replay")
            if self.authorization_receipt_verifier is None:
                verify_authorization_receipt(
                    authorization,
                    plan,
                    receipt_root=self.authorization_receipt_root,
                    trusted_uid=self.trusted_uid,
                )
            else:
                self.authorization_receipt_verifier(authorization, plan)
            if self.catalog_resolver is None:
                stack, catalog_sha256 = authoritative_stack(plan, self.catalog_path)
            else:
                stack, catalog_sha256 = self.catalog_resolver(plan)
            try:
                native_vendor_stack.validate_stack(stack)
            except native_vendor_stack.NativeVendorStackError as error:
                raise NativeStackManagerError("native_stack_catalog_untrusted") from error
            if (
                expected_plan_identity(stack) != plan["identity"]
                or operations.SHA256.fullmatch(str(catalog_sha256)) is None
            ):
                raise NativeStackManagerError("native_stack_catalog_identity_mismatch")
            pending = self._pending_records()
            if pending and plan["action"] != "recover":
                raise NativeStackManagerError("native_stack_recovery_required")
            # Bind the operator's recovery plan to the independently observed
            # pre-recovery state before the mandatory fail-safe closure mutates
            # network or run state.
            prior = self._initial_status(plan, authorization)
            # A recovery never reuses an expired plan or authorization from an
            # older ambiguous journal. The new recovery action performs one
            # global stop/deny/conntrack/readback sequence under its own fresh
            # Touch ID authority, then terminalizes the old journals only after
            # that recovery has a durable commit decision.
            grant = self._prepare_grant(plan, authorization)
            timestamp = self.now()
            journal: dict[str, Any] = {
                "schema": TRANSACTION_SCHEMA,
                "action_id": plan["action_id"],
                "action": plan["action"],
                "plan": plan,
                "plan_sha256": plan["plan_sha256"],
                "authorization": authorization,
                "authorization_sha256": authorization["authorization_sha256"],
                "catalog_sha256": catalog_sha256,
                "prior_status": prior,
                "successor_grant": grant,
                "phase": "prepared",
                "completed_steps": [],
                "provider_evidence_sha256": None,
                "decided_receipt": None,
                "error_code": None,
                "created_at": timestamp,
                "updated_at": timestamp,
                "journal_sha256": "0" * 64,
            }
            journal["journal_sha256"] = digest(_journal_body(journal))
            path = self.state_root / f"{plan['action_id']}.json"
            if path.exists():
                raise NativeStackManagerError("native_stack_action_replay")
            atomic_json(path, validate_journal(journal), self.trusted_uid)
            self.crash_hook("prepared")
            evidence: list[dict[str, Any]] = []
            try:
                stopped = self._stop_bound_runs(path, journal)
                if stopped is not None:
                    evidence.append(stopped)
                # Every action begins from a fully closed, tuple-cleared state.
                evidence.extend(self._rotation(path, journal, grant, "successor"))
                self._persist(path, journal, "provider-action-pending")
                provider = _exact_provider_result(
                    self.backend.provider_action(plan, authorization), plan, authorization
                )
                evidence.append(provider)
                self._persist(
                    path,
                    journal,
                    "provider-action-verified",
                    provider_evidence_sha256=provider["evidence_sha256"],
                )
                # Login/status/entitlement/logout grants are always temporary.
                if grant is not None:
                    evidence.extend(self._rotation(path, journal, None, "close"))
                self._persist(path, journal, "readback-pending")
                status = operations.validate_status(
                    self.backend.status(plan, authorization)
                )
                self._verify_final_status(plan, status)
                self._persist(path, journal, "readback-verified")
                evidence_sha256 = digest(evidence)
                receipt = operations.make_receipt(
                    plan=plan,
                    status=status,
                    result="verified",
                    evidence_sha256=evidence_sha256,
                    completed_at=self.now(),
                )
                # The journal is the root-owned staging record. Persist the
                # full validated receipt as the durable commit decision before
                # it becomes visible in the receipt directory. Recovery can
                # then complete publication without repeating provider work.
                self._persist(
                    path, journal, "commit-decided", decided_receipt=receipt
                )
                self._publish_decided_receipt(path, journal)
                if plan["action"] == "recover":
                    for old_path, old in pending:
                        self._persist(
                            old_path,
                            old,
                            "recovered-fenced",
                            error_code=None,
                        )
                self._archive_terminal_records()
                return receipt
            except Exception as error:
                code = _safe_error(error)
                try:
                    self._persist(path, journal, "failure-observed", error_code=code)
                    self._force_closed(path, journal)
                    self._persist(path, journal, "recovery-required", error_code=code)
                except Exception:
                    self._emergency_close(plan, authorization)
                raise


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("command", choices=("apply",))
    value.add_argument("--plan-json", required=True)
    value.add_argument("--authorization-json", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        raw = args.plan_json.encode("ascii")
        authorization_raw = args.authorization_json.encode("ascii")
        if len(raw) > MAX_JSON or len(authorization_raw) > MAX_JSON:
            raise NativeStackManagerError("native_stack_plan_oversized")
        plan = json.loads(raw)
        authorization = json.loads(authorization_raw)
        release_id = Path(__file__).resolve().parent.name
        if operations.SHA256.fullmatch(release_id) is None:
            raise NativeStackManagerError("native_stack_protected_release_invalid")
        receipt = NativeStackManager(
            SubprocessBackend(), host_release_id=release_id
        ).apply(plan, authorization)
        sys.stdout.buffer.write(operations.canonical_bytes(receipt))
        return 0
    except (
        NativeStackManagerError,
        operations.NativeStackOperationError,
        native_egress.NativeEgressError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        code = _safe_error(error)
        output = {
            "schema": "secure-sandbox-native-stack-manager-error-v1",
            "status": "rejected",
            "error": code,
        }
        sys.stderr.buffer.write(canonical(output))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
