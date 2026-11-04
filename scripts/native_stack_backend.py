#!/usr/bin/env python3
"""Content-free Host adapter for protected native vendor stack operations.

The root manager passes one self-digested Host ticket. This adapter independently
revalidates the Touch ID receipt and protected catalog, prepares DNS-pinned
egress, invokes content-free guest controls, and delegates OpenAI credential
custody to one exact Developer-ID-signed Swift client. It never accepts an
OAuth secret or raw provider response.
"""

from __future__ import annotations

import hashlib
import fcntl
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import pwd
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
SUPPORT = HERE / "native_stack_support"
if SUPPORT.is_file():
    sys.path.insert(0, str(SUPPORT))
elif (HERE.parent / "shared/native_egress.py").is_file():
    sys.path.insert(0, str(HERE.parent))

from shared import model_stack_runtime_binding
from shared import native_codex_projection
from shared import native_codex_ui_handle
from shared import native_egress
from shared import native_program_attestation
from shared import native_projection_identity_recovery
from shared import native_projection_reconciliation
from shared import native_stack_operations as operations
from shared import native_stack_runtime_binding
from shared import native_stack_session
from shared import native_terminal_handle
from shared import native_vendor_stack
from shared import runtime_authority
from shared import session_context_binding


def _load_manager() -> Any:
    path = next(
        (candidate for candidate in (
            HERE / "native_stack_manager", HERE / "native_stack_manager.py"
        ) if candidate.is_file()),
        None,
    )
    if path is None:
        raise RuntimeError("native_stack_manager_unavailable")
    loader = importlib.machinery.SourceFileLoader(
        "native_stack_backend_manager", str(path)
    )
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None:
        raise RuntimeError("native_stack_manager_unavailable")
    module = importlib.util.module_from_spec(specification)
    loader.exec_module(module)
    return module


MANAGER = _load_manager()
MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 128 * 1024
HOST_TICKET_SCHEMA = "secure-sandbox-native-stack-host-ticket-v1"
SESSION_HOST_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-session-host-ticket-v1"
)
SESSION_CONTINUATION_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-session-continuation-ticket-v1"
)
SESSION_PREPARE_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-session-prepare-ticket-v1"
)
SESSION_RECOVERY_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-session-recovery-ticket-v1"
)
SESSION_CODEX_PREPARE_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-codex-prepare-ticket-v1"
)
INTERACTIVE_HOST_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-interactive-host-ticket-v1"
)
PROVIDER_RESULT_SCHEMA = "secure-sandbox-native-stack-provider-result-v1"
CREDENTIAL_HANDOFF_SCHEMA = "secure-sandbox-native-credential-client-handoff-v1"
PROJECTION_RECONCILIATION_HANDOFF_SCHEMA = (
    "secure-sandbox-native-projection-reconciliation-handoff-v1"
)
PROJECTION_IDENTITY_RECOVERY_HANDOFF_SCHEMA = (
    "secure-sandbox-native-projection-identity-recovery-handoff-v1"
)
PROJECTION_RECONCILIATION_HOST_TICKET_SCHEMA = (
    "secure-sandbox-native-projection-reconciliation-host-ticket-v1"
)
PROJECTION_IDENTITY_RECOVERY_HOST_TICKET_SCHEMA = (
    "secure-sandbox-native-projection-identity-recovery-host-ticket-v1"
)
CREDENTIAL_TICKET_SCHEMA = "secure-sandbox-native-credential-authorization-ticket-v1"
CREDENTIAL_TICKET_ROOT = Path("/usr/local/var/lib/secure-sandbox/native-credential-tickets")
CREDENTIAL_TICKET_LOCK = ".inventory.lock"
CREDENTIAL_TICKET_MAXIMUM = 1024
CREDENTIAL_TICKET_MAXIMUM_BYTES = 32 * 1024
CREDENTIAL_TICKET_TEMP_MAXIMUM_AGE_SECONDS = 300
AUTHORIZATION_RECEIPT_ROOT = Path("/usr/local/var/log/secure-sandbox/authorization-receipts")
CATALOG_PATH = Path("/usr/local/var/lib/secure-sandbox/native-stack-catalog/catalog.json")
PROGRAM_ATTESTATION_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-program-attestations"
)
TERMINAL_HANDLE_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-terminal-handles"
)
CODEX_UI_HANDLE_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-codex-ui-handles"
)
CONTROL_CLIENT = HERE / "control_client"
SSH_CONFIG = HERE / "ssh_config"
SIGNED_CREDENTIAL_CLIENT = HERE / "native_stack_credential_client"
PROJECTION_CONSUMER = HERE / "native_projection_consumer"
LAUNCHCTL = Path("/bin/launchctl")

QUALIFICATION_PERSONA_SHA256 = hashlib.sha256(
    b"secure-sandbox-native-entitlement-qualification-persona-v1\n"
).hexdigest()
QUALIFICATION_TOOL_CATALOG_SHA256 = hashlib.sha256(
    b'{"schema":"secure-sandbox-native-qualification-tools-v1","tools":[]}\n'
).hexdigest()
QUALIFICATION_EXTENSION_SET_SHA256 = hashlib.sha256(
    b'{"extensions":[],"schema":"secure-sandbox-native-qualification-extensions-v1"}\n'
).hexdigest()


class NativeStackBackendError(RuntimeError):
    """Stable fail-closed adapter rejection."""


def canonical(value: object) -> bytes:
    try:
        raw = (
            json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeStackBackendError("native_stack_backend_value_invalid") from error
    if len(raw) > MAX_INPUT:
        raise NativeStackBackendError("native_stack_backend_value_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_canonical(stream: Any = sys.stdin.buffer) -> dict[str, Any]:
    raw = stream.read(MAX_INPUT + 1)
    if not 2 <= len(raw) <= MAX_INPUT:
        raise NativeStackBackendError("native_stack_backend_input_size_invalid")
    if any(name in raw.lower() for name in MANAGER.FORBIDDEN_SERIALIZED_NAMES):
        raise NativeStackBackendError("native_stack_backend_secret_field_forbidden")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_input_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeStackBackendError("native_stack_backend_input_not_canonical")
    return value


def validate_host_ticket(
    value: object,
    *,
    now: int,
    expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH,
    trusted_uid: int = 0,
    require_fresh: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "ticket_sha256"
    }:
        raise NativeStackBackendError("native_stack_backend_ticket_fields_invalid")
    body = {"schema": value.get("schema"), "plan": value.get("plan"),
            "authorization": value.get("authorization")}
    if (value["schema"] != HOST_TICKET_SCHEMA
            or value["ticket_sha256"] != digest(body)):
        raise NativeStackBackendError("native_stack_backend_ticket_invalid")
    try:
        plan = operations.validate_plan(
            value["plan"], now=now, require_fresh=require_fresh
        )
        authorization = MANAGER.validate_authorization(
            value["authorization"], plan, now=now,
            require_fresh=require_fresh,
            expected_host_release_id=expected_host_release_id,
        )
        if require_fresh:
            MANAGER.verify_authorization_receipt(
                authorization, plan, receipt_root=receipt_root,
                trusted_uid=trusted_uid,
            )
        stack, catalog_sha256 = MANAGER.authoritative_stack(plan, catalog_path)
    except (MANAGER.NativeStackManagerError,
            operations.NativeStackOperationError) as error:
        raise NativeStackBackendError("native_stack_backend_authority_rejected") from error
    if MANAGER.expected_plan_identity(stack) != plan["identity"]:
        raise NativeStackBackendError("native_stack_backend_catalog_mismatch")
    return plan, authorization, stack, catalog_sha256


def validate_session_host_ticket(
    value: object,
    *,
    now: int,
    expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH,
    trusted_uid: int = 0,
    require_fresh: bool = True,
    verify_pending_receipt: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    """Independently validate one session-start/stop Touch ID authority."""
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "ticket_sha256"
    }:
        raise NativeStackBackendError(
            "native_stack_session_ticket_fields_invalid"
        )
    body = {
        "schema": value.get("schema"), "plan": value.get("plan"),
        "authorization": value.get("authorization"),
    }
    if (value.get("schema") != SESSION_HOST_TICKET_SCHEMA
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError("native_stack_session_ticket_invalid")
    try:
        plan = native_stack_session.validate_plan(
            value["plan"], now=now, require_fresh=require_fresh
        )
        authorization = native_stack_session.validate_authorization(
            value["authorization"], plan, now=now,
            expected_host_release_id=expected_host_release_id,
            require_fresh=require_fresh,
        )
        receipt = (
            MANAGER.trusted_canonical_document(
                receipt_root / f"{authorization['authorization_id']}.json",
                trusted_uid,
            )
            if verify_pending_receipt else None
        )
        expected_receipt_fields = {
            "schema", "request_id", "request_sha256", "status",
            "started_at", "completed_at", "operation", "declared_agent",
            "declared_session", "identity_evidence",
            "authorization_method", "ceremony", "purpose", "resource",
            "exit_status", "stdout_sha256", "stderr_sha256",
            "native_session_action_id", "native_session_id",
            "native_session_plan_sha256", "host_release_id",
        }
        if (verify_pending_receipt and (
                not isinstance(receipt, dict)
                or set(receipt) != expected_receipt_fields
                or digest(receipt) != authorization["pending_receipt_sha256"]
                or receipt["schema"]
                    != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt["request_id"] != authorization["authorization_id"]
                or receipt["request_sha256"]
                    != authorization["request_sha256"]
                or receipt["status"] != "executing"
                or receipt["started_at"] != authorization["authorized_at"]
                or receipt["completed_at"] is not None
                or receipt["operation"] != f"native-{plan['action']}"
                or receipt["identity_evidence"] != "operator-declared"
                or receipt["authorization_method"] != "touch-id"
                or receipt["ceremony"] != "approve"
                or receipt["exit_status"] is not None
                or receipt["stdout_sha256"] is not None
                or receipt["stderr_sha256"] is not None
                or receipt["native_session_action_id"] != plan["action_id"]
                or receipt["native_session_id"] != plan["session_id"]
                or receipt["native_session_plan_sha256"]
                    != plan["plan_sha256"]
                or receipt["host_release_id"]
                    != authorization["host_release_id"]
                or hashlib.sha256(
                    receipt["declared_agent"].encode("utf-8")
                ).hexdigest() != authorization["requesting_agent_sha256"]
                or hashlib.sha256(
                    receipt["declared_session"].encode("utf-8")
                ).hexdigest()
                    != authorization["requesting_session_sha256"])):
            raise NativeStackBackendError(
                "native_stack_session_receipt_invalid"
            )
        MANAGER._trusted_directory(catalog_path.parent, trusted_uid)
        catalog = native_vendor_stack.load_catalog(catalog_path, private=True)
        catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(catalog)
        ).hexdigest()
        stack = native_vendor_stack.stack_by_id(catalog, plan["stack_id"])
        expected_native = native_stack_runtime_binding.make_binding(stack)
        authority = runtime_authority.validate_binding(
            plan["runtime_authority"]
        )
    except (
        OSError,
        MANAGER.NativeStackManagerError,
        native_stack_session.NativeStackSessionError,
        native_stack_runtime_binding.NativeStackBindingError,
        native_vendor_stack.NativeVendorStackError,
        runtime_authority.RuntimeAuthorityError,
    ) as error:
        raise NativeStackBackendError(
            "native_stack_session_authority_rejected"
        ) from error
    if (catalog_sha256 != plan["catalog_sha256"]
            or native_vendor_stack.stack_revision(stack)
                != plan["stack_sha256"]
            or authority["model_stack_binding"]["authority"]
                != expected_native):
        raise NativeStackBackendError(
            "native_stack_session_catalog_mismatch"
        )
    return plan, authorization, stack, catalog_sha256


def _verify_completed_session_receipt(
    authorization: Mapping[str, Any], plan: Mapping[str, Any],
    public_handle: Mapping[str, Any], *, receipt_root: Path,
    trusted_uid: int,
) -> None:
    receipt = MANAGER.trusted_canonical_document(
        receipt_root / f"{authorization['authorization_id']}.json",
        trusted_uid,
    )
    expected = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "native_session_action_id", "native_session_id",
        "native_session_plan_sha256", "host_release_id",
    }
    pending = dict(receipt)
    pending.update({
        "status": "executing", "completed_at": None, "exit_status": None,
        "stdout_sha256": None, "stderr_sha256": None,
    })
    if (set(receipt) != expected
            or receipt.get("schema")
                != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != authorization["authorization_id"]
            or receipt.get("request_sha256")
                != authorization["request_sha256"]
            or receipt.get("status") != "succeeded"
            or receipt.get("started_at") != authorization["authorized_at"]
            or not isinstance(receipt.get("completed_at"), int)
            or isinstance(receipt.get("completed_at"), bool)
            or receipt["completed_at"] < receipt["started_at"]
            or receipt.get("operation") != "native-session-start"
            or receipt.get("identity_evidence") != "operator-declared"
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("ceremony") != "approve"
            or receipt.get("exit_status") != 0
            or receipt.get("stdout_sha256")
                != hashlib.sha256(canonical(public_handle)).hexdigest()
            or receipt.get("stderr_sha256") != hashlib.sha256(b"").hexdigest()
            or receipt.get("native_session_action_id") != plan["action_id"]
            or receipt.get("native_session_id") != plan["session_id"]
            or receipt.get("native_session_plan_sha256") != plan["plan_sha256"]
            or receipt.get("host_release_id")
                != authorization["host_release_id"]
            or hashlib.sha256(
                str(receipt.get("declared_agent")).encode("utf-8")
            ).hexdigest() != authorization["requesting_agent_sha256"]
            or hashlib.sha256(
                str(receipt.get("declared_session")).encode("utf-8")
            ).hexdigest() != authorization["requesting_session_sha256"]
            or digest(pending) != authorization["pending_receipt_sha256"]):
        raise NativeStackBackendError(
            "native_stack_session_completed_receipt_invalid"
        )


def validate_session_continuation_ticket(
    value: object, *, now: int, expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH,
    terminal_root: Path = TERMINAL_HANDLE_ROOT,
    codex_ui_root: Path = CODEX_UI_HANDLE_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "handle_id", "ticket_sha256"
    }:
        raise NativeStackBackendError(
            "native_stack_session_continuation_ticket_fields_invalid"
        )
    body = {
        "schema": value.get("schema"), "plan": value.get("plan"),
        "authorization": value.get("authorization"),
        "handle_id": value.get("handle_id"),
    }
    if (value.get("schema") != SESSION_CONTINUATION_TICKET_SCHEMA
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_stack_session_continuation_ticket_invalid"
        )
    session_body = {
        "schema": SESSION_HOST_TICKET_SCHEMA,
        "plan": value["plan"], "authorization": value["authorization"],
    }
    plan, authorization, stack, catalog_sha256 = validate_session_host_ticket(
        {**session_body, "ticket_sha256": digest(session_body)},
        now=now, expected_host_release_id=expected_host_release_id,
        receipt_root=receipt_root, catalog_path=catalog_path,
        trusted_uid=trusted_uid, require_fresh=False,
        verify_pending_receipt=False,
    )
    try:
        if stack["vendor_id"] == "anthropic":
            record, consumption = native_terminal_handle.read_consumed_by_id(
                root=terminal_root, handle_id=str(value["handle_id"]),
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            )
            public = native_terminal_handle.public_record(record)
        elif stack["vendor_id"] == "openai":
            record, consumption = native_codex_ui_handle.read_consumed_by_id(
                root=codex_ui_root, handle_id=str(value["handle_id"]),
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            )
            public = native_codex_ui_handle.public_record(record)
        else:
            raise NativeStackBackendError(
                "native_stack_session_handle_vendor_invalid"
            )
    except (
        OSError,
        native_terminal_handle.NativeTerminalHandleError,
        native_codex_ui_handle.NativeCodexUIHandleError,
    ) as error:
        raise NativeStackBackendError(
            "native_stack_session_handle_unavailable"
        ) from error
    if (plan["action"] != "session-start"
            or value["handle_id"] != record["handle_id"]
            or record["kind"] != (
                "claude-session" if stack["vendor_id"] == "anthropic"
                else native_codex_ui_handle.KIND
            )
            or record["operation_id"] != plan["action_id"]
            or record["session_id"] != plan["session_id"]
            or record["plan_sha256"] != plan["plan_sha256"]
            or record["authorization_sha256"]
                != authorization["authorization_sha256"]
            or record["stack_sha256"] != plan["stack_sha256"]
            or record["catalog_sha256"] != catalog_sha256
            or consumption["claimed_at"] >= record["expires_at"]):
        raise NativeStackBackendError(
            "native_stack_session_handle_mismatch"
        )
    _verify_completed_session_receipt(
        authorization, plan, public, receipt_root=receipt_root,
        trusted_uid=trusted_uid,
    )
    return plan, authorization, stack, catalog_sha256


def validate_session_prepare_ticket(
    value: object, *, now: int, expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH, trusted_uid: int = 0,
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], str, dict[str, Any]
]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "grant", "ticket_sha256"
    }:
        raise NativeStackBackendError(
            "native_stack_session_prepare_ticket_fields_invalid"
        )
    body = {
        "schema": value.get("schema"), "plan": value.get("plan"),
        "authorization": value.get("authorization"),
        "grant": value.get("grant"),
    }
    if (value.get("schema") != SESSION_PREPARE_TICKET_SCHEMA
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_stack_session_prepare_ticket_invalid"
        )
    session_body = {
        "schema": SESSION_HOST_TICKET_SCHEMA,
        "plan": value["plan"], "authorization": value["authorization"],
    }
    plan, authorization, stack, catalog_sha256 = validate_session_host_ticket(
        {**session_body, "ticket_sha256": digest(session_body)},
        now=now, expected_host_release_id=expected_host_release_id,
        receipt_root=receipt_root, catalog_path=catalog_path,
        trusted_uid=trusted_uid,
    )
    try:
        grant = native_egress.validate_grant(value["grant"], now=now)
        authority = runtime_authority.validate_binding(
            plan["runtime_authority"]
        )
    except (
        native_egress.NativeEgressError,
        runtime_authority.RuntimeAuthorityError,
    ) as error:
        raise NativeStackBackendError(
            "native_stack_session_prepare_grant_invalid"
        ) from error
    binding = grant["binding"]
    duration = native_stack_session.LEASE_DURATIONS.get(
        plan["lease_profile_id"]
    )
    maximum = native_egress.POLICIES[stack["network_policy_id"]]["phases"][
        native_egress.PHASE_INFERENCE
    ]["maximum_duration_seconds"]
    if (duration is None or duration > maximum
            or grant["phase"] != native_egress.PHASE_INFERENCE
            or binding["kind"] != "runtime-authority"
            or binding["value"] != authority
            or grant["issued_at"] < authorization["authorized_at"]
            or grant["expires_at"] - grant["issued_at"] != duration):
        raise NativeStackBackendError(
            "native_stack_session_prepare_grant_mismatch"
        )
    try:
        lease = native_stack_session.make_session_lease(
            lease_profile_id=plan["lease_profile_id"],
            session_id=plan["session_id"],
            runtime_authority_sha256=plan["runtime_authority_sha256"],
            grant_id=grant["grant_id"], grant_sha256=grant["grant_sha256"],
            issued_at=grant["issued_at"], expires_at=grant["expires_at"],
        )
    except native_stack_session.NativeStackSessionError as error:
        raise NativeStackBackendError(
            "native_stack_session_prepare_lease_invalid"
        ) from error
    return plan, authorization, stack, catalog_sha256, lease


def validate_codex_prepare_ticket(
    value: object, *, now: int, expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH,
    codex_ui_root: Path = CODEX_UI_HANDLE_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any],
    dict[str, Any],
]:
    fields = {
        "schema", "plan", "authorization", "handle_id", "session_lease",
        "projection_claim", "ticket_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackBackendError(
            "native_codex_prepare_ticket_fields_invalid"
        )
    body = {key: value.get(key) for key in fields - {"ticket_sha256"}}
    if (value.get("schema") != SESSION_CODEX_PREPARE_TICKET_SCHEMA
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError("native_codex_prepare_ticket_invalid")
    continuation = {
        "schema": SESSION_CONTINUATION_TICKET_SCHEMA,
        "plan": value["plan"], "authorization": value["authorization"],
        "handle_id": value["handle_id"],
    }
    continuation["ticket_sha256"] = digest(continuation)
    plan, authorization, stack, _catalog = validate_session_continuation_ticket(
        continuation, now=now,
        expected_host_release_id=expected_host_release_id,
        receipt_root=receipt_root, catalog_path=catalog_path,
        codex_ui_root=codex_ui_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    try:
        lease = native_stack_session.validate_session_lease(
            value["session_lease"], now=now, require_fresh=True
        )
        claim = native_codex_projection.validate_claim(
            value["projection_claim"], now_ms=now * 1000
        )
        record, _consumption = native_codex_ui_handle.read_consumed_by_id(
            root=codex_ui_root, handle_id=str(value["handle_id"]),
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        )
    except (
        native_stack_session.NativeStackSessionError,
        native_codex_projection.NativeCodexProjectionError,
        native_codex_ui_handle.NativeCodexUIHandleError,
        OSError,
    ) as error:
        raise NativeStackBackendError(
            "native_codex_prepare_authority_invalid"
        ) from error
    if (stack["vendor_id"] != "openai" or lease != record["session_lease"]
            or lease["session_id"] != plan["session_id"]
            or lease["runtime_authority_sha256"]
                != plan["runtime_authority_sha256"]
            or claim["operation_id"] != plan["action_id"]
            or claim["session_authority_sha256"]
                != plan["runtime_authority_sha256"]
            or claim["authorization_receipt_sha256"]
                != authorization["pending_receipt_sha256"]):
        raise NativeStackBackendError(
            "native_codex_prepare_authority_mismatch"
        )
    return plan, authorization, stack, lease, claim


def validate_session_recovery_ticket(
    value: object, *, now: int, expected_host_release_id: str,
    catalog_path: Path = CATALOG_PATH, trusted_uid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    """Validate cleanup-only authority; it can never start or open egress."""
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "journal_sha256", "ticket_sha256"
    }:
        raise NativeStackBackendError(
            "native_stack_session_recovery_ticket_fields_invalid"
        )
    body = {
        "schema": value.get("schema"), "plan": value.get("plan"),
        "authorization": value.get("authorization"),
        "journal_sha256": value.get("journal_sha256"),
    }
    if (value.get("schema") != SESSION_RECOVERY_TICKET_SCHEMA
            or operations.SHA256.fullmatch(
                str(value.get("journal_sha256", ""))
            ) is None
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_stack_session_recovery_ticket_invalid"
        )
    try:
        plan = native_stack_session.validate_plan(
            value["plan"], now=now, require_fresh=False
        )
        authorization = native_stack_session.validate_authorization(
            value["authorization"], plan, now=now,
            expected_host_release_id=expected_host_release_id,
            require_fresh=False,
        )
        MANAGER._trusted_directory(catalog_path.parent, trusted_uid)
        catalog = native_vendor_stack.load_catalog(catalog_path, private=True)
        catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(catalog)
        ).hexdigest()
        stack = native_vendor_stack.stack_by_id(catalog, plan["stack_id"])
        expected_native = native_stack_runtime_binding.make_binding(stack)
        authority = runtime_authority.validate_binding(
            plan["runtime_authority"]
        )
    except (
        OSError,
        MANAGER.NativeStackManagerError,
        native_stack_session.NativeStackSessionError,
        native_stack_runtime_binding.NativeStackBindingError,
        native_vendor_stack.NativeVendorStackError,
        runtime_authority.RuntimeAuthorityError,
    ) as error:
        raise NativeStackBackendError(
            "native_stack_session_recovery_authority_invalid"
        ) from error
    if (plan["action"] != "session-start"
            or catalog_sha256 != plan["catalog_sha256"]
            or native_vendor_stack.stack_revision(stack) != plan["stack_sha256"]
            or authority["model_stack_binding"]["authority"] != expected_native):
        raise NativeStackBackendError(
            "native_stack_session_recovery_authority_mismatch"
        )
    return plan, authorization, stack, catalog_sha256


def _verify_projection_reconciliation_receipt(
    authorization: Mapping[str, Any], plan: Mapping[str, Any], *,
    receipt_root: Path, trusted_uid: int,
) -> None:
    receipt = MANAGER.trusted_canonical_document(
        receipt_root / f"{authorization['authorization_id']}.json",
        trusted_uid,
    )
    expected = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "native_projection_recovery_operation_id",
        "native_projection_original_operation_id",
        "native_projection_reconciliation_plan_sha256", "host_release_id",
    }
    if (set(receipt) != expected
            or receipt.get("schema")
                != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != authorization["authorization_id"]
            or receipt.get("request_sha256") != authorization["request_sha256"]
            or receipt.get("status") != "executing"
            or receipt.get("started_at") != authorization["authorized_at"]
            or receipt.get("completed_at") is not None
            or receipt.get("operation")
                != native_projection_reconciliation.OPERATION
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("ceremony") != "approve"
            or receipt.get("exit_status") is not None
            or receipt.get("stdout_sha256") is not None
            or receipt.get("stderr_sha256") is not None
            or receipt.get("native_projection_recovery_operation_id")
                != plan["recovery_operation_id"]
            or receipt.get("native_projection_original_operation_id")
                != plan["original_operation_id"]
            or receipt.get("native_projection_reconciliation_plan_sha256")
                != plan["plan_sha256"]
            or receipt.get("host_release_id") != plan["host_release_id"]
            or digest(receipt) != authorization["pending_receipt_sha256"]
            or hashlib.sha256(
                receipt["declared_agent"].encode("utf-8")
            ).hexdigest() != authorization["requesting_agent_sha256"]
            or hashlib.sha256(
                receipt["declared_session"].encode("utf-8")
            ).hexdigest() != authorization["requesting_session_sha256"]):
        raise NativeStackBackendError(
            "native_projection_reconciliation_receipt_invalid"
        )


def validate_projection_reconciliation_host_ticket(
    value: object, *, now: int, expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH, trusted_uid: int = 0,
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any],
    dict[str, Any], str,
]:
    fields = {
        "schema", "plan", "authorization", "original_plan",
        "original_authorization", "journal_sha256", "ticket_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeStackBackendError(
            "native_projection_reconciliation_host_ticket_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"ticket_sha256"}}
    if (value.get("schema") != PROJECTION_RECONCILIATION_HOST_TICKET_SCHEMA
            or operations.SHA256.fullmatch(
                str(value.get("journal_sha256", ""))
            ) is None
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_projection_reconciliation_host_ticket_invalid"
        )
    try:
        plan = native_projection_reconciliation.validate_plan(
            value["plan"], now=now, require_fresh=True
        )
        authorization = native_projection_reconciliation.validate_authorization(
            value["authorization"], plan, now=now,
            expected_host_release_id=expected_host_release_id,
        )
    except native_projection_reconciliation.NativeProjectionReconciliationError as error:
        raise NativeStackBackendError(
            "native_projection_reconciliation_authority_invalid"
        ) from error
    recovery_body = {
        "schema": SESSION_RECOVERY_TICKET_SCHEMA,
        "plan": value["original_plan"],
        "authorization": value["original_authorization"],
        "journal_sha256": value["journal_sha256"],
    }
    original_plan, original_authorization, stack, catalog_sha256 = (
        validate_session_recovery_ticket(
            {**recovery_body, "ticket_sha256": digest(recovery_body)},
            now=now, expected_host_release_id=expected_host_release_id,
            catalog_path=catalog_path, trusted_uid=trusted_uid,
        )
    )
    _verify_projection_reconciliation_receipt(
        authorization, plan, receipt_root=receipt_root,
        trusted_uid=trusted_uid,
    )
    if (stack.get("vendor_id") != "openai"
            or plan["original_operation_id"] != original_plan["action_id"]
            or plan["session_id"] != original_plan["session_id"]
            or plan["stack_id"] != original_plan["stack_id"]
            or plan["stack_sha256"] != original_plan["stack_sha256"]
            or plan["session_authority_sha256"]
                != original_plan["runtime_authority_sha256"]
            or plan["host_release_id"] != expected_host_release_id):
        raise NativeStackBackendError(
            "native_projection_reconciliation_authority_mismatch"
        )
    return (
        plan, authorization, original_plan, original_authorization, stack,
        catalog_sha256,
    )


def _verify_projection_identity_recovery_receipt(
    authorization: Mapping[str, Any], plan: Mapping[str, Any], *,
    receipt_root: Path, trusted_uid: int,
) -> None:
    receipt = MANAGER.trusted_canonical_document(
        receipt_root / f"{authorization['authorization_id']}.json",
        trusted_uid,
    )
    expected = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "native_projection_recovery_operation_id",
        "native_projection_original_operation_id",
        "native_projection_identity_recovery_plan_sha256", "host_release_id",
    }
    if (set(receipt) != expected
            or receipt.get("schema")
                != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != authorization["authorization_id"]
            or receipt.get("request_sha256") != authorization["request_sha256"]
            or receipt.get("status") != "executing"
            or receipt.get("started_at") != authorization["authorized_at"]
            or receipt.get("completed_at") is not None
            or receipt.get("operation")
                != native_projection_identity_recovery.OPERATION
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("ceremony") != "approve"
            or receipt.get("exit_status") is not None
            or receipt.get("stdout_sha256") is not None
            or receipt.get("stderr_sha256") is not None
            or receipt.get("native_projection_recovery_operation_id")
                != plan["recovery_operation_id"]
            or receipt.get("native_projection_original_operation_id")
                != plan["original_operation_id"]
            or receipt.get(
                "native_projection_identity_recovery_plan_sha256"
            ) != plan["plan_sha256"]
            or receipt.get("host_release_id") != plan["host_release_id"]
            or digest(receipt) != authorization["pending_receipt_sha256"]
            or hashlib.sha256(
                receipt["declared_agent"].encode("utf-8")
            ).hexdigest() != authorization["requesting_agent_sha256"]
            or hashlib.sha256(
                receipt["declared_session"].encode("utf-8")
            ).hexdigest() != authorization["requesting_session_sha256"]):
        raise NativeStackBackendError(
            "native_projection_identity_recovery_receipt_invalid"
        )


def validate_projection_identity_recovery_host_ticket(
    value: object, *, now: int, expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH, trusted_uid: int = 0,
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any],
    dict[str, Any], str,
]:
    fields = {
        "schema", "plan", "authorization", "original_plan",
        "original_authorization", "journal_sha256", "ticket_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeStackBackendError(
            "native_projection_identity_recovery_host_ticket_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"ticket_sha256"}}
    if (value.get("schema") != PROJECTION_IDENTITY_RECOVERY_HOST_TICKET_SCHEMA
            or operations.SHA256.fullmatch(
                str(value.get("journal_sha256", ""))
            ) is None
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_projection_identity_recovery_host_ticket_invalid"
        )
    try:
        plan = native_projection_identity_recovery.validate_plan(
            value["plan"], now=now, require_fresh=True
        )
        authorization = (
            native_projection_identity_recovery.validate_authorization(
                value["authorization"], plan, now=now,
                expected_host_release_id=expected_host_release_id,
            )
        )
    except native_projection_identity_recovery.NativeProjectionIdentityRecoveryError as error:
        raise NativeStackBackendError(
            "native_projection_identity_recovery_authority_invalid"
        ) from error
    recovery_body = {
        "schema": SESSION_RECOVERY_TICKET_SCHEMA,
        "plan": value["original_plan"],
        "authorization": value["original_authorization"],
        "journal_sha256": value["journal_sha256"],
    }
    original_plan, original_authorization, stack, catalog_sha256 = (
        validate_session_recovery_ticket(
            {**recovery_body, "ticket_sha256": digest(recovery_body)},
            now=now, expected_host_release_id=expected_host_release_id,
            catalog_path=catalog_path, trusted_uid=trusted_uid,
        )
    )
    _verify_projection_identity_recovery_receipt(
        authorization, plan, receipt_root=receipt_root,
        trusted_uid=trusted_uid,
    )
    if (stack.get("vendor_id") != "openai"
            or plan["original_operation_id"] != original_plan["action_id"]
            or plan["session_id"] != original_plan["session_id"]
            or plan["stack_id"] != original_plan["stack_id"]
            or plan["stack_sha256"] != original_plan["stack_sha256"]
            or plan["session_authority_sha256"]
                != original_plan["runtime_authority_sha256"]
            or plan["host_release_id"] != expected_host_release_id):
        raise NativeStackBackendError(
            "native_projection_identity_recovery_authority_mismatch"
        )
    return (
        plan, authorization, original_plan, original_authorization, stack,
        catalog_sha256,
    )


def prepare_login_handle(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], catalog_sha256: str, *, now: int,
    terminal_root: Path = TERMINAL_HANDLE_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    if (plan["action"] != "signin-begin"
            or stack["vendor_id"] != "anthropic"
            or plan["identity"]["stack_sha256"]
                != native_vendor_stack.stack_revision(stack)):
        raise NativeStackBackendError(
            "native_stack_interactive_login_invalid"
        )
    _ensure_root_directory(
        terminal_root, 0o700, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    action_id = plan["action_id"]
    record = native_terminal_handle.make_record(
        handle_id=action_id, kind="claude-login", operation_id=action_id,
        plan_sha256=plan["plan_sha256"],
        authorization_sha256=authorization["authorization_sha256"],
        stack_sha256=plan["identity"]["stack_sha256"],
        catalog_sha256=catalog_sha256, session_id=action_id,
        remote_arguments=[
            action_id, plan["plan_sha256"],
            authorization["authorization_sha256"],
            plan["identity"]["stack_sha256"], catalog_sha256,
        ],
        issued_at=now, expires_at=min(
            authorization["expires_at"],
            now + native_terminal_handle.MAXIMUM_LIFETIME_SECONDS,
        ),
    )
    return native_terminal_handle.publish(
        record, root=terminal_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )


def _verify_completed_interactive_receipt(
    authorization: Mapping[str, Any], plan: Mapping[str, Any],
    public_handle: Mapping[str, Any], *, receipt_root: Path,
    trusted_uid: int,
) -> None:
    receipt = MANAGER.trusted_canonical_document(
        receipt_root / f"{authorization['authorization_id']}.json",
        trusted_uid,
    )
    expected = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "native_action_id", "native_plan_sha256", "host_release_id",
    }
    pending = dict(receipt)
    pending.update({
        "status": "executing", "completed_at": None, "exit_status": None,
        "stdout_sha256": None, "stderr_sha256": None,
    })
    if (set(receipt) != expected
            or receipt.get("schema")
                != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != authorization["authorization_id"]
            or receipt.get("request_sha256")
                != authorization["request_sha256"]
            or receipt.get("status") != "succeeded"
            or receipt.get("started_at") != authorization["authorized_at"]
            or not isinstance(receipt.get("completed_at"), int)
            or isinstance(receipt.get("completed_at"), bool)
            or receipt["completed_at"] < receipt["started_at"]
            or receipt.get("operation") != "native-stack-signin-begin"
            or receipt.get("identity_evidence") != "operator-declared"
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("ceremony") != "approve"
            or receipt.get("exit_status") != 0
            or receipt.get("stdout_sha256")
                != hashlib.sha256(canonical(public_handle)).hexdigest()
            or receipt.get("stderr_sha256") != hashlib.sha256(b"").hexdigest()
            or receipt.get("native_action_id") != plan["action_id"]
            or receipt.get("native_plan_sha256") != plan["plan_sha256"]
            or receipt.get("host_release_id")
                != authorization["host_release_id"]
            or hashlib.sha256(
                str(receipt.get("declared_agent")).encode("utf-8")
            ).hexdigest() != authorization["requesting_agent_sha256"]
            or hashlib.sha256(
                str(receipt.get("declared_session")).encode("utf-8")
            ).hexdigest() != authorization["requesting_session_sha256"]
            or digest(pending) != authorization["pending_receipt_sha256"]):
        raise NativeStackBackendError(
            "native_stack_interactive_receipt_invalid"
        )


def validate_interactive_resume_ticket(
    value: object, *, now: int, expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH,
    terminal_root: Path = TERMINAL_HANDLE_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "handle_id", "ticket_sha256"
    }:
        raise NativeStackBackendError(
            "native_stack_interactive_ticket_fields_invalid"
        )
    body = {
        "schema": value.get("schema"), "plan": value.get("plan"),
        "authorization": value.get("authorization"),
        "handle_id": value.get("handle_id"),
    }
    if (value.get("schema") != INTERACTIVE_HOST_TICKET_SCHEMA
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_stack_interactive_ticket_invalid"
        )
    plan, authorization, stack, catalog_sha256 = validate_host_ticket(
        {
            "schema": HOST_TICKET_SCHEMA,
            "plan": value["plan"], "authorization": value["authorization"],
            "ticket_sha256": digest({
                "schema": HOST_TICKET_SCHEMA,
                "plan": value["plan"],
                "authorization": value["authorization"],
            }),
        },
        now=now, expected_host_release_id=expected_host_release_id,
        receipt_root=receipt_root, catalog_path=catalog_path,
        trusted_uid=trusted_uid, require_fresh=False,
    )
    try:
        record, _consumption = native_terminal_handle.read_consumed_by_id(
            root=terminal_root, handle_id=str(value["handle_id"]),
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        )
        public = native_terminal_handle.public_record(record)
    except (OSError, native_terminal_handle.NativeTerminalHandleError) as error:
        raise NativeStackBackendError(
            "native_stack_interactive_handle_unavailable"
        ) from error
    expected_arguments = [
        plan["action_id"], plan["plan_sha256"],
        authorization["authorization_sha256"],
        plan["identity"]["stack_sha256"], catalog_sha256,
    ]
    if (plan["action"] != "signin-begin" or stack["vendor_id"] != "anthropic"
            or value["handle_id"] != plan["action_id"]
            or record["kind"] != "claude-login"
            or record["operation_id"] != plan["action_id"]
            or record["session_id"] != plan["action_id"]
            or record["plan_sha256"] != plan["plan_sha256"]
            or record["authorization_sha256"]
                != authorization["authorization_sha256"]
            or record["stack_sha256"] != plan["identity"]["stack_sha256"]
            or record["catalog_sha256"] != catalog_sha256
            or record["remote_arguments"] != expected_arguments):
        raise NativeStackBackendError(
            "native_stack_interactive_handle_mismatch"
        )
    _verify_completed_interactive_receipt(
        authorization, plan, public, receipt_root=receipt_root,
        trusted_uid=trusted_uid,
    )
    return plan, authorization, stack, catalog_sha256


def validate_program_attestation_ticket(
    value: object,
    *,
    now: int,
    expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH,
    trusted_uid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "ticket_sha256"
    }:
        raise NativeStackBackendError(
            "native_program_attestation_ticket_fields_invalid"
        )
    body = {
        "schema": value.get("schema"), "plan": value.get("plan"),
        "authorization": value.get("authorization"),
    }
    if (value.get("schema")
            != "secure-sandbox-native-program-attestation-host-ticket-v1"
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError("native_program_attestation_ticket_invalid")
    try:
        plan = native_program_attestation.validate_plan(
            value["plan"], now=now, require_fresh=True
        )
        authorization = native_program_attestation.validate_authorization(
            value["authorization"], plan, now=now,
            expected_host_release_id=expected_host_release_id,
        )
        receipt = MANAGER.trusted_canonical_document(
            receipt_root / f"{authorization['authorization_id']}.json",
            trusted_uid,
        )
        expected_receipt_fields = {
            "schema", "request_id", "request_sha256", "status", "started_at",
            "completed_at", "operation", "declared_agent", "declared_session",
            "identity_evidence", "authorization_method", "ceremony", "purpose",
            "resource", "exit_status", "stdout_sha256", "stderr_sha256",
            "native_program_attestation_id", "native_program_plan_sha256",
            "host_release_id",
        }
        if (set(receipt) != expected_receipt_fields
                or digest(receipt) != authorization["pending_receipt_sha256"]
                or receipt["schema"]
                    != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt["request_id"] != authorization["authorization_id"]
                or receipt["request_sha256"] != authorization["request_sha256"]
                or receipt["status"] != "executing"
                or receipt["started_at"] != authorization["authorized_at"]
                or receipt["completed_at"] is not None
                or receipt["operation"] != native_program_attestation.OPERATION
                or receipt["identity_evidence"] != "operator-declared"
                or receipt["authorization_method"] != "touch-id"
                or receipt["ceremony"] != "approve"
                or receipt["exit_status"] is not None
                or receipt["stdout_sha256"] is not None
                or receipt["stderr_sha256"] is not None
                or receipt["native_program_attestation_id"]
                    != plan["attestation_id"]
                or receipt["native_program_plan_sha256"] != plan["plan_sha256"]
                or receipt["host_release_id"] != authorization["host_release_id"]
                or hashlib.sha256(
                    receipt["declared_agent"].encode("utf-8")
                ).hexdigest() != authorization["requesting_agent_sha256"]
                or hashlib.sha256(
                    receipt["declared_session"].encode("utf-8")
                ).hexdigest() != authorization["requesting_session_sha256"]):
            raise NativeStackBackendError(
                "native_program_attestation_receipt_invalid"
            )
        MANAGER._trusted_directory(catalog_path.parent, trusted_uid)
        catalog = native_vendor_stack.load_catalog(catalog_path, private=True)
        catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(catalog)
        ).hexdigest()
        stack = native_vendor_stack.stack_by_id(catalog, plan["stack_id"])
    except (
        OSError,
        MANAGER.NativeStackManagerError,
        native_program_attestation.NativeProgramAttestationError,
        native_vendor_stack.NativeVendorStackError,
    ) as error:
        raise NativeStackBackendError(
            "native_program_attestation_authority_rejected"
        ) from error
    binding = stack["account_binding"]
    if (stack["vendor_id"] != "anthropic"
            or catalog_sha256 != plan["catalog_sha256"]
            or native_vendor_stack.stack_revision(stack) != plan["stack_sha256"]
            or stack["harness"]["generation_id"]
                != plan["harness_generation_id"]
            or binding["account_subject_sha256"]
                != plan["account_subject_sha256"]
            or binding["workspace_sha256"] != plan["workspace_sha256"]
            or binding["program_id"] != plan["program_id"]
            or binding["program_tier"] != plan["program_tier"]
            or binding["program_requirements_version"]
                != plan["program_requirements_version"]):
        raise NativeStackBackendError(
            "native_program_attestation_catalog_mismatch"
        )
    return plan, authorization, stack, catalog_sha256


def program_attestation_request(
    plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    body = {
        "operation_id": plan["attestation_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "stack_sha256": plan["stack_sha256"],
        "harness_generation_id": plan["harness_generation_id"],
        "account_subject_sha256": plan["account_subject_sha256"],
        "workspace_sha256": plan["workspace_sha256"],
        "program_id": plan["program_id"],
        "program_tier": plan["program_tier"],
        "program_requirements_version": plan["program_requirements_version"],
        "attestation_receipt_sha256": authorization["pending_receipt_sha256"],
    }
    return {
        "schema": "secure-sandbox-native-program-attestation-request-v1",
        **body, "request_sha256": digest(body),
    }


def _inspect_program_status(
    plan: Mapping[str, Any], *, guest: Callable[[str, object], dict[str, Any]]
) -> dict[str, Any]:
    body = {
        "operation_id": plan["attestation_id"],
        "stack_id": plan["stack_id"], "stack_sha256": plan["stack_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
    }
    request = {
        "schema": "secure-sandbox-native-stack-inspect-status-request-v1",
        **body, "request_sha256": digest(body),
    }
    return operations.validate_status(
        guest("native-stack-inspect-status", request)
    )


def program_attest(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *,
    guest: Callable[[str, object], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    guest_transport = guest_call if guest is None else guest
    before = _inspect_program_status(plan, guest=guest_transport)
    binding = stack["account_binding"]
    if (before["status_sha256"] != plan["status_sha256"]
            or before["harness"]["state"] != "admitted"
            or before["harness"]["generation_id"]
                != plan["harness_generation_id"]
            or before["authentication"]["state"] != "signed-in"
            or before["account_binding"]["state"] != "bound"
            or before["account_binding"]["account_subject_sha256"]
                != binding["account_subject_sha256"]
            or before["account_binding"]["workspace_sha256"]
                != binding["workspace_sha256"]
            or before["network"]["phase"] != "closed"
            or before["live_run_count"] != 0
            or before["fence_reason"] is not None):
        raise NativeStackBackendError(
            "native_program_attestation_status_changed"
        )
    reply = guest_transport(
        "native-program-attestation",
        program_attestation_request(plan, authorization),
    )
    expected = {
        "schema", "action_id", "action", "plan_sha256",
        "authorization_sha256", "status", "evidence_sha256",
    }
    if (not isinstance(reply, dict) or set(reply) != expected
            or reply["schema"] != PROVIDER_RESULT_SCHEMA
            or reply["action_id"] != plan["attestation_id"]
            or reply["action"] != "program-attest"
            or reply["plan_sha256"] != plan["plan_sha256"]
            or reply["authorization_sha256"]
                != authorization["authorization_sha256"]
            or reply["status"] != "verified"
            or operations.SHA256.fullmatch(
                str(reply["evidence_sha256"])
            ) is None):
        raise NativeStackBackendError(
            "native_program_attestation_guest_invalid"
        )
    after = _inspect_program_status(plan, guest=guest_transport)
    program = after["program_entitlement"]
    if (program["state"] != "verified"
            or program["assurance"] != "operator-external"
            or program["evidence_sha256"] != reply["evidence_sha256"]
            or after["network"]["phase"] != "closed"
            or after["live_run_count"] != 0):
        raise NativeStackBackendError(
            "native_program_attestation_readback_invalid"
        )
    return dict(reply)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=0.5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=1)


def run_bounded(
    command: Sequence[str], input_bytes: bytes, *, timeout: float,
    maximum_output: int = MAX_OUTPUT, pass_fds: tuple[int, ...] = (),
) -> bytes:
    if not input_bytes or len(input_bytes) > MAX_INPUT:
        raise NativeStackBackendError("native_stack_backend_child_input_invalid")
    process = subprocess.Popen(
        list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
        pass_fds=pass_fds,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
    )
    if process.stdin is None or process.stdout is None:
        _terminate(process)
        raise NativeStackBackendError("native_stack_backend_child_failed")
    os.set_blocking(process.stdin.fileno(), False)
    os.set_blocking(process.stdout.fileno(), False)
    poller = select.poll()
    poller.register(process.stdin.fileno(), select.POLLOUT)
    poller.register(process.stdout.fileno(), select.POLLIN | select.POLLHUP)
    sent, output, stdout_open = 0, bytearray(), True
    deadline = time.monotonic() + timeout
    try:
        while stdout_open or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeStackBackendError("native_stack_backend_child_timeout")
            for descriptor, _events in poller.poll(
                max(1, int(min(remaining, 0.25) * 1000))
            ):
                if descriptor == process.stdin.fileno():
                    if sent < len(input_bytes):
                        try:
                            sent += os.write(process.stdin.fileno(), input_bytes[sent:])
                        except BlockingIOError:
                            pass
                    if sent == len(input_bytes):
                        poller.unregister(process.stdin.fileno())
                        process.stdin.close()
                elif descriptor == process.stdout.fileno():
                    try:
                        block = os.read(
                            process.stdout.fileno(),
                            min(65536, maximum_output + 1 - len(output)),
                        )
                    except BlockingIOError:
                        continue
                    if block:
                        output.extend(block)
                        if len(output) > maximum_output:
                            raise NativeStackBackendError(
                                "native_stack_backend_child_output_oversized"
                            )
                    else:
                        poller.unregister(process.stdout.fileno())
                        stdout_open = False
                        process.stdout.close()
            if process.poll() is not None and not stdout_open:
                break
        result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if result != 0 or not 2 <= len(output) <= maximum_output:
            raise NativeStackBackendError("native_stack_backend_child_failed")
        return bytes(output)
    except Exception:
        _terminate(process)
        raise
    finally:
        if not process.stdin.closed:
            process.stdin.close()
        if not process.stdout.closed:
            process.stdout.close()


def _resolver_child(hostname: str, descriptor: int) -> None:
    try:
        values = socket.getaddrinfo(
            hostname, 443, family=socket.AF_INET,
            type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
        raw = canonical({
            "hostname": hostname,
            "ipv4": sorted({item[4][0] for item in values}),
        })
        if len(raw) > 4096:
            raise ValueError
        os.write(descriptor, raw)
        os._exit(0)
    except BaseException:
        os._exit(1)


def resolve_once(hostname: str, *, timeout: float = 5.0) -> tuple[str, ...]:
    if (native_egress.HOSTNAME.fullmatch(hostname) is None
            or hostname != hostname.lower()):
        raise NativeStackBackendError("native_stack_backend_hostname_invalid")
    reader, writer = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(reader)
        _resolver_child(hostname, writer)
    os.close(writer)
    output, deadline, status = bytearray(), time.monotonic() + timeout, None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeStackBackendError("native_stack_backend_dns_timeout")
            readable, _, _ = select.select([reader], [], [], min(remaining, 0.1))
            if readable:
                block = os.read(reader, 4097 - len(output))
                if not block:
                    break
                output.extend(block)
                if len(output) > 4096:
                    raise NativeStackBackendError("native_stack_backend_dns_oversized")
            waited, observed = os.waitpid(child, os.WNOHANG)
            if waited == child:
                status = observed
                if not readable:
                    output.extend(os.read(reader, 4097 - len(output)))
                    break
        if status is None:
            _, status = os.waitpid(child, 0)
        if status != 0:
            raise NativeStackBackendError("native_stack_backend_dns_failed")
    except Exception:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
        raise
    finally:
        os.close(reader)
    try:
        value = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_dns_invalid") from error
    if (not isinstance(value, dict)
            or set(value) != {"hostname", "ipv4"}
            or value["hostname"] != hostname
            or bytes(output) != canonical(value)
            or not isinstance(value["ipv4"], list)
            or not 1 <= len(value["ipv4"]) <= 16
            or value["ipv4"] != sorted(set(value["ipv4"]))):
        raise NativeStackBackendError("native_stack_backend_dns_invalid")
    result = []
    for item in value["ipv4"]:
        try:
            address = ipaddress.ip_address(item)
        except ValueError as error:
            raise NativeStackBackendError(
                "native_stack_backend_dns_address_invalid"
            ) from error
        if address.version != 4 or not address.is_global or str(address) != item:
            raise NativeStackBackendError("native_stack_backend_dns_address_invalid")
        result.append(item)
    return tuple(result)


def resolve_policy(
    policy_id: str, phase: str, *,
    resolver: Callable[[str], tuple[str, ...]] = resolve_once,
) -> dict[str, list[str]]:
    policy = native_egress.POLICIES.get(policy_id)
    specification = None if policy is None else policy["phases"].get(phase)
    if specification is None:
        raise NativeStackBackendError("native_stack_backend_egress_phase_invalid")
    result = {}
    for hostname in sorted(specification["hosts"]):
        stable = sorted(set(resolver(hostname)) & set(resolver(hostname)))
        if not stable or len(stable) > 16:
            raise NativeStackBackendError(
                "native_stack_backend_dns_rebinding_ambiguous"
            )
        result[hostname] = stable
    return result


def guest_call(operation: str, payload: object) -> dict[str, Any]:
    raw = run_bounded([
        str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
        "--timeout-seconds", "120", "sandbox-research-control", "pipe", operation,
    ], canonical(payload), timeout=150)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_guest_reply_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeStackBackendError("native_stack_backend_guest_reply_invalid")
    return value


def _session_authority_readback(
    plan: Mapping[str, Any], *,
    guest: Callable[[str, object], dict[str, Any]],
) -> dict[str, Any]:
    context = plan["runtime_authority"]["session_context_binding"]
    body = {
        "operation_id": plan["action_id"],
        "stack_sha256": plan["stack_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
        "session_id": plan["session_id"],
        "source_id": plan["source_id"],
        "source_manifest_sha256": plan["source_manifest_sha256"],
        "persona_sha256": context["persona_sha256"],
        "tool_catalog_sha256": context["tool_catalog_sha256"],
        "extension_set_sha256": context["extension_set_sha256"],
    }
    request = {
        "schema": "secure-sandbox-native-session-authority-request-v1",
        **body, "request_sha256": digest(body),
    }
    reply = guest("native-session-authority", request)
    expected = {"schema", "authority", "evidence_sha256"}
    try:
        authority = runtime_authority.validate_binding(reply.get("authority"))
    except (AttributeError, runtime_authority.RuntimeAuthorityError) as error:
        raise NativeStackBackendError(
            "native_stack_session_authority_reply_invalid"
        ) from error
    expected_evidence = digest({
        "operation_id": plan["action_id"],
        "request_sha256": request["request_sha256"],
        "authority_sha256": authority["binding_sha256"],
    })
    if (not isinstance(reply, dict) or set(reply) != expected
            or reply.get("schema")
                != "secure-sandbox-native-session-authority-reply-v1"
            or authority != plan["runtime_authority"]
            or reply.get("evidence_sha256") != expected_evidence):
        raise NativeStackBackendError(
            "native_stack_session_authority_reply_invalid"
        )
    return authority


def _session_status(
    plan: Mapping[str, Any], stack: Mapping[str, Any], *, now: int,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]],
    guest: Callable[[str, object], dict[str, Any]],
) -> dict[str, Any]:
    body = {
        "operation_id": plan["action_id"],
        "stack_id": plan["stack_id"],
        "stack_sha256": plan["stack_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
    }
    observed = operations.validate_status(guest(
        "native-stack-inspect-status",
        {
            "schema": "secure-sandbox-native-stack-inspect-status-request-v1",
            **body, "request_sha256": digest(body),
        },
    ))
    if stack["vendor_id"] == "openai":
        reply = credential(credential_handoff(
            operation="status", operation_id=plan["action_id"],
            plan=None, authorization=None,
        ))
        observed = merge_openai_status(observed, reply, stack, now=now)
    return enforce_program_attestation_commit(
        observed, stack, plan["catalog_sha256"]
    )


def reconcile_projection(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    original_plan: Mapping[str, Any],
    original_authorization: Mapping[str, Any], stack: Mapping[str, Any], *,
    now: int,
    credential: Callable[..., dict[str, Any]] | None = None,
    status_credential: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
    ticket_root: Path = CREDENTIAL_TICKET_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    """Clear one exact ambiguous projection only after fresh closure proof."""
    reconciliation_transport = (
        signed_projection_reconciliation_call
        if credential is None else credential
    )
    status_transport = (
        signed_credential_call
        if status_credential is None else status_credential
    )
    stop = session_stop_continuation(
        original_plan, original_authorization, stack, guest=guest
    )
    observed = _session_status(
        original_plan, stack, now=now,
        credential=status_transport, guest=guest,
    )
    custody = observed["credential_custody"]
    try:
        egress_evidence = (
            native_projection_reconciliation.closed_egress_evidence_sha256(
                observed
            )
        )
    except native_projection_reconciliation.NativeProjectionReconciliationError as error:
        raise NativeStackBackendError(
            "native_projection_reconciliation_closure_unverified"
        ) from error
    if (stop.get("state") != "absent"
            or operations.SHA256.fullmatch(
                str(stop.get("evidence_sha256", ""))
            ) is None
            or stop["evidence_sha256"]
                != plan["guest_absence_evidence_sha256"]
            or egress_evidence != plan["egress_closed_evidence_sha256"]
            or observed["network"]["phase"] != "closed"
            or observed["live_run_count"] != 0
            or custody["state"] not in {"ambiguous", "session-projected"}):
        raise NativeStackBackendError(
            "native_projection_reconciliation_closure_unverified"
        )
    ticket = native_projection_reconciliation.make_ticket(
        plan, authorization, ticket_id=authorization["authorization_id"],
        now=now, expected_host_release_id=installed_release_id(),
    )
    _atomic_ticket(
        ticket_root / f"{ticket['ticket_id']}.json", ticket,
        now=now, trusted_uid=trusted_uid, trusted_gid=trusted_gid,
    )
    handoff = projection_reconciliation_handoff(ticket)
    return reconciliation_transport(handoff, plan=plan)


def recover_projection_identity(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    original_plan: Mapping[str, Any],
    original_authorization: Mapping[str, Any], stack: Mapping[str, Any], *,
    now: int,
    credential: Callable[..., dict[str, Any]] | None = None,
    status_credential: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
    ticket_root: Path = CREDENTIAL_TICKET_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    """Read one committed projection identity without clearing custody."""
    identity_transport = (
        signed_projection_identity_recovery_call
        if credential is None else credential
    )
    status_transport = (
        signed_credential_call
        if status_credential is None else status_credential
    )
    stop = session_stop_continuation(
        original_plan, original_authorization, stack, guest=guest
    )
    observed = _session_status(
        original_plan, stack, now=now,
        credential=status_transport, guest=guest,
    )
    custody = observed["credential_custody"]
    if (stop.get("state") != "absent"
            or operations.SHA256.fullmatch(
                str(stop.get("evidence_sha256", ""))
            ) is None
            or observed["network"]["phase"] != "closed"
            or observed["live_run_count"] != 0
            or custody["state"] not in {"ambiguous", "session-projected"}):
        raise NativeStackBackendError(
            "native_projection_identity_recovery_state_unverified"
        )
    ticket = native_projection_identity_recovery.make_ticket(
        plan, authorization, ticket_id=authorization["authorization_id"],
        now=now, expected_host_release_id=installed_release_id(),
    )
    _atomic_ticket(
        ticket_root / f"{ticket['ticket_id']}.json", ticket,
        now=now, trusted_uid=trusted_uid, trusted_gid=trusted_gid,
    )
    handoff = projection_identity_recovery_handoff(ticket)
    return identity_transport(handoff, plan=plan)


def _session_control_request(
    plan: Mapping[str, Any], authorization: Mapping[str, Any], *,
    vendor: str,
) -> dict[str, Any]:
    body = {
        "operation_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "session_id": plan["session_id"],
        "runtime_authority_sha256": plan["runtime_authority_sha256"],
    }
    return {
        "schema": f"secure-sandbox-native-{vendor}-session-stop-request-v1",
        **body, "request_sha256": digest(body),
    }


def session_prepare_grant(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *, now: int,
    resolver: Callable[[str], tuple[str, ...]] = resolve_once,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    """Prepare but never publish one runtime-authority inference grant."""
    if plan["action"] != "session-start":
        raise NativeStackBackendError(
            "native_stack_session_grant_action_invalid"
        )
    duration = native_stack_session.LEASE_DURATIONS.get(
        plan["lease_profile_id"]
    )
    if duration is None:
        raise NativeStackBackendError(
            "native_stack_session_lease_profile_invalid"
        )
    credential_transport = (
        signed_credential_call if credential is None else credential
    )
    status_value = _session_status(
        plan, stack, now=now, credential=credential_transport, guest=guest
    )
    if status_value["status_sha256"] != plan["status_sha256"]:
        raise NativeStackBackendError("native_stack_session_status_changed")
    native_stack_session.require_start_status(
        status_value, stack_sha256=plan["stack_sha256"]
    )
    authority = _session_authority_readback(plan, guest=guest)
    pins = resolve_policy(
        stack["network_policy_id"], native_egress.PHASE_INFERENCE,
        resolver=resolver,
    )
    maximum = native_egress.POLICIES[stack["network_policy_id"]]["phases"][
        native_egress.PHASE_INFERENCE
    ]["maximum_duration_seconds"]
    if duration > maximum:
        raise NativeStackBackendError(
            "native_stack_session_lease_policy_mismatch"
        )
    expires_at = now + duration
    return native_egress.make_grant(
        binding_kind="runtime-authority", binding_value=authority,
        phase=native_egress.PHASE_INFERENCE, resolved_ipv4=pins,
        issued_at=now, expires_at=expires_at,
    )


def _validate_session_stop_reply(
    value: object, plan: Mapping[str, Any], *, vendor: str,
) -> dict[str, Any]:
    expected = {
        "schema", "operation_id", "session_id", "state",
        "final_summary_sha256", "evidence_sha256",
    }
    if (not isinstance(value, dict) or set(value) != expected
            or value.get("schema")
                != f"secure-sandbox-native-{vendor}-session-stop-reply-v1"
            or value.get("operation_id") != plan["action_id"]
            or value.get("session_id") != plan["session_id"]
            or value.get("state") != "absent"
            or operations.SHA256.fullmatch(
                str(value.get("final_summary_sha256"))
            ) is None
            or operations.SHA256.fullmatch(
                str(value.get("evidence_sha256"))
            ) is None):
        raise NativeStackBackendError(
            "native_stack_session_stop_reply_invalid"
        )
    return dict(value)


def session_operation(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *, now: int,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
    terminal_root: Path = TERMINAL_HANDLE_ROOT,
    codex_ui_root: Path = CODEX_UI_HANDLE_ROOT,
    terminal_handle_id: str | None = None,
    trusted_uid: int = 0, trusted_gid: int = 0,
    session_lease: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Publish one vendor-specific stream authority or prove a run absent."""
    credential_transport = (
        signed_credential_call if credential is None else credential
    )
    status_value = _session_status(
        plan, stack, now=now, credential=credential_transport, guest=guest
    )
    if status_value["status_sha256"] != plan["status_sha256"]:
        raise NativeStackBackendError("native_stack_session_status_changed")
    vendor = "claude" if stack["vendor_id"] == "anthropic" else "codex"
    if plan["action"] == "session-stop":
        request = _session_control_request(
            plan, authorization, vendor=vendor
        )
        return _validate_session_stop_reply(
            guest(f"native-{vendor}-session-stop", request),
            plan, vendor=vendor,
        )
    if plan["action"] != "session-start":
        raise NativeStackBackendError("native_stack_session_action_invalid")
    if session_lease is None:
        raise NativeStackBackendError("native_stack_session_lease_missing")
    try:
        lease = native_stack_session.validate_session_lease(
            session_lease, now=now, require_fresh=True
        )
    except native_stack_session.NativeStackSessionError as error:
        raise NativeStackBackendError(
            "native_stack_session_lease_invalid"
        ) from error
    if (lease["lease_profile_id"] != plan["lease_profile_id"]
            or lease["session_id"] != plan["session_id"]
            or lease["runtime_authority_sha256"]
                != plan["runtime_authority_sha256"]):
        raise NativeStackBackendError(
            "native_stack_session_lease_mismatch"
        )
    native_stack_session.require_start_status(
        status_value, stack_sha256=plan["stack_sha256"]
    )
    _session_authority_readback(plan, guest=guest)
    if stack["vendor_id"] == "openai":
        _ensure_root_directory(
            codex_ui_root, 0o700, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        harness = plan["runtime_authority"]["harness_binding"]
        record = native_codex_ui_handle.make_record(
            handle_id=(str(uuid.uuid4()) if terminal_handle_id is None
                       else terminal_handle_id),
            operation_id=plan["action_id"],
            plan_sha256=plan["plan_sha256"],
            authorization_sha256=authorization["authorization_sha256"],
            stack_sha256=plan["stack_sha256"],
            catalog_sha256=plan["catalog_sha256"],
            session_id=plan["session_id"],
            runtime_authority_sha256=plan["runtime_authority_sha256"],
            harness_generation_id=harness["harness_generation_id"],
            harness_executable_sha256=harness["harness_executable_sha256"],
            session_lease=lease, issued_at=now,
            expires_at=min(
                authorization["expires_at"], lease["expires_at"],
                now + native_codex_ui_handle.MAXIMUM_LIFETIME_SECONDS,
            ),
        )
        return native_codex_ui_handle.publish(
            record, root=codex_ui_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
    if stack["vendor_id"] != "anthropic":
        raise NativeStackBackendError("native_stack_session_vendor_invalid")
    prepare_body = {
        "operation_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "session_id": plan["session_id"],
        "runtime_authority": plan["runtime_authority"],
        "resume_session_id": plan["resume_session_id"],
        "session_lease": lease,
    }
    reply = guest("native-claude-session-prepare", {
        "schema": "secure-sandbox-native-claude-session-prepare-request-v1",
        **prepare_body, "request_sha256": digest(prepare_body),
    })
    expected_reply = {
        "schema", "operation_id", "prepare_sha256",
        "session_lease_sha256", "session_expires_at", "evidence_sha256",
    }
    if (not isinstance(reply, dict) or set(reply) != expected_reply
            or reply.get("schema")
                != "secure-sandbox-native-claude-session-prepare-reply-v1"
            or reply.get("operation_id") != plan["action_id"]
            or operations.SHA256.fullmatch(
                str(reply.get("prepare_sha256"))
            ) is None
            or reply.get("session_lease_sha256") != lease["lease_sha256"]
            or reply.get("session_expires_at") != lease["expires_at"]
            or operations.SHA256.fullmatch(
                str(reply.get("evidence_sha256"))
            ) is None):
        raise NativeStackBackendError(
            "native_stack_session_prepare_reply_invalid"
        )
    _ensure_root_directory(
        terminal_root, 0o700, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    handle_id = str(uuid.uuid4()) if terminal_handle_id is None else terminal_handle_id
    record = native_terminal_handle.make_record(
        handle_id=handle_id, kind="claude-session",
        operation_id=plan["action_id"], plan_sha256=plan["plan_sha256"],
        authorization_sha256=authorization["authorization_sha256"],
        stack_sha256=plan["stack_sha256"],
        catalog_sha256=plan["catalog_sha256"], session_id=plan["session_id"],
        remote_arguments=[plan["action_id"], reply["prepare_sha256"]],
        issued_at=now, expires_at=min(
            authorization["expires_at"], lease["expires_at"],
            now + native_terminal_handle.MAXIMUM_LIFETIME_SECONDS,
        ),
    )
    return native_terminal_handle.publish(
        record, root=terminal_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )


def session_stop_continuation(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    if plan["action"] != "session-start":
        raise NativeStackBackendError(
            "native_stack_session_continuation_action_invalid"
        )
    vendor = "claude" if stack["vendor_id"] == "anthropic" else "codex"
    request = _session_control_request(plan, authorization, vendor=vendor)
    return _validate_session_stop_reply(
        guest(f"native-{vendor}-session-stop", request),
        plan, vendor=vendor,
    )


def projection_consumer_identity(
    *, path: Path = PROJECTION_CONSUMER, host_release_id: str | None = None,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> tuple[str, str, str]:
    """Hash the immutable consumer through one verified open description."""
    release = installed_release_id() if host_release_id is None else (
        host_release_id
    )
    expected = Path(
        "/usr/local/libexec/secure-sandbox-host/releases"
    ) / release / "native_projection_consumer"
    if (operations.SHA256.fullmatch(release) is None
            or path != expected):
        raise NativeStackBackendError(
            "native_codex_projection_consumer_release_mismatch"
        )
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as error:
        raise NativeStackBackendError(
            "native_codex_projection_consumer_unavailable"
        ) from error
    digest_value = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest_value.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = (
        before.st_dev, before.st_ino, before.st_size,
        before.st_mtime_ns, before.st_ctime_ns,
    )
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != trusted_uid or before.st_gid != trusted_gid
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o555
            or not 1 <= before.st_size <= 64 * 1024 * 1024
            or identity != (
                opened.st_dev, opened.st_ino, opened.st_size,
                opened.st_mtime_ns, opened.st_ctime_ns,
            )
            or identity != (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            )):
        raise NativeStackBackendError(
            "native_codex_projection_consumer_untrusted"
        )
    return str(path), digest_value.hexdigest(), release


def codex_projection_authority(
    plan: Mapping[str, Any], authorization: Mapping[str, Any], *, now: int,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
    consumer_identity: Callable[[], tuple[str, str, str]] | None = None,
    time_source: Callable[[], int] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any], int]:
    """Build the sole immutable projection policy from an exact PASS."""
    request = native_codex_projection.make_projection_status_request(
        operation_id=plan["action_id"], authority=plan["runtime_authority"]
    )
    started = monotonic()
    reply = guest("native-projection-isolation-status", request)
    elapsed = monotonic() - started
    if elapsed < 0 or elapsed > 150:
        raise NativeStackBackendError(
            "native_codex_projection_qualification_timeout"
        )
    observed_now = max(
        now, int(time.time()) if time_source is None else time_source()
    )
    try:
        observation = native_codex_projection.validate_projection_status_reply(
            reply, request_value=request, now=observed_now
        )
        path, executable_sha256, host_release_id = (
            projection_consumer_identity()
            if consumer_identity is None else consumer_identity()
        )
        authority = native_codex_projection.make_projection_authority(
            consumer_executable_path=path,
            consumer_executable_sha256=executable_sha256,
            host_release_id=host_release_id,
            operation_id=plan["action_id"],
            request_sha256=authorization["request_sha256"],
            stack_sha256=plan["stack_sha256"],
            authority=plan["runtime_authority"], observation=observation,
            now=observed_now,
        )
    except native_codex_projection.NativeCodexProjectionError as error:
        raise NativeStackBackendError(
            "native_codex_projection_qualification_invalid"
        ) from error
    if authority["qualification_expires_at"] <= observed_now:
        raise NativeStackBackendError(
            "native_codex_projection_qualification_expired"
        )
    return authority, observed_now


def codex_project_credential(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *, projection_fd: int, now: int,
    credential: Callable[..., dict[str, Any]] | None = None,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
    consumer_identity: Callable[[], tuple[str, str, str]] | None = None,
    time_source: Callable[[], int] | None = None,
    ticket_root: Path = CREDENTIAL_TICKET_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    """Start the signed consumer; credential bytes remain on the supplied fd."""
    if stack["vendor_id"] != "openai" or plan["action"] != "session-start":
        raise NativeStackBackendError("native_codex_projection_vendor_invalid")
    _session_authority_readback(plan, guest=guest)
    projection_authority, issued_at = codex_projection_authority(
        plan, authorization, now=now, guest=guest,
        consumer_identity=consumer_identity,
        time_source=time_source,
    )
    _atomic_ticket(
        ticket_root / f"{authorization['authorization_id']}.json",
        make_credential_ticket(
            operation="projectForSession", action="session-start",
            plan=plan, authorization=authorization,
            session_authority_sha256=plan["runtime_authority_sha256"],
            projection_authority=projection_authority,
            issued_at=issued_at,
            expires_at=min(
                authorization["expires_at"],
                projection_authority["qualification_expires_at"],
                issued_at + 180,
            ),
        ),
        now=issued_at, trusted_uid=trusted_uid, trusted_gid=trusted_gid,
    )
    credential_transport = (
        signed_credential_call if credential is None else credential
    )
    return credential_transport(
        credential_handoff(
            operation="projectForSession", operation_id=plan["action_id"],
            plan=plan, authorization=authorization,
            session_authority_sha256=plan["runtime_authority_sha256"],
            projection_authority=projection_authority,
        ), projection_fd=projection_fd,
    )


def codex_prepare_session(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], lease: Mapping[str, Any],
    claim: Mapping[str, Any], *, now: int,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
    consumer_identity: Callable[[], tuple[str, str, str]] | None = None,
    time_source: Callable[[], int] | None = None,
    ticket_root: Path = CREDENTIAL_TICKET_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    if stack["vendor_id"] != "openai" or plan["action"] != "session-start":
        raise NativeStackBackendError("native_codex_prepare_vendor_invalid")
    expires_at = min(
        now + 120, claim["access_expires_at_ms"] // 1000,
        lease["expires_at"],
    )
    if expires_at <= now:
        raise NativeStackBackendError("native_codex_prepare_expired")
    ticket = load_projection_credential_ticket(
        authorization["authorization_id"], plan=plan,
        authorization=authorization, now=now, ticket_root=ticket_root,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid,
    )
    expires_at = min(expires_at, ticket["expires_at"])
    if expires_at <= now:
        raise NativeStackBackendError("native_codex_prepare_expired")
    projection_authority = ticket_projection_authority(
        ticket, now=now
    )
    current_authority, refreshed_at = codex_projection_authority(
        plan, authorization, now=now, guest=guest,
        consumer_identity=consumer_identity,
        time_source=time_source,
    )
    if ticket["expires_at"] <= refreshed_at:
        raise NativeStackBackendError("native_codex_prepare_expired")
    ticket_projection_authority(ticket, now=refreshed_at)
    if current_authority != projection_authority:
        raise NativeStackBackendError(
            "native_codex_projection_qualification_changed"
        )
    expires_at = min(
        refreshed_at + 120, claim["access_expires_at_ms"] // 1000,
        lease["expires_at"], ticket["expires_at"],
    )
    if expires_at <= refreshed_at:
        raise NativeStackBackendError("native_codex_prepare_expired")
    body = {
        "operation_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "session_id": plan["session_id"],
        "runtime_authority": plan["runtime_authority"],
        "projection_id": plan["action_id"],
        "access_token_sha256": claim["access_token_sha256"],
        "expires_at": expires_at, "session_lease": dict(lease),
        "stack_sha256": ticket["stack_sha256"],
        "operator_request_sha256": ticket["request_sha256"],
        "projection_ticket_issued_at": ticket["issued_at"],
        "projection_ticket_expires_at": ticket["expires_at"],
        "projection_ticket_sha256": ticket["ticket_sha256"],
        "projection_authority": projection_authority,
    }
    reply = guest("native-codex-session-prepare", {
        "schema": "secure-sandbox-native-codex-session-prepare-request-v1",
        **body, "request_sha256": digest(body),
    })
    expected = {
        "schema", "operation_id", "prepare_sha256", "expires_at",
        "session_lease_sha256", "session_expires_at", "evidence_sha256",
    }
    if (not isinstance(reply, dict) or set(reply) != expected
            or reply.get("schema")
                != "secure-sandbox-native-codex-session-prepare-reply-v1"
            or reply.get("operation_id") != plan["action_id"]
            or reply.get("expires_at") != expires_at
            or reply.get("session_lease_sha256") != lease["lease_sha256"]
            or reply.get("session_expires_at") != lease["expires_at"]
            or any(operations.SHA256.fullmatch(str(reply.get(field, ""))) is None
                   for field in ("prepare_sha256", "evidence_sha256"))):
        raise NativeStackBackendError("native_codex_prepare_reply_invalid")
    return dict(reply)


def qualification_request(
    plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    body = {
        "action_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "session_id": plan["action_id"],
        "persona_sha256": QUALIFICATION_PERSONA_SHA256,
        "tool_catalog_sha256": QUALIFICATION_TOOL_CATALOG_SHA256,
        "extension_set_sha256": QUALIFICATION_EXTENSION_SET_SHA256,
    }
    return {"schema": "secure-sandbox-native-stack-qualification-request-v1",
            **body, "request_sha256": digest(body)}


def validate_qualification_authority(
    value: object, *, plan: Mapping[str, Any], stack: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        authority = runtime_authority.validate_binding(value)
        expected_model = model_stack_runtime_binding.make_binding(
            model_stack_runtime_binding.NATIVE_MODE,
            native_stack_runtime_binding.make_binding(stack),
        )
        expected_session = session_context_binding.make_binding(
            session_id=plan["action_id"], source_id=None,
            source_manifest_sha256=None,
            persona_sha256=QUALIFICATION_PERSONA_SHA256,
            tool_catalog_sha256=QUALIFICATION_TOOL_CATALOG_SHA256,
            extension_set_sha256=QUALIFICATION_EXTENSION_SET_SHA256,
        )
    except Exception as error:
        raise NativeStackBackendError(
            "native_stack_backend_qualification_invalid"
        ) from error
    harness = authority["harness_binding"]
    if (authority["model_stack_binding"] != expected_model
            or authority["session_context_binding"] != expected_session
            or harness["harness_id"] != plan["identity"]["harness_id"]
            or harness["harness_generation_id"]
                != plan["identity"]["harness_generation_id"]
            or harness["harness_adapter_id"]
                != plan["identity"]["harness_adapter_id"]):
        raise NativeStackBackendError("native_stack_backend_qualification_mismatch")
    return authority


def prepare_grant(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *, now: int,
    resolver: Callable[[str], tuple[str, ...]] = resolve_once,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    phase = plan["requested_network_phase"]
    if (phase == "closed" or (
        plan["identity"]["vendor_id"] == "openai"
        and plan["action"] in {"signin-begin", "status-verify", "logout"}
    )):
        return {"schema": MANAGER.CLOSED_POLICY_SCHEMA, "state": "closed"}
    if phase == native_egress.PHASE_LOGIN:
        kind, binding = "stack-intent", native_egress.make_stack_intent(stack)
    elif phase == native_egress.PHASE_STATUS_LOGOUT:
        kind, binding = "native-stack", native_stack_runtime_binding.make_binding(stack)
    elif phase == native_egress.PHASE_INFERENCE:
        reply = guest("native-qualification-authority",
                      qualification_request(plan, authorization))
        if (set(reply) != {"schema", "authority", "evidence_sha256"}
                or reply["schema"]
                    != "secure-sandbox-native-stack-qualification-reply-v1"
                or operations.SHA256.fullmatch(
                    str(reply["evidence_sha256"])
                ) is None):
            raise NativeStackBackendError(
                "native_stack_backend_qualification_reply_invalid"
            )
        kind = "runtime-authority"
        binding = validate_qualification_authority(
            reply["authority"], plan=plan, stack=stack
        )
    else:
        raise NativeStackBackendError("native_stack_backend_phase_invalid")
    pins = resolve_policy(
        plan["identity"]["network_policy_id"], phase, resolver=resolver
    )
    maximum = native_egress.POLICIES[
        plan["identity"]["network_policy_id"]
    ]["phases"][phase]["maximum_duration_seconds"]
    expires_at = min(plan["expires_at"], now + maximum)
    if expires_at <= now:
        raise NativeStackBackendError("native_stack_backend_grant_expired")
    return native_egress.make_grant(
        binding_kind=kind, binding_value=binding, phase=phase,
        resolved_ipv4=pins, issued_at=now, expires_at=expires_at,
    )


def _ensure_root_directory(
    path: Path, mode: int, *, trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
                or parent.st_uid != trusted_uid or parent.st_mode & 0o022):
            raise NativeStackBackendError("native_stack_backend_state_parent_untrusted")
        os.mkdir(path, mode)
        info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != trusted_uid or info.st_gid != trusted_gid
            or stat.S_IMODE(info.st_mode) != mode):
        raise NativeStackBackendError("native_stack_backend_state_root_untrusted")


def _validate_credential_ticket(value: object) -> dict[str, Any]:
    fields = {
        "schema", "ticket_id", "operation_id", "request_id", "operation",
        "action", "provider", "plan_sha256", "stack_sha256",
        "session_authority_sha256", "request_sha256",
        "authorization_receipt_sha256", "issued_at", "expires_at", "status",
        "ticket_sha256",
    } | set(native_codex_projection.PROJECTION_AUTHORITY_FIELDS)
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "ticket_sha256"}}
    pairing = {
        "login": ("signin-begin", False),
        "refresh": ("entitlement-verify", False),
        "projectForSession": ("session-start", True),
        "logout": ("logout", False),
        "destroyLocalCredential": ("credential-destroy", False),
        "recoverLocalState": ("recover", False),
    }.get(value.get("operation"))
    issued = value.get("issued_at")
    expires = value.get("expires_at")
    projection = {
        field: value.get(field)
        for field in native_codex_projection.PROJECTION_AUTHORITY_FIELDS
    }
    projection_valid = bool(pairing is not None and not pairing[1] and all(
        item is None for item in projection.values()
    ))
    if pairing is not None and pairing[1]:
        try:
            native_codex_projection.validate_projection_authority(
                projection,
                operation_id=str(value.get("operation_id")),
                request_sha256=str(value.get("request_sha256")),
                stack_sha256=str(value.get("stack_sha256")),
                session_authority_sha256=str(
                    value.get("session_authority_sha256")
                ),
                ticket_issued_at=issued if isinstance(issued, int) else 0,
                ticket_expires_at=expires if isinstance(expires, int) else 0,
            )
            projection_valid = True
        except native_codex_projection.NativeCodexProjectionError:
            projection_valid = False
    if (value.get("schema") != CREDENTIAL_TICKET_SCHEMA
            or pairing is None or value.get("action") != pairing[0]
            or value.get("provider") != "openAIChatGPT"
            or value.get("status") != "authorized"
            or any(operations.UUID4.fullmatch(str(value.get(field, ""))) is None
                   for field in ("ticket_id", "operation_id", "request_id"))
            or value.get("request_id") != value.get("ticket_id")
            or any(operations.SHA256.fullmatch(str(value.get(field, ""))) is None
                   for field in (
                       "plan_sha256", "stack_sha256", "request_sha256",
                       "authorization_receipt_sha256", "ticket_sha256",
                   ))
            or (value.get("session_authority_sha256") is not None)
                != pairing[1]
            or (pairing[1] and operations.SHA256.fullmatch(
                str(value.get("session_authority_sha256", ""))
            ) is None)
            or not projection_valid
            or not isinstance(issued, int) or isinstance(issued, bool)
            or not isinstance(expires, int) or isinstance(expires, bool)
            or issued < 1 or not issued < expires <= issued + 180
            or value.get("ticket_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_invalid"
        )
    return {"schema": CREDENTIAL_TICKET_SCHEMA, **body,
            "ticket_sha256": value["ticket_sha256"]}


def _validate_any_credential_ticket(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping) and value.get("schema") == (
        native_projection_identity_recovery.TICKET_SCHEMA
    ):
        try:
            return native_projection_identity_recovery.validate_ticket(value)
        except (
            native_projection_identity_recovery
            .NativeProjectionIdentityRecoveryError
        ) as error:
            raise NativeStackBackendError(
                "native_stack_backend_credential_ticket_invalid"
            ) from error
    if isinstance(value, Mapping) and value.get("schema") == (
        native_projection_reconciliation.TICKET_SCHEMA
    ):
        try:
            return native_projection_reconciliation.validate_ticket(value)
        except (
            native_projection_reconciliation.NativeProjectionReconciliationError
        ) as error:
            raise NativeStackBackendError(
                "native_stack_backend_credential_ticket_invalid"
            ) from error
    return _validate_credential_ticket(value)


def _read_ticket_at(
    directory: int, name: str, *, trusted_uid: int, trusted_gid: int,
) -> dict[str, Any]:
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
    except OSError as error:
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_inventory_untrusted"
        ) from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o644
                or not 2 <= info.st_size <= CREDENTIAL_TICKET_MAXIMUM_BYTES):
            raise NativeStackBackendError(
                "native_stack_backend_credential_ticket_inventory_untrusted"
            )
        raw = os.read(descriptor, info.st_size + 1)
        if len(raw) != info.st_size or os.read(descriptor, 1):
            raise NativeStackBackendError(
                "native_stack_backend_credential_ticket_changed"
            )
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_inventory_untrusted"
        ) from error
    if raw != canonical(value):
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_inventory_untrusted"
        )
    return _validate_any_credential_ticket(value)


def ticket_projection_authority(
    ticket: Mapping[str, Any], *, now: int,
) -> dict[str, Any]:
    try:
        return native_codex_projection.validate_projection_authority(
            {
                field: ticket[field]
                for field in native_codex_projection.PROJECTION_AUTHORITY_FIELDS
            },
            operation_id=ticket["operation_id"],
            request_sha256=ticket["request_sha256"],
            stack_sha256=ticket["stack_sha256"],
            session_authority_sha256=ticket["session_authority_sha256"],
            ticket_issued_at=ticket["issued_at"],
            ticket_expires_at=ticket["expires_at"], now=now,
        )
    except (KeyError,
            native_codex_projection.NativeCodexProjectionError) as error:
        raise NativeStackBackendError(
            "native_codex_projection_ticket_authority_invalid"
        ) from error


def load_projection_credential_ticket(
    ticket_id: str, *, plan: Mapping[str, Any],
    authorization: Mapping[str, Any], now: int,
    ticket_root: Path = CREDENTIAL_TICKET_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    if operations.UUID4.fullmatch(ticket_id) is None:
        raise NativeStackBackendError(
            "native_codex_projection_ticket_identity_invalid"
        )
    try:
        directory = os.open(
            ticket_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise NativeStackBackendError(
            "native_codex_projection_ticket_unavailable"
        ) from error
    try:
        root_info = os.fstat(directory)
        current = ticket_root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or (root_info.st_dev, root_info.st_ino)
                    != (current.st_dev, current.st_ino)
                or root_info.st_uid != trusted_uid
                or root_info.st_gid != trusted_gid
                or stat.S_IMODE(root_info.st_mode) != 0o755):
            raise NativeStackBackendError(
                "native_codex_projection_ticket_root_untrusted"
            )
        ticket = _read_ticket_at(
            directory, f"{ticket_id}.json", trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
    finally:
        os.close(directory)
    if (ticket.get("operation") != "projectForSession"
            or ticket.get("action") != "session-start"
            or ticket.get("ticket_id") != ticket_id
            or ticket.get("operation_id") != plan["action_id"]
            or ticket.get("plan_sha256") != plan["plan_sha256"]
            or ticket.get("stack_sha256") != plan["stack_sha256"]
            or ticket.get("session_authority_sha256")
                != plan["runtime_authority_sha256"]
            or ticket.get("request_sha256")
                != authorization["request_sha256"]
            or ticket.get("authorization_receipt_sha256")
                != authorization["pending_receipt_sha256"]
            or ticket.get("expires_at", 0) <= now):
        raise NativeStackBackendError(
            "native_codex_projection_ticket_mismatch"
        )
    ticket_projection_authority(ticket, now=now)
    return dict(ticket)


def _credential_ticket_inventory(
    directory: int, *, now: int, trusted_uid: int, trusted_gid: int,
) -> dict[str, dict[str, Any]]:
    uuid_fragment = operations.UUID4.pattern.removeprefix("^").removesuffix("$")
    final_name = re.compile(rf"({uuid_fragment})\.json")
    temporary_name = re.compile(rf"\.ticket-({uuid_fragment})")
    retained: dict[str, dict[str, Any]] = {}
    changed = False
    names = sorted(os.listdir(directory))
    if len(names) > CREDENTIAL_TICKET_MAXIMUM + 1:
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_capacity_exceeded"
        )
    for name in names:
        if name == CREDENTIAL_TICKET_LOCK:
            continue
        final = final_name.fullmatch(name)
        if final is not None:
            ticket = _read_ticket_at(
                directory, name, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid,
            )
            if ticket["ticket_id"] != final.group(1):
                raise NativeStackBackendError(
                    "native_stack_backend_credential_ticket_inventory_untrusted"
                )
            if ticket["expires_at"] <= now:
                os.unlink(name, dir_fd=directory)
                changed = True
            else:
                retained[name] = ticket
            continue
        if temporary_name.fullmatch(name) is not None:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                    or stat.S_IMODE(info.st_mode) not in {0o600, 0o644}):
                raise NativeStackBackendError(
                    "native_stack_backend_credential_ticket_inventory_untrusted"
                )
            if info.st_mtime > now - CREDENTIAL_TICKET_TEMP_MAXIMUM_AGE_SECONDS:
                raise NativeStackBackendError(
                    "native_stack_backend_credential_ticket_write_incomplete"
                )
            os.unlink(name, dir_fd=directory)
            changed = True
            continue
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_inventory_untrusted"
        )
    if changed:
        os.fsync(directory)
    if len(retained) >= CREDENTIAL_TICKET_MAXIMUM:
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_capacity_exceeded"
        )
    return retained


def _atomic_ticket(
    path: Path, value: object, *, now: int | None = None,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    ticket = _validate_any_credential_ticket(value)
    if path.name != f"{ticket['ticket_id']}.json":
        raise NativeStackBackendError(
            "native_stack_backend_credential_ticket_path_invalid"
        )
    _ensure_root_directory(
        path.parent, 0o755, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    directory = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    lock = -1
    temporary = f".ticket-{uuid.uuid4()}"
    temporary_created = False
    try:
        lock = os.open(
            CREDENTIAL_TICKET_LOCK,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=directory,
        )
        os.fchown(lock, trusted_uid, trusted_gid)
        os.fchmod(lock, 0o600)
        lock_info = os.fstat(lock)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1
                or lock_info.st_uid != trusted_uid
                or lock_info.st_gid != trusted_gid
                or stat.S_IMODE(lock_info.st_mode) != 0o600):
            raise NativeStackBackendError(
                "native_stack_backend_credential_ticket_lock_untrusted"
            )
        fcntl.flock(lock, fcntl.LOCK_EX)
        observed_at = int(time.time()) if now is None else now
        retained = _credential_ticket_inventory(
            directory, now=observed_at, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        existing = retained.get(path.name)
        if existing is not None:
            if existing != ticket:
                raise NativeStackBackendError(
                    "native_stack_backend_credential_ticket_replay_conflict"
                )
            return
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600, dir_fd=directory,
        )
        temporary_created = True
        try:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o600)
            raw = canonical(ticket)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise NativeStackBackendError(
                        "native_stack_backend_credential_ticket_write_failed"
                    )
                view = view[count:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary_created = False
        os.fsync(directory)
        if _read_ticket_at(
            directory, path.name, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ) != ticket:
            raise NativeStackBackendError(
                "native_stack_backend_credential_ticket_readback_failed"
            )
    finally:
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
            except FileNotFoundError:
                pass
        if lock >= 0:
            os.close(lock)
        os.close(directory)


def make_credential_ticket(
    *, operation: str, action: str, plan: Mapping[str, Any],
    authorization: Mapping[str, Any], session_authority_sha256: str | None = None,
    projection_authority: Mapping[str, Any] | None = None,
    issued_at: int | None = None, expires_at: int | None = None,
) -> dict[str, Any]:
    stack_sha256 = (
        plan["identity"]["stack_sha256"]
        if "identity" in plan else plan["stack_sha256"]
    )
    projection_fields = {
        field: None
        for field in native_codex_projection.PROJECTION_AUTHORITY_FIELDS
    }
    if projection_authority is not None:
        projection_fields.update(projection_authority)
    body = {
        "ticket_id": authorization["authorization_id"],
        "operation_id": plan["action_id"],
        "request_id": authorization["authorization_id"],
        "operation": operation, "action": action, "provider": "openAIChatGPT",
        "plan_sha256": plan["plan_sha256"],
        "stack_sha256": stack_sha256,
        "session_authority_sha256": session_authority_sha256,
        **projection_fields,
        "request_sha256": authorization["request_sha256"],
        "authorization_receipt_sha256": authorization["pending_receipt_sha256"],
        "issued_at": (
            authorization["authorized_at"] if issued_at is None else issued_at
        ),
        "expires_at": (
            authorization["expires_at"] if expires_at is None else expires_at
        ),
        "status": "authorized",
    }
    return {"schema": CREDENTIAL_TICKET_SCHEMA, **body,
            "ticket_sha256": digest(body)}


def credential_handoff(
    *, operation: str, operation_id: str, plan: Mapping[str, Any] | None,
    authorization: Mapping[str, Any] | None,
    session_authority_sha256: str | None = None,
    projection_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    stack_sha256 = None
    if plan is not None:
        stack_sha256 = (
            plan["identity"]["stack_sha256"]
            if "identity" in plan else plan["stack_sha256"]
        )
    projection_fields = {
        field: None
        for field in native_codex_projection.PROJECTION_AUTHORITY_FIELDS
    }
    if projection_authority is not None:
        projection_fields.update(projection_authority)
    body = {
        "operation_id": operation_id, "operation": operation,
        "authorization_ticket_id": None if authorization is None else authorization["authorization_id"],
        "plan_sha256": None if plan is None else plan["plan_sha256"],
        "operator_request_sha256": None if authorization is None else authorization["request_sha256"],
        "stack_sha256": stack_sha256,
        "session_authority_sha256": session_authority_sha256,
        **projection_fields,
        "authorization_receipt_sha256": None if authorization is None else authorization["pending_receipt_sha256"],
    }
    return {"schema": CREDENTIAL_HANDOFF_SCHEMA, **body,
            "handoff_sha256": digest(body)}


def projection_reconciliation_handoff(
    ticket: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = native_projection_reconciliation.validate_ticket(ticket)
    except native_projection_reconciliation.NativeProjectionReconciliationError as error:
        raise NativeStackBackendError(
            "native_projection_reconciliation_ticket_invalid"
        ) from error
    body = {
        key: validated[key] for key in (
            "ticket_id", "recovery_operation_id", "original_operation_id",
            "process_identifier", "process_start_time_us",
            "consumer_executable_sha256", "session_authority_sha256",
            "stack_sha256", "recovery_plan_sha256",
            "guest_absence_evidence_sha256",
            "egress_closed_evidence_sha256", "host_release_id",
            "recovery_request_sha256", "recovery_receipt_sha256",
        )
    }
    return {
        "schema": PROJECTION_RECONCILIATION_HANDOFF_SCHEMA,
        **body, "handoff_sha256": digest(body),
    }


def projection_identity_recovery_handoff(
    ticket: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = native_projection_identity_recovery.validate_ticket(ticket)
    except native_projection_identity_recovery.NativeProjectionIdentityRecoveryError as error:
        raise NativeStackBackendError(
            "native_projection_identity_recovery_ticket_invalid"
        ) from error
    body = {
        key: validated[key] for key in (
            "ticket_id", "recovery_operation_id", "original_operation_id",
            "session_authority_sha256", "stack_sha256",
            "recovery_plan_sha256", "host_release_id",
            "recovery_request_sha256", "recovery_receipt_sha256",
        )
    }
    return {
        "schema": PROJECTION_IDENTITY_RECOVERY_HANDOFF_SCHEMA,
        **body, "handoff_sha256": digest(body),
    }


def validate_credential_reply(value: object) -> dict[str, Any]:
    expected = {"schema", "operation_id", "verified", "status", "projection",
                "error_code", "response_sha256", "reply_sha256"}
    if not isinstance(value, dict) or set(value) != expected:
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid")
    body = {key: value[key] for key in expected - {"schema", "reply_sha256"}}
    if (value["schema"] != "secure-sandbox-native-credential-client-reply-v1"
            or operations.SHA256.fullmatch(str(value["response_sha256"])) is None
            or value["reply_sha256"] != digest(body)
            or not isinstance(value["verified"], bool)
            or (value["verified"] and value["error_code"] is not None)
            or (not value["verified"] and value["error_code"] is None)):
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid")
    if not value["verified"]:
        raise NativeStackBackendError("native_stack_backend_credential_rejected")
    return dict(value)


def validate_projection_reconciliation_reply(
    value: object, *, plan: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        return native_projection_reconciliation.validate_reply(
            value, plan_value=plan
        )
    except native_projection_reconciliation.NativeProjectionReconciliationError as error:
        raise NativeStackBackendError(
            "native_projection_reconciliation_reply_invalid"
        ) from error


def validate_projection_identity_recovery_reply(
    value: object, *, plan: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        return native_projection_identity_recovery.validate_reply(
            value, plan_value=plan
        )
    except native_projection_identity_recovery.NativeProjectionIdentityRecoveryError as error:
        raise NativeStackBackendError(
            "native_projection_identity_recovery_reply_invalid"
        ) from error


def console_uid(console: Path = Path("/dev/console")) -> int:
    try:
        uid = console.stat().st_uid
        account = pwd.getpwuid(uid)
    except (OSError, KeyError) as error:
        raise NativeStackBackendError("native_stack_backend_console_user_unavailable") from error
    if (uid <= 0 or account.pw_uid != uid
            or account.pw_dir in {"", "/var/empty", "/nonexistent"}
            or account.pw_shell.endswith("nologin")):
        raise NativeStackBackendError("native_stack_backend_console_user_invalid")
    return uid


def _trusted_executable(path: Path) -> None:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = os.fstat(descriptor); os.close(descriptor)
    except OSError as error:
        raise NativeStackBackendError("native_stack_backend_signed_client_unavailable") from error
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o555
            or not 1 <= before.st_size <= 64 * 1024 * 1024
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)):
        raise NativeStackBackendError("native_stack_backend_signed_client_untrusted")


def signed_credential_call(
    handoff: Mapping[str, Any], *, client: Path = SIGNED_CREDENTIAL_CLIENT,
    launchctl: Path = LAUNCHCTL, uid: int | None = None,
    state_root: Path = Path("/usr/local/var/run/secure-sandbox"),
    projection_fd: int | None = None,
    reply_validator: Callable[[object], dict[str, Any]] = validate_credential_reply,
) -> dict[str, Any]:
    _trusted_executable(client)
    _ensure_root_directory(state_root, 0o700)
    operator_uid = console_uid() if uid is None else uid
    requires_projection = handoff.get("operation") == "projectForSession"
    if requires_projection != (projection_fd is not None):
        raise NativeStackBackendError(
            "native_stack_backend_projection_channel_invalid"
        )
    if projection_fd is not None:
        try:
            projection_info = os.fstat(projection_fd)
            socket_type = socket.socket(fileno=os.dup(projection_fd))
            try:
                actual_family = socket_type.family
                actual_type = socket_type.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                socket_type.getpeername()
                local_address = socket_type.getsockname()
            finally:
                socket_type.close()
        except OSError as error:
            raise NativeStackBackendError(
                "native_stack_backend_projection_channel_invalid"
            ) from error
        if (projection_fd < 3 or not stat.S_ISSOCK(projection_info.st_mode)
                or os.isatty(projection_fd)
                or actual_family != socket.AF_UNIX
                or actual_type != socket.SOCK_STREAM
                or not isinstance(local_address, str)):
            raise NativeStackBackendError(
                "native_stack_backend_projection_channel_invalid"
            )
    descriptor, name = tempfile.mkstemp(prefix="native-credential-handoff.", dir=state_root)
    try:
        os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400)
        os.write(descriptor, canonical(handoff)); os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET); os.unlink(name)
        command = [str(launchctl), "asuser", str(operator_uid), str(client),
                   "--request-fd", str(descriptor)]
        descriptors = (descriptor,)
        if projection_fd is not None:
            command.extend(["--projection-fd", str(projection_fd)])
            descriptors = (descriptor, projection_fd)
        output = run_bounded(
            command,
            b"\n", timeout=180, maximum_output=32 * 1024,
            pass_fds=descriptors,
        )
    finally:
        os.close(descriptor)
        try: os.unlink(name)
        except FileNotFoundError: pass
    try:
        value = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid") from error
    if not isinstance(value, dict) or output != canonical(value):
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid")
    return reply_validator(value)


def signed_projection_reconciliation_call(
    handoff: Mapping[str, Any], *, plan: Mapping[str, Any],
    client: Path = SIGNED_CREDENTIAL_CLIENT, launchctl: Path = LAUNCHCTL,
    uid: int | None = None,
    state_root: Path = Path("/usr/local/var/run/secure-sandbox"),
) -> dict[str, Any]:
    return signed_credential_call(
        handoff, client=client, launchctl=launchctl, uid=uid,
        state_root=state_root,
        reply_validator=lambda value: validate_projection_reconciliation_reply(
            value, plan=plan
        ),
    )


def signed_projection_identity_recovery_call(
    handoff: Mapping[str, Any], *, plan: Mapping[str, Any],
    client: Path = SIGNED_CREDENTIAL_CLIENT, launchctl: Path = LAUNCHCTL,
    uid: int | None = None,
    state_root: Path = Path("/usr/local/var/run/secure-sandbox"),
) -> dict[str, Any]:
    return signed_credential_call(
        handoff, client=client, launchctl=launchctl, uid=uid,
        state_root=state_root,
        reply_validator=lambda value: (
            validate_projection_identity_recovery_reply(value, plan=plan)
        ),
    )


def credential_operation(
    operation: str, action: str, plan: Mapping[str, Any],
    authorization: Mapping[str, Any], *,
    call: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
) -> dict[str, Any]:
    _atomic_ticket(
        CREDENTIAL_TICKET_ROOT / f"{authorization['authorization_id']}.json",
        make_credential_ticket(operation=operation, action=action, plan=plan,
                               authorization=authorization),
    )
    return call(credential_handoff(
        operation=operation, operation_id=plan["action_id"], plan=plan,
        authorization=authorization,
    ))


def qualification_authority(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    reply = guest("native-qualification-authority",
                  qualification_request(plan, authorization))
    if (set(reply) != {"schema", "authority", "evidence_sha256"}
            or reply["schema"] != "secure-sandbox-native-stack-qualification-reply-v1"
            or operations.SHA256.fullmatch(str(reply["evidence_sha256"])) is None):
        raise NativeStackBackendError("native_stack_backend_qualification_reply_invalid")
    return validate_qualification_authority(reply["authority"], plan=plan, stack=stack)


def provider_action(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    evidence: list[str] = []
    if plan["identity"]["vendor_id"] == "openai":
        operation = {
            "signin-begin": "login", "status-verify": "status",
            "entitlement-verify": "refresh", "logout": "logout",
            "credential-destroy": "destroyLocalCredential",
            "recover": "recoverLocalState",
        }.get(plan["action"])
        if operation == "status":
            reply = credential(credential_handoff(
                operation="status", operation_id=str(uuid.uuid4()),
                plan=None, authorization=None,
            ))
            evidence.append(reply["reply_sha256"])
        elif operation is not None:
            reply = credential_operation(
                operation, plan["action"], plan, authorization, call=credential
            )
            evidence.append(reply["reply_sha256"])
        # Activation does not project a token or launch Codex. Projection is
        # reserved for the separate Touch-ID-bound session-start ceremony.
    authority = None
    if plan["action"] == "entitlement-verify":
        authority = qualification_authority(plan, authorization, stack, guest=guest)
    body = {
        "operation_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "action": plan["action"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "harness_generation_id": plan["identity"]["harness_generation_id"],
        "runtime_authority": authority,
    }
    request = {"schema": "secure-sandbox-native-provider-guest-request-v1",
               **body, "request_sha256": digest(body)}
    reply = guest("native-provider-action", request)
    expected = {"schema", "action_id", "action", "plan_sha256",
                "authorization_sha256", "status", "evidence_sha256"}
    if (set(reply) != expected or reply["schema"] != PROVIDER_RESULT_SCHEMA
            or reply["action_id"] != plan["action_id"]
            or reply["action"] != plan["action"]
            or reply["plan_sha256"] != plan["plan_sha256"]
            or reply["authorization_sha256"] != authorization["authorization_sha256"]
            or reply["status"] != "verified"
            or operations.SHA256.fullmatch(str(reply["evidence_sha256"])) is None):
        raise NativeStackBackendError("native_stack_backend_guest_provider_invalid")
    evidence.append(reply["evidence_sha256"])
    return {**reply, "evidence_sha256": digest(evidence)}


def protected_status_request(
    plan: Mapping[str, Any], authorization: Mapping[str, Any], catalog_sha256: str
) -> dict[str, Any]:
    body = {
        "operation_id": plan["action_id"], "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "stack_id": plan["identity"]["stack_id"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "catalog_sha256": catalog_sha256,
    }
    return {"schema": "secure-sandbox-native-stack-guest-status-request-v1",
            **body, "request_sha256": digest(body)}


def merge_openai_status(
    guest_status: Mapping[str, Any], credential_reply: Mapping[str, Any],
    stack: Mapping[str, Any], *, now: int,
) -> dict[str, Any]:
    status = credential_reply.get("status")
    if not isinstance(status, dict) or credential_reply.get("projection") is not None:
        raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
    fields = {"provider", "state", "client_id_sha256", "account_subject_sha256",
              "workspace_sha256", "scope_sha256", "access_expires_at_ms",
              "earliest_refresh_at_ms", "refresh_expires_at_ms",
              "custody_state", "custody_tombstone_sha256",
              "custody_projection_count"}
    if set(status) != fields or status["provider"] != "openAIChatGPT":
        raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
    if (status["custody_state"] == "ambiguous"
            and status["custody_projection_count"] != 0):
        raise NativeStackBackendError(
            "native_stack_backend_credential_status_invalid"
        )
    state = status["state"]
    evidence = credential_reply["reply_sha256"]
    if state == "loggedOut":
        auth_state, binding_state, account, workspace = "signed-out", "unbound", None, None
    elif state in {"ready", "refreshRequired"}:
        auth_state = "signed-in" if state == "ready" else "expired"
        account, workspace = status["account_subject_sha256"], status["workspace_sha256"]
        if (operations.SHA256.fullmatch(str(account)) is None
                or operations.SHA256.fullmatch(str(workspace)) is None):
            raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
        configured = stack["account_binding"]
        if configured["account_subject_sha256"] is None:
            binding_state = "observed"
        elif (account, workspace) == (configured["account_subject_sha256"],
                                      configured["workspace_sha256"]):
            binding_state = "bound"
        else:
            binding_state = "mismatch"
    elif state == "blocked":
        auth_state, binding_state, account, workspace = "ambiguous", "ambiguous", None, None
    else:
        raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
    authentication = {"state": auth_state, "observed_at": now,
                      "evidence_sha256": evidence}
    account_binding = {
        "state": binding_state, "observed_at": now, "evidence_sha256": evidence,
        "account_subject_sha256": account, "workspace_sha256": workspace,
    }
    credential_custody = {
        "state": status["custody_state"],
        "observed_at": now,
        "evidence_sha256": evidence,
        "tombstone_sha256": status["custody_tombstone_sha256"],
        "projection_count": status["custody_projection_count"],
    }
    return operations.make_status(
        stack=stack, harness=guest_status["harness"],
        authentication=authentication, account_binding=account_binding,
        credential_custody=credential_custody,
        program_entitlement=guest_status["program_entitlement"],
        model_entitlement=guest_status["model_entitlement"],
        network=guest_status["network"], activation=guest_status["activation"],
        live_run_count=guest_status["live_run_count"],
        fence_reason=guest_status["fence_reason"],
    )


def enforce_program_attestation_commit(
    status_value: Mapping[str, Any], stack: Mapping[str, Any],
    catalog_sha256: str, *,
    commit_root: Path = PROGRAM_ATTESTATION_ROOT,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    trusted_uid: int = 0,
) -> dict[str, Any]:
    status = operations.validate_status(status_value)
    program = status["program_entitlement"]
    if (program["state"] != "verified"
            or program["assurance"] != "operator-external"):
        return status
    try:
        commit = native_program_attestation.validate_commit(
            MANAGER.trusted_canonical_document(
                commit_root / f"{status['stack_sha256']}.json", trusted_uid
            )
        )
        receipt = MANAGER.trusted_canonical_document(
            receipt_root / f"{commit['authorization_id']}.json", trusted_uid
        )
        expected_receipt_fields = {
            "schema", "request_id", "request_sha256", "status", "started_at",
            "completed_at", "operation", "declared_agent", "declared_session",
            "identity_evidence", "authorization_method", "ceremony", "purpose",
            "resource", "exit_status", "stdout_sha256", "stderr_sha256",
            "native_program_attestation_id", "native_program_plan_sha256",
            "native_program_provider_evidence_sha256", "host_release_id",
        }
        binding = stack["account_binding"]
        if (set(receipt) != expected_receipt_fields
                or hashlib.sha256(canonical(receipt)).hexdigest()
                    != commit["operator_receipt_sha256"]
                or receipt["schema"]
                    != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt["request_id"] != commit["authorization_id"]
                or receipt["status"] != "succeeded"
                or receipt["operation"] != native_program_attestation.OPERATION
                or receipt["authorization_method"] != "touch-id"
                or receipt["ceremony"] != "approve"
                or receipt["exit_status"] != 0
                or receipt["native_program_attestation_id"]
                    != commit["attestation_id"]
                or receipt["native_program_plan_sha256"]
                    != commit["plan_sha256"]
                or receipt["native_program_provider_evidence_sha256"]
                    != commit["provider_evidence_sha256"]
                or commit["stack_id"] != stack["stack_id"]
                or commit["stack_sha256"]
                    != native_vendor_stack.stack_revision(stack)
                or commit["catalog_sha256"] != catalog_sha256
                or commit["harness_generation_id"]
                    != stack["harness"]["generation_id"]
                or commit["account_subject_sha256"]
                    != binding["account_subject_sha256"]
                or commit["workspace_sha256"] != binding["workspace_sha256"]
                or commit["program_id"] != binding["program_id"]
                or commit["program_tier"] != binding["program_tier"]
                or commit["program_requirements_version"]
                    != binding["program_requirements_version"]
                or commit["provider_evidence_sha256"]
                    != program["evidence_sha256"]):
            raise NativeStackBackendError(
                "native_program_attestation_commit_mismatch"
            )
        return status
    except (
        OSError,
        MANAGER.NativeStackManagerError,
        NativeStackBackendError,
        native_program_attestation.NativeProgramAttestationError,
    ):
        unknown = {
            "state": "unknown", "assurance": "unknown",
            "observed_at": program["observed_at"],
            "evidence_sha256": digest({
                "reason": "host-program-commit-unavailable",
                "guest_evidence_sha256": program["evidence_sha256"],
                "stack_sha256": status["stack_sha256"],
            }),
        }
        return operations.make_status(
            stack=stack, harness=status["harness"],
            authentication=status["authentication"],
            account_binding=status["account_binding"],
            credential_custody=status["credential_custody"],
            program_entitlement=unknown,
            model_entitlement=status["model_entitlement"],
            network=status["network"], activation=status["activation"],
            live_run_count=status["live_run_count"],
            fence_reason=status["fence_reason"],
        )


def status(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], catalog_sha256: str, *, now: int,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    observed = operations.validate_status(guest(
        "native-stack-status",
        protected_status_request(plan, authorization, catalog_sha256),
    ))
    if plan["identity"]["vendor_id"] == "openai":
        reply = credential(credential_handoff(
            operation="status", operation_id=str(uuid.uuid4()),
            plan=None, authorization=None,
        ))
        observed = merge_openai_status(observed, reply, stack, now=now)
    return enforce_program_attestation_commit(
        observed, stack, catalog_sha256
    )


def validate_inspect_request(
    value: object, *, catalog_path: Path = CATALOG_PATH
) -> tuple[dict[str, Any], dict[str, Any], str]:
    fields = {"schema", "operation_id", "stack_id", "stack_sha256",
              "catalog_sha256", "request_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackBackendError("native_stack_backend_inspect_fields_invalid")
    body = {key: value[key] for key in fields - {"schema", "request_sha256"}}
    if (value["schema"] != "secure-sandbox-native-stack-inspect-request-v1"
            or operations.UUID4.fullmatch(str(value["operation_id"])) is None
            or operations.SHA256.fullmatch(str(value["stack_sha256"])) is None
            or operations.SHA256.fullmatch(str(value["catalog_sha256"])) is None
            or value["request_sha256"] != digest(body)):
        raise NativeStackBackendError("native_stack_backend_inspect_invalid")
    try:
        MANAGER._trusted_directory(catalog_path.parent, os.geteuid())
        catalog = native_vendor_stack.load_catalog(catalog_path, private=True)
        catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(catalog)
        ).hexdigest()
        stack = native_vendor_stack.stack_by_id(catalog, value["stack_id"])
    except (
        OSError,
        MANAGER.NativeStackManagerError,
        native_vendor_stack.NativeVendorStackError,
    ) as error:
        raise NativeStackBackendError("native_stack_backend_catalog_untrusted") from error
    if (catalog_sha256 != value["catalog_sha256"]
            or native_vendor_stack.stack_revision(stack) != value["stack_sha256"]):
        raise NativeStackBackendError("native_stack_backend_inspect_catalog_changed")
    return dict(value), stack, catalog_sha256


def validate_session_plan_request(
    value: object, *, catalog_path: Path = CATALOG_PATH,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    fields = {
        "schema", "action", "action_id", "session_id", "stack_id",
        "stack_sha256", "catalog_sha256", "source_id",
        "resume_session_id", "lease_profile_id", "request_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackBackendError(
            "native_stack_session_plan_request_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "request_sha256"}}
    action = value.get("action")
    source_id = value.get("source_id")
    resume = value.get("resume_session_id")
    lease = value.get("lease_profile_id")
    if (value.get("schema")
            != "secure-sandbox-native-stack-session-plan-request-v1"
            or action not in native_stack_session.ACTIONS
            or operations.UUID4.fullmatch(str(value.get("action_id"))) is None
            or operations.UUID4.fullmatch(str(value.get("session_id"))) is None
            or not isinstance(value.get("stack_id"), str)
            or native_vendor_stack.IDENTIFIER.fullmatch(
                value["stack_id"]
            ) is None
            or operations.SHA256.fullmatch(
                str(value.get("stack_sha256"))
            ) is None
            or operations.SHA256.fullmatch(
                str(value.get("catalog_sha256"))
            ) is None
            or (source_id is not None and operations.UUID4.fullmatch(
                str(source_id)
            ) is None)
            or (resume is not None and operations.UUID4.fullmatch(
                str(resume)
            ) is None)
            or resume == value.get("session_id")
            or (action == "session-start" and (
                lease not in native_stack_session.LEASE_DURATIONS
            ))
            or (action == "session-stop" and (
                lease is not None or resume is not None
            ))
            or value.get("request_sha256") != digest(body)):
        raise NativeStackBackendError(
            "native_stack_session_plan_request_invalid"
        )
    try:
        MANAGER._trusted_directory(catalog_path.parent, os.geteuid())
        catalog = native_vendor_stack.load_catalog(catalog_path, private=True)
        catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(catalog)
        ).hexdigest()
        stack = native_vendor_stack.stack_by_id(catalog, value["stack_id"])
    except (
        OSError,
        MANAGER.NativeStackManagerError,
        native_vendor_stack.NativeVendorStackError,
    ) as error:
        raise NativeStackBackendError(
            "native_stack_session_plan_catalog_untrusted"
        ) from error
    if (catalog_sha256 != value["catalog_sha256"]
            or native_vendor_stack.stack_revision(stack)
                != value["stack_sha256"]):
        raise NativeStackBackendError(
            "native_stack_session_plan_catalog_changed"
        )
    return dict(value), stack, catalog_sha256


def session_plan(
    request: Mapping[str, Any], stack: Mapping[str, Any], *, now: int,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    """Build a session plan from independently measured guest policy state."""
    authority_body = {
        "operation_id": request["action_id"],
        "stack_id": request["stack_id"],
        "stack_sha256": request["stack_sha256"],
        "catalog_sha256": request["catalog_sha256"],
        "session_id": request["session_id"],
        "source_id": request["source_id"],
    }
    authority_reply = guest("native-session-plan-authority", {
        "schema": (
            "secure-sandbox-native-session-plan-authority-request-v1"
        ),
        **authority_body, "request_sha256": digest(authority_body),
    })
    if (not isinstance(authority_reply, dict) or set(authority_reply) != {
            "schema", "authority", "evidence_sha256"
        } or authority_reply.get("schema")
            != "secure-sandbox-native-session-plan-authority-reply-v1"
            or operations.SHA256.fullmatch(
                str(authority_reply.get("evidence_sha256"))
            ) is None):
        raise NativeStackBackendError(
            "native_stack_session_plan_authority_reply_invalid"
        )
    try:
        authority = runtime_authority.validate_binding(
            authority_reply["authority"]
        )
        expected_native = native_stack_runtime_binding.make_binding(dict(stack))
    except (
        runtime_authority.RuntimeAuthorityError,
        native_stack_runtime_binding.NativeStackBindingError,
    ) as error:
        raise NativeStackBackendError(
            "native_stack_session_plan_authority_invalid"
        ) from error
    expected_evidence = digest({
        "operation_id": request["action_id"],
        "request_sha256": digest(authority_body),
        "authority_sha256": authority["binding_sha256"],
    })
    context = authority["session_context_binding"]
    harness = authority["harness_binding"]
    if (authority["model_stack_binding"]["authority"] != expected_native
            or context["session_id"] != request["session_id"]
            or context["source_id"] != request["source_id"]
            or (context["source_id"] is None)
                != (context["source_manifest_sha256"] is None)
            or harness["harness_generation_id"]
                != stack["harness"]["generation_id"]
            or authority_reply["evidence_sha256"] != expected_evidence):
        raise NativeStackBackendError(
            "native_stack_session_plan_authority_mismatch"
        )
    inspect_request = {
        "operation_id": request["action_id"],
        "stack_id": request["stack_id"],
        "stack_sha256": request["stack_sha256"],
        "catalog_sha256": request["catalog_sha256"],
    }
    status_value = inspect_status(
        inspect_request, stack, now=now, credential=credential, guest=guest
    )
    if (status_value["harness"]["generation_id"]
            != harness["harness_generation_id"]
            or status_value["harness"]["binding_sha256"]
                != harness["binding_sha256"]):
        raise NativeStackBackendError(
            "native_stack_session_plan_harness_readback_mismatch"
        )
    if request["action"] == "session-start":
        try:
            native_stack_session.require_start_status(
                status_value, stack_sha256=request["stack_sha256"]
            )
        except native_stack_session.NativeStackSessionError as error:
            raise NativeStackBackendError(
                "native_stack_session_plan_status_not_startable"
            ) from error
    try:
        return native_stack_session.make_plan(
            action=request["action"], action_id=request["action_id"],
            session_id=request["session_id"], stack_id=request["stack_id"],
            stack_sha256=request["stack_sha256"],
            catalog_sha256=request["catalog_sha256"],
            status_sha256=status_value["status_sha256"],
            runtime_authority_value=authority,
            source_id=context["source_id"],
            source_manifest_sha256=context["source_manifest_sha256"],
            resume_session_id=request["resume_session_id"],
            lease_profile_id=request["lease_profile_id"], created_at=now,
        )
    except native_stack_session.NativeStackSessionError as error:
        raise NativeStackBackendError(
            "native_stack_session_plan_rejected"
        ) from error


def inspect_status(
    request: Mapping[str, Any], stack: Mapping[str, Any], *, now: int,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    guest_body = {key: request[key] for key in (
        "operation_id", "stack_id", "stack_sha256", "catalog_sha256"
    )}
    guest_request = {
        "schema": "secure-sandbox-native-stack-inspect-status-request-v1",
        **guest_body, "request_sha256": digest(guest_body),
    }
    observed = operations.validate_status(
        guest("native-stack-inspect-status", guest_request)
    )
    if stack["vendor_id"] == "openai":
        reply = credential(credential_handoff(
            operation="status", operation_id=request["operation_id"],
            plan=None, authorization=None,
        ))
        observed = merge_openai_status(observed, reply, stack, now=now)
    return enforce_program_attestation_commit(
        observed, stack, request["catalog_sha256"]
    )


def installed_release_id() -> str:
    release = Path(__file__).resolve().parent.name
    if operations.SHA256.fullmatch(release) is None:
        raise NativeStackBackendError("native_stack_backend_release_invalid")
    return release


def dispatch(
    operation: str, value: Mapping[str, Any], *, now: int,
    projection_fd: int | None = None,
) -> dict[str, Any]:
    if operation == "projection-reconcile":
        (reconciliation_plan, reconciliation_authorization,
         original_plan, original_authorization, reconciliation_stack,
         _catalog) = validate_projection_reconciliation_host_ticket(
            value, now=now,
            expected_host_release_id=installed_release_id(),
        )
        return reconcile_projection(
            reconciliation_plan, reconciliation_authorization,
            original_plan, original_authorization, reconciliation_stack,
            now=now,
        )
    if operation == "projection-identity-recover":
        (identity_plan, identity_authorization,
         original_plan, original_authorization, identity_stack,
         _catalog) = validate_projection_identity_recovery_host_ticket(
            value, now=now,
            expected_host_release_id=installed_release_id(),
        )
        return recover_projection_identity(
            identity_plan, identity_authorization,
            original_plan, original_authorization, identity_stack,
            now=now,
        )
    if operation == "inspect-status":
        request, stack, _catalog_sha256 = validate_inspect_request(value)
        return inspect_status(request, stack, now=now)
    if operation == "session-plan":
        request, stack, _catalog_sha256 = validate_session_plan_request(value)
        return session_plan(request, stack, now=now)
    if operation == "program-attest":
        plan, authorization, stack, _catalog_sha256 = (
            validate_program_attestation_ticket(
                value, now=now,
                expected_host_release_id=installed_release_id(),
            )
        )
        return program_attest(plan, authorization, stack)
    if operation == "session-codex-project":
        if projection_fd is None:
            raise NativeStackBackendError(
                "native_codex_projection_channel_missing"
            )
        codex_plan, codex_authorization, codex_stack, _catalog = (
            validate_session_continuation_ticket(
                value, now=now,
                expected_host_release_id=installed_release_id(),
            )
        )
        return codex_project_credential(
            codex_plan, codex_authorization, codex_stack,
            projection_fd=projection_fd, now=now,
        )
    if operation == "session-codex-prepare":
        if projection_fd is not None:
            raise NativeStackBackendError(
                "native_codex_projection_channel_unexpected"
            )
        (codex_plan, codex_authorization, codex_stack,
         codex_lease, codex_claim) = validate_codex_prepare_ticket(
            value, now=now,
            expected_host_release_id=installed_release_id(),
        )
        return codex_prepare_session(
            codex_plan, codex_authorization, codex_stack,
            codex_lease, codex_claim, now=now,
        )
    if operation == "provider-action-resume":
        resume_plan, resume_authorization, resume_stack, _catalog = (
            validate_interactive_resume_ticket(
                value, now=now,
                expected_host_release_id=installed_release_id(),
            )
        )
        return provider_action(
            resume_plan, resume_authorization, resume_stack
        )
    if operation == "session-operation":
        session_plan, session_authorization, session_stack, _catalog = (
            validate_session_host_ticket(
                value, now=now,
                expected_host_release_id=installed_release_id(),
            )
        )
        return session_operation(
            session_plan, session_authorization, session_stack, now=now
        )
    if operation == "session-prepare":
        (prepared_plan, prepared_authorization, prepared_stack,
         _prepared_catalog, prepared_lease) = validate_session_prepare_ticket(
            value, now=now,
            expected_host_release_id=installed_release_id(),
        )
        return session_operation(
            prepared_plan, prepared_authorization, prepared_stack, now=now,
            session_lease=prepared_lease,
        )
    if operation in {"session-status", "session-prepare-grant"}:
        session_plan, session_authorization, session_stack, _catalog = (
            validate_session_host_ticket(
                value, now=now,
                expected_host_release_id=installed_release_id(),
            )
        )
        if operation == "session-status":
            return _session_status(
                session_plan, session_stack, now=now,
                credential=signed_credential_call, guest=guest_call,
            )
        return session_prepare_grant(
            session_plan, session_authorization, session_stack, now=now
        )
    if operation in {
        "session-stop-continuation", "session-status-continuation"
    }:
        continued_plan, continued_authorization, continued_stack, _catalog = (
            validate_session_continuation_ticket(
                value, now=now,
                expected_host_release_id=installed_release_id(),
            )
        )
        if operation == "session-stop-continuation":
            return session_stop_continuation(
                continued_plan, continued_authorization, continued_stack
            )
        return _session_status(
            continued_plan, continued_stack, now=now,
            credential=signed_credential_call, guest=guest_call,
        )
    if operation in {"session-recover-stop", "session-recover-status"}:
        recovered_plan, recovered_authorization, recovered_stack, _catalog = (
            validate_session_recovery_ticket(
                value, now=now,
                expected_host_release_id=installed_release_id(),
            )
        )
        if operation == "session-recover-stop":
            return session_stop_continuation(
                recovered_plan, recovered_authorization, recovered_stack
            )
        return _session_status(
            recovered_plan, recovered_stack, now=now,
            credential=signed_credential_call, guest=guest_call,
        )
    plan, authorization, stack, catalog_sha256 = validate_host_ticket(
        value, now=now, expected_host_release_id=installed_release_id()
    )
    if operation == "status":
        return status(
            plan, authorization, stack, catalog_sha256, now=now
        )
    if operation == "prepare-grant":
        return prepare_grant(plan, authorization, stack, now=now)
    if operation == "provider-action":
        return provider_action(plan, authorization, stack)
    if operation == "prepare-interactive":
        return prepare_login_handle(
            plan, authorization, stack, catalog_sha256, now=now
        )
    raise NativeStackBackendError("native_stack_backend_operation_invalid")


def main() -> int:
    parser = __import__("argparse").ArgumentParser()
    parser.add_argument(
        "operation",
        choices=(
            "status", "prepare-grant", "provider-action", "inspect-status",
            "session-plan",
            "program-attest", "projection-reconcile",
            "projection-identity-recover",
            "session-operation",
            "prepare-interactive", "provider-action-resume",
            "session-status", "session-prepare-grant",
            "session-stop-continuation", "session-status-continuation",
            "session-prepare",
            "session-recover-stop", "session-recover-status",
            "session-codex-project", "session-codex-prepare",
        ),
    )
    parser.add_argument("--projection-fd", type=int)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise NativeStackBackendError("native_stack_backend_root_required")
        if ((args.operation == "session-codex-project")
                != (args.projection_fd is not None)):
            raise NativeStackBackendError(
                "native_codex_projection_channel_argument_invalid"
            )
        result = dispatch(
            args.operation, read_canonical(), now=int(time.time()),
            projection_fd=args.projection_fd,
        )
    except (
        NativeStackBackendError,
        native_projection_identity_recovery.NativeProjectionIdentityRecoveryError,
        native_projection_reconciliation.NativeProjectionReconciliationError,
        native_codex_projection.NativeCodexProjectionError,
        native_codex_ui_handle.NativeCodexUIHandleError,
        OSError, KeyError, ValueError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
