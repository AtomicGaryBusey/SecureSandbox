#!/usr/bin/env python3
"""Exact, content-free Touch ID plans for native vendor session lifetime.

Session authority is deliberately separate from stack activation.  Activating a
stack never projects a credential or starts a harness; a fresh session-start
plan binds one immutable runtime authority.  Session-stop binds that same
authority and cannot authorize another session.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from shared import model_stack_runtime_binding
from shared import native_stack_operations
from shared import runtime_authority


PLAN_SCHEMA = "secure-sandbox-native-stack-session-plan-v1"
AUTHORIZATION_SCHEMA = "secure-sandbox-native-stack-session-touchid-authorization-v1"
ACTIONS = {"session-start", "session-stop"}
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,62}")
MAXIMUM_LIFETIME_SECONDS = 180


class NativeStackSessionError(ValueError):
    """Stable fail-closed session authority validation error."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeStackSessionError("native_stack_session_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _uuid4(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeStackSessionError(f"native_stack_session_{label}_invalid")
    return value


def _digest(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeStackSessionError(f"native_stack_session_{label}_invalid")
    return value


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise NativeStackSessionError(f"native_stack_session_{label}_invalid")
    return value


def validate_plan(
    value: object, *, now: int | None = None, require_fresh: bool = False,
) -> dict[str, Any]:
    fields = {
        "schema", "action", "action_id", "session_id", "stack_id",
        "stack_sha256", "catalog_sha256", "status_sha256",
        "runtime_authority", "runtime_authority_sha256", "source_id",
        "source_manifest_sha256", "resume_session_id", "lease_profile_id",
        "created_at", "expires_at", "plan_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeStackSessionError("native_stack_session_plan_fields_invalid")
    if value.get("schema") != PLAN_SCHEMA or value.get("action") not in ACTIONS:
        raise NativeStackSessionError("native_stack_session_plan_identity_invalid")
    action_id = _uuid4(value.get("action_id"), "action_id")
    session_id = _uuid4(value.get("session_id"), "session_id")
    if (not isinstance(value.get("stack_id"), str)
            or IDENTIFIER.fullmatch(value["stack_id"]) is None):
        raise NativeStackSessionError("native_stack_session_stack_id_invalid")
    for field in (
        "stack_sha256", "catalog_sha256", "status_sha256",
        "runtime_authority_sha256",
    ):
        _digest(value.get(field), field)
    try:
        authority = runtime_authority.validate_binding(value.get("runtime_authority"))
    except runtime_authority.RuntimeAuthorityError as error:
        raise NativeStackSessionError("native_stack_session_runtime_authority_invalid") from error
    if (authority["binding_sha256"] != value["runtime_authority_sha256"]
            or authority["session_context_binding"]["session_id"] != session_id):
        raise NativeStackSessionError("native_stack_session_runtime_authority_mismatch")
    native = authority["model_stack_binding"]["authority"]
    if (authority["model_stack_binding"]["mode"]
            != model_stack_runtime_binding.NATIVE_MODE
            or native["stack_id"] != value["stack_id"]
            or native["stack_sha256"] != value["stack_sha256"]):
        raise NativeStackSessionError("native_stack_session_stack_authority_mismatch")
    source_id = _uuid4(value.get("source_id"), "source_id", optional=True)
    source_digest = _digest(
        value.get("source_manifest_sha256"), "source_manifest_sha256", optional=True
    )
    context = authority["session_context_binding"]
    if ((source_id is None) != (source_digest is None)
            or context["source_id"] != source_id
            or context["source_manifest_sha256"] != source_digest):
        raise NativeStackSessionError("native_stack_session_source_authority_mismatch")
    resume = _uuid4(
        value.get("resume_session_id"), "resume_session_id", optional=True
    )
    if resume == session_id:
        raise NativeStackSessionError("native_stack_session_resume_identity_invalid")
    lease = value.get("lease_profile_id")
    if lease is not None and (
        not isinstance(lease, str) or IDENTIFIER.fullmatch(lease) is None
    ):
        raise NativeStackSessionError("native_stack_session_lease_profile_invalid")
    created = _integer(value.get("created_at"), "created_at", 1)
    expires = _integer(value.get("expires_at"), "expires_at", 1)
    if expires <= created or expires > created + MAXIMUM_LIFETIME_SECONDS:
        raise NativeStackSessionError("native_stack_session_plan_lifetime_invalid")
    if require_fresh:
        if now is None or now < created or now >= expires:
            raise NativeStackSessionError("native_stack_session_plan_expired")
    body = {key: value[key] for key in fields - {"schema", "plan_sha256"}}
    supplied = _digest(value.get("plan_sha256"), "plan_sha256")
    if not hmac.compare_digest(str(supplied), sha256(body)):
        raise NativeStackSessionError("native_stack_session_plan_digest_mismatch")
    return {"schema": PLAN_SCHEMA, **body, "plan_sha256": supplied}


def make_plan(
    *, action: str, action_id: str, session_id: str, stack_id: str,
    stack_sha256: str, catalog_sha256: str, status_sha256: str,
    runtime_authority_value: object, source_id: str | None,
    source_manifest_sha256: str | None, resume_session_id: str | None,
    lease_profile_id: str | None, created_at: int,
) -> dict[str, Any]:
    try:
        authority = runtime_authority.validate_binding(runtime_authority_value)
    except runtime_authority.RuntimeAuthorityError as error:
        raise NativeStackSessionError("native_stack_session_runtime_authority_invalid") from error
    body = {
        "action": action, "action_id": action_id, "session_id": session_id,
        "stack_id": stack_id, "stack_sha256": stack_sha256,
        "catalog_sha256": catalog_sha256, "status_sha256": status_sha256,
        "runtime_authority": authority,
        "runtime_authority_sha256": authority["binding_sha256"],
        "source_id": source_id, "source_manifest_sha256": source_manifest_sha256,
        "resume_session_id": resume_session_id,
        "lease_profile_id": lease_profile_id, "created_at": created_at,
        "expires_at": created_at + MAXIMUM_LIFETIME_SECONDS,
    }
    return validate_plan({"schema": PLAN_SCHEMA, **body, "plan_sha256": sha256(body)})


def require_start_status(value: object, *, stack_sha256: str) -> dict[str, Any]:
    try:
        status = native_stack_operations.validate_status(value)
    except native_stack_operations.NativeStackOperationError as error:
        raise NativeStackSessionError("native_stack_session_status_invalid") from error
    if (status["stack_sha256"] != stack_sha256
            or status["harness"]["state"] != "admitted"
            or status["authentication"]["state"] != "signed-in"
            or status["credential_custody"]["state"] != "retained"
            or status["account_binding"]["state"] != "bound"
            or status["program_entitlement"]["state"] != "verified"
            or status["program_entitlement"]["assurance"] == "unknown"
            or status["model_entitlement"]["state"] != "verified"
            or status["model_entitlement"]["assurance"] != "provider-enforced"
            or status["network"]["phase"] != "closed"
            or status["activation"]["state"] != "active"
            or status["live_run_count"] != 0
            or status["fence_reason"] is not None):
        raise NativeStackSessionError("native_stack_session_status_not_startable")
    return status


def validate_authorization(
    value: object, plan_value: object, *, now: int,
    expected_host_release_id: str,
) -> dict[str, Any]:
    plan = validate_plan(plan_value, now=now, require_fresh=True)
    fields = {
        "schema", "authorization_id", "plan_sha256", "action", "session_id",
        "runtime_authority_sha256", "request_sha256",
        "pending_receipt_sha256", "host_release_id", "method",
        "password_fallback", "requesting_agent_sha256",
        "requesting_session_sha256", "authorized_at", "expires_at", "status",
        "authorization_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeStackSessionError("native_stack_session_authorization_fields_invalid")
    body = {key: value[key] for key in fields - {"schema", "authorization_sha256"}}
    if (value.get("schema") != AUTHORIZATION_SCHEMA
            or _uuid4(value.get("authorization_id"), "authorization_id") is None
            or value.get("plan_sha256") != plan["plan_sha256"]
            or value.get("action") != plan["action"]
            or value.get("session_id") != plan["session_id"]
            or value.get("runtime_authority_sha256")
                != plan["runtime_authority_sha256"]
            or _digest(value.get("request_sha256"), "request_sha256") is None
            or _digest(
                value.get("pending_receipt_sha256"), "pending_receipt_sha256"
            ) is None
            or value.get("method") != "touch-id"
            or value.get("password_fallback") is not False
            or _digest(
                value.get("requesting_agent_sha256"),
                "requesting_agent_sha256",
            ) is None
            or _digest(
                value.get("requesting_session_sha256"),
                "requesting_session_sha256",
            ) is None
            or value.get("host_release_id") != expected_host_release_id
            or value.get("status") != "authorized"):
        raise NativeStackSessionError("native_stack_session_authorization_invalid")
    authorized = _integer(value.get("authorized_at"), "authorized_at", 1)
    expires = _integer(value.get("expires_at"), "authorization_expires_at", 1)
    if (authorized < plan["created_at"] or expires > plan["expires_at"]
            or expires <= authorized or not authorized <= now < expires):
        raise NativeStackSessionError("native_stack_session_authorization_expired")
    supplied = _digest(value.get("authorization_sha256"), "authorization_sha256")
    if not hmac.compare_digest(str(supplied), sha256(body)):
        raise NativeStackSessionError("native_stack_session_authorization_digest_mismatch")
    return {"schema": AUTHORIZATION_SCHEMA, **body, "authorization_sha256": supplied}
