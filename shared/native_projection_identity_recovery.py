#!/usr/bin/env python3
"""Exact Touch ID authority to recover committed projection identity.

This ceremony is read-only with respect to credential custody.  It exists for
the narrow crash window in which the signed credential helper durably commits
the consumer process identity before the Host persists the helper reply.  A
fresh, single-use root ticket authorizes the helper to disclose only that
content-free identity.  It never clears a projection and it is deliberately
separate from the later closure/reconciliation ceremony.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping


PLAN_SCHEMA = "secure-sandbox-native-projection-identity-recovery-plan-v1"
AUTHORIZATION_SCHEMA = (
    "secure-sandbox-native-projection-identity-recovery-touchid-authorization-v1"
)
TICKET_SCHEMA = "secure-sandbox-native-projection-identity-recovery-ticket-v1"
REPLY_SCHEMA = "secure-sandbox-native-projection-identity-recovery-reply-v1"
OPERATION = "native-projection-identity-recover"
RESOURCE = "Recover exact committed native credential projection identity"
PROVIDER = "openAIChatGPT"
MAXIMUM_LIFETIME_SECONDS = 120
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,62}")


class NativeProjectionIdentityRecoveryError(ValueError):
    """Stable fail-closed identity-recovery validation error."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_not_canonicalizable"
        ) from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeProjectionIdentityRecoveryError(
            f"native_projection_identity_recovery_{label}_invalid"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeProjectionIdentityRecoveryError(
            f"native_projection_identity_recovery_{label}_invalid"
        )
    return value


def _integer(value: object, label: str, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise NativeProjectionIdentityRecoveryError(
            f"native_projection_identity_recovery_{label}_invalid"
        )
    return value


def validate_plan(
    value: object, *, now: int | None = None, require_fresh: bool = False,
) -> dict[str, Any]:
    fields = {
        "schema", "recovery_operation_id", "original_operation_id",
        "session_id", "stack_id", "stack_sha256",
        "session_authority_sha256", "host_release_id", "created_at",
        "expires_at", "plan_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_plan_fields_invalid"
        )
    if value.get("schema") != PLAN_SCHEMA:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_plan_schema_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "plan_sha256"}}
    recovery_id = _uuid4(
        value.get("recovery_operation_id"), "recovery_operation_id"
    )
    original_id = _uuid4(
        value.get("original_operation_id"), "original_operation_id"
    )
    if recovery_id == original_id:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_operation_identity_invalid"
        )
    _uuid4(value.get("session_id"), "session_id")
    if (not isinstance(value.get("stack_id"), str)
            or IDENTIFIER.fullmatch(value["stack_id"]) is None):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_stack_id_invalid"
        )
    for field in (
        "stack_sha256", "session_authority_sha256", "host_release_id",
    ):
        _digest(value.get(field), field)
    created = _integer(value.get("created_at"), "created_at")
    expires = _integer(value.get("expires_at"), "expires_at")
    if expires <= created or expires > created + MAXIMUM_LIFETIME_SECONDS:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_plan_lifetime_invalid"
        )
    if require_fresh and (now is None or now < created or now >= expires):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_plan_expired"
        )
    supplied = _digest(value.get("plan_sha256"), "plan_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_plan_digest_mismatch"
        )
    return {"schema": PLAN_SCHEMA, **body, "plan_sha256": supplied}


def make_plan(
    *, recovery_operation_id: str, original_operation_id: str,
    session_id: str, stack_id: str, stack_sha256: str,
    session_authority_sha256: str, host_release_id: str, created_at: int,
) -> dict[str, Any]:
    body = {
        "recovery_operation_id": recovery_operation_id,
        "original_operation_id": original_operation_id,
        "session_id": session_id,
        "stack_id": stack_id,
        "stack_sha256": stack_sha256,
        "session_authority_sha256": session_authority_sha256,
        "host_release_id": host_release_id,
        "created_at": created_at,
        "expires_at": created_at + MAXIMUM_LIFETIME_SECONDS,
    }
    return validate_plan({
        "schema": PLAN_SCHEMA, **body, "plan_sha256": sha256(body),
    })


def validate_authorization(
    value: object, plan_value: object, *, now: int,
    expected_host_release_id: str, require_fresh: bool = True,
) -> dict[str, Any]:
    plan = validate_plan(plan_value, now=now, require_fresh=require_fresh)
    fields = {
        "schema", "authorization_id", "recovery_operation_id",
        "original_operation_id", "plan_sha256", "request_sha256",
        "pending_receipt_sha256", "host_release_id", "method",
        "password_fallback", "requesting_agent_sha256",
        "requesting_session_sha256", "authorized_at", "expires_at",
        "status", "authorization_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_authorization_fields_invalid"
        )
    body = {
        key: value[key] for key in fields - {"schema", "authorization_sha256"}
    }
    if (value.get("schema") != AUTHORIZATION_SCHEMA
            or _uuid4(value.get("authorization_id"), "authorization_id") is None
            or value.get("recovery_operation_id")
                != plan["recovery_operation_id"]
            or value.get("original_operation_id")
                != plan["original_operation_id"]
            or value.get("plan_sha256") != plan["plan_sha256"]
            or _digest(value.get("request_sha256"), "request_sha256") is None
            or _digest(
                value.get("pending_receipt_sha256"),
                "pending_receipt_sha256",
            ) is None
            or value.get("host_release_id") != expected_host_release_id
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
            or value.get("status") != "authorized"):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_authorization_invalid"
        )
    authorized = _integer(value.get("authorized_at"), "authorized_at")
    expires = _integer(value.get("expires_at"), "authorization_expires_at")
    if (authorized < plan["created_at"] or expires > plan["expires_at"]
            or expires <= authorized
            or (require_fresh and not authorized <= now < expires)):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_authorization_expired"
        )
    supplied = _digest(
        value.get("authorization_sha256"), "authorization_sha256"
    )
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_authorization_digest_mismatch"
        )
    return {
        "schema": AUTHORIZATION_SCHEMA, **body,
        "authorization_sha256": supplied,
    }


def make_ticket(
    plan_value: object, authorization_value: object, *, ticket_id: str,
    now: int, expected_host_release_id: str,
) -> dict[str, Any]:
    plan = validate_plan(plan_value, now=now, require_fresh=True)
    authorization = validate_authorization(
        authorization_value, plan, now=now,
        expected_host_release_id=expected_host_release_id,
    )
    _uuid4(ticket_id, "ticket_id")
    body = {
        "ticket_id": ticket_id,
        "recovery_operation_id": plan["recovery_operation_id"],
        "original_operation_id": plan["original_operation_id"],
        "provider": PROVIDER,
        "session_authority_sha256": plan["session_authority_sha256"],
        "stack_sha256": plan["stack_sha256"],
        "recovery_plan_sha256": plan["plan_sha256"],
        "host_release_id": plan["host_release_id"],
        "recovery_request_sha256": authorization["request_sha256"],
        "recovery_receipt_sha256": authorization["pending_receipt_sha256"],
        "issued_at": authorization["authorized_at"],
        "expires_at": authorization["expires_at"],
        "status": "authorized",
    }
    return validate_ticket({
        "schema": TICKET_SCHEMA, **body, "ticket_sha256": sha256(body),
    }, now=now, require_fresh=True)


def validate_ticket(
    value: object, *, now: int | None = None, require_fresh: bool = False,
) -> dict[str, Any]:
    fields = {
        "schema", "ticket_id", "recovery_operation_id",
        "original_operation_id", "provider", "session_authority_sha256",
        "stack_sha256", "recovery_plan_sha256", "host_release_id",
        "recovery_request_sha256", "recovery_receipt_sha256", "issued_at",
        "expires_at", "status", "ticket_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_ticket_fields_invalid"
        )
    if value.get("schema") != TICKET_SCHEMA:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_ticket_schema_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "ticket_sha256"}}
    for field in ("ticket_id", "recovery_operation_id", "original_operation_id"):
        _uuid4(value.get(field), field)
    if value["recovery_operation_id"] == value["original_operation_id"]:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_operation_identity_invalid"
        )
    if value.get("provider") != PROVIDER or value.get("status") != "authorized":
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_ticket_identity_invalid"
        )
    for field in (
        "session_authority_sha256", "stack_sha256", "recovery_plan_sha256",
        "host_release_id", "recovery_request_sha256",
        "recovery_receipt_sha256",
    ):
        _digest(value.get(field), field)
    issued = _integer(value.get("issued_at"), "issued_at")
    expires = _integer(value.get("expires_at"), "expires_at")
    if expires <= issued or expires > issued + MAXIMUM_LIFETIME_SECONDS:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_ticket_lifetime_invalid"
        )
    if require_fresh and (now is None or now < issued or now >= expires):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_ticket_expired"
        )
    supplied = _digest(value.get("ticket_sha256"), "ticket_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_ticket_digest_mismatch"
        )
    return {"schema": TICKET_SCHEMA, **body, "ticket_sha256": supplied}


def validate_reply(value: object, *, plan_value: object) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    fields = {
        "schema", "outcome", "recovery_operation_id",
        "original_operation_id", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "session_authority_sha256", "identity_evidence_sha256",
        "reply_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_reply_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "reply_sha256"}}
    if (value.get("schema") != REPLY_SCHEMA
            or value.get("outcome") != "verified"
            or value.get("recovery_operation_id")
                != plan["recovery_operation_id"]
            or value.get("original_operation_id")
                != plan["original_operation_id"]
            or value.get("session_authority_sha256")
                != plan["session_authority_sha256"]):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_reply_mismatch"
        )
    _integer(value.get("process_identifier"), "process_identifier")
    _integer(value.get("process_start_time_us"), "process_start_time_us")
    _digest(
        value.get("consumer_executable_sha256"),
        "consumer_executable_sha256",
    )
    _digest(value.get("identity_evidence_sha256"), "identity_evidence_sha256")
    supplied = _digest(value.get("reply_sha256"), "reply_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionIdentityRecoveryError(
            "native_projection_identity_recovery_reply_digest_mismatch"
        )
    return {"schema": REPLY_SCHEMA, **body, "reply_sha256": supplied}
