#!/usr/bin/env python3
"""Exact Touch ID authority for ambiguous native credential projections.

This ceremony is deliberately distinct from session start/stop and generic
stack recovery.  It can clear exactly one durable helper projection only after
Host has independently proved the bound Research run absent and inference
egress closed.  PID absence, authorization expiry, or wall-clock age alone are
never reconciliation authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping


PLAN_SCHEMA = "secure-sandbox-native-projection-reconciliation-plan-v1"
AUTHORIZATION_SCHEMA = (
    "secure-sandbox-native-projection-reconciliation-touchid-authorization-v1"
)
TICKET_SCHEMA = "secure-sandbox-native-projection-reconciliation-ticket-v1"
IDENTITY_SCHEMA = "secure-sandbox-native-projection-identity-v1"
EVIDENCE_SCHEMA = "secure-sandbox-native-projection-closure-evidence-v1"
REPLY_SCHEMA = "secure-sandbox-native-projection-reconciliation-reply-v1"
OPERATION = "native-projection-reconcile"
RESOURCE = "Exact ambiguous native credential projection recovery"
PROVIDER = "openAIChatGPT"
MAXIMUM_LIFETIME_SECONDS = 120
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,62}")


class NativeProjectionReconciliationError(ValueError):
    """Stable fail-closed projection-reconciliation validation error."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_not_canonicalizable"
        ) from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeProjectionReconciliationError(
            f"native_projection_reconciliation_{label}_invalid"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeProjectionReconciliationError(
            f"native_projection_reconciliation_{label}_invalid"
        )
    return value


def _integer(value: object, label: str, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise NativeProjectionReconciliationError(
            f"native_projection_reconciliation_{label}_invalid"
        )
    return value


def validate_identity(value: object) -> dict[str, Any]:
    fields = {
        "schema", "original_operation_id", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "session_authority_sha256", "credential_response_sha256",
        "credential_reply_sha256", "observed_at", "identity_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_identity_fields_invalid"
        )
    if value.get("schema") != IDENTITY_SCHEMA:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_identity_schema_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "identity_sha256"}}
    _uuid4(value.get("original_operation_id"), "original_operation_id")
    _integer(value.get("process_identifier"), "process_identifier")
    _integer(value.get("process_start_time_us"), "process_start_time_us")
    for field in (
        "consumer_executable_sha256", "session_authority_sha256",
        "credential_response_sha256", "credential_reply_sha256",
    ):
        _digest(value.get(field), field)
    _integer(value.get("observed_at"), "observed_at")
    supplied = _digest(value.get("identity_sha256"), "identity_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_identity_digest_mismatch"
        )
    return {"schema": IDENTITY_SCHEMA, **body, "identity_sha256": supplied}


def make_identity(
    *, original_operation_id: str, process_identifier: int,
    process_start_time_us: int, consumer_executable_sha256: str,
    session_authority_sha256: str, credential_response_sha256: str,
    credential_reply_sha256: str, observed_at: int,
) -> dict[str, Any]:
    body = {
        "original_operation_id": original_operation_id,
        "process_identifier": process_identifier,
        "process_start_time_us": process_start_time_us,
        "consumer_executable_sha256": consumer_executable_sha256,
        "session_authority_sha256": session_authority_sha256,
        "credential_response_sha256": credential_response_sha256,
        "credential_reply_sha256": credential_reply_sha256,
        "observed_at": observed_at,
    }
    return validate_identity({
        "schema": IDENTITY_SCHEMA, **body, "identity_sha256": sha256(body),
    })


def validate_closure_evidence(value: object) -> dict[str, Any]:
    fields = {
        "schema", "original_operation_id", "guest_absence_evidence_sha256",
        "egress_closed_evidence_sha256", "observed_at", "evidence_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_evidence_fields_invalid"
        )
    if value.get("schema") != EVIDENCE_SCHEMA:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_evidence_schema_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "evidence_sha256"}}
    _uuid4(value.get("original_operation_id"), "original_operation_id")
    _digest(
        value.get("guest_absence_evidence_sha256"),
        "guest_absence_evidence_sha256",
    )
    _digest(
        value.get("egress_closed_evidence_sha256"),
        "egress_closed_evidence_sha256",
    )
    _integer(value.get("observed_at"), "observed_at")
    supplied = _digest(value.get("evidence_sha256"), "evidence_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_evidence_digest_mismatch"
        )
    return {"schema": EVIDENCE_SCHEMA, **body, "evidence_sha256": supplied}


def make_closure_evidence(
    *, original_operation_id: str, guest_absence_evidence_sha256: str,
    egress_closed_evidence_sha256: str, observed_at: int,
) -> dict[str, Any]:
    body = {
        "original_operation_id": original_operation_id,
        "guest_absence_evidence_sha256": guest_absence_evidence_sha256,
        "egress_closed_evidence_sha256": egress_closed_evidence_sha256,
        "observed_at": observed_at,
    }
    return validate_closure_evidence({
        "schema": EVIDENCE_SCHEMA, **body, "evidence_sha256": sha256(body),
    })


def closed_egress_evidence_sha256(status: object) -> str:
    """Reduce a validated status to stable, exact closed-egress authority.

    Observation time is intentionally excluded: the Touch ID plan and apply
    readbacks occur at different instants.  Every security-relevant closed
    network field, stack identity, and live-run count remains bound.
    """
    if not isinstance(status, Mapping):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_egress_status_invalid"
        )
    network = status.get("network")
    if (not isinstance(network, Mapping)
            or set(network)
                != {"phase", "grant_sha256", "expires_at", "observed_at"}
            or network.get("phase") != "closed"
            or network.get("grant_sha256") is not None
            or network.get("expires_at") is not None
            or not isinstance(network.get("observed_at"), int)
            or isinstance(network.get("observed_at"), bool)
            or network["observed_at"] < 1
            or status.get("live_run_count") != 0
            or not isinstance(status.get("stack_sha256"), str)
            or SHA256.fullmatch(status["stack_sha256"]) is None):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_egress_not_closed"
        )
    return sha256({
        "stack_sha256": status["stack_sha256"],
        "network": {
            "phase": "closed", "grant_sha256": None, "expires_at": None,
        },
        "live_run_count": 0,
    })


def validate_plan(
    value: object, *, now: int | None = None, require_fresh: bool = False,
) -> dict[str, Any]:
    fields = {
        "schema", "recovery_operation_id", "original_operation_id",
        "session_id", "stack_id", "stack_sha256",
        "session_authority_sha256", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "guest_absence_evidence_sha256", "egress_closed_evidence_sha256",
        "host_release_id", "created_at", "expires_at", "plan_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_plan_fields_invalid"
        )
    if value.get("schema") != PLAN_SCHEMA:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_plan_schema_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "plan_sha256"}}
    recovery_id = _uuid4(
        value.get("recovery_operation_id"), "recovery_operation_id"
    )
    original_id = _uuid4(
        value.get("original_operation_id"), "original_operation_id"
    )
    if recovery_id == original_id:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_operation_identity_invalid"
        )
    _uuid4(value.get("session_id"), "session_id")
    if (not isinstance(value.get("stack_id"), str)
            or IDENTIFIER.fullmatch(value["stack_id"]) is None):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_stack_id_invalid"
        )
    for field in (
        "stack_sha256", "session_authority_sha256",
        "consumer_executable_sha256", "guest_absence_evidence_sha256",
        "egress_closed_evidence_sha256", "host_release_id",
    ):
        _digest(value.get(field), field)
    _integer(value.get("process_identifier"), "process_identifier")
    _integer(value.get("process_start_time_us"), "process_start_time_us")
    created = _integer(value.get("created_at"), "created_at")
    expires = _integer(value.get("expires_at"), "expires_at")
    if expires <= created or expires > created + MAXIMUM_LIFETIME_SECONDS:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_plan_lifetime_invalid"
        )
    if require_fresh and (now is None or now < created or now >= expires):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_plan_expired"
        )
    supplied = _digest(value.get("plan_sha256"), "plan_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_plan_digest_mismatch"
        )
    return {"schema": PLAN_SCHEMA, **body, "plan_sha256": supplied}


def make_plan(
    *, recovery_operation_id: str, original_operation_id: str,
    session_id: str, stack_id: str, stack_sha256: str,
    session_authority_sha256: str, process_identifier: int,
    process_start_time_us: int, consumer_executable_sha256: str,
    guest_absence_evidence_sha256: str,
    egress_closed_evidence_sha256: str, host_release_id: str,
    created_at: int,
) -> dict[str, Any]:
    body = {
        "recovery_operation_id": recovery_operation_id,
        "original_operation_id": original_operation_id,
        "session_id": session_id, "stack_id": stack_id,
        "stack_sha256": stack_sha256,
        "session_authority_sha256": session_authority_sha256,
        "process_identifier": process_identifier,
        "process_start_time_us": process_start_time_us,
        "consumer_executable_sha256": consumer_executable_sha256,
        "guest_absence_evidence_sha256": guest_absence_evidence_sha256,
        "egress_closed_evidence_sha256": egress_closed_evidence_sha256,
        "host_release_id": host_release_id, "created_at": created_at,
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
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_authorization_fields_invalid"
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
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_authorization_invalid"
        )
    authorized = _integer(value.get("authorized_at"), "authorized_at")
    expires = _integer(value.get("expires_at"), "authorization_expires_at")
    if (authorized < plan["created_at"] or expires > plan["expires_at"]
            or expires <= authorized
            or (require_fresh and not authorized <= now < expires)):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_authorization_expired"
        )
    supplied = _digest(
        value.get("authorization_sha256"), "authorization_sha256"
    )
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_authorization_digest_mismatch"
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
        "process_identifier": plan["process_identifier"],
        "process_start_time_us": plan["process_start_time_us"],
        "consumer_executable_sha256": plan["consumer_executable_sha256"],
        "session_authority_sha256": plan["session_authority_sha256"],
        "stack_sha256": plan["stack_sha256"],
        "recovery_plan_sha256": plan["plan_sha256"],
        "guest_absence_evidence_sha256": (
            plan["guest_absence_evidence_sha256"]
        ),
        "egress_closed_evidence_sha256": (
            plan["egress_closed_evidence_sha256"]
        ),
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
        "original_operation_id", "provider", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "session_authority_sha256", "stack_sha256",
        "recovery_plan_sha256", "guest_absence_evidence_sha256",
        "egress_closed_evidence_sha256", "host_release_id",
        "recovery_request_sha256", "recovery_receipt_sha256", "issued_at",
        "expires_at", "status", "ticket_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_ticket_fields_invalid"
        )
    if value.get("schema") != TICKET_SCHEMA:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_ticket_schema_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "ticket_sha256"}}
    for field in ("ticket_id", "recovery_operation_id", "original_operation_id"):
        _uuid4(value.get(field), field)
    if value["recovery_operation_id"] == value["original_operation_id"]:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_operation_identity_invalid"
        )
    if value.get("provider") != PROVIDER or value.get("status") != "authorized":
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_ticket_identity_invalid"
        )
    _integer(value.get("process_identifier"), "process_identifier")
    _integer(value.get("process_start_time_us"), "process_start_time_us")
    for field in (
        "consumer_executable_sha256", "session_authority_sha256",
        "stack_sha256", "recovery_plan_sha256",
        "guest_absence_evidence_sha256", "egress_closed_evidence_sha256",
        "host_release_id", "recovery_request_sha256",
        "recovery_receipt_sha256",
    ):
        _digest(value.get(field), field)
    issued = _integer(value.get("issued_at"), "issued_at")
    expires = _integer(value.get("expires_at"), "expires_at")
    if expires <= issued or expires > issued + MAXIMUM_LIFETIME_SECONDS:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_ticket_lifetime_invalid"
        )
    if require_fresh and (now is None or now < issued or now >= expires):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_ticket_expired"
        )
    supplied = _digest(value.get("ticket_sha256"), "ticket_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_ticket_digest_mismatch"
        )
    return {"schema": TICKET_SCHEMA, **body, "ticket_sha256": supplied}


def validate_reply(
    value: object, *, plan_value: object,
) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    fields = {
        "schema", "outcome", "recovery_operation_id",
        "original_operation_id", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "session_authority_sha256", "reconciliation_evidence_sha256",
        "reply_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_reply_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "reply_sha256"}}
    if (value.get("schema") != REPLY_SCHEMA
            or value.get("outcome") != "verified"
            or value.get("recovery_operation_id")
                != plan["recovery_operation_id"]
            or value.get("original_operation_id")
                != plan["original_operation_id"]
            or value.get("process_identifier") != plan["process_identifier"]
            or value.get("process_start_time_us")
                != plan["process_start_time_us"]
            or value.get("consumer_executable_sha256")
                != plan["consumer_executable_sha256"]
            or value.get("session_authority_sha256")
                != plan["session_authority_sha256"]):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_reply_mismatch"
        )
    _digest(
        value.get("reconciliation_evidence_sha256"),
        "reconciliation_evidence_sha256",
    )
    supplied = _digest(value.get("reply_sha256"), "reply_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProjectionReconciliationError(
            "native_projection_reconciliation_reply_digest_mismatch"
        )
    return {"schema": REPLY_SCHEMA, **body, "reply_sha256": supplied}
