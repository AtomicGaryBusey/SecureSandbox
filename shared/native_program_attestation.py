#!/usr/bin/env python3
"""Touch ID authority for operator-external native program declarations.

This contract cannot claim provider verification.  It records only that the
operator explicitly declared an external program enrollment for the exact
account, workspace, requirements snapshot, harness generation, and stack
revision displayed by the authorization UI.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from shared import native_stack_operations
from shared import native_vendor_stack


PLAN_SCHEMA = "secure-sandbox-native-program-attestation-plan-v1"
AUTHORIZATION_SCHEMA = "secure-sandbox-native-program-attestation-touchid-authorization-v1"
COMMIT_SCHEMA = "secure-sandbox-native-program-attestation-commit-v1"
RESOURCE = "Native vendor external-program declaration"
OPERATION = "native-program-attest"
ASSURANCE = "operator-external"
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
MAXIMUM_LIFETIME_SECONDS = 180


class NativeProgramAttestationError(ValueError):
    """Stable fail-closed program-attestation validation error."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeProgramAttestationError(
            "native_program_attestation_not_canonicalizable"
        ) from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeProgramAttestationError(
            f"native_program_attestation_{label}_invalid"
        )
    return value


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeProgramAttestationError(
            f"native_program_attestation_{label}_invalid"
        )
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise NativeProgramAttestationError(
            f"native_program_attestation_{label}_invalid"
        )
    return value


def validate_plan(
    value: object, *, now: int | None = None, require_fresh: bool = False,
) -> dict[str, Any]:
    fields = {
        "schema", "attestation_id", "stack_id", "stack_sha256",
        "catalog_sha256", "status_sha256", "harness_generation_id",
        "account_subject_sha256", "workspace_sha256", "program_id",
        "program_tier", "program_requirements_version", "assurance",
        "created_at", "expires_at", "plan_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProgramAttestationError(
            "native_program_attestation_plan_fields_invalid"
        )
    if value.get("schema") != PLAN_SCHEMA:
        raise NativeProgramAttestationError(
            "native_program_attestation_plan_schema_invalid"
        )
    _uuid4(value.get("attestation_id"), "attestation_id")
    if (not isinstance(value.get("stack_id"), str)
            or native_vendor_stack.IDENTIFIER.fullmatch(value["stack_id"]) is None):
        raise NativeProgramAttestationError(
            "native_program_attestation_stack_id_invalid"
        )
    for field in (
        "stack_sha256", "catalog_sha256", "status_sha256",
        "harness_generation_id", "account_subject_sha256", "workspace_sha256",
    ):
        _digest(value.get(field), field)
    for field in ("program_id", "program_tier", "program_requirements_version"):
        if (not isinstance(value.get(field), str)
                or native_vendor_stack.IDENTIFIER.fullmatch(value[field]) is None):
            raise NativeProgramAttestationError(
                f"native_program_attestation_{field}_invalid"
            )
    if value.get("assurance") != ASSURANCE:
        raise NativeProgramAttestationError(
            "native_program_attestation_assurance_invalid"
        )
    created = _integer(value.get("created_at"), "created_at")
    expires = _integer(value.get("expires_at"), "expires_at")
    if expires <= created or expires > created + MAXIMUM_LIFETIME_SECONDS:
        raise NativeProgramAttestationError(
            "native_program_attestation_lifetime_invalid"
        )
    if require_fresh and (now is None or now < created or now >= expires):
        raise NativeProgramAttestationError(
            "native_program_attestation_expired"
        )
    body = {key: value[key] for key in fields - {"schema", "plan_sha256"}}
    supplied = _digest(value.get("plan_sha256"), "plan_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProgramAttestationError(
            "native_program_attestation_digest_mismatch"
        )
    return {"schema": PLAN_SCHEMA, **body, "plan_sha256": supplied}


def make_plan(
    *, stack: object, catalog_sha256: str, status_value: object,
    attestation_id: str, created_at: int,
) -> dict[str, Any]:
    try:
        validated = native_vendor_stack.validate_stack(stack)
        status = native_stack_operations.validate_status(status_value)
    except (
        native_vendor_stack.NativeVendorStackError,
        native_stack_operations.NativeStackOperationError,
    ) as error:
        raise NativeProgramAttestationError(
            "native_program_attestation_input_invalid"
        ) from error
    revision = native_vendor_stack.stack_revision(validated)
    binding = validated["account_binding"]
    harness = validated["harness"]
    if (status["stack_id"] != validated["stack_id"]
            or status["stack_sha256"] != revision
            or status["harness"]["state"] != "admitted"
            or status["authentication"]["state"] != "signed-in"
            or status["account_binding"]["state"] != "bound"
            or status["account_binding"]["account_subject_sha256"]
                != binding["account_subject_sha256"]
            or status["account_binding"]["workspace_sha256"]
                != binding["workspace_sha256"]
            or status["network"]["phase"] != "closed"
            or status["live_run_count"] != 0
            or status["fence_reason"] is not None
            or harness["generation_id"] is None
            or any(binding[name] is None for name in (
                "account_subject_sha256", "workspace_sha256", "program_id",
                "program_tier", "program_requirements_version"))):
        raise NativeProgramAttestationError(
            "native_program_attestation_status_not_attestable"
        )
    body = {
        "attestation_id": attestation_id, "stack_id": validated["stack_id"],
        "stack_sha256": revision, "catalog_sha256": _digest(
            catalog_sha256, "catalog_sha256"),
        "status_sha256": status["status_sha256"],
        "harness_generation_id": harness["generation_id"],
        "account_subject_sha256": binding["account_subject_sha256"],
        "workspace_sha256": binding["workspace_sha256"],
        "program_id": binding["program_id"],
        "program_tier": binding["program_tier"],
        "program_requirements_version": binding["program_requirements_version"],
        "assurance": ASSURANCE, "created_at": created_at,
        "expires_at": created_at + MAXIMUM_LIFETIME_SECONDS,
    }
    return validate_plan(
        {"schema": PLAN_SCHEMA, **body, "plan_sha256": sha256(body)}
    )


def validate_authorization(
    value: object, plan_value: object, *, now: int,
    expected_host_release_id: str,
) -> dict[str, Any]:
    plan = validate_plan(plan_value, now=now, require_fresh=True)
    fields = {
        "schema", "authorization_id", "attestation_id", "plan_sha256",
        "request_sha256", "pending_receipt_sha256", "host_release_id",
        "method", "password_fallback", "requesting_agent_sha256",
        "requesting_session_sha256", "authorized_at", "expires_at", "status",
        "authorization_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProgramAttestationError(
            "native_program_attestation_authorization_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "authorization_sha256"}}
    if (value.get("schema") != AUTHORIZATION_SCHEMA
            or _uuid4(value.get("authorization_id"), "authorization_id") is None
            or value.get("attestation_id") != plan["attestation_id"]
            or value.get("plan_sha256") != plan["plan_sha256"]
            or _digest(value.get("request_sha256"), "request_sha256") is None
            or _digest(
                value.get("pending_receipt_sha256"), "pending_receipt_sha256"
            ) is None
            or value.get("method") != "touch-id"
            or value.get("password_fallback") is not False
            or _digest(
                value.get("requesting_agent_sha256"), "requesting_agent_sha256"
            ) is None
            or _digest(
                value.get("requesting_session_sha256"),
                "requesting_session_sha256",
            ) is None
            or value.get("host_release_id") != expected_host_release_id
            or value.get("status") != "authorized"):
        raise NativeProgramAttestationError(
            "native_program_attestation_authorization_invalid"
        )
    authorized = _integer(value.get("authorized_at"), "authorized_at")
    expires = _integer(value.get("expires_at"), "authorization_expires_at")
    if (authorized < plan["created_at"] or expires > plan["expires_at"]
            or expires <= authorized or not authorized <= now < expires):
        raise NativeProgramAttestationError(
            "native_program_attestation_authorization_expired"
        )
    supplied = _digest(value.get("authorization_sha256"), "authorization_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProgramAttestationError(
            "native_program_attestation_authorization_digest_mismatch"
        )
    return {"schema": AUTHORIZATION_SCHEMA, **body,
            "authorization_sha256": supplied}


def validate_commit(value: object) -> dict[str, Any]:
    fields = {
        "schema", "attestation_id", "stack_id", "stack_sha256",
        "catalog_sha256", "status_sha256", "harness_generation_id",
        "account_subject_sha256", "workspace_sha256", "program_id",
        "program_tier", "program_requirements_version", "assurance",
        "plan_sha256", "authorization_id", "authorization_sha256",
        "operator_receipt_sha256", "provider_evidence_sha256",
        "committed_at", "commit_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeProgramAttestationError(
            "native_program_attestation_commit_fields_invalid"
        )
    if (value.get("schema") != COMMIT_SCHEMA
            or value.get("assurance") != ASSURANCE):
        raise NativeProgramAttestationError(
            "native_program_attestation_commit_identity_invalid"
        )
    _uuid4(value.get("attestation_id"), "commit_attestation_id")
    _uuid4(value.get("authorization_id"), "commit_authorization_id")
    if (not isinstance(value.get("stack_id"), str)
            or native_vendor_stack.IDENTIFIER.fullmatch(value["stack_id"]) is None):
        raise NativeProgramAttestationError(
            "native_program_attestation_commit_stack_id_invalid"
        )
    for field in (
        "stack_sha256", "catalog_sha256", "status_sha256",
        "harness_generation_id", "account_subject_sha256", "workspace_sha256",
        "plan_sha256", "authorization_sha256", "operator_receipt_sha256",
        "provider_evidence_sha256",
    ):
        _digest(value.get(field), f"commit_{field}")
    for field in ("program_id", "program_tier", "program_requirements_version"):
        if (not isinstance(value.get(field), str)
                or native_vendor_stack.IDENTIFIER.fullmatch(value[field]) is None):
            raise NativeProgramAttestationError(
                f"native_program_attestation_commit_{field}_invalid"
            )
    _integer(value.get("committed_at"), "commit_committed_at")
    body = {key: value[key] for key in fields - {"schema", "commit_sha256"}}
    supplied = _digest(value.get("commit_sha256"), "commit_sha256")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeProgramAttestationError(
            "native_program_attestation_commit_digest_mismatch"
        )
    return {"schema": COMMIT_SCHEMA, **body, "commit_sha256": supplied}


def make_commit(
    *, plan_value: object, authorization_value: object,
    operator_receipt_sha256: str, provider_evidence_sha256: str,
    committed_at: int,
) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    if not isinstance(authorization_value, Mapping):
        raise NativeProgramAttestationError(
            "native_program_attestation_authorization_invalid"
        )
    authorization_now = authorization_value.get("authorized_at")
    expected_release = authorization_value.get("host_release_id")
    if (not isinstance(authorization_now, int)
            or isinstance(authorization_now, bool)
            or not isinstance(expected_release, str)):
        raise NativeProgramAttestationError(
            "native_program_attestation_authorization_invalid"
        )
    authorization = validate_authorization(
        authorization_value, plan,
        now=authorization_now,
        expected_host_release_id=expected_release,
    )
    committed = _integer(committed_at, "committed_at")
    if committed < authorization["authorized_at"]:
        raise NativeProgramAttestationError(
            "native_program_attestation_commit_time_invalid"
        )
    body = {
        "attestation_id": plan["attestation_id"],
        "stack_id": plan["stack_id"], "stack_sha256": plan["stack_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
        "status_sha256": plan["status_sha256"],
        "harness_generation_id": plan["harness_generation_id"],
        "account_subject_sha256": plan["account_subject_sha256"],
        "workspace_sha256": plan["workspace_sha256"],
        "program_id": plan["program_id"], "program_tier": plan["program_tier"],
        "program_requirements_version": plan["program_requirements_version"],
        "assurance": ASSURANCE, "plan_sha256": plan["plan_sha256"],
        "authorization_id": authorization["authorization_id"],
        "authorization_sha256": authorization["authorization_sha256"],
        "operator_receipt_sha256": _digest(
            operator_receipt_sha256, "operator_receipt_sha256"
        ),
        "provider_evidence_sha256": _digest(
            provider_evidence_sha256, "provider_evidence_sha256"
        ),
        "committed_at": committed,
    }
    return validate_commit({
        "schema": COMMIT_SCHEMA, **body, "commit_sha256": sha256(body),
    })
