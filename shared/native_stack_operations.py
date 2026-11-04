#!/usr/bin/env python3
"""Content-free status and protected-plan contracts for native vendor stacks.

The schemas in this module deliberately cannot carry an OAuth token,
authorization code, PKCE verifier, email address, provider response body, or
credential path.  They are the only native-stack facts allowed to cross from a
vendor-specific credential compartment into the Host control plane and GUI.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any, Mapping

from shared import native_vendor_stack


STATUS_SCHEMA = "secure-sandbox-native-stack-operational-status-v1"
PLAN_SCHEMA = "secure-sandbox-native-stack-action-plan-v1"
RECEIPT_SCHEMA = "secure-sandbox-native-stack-action-receipt-v1"

SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

ACTIONS = {
    "signin-begin",
    "binding-commit",
    "status-verify",
    "entitlement-verify",
    "activate",
    "rollback",
    "logout",
    "credential-destroy",
    "recover",
}

ACTION_PHASE = {
    "signin-begin": "login",
    "binding-commit": "closed",
    "status-verify": "status-logout",
    "entitlement-verify": "inference",
    "activate": "closed",
    "rollback": "closed",
    "logout": "status-logout",
    "credential-destroy": "closed",
    "recover": "closed",
}

HARNESS_STATES = {"missing", "admitted", "mismatch", "revoked", "ambiguous"}
AUTH_STATES = {"signed-out", "signed-in", "expired", "revoked", "ambiguous", "fenced"}
BINDING_STATES = {"unbound", "observed", "bound", "mismatch", "ambiguous"}
ENTITLEMENT_STATES = {"unknown", "verified", "denied", "stale", "ambiguous"}
CREDENTIAL_CUSTODY_STATES = {
    "absent", "retained", "session-projected", "ambiguous"
}
NETWORK_PHASES = {"closed", "login", "inference", "status-logout", "ambiguous"}
ACTIVATION_STATES = {
    "inactive",
    "active",
    "fenced",
    "rollback-pending",
    "recovery-required",
}
RECEIPT_RESULTS = {"verified", "rejected", "cancelled", "expired", "ambiguous"}


class NativeStackOperationError(ValueError):
    """Stable fail-closed native-stack operation validation failure."""


def canonical_bytes(value: object) -> bytes:
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
        raise NativeStackOperationError("native_stack_operation_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackOperationError(f"native_stack_{label}_fields_invalid")
    return value


def _digest(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeStackOperationError(f"native_stack_{label}_invalid")
    return value


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise NativeStackOperationError(f"native_stack_{label}_invalid")
    return value


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeStackOperationError(f"native_stack_{label}_invalid")
    return value


def _choice(value: object, allowed: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise NativeStackOperationError(f"native_stack_{label}_invalid")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise NativeStackOperationError(f"native_stack_{label}_invalid")
    return value


def _validate_observation(
    value: object,
    *,
    allowed_states: set[str],
    label: str,
    binding_fields: tuple[str, ...] = (),
) -> dict[str, Any]:
    observation = _exact(
        value,
        {"state", "observed_at", "evidence_sha256", *binding_fields},
        label,
    )
    _choice(observation["state"], allowed_states, f"{label}_state")
    observed_at = observation["observed_at"]
    evidence = observation["evidence_sha256"]
    if (observed_at is None) != (evidence is None):
        raise NativeStackOperationError(f"native_stack_{label}_evidence_incomplete")
    if observed_at is not None:
        _integer(observed_at, f"{label}_observed_at", 1)
        _digest(evidence, f"{label}_evidence_sha256")
    for field in binding_fields:
        _digest(observation[field], f"{label}_{field}", optional=True)
    return observation


def validate_status(value: object) -> dict[str, Any]:
    status = _exact(
        value,
        {
            "schema",
            "stack_id",
            "stack_sha256",
            "harness",
            "authentication",
            "credential_custody",
            "account_binding",
            "program_entitlement",
            "model_entitlement",
            "network",
            "activation",
            "live_run_count",
            "fence_reason",
            "status_sha256",
        },
        "operational_status",
    )
    if status["schema"] != STATUS_SCHEMA:
        raise NativeStackOperationError("native_stack_operational_status_schema_invalid")
    if (
        not isinstance(status["stack_id"], str)
        or native_vendor_stack.IDENTIFIER.fullmatch(status["stack_id"]) is None
    ):
        raise NativeStackOperationError("native_stack_operational_status_stack_id_invalid")
    _digest(status["stack_sha256"], "operational_status_stack_sha256")

    harness = _validate_observation(
        status["harness"],
        allowed_states=HARNESS_STATES,
        label="harness_status",
        binding_fields=("generation_id", "binding_sha256"),
    )
    if harness["state"] == "admitted" and (
        harness["generation_id"] is None or harness["binding_sha256"] is None
    ):
        raise NativeStackOperationError("native_stack_harness_status_admission_incomplete")

    _validate_observation(
        status["authentication"],
        allowed_states=AUTH_STATES,
        label="authentication_status",
    )
    custody = _exact(
        status["credential_custody"],
        {
            "state", "observed_at", "evidence_sha256", "tombstone_sha256",
            "projection_count",
        },
        "credential_custody_status",
    )
    custody_state = _choice(
        custody["state"],
        CREDENTIAL_CUSTODY_STATES,
        "credential_custody_status_state",
    )
    _integer(custody["observed_at"], "credential_custody_status_observed_at", 1)
    _digest(
        custody["evidence_sha256"],
        "credential_custody_status_evidence_sha256",
    )
    _digest(
        custody["tombstone_sha256"],
        "credential_custody_status_tombstone_sha256",
        optional=True,
    )
    projection_count = custody["projection_count"]
    if custody_state == "ambiguous":
        if projection_count is not None or custody["tombstone_sha256"] is not None:
            raise NativeStackOperationError(
                "native_stack_credential_custody_status_ambiguous_claim"
            )
    else:
        _integer(
            projection_count,
            "credential_custody_status_projection_count",
        )
        if custody_state == "session-projected":
            if projection_count < 1 or custody["tombstone_sha256"] is not None:
                raise NativeStackOperationError(
                    "native_stack_credential_custody_status_projection_invalid"
                )
        elif projection_count != 0:
            raise NativeStackOperationError(
                "native_stack_credential_custody_status_projection_invalid"
            )
        if custody_state == "retained" and custody["tombstone_sha256"] is not None:
            raise NativeStackOperationError(
                "native_stack_credential_custody_status_tombstone_invalid"
            )
    account = _validate_observation(
        status["account_binding"],
        allowed_states=BINDING_STATES,
        label="account_binding_status",
        binding_fields=("account_subject_sha256", "workspace_sha256"),
    )
    if account["state"] in {"observed", "bound", "mismatch"} and (
        account["account_subject_sha256"] is None or account["workspace_sha256"] is None
    ):
        raise NativeStackOperationError("native_stack_account_binding_status_incomplete")

    _validate_observation(
        status["program_entitlement"],
        allowed_states=ENTITLEMENT_STATES,
        label="program_entitlement_status",
    )
    _validate_observation(
        status["model_entitlement"],
        allowed_states=ENTITLEMENT_STATES,
        label="model_entitlement_status",
    )

    network = _exact(
        status["network"],
        {"phase", "grant_sha256", "expires_at", "observed_at"},
        "network_status",
    )
    phase = _choice(network["phase"], NETWORK_PHASES, "network_status_phase")
    if phase == "closed":
        if network["grant_sha256"] is not None or network["expires_at"] is not None:
            raise NativeStackOperationError("native_stack_network_status_closed_has_grant")
    elif phase != "ambiguous":
        _digest(network["grant_sha256"], "network_status_grant_sha256")
        _integer(network["expires_at"], "network_status_expires_at", 1)
    else:
        _digest(network["grant_sha256"], "network_status_grant_sha256", optional=True)
        if network["expires_at"] is not None:
            _integer(network["expires_at"], "network_status_expires_at", 1)
    _integer(network["observed_at"], "network_status_observed_at", 1)

    activation = _validate_observation(
        status["activation"],
        allowed_states=ACTIVATION_STATES,
        label="activation_status",
        binding_fields=("receipt_sha256",),
    )
    if activation["state"] == "active" and activation["receipt_sha256"] is None:
        raise NativeStackOperationError("native_stack_activation_status_receipt_missing")

    _integer(status["live_run_count"], "operational_status_live_run_count")
    if status["fence_reason"] is not None and (
        not isinstance(status["fence_reason"], str)
        or native_vendor_stack.IDENTIFIER.fullmatch(status["fence_reason"]) is None
    ):
        raise NativeStackOperationError("native_stack_operational_status_fence_reason_invalid")
    if activation["state"] in {"fenced", "recovery-required"}:
        if status["fence_reason"] is None:
            raise NativeStackOperationError("native_stack_operational_status_fence_reason_missing")
    elif status["fence_reason"] is not None:
        raise NativeStackOperationError("native_stack_operational_status_unexpected_fence_reason")

    body = {key: status[key] for key in status if key not in {"schema", "status_sha256"}}
    supplied = _digest(status["status_sha256"], "operational_status_digest")
    if not hmac.compare_digest(str(supplied), sha256(body)):
        raise NativeStackOperationError("native_stack_operational_status_digest_mismatch")
    return status


def make_status(
    *,
    stack: object,
    harness: dict[str, Any],
    authentication: dict[str, Any],
    credential_custody: dict[str, Any],
    account_binding: dict[str, Any],
    program_entitlement: dict[str, Any],
    model_entitlement: dict[str, Any],
    network: dict[str, Any],
    activation: dict[str, Any],
    live_run_count: int,
    fence_reason: str | None = None,
) -> dict[str, Any]:
    validated = native_vendor_stack.validate_stack(stack)
    body = {
        "stack_id": validated["stack_id"],
        "stack_sha256": native_vendor_stack.stack_revision(validated),
        "harness": harness,
        "authentication": authentication,
        "credential_custody": credential_custody,
        "account_binding": account_binding,
        "program_entitlement": program_entitlement,
        "model_entitlement": model_entitlement,
        "network": network,
        "activation": activation,
        "live_run_count": live_run_count,
        "fence_reason": fence_reason,
    }
    return validate_status({"schema": STATUS_SCHEMA, **body, "status_sha256": sha256(body)})


def _stack_plan_identity(stack: dict[str, Any]) -> dict[str, Any]:
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


PLAN_IDENTITY_FIELDS = {
    "stack_id",
    "stack_sha256",
    "vendor_id",
    "harness_id",
    "harness_generation_id",
    "harness_adapter_id",
    "authentication_mode",
    "credential_custody",
    "account_subject_sha256",
    "workspace_sha256",
    "program_id",
    "program_tier",
    "program_requirements_version",
    "model_id",
    "model_settings_sha256",
    "network_policy_id",
}


def validate_plan(value: object, *, now: int | None = None, require_fresh: bool = False) -> dict[str, Any]:
    plan = _exact(
        value,
        {
            "schema",
            "action_id",
            "action",
            "created_at",
            "expires_at",
            "identity",
            "current_status_sha256",
            "observed_account_subject_sha256",
            "observed_workspace_sha256",
            "requested_network_phase",
            "impact",
            "plan_sha256",
        },
        "action_plan",
    )
    if plan["schema"] != PLAN_SCHEMA:
        raise NativeStackOperationError("native_stack_action_plan_schema_invalid")
    _uuid4(plan["action_id"], "action_plan_id")
    action = _choice(plan["action"], ACTIONS, "action_plan_action")
    created = _integer(plan["created_at"], "action_plan_created_at", 1)
    expires = _integer(plan["expires_at"], "action_plan_expires_at", 1)
    if not created < expires <= created + 300:
        raise NativeStackOperationError("native_stack_action_plan_lifetime_invalid")
    if require_fresh and (now if now is not None else int(time.time())) >= expires:
        raise NativeStackOperationError("native_stack_action_plan_expired")

    identity = _exact(plan["identity"], PLAN_IDENTITY_FIELDS, "action_plan_identity")
    for field in (
        "stack_id",
        "vendor_id",
        "harness_id",
        "harness_adapter_id",
        "authentication_mode",
        "credential_custody",
        "program_id",
        "program_tier",
        "program_requirements_version",
        "network_policy_id",
    ):
        if (
            not isinstance(identity[field], str)
            or native_vendor_stack.IDENTIFIER.fullmatch(identity[field]) is None
        ):
            raise NativeStackOperationError(f"native_stack_action_plan_{field}_invalid")
    for field in ("stack_sha256", "model_settings_sha256"):
        _digest(identity[field], f"action_plan_{field}")
    for field in ("harness_generation_id", "account_subject_sha256", "workspace_sha256"):
        _digest(identity[field], f"action_plan_{field}", optional=True)
    if (
        not isinstance(identity["model_id"], str)
        or native_vendor_stack.MODEL_ID.fullmatch(identity["model_id"]) is None
    ):
        raise NativeStackOperationError("native_stack_action_plan_model_id_invalid")
    _digest(plan["current_status_sha256"], "action_plan_status_sha256")
    for field in ("observed_account_subject_sha256", "observed_workspace_sha256"):
        _digest(plan[field], f"action_plan_{field}", optional=True)
    if (plan["observed_account_subject_sha256"] is None) != (
        plan["observed_workspace_sha256"] is None
    ):
        raise NativeStackOperationError("native_stack_action_plan_observed_binding_incomplete")
    if action == "binding-commit":
        if plan["observed_account_subject_sha256"] is None:
            raise NativeStackOperationError("native_stack_action_plan_observed_binding_missing")
    elif plan["observed_account_subject_sha256"] is not None:
        raise NativeStackOperationError("native_stack_action_plan_observed_binding_unexpected")

    if plan["requested_network_phase"] != ACTION_PHASE[action]:
        raise NativeStackOperationError("native_stack_action_plan_network_phase_invalid")
    impact = _exact(
        plan["impact"],
        {"stops_bound_runs", "destroys_credentials", "changes_live_authority"},
        "action_plan_impact",
    )
    for field in impact:
        _bool(impact[field], f"action_plan_impact_{field}")
    expected_impact = {
        "stops_bound_runs": action in {
            "binding-commit", "rollback", "logout", "credential-destroy", "recover"
        },
        "destroys_credentials": action == "credential-destroy",
        "changes_live_authority": action in {
            "signin-begin", "binding-commit", "activate", "rollback", "logout",
            "credential-destroy", "recover"
        },
    }
    if impact != expected_impact:
        raise NativeStackOperationError("native_stack_action_plan_impact_mismatch")

    body = {key: plan[key] for key in plan if key not in {"schema", "plan_sha256"}}
    supplied = _digest(plan["plan_sha256"], "action_plan_digest")
    if not hmac.compare_digest(str(supplied), sha256(body)):
        raise NativeStackOperationError("native_stack_action_plan_digest_mismatch")
    return plan


def make_plan(
    *,
    stack: object,
    status: object,
    action: str,
    observed_account_subject_sha256: str | None = None,
    observed_workspace_sha256: str | None = None,
    created_at: int | None = None,
    action_id: str | None = None,
) -> dict[str, Any]:
    validated_stack = native_vendor_stack.validate_stack(stack)
    validated_status = validate_status(status)
    if (
        validated_status["stack_id"] != validated_stack["stack_id"]
        or validated_status["stack_sha256"] != native_vendor_stack.stack_revision(validated_stack)
    ):
        raise NativeStackOperationError("native_stack_action_plan_status_mismatch")
    _choice(action, ACTIONS, "action_plan_action")
    timestamp = int(time.time()) if created_at is None else created_at
    body = {
        "action_id": str(uuid.uuid4()) if action_id is None else action_id,
        "action": action,
        "created_at": timestamp,
        "expires_at": timestamp + 300,
        "identity": _stack_plan_identity(validated_stack),
        "current_status_sha256": validated_status["status_sha256"],
        "observed_account_subject_sha256": observed_account_subject_sha256,
        "observed_workspace_sha256": observed_workspace_sha256,
        "requested_network_phase": ACTION_PHASE[action],
        "impact": {
            "stops_bound_runs": action in {
                "binding-commit", "rollback", "logout", "credential-destroy", "recover"
            },
            "destroys_credentials": action == "credential-destroy",
            "changes_live_authority": action in {
                "signin-begin", "binding-commit", "activate", "rollback", "logout",
                "credential-destroy", "recover"
            },
        },
    }
    return validate_plan({"schema": PLAN_SCHEMA, **body, "plan_sha256": sha256(body)})


def validate_receipt(value: object) -> dict[str, Any]:
    receipt = _exact(
        value,
        {
            "schema",
            "action_id",
            "action",
            "plan_sha256",
            "completed_at",
            "result",
            "status_sha256",
            "evidence_sha256",
            "receipt_sha256",
        },
        "action_receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise NativeStackOperationError("native_stack_action_receipt_schema_invalid")
    _uuid4(receipt["action_id"], "action_receipt_id")
    _choice(receipt["action"], ACTIONS, "action_receipt_action")
    _digest(receipt["plan_sha256"], "action_receipt_plan_sha256")
    _integer(receipt["completed_at"], "action_receipt_completed_at", 1)
    _choice(receipt["result"], RECEIPT_RESULTS, "action_receipt_result")
    _digest(receipt["status_sha256"], "action_receipt_status_sha256")
    _digest(receipt["evidence_sha256"], "action_receipt_evidence_sha256")
    body = {key: receipt[key] for key in receipt if key not in {"schema", "receipt_sha256"}}
    supplied = _digest(receipt["receipt_sha256"], "action_receipt_digest")
    if not hmac.compare_digest(str(supplied), sha256(body)):
        raise NativeStackOperationError("native_stack_action_receipt_digest_mismatch")
    return receipt


def make_receipt(
    *,
    plan: object,
    status: object,
    result: str,
    evidence_sha256: str,
    completed_at: int | None = None,
) -> dict[str, Any]:
    validated_plan = validate_plan(plan)
    validated_status = validate_status(status)
    body = {
        "action_id": validated_plan["action_id"],
        "action": validated_plan["action"],
        "plan_sha256": validated_plan["plan_sha256"],
        "completed_at": int(time.time()) if completed_at is None else completed_at,
        "result": result,
        "status_sha256": validated_status["status_sha256"],
        "evidence_sha256": evidence_sha256,
    }
    return validate_receipt(
        {"schema": RECEIPT_SCHEMA, **body, "receipt_sha256": sha256(body)}
    )
