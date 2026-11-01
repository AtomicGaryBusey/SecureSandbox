#!/usr/bin/env python3
"""Acceptance-only interactive plan consumer with no production authority."""

from __future__ import annotations

import re
import uuid
from typing import Any

import harness_generation_store as store_module
from harness_lifecycle_acceptance import (
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    case_record,
    digest,
    validate_campaign,
)


PLAN_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-interactive-plan-v1"
RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-interactive-result-v1"
LEDGER_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-authorization-ledger-v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
INTERACTIVE_CATEGORIES = frozenset({"authorization", "runtime", "management"})
INTERACTIVE_OPERATIONS = frozenset({
    "authorize", "migrate", "rollback", "retire", "reclaim", "revoke", "contain",
})


class InteractiveAcceptanceError(RuntimeError):
    """Stable failure for the non-authorizing interactive acceptance core."""


def canonical_bytes(value: object) -> bytes:
    try:
        return canonical(value)
    except AcceptanceError as error:
        raise InteractiveAcceptanceError("interactive_value_invalid") from error


def uuid4(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise InteractiveAcceptanceError(f"{label}_invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise InteractiveAcceptanceError(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise InteractiveAcceptanceError(f"{label}_invalid")
    return value


def sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise InteractiveAcceptanceError(f"{label}_invalid")
    return value


def validate_plan(value: object, campaign: dict[str, Any], now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InteractiveAcceptanceError("interactive_plan_invalid")
    expected = {
        "schema", "plan_id", "transaction_id", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
        "category", "operation", "generation_id", "operator_uid", "created_at", "expires_at",
        "candidate_authority", "production_material_used", "production_store_access",
        "plan_sha256",
    }
    unsigned = {name: item for name, item in value.items() if name != "plan_sha256"}
    case_id = value.get("case_id")
    case = CASE_BY_ID.get(case_id) if isinstance(case_id, str) else None
    if (set(value) != expected or value.get("schema") != PLAN_SCHEMA
            or case is None or case.category not in INTERACTIVE_CATEGORIES
            or value.get("category") != case.category
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256") != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("procedure_sha256")
               != case_record(case)["procedure"]["procedure_sha256"]
            or value.get("operation") not in INTERACTIVE_OPERATIONS
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("production_store_access") is not False
            or value.get("plan_sha256") != digest(unsigned)):
        raise InteractiveAcceptanceError("interactive_plan_invalid")
    uuid4(value.get("plan_id"), "plan_id")
    uuid4(value.get("transaction_id"), "transaction_id")
    sha256(value.get("generation_id"), "generation_id")
    created = value.get("created_at"); expires = value.get("expires_at")
    operator_uid = value.get("operator_uid")
    if (not isinstance(operator_uid, int) or isinstance(operator_uid, bool)
            or not 1 <= operator_uid < 2 ** 31):
        raise InteractiveAcceptanceError("interactive_operator_uid_invalid")
    if (not isinstance(created, int) or isinstance(created, bool)
            or not isinstance(expires, int) or isinstance(expires, bool)
            or created > now + 300 or not now < expires <= created + 300):
        raise InteractiveAcceptanceError("interactive_plan_time_invalid")
    return value


def make_plan(campaign: dict[str, Any], case_id: str, operation: str,
              generation_id: str, operator_uid: int, now: int, *, plan_id: str | None = None,
              transaction_id: str | None = None, lifetime: int = 300) -> dict[str, Any]:
    validated = validate_campaign(campaign, now)
    case = CASE_BY_ID.get(case_id)
    if case is None or case.category not in INTERACTIVE_CATEGORIES:
        raise InteractiveAcceptanceError("interactive_case_invalid")
    if operation not in INTERACTIVE_OPERATIONS:
        raise InteractiveAcceptanceError("interactive_operation_invalid")
    if not isinstance(lifetime, int) or isinstance(lifetime, bool) or not 1 <= lifetime <= 300:
        raise InteractiveAcceptanceError("interactive_plan_lifetime_invalid")
    sha256(generation_id, "generation_id")
    procedure = case_record(case)["procedure"]
    value = {
        "schema": PLAN_SCHEMA,
        "plan_id": plan_id or str(uuid.uuid4()),
        "transaction_id": transaction_id or str(uuid.uuid4()),
        "campaign_id": validated["campaign_id"],
        "campaign_sha256": validated["campaign_sha256"],
        "machine_identity_sha256": validated["machine_identity_sha256"],
        "source_commit": validated["source_commit"],
        "case_id": case_id, "procedure_sha256": procedure["procedure_sha256"],
        "category": case.category, "operation": operation,
        "generation_id": generation_id, "operator_uid": operator_uid,
        "created_at": now, "expires_at": now + lifetime,
        "candidate_authority": "none", "production_material_used": False,
        "production_store_access": False,
    }
    value["plan_sha256"] = digest(value)
    return validate_plan(value, validated, now)


def empty_ledger(campaign: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema": LEDGER_SCHEMA, "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"], "epoch": 0,
        "consumed_authorization_sha256": [],
    }
    value["ledger_sha256"] = digest(value)
    return value


def validate_ledger(value: object, campaign: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InteractiveAcceptanceError("interactive_ledger_invalid")
    expected = {
        "schema", "campaign_id", "campaign_sha256", "epoch",
        "consumed_authorization_sha256", "ledger_sha256",
    }
    unsigned = {name: item for name, item in value.items() if name != "ledger_sha256"}
    consumed = value.get("consumed_authorization_sha256")
    if (set(value) != expected or value.get("schema") != LEDGER_SCHEMA
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or not isinstance(value.get("epoch"), int) or isinstance(value["epoch"], bool)
            or value["epoch"] < 0 or not isinstance(consumed, list)
            or consumed != sorted(set(consumed))
            or any(not isinstance(item, str) or SHA256.fullmatch(item) is None
                   for item in consumed)
            or value.get("ledger_sha256") != digest(unsigned)):
        raise InteractiveAcceptanceError("interactive_ledger_invalid")
    return value


def consume(stored_plan: object, supplied_plan: object, authorization: object,
            ledger: object, campaign: dict[str, Any], now: int) -> tuple[
                dict[str, Any], dict[str, Any],
            ]:
    validated_campaign = validate_campaign(campaign, now)
    stored = validate_plan(stored_plan, validated_campaign, now)
    supplied = validate_plan(supplied_plan, validated_campaign, now)
    current_ledger = validate_ledger(ledger, validated_campaign)
    if canonical_bytes(stored) != canonical_bytes(supplied):
        raise InteractiveAcceptanceError("interactive_plan_changed")
    if not isinstance(authorization, dict):
        raise InteractiveAcceptanceError("interactive_authorization_invalid")
    try:
        accepted_authorization = store_module.validate_authorization(
            authorization, supplied, now,
        )
    except store_module.GenerationStoreError as error:
        raise InteractiveAcceptanceError("interactive_authorization_invalid") from error
    authorization_sha256 = accepted_authorization["authorization_sha256"]
    if authorization_sha256 in current_ledger["consumed_authorization_sha256"]:
        raise InteractiveAcceptanceError("interactive_authorization_replayed")
    consumed = sorted([
        *current_ledger["consumed_authorization_sha256"], authorization_sha256,
    ])
    next_ledger = {
        "schema": LEDGER_SCHEMA, "campaign_id": validated_campaign["campaign_id"],
        "campaign_sha256": validated_campaign["campaign_sha256"],
        "epoch": current_ledger["epoch"] + 1,
        "consumed_authorization_sha256": consumed,
    }
    next_ledger["ledger_sha256"] = digest(next_ledger)
    result = {
        "schema": RESULT_SCHEMA, "status": "authorized-for-acceptance-only",
        "campaign_id": validated_campaign["campaign_id"],
        "campaign_sha256": validated_campaign["campaign_sha256"],
        "machine_identity_sha256": validated_campaign["machine_identity_sha256"],
        "source_commit": validated_campaign["source_commit"],
        "case_id": supplied["case_id"], "plan_id": supplied["plan_id"],
        "plan_sha256": supplied["plan_sha256"],
        "transaction_id": supplied["transaction_id"],
        "operation": supplied["operation"], "generation_id": supplied["generation_id"],
        "operator_uid": supplied["operator_uid"],
        "authorization_sha256": authorization_sha256,
        "prior_ledger_sha256": current_ledger["ledger_sha256"],
        "ledger_sha256": next_ledger["ledger_sha256"],
        "candidate_authority": "none", "production_material_used": False,
        "production_store_access": False, "lifecycle_mutation_performed": False,
    }
    result["result_sha256"] = digest(result)
    return result, next_ledger
