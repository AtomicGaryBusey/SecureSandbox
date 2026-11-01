#!/usr/bin/env python3
"""Acceptance-only runtime and management scenarios with no admission authority."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import harness_generation_store as generation_store
from harness_lifecycle_acceptance import (
    CASE_BY_ID,
    case_record,
    digest,
    validate_campaign,
)
from harness_lifecycle_acceptance_interactive import validate_plan
from harness_runtime_binding import make_binding, validate_binding


STATE_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-scenario-state-v1"
RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-scenario-result-v1"
RUNTIME_CASES = frozenset({
    "activate-future-session",
    "preserve-old-session-pinning",
    "legacy-session-fails-closed",
    "legacy-session-touchid-migration",
})
MANAGEMENT_CASES = frozenset({
    "rollback-explicit",
    "retire-zero-reference",
    "reject-retire-referenced",
    "reclaim-zero-reference",
    "revoke-generation",
    "emergency-containment",
})
SCENARIO_CASES = RUNTIME_CASES | MANAGEMENT_CASES
TOUCH_ID_CASES = frozenset(
    case_id for case_id in SCENARIO_CASES if CASE_BY_ID[case_id].requires_touch_id
)
OPERATION = {
    "legacy-session-touchid-migration": "migrate",
    "rollback-explicit": "rollback",
    "retire-zero-reference": "retire",
    "reject-retire-referenced": "retire",
    "revoke-generation": "revoke",
}


class ScenarioError(RuntimeError):
    """Stable rejection for isolated runtime and management scenarios."""


def _generation(campaign: dict[str, Any], case_id: str, role: str) -> str:
    return digest({
        "campaign_sha256": campaign["campaign_sha256"],
        "case_id": case_id,
        "role": role,
    })


def _session(campaign: dict[str, Any], case_id: str, role: str) -> str:
    # Session identifiers are evidence-only deterministic digests, not live IDs.
    return digest({
        "campaign_sha256": campaign["campaign_sha256"],
        "case_id": case_id,
        "role": role,
        "kind": "acceptance-session",
    })


def _binding(generation_id: str, role: str) -> dict[str, str]:
    return make_binding(
        harness_id="disposable-synthetic-harness",
        generation_id=generation_id,
        manifest_sha256=digest({"generation_id": generation_id, "kind": "manifest"}),
        executable_sha256=digest({"generation_id": generation_id, "kind": "executable"}),
        inventory_sha256=digest({"generation_id": generation_id, "kind": "inventory"}),
        adapter_id="claude-core-v1",
        adapter_sha256=digest({"generation_id": generation_id, "kind": role}),
    )


def _redigest(state: dict[str, Any]) -> dict[str, Any]:
    value = dict(state)
    value.pop("state_sha256", None)
    value["state_sha256"] = digest(value)
    return value


def initial_state(campaign: dict[str, Any], case_id: str, *, now: int) -> dict[str, Any]:
    campaign = validate_campaign(campaign, now)
    case = CASE_BY_ID.get(case_id)
    if case_id not in SCENARIO_CASES or case is None:
        raise ScenarioError("scenario_case_invalid")
    first = _generation(campaign, case_id, "generation-a")
    second = _generation(campaign, case_id, "generation-b")
    first_status = "active"
    second_status = "retained"
    active = first
    predecessor = None
    sessions: dict[str, dict[str, Any]] = {}
    target = second

    if case_id in {"preserve-old-session-pinning", "rollback-explicit"}:
        first_status = "retained"; second_status = "active"
        active = second; predecessor = first; target = first
    if case_id == "reclaim-zero-reference":
        second_status = "retired"
    old_session = _session(campaign, case_id, "old")
    legacy_session = _session(campaign, case_id, "legacy")
    if case_id == "preserve-old-session-pinning":
        sessions[old_session] = {
            "status": "resumable", "binding": _binding(first, "generation-a"),
        }
    elif case_id == "legacy-session-fails-closed":
        sessions[legacy_session] = {"status": "legacy", "binding": None}
    elif case_id == "legacy-session-touchid-migration":
        sessions[legacy_session] = {"status": "legacy", "binding": None}
        target = active
    elif case_id == "reject-retire-referenced":
        sessions[old_session] = {
            "status": "resumable", "binding": _binding(second, "generation-b"),
        }

    state = {
        "schema": STATE_SCHEMA,
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"],
        "case_id": case_id,
        "epoch": 0,
        "active_generation_id": active,
        "predecessor_generation_id": predecessor,
        "target_generation_id": target,
        "generations": [
            {
                "generation_id": first,
                "binding": _binding(first, "generation-a"),
                "status": first_status,
                "release_present": True,
                "evidence_retained": True,
            },
            {
                "generation_id": second,
                "binding": _binding(second, "generation-b"),
                "status": second_status,
                "release_present": True,
                "evidence_retained": True,
            },
        ],
        "sessions": sessions,
        "revoked_generation_ids": [],
        "containment": False,
        "candidate_authority": "none",
        "production_material_used": False,
        "production_store_access": False,
        "lifecycle_mutation_performed": False,
    }
    return validate_state(_redigest(state), campaign, case_id)


def validate_state(value: object, campaign: dict[str, Any], case_id: str) -> dict[str, Any]:
    expected = {
        "schema", "campaign_id", "campaign_sha256", "source_commit", "case_id",
        "epoch", "active_generation_id", "predecessor_generation_id",
        "target_generation_id", "generations", "sessions",
        "revoked_generation_ids", "containment", "candidate_authority",
        "production_material_used", "production_store_access",
        "lifecycle_mutation_performed", "state_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ScenarioError("scenario_state_invalid")
    unsigned = {name: item for name, item in value.items() if name != "state_sha256"}
    if (value.get("schema") != STATE_SCHEMA
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case_id
            or not isinstance(value.get("epoch"), int)
            or isinstance(value.get("epoch"), bool) or value["epoch"] < 0
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("production_store_access") is not False
            or value.get("lifecycle_mutation_performed") is not False
            or value.get("state_sha256") != digest(unsigned)):
        raise ScenarioError("scenario_state_invalid")
    generations = value.get("generations")
    if not isinstance(generations, list) or len(generations) != 2:
        raise ScenarioError("scenario_generation_inventory_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for record in generations:
        if (not isinstance(record, dict) or set(record) != {
                "generation_id", "binding", "status", "release_present",
                "evidence_retained"}):
            raise ScenarioError("scenario_generation_invalid")
        binding = validate_binding(record["binding"])
        generation_id = record.get("generation_id")
        if (binding["harness_generation_id"] != generation_id
                or generation_id in by_id
                or record.get("status") not in {"active", "retained", "retired", "revoked"}
                or not isinstance(record.get("release_present"), bool)
                or record.get("evidence_retained") is not True):
            raise ScenarioError("scenario_generation_invalid")
        by_id[generation_id] = record
    if value.get("target_generation_id") not in by_id:
        raise ScenarioError("scenario_target_invalid")
    active = value.get("active_generation_id")
    predecessor = value.get("predecessor_generation_id")
    if (active is not None and (active not in by_id or by_id[active]["status"] != "active")
            or predecessor is not None and (
                predecessor not in by_id or by_id[predecessor]["status"] != "retained")
            or active is not None and active == predecessor
            or sum(record["status"] == "active" for record in generations)
               != (0 if active is None else 1)):
        raise ScenarioError("scenario_selector_invalid")
    revoked = value.get("revoked_generation_ids")
    if (not isinstance(revoked, list) or revoked != sorted(set(revoked))
            or any(item not in by_id or by_id[item]["status"] != "revoked"
                   for item in revoked)):
        raise ScenarioError("scenario_floor_invalid")
    sessions = value.get("sessions")
    if not isinstance(sessions, dict):
        raise ScenarioError("scenario_sessions_invalid")
    for session_id, record in sessions.items():
        if (not isinstance(session_id, str) or not isinstance(record, dict)
                or set(record) != {"status", "binding"}
                or record.get("status") not in {"legacy", "resumable"}):
            raise ScenarioError("scenario_session_invalid")
        if record["status"] == "legacy":
            if record["binding"] is not None:
                raise ScenarioError("scenario_legacy_binding_invalid")
        elif validate_binding(record["binding"])["harness_generation_id"] not in by_id:
            raise ScenarioError("scenario_session_binding_invalid")
    if not isinstance(value.get("containment"), bool):
        raise ScenarioError("scenario_containment_invalid")
    return value


def _authorized(plan: object, authorization: object, campaign: dict[str, Any],
                case_id: str, state: dict[str, Any], now: int) -> dict[str, Any]:
    validated_plan = validate_plan(plan, campaign, now)
    if (validated_plan["case_id"] != case_id
            or validated_plan["category"] != CASE_BY_ID[case_id].category
            or validated_plan["operation"] != OPERATION[case_id]
            or validated_plan["generation_id"] != state["target_generation_id"]):
        raise ScenarioError("scenario_plan_binding_invalid")
    try:
        return generation_store.validate_authorization(
            authorization, validated_plan, now,
        )
    except generation_store.GenerationStoreError as error:
        raise ScenarioError("scenario_authorization_invalid") from error


def _replace_generation(state: dict[str, Any], generation_id: str,
                        **changes: object) -> None:
    for index, record in enumerate(state["generations"]):
        if record["generation_id"] == generation_id:
            state["generations"][index] = {**record, **changes}
            return
    raise ScenarioError("scenario_generation_missing")


def execute_case(campaign: dict[str, Any], case_id: str, raw_state: object, *,
                 plan: object | None = None, authorization: object | None = None,
                 now: int) -> dict[str, Any]:
    campaign = validate_campaign(campaign, now)
    before = validate_state(raw_state, campaign, case_id)
    state = deepcopy(before)
    auth_sha = None
    if case_id in TOUCH_ID_CASES:
        auth = _authorized(plan, authorization, campaign, case_id, state, now)
        auth_sha = auth["authorization_sha256"]
    elif plan is not None or authorization is not None:
        raise ScenarioError("scenario_unexpected_authorization")

    target = state["target_generation_id"]
    evidence: dict[str, Any] = {}
    outcome = CASE_BY_ID[case_id].expected
    if case_id == "activate-future-session":
        prior = state["active_generation_id"]
        _replace_generation(state, prior, status="retained")
        _replace_generation(state, target, status="active")
        state["active_generation_id"] = target
        state["predecessor_generation_id"] = prior
        session_id = _session(campaign, case_id, "future")
        binding = next(item["binding"] for item in state["generations"]
                       if item["generation_id"] == target)
        state["sessions"][session_id] = {"status": "resumable", "binding": binding}
        evidence = {"session_id": session_id, "binding": binding}
    elif case_id == "preserve-old-session-pinning":
        session_id, record = next(iter(state["sessions"].items()))
        evidence = {"session_id": session_id, "binding": record["binding"]}
    elif case_id == "legacy-session-fails-closed":
        session_id = next(iter(state["sessions"]))
        evidence = {"session_id": session_id, "error": "legacy_session_unbound"}
    elif case_id == "legacy-session-touchid-migration":
        session_id, record = next(iter(state["sessions"].items()))
        binding = next(item["binding"] for item in state["generations"]
                       if item["generation_id"] == target)
        record.update({"status": "resumable", "binding": binding})
        evidence = {"session_id": session_id, "binding": binding}
    elif case_id == "rollback-explicit":
        old_active = state["active_generation_id"]
        _replace_generation(state, old_active, status="retained")
        _replace_generation(state, target, status="active")
        state["active_generation_id"] = target
        state["predecessor_generation_id"] = old_active
        evidence = {"rolled_back_to": target}
    elif case_id in {"retire-zero-reference", "reject-retire-referenced"}:
        references = sum(
            record["binding"] is not None
            and record["binding"]["harness_generation_id"] == target
            for record in state["sessions"].values()
        )
        evidence = {"generation_id": target, "reference_count": references}
        if case_id == "retire-zero-reference":
            if references:
                raise ScenarioError("scenario_reference_count_changed")
            _replace_generation(state, target, status="retired")
        elif references == 0:
            raise ScenarioError("scenario_reference_fixture_invalid")
    elif case_id == "reclaim-zero-reference":
        record = next(item for item in state["generations"]
                      if item["generation_id"] == target)
        if record["status"] != "retired" or any(
                item["binding"] is not None
                and item["binding"]["harness_generation_id"] == target
                for item in state["sessions"].values()):
            raise ScenarioError("scenario_reclaim_precondition_invalid")
        _replace_generation(state, target, release_present=False)
        evidence = {"generation_id": target, "evidence_retained": True}
    elif case_id == "revoke-generation":
        _replace_generation(state, target, status="revoked")
        state["revoked_generation_ids"] = [target]
        if state["predecessor_generation_id"] == target:
            state["predecessor_generation_id"] = None
        evidence = {"generation_id": target, "runtime_denied": True}
    elif case_id == "emergency-containment":
        active = state["active_generation_id"]
        _replace_generation(state, active, status="retained")
        state["active_generation_id"] = None
        state["predecessor_generation_id"] = None
        state["containment"] = True
        evidence = {"contained_generation_id": active, "runtime_denied": True}
    else:
        raise ScenarioError("scenario_case_invalid")

    changed = state != before
    if outcome == "rejected" and changed:
        raise ScenarioError("scenario_rejection_mutated_state")
    if changed:
        state["epoch"] += 1
    after = validate_state(_redigest(state), campaign, case_id)
    value = {
        "schema": RESULT_SCHEMA,
        "status": "verified" if outcome == "passed" else "rejected",
        "outcome": outcome,
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"],
        "case_id": case_id,
        "procedure_sha256": case_record(CASE_BY_ID[case_id])["procedure"][
            "procedure_sha256"
        ],
        "before_state_sha256": before["state_sha256"],
        "after_state": after,
        "authorization_sha256": auth_sha,
        "evidence": evidence,
        "candidate_authority": "none",
        "production_material_used": False,
        "production_store_access": False,
        "lifecycle_mutation_performed": False,
    }
    value["result_sha256"] = digest(value)
    return validate_result(value, campaign, case_id)


def validate_result(value: object, campaign: dict[str, Any], case_id: str) -> dict[str, Any]:
    expected = {
        "schema", "status", "outcome", "campaign_id", "campaign_sha256",
        "source_commit", "case_id", "procedure_sha256", "before_state_sha256",
        "after_state", "authorization_sha256", "evidence", "candidate_authority",
        "production_material_used", "production_store_access",
        "lifecycle_mutation_performed", "result_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ScenarioError("scenario_result_invalid")
    case = CASE_BY_ID.get(case_id)
    unsigned = {name: item for name, item in value.items() if name != "result_sha256"}
    after = validate_state(value.get("after_state"), campaign, case_id)
    if (case_id not in SCENARIO_CASES or case is None
            or value.get("schema") != RESULT_SCHEMA
            or value.get("status") != (
                "verified" if case.expected == "passed" else "rejected")
            or value.get("outcome") != case.expected
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case_id
            or value.get("procedure_sha256")
               != case_record(case)["procedure"]["procedure_sha256"]
            or not isinstance(value.get("before_state_sha256"), str)
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("production_store_access") is not False
            or value.get("lifecycle_mutation_performed") is not False
            or not isinstance(value.get("evidence"), dict)
            or value.get("result_sha256") != digest(unsigned)):
        raise ScenarioError("scenario_result_invalid")
    if case.requires_touch_id:
        if (not isinstance(value.get("authorization_sha256"), str)
                or generation_store.SHA256_RE.fullmatch(
                    value["authorization_sha256"],
                ) is None):
            raise ScenarioError("scenario_result_authorization_invalid")
    elif value.get("authorization_sha256") is not None:
        raise ScenarioError("scenario_result_authorization_invalid")
    if case.expected == "rejected" and (
            value["before_state_sha256"] != after["state_sha256"]):
        raise ScenarioError("scenario_rejection_state_changed")
    return value
