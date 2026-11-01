#!/usr/bin/env python3
"""Project one finalized Touch ID acceptance case into fixed observations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_observation,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-authorization-projection-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-authorization-projection-error-v1"
MEDIA_TYPE = "application/json"


class AuthorizationProjectionError(RuntimeError):
    """Stable failure for fixed Touch ID acceptance projection."""


def load_script(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AuthorizationProjectionError("authorization_projection_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTH = load_script(
    "harness_lifecycle_acceptance_authorization_projection_driver",
    ROOT / "scripts/harness-lifecycle-acceptance-authorization.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_authorization_projection_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)


if __name__ == "__main__":
    AUTH.require_protected_main_path(Path(__file__), os.geteuid())


def finalized_artifacts(campaign: dict[str, Any], case_id: str,
                        root: Path, uid: int, *, now: int | None = None) -> tuple[
                            dict[str, Path], dict[str, bytes], dict[str, Any],
                        ]:
    case = CASE_BY_ID.get(case_id)
    if case is None or case.category != "authorization":
        raise AuthorizationProjectionError("authorization_projection_case_invalid")
    state = (root / campaign["campaign_id"] / "interactive"
             / "authorization" / case_id)
    AUTH.trusted_directory(state, uid, 0o700)
    names = {
        "campaign": "campaign.json", "stored-plan": "plan.json",
        "request-plan": "request-plan.json", "prepared": "prepared.json",
        "ledger": "ledger.json", "store-before": "store-before.json",
        "research-before": "research-before.json",
        "broker-receipt": "broker-receipt.json",
        "research-after": "research-after.json", "readback": "readback.json",
        "finalized": "finalized.json",
    }
    paths = {name: state / filename for name, filename in names.items()}
    values = {
        name: AUTH.trusted_json(path, uid, 0o600 if name == "ledger" else 0o400)
        for name, path in paths.items()
    }
    if values["campaign"] != campaign:
        raise AuthorizationProjectionError("authorization_projection_campaign_changed")
    stored = values["stored-plan"]; requested = values["request-plan"]
    current_time = int(time.time()) if now is None else now
    check_time = min(current_time, requested["expires_at"] - 1)
    try:
        AUTH.validate_plan(stored, campaign, check_time)
        AUTH.validate_plan(requested, campaign, check_time)
        ledger = AUTH.validate_ledger(values["ledger"], campaign)
    except (AcceptanceError, AUTH.InteractiveAcceptanceError) as error:
        raise AuthorizationProjectionError("authorization_projection_state_invalid") from error
    result_paths = list(state.glob("result-*.json"))
    expected_result = case_id in {"touchid-approve-exact-plan", "touchid-replay"}
    if len(result_paths) != (1 if expected_result else 0):
        raise AuthorizationProjectionError("authorization_projection_result_inventory_invalid")
    result = None; result_raw = None
    if result_paths:
        result = AUTH.validate_result(
            AUTH.trusted_json(result_paths[0], uid, 0o400), campaign, stored, ledger,
        )
        result_raw = canonical(result)
        paths["authorization-result"] = result_paths[0]
        values["authorization-result"] = result
    finalized = values["finalized"]
    expected_finalized = {
        "schema", "status", "outcome", "campaign_id", "campaign_sha256",
        "source_commit", "case_id", "procedure_sha256", "request_id",
        "request_plan_sha256", "stored_plan_sha256", "broker_receipt_sha256",
        "research_status_sha256", "isolated_store_sha256", "readback_sha256",
        "result_sha256", "candidate_authority", "production_material_used",
        "production_store_access", "lifecycle_mutation_performed", "observed_at",
        "finalized_sha256",
    }
    finalized_unsigned = {
        name: item for name, item in finalized.items() if name != "finalized_sha256"
    }
    readback = values["readback"]
    readback_unsigned = {
        name: item for name, item in readback.items() if name != "readback_sha256"
    }
    receipt = values["broker-receipt"]
    outcome = AUTH.validate_broker_receipt(
        receipt, campaign, requested, finalized.get("request_id"),
        result_raw if case_id == "touchid-approve-exact-plan" else None,
    )
    before = AUTH.validate_research_status(values["research-before"])
    after = AUTH.validate_research_status(values["research-after"])
    try:
        store_after = AUTH.validate_isolated_store(
            AUTH.isolated_store(root, campaign["campaign_id"], uid).inspect_status(),
        )
    except AUTH.generation_store.GenerationStoreError as error:
        raise AuthorizationProjectionError("authorization_projection_store_invalid") from error
    expected_kind = "plan-readback" if case.expected == "passed" else "selector-readback"
    expected_readback = ({
        "schema", "status", "kind", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
        "plan_id", "plan_sha256", "transaction_id", "generation_id",
        "operator_uid", "broker_receipt_sha256", "result_sha256",
        "isolated_store_sha256", "candidate_authority", "production_material_used",
        "production_store_access", "lifecycle_mutation_performed", "observed_at",
        "readback_sha256",
    } if case.expected == "passed" else {
        "schema", "status", "kind", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
        "request_plan_sha256", "expected_generation_id", "requested_generation_id",
        "research_before", "research_after", "selector_unchanged",
        "broker_receipt_sha256", "isolated_store_sha256", "candidate_authority",
        "production_material_used", "production_store_access",
        "lifecycle_mutation_performed", "observed_at", "readback_sha256",
    })
    if (set(finalized) != expected_finalized
            or set(readback) != expected_readback
            or finalized.get("schema")
            != "secure-sandbox-harness-lifecycle-acceptance-authorization-finalized-v1"
            or finalized.get("status") != "verified"
            or finalized.get("outcome") != outcome
            or finalized.get("campaign_id") != campaign["campaign_id"]
            or finalized.get("campaign_sha256") != campaign["campaign_sha256"]
            or finalized.get("source_commit") != campaign["source_commit"]
            or finalized.get("case_id") != case_id
            or finalized.get("procedure_sha256")
               != stored["procedure_sha256"]
            or finalized.get("request_plan_sha256") != requested["plan_sha256"]
            or finalized.get("stored_plan_sha256") != stored["plan_sha256"]
            or finalized.get("broker_receipt_sha256") != digest(receipt)
            or finalized.get("research_status_sha256") != digest(after)
            or finalized.get("isolated_store_sha256") != digest(store_after)
            or finalized.get("readback_sha256") != readback.get("readback_sha256")
            or finalized.get("result_sha256")
               != (None if result is None else result["result_sha256"])
            or finalized.get("candidate_authority") != "none"
            or finalized.get("production_material_used") is not False
            or finalized.get("production_store_access") is not False
            or finalized.get("lifecycle_mutation_performed") is not False
            or finalized.get("finalized_sha256") != digest(finalized_unsigned)
            or readback.get("kind") != expected_kind
            or readback.get("campaign_id") != campaign["campaign_id"]
            or readback.get("case_id") != case_id
            or readback.get("candidate_authority") != "none"
            or readback.get("production_material_used") is not False
            or readback.get("production_store_access") is not False
            or readback.get("lifecycle_mutation_performed") is not False
            or readback.get("readback_sha256") != digest(readback_unsigned)
            or before != after
            or values["store-before"] != store_after):
        raise AuthorizationProjectionError("authorization_projection_binding_invalid")
    if case.expected == "passed":
        if readback.get("status") != "verified":
            raise AuthorizationProjectionError("authorization_projection_readback_invalid")
    elif (readback.get("status") != "rejected"
          or readback.get("selector_unchanged") is not True
          or readback.get("research_before") != before
          or readback.get("research_after") != after):
        raise AuthorizationProjectionError("authorization_projection_readback_invalid")
    raw = {name: canonical(value) for name, value in values.items()}
    return paths, raw, finalized


def artifact_arguments(case_id: str, kind: str,
                       paths: dict[str, Path]) -> list[list[str]]:
    if kind in {"broker-receipt", "broker-rejection"}:
        names = ["broker-receipt", "finalized", "request-plan", "readback"]
        if "authorization-result" in paths:
            names.append("authorization-result")
        authorities = {
            "broker-receipt": "touchid-broker", "finalized": "privileged-control",
            "request-plan": "privileged-control",
            "readback": "privileged-control",
            "authorization-result": "privileged-control",
        }
    elif kind == "plan-readback":
        names = [
            "readback", "stored-plan", "request-plan", "broker-receipt",
            "authorization-result",
        ]
        authorities = {
            "readback": "privileged-control", "stored-plan": "privileged-control",
            "request-plan": "privileged-control", "broker-receipt": "touchid-broker",
            "authorization-result": "privileged-control",
        }
    elif kind == "selector-readback":
        names = [
            "research-after", "research-before", "readback", "broker-receipt",
            "finalized",
        ]
        authorities = {
            "research-after": "protected-research",
            "research-before": "protected-research",
            "readback": "privileged-control", "broker-receipt": "touchid-broker",
            "finalized": "privileged-control",
        }
    else:
        raise AuthorizationProjectionError("authorization_projection_kind_invalid")
    return [[name, authorities[name], str(paths[name]), MEDIA_TYPE] for name in names]


def existing_observation(path: Path, campaign: dict[str, Any], case_id: str,
                         kind: str, arguments: list[list[str]],
                         raw: dict[str, bytes]) -> str:
    try:
        payload = OBSERVER.trusted_read(path); value = json.loads(payload)
        validate_observation(value, campaign, CASE_BY_ID[case_id])
    except (AcceptanceError, OSError, UnicodeDecodeError,
            json.JSONDecodeError) as error:
        raise AuthorizationProjectionError(
            "authorization_existing_observation_invalid",
        ) from error
    artifacts = value.get("evidence", {}).get("artifacts", [])
    names = [item[0] for item in arguments]
    authorities = [item[1] for item in arguments]
    if (canonical(value) != payload or value.get("kind") != kind
            or [item.get("name") for item in artifacts] != names
            or any(item.get("authority") != authority
                   or item.get("sha256") != hashlib.sha256(raw[name]).hexdigest()
                   for item, name, authority in zip(artifacts, names, authorities))):
        raise AuthorizationProjectionError(
            "authorization_existing_observation_mismatch",
        )
    return value["observation_sha256"]


def project(case_id: str, operator_uid: int, *, root: Path = AUTH.STATE_ROOT,
            uid: int = 0, now: int | None = None) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    campaign = AUTH.protected_context(case_id, operator_uid, current_time, uid)
    home = Path(AUTH.pwd.getpwuid(operator_uid).pw_dir)
    observations = home / AUTH.CAMPAIGN_RELATIVE / "observations"
    AUTH.trusted_directory(observations, operator_uid, 0o700)
    paths, raw, finalized = finalized_artifacts(
        campaign, case_id, root, uid, now=current_time,
    )
    case = CASE_BY_ID[case_id]
    projected: dict[str, str] = {}; created: list[str] = []; resumed: list[str] = []
    with tempfile.TemporaryDirectory(
            prefix="secure-sandbox-authorization-projection.") as temporary:
        stage = Path(temporary); stage.chmod(0o700)
        for kind in case.evidence_kinds:
            arguments = artifact_arguments(case_id, kind, paths)
            destination = observations / f"{case_id}.{kind}.json"
            if os.path.lexists(destination):
                projected[kind] = existing_observation(
                    destination, campaign, case_id, kind, arguments, raw,
                )
                resumed.append(kind); continue
            observation = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=arguments, output_directory=stage,
                now=current_time, output_directory_uid=uid, output_mode=0o444,
            )
            staged = stage / destination.name
            OBSERVER.write_new(destination, observation, 0o444)
            staged.unlink()
            projected[kind] = observation["observation_sha256"]; created.append(kind)
    value = {
        "schema": SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "procedure_sha256": finalized["procedure_sha256"],
        "observation_sha256": {
            kind: projected[kind] for kind in case.evidence_kinds
        },
        "recorded_observation_kinds": created,
        "resumed_observation_kinds": resumed,
        "candidate_authority": "none", "production_material_used": False,
    }
    value["projection_sha256"] = digest(value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Project one fixed Touch ID acceptance case",
    )
    value.add_argument("--case", required=True)
    value.add_argument("--operator-uid", type=int, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if os.geteuid() != 0 or not 1 <= args.operator_uid < 2 ** 31:
        raise AuthorizationProjectionError("authorization_projection_root_required")
    result = project(args.case, args.operator_uid)
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, AuthorizationProjectionError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, AuthorizationProjectionError) \
            else "authorization_projection_failed"
        sys.stderr.buffer.write(canonical({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }))
        raise SystemExit(1)
