#!/usr/bin/env python3
"""Project finalized runtime and management scenarios without changing authority."""

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
    AcceptanceError, CASE_BY_ID, canonical, digest, validate_observation,
)
from harness_lifecycle_acceptance_scenarios import (  # noqa: E402
    SCENARIO_CASES, ScenarioError, validate_result,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-scenario-projection-v1"
MEDIA_TYPE = "application/json"


class ScenarioProjectionError(RuntimeError):
    """Stable failure for a fixed scenario projection."""


def load_script(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ScenarioProjectionError("scenario_projection_module_unavailable")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_projection_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-scenario-supervisor.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_projection_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)


if __name__ == "__main__":
    SUPERVISOR.AUTH.require_protected_main_path(Path(__file__), os.geteuid())


def artifacts(kind: str, paths: dict[str, Path]) -> list[list[str]]:
    if kind == "broker-receipt":
        inventory = (("broker-receipt", "touchid-broker"),
                     ("research-result", "protected-research"),
                     ("control-readback", "privileged-control"))
    elif kind in {"session-binding", "session-rejection"}:
        inventory = (("host-readback", "protected-host"),
                     ("research-result", "protected-research"))
    elif kind in {"boundary-readback", "reference-rejection",
                  "containment-receipt"}:
        inventory = (("control-readback", "privileged-control"),
                     ("research-result", "protected-research"))
    else:
        inventory = (("research-result", "protected-research"),
                     ("control-readback", "privileged-control"))
    if any(name not in paths for name, _authority in inventory):
        raise ScenarioProjectionError("scenario_projection_artifact_missing")
    return [[name, authority, str(paths[name]), MEDIA_TYPE]
            for name, authority in inventory]


def existing(path: Path, campaign: dict[str, Any], case_id: str, kind: str,
             arguments: list[list[str]], raw: dict[str, bytes]) -> str:
    try:
        payload = OBSERVER.trusted_read(path); value = json.loads(payload)
        validate_observation(value, campaign, CASE_BY_ID[case_id])
    except (AcceptanceError, OSError, UnicodeDecodeError,
            json.JSONDecodeError) as error:
        raise ScenarioProjectionError("scenario_existing_observation_invalid") from error
    evidence = value.get("evidence", {}).get("artifacts", [])
    if (canonical(value) != payload or value.get("kind") != kind
            or [item.get("name") for item in evidence]
               != [item[0] for item in arguments]
            or any(item.get("authority") != authority
                   or item.get("sha256") != hashlib.sha256(raw[name]).hexdigest()
                   for item, (name, authority, _path, _media)
                   in zip(evidence, arguments))):
        raise ScenarioProjectionError("scenario_existing_observation_mismatch")
    return value["observation_sha256"]


def project(category: str, case_id: str, operator_uid: int, *,
            root: Path = SUPERVISOR.STATE_ROOT, uid: int = 0,
            now: int | None = None) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    if case_id not in SCENARIO_CASES or case_id not in SUPERVISOR._allowed(category):
        raise ScenarioProjectionError("scenario_projection_case_invalid")
    campaign = SUPERVISOR.AUTH.protected_context(
        case_id, operator_uid, current_time, uid,
        driver=SUPERVISOR.DRIVER[category], category=category,
    )
    state = SUPERVISOR._state_path(root, campaign, category, case_id)
    SUPERVISOR.AUTH.trusted_directory(state, uid, 0o700)
    paths = {
        "research-result": state / "research-result.json",
        "host-readback": state / "host-readback.json",
        "control-readback": state / "control-readback.json",
        "finalized": state / "finalized.json",
    }
    if case_id in SUPERVISOR.TOUCH_ID_CASES:
        paths["broker-receipt"] = state / "broker-receipt.json"
    values = {
        name: SUPERVISOR.AUTH.trusted_json(path, uid, 0o400)
        for name, path in paths.items()
    }
    result = validate_result(values["research-result"], campaign, case_id)
    finalized = values["finalized"]
    host_readback = values["host-readback"]
    control_readback = values["control-readback"]
    host_unsigned = {
        name: item for name, item in host_readback.items()
        if name != "readback_sha256"
    }
    control_unsigned = {
        name: item for name, item in control_readback.items()
        if name != "readback_sha256"
    }
    receipt_sha256 = (
        digest(values["broker-receipt"])
        if "broker-receipt" in values else None
    )
    if (finalized.get("schema")
            != "secure-sandbox-harness-lifecycle-acceptance-scenario-finalized-v1"
            or finalized.get("status") != "verified"
            or finalized.get("campaign_sha256") != campaign["campaign_sha256"]
            or finalized.get("case_id") != case_id
            or finalized.get("category") != category
            or finalized.get("result_sha256") != result["result_sha256"]
            or finalized.get("host_readback_sha256")
               != host_readback.get("readback_sha256")
            or finalized.get("control_readback_sha256")
               != control_readback.get("readback_sha256")
            or finalized.get("broker_receipt_sha256") != receipt_sha256
            or finalized.get("finalized_sha256") != digest({
                name: item for name, item in finalized.items()
                if name != "finalized_sha256"
            })
            or host_readback.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-host-scenario-readback-v1"
            or host_readback.get("status") != result["status"]
            or host_readback.get("campaign_id") != campaign["campaign_id"]
            or host_readback.get("campaign_sha256") != campaign["campaign_sha256"]
            or host_readback.get("source_commit") != campaign["source_commit"]
            or host_readback.get("case_id") != case_id
            or host_readback.get("procedure_sha256") != result["procedure_sha256"]
            or host_readback.get("research_result_sha256")
               != result["result_sha256"]
            or host_readback.get("evidence") != result["evidence"]
            or host_readback.get("candidate_authority") != "none"
            or host_readback.get("production_material_used") is not False
            or host_readback.get("production_store_access") is not False
            or host_readback.get("lifecycle_mutation_performed") is not False
            or host_readback.get("readback_sha256") != digest(host_unsigned)
            or control_readback.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-control-scenario-readback-v1"
            or control_readback.get("status") != result["status"]
            or control_readback.get("campaign_id") != campaign["campaign_id"]
            or control_readback.get("campaign_sha256") != campaign["campaign_sha256"]
            or control_readback.get("source_commit") != campaign["source_commit"]
            or control_readback.get("case_id") != case_id
            or control_readback.get("research_result_sha256")
               != result["result_sha256"]
            or control_readback.get("before_state_sha256")
               != result["before_state_sha256"]
            or control_readback.get("after_state_sha256")
               != result["after_state"]["state_sha256"]
            or control_readback.get("broker_receipt_sha256") != receipt_sha256
            or control_readback.get("candidate_authority") != "none"
            or control_readback.get("production_material_used") is not False
            or control_readback.get("production_store_access") is not False
            or control_readback.get("lifecycle_mutation_performed") is not False
            or control_readback.get("readback_sha256") != digest(control_unsigned)):
        raise ScenarioProjectionError("scenario_projection_finalized_invalid")
    raw = {name: canonical(value) for name, value in values.items()}
    home = Path(SUPERVISOR.AUTH.pwd.getpwuid(operator_uid).pw_dir)
    observations = home / SUPERVISOR.AUTH.CAMPAIGN_RELATIVE / "observations"
    SUPERVISOR.AUTH.trusted_directory(observations, operator_uid, 0o700)
    case = CASE_BY_ID[case_id]
    projected: dict[str, str] = {}; created: list[str] = []; resumed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="secure-sandbox-scenario-projection.") as tmp:
        stage = Path(tmp); stage.chmod(0o700)
        for kind in case.evidence_kinds:
            arguments = artifacts(kind, paths)
            destination = observations / f"{case_id}.{kind}.json"
            if os.path.lexists(destination):
                projected[kind] = existing(
                    destination, campaign, case_id, kind, arguments, raw,
                )
                resumed.append(kind); continue
            observation = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=arguments, output_directory=stage,
                now=current_time, output_directory_uid=uid, output_mode=0o444,
            )
            (stage / destination.name).unlink()
            OBSERVER.write_new(destination, observation, 0o444)
            projected[kind] = observation["observation_sha256"]; created.append(kind)
    value = {
        "schema": SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"], "category": category,
        "case_id": case_id,
        "observation_sha256": {kind: projected[kind]
                               for kind in case.evidence_kinds},
        "recorded_observation_kinds": created,
        "resumed_observation_kinds": resumed,
        "candidate_authority": "none", "production_material_used": False,
    }
    value["projection_sha256"] = digest(value)
    return value


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Project one lifecycle scenario")
    parser.add_argument("--category", choices=("runtime", "management"), required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--operator-uid", type=int, required=True)
    args = parser.parse_args(arguments)
    if os.geteuid() != 0 or not 1 <= args.operator_uid < 2 ** 31:
        raise ScenarioProjectionError("scenario_projection_root_required")
    sys.stdout.buffer.write(canonical(project(
        args.category, args.case, args.operator_uid,
    )))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, ScenarioError, ScenarioProjectionError,
            SUPERVISOR.ScenarioSupervisorError,
            SUPERVISOR.AUTH.AuthorizationDriverError,
            OSError, ValueError) as error:
        reason = str(error) if isinstance(error, ScenarioProjectionError) \
            else "scenario_projection_failed"
        sys.stderr.buffer.write(canonical({
            "schema": "secure-sandbox-harness-lifecycle-acceptance-scenario-projection-error-v1",
            "status": "rejected", "error": reason,
        }))
        raise SystemExit(1)
