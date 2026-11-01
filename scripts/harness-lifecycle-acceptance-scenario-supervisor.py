#!/usr/bin/env python3
"""Fixed Host supervisor for Research runtime and management scenarios."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import canonical, digest  # noqa: E402
from harness_lifecycle_acceptance_interactive import make_plan  # noqa: E402
from harness_lifecycle_acceptance_scenarios import (  # noqa: E402
    MANAGEMENT_CASES,
    OPERATION,
    RUNTIME_CASES,
    TOUCH_ID_CASES,
    ScenarioError,
    initial_state,
    validate_result,
    validate_state,
)


PROTECTED_RELEASES = Path(
    "/usr/local/libexec/secure-sandbox-harness-acceptance/releases"
)
REMOTE_RELEASE_ROOT = Path(
    "/usr/local/libexec/secure-sandbox/harness-lifecycle-acceptance-scenarios"
)
REMOTE_STATE_ROOT = Path("/var/lib/secure-sandbox/harness-lifecycle-acceptance")
STATE_ROOT = Path("/var/db/SecureSandbox/harness-lifecycle-acceptance")
RECEIPT_ROOT = Path(
    "/usr/local/var/log/secure-sandbox/authorization-receipts"
)
DRIVER = {
    "runtime": "bound-session-runtime-fixture",
    "management": "protected-management-fixture",
}
REMOTE_FILES = {
    "harness-lifecycle-acceptance-scenario-research.py":
        "scripts/harness-lifecycle-acceptance-scenario-research.py",
    "harness_lifecycle_acceptance.py": "shared/harness_lifecycle_acceptance.py",
    "harness_lifecycle_acceptance_interactive.py":
        "shared/harness_lifecycle_acceptance_interactive.py",
    "harness_lifecycle_acceptance_scenarios.py":
        "shared/harness_lifecycle_acceptance_scenarios.py",
    "harness_generation_store.py": "shared/harness_generation_store.py",
    "harness_runtime_binding.py": "shared/harness_runtime_binding.py",
    "privileged_workflow.py": "shared/privileged_workflow.py",
    "install-harness-lifecycle-acceptance-scenarios.sh":
        "scripts/install-harness-lifecycle-acceptance-scenarios.sh",
}


class ScenarioSupervisorError(RuntimeError):
    """Stable failure for the protected Host scenario supervisor."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ScenarioSupervisorError("scenario_supervisor_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTH = load_script(
    "harness_lifecycle_acceptance_scenario_authorization",
    ROOT / "scripts/harness-lifecycle-acceptance-authorization.py",
)
COMMON = load_script(
    "harness_lifecycle_acceptance_scenario_common",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
ENROLLER = load_script(
    "harness_lifecycle_acceptance_scenario_enrollment",
    ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py",
)
ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_acceptance_scenario_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)


def _allowed(category: str) -> frozenset[str]:
    if category == "runtime":
        return RUNTIME_CASES
    if category == "management":
        return MANAGEMENT_CASES
    raise ScenarioSupervisorError("scenario_supervisor_category_invalid")


def production_scan(home: Path, environment: dict[str, str],
                    runner: Any = subprocess.run) -> dict[str, Any]:
    AUTH.trusted_directory(home, home.stat().st_uid, 0o700)
    present_environment = sorted(
        name for name in ENROLLER.PROVIDER_ENVIRONMENT if environment.get(name)
    )
    present_paths = sorted(
        relative for relative in (
            ".anthropic", ".claude", ".config/openai", ".config/gemini",
            ".gemini", ".aws/credentials", ".aws/config",
            ".config/gcloud/application_default_credentials.json",
            ".azure/accessTokens.json", ".config/op", ".config/gh/hosts.yml",
            ".netrc",
        ) if os.path.lexists(home / relative)
    )
    if present_environment or present_paths:
        raise ScenarioSupervisorError("scenario_production_material_present")
    try:
        ENROLLER.keychain_absent(runner)
    except (ENROLLER.AcceptanceError, OSError, subprocess.SubprocessError) as error:
        raise ScenarioSupervisorError("scenario_production_keychain_present") from error
    return {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-scenario-scan-v1",
        "status": "absent", "present_environment": [], "present_paths": [],
        "present_keychain_services": [],
    }


def stage_release(release: Path, campaign: dict[str, Any], stage: Path) -> list[Path]:
    files = []
    for name, relative in REMOTE_FILES.items():
        source = release / relative
        executable = relative.startswith("scripts/")
        payload = ACCEPTANCE_CLI._protected_file(
            source, 0, 0o555 if executable else 0o444,
        )
        destination = stage / name
        destination.write_bytes(payload)
        destination.chmod(0o700 if executable else 0o600)
        files.append(destination)
    campaign_path = stage / "campaign.json"
    campaign_path.write_bytes(canonical(campaign)); campaign_path.chmod(0o600)
    files.append(campaign_path)
    return files


def deploy(release: Path, campaign: dict[str, Any], destination: Path) -> None:
    for path in (COMMON.CONTROL_CLIENT, COMMON.SSH_CONFIG):
        COMMON.prerequisite(path, executable=path != COMMON.SSH_CONFIG)
    with tempfile.TemporaryDirectory(
            prefix=".scenario-deploy-", dir=destination) as temporary:
        stage = Path(temporary); stage.chmod(0o700)
        files = stage_release(release, campaign, stage)
        installer = stage / "install-harness-lifecycle-acceptance-scenarios.sh"
        argv = [
            str(COMMON.CONTROL_CLIENT), "client", "--ssh-config",
            str(COMMON.SSH_CONFIG), COMMON.RESEARCH_CONTROL, "deploy",
            installer.name, campaign["campaign_id"], campaign["source_commit"],
        ]
        for path in files:
            argv.extend(("--file", str(path)))
        result = COMMON.command(argv, timeout=120)
        expected = (f"harness-lifecycle-acceptance-scenarios:installed:"
                    f"{campaign['campaign_id']}:{campaign['source_commit']}\n").encode()
        if result.stdout != expected:
            raise ScenarioSupervisorError("scenario_deployment_invalid")


def run_research(campaign: dict[str, Any], case_id: str, category: str,
                 plan: dict[str, Any] | None,
                 authorization: dict[str, Any] | None) -> dict[str, Any]:
    release = REMOTE_RELEASE_ROOT / campaign["source_commit"]
    campaign_path = REMOTE_STATE_ROOT / campaign["campaign_id"] / "campaign.json"
    argv = [
        str(COMMON.SSH), "-F", str(COMMON.SSH_CONFIG), COMMON.RESEARCH_ADMIN,
        "/usr/bin/python3", "-I",
        str(release / "scripts/harness-lifecycle-acceptance-scenario-research.py"),
        "--campaign", str(campaign_path), "--case", case_id,
        "--category", category,
    ]
    if plan is not None and authorization is not None:
        argv.extend((
            "--plan-json", canonical(plan).decode("ascii"),
            "--authorization-json", canonical(authorization).decode("ascii"),
        ))
    result = COMMON.command(argv, timeout=90)
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScenarioSupervisorError("scenario_research_result_invalid") from error
    if canonical(value) != result.stdout:
        raise ScenarioSupervisorError("scenario_research_result_noncanonical")
    try:
        return validate_result(value, campaign, case_id)
    except ScenarioError as error:
        raise ScenarioSupervisorError("scenario_research_result_invalid") from error


def _state_path(root: Path, campaign: dict[str, Any], category: str,
                case_id: str) -> Path:
    return root / campaign["campaign_id"] / "interactive" / category / case_id


def prepare(category: str, case_id: str, operator_uid: int, *,
            root: Path = STATE_ROOT, uid: int = 0, now: int | None = None,
            deployer: Callable[[Path, dict[str, Any], Path], None] = deploy,
            scanner: Callable[[Path, dict[str, str]], dict[str, Any]] = production_scan,
            environment: dict[str, str] | None = None) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    if case_id not in _allowed(category):
        raise ScenarioSupervisorError("scenario_supervisor_case_invalid")
    campaign = AUTH.protected_context(
        case_id, operator_uid, current_time, uid,
        driver=DRIVER[category], category=category,
    )
    release = PROTECTED_RELEASES / campaign["source_commit"]
    home = Path(AUTH.pwd.getpwuid(operator_uid).pw_dir)
    scan = scanner(home, dict(os.environ) if environment is None else environment)
    if (not isinstance(scan, dict) or set(scan) != {
            "schema", "status", "present_environment", "present_paths",
            "present_keychain_services"}
            or scan.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-scenario-scan-v1"
            or scan.get("status") != "absent"
            or any(scan.get(name) != [] for name in (
                "present_environment", "present_paths", "present_keychain_services"))):
        raise ScenarioSupervisorError("scenario_production_scan_invalid")
    campaign_root = root / campaign["campaign_id"]
    AUTH.create_directory(campaign_root, uid, 0o700)
    interactive = campaign_root / "interactive"; AUTH.create_directory(interactive, uid, 0o700)
    category_root = interactive / category; AUTH.create_directory(category_root, uid, 0o700)
    state_path = category_root / case_id
    if os.path.lexists(state_path):
        raise ScenarioSupervisorError("scenario_case_already_prepared")
    AUTH.create_directory(state_path, uid, 0o700)
    before = initial_state(campaign, case_id, now=current_time)
    plan = None
    if case_id in TOUCH_ID_CASES:
        plan = make_plan(
            campaign, case_id, OPERATION[case_id], before["target_generation_id"],
            operator_uid, current_time,
        )
    AUTH.atomic_replace(state_path / "campaign.json", campaign, uid, 0o400)
    AUTH.atomic_replace(state_path / "state-before.json", before, uid, 0o400)
    AUTH.atomic_replace(state_path / "production-scan.json", scan, uid, 0o400)
    if plan is not None:
        AUTH.atomic_replace(state_path / "plan.json", plan, uid, 0o400)
    value = {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-scenario-prepared-v1",
        "status": "reserved", "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"], "category": category,
        "case_id": case_id, "operator_uid": operator_uid,
        "state_sha256": before["state_sha256"], "plan": plan,
        "production_scan_sha256": digest(scan), "candidate_authority": "none",
        "production_material_used": False, "production_store_access": False,
        "research_deployment": "pending",
    }
    value["prepared_sha256"] = digest(value)
    AUTH.atomic_replace(state_path / "prepared.json", value, uid, 0o400)
    try:
        deployer(release, campaign, state_path)
    except BaseException as error:
        failure = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-scenario-failure-v1",
            "status": "failed-closed", "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "source_commit": campaign["source_commit"], "category": category,
            "case_id": case_id, "phase": "research-deployment",
            "error_class_sha256": hashlib.sha256(
                type(error).__name__.encode("ascii")
            ).hexdigest(),
            "candidate_authority": "none", "production_material_used": False,
            "production_store_access": False,
        }
        failure["failure_sha256"] = digest(failure)
        AUTH.publish_exact(state_path / "failure.json", failure, uid, 0o400)
        raise
    value["status"] = "prepared"; value["research_deployment"] = "installed"
    value["prepared_sha256"] = digest({
        name: item for name, item in value.items() if name != "prepared_sha256"
    })
    AUTH.atomic_replace(state_path / "prepared.json", value, uid, 0o400)
    return value


def execute(category: str, case_id: str, operator_uid: int, *,
            plan: dict[str, Any] | None = None,
            authorization: dict[str, Any] | None = None,
            root: Path = STATE_ROOT, uid: int = 0, now: int | None = None,
            research_runner: Callable[[dict[str, Any], str, str,
                                       dict[str, Any] | None,
                                       dict[str, Any] | None], dict[str, Any]] = run_research) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    if case_id not in _allowed(category):
        raise ScenarioSupervisorError("scenario_supervisor_case_invalid")
    campaign = AUTH.protected_context(
        case_id, operator_uid, current_time, uid,
        driver=DRIVER[category], category=category,
    )
    state_path = _state_path(root, campaign, category, case_id)
    AUTH.trusted_directory(state_path, uid, 0o700)
    if os.path.lexists(state_path / "failure.json"):
        raise ScenarioSupervisorError("scenario_prior_failure_retained")
    stored_campaign = AUTH.trusted_json(state_path / "campaign.json", uid, 0o400)
    before = validate_state(
        AUTH.trusted_json(state_path / "state-before.json", uid, 0o400),
        campaign, case_id,
    )
    if stored_campaign != campaign:
        raise ScenarioSupervisorError("scenario_campaign_changed")
    scan = AUTH.trusted_json(state_path / "production-scan.json", uid, 0o400)
    prepared = AUTH.trusted_json(state_path / "prepared.json", uid, 0o400)
    expected_prepared = {
        "schema", "status", "campaign_id", "campaign_sha256", "source_commit",
        "category", "case_id", "operator_uid", "state_sha256", "plan",
        "production_scan_sha256", "candidate_authority",
        "production_material_used", "production_store_access",
        "research_deployment", "prepared_sha256",
    }
    if (set(prepared) != expected_prepared
            or prepared.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-scenario-prepared-v1"
            or prepared.get("status") != "prepared"
            or prepared.get("campaign_id") != campaign["campaign_id"]
            or prepared.get("campaign_sha256") != campaign["campaign_sha256"]
            or prepared.get("source_commit") != campaign["source_commit"]
            or prepared.get("category") != category
            or prepared.get("case_id") != case_id
            or prepared.get("operator_uid") != operator_uid
            or prepared.get("state_sha256") != before["state_sha256"]
            or prepared.get("production_scan_sha256") != digest(scan)
            or prepared.get("candidate_authority") != "none"
            or prepared.get("production_material_used") is not False
            or prepared.get("production_store_access") is not False
            or prepared.get("research_deployment") != "installed"
            or prepared.get("prepared_sha256") != digest({
                name: item for name, item in prepared.items()
                if name != "prepared_sha256"
            })):
        raise ScenarioSupervisorError("scenario_prepared_invalid")
    if case_id in TOUCH_ID_CASES:
        stored_plan = AUTH.trusted_json(state_path / "plan.json", uid, 0o400)
        if plan != stored_plan or prepared.get("plan") != stored_plan \
                or authorization is None:
            raise ScenarioSupervisorError("scenario_plan_changed")
        try:
            AUTH.generation_store.validate_authorization(
                authorization, stored_plan, current_time,
            )
        except AUTH.generation_store.GenerationStoreError as error:
            raise ScenarioSupervisorError(
                "scenario_authorization_invalid",
            ) from error
    elif prepared.get("plan") is not None or plan is not None or authorization is not None:
        raise ScenarioSupervisorError("scenario_authorization_forbidden")
    if authorization is not None:
        # Journal the exact broker-created authorization before crossing the
        # Host/Research boundary. A response-loss retry can then resume only
        # the same authorization; a second biometric grant cannot be silently
        # rebound to an already-published Research result.
        AUTH.publish_exact(
            state_path / "touchid-authorization.json", authorization, uid, 0o400,
        )
    result = research_runner(campaign, case_id, category, plan, authorization)
    if result["before_state_sha256"] != before["state_sha256"]:
        raise ScenarioSupervisorError("scenario_research_fixture_changed")
    AUTH.publish_exact(state_path / "research-result.json", result, uid, 0o400)
    return result


def validate_broker_receipt(receipt: object, campaign: dict[str, Any],
                            plan: dict[str, Any], result: dict[str, Any],
                            authorization: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "host_release_id", "acceptance_campaign_sha256", "acceptance_case_id",
        "acceptance_generation_id", "acceptance_operator_uid",
        "acceptance_plan_sha256", "acceptance_source_commit",
    }
    empty = hashlib.sha256(b"").hexdigest()
    if (not isinstance(receipt, dict) or set(receipt) != expected
            or receipt.get("schema")
               != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != authorization.get("authorization_id")
            or receipt.get("status") != "succeeded"
            or receipt.get("operation") != "harness-acceptance-authorize"
            or receipt.get("identity_evidence") != "operator-declared"
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("ceremony") != "approve"
            or receipt.get("resource")
               != "Disposable harness lifecycle acceptance plan"
            or receipt.get("exit_status") != 0
            or receipt.get("stdout_sha256")
               != hashlib.sha256(canonical(result)).hexdigest()
            or receipt.get("stderr_sha256") != empty
            or receipt.get("acceptance_campaign_sha256")
               != campaign["campaign_sha256"]
            or receipt.get("acceptance_case_id") != plan["case_id"]
            or receipt.get("acceptance_generation_id") != plan["generation_id"]
            or receipt.get("acceptance_operator_uid") != plan["operator_uid"]
            or receipt.get("acceptance_plan_sha256") != plan["plan_sha256"]
            or receipt.get("acceptance_source_commit") != campaign["source_commit"]
            or not isinstance(receipt.get("request_sha256"), str)
            or AUTH.generation_store.SHA256_RE.fullmatch(
                receipt["request_sha256"],
            ) is None
            or not isinstance(receipt.get("host_release_id"), str)
            or AUTH.generation_store.SHA256_RE.fullmatch(
                receipt["host_release_id"],
            ) is None
            or AUTH.UUID4.fullmatch(str(receipt.get("request_id", ""))) is None
            or not isinstance(receipt.get("started_at"), int)
            or isinstance(receipt.get("started_at"), bool)
            or not isinstance(receipt.get("completed_at"), int)
            or isinstance(receipt.get("completed_at"), bool)
            or receipt["completed_at"] < receipt["started_at"]
            or not plan["created_at"] <= receipt["started_at"] < plan["expires_at"]):
        raise ScenarioSupervisorError("scenario_broker_receipt_invalid")
    return receipt


def finalize(category: str, case_id: str, operator_uid: int, *,
             request_id: str | None = None, root: Path = STATE_ROOT,
             receipt_root: Path = RECEIPT_ROOT, uid: int = 0,
             now: int | None = None) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    campaign = AUTH.protected_context(
        case_id, operator_uid, current_time, uid,
        driver=DRIVER[category], category=category,
    )
    state_path = _state_path(root, campaign, category, case_id)
    AUTH.trusted_directory(state_path, uid, 0o700)
    before = validate_state(
        AUTH.trusted_json(state_path / "state-before.json", uid, 0o400),
        campaign, case_id,
    )
    result = validate_result(
        AUTH.trusted_json(state_path / "research-result.json", uid, 0o400),
        campaign, case_id,
    )
    if result["before_state_sha256"] != before["state_sha256"]:
        raise ScenarioSupervisorError("scenario_finalize_fixture_changed")
    receipt = None
    if case_id in TOUCH_ID_CASES:
        if request_id is None or AUTH.UUID4.fullmatch(request_id) is None:
            raise ScenarioSupervisorError("scenario_request_id_invalid")
        plan = AUTH.trusted_json(state_path / "plan.json", uid, 0o400)
        authorization = AUTH.trusted_json(
            state_path / "touchid-authorization.json", uid, 0o400,
        )
        try:
            validated_authorization = AUTH.generation_store.validate_authorization(
                authorization, plan, authorization.get("authorized_at"),
            )
        except (AUTH.generation_store.GenerationStoreError, TypeError) as error:
            raise ScenarioSupervisorError(
                "scenario_authorization_binding_invalid",
            ) from error
        if (validated_authorization.get("authorization_sha256")
                != result["authorization_sha256"]):
            raise ScenarioSupervisorError("scenario_authorization_binding_invalid")
        AUTH.trusted_directory(receipt_root, uid, 0o700)
        receipt = validate_broker_receipt(
            AUTH.trusted_json(receipt_root / f"{request_id}.json", uid, 0o600),
            campaign, plan, result, authorization,
        )
        AUTH.publish_exact(state_path / "broker-receipt.json", receipt, uid, 0o400)
    elif request_id is not None:
        raise ScenarioSupervisorError("scenario_request_id_forbidden")

    observed_at = current_time if receipt is None else receipt["completed_at"]
    if receipt is None:
        # Preserve the first durable timestamp across a response-loss retry.
        # Any substituted root-owned record still has to match the complete
        # deterministic projection below before publication can resume.
        for existing_name in (
                "finalized.json", "control-readback.json", "host-readback.json"):
            existing_path = state_path / existing_name
            if os.path.lexists(existing_path):
                prior = AUTH.trusted_json(existing_path, uid, 0o400)
                prior_time = prior.get("observed_at")
                if not isinstance(prior_time, int) or isinstance(prior_time, bool):
                    raise ScenarioSupervisorError("scenario_observed_at_invalid")
                observed_at = prior_time
                break
    host_readback = {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-host-scenario-readback-v1",
        "status": result["status"], "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"], "case_id": case_id,
        "procedure_sha256": result["procedure_sha256"],
        "research_result_sha256": result["result_sha256"],
        "evidence": result["evidence"], "observed_at": observed_at,
        "candidate_authority": "none", "production_material_used": False,
        "production_store_access": False, "lifecycle_mutation_performed": False,
    }
    host_readback["readback_sha256"] = digest(host_readback)
    control_readback = {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-control-scenario-readback-v1",
        "status": result["status"], "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"], "case_id": case_id,
        "research_result_sha256": result["result_sha256"],
        "before_state_sha256": before["state_sha256"],
        "after_state_sha256": result["after_state"]["state_sha256"],
        "broker_receipt_sha256": None if receipt is None else digest(receipt),
        "observed_at": observed_at, "candidate_authority": "none",
        "production_material_used": False, "production_store_access": False,
        "lifecycle_mutation_performed": False,
    }
    control_readback["readback_sha256"] = digest(control_readback)
    AUTH.publish_exact(state_path / "host-readback.json", host_readback, uid, 0o400)
    AUTH.publish_exact(
        state_path / "control-readback.json", control_readback, uid, 0o400,
    )
    value = {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-scenario-finalized-v1",
        "status": "verified", "outcome": result["outcome"],
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"], "category": category,
        "case_id": case_id, "result_sha256": result["result_sha256"],
        "host_readback_sha256": host_readback["readback_sha256"],
        "control_readback_sha256": control_readback["readback_sha256"],
        "broker_receipt_sha256": None if receipt is None else digest(receipt),
        "observed_at": observed_at, "candidate_authority": "none",
        "production_material_used": False, "production_store_access": False,
        "lifecycle_mutation_performed": False,
    }
    value["finalized_sha256"] = digest(value)
    AUTH.publish_exact(state_path / "finalized.json", value, uid, 0o400)
    return value
