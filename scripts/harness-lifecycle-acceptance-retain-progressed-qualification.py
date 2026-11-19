#!/usr/bin/env python3
"""Retain a progressed qualification campaign after a later control rejection."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASES,
    canonical,
    digest,
    validate_campaign,
)


def load_script(name: str, path: Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("retention_dependency_unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RETENTION = load_script(
    "progressed_qualification_retention_common",
    ROOT / "scripts/harness-lifecycle-acceptance-retain-empty-campaign.py",
)
ACCEPTANCE_CLI = load_script(
    "progressed_qualification_retention_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)

PLAN_SCHEMA = (
    "secure-sandbox-harness-lifecycle-progressed-qualification-rejection-"
    "retention-plan-v1"
)
RESULT_SCHEMA = (
    "secure-sandbox-harness-lifecycle-progressed-qualification-rejection-"
    "retention-v1"
)
FAILURE_SCHEMA = (
    "secure-sandbox-harness-lifecycle-progressed-qualification-rejection-v1"
)
ERROR_SCHEMA = (
    "secure-sandbox-harness-lifecycle-progressed-qualification-retention-error-v1"
)
ACKNOWLEDGEMENT = (
    "RETAIN PROGRESSED QUALIFICATION CONTROL REJECTION WITHOUT DELETION"
)
COMPLETED_CASE_ID = "qualification-no-preexecution"
RESERVED_CASE_ID = "qualification-zero-production-authority"
FAILURE_NAME = "control-rejection.json"
SUPERVISOR_ERROR = "supervisor_command_rejected"
CONTROL_ERROR = "status_1"
QUALIFICATION_RAW = {
    "research-result.json", "quarantine-readback.json",
    "authority-readback.json", "production-material-scan.json",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RESERVED_CASE_INDEX = next(
    index for index, case in enumerate(CASES)
    if case.case_id == RESERVED_CASE_ID
)
COMPLETED_CASE_COUNT = RESERVED_CASE_INDEX
COMPLETED_OBSERVATION_COUNT = sum(
    len(case.evidence_kinds) for case in CASES[:RESERVED_CASE_INDEX]
)
COMPLETED_BINDING_SCHEMA = (
    "secure-sandbox-progressed-qualification-completed-binding-v1"
)
COMPLETED_BINDING_PROGRAM = r'''\
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

release = Path(sys.argv[1])
campaign_path = Path(sys.argv[2])
observations = Path(sys.argv[3])
raw_directory = Path(sys.argv[4])
historical = int(sys.argv[5])
operator_uid = int(sys.argv[6])
case_id = sys.argv[7]
schema = sys.argv[8]
sys.path.insert(0, str(release / "shared"))
path = release / "scripts/harness-lifecycle-acceptance-qualification-observe.py"
specification = importlib.util.spec_from_file_location(
    "retained_completed_qualification_binding", path,
)
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)
campaign = module.validate_campaign(
    module.ACCEPTANCE_CLI.trusted_json(
        campaign_path, expected_uid=operator_uid,
    ), historical, allow_expired=True,
)
case = module.ACCEPTANCE_CLI.case_record(module.CASE_BY_ID[case_id])
_paths, _values, raw = module.raw_set(
    campaign, case, raw_directory, historical, expected_uid=operator_uid,
)
descriptor = os.open(observations, os.O_RDONLY | os.O_DIRECTORY)
try:
    observed = {
        kind: module.existing_observation_at(
            descriptor, f"{case_id}.{kind}.json",
            campaign, case, kind, raw,
        )
        for kind in case["evidence_kinds"]
    }
finally:
    os.close(descriptor)
value = {
    "schema": schema,
    "status": "verified",
    "campaign_id": campaign["campaign_id"],
    "source_commit": campaign["source_commit"],
    "case_id": case_id,
    "historical_observed_at": historical,
    "raw_sha256": {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in sorted(raw.items())
    },
    "observation_sha256": dict(sorted(observed.items())),
}
value["binding_sha256"] = module.digest(value)
sys.stdout.buffer.write(module.canonical(value))
'''


class ProgressedQualificationRetentionError(RuntimeError):
    """Stable fail-closed retention error."""


def verify_completed_binding(campaign: dict[str, Any], root: Path,
                             uid: int, now: int) -> str:
    raw_directory = root / "raw/qualification" / COMPLETED_CASE_ID
    try:
        historical = RETENTION.qualification_historical_raw_observed_at(
            raw_directory, uid, campaign, now,
        )
        release = (
            ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT / "releases"
            / campaign["source_commit"]
        )
        completed = subprocess.run(
            [
                "/usr/bin/python3", "-I", "-c", COMPLETED_BINDING_PROGRAM,
                str(release), str(root / "campaign.json"),
                str(root / "observations"), str(raw_directory),
                str(historical), str(uid), COMPLETED_CASE_ID,
                COMPLETED_BINDING_SCHEMA,
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd="/", timeout=45, check=False,
            env={
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, RETENTION.RetentionError,
            subprocess.SubprocessError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_completed_binding_failed",
        ) from error
    if (completed.returncode != 0 or completed.stderr or not completed.stdout
            or len(completed.stdout) > 128 * 1024):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_completed_binding_failed",
        )
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_completed_binding_failed",
        ) from error
    unsigned = {key: item for key, item in value.items()
                if key != "binding_sha256"} if isinstance(value, dict) else {}
    if (not isinstance(value, dict) or canonical(value) != completed.stdout
            or set(value) != {
                "schema", "status", "campaign_id", "source_commit",
                "case_id", "historical_observed_at", "raw_sha256",
                "observation_sha256", "binding_sha256",
            }
            or value.get("schema") != COMPLETED_BINDING_SCHEMA
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != COMPLETED_CASE_ID
            or value.get("historical_observed_at") != historical
            or value.get("binding_sha256") != digest(unsigned)):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_completed_binding_failed",
        )
    return value["binding_sha256"]


def trusted_external(path: Path, uid: int, *, canonical_json: bool) -> tuple[bytes, Any]:
    try:
        raw = RETENTION._trusted_file_bytes(
            path, uid, mode=0o600, maximum=128 * 1024,
        )
    except (RETENTION.RetentionError, OSError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_external_evidence_untrusted",
        ) from error
    if not canonical_json:
        return raw, None
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_external_evidence_invalid",
        ) from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_external_evidence_invalid",
        )
    return raw, value


def failure_record(campaign: dict[str, Any], supervisor_output: Path,
                   control_audit: Path, diagnostic_source: Path,
                   reviewed_diagnostic: bytes, uid: int,
                   now: int) -> dict[str, Any]:
    output_raw, _ = trusted_external(supervisor_output, uid, canonical_json=False)
    try:
        output_text = output_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_supervisor_output_invalid",
        ) from error
    if (not output_text.rstrip().endswith(
            "SupervisorError: supervisor_command_rejected")
            or '"status":"recorded"' in output_text):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_supervisor_output_invalid",
        )
    audit_raw, audit = trusted_external(control_audit, uid, canonical_json=True)
    try:
        diagnostic_raw = RETENTION._trusted_file_bytes(
            diagnostic_source, uid, mode=0o700, maximum=64 * 1024,
        )
    except (RETENTION.RetentionError, OSError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_diagnostic_source_untrusted",
        ) from error
    if diagnostic_raw != reviewed_diagnostic:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_diagnostic_source_mismatch",
        )
    expected_guards = {
        "/run/secure-sandbox/evidence-run-id": False,
        "/run/secure-sandbox/run-id": False,
        "/var/lib/secure-sandbox/run-lifecycle/active.json": False,
        "/var/lib/secure-sandbox/run-lifecycle/failure-latched.json": False,
    }
    tail = audit.get("control_audit_tail") if isinstance(audit, dict) else None
    audit_keys = {
        "authority", "campaign_id", "case_id", "claude_process_present",
        "control_audit_tail", "files", "fixture_inventory",
        "guard_path_presence", "installed_release_mismatches", "release",
        "research_campaign_match", "schema", "status",
    }
    if (set(audit) != audit_keys
            or audit.get("schema")
            != "secure-sandbox-qualification-research-diagnostic-v1"
            or audit.get("status") != "observed"
            or audit.get("authority") != "diagnostic-only"
            or audit.get("campaign_id") != campaign["campaign_id"]
            or audit.get("case_id") != RESERVED_CASE_ID
            or audit.get("release") != campaign["source_commit"]
            or audit.get("claude_process_present") is not False
            or audit.get("guard_path_presence") != expected_guards
            or audit.get("installed_release_mismatches") != []
            or audit.get("research_campaign_match") is not True
            or audit.get("fixture_inventory") != [COMPLETED_CASE_ID]
            or audit.get("files") != {}
            or not isinstance(tail, list)):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_control_audit_invalid",
        )
    audit_event_keys = {
        "timestamp", "outcome", "kind", "operation", "error", "request_id",
    }
    if any(
            not isinstance(item, dict) or set(item) != audit_event_keys
            or not isinstance(item.get("timestamp"), int)
            or isinstance(item.get("timestamp"), bool)
            or not isinstance(item.get("outcome"), str)
            or not isinstance(item.get("kind"), str)
            or not isinstance(item.get("operation"), str)
            or not isinstance(item.get("error"), str)
            or not isinstance(item.get("request_id"), str)
            for item in tail):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_control_audit_invalid",
        )
    operation = "install-harness-lifecycle-acceptance-qualification.sh"
    failed = [
        item for item in tail
        if isinstance(item, dict)
        and item.get("kind") == "deploy"
        and item.get("operation") == operation
        and item.get("outcome") == "command_failed"
        and item.get("error") == CONTROL_ERROR
    ]
    accepted = [
        item for item in tail
        if isinstance(item, dict)
        and item.get("kind") == "deploy"
        and item.get("operation") == operation
        and item.get("outcome") == "accepted"
        and item.get("error") == ""
    ]
    if len(failed) != 1 or not accepted:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_control_audit_invalid",
        )
    event = failed[0]
    timestamp = event.get("timestamp")
    request_id = event.get("request_id")
    if (not isinstance(timestamp, int) or isinstance(timestamp, bool)
            or not campaign["created_at"] <= timestamp < campaign["expires_at"]
            or timestamp > now
            or not isinstance(request_id, str)
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}", request_id,
            ) is None
            or max(item["timestamp"] for item in accepted) >= timestamp
            or not any(
                item["kind"] == "deploy"
                and item["operation"] == operation
                and item["outcome"] == "started"
                and item["error"] == ""
                and item["request_id"] == request_id
                and item["timestamp"] == timestamp
                for item in tail
            )):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_control_audit_invalid",
        )
    value = {
        "schema": FAILURE_SCHEMA,
        "status": "rejected",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"],
        "completed_case_id": COMPLETED_CASE_ID,
        "reserved_case_id": RESERVED_CASE_ID,
        "supervisor_error": SUPERVISOR_ERROR,
        "control_error": CONTROL_ERROR,
        "control_request_id": request_id,
        "observed_at": timestamp,
        "supervisor_output_sha256": hashlib.sha256(output_raw).hexdigest(),
        "supervisor_output_size": len(output_raw),
        "control_audit_sha256": hashlib.sha256(audit_raw).hexdigest(),
        "control_audit_size": len(audit_raw),
        "diagnostic_source_sha256": hashlib.sha256(diagnostic_raw).hexdigest(),
        "research_case_state": "absent-before-execution",
        "installed_release_match": True,
        "campaign_match": True,
        "active_run_markers_present": False,
        "claude_process_present": False,
        "retry_permitted": False,
        "candidate_authority": "none",
        "production_material_used": False,
    }
    value["rejection_sha256"] = digest(value)
    return value


def published_diagnostic_source(replacement: str) -> bytes:
    try:
        raw = RETENTION.PREFLIGHT.git_command(
            [
                "show",
                f"{replacement}:scripts/"
                "install-harness-lifecycle-acceptance-qualification-control-diagnostic.sh",
            ],
            cwd=ROOT,
        )
    except RETENTION.PREFLIGHT.PreflightError as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_diagnostic_source_unavailable",
        ) from error
    if not raw or len(raw) > 64 * 1024:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_diagnostic_source_unavailable",
        )
    return raw


def validate_failure(value: Any, campaign: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "source_commit", "completed_case_id", "reserved_case_id",
        "supervisor_error", "control_error", "control_request_id",
        "observed_at", "supervisor_output_sha256", "supervisor_output_size",
        "control_audit_sha256", "control_audit_size", "research_case_state",
        "diagnostic_source_sha256",
        "installed_release_match", "campaign_match",
        "active_run_markers_present", "claude_process_present",
        "retry_permitted", "candidate_authority", "production_material_used",
        "rejection_sha256",
    }
    unsigned = {key: item for key, item in value.items()
                if key != "rejection_sha256"} if isinstance(value, dict) else {}
    if (not isinstance(value, dict) or set(value) != expected
            or value.get("schema") != FAILURE_SCHEMA
            or value.get("status") != "rejected"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("completed_case_id") != COMPLETED_CASE_ID
            or value.get("reserved_case_id") != RESERVED_CASE_ID
            or value.get("supervisor_error") != SUPERVISOR_ERROR
            or value.get("control_error") != CONTROL_ERROR
            or value.get("research_case_state") != "absent-before-execution"
            or value.get("installed_release_match") is not True
            or value.get("campaign_match") is not True
            or value.get("active_run_markers_present") is not False
            or value.get("claude_process_present") is not False
            or value.get("retry_permitted") is not False
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or not isinstance(value.get("observed_at"), int)
            or isinstance(value.get("observed_at"), bool)
            or not campaign["created_at"] <= value["observed_at"] < campaign["expires_at"]
            or not isinstance(value.get("supervisor_output_size"), int)
            or isinstance(value.get("supervisor_output_size"), bool)
            or not 0 < value["supervisor_output_size"] <= 128 * 1024
            or not isinstance(value.get("control_audit_size"), int)
            or isinstance(value.get("control_audit_size"), bool)
            or not 0 < value["control_audit_size"] <= 128 * 1024
            or not isinstance(value.get("control_request_id"), str)
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                value.get("control_request_id", ""),
            ) is None
            or any(SHA256.fullmatch(str(value.get(name, ""))) is None for name in (
                "supervisor_output_sha256", "control_audit_sha256",
                "diagnostic_source_sha256",
            ))
            or value.get("rejection_sha256") != digest(unsigned)):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_failure_record_invalid",
        )
    return value


def validate_layout(root: Path, uid: int, *, protected_uid: int = 0
                    ) -> tuple[dict[str, Any], str, dict[str, Any]]:
    root_descriptor = RETENTION._directory(root, uid)
    try:
        entries = set(os.listdir(root_descriptor))
    finally:
        os.close(root_descriptor)
    if entries not in (
            RETENTION.EXPECTED_ROOT,
            RETENTION.EXPECTED_ROOT | {RETENTION.PLAN_NAME}):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_root_inventory_invalid",
        )
    campaign_raw = RETENTION._campaign_bytes(root, uid)
    try:
        campaign = validate_campaign(
            json.loads(campaign_raw), int(time.time()), allow_expired=True,
        )
    except (AcceptanceError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_campaign_invalid",
        ) from error
    if canonical(campaign) != campaign_raw:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_campaign_invalid",
        )
    completed_index = next(
        index for index, case in enumerate(CASES)
        if case.case_id == COMPLETED_CASE_ID
    )
    reserved_index = next(
        index for index, case in enumerate(CASES)
        if case.case_id == RESERVED_CASE_ID
    )
    if reserved_index != completed_index + 1:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_suite_order_invalid",
        )
    prior_cases = CASES[:reserved_index]
    observations = {
        f"{case.case_id}.{kind}.json"
        for case in prior_cases for kind in case.evidence_kinds
    }
    expected_directories = (
        (Path("observations"), observations),
        (Path("raw"), RETENTION.EXPECTED_RAW),
        (Path("raw/bootstrap"), {
            RETENTION.RESERVED_CASE_ID, RETENTION.HOME_REJECTION_CASE_ID,
        }),
        (Path("raw/bootstrap") / RETENTION.RESERVED_CASE_ID,
         set(RETENTION.OWNER_PROJECTION_RAW_FILES.values())),
        (Path("raw/bootstrap") / RETENTION.HOME_REJECTION_CASE_ID, {
            "machine-enrollment.json", "production-material-scan.json",
        }),
        (Path("raw/qualification"), {
            COMPLETED_CASE_ID, RESERVED_CASE_ID,
        }),
        (Path("raw/qualification") / COMPLETED_CASE_ID, QUALIFICATION_RAW),
        (Path("raw/qualification") / RESERVED_CASE_ID, {FAILURE_NAME}),
        (Path("raw/recovery"), set()),
    )
    for relative, expected in expected_directories:
        descriptor = RETENTION._directory(root / relative, uid)
        try:
            if set(os.listdir(descriptor)) != set(expected):
                raise ProgressedQualificationRetentionError(
                    "progressed_qualification_inventory_invalid",
                )
        finally:
            os.close(descriptor)
    try:
        next_value = ACCEPTANCE_CLI.next_case(
            campaign, root / "observations",
            observation_uid=protected_uid, directory_uid=uid,
        )
    except (AcceptanceError, OSError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_observations_invalid",
        ) from error
    if (next_value.get("status") != "pending"
            or next_value.get("case", {}).get("case_id") != RESERVED_CASE_ID):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_next_case_invalid",
        )
    completed_binding_sha256 = verify_completed_binding(
        campaign, root, uid, int(time.time()),
    )
    specs = [
        *[(Path("observations") / name, protected_uid, 0o444)
          for name in sorted(observations)],
        *[(Path("raw/bootstrap") / RETENTION.RESERVED_CASE_ID / name,
           uid, 0o600)
          for name in sorted(RETENTION.OWNER_PROJECTION_RAW_FILES.values())],
        *[(Path("raw/bootstrap") / RETENTION.HOME_REJECTION_CASE_ID / name,
           uid, 0o600)
          for name in ("machine-enrollment.json", "production-material-scan.json")],
        *[(Path("raw/qualification") / COMPLETED_CASE_ID / name, uid, 0o600)
          for name in sorted(QUALIFICATION_RAW)],
        (Path("raw/qualification") / RESERVED_CASE_ID / FAILURE_NAME,
         uid, 0o600),
    ]
    files = []
    failure = None
    for relative, owner, mode in specs:
        raw = RETENTION._trusted_file_bytes(
            root / relative, owner, mode=mode, maximum=128 * 1024,
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_json_invalid",
            ) from error
        if not isinstance(value, dict) or canonical(value) != raw:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_json_invalid",
            )
        if relative.name == FAILURE_NAME:
            failure = validate_failure(value, campaign)
        files.append({
            "path": str(relative), "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw), "mode": mode, "uid": owner,
        })
    if failure is None:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_failure_record_missing",
        )
    inventory = {
        "campaign_sha256": hashlib.sha256(campaign_raw).hexdigest(),
        "directories": sorted(str(relative) for relative, _ in expected_directories),
        "files": ["campaign.json", *sorted(files, key=lambda item: item["path"])],
        "completed_case_count": reserved_index,
        "completed_observation_count": len(observations),
        "completed_binding_sha256": completed_binding_sha256,
        "reserved_case_id": RESERVED_CASE_ID,
    }
    return campaign, digest(inventory), failure


def plan_value(campaign: dict[str, Any], inventory_sha256: str,
               failure: dict[str, Any], replacement: str,
               remote_tips: dict[str, str], uid: int, now: int) -> dict[str, Any]:
    value = {
        "schema": PLAN_SCHEMA, "status": "prepared",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "campaign_source_commit": campaign["source_commit"],
        "replacement_source_commit": replacement,
        "remote_tips": remote_tips,
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "operator_uid": uid,
        "reason": "later-qualification-control-rejected-before-execution",
        "observed_at": now,
        "inventory_sha256": inventory_sha256,
        "destination_name": campaign["campaign_id"],
        "completed_case_count": COMPLETED_CASE_COUNT,
        "completed_observation_count": COMPLETED_OBSERVATION_COUNT,
        "completed_case_id": COMPLETED_CASE_ID,
        "reserved_case_id": RESERVED_CASE_ID,
        "expected_error": SUPERVISOR_ERROR,
        "evidence_state": "protected-first-qualification-plus-later-control-rejection",
        "failure_record_sha256": failure["rejection_sha256"],
        "protected_host_state": "retained-in-place-by-campaign-id",
        "protected_research_state": "retained-in-place-by-campaign-id",
    }
    value["plan_sha256"] = digest(value)
    return value


def validate_plan(value: Any, campaign: dict[str, Any], inventory: str,
                  uid: int, replacement: str) -> dict[str, Any]:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "campaign_source_commit", "replacement_source_commit", "remote_tips",
        "machine_identity_sha256", "operator_uid", "reason", "observed_at",
        "inventory_sha256", "destination_name", "completed_case_count",
        "completed_observation_count", "completed_case_id", "reserved_case_id",
        "expected_error", "evidence_state", "failure_record_sha256",
        "protected_host_state", "protected_research_state", "plan_sha256",
    }
    unsigned = {key: item for key, item in value.items()
                if key != "plan_sha256"} if isinstance(value, dict) else {}
    if (not isinstance(value, dict) or set(value) != expected
            or value.get("schema") != PLAN_SCHEMA
            or value.get("status") != "prepared"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("campaign_source_commit") != campaign["source_commit"]
            or value.get("replacement_source_commit") != replacement
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("operator_uid") != uid
            or value.get("reason")
               != "later-qualification-control-rejected-before-execution"
            or value.get("inventory_sha256") != inventory
            or value.get("destination_name") != campaign["campaign_id"]
            or value.get("completed_case_count") != COMPLETED_CASE_COUNT
            or value.get("completed_observation_count")
               != COMPLETED_OBSERVATION_COUNT
            or value.get("completed_case_id") != COMPLETED_CASE_ID
            or value.get("reserved_case_id") != RESERVED_CASE_ID
            or value.get("expected_error") != SUPERVISOR_ERROR
            or value.get("evidence_state")
               != "protected-first-qualification-plus-later-control-rejection"
            or value.get("protected_host_state")
               != "retained-in-place-by-campaign-id"
            or value.get("protected_research_state")
               != "retained-in-place-by-campaign-id"
            or not isinstance(value.get("observed_at"), int)
            or isinstance(value.get("observed_at"), bool)
            or not campaign["created_at"] <= value["observed_at"] <= int(time.time())
            or SHA256.fullmatch(str(value.get("failure_record_sha256", ""))) is None
            or value.get("plan_sha256") != digest(unsigned)
            or not RETENTION._remote_tips_for(
                replacement, value.get("remote_tips"))):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_plan_invalid",
        )
    return value


def result_value(campaign: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema": RESULT_SCHEMA, "status": "retained",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "replacement_source_commit": plan["replacement_source_commit"],
        "plan_sha256": plan["plan_sha256"],
        "destination_name": campaign["campaign_id"],
        "completed_case_count": COMPLETED_CASE_COUNT,
        "completed_observation_count": COMPLETED_OBSERVATION_COUNT,
        "completed_case_id": COMPLETED_CASE_ID,
        "reserved_case_id": RESERVED_CASE_ID,
        "expected_error": SUPERVISOR_ERROR,
        "evidence_state": "protected-first-qualification-plus-later-control-rejection",
        "failure_record_sha256": plan["failure_record_sha256"],
        "protected_host_state": "retained-in-place-by-campaign-id",
        "protected_research_state": "retained-in-place-by-campaign-id",
        "authority": "retention-only",
    }
    value["result_sha256"] = digest(value)
    return value


def verify_retained(*, expected_campaign_id: str, expected_source_commit: str,
                    expected_replacement_commit: str, home: Path | None = None,
                    protected_uid: int = 0) -> dict[str, Any]:
    home = Path.home() if home is None else home
    uid = os.geteuid()
    destination = (
        home / RETENTION.RETAINED_RELATIVE / expected_campaign_id
    )
    campaign, inventory, failure = validate_layout(
        destination, uid, protected_uid=protected_uid,
    )
    if (campaign["campaign_id"] != expected_campaign_id
            or campaign["source_commit"] != expected_source_commit):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_expected_campaign_mismatch",
        )
    plan = RETENTION._trusted_canonical_record(
        destination / RETENTION.PLAN_NAME, uid, "retention_plan",
    )
    validate_plan(
        plan, campaign, inventory, uid, expected_replacement_commit,
    )
    if plan["failure_record_sha256"] != failure["rejection_sha256"]:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_failure_binding_invalid",
        )
    RETENTION._is_ancestor(
        campaign["source_commit"], expected_replacement_commit,
    )
    return result_value(campaign, plan)


def retain(*, expected_campaign_id: str, expected_source_commit: str,
           acknowledgement: str, supervisor_output: Path, control_audit: Path,
           diagnostic_source: Path,
           now: int | None = None, home: Path | None = None,
           protected_uid: int = 0,
           source_probe: Callable[[], tuple[str, dict[str, str]]] | None = None,
           identity_probe: Callable[[], str] | None = None,
           predecessor_probe: Callable[[str], str] | None = None,
           diagnostic_probe: Callable[[str], bytes] | None = None,
           rename: Callable[[int, str, int, str], None] = RETENTION._rename_exclusive,
           ) -> dict[str, Any]:
    if acknowledgement != ACKNOWLEDGEMENT:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_acknowledgement_required",
        )
    if platform.system() != "Darwin":
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_disposable_mac_required",
        )
    home = Path.home() if home is None else home
    uid = os.geteuid()
    root = home / RETENTION.CAMPAIGN_RELATIVE
    campaign_raw = RETENTION._campaign_bytes(root, uid)
    try:
        campaign = validate_campaign(
            json.loads(campaign_raw), int(time.time()), allow_expired=True,
        )
    except (AcceptanceError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_campaign_invalid",
        ) from error
    if (campaign["campaign_id"] != expected_campaign_id
            or campaign["source_commit"] != expected_source_commit):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_expected_campaign_mismatch",
        )
    source_probe = RETENTION.PREFLIGHT.source_checkout if source_probe is None else source_probe
    try:
        replacement, remote_tips = source_probe()
    except (RETENTION.PREFLIGHT.PreflightError, OSError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_source_preflight_failed",
        ) from error
    if replacement == campaign["source_commit"]:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_replacement_required",
        )
    RETENTION._is_ancestor(campaign["source_commit"], replacement)
    if not RETENTION._remote_tips_for(replacement, remote_tips):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_remote_tips_invalid",
        )
    identity_probe = (
        RETENTION.SUPERVISOR.current_machine_identity
        if identity_probe is None else identity_probe
    )
    try:
        machine_identity = identity_probe()
    except (RETENTION.SUPERVISOR.SupervisorError, OSError) as error:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_machine_identity_unavailable",
        ) from error
    if machine_identity != campaign["machine_identity_sha256"]:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_machine_identity_mismatch",
        )
    predecessor_probe = (
        RETENTION.verify_predecessor_driver_inventory
        if predecessor_probe is None else predecessor_probe
    )
    predecessor_probe(campaign["source_commit"])
    diagnostic_probe = (
        published_diagnostic_source if diagnostic_probe is None
        else diagnostic_probe
    )
    reviewed_diagnostic = diagnostic_probe(replacement)
    if not isinstance(reviewed_diagnostic, bytes):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_diagnostic_source_unavailable",
        )
    observed_at = int(time.time()) if now is None else now
    record = failure_record(
        campaign, supervisor_output, control_audit, diagnostic_source,
        reviewed_diagnostic, uid, observed_at,
    )
    reservation = root / "raw/qualification" / RESERVED_CASE_ID
    descriptor = RETENTION._directory(reservation, uid)
    try:
        entries = set(os.listdir(descriptor))
        if entries == set():
            RETENTION._write_new_at(descriptor, FAILURE_NAME, record)
        elif entries == {FAILURE_NAME}:
            existing = RETENTION._trusted_canonical_record(
                reservation / FAILURE_NAME, uid, "retention_failure_record",
            )
            if existing != record:
                raise ProgressedQualificationRetentionError(
                    "progressed_qualification_failure_record_mismatch",
                )
        else:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_reservation_not_empty",
            )
    finally:
        os.close(descriptor)
    campaign, inventory, retained_failure = validate_layout(
        root, uid, protected_uid=protected_uid,
    )
    if retained_failure != record:
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_failure_record_mismatch",
        )
    planned = plan_value(
        campaign, inventory, record, replacement, remote_tips, uid, observed_at,
    )
    source_parent = RETENTION._directory(
        root.parent, uid, frozenset({0o700, 0o755}),
    )
    root_descriptor = RETENTION._directory(root, uid)
    retained_descriptor = None
    try:
        root_identity = RETENTION._directory_identity(os.fstat(root_descriptor))
        named_source = os.stat(
            root.name, dir_fd=source_parent, follow_symlinks=False,
        )
        if RETENTION._directory_identity(named_source) != root_identity:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_source_identity_changed",
            )
        plan_path = root / RETENTION.PLAN_NAME
        if os.path.lexists(plan_path):
            plan = RETENTION._trusted_canonical_record(
                plan_path, uid, "retention_plan",
            )
            validate_plan(plan, campaign, inventory, uid, replacement)
        else:
            plan = planned
            RETENTION._write_new_at(root_descriptor, RETENTION.PLAN_NAME, plan)
            if RETENTION._trusted_canonical_record(
                    plan_path, uid, "retention_plan") != plan:
                raise ProgressedQualificationRetentionError(
                    "progressed_qualification_plan_write_failed",
                )
        if plan["failure_record_sha256"] != retained_failure["rejection_sha256"]:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_failure_binding_invalid",
            )
        retained_parent = home / RETENTION.RETAINED_RELATIVE.parent
        handoff = RETENTION._directory(retained_parent, uid)
        try:
            try:
                os.mkdir(
                    RETENTION.RETAINED_RELATIVE.name, mode=0o700,
                    dir_fd=handoff,
                )
            except FileExistsError:
                pass
            else:
                os.chmod(
                    RETENTION.RETAINED_RELATIVE.name, 0o700,
                    dir_fd=handoff, follow_symlinks=False,
                )
                os.fsync(handoff)
            retained = retained_parent / RETENTION.RETAINED_RELATIVE.name
            retained_descriptor = RETENTION._directory(retained, uid)
        finally:
            os.close(handoff)
        try:
            os.stat(campaign["campaign_id"], dir_fd=retained_descriptor,
                    follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_destination_exists",
            )
        named_source = os.stat(
            root.name, dir_fd=source_parent, follow_symlinks=False,
        )
        if RETENTION._directory_identity(named_source) != root_identity:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_source_identity_changed",
            )
        rename(
            source_parent, root.name, retained_descriptor,
            campaign["campaign_id"],
        )
        try:
            os.stat(root.name, dir_fd=source_parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_source_still_present",
            )
        retained_info = os.stat(
            campaign["campaign_id"], dir_fd=retained_descriptor,
            follow_symlinks=False,
        )
        if RETENTION._directory_identity(retained_info) != root_identity:
            raise ProgressedQualificationRetentionError(
                "progressed_qualification_destination_identity_mismatch",
            )
        os.fsync(source_parent)
        os.fsync(retained_descriptor)
    finally:
        os.close(root_descriptor)
        os.close(source_parent)
        if retained_descriptor is not None:
            os.close(retained_descriptor)
    if os.path.lexists(root):
        raise ProgressedQualificationRetentionError(
            "progressed_qualification_source_still_present",
        )
    return verify_retained(
        expected_campaign_id=campaign["campaign_id"],
        expected_source_commit=campaign["source_commit"],
        expected_replacement_commit=replacement,
        home=home, protected_uid=protected_uid,
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Retain a later qualification control rejection",
    )
    commands = value.add_subparsers(dest="command", required=True)
    retain_parser = commands.add_parser("retain")
    retain_parser.add_argument("--expected-campaign-id", required=True)
    retain_parser.add_argument("--expected-source-commit", required=True)
    retain_parser.add_argument("--supervisor-output", type=Path, required=True)
    retain_parser.add_argument("--control-audit", type=Path, required=True)
    retain_parser.add_argument("--diagnostic-source", type=Path, required=True)
    retain_parser.add_argument("--acknowledge", required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--expected-campaign-id", required=True)
    verify_parser.add_argument("--expected-source-commit", required=True)
    verify_parser.add_argument("--expected-replacement-commit", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if args.command == "retain":
        result = retain(
            expected_campaign_id=args.expected_campaign_id,
            expected_source_commit=args.expected_source_commit,
            acknowledgement=args.acknowledge,
            supervisor_output=args.supervisor_output,
            control_audit=args.control_audit,
            diagnostic_source=args.diagnostic_source,
        )
    else:
        result = verify_retained(
            expected_campaign_id=args.expected_campaign_id,
            expected_source_commit=args.expected_source_commit,
            expected_replacement_commit=args.expected_replacement_commit,
        )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, ProgressedQualificationRetentionError,
            RETENTION.RetentionError, OSError) as error:
        sys.stdout.buffer.write(canonical({
            "schema": ERROR_SCHEMA, "status": "rejected",
            "error": str(error),
        }))
        raise SystemExit(1)
