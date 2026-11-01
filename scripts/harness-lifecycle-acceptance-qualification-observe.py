#!/usr/bin/env python3
"""Validate and project protected qualification raw evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_campaign,
    validate_observation,
)


SCHEMA = "secure-sandbox-harness-lifecycle-qualification-projection-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-qualification-projection-error-v1"
MEDIA_TYPE = "application/json"
RAW_FILES = {
    "research": "research-result.json",
    "quarantine": "quarantine-readback.json",
    "authority": "authority-readback.json",
    "production": "production-material-scan.json",
}
PRIMARY = {
    "execution-observation": ("research", "protected-research"),
    "isolation-observation": ("research", "protected-research"),
    "process-observation": ("research", "protected-research"),
    "credential-observation": ("research", "protected-research"),
    "network-observation": ("research", "protected-research"),
    "quarantine-readback": ("quarantine", "protected-host"),
    "authority-readback": ("authority", "protected-host"),
    "production-material-scan": ("production", "disposable-supervisor"),
}
CONTEXT_NAMES = {
    "research": "research-context",
    "quarantine": "host-quarantine-context",
    "authority": "host-authority-context",
    "production": "disposable-scan-context",
}
AUTHORITIES = {
    "research": "protected-research",
    "quarantine": "protected-host",
    "authority": "protected-host",
    "production": "disposable-supervisor",
}


class QualificationProjectionError(RuntimeError):
    """Stable, content-free projection failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise QualificationProjectionError("qualification_projection_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_qualification_projection_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-qualification-supervisor.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_qualification_projection_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)
ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_acceptance_qualification_projection_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)


def private_directory(path: Path, label: str) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise QualificationProjectionError(f"{label}_untrusted")


def trusted_json(path: Path) -> dict[str, Any]:
    try:
        return SUPERVISOR.COMMON.trusted_json(path)
    except SUPERVISOR.COMMON.SupervisorError as error:
        raise QualificationProjectionError("qualification_raw_file_untrusted") from error


def raw_set(campaign: dict[str, Any], case: dict[str, Any], raw_directory: Path,
            now: int) -> tuple[dict[str, Path], dict[str, dict[str, Any]],
                               dict[str, bytes]]:
    private_directory(raw_directory, "qualification_raw_directory")
    entries = {item.name: item for item in raw_directory.iterdir()}
    if set(entries) != set(RAW_FILES.values()):
        raise QualificationProjectionError("qualification_raw_inventory_invalid")
    paths = {name: entries[filename] for name, filename in RAW_FILES.items()}
    values = {name: trusted_json(path) for name, path in paths.items()}
    research = values["research"]
    try:
        SUPERVISOR.QUALIFICATION.validate_result(research, campaign, case)
    except SUPERVISOR.QUALIFICATION.QualificationDriverError as error:
        raise QualificationProjectionError("qualification_research_invalid") from error

    quarantine = values["quarantine"]
    authority = values["authority"]
    production = values["production"]
    for value, schema, field in (
        (quarantine, SUPERVISOR.QUARANTINE_SCHEMA, "quarantine_sha256"),
        (authority, SUPERVISOR.AUTHORITY_SCHEMA, "authority_sha256"),
        (production, SUPERVISOR.SCAN_SCHEMA, "scan_sha256"),
    ):
        SUPERVISOR.validate_record(
            value, campaign, case, schema, field, now, "passed",
        )
    if (set(quarantine) != {
            "schema", "status", "campaign_id", "campaign_sha256",
            "machine_identity_sha256", "source_commit", "case_id",
            "procedure_sha256", "observed_at", "before", "after", "unchanged",
            "host_execution", "candidate_authority", "production_material_used",
            "quarantine_sha256",
            } or quarantine.get("before") != quarantine.get("after")
            or quarantine.get("unchanged") is not True
            or quarantine.get("host_execution") is not False):
        raise QualificationProjectionError("qualification_quarantine_invalid")
    fixture = quarantine["before"]
    if (not isinstance(fixture, dict) or set(fixture) != {
            "path", "sha256", "size", "mode", "owner_uid", "link_count",
            "executable", "manifest_sha256", "state",
            } or fixture.get("mode") != 0o444 or fixture.get("owner_uid") != 0
            or fixture.get("link_count") != 1 or fixture.get("executable") is not False
            or fixture.get("state") != "inert-protected-payload"
            or not isinstance(fixture.get("sha256"), str)
            or SUPERVISOR.COMMON.SHA256.fullmatch(fixture["sha256"]) is None):
        raise QualificationProjectionError("qualification_quarantine_invalid")
    if (set(authority) != {
            "schema", "status", "campaign_id", "campaign_sha256",
            "machine_identity_sha256", "source_commit", "case_id",
            "procedure_sha256", "observed_at", "research_result_sha256",
            "research_candidate_authority", "admission_performed",
            "activation_performed", "selector_changed", "session_migrated",
            "candidate_authority", "production_material_used", "authority_sha256",
            } or authority.get("research_result_sha256") != research["result_sha256"]
            or authority.get("research_candidate_authority") != "none"
            or any(authority.get(field) is not False for field in (
                "admission_performed", "activation_performed", "selector_changed",
                "session_migrated",
            ))):
        raise QualificationProjectionError("qualification_authority_invalid")
    if (set(production) != {
            "schema", "status", "campaign_id", "campaign_sha256",
            "machine_identity_sha256", "source_commit", "case_id",
            "procedure_sha256", "observed_at", "checked_environment",
            "checked_home_paths", "checked_keychain_services", "present_environment",
            "present_home_paths", "present_keychain_services",
            "production_data_present", "production_credentials_present",
            "candidate_authority", "production_material_used", "scan_sha256",
            } or production.get("present_environment") != []
            or production.get("present_home_paths") != []
            or production.get("present_keychain_services") != []
            or production.get("production_data_present") is not False
            or production.get("production_credentials_present") is not False
            or production.get("checked_environment")
               != sorted(SUPERVISOR.ENROLLER.PROVIDER_ENVIRONMENT)
            or production.get("checked_home_paths")
               != list(SUPERVISOR.PRODUCTION_HOME_PATHS)
            or production.get("checked_keychain_services")
               != list(SUPERVISOR.ENROLLER.KEYCHAIN_SERVICES)):
        raise QualificationProjectionError("qualification_production_scan_invalid")
    raw = {name: canonical(value) for name, value in values.items()}
    return paths, values, raw


def artifact_arguments(kind: str, paths: dict[str, Path]) -> list[list[str]]:
    primary_name, primary_authority = PRIMARY[kind]
    arguments = [[kind, primary_authority, str(paths[primary_name]), MEDIA_TYPE]]
    for name in ("research", "quarantine", "authority", "production"):
        if name != primary_name:
            arguments.append([
                CONTEXT_NAMES[name], AUTHORITIES[name], str(paths[name]), MEDIA_TYPE,
            ])
    return arguments


def existing_observation(path: Path, campaign: dict[str, Any],
                         case: dict[str, Any], kind: str,
                         raw: dict[str, bytes]) -> str:
    try:
        payload = OBSERVER.trusted_read(path)
        value = json.loads(payload)
    except (AcceptanceError, OSError, UnicodeDecodeError,
            json.JSONDecodeError) as error:
        raise QualificationProjectionError(
            "qualification_existing_observation_invalid",
        ) from error
    primary, authority = PRIMARY[kind]
    ordered = [primary] + [name for name in (
        "research", "quarantine", "authority", "production",
    ) if name != primary]
    names = [kind] + [CONTEXT_NAMES[name] for name in ordered[1:]]
    authorities = [authority] + [AUTHORITIES[name] for name in ordered[1:]]
    artifacts = value.get("evidence", {}).get("artifacts") \
        if isinstance(value, dict) else None
    if (not isinstance(value, dict) or canonical(value) != payload
            or value.get("kind") != kind or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts
                if isinstance(item, dict)] != names
            or any(not isinstance(item, dict)
                   or item.get("authority") != expected_authority
                   or item.get("sha256") != hashlib.sha256(raw[name]).hexdigest()
                   for item, name, expected_authority
                   in zip(artifacts, ordered, authorities))):
        raise QualificationProjectionError(
            "qualification_existing_observation_mismatch",
        )
    try:
        validate_observation(value, campaign, CASE_BY_ID[case["case_id"]])
    except AcceptanceError as error:
        raise QualificationProjectionError(
            "qualification_existing_observation_invalid",
        ) from error
    return value["observation_sha256"]


def project(campaign_path: Path, observations: Path, case_id: str,
            raw_directory: Path, now: int) -> dict[str, Any]:
    try:
        campaign = validate_campaign(ACCEPTANCE_CLI.trusted_json(campaign_path), now)
        case = SUPERVISOR.next_case(campaign, observations, case_id)
        release = SUPERVISOR.require_protected_path(
            ROOT / "scripts/harness-lifecycle-acceptance-qualification-supervisor.py",
        )
        ACCEPTANCE_CLI.verify_protected_driver(
            SUPERVISOR.PROTECTED_RELEASES.parent, campaign["source_commit"],
            "research-qualification-fixture", 0,
        )
        machine = SUPERVISOR.COMMON.current_machine_identity()
    except (AcceptanceError, OSError, QualificationProjectionError,
            SUPERVISOR.QualificationSupervisorError,
            SUPERVISOR.COMMON.SupervisorError) as error:
        raise QualificationProjectionError("qualification_projection_preflight_failed") from error
    if (release.name != campaign["source_commit"]
            or machine != campaign["machine_identity_sha256"]):
        raise QualificationProjectionError("qualification_projection_binding_mismatch")
    private_directory(observations, "qualification_observations")
    paths, _, raw = raw_set(campaign, case, raw_directory, now)
    projected: dict[str, str] = {}
    existing: list[str] = []
    created: list[str] = []
    with tempfile.TemporaryDirectory(
            prefix="secure-sandbox-qualification-projection.") as temporary:
        stage = Path(temporary)
        stage.chmod(0o700)
        for kind in case["evidence_kinds"]:
            output = observations / f"{case_id}.{kind}.json"
            if os.path.lexists(output):
                projected[kind] = existing_observation(
                    output, campaign, case, kind, raw,
                )
                existing.append(kind)
                continue
            result = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=artifact_arguments(kind, paths),
                output_directory=stage, now=now,
            )
            staged = stage / output.name
            OBSERVER.write_new(output, result)
            staged.unlink()
            projected[kind] = result["observation_sha256"]
            created.append(kind)
    directory = os.open(observations, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    value = {
        "schema": SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observation_sha256": {
            kind: projected[kind] for kind in case["evidence_kinds"]
        },
        "resumed_observation_kinds": existing,
        "recorded_observation_kinds": created,
        "candidate_authority": "none", "production_material_used": False,
    }
    value["projection_sha256"] = digest(value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Project one qualification raw set into fixed observations",
    )
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--observations", type=Path, required=True)
    value.add_argument("--case", required=True)
    value.add_argument("--raw-directory", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    result = project(
        arguments.campaign, arguments.observations, arguments.case,
        arguments.raw_directory, int(time.time()),
    )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, QualificationProjectionError, OSError) as error:
        reason = str(error) if isinstance(error, QualificationProjectionError) \
            else "qualification_projection_failed"
        print(json.dumps({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
