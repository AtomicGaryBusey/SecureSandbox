#!/usr/bin/env python3
"""Collect and project the fixed disposable-Mac provenance acceptance cases."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
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
from harness_lifecycle_provenance_fixture import (  # noqa: E402
    EXPECTED_ERRORS,
    PROVENANCE_CASES,
    ProvenanceFixture,
    ProvenanceFixtureError,
    SCHEMA as FIXTURE_SCHEMA,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-provenance-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-provenance-error-v1"
RAW_FILENAME = "provenance-result.json"
MEDIA_TYPE = "application/json"
PROTECTED_STATE_ROOT = Path(
    "/var/db/SecureSandbox/harness-lifecycle-acceptance"
)


class ProvenanceDriverError(RuntimeError):
    """Stable, content-free provenance driver failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ProvenanceDriverError("provenance_driver_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_provenance_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_provenance_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)
ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_acceptance_provenance_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)


def private_directory(path: Path, label: str,
                      expected_uid: int | None = None) -> None:
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
        raise ProvenanceDriverError(f"{label}_untrusted")


def write_new(path: Path, value: dict[str, Any]) -> None:
    payload = canonical(value)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProvenanceDriverError("provenance_result_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def next_case(campaign: dict[str, Any], observations: Path,
              case_id: str, operator_uid: int) -> dict[str, Any]:
    try:
        value = ACCEPTANCE_CLI.next_case(
            campaign, observations, observation_uid=0,
            directory_uid=operator_uid,
        )
    except (AcceptanceError, OSError) as error:
        raise ProvenanceDriverError("provenance_case_status_invalid") from error
    case = value.get("case")
    expected = CASE_BY_ID.get(case_id)
    if (value.get("status") != "pending" or not isinstance(case, dict)
            or expected is None or expected.category != "provenance"
            or case_id not in PROVENANCE_CASES
            or case.get("case_id") != case_id
            or case.get("procedure", {}).get("driver") != "host-provenance-fixture"
            or case.get("evidence_kinds") != list(expected.evidence_kinds)):
        raise ProvenanceDriverError("provenance_case_not_next")
    return case


def preflight(campaign_path: Path, observations: Path, case_id: str,
              now: int, operator_uid: int, installation_root: Path,
              expected_install_uid: int) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        campaign = validate_campaign(ACCEPTANCE_CLI.trusted_json(
            campaign_path, expected_uid=operator_uid,
        ), now)
        ACCEPTANCE_CLI.verify_protected_driver(
            installation_root, campaign["source_commit"],
            "host-provenance-fixture", expected_install_uid,
        )
        machine = SUPERVISOR.current_machine_identity()
    except (AcceptanceError, SUPERVISOR.SupervisorError, OSError) as error:
        raise ProvenanceDriverError("provenance_preflight_failed") from error
    if machine != campaign["machine_identity_sha256"]:
        raise ProvenanceDriverError("provenance_machine_identity_mismatch")
    private_directory(
        observations, "provenance_observations", expected_uid=operator_uid,
    )
    return campaign, next_case(campaign, observations, case_id, operator_uid)


def validate_fixture_result(case: dict[str, Any], value: dict[str, Any]) -> None:
    expected_fields = {
        "schema", "status", "case_id", "expected", "observed_error", "result",
        "generation_id", "protected_state_before_sha256",
        "protected_state_after_sha256", "state", "candidate_authority",
        "production_material_used",
    }
    expected_status = "verified" if case["expected"] == "passed" else "rejected"
    if (set(value) != expected_fields or value.get("schema") != FIXTURE_SCHEMA
            or value.get("status") != expected_status
            or value.get("case_id") != case["case_id"]
            or value.get("expected") != case["expected"]
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or not SUPERVISOR.SHA256.fullmatch(
                str(value.get("protected_state_before_sha256", "")))
            or not SUPERVISOR.SHA256.fullmatch(
                str(value.get("protected_state_after_sha256", "")))
            or not isinstance(value.get("state"), dict)
            or value["state"].get("schema")
               != "secure-sandbox-harness-lifecycle-status-v1"
            or value["state"].get("authority") != "none"):
        raise ProvenanceDriverError("provenance_fixture_result_invalid")
    if case["expected"] == "rejected":
        if (value.get("observed_error") != EXPECTED_ERRORS[case["case_id"]]
                or value.get("result") is not None
                or value["protected_state_before_sha256"]
                   != value["protected_state_after_sha256"]):
            raise ProvenanceDriverError("provenance_fixture_rejection_invalid")
    else:
        result = value.get("result")
        if (value.get("observed_error") is not None or not isinstance(result, dict)
                or result.get("schema")
                   != "secure-sandbox-harness-lifecycle-receipt-v1"):
            raise ProvenanceDriverError("provenance_fixture_success_invalid")
        if case["case_id"] == "acquire-clean-carrier":
            generations = value["state"].get("generations")
            if (result.get("action") != "acquire"
                    or result.get("status") != "artifact_quarantined"
                    or result.get("generation_id") != value.get("generation_id")
                    or not isinstance(generations, list)
                    or not any(item.get("generation_id") == value["generation_id"]
                               and item.get("state") == "quarantined"
                               for item in generations if isinstance(item, dict))):
                raise ProvenanceDriverError("provenance_acquisition_result_invalid")
        elif (result.get("action") != "check"
              or result.get("status") != "metadata_verified"
              or result.get("sequence") != 2):
            raise ProvenanceDriverError("provenance_fast_forward_result_invalid")


def validate_record(campaign: dict[str, Any], case: dict[str, Any],
                    value: dict[str, Any], now: int) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
        "observed_at", "fixture", "fixture_sha256", "candidate_authority",
        "production_material_used", "record_sha256",
    }
    fixture = value.get("fixture")
    unsigned = {key: item for key, item in value.items() if key != "record_sha256"}
    observed_at = value.get("observed_at")
    if (set(value) != expected or value.get("schema") != SCHEMA
            or value.get("status") != case["expected"]
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256")
               != case["procedure"]["procedure_sha256"]
            or not isinstance(observed_at, int) or isinstance(observed_at, bool)
            or not campaign["created_at"] <= observed_at < campaign["expires_at"]
            or observed_at > now + 300 or now - observed_at > 3600
            or not isinstance(fixture, dict)
            or value.get("fixture_sha256") != digest(fixture)
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("record_sha256") != digest(unsigned)):
        raise ProvenanceDriverError("provenance_record_invalid")
    validate_fixture_result(case, fixture)


def reserve_case(raw_root: Path, case_id: str) -> Path:
    private_directory(raw_root, "provenance_raw_root")
    destination = raw_root / case_id
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError:
        private_directory(destination, "provenance_raw_case")
    else:
        directory = os.open(raw_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return destination


def project(campaign: dict[str, Any], case: dict[str, Any], raw_path: Path,
            observations: Path, now: int, operator_uid: int) -> list[dict[str, Any]]:
    created = []
    for kind in case["evidence_kinds"]:
        output = observations / f"{case['case_id']}.{kind}.json"
        if output.exists():
            existing = SUPERVISOR.trusted_json(output)
            validate_observation(existing, campaign, CASE_BY_ID[case["case_id"]])
            if (existing.get("kind") != kind
                    or existing.get("evidence", {}).get("source_sha256")
                       != hashlib.sha256(OBSERVER.trusted_read(raw_path)).hexdigest()):
                raise ProvenanceDriverError("provenance_existing_observation_invalid")
            created.append(existing)
            continue
        created.append(OBSERVER.observe(
            campaign=campaign, case_id=case["case_id"], kind=kind,
            artifact_arguments=[[
                kind, "protected-host", str(raw_path), MEDIA_TYPE,
            ]],
            output_directory=observations, now=now,
            output_directory_uid=operator_uid, output_mode=0o444,
        ))
    return created


def run(campaign_path: Path, observations: Path, raw_root: Path,
        case_id: str, now: int, *, operator_uid: int,
        installation_root: Path = ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
        expected_install_uid: int = 0) -> dict[str, Any]:
    campaign, case = preflight(
        campaign_path, observations, case_id, now, operator_uid,
        installation_root, expected_install_uid,
    )
    destination = reserve_case(raw_root, case_id)
    raw_path = destination / RAW_FILENAME
    if raw_path.exists():
        if set(item.name for item in destination.iterdir()) != {RAW_FILENAME}:
            raise ProvenanceDriverError("provenance_raw_inventory_invalid")
        record = SUPERVISOR.trusted_json(raw_path)
        validate_record(campaign, case, record, now)
    else:
        if any(destination.iterdir()):
            raise ProvenanceDriverError("provenance_raw_inventory_invalid")
        with tempfile.TemporaryDirectory(
            prefix="secure-sandbox-provenance-fixture.", dir=raw_root,
        ) as directory:
            fixture_root = Path(directory); fixture_root.chmod(0o700)
            try:
                fixture = ProvenanceFixture(fixture_root, now=now).run(case_id)
            except (ProvenanceFixtureError, subprocess.SubprocessError, OSError) as error:
                raise ProvenanceDriverError("provenance_fixture_failed") from error
        validate_fixture_result(case, fixture)
        record = {
            "schema": SCHEMA, "status": case["expected"],
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "machine_identity_sha256": campaign["machine_identity_sha256"],
            "source_commit": campaign["source_commit"], "case_id": case_id,
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "observed_at": now, "fixture": fixture,
            "fixture_sha256": digest(fixture), "candidate_authority": "none",
            "production_material_used": False,
        }
        record["record_sha256"] = digest(record)
        validate_record(campaign, case, record, now)
        write_new(raw_path, record)
    observations_created = project(
        campaign, case, raw_path, observations, now, operator_uid,
    )
    return {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-provenance-result-v1",
        "status": "recorded", "case_id": case_id,
        "record_sha256": record["record_sha256"],
        "observation_sha256": [item["observation_sha256"]
                               for item in observations_created],
        "authority": "acceptance-evidence-only",
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Run one fixed disposable-Mac provenance acceptance case",
    )
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--observations", type=Path, required=True)
    value.add_argument("--case", required=True)
    value.add_argument("--operator-uid", type=int, required=True)
    return value


def fixed_raw_root(campaign_id: str) -> Path:
    if os.geteuid() != 0:
        raise ProvenanceDriverError("provenance_root_required")
    current = PROTECTED_STATE_ROOT
    for path in (
        current,
        current / campaign_id,
        current / campaign_id / "provenance",
    ):
        if not os.path.lexists(path):
            path.mkdir(mode=0o700)
        private_directory(path, "provenance_protected_state", expected_uid=0)
    return current / campaign_id / "provenance"


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if os.geteuid() != 0 or not 1 <= args.operator_uid < 2 ** 31:
        raise ProvenanceDriverError("provenance_root_context_required")
    campaign = validate_campaign(ACCEPTANCE_CLI.trusted_json(
        args.campaign, expected_uid=args.operator_uid,
    ), int(time.time()))
    result = run(
        args.campaign, args.observations, fixed_raw_root(campaign["campaign_id"]),
        args.case, int(time.time()), operator_uid=args.operator_uid,
        installation_root=ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
        expected_install_uid=0,
    )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, ProvenanceDriverError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, ProvenanceDriverError) \
            else "provenance_acceptance_failed"
        print(json.dumps({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
