#!/usr/bin/env python3
"""Collect and project fixed disposable-Mac archive rejection evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
sys.dont_write_bytecode = True
import time
from pathlib import Path
from types import ModuleType
from typing import Any


PROTECTED_RELEASES = Path(
    "/usr/local/libexec/secure-sandbox-harness-acceptance/releases"
)


def require_protected_main_path(path: Path, effective_uid: int) -> None:
    """Reject privileged checkout execution before any local module import."""
    if effective_uid != 0:
        return
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(PROTECTED_RELEASES)
    except ValueError as error:
        raise SystemExit("archive_driver_protected_invocation_required") from error
    parts = relative.parts
    if (len(parts) != 3 or len(parts[0]) != 40
            or any(character not in "0123456789abcdef" for character in parts[0])
            or parts[1:] != ("scripts", path.name)):
        raise SystemExit("archive_driver_protected_invocation_required")


if __name__ == "__main__":
    require_protected_main_path(Path(__file__), os.geteuid())


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
from harness_lifecycle_archive_fixture import (  # noqa: E402
    ARCHIVE_CASES,
    EXPECTED_ERRORS,
    ArchiveFixtureError,
    SCHEMA as FIXTURE_SCHEMA,
    run as run_fixture,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-archive-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-archive-error-v1"
RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-archive-result-v1"
RAW_FILENAME = "archive-result.json"
MEDIA_TYPE = "application/json"
PROTECTED_STATE_ROOT = Path(
    "/var/db/SecureSandbox/harness-lifecycle-acceptance"
)


class ArchiveDriverError(RuntimeError):
    """Stable, content-free archive driver failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ArchiveDriverError("archive_driver_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_archive_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_archive_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)
ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_acceptance_archive_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)


def private_directory(path: Path, label: str,
                      expected_uid: int | None = None) -> None:
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
        raise ArchiveDriverError(f"{label}_untrusted")


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
                raise ArchiveDriverError("archive_result_write_failed")
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
        raise ArchiveDriverError("archive_case_status_invalid") from error
    case = value.get("case")
    expected = CASE_BY_ID.get(case_id)
    if (value.get("status") != "pending" or not isinstance(case, dict)
            or expected is None or expected.category != "archive"
            or case_id not in ARCHIVE_CASES
            or case.get("case_id") != case_id
            or case.get("procedure", {}).get("driver") != "host-archive-fixture"
            or case.get("evidence_kinds") != list(expected.evidence_kinds)):
        raise ArchiveDriverError("archive_case_not_next")
    return case


def preflight(campaign_path: Path, observations: Path, case_id: str,
              now: int, operator_uid: int, installation_root: Path,
              expected_install_uid: int) -> tuple[dict[str, Any], dict[str, Any]]:
    if installation_root == ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT:
        raise ArchiveDriverError("archive_production_boundary_required")
    try:
        campaign = validate_campaign(ACCEPTANCE_CLI.trusted_json(
            campaign_path, expected_uid=operator_uid,
        ), now)
        ACCEPTANCE_CLI.verify_protected_driver(
            installation_root, campaign["source_commit"],
            "host-archive-fixture", expected_install_uid,
        )
        machine = SUPERVISOR.current_machine_identity()
    except (AcceptanceError, SUPERVISOR.SupervisorError, OSError) as error:
        raise ArchiveDriverError("archive_preflight_failed") from error
    if machine != campaign["machine_identity_sha256"]:
        raise ArchiveDriverError("archive_machine_identity_mismatch")
    private_directory(
        observations, "archive_observations", expected_uid=operator_uid,
    )
    return campaign, next_case(campaign, observations, case_id, operator_uid)


def validate_fixture_result(case: dict[str, Any], value: dict[str, Any]) -> None:
    expected = {
        "schema", "status", "case_id", "expected", "observed_error",
        "archive_sha256", "archive_size", "protected_state_before_sha256",
        "protected_state_after_sha256", "extracted", "executed",
        "candidate_authority", "production_material_used",
    }
    if (set(value) != expected or value.get("schema") != FIXTURE_SCHEMA
            or value.get("status") != "rejected"
            or value.get("case_id") != case["case_id"]
            or value.get("expected") != "rejected"
            or value.get("observed_error") != EXPECTED_ERRORS[case["case_id"]]
            or not SUPERVISOR.SHA256.fullmatch(
                str(value.get("archive_sha256", "")))
            or not isinstance(value.get("archive_size"), int)
            or isinstance(value.get("archive_size"), bool)
            or not 0 < value["archive_size"] <= 8 * 1024 * 1024
            or not SUPERVISOR.SHA256.fullmatch(
                str(value.get("protected_state_before_sha256", "")))
            or value.get("protected_state_before_sha256")
               != value.get("protected_state_after_sha256")
            or value.get("extracted") is not False
            or value.get("executed") is not False
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False):
        raise ArchiveDriverError("archive_fixture_result_invalid")


def validate_record(campaign: dict[str, Any], case: dict[str, Any],
                    value: dict[str, Any], now: int) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id",
        "procedure_sha256", "observed_at", "fixture", "fixture_sha256",
        "candidate_authority", "production_material_used", "record_sha256",
    }
    fixture = value.get("fixture")
    unsigned = {key: item for key, item in value.items() if key != "record_sha256"}
    observed_at = value.get("observed_at")
    if (set(value) != expected or value.get("schema") != SCHEMA
            or value.get("status") != "rejected"
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
        raise ArchiveDriverError("archive_record_invalid")
    validate_fixture_result(case, fixture)


def reserve_case(raw_root: Path, case_id: str) -> Path:
    private_directory(raw_root, "archive_raw_root")
    destination = raw_root / case_id
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError:
        private_directory(destination, "archive_raw_case")
    else:
        directory = os.open(raw_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return destination


def project(campaign: dict[str, Any], case: dict[str, Any], raw_path: Path,
            observations: Path, now: int, operator_uid: int) -> dict[str, Any]:
    output = observations / f"{case['case_id']}.archive-rejection.json"
    if output.exists():
        existing = SUPERVISOR.trusted_json(output)
        validate_observation(existing, campaign, CASE_BY_ID[case["case_id"]])
        if (existing.get("kind") != "archive-rejection"
                or existing.get("evidence", {}).get("source_sha256")
                   != hashlib.sha256(OBSERVER.trusted_read(raw_path)).hexdigest()):
            raise ArchiveDriverError("archive_existing_observation_invalid")
        return existing
    return OBSERVER.observe(
        campaign=campaign, case_id=case["case_id"], kind="archive-rejection",
        artifact_arguments=[[
            "archive-rejection", "protected-host", str(raw_path), MEDIA_TYPE,
        ]],
        output_directory=observations, now=now,
        output_directory_uid=operator_uid, output_mode=0o444,
    )


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
            raise ArchiveDriverError("archive_raw_inventory_invalid")
        record = SUPERVISOR.trusted_json(raw_path)
        validate_record(campaign, case, record, now)
    else:
        if any(destination.iterdir()):
            raise ArchiveDriverError("archive_raw_inventory_invalid")
        try:
            fixture = run_fixture(case_id)
        except (ArchiveFixtureError, OSError) as error:
            raise ArchiveDriverError("archive_fixture_failed") from error
        validate_fixture_result(case, fixture)
        record = {
            "schema": SCHEMA, "status": "rejected",
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
    observation = project(
        campaign, case, raw_path, observations, now, operator_uid,
    )
    return {
        "schema": RESULT_SCHEMA, "status": "recorded", "case_id": case_id,
        "record_sha256": record["record_sha256"],
        "observation_sha256": observation["observation_sha256"],
        "authority": "acceptance-evidence-only",
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Run one fixed disposable-Mac archive rejection case",
    )
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--observations", type=Path, required=True)
    value.add_argument("--case", required=True)
    value.add_argument("--operator-uid", type=int, required=True)
    return value


def fixed_raw_root(campaign_id: str) -> Path:
    if os.geteuid() != 0:
        raise ArchiveDriverError("archive_root_required")
    current = PROTECTED_STATE_ROOT
    for path in (
        current,
        current / campaign_id,
        current / campaign_id / "archive",
    ):
        if not os.path.lexists(path):
            path.mkdir(mode=0o700)
        private_directory(path, "archive_protected_state", expected_uid=0)
    return current / campaign_id / "archive"


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if os.geteuid() != 0 or not 1 <= args.operator_uid < 2 ** 31:
        raise ArchiveDriverError("archive_root_context_required")
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
    except (AcceptanceError, ArchiveDriverError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, ArchiveDriverError) \
            else "archive_acceptance_failed"
        print(json.dumps({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
