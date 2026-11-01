#!/usr/bin/env python3
"""Collect and project fixed disposable-Mac bootstrap acceptance evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
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
    validate_enrollment,
    validate_observation,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-bootstrap-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-bootstrap-error-v1"
HOST_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-host-install-v1"
RESEARCH_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-research-install-v1"
SCAN_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-production-scan-v1"
ENROLLMENT_READBACK_SCHEMA = (
    "secure-sandbox-harness-lifecycle-acceptance-enrollment-readback-v1"
)
INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
STABLE_LAUNCHER = Path("/usr/local/bin/secure-sandbox-claude")
MEDIA_TYPE = "application/json"
MAX_JSON = 64 * 1024
CASE_FILES = {
    "bootstrap-clean-install": {
        "host-install-readback": "host-install-readback.json",
        "research-install-readback": "research-install-readback.json",
        "boundary-readback": "boundary-readback.json",
    },
    "bootstrap-no-production-material": {
        "production-material-scan": "production-material-scan.json",
        "machine-enrollment": "machine-enrollment.json",
    },
}
AUTHORITIES = {
    "host-install-readback": "protected-host",
    "research-install-readback": "protected-research",
    "boundary-readback": "privileged-control",
    "production-material-scan": "disposable-supervisor",
    "machine-enrollment": "disposable-supervisor",
}
SUPPORT = {
    "host-install-readback": (),
    "research-install-readback": ("boundary-readback",),
    "boundary-readback": ("research-install-readback",),
    "production-material-scan": ("machine-enrollment",),
    "machine-enrollment": ("production-material-scan",),
}


class BootstrapError(RuntimeError):
    """Stable, content-free bootstrap acceptance failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BootstrapError("bootstrap_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_bootstrap_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_bootstrap_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)
ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_acceptance_bootstrap_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)
HOST_RELEASE = load_script(
    "harness_lifecycle_acceptance_host_release",
    ROOT / "scripts/host-controller-release.py",
)
ENROLLER = load_script(
    "harness_lifecycle_acceptance_enrollment",
    ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py",
)
PRODUCTION_HOME_PATHS = ENROLLER.PROVIDER_HOME_PATHS


def private_directory(path: Path, label: str) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise BootstrapError(f"{label}_untrusted")


def reserve_case(root: Path, case_id: str) -> Path:
    private_directory(root, "bootstrap_raw_root")
    destination = root / case_id
    if os.path.lexists(destination):
        raise BootstrapError("bootstrap_raw_case_exists")
    destination.mkdir(mode=0o700)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return destination


def trusted_json(path: Path, maximum: int = MAX_JSON) -> dict[str, Any]:
    try:
        return SUPERVISOR.trusted_json(path, maximum)
    except SUPERVISOR.SupervisorError as error:
        raise BootstrapError("bootstrap_input_untrusted") from error


def next_bootstrap_case(campaign: dict[str, Any], observations: Path,
                        case_id: str) -> dict[str, Any]:
    try:
        value = ACCEPTANCE_CLI.next_case(campaign, observations)
    except (AcceptanceError, OSError) as error:
        raise BootstrapError("bootstrap_case_status_invalid") from error
    case = value.get("case")
    if (value.get("status") != "pending" or not isinstance(case, dict)
            or case.get("case_id") != case_id):
        raise BootstrapError("bootstrap_case_not_next")
    if (case.get("category") != "bootstrap"
            or case.get("expected") != "passed"
            or case.get("procedure", {}).get("driver") != "clean-machine-bootstrap"
            or case_id not in CASE_FILES
            or case.get("evidence_kinds") != list(CASE_FILES[case_id])):
        raise BootstrapError("bootstrap_case_invalid")
    return case


def preflight(campaign_path: Path, observations: Path,
              case_id: str, now: int) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        campaign = validate_campaign(trusted_json(campaign_path), now)
        SUPERVISOR.verify_source_checkout(campaign)
        machine = SUPERVISOR.current_machine_identity()
    except (AcceptanceError, SUPERVISOR.SupervisorError) as error:
        raise BootstrapError("bootstrap_preflight_failed") from error
    if machine != campaign["machine_identity_sha256"]:
        raise BootstrapError("bootstrap_machine_identity_mismatch")
    return campaign, next_bootstrap_case(campaign, observations, case_id)


def control(operation: str) -> dict[str, Any]:
    try:
        return SUPERVISOR.json_command([
            str(SUPERVISOR.CONTROL_CLIENT), "client", "--ssh-config",
            str(SUPERVISOR.SSH_CONFIG), "--timeout-seconds", "30",
            SUPERVISOR.RESEARCH_CONTROL, "run", operation,
        ], timeout=40, canonical_output=False)
    except SUPERVISOR.SupervisorError as error:
        raise BootstrapError("bootstrap_research_readback_failed") from error


def receipt(schema: str, campaign: dict[str, Any], case: dict[str, Any],
            now: int, fields: dict[str, Any], digest_field: str) -> dict[str, Any]:
    value = {
        "schema": schema, "status": "verified",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"], "case_id": case["case_id"],
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observed_at": now, **fields, "candidate_authority": "none",
        "production_material_used": False,
    }
    value[digest_field] = digest(value)
    return value


def valid_observed_at(campaign: dict[str, Any], value: dict[str, Any], now: int) -> bool:
    observed = value.get("observed_at")
    return (isinstance(observed, int) and not isinstance(observed, bool)
            and campaign["created_at"] <= observed < campaign["expires_at"]
            and observed <= now + 300 and now - observed <= 3600)


def validate_host_receipt(campaign: dict[str, Any], case: dict[str, Any],
                          value: dict[str, Any], now: int) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id",
        "procedure_sha256", "observed_at", "release", "release_sha256",
        "candidate_authority", "production_material_used", "receipt_sha256",
    }
    release = value.get("release")
    unsigned = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if (set(value) != expected or value.get("schema") != HOST_SCHEMA
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256")
               != case["procedure"]["procedure_sha256"]
            or not valid_observed_at(campaign, value, now)
            or not isinstance(release, dict)
            or set(release) != {
                "schema", "status", "release_id", "launcher_sha256", "payloads",
            }
            or release.get("schema") != HOST_RELEASE.SCHEMA
            or release.get("status") != "verified"
            or not isinstance(release.get("release_id"), str)
            or SUPERVISOR.SHA256.fullmatch(release["release_id"]) is None
            or not isinstance(release.get("launcher_sha256"), str)
            or SUPERVISOR.SHA256.fullmatch(release["launcher_sha256"]) is None
            or not isinstance(release.get("payloads"), dict)
            or not release["payloads"]
            or any(not isinstance(name, str) or not isinstance(item, str)
                   or SUPERVISOR.SHA256.fullmatch(item) is None
                   for name, item in release["payloads"].items())
            or value.get("release_sha256") != digest(release)
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("receipt_sha256") != digest(unsigned)):
        raise BootstrapError("bootstrap_host_receipt_invalid")


def validate_research_receipt(campaign: dict[str, Any], case: dict[str, Any],
                              value: dict[str, Any], boundary: dict[str, Any],
                              now: int) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id",
        "procedure_sha256", "observed_at", "control_status", "store_status",
        "store_status_sha256", "boundary_sha256", "candidate_authority",
        "production_material_used", "receipt_sha256",
    }
    store = value.get("store_status")
    control_status = value.get("control_status")
    unsigned = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if (set(value) != expected or value.get("schema") != RESEARCH_SCHEMA
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256")
               != case["procedure"]["procedure_sha256"]
            or not valid_observed_at(campaign, value, now)
            or not isinstance(control_status, dict)
            or control_status != {
                "schema": "secure-sandbox-privileged-control-status-v1",
                "role": "research",
            }
            or not isinstance(store, dict)
            or store.get("schema")
               != "secure-sandbox-harness-generation-status-v1"
            or store.get("status") != "verified"
            or store.get("admission") != "open"
            or store.get("recovery_pending") is not False
            or store.get("boundary") != boundary
            or value.get("store_status_sha256") != digest(store)
            or value.get("boundary_sha256") != digest(boundary)
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("receipt_sha256") != digest(unsigned)):
        raise BootstrapError("bootstrap_research_receipt_invalid")
    try:
        SUPERVISOR.validate_boundary(boundary)
    except SUPERVISOR.SupervisorError as error:
        raise BootstrapError("bootstrap_boundary_invalid") from error


def collect_clean_install(campaign: dict[str, Any], case: dict[str, Any],
                          destination: Path, now: int) -> list[str]:
    try:
        for path in (SUPERVISOR.CONTROL_CLIENT, SUPERVISOR.SSH_CONFIG):
            SUPERVISOR.prerequisite(path, executable=path != SUPERVISOR.SSH_CONFIG)
        installed_gpgv = INSTALL_ROOT / "current/gpgv"
        release = HOST_RELEASE.verify(
            ROOT, INSTALL_ROOT, STABLE_LAUNCHER, 0,
            HOST_RELEASE.DEFAULT_OP_BINARY, installed_gpgv,
        )
    except (SUPERVISOR.SupervisorError, HOST_RELEASE.ReleaseFailure, OSError) as error:
        raise BootstrapError("bootstrap_host_install_unverified") from error
    control_status = control("control-status")
    store_status = control("harness-generation-status")
    boundary = control("harness-generation-verify-boundary")
    host = receipt(HOST_SCHEMA, campaign, case, now, {
        "release": release, "release_sha256": digest(release),
    }, "receipt_sha256")
    research = receipt(RESEARCH_SCHEMA, campaign, case, now, {
        "control_status": control_status, "store_status": store_status,
        "store_status_sha256": digest(store_status),
        "boundary_sha256": digest(boundary),
    }, "receipt_sha256")
    validate_host_receipt(campaign, case, host, now)
    validate_research_receipt(campaign, case, research, boundary, now)
    values = {
        "host-install-readback.json": host,
        "research-install-readback.json": research,
        "boundary-readback.json": boundary,
    }
    for name, value in values.items():
        SUPERVISOR.write_new(destination / name, value)
    return list(values)


def production_scan(home: Path, environment: dict[str, str],
                    runner: Any) -> dict[str, Any]:
    home_info = home.lstat()
    if (not stat.S_ISDIR(home_info.st_mode) or stat.S_ISLNK(home_info.st_mode)
            or home_info.st_uid != os.geteuid()
            or stat.S_IMODE(home_info.st_mode) != 0o700):
        raise BootstrapError("bootstrap_home_untrusted")
    present_environment = sorted(
        name for name in ENROLLER.PROVIDER_ENVIRONMENT if environment.get(name)
    )
    present_paths = sorted(
        relative for relative in PRODUCTION_HOME_PATHS
        if os.path.lexists(home / relative)
    )
    if present_environment or present_paths:
        raise BootstrapError("bootstrap_production_material_marker_present")
    try:
        ENROLLER.keychain_absent(runner)
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        raise BootstrapError("bootstrap_production_keychain_marker_present") from error
    return {
        "checked_environment": sorted(ENROLLER.PROVIDER_ENVIRONMENT),
        "checked_home_paths": list(PRODUCTION_HOME_PATHS),
        "checked_keychain_services": list(ENROLLER.KEYCHAIN_SERVICES),
    }


def validate_scan_receipts(campaign: dict[str, Any], case: dict[str, Any],
                           scan: dict[str, Any], enrollment_readback: dict[str, Any],
                           now: int) -> None:
    enrollment = enrollment_readback.get("enrollment")
    try:
        validated = validate_enrollment(enrollment, now)
    except AcceptanceError as error:
        raise BootstrapError("bootstrap_enrollment_invalid") from error
    for value, schema, digest_field in (
        (scan, SCAN_SCHEMA, "scan_sha256"),
        (enrollment_readback, ENROLLMENT_READBACK_SCHEMA, "readback_sha256"),
    ):
        unsigned = {key: item for key, item in value.items() if key != digest_field}
        if (value.get("schema") != schema
                or value.get("campaign_id") != campaign["campaign_id"]
                or value.get("campaign_sha256") != campaign["campaign_sha256"]
                or value.get("machine_identity_sha256")
                   != campaign["machine_identity_sha256"]
                or value.get("source_commit") != campaign["source_commit"]
                or value.get("case_id") != case["case_id"]
                or value.get("procedure_sha256")
                   != case["procedure"]["procedure_sha256"]
                or not valid_observed_at(campaign, value, now)
                or value.get("candidate_authority") != "none"
                or value.get("production_material_used") is not False
                or value.get(digest_field) != digest(unsigned)):
            raise BootstrapError("bootstrap_scan_receipt_invalid")
    scan_fields = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id",
        "procedure_sha256", "observed_at", "checked_environment",
        "checked_home_paths", "checked_keychain_services",
        "production_data_present", "production_credentials_present",
        "present_environment", "present_home_paths", "present_keychain_services",
        "candidate_authority", "production_material_used", "scan_sha256",
    }
    enrollment_fields = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id",
        "procedure_sha256", "observed_at", "enrollment", "enrollment_sha256",
        "candidate_authority", "production_material_used", "readback_sha256",
    }
    if (set(scan) != scan_fields or set(enrollment_readback) != enrollment_fields
            or scan.get("status") != "absent"
            or scan.get("checked_environment")
               != sorted(ENROLLER.PROVIDER_ENVIRONMENT)
            or scan.get("checked_home_paths") != list(PRODUCTION_HOME_PATHS)
            or scan.get("checked_keychain_services")
               != list(ENROLLER.KEYCHAIN_SERVICES)
            or scan.get("production_data_present") is not False
            or scan.get("production_credentials_present") is not False
            or scan.get("present_environment") != []
            or scan.get("present_home_paths") != []
            or scan.get("present_keychain_services") != []
            or enrollment_readback.get("status") != "verified"
            or enrollment_readback.get("enrollment_sha256")
               != validated["enrollment_sha256"]
            or validated["machine_identity_sha256"]
               != campaign["machine_identity_sha256"]):
        raise BootstrapError("bootstrap_scan_receipt_invalid")


def collect_production_scan(campaign: dict[str, Any], case: dict[str, Any],
                            destination: Path, enrollment_path: Path | None,
                            now: int, *, home: Path | None = None,
                            environment: dict[str, str] | None = None,
                            runner: Any = None) -> list[str]:
    if enrollment_path is None:
        raise BootstrapError("bootstrap_enrollment_required")
    enrollment = trusted_json(enrollment_path)
    scan_facts = production_scan(
        home or Path.home(), environment if environment is not None else dict(os.environ),
        runner or ENROLLER.subprocess.run,
    )
    scan = receipt(SCAN_SCHEMA, campaign, case, now, {
        **scan_facts, "status": "absent", "production_data_present": False,
        "production_credentials_present": False, "present_environment": [],
        "present_home_paths": [], "present_keychain_services": [],
    }, "scan_sha256")
    enrollment_readback = receipt(
        ENROLLMENT_READBACK_SCHEMA, campaign, case, now,
        {"enrollment": enrollment,
         "enrollment_sha256": enrollment.get("enrollment_sha256")},
        "readback_sha256",
    )
    validate_scan_receipts(campaign, case, scan, enrollment_readback, now)
    values = {
        "production-material-scan.json": scan,
        "machine-enrollment.json": enrollment_readback,
    }
    for name, value in values.items():
        SUPERVISOR.write_new(destination / name, value)
    return list(values)


def collect(campaign_path: Path, observations: Path, case_id: str,
            raw_root: Path, enrollment_path: Path | None, now: int,
            **scan_overrides: Any) -> dict[str, Any]:
    campaign, case = preflight(campaign_path, observations, case_id, now)
    destination = reserve_case(raw_root, case_id)
    if case_id == "bootstrap-clean-install":
        files = collect_clean_install(campaign, case, destination, now)
    else:
        files = collect_production_scan(
            campaign, case, destination, enrollment_path, now, **scan_overrides,
        )
    value = {
        "schema": SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "raw_directory": str(destination), "raw_files": files,
        "candidate_authority": "none", "production_material_used": False,
    }
    value["bootstrap_sha256"] = digest(value)
    return value


def raw_set(campaign: dict[str, Any], case: dict[str, Any],
            raw_directory: Path, now: int) -> tuple[dict[str, Path], dict[str, bytes]]:
    private_directory(raw_directory, "bootstrap_raw_directory")
    expected = CASE_FILES[case["case_id"]]
    entries = {item.name: item for item in raw_directory.iterdir()}
    if set(entries) != set(expected.values()):
        raise BootstrapError("bootstrap_raw_inventory_invalid")
    paths = {kind: entries[name] for kind, name in expected.items()}
    values = {kind: trusted_json(path) for kind, path in paths.items()}
    if case["case_id"] == "bootstrap-clean-install":
        validate_host_receipt(
            campaign, case, values["host-install-readback"], now,
        )
        validate_research_receipt(
            campaign, case, values["research-install-readback"],
            values["boundary-readback"], now,
        )
    else:
        validate_scan_receipts(
            campaign, case, values["production-material-scan"],
            values["machine-enrollment"], now,
        )
    return paths, {kind: canonical(value) for kind, value in values.items()}


def artifact_arguments(kind: str, paths: dict[str, Path]) -> list[list[str]]:
    return [
        [item, AUTHORITIES[item], str(paths[item]), MEDIA_TYPE]
        for item in (kind, *SUPPORT[kind])
    ]


def existing_observation(path: Path, campaign: dict[str, Any], case: dict[str, Any],
                         kind: str, raw_values: dict[str, bytes]) -> str:
    try:
        raw = OBSERVER.trusted_read(path)
        value = json.loads(raw)
    except (AcceptanceError, OSError, UnicodeDecodeError,
            json.JSONDecodeError) as error:
        raise BootstrapError("bootstrap_existing_observation_invalid") from error
    expected_kinds = [kind, *SUPPORT[kind]]
    evidence = value.get("evidence") if isinstance(value, dict) else None
    artifacts = evidence.get("artifacts") if isinstance(evidence, dict) else None
    if (not isinstance(value, dict) or canonical(value) != raw
            or value.get("kind") != kind or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts
                if isinstance(item, dict)] != expected_kinds
            or any(not isinstance(item, dict)
                   or item.get("authority") != AUTHORITIES[item_kind]
                   or item.get("sha256")
                      != hashlib.sha256(raw_values[item_kind]).hexdigest()
                   for item, item_kind in zip(artifacts, expected_kinds))):
        raise BootstrapError("bootstrap_existing_observation_mismatch")
    try:
        validate_observation(value, campaign, CASE_BY_ID[case["case_id"]])
    except AcceptanceError as error:
        raise BootstrapError("bootstrap_existing_observation_invalid") from error
    return value["observation_sha256"]


def write_snapshot(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BootstrapError("bootstrap_snapshot_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_staged(staged: Path, destination: Path) -> None:
    value = trusted_json(staged)
    try:
        OBSERVER.write_new(destination, value)
    except (AcceptanceError, OSError) as error:
        raise BootstrapError("bootstrap_observation_publication_failed") from error


def project(campaign_path: Path, observations: Path, case_id: str,
            raw_directory: Path, now: int) -> dict[str, Any]:
    campaign, case = preflight(campaign_path, observations, case_id, now)
    _, raw_values = raw_set(campaign, case, raw_directory, now)
    private_directory(observations, "bootstrap_observation_directory")
    existing: dict[str, str] = {}
    missing: list[str] = []
    for kind in case["evidence_kinds"]:
        destination = observations / f"{case_id}.{kind}.json"
        if os.path.lexists(destination):
            existing[kind] = existing_observation(
                destination, campaign, case, kind, raw_values,
            )
        else:
            missing.append(kind)
    projected = dict(existing)
    with tempfile.TemporaryDirectory(
            prefix="secure-sandbox-bootstrap-projection.") as temporary:
        stage = Path(temporary); stage.chmod(0o700)
        snapshots = stage / "raw"; snapshots.mkdir(mode=0o700)
        staged = stage / "observations"; staged.mkdir(mode=0o700)
        snapshot_paths: dict[str, Path] = {}
        for kind, raw in raw_values.items():
            path = snapshots / CASE_FILES[case_id][kind]
            write_snapshot(path, raw); snapshot_paths[kind] = path
        for kind in missing:
            observation = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=artifact_arguments(kind, snapshot_paths),
                output_directory=staged, now=now,
            )
            projected[kind] = observation["observation_sha256"]
        for kind in missing:
            name = f"{case_id}.{kind}.json"
            publish_staged(staged / name, observations / name)
    directory = os.open(observations, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    value = {
        "schema": SCHEMA, "status": "projected",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observation_sha256": {
            kind: projected[kind] for kind in case["evidence_kinds"]
        },
        "resumed_observation_kinds": [
            kind for kind in case["evidence_kinds"] if kind in existing
        ],
        "recorded_observation_kinds": missing,
        "candidate_authority": "none", "production_material_used": False,
    }
    value["bootstrap_sha256"] = digest(value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Collect or project fixed disposable-Mac bootstrap evidence",
    )
    commands = value.add_subparsers(dest="command", required=True)
    for name in ("collect", "project"):
        command = commands.add_parser(name)
        command.add_argument("--campaign", type=Path, required=True)
        command.add_argument("--observations", type=Path, required=True)
        command.add_argument("--case", required=True)
    collect_command = commands.choices["collect"]
    collect_command.add_argument("--raw-root", type=Path, required=True)
    collect_command.add_argument("--enrollment", type=Path)
    project_command = commands.choices["project"]
    project_command.add_argument("--raw-directory", type=Path, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    now = int(time.time())
    if args.command == "collect":
        result = collect(
            args.campaign, args.observations, args.case, args.raw_root,
            args.enrollment, now,
        )
    else:
        result = project(
            args.campaign, args.observations, args.case, args.raw_directory, now,
        )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, AcceptanceError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, BootstrapError) \
            else "bootstrap_acceptance_failed"
        sys.stderr.buffer.write(canonical({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }))
        raise SystemExit(1)
