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
    CONTINUATION_ARTIFACT_NAME,
    MAX_OBSERVATION_SECONDS,
    canonical,
    continuation_record,
    digest,
    validate_campaign,
    validate_enrollment,
    validate_observation,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-bootstrap-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-bootstrap-error-v1"
HOST_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-host-install-v1"
STACK_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-stack-readback-v1"
RESEARCH_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-research-install-v1"
SCAN_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-production-scan-v1"
ENROLLMENT_READBACK_SCHEMA = (
    "secure-sandbox-harness-lifecycle-acceptance-enrollment-readback-v1"
)
INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
STABLE_LAUNCHER = Path("/usr/local/bin/secure-sandbox-claude")
MEDIA_TYPE = "application/json"
MAX_JSON = 64 * 1024
HOST_RELEASE_FIELDS = {
    "schema", "status", "release_id", "launcher_sha256", "payloads",
    "host_release_launcher_pair_sha256", "candidate_authority_sha256",
    "release_tree_identity_sha256", "developer_id_team_id",
    "developer_id_team_floor_sha256",
    "developer_id_team_floor_release_id",
}
HOST_RELEASE_DIGEST_FIELDS = {
    "release_id", "launcher_sha256", "host_release_launcher_pair_sha256",
    "candidate_authority_sha256", "release_tree_identity_sha256",
    "developer_id_team_floor_sha256",
    "developer_id_team_floor_release_id",
}
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
LIFECYCLE = load_script(
    "harness_lifecycle_acceptance_parallels_lifecycle",
    ROOT / "scripts/parallels-lifecycle.py",
)
PRODUCTION_HOME_PATHS = ENROLLER.PROVIDER_HOME_PATHS


def private_directory(path: Path, label: str,
                      expected_uid: int | None = None) -> None:
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
        raise BootstrapError(f"{label}_untrusted")


def open_private_directory(path: Path, label: str, expected_uid: int) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise BootstrapError(f"{label}_untrusted") from error
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(descriptor)
        raise BootstrapError(f"{label}_untrusted")
    return descriptor


def directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def trusted_json_at(parent: int, name: str, *, expected_uid: int,
                    expected_mode: int, maximum: int = MAX_JSON
                    ) -> tuple[dict[str, Any], bytes, os.stat_result]:
    if "/" in name or name in {"", ".", ".."}:
        raise BootstrapError("bootstrap_input_untrusted")
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        try:
            opened = os.fstat(descriptor)
            chunks = bytearray()
            while len(chunks) <= maximum:
                chunk = os.read(
                    descriptor, min(65536, maximum + 1 - len(chunks)),
                )
                if not chunk:
                    break
                chunks.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise BootstrapError("bootstrap_input_untrusted") from error
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != expected_uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != expected_mode
            or not 0 < before.st_size <= maximum
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or len(chunks) != opened.st_size or len(chunks) > maximum):
        raise BootstrapError("bootstrap_input_untrusted")
    raw = bytes(chunks)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapError("bootstrap_input_untrusted") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise BootstrapError("bootstrap_input_untrusted")
    return value, raw, opened


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


def trusted_json(path: Path, maximum: int = MAX_JSON,
                 expected_uid: int | None = None) -> dict[str, Any]:
    try:
        return ACCEPTANCE_CLI.trusted_json(
            path, maximum, expected_uid=expected_uid,
        )
    except AcceptanceError as error:
        raise BootstrapError("bootstrap_input_untrusted") from error


def next_bootstrap_case(campaign: dict[str, Any], observations: Path,
                        case_id: str, operator_uid: int) -> dict[str, Any]:
    try:
        value = ACCEPTANCE_CLI.next_case(
            campaign, observations, observation_uid=0,
            directory_uid=operator_uid,
        )
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


def next_bootstrap_case_at(campaign: dict[str, Any], observations: int,
                           case_id: str) -> dict[str, Any]:
    entries = set(os.listdir(observations))
    expected = {
        f"{case.case_id}.{kind}.json"
        for case in ACCEPTANCE_CLI.CASES for kind in case.evidence_kinds
    }
    if not entries <= expected:
        raise BootstrapError("bootstrap_case_status_invalid")
    next_id = None
    for suite_case in ACCEPTANCE_CLI.CASES:
        missing = False
        for kind in suite_case.evidence_kinds:
            name = f"{suite_case.case_id}.{kind}.json"
            if name not in entries:
                missing = True
                continue
            value, _raw, _info = trusted_json_at(
                observations, name, expected_uid=0, expected_mode=0o444,
            )
            try:
                validate_observation(value, campaign, suite_case)
            except AcceptanceError as error:
                raise BootstrapError("bootstrap_case_status_invalid") from error
            if value.get("kind") != kind:
                raise BootstrapError("bootstrap_case_status_invalid")
        present = any(
            f"{suite_case.case_id}.{kind}.json" in entries
            for kind in suite_case.evidence_kinds
        )
        if missing:
            if next_id is None:
                next_id = suite_case.case_id
            elif present:
                raise BootstrapError("bootstrap_case_status_invalid")
        elif next_id is not None:
            raise BootstrapError("bootstrap_case_status_invalid")
    expected_case = CASE_BY_ID.get(case_id)
    expected_record = (
        ACCEPTANCE_CLI.case_record(expected_case)
        if expected_case is not None else None
    )
    if (next_id != case_id or expected_case is None
            or expected_case.category != "bootstrap"
            or expected_case.expected != "passed"
            or expected_record is None
            or expected_record.get("procedure", {}).get("driver")
               != "clean-machine-bootstrap"
            or case_id not in CASE_FILES
            or list(expected_case.evidence_kinds) != list(CASE_FILES[case_id])):
        raise BootstrapError("bootstrap_case_not_next")
    return expected_record


def require_protected_release(campaign: dict[str, Any]) -> None:
    expected_root = (
        ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT / "releases"
        / campaign["source_commit"]
    )
    if ROOT.resolve(strict=True) != expected_root or os.geteuid() != 0:
        raise BootstrapError("bootstrap_protected_release_required")
    try:
        for driver in ACCEPTANCE_CLI.DRIVER_ENTRYPOINTS:
            ACCEPTANCE_CLI.verify_protected_driver(
                ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
                campaign["source_commit"], driver, 0,
            )
    except (AcceptanceError, FileNotFoundError, OSError) as error:
        raise BootstrapError("bootstrap_protected_release_required") from error


def preflight(campaign_path: Path, observations: Path,
              case_id: str, now: int, *, operator_uid: int | None = None,
              protected_projection: bool = False,
              observations_descriptor: int | None = None,
              ) -> tuple[dict[str, Any], dict[str, Any]]:
    owner = os.geteuid() if operator_uid is None else operator_uid
    try:
        campaign = validate_campaign(
            trusted_json(campaign_path, expected_uid=owner), now,
        )
        if protected_projection:
            require_protected_release(campaign)
        else:
            SUPERVISOR.verify_source_checkout(campaign, ROOT)
        machine = SUPERVISOR.current_machine_identity()
    except (AcceptanceError, OSError, SUPERVISOR.SupervisorError) as error:
        raise BootstrapError("bootstrap_preflight_failed") from error
    if machine != campaign["machine_identity_sha256"]:
        raise BootstrapError("bootstrap_machine_identity_mismatch")
    if protected_projection:
        if observations_descriptor is None:
            raise BootstrapError("bootstrap_observation_directory_untrusted")
        return campaign, next_bootstrap_case_at(
            campaign, observations_descriptor, case_id,
        )
    return campaign, next_bootstrap_case(campaign, observations, case_id, owner)


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


def stack_readback(campaign: dict[str, Any], case: dict[str, Any],
                   now: int) -> dict[str, Any]:
    try:
        LIFECYCLE.require_mutation_prerequisites()
        if LIFECYCLE.gui_running():
            raise BootstrapError("bootstrap_stack_gui_running")
        observed, reachable = LIFECYCLE.observe(reachability=True)
    except (LIFECYCLE.LifecycleError, subprocess.SubprocessError,
            OSError) as error:
        raise BootstrapError("bootstrap_stack_readback_failed") from error
    expected_observed = {
        "gateway": "running", "research": "running", "target": "stopped",
        "gateway_net0": "disconnected",
    }
    expected_reachable = {
        "gateway": "reachable", "research": "reachable",
        "target": "unreachable",
    }
    if observed != expected_observed or reachable != expected_reachable:
        raise BootstrapError("bootstrap_stack_readback_invalid")
    value = {
        "schema": STACK_SCHEMA, "status": "verified",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "source_commit": campaign["source_commit"],
        "case_id": case["case_id"],
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observed_at": now, "observed": observed,
        "reachability": reachable, "parallels_gui_closed": True,
        "candidate_authority": "none", "production_material_used": False,
    }
    value["stack_readback_sha256"] = digest(value)
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
        "stack_readback", "stack_readback_sha256",
        "candidate_authority", "production_material_used", "receipt_sha256",
    }
    release = value.get("release")
    stack = value.get("stack_readback")
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
            or set(release) != HOST_RELEASE_FIELDS
            or release.get("schema") != HOST_RELEASE.SCHEMA
            or release.get("status") != "verified"
            or any(not isinstance(release.get(name), str)
                   or SUPERVISOR.SHA256.fullmatch(release[name]) is None
                   for name in HOST_RELEASE_DIGEST_FIELDS)
            or not isinstance(release.get("payloads"), dict)
            or not release["payloads"]
            or any(not isinstance(name, str) or not isinstance(item, str)
                   or SUPERVISOR.SHA256.fullmatch(item) is None
                   for name, item in release["payloads"].items())
            or release.get("developer_id_team_id")
               != HOST_RELEASE.NATIVE_HOST_PRODUCTS_TEAM_ID
            or value.get("release_sha256") != digest(release)
            or not isinstance(stack, dict)
            or value.get("stack_readback_sha256") != digest(stack)
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("receipt_sha256") != digest(unsigned)):
        raise BootstrapError("bootstrap_host_receipt_invalid")
    validate_stack_readback(campaign, case, stack, now)


def validate_stack_readback(campaign: dict[str, Any], case: dict[str, Any],
                            value: dict[str, Any], now: int) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "source_commit", "case_id", "procedure_sha256", "observed_at",
        "observed", "reachability", "parallels_gui_closed",
        "candidate_authority", "production_material_used",
        "stack_readback_sha256",
    }
    unsigned = {
        key: item for key, item in value.items()
        if key != "stack_readback_sha256"
    }
    if (set(value) != expected or value.get("schema") != STACK_SCHEMA
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256")
               != case["procedure"]["procedure_sha256"]
            or not valid_observed_at(campaign, value, now)
            or value.get("observed") != {
                "gateway": "running", "research": "running",
                "target": "stopped", "gateway_net0": "disconnected",
            }
            or value.get("reachability") != {
                "gateway": "reachable", "research": "reachable",
                "target": "unreachable",
            }
            or value.get("parallels_gui_closed") is not True
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("stack_readback_sha256") != digest(unsigned)):
        raise BootstrapError("bootstrap_stack_receipt_invalid")


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


def clean_install_readback(campaign: dict[str, Any], case: dict[str, Any],
                           now: int) -> dict[str, dict[str, Any]]:
    """Read and validate the fixed clean-install boundary without publication."""
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
    stack = stack_readback(campaign, case, now)
    host = receipt(HOST_SCHEMA, campaign, case, now, {
        "release": release, "release_sha256": digest(release),
        "stack_readback": stack, "stack_readback_sha256": digest(stack),
    }, "receipt_sha256")
    research = receipt(RESEARCH_SCHEMA, campaign, case, now, {
        "control_status": control_status, "store_status": store_status,
        "store_status_sha256": digest(store_status),
        "boundary_sha256": digest(boundary),
    }, "receipt_sha256")
    validate_host_receipt(campaign, case, host, now)
    validate_research_receipt(campaign, case, research, boundary, now)
    return {
        "host-install-readback.json": host,
        "research-install-readback.json": research,
        "boundary-readback.json": boundary,
    }


def collect_clean_install(campaign: dict[str, Any], case: dict[str, Any],
                          destination: Path, now: int) -> list[str]:
    values = clean_install_readback(campaign, case, now)
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
        validated = validate_enrollment(
            enrollment, now, allow_historical=True,
        )
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
            raw_directory: Path, now: int, *, raw_uid: int | None = None
            ) -> tuple[dict[str, Path], dict[str, bytes]]:
    private_directory(
        raw_directory, "bootstrap_raw_directory", expected_uid=raw_uid,
    )
    expected = CASE_FILES[case["case_id"]]
    entries = {item.name: item for item in raw_directory.iterdir()}
    if set(entries) != set(expected.values()):
        raise BootstrapError("bootstrap_raw_inventory_invalid")
    paths = {kind: entries[name] for kind, name in expected.items()}
    values = {
        kind: trusted_json(path, expected_uid=raw_uid)
        for kind, path in paths.items()
    }
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


def raw_set_at(campaign: dict[str, Any], case: dict[str, Any],
               raw_directory: int, now: int, operator_uid: int, *,
               allow_historical: bool = False
               ) -> tuple[dict[str, bytes], str]:
    expected = CASE_FILES[case["case_id"]]
    if set(os.listdir(raw_directory)) != set(expected.values()):
        raise BootstrapError("bootstrap_raw_inventory_invalid")
    values: dict[str, dict[str, Any]] = {}
    opened: dict[str, os.stat_result] = {}
    for kind, name in expected.items():
        value, _raw, info = trusted_json_at(
            raw_directory, name, expected_uid=operator_uid,
            expected_mode=0o600,
        )
        values[kind] = value
        opened[name] = info
    observed_times = {
        value.get("observed_at") for value in values.values()
        if isinstance(value, dict) and "observed_at" in value
    }
    if (len(observed_times) != 1
            or any(not isinstance(item, int) or isinstance(item, bool)
                   for item in observed_times)):
        raise BootstrapError("bootstrap_raw_observed_at_invalid")
    historical = next(iter(observed_times))
    validation_time = (
        historical
        if allow_historical and now - historical > MAX_OBSERVATION_SECONDS
        else now
    )
    if case["case_id"] == "bootstrap-clean-install":
        validate_host_receipt(
            campaign, case, values["host-install-readback"], validation_time,
        )
        validate_research_receipt(
            campaign, case, values["research-install-readback"],
            values["boundary-readback"], validation_time,
        )
    else:
        validate_scan_receipts(
            campaign, case, values["production-material-scan"],
            values["machine-enrollment"], validation_time,
        )
    return (
        {kind: canonical(value) for kind, value in values.items()},
        raw_custody_sha256(opened),
    )


def raw_custody_sha256(opened: dict[str, os.stat_result]) -> str:
    records = []
    for name, info in sorted(opened.items()):
        records.append({
            "name": name, "device": info.st_dev, "inode": info.st_ino,
            "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode), "links": info.st_nlink,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns,
        })
    return digest(records)


def artifact_arguments(kind: str, paths: dict[str, Path], *,
                       continuation: Path | None = None) -> list[list[str]]:
    result = [
        [item, AUTHORITIES[item], str(paths[item]), MEDIA_TYPE]
        for item in (kind, *SUPPORT[kind])
    ]
    if continuation is not None:
        result.append([
            CONTINUATION_ARTIFACT_NAME, "protected-host",
            str(continuation), MEDIA_TYPE,
        ])
    return result


def existing_observation(path: Path, campaign: dict[str, Any], case: dict[str, Any],
                         kind: str, raw_values: dict[str, bytes], *,
                         observation_uid: int, observation_mode: int) -> str:
    try:
        info = path.lstat()
        value = trusted_json(path, expected_uid=observation_uid)
        raw = canonical(value)
    except (BootstrapError, OSError) as error:
        raise BootstrapError("bootstrap_existing_observation_invalid") from error
    expected_kinds = [kind, *SUPPORT[kind]]
    allowed_artifacts = (
        expected_kinds,
        [*expected_kinds, CONTINUATION_ARTIFACT_NAME],
    )
    evidence = value.get("evidence") if isinstance(value, dict) else None
    artifacts = evidence.get("artifacts") if isinstance(evidence, dict) else None
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != observation_uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != observation_mode
            or not isinstance(value, dict) or canonical(value) != raw
            or value.get("kind") != kind or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts
                if isinstance(item, dict)] not in allowed_artifacts
            or any(not isinstance(item, dict)
                   or item.get("authority") != AUTHORITIES[item_kind]
                   or item.get("sha256")
                      != hashlib.sha256(raw_values[item_kind]).hexdigest()
                   for item, item_kind in zip(
                       artifacts[:len(expected_kinds)], expected_kinds,
                   ))):
        raise BootstrapError("bootstrap_existing_observation_mismatch")
    try:
        validate_observation(value, campaign, CASE_BY_ID[case["case_id"]])
    except AcceptanceError as error:
        raise BootstrapError("bootstrap_existing_observation_invalid") from error
    return value["observation_sha256"]


def existing_observation_at(parent: int, name: str,
                            campaign: dict[str, Any], case: dict[str, Any],
                            kind: str, raw_values: dict[str, bytes]) -> str:
    value, raw, info = trusted_json_at(
        parent, name, expected_uid=0, expected_mode=0o444,
    )
    expected_kinds = [kind, *SUPPORT[kind]]
    allowed_artifacts = (
        expected_kinds,
        [*expected_kinds, CONTINUATION_ARTIFACT_NAME],
    )
    evidence = value.get("evidence") if isinstance(value, dict) else None
    artifacts = evidence.get("artifacts") if isinstance(evidence, dict) else None
    if (not stat.S_ISREG(info.st_mode) or value.get("kind") != kind
            or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts
                if isinstance(item, dict)] not in allowed_artifacts
            or any(not isinstance(item, dict)
                   or item.get("authority") != AUTHORITIES[item_kind]
                   or item.get("sha256")
                      != hashlib.sha256(raw_values[item_kind]).hexdigest()
                   for item, item_kind in zip(
                       artifacts[:len(expected_kinds)], expected_kinds,
                   ))
            or canonical(value) != raw):
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


def publish_staged(staged: Path, destination: Path, *, mode: int) -> None:
    value = trusted_json(staged)
    try:
        OBSERVER.write_new(destination, value, mode=mode)
    except (AcceptanceError, OSError) as error:
        raise BootstrapError("bootstrap_observation_publication_failed") from error


def publish_staged_at(staged: Path, parent: int, name: str, *, mode: int) -> None:
    value = trusted_json(staged)
    payload = canonical(value)
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode, dir_fd=parent,
        )
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise BootstrapError(
                        "bootstrap_observation_publication_failed"
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise BootstrapError(
            "bootstrap_observation_publication_failed"
        ) from error


def project(campaign_path: Path, observations: Path, case_id: str,
            raw_directory: Path, now: int, *, operator_uid: int | None = None
            ) -> dict[str, Any]:
    protected_projection = operator_uid is not None
    owner = os.geteuid() if operator_uid is None else operator_uid
    if protected_projection and (os.geteuid() != 0 or not 1 <= owner < 2 ** 31):
        raise BootstrapError("bootstrap_protected_projection_context_required")
    observations_descriptor = None
    raw_descriptor = None
    if protected_projection:
        observations_descriptor = open_private_directory(
            observations, "bootstrap_observation_directory", owner,
        )
        raw_descriptor = open_private_directory(
            raw_directory, "bootstrap_raw_directory", owner,
        )
    try:
        campaign, case = preflight(
            campaign_path, observations, case_id, now, operator_uid=owner,
            protected_projection=protected_projection,
            observations_descriptor=observations_descriptor,
        )
        if protected_projection:
            if raw_descriptor is None:
                raise BootstrapError("bootstrap_raw_directory_untrusted")
            raw_values, raw_custody = raw_set_at(
                campaign, case, raw_descriptor, now, owner,
                allow_historical=True,
            )
        else:
            _, raw_values = raw_set(
                campaign, case, raw_directory, now, raw_uid=owner,
            )
            raw_custody = None
            private_directory(
                observations, "bootstrap_observation_directory",
                expected_uid=owner,
            )
        observed_times = {
            json.loads(raw).get("observed_at")
            for raw in raw_values.values()
            if isinstance(json.loads(raw), dict)
            and "observed_at" in json.loads(raw)
        }
        if (len(observed_times) != 1
                or any(not isinstance(item, int) or isinstance(item, bool)
                       for item in observed_times)):
            raise BootstrapError("bootstrap_raw_observed_at_invalid")
        historical_observed_at = next(iter(observed_times))
        continuation_context = None
        if now - historical_observed_at > MAX_OBSERVATION_SECONDS:
            if not protected_projection or raw_descriptor is None:
                raise BootstrapError("bootstrap_stale_projection_requires_protection")
            manifest = ACCEPTANCE_CLI.verify_protected_driver(
                ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
                campaign["source_commit"], "clean-machine-bootstrap", 0,
            )
            continuation_context = {
                "historical_observed_at": historical_observed_at,
                "protected_driver": "clean-machine-bootstrap",
                "protected_manifest_sha256": manifest["manifest_sha256"],
                "raw_custody_sha256": raw_custody,
            }
        result = project_bound(
            campaign, case, observations, observations_descriptor,
            raw_values, now, protected_projection, owner,
            continuation_context=continuation_context,
        )
        if protected_projection:
            if observations_descriptor is None:
                raise BootstrapError(
                    "bootstrap_observation_directory_untrusted"
                )
            named = observations.lstat()
            if (directory_identity(named)
                    != directory_identity(os.fstat(observations_descriptor))):
                raise BootstrapError(
                    "bootstrap_observation_directory_identity_changed"
                )
            if raw_descriptor is None:
                raise BootstrapError("bootstrap_raw_directory_untrusted")
            named_raw = raw_directory.lstat()
            if (directory_identity(named_raw)
                    != directory_identity(os.fstat(raw_descriptor))):
                raise BootstrapError("bootstrap_raw_directory_identity_changed")
        return result
    finally:
        if raw_descriptor is not None:
            os.close(raw_descriptor)
        if observations_descriptor is not None:
            os.close(observations_descriptor)


def project_bound(campaign: dict[str, Any], case: dict[str, Any],
                  observations: Path, observations_descriptor: int | None,
                  raw_values: dict[str, bytes], now: int,
                  protected_projection: bool, owner: int, *,
                  continuation_context: dict[str, Any] | None = None,
                  ) -> dict[str, Any]:
    case_id = case["case_id"]
    observation_uid = 0 if protected_projection else owner
    observation_mode = 0o444 if protected_projection else 0o600
    existing: dict[str, str] = {}
    missing: list[str] = []
    for kind in case["evidence_kinds"]:
        destination = observations / f"{case_id}.{kind}.json"
        present = (
            f"{case_id}.{kind}.json" in os.listdir(observations_descriptor)
            if protected_projection and observations_descriptor is not None
            else os.path.lexists(destination)
        )
        if present:
            if protected_projection:
                if observations_descriptor is None:
                    raise BootstrapError(
                        "bootstrap_observation_directory_untrusted"
                    )
                existing[kind] = existing_observation_at(
                    observations_descriptor, f"{case_id}.{kind}.json",
                    campaign, case, kind, raw_values,
                )
            else:
                existing[kind] = existing_observation(
                    destination, campaign, case, kind, raw_values,
                    observation_uid=observation_uid,
                    observation_mode=observation_mode,
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
            continuation_path = None
            if continuation_context is not None:
                raw_names = [kind, *SUPPORT[kind]]
                continuation = continuation_record(
                    campaign, CASE_BY_ID[case_id],
                    historical_observed_at=continuation_context[
                        "historical_observed_at"
                    ],
                    continued_at=now,
                    protected_driver=continuation_context["protected_driver"],
                    protected_manifest_sha256=continuation_context[
                        "protected_manifest_sha256"
                    ],
                    raw_sha256={
                        item: hashlib.sha256(raw_values[item]).hexdigest()
                        for item in raw_names
                    },
                    raw_custody_sha256=continuation_context[
                        "raw_custody_sha256"
                    ],
                )
                continuation_path = (
                    snapshots / f"{kind}.continuation-readback.json"
                )
                write_snapshot(continuation_path, canonical(continuation))
            observation = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=artifact_arguments(
                    kind, snapshot_paths, continuation=continuation_path,
                ),
                output_directory=staged, now=now,
                output_mode=observation_mode,
            )
            projected[kind] = observation["observation_sha256"]
        for kind in missing:
            name = f"{case_id}.{kind}.json"
            if protected_projection:
                if observations_descriptor is None:
                    raise BootstrapError(
                        "bootstrap_observation_directory_untrusted"
                    )
                publish_staged_at(
                    staged / name, observations_descriptor, name,
                    mode=observation_mode,
                )
            else:
                publish_staged(
                    staged / name, observations / name, mode=observation_mode,
                )
    if protected_projection:
        if observations_descriptor is None:
            raise BootstrapError("bootstrap_observation_directory_untrusted")
        os.fsync(observations_descriptor)
    else:
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
    project_command.add_argument("--operator-uid", type=int)
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
            operator_uid=args.operator_uid,
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
