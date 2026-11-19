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
    CONTINUATION_ARTIFACT_NAME,
    MAX_OBSERVATION_SECONDS,
    canonical,
    continuation_record,
    digest,
    validate_campaign,
    validate_observation,
)


SCHEMA = "secure-sandbox-harness-lifecycle-qualification-projection-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-qualification-projection-error-v1"
MEDIA_TYPE = "application/json"
MAX_JSON = 64 * 1024
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


def private_directory(path: Path, label: str,
                      expected_uid: int | None = None) -> None:
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
        raise QualificationProjectionError(f"{label}_untrusted")


def open_private_directory(path: Path, label: str, expected_uid: int) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise QualificationProjectionError(f"{label}_untrusted") from error
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(descriptor)
        raise QualificationProjectionError(f"{label}_untrusted")
    return descriptor


def directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def trusted_json_at(parent: int, name: str, *, expected_uid: int,
                    expected_mode: int, maximum: int = MAX_JSON
                    ) -> tuple[dict[str, Any], bytes, os.stat_result]:
    if "/" in name or name in {"", ".", ".."}:
        raise QualificationProjectionError("qualification_raw_file_untrusted")
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
        raise QualificationProjectionError(
            "qualification_raw_file_untrusted",
        ) from error
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
        raise QualificationProjectionError("qualification_raw_file_untrusted")
    raw = bytes(chunks)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationProjectionError(
            "qualification_raw_file_untrusted",
        ) from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise QualificationProjectionError("qualification_raw_file_untrusted")
    return value, raw, opened


def trusted_json(path: Path) -> dict[str, Any]:
    try:
        return SUPERVISOR.COMMON.trusted_json(path)
    except SUPERVISOR.COMMON.SupervisorError as error:
        raise QualificationProjectionError("qualification_raw_file_untrusted") from error


def validate_raw_values(campaign: dict[str, Any], case: dict[str, Any],
                        values: dict[str, dict[str, Any]], now: int
                        ) -> dict[str, bytes]:
    if set(values) != set(RAW_FILES):
        raise QualificationProjectionError("qualification_raw_inventory_invalid")
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
    return raw


def raw_set(campaign: dict[str, Any], case: dict[str, Any], raw_directory: Path,
            now: int, *, expected_uid: int | None = None
            ) -> tuple[dict[str, Path], dict[str, dict[str, Any]],
                       dict[str, bytes]]:
    private_directory(
        raw_directory, "qualification_raw_directory",
        expected_uid=expected_uid,
    )
    entries = {item.name: item for item in raw_directory.iterdir()}
    if set(entries) != set(RAW_FILES.values()):
        raise QualificationProjectionError("qualification_raw_inventory_invalid")
    paths = {name: entries[filename] for name, filename in RAW_FILES.items()}
    values = {name: trusted_json(path) for name, path in paths.items()}
    return paths, values, validate_raw_values(campaign, case, values, now)


def raw_set_at(campaign: dict[str, Any], case: dict[str, Any],
               raw_directory: int, now: int, operator_uid: int, *,
               allow_historical: bool = False
               ) -> tuple[dict[str, bytes], str]:
    if set(os.listdir(raw_directory)) != set(RAW_FILES.values()):
        raise QualificationProjectionError("qualification_raw_inventory_invalid")
    values: dict[str, dict[str, Any]] = {}
    opened: dict[str, os.stat_result] = {}
    for name, filename in RAW_FILES.items():
        value, _raw, info = trusted_json_at(
            raw_directory, filename, expected_uid=operator_uid,
            expected_mode=0o600,
        )
        values[name] = value
        opened[filename] = info
    observed_times = {
        value.get("observed_at") for value in values.values()
        if "observed_at" in value
    }
    if (len(observed_times) != 1
            or any(not isinstance(item, int) or isinstance(item, bool)
                   for item in observed_times)):
        raise QualificationProjectionError(
            "qualification_raw_observed_at_invalid",
        )
    historical = next(iter(observed_times))
    validation_time = (
        historical
        if allow_historical and now - historical > MAX_OBSERVATION_SECONDS
        else now
    )
    return (
        validate_raw_values(campaign, case, values, validation_time),
        raw_custody_sha256(opened),
    )


def raw_custody_sha256(opened: dict[str, os.stat_result]) -> str:
    records = []
    for filename, info in sorted(opened.items()):
        records.append({
            "name": filename, "device": info.st_dev, "inode": info.st_ino,
            "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode), "links": info.st_nlink,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns,
        })
    return digest(records)


def artifact_arguments(kind: str, paths: dict[str, Path], *,
                       continuation: Path | None = None) -> list[list[str]]:
    primary_name, primary_authority = PRIMARY[kind]
    arguments = [[kind, primary_authority, str(paths[primary_name]), MEDIA_TYPE]]
    for name in ("research", "quarantine", "authority", "production"):
        if name != primary_name:
            arguments.append([
                CONTEXT_NAMES[name], AUTHORITIES[name], str(paths[name]), MEDIA_TYPE,
            ])
    if continuation is not None:
        arguments.append([
            CONTINUATION_ARTIFACT_NAME, "protected-host",
            str(continuation), MEDIA_TYPE,
        ])
    return arguments


def existing_observation(path: Path, campaign: dict[str, Any],
                         case: dict[str, Any], kind: str,
                         raw: dict[str, bytes], *, observation_uid: int,
                         observation_mode: int) -> str:
    try:
        info = path.lstat()
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
    allowed_names = (names, [*names, CONTINUATION_ARTIFACT_NAME])
    authorities = [authority] + [AUTHORITIES[name] for name in ordered[1:]]
    artifacts = value.get("evidence", {}).get("artifacts") \
        if isinstance(value, dict) else None
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != observation_uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != observation_mode
            or not isinstance(value, dict) or canonical(value) != payload
            or value.get("kind") != kind or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts
                if isinstance(item, dict)] not in allowed_names
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


def existing_observation_at(parent: int, name: str,
                            campaign: dict[str, Any], case: dict[str, Any],
                            kind: str, raw: dict[str, bytes]) -> str:
    value, payload, info = trusted_json_at(
        parent, name, expected_uid=0, expected_mode=0o444,
    )
    primary, authority = PRIMARY[kind]
    ordered = [primary] + [name for name in (
        "research", "quarantine", "authority", "production",
    ) if name != primary]
    names = [kind] + [CONTEXT_NAMES[item] for item in ordered[1:]]
    allowed_names = (names, [*names, CONTINUATION_ARTIFACT_NAME])
    authorities = [authority] + [AUTHORITIES[item] for item in ordered[1:]]
    artifacts = value.get("evidence", {}).get("artifacts") \
        if isinstance(value, dict) else None
    if (not stat.S_ISREG(info.st_mode) or value.get("kind") != kind
            or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts
                if isinstance(item, dict)] not in allowed_names
            or any(not isinstance(item, dict)
                   or item.get("authority") != expected_authority
                   or item.get("sha256") != hashlib.sha256(raw[item_name]).hexdigest()
                   for item, item_name, expected_authority
                   in zip(artifacts, ordered, authorities))
            or canonical(value) != payload):
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


def require_protected_release(campaign: dict[str, Any]) -> Path:
    expected = (
        ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT / "releases"
        / campaign["source_commit"]
    )
    try:
        resolved = ROOT.resolve(strict=True)
    except OSError as error:
        raise QualificationProjectionError(
            "qualification_protected_release_required",
        ) from error
    if resolved != expected or os.geteuid() != 0:
        raise QualificationProjectionError(
            "qualification_protected_release_required",
        )
    try:
        ACCEPTANCE_CLI.verify_protected_driver(
            ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
            campaign["source_commit"],
            "research-qualification-fixture", 0,
        )
    except (AcceptanceError, FileNotFoundError, OSError) as error:
        raise QualificationProjectionError(
            "qualification_protected_release_required",
        ) from error
    return resolved


def next_qualification_case_at(campaign: dict[str, Any], observations: int,
                               case_id: str) -> dict[str, Any]:
    entries = set(os.listdir(observations))
    expected = {
        f"{case.case_id}.{kind}.json"
        for case in ACCEPTANCE_CLI.CASES for kind in case.evidence_kinds
    }
    if not entries <= expected:
        raise QualificationProjectionError(
            "qualification_campaign_status_invalid",
        )
    next_id = None
    for suite_case in ACCEPTANCE_CLI.CASES:
        missing = False
        for kind in suite_case.evidence_kinds:
            name = f"{suite_case.case_id}.{kind}.json"
            if name not in entries:
                missing = True
                continue
            try:
                value = trusted_json_at(
                    observations, name, expected_uid=0, expected_mode=0o444,
                )[0]
                validate_observation(value, campaign, suite_case)
            except (AcceptanceError, QualificationProjectionError) as error:
                raise QualificationProjectionError(
                    "qualification_campaign_status_invalid",
                ) from error
            if value.get("kind") != kind:
                raise QualificationProjectionError(
                    "qualification_campaign_status_invalid",
                )
        present = any(
            f"{suite_case.case_id}.{kind}.json" in entries
            for kind in suite_case.evidence_kinds
        )
        if missing:
            if next_id is None:
                next_id = suite_case.case_id
            elif present:
                raise QualificationProjectionError(
                    "qualification_campaign_status_invalid",
                )
        elif next_id is not None:
            raise QualificationProjectionError(
                "qualification_campaign_status_invalid",
            )
    expected_case = CASE_BY_ID.get(case_id)
    record = (
        ACCEPTANCE_CLI.case_record(expected_case)
        if expected_case is not None else None
    )
    if (next_id != case_id or expected_case is None
            or expected_case.category != "qualification"
            or record is None
            or record.get("procedure", {}).get("driver")
               != "research-qualification-fixture"
            or record.get("evidence_kinds")
               != list(expected_case.evidence_kinds)):
        raise QualificationProjectionError("qualification_case_not_next")
    return record


def write_snapshot(path: Path, raw: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise QualificationProjectionError(
                        "qualification_snapshot_write_failed",
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise QualificationProjectionError(
            "qualification_snapshot_write_failed",
        ) from error


def publish_staged_at(staged: Path, parent: int, name: str) -> None:
    try:
        staged_raw = OBSERVER.trusted_read(staged)
        value = json.loads(staged_raw)
        if not isinstance(value, dict) or canonical(value) != staged_raw:
            raise QualificationProjectionError(
                "qualification_observation_publication_failed",
            )
        payload = canonical(value)
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o444, dir_fd=parent,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise QualificationProjectionError(
                        "qualification_observation_publication_failed",
                    )
                view = view[written:]
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (AcceptanceError, OSError, UnicodeDecodeError,
            json.JSONDecodeError) as error:
        raise QualificationProjectionError(
            "qualification_observation_publication_failed",
        ) from error


def project(campaign_path: Path, observations: Path, case_id: str,
            raw_directory: Path, now: int, *, operator_uid: int | None = None
            ) -> dict[str, Any]:
    protected_projection = operator_uid is not None
    owner = os.geteuid() if operator_uid is None else operator_uid
    if protected_projection and (os.geteuid() != 0 or not 1 <= owner < 2 ** 31):
        raise QualificationProjectionError(
            "qualification_protected_projection_context_required",
        )
    observations_descriptor = None
    raw_descriptor = None
    if protected_projection:
        observations_descriptor = open_private_directory(
            observations, "qualification_observations", owner,
        )
        raw_descriptor = open_private_directory(
            raw_directory, "qualification_raw_directory", owner,
        )
    try:
        try:
            campaign = validate_campaign(
                ACCEPTANCE_CLI.trusted_json(
                    campaign_path, expected_uid=owner,
                ),
                now,
            )
            if protected_projection:
                require_protected_release(campaign)
                if observations_descriptor is None:
                    raise QualificationProjectionError(
                        "qualification_observations_untrusted",
                    )
                case = next_qualification_case_at(
                    campaign, observations_descriptor, case_id,
                )
            else:
                case = SUPERVISOR.next_case(campaign, observations, case_id)
                release = SUPERVISOR.require_protected_path(
                    ROOT / "scripts/harness-lifecycle-acceptance-qualification-supervisor.py",
                )
                if release.name != campaign["source_commit"]:
                    raise QualificationProjectionError(
                        "qualification_projection_binding_mismatch",
                    )
            ACCEPTANCE_CLI.verify_protected_driver(
                SUPERVISOR.PROTECTED_RELEASES.parent,
                campaign["source_commit"],
                "research-qualification-fixture", 0,
            )
            machine = SUPERVISOR.COMMON.current_machine_identity()
        except (AcceptanceError, OSError, QualificationProjectionError,
                SUPERVISOR.QualificationSupervisorError,
                SUPERVISOR.COMMON.SupervisorError) as error:
            raise QualificationProjectionError(
                "qualification_projection_preflight_failed",
            ) from error
        if machine != campaign["machine_identity_sha256"]:
            raise QualificationProjectionError(
                "qualification_projection_binding_mismatch",
            )
        if protected_projection:
            if raw_descriptor is None:
                raise QualificationProjectionError(
                    "qualification_raw_directory_untrusted",
                )
            raw, raw_custody = raw_set_at(
                campaign, case, raw_descriptor, now, owner,
                allow_historical=True,
            )
        else:
            private_directory(
                observations, "qualification_observations",
                expected_uid=owner,
            )
            _, _, raw = raw_set(
                campaign, case, raw_directory, now, expected_uid=owner,
            )
            raw_custody = None
        observed_times = {
            value.get("observed_at")
            for payload in raw.values()
            for value in (json.loads(payload),)
            if isinstance(value, dict) and "observed_at" in value
        }
        if (len(observed_times) != 1
                or any(not isinstance(item, int) or isinstance(item, bool)
                       for item in observed_times)):
            raise QualificationProjectionError(
                "qualification_raw_observed_at_invalid",
            )
        historical_observed_at = next(iter(observed_times))
        continuation_context = None
        if now - historical_observed_at > MAX_OBSERVATION_SECONDS:
            if not protected_projection or raw_descriptor is None:
                raise QualificationProjectionError(
                    "qualification_stale_projection_requires_protection",
                )
            manifest = ACCEPTANCE_CLI.verify_protected_driver(
                ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
                campaign["source_commit"],
                "research-qualification-fixture", 0,
            )
            continuation_context = {
                "historical_observed_at": historical_observed_at,
                "protected_manifest_sha256": manifest["manifest_sha256"],
                "raw_custody_sha256": raw_custody,
            }
        result = project_bound(
            campaign, case, observations, observations_descriptor,
            raw, now, protected_projection, owner,
            continuation_context=continuation_context,
        )
        if protected_projection:
            if observations_descriptor is None or raw_descriptor is None:
                raise QualificationProjectionError(
                    "qualification_projection_directory_untrusted",
                )
            if (directory_identity(observations.lstat())
                    != directory_identity(os.fstat(observations_descriptor))
                    or directory_identity(raw_directory.lstat())
                    != directory_identity(os.fstat(raw_descriptor))):
                raise QualificationProjectionError(
                    "qualification_projection_directory_identity_changed",
                )
        return result
    finally:
        if raw_descriptor is not None:
            os.close(raw_descriptor)
        if observations_descriptor is not None:
            os.close(observations_descriptor)


def project_bound(campaign: dict[str, Any], case: dict[str, Any],
                  observations: Path, observations_descriptor: int | None,
                  raw: dict[str, bytes], now: int,
                  protected_projection: bool, owner: int, *,
                  continuation_context: dict[str, Any] | None = None,
                  ) -> dict[str, Any]:
    case_id = case["case_id"]
    observation_uid = 0 if protected_projection else owner
    observation_mode = 0o444 if protected_projection else 0o600
    projected: dict[str, str] = {}
    existing: list[str] = []
    created: list[str] = []
    missing: list[str] = []
    for kind in case["evidence_kinds"]:
        name = f"{case_id}.{kind}.json"
        output = observations / name
        present = (
            name in os.listdir(observations_descriptor)
            if protected_projection and observations_descriptor is not None
            else os.path.lexists(output)
        )
        if present:
            if protected_projection:
                if observations_descriptor is None:
                    raise QualificationProjectionError(
                        "qualification_observations_untrusted",
                    )
                projected[kind] = existing_observation_at(
                    observations_descriptor, name, campaign, case, kind, raw,
                )
            else:
                projected[kind] = existing_observation(
                    output, campaign, case, kind, raw,
                    observation_uid=observation_uid,
                    observation_mode=observation_mode,
                )
            existing.append(kind)
        else:
            missing.append(kind)
    with tempfile.TemporaryDirectory(
            prefix="secure-sandbox-qualification-projection.") as temporary:
        stage = Path(temporary)
        stage.chmod(0o700)
        snapshots = stage / "raw"
        snapshots.mkdir(mode=0o700)
        snapshot_paths: dict[str, Path] = {}
        for name, payload in raw.items():
            path = snapshots / RAW_FILES[name]
            write_snapshot(path, payload)
            snapshot_paths[name] = path
        output_stage = stage / "observations"
        output_stage.mkdir(mode=0o700)
        staged_results: dict[str, dict[str, Any]] = {}
        for kind in missing:
            continuation_path = None
            if continuation_context is not None:
                primary, _authority = PRIMARY[kind]
                ordered = [primary] + [name for name in (
                    "research", "quarantine", "authority", "production",
                ) if name != primary]
                artifact_names = [kind] + [
                    CONTEXT_NAMES[name] for name in ordered[1:]
                ]
                continuation = continuation_record(
                    campaign, CASE_BY_ID[case_id],
                    historical_observed_at=continuation_context[
                        "historical_observed_at"
                    ],
                    continued_at=now,
                    protected_driver="research-qualification-fixture",
                    protected_manifest_sha256=continuation_context[
                        "protected_manifest_sha256"
                    ],
                    raw_sha256={
                        artifact_name: hashlib.sha256(raw[raw_name]).hexdigest()
                        for artifact_name, raw_name
                        in zip(artifact_names, ordered)
                    },
                    raw_custody_sha256=continuation_context[
                        "raw_custody_sha256"
                    ],
                )
                continuation_path = (
                    snapshots / f"{kind}.continuation-readback.json"
                )
                write_snapshot(continuation_path, canonical(continuation))
            result = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=artifact_arguments(
                    kind, snapshot_paths, continuation=continuation_path,
                ),
                output_directory=output_stage, now=now,
                output_mode=0o600,
            )
            projected[kind] = result["observation_sha256"]
            staged_results[kind] = result
            created.append(kind)
        for kind in missing:
            name = f"{case_id}.{kind}.json"
            if protected_projection:
                if observations_descriptor is None:
                    raise QualificationProjectionError(
                        "qualification_observations_untrusted",
                    )
                publish_staged_at(
                    output_stage / name, observations_descriptor, name,
                )
            else:
                OBSERVER.write_new(
                    observations / name, staged_results[kind], mode=0o600,
                )
    if protected_projection:
        if observations_descriptor is None:
            raise QualificationProjectionError(
                "qualification_observations_untrusted",
            )
        os.fsync(observations_descriptor)
    else:
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
    value.add_argument("--operator-uid", type=int)
    return value


def main() -> int:
    arguments = parser().parse_args()
    result = project(
        arguments.campaign, arguments.observations, arguments.case,
        arguments.raw_directory, int(time.time()),
        operator_uid=arguments.operator_uid,
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
