#!/usr/bin/env python3
"""Operator CLI for disposable-Mac harness lifecycle acceptance evidence."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import sys
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    assemble_export,
    CAMPAIGN_SCHEMA,
    CASES,
    COLLECTOR_PRIMARY_AUTHORITY,
    DRIVER_ENTRYPOINTS,
    PHYSICAL_DRIVER_BLOCKERS,
    PROTECTED_DRIVER_MANIFEST_SCHEMA,
    PROTECTED_DRIVER_PAYLOADS,
    EVIDENCE_SCHEMA,
    EVIDENCE_KIND_COLLECTOR,
    MAX_CAMPAIGN_SECONDS,
    OBSERVATION_SCHEMA,
    canonical,
    case_record,
    digest,
    suite_sha256,
    validate_campaign,
    validate_enrollment,
    validate_observation,
    verdict,
    SUITE_ID,
)


MAX_JSON = 32 * 1024 * 1024
PROTECTED_INSTALL_ROOT = Path(
    "/usr/local/libexec/secure-sandbox-harness-acceptance"
)
MORNING_PREFLIGHT_SCHEMA = (
    "secure-sandbox-harness-lifecycle-morning-preflight-v1"
)
MORNING_PREFLIGHT_KEYS = {
    "schema", "status", "observed_at", "source_commit", "branch",
    "remote_tips", "machine_identity_sha256", "operator_uid",
    "enrollment_sha256", "production_material_absent",
    "bootstrap_controller_state", "bootstrap_trust_root",
    "parallels_gui_closed", "vm_states", "source_driver_count",
    "source_closure_complete", "protected_driver_count",
    "protected_installation_ready", "touch_id_cases_queued",
    "touch_id_authorization_ready", "next_authorization", "next_action",
    "authority", "preflight_sha256",
}


def _protected_file(path: Path, expected_uid: int, mode: int,
                    maximum: int = MAX_JSON) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != expected_uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= maximum):
        raise AcceptanceError("protected_driver_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if (identity(before) != identity(opened) or identity(opened) != identity(after)
            or len(data) != opened.st_size or len(data) > maximum):
        raise AcceptanceError("protected_driver_file_changed")
    return bytes(data)


def _protected_directory(path: Path, expected_uid: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) not in {0o555, 0o755}):
        raise AcceptanceError("protected_driver_directory_untrusted")


def verify_protected_driver(
    protected_root: Path, source_commit: str, driver: str,
    expected_uid: int = 0,
) -> dict:
    if (len(source_commit) != 40
            or any(character not in "0123456789abcdef" for character in source_commit)
            or driver not in PROTECTED_DRIVER_PAYLOADS):
        raise AcceptanceError("protected_driver_identity_invalid")
    releases = protected_root / "releases"
    release = releases / source_commit
    for directory in (protected_root, releases, release):
        _protected_directory(directory, expected_uid)
    raw = _protected_file(release / "manifest.json", expected_uid, 0o444)
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("protected_driver_manifest_invalid") from error
    if not isinstance(manifest, dict):
        raise AcceptanceError("protected_driver_manifest_invalid")
    unsigned = {key: value for key, value in manifest.items()
                if key != "manifest_sha256"}
    if (canonical(manifest) != raw
            or set(manifest) != {
                "schema", "suite_id", "suite_sha256", "source_commit",
                "drivers", "files", "manifest_sha256",
            }
            or manifest.get("schema") != PROTECTED_DRIVER_MANIFEST_SCHEMA
            or manifest.get("suite_id") != SUITE_ID
            or manifest.get("suite_sha256") != suite_sha256()
            or manifest.get("source_commit") != source_commit
            or manifest.get("manifest_sha256") != digest(unsigned)):
        raise AcceptanceError("protected_driver_manifest_invalid")
    drivers = manifest.get("drivers")
    files = manifest.get("files")
    expected_payloads = list(PROTECTED_DRIVER_PAYLOADS[driver])
    if (not isinstance(drivers, dict) or not drivers
            or any(name not in PROTECTED_DRIVER_PAYLOADS for name in drivers)
            or any(payloads != list(PROTECTED_DRIVER_PAYLOADS[name])
                   for name, payloads in drivers.items())
            or drivers.get(driver) != expected_payloads
            or not isinstance(files, list) or not 1 <= len(files) <= 64
            or files != sorted(files, key=lambda item: item.get("path", "")
                               if isinstance(item, dict) else "")):
        raise AcceptanceError("protected_driver_manifest_invalid")
    records: dict[str, dict] = {}
    for record in files:
        if (not isinstance(record, dict)
                or set(record) != {"mode", "path", "sha256", "size"}
                or not isinstance(record.get("path"), str)
                or record["path"] in records
                or record["path"].startswith("/") or ".." in record["path"].split("/")
                or record.get("mode") not in {0o444, 0o555}
                or not isinstance(record.get("size"), int)
                or isinstance(record.get("size"), bool)
                or not 0 < record["size"] <= MAX_JSON
                or not isinstance(record.get("sha256"), str)
                or len(record["sha256"]) != 64
                or any(value not in "0123456789abcdef" for value in record["sha256"])):
            raise AcceptanceError("protected_driver_manifest_invalid")
        records[record["path"]] = record
    referenced = {
        path for payloads in drivers.values() for path in payloads
    }
    if set(records) != referenced:
        raise AcceptanceError("protected_driver_manifest_invalid")
    actual: set[str] = set()
    for path in release.rglob("*"):
        relative = path.relative_to(release).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != expected_uid:
            raise AcceptanceError("protected_driver_inventory_untrusted")
        if stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) not in {0o555, 0o755}:
                raise AcceptanceError("protected_driver_inventory_untrusted")
        elif stat.S_ISREG(info.st_mode):
            actual.add(relative)
        else:
            raise AcceptanceError("protected_driver_inventory_untrusted")
    if actual != {*records, "manifest.json"}:
        raise AcceptanceError("protected_driver_inventory_untrusted")
    for relative in expected_payloads:
        record = records[relative]
        payload = _protected_file(
            release / relative, expected_uid, record["mode"],
        )
        if (len(payload) != record["size"]
                or not hmac.compare_digest(
                    hashlib.sha256(payload).hexdigest(), record["sha256"],
                )):
            raise AcceptanceError("protected_driver_payload_mismatch")
    return manifest


def driver_readiness(root: Path = ROOT, *, source_commit: str | None = None,
                     protected_root: Path = PROTECTED_INSTALL_ROOT,
                     expected_install_uid: int = 0) -> dict:
    drivers = []
    ready = True
    for driver, relative_paths in DRIVER_ENTRYPOINTS.items():
        missing = []
        rejected = []
        for relative in relative_paths:
            path = root / relative
            try:
                info = path.lstat()
            except FileNotFoundError:
                missing.append(relative)
                continue
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or not 0 < info.st_size <= MAX_JSON):
                rejected.append(relative)
        source_complete = not missing and not rejected
        installation_error = None
        protected_installation = False
        eligibility_error = PHYSICAL_DRIVER_BLOCKERS.get(driver)
        if source_complete and eligibility_error is not None:
            installation_error = eligibility_error
        elif source_complete and source_commit is not None:
            try:
                verify_protected_driver(
                    protected_root, source_commit, driver, expected_install_uid,
                )
            except (AcceptanceError, FileNotFoundError, OSError) as error:
                installation_error = (
                    str(error) if isinstance(error, AcceptanceError)
                    else "protected_driver_installation_missing"
                )
            else:
                protected_installation = True
        elif source_complete:
            installation_error = "protected_driver_source_commit_required"
        available = source_complete and protected_installation
        ready = ready and available
        drivers.append({
            "driver": driver,
            "available": available,
            "entrypoints": list(relative_paths),
            "missing": missing,
            "rejected": rejected,
            "source_complete": source_complete,
            "protected_installation": protected_installation,
            "physical_eligibility": eligibility_error is None,
            "installation_error": installation_error,
        })
    return {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-driver-readiness-v1",
        "status": "ready" if ready else "incomplete",
        "suite_id": SUITE_ID,
        "suite_sha256": suite_sha256(),
        "driver_count": len(DRIVER_ENTRYPOINTS),
        "available_driver_count": sum(item["available"] for item in drivers),
        "drivers": drivers,
        "campaign_initialization_allowed": ready,
        "authority": "none",
    }


def require_driver_readiness(root: Path = ROOT, *, source_commit: str,
                             protected_root: Path = PROTECTED_INSTALL_ROOT,
                             expected_install_uid: int = 0) -> None:
    if driver_readiness(
        root, source_commit=source_commit, protected_root=protected_root,
        expected_install_uid=expected_install_uid,
    )["campaign_initialization_allowed"] is not True:
        raise AcceptanceError("acceptance_driver_inventory_incomplete")


def trusted_json(path: Path, maximum: int = MAX_JSON,
                 expected_uid: int | None = None) -> dict:
    before = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != owner or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < before.st_size <= maximum):
        raise AcceptanceError("input_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > maximum):
        raise AcceptanceError("input_file_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("input_json_invalid") from error
    if not isinstance(value, dict) or canonical(value) != bytes(data):
        raise AcceptanceError("input_json_noncanonical")
    return value


def write_new(path: Path, value: dict) -> None:
    payload = canonical(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AcceptanceError("output_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def trusted_observations(path: Path, observation_uid: int = 0) -> list[dict]:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise AcceptanceError("observation_directory_untrusted")
    expected = {
        f"{case.case_id}.{kind}.json"
        for case in CASES for kind in case.evidence_kinds
    }
    entries = {item.name: item for item in path.iterdir()}
    if set(entries) != expected:
        raise AcceptanceError("observation_file_inventory_invalid")
    return [
        trusted_json(
            entries[f"{case.case_id}.{kind}.json"], 64 * 1024,
            expected_uid=observation_uid,
        )
        for case in CASES for kind in case.evidence_kinds
    ]


def campaign_status(campaign: dict, path: Path, observation_uid: int = 0,
                    directory_uid: int | None = None) -> dict:
    info = path.lstat()
    owner = os.geteuid() if directory_uid is None else directory_uid
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise AcceptanceError("observation_directory_untrusted")
    expected = {
        f"{case.case_id}.{kind}.json": (case, kind)
        for case in CASES for kind in case.evidence_kinds
    }
    entries = {item.name: item for item in path.iterdir()}
    if any(name not in expected for name in entries):
        raise AcceptanceError("observation_file_inventory_invalid")
    completed: list[str] = []
    missing: list[dict[str, object]] = []
    for case in CASES:
        missing_kinds = []
        for kind in case.evidence_kinds:
            name = f"{case.case_id}.{kind}.json"
            if name not in entries:
                missing_kinds.append(kind)
                continue
            observation = trusted_json(
                entries[name], 64 * 1024, expected_uid=observation_uid,
            )
            validate_observation(observation, campaign, case)
            if observation["kind"] != kind:
                raise AcceptanceError("observation_filename_binding_invalid")
        if missing_kinds:
            missing.append({"case_id": case.case_id, "evidence_kinds": missing_kinds})
        else:
            completed.append(case.case_id)
    return {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-status-v1",
        "campaign_id": campaign["campaign_id"],
        "suite_sha256": campaign["suite_sha256"],
        "case_count": len(CASES),
        "observation_count": len(expected),
        "completed_case_count": len(completed),
        "completed_cases": completed,
        "missing": missing,
        "next_case": missing[0]["case_id"] if missing else None,
        "ready_for_assembly": not missing,
        "authority": "none",
    }


def next_case(campaign: dict, path: Path, observation_uid: int = 0,
              directory_uid: int | None = None) -> dict:
    status = campaign_status(campaign, path, observation_uid, directory_uid)
    case_id = status["next_case"]
    if case_id is None:
        return {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-next-v1",
            "campaign_id": campaign["campaign_id"],
            "suite_sha256": campaign["suite_sha256"],
            "status": "complete",
            "case": None,
            "missing_evidence": [],
            "authority": "none",
        }
    case = next(item for item in CASES if item.case_id == case_id)
    missing = next(item["evidence_kinds"] for item in status["missing"]
                   if item["case_id"] == case_id)
    return {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-next-v1",
        "campaign_id": campaign["campaign_id"],
        "suite_sha256": campaign["suite_sha256"],
        "status": "pending",
        "case": case_record(case),
        "missing_evidence": [
            {"kind": kind, "collector": EVIDENCE_KIND_COLLECTOR[kind]}
            for kind in missing
        ],
        "authority": "none",
    }


def initialization_preflight(
    path: Path, enrollment: dict, source_commit: str, now: int,
    expected_uid: int,
) -> dict:
    value = trusted_json(path, 1024 * 1024, expected_uid=expected_uid)
    claimed = value.get("preflight_sha256")
    unsigned = dict(value)
    unsigned.pop("preflight_sha256", None)
    observed = value.get("observed_at")
    states = value.get("vm_states")
    bootstrap = value.get("bootstrap_trust_root")
    expected_bootstrap_paths = ["/", "/private", "/private/var", "/private/var/db"]
    bootstrap_keys = {
        "path", "device", "inode", "uid", "gid", "mode", "acl_present",
    }
    exact_integer = lambda item: (  # noqa: E731
        isinstance(item, int) and not isinstance(item, bool)
    )
    bootstrap_valid = (
        isinstance(bootstrap, list)
        and len(bootstrap) == len(expected_bootstrap_paths)
        and all(
            isinstance(item, dict)
            and set(item) == bootstrap_keys
            and item.get("path") == expected_bootstrap_paths[index]
            and exact_integer(item.get("device")) and item["device"] >= 0
            and exact_integer(item.get("inode")) and item["inode"] > 0
            and exact_integer(item.get("uid")) and item["uid"] == 0
            and exact_integer(item.get("gid")) and item["gid"] >= 0
            and exact_integer(item.get("mode"))
            and 0 <= item["mode"] <= 0o7777
            and item["mode"] & 0o100 != 0
            and item["mode"] & 0o022 == 0
            and item.get("acl_present") is False
            for index, item in enumerate(bootstrap)
        )
    )
    if (set(value) != MORNING_PREFLIGHT_KEYS
            or value.get("schema") != MORNING_PREFLIGHT_SCHEMA
            or value.get("status") != "ready"
            or value.get("source_commit") != source_commit
            or value.get("branch") != "public-release"
            or value.get("remote_tips") != {"origin": source_commit}
            or value.get("machine_identity_sha256")
               != enrollment["machine_identity_sha256"]
            or value.get("enrollment_sha256")
               != enrollment["enrollment_sha256"]
            or not exact_integer(observed)
            or observed > now + 300 or now - observed > 3600
            or not exact_integer(value.get("operator_uid"))
            or value.get("operator_uid") != expected_uid
            or value.get("production_material_absent") is not True
            or value.get("bootstrap_controller_state")
               not in {
                   "absent", "empty-coordination-residue",
                   "installed-synthetic-control-state",
               }
            or not bootstrap_valid
            or value.get("parallels_gui_closed") is not True
            or not isinstance(states, dict)
            or set(states) != {"gateway", "research", "target"}
            or not all(state in {"running", "stopped"}
                       for state in states.values())
            or not exact_integer(value.get("source_driver_count"))
            or value.get("source_driver_count") != len(DRIVER_ENTRYPOINTS)
            or value.get("source_closure_complete") is not True
            or not exact_integer(value.get("protected_driver_count"))
            or value.get("protected_driver_count") != len(DRIVER_ENTRYPOINTS)
            or value.get("protected_installation_ready") is not True
            or not exact_integer(value.get("touch_id_cases_queued"))
            or value.get("touch_id_cases_queued") != 11
            or value.get("touch_id_authorization_ready") is not False
            or value.get("next_authorization") != "none"
            or value.get("next_action")
               != "initialize-exact-commit-campaign"
            or value.get("authority") != "none"
            or not isinstance(claimed, str) or claimed != digest(unsigned)):
        raise AcceptanceError("campaign_preflight_invalid")
    return value


def initialize(enrollment_path: Path, preflight_path: Path,
               source_commit: str, output: Path,
               now: int, lifetime: int, *, driver_root: Path = ROOT,
               protected_root: Path = PROTECTED_INSTALL_ROOT,
               expected_install_uid: int = 0,
               expected_preflight_uid: int | None = None) -> dict:
    require_driver_readiness(
        driver_root, source_commit=source_commit, protected_root=protected_root,
        expected_install_uid=expected_install_uid,
    )
    enrollment = validate_enrollment(
        trusted_json(enrollment_path, 64 * 1024), now, allow_historical=True,
    )
    if len(source_commit) != 40 or any(character not in "0123456789abcdef" for character in source_commit):
        raise AcceptanceError("source_commit_invalid")
    operator_uid = (
        os.geteuid() if expected_preflight_uid is None
        else expected_preflight_uid
    )
    initialization_preflight(
        preflight_path, enrollment, source_commit, now, operator_uid,
    )
    if not 3600 <= lifetime <= MAX_CAMPAIGN_SECONDS:
        raise AcceptanceError("campaign_lifetime_invalid")
    value = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": str(uuid.uuid4()),
        "suite_id": SUITE_ID,
        "suite_sha256": suite_sha256(),
        "machine_identity_sha256": enrollment["machine_identity_sha256"],
        "source_commit": source_commit,
        "created_at": now,
        "expires_at": now + lifetime,
        "environment": "disposable-mac",
        "production_data_present": False,
        "production_credentials_present": False,
        "synthetic_credentials_only": True,
        "authority": "acceptance-evidence-only",
    }
    value["campaign_sha256"] = digest(value)
    validate_campaign(value, now)
    write_new(output, value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Verify disposable-Mac harness lifecycle acceptance")
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("catalog")
    readiness = commands.add_parser("readiness")
    readiness.add_argument("--source-commit")
    initialize_command = commands.add_parser("initialize")
    initialize_command.add_argument("--enrollment", type=Path, required=True)
    initialize_command.add_argument("--preflight", type=Path, required=True)
    initialize_command.add_argument("--source-commit", required=True)
    initialize_command.add_argument("--output", type=Path, required=True)
    initialize_command.add_argument(
        "--lifetime-seconds", type=int, default=MAX_CAMPAIGN_SECONDS,
    )
    campaign = commands.add_parser("verify-campaign")
    campaign.add_argument("path", type=Path)
    status = commands.add_parser("status")
    status.add_argument("--campaign", type=Path, required=True)
    status.add_argument("--observations", type=Path, required=True)
    next_command = commands.add_parser("next")
    next_command.add_argument("--campaign", type=Path, required=True)
    next_command.add_argument("--observations", type=Path, required=True)
    export = commands.add_parser("verify-export")
    export.add_argument("path", type=Path)
    assemble = commands.add_parser("assemble")
    assemble.add_argument("--campaign", type=Path, required=True)
    assemble.add_argument("--observations", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    now = int(time.time())
    if args.command == "catalog":
        result = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-catalog-v1",
            "suite_id": SUITE_ID,
            "suite_sha256": suite_sha256(),
            "case_count": len(CASES),
            "cases": [case_record(case) for case in CASES],
            "authority": "none",
        }
    elif args.command == "readiness":
        result = driver_readiness(source_commit=args.source_commit)
    elif args.command == "initialize":
        result = initialize(
            args.enrollment, args.preflight, args.source_commit, args.output,
            now, args.lifetime_seconds,
        )
    elif args.command == "verify-campaign":
        result = validate_campaign(trusted_json(args.path), now)
    elif args.command == "status":
        campaign = validate_campaign(trusted_json(args.campaign), now)
        result = campaign_status(campaign, args.observations)
    elif args.command == "next":
        campaign = validate_campaign(trusted_json(args.campaign), now)
        result = next_case(campaign, args.observations)
    elif args.command == "verify-export":
        result = verdict(trusted_json(args.path), now)
    else:
        campaign = validate_campaign(trusted_json(args.campaign), now)
        result = assemble_export(campaign, trusted_observations(args.observations), now)
        write_new(args.output, result)
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, AcceptanceError) else "acceptance_io_failed"
        print(json.dumps({
            "schema": "secure-sandbox-harness-lifecycle-acceptance-error-v1",
            "status": "rejected",
            "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
