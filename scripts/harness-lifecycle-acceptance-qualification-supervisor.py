#!/usr/bin/env python3
"""Protected Host supervisor for Research qualification acceptance cases."""

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


PROTECTED_RELEASES = Path(
    "/usr/local/libexec/secure-sandbox-harness-acceptance/releases"
)
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_campaign,
)


SCHEMA = "secure-sandbox-harness-lifecycle-qualification-supervisor-v1"
QUARANTINE_SCHEMA = "secure-sandbox-harness-lifecycle-qualification-quarantine-v1"
AUTHORITY_SCHEMA = "secure-sandbox-harness-lifecycle-qualification-authority-v1"
SCAN_SCHEMA = "secure-sandbox-harness-lifecycle-qualification-production-scan-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-qualification-supervisor-error-v1"
MEDIA_TYPE = "application/json"
REMOTE_RELEASE_ROOT = Path(
    "/usr/local/libexec/secure-sandbox/harness-lifecycle-acceptance-qualification"
)
REMOTE_STATE_ROOT = Path("/var/lib/secure-sandbox/harness-lifecycle-acceptance")
REMOTE_FILES = {
    "harness-lifecycle-acceptance-qualification.py":
        "scripts/harness-lifecycle-acceptance-qualification.py",
    "harness_lifecycle_acceptance.py": "shared/harness_lifecycle_acceptance.py",
    "harness_lifecycle_qualification_fixture.py":
        "shared/harness_lifecycle_qualification_fixture.py",
    "harness_qualification.py": "shared/harness_qualification.py",
    "harness_qualification_fixture.py": "shared/harness_qualification_fixture.py",
    "claude_core_adapter.py": "shared/claude_core_adapter.py",
    "malicious_harness.py": "fixtures/harness-qualification/malicious_harness.py",
    "install-harness-lifecycle-acceptance-qualification.sh":
        "scripts/install-harness-lifecycle-acceptance-qualification.sh",
}
PRODUCTION_HOME_PATHS = (
    ".anthropic", ".claude", ".config/openai", ".config/gemini", ".gemini",
    ".aws/credentials", ".aws/config",
    ".config/gcloud/application_default_credentials.json",
    ".config/gcloud/credentials.db", ".azure/accessTokens.json",
    ".azure/msal_token_cache.json", ".config/op", ".config/gh/hosts.yml",
    ".netrc",
)


class QualificationSupervisorError(RuntimeError):
    """Stable, content-free Host supervisor failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise QualificationSupervisorError("qualification_supervisor_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMMON = load_script(
    "harness_lifecycle_acceptance_qualification_common",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_acceptance_qualification_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)
QUALIFICATION = load_script(
    "harness_lifecycle_acceptance_qualification_research",
    ROOT / "scripts/harness-lifecycle-acceptance-qualification.py",
)
ENROLLER = load_script(
    "harness_lifecycle_acceptance_qualification_enrollment",
    ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py",
)


def require_protected_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(PROTECTED_RELEASES)
    except ValueError as error:
        raise QualificationSupervisorError(
            "qualification_supervisor_protected_invocation_required",
        ) from error
    if (len(relative.parts) != 3 or relative.parts[1:] != ("scripts", path.name)
            or len(relative.parts[0]) != 40
            or any(item not in "0123456789abcdef" for item in relative.parts[0])):
        raise QualificationSupervisorError(
            "qualification_supervisor_protected_invocation_required",
        )
    return resolved.parent.parent


def private_directory(path: Path, label: str, uid: int | None = None) -> None:
    owner = os.geteuid() if uid is None else uid
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
        raise QualificationSupervisorError(f"{label}_untrusted")


def reserve_case(root: Path, case_id: str) -> Path:
    private_directory(root, "qualification_raw_root")
    destination = root / case_id
    if os.path.lexists(destination):
        raise QualificationSupervisorError("qualification_raw_case_exists")
    destination.mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return destination


def next_case(campaign: dict[str, Any], observations: Path,
              case_id: str) -> dict[str, Any]:
    try:
        value = ACCEPTANCE_CLI.next_case(campaign, observations)
    except (AcceptanceError, OSError) as error:
        raise QualificationSupervisorError(
            "qualification_campaign_status_invalid",
        ) from error
    case = value.get("case")
    expected = CASE_BY_ID.get(case_id)
    if (value.get("status") != "pending" or not isinstance(case, dict)
            or expected is None or expected.category != "qualification"
            or case.get("case_id") != case_id
            or case.get("procedure", {}).get("driver")
               != "research-qualification-fixture"
            or case.get("evidence_kinds") != list(expected.evidence_kinds)):
        raise QualificationSupervisorError("qualification_case_not_next")
    return case


def preflight(campaign_path: Path, observations: Path, case_id: str,
              now: int, release: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        campaign = validate_campaign(
            ACCEPTANCE_CLI.trusted_json(campaign_path), now,
        )
        ACCEPTANCE_CLI.verify_protected_driver(
            PROTECTED_RELEASES.parent, campaign["source_commit"],
            "research-qualification-fixture", 0,
        )
        machine = COMMON.current_machine_identity()
    except (AcceptanceError, COMMON.SupervisorError, OSError) as error:
        raise QualificationSupervisorError("qualification_preflight_failed") from error
    if (release.name != campaign["source_commit"]
            or machine != campaign["machine_identity_sha256"]):
        raise QualificationSupervisorError("qualification_preflight_binding_mismatch")
    private_directory(observations, "qualification_observations")
    return campaign, next_case(campaign, observations, case_id)


def stage_release(release: Path, campaign: dict[str, Any], stage: Path) -> list[Path]:
    files = []
    for name, relative in REMOTE_FILES.items():
        source = release / relative
        raw = ACCEPTANCE_CLI._protected_file(
            source, 0, 0o555 if relative.startswith("scripts/") else 0o444,
        )
        destination = stage / name
        destination.write_bytes(raw)
        destination.chmod(0o700 if name.endswith(".sh") else 0o600)
        files.append(destination)
    campaign_path = stage / "campaign.json"
    campaign_path.write_bytes(canonical(campaign))
    campaign_path.chmod(0o600)
    files.append(campaign_path)
    return files


def deploy(release: Path, campaign: dict[str, Any], destination: Path) -> None:
    for path in (COMMON.CONTROL_CLIENT, COMMON.SSH_CONFIG):
        COMMON.prerequisite(path, executable=path != COMMON.SSH_CONFIG)
    with tempfile.TemporaryDirectory(
            prefix=".qualification-deploy-", dir=destination) as temporary:
        stage = Path(temporary)
        stage.chmod(0o700)
        files = stage_release(release, campaign, stage)
        installer = stage / "install-harness-lifecycle-acceptance-qualification.sh"
        argv = [
            str(COMMON.CONTROL_CLIENT), "client", "--ssh-config",
            str(COMMON.SSH_CONFIG), COMMON.RESEARCH_CONTROL, "deploy",
            installer.name, campaign["campaign_id"], campaign["source_commit"],
        ]
        for path in files:
            argv.extend(("--file", str(path)))
        result = COMMON.command(argv, timeout=120)
        expected = (f"harness-lifecycle-acceptance-qualification:installed:"
                    f"{campaign['campaign_id']}:{campaign['source_commit']}\n").encode()
        if result.stdout != expected:
            raise QualificationSupervisorError("qualification_deployment_invalid")


def run_research(campaign: dict[str, Any], case_id: str) -> dict[str, Any]:
    release = REMOTE_RELEASE_ROOT / campaign["source_commit"]
    campaign_root = REMOTE_STATE_ROOT / campaign["campaign_id"]
    result = COMMON.json_command([
        str(COMMON.SSH), "-F", str(COMMON.SSH_CONFIG), COMMON.RESEARCH_ADMIN,
        str(QUALIFICATION.PYTHON),
        str(release / "scripts/harness-lifecycle-acceptance-qualification.py"),
        "execute", "--campaign", str(campaign_root / "campaign.json"),
        "--case", case_id, "--output-root",
        str(campaign_root / "qualification-fixtures"),
    ], timeout=180)
    return result


def protected_fixture_state(release: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    relative = "fixtures/harness-qualification/malicious_harness.py"
    path = release / relative
    info = path.lstat()
    raw = ACCEPTANCE_CLI._protected_file(path, 0, 0o444)
    if info.st_mode & 0o111:
        raise QualificationSupervisorError("qualification_fixture_executable")
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "mode": stat.S_IMODE(info.st_mode),
        "owner_uid": info.st_uid,
        "link_count": info.st_nlink,
        "executable": False,
        "manifest_sha256": manifest["manifest_sha256"],
        "state": "inert-protected-payload",
    }


def production_scan(home: Path, environment: dict[str, str],
                    runner: Any = subprocess.run) -> dict[str, Any]:
    private_directory(home, "qualification_home")
    present_environment = sorted(
        name for name in ENROLLER.PROVIDER_ENVIRONMENT if environment.get(name)
    )
    present_paths = sorted(
        relative for relative in PRODUCTION_HOME_PATHS
        if os.path.lexists(home / relative)
    )
    if present_environment or present_paths:
        raise QualificationSupervisorError("qualification_production_material_present")
    try:
        ENROLLER.keychain_absent(runner)
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        raise QualificationSupervisorError(
            "qualification_production_keychain_present",
        ) from error
    return {
        "checked_environment": sorted(ENROLLER.PROVIDER_ENVIRONMENT),
        "checked_home_paths": list(PRODUCTION_HOME_PATHS),
        "checked_keychain_services": list(ENROLLER.KEYCHAIN_SERVICES),
        "present_environment": [], "present_home_paths": [],
        "present_keychain_services": [],
    }


def record(schema: str, campaign: dict[str, Any], case: dict[str, Any],
           now: int, status: str, fields: dict[str, Any], digest_field: str) -> dict[str, Any]:
    value = {
        "schema": schema, "status": status,
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"],
        "case_id": case["case_id"],
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observed_at": now, **fields, "candidate_authority": "none",
        "production_material_used": False,
    }
    value[digest_field] = digest(value)
    return value


def validate_record(value: dict[str, Any], campaign: dict[str, Any],
                    case: dict[str, Any], schema: str, digest_field: str,
                    now: int, status: str) -> None:
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    observed = value.get("observed_at")
    if (value.get("schema") != schema or value.get("status") != status
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256")
               != case["procedure"]["procedure_sha256"]
            or not isinstance(observed, int) or isinstance(observed, bool)
            or not campaign["created_at"] <= observed < campaign["expires_at"]
            or observed > now + 300 or now - observed > 3600
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get(digest_field) != digest(unsigned)):
        raise QualificationSupervisorError("qualification_record_invalid")


def collect(campaign_path: Path, observations: Path, raw_root: Path,
            case_id: str, now: int, *, release: Path | None = None,
            home: Path | None = None, environment: dict[str, str] | None = None,
            runner: Any = subprocess.run) -> dict[str, Any]:
    protected_release = release or require_protected_path(Path(__file__))
    campaign, case = preflight(
        campaign_path, observations, case_id, now, protected_release,
    )
    destination = reserve_case(raw_root, case_id)
    manifest = ACCEPTANCE_CLI.verify_protected_driver(
        PROTECTED_RELEASES.parent, campaign["source_commit"],
        "research-qualification-fixture", 0,
    )
    before = protected_fixture_state(protected_release, manifest)
    scan = production_scan(
        home or Path.home(), environment if environment is not None else dict(os.environ),
        runner,
    )
    deploy(protected_release, campaign, destination)
    research = run_research(campaign, case_id)
    try:
        QUALIFICATION.validate_result(research, campaign, case)
    except QUALIFICATION.QualificationDriverError as error:
        raise QualificationSupervisorError(
            "qualification_research_result_invalid",
        ) from error
    after = protected_fixture_state(protected_release, manifest)
    if before != after:
        raise QualificationSupervisorError("qualification_host_fixture_changed")

    quarantine = record(QUARANTINE_SCHEMA, campaign, case, now, "passed", {
        "before": before, "after": after,
        "unchanged": True, "host_execution": False,
    }, "quarantine_sha256")
    authority = record(AUTHORITY_SCHEMA, campaign, case, now, "passed", {
        "research_result_sha256": research["result_sha256"],
        "research_candidate_authority": research["candidate_authority"],
        "admission_performed": False, "activation_performed": False,
        "selector_changed": False, "session_migrated": False,
    }, "authority_sha256")
    production = record(SCAN_SCHEMA, campaign, case, now, "passed", {
        **scan, "production_data_present": False,
        "production_credentials_present": False,
    }, "scan_sha256")
    for value, schema, field in (
        (quarantine, QUARANTINE_SCHEMA, "quarantine_sha256"),
        (authority, AUTHORITY_SCHEMA, "authority_sha256"),
        (production, SCAN_SCHEMA, "scan_sha256"),
    ):
        validate_record(value, campaign, case, schema, field, now, "passed")
    values = {
        "research-result.json": research,
        "quarantine-readback.json": quarantine,
        "authority-readback.json": authority,
        "production-material-scan.json": production,
    }
    for name, value in values.items():
        COMMON.write_new(destination / name, value)
    result = {
        "schema": SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "raw_directory": str(destination), "raw_files": list(values),
        "candidate_authority": "none", "production_material_used": False,
    }
    result["supervisor_sha256"] = digest(result)
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Run one protected Research qualification acceptance case",
    )
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--observations", type=Path, required=True)
    value.add_argument("--raw-root", type=Path, required=True)
    value.add_argument("--case", required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    result = collect(
        arguments.campaign, arguments.observations, arguments.raw_root,
        arguments.case, int(time.time()),
    )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, QualificationSupervisorError, OSError) as error:
        reason = str(error) if isinstance(error, QualificationSupervisorError) \
            else "qualification_supervisor_failed"
        print(json.dumps({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
