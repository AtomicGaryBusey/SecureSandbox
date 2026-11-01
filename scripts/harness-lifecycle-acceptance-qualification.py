#!/usr/bin/env python3
"""Protected Research qualification execution with independent OS controls.

The synthetic candidate remains non-admitting.  ``worker`` runs the fixed
qualification core and can never produce physical evidence by itself.
``execute`` is the root-only Research wrapper: it launches that worker in a
transient systemd unit, independently reads the unit's isolation properties
and empty post-run cgroup, and binds those facts to the campaign and case.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    case_record,
    digest,
    validate_campaign,
)
from harness_lifecycle_qualification_fixture import (  # noqa: E402
    ACCEPTANCE_CASES,
    SCHEMA as CORE_SCHEMA,
    QualificationFixtureError,
    run_case,
)


RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-qualification-research-v1"
MAX_JSON = 1024 * 1024
INSTALL_ROOT = Path(
    "/usr/local/libexec/secure-sandbox/harness-lifecycle-acceptance-qualification"
)
STATE_ROOT = Path("/var/lib/secure-sandbox/harness-lifecycle-acceptance")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
PYTHON = Path("/usr/bin/python3")
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
UNIT = re.compile(r"secure-sandbox-qualification-[a-z0-9-]{1,160}\.service")
FORBIDDEN_ENVIRONMENT = (
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN",
    "GH_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID", "GOOGLE_APPLICATION_CREDENTIALS",
)
SHOW_PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "Result", "ExecMainCode",
    "ExecMainStatus", "NRestarts", "ControlGroup", "TasksMax",
    "PrivateNetwork", "ProtectSystem", "ProtectHome", "PrivateTmp",
    "PrivateDevices", "NoNewPrivileges", "DynamicUser",
    "RestrictAddressFamilies", "IPAddressDeny", "Environment",
    "UnsetEnvironment",
)


class QualificationDriverError(RuntimeError):
    """Stable, content-free protected-driver failure."""


def trusted_json(path: Path, *, expected_uid: int | None = None,
                 maximum: int = MAX_JSON) -> dict[str, Any]:
    owner = os.geteuid() if expected_uid is None else expected_uid
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != owner or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o444, 0o600}
            or not 0 < before.st_size <= maximum):
        raise QualificationDriverError("qualification_input_untrusted")
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
        raise QualificationDriverError("qualification_input_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationDriverError("qualification_input_invalid") from error
    if not isinstance(value, dict) or canonical(value) != bytes(data):
        raise QualificationDriverError("qualification_input_noncanonical")
    return value


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
                raise QualificationDriverError("qualification_output_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def command(argv: list[str], *, accepted: tuple[int, ...] = (0,),
            timeout: float = 60) -> subprocess.CompletedProcess[bytes]:
    try:
        value = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=timeout,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationDriverError("qualification_command_failed") from error
    if (value.returncode not in accepted or len(value.stdout) > MAX_JSON
            or len(value.stderr) > MAX_JSON):
        raise QualificationDriverError("qualification_command_rejected")
    return value


def installed_release(source_commit: str) -> Path:
    if COMMIT.fullmatch(source_commit) is None:
        raise QualificationDriverError("qualification_source_commit_invalid")
    release = ROOT.resolve()
    if (release.parent != INSTALL_ROOT or release.name != source_commit
            or Path(__file__).resolve()
               != release / "scripts/harness-lifecycle-acceptance-qualification.py"):
        raise QualificationDriverError("qualification_protected_release_required")
    return release


def qualification_case(campaign: dict[str, Any], case_id: str) -> dict[str, Any]:
    case = CASE_BY_ID.get(case_id)
    if (case is None or case.category != "qualification"
            or case_id not in ACCEPTANCE_CASES):
        raise QualificationDriverError("qualification_case_invalid")
    record = case_record(case)
    if (record["procedure"]["driver"] != "research-qualification-fixture"
            or campaign["environment"] != "disposable-mac"
            or campaign["production_data_present"] is not False
            or campaign["production_credentials_present"] is not False
            or campaign["synthetic_credentials_only"] is not True):
        raise QualificationDriverError("qualification_campaign_rejected")
    return record


def unit_name(campaign: dict[str, Any], case_id: str) -> str:
    compact = campaign["campaign_id"].replace("-", "")[:16]
    value = f"secure-sandbox-qualification-{compact}-{case_id}.service"
    if UNIT.fullmatch(value) is None:
        raise QualificationDriverError("qualification_unit_invalid")
    return value


def parse_show(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise QualificationDriverError("qualification_unit_readback_invalid") from error
    values: dict[str, str] = {}
    for line in lines:
        name, separator, value = line.partition("=")
        if not separator or name not in SHOW_PROPERTIES or name in values:
            raise QualificationDriverError("qualification_unit_readback_invalid")
        values[name] = value
    if set(values) != set(SHOW_PROPERTIES):
        raise QualificationDriverError("qualification_unit_readback_invalid")
    return values


def validate_unit_properties(values: dict[str, str], expected_unit: str) -> dict[str, Any]:
    try:
        environment = shlex.split(values["Environment"])
        unset = shlex.split(values["UnsetEnvironment"])
        tasks_max = int(values["TasksMax"])
        restarts = int(values["NRestarts"])
        main_status = int(values["ExecMainStatus"])
    except (KeyError, ValueError) as error:
        raise QualificationDriverError("qualification_unit_readback_invalid") from error
    expected_environment = {"LANG=C.UTF-8", "PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1"}
    if (values.get("Id") != expected_unit
            or values.get("LoadState") != "loaded"
            or values.get("ActiveState") != "active"
            or values.get("SubState") != "exited"
            or values.get("Result") != "success"
            or values.get("ExecMainCode") != "1"
            or main_status != 0 or restarts != 0 or tasks_max != 2
            or values.get("PrivateNetwork") != "yes"
            or values.get("ProtectSystem") != "strict"
            or values.get("ProtectHome") != "yes"
            or values.get("PrivateTmp") != "yes"
            or values.get("PrivateDevices") != "yes"
            or values.get("NoNewPrivileges") != "yes"
            or values.get("DynamicUser") != "yes"
            or set(values.get("RestrictAddressFamilies", "").split()) != {"AF_UNIX"}
            or values.get("IPAddressDeny") != "any"
            or set(environment) != expected_environment
            or set(unset) != set(FORBIDDEN_ENVIRONMENT)
            or not values.get("ControlGroup", "").startswith("/")):
        raise QualificationDriverError("qualification_isolation_unverified")
    return {
        "control_group": values["ControlGroup"],
        "dynamic_user": True,
        "environment": sorted(environment),
        "exec_main_status": main_status,
        "ip_address_deny": "any",
        "n_restarts": restarts,
        "no_new_privileges": True,
        "private_devices": True,
        "private_network": True,
        "private_tmp": True,
        "protect_home": True,
        "protect_system": "strict",
        "restrict_address_families": ["AF_UNIX"],
        "tasks_max": tasks_max,
        "unset_environment": sorted(unset),
        "unit": expected_unit,
        "unit_result": "success",
    }


def empty_control_group(control_group: str) -> dict[str, Any]:
    relative = control_group.removeprefix("/")
    root = Path("/sys/fs/cgroup")
    group = root / relative
    try:
        processes = (group / "cgroup.procs").read_text(encoding="ascii").split()
        events = dict(
            line.split(maxsplit=1)
            for line in (group / "cgroup.events").read_text(encoding="ascii").splitlines()
        )
    except (OSError, ValueError) as error:
        raise QualificationDriverError("qualification_cgroup_unreadable") from error
    if processes or events.get("populated") != "0":
        raise QualificationDriverError("qualification_cgroup_not_empty")
    return {"cgroup_procs": [], "populated": False}


def boot_sha256() -> str:
    try:
        raw = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    except OSError as error:
        raise QualificationDriverError("qualification_boot_identity_unavailable") from error
    if not raw.endswith(b"\n") or not 1 < len(raw) <= 128:
        raise QualificationDriverError("qualification_boot_identity_invalid")
    return hashlib.sha256(raw).hexdigest()


def reserve_output(path: Path) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def worker(case_id: str, now: int) -> dict[str, Any]:
    fixture_uid = (0 if ROOT.resolve().parent == INSTALL_ROOT
                   and COMMIT.fullmatch(ROOT.resolve().name) is not None
                   else os.geteuid())
    try:
        value = run_case(case_id, now, fixture_uid=fixture_uid)
    except (QualificationFixtureError, OSError) as error:
        raise QualificationDriverError("qualification_worker_failed") from error
    if (value.get("schema") != CORE_SCHEMA or value.get("case_id") != case_id
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("physical_evidence_eligible") is not False
            or value.get("physical_blocker")
               != "independent_research_observer_required"):
        raise QualificationDriverError("qualification_worker_result_invalid")
    return value


def systemd_argv(unit: str, release: Path, case_id: str, now: int,
                 stdout_path: Path, stderr_path: Path) -> list[str]:
    unset = " ".join(FORBIDDEN_ENVIRONMENT)
    return [
        str(SYSTEMD_RUN), "--quiet", "--wait", f"--unit={unit}",
        "--property=Type=oneshot", "--property=RemainAfterExit=yes",
        "--property=DynamicUser=yes", "--property=PrivateNetwork=yes",
        "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=IPAddressDeny=any", "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
        "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes", "--property=LockPersonality=yes",
        "--property=MemoryDenyWriteExecute=yes", "--property=TasksMax=2",
        "--property=Environment=LANG=C.UTF-8 PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1",
        f"--property=UnsetEnvironment={unset}",
        f"--property=StandardOutput=file:{stdout_path}",
        f"--property=StandardError=file:{stderr_path}",
        str(PYTHON), "-I",
        str(release / "scripts/harness-lifecycle-acceptance-qualification.py"),
        "worker", "--case", case_id, "--now", str(now),
    ]


def execute(campaign_path: Path, case_id: str, output_root: Path,
            now: int) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise QualificationDriverError("qualification_root_required")
    try:
        campaign = validate_campaign(trusted_json(campaign_path, expected_uid=0), now)
    except (AcceptanceError, OSError, QualificationDriverError) as error:
        raise QualificationDriverError("qualification_campaign_invalid") from error
    release = installed_release(campaign["source_commit"])
    case = qualification_case(campaign, case_id)
    root_info = output_root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700):
        raise QualificationDriverError("qualification_output_root_untrusted")
    destination = output_root / case_id
    destination.mkdir(mode=0o700)
    parent = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    stdout_path = destination / "worker.json"
    stderr_path = destination / "worker.stderr"
    reserve_output(stdout_path)
    reserve_output(stderr_path)
    unit = unit_name(campaign, case_id)
    try:
        command(systemd_argv(
            unit, release, case_id, now, stdout_path, stderr_path,
        ), timeout=120)
        arguments = [str(SYSTEMCTL), "show", unit]
        for name in SHOW_PROPERTIES:
            arguments.extend(("--property", name))
        properties = validate_unit_properties(
            parse_show(command(arguments).stdout), unit,
        )
        cgroup = empty_control_group(properties["control_group"])
        core = trusted_json(stdout_path, expected_uid=0)
        if stderr_path.stat().st_size != 0:
            raise QualificationDriverError("qualification_worker_stderr_present")
        if worker_result_invalid(core, case_id):
            raise QualificationDriverError("qualification_worker_result_invalid")
        value = {
            "schema": RESULT_SCHEMA,
            "status": case["expected"],
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "machine_identity_sha256": campaign["machine_identity_sha256"],
            "source_commit": campaign["source_commit"],
            "case_id": case_id,
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "qualification_case_id": ACCEPTANCE_CASES[case_id],
            "core_result": core,
            "core_result_sha256": digest(core),
            "systemd_isolation": properties,
            "cgroup_readback": cgroup,
            "research_boot_sha256": boot_sha256(),
            "observer_scope": "protected-research-systemd",
            "network_connections": [],
            "child_processes_after_completion": [],
            "production_credential_environment": [],
            "candidate_authority": "none",
            "production_material_used": False,
            "physical_evidence_eligible": True,
        }
        value["result_sha256"] = digest(value)
        validate_result(value, campaign, case)
        write_new(destination / "result.json", value)
        return value
    finally:
        command([str(SYSTEMCTL), "stop", unit], accepted=(0, 5), timeout=30)
        command([str(SYSTEMCTL), "reset-failed", unit], accepted=(0, 1, 5), timeout=30)


def worker_result_invalid(value: dict[str, Any], case_id: str) -> bool:
    unsigned = {key: item for key, item in value.items()
                if key != "fixture_result_sha256"}
    return (
        value.get("schema") != CORE_SCHEMA
        or value.get("status") != "verified"
        or value.get("case_id") != case_id
        or value.get("qualification_case_id") != ACCEPTANCE_CASES[case_id]
        or value.get("candidate_authority") != "none"
        or value.get("production_material_used") is not False
        or value.get("physical_evidence_eligible") is not False
        or value.get("physical_blocker") != "independent_research_observer_required"
        or value.get("fixture_result_sha256") != digest(unsigned)
    )


def validate_result(value: dict[str, Any], campaign: dict[str, Any],
                    case: dict[str, Any]) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id",
        "procedure_sha256", "qualification_case_id", "core_result",
        "core_result_sha256", "systemd_isolation", "cgroup_readback",
        "research_boot_sha256", "observer_scope", "network_connections",
        "child_processes_after_completion", "production_credential_environment",
        "candidate_authority", "production_material_used",
        "physical_evidence_eligible", "result_sha256",
    }
    unsigned = {key: item for key, item in value.items() if key != "result_sha256"}
    isolation = value.get("systemd_isolation")
    cgroup = value.get("cgroup_readback")
    core = value.get("core_result")
    isolation_fields = {
        "control_group", "dynamic_user", "environment", "exec_main_status",
        "ip_address_deny", "n_restarts", "no_new_privileges",
        "private_devices", "private_network", "private_tmp", "protect_home",
        "protect_system", "restrict_address_families", "tasks_max",
        "unset_environment", "unit", "unit_result",
    }
    expected_unit = unit_name(campaign, case["case_id"])
    expected_environment = sorted({
        "LANG=C.UTF-8", "PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1",
    })
    if (set(value) != expected or value.get("schema") != RESULT_SCHEMA
            or value.get("status") != case["expected"]
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256")
               != case["procedure"]["procedure_sha256"]
            or value.get("qualification_case_id")
               != ACCEPTANCE_CASES[case["case_id"]]
            or not isinstance(core, dict)
            or worker_result_invalid(core, case["case_id"])
            or value.get("core_result_sha256") != digest(core)
            or not isinstance(isolation, dict) or set(isolation) != isolation_fields
            or isolation.get("dynamic_user") is not True
            or not isinstance(isolation.get("control_group"), str)
            or not isolation["control_group"].startswith("/")
            or isolation.get("environment") != expected_environment
            or isolation.get("exec_main_status") != 0
            or isolation.get("ip_address_deny") != "any"
            or isolation.get("n_restarts") != 0
            or isolation.get("no_new_privileges") is not True
            or isolation.get("private_devices") is not True
            or isolation.get("private_network") is not True
            or isolation.get("private_tmp") is not True
            or isolation.get("protect_home") is not True
            or isolation.get("protect_system") != "strict"
            or isolation.get("restrict_address_families") != ["AF_UNIX"]
            or isolation.get("tasks_max") != 2
            or set(isolation.get("unset_environment", []))
               != set(FORBIDDEN_ENVIRONMENT)
            or isolation.get("unit") != expected_unit
            or isolation.get("unit_result") != "success"
            or not isinstance(cgroup, dict)
            or cgroup != {"cgroup_procs": [], "populated": False}
            or not isinstance(value.get("research_boot_sha256"), str)
            or SHA256.fullmatch(value["research_boot_sha256"]) is None
            or value.get("observer_scope") != "protected-research-systemd"
            or value.get("network_connections") != []
            or value.get("child_processes_after_completion") != []
            or value.get("production_credential_environment") != []
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("physical_evidence_eligible") is not True
            or value.get("result_sha256") != digest(unsigned)):
        raise QualificationDriverError("qualification_result_invalid")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Run protected Research qualification acceptance",
    )
    commands = value.add_subparsers(dest="command", required=True)
    worker_parser = commands.add_parser("worker")
    worker_parser.add_argument("--case", required=True)
    worker_parser.add_argument("--now", type=int, required=True)
    execute_parser = commands.add_parser("execute")
    execute_parser.add_argument("--campaign", type=Path, required=True)
    execute_parser.add_argument("--case", required=True)
    execute_parser.add_argument("--output-root", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "worker":
            value = worker(arguments.case, arguments.now)
        else:
            value = execute(
                arguments.campaign, arguments.case, arguments.output_root,
                int(time.time()),
            )
    except (QualificationDriverError, AcceptanceError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
