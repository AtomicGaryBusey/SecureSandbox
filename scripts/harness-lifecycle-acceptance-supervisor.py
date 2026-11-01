#!/usr/bin/env python3
"""Host supervisor for disposable Research recovery acceptance cases.

This executable has one destructive target: the suite-bound Research VM for a
power-loss recovery case.  It does not admit, activate, download, or select a
harness and it emits raw fixed-collector artifacts rather than observations.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_campaign,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-supervisor-v1"
FAULT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-fault-injection-v1"
COLD_BOOT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-cold-boot-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-supervisor-error-v1"
POWER_ACKNOWLEDGEMENT = "HARD POWER ONLY THE DISPOSABLE RESEARCH VM"
RESEARCH_VM = "SecureSandbox-Research"
RESEARCH_ADMIN = "sandbox-research-admin"
RESEARCH_CONTROL = "sandbox-research-control"
PRLCTL = Path("/Applications/Parallels Desktop.app/Contents/MacOS/prlctl")
PGREP = Path("/usr/bin/pgrep")
SSH = Path("/usr/bin/ssh")
GIT = Path("/usr/bin/git")
CONTROL_CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
LOCK = Path(tempfile.gettempdir()) / "secure-sandbox-lifecycle.lock"
REMOTE_RELEASE_ROOT = Path("/usr/local/libexec/secure-sandbox/harness-lifecycle-acceptance-recovery")
REMOTE_STATE_ROOT = Path("/var/lib/secure-sandbox/harness-lifecycle-acceptance")
MAX_OUTPUT = 64 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID_LINE = re.compile(rb'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"')
SERIAL_LINE = re.compile(rb'"IOPlatformSerialNumber"\s*=\s*"([^"\r\n]{1,128})"')
MODEL_LINE = re.compile(rb'"model"\s*=\s*<"([^"\r\n]{1,128})')
SOURCE_FILES = {
    "harness-lifecycle-acceptance-recovery.py": "scripts/harness-lifecycle-acceptance-recovery.py",
    "harness_lifecycle_acceptance.py": "shared/harness_lifecycle_acceptance.py",
    "harness_lifecycle_acceptance_fixture.py": "shared/harness_lifecycle_acceptance_fixture.py",
    "harness_generation_store.py": "shared/harness_generation_store.py",
    "harness_archive_preflight.py": "shared/harness_archive_preflight.py",
    "harness_lifecycle.py": "shared/harness_lifecycle.py",
    "harness_runtime_binding.py": "shared/harness_runtime_binding.py",
    "privileged_workflow.py": "shared/privileged_workflow.py",
    "install-harness-lifecycle-acceptance-recovery.sh":
        "scripts/install-harness-lifecycle-acceptance-recovery.sh",
}


class SupervisorError(RuntimeError):
    """Stable, content-free supervisor failure."""


def trusted_json(path: Path, maximum: int = MAX_OUTPUT) -> dict[str, Any]:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.geteuid() or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < before.st_size <= maximum):
        raise SupervisorError("supervisor_input_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns)
            != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > maximum):
        raise SupervisorError("supervisor_input_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SupervisorError("supervisor_input_invalid") from error
    if not isinstance(value, dict) or canonical(value) != data:
        raise SupervisorError("supervisor_input_noncanonical")
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
                raise SupervisorError("supervisor_output_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def command(argv: list[str], *, timeout: float = 30,
            accepted: tuple[int, ...] = (0,),
            maximum: int = MAX_OUTPUT,
            environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
            start_new_session=True,
            cwd=ROOT,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SupervisorError("supervisor_command_failed") from error
    if (len(result.stdout) > maximum or len(result.stderr) > maximum
            or result.returncode not in accepted):
        raise SupervisorError("supervisor_command_rejected")
    return result


def json_command(argv: list[str], *, timeout: float = 30,
                 canonical_output: bool = True) -> dict[str, Any]:
    result = command(argv, timeout=timeout)
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SupervisorError("supervisor_command_json_invalid") from error
    if (not isinstance(value, dict)
            or (canonical_output and canonical(value) != result.stdout)):
        raise SupervisorError("supervisor_command_json_noncanonical")
    return value


def prerequisite(path: Path, *, executable: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise SupervisorError("supervisor_prerequisite_missing") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (executable and not os.access(path, os.X_OK))):
        raise SupervisorError("supervisor_prerequisite_untrusted")


def verify_source_checkout(campaign: dict[str, Any]) -> None:
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    head = command(
        [str(GIT), "rev-parse", "--verify", "HEAD^{commit}"],
        environment=environment,
    ).stdout
    if head != f"{campaign['source_commit']}\n".encode("ascii"):
        raise SupervisorError("supervisor_source_checkout_mismatch")
    command(
        [str(GIT), "diff", "--quiet", "--exit-code", campaign["source_commit"], "--"],
        environment=environment,
    )


def acquire_lock() -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(LOCK, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise SupervisorError("supervisor_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise SupervisorError("supervisor_already_running") from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def vm_state(name: str) -> str:
    result = command([str(PRLCTL), "list", "--all", "--json", name])
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SupervisorError("supervisor_vm_inventory_invalid") from error
    if (not isinstance(value, list) or len(value) != 1
            or value[0].get("name") != name
            or value[0].get("status") not in {"running", "stopped"}):
        raise SupervisorError("supervisor_vm_inventory_invalid")
    return str(value[0]["status"])


def vm_inventory() -> dict[str, str]:
    return {
        "gateway": vm_state("SecureSandbox-Gateway"),
        "research": vm_state(RESEARCH_VM),
        "target": vm_state("SecureSandbox-Target"),
    }


def require_gui_closed() -> None:
    result = command([str(PGREP), "-x", "prl_client_app"], accepted=(0, 1))
    if result.returncode == 0:
        raise SupervisorError("parallels_gui_must_be_closed")


def current_machine_identity() -> str:
    if platform.system() != "Darwin" or platform.machine() not in {"arm64", "x86_64"}:
        raise SupervisorError("supervisor_disposable_mac_required")
    result = command([
        "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice",
    ], maximum=1024 * 1024)
    platform_uuid = UUID_LINE.search(result.stdout)
    serial = SERIAL_LINE.search(result.stdout)
    model = MODEL_LINE.search(result.stdout)
    if platform_uuid is None or serial is None or model is None:
        raise SupervisorError("supervisor_machine_identity_invalid")
    material = b"\0".join(
        (platform_uuid.group(1).lower(), serial.group(1), model.group(1)),
    )
    return hashlib.sha256(material).hexdigest()


def remote_worker(campaign: dict[str, Any], operation: str,
                  case_id: str) -> list[str]:
    release = REMOTE_RELEASE_ROOT / campaign["source_commit"] / "recovery.py"
    remote_campaign = REMOTE_STATE_ROOT / campaign["campaign_id"] / "campaign.json"
    return [
        str(SSH), "-F", str(SSH_CONFIG), RESEARCH_ADMIN,
        "/usr/bin/python3", str(release), operation,
        "--campaign", str(remote_campaign), "--case", case_id,
    ]


def remote_json(campaign: dict[str, Any], operation: str,
                case_id: str, *, timeout: float = 30) -> dict[str, Any]:
    return json_command(remote_worker(campaign, operation, case_id), timeout=timeout)


def read_worker_checkpoint(process: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    if process.stdout is None:
        raise SupervisorError("supervisor_worker_pipe_missing")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        ready = selector.select(timeout)
        if not ready:
            raise SupervisorError("supervisor_checkpoint_timeout")
        raw = process.stdout.readline(MAX_OUTPUT + 1)
    finally:
        selector.close()
    if not raw or len(raw) > MAX_OUTPUT:
        raise SupervisorError("supervisor_checkpoint_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SupervisorError("supervisor_checkpoint_invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise SupervisorError("supervisor_checkpoint_noncanonical")
    return value


def stage_exact_commit(campaign: dict[str, Any], directory: Path) -> list[Path]:
    commit = campaign["source_commit"]
    git_environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    command(
        [str(GIT), "cat-file", "-e", f"{commit}^{{commit}}"],
        environment=git_environment,
    )
    staged: list[Path] = []
    for name, source in SOURCE_FILES.items():
        result = command(
            [str(GIT), "cat-file", "blob", f"{commit}:{source}"],
            maximum=1024 * 1024, environment=git_environment,
        )
        if not result.stdout or len(result.stdout) > 1024 * 1024:
            raise SupervisorError("supervisor_source_blob_invalid")
        destination = directory / name
        destination.write_bytes(result.stdout)
        destination.chmod(0o700 if name.endswith(".sh") else 0o600)
        staged.append(destination)
    campaign_destination = directory / "campaign.json"
    campaign_destination.write_bytes(canonical(campaign))
    campaign_destination.chmod(0o600)
    staged.append(campaign_destination)
    return staged


def deploy(campaign: dict[str, Any], staging_root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix=".acceptance-deploy-",
                                     dir=staging_root) as temporary:
        stage = Path(temporary)
        stage.chmod(0o700)
        files = stage_exact_commit(campaign, stage)
        installer = stage / "install-harness-lifecycle-acceptance-recovery.sh"
        argv = [
            str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
            RESEARCH_CONTROL, "deploy", installer.name,
            campaign["campaign_id"], campaign["source_commit"],
        ]
        for path in files:
            argv.extend(("--file", str(path)))
        result = command(argv, timeout=120)
        expected = (f"harness-lifecycle-acceptance-recovery:installed:"
                    f"{campaign['campaign_id']}:{campaign['source_commit']}\n").encode()
        if result.stdout != expected:
            raise SupervisorError("supervisor_deployment_invalid")


def next_recovery_case(campaign_path: Path, observations: Path,
                       requested: str) -> dict[str, Any]:
    value = json_command([
        sys.executable, str(ROOT / "scripts/harness-lifecycle-acceptance.py"), "next",
        "--campaign", str(campaign_path), "--observations", str(observations),
    ], canonical_output=False)
    record = value.get("case")
    if (value.get("status") != "pending" or not isinstance(record, dict)
            or record.get("case_id") != requested or record.get("category") != "recovery"
            or record.get("expected") != "passed"
            or not isinstance(record.get("procedure"), dict)
            or record["procedure"].get("driver") != "research-recovery-fixture"):
        raise SupervisorError("supervisor_case_not_next_recovery_case")
    return record


def validate_checkpoint(campaign: dict[str, Any], case: dict[str, Any],
                        checkpoint: dict[str, Any]) -> None:
    unsigned = {key: value for key, value in checkpoint.items()
                if key != "checkpoint_sha256"}
    if (checkpoint.get("schema")
            != "secure-sandbox-harness-lifecycle-acceptance-checkpoint-v1"
            or checkpoint.get("status") != "recorded"
            or checkpoint.get("campaign_id") != campaign["campaign_id"]
            or checkpoint.get("campaign_sha256") != campaign["campaign_sha256"]
            or checkpoint.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or checkpoint.get("source_commit") != campaign["source_commit"]
            or checkpoint.get("case_id") != case["case_id"]
            or checkpoint.get("checkpoint")
               != case["procedure"]["interruption_checkpoint"]
            or not isinstance(checkpoint.get("worker_pid"), int)
            or not isinstance(checkpoint.get("worker_start_time"), int)
            or not isinstance(checkpoint.get("research_boot_sha256"), str)
            or len(checkpoint["research_boot_sha256"]) != 64
            or checkpoint.get("candidate_authority") != "none"
            or checkpoint.get("production_material_used") is not False
            or checkpoint.get("checkpoint_sha256") != digest(unsigned)):
        raise SupervisorError("supervisor_checkpoint_binding_invalid")


def wait_vm_state(name: str, expected: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if vm_state(name) == expected:
                return
        except SupervisorError:
            pass
        time.sleep(0.5)
    raise SupervisorError("supervisor_vm_transition_unverified")


def wait_research_control(timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            command([
                str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
                RESEARCH_CONTROL, "--timeout-seconds", "3", "run", "control-status",
            ], timeout=8)
            return
        except SupervisorError:
            time.sleep(1)
    raise SupervisorError("supervisor_research_restart_unreachable")


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise SupervisorError("supervisor_worker_transport_stuck") from error


def validate_stop(campaign: dict[str, Any], case: dict[str, Any],
                  checkpoint: dict[str, Any], value: dict[str, Any]) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256", "case_id",
        "checkpoint", "checkpoint_sha256", "worker_pid", "worker_start_time",
        "process_state", "research_boot_sha256", "candidate_authority",
        "production_material_used", "stop_sha256",
    }
    unsigned = {key: item for key, item in value.items() if key != "stop_sha256"}
    if (set(value) != expected
            or value.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-worker-stop-v1"
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("case_id") != case["case_id"]
            or value.get("checkpoint") != checkpoint["checkpoint"]
            or value.get("checkpoint_sha256") != checkpoint["checkpoint_sha256"]
            or value.get("worker_pid") != checkpoint["worker_pid"]
            or value.get("worker_start_time") != checkpoint["worker_start_time"]
            or value.get("process_state") not in {"T", "t"}
            or value.get("research_boot_sha256")
               != checkpoint["research_boot_sha256"]
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("stop_sha256") != digest(unsigned)):
        raise SupervisorError("supervisor_worker_stop_unverified")


def validate_termination(campaign: dict[str, Any], case: dict[str, Any],
                         checkpoint: dict[str, Any], value: dict[str, Any]) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256", "case_id",
        "checkpoint", "checkpoint_sha256", "worker_pid", "worker_start_time",
        "research_boot_sha256", "signal", "candidate_authority",
        "production_material_used", "termination_sha256",
    }
    unsigned = {key: item for key, item in value.items()
                if key != "termination_sha256"}
    if (set(value) != expected
            or value.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-worker-termination-v1"
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("case_id") != case["case_id"]
            or value.get("checkpoint") != checkpoint["checkpoint"]
            or value.get("checkpoint_sha256") != checkpoint["checkpoint_sha256"]
            or value.get("worker_pid") != checkpoint["worker_pid"]
            or value.get("worker_start_time") != checkpoint["worker_start_time"]
            or value.get("research_boot_sha256")
               != checkpoint["research_boot_sha256"]
            or value.get("signal") != "SIGKILL"
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("termination_sha256") != digest(unsigned)):
        raise SupervisorError("supervisor_worker_termination_invalid")


def validate_boot(campaign: dict[str, Any], case: dict[str, Any],
                  value: dict[str, Any]) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256", "case_id",
        "research_boot_sha256", "candidate_authority", "production_material_used",
        "boot_sha256",
    }
    unsigned = {key: item for key, item in value.items() if key != "boot_sha256"}
    if (set(value) != expected
            or value.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-research-boot-v1"
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("case_id") != case["case_id"]
            or not isinstance(value.get("research_boot_sha256"), str)
            or SHA256.fullmatch(value["research_boot_sha256"]) is None
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("boot_sha256") != digest(unsigned)):
        raise SupervisorError("supervisor_boot_readback_invalid")


def validate_fault(campaign: dict[str, Any], case: dict[str, Any],
                   value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id",
        "procedure_sha256", "interaction", "checkpoint", "checkpoint_sha256",
        "worker_checkpoint", "worker_stop", "worker_termination", "vm_before",
        "vm_stopped", "vm_restarted", "vm_after", "candidate_authority",
        "production_material_used", "fault_sha256",
    }
    unsigned = {key: item for key, item in value.items() if key != "fault_sha256"}
    checkpoint = value.get("worker_checkpoint")
    stopped = value.get("worker_stop")
    termination = value.get("worker_termination")
    before = value.get("vm_before")
    stopped_inventory = value.get("vm_stopped")
    restarted = value.get("vm_restarted")
    after = value.get("vm_after")
    interaction = case["procedure"]["interaction"]
    if (set(value) != expected
            or value.get("schema") != FAULT_SCHEMA
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256")
               != case["procedure"]["procedure_sha256"]
            or value.get("interaction") != interaction
            or not isinstance(checkpoint, dict)
            or value.get("checkpoint") != checkpoint.get("checkpoint")
            or value.get("checkpoint_sha256") != checkpoint.get("checkpoint_sha256")
            or not isinstance(stopped, dict)
            or not isinstance(before, dict) or set(before) != {"gateway", "research", "target"}
            or any(item not in {"running", "stopped"} for item in before.values())
            or before.get("research") != "running"
            or after != before
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("fault_sha256") != digest(unsigned)):
        raise SupervisorError("supervisor_fault_receipt_invalid")
    validate_checkpoint(campaign, case, checkpoint)
    validate_stop(campaign, case, checkpoint, stopped)
    if interaction == "supervisor-process-kill":
        if (not isinstance(termination, dict) or stopped_inventory is not None
                or restarted is not None):
            raise SupervisorError("supervisor_fault_receipt_invalid")
        validate_termination(campaign, case, checkpoint, termination)
    elif interaction == "supervisor-research-vm-hard-power":
        if (termination is not None or not isinstance(stopped_inventory, dict)
                or not isinstance(restarted, dict)
                or set(stopped_inventory) != {"gateway", "research", "target"}
                or set(restarted) != {"gateway", "research", "target"}
                or stopped_inventory.get("research") != "stopped"
                or restarted.get("research") != "running"
                or stopped_inventory.get("gateway") != before.get("gateway")
                or stopped_inventory.get("target") != before.get("target")
                or restarted.get("gateway") != before.get("gateway")
                or restarted.get("target") != before.get("target")):
            raise SupervisorError("supervisor_fault_receipt_invalid")
    else:
        raise SupervisorError("supervisor_fault_receipt_invalid")
    return checkpoint


def validate_cold_boot(campaign: dict[str, Any], case: dict[str, Any],
                       checkpoint: dict[str, Any], value: dict[str, Any]) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256", "case_id",
        "checkpoint_sha256", "pre_boot", "post_boot", "vm_stopped",
        "vm_restarted", "gateway_unchanged", "target_unchanged",
        "candidate_authority", "production_material_used", "cold_boot_sha256",
    }
    unsigned = {key: item for key, item in value.items()
                if key != "cold_boot_sha256"}
    pre_boot = value.get("pre_boot")
    post_boot = value.get("post_boot")
    stopped = value.get("vm_stopped")
    restarted = value.get("vm_restarted")
    if (set(value) != expected or value.get("schema") != COLD_BOOT_SCHEMA
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("case_id") != case["case_id"]
            or value.get("checkpoint_sha256") != checkpoint["checkpoint_sha256"]
            or not isinstance(pre_boot, dict) or not isinstance(post_boot, dict)
            or not isinstance(stopped, dict) or not isinstance(restarted, dict)
            or set(stopped) != {"gateway", "research", "target"}
            or set(restarted) != {"gateway", "research", "target"}
            or stopped.get("research") != "stopped"
            or restarted.get("research") != "running"
            or stopped.get("gateway") != restarted.get("gateway")
            or stopped.get("target") != restarted.get("target")
            or value.get("gateway_unchanged") is not True
            or value.get("target_unchanged") is not True
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("cold_boot_sha256") != digest(unsigned)):
        raise SupervisorError("supervisor_cold_boot_receipt_invalid")
    validate_boot(campaign, case, pre_boot)
    validate_boot(campaign, case, post_boot)
    if (pre_boot["research_boot_sha256"] != checkpoint["research_boot_sha256"]
            or post_boot["research_boot_sha256"]
               == checkpoint["research_boot_sha256"]):
        raise SupervisorError("supervisor_cold_boot_receipt_invalid")


def validate_recovery(campaign: dict[str, Any], case: dict[str, Any],
                      checkpoint: dict[str, Any],
                      result: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(result) != {
        "schema", "status", "campaign_id", "campaign_sha256", "case_id",
        "checkpoint", "checkpoint_sha256", "recovery", "candidate_authority",
        "production_material_used", "result_sha256",
    }:
        raise SupervisorError("supervisor_recovery_invalid")
    unsigned = {key: value for key, value in result.items() if key != "result_sha256"}
    recovery = result.get("recovery")
    boundary = recovery.get("boundary") if isinstance(recovery, dict) else None
    recovery_keys = {
        "schema", "status", "campaign_id", "campaign_sha256", "case_id",
        "checkpoint", "recovery_result", "active_generation_id", "boundary_sha256",
        "boundary", "candidate_authority", "production_material_used", "recovery_sha256",
    }
    recovery_unsigned = ({key: value for key, value in recovery.items()
                          if key != "recovery_sha256"}
                         if isinstance(recovery, dict) else {})
    if (result.get("schema")
            != "secure-sandbox-harness-lifecycle-acceptance-recovery-result-v1"
            or result.get("status") != "recovered"
            or result.get("campaign_id") != campaign["campaign_id"]
            or result.get("campaign_sha256") != campaign["campaign_sha256"]
            or result.get("case_id") != case["case_id"]
            or result.get("checkpoint")
               != case["procedure"]["interruption_checkpoint"]
            or result.get("checkpoint_sha256") != checkpoint["checkpoint_sha256"]
            or result.get("candidate_authority") != "none"
            or result.get("production_material_used") is not False
            or result.get("result_sha256") != digest(unsigned)
            or not isinstance(recovery, dict) or set(recovery) != recovery_keys
            or recovery.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-recovery-v1"
            or recovery.get("status") != "recovered"
            or recovery.get("campaign_id") != campaign["campaign_id"]
            or recovery.get("campaign_sha256") != campaign["campaign_sha256"]
            or recovery.get("case_id") != case["case_id"]
            or recovery.get("checkpoint")
               != case["procedure"]["interruption_checkpoint"]
            or recovery.get("candidate_authority") != "none"
            or recovery.get("production_material_used") is not False
            or recovery.get("recovery_sha256") != digest(recovery_unsigned)
            or not isinstance(boundary, dict)
            or recovery.get("recovery_result") not in {
                "pre-transaction-loss-safe", "restored_predecessor", "committed",
                "committed-readback",
            }
            or recovery.get("active_generation_id")
               != boundary.get("active_generation_id")
            or recovery.get("boundary_sha256") != digest(boundary)):
        raise SupervisorError("supervisor_recovery_invalid")
    validate_boundary(boundary)
    return recovery, boundary


def validate_boundary(value: dict[str, Any]) -> None:
    expected = {
        "schema", "status", "active_generation_id", "generation_count",
        "catalog_sha256", "selector_sha256", "floor_sha256",
    }
    if (set(value) != expected
            or value.get("schema")
               != "secure-sandbox-harness-generation-boundary-v1"
            or value.get("status") != "verified"
            or (value.get("active_generation_id") is not None
                and (not isinstance(value.get("active_generation_id"), str)
                     or SHA256.fullmatch(value["active_generation_id"]) is None))
            or not isinstance(value.get("generation_count"), int)
            or not 0 <= value["generation_count"] <= 1024
            or any(not isinstance(value.get(field), str)
                   or SHA256.fullmatch(value[field]) is None
                   for field in ("catalog_sha256", "selector_sha256", "floor_sha256"))):
        raise SupervisorError("supervisor_boundary_readback_invalid")


def output_destination(root: Path, case_id: str) -> Path:
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise SupervisorError("supervisor_evidence_root_untrusted")
    path = root / case_id
    if os.path.lexists(path):
        raise SupervisorError("supervisor_evidence_case_exists")
    return path


def execute(campaign_path: Path, observations: Path, case_id: str,
            evidence_root: Path, acknowledgement: str) -> dict[str, Any]:
    now = int(time.time())
    campaign = validate_campaign(trusted_json(campaign_path), now)
    verify_source_checkout(campaign)
    if current_machine_identity() != campaign["machine_identity_sha256"]:
        raise SupervisorError("supervisor_machine_identity_mismatch")
    case = next_recovery_case(campaign_path, observations, case_id)
    destination = output_destination(evidence_root, case_id)
    interaction = case["procedure"]["interaction"]
    if interaction == "supervisor-research-vm-hard-power":
        if acknowledgement != POWER_ACKNOWLEDGEMENT:
            raise SupervisorError("supervisor_power_acknowledgement_required")
    elif interaction == "supervisor-process-kill":
        if acknowledgement:
            raise SupervisorError("supervisor_acknowledgement_not_applicable")
    else:
        raise SupervisorError("supervisor_interaction_invalid")
    for path in (PRLCTL, PGREP, SSH, GIT, CONTROL_CLIENT, SSH_CONFIG):
        prerequisite(path, executable=path != SSH_CONFIG)
    lock = acquire_lock()
    worker: subprocess.Popen[bytes] | None = None
    checkpoint_bound = False
    try:
        require_gui_closed()
        before = vm_inventory()
        if before["research"] != "running":
            raise SupervisorError("supervisor_research_not_running")
        destination.mkdir(mode=0o700)
        parent = os.open(evidence_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        deploy(campaign, destination)
        pre_boot = (remote_json(campaign, "boot-readback", case_id)
                    if interaction == "supervisor-research-vm-hard-power" else None)
        if pre_boot is not None:
            validate_boot(campaign, case, pre_boot)
        worker = subprocess.Popen(
            remote_worker(campaign, "run", case_id), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        checkpoint = read_worker_checkpoint(worker, 60)
        validate_checkpoint(campaign, case, checkpoint)
        checkpoint_bound = True
        stopped = remote_json(campaign, "inspect", case_id)
        validate_stop(campaign, case, checkpoint, stopped)

        termination = None
        stopped_inventory = None
        restarted_inventory = None
        post_boot = None
        if interaction == "supervisor-process-kill":
            termination = remote_json(campaign, "terminate", case_id)
            validate_termination(campaign, case, checkpoint, termination)
        else:
            require_gui_closed()
            command([str(PRLCTL), "stop", RESEARCH_VM, "--kill"], timeout=30)
            wait_vm_state(RESEARCH_VM, "stopped")
            stopped_inventory = vm_inventory()
            if (stopped_inventory["gateway"] != before["gateway"]
                    or stopped_inventory["target"] != before["target"]
                    or stopped_inventory["research"] != "stopped"):
                raise SupervisorError("supervisor_power_scope_violation")
            require_gui_closed()
            command([str(PRLCTL), "start", RESEARCH_VM], timeout=30)
            wait_vm_state(RESEARCH_VM, "running", 60)
            wait_research_control()
            restarted_inventory = vm_inventory()
            if (restarted_inventory["gateway"] != before["gateway"]
                    or restarted_inventory["target"] != before["target"]
                    or restarted_inventory["research"] != "running"):
                raise SupervisorError("supervisor_restart_scope_violation")
            post_boot = remote_json(campaign, "boot-readback", case_id)
            validate_boot(campaign, case, post_boot)
            if (pre_boot is None
                    or pre_boot.get("research_boot_sha256")
                       != checkpoint["research_boot_sha256"]
                    or post_boot.get("research_boot_sha256")
                       == checkpoint["research_boot_sha256"]):
                raise SupervisorError("supervisor_cold_boot_unverified")

        terminate_process(worker)
        worker = None
        result = remote_json(campaign, "recover", case_id, timeout=60)
        recovery, boundary = validate_recovery(campaign, case, checkpoint, result)
        after = vm_inventory()
        if after != before:
            raise SupervisorError("supervisor_final_vm_state_changed")

        fault = {
            "schema": FAULT_SCHEMA, "status": "verified",
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "machine_identity_sha256": campaign["machine_identity_sha256"],
            "source_commit": campaign["source_commit"], "case_id": case_id,
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "interaction": interaction,
            "checkpoint": checkpoint["checkpoint"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "worker_checkpoint": checkpoint,
            "worker_stop": stopped, "worker_termination": termination,
            "vm_before": before, "vm_stopped": stopped_inventory,
            "vm_restarted": restarted_inventory, "vm_after": after,
            "candidate_authority": "none", "production_material_used": False,
        }
        fault["fault_sha256"] = digest(fault)
        validate_fault(campaign, case, fault)
        write_new(destination / "fault-injection-receipt.json", fault)
        if interaction == "supervisor-research-vm-hard-power":
            cold_boot = {
                "schema": COLD_BOOT_SCHEMA, "status": "verified",
                "campaign_id": campaign["campaign_id"],
                "campaign_sha256": campaign["campaign_sha256"], "case_id": case_id,
                "checkpoint_sha256": checkpoint["checkpoint_sha256"],
                "pre_boot": pre_boot, "post_boot": post_boot,
                "vm_stopped": stopped_inventory, "vm_restarted": restarted_inventory,
                "gateway_unchanged": True, "target_unchanged": True,
                "candidate_authority": "none", "production_material_used": False,
            }
            cold_boot["cold_boot_sha256"] = digest(cold_boot)
            validate_cold_boot(campaign, case, checkpoint, cold_boot)
            write_new(destination / "cold-boot-readback.json", cold_boot)
        write_new(destination / "recovery-receipt.json", result)
        write_new(destination / "boundary-readback.json", boundary)
        directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        summary = {
            "schema": SCHEMA, "status": "verified",
            "campaign_id": campaign["campaign_id"], "case_id": case_id,
            "interaction": interaction, "checkpoint": checkpoint["checkpoint"],
            "evidence_directory": str(destination),
            "evidence_kinds": list(case["evidence_kinds"]),
            "candidate_authority": "none", "production_material_used": False,
        }
        summary["supervisor_sha256"] = digest(summary)
        return summary
    finally:
        if worker is not None:
            if checkpoint_bound:
                try:
                    remote_json(campaign, "abort", case_id)
                except SupervisorError:
                    pass
            terminate_process(worker)
        os.close(lock)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Drive one suite-bound disposable Research recovery case",
    )
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--observations", type=Path, required=True)
    value.add_argument("--case", required=True)
    value.add_argument("--evidence-directory", type=Path, required=True)
    value.add_argument("--acknowledge", default="")
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    result = execute(
        args.campaign, args.observations, args.case,
        args.evidence_directory, args.acknowledge,
    )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, SupervisorError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, (AcceptanceError, SupervisorError)) \
            else "supervisor_failed"
        sys.stderr.buffer.write(canonical({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }))
        raise SystemExit(1)
