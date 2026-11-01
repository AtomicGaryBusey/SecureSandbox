#!/usr/bin/env python3
"""Disposable-only recovery fixture worker with an external stop handshake."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_campaign,
)
from harness_lifecycle_acceptance_fixture import (  # noqa: E402
    AcceptanceFixtureError,
    CHECKPOINT_SCHEMA,
    RecoveryFixture,
)


RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-recovery-result-v1"
STOP_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-worker-stop-v1"
TERMINATION_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-worker-termination-v1"
ABORT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-worker-abort-v1"
BOOT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-research-boot-v1"
MAX_JSON = 64 * 1024


def trusted_json(path: Path) -> dict:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.geteuid() or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < before.st_size <= MAX_JSON):
        raise AcceptanceFixtureError("recovery_input_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= MAX_JSON:
            chunk = os.read(descriptor, min(65536, MAX_JSON + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > MAX_JSON):
        raise AcceptanceFixtureError("recovery_input_changed")
    raw = bytes(data)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceFixtureError("recovery_input_invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise AcceptanceFixtureError("recovery_input_noncanonical")
    return value


def write_new(path: Path, value: dict) -> None:
    payload = canonical(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AcceptanceFixtureError("recovery_output_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def campaign_and_workspace(campaign_path: Path, case_id: str, now: int,
                           *, create: bool) -> tuple[dict, Path]:
    campaign = validate_campaign(trusted_json(campaign_path), now)
    case = CASE_BY_ID.get(case_id)
    if (case is None or case.category != "recovery"
            or case_record_driver(case) != "research-recovery-fixture"):
        raise AcceptanceFixtureError("recovery_case_invalid")
    parent = campaign_path.parent
    parent_info = parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise AcceptanceFixtureError("recovery_campaign_root_untrusted")
    fixtures = parent / "recovery-fixtures"
    if create and not fixtures.exists():
        fixtures.mkdir(mode=0o700)
    info = fixtures.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise AcceptanceFixtureError("recovery_fixture_root_untrusted")
    return campaign, fixtures / case_id


def case_record_driver(case: object) -> str:
    # Import lazily through the public suite projection so the driver identity
    # is covered by the same suite digest as the campaign.
    from harness_lifecycle_acceptance import case_record
    return str(case_record(case)["procedure"]["driver"])


def checkpoint_event(campaign: dict, case_id: str, checkpoint: str) -> dict:
    identity = process_identity(os.getpid())
    value = {
        "schema": CHECKPOINT_SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"], "case_id": case_id,
        "checkpoint": checkpoint, "worker_pid": os.getpid(),
        "worker_start_time": identity["start_time"],
        "research_boot_sha256": boot_sha256(),
        "observed_at": int(time.time()), "candidate_authority": "none",
        "production_material_used": False,
    }
    value["checkpoint_sha256"] = digest(value)
    return value


def boot_sha256() -> str:
    raw = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    if not raw.endswith(b"\n") or len(raw) > 128:
        raise AcceptanceFixtureError("research_boot_identity_invalid")
    return hashlib.sha256(raw).hexdigest()


def process_identity(pid: int) -> dict[str, object]:
    if not 1 < pid < 2 ** 31:
        raise AcceptanceFixtureError("recovery_worker_pid_invalid")
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    closing = raw.rfind(")")
    fields = raw[closing + 2:].split() if closing > 0 else []
    if len(fields) < 20 or not fields[19].isdigit() or not fields[0]:
        raise AcceptanceFixtureError("recovery_worker_identity_invalid")
    return {"state": fields[0], "start_time": int(fields[19])}


def checkpoint_for(campaign_path: Path, case_id: str, now: int) -> tuple[dict, dict]:
    campaign, workspace = campaign_and_workspace(campaign_path, case_id, now, create=False)
    checkpoint = trusted_json(workspace / "checkpoint.json")
    unsigned = {key: value for key, value in checkpoint.items()
                if key != "checkpoint_sha256"}
    case = CASE_BY_ID[case_id]
    expected_checkpoint = case_id.split("-loss-", 1)[1]
    if (checkpoint.get("schema") != CHECKPOINT_SCHEMA
            or checkpoint.get("status") != "recorded"
            or checkpoint.get("campaign_id") != campaign["campaign_id"]
            or checkpoint.get("campaign_sha256") != campaign["campaign_sha256"]
            or checkpoint.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or checkpoint.get("source_commit") != campaign["source_commit"]
            or checkpoint.get("case_id") != case_id
            or checkpoint.get("checkpoint") != expected_checkpoint
            or not isinstance(checkpoint.get("worker_pid"), int)
            or not isinstance(checkpoint.get("worker_start_time"), int)
            or checkpoint.get("research_boot_sha256") != boot_sha256()
            or checkpoint.get("candidate_authority") != "none"
            or checkpoint.get("production_material_used") is not False
            or checkpoint.get("checkpoint_sha256") != digest(unsigned)
            or case.category != "recovery"):
        raise AcceptanceFixtureError("recovery_checkpoint_invalid")
    return campaign, checkpoint


def inspect_stopped_worker(campaign_path: Path, case_id: str, now: int) -> dict:
    campaign, checkpoint = checkpoint_for(campaign_path, case_id, now)
    identity = process_identity(checkpoint["worker_pid"])
    if (identity["start_time"] != checkpoint["worker_start_time"]
            or identity["state"] not in {"T", "t"}):
        raise AcceptanceFixtureError("recovery_worker_not_stopped")
    value = {
        "schema": STOP_SCHEMA, "status": "verified",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"], "case_id": case_id,
        "checkpoint": checkpoint["checkpoint"],
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "worker_pid": checkpoint["worker_pid"],
        "worker_start_time": checkpoint["worker_start_time"],
        "process_state": identity["state"],
        "research_boot_sha256": checkpoint["research_boot_sha256"],
        "candidate_authority": "none", "production_material_used": False,
    }
    value["stop_sha256"] = digest(value)
    return value


def kill_stopped_worker(campaign_path: Path, case_id: str, now: int,
                        *, abort: bool) -> dict:
    if not abort and not case_id.startswith("process-loss-"):
        raise AcceptanceFixtureError("recovery_process_case_required")
    stopped = inspect_stopped_worker(campaign_path, case_id, now)
    os.kill(stopped["worker_pid"], signal.SIGKILL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            current = process_identity(stopped["worker_pid"])
        except (FileNotFoundError, ProcessLookupError):
            break
        if (current["start_time"] != stopped["worker_start_time"]
                or current["state"] == "Z"):
            break
        time.sleep(0.05)
    else:
        raise AcceptanceFixtureError("recovery_worker_termination_unverified")
    value = {
        "schema": ABORT_SCHEMA if abort else TERMINATION_SCHEMA,
        "status": "aborted" if abort else "verified",
        "campaign_id": stopped["campaign_id"],
        "campaign_sha256": stopped["campaign_sha256"], "case_id": case_id,
        "checkpoint": stopped["checkpoint"],
        "checkpoint_sha256": stopped["checkpoint_sha256"],
        "worker_pid": stopped["worker_pid"],
        "worker_start_time": stopped["worker_start_time"],
        "research_boot_sha256": stopped["research_boot_sha256"],
        "signal": "SIGKILL", "candidate_authority": "none",
        "production_material_used": False,
    }
    value["abort_sha256" if abort else "termination_sha256"] = digest(value)
    return value


def terminate_stopped_worker(campaign_path: Path, case_id: str, now: int) -> dict:
    return kill_stopped_worker(campaign_path, case_id, now, abort=False)


def abort_stopped_worker(campaign_path: Path, case_id: str, now: int) -> dict:
    return kill_stopped_worker(campaign_path, case_id, now, abort=True)


def boot_readback(campaign_path: Path, case_id: str, now: int) -> dict:
    campaign = validate_campaign(trusted_json(campaign_path), now)
    case = CASE_BY_ID.get(case_id)
    recovery_case = case_id.startswith("power-loss-")
    cold_boot_case = (
        case is not None and case.category == "cold-boot"
        and case_record_driver(case) == "cold-boot-readback-fixture"
    )
    if case is None or not case.requires_reboot or not (recovery_case or cold_boot_case):
        raise AcceptanceFixtureError("recovery_power_case_required")
    value = {
        "schema": BOOT_SCHEMA, "status": "verified",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"], "case_id": case_id,
        "research_boot_sha256": boot_sha256(),
        "candidate_authority": "none", "production_material_used": False,
    }
    value["boot_sha256"] = digest(value)
    return value


def run_fixture(campaign_path: Path, case_id: str, now: int) -> None:
    campaign, workspace = campaign_and_workspace(campaign_path, case_id, now, create=True)
    worker = RecoveryFixture(workspace, campaign, case_id)

    def reached(checkpoint: str) -> None:
        event = checkpoint_event(campaign, case_id, checkpoint)
        write_new(worker.checkpoint_path, event)
        sys.stdout.buffer.write(canonical(event))
        sys.stdout.buffer.flush()
        os.kill(os.getpid(), signal.SIGSTOP)
        os._exit(125)

    worker.run(reached)
    raise AcceptanceFixtureError("recovery_checkpoint_not_reached")


def recover_fixture(campaign_path: Path, case_id: str, now: int) -> dict:
    campaign, workspace = campaign_and_workspace(campaign_path, case_id, now, create=False)
    worker = RecoveryFixture(workspace, campaign, case_id)
    checkpoint = trusted_json(worker.checkpoint_path)
    unsigned_checkpoint = {key: value for key, value in checkpoint.items()
                           if key != "checkpoint_sha256"}
    if (checkpoint.get("schema") != CHECKPOINT_SCHEMA
            or checkpoint.get("status") != "recorded"
            or checkpoint.get("campaign_id") != campaign["campaign_id"]
            or checkpoint.get("campaign_sha256") != campaign["campaign_sha256"]
            or checkpoint.get("case_id") != case_id
            or checkpoint.get("checkpoint") != worker.checkpoint
            or checkpoint.get("candidate_authority") != "none"
            or checkpoint.get("production_material_used") is not False
            or checkpoint.get("checkpoint_sha256") != digest(unsigned_checkpoint)):
        raise AcceptanceFixtureError("recovery_checkpoint_invalid")
    recovery = worker.recover()
    value = {
        "schema": RESULT_SCHEMA, "status": "recovered",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"], "case_id": case_id,
        "checkpoint": worker.checkpoint,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "recovery": recovery, "candidate_authority": "none",
        "production_material_used": False,
    }
    value["result_sha256"] = digest(value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Run a disposable Research recovery fixture")
    commands = value.add_subparsers(dest="command", required=True)
    for name in ("run", "inspect", "terminate", "abort", "recover", "boot-readback"):
        command = commands.add_parser(name)
        command.add_argument("--campaign", type=Path, required=True)
        command.add_argument("--case", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    now = int(time.time())
    if args.command == "run":
        run_fixture(args.campaign, args.case, now)
        raise AcceptanceFixtureError("recovery_worker_returned")
    if args.command == "inspect":
        result = inspect_stopped_worker(args.campaign, args.case, now)
    elif args.command == "terminate":
        result = terminate_stopped_worker(args.campaign, args.case, now)
    elif args.command == "abort":
        result = abort_stopped_worker(args.campaign, args.case, now)
    elif args.command == "boot-readback":
        result = boot_readback(args.campaign, args.case, now)
    else:
        result = recover_fixture(args.campaign, args.case, now)
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, AcceptanceFixtureError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, (AcceptanceError, AcceptanceFixtureError)) \
            else "recovery_fixture_failed"
        print(json.dumps({
            "schema": "secure-sandbox-harness-lifecycle-acceptance-recovery-error-v1",
            "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
