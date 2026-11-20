#!/usr/bin/env python3
"""Run consecutive noninteractive acceptance ceremonies in one visible TTY.

This helper is convenience, never authority.  Every case is a distinct sudo
subprocess against the exact campaign-bound immutable driver.  The protected
driver and protected ``next`` command independently enforce ordering and
evidence custody.  The helper neither opens a root shell nor refreshes,
extends, or otherwise manages sudo's credential cache.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


COMMIT = re.compile(r"[0-9a-f]{40}")
CASE_ID = re.compile(r"[a-z][a-z0-9-]{0,95}")
CAMPAIGN_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}"
)
PROTECTED_ROOT = Path("/usr/local/libexec/secure-sandbox-harness-acceptance")
PYTHON = Path("/usr/bin/python3")
SUDO = Path("/usr/bin/sudo")
ENV = Path("/usr/bin/env")
MAX_JSON = 32 * 1024 * 1024
MAX_DRIVER_OUTPUT = 1024 * 1024
MAX_CASES = 32
ALLOWED_DRIVERS = {
    "host-provenance-fixture": (
        "provenance", "harness-lifecycle-acceptance-provenance.py",
    ),
    "host-archive-fixture": (
        "archive", "harness-lifecycle-acceptance-archive.py",
    ),
}
QUALIFICATION_DRIVER = "research-qualification-fixture"
QUALIFICATION_ACTION = "qualification-two-phase"
QUALIFICATION_SUPERVISOR = "harness-lifecycle-acceptance-qualification-supervisor.py"
QUALIFICATION_PROJECTOR = "harness-lifecycle-acceptance-qualification-observe.py"
QUALIFICATION_COLLECT_SCHEMA = (
    "secure-sandbox-harness-lifecycle-qualification-supervisor-v1"
)
QUALIFICATION_PROJECT_SCHEMA = (
    "secure-sandbox-harness-lifecycle-qualification-projection-v1"
)
QUALIFICATION_RAW_FILES = [
    "research-result.json", "quarantine-readback.json",
    "authority-readback.json", "production-material-scan.json",
]


class CeremonyBurstError(RuntimeError):
    """Stable failure for the non-authoritative operator helper."""


def canonical(value: dict[str, Any]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ) + "\n").encode("ascii")


def digest(value: dict[str, Any]) -> str:
    import hashlib
    return hashlib.sha256(canonical(value)).hexdigest()


def emit(status: str, phase: str, **values: Any) -> None:
    record = {
        "schema": "secure-sandbox-harness-lifecycle-ceremony-burst-v1",
        "status": status,
        "phase": phase,
        "authority": "none",
        **values,
    }
    stream = sys.stdout.buffer if status in {"ready", "verified", "stopped"} \
        else sys.stderr.buffer
    stream.write(canonical(record))
    stream.flush()


def trusted_directory(path: Path, uid: int, label: str) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise CeremonyBurstError(f"{label}_untrusted")


def load_campaign(path: Path, uid: int) -> dict[str, Any]:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size <= 0 or info.st_size > MAX_JSON):
        raise CeremonyBurstError("campaign_untrusted")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CeremonyBurstError("campaign_untrusted") from error
    if (not isinstance(value, dict)
            or not COMMIT.fullmatch(str(value.get("source_commit", "")))
            or not CAMPAIGN_ID.fullmatch(str(value.get("campaign_id", "")))):
        raise CeremonyBurstError("campaign_untrusted")
    return value


def require_root_owned_path(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not expected or stat.S_ISLNK(info.st_mode) or info.st_uid != 0
            or (not directory and info.st_nlink != 1)
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise CeremonyBurstError("protected_release_untrusted")


def protected_release(commit: str) -> Path:
    release = PROTECTED_ROOT / "releases" / commit
    for path in (
        Path("/usr"), Path("/usr/local"), Path("/usr/local/libexec"),
        PROTECTED_ROOT, PROTECTED_ROOT / "releases", release,
        release / "scripts",
    ):
        require_root_owned_path(path, directory=True)
    for path in (
        release / "scripts/harness-lifecycle-acceptance.py",
        release / "scripts" / QUALIFICATION_SUPERVISOR,
        release / "scripts" / QUALIFICATION_PROJECTOR,
        *(
            release / "scripts" / script
            for _, script in ALLOWED_DRIVERS.values()
        ),
    ):
        require_root_owned_path(path, directory=False)
    return release


def clean_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C", "LC_ALL": "C",
    }


def query_next(release: Path, campaign: Path, observations: Path,
               *, runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
               ) -> dict[str, Any]:
    try:
        result = runner(
            [str(PYTHON), "-I",
             str(release / "scripts/harness-lifecycle-acceptance.py"),
             "next", "--campaign", str(campaign),
             "--observations", str(observations)],
            cwd=Path("/"), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=clean_environment(), timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CeremonyBurstError("next_query_failed") from error
    if (result.returncode != 0 or result.stderr
            or not result.stdout or len(result.stdout) > MAX_JSON):
        raise CeremonyBurstError("next_query_failed")
    try:
        value = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CeremonyBurstError("next_query_failed") from error
    if not isinstance(value, dict):
        raise CeremonyBurstError("next_query_failed")
    return value


def eligible_case(value: dict[str, Any]) -> tuple[str, str] | None:
    if value.get("status") == "complete" and value.get("case") is None:
        return None
    case = value.get("case")
    if value.get("status") != "pending" or not isinstance(case, dict):
        raise CeremonyBurstError("next_case_invalid")
    case_id = case.get("case_id")
    procedure = case.get("procedure")
    if (not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id)
            or not isinstance(procedure, dict)):
        raise CeremonyBurstError("next_case_invalid")
    driver = procedure.get("driver")
    allowed = ALLOWED_DRIVERS.get(str(driver))
    if driver == QUALIFICATION_DRIVER:
        if (case.get("category") != "qualification"
                or case.get("destructive") is not False
                or case.get("requires_touch_id") is not False
                or case.get("requires_reboot") is not False
                or procedure.get("interaction") != "none"):
            raise CeremonyBurstError("next_case_not_burst_eligible")
        return case_id, QUALIFICATION_ACTION
    if allowed is None:
        return None
    category, script = allowed
    if (case.get("category") != category
            or case.get("destructive") is not False
            or case.get("requires_touch_id") is not False
            or case.get("requires_reboot") is not False
            or procedure.get("interaction") != "none"):
        raise CeremonyBurstError("next_case_not_burst_eligible")
    return case_id, script


def parse_driver_result(raw: bytes, case_id: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_DRIVER_OUTPUT:
        raise CeremonyBurstError("driver_output_invalid")
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        raise CeremonyBurstError("driver_output_invalid")
    try:
        value = json.loads(lines[0])
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CeremonyBurstError("driver_output_invalid") from error
    if (not isinstance(value, dict) or value.get("status") != "recorded"
            or value.get("case_id") != case_id
            or value.get("authority") != "acceptance-evidence-only"):
        raise CeremonyBurstError("driver_output_invalid")
    return value


def run_logged(command: list[str], log_path: Path, *,
               environment: dict[str, str] | None = None,
               popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
               ) -> bytes:
    descriptor = os.open(
        log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    raw = bytearray()
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as log:
            try:
                process = popen(
                    command, cwd=Path("/"), stdin=None,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    env=environment, bufsize=0,
                )
            except OSError as error:
                raise CeremonyBurstError("driver_launch_failed") from error
            if process.stdout is None:
                raise CeremonyBurstError("driver_launch_failed")
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                log.write(chunk)
                log.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                if len(raw) + len(chunk) > MAX_DRIVER_OUTPUT:
                    process.terminate()
                    process.wait(timeout=5)
                    raise CeremonyBurstError("driver_output_oversized")
                raw.extend(chunk)
            returncode = process.wait()
            log.flush()
            os.fsync(log.fileno())
    finally:
        parent = os.open(log_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    if returncode != 0:
        raise CeremonyBurstError("driver_rejected")
    return bytes(raw)


def run_driver(command: list[str], log_path: Path, case_id: str,
               *, popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
               ) -> dict[str, Any]:
    raw = run_logged(
        command, log_path, environment=clean_environment(), popen=popen,
    )
    return parse_driver_result(raw, case_id)


def parsed_single_record(raw: bytes, error: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_DRIVER_OUTPUT:
        raise CeremonyBurstError(error)
    lines = [line for line in raw.splitlines() if line.strip()]
    if len(lines) != 1:
        raise CeremonyBurstError(error)
    try:
        value = json.loads(lines[0])
    except (UnicodeError, json.JSONDecodeError) as exception:
        raise CeremonyBurstError(error) from exception
    if not isinstance(value, dict):
        raise CeremonyBurstError(error)
    return value


def validate_qualification_record(value: dict[str, Any], case_id: str, *,
                                  projection: bool) -> None:
    schema = QUALIFICATION_PROJECT_SCHEMA if projection \
        else QUALIFICATION_COLLECT_SCHEMA
    digest_field = "projection_sha256" if projection else "supervisor_sha256"
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    if (value.get("schema") != schema or value.get("status") != "recorded"
            or value.get("case_id") != case_id
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get(digest_field) != digest(unsigned)):
        raise CeremonyBurstError("qualification_result_invalid")


def run_qualification_case(release: Path, campaign_path: Path,
                           observations: Path, raw_root: Path,
                           handoff: Path, campaign_id: str, case_id: str,
                           uid: int, *,
                           popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
                           ) -> dict[str, Any]:
    raw_directory = raw_root / case_id
    if os.path.lexists(raw_directory):
        raise CeremonyBurstError("qualification_raw_case_exists")
    collect_log = handoff / (
        f"ceremony-burst-{campaign_id}-{case_id}-collect.log"
    )
    project_log = handoff / (
        f"ceremony-burst-{campaign_id}-{case_id}-project.log"
    )
    if os.path.lexists(collect_log) or os.path.lexists(project_log):
        raise CeremonyBurstError("qualification_log_exists")
    collect_command = [
        str(PYTHON), "-I", str(release / "scripts" / QUALIFICATION_SUPERVISOR),
        "--campaign", str(campaign_path),
        "--observations", str(observations),
        "--raw-root", str(raw_root), "--case", case_id,
    ]
    collect_raw = run_logged(
        collect_command, collect_log, environment=None, popen=popen,
    )
    collected = parsed_single_record(
        collect_raw, "qualification_collection_invalid",
    )
    validate_qualification_record(collected, case_id, projection=False)
    if (collected.get("raw_directory") != str(raw_directory)
            or collected.get("raw_files") != QUALIFICATION_RAW_FILES):
        raise CeremonyBurstError("qualification_collection_invalid")
    trusted_directory(raw_directory, uid, "qualification_raw_case")

    project_command = [
        str(SUDO), "--", str(ENV), "-i",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C",
        "HOME=/var/empty", "PYTHONDONTWRITEBYTECODE=1",
        str(PYTHON), "-I", str(release / "scripts" / QUALIFICATION_PROJECTOR),
        "--campaign", str(campaign_path),
        "--observations", str(observations), "--case", case_id,
        "--raw-directory", str(raw_directory), "--operator-uid", str(uid),
    ]
    project_raw = run_logged(
        project_command, project_log,
        environment=clean_environment(), popen=popen,
    )
    projected = parsed_single_record(
        project_raw, "qualification_projection_invalid",
    )
    validate_qualification_record(projected, case_id, projection=True)
    return projected


def execute(*, runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
            popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
            ) -> dict[str, Any]:
    uid = os.getuid()
    if os.geteuid() == 0 or uid <= 0 or not os.isatty(0) or not os.isatty(1):
        raise CeremonyBurstError("visible_operator_tty_required")
    account = pwd.getpwuid(uid)
    home = Path(account.pw_dir)
    if not home.is_absolute() or home.is_symlink():
        raise CeremonyBurstError("operator_home_untrusted")
    home_info = home.lstat()
    if (not stat.S_ISDIR(home_info.st_mode) or home_info.st_uid != uid
            or stat.S_IMODE(home_info.st_mode) & 0o022):
        raise CeremonyBurstError("operator_home_untrusted")

    campaign_root = home / "Library/Application Support/SecureSandbox/harness-acceptance"
    campaign_path = campaign_root / "campaign.json"
    observations = campaign_root / "observations"
    qualification_raw = campaign_root / "raw/qualification"
    handoff = home / "SecureSandbox-Acceptance-Handoff"
    trusted_directory(campaign_root, uid, "campaign_root")
    trusted_directory(observations, uid, "observations")
    trusted_directory(campaign_root / "raw", uid, "raw_root")
    trusted_directory(qualification_raw, uid, "qualification_raw_root")
    trusted_directory(handoff, uid, "handoff")
    campaign = load_campaign(campaign_path, uid)
    release = protected_release(campaign["source_commit"])

    completed: list[str] = []
    seen: set[str] = set()
    emit(
        "ready", "start", campaign_id=campaign["campaign_id"],
        source_commit=campaign["source_commit"], max_cases=MAX_CASES,
        sudo_cache_management=False, persistent_root_shell=False,
    )
    for _ in range(MAX_CASES):
        before = query_next(
            release, campaign_path, observations, runner=runner,
        )
        eligible = eligible_case(before)
        if eligible is None:
            case = before.get("case")
            return {
                "status": "stopped", "completed_cases": completed,
                "next_case": case.get("case_id") if isinstance(case, dict) else None,
                "reason": "campaign_complete" if before.get("status") == "complete"
                else "next_driver_not_burst_eligible",
            }
        case_id, script = eligible
        if case_id in seen:
            raise CeremonyBurstError("next_case_did_not_advance")
        seen.add(case_id)
        log_path = handoff / (
            f"ceremony-burst-{campaign['campaign_id']}-{case_id}.log"
        )
        emit(
            "ready", "case", campaign_id=campaign["campaign_id"],
            case_id=case_id, completed_count=len(completed),
        )
        command = [
            str(SUDO), "--", str(ENV), "-i",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C",
            str(PYTHON), "-I", str(release / "scripts" / script),
            "--campaign", str(campaign_path),
            "--observations", str(observations),
            "--case", case_id, "--operator-uid", str(uid),
        ]
        if script == QUALIFICATION_ACTION:
            result = run_qualification_case(
                release, campaign_path, observations, qualification_raw,
                handoff, campaign["campaign_id"], case_id, uid, popen=popen,
            )
            result_log = handoff / (
                f"ceremony-burst-{campaign['campaign_id']}-{case_id}-project.log"
            )
        else:
            result = run_driver(command, log_path, case_id, popen=popen)
            result_log = log_path
        after = query_next(
            release, campaign_path, observations, runner=runner,
        )
        after_case = after.get("case")
        if (after.get("status") == "pending" and isinstance(after_case, dict)
                and after_case.get("case_id") == case_id):
            raise CeremonyBurstError("next_case_did_not_advance")
        completed.append(case_id)
        emit(
            "verified", "case", campaign_id=campaign["campaign_id"],
            case_id=case_id, log=str(result_log),
            record_sha256=(result.get("record_sha256")
                           or result.get("projection_sha256")),
            completed_count=len(completed),
        )
    raise CeremonyBurstError("burst_case_limit_reached")


def parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description=(
            "Run only consecutive noninteractive, non-destructive provenance, "
            "archive, and qualification cases in one visible operator TTY"
        ),
    )


def main(arguments: list[str] | None = None) -> int:
    parser().parse_args(arguments)
    try:
        result = execute()
    except (CeremonyBurstError, KeyError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, CeremonyBurstError) \
            else "ceremony_burst_failed"
        emit("rejected", "result", error=reason)
        return 1
    terminal_status = result.pop("status", None)
    if terminal_status != "stopped":
        emit("rejected", "result", error="ceremony_burst_result_invalid")
        return 1
    emit("stopped", "result", **result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
