#!/usr/bin/env python3
"""Atomically retain a no-evidence rejected campaign before a source repair.

This is deliberately narrower than a general archive or reset command.  It
accepts only the fixed local campaign layout.  The ordinary path requires
every evidence directory to be empty.  One separate, literal ceremony accepts
only an empty ``bootstrap-clean-install`` reservation left by the historically
observed ``bootstrap_host_receipt_invalid`` rejection.  Both paths record the
exact old and replacement source bindings and move the complete directory
without overwrite.  Neither deletes or modifies an observation.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    DRIVER_ENTRYPOINTS,
    canonical,
    digest,
    validate_campaign,
)


def _load(name: str, relative: str) -> Any:
    specification = importlib.util.spec_from_file_location(name, ROOT / relative)
    if specification is None or specification.loader is None:
        raise RetentionError("retention_dependency_unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ACCEPTANCE_CLI = _load(
    "retention_acceptance_cli", "scripts/harness-lifecycle-acceptance.py",
)
PREFLIGHT = _load(
    "retention_morning_preflight",
    "scripts/harness-lifecycle-acceptance-morning-preflight.py",
)
SUPERVISOR = _load(
    "retention_acceptance_supervisor",
    "scripts/harness-lifecycle-acceptance-supervisor.py",
)


SCHEMA = "secure-sandbox-harness-lifecycle-empty-campaign-retention-plan-v1"
RESERVED_SCHEMA = (
    "secure-sandbox-harness-lifecycle-empty-reservation-retention-plan-v1"
)
SUPERSESSION_SCHEMA = (
    "secure-sandbox-harness-lifecycle-empty-campaign-retention-"
    "supersession-v1"
)
RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-empty-campaign-retention-v2"
RESERVED_RESULT_SCHEMA = (
    "secure-sandbox-harness-lifecycle-empty-reservation-retention-v1"
)
ACKNOWLEDGEMENT = "RETAIN EMPTY REJECTED CAMPAIGN WITHOUT DELETION"
RESERVED_ACKNOWLEDGEMENT = (
    "RETAIN EMPTY RESERVED BOOTSTRAP REJECTION WITHOUT DELETION"
)
RESERVED_CASE_ID = "bootstrap-clean-install"
RESERVED_EXPECTED_ERROR = "bootstrap_host_receipt_invalid"
RESERVED_DIAGNOSTIC_SCHEMA = (
    "secure-sandbox-harness-lifecycle-bootstrap-rejection-diagnostic-v1"
)
MODERN_HOST_RELEASE_FIELDS = [
    "candidate_authority_sha256", "developer_id_team_floor_release_id",
    "developer_id_team_floor_sha256", "developer_id_team_id",
    "host_release_launcher_pair_sha256", "launcher_sha256", "payloads",
    "release_id", "release_tree_identity_sha256", "schema", "status",
]
RESERVED_DIAGNOSTIC_PROGRAM = r'''\
import importlib.util
import json
import os
import sys
from pathlib import Path

try:
    release = Path(sys.argv[1])
    campaign_path = Path(sys.argv[2])
    observations = Path(sys.argv[3])
    now = int(sys.argv[4])
    expected_case = sys.argv[5]
    expected_error = sys.argv[6]
    diagnostic_schema = sys.argv[7]

    sys.path.insert(0, str(release / "shared"))
    entrypoint = release / "scripts/harness-lifecycle-acceptance-bootstrap.py"
    specification = importlib.util.spec_from_file_location(
        "retention_installed_bootstrap_diagnostic", entrypoint,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("entrypoint_unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    campaign = module.validate_campaign(
        module.trusted_json(campaign_path), now, allow_expired=True,
    )
    next_value = module.ACCEPTANCE_CLI.next_case(
        campaign, observations, observation_uid=os.geteuid(),
        directory_uid=os.geteuid(),
    )
    case = next_value.get("case")
    if (next_value.get("status") != "pending"
            or not isinstance(case, dict)
            or case.get("case_id") != expected_case):
        raise RuntimeError("case_invalid")

    live_release = module.HOST_RELEASE.verify(
        module.ROOT, module.INSTALL_ROOT, module.STABLE_LAUNCHER, 0,
        module.HOST_RELEASE.DEFAULT_OP_BINARY,
        module.INSTALL_ROOT / "current/gpgv",
    )
    host = module.receipt(
        module.HOST_SCHEMA, campaign, case, now,
        {"release": live_release,
         "release_sha256": module.digest(live_release)},
        "receipt_sha256",
    )
    try:
        module.validate_host_receipt(campaign, case, host, now)
    except module.BootstrapError as error:
        if str(error) != expected_error:
            raise RuntimeError("error_mismatch") from error
    else:
        raise RuntimeError("error_not_reproduced")

    value = {
        "schema": diagnostic_schema,
        "status": "confirmed",
        "case_id": expected_case,
        "error": expected_error,
        "source_commit": campaign["source_commit"],
        "observed_at": now,
        "host_release_fields": sorted(live_release),
        "host_release_sha256": module.digest(live_release),
    }
    value["diagnostic_sha256"] = module.digest(value)
    sys.stdout.buffer.write(module.canonical(value))
except BaseException:
    os._exit(70)
'''
CAMPAIGN_RELATIVE = Path("Library/Application Support/SecureSandbox/harness-acceptance")
RETAINED_RELATIVE = Path("SecureSandbox-Acceptance-Handoff/retired-campaigns")
PLAN_NAME = "retention-plan.json"
SUPERSESSION_PREFIX = "retention-plan-supersession-"
SUPERSESSION_PATTERN = re.compile(
    rf"^{re.escape(SUPERSESSION_PREFIX)}([0-9a-f]{{40}})\.json$",
)
EXPECTED_ROOT = {"campaign.json", "observations", "raw"}
EXPECTED_RAW = {"bootstrap", "qualification", "recovery"}
RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
RENAME_RESOLVE_BENEATH = 0x00000020
MAX_CAMPAIGN = 1024 * 1024
MAX_SUPERSESSIONS = 32


class RetentionError(RuntimeError):
    """Stable, content-free rejected-retention result."""


def acl_absent(descriptor: int) -> bool:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        get_acl = libc.acl_get_fd_np
        get_acl.argtypes = [ctypes.c_int, ctypes.c_int]
        get_acl.restype = ctypes.c_void_p
        free_acl = libc.acl_free
        free_acl.argtypes = [ctypes.c_void_p]
        free_acl.restype = ctypes.c_int
    except (AttributeError, OSError):
        return False
    ctypes.set_errno(0)
    value = get_acl(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if value:
        free_acl(value)
        return False
    return ctypes.get_errno() == errno.ENOENT


def _directory(path: Path, uid: int,
               modes: frozenset[int] = frozenset({0o700})) -> int:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) not in modes
            or not acl_absent(descriptor)):
        os.close(descriptor)
        raise RetentionError("retention_directory_untrusted")
    return descriptor


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _campaign_bytes(root: Path, uid: int) -> bytes:
    path = root / "campaign.json"
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_CAMPAIGN):
        raise RetentionError("retention_campaign_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if not acl_absent(descriptor):
            raise RetentionError("retention_campaign_untrusted")
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, MAX_CAMPAIGN + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if (identity(before) != identity(opened) or identity(opened) != identity(after)
            or len(raw) != opened.st_size or len(raw) > MAX_CAMPAIGN):
        raise RetentionError("retention_campaign_changed")
    return raw


def validate_empty_layout(root: Path, uid: int, *,
                          reserved_bootstrap: bool = False
                          ) -> tuple[dict[str, Any], str]:
    root_descriptor = _directory(root, uid)
    try:
        entries = set(os.listdir(root_descriptor))
    finally:
        os.close(root_descriptor)
    extra = entries - EXPECTED_ROOT
    supersessions = {name for name in extra if SUPERSESSION_PATTERN.fullmatch(name)}
    if (extra not in (set(), {PLAN_NAME})
            and (PLAN_NAME not in extra
                 or extra != {PLAN_NAME} | supersessions
                 or len(supersessions) > MAX_SUPERSESSIONS)):
        raise RetentionError("retention_campaign_not_empty")
    raw = _campaign_bytes(root, uid)
    try:
        campaign = validate_campaign(json.loads(raw), int(time.time()), allow_expired=True)
    except (AcceptanceError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetentionError("retention_campaign_invalid") from error
    if canonical(campaign) != raw:
        raise RetentionError("retention_campaign_invalid")
    bootstrap_entries = (
        {RESERVED_CASE_ID} if reserved_bootstrap else set()
    )
    for relative, expected in (
        (Path("observations"), set()),
        (Path("raw"), EXPECTED_RAW),
        (Path("raw/bootstrap"), bootstrap_entries),
        (Path("raw/qualification"), set()),
        (Path("raw/recovery"), set()),
    ):
        descriptor = _directory(root / relative, uid)
        try:
            if set(os.listdir(descriptor)) != expected:
                raise RetentionError("retention_campaign_not_empty")
        finally:
            os.close(descriptor)
    directories = [
        ".", "observations", "raw", "raw/bootstrap",
        "raw/qualification", "raw/recovery",
    ]
    if reserved_bootstrap:
        reservation = root / "raw/bootstrap" / RESERVED_CASE_ID
        descriptor = _directory(reservation, uid)
        try:
            if os.listdir(descriptor):
                raise RetentionError("retention_reserved_case_not_empty")
        finally:
            os.close(descriptor)
        try:
            next_value = ACCEPTANCE_CLI.next_case(
                campaign, root / "observations",
                observation_uid=uid, directory_uid=uid,
            )
        except (AcceptanceError, OSError) as error:
            raise RetentionError("retention_reserved_case_invalid") from error
        next_case = next_value.get("case")
        if (next_value.get("status") != "pending"
                or not isinstance(next_case, dict)
                or next_case.get("case_id") != RESERVED_CASE_ID):
            raise RetentionError("retention_reserved_case_invalid")
        directories.append(f"raw/bootstrap/{RESERVED_CASE_ID}")
    inventory = {
        "campaign_sha256": hashlib.sha256(raw).hexdigest(),
        "directories": directories,
        "files": ["campaign.json"],
    }
    return campaign, digest(inventory)


def _validate_reserved_diagnostic(value: Any,
                                  campaign: dict[str, Any]) -> None:
    if not isinstance(value, dict):
        raise RetentionError("retention_reserved_diagnostic_invalid")
    unsigned = {
        key: item for key, item in value.items()
        if key != "diagnostic_sha256"
    }
    observed_at = value.get("observed_at")
    if (set(value) != {
            "schema", "status", "case_id", "error", "source_commit",
            "observed_at", "host_release_fields", "host_release_sha256",
            "diagnostic_sha256",
        }
            or value.get("schema") != RESERVED_DIAGNOSTIC_SCHEMA
            or value.get("status") != "confirmed"
            or value.get("case_id") != RESERVED_CASE_ID
            or value.get("error") != RESERVED_EXPECTED_ERROR
            or value.get("source_commit") != campaign["source_commit"]
            or not isinstance(observed_at, int)
            or isinstance(observed_at, bool)
            or observed_at < campaign["created_at"]
            or observed_at > int(time.time())
            or value.get("host_release_fields") != MODERN_HOST_RELEASE_FIELDS
            or not isinstance(value.get("host_release_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["host_release_sha256"])
               is None
            or value.get("diagnostic_sha256") != digest(unsigned)):
        raise RetentionError("retention_reserved_diagnostic_invalid")


def confirm_reserved_bootstrap_failure(
        campaign: dict[str, Any], observations: Path, now: int
        ) -> dict[str, Any]:
    release = (
        ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT / "releases"
        / campaign["source_commit"]
    )
    try:
        completed = subprocess.run(
            [
                "/usr/bin/python3", "-I", "-c",
                RESERVED_DIAGNOSTIC_PROGRAM,
                str(release), str(observations.parent / "campaign.json"),
                str(observations), str(now), RESERVED_CASE_ID,
                RESERVED_EXPECTED_ERROR, RESERVED_DIAGNOSTIC_SCHEMA,
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd="/", timeout=45, check=False,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RetentionError("retention_reserved_diagnostic_failed") from error
    if (completed.returncode != 0 or completed.stderr
            or not completed.stdout or len(completed.stdout) > 64 * 1024):
        raise RetentionError("retention_reserved_diagnostic_failed")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetentionError("retention_reserved_diagnostic_failed") from error
    if canonical(value) != completed.stdout:
        raise RetentionError("retention_reserved_diagnostic_failed")
    _validate_reserved_diagnostic(value, campaign)
    return value


def _write_new_at(parent_descriptor: int, name: str,
                  value: dict[str, Any]) -> None:
    raw = canonical(value)
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        dir_fd=parent_descriptor,
    )
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RetentionError("retention_plan_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent_descriptor)


def _rename_exclusive(source_parent: int, source: str,
                      destination_parent: int, destination: str) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameatx_np
    except (AttributeError, OSError) as error:
        raise RetentionError("retention_atomic_rename_unavailable") from error
    rename.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    if rename(
        source_parent, os.fsencode(source),
        destination_parent, os.fsencode(destination),
        RENAME_EXCL | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH,
    ) != 0:
        raise RetentionError("retention_atomic_rename_failed")


def _trusted_plan(path: Path, uid: int) -> dict[str, Any]:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_CAMPAIGN):
        raise RetentionError("retention_plan_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if not acl_absent(descriptor):
            raise RetentionError("retention_plan_untrusted")
        opened = os.fstat(descriptor)
        data = os.read(descriptor, MAX_CAMPAIGN + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if (identity(before) != identity(opened) or identity(opened) != identity(after)
            or len(data) != opened.st_size):
        raise RetentionError("retention_plan_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetentionError("retention_plan_invalid") from error
    if not isinstance(value, dict):
        raise RetentionError("retention_plan_invalid")
    unsigned = {key: item for key, item in value.items() if key != "plan_sha256"}
    common = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "campaign_source_commit", "replacement_source_commit", "remote_tips",
        "machine_identity_sha256", "operator_uid", "reason", "observed_at",
        "inventory_sha256", "destination_name", "plan_sha256",
    }
    ordinary = (
        set(value) == common
        and value.get("schema") == SCHEMA
        and value.get("reason") == "preflight-failed-before-evidence"
    )
    reserved = (
        set(value) == common | {
            "reserved_case_id", "expected_error", "evidence_state",
            "rejection_diagnostic",
        }
        and value.get("schema") == RESERVED_SCHEMA
        and value.get("reason") == "collector-rejected-after-empty-reservation"
        and value.get("reserved_case_id") == RESERVED_CASE_ID
        and value.get("expected_error") == RESERVED_EXPECTED_ERROR
        and value.get("evidence_state") == "empty-reservation"
    )
    if reserved:
        _validate_reserved_diagnostic(
            value.get("rejection_diagnostic"), {
                "source_commit": value.get("campaign_source_commit"),
                "created_at": 0,
            },
        )
    if (canonical(value) != data or not (ordinary or reserved)
            or value.get("status") != "prepared"
            or not isinstance(value.get("observed_at"), int)
            or isinstance(value.get("observed_at"), bool)
            or not isinstance(value.get("operator_uid"), int)
            or isinstance(value.get("operator_uid"), bool)
            or value.get("plan_sha256") != digest(unsigned)):
        raise RetentionError("retention_plan_invalid")
    return value


def _trusted_canonical_record(path: Path, uid: int, label: str) -> dict[str, Any]:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_CAMPAIGN):
        raise RetentionError(f"{label}_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if not acl_absent(descriptor):
            raise RetentionError(f"{label}_untrusted")
        opened = os.fstat(descriptor)
        data = os.read(descriptor, MAX_CAMPAIGN + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda result: (
        result.st_dev, result.st_ino, result.st_mode, result.st_uid,
        result.st_gid, result.st_nlink, result.st_size, result.st_mtime_ns,
        result.st_ctime_ns,
    )
    if (identity(before) != identity(opened) or identity(opened) != identity(after)
            or len(data) != opened.st_size):
        raise RetentionError(f"{label}_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetentionError(f"{label}_invalid") from error
    if not isinstance(value, dict) or canonical(value) != data:
        raise RetentionError(f"{label}_invalid")
    return value


def _trusted_supersession(path: Path, uid: int) -> dict[str, Any]:
    value = _trusted_canonical_record(path, uid, "retention_supersession")
    unsigned = {
        key: item for key, item in value.items()
        if key != "supersession_sha256"
    }
    expected_keys = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "campaign_source_commit", "prior_replacement_source_commit",
        "replacement_source_commit", "prior_authority_sha256",
        "remote_tips", "machine_identity_sha256", "operator_uid", "reason",
        "observed_at", "inventory_sha256", "destination_name",
        "supersession_sha256",
    }
    match = SUPERSESSION_PATTERN.fullmatch(path.name)
    if (set(value) != expected_keys
            or value.get("schema") != SUPERSESSION_SCHEMA
            or value.get("status") != "prepared"
            or value.get("reason") != "retention-plan-compatible-descendant"
            or not isinstance(value.get("observed_at"), int)
            or isinstance(value.get("observed_at"), bool)
            or not isinstance(value.get("operator_uid"), int)
            or isinstance(value.get("operator_uid"), bool)
            or value.get("supersession_sha256") != digest(unsigned)
            or match is None
            or match.group(1) != value.get("replacement_source_commit")):
        raise RetentionError("retention_supersession_invalid")
    return value


def _remote_tips_for(commit: str, remote_tips: Any) -> bool:
    expected = {name for name, _url in PREFLIGHT.AUTHORIZED_REMOTES}
    return (
        isinstance(remote_tips, dict)
        and set(remote_tips) == expected
        and all(value == commit for value in remote_tips.values())
    )


def _is_ancestor(older: str, newer: str) -> None:
    try:
        PREFLIGHT.git_command(
            ["merge-base", "--is-ancestor", older, newer], cwd=ROOT,
        )
    except PREFLIGHT.PreflightError as error:
        raise RetentionError("retention_replacement_not_descendant") from error


def _validate_plan_binding(plan: dict[str, Any], campaign: dict[str, Any],
                           inventory_sha256: str, uid: int, *,
                           reserved_bootstrap: bool = False) -> None:
    if reserved_bootstrap:
        try:
            _validate_reserved_diagnostic(
                plan.get("rejection_diagnostic"), campaign,
            )
        except RetentionError:
            mode_valid = False
        else:
            mode_valid = (
                plan.get("schema") == RESERVED_SCHEMA
                and plan.get("reserved_case_id") == RESERVED_CASE_ID
                and plan.get("expected_error") == RESERVED_EXPECTED_ERROR
                and plan.get("evidence_state") == "empty-reservation"
            )
    else:
        mode_valid = plan.get("schema") == SCHEMA
    if (not mode_valid
            or plan.get("campaign_id") != campaign["campaign_id"]
            or plan.get("campaign_sha256") != campaign["campaign_sha256"]
            or plan.get("campaign_source_commit") != campaign["source_commit"]
            or plan.get("machine_identity_sha256")
            != campaign["machine_identity_sha256"]
            or plan.get("operator_uid") != uid
            or plan.get("inventory_sha256") != inventory_sha256
            or plan.get("destination_name") != campaign["campaign_id"]
            or plan.get("replacement_source_commit")
            == campaign["source_commit"]
            or plan.get("observed_at", 0) < campaign["created_at"]
            or plan.get("observed_at", 0) > int(time.time())
            or not _remote_tips_for(
                plan.get("replacement_source_commit", ""),
                plan.get("remote_tips"),
            )):
        raise RetentionError("retention_plan_mismatch")
    _is_ancestor(
        campaign["source_commit"], plan["replacement_source_commit"],
    )


def _supersession_chain(root: Path, uid: int, plan: dict[str, Any],
                        campaign: dict[str, Any],
                        inventory_sha256: str) -> list[dict[str, Any]]:
    entries = {
        name for name in os.listdir(root)
        if SUPERSESSION_PATTERN.fullmatch(name)
    }
    chain: list[dict[str, Any]] = []
    authority_sha256 = plan["plan_sha256"]
    replacement = plan["replacement_source_commit"]
    observed_at = plan["observed_at"]
    while entries:
        candidates: list[tuple[str, dict[str, Any]]] = []
        for name in sorted(entries):
            value = _trusted_supersession(root / name, uid)
            if value["prior_authority_sha256"] == authority_sha256:
                candidates.append((name, value))
        if len(candidates) != 1:
            raise RetentionError("retention_supersession_chain_invalid")
        name, value = candidates[0]
        if (value["campaign_id"] != campaign["campaign_id"]
                or value["campaign_sha256"] != campaign["campaign_sha256"]
                or value["campaign_source_commit"] != campaign["source_commit"]
                or value["prior_replacement_source_commit"] != replacement
                or value["replacement_source_commit"] == replacement
                or value["observed_at"] < observed_at
                or value["observed_at"] > int(time.time())
                or value["machine_identity_sha256"]
                != campaign["machine_identity_sha256"]
                or value["operator_uid"] != uid
                or value["inventory_sha256"] != inventory_sha256
                or value["destination_name"] != campaign["campaign_id"]
                or not _remote_tips_for(
                    value["replacement_source_commit"], value["remote_tips"],
                )):
            raise RetentionError("retention_supersession_mismatch")
        _is_ancestor(replacement, value["replacement_source_commit"])
        replacement = value["replacement_source_commit"]
        authority_sha256 = value["supersession_sha256"]
        observed_at = value["observed_at"]
        chain.append(value)
        entries.remove(name)
    return chain


def _result(campaign: dict[str, Any], replacement: str,
            plan: dict[str, Any],
            supersessions: list[dict[str, Any]]) -> dict[str, Any]:
    authority_sha256 = (
        supersessions[-1]["supersession_sha256"]
        if supersessions else plan["plan_sha256"]
    )
    reserved = plan.get("schema") == RESERVED_SCHEMA
    value = {
        "schema": RESERVED_RESULT_SCHEMA if reserved else RESULT_SCHEMA,
        "status": "retained",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "replacement_source_commit": replacement,
        "plan_sha256": plan["plan_sha256"],
        "supersession_sha256s": [
            item["supersession_sha256"] for item in supersessions
        ],
        "retention_authority_sha256": authority_sha256,
        "destination_name": campaign["campaign_id"],
        "authority": "retention-only",
    }
    if reserved:
        value.update({
            "reserved_case_id": RESERVED_CASE_ID,
            "expected_error": RESERVED_EXPECTED_ERROR,
            "evidence_state": "empty-reservation",
            "diagnostic_sha256":
                plan["rejection_diagnostic"]["diagnostic_sha256"],
        })
    value["result_sha256"] = digest(value)
    return value


def verify_retained(*, expected_campaign_id: str,
                    expected_source_commit: str,
                    expected_replacement_commit: str,
                    reserved_bootstrap: bool = False,
                    home: Path | None = None,
                    source_probe: Callable[[], tuple[str, dict[str, str]]] | None = None,
                    identity_probe: Callable[[], str] | None = None) -> dict[str, Any]:
    if platform.system() != "Darwin":
        raise RetentionError("retention_disposable_mac_required")
    home = Path.home() if home is None else home
    uid = os.geteuid()
    live = home / CAMPAIGN_RELATIVE
    destination = home / RETAINED_RELATIVE / expected_campaign_id
    if os.path.lexists(live):
        raise RetentionError("retention_source_still_present")
    campaign, inventory_sha256 = validate_empty_layout(
        destination, uid, reserved_bootstrap=reserved_bootstrap,
    )
    if (campaign["campaign_id"] != expected_campaign_id
            or campaign["source_commit"] != expected_source_commit):
        raise RetentionError("retention_expected_campaign_mismatch")
    plan = _trusted_plan(destination / PLAN_NAME, uid)
    source_probe = PREFLIGHT.source_checkout if source_probe is None else source_probe
    replacement, remote_tips = source_probe()
    if replacement != expected_replacement_commit:
        raise RetentionError("retention_replacement_commit_mismatch")
    _is_ancestor(campaign["source_commit"], replacement)
    identity_probe = SUPERVISOR.current_machine_identity if identity_probe is None else identity_probe
    machine_identity = identity_probe()
    if machine_identity != campaign["machine_identity_sha256"]:
        raise RetentionError("retention_machine_identity_mismatch")
    readiness = ACCEPTANCE_CLI.driver_readiness(
        ROOT, source_commit=campaign["source_commit"],
    )
    if (readiness.get("available_driver_count") != len(DRIVER_ENTRYPOINTS)
            or readiness.get("status") != "ready"):
        raise RetentionError("retention_predecessor_driver_invalid")
    _validate_plan_binding(
        plan, campaign, inventory_sha256, uid,
        reserved_bootstrap=reserved_bootstrap,
    )
    supersessions = _supersession_chain(
        destination, uid, plan, campaign, inventory_sha256,
    )
    final_replacement = (
        supersessions[-1]["replacement_source_commit"]
        if supersessions else plan["replacement_source_commit"]
    )
    if (final_replacement != replacement
            or not _remote_tips_for(replacement, remote_tips)):
        raise RetentionError("retention_replacement_commit_mismatch")
    return _result(campaign, replacement, plan, supersessions)


def retain(*, expected_campaign_id: str, expected_source_commit: str,
           acknowledgement: str, now: int | None = None,
           reserved_bootstrap: bool = False,
           home: Path | None = None,
           rename: Callable[[int, str, int, str], None] = _rename_exclusive,
           source_probe: Callable[[], tuple[str, dict[str, str]]] | None = None,
           identity_probe: Callable[[], str] | None = None,
           reserved_probe: Callable[[dict[str, Any], Path, int],
                                    dict[str, Any]] | None = None
           ) -> dict[str, Any]:
    expected_acknowledgement = (
        RESERVED_ACKNOWLEDGEMENT if reserved_bootstrap else ACKNOWLEDGEMENT
    )
    if acknowledgement != expected_acknowledgement:
        raise RetentionError("retention_acknowledgement_required")
    if platform.system() != "Darwin":
        raise RetentionError("retention_disposable_mac_required")
    home = Path.home() if home is None else home
    uid = os.geteuid()
    root = home / CAMPAIGN_RELATIVE
    campaign, inventory_sha256 = validate_empty_layout(
        root, uid, reserved_bootstrap=reserved_bootstrap,
    )
    if (campaign["campaign_id"] != expected_campaign_id
            or campaign["source_commit"] != expected_source_commit):
        raise RetentionError("retention_expected_campaign_mismatch")
    source_probe = PREFLIGHT.source_checkout if source_probe is None else source_probe
    replacement, remote_tips = source_probe()
    if replacement == campaign["source_commit"]:
        raise RetentionError("retention_replacement_commit_required")
    _is_ancestor(campaign["source_commit"], replacement)
    identity_probe = SUPERVISOR.current_machine_identity if identity_probe is None else identity_probe
    if identity_probe() != campaign["machine_identity_sha256"]:
        raise RetentionError("retention_machine_identity_mismatch")
    readiness = ACCEPTANCE_CLI.driver_readiness(
        ROOT, source_commit=campaign["source_commit"],
    )
    if (readiness.get("available_driver_count") != len(DRIVER_ENTRYPOINTS)
            or readiness.get("status") != "ready"):
        raise RetentionError("retention_predecessor_driver_invalid")

    destination_name = campaign["campaign_id"]
    source_parent = _directory(root.parent, uid, frozenset({0o700, 0o755}))
    root_descriptor = _directory(root, uid)
    retained_descriptor: int | None = None
    try:
        root_identity = _directory_identity(os.fstat(root_descriptor))
        named_source = os.stat(
            root.name, dir_fd=source_parent, follow_symlinks=False,
        )
        if _directory_identity(named_source) != root_identity:
            raise RetentionError("retention_source_identity_changed")

        handoff = home / RETAINED_RELATIVE.parent
        handoff_descriptor = _directory(handoff, uid)
        try:
            retained = handoff / RETAINED_RELATIVE.name
            try:
                os.mkdir(
                    RETAINED_RELATIVE.name, mode=0o700,
                    dir_fd=handoff_descriptor,
                )
            except FileExistsError:
                pass
            else:
                os.chmod(
                    RETAINED_RELATIVE.name, 0o700,
                    dir_fd=handoff_descriptor, follow_symlinks=False,
                )
                os.fsync(handoff_descriptor)
            retained_descriptor = _directory(retained, uid)
        finally:
            os.close(handoff_descriptor)
        try:
            os.stat(
                destination_name, dir_fd=retained_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise RetentionError("retention_destination_exists")

        observed_at = int(time.time()) if now is None else now
        rejection_diagnostic = None
        plan_path = root / PLAN_NAME
        if reserved_bootstrap and not os.path.lexists(plan_path):
            probe = (
                confirm_reserved_bootstrap_failure
                if reserved_probe is None else reserved_probe
            )
            rejection_diagnostic = probe(
                campaign, root / "observations", observed_at,
            )
            _validate_reserved_diagnostic(rejection_diagnostic, campaign)
        plan = {
            "schema": RESERVED_SCHEMA if reserved_bootstrap else SCHEMA,
            "status": "prepared",
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "campaign_source_commit": campaign["source_commit"],
            "replacement_source_commit": replacement,
            "remote_tips": remote_tips,
            "machine_identity_sha256": campaign["machine_identity_sha256"],
            "operator_uid": uid,
            "reason": (
                "collector-rejected-after-empty-reservation"
                if reserved_bootstrap else "preflight-failed-before-evidence"
            ),
            "observed_at": observed_at,
            "inventory_sha256": inventory_sha256,
            "destination_name": destination_name,
        }
        if reserved_bootstrap:
            plan.update({
                "reserved_case_id": RESERVED_CASE_ID,
                "expected_error": RESERVED_EXPECTED_ERROR,
                "evidence_state": "empty-reservation",
                "rejection_diagnostic": rejection_diagnostic,
            })
        plan["plan_sha256"] = digest(plan)
        if os.path.lexists(plan_path):
            plan = _trusted_plan(plan_path, uid)
            _validate_plan_binding(
                plan, campaign, inventory_sha256, uid,
                reserved_bootstrap=reserved_bootstrap,
            )
        else:
            if not _remote_tips_for(replacement, remote_tips):
                raise RetentionError("retention_remote_tips_mismatch")
            _write_new_at(root_descriptor, PLAN_NAME, plan)
            if _trusted_plan(plan_path, uid) != plan:
                raise RetentionError("retention_plan_write_failed")

        supersessions = _supersession_chain(
            root, uid, plan, campaign, inventory_sha256,
        )
        prior_replacement = (
            supersessions[-1]["replacement_source_commit"]
            if supersessions else plan["replacement_source_commit"]
        )
        prior_authority = (
            supersessions[-1]["supersession_sha256"]
            if supersessions else plan["plan_sha256"]
        )
        if prior_replacement != replacement:
            _is_ancestor(prior_replacement, replacement)
            if not _remote_tips_for(replacement, remote_tips):
                raise RetentionError("retention_remote_tips_mismatch")
            supersession = {
                "schema": SUPERSESSION_SCHEMA,
                "status": "prepared",
                "campaign_id": campaign["campaign_id"],
                "campaign_sha256": campaign["campaign_sha256"],
                "campaign_source_commit": campaign["source_commit"],
                "prior_replacement_source_commit": prior_replacement,
                "replacement_source_commit": replacement,
                "prior_authority_sha256": prior_authority,
                "remote_tips": remote_tips,
                "machine_identity_sha256": campaign["machine_identity_sha256"],
                "operator_uid": uid,
                "reason": "retention-plan-compatible-descendant",
                "observed_at": int(time.time()) if now is None else now,
                "inventory_sha256": inventory_sha256,
                "destination_name": destination_name,
            }
            supersession["supersession_sha256"] = digest(supersession)
            supersession_path = (
                root / f"{SUPERSESSION_PREFIX}{replacement}.json"
            )
            if os.path.lexists(supersession_path):
                if _trusted_supersession(supersession_path, uid) != supersession:
                    raise RetentionError("retention_supersession_mismatch")
            else:
                _write_new_at(root_descriptor, supersession_path.name, supersession)
                if _trusted_supersession(supersession_path, uid) != supersession:
                    raise RetentionError("retention_supersession_write_failed")
            supersessions.append(supersession)

        named_source = os.stat(
            root.name, dir_fd=source_parent, follow_symlinks=False,
        )
        if _directory_identity(named_source) != root_identity:
            raise RetentionError("retention_source_identity_changed")
        rename(source_parent, root.name, retained_descriptor, destination_name)
        try:
            os.stat(root.name, dir_fd=source_parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RetentionError("retention_source_still_present")
        retained_info = os.stat(
            destination_name, dir_fd=retained_descriptor, follow_symlinks=False,
        )
        if _directory_identity(retained_info) != root_identity:
            raise RetentionError("retention_destination_identity_mismatch")
        os.fsync(source_parent)
        os.fsync(retained_descriptor)
    finally:
        os.close(root_descriptor)
        os.close(source_parent)
        if retained_descriptor is not None:
            os.close(retained_descriptor)
    destination = retained / destination_name
    retained_campaign, retained_inventory = validate_empty_layout(
        destination, uid, reserved_bootstrap=reserved_bootstrap,
    )
    retained_plan = _trusted_plan(destination / PLAN_NAME, uid)
    retained_supersessions = _supersession_chain(
        destination, uid, retained_plan, retained_campaign, retained_inventory,
    )
    if (os.path.lexists(root) or retained_campaign != campaign
            or retained_inventory != inventory_sha256 or retained_plan != plan
            or retained_supersessions != supersessions):
        raise RetentionError("retention_readback_failed")
    return _result(campaign, replacement, plan, supersessions)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Retain one no-evidence rejected acceptance campaign",
    )
    commands = value.add_subparsers(dest="command", required=True)
    for name in ("retain", "retain-reserved-bootstrap"):
        command = commands.add_parser(name)
        command.add_argument("--expected-campaign-id", required=True)
        command.add_argument("--expected-source-commit", required=True)
        acknowledgement = (
            RESERVED_ACKNOWLEDGEMENT
            if name == "retain-reserved-bootstrap" else ACKNOWLEDGEMENT
        )
        command.add_argument(
            "--acknowledge", required=True,
            help=f"must equal {acknowledgement!r}",
        )
    for name in ("verify", "verify-reserved-bootstrap"):
        command = commands.add_parser(name)
        command.add_argument("--expected-campaign-id", required=True)
        command.add_argument("--expected-source-commit", required=True)
        command.add_argument("--expected-replacement-commit", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    reserved_bootstrap = args.command.endswith("reserved-bootstrap")
    if args.command.startswith("retain"):
        result = retain(
            expected_campaign_id=args.expected_campaign_id,
            expected_source_commit=args.expected_source_commit,
            acknowledgement=args.acknowledge,
            reserved_bootstrap=reserved_bootstrap,
        )
    else:
        result = verify_retained(
            expected_campaign_id=args.expected_campaign_id,
            expected_source_commit=args.expected_source_commit,
            expected_replacement_commit=args.expected_replacement_commit,
            reserved_bootstrap=reserved_bootstrap,
        )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RetentionError, AcceptanceError, OSError) as error:
        sys.stdout.buffer.write(canonical({
            "schema": "secure-sandbox-harness-lifecycle-empty-campaign-retention-error-v1",
            "status": "rejected",
            "error": str(error),
        }))
        raise SystemExit(1)
