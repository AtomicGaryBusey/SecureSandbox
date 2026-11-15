#!/usr/bin/env python3
"""Atomically retain an empty rejected campaign before an exact-source repair.

This is deliberately narrower than a general archive or reset command.  It
accepts only the fixed local campaign layout, requires every evidence
directory to be empty, records the exact old and replacement source bindings,
and moves the complete directory without overwrite.  It never deletes or
modifies an observation.
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
import stat
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
RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-empty-campaign-retention-v1"
ACKNOWLEDGEMENT = "RETAIN EMPTY REJECTED CAMPAIGN WITHOUT DELETION"
CAMPAIGN_RELATIVE = Path("Library/Application Support/SecureSandbox/harness-acceptance")
RETAINED_RELATIVE = Path("SecureSandbox-Acceptance-Handoff/retired-campaigns")
PLAN_NAME = "retention-plan.json"
EXPECTED_ROOT = {"campaign.json", "observations", "raw"}
EXPECTED_RAW = {"bootstrap", "qualification", "recovery"}
RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
RENAME_RESOLVE_BENEATH = 0x00000020
MAX_CAMPAIGN = 1024 * 1024


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


def _directory(path: Path, uid: int) -> int:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700
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


def validate_empty_layout(root: Path, uid: int) -> tuple[dict[str, Any], str]:
    root_descriptor = _directory(root, uid)
    try:
        entries = set(os.listdir(root_descriptor))
    finally:
        os.close(root_descriptor)
    if entries != EXPECTED_ROOT and entries != EXPECTED_ROOT | {PLAN_NAME}:
        raise RetentionError("retention_campaign_not_empty")
    raw = _campaign_bytes(root, uid)
    try:
        campaign = validate_campaign(json.loads(raw), int(time.time()), allow_expired=True)
    except (AcceptanceError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetentionError("retention_campaign_invalid") from error
    if canonical(campaign) != raw:
        raise RetentionError("retention_campaign_invalid")
    for relative, expected in (
        (Path("observations"), set()),
        (Path("raw"), EXPECTED_RAW),
        (Path("raw/bootstrap"), set()),
        (Path("raw/qualification"), set()),
        (Path("raw/recovery"), set()),
    ):
        descriptor = _directory(root / relative, uid)
        try:
            if set(os.listdir(descriptor)) != expected:
                raise RetentionError("retention_campaign_not_empty")
        finally:
            os.close(descriptor)
    inventory = {
        "campaign_sha256": hashlib.sha256(raw).hexdigest(),
        "directories": [
            ".", "observations", "raw", "raw/bootstrap",
            "raw/qualification", "raw/recovery",
        ],
        "files": ["campaign.json"],
    }
    return campaign, digest(inventory)


def _write_new(path: Path, value: dict[str, Any]) -> None:
    raw = canonical(value)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RetentionError("retention_plan_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


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
    if (canonical(value) != data or set(value) != {
        "schema", "status", "campaign_id", "campaign_sha256",
        "campaign_source_commit", "replacement_source_commit", "remote_tips",
        "machine_identity_sha256", "operator_uid", "reason", "observed_at",
        "inventory_sha256", "destination_name", "plan_sha256",
    } or value.get("schema") != SCHEMA or value.get("status") != "prepared"
            or value.get("reason") != "preflight-failed-before-evidence"
            or not isinstance(value.get("observed_at"), int)
            or isinstance(value.get("observed_at"), bool)
            or not isinstance(value.get("operator_uid"), int)
            or isinstance(value.get("operator_uid"), bool)
            or value.get("plan_sha256") != digest(unsigned)):
        raise RetentionError("retention_plan_invalid")
    return value


def _result(campaign: dict[str, Any], replacement: str,
            plan: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema": RESULT_SCHEMA,
        "status": "retained",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "replacement_source_commit": replacement,
        "plan_sha256": plan["plan_sha256"],
        "destination_name": campaign["campaign_id"],
        "authority": "retention-only",
    }
    value["result_sha256"] = digest(value)
    return value


def verify_retained(*, expected_campaign_id: str,
                    expected_source_commit: str,
                    expected_replacement_commit: str,
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
    campaign, inventory_sha256 = validate_empty_layout(destination, uid)
    if (campaign["campaign_id"] != expected_campaign_id
            or campaign["source_commit"] != expected_source_commit):
        raise RetentionError("retention_expected_campaign_mismatch")
    plan = _trusted_plan(destination / PLAN_NAME, uid)
    source_probe = PREFLIGHT.source_checkout if source_probe is None else source_probe
    replacement, remote_tips = source_probe()
    if replacement != expected_replacement_commit:
        raise RetentionError("retention_replacement_commit_mismatch")
    try:
        PREFLIGHT.git_command([
            "merge-base", "--is-ancestor", campaign["source_commit"], replacement,
        ], cwd=ROOT)
    except PREFLIGHT.PreflightError as error:
        raise RetentionError("retention_replacement_not_descendant") from error
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
    expected_plan = {
        "schema": SCHEMA,
        "status": "prepared",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "campaign_source_commit": campaign["source_commit"],
        "replacement_source_commit": replacement,
        "remote_tips": remote_tips,
        "machine_identity_sha256": machine_identity,
        "operator_uid": uid,
        "reason": "preflight-failed-before-evidence",
        "observed_at": plan["observed_at"],
        "inventory_sha256": inventory_sha256,
        "destination_name": campaign["campaign_id"],
    }
    expected_plan["plan_sha256"] = digest(expected_plan)
    if plan != expected_plan:
        raise RetentionError("retention_plan_mismatch")
    return _result(campaign, replacement, plan)


def retain(*, expected_campaign_id: str, expected_source_commit: str,
           acknowledgement: str, now: int | None = None,
           home: Path | None = None,
           rename: Callable[[int, str, int, str], None] = _rename_exclusive,
           source_probe: Callable[[], tuple[str, dict[str, str]]] | None = None,
           identity_probe: Callable[[], str] | None = None) -> dict[str, Any]:
    if acknowledgement != ACKNOWLEDGEMENT:
        raise RetentionError("retention_acknowledgement_required")
    if platform.system() != "Darwin":
        raise RetentionError("retention_disposable_mac_required")
    home = Path.home() if home is None else home
    uid = os.geteuid()
    root = home / CAMPAIGN_RELATIVE
    campaign, inventory_sha256 = validate_empty_layout(root, uid)
    if (campaign["campaign_id"] != expected_campaign_id
            or campaign["source_commit"] != expected_source_commit):
        raise RetentionError("retention_expected_campaign_mismatch")
    source_probe = PREFLIGHT.source_checkout if source_probe is None else source_probe
    replacement, remote_tips = source_probe()
    if replacement == campaign["source_commit"]:
        raise RetentionError("retention_replacement_commit_required")
    try:
        PREFLIGHT.git_command([
            "merge-base", "--is-ancestor", campaign["source_commit"], replacement,
        ], cwd=ROOT)
    except PREFLIGHT.PreflightError as error:
        raise RetentionError("retention_replacement_not_descendant") from error
    identity_probe = SUPERVISOR.current_machine_identity if identity_probe is None else identity_probe
    if identity_probe() != campaign["machine_identity_sha256"]:
        raise RetentionError("retention_machine_identity_mismatch")
    readiness = ACCEPTANCE_CLI.driver_readiness(
        ROOT, source_commit=campaign["source_commit"],
    )
    if (readiness.get("available_driver_count") != len(DRIVER_ENTRYPOINTS)
            or readiness.get("status") != "ready"):
        raise RetentionError("retention_predecessor_driver_invalid")

    handoff = home / RETAINED_RELATIVE.parent
    handoff_descriptor = _directory(handoff, uid)
    try:
        retained = handoff / RETAINED_RELATIVE.name
        try:
            retained.mkdir(mode=0o700)
        except FileExistsError:
            pass
        retained_descriptor = _directory(retained, uid)
    finally:
        os.close(handoff_descriptor)
    destination_name = campaign["campaign_id"]
    plan = {
        "schema": SCHEMA,
        "status": "prepared",
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "campaign_source_commit": campaign["source_commit"],
        "replacement_source_commit": replacement,
        "remote_tips": remote_tips,
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "operator_uid": uid,
        "reason": "preflight-failed-before-evidence",
        "observed_at": int(time.time()) if now is None else now,
        "inventory_sha256": inventory_sha256,
        "destination_name": destination_name,
    }
    plan["plan_sha256"] = digest(plan)
    plan_path = root / PLAN_NAME
    if plan_path.exists():
        existing = _trusted_plan(plan_path, uid)
        comparable = dict(existing)
        comparable["observed_at"] = plan["observed_at"]
        comparable.pop("plan_sha256")
        expected = dict(plan)
        expected.pop("plan_sha256")
        if comparable != expected:
            raise RetentionError("retention_plan_mismatch")
        plan = existing
    else:
        _write_new(plan_path, plan)

    source_parent = _directory(root.parent, uid)
    root_descriptor = _directory(root, uid)
    try:
        root_identity = _directory_identity(os.fstat(root_descriptor))
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
        os.close(retained_descriptor)
    destination = retained / destination_name
    retained_campaign, retained_inventory = validate_empty_layout(destination, uid)
    retained_plan = _trusted_plan(destination / PLAN_NAME, uid)
    if (root.exists() or retained_campaign != campaign
            or retained_inventory != inventory_sha256 or retained_plan != plan):
        raise RetentionError("retention_readback_failed")
    return _result(campaign, replacement, plan)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Retain one empty rejected acceptance campaign",
    )
    commands = value.add_subparsers(dest="command", required=True)
    retain_command = commands.add_parser("retain")
    retain_command.add_argument("--expected-campaign-id", required=True)
    retain_command.add_argument("--expected-source-commit", required=True)
    retain_command.add_argument("--acknowledge", required=True)
    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--expected-campaign-id", required=True)
    verify_command.add_argument("--expected-source-commit", required=True)
    verify_command.add_argument("--expected-replacement-commit", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if args.command == "retain":
        result = retain(
            expected_campaign_id=args.expected_campaign_id,
            expected_source_commit=args.expected_source_commit,
            acknowledgement=args.acknowledge,
        )
    else:
        result = verify_retained(
            expected_campaign_id=args.expected_campaign_id,
            expected_source_commit=args.expected_source_commit,
            expected_replacement_commit=args.expected_replacement_commit,
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
