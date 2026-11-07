#!/usr/bin/env python3
"""Read-only gate before any disposable-Mac root or Touch ID ceremony."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    DRIVER_ENTRYPOINTS,
    canonical,
    digest,
    validate_enrollment,
)


SCHEMA = "secure-sandbox-harness-lifecycle-morning-preflight-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-morning-preflight-error-v1"
PUBLIC_BRANCH = "public-release"
AUTHORIZED_REMOTES = (
    ("origin", "https://github.com/AtomicGaryBusey/SecureSandbox.git"),
)
MAX_OUTPUT = 1024 * 1024
TOUCH_ID_CASE_COUNT = 11
NEXT_ACTIONS = (
    "bootstrap-root-owned-exact-commit-host-installer",
    "initialize-exact-commit-campaign",
)
PREFLIGHT_RECEIPT_KEYS = {
    "schema", "status", "observed_at", "source_commit", "branch",
    "remote_tips", "machine_identity_sha256", "operator_uid",
    "enrollment_sha256", "production_material_absent",
    "bootstrap_trust_root", "parallels_gui_closed", "vm_states",
    "source_driver_count", "source_closure_complete",
    "protected_driver_count", "protected_installation_ready",
    "touch_id_cases_queued", "touch_id_authorization_ready",
    "next_authorization", "next_action", "authority", "preflight_sha256",
}
BOOTSTRAP_RECORD_KEYS = {
    "path", "device", "inode", "uid", "gid", "mode", "acl_present",
}
BOOTSTRAP_TRUST_HIERARCHY = (
    Path("/"), Path("/private"), Path("/private/var"), Path("/private/var/db"),
)


class PreflightError(RuntimeError):
    """Stable, content-free preflight failure."""


def exact_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PreflightError("preflight_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_morning_acceptance_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)
ENROLLER = load_script(
    "harness_lifecycle_morning_enroller",
    ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py",
)
SUPERVISOR = load_script(
    "harness_lifecycle_morning_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)


def git_command(
    arguments: list[str], *, cwd: Path,
    runner: Callable[..., Any] = subprocess.run,
) -> bytes:
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = runner(
            ["/usr/bin/git", *arguments], cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=30, env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError("preflight_git_probe_failed") from error
    if (result.returncode != 0 or len(result.stdout) > MAX_OUTPUT
            or len(result.stderr) > 64 * 1024):
        raise PreflightError("preflight_git_probe_failed")
    return result.stdout


def source_checkout(*, runner: Callable[..., Any] = subprocess.run) -> tuple[str, dict[str, str]]:
    head = git_command(
        ["rev-parse", "--verify", "HEAD^{commit}"], cwd=ROOT, runner=runner,
    )
    branch = git_command(
        ["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=ROOT,
        runner=runner,
    )
    status = git_command(
        ["status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT,
        runner=runner,
    )
    try:
        commit = head.decode("ascii").strip()
        branch_name = branch.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise PreflightError("preflight_checkout_invalid") from error
    if (len(commit) != 40 or any(value not in "0123456789abcdef" for value in commit)
            or branch_name != PUBLIC_BRANCH or status):
        raise PreflightError("preflight_checkout_invalid")
    tips: dict[str, str] = {}
    for remote, authorized_url in AUTHORIZED_REMOTES:
        raw = git_command(
            ["ls-remote", "--exit-code", authorized_url,
             f"refs/heads/{PUBLIC_BRANCH}"],
            cwd=Path("/"), runner=runner,
        )
        try:
            fields = raw.decode("ascii", "strict").split()
        except UnicodeDecodeError as error:
            raise PreflightError("preflight_remote_tip_invalid") from error
        if fields != [commit, f"refs/heads/{PUBLIC_BRANCH}"]:
            raise PreflightError("preflight_remote_tip_mismatch")
        tips[remote] = commit
    return commit, tips


def production_material_absent(
    *, home: Path, environment: dict[str, str],
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    if any(environment.get(name) for name in ENROLLER.PROVIDER_ENVIRONMENT):
        raise PreflightError("preflight_production_material_present")
    if any(os.path.lexists(home / relative) for relative in ENROLLER.FORBIDDEN_HOME_PATHS):
        raise PreflightError("preflight_production_material_present")
    try:
        ENROLLER.keychain_absent(runner)
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        raise PreflightError("preflight_production_material_present") from error


def trusted_bootstrap_hierarchy(
    *, hierarchy: tuple[Path, ...] = BOOTSTRAP_TRUST_HIERARCHY,
    expected_uid: int = 0, runner: Callable[..., Any] = subprocess.run,
    lstat: Callable[..., os.stat_result] = os.lstat,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in hierarchy:
        try:
            info = lstat(path)
        except OSError as error:
            raise PreflightError("preflight_bootstrap_trust_root_invalid") from error
        mode = stat.S_IMODE(info.st_mode)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != expected_uid
                or mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise PreflightError("preflight_bootstrap_trust_root_invalid")
        try:
            result = runner(
                ["/bin/ls", "-lde", str(path)], cwd=Path("/"),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=5,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise PreflightError("preflight_bootstrap_trust_root_invalid") from error
        # macOS ls -e prints every extended ACL entry on a continuation line.
        # The fixed hierarchy must have only the single ordinary listing line.
        if (result.returncode != 0 or len(result.stdout) > 4096
                or result.stderr
                or len(result.stdout.splitlines()) != 1):
            raise PreflightError("preflight_bootstrap_trust_root_invalid")
        try:
            after = lstat(path)
        except OSError as error:
            raise PreflightError("preflight_bootstrap_trust_root_invalid") from error
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        after_identity = (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
        )
        if after_identity != identity:
            raise PreflightError("preflight_bootstrap_trust_root_invalid")
        records.append({
            "path": str(path), "device": info.st_dev, "inode": info.st_ino,
            "uid": info.st_uid, "gid": info.st_gid, "mode": mode,
            "acl_present": False,
        })
    return records


def write_preflight_receipt(
    path: Path, value: dict[str, Any], *, expected_uid: int | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    owner = os.geteuid() if expected_uid is None else expected_uid
    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PreflightError("preflight_output_directory_invalid")
    parent = path.parent
    try:
        before = parent.lstat()
    except OSError as error:
        raise PreflightError("preflight_output_directory_invalid") from error
    if (stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode)
            or before.st_uid != owner or stat.S_IMODE(before.st_mode) != 0o700):
        raise PreflightError("preflight_output_directory_invalid")
    try:
        acl = runner(
            ["/bin/ls", "-lde", str(parent)], cwd=Path("/"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError("preflight_output_directory_invalid") from error
    if (acl.returncode != 0 or len(acl.stdout) > 4096 or acl.stderr
            or len(acl.stdout.splitlines()) != 1):
        raise PreflightError("preflight_output_directory_invalid")

    directory = -1
    descriptor = -1
    try:
        directory = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        opened = os.fstat(directory)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid)
        if ((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid)
                != identity):
            raise PreflightError("preflight_output_directory_invalid")
        descriptor = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=directory,
        )
        os.fchmod(descriptor, 0o600)
        payload = canonical(value)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PreflightError("preflight_output_publish_failed")
            view = view[written:]
        published = os.fstat(descriptor)
        if (not stat.S_ISREG(published.st_mode) or published.st_uid != owner
                or published.st_nlink != 1
                or stat.S_IMODE(published.st_mode) != 0o600
                or published.st_size != len(payload)):
            raise PreflightError("preflight_output_publish_failed")
        os.fsync(descriptor)
        os.fsync(directory)
    except OSError as error:
        raise PreflightError("preflight_output_publish_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)


def validated_receipt_source_commit(
    path: Path, expected_action: str, *, expected_uid: int | None = None,
) -> str:
    owner = os.geteuid() if expected_uid is None else expected_uid
    try:
        value = ACCEPTANCE_CLI.trusted_json(path, expected_uid=owner)
    except (AcceptanceError, OSError) as error:
        raise PreflightError("preflight_receipt_invalid") from error
    claimed = value.get("preflight_sha256")
    unsigned = dict(value)
    unsigned.pop("preflight_sha256", None)
    source_commit = value.get("source_commit")
    protected_ready = expected_action == "initialize-exact-commit-campaign"
    bootstrap = value.get("bootstrap_trust_root")
    expected_bootstrap_paths = [str(item) for item in BOOTSTRAP_TRUST_HIERARCHY]
    bootstrap_valid = (
        isinstance(bootstrap, list)
        and len(bootstrap) == len(expected_bootstrap_paths)
        and all(
            isinstance(item, dict)
            and set(item) == BOOTSTRAP_RECORD_KEYS
            and item.get("path") == expected_bootstrap_paths[index]
            and exact_integer(item.get("device"))
            and item["device"] >= 0
            and exact_integer(item.get("inode"))
            and item["inode"] > 0
            and exact_integer(item.get("uid"))
            and item["uid"] == 0
            and exact_integer(item.get("gid"))
            and item["gid"] >= 0
            and exact_integer(item.get("mode"))
            and 0 <= item["mode"] <= 0o7777
            and item["mode"] & 0o100 != 0
            and item["mode"] & 0o022 == 0
            and item.get("acl_present") is False
            for index, item in enumerate(bootstrap)
        )
    )
    machine_identity = value.get("machine_identity_sha256")
    enrollment_digest = value.get("enrollment_sha256")
    observed_at = value.get("observed_at")
    vm_states = value.get("vm_states")
    if (set(value) != PREFLIGHT_RECEIPT_KEYS
            or value.get("schema") != SCHEMA or value.get("status") != "ready"
            or value.get("next_action") != expected_action
            or not exact_integer(value.get("operator_uid"))
            or value.get("operator_uid") != owner
            or value.get("authority") != "none"
            or not exact_integer(observed_at)
            or observed_at <= 0
            or not isinstance(machine_identity, str) or len(machine_identity) != 64
            or any(character not in "0123456789abcdef"
                   for character in machine_identity)
            or not isinstance(enrollment_digest, str) or len(enrollment_digest) != 64
            or any(character not in "0123456789abcdef"
                   for character in enrollment_digest)
            or value.get("production_material_absent") is not True
            or not bootstrap_valid
            or value.get("parallels_gui_closed") is not True
            or not isinstance(vm_states, dict)
            or set(vm_states) != {"gateway", "research", "target"}
            or not (all(state in {"running", "stopped"}
                        for state in vm_states.values())
                    or not protected_ready
                    and all(state == "absent" for state in vm_states.values()))
            or not exact_integer(value.get("source_driver_count"))
            or value["source_driver_count"] != len(DRIVER_ENTRYPOINTS)
            or value.get("source_closure_complete") is not True
            or not exact_integer(value.get("protected_driver_count"))
            or value["protected_driver_count"]
            != (len(DRIVER_ENTRYPOINTS) if protected_ready else 0)
            or value.get("touch_id_authorization_ready") is not False
            or not exact_integer(value.get("touch_id_cases_queued"))
            or value["touch_id_cases_queued"] != TOUCH_ID_CASE_COUNT
            or value.get("protected_installation_ready") is not protected_ready
            or value.get("next_authorization")
            != ("none" if protected_ready else "root-password")
            or not isinstance(source_commit, str) or len(source_commit) != 40
            or any(character not in "0123456789abcdef" for character in source_commit)
            or value.get("branch") != PUBLIC_BRANCH
            or value.get("remote_tips") != {"origin": source_commit}
            or not isinstance(claimed, str) or claimed != digest(unsigned)):
        raise PreflightError("preflight_receipt_invalid")
    return source_commit


def run_preflight(
    enrollment_path: Path, *, now: int, home: Path,
    environment: dict[str, str], git_runner: Callable[..., Any] = subprocess.run,
    probe_runner: Callable[..., Any] = subprocess.run,
    protected_root: Path = ACCEPTANCE_CLI.PROTECTED_INSTALL_ROOT,
    expected_install_uid: int = 0,
    effective_uid: int | None = None,
) -> dict[str, Any]:
    operator_uid = os.geteuid() if effective_uid is None else effective_uid
    if operator_uid == 0:
        raise PreflightError("preflight_must_not_run_as_root")
    bootstrap_trust_root = trusted_bootstrap_hierarchy(runner=probe_runner)
    commit, remote_tips = source_checkout(runner=git_runner)
    try:
        enrollment = validate_enrollment(
            ACCEPTANCE_CLI.trusted_json(enrollment_path), now,
        )
        identity = ENROLLER.machine_identity(probe_runner)
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        raise PreflightError("preflight_enrollment_invalid") from error
    if identity != enrollment["machine_identity_sha256"]:
        raise PreflightError("preflight_machine_identity_mismatch")
    production_material_absent(
        home=home, environment=environment, runner=probe_runner,
    )

    source = ACCEPTANCE_CLI.driver_readiness(ROOT)
    if (source.get("driver_count") != len(DRIVER_ENTRYPOINTS)
            or not all(item.get("source_complete") is True for item in source["drivers"])):
        raise PreflightError("preflight_source_closure_incomplete")
    installed = ACCEPTANCE_CLI.driver_readiness(
        ROOT, source_commit=commit, protected_root=protected_root,
        expected_install_uid=expected_install_uid,
    )
    installed_count = installed["available_driver_count"]
    if installed_count not in {0, len(DRIVER_ENTRYPOINTS)}:
        raise PreflightError("preflight_protected_installation_partial")
    if installed_count == 0 and any(
        item.get("installation_error") != "protected_driver_installation_missing"
        for item in installed["drivers"]
    ):
        raise PreflightError("preflight_protected_installation_invalid")

    try:
        SUPERVISOR.require_gui_closed()
        vm_states = SUPERVISOR.vm_inventory(allow_all_absent=installed_count == 0)
    except SUPERVISOR.SupervisorError as error:
        raise PreflightError("preflight_vm_boundary_invalid") from error
    if (set(vm_states) != {"gateway", "research", "target"}
            or not (all(state in {"running", "stopped"} for state in vm_states.values())
                    or installed_count == 0
                    and all(state == "absent" for state in vm_states.values()))):
        raise PreflightError("preflight_vm_boundary_invalid")

    protected_ready = installed_count == len(DRIVER_ENTRYPOINTS)
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "ready",
        "observed_at": now,
        "source_commit": commit,
        "branch": PUBLIC_BRANCH,
        "remote_tips": remote_tips,
        "machine_identity_sha256": identity,
        "operator_uid": operator_uid,
        "enrollment_sha256": enrollment["enrollment_sha256"],
        "production_material_absent": True,
        "bootstrap_trust_root": bootstrap_trust_root,
        "parallels_gui_closed": True,
        "vm_states": vm_states,
        "source_driver_count": len(DRIVER_ENTRYPOINTS),
        "source_closure_complete": True,
        "protected_driver_count": installed_count,
        "protected_installation_ready": protected_ready,
        "touch_id_cases_queued": TOUCH_ID_CASE_COUNT,
        "touch_id_authorization_ready": False,
        "next_authorization": "none" if protected_ready else "root-password",
        "next_action": (
            "initialize-exact-commit-campaign" if protected_ready
            else "bootstrap-root-owned-exact-commit-host-installer"
        ),
        "authority": "none",
    }
    value["preflight_sha256"] = digest(value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Read-only gate before disposable-Mac operator ceremonies",
    )
    source = value.add_mutually_exclusive_group(required=True)
    source.add_argument("--enrollment", type=Path)
    source.add_argument("--source-commit-from-receipt", type=Path)
    value.add_argument("--expect-next-action", choices=NEXT_ACTIONS)
    value.add_argument("--output", type=Path)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if args.source_commit_from_receipt is not None:
        if args.expect_next_action is None or args.output is not None:
            raise PreflightError("preflight_receipt_request_invalid")
        print(validated_receipt_source_commit(
            args.source_commit_from_receipt, args.expect_next_action,
        ))
        return 0
    if args.output is not None and args.expect_next_action is None:
        raise PreflightError("preflight_expected_next_action_required")
    result = run_preflight(
        args.enrollment, now=int(time.time()), home=Path.home(),
        environment=dict(os.environ),
    )
    if (args.expect_next_action is not None
            and result["next_action"] != args.expect_next_action):
        raise PreflightError("preflight_unexpected_next_action")
    if args.output is None:
        sys.stdout.buffer.write(canonical(result))
    else:
        write_preflight_receipt(args.output, result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PreflightError, AcceptanceError, OSError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, (PreflightError, AcceptanceError)) else "preflight_failed"
        print(json.dumps({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
