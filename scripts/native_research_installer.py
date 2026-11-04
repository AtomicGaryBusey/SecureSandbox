#!/usr/bin/python3
"""Transactional, default-closed installer for the native Research runtime."""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import json
import os
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence


SOURCE_ROOT = Path("/tmp")
INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox")
RESEARCH_ROOT = INSTALL_ROOT / "research"
SHARED_ROOT = INSTALL_ROOT / "shared"
ETC_ROOT = Path("/etc/secure-sandbox")
STATE_ROOT = Path("/var/lib/secure-sandbox/native-vendor")
CONTROL_ROOT = STATE_ROOT / "controller"
INSTALL_STATE_ROOT = STATE_ROOT / "install"
PENDING = INSTALL_STATE_ROOT / "native-research-install.pending.json"
BACKUP_ROOT = INSTALL_STATE_ROOT / "backups"
SOURCE_ARCHIVE_ROOT = INSTALL_STATE_ROOT / "sources"
RECOVERY_ROOT = INSTALL_ROOT / "native-install-recovery"
LOCK_PATH = INSTALL_STATE_ROOT / "install.lock"
LIFECYCLE_ROOT = CONTROL_ROOT / "lifecycle"
LIFECYCLE_LOCK = LIFECYCLE_ROOT / ".lock"
MANIFEST = ETC_ROOT / "native-research-release.json"
CATALOG = ETC_ROOT / "native-vendor-stacks.json"
SERVICE = "native-harness-supervisor.service"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_TOTAL = 64 * 1024 * 1024
MAX_SOURCE_ARCHIVES = 8
MAX_HELPERS = 32
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
STACK_ID = re.compile(r"[a-z][a-z0-9-]{0,62}")


class NativeResearchInstallError(RuntimeError):
    """Stable fail-closed installation error."""


PACKAGE_SOURCES: Mapping[str, tuple[str, ...]] = {
    "native_claude_adapter.py": ("research/native_claude_adapter.py",),
    "native_claude_login_channel.py": ("research/native_claude_login_channel.py",),
    "native_claude_login_replay.py": ("research/native_claude_login_replay.py",),
    "native_claude_session_controller.py": ("research/native_claude_session_controller.py",),
    "native_codex_isolation_qualification.py": (
        "research/native_codex_isolation_qualification.py",),
    "native_codex_policy.py": ("research/native_codex_policy.py",),
    "native_codex_protocol_firewall.py": (
        "research/native_codex_protocol_firewall.py",),
    "native_codex_run_journal.py": ("research/native_codex_run_journal.py",),
    "native_codex_session_controller.py": (
        "research/native_codex_session_controller.py",),
    "native_harness_supervisor.py": ("research/native_harness_supervisor.py",),
    "native_lifecycle_fence.py": ("research/native_lifecycle_fence.py",),
    "native_projection_isolation.py": ("research/native_projection_isolation.py",),
    "native_provider_controller.py": ("research/native_provider_controller.py",),
    "session_policy_runtime.py": ("research/session_policy_runtime.py",),
    "shared_init.py": ("shared/__init__.py",),
    "harness_generation_store.py": ("shared/harness_generation_store.py",),
    "harness_runtime_binding.py": ("shared/harness_runtime_binding.py",),
    "model_stack_runtime_binding.py": ("shared/model_stack_runtime_binding.py",),
    "native_egress.py": ("shared/native_egress.py",),
    "native_guest_control.py": ("shared/native_guest_control.py",),
    "native_research_release.py": ("shared/native_research_release.py",),
    "native_stack_operations.py": ("shared/native_stack_operations.py",),
    "native_stack_runtime_binding.py": ("shared/native_stack_runtime_binding.py",),
    "native_vendor_stack.py": ("shared/native_vendor_stack.py",),
    "privileged_workflow.py": ("shared/privileged_workflow.py",),
    "runtime_authority.py": ("shared/runtime_authority.py",),
    "session_context_binding.py": ("shared/session_context_binding.py",),
}

ROOT_SOURCES: Mapping[str, tuple[str, ...]] = {
    "privileged_control.py": ("privileged_control.py",),
    "native_guest_control.py": ("native_guest_control.py",),
    "render_research_firewall.py": ("render_research_firewall.py",),
}

ENTRYPOINTS = (
    "native_provider_controller.py",
    "native_claude_login_channel.py",
    "native_claude_session_controller.py",
    "native_codex_session_controller.py",
    "native_harness_supervisor.py",
)


def canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, allow_nan=False, ensure_ascii=True,
                           separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeResearchInstallError(
            "native_research_install_value_invalid") from error


def run(command: Sequence[str], *, accepted: set[int] = {0},
        input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(command), check=False, input=input_bytes,
        stdin=None if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
             "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})
    if result.returncode not in accepted:
        raise NativeResearchInstallError("native_research_install_command_failed")
    return result


def ensure_directory(path: Path, mode: int, *, create: bool = True) -> None:
    created = False
    try:
        path.mkdir(mode=mode)
        created = True
    except FileExistsError:
        pass
    except FileNotFoundError:
        if not create:
            raise
        ensure_directory(path.parent, 0o755)
        path.mkdir(mode=mode)
        created = True
    if created:
        os.chown(path, 0, 0)
        os.chmod(path, mode)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode):
        raise NativeResearchInstallError(
            "native_research_install_directory_untrusted")


def bootstrap() -> None:
    for path, mode in (
        (INSTALL_ROOT, 0o755), (RESEARCH_ROOT, 0o755), (SHARED_ROOT, 0o755),
        (ETC_ROOT, 0o755), (ETC_ROOT / "native-codex-policy", 0o755),
        (STATE_ROOT, 0o700), (CONTROL_ROOT, 0o700),
        (LIFECYCLE_ROOT, 0o700), (INSTALL_STATE_ROOT, 0o700),
        (BACKUP_ROOT, 0o700), (SOURCE_ARCHIVE_ROOT, 0o700),
        (RECOVERY_ROOT, 0o755),
        (STATE_ROOT / "anthropic", 0o700),
    ):
        ensure_directory(path, mode)


def lock_file(path: Path) -> int:
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    os.fchown(descriptor, 0, 0)
    os.fchmod(descriptor, 0o600)
    info = os.fstat(descriptor)
    current = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or stat.S_ISLNK(current.st_mode)
            or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
        os.close(descriptor)
        raise NativeResearchInstallError("native_research_install_lock_untrusted")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def read_regular(path: Path, *, maximum: int = MAX_SOURCE_BYTES,
                 uid: int = 0, mode: int | None = None) -> bytes:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_nlink != 1 or opened.st_uid != uid
            or opened.st_gid != 0 or opened.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(opened.st_mode) != mode)
            or len(raw) != opened.st_size or len(raw) > maximum
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)):
        raise NativeResearchInstallError(
            "native_research_install_file_untrusted")
    return bytes(raw)


def atomic_write(path: Path, raw: bytes, *, mode: int) -> None:
    before_parent = path.parent.lstat()
    parent = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = "." + path.name + "." + str(uuid.uuid4()) + ".tmp"
    try:
        opened_parent = os.fstat(parent)
        if (not stat.S_ISDIR(opened_parent.st_mode)
                or stat.S_ISLNK(before_parent.st_mode)
                or opened_parent.st_uid != 0 or opened_parent.st_gid != 0
                or opened_parent.st_mode & 0o022
                or (opened_parent.st_dev, opened_parent.st_ino)
                   != (before_parent.st_dev, before_parent.st_ino)):
            raise NativeResearchInstallError(
                "native_research_install_destination_parent_untrusted")
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, mode)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise NativeResearchInstallError(
                        "native_research_install_write_failed")
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)
    if read_regular(path, maximum=max(len(raw), 1), mode=mode) != raw:
        raise NativeResearchInstallError(
            "native_research_install_readback_failed")


def source_names() -> set[str]:
    return {
        "install-native-research-runtime.sh", "native_research_installer.py",
        "native_install_transaction.py", "native_runtime_entry.py",
        "native_codex_launcher.c", "native-codex-config.toml",
        "native-claude-session-settings.json", "native-harness-supervisor.service",
        "secure-sandbox-native.conf", *PACKAGE_SOURCES, *ROOT_SOURCES,
    }


def snapshot_sources() -> tuple[Path, list[dict[str, Any]]]:
    archives = [item for item in SOURCE_ARCHIVE_ROOT.iterdir()
                if item.is_dir() and UUID4.fullmatch(item.name)]
    if len(archives) >= MAX_SOURCE_ARCHIVES:
        raise NativeResearchInstallError(
            "native_research_install_source_retention_limit")
    snapshot = SOURCE_ARCHIVE_ROOT / str(uuid.uuid4())
    snapshot.mkdir(mode=0o700)
    manifest: list[dict[str, Any]] = []
    total = 0
    try:
        for name in sorted(source_names()):
            raw = read_regular(SOURCE_ROOT / name)
            total += len(raw)
            if total > MAX_SOURCE_TOTAL:
                raise NativeResearchInstallError(
                    "native_research_install_sources_oversized")
            target = snapshot / name
            atomic_write(target, raw, mode=0o600)
            manifest.append({"name": name, "size": len(raw),
                             "sha256": hashlib.sha256(raw).hexdigest()})
        os.chmod(snapshot, 0o700)
        return snapshot, manifest
    except Exception:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise


def validate_source_syntax(snapshot: Path) -> None:
    for name in sorted(source_names()):
        if name.endswith(".py"):
            raw = read_regular(snapshot / name, mode=0o600)
            try:
                compile(raw, name, "exec", dont_inherit=True)
            except (SyntaxError, ValueError) as error:
                raise NativeResearchInstallError(
                    "native_research_install_source_syntax_invalid") from error
    try:
        json.loads(read_regular(
            snapshot / "native-claude-session-settings.json", mode=0o600))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeResearchInstallError(
            "native_research_install_source_json_invalid") from error


def remove_snapshot(path: Path) -> None:
    if path.parent != SOURCE_ARCHIVE_ROOT or UUID4.fullmatch(path.name) is None:
        raise NativeResearchInstallError(
            "native_research_install_source_archive_invalid")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise NativeResearchInstallError(
            "native_research_install_source_archive_untrusted")
    for child in path.iterdir():
        if child.name not in source_names():
            raise NativeResearchInstallError(
                "native_research_install_source_archive_untrusted")
        read_regular(child, mode=0o600)
        child.unlink()
    path.rmdir()


def install_recovery_helper(snapshot: Path) -> Path:
    raw = read_regular(snapshot / "native_install_transaction.py", mode=0o600)
    digest = hashlib.sha256(raw).hexdigest()
    helpers = [item.name for item in RECOVERY_ROOT.iterdir()
               if item.is_dir() and SHA256.fullmatch(item.name)]
    if digest not in helpers and len(helpers) >= MAX_HELPERS:
        raise NativeResearchInstallError(
            "native_research_install_helper_retention_limit")
    directory = RECOVERY_ROOT / digest
    try:
        directory.mkdir(mode=0o755)
    except FileExistsError:
        pass
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o755):
        raise NativeResearchInstallError(
            "native_research_install_helper_directory_untrusted")
    helper = directory / "native_install_transaction.py"
    try:
        observed = read_regular(helper, mode=0o555)
    except FileNotFoundError:
        atomic_write(helper, raw, mode=0o555)
    else:
        if observed != raw:
            raise NativeResearchInstallError(
                "native_research_install_helper_collision")
    return helper


def helper_command(helper: Path, *arguments: str) -> dict[str, Any]:
    result = run(["/usr/bin/python3", str(helper), *arguments])
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeResearchInstallError(
            "native_research_install_helper_result_invalid") from error
    if not isinstance(value, dict) or result.stdout != canonical(value):
        raise NativeResearchInstallError(
            "native_research_install_helper_result_invalid")
    return value


def validate_metadata(value: object) -> dict[str, Any]:
    fields = {
        "compatibility", "source_snapshot", "source_manifest",
        "source_manifest_sha256", "service", "identities", "directories",
        "production_projection",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    if (value["compatibility"] != "native-research-runtime-v1"
            or value["production_projection"]
               != "closed-pending-live-qualification-and-driver"):
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    snapshot = Path(value["source_snapshot"])
    if (snapshot.parent != SOURCE_ARCHIVE_ROOT
            or UUID4.fullmatch(snapshot.name) is None):
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    sources = value["source_manifest"]
    if (not isinstance(sources, list)
            or len(sources) != len(source_names())):
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    observed_names: list[str] = []
    for item in sources:
        if (not isinstance(item, dict)
                or set(item) != {"name", "size", "sha256"}
                or item["name"] not in source_names()
                or not isinstance(item["size"], int)
                or isinstance(item["size"], bool)
                or not 1 <= item["size"] <= MAX_SOURCE_BYTES
                or not isinstance(item["sha256"], str)
                or SHA256.fullmatch(item["sha256"]) is None):
            raise NativeResearchInstallError(
                "native_research_install_pending_metadata_invalid")
        observed_names.append(item["name"])
    if (observed_names != sorted(source_names())
            or value["source_manifest_sha256"]
               != hashlib.sha256(canonical(sources)).hexdigest()):
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    service = value["service"]
    if (not isinstance(service, dict)
            or set(service) != {
                "LoadState", "ActiveState", "SubState", "MainPID", "enabled"
            }
            or service["LoadState"] not in {"loaded", "not-found"}
            or service["ActiveState"] != "inactive"
            or service["SubState"] != "dead" or service["MainPID"] != "0"
            or service["enabled"] not in {
                "enabled", "disabled", "static", "not-found"}):
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    if ((service["LoadState"] == "not-found")
            != (service["enabled"] == "not-found")):
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    identities = value["identities"]
    if not isinstance(identities, dict) or set(identities) != {
        "native-harness", "native-claude", "native-codex"
    }:
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    for identity in identities.values():
        if identity is None:
            continue
        if (not isinstance(identity, dict)
                or set(identity) != {
                    "uid", "gid", "group_gid", "home", "shell", "members",
                    "groups"}
                or not all(isinstance(identity[name], int)
                           and not isinstance(identity[name], bool)
                           and identity[name] > 0
                           for name in ("uid", "gid", "group_gid"))
                or identity["gid"] != identity["group_gid"]
                or identity["home"] != "/var/empty"
                or identity["shell"] != "/usr/sbin/nologin"
                or identity["members"] != []
                or identity["groups"] != [identity["gid"]]):
            raise NativeResearchInstallError(
                "native_research_install_pending_metadata_invalid")
    directories = value["directories"]
    if not isinstance(directories, list) or len(directories) > 64:
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    names: list[str] = []
    fixed_prefixes = (
        str(CONTROL_ROOT) + "/", str(STATE_ROOT / "anthropic") + "/",
        "/run/secure-sandbox/native-codex",
        "/run/secure-sandbox/native-claude",
    )
    for item in directories:
        if (not isinstance(item, dict) or item.get("state") not in {
                "absent", "directory"} or not isinstance(item.get("path"), str)
                or not Path(item["path"]).is_absolute()
                or ".." in Path(item["path"]).parts
                or not item["path"].startswith(fixed_prefixes)):
            raise NativeResearchInstallError(
                "native_research_install_pending_metadata_invalid")
        if item["state"] == "absent":
            if set(item) != {"path", "state"}:
                raise NativeResearchInstallError(
                    "native_research_install_pending_metadata_invalid")
        elif (set(item) != {"path", "state", "uid", "gid", "mode"}
              or not all(isinstance(item[name], int)
                         and not isinstance(item[name], bool)
                         for name in ("uid", "gid", "mode"))
              or item["uid"] < 0 or item["gid"] < 0
              or not 0 <= item["mode"] <= 0o7777):
            raise NativeResearchInstallError(
                "native_research_install_pending_metadata_invalid")
        names.append(item["path"])
    if len(names) != len(set(names)):
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    return value


def helper_from_pending() -> tuple[Path, dict[str, Any]]:
    raw = read_regular(PENDING, maximum=256 * 1024, mode=0o600)
    try:
        record = json.loads(raw)
        helper_value = record["recovery_helper"]
        helper = Path(helper_value["path"])
        expected = helper_value["sha256"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise NativeResearchInstallError(
            "native_research_install_pending_invalid") from error
    pattern = re.compile(
        re.escape(str(RECOVERY_ROOT))
        + r"/([0-9a-f]{64})/native_install_transaction\.py")
    match = pattern.fullmatch(str(helper))
    if (match is None or match.group(1) != expected
            or hashlib.sha256(read_regular(helper, mode=0o555)).hexdigest()
               != expected):
        raise NativeResearchInstallError(
            "native_research_install_recovery_helper_untrusted")
    inspection = helper_command(helper, "inspect", "--pending", str(PENDING))
    return helper, inspection


def service_state() -> dict[str, str]:
    result = run([
        "/usr/bin/systemctl", "show", SERVICE, "--property=LoadState",
        "--property=ActiveState", "--property=SubState", "--property=MainPID",
    ], accepted={0, 1, 4})
    values: dict[str, str] = {}
    for line in result.stdout.decode("ascii", "strict").splitlines():
        name, separator, value = line.partition("=")
        if separator:
            values[name] = value
    enabled_result = run(
        ["/usr/bin/systemctl", "is-enabled", SERVICE],
        accepted={0, 1, 3, 4})
    enabled = enabled_result.stdout.decode("ascii", "strict").strip() or "not-found"
    expected = {"LoadState", "ActiveState", "SubState", "MainPID"}
    if set(values) != expected or enabled not in {
        "enabled", "disabled", "static", "not-found"
    }:
        raise NativeResearchInstallError(
            "native_research_install_service_state_invalid")
    if values["LoadState"] == "not-found":
        if enabled != "not-found":
            raise NativeResearchInstallError(
                "native_research_install_service_state_invalid")
    elif (values["LoadState"] != "loaded" or values["ActiveState"] != "inactive"
          or values["SubState"] != "dead" or values["MainPID"] != "0"):
        raise NativeResearchInstallError(
            "native_research_install_service_not_quiescent")
    return {**values, "enabled": enabled}


def identity_state(name: str) -> dict[str, Any] | None:
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        try:
            grp.getgrnam(name)
        except KeyError:
            return None
        raise NativeResearchInstallError(
            "native_research_install_identity_partial")
    try:
        group = grp.getgrnam(name)
    except KeyError as error:
        raise NativeResearchInstallError(
            "native_research_install_identity_partial") from error
    supplementary = os.getgrouplist(name, account.pw_gid)
    value = {
        "uid": account.pw_uid, "gid": account.pw_gid,
        "group_gid": group.gr_gid, "home": account.pw_dir,
        "shell": account.pw_shell, "members": sorted(group.gr_mem),
        "groups": sorted(supplementary),
    }
    if (value["uid"] == 0 or value["gid"] == 0
            or value["gid"] != value["group_gid"]
            or value["home"] != "/var/empty"
            or value["shell"] != "/usr/sbin/nologin"
            or value["members"] or value["groups"] != [value["gid"]]):
        raise NativeResearchInstallError(
            "native_research_install_identity_untrusted")
    return value


def create_identity(name: str) -> dict[str, Any]:
    if identity_state(name) is None:
        run(["/usr/sbin/groupadd", "--system", name])
        run(["/usr/sbin/useradd", "--system", "--gid", name,
             "--home-dir", "/var/empty", "--shell", "/usr/sbin/nologin", name])
    result = identity_state(name)
    if result is None:
        raise NativeResearchInstallError(
            "native_research_install_identity_missing")
    return result


def remove_new_identity(name: str) -> None:
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        account = None
    try:
        group = grp.getgrnam(name)
    except KeyError:
        group = None
    if account is not None:
        if (account.pw_uid == 0 or account.pw_gid == 0
                or account.pw_dir != "/var/empty"
                or account.pw_shell != "/usr/sbin/nologin"):
            raise NativeResearchInstallError(
                "native_research_install_recovery_identity_untrusted")
        result = run(
            ["/usr/bin/pgrep", "-u", str(account.pw_uid)], accepted={0, 1})
        if result.returncode == 0:
            raise NativeResearchInstallError(
                "native_research_install_recovery_identity_busy")
        run(["/usr/sbin/userdel", name])
    if group is not None:
        try:
            current = grp.getgrnam(name)
        except KeyError:
            current = None
        if current is not None:
            if current.gr_gid == 0 or current.gr_mem:
                raise NativeResearchInstallError(
                    "native_research_install_recovery_identity_untrusted")
            run(["/usr/sbin/groupdel", name])
    try:
        pwd.getpwnam(name)
    except KeyError:
        pass
    else:
        raise NativeResearchInstallError(
            "native_research_install_recovery_identity_mismatch")
    try:
        grp.getgrnam(name)
    except KeyError:
        pass
    else:
        raise NativeResearchInstallError(
            "native_research_install_recovery_identity_mismatch")


def require_no_processes(identities: Mapping[str, Any]) -> None:
    for name, value in identities.items():
        if value is None:
            continue
        result = run(["/usr/bin/pgrep", "-u", str(value["uid"])], accepted={0, 1})
        if result.returncode == 0:
            raise NativeResearchInstallError(
                "native_research_install_identity_busy")
    scopes = run([
        "/usr/bin/systemctl", "list-units", "--all", "--no-legend",
        "--plain", "secure-sandbox-native-run-*.scope"], accepted={0})
    if scopes.stdout.strip():
        raise NativeResearchInstallError(
            "native_research_install_scope_busy")


def require_recovery_quiescence(metadata: Mapping[str, Any]) -> None:
    """Fence rollback until no process can retain a replaced artifact."""
    observed = run([
        "/usr/bin/systemctl", "show", SERVICE, "--property=ActiveState",
        "--property=SubState", "--property=MainPID",
    ], accepted={0, 1, 4})
    service_values: dict[str, str] = {}
    for line in observed.stdout.decode("ascii", "strict").splitlines():
        name, separator, value = line.partition("=")
        if separator:
            service_values[name] = value
    if (set(service_values) != {"ActiveState", "SubState", "MainPID"}
            or service_values["ActiveState"] != "inactive"
            or service_values["SubState"] not in {"dead", "failed"}
            or service_values["MainPID"] != "0"):
        raise NativeResearchInstallError(
            "native_research_install_recovery_service_busy")
    current: dict[str, Any] = {}
    identities = metadata.get("identities")
    if not isinstance(identities, dict) or set(identities) != {
        "native-harness", "native-claude", "native-codex"
    }:
        raise NativeResearchInstallError(
            "native_research_install_pending_metadata_invalid")
    for name in identities:
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            continue
        current[name] = {"uid": account.pw_uid}
    require_no_processes(current)
    grant = Path("/var/lib/secure-sandbox/native-egress/active.json")
    if grant.exists() or grant.is_symlink():
        raise NativeResearchInstallError(
            "native_research_install_recovery_active_grant")


def catalog_stack_ids() -> list[str]:
    raw = read_regular(CATALOG, maximum=1024 * 1024, mode=0o644)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeResearchInstallError(
            "native_research_install_catalog_invalid") from error
    if raw != canonical(value) or not isinstance(value, dict):
        raise NativeResearchInstallError(
            "native_research_install_catalog_invalid")
    stacks = value.get("stacks")
    if (value.get("schema") != "secure-sandbox-native-vendor-stack-catalog-v1"
            or not isinstance(stacks, list)):
        raise NativeResearchInstallError(
            "native_research_install_catalog_invalid")
    result: list[str] = []
    for stack in stacks:
        if (not isinstance(stack, dict) or stack.get("vendor_id") != "anthropic"
                or not isinstance(stack.get("stack_id"), str)
                or STACK_ID.fullmatch(stack["stack_id"]) is None):
            if isinstance(stack, dict) and stack.get("vendor_id") != "anthropic":
                continue
            raise NativeResearchInstallError(
                "native_research_install_catalog_invalid")
        result.append(stack["stack_id"])
    if len(result) != len(set(result)):
        raise NativeResearchInstallError(
            "native_research_install_catalog_invalid")
    return sorted(result)


def directory_prestate(paths: Sequence[Path]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            result.append({"path": str(path), "state": "absent"})
            continue
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise NativeResearchInstallError(
                "native_research_install_runtime_directory_untrusted")
        result.append({"path": str(path), "state": "directory",
                       "uid": info.st_uid, "gid": info.st_gid,
                       "mode": stat.S_IMODE(info.st_mode)})
    return result


def create_runtime_directories(stack_ids: Sequence[str], identities: Mapping[str, Any]) -> None:
    root_directories = (
        CONTROL_ROOT / "credential-tombstones", CONTROL_ROOT / "login-proofs",
        CONTROL_ROOT / "login-handles", CONTROL_ROOT / "native-runs",
        CONTROL_ROOT / "native-claude-runs",
        CONTROL_ROOT / "qualification-receipts",
        CONTROL_ROOT / "qualification-journal",
    )
    for path in root_directories:
        created = False
        try:
            path.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
        if created:
            os.chown(path, 0, 0)
            os.chmod(path, 0o700)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeResearchInstallError(
                "native_research_install_runtime_directory_untrusted")
    claude = identities["native-claude"]
    for stack_id in stack_ids:
        parent = STATE_ROOT / "anthropic" / stack_id
        config = parent / "claude-config"
        for path in (parent, config):
            created = False
            try:
                path.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            if created:
                os.chown(path, claude["uid"], claude["gid"])
                os.chmod(path, 0o700)
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != claude["uid"] or info.st_gid != claude["gid"]
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise NativeResearchInstallError(
                    "native_research_install_runtime_directory_untrusted")


def restore_external(metadata: Mapping[str, Any]) -> None:
    run(["/usr/bin/systemctl", "daemon-reload"])
    service = metadata["service"]
    enabled = service["enabled"]
    if enabled == "enabled":
        run(["/usr/bin/systemctl", "enable", SERVICE])
    elif enabled == "disabled":
        run(["/usr/bin/systemctl", "disable", SERVICE], accepted={0, 1})
    if Path("/etc/nftables.conf").exists():
        run(["/usr/sbin/nft", "-c", "-f", "/etc/nftables.conf"])
        run(["/usr/sbin/nft", "-f", "/etc/nftables.conf"])
    for item in sorted(metadata["directories"],
                       key=lambda value: value["path"].count("/"), reverse=True):
        path = Path(item["path"])
        if item["state"] == "absent":
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise NativeResearchInstallError(
                    "native_research_install_recovery_directory_not_empty") from error
        else:
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != item["uid"] or info.st_gid != item["gid"]
                    or stat.S_IMODE(info.st_mode) != item["mode"]):
                raise NativeResearchInstallError(
                    "native_research_install_recovery_directory_mismatch")
    for name in reversed(("native-codex", "native-claude", "native-harness")):
        if metadata["identities"][name] is None:
            remove_new_identity(name)
        elif identity_state(name) != metadata["identities"][name]:
            raise NativeResearchInstallError(
                "native_research_install_recovery_identity_mismatch")
    if service_state() != service:
        raise NativeResearchInstallError(
            "native_research_install_recovery_service_mismatch")


def recover_pending() -> None:
    helper, inspection = helper_from_pending()
    decision = inspection.get("decision")
    metadata = validate_metadata(inspection.get("metadata"))
    require_recovery_quiescence(metadata)
    if decision == "commit":
        helper_command(helper, "commit", "--pending", str(PENDING))
    elif decision in {None, "recover"}:
        helper_command(helper, "recover", "--pending", str(PENDING))
        restore_external(metadata)
        helper_command(helper, "finalize-recovery", "--pending", str(PENDING))
    else:
        raise NativeResearchInstallError(
            "native_research_install_pending_decision_invalid")
    snapshot = Path(str(metadata.get("source_snapshot", "")))
    if snapshot.parent == SOURCE_ARCHIVE_ROOT and snapshot.exists():
        remove_snapshot(snapshot)


def compile_launcher(snapshot: Path) -> bytes:
    output = snapshot / "native-codex-launcher.bin"
    try:
        run([
            "/usr/bin/cc", "-std=c11", "-O2", "-D_FORTIFY_SOURCE=3",
            "-fstack-protector-strong", "-fPIE", "-pie", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-function",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            str(snapshot / "native_codex_launcher.c"), "-o", str(output),
        ])
        os.chown(output, 0, 0)
        os.chmod(output, 0o600)
        return read_regular(output, mode=0o600)
    finally:
        try:
            output.unlink()
        except FileNotFoundError:
            pass


def install_files(snapshot: Path, launcher: bytes) -> None:
    for source, destinations in PACKAGE_SOURCES.items():
        raw = read_regular(snapshot / source, mode=0o600)
        for destination in destinations:
            relative = Path(destination)
            target = INSTALL_ROOT / relative
            atomic_write(target, raw, mode=0o444)
    for source, destinations in ROOT_SOURCES.items():
        raw = read_regular(snapshot / source, mode=0o600)
        for destination in destinations:
            atomic_write(INSTALL_ROOT / destination, raw, mode=0o755)
    entry = read_regular(snapshot / "native_runtime_entry.py", mode=0o600)
    for name in ENTRYPOINTS:
        atomic_write(INSTALL_ROOT / name, entry, mode=0o755)
    qualification = read_regular(
        snapshot / "native_codex_isolation_qualification.py", mode=0o600)
    protocol = read_regular(
        snapshot / "native_codex_protocol_firewall.py", mode=0o600)
    atomic_write(INSTALL_ROOT / "native_codex_isolation_qualification.py",
                 qualification, mode=0o555)
    atomic_write(INSTALL_ROOT / "native-codex-isolation-probe",
                 qualification, mode=0o555)
    atomic_write(INSTALL_ROOT / "native_codex_protocol_firewall.py",
                 protocol, mode=0o555)
    atomic_write(INSTALL_ROOT / "native-codex-launcher", launcher, mode=0o555)
    atomic_write(ETC_ROOT / "native-codex-policy/config.toml",
                 read_regular(snapshot / "native-codex-config.toml", mode=0o600),
                 mode=0o444)
    atomic_write(Path("/etc/claude-code/native-claude-session-settings.json"),
                 read_regular(snapshot / "native-claude-session-settings.json", mode=0o600),
                 mode=0o444)
    atomic_write(Path("/etc/systemd/system/native-harness-supervisor.service"),
                 read_regular(snapshot / "native-harness-supervisor.service", mode=0o600),
                 mode=0o644)
    atomic_write(Path("/etc/tmpfiles.d/secure-sandbox-native.conf"),
                 read_regular(snapshot / "secure-sandbox-native.conf", mode=0o600),
                 mode=0o644)
    atomic_write(ETC_ROOT / "native-egress-installed",
                 b"secure-sandbox-native-egress-installed-v1\n", mode=0o600)
    atomic_write(ETC_ROOT / "native-egress-role", b"research\n", mode=0o600)


def validate_installed_catalog(expected_anthropic_ids: Sequence[str]) -> None:
    sys.path.insert(0, str(INSTALL_ROOT))
    importlib.invalidate_caches()
    module = importlib.import_module("shared.native_vendor_stack")
    catalog = module.load_catalog(CATALOG, private=False)
    observed = sorted(
        stack["stack_id"] for stack in catalog["stacks"]
        if stack["vendor_id"] == "anthropic")
    if observed != list(expected_anthropic_ids):
        raise NativeResearchInstallError(
            "native_research_install_catalog_readback_mismatch")


def install_binding_key() -> None:
    path = STATE_ROOT / "anthropic/account-binding.key"
    try:
        raw = read_regular(path, maximum=32, mode=0o400)
    except FileNotFoundError:
        atomic_write(path, os.urandom(32), mode=0o400)
    else:
        if len(raw) != 32:
            raise NativeResearchInstallError(
                "native_research_install_binding_key_invalid")


def install_firewall() -> None:
    temporary = Path("/run/secure-sandbox-native-firewall.new")
    try:
        run([str(INSTALL_ROOT / "render_research_firewall.py"),
             "--output", str(temporary)])
        raw = read_regular(temporary, maximum=MAX_SOURCE_BYTES, mode=0o600)
        run(["/usr/sbin/nft", "-c", "-f", str(temporary)])
        atomic_write(Path("/etc/nftables.conf"), raw, mode=0o644)
        run(["/usr/sbin/nft", "-f", "/etc/nftables.conf"])
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def publish_release_manifest() -> dict[str, Any]:
    sys.path.insert(0, str(INSTALL_ROOT))
    importlib.invalidate_caches()
    module = importlib.import_module("shared.native_research_release")
    value = module.observe()
    atomic_write(MANIFEST, module.canonical(value), mode=0o444)
    if module.verify_installed() != value:
        raise NativeResearchInstallError(
            "native_research_install_release_readback_failed")
    return value


def destination_paths() -> list[Path]:
    result: set[Path] = {
        INSTALL_ROOT / "privileged_control.py",
        INSTALL_ROOT / "native_guest_control.py",
        INSTALL_ROOT / "render_research_firewall.py",
        INSTALL_ROOT / "native_codex_isolation_qualification.py",
        INSTALL_ROOT / "native_codex_protocol_firewall.py",
        INSTALL_ROOT / "native-codex-isolation-probe",
        INSTALL_ROOT / "native-codex-launcher",
        ETC_ROOT / "native-codex-policy/config.toml",
        ETC_ROOT / "native-egress-installed", ETC_ROOT / "native-egress-role",
        Path("/etc/claude-code/native-claude-session-settings.json"),
        Path("/etc/systemd/system/native-harness-supervisor.service"),
        Path("/etc/tmpfiles.d/secure-sandbox-native.conf"),
        Path("/etc/nftables.conf"), MANIFEST,
        STATE_ROOT / "anthropic/account-binding.key",
    }
    result.update(INSTALL_ROOT / name for name in ENTRYPOINTS)
    for destinations in PACKAGE_SOURCES.values():
        result.update(INSTALL_ROOT / name for name in destinations)
    if len(result) > 64:
        raise NativeResearchInstallError(
            "native_research_install_destination_limit")
    return sorted(result, key=str)


def main() -> int:
    if os.geteuid() != 0 or os.getegid() != 0:
        return 1
    bootstrap()
    install_lock = lock_file(LOCK_PATH)
    lifecycle_lock = lock_file(LIFECYCLE_LOCK)
    snapshot: Path | None = None
    helper: Path | None = None
    began = False
    try:
        if PENDING.exists() or PENDING.is_symlink():
            recover_pending()
        promotion_fence = LIFECYCLE_ROOT / "promotion-fence.json"
        if promotion_fence.exists() or promotion_fence.is_symlink():
            raise NativeResearchInstallError(
                "native_research_install_promotion_fence_active")
        service = service_state()
        identities = {name: identity_state(name) for name in (
            "native-harness", "native-claude", "native-codex")}
        require_no_processes(identities)
        grant = Path("/var/lib/secure-sandbox/native-egress/active.json")
        if grant.exists() or grant.is_symlink():
            raise NativeResearchInstallError(
                "native_research_install_active_grant_forbidden")
        stack_ids = catalog_stack_ids()
        runtime_paths = [
            CONTROL_ROOT / "credential-tombstones", CONTROL_ROOT / "login-proofs",
            CONTROL_ROOT / "login-handles", CONTROL_ROOT / "native-runs",
            CONTROL_ROOT / "native-claude-runs",
            CONTROL_ROOT / "qualification-receipts",
            CONTROL_ROOT / "qualification-journal",
            Path("/run/secure-sandbox/native-codex"),
            Path("/run/secure-sandbox/native-codex/preparations"),
            Path("/run/secure-sandbox/native-codex/permits"),
            Path("/run/secure-sandbox/native-codex/session-state"),
            Path("/run/secure-sandbox/native-claude"),
            Path("/run/secure-sandbox/native-claude/preparations"),
            Path("/run/secure-sandbox/native-claude/session-state"),
        ]
        for stack_id in stack_ids:
            runtime_paths.extend((STATE_ROOT / "anthropic" / stack_id,
                                  STATE_ROOT / "anthropic" / stack_id / "claude-config"))
        directories = directory_prestate(runtime_paths)
        snapshot, source_manifest = snapshot_sources()
        validate_source_syntax(snapshot)
        launcher = compile_launcher(snapshot)
        helper = install_recovery_helper(snapshot)
        metadata = {
            "compatibility": "native-research-runtime-v1",
            "source_snapshot": str(snapshot),
            "source_manifest": source_manifest,
            "source_manifest_sha256": hashlib.sha256(canonical(source_manifest)).hexdigest(),
            "service": service, "identities": identities,
            "directories": directories,
            "production_projection": "closed-pending-live-qualification-and-driver",
        }
        backup = BACKUP_ROOT / (
            "native-research-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            + "-" + str(uuid.uuid4()))
        helper_command(
            helper, "begin", "--pending", str(PENDING), "--backup", str(backup),
            "--recovery-helper", str(helper), "--metadata-json",
            canonical(metadata).decode("ascii").strip(),
            *(str(path) for path in destination_paths()))
        began = True
        created = {name: create_identity(name) for name in identities}
        install_files(snapshot, launcher)
        validate_installed_catalog(stack_ids)
        create_runtime_directories(stack_ids, created)
        install_binding_key()
        run(["/usr/bin/systemd-analyze", "verify",
             "/etc/systemd/system/native-harness-supervisor.service"])
        run(["/usr/bin/systemctl", "daemon-reload"])
        run(["/usr/bin/systemctl", "disable", SERVICE], accepted={0, 1})
        run(["/usr/bin/systemd-tmpfiles", "--create",
             "/etc/tmpfiles.d/secure-sandbox-native.conf"])
        install_firewall()
        release = publish_release_manifest()
        post_service = service_state()
        if (post_service["LoadState"] != "loaded"
                or post_service["ActiveState"] != "inactive"
                or post_service["SubState"] != "dead"
                or post_service["MainPID"] != "0"
                or post_service["enabled"] != "disabled"):
            raise NativeResearchInstallError(
                "native_research_install_service_readback_failed")
        helper_command(helper, "commit", "--pending", str(PENDING))
        began = False
        remove_snapshot(snapshot)
        snapshot = None
        sys.stdout.buffer.write(canonical({
            "schema": "secure-sandbox-native-research-install-result-v1",
            "status": "installed-default-closed",
            "research_release_id": release["release_id"],
            "projection": "closed-pending-live-qualification-and-driver",
        }))
        return 0
    except Exception:
        if began and helper is not None:
            try:
                helper_command(helper, "recover", "--pending", str(PENDING))
                _helper, inspection = helper_from_pending()
                restore_external(inspection["metadata"])
                helper_command(helper, "finalize-recovery", "--pending", str(PENDING))
                began = False
            except Exception:
                # The durable pending record deliberately remains the fence.
                pass
        if (not began and snapshot is not None
                and not PENDING.exists() and not PENDING.is_symlink()
                and snapshot.exists()):
            try:
                remove_snapshot(snapshot)
                snapshot = None
            except Exception:
                pass
        return 75 if began else 1
    finally:
        fcntl.flock(lifecycle_lock, fcntl.LOCK_UN)
        os.close(lifecycle_lock)
        fcntl.flock(install_lock, fcntl.LOCK_UN)
        os.close(install_lock)


if __name__ == "__main__":
    raise SystemExit(main())
