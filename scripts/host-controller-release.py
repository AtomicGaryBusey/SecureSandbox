#!/usr/bin/env python3
"""Publish, verify, and roll back immutable host-controller releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "secure-sandbox-host-controller-release-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PAYLOAD_SOURCES = {
    "controller": Path("scripts/claude-run-controller.sh"),
    "installer_verifier": Path("scripts/verify_ubuntu_installer.py"),
    "op_agents": Path("scripts/op-agents-controller.sh"),
    "pki_anchor": Path("scripts/pki-host-anchor.py"),
    "ssh_config": Path("config/ssh_config"),
}
PAYLOAD_NAMES = {*PAYLOAD_SOURCES, "gpgv"}
LAUNCHER_SOURCE = Path("scripts/secure-sandbox-claude-launcher.py")
DEFAULT_OP_BINARY = Path("/opt/homebrew/bin/op")
DEFAULT_GPGV_BINARY = Path("/opt/homebrew/bin/gpgv")
MAX_RELEASES = 32
MAX_RELEASE_DIRECTORY_ENTRIES = 64
MAX_ACTIVE_MARKERS = 64
EXPECTED_MODES = {
    "controller": 0o755,
    "gpgv": 0o555,
    "installer_verifier": 0o755,
    "op_agents": 0o755,
    "pki_anchor": 0o755,
    "ssh_config": 0o444,
    "manifest.json": 0o444,
}
LEGACY_PAYLOAD_NAMES = {"controller", "op_agents", "ssh_config"}
PRE_INSTALLER_PAYLOAD_NAMES = {"controller", "op_agents", "pki_anchor", "ssh_config"}


class ReleaseFailure(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def release_identity(payloads: dict[str, str]) -> str:
    identity = bytearray()
    for name in sorted(payloads):
        identity.extend(f"{name}\0{payloads[name]}\n".encode("ascii"))
    return sha256_bytes(bytes(identity))


def read_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except (FileNotFoundError, OSError) as error:
        raise ReleaseFailure(f"source_not_regular:{path}") from error
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ReleaseFailure(f"source_not_regular:{path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ReleaseFailure(f"source_changed_during_read:{path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def source_payload(
    repo: Path,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> tuple[dict[str, bytes], dict[str, str], str]:
    values = {name: read_regular(repo / relative) for name, relative in PAYLOAD_SOURCES.items()}
    resolved_op = op_binary.resolve(strict=True)
    op_bytes = read_regular(resolved_op)
    op_path_shell = shlex.quote(str(resolved_op)).encode("utf-8")
    op_hash_shell = shlex.quote(sha256_bytes(op_bytes)).encode("ascii")
    bridge = values["op_agents"]
    if bridge.count(b"__OP_PATH_SHELL__") != 1 or bridge.count(b"__OP_SHA256_SHELL__") != 1:
        raise ReleaseFailure("op_bridge_template_invalid")
    values["op_agents"] = bridge.replace(b"__OP_PATH_SHELL__", op_path_shell).replace(
        b"__OP_SHA256_SHELL__", op_hash_shell
    )
    resolved_gpgv = gpgv_binary.resolve(strict=True)
    gpgv_bytes = read_regular(resolved_gpgv)
    values["gpgv"] = gpgv_bytes
    verifier = values["installer_verifier"]
    if verifier.count(b"__GPGV_SHA256__") != 1:
        raise ReleaseFailure("installer_verifier_template_invalid")
    values["installer_verifier"] = verifier.replace(
        b"__GPGV_SHA256__", sha256_bytes(gpgv_bytes).encode("ascii")
    )
    try:
        compile(values["pki_anchor"], str(repo / PAYLOAD_SOURCES["pki_anchor"]), "exec")
        compile(values["installer_verifier"], str(repo / PAYLOAD_SOURCES["installer_verifier"]), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("python_payload_syntax_invalid") from error
    hashes = {name: sha256_bytes(value) for name, value in values.items()}
    return values, hashes, release_identity(hashes)


def invoking_home() -> Path:
    name = os.environ.get("SUDO_USER")
    if name:
        return Path(pwd.getpwnam(name).pw_dir)
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def active_markers(state_root: Path) -> list[str]:
    if state_root.exists() and (state_root.is_symlink() or not state_root.is_dir()):
        raise ReleaseFailure("controller_state_directory_invalid")
    active = state_root / "active"
    if not active.exists():
        return []
    if active.is_symlink() or not active.is_dir():
        raise ReleaseFailure("active_marker_directory_invalid")
    markers = list(active.iterdir())
    if len(markers) > MAX_ACTIVE_MARKERS:
        raise ReleaseFailure("active_marker_limit_exceeded")
    live: list[str] = []
    for marker in markers:
        if marker.is_symlink() or not marker.is_file():
            raise ReleaseFailure("active_marker_invalid")
        try:
            value = json.loads(marker.read_text(encoding="ascii"))
            pid = value["pid"]
            release_id = value["release_id"]
            if not isinstance(pid, int) or pid <= 1 or not isinstance(release_id, str) or not SHA256.fullmatch(release_id):
                raise ValueError
            os.kill(pid, 0)
            live.append(marker.name)
        except ProcessLookupError:
            marker.unlink()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            raise ReleaseFailure(f"active_marker_unreadable:{marker.name}") from error
    return live


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_symlink(target: str, link: Path) -> None:
    temporary = link.parent / f".{link.name}.new-{os.getpid()}"
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    temporary.symlink_to(target)
    os.replace(temporary, link)
    fsync_directory(link.parent)


def ensure_root(default_layout: bool) -> None:
    if default_layout and os.geteuid() != 0:
        raise ReleaseFailure("root_required")


def prepare_release_root(install_root: Path, expected_uid: int) -> Path:
    releases = install_root / "releases"
    if install_root.exists():
        info = install_root.lstat()
        if install_root.is_symlink() or not install_root.is_dir() or info.st_uid != expected_uid:
            raise ReleaseFailure("install_root_untrusted")
    if releases.exists():
        info = releases.lstat()
        if releases.is_symlink() or not releases.is_dir() or info.st_uid != expected_uid:
            raise ReleaseFailure("release_root_untrusted")
    releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(install_root, 0o755)
    os.chmod(releases, 0o755)
    entries = list(releases.iterdir())
    if len(entries) > MAX_RELEASE_DIRECTORY_ENTRIES:
        raise ReleaseFailure("release_root_entry_limit_exceeded")
    release_count = 0
    for entry in entries:
        if entry.name.startswith(".staging-"):
            info = entry.lstat()
            if entry.is_symlink() or not entry.is_dir() or info.st_uid != expected_uid:
                raise ReleaseFailure("release_root_untrusted")
            os.chmod(entry, 0o755)
            shutil.rmtree(entry)
            continue
        if not SHA256.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            raise ReleaseFailure("release_root_untrusted")
        release_count += 1
    if release_count > MAX_RELEASES:
        raise ReleaseFailure("release_count_limit_exceeded")
    return releases


def exact_mode(path: Path, mode: int) -> None:
    os.chmod(path, mode, follow_symlinks=False)


def validate_shell_payload(value: bytes, label: str) -> None:
    with tempfile.NamedTemporaryFile(prefix=f"secure-sandbox-{label}-", suffix=".sh") as syntax_copy:
        syntax_copy.write(value)
        syntax_copy.flush()
        syntax_result = subprocess.run(
            ["/bin/bash", "-n", syntax_copy.name], check=False, capture_output=True, text=True
        )
        if syntax_result.returncode != 0:
            raise ReleaseFailure(f"{label}_syntax_invalid")


def install(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    values, hashes, release_id = source_payload(repo, op_binary, gpgv_binary)
    launcher_bytes = read_regular(repo / LAUNCHER_SOURCE)
    try:
        compile(launcher_bytes, str(repo / LAUNCHER_SOURCE), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("stable_launcher_syntax_invalid") from error
    validate_shell_payload(values["controller"], "controller")
    validate_shell_payload(values["op_agents"], "op_bridge")
    releases = prepare_release_root(install_root, expected_uid)
    final = releases / release_id
    if not final.exists():
        if sum(1 for entry in releases.iterdir() if SHA256.fullmatch(entry.name)) >= MAX_RELEASES:
            raise ReleaseFailure("release_count_limit_exceeded")
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
        try:
            for name, value in values.items():
                path = staging / name
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                mode = EXPECTED_MODES[name]
                descriptor = os.open(path, flags, mode)
                try:
                    os.write(descriptor, value)
                    os.fsync(descriptor)
                    os.fchmod(descriptor, mode)
                finally:
                    os.close(descriptor)
            manifest = {"schema": SCHEMA, "release_id": release_id, "payloads": hashes}
            manifest_path = staging / "manifest.json"
            descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
            try:
                os.write(descriptor, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
                os.fsync(descriptor)
                os.fchmod(descriptor, EXPECTED_MODES["manifest.json"])
            finally:
                os.close(descriptor)
            os.chmod(staging, 0o555)
            fsync_directory(staging)
            os.rename(staging, final)
            fsync_directory(releases)
        except BaseException:
            if staging.exists():
                os.chmod(staging, 0o755)
                shutil.rmtree(staging)
            raise
    candidate = install_root / f".candidate-{os.getpid()}"
    candidate.symlink_to(f"releases/{release_id}")
    try:
        verified_release(install_root, candidate, expected_uid)
    finally:
        candidate.unlink()
    current = install_root / "current"
    old_current: str | None = None
    if current.is_symlink():
        old_path, _ = verified_release(install_root, current, expected_uid, allow_legacy=True)
        old_current = f"releases/{old_path.name}"
    elif current.exists():
        raise ReleaseFailure("release_link_invalid:current")
    launcher_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if launcher_path.exists():
        installed_launcher = read_regular(launcher_path)
        launcher_info = launcher_path.stat()
        if launcher_info.st_uid != expected_uid or launcher_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReleaseFailure("launcher_permissions_invalid")
        if installed_launcher != launcher_bytes:
            raise ReleaseFailure("stable_launcher_change_requires_migration")
    else:
        launcher_tmp = launcher_path.parent / f".{launcher_path.name}.new-{os.getpid()}"
        descriptor = os.open(launcher_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        try:
            os.write(descriptor, launcher_bytes)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o755)
        finally:
            os.close(descriptor)
        os.replace(launcher_tmp, launcher_path)
        fsync_directory(launcher_path.parent)
    if old_current and old_current != f"releases/{release_id}":
        atomic_symlink(old_current, install_root / "previous")
    atomic_symlink(f"releases/{release_id}", current)
    result = verify(repo, install_root, launcher_path, expected_uid, op_binary, gpgv_binary)
    result["status"] = "deployed"
    return result


def verified_release(
    install_root: Path, link: Path, expected_uid: int, allow_legacy: bool = False
) -> tuple[Path, dict[str, Any]]:
    releases = install_root / "releases"
    if not link.is_symlink():
        raise ReleaseFailure(f"release_link_missing:{link.name}")
    path = link.resolve(strict=True)
    try:
        relative = path.relative_to(releases.resolve(strict=True))
    except ValueError as error:
        raise ReleaseFailure(f"release_link_escapes_root:{link.name}") from error
    if len(relative.parts) != 1 or not SHA256.fullmatch(relative.name):
        raise ReleaseFailure("release_id_invalid")
    manifest_path = path / "manifest.json"
    manifest = json.loads(read_regular(manifest_path).decode("utf-8"))
    if manifest.get("schema") != SCHEMA or manifest.get("release_id") != relative.name:
        raise ReleaseFailure("release_manifest_identity_mismatch")
    payloads = manifest.get("payloads")
    valid_names = PAYLOAD_NAMES
    if not isinstance(payloads, dict) or (
        set(payloads) != valid_names and not (
            allow_legacy and set(payloads) in (LEGACY_PAYLOAD_NAMES, PRE_INSTALLER_PAYLOAD_NAMES)
        )
    ):
        raise ReleaseFailure("release_manifest_payloads_invalid")
    for item in [install_root, releases, path, manifest_path, *(path / name for name in payloads)]:
        info = item.stat()
        if info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReleaseFailure(f"release_permissions_invalid:{item.name}")
    if stat.S_IMODE(install_root.stat().st_mode) != 0o755 or stat.S_IMODE(releases.stat().st_mode) != 0o755:
        raise ReleaseFailure("release_root_mode_invalid")
    if stat.S_IMODE(path.stat().st_mode) != 0o555:
        raise ReleaseFailure("release_directory_mode_invalid")
    for name in [*payloads, "manifest.json"]:
        expected_mode = EXPECTED_MODES[name]
        if stat.S_IMODE((path / name).stat().st_mode) != expected_mode:
            raise ReleaseFailure(f"release_mode_invalid:{name}")
    for name, expected in payloads.items():
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise ReleaseFailure("release_manifest_hash_invalid")
        if sha256_bytes(read_regular(path / name)) != expected:
            raise ReleaseFailure(f"release_payload_hash_mismatch:{name}")
    if release_identity(payloads) != relative.name:
        raise ReleaseFailure("release_digest_mismatch")
    return path, manifest


def verify(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    path, manifest = verified_release(install_root, install_root / "current", expected_uid)
    launcher = read_regular(launcher_path)
    source_launcher = read_regular(repo / LAUNCHER_SOURCE)
    if sha256_bytes(launcher) != sha256_bytes(source_launcher):
        raise ReleaseFailure("launcher_source_mismatch")
    info = launcher_path.stat()
    if (info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or stat.S_IMODE(info.st_mode) != 0o755):
        raise ReleaseFailure("launcher_permissions_invalid")
    _, source_hashes, source_id = source_payload(repo, op_binary, gpgv_binary)
    if manifest["payloads"] != source_hashes or manifest["release_id"] != source_id:
        raise ReleaseFailure("active_release_source_mismatch")
    return {
        "schema": SCHEMA,
        "status": "verified",
        "release_id": path.name,
        "launcher_sha256": sha256_bytes(launcher),
        "payloads": manifest["payloads"],
    }


def rollback(
    repo: Path,
    install_root: Path,
    state_root: Path,
    target_id: str | None,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    current_path, _ = verified_release(install_root, install_root / "current", expected_uid)
    if target_id is None:
        target_path, _ = verified_release(install_root, install_root / "previous", expected_uid)
    else:
        if not SHA256.fullmatch(target_id):
            raise ReleaseFailure("rollback_release_id_invalid")
        target_link = install_root / f".rollback-{os.getpid()}"
        target_link.symlink_to(f"releases/{target_id}")
        try:
            target_path, _ = verified_release(install_root, target_link, expected_uid)
        finally:
            target_link.unlink()
    if target_path == current_path:
        raise ReleaseFailure("rollback_target_already_current")
    try:
        _, _, source_id = source_payload(repo, op_binary, gpgv_binary)
        repo_match: bool | None = target_path.name == source_id
    except (ReleaseFailure, OSError):
        repo_match = None
    atomic_symlink(f"releases/{current_path.name}", install_root / "previous")
    atomic_symlink(f"releases/{target_path.name}", install_root / "current")
    return {
        "schema": SCHEMA,
        "status": "rolled_back",
        "release_id": target_path.name,
        "repo_match": repo_match,
        "warning": None if repo_match is True else "active_release_source_mismatch_until_repository_realigns",
    }


def migrate_launcher(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    expected_installed_sha256: str,
    expected_replacement_sha256: str,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if not SHA256.fullmatch(expected_installed_sha256) or not SHA256.fullmatch(expected_replacement_sha256):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    verified_release(install_root, install_root / "current", expected_uid, allow_legacy=True)
    installed = read_regular(launcher_path)
    installed_hash = sha256_bytes(installed)
    if installed_hash != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    info = launcher_path.stat()
    if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o755:
        raise ReleaseFailure("launcher_permissions_invalid")
    replacement = read_regular(repo / LAUNCHER_SOURCE)
    try:
        compile(replacement, str(repo / LAUNCHER_SOURCE), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("stable_launcher_syntax_invalid") from error
    replacement_hash = sha256_bytes(replacement)
    if replacement_hash != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    if replacement_hash == installed_hash:
        raise ReleaseFailure("launcher_migration_not_required")
    backup_root = install_root / "launcher-backups"
    if backup_root.exists():
        backup_info = backup_root.lstat()
        if backup_root.is_symlink() or not backup_root.is_dir() or backup_info.st_uid != expected_uid:
            raise ReleaseFailure("launcher_backup_root_untrusted")
    backup_root.mkdir(mode=0o555, exist_ok=True)
    exact_mode(backup_root, 0o555)
    backup = backup_root / installed_hash
    if not backup.exists():
        exact_mode(backup_root, 0o755)
        descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o555)
        try:
            os.write(descriptor, installed)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o555)
        finally:
            os.close(descriptor)
        exact_mode(backup_root, 0o555)
        fsync_directory(backup_root)
    else:
        backup_info = backup.stat()
        if (backup_info.st_uid != expected_uid or stat.S_IMODE(backup_info.st_mode) != 0o555
                or sha256_bytes(read_regular(backup)) != installed_hash):
            raise ReleaseFailure("launcher_backup_mismatch")
    temporary = launcher_path.parent / f".{launcher_path.name}.migration-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    try:
        os.write(descriptor, replacement)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o755)
    finally:
        os.close(descriptor)
    os.replace(temporary, launcher_path)
    fsync_directory(launcher_path.parent)
    if sha256_bytes(read_regular(launcher_path)) != replacement_hash:
        raise ReleaseFailure("launcher_migration_verification_failed")
    return {
        "schema": SCHEMA,
        "status": "launcher_migrated",
        "previous_launcher_sha256": installed_hash,
        "launcher_sha256": replacement_hash,
        "backup": str(backup),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("command", choices=("install", "verify", "rollback", "migrate-launcher"))
    result.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    result.add_argument("--install-root", type=Path, default=Path("/usr/local/libexec/secure-sandbox-host"))
    result.add_argument("--launcher", type=Path, default=Path("/usr/local/bin/secure-sandbox-claude"))
    result.add_argument("--state-root", type=Path)
    result.add_argument("--release-id")
    result.add_argument("--expected-launcher-sha256")
    result.add_argument("--expected-replacement-sha256")
    result.add_argument("--op-binary", type=Path, default=DEFAULT_OP_BINARY)
    result.add_argument("--gpgv-binary", type=Path, default=DEFAULT_GPGV_BINARY)
    result.add_argument("--json", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    default_layout = args.install_root == Path("/usr/local/libexec/secure-sandbox-host")
    if args.state_root is None:
        state_root = invoking_home() / "Library/Application Support/SecureSandbox/controller-state"
    else:
        state_root = args.state_root
    expected_uid = 0 if default_layout else os.geteuid()
    try:
        if args.command == "install":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            result = install(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.op_binary, args.gpgv_binary,
            )
        elif args.command == "verify":
            result = verify(
                args.repo.resolve(), args.install_root, args.launcher,
                expected_uid, args.op_binary, args.gpgv_binary,
            )
        elif args.command == "rollback":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            result = rollback(
                args.repo.resolve(), args.install_root, state_root, args.release_id,
                expected_uid, args.op_binary, args.gpgv_binary,
            )
        else:
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if not args.expected_launcher_sha256 or not args.expected_replacement_sha256:
                raise ReleaseFailure("expected_launcher_hash_required")
            result = migrate_launcher(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_launcher_sha256, args.expected_replacement_sha256,
            )
        print(json.dumps(result, indent=2 if args.json else None, sort_keys=True))
        return 0
    except (ReleaseFailure, OSError, subprocess.CalledProcessError, json.JSONDecodeError, SyntaxError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
