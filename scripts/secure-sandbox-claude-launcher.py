#!/usr/bin/python3
"""Root-owned stable launcher for one verified host-controller release."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import sys
import time
import uuid
from pathlib import Path

INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
ACCOUNT_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
STATE_ROOT = ACCOUNT_HOME / "Library/Application Support/SecureSandbox/controller-state"
SCHEMA = "secure-sandbox-host-controller-release-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
LEGACY_RELEASE_ID = "cd29ebd476794c46437ddea59ca161551d2767a0f668a6eede5a1f18f9b660dd"
LOCK_INCOMPLETE_GRACE_SECONDS = 30.0
MAX_CONTROLLER_STATE_ENTRIES = 128


class LaunchFailure(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _remove_claimed_lock(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


def _claim_stale_lock(lock: Path, state_root: Path) -> bool:
    claimed = state_root / f".coordination.lock.reclaim-{os.getpid()}-{uuid.uuid4()}"
    try:
        os.rename(lock, claimed)
    except FileNotFoundError:
        return False
    _remove_claimed_lock(claimed)
    return True


def _cleanup_lock_tombstones(state_root: Path) -> None:
    entries = list(state_root.iterdir())
    if len(entries) > MAX_CONTROLLER_STATE_ENTRIES:
        raise LaunchFailure("controller_state_entry_limit_exceeded")
    prefixes = (".coordination.lock.reclaim-", ".coordination.lock.release-")
    for entry in entries:
        if not entry.name.startswith(prefixes):
            continue
        info = entry.lstat()
        if entry.is_symlink() or not entry.is_dir() or info.st_uid != os.geteuid():
            raise LaunchFailure("controller_lock_tombstone_invalid")
        if time.time() - info.st_mtime >= LOCK_INCOMPLETE_GRACE_SECONDS:
            _remove_claimed_lock(entry)


def acquire_lock(state_root: Path, timeout: float = 10.0) -> Path:
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_root.is_symlink() or not state_root.is_dir() or state_root.stat().st_uid != os.geteuid():
        raise LaunchFailure("controller_state_directory_invalid")
    os.chmod(state_root, 0o700)
    _cleanup_lock_tombstones(state_root)
    lock = state_root / "coordination.lock"
    deadline = time.monotonic() + timeout
    while True:
        try:
            lock.mkdir(mode=0o700)
            pid_temporary = lock / ".pid.new"
            descriptor = os.open(pid_temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(pid_temporary, lock / "pid")
            return lock
        except FileExistsError:
            stale = False
            try:
                pid = int((lock / "pid").read_text(encoding="ascii").strip())
                os.kill(pid, 0)
            except ProcessLookupError:
                stale = True
            except PermissionError:
                stale = False
            except (FileNotFoundError, ValueError):
                try:
                    stale = time.time() - lock.stat().st_mtime >= LOCK_INCOMPLETE_GRACE_SECONDS
                except FileNotFoundError:
                    continue
            except OSError:
                stale = False
            if stale and _claim_stale_lock(lock, state_root):
                continue
            if time.monotonic() >= deadline:
                raise LaunchFailure("controller_coordination_lock_timeout")
            time.sleep(0.05)


def release_lock(lock: Path) -> None:
    tombstone = lock.parent / f".coordination.lock.release-{os.getpid()}-{uuid.uuid4()}"
    try:
        os.rename(lock, tombstone)
    except FileNotFoundError:
        return
    _remove_claimed_lock(tombstone)


def load_release(install_root: Path, expected_uid: int = 0) -> tuple[Path, str]:
    releases = install_root / "releases"
    current = install_root / "current"
    if not current.is_symlink():
        raise LaunchFailure("controller_current_missing")
    release = current.resolve(strict=True)
    try:
        relative = release.relative_to(releases.resolve(strict=True))
    except ValueError as error:
        raise LaunchFailure("controller_current_escapes_release_root") from error
    if len(relative.parts) != 1 or not SHA256.fullmatch(relative.name):
        raise LaunchFailure("controller_release_id_invalid")
    manifest_path = release / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise LaunchFailure("controller_manifest_invalid")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LaunchFailure("controller_manifest_invalid") from error
    if manifest.get("schema") != SCHEMA or manifest.get("release_id") != relative.name:
        raise LaunchFailure("controller_manifest_identity_mismatch")
    payloads = manifest.get("payloads")
    payload_names = set(payloads) if isinstance(payloads, dict) else set()
    current_names = {"controller", "op_agents", "pki_anchor", "ssh_config"}
    legacy_names = {"controller", "op_agents", "ssh_config"}
    if payload_names != current_names and not (relative.name == LEGACY_RELEASE_ID and payload_names == legacy_names):
        raise LaunchFailure("controller_manifest_payloads_invalid")
    identity = bytearray()
    for protected in (install_root, releases, release, manifest_path):
        info = protected.stat()
        if info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise LaunchFailure(f"controller_permissions_invalid:{protected.name}")
    for name in sorted(payloads):
        expected = payloads[name]
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise LaunchFailure("controller_manifest_hash_invalid")
        path = release / name
        if path.is_symlink() or not path.is_file():
            raise LaunchFailure(f"controller_payload_invalid:{name}")
        actual = digest(path.read_bytes())
        info = path.stat()
        if info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise LaunchFailure(f"controller_permissions_invalid:{name}")
        if actual != expected:
            raise LaunchFailure(f"controller_payload_hash_mismatch:{name}")
        identity.extend(f"{name}\0{actual}\n".encode("ascii"))
    if digest(bytes(identity)) != relative.name:
        raise LaunchFailure("controller_release_digest_mismatch")
    return release, relative.name


def main() -> int:
    marker: Path | None = None
    lock: Path | None = None
    try:
        lock = acquire_lock(STATE_ROOT)
        release, release_id = load_release(INSTALL_ROOT)
        runs = STATE_ROOT / "active"
        runs.mkdir(mode=0o700, exist_ok=True)
        if runs.is_symlink() or not runs.is_dir() or runs.stat().st_uid != os.geteuid():
            raise LaunchFailure("controller_active_directory_invalid")
        os.chmod(runs, 0o700)
        marker = runs / f"{os.getpid()}-{uuid.uuid4()}.json"
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(
                descriptor,
                (json.dumps({"pid": os.getpid(), "release_id": release_id}, sort_keys=True) + "\n").encode("ascii"),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        release_lock(lock)
        lock = None
        environment = os.environ.copy()
        environment["SECURE_SANDBOX_ACTIVE_MARKER"] = str(marker)
        environment["SECURE_SANDBOX_RELEASE_ID"] = release_id
        environment["SECURE_SANDBOX_STATE_ROOT"] = str(STATE_ROOT)
        os.execve(str(release / "controller"), ["secure-sandbox-claude", *sys.argv[1:]], environment)
    except (LaunchFailure, OSError) as error:
        print(f"secure-sandbox-claude: {error}", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            release_lock(lock)
        if marker is not None:
            try:
                marker.unlink()
            except FileNotFoundError:
                pass
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

