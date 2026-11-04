#!/usr/bin/env python3
"""Root-only native Codex launch supervisor contract.

The Host credential bridge owns the token stream.  This module never reads it:
stdin is inherited directly by the C launcher, which consumes the fixed binary
projection frame and then becomes the admitted Codex executable.  The only
credential-derived value accepted here is a SHA-256 digest used to mint one
root-owned, unlinked, read-only fd-3 permit.

Every launched process is owned by an exact transient systemd scope selected by
``native_guest_control`` during stop-bound-runs. The scope is lifetime-bound to
``native-harness-supervisor.service`` and independently read back through its
cgroup before the launch is accepted.
"""

from __future__ import annotations

import fcntl
import hashlib
import ctypes
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable

from research import native_codex_policy as policy
from research import native_lifecycle_fence


STATE_ROOT = Path("/run/secure-sandbox/native-codex/session-state")
CONTROL_ROOT = Path("/run/secure-sandbox/native-codex")
AUTHORITY_PATH = CONTROL_ROOT / "launch.authority"
LOCK_PATH = CONTROL_ROOT / "launch.lock"
PERMIT_ROOT = CONTROL_ROOT / "permits"
POLICY_ROOT = Path("/var/lib/secure-sandbox/native-vendor/openai/codex-policy")
BASELINE_CONFIG = POLICY_ROOT / "config.toml"
LAUNCHER = Path("/usr/local/libexec/secure-sandbox/native-codex-launcher")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
BUSCTL = Path("/usr/bin/busctl")
CGROUP_ROOT = Path("/sys/fs/cgroup")
IDENTITY = "native-harness"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = re.compile(r"[0-9a-f]{64}")


class NativeCodexSessionError(RuntimeError):
    """Stable fail-closed native Codex supervisor error."""


def _require_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    information = path.lstat()
    if (
        not stat.S_ISDIR(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_uid != uid
        or information.st_gid != gid
        or stat.S_IMODE(information.st_mode) != mode
    ):
        raise NativeCodexSessionError("native_codex_session_directory_untrusted")


def _make_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    _require_directory(path, uid=uid, gid=gid, mode=mode)


def _copy_exact_config(
    source: Path,
    destination: Path,
    *,
    trusted_uid: int,
    trusted_gid: int,
) -> None:
    information = source.lstat()
    if (
        not stat.S_ISREG(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_nlink != 1
        or information.st_uid != trusted_uid
        or information.st_gid != trusted_gid
        or stat.S_IMODE(information.st_mode) != 0o640
        or not 1 <= information.st_size <= 262_144
    ):
        raise NativeCodexSessionError("native_codex_session_policy_untrusted")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    destination_fd = -1
    try:
        opened = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino) != (information.st_dev, information.st_ino):
            raise NativeCodexSessionError("native_codex_session_policy_changed")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o640,
        )
        os.fchown(destination_fd, trusted_uid, trusted_gid)
        remaining = information.st_size
        digest = hashlib.sha256()
        copied = hashlib.sha256()
        while remaining:
            block = os.read(source_fd, min(65_536, remaining))
            if not block:
                raise NativeCodexSessionError("native_codex_session_policy_truncated")
            digest.update(block)
            view = memoryview(block)
            while view:
                count = os.write(destination_fd, view)
                if count <= 0:
                    raise NativeCodexSessionError("native_codex_session_policy_write_failed")
                copied.update(view[:count])
                view = view[count:]
            remaining -= len(block)
        if os.read(source_fd, 1) or digest.digest() != copied.digest():
            raise NativeCodexSessionError("native_codex_session_policy_changed")
        os.fchmod(destination_fd, 0o640)
        os.fsync(destination_fd)
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def create_session_layout(
    descriptor_value: object,
    *,
    state_root: Path = STATE_ROOT,
    baseline_config: Path = BASELINE_CONFIG,
    trusted_uid: int = 0,
    launcher_uid: int,
    launcher_gid: int,
    installation_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
) -> Path:
    """Create the exact fresh CODEX_HOME projection accepted by the launcher."""
    descriptor = policy.validate_launch_descriptor(descriptor_value)
    session_id = descriptor["session_id"]
    if UUID4.fullmatch(session_id) is None or launcher_uid == 0 or launcher_gid == 0:
        raise NativeCodexSessionError("native_codex_session_identity_invalid")
    _require_directory(
        state_root, uid=trusted_uid, gid=launcher_gid, mode=0o750
    )
    session = state_root / session_id
    try:
        _make_directory(
            session, uid=trusted_uid, gid=launcher_gid, mode=0o710
        )
        for name in ("home", "cache", "tmp"):
            _make_directory(
                session / name, uid=launcher_uid, gid=launcher_gid, mode=0o700
            )
        codex_home = session / "codex-home"
        _make_directory(
            codex_home, uid=trusted_uid, gid=launcher_gid, mode=0o710
        )
        _copy_exact_config(
            baseline_config,
            codex_home / "config.toml",
            trusted_uid=trusted_uid,
            trusted_gid=launcher_gid,
        )
        _make_directory(
            codex_home / "skills", uid=trusted_uid, gid=launcher_gid, mode=0o750
        )
        for name in ("state", "logs", "tmp", ".tmp"):
            _make_directory(
                codex_home / name,
                uid=launcher_uid,
                gid=launcher_gid,
                mode=0o700,
            )
        installation_id = installation_id_factory()
        if UUID4.fullmatch(installation_id) is None:
            raise NativeCodexSessionError("native_codex_installation_id_invalid")
        installation_fd = os.open(
            codex_home / "installation_id",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.fchown(installation_fd, launcher_uid, launcher_gid)
            os.fchmod(installation_fd, 0o600)
            if os.write(installation_fd, installation_id.encode("ascii")) != 36:
                raise NativeCodexSessionError("native_codex_installation_id_write_failed")
            os.fsync(installation_fd)
        finally:
            os.close(installation_fd)
        directory = os.open(codex_home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return session
    except Exception:
        if session.exists() and not session.is_symlink():
            shutil.rmtree(session)
        raise


def claim_projection_permit(
    descriptor_value: object,
    *,
    projection_id: str,
    access_token_sha256: str,
    issued_at_unix: int,
    expires_at_unix: int,
    launcher_uid: int,
    launcher_gid: int,
    permit_root: Path = PERMIT_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> int:
    """Return the sole pathless, rewound, root-owned 0400 permit description."""
    if SHA256.fullmatch(access_token_sha256) is None:
        raise NativeCodexSessionError("native_codex_token_digest_invalid")
    _require_directory(permit_root, uid=trusted_uid, gid=trusted_gid, mode=0o700)
    permit = policy.make_projection_permit(
        descriptor_value,
        projection_id=projection_id,
        access_token_sha256=access_token_sha256,
        issued_at_unix=issued_at_unix,
        expires_at_unix=expires_at_unix,
        launcher_uid=launcher_uid,
        launcher_gid=launcher_gid,
    )
    payload = policy.projection_permit_bytes(permit)
    path = permit_root / f".{projection_id}.permit"
    writer = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
    )
    reader = -1
    try:
        os.fchown(writer, trusted_uid, trusted_gid)
        os.fchmod(writer, 0o400)
        view = memoryview(payload)
        while view:
            count = os.write(writer, view)
            if count <= 0:
                raise NativeCodexSessionError("native_codex_permit_write_failed")
            view = view[count:]
        os.fsync(writer)
        os.close(writer)
        writer = -1
        reader = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        information = os.fstat(reader)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or information.st_uid != trusted_uid
            or information.st_gid != trusted_gid
            or stat.S_IMODE(information.st_mode) != 0o400
            or information.st_size != len(payload)
        ):
            raise NativeCodexSessionError("native_codex_permit_untrusted")
        path.unlink()
        directory = os.open(permit_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        information = os.fstat(reader)
        if information.st_nlink != 0 or os.lseek(reader, 0, os.SEEK_CUR) != 0:
            raise NativeCodexSessionError("native_codex_permit_not_pathless")
        result, reader = reader, -1
        return result
    finally:
        if reader >= 0:
            os.close(reader)
        if writer >= 0:
            os.close(writer)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, 15)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, 9)
    except ProcessLookupError:
        return
    process.wait(timeout=2)


def verify_transient_scope(
    unit: str,
    *,
    launcher_uid: int,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    deadline_seconds: float = 5.0,
) -> dict[str, object]:
    """Require exact dependencies and launcher UID for every cgroup member."""
    if re.fullmatch(r"secure-sandbox-native-run-[0-9a-f]{32}\.scope", unit) is None:
        raise NativeCodexSessionError("native_codex_scope_name_invalid")
    deadline = time.monotonic() + deadline_seconds
    last_error = "native_codex_scope_unavailable"
    while time.monotonic() < deadline:
        result = runner(
            [str(systemctl), "show", unit,
             "--property=ActiveState,BindsTo,After,PartOf,ControlGroup"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=2,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        if result.returncode != 0 or len(result.stdout) > 16 * 1024:
            time.sleep(0.05)
            continue
        fields: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                name, content = line.split("=", 1)
                fields[name] = content
        dependency = "native-harness-supervisor.service"
        if (fields.get("ActiveState") != "active"
                or dependency not in fields.get("BindsTo", "").split()
                or dependency not in fields.get("After", "").split()
                or dependency not in fields.get("PartOf", "").split()):
            last_error = "native_codex_scope_dependency_invalid"
            time.sleep(0.05)
            continue
        cgroup = fields.get("ControlGroup", "")
        if (not cgroup.startswith("/") or ".." in Path(cgroup).parts
                or not cgroup.endswith("/" + unit)):
            last_error = "native_codex_scope_cgroup_invalid"
            time.sleep(0.05)
            continue
        try:
            pids = [int(item) for item in (
                cgroup_root / cgroup.lstrip("/") / "cgroup.procs"
            ).read_text(encoding="ascii").splitlines()]
        except (OSError, ValueError, UnicodeError):
            last_error = "native_codex_scope_process_readback_failed"
            time.sleep(0.05)
            continue
        if not pids or len(pids) > 64:
            last_error = "native_codex_scope_process_count_invalid"
            time.sleep(0.05)
            continue
        accepted = True
        for pid in pids:
            try:
                status = (proc_root / str(pid) / "status").read_text(
                    encoding="ascii")
                matches = [line for line in status.splitlines()
                           if line.startswith("Uid:")]
                values = matches[0].split()[1:] if len(matches) == 1 else []
                if len(values) != 4 or any(
                    int(value) != launcher_uid for value in values
                ):
                    accepted = False
                    break
            except (OSError, ValueError, UnicodeError):
                accepted = False
                break
        if accepted:
            return {"unit": unit, "cgroup": cgroup,
                    "process_count": len(pids)}
        last_error = "native_codex_scope_uid_invalid"
        time.sleep(0.05)
    raise NativeCodexSessionError(last_error)


def start_transient_scope(
    unit: str,
    pid: int,
    *,
    busctl: Path = BUSCTL,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    """Atomically attach one already-stopped process to a transient scope."""
    if (re.fullmatch(r"secure-sandbox-native-run-[0-9a-f]{32}\.scope", unit) is None
            or not isinstance(pid, int) or pid <= 1):
        raise NativeCodexSessionError("native_codex_scope_request_invalid")
    dependency = "native-harness-supervisor.service"
    command = [
        str(busctl), "--system", "--quiet", "--timeout=5s", "call",
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartTransientUnit",
        "ssa(sv)a(sa(sv))", unit, "fail", "7",
        "PIDs", "au", "1", str(pid),
        "Description", "s", "SecureSandbox native vendor run",
        "BindsTo", "as", "1", dependency,
        "After", "as", "1", dependency,
        "PartOf", "as", "1", dependency,
        "KillMode", "s", "control-group",
        "CollectMode", "s", "inactive-or-failed",
        "0",
    ]
    result = runner(
        command, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise NativeCodexSessionError("native_codex_scope_create_failed")


def _child_hardening() -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, 9, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG, SIGKILL
            raise OSError(ctypes.get_errno(), "prctl")


def _launch_and_wait_admitted(
    authority_value: object,
    *,
    projection_id: str,
    access_token_sha256: str,
    input_fd: int = 0,
    now: int | None = None,
    expires_at_unix: int | None = None,
    launcher_path: Path = LAUNCHER,
    state_root: Path = STATE_ROOT,
    control_root: Path = CONTROL_ROOT,
    policy_root: Path = POLICY_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
    identity_name: str = IDENTITY,
    busctl_path: Path = BUSCTL,
    systemctl_path: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    scope_verifier: Callable[..., dict[str, object]] = verify_transient_scope,
    scope_starter: Callable[..., None] = start_transient_scope,
) -> int:
    """Launch one session after the lifecycle admission lock is held.

    The caller's ``input_fd`` is projected unchanged.  This process never reads
    or buffers it, so the token cannot enter a Python object, JSON record, log,
    argv, environment variable, or durable file.
    """
    if os.geteuid() != trusted_uid:
        raise NativeCodexSessionError("native_codex_supervisor_not_root")
    identity = pwd.getpwnam(identity_name)
    if identity.pw_uid == 0 or identity.pw_gid == 0:
        raise NativeCodexSessionError("native_codex_session_identity_invalid")
    descriptor = policy.make_launch_descriptor(authority_value)
    _require_directory(control_root, uid=trusted_uid, gid=trusted_gid, mode=0o700)
    _require_directory(policy_root, uid=trusted_uid, gid=identity.pw_gid, mode=0o750)
    lock = os.open(
        control_root / LOCK_PATH.name,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.fchmod(lock, 0o600)
        os.fchown(lock, trusted_uid, trusted_gid)
        fcntl.flock(lock, fcntl.LOCK_EX)
        session = create_session_layout(
            descriptor,
            state_root=state_root,
            baseline_config=policy_root / "config.toml",
            trusted_uid=trusted_uid,
            launcher_uid=identity.pw_uid,
            launcher_gid=identity.pw_gid,
        )
        policy.write_launch_descriptor(
            control_root / AUTHORITY_PATH.name,
            descriptor,
            uid=trusted_uid,
            gid=identity.pw_gid,
        )
        issued = int(time.time()) if now is None else now
        expires = issued + 60 if expires_at_unix is None else expires_at_unix
        permit_fd = claim_projection_permit(
            descriptor,
            projection_id=projection_id,
            access_token_sha256=access_token_sha256,
            issued_at_unix=issued,
            expires_at_unix=expires,
            launcher_uid=identity.pw_uid,
            launcher_gid=identity.pw_gid,
            permit_root=control_root / PERMIT_ROOT.name,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        unit = (
            "secure-sandbox-native-run-"
            + descriptor["session_id"].replace("-", "")
            + ".scope"
        )

        child = -1
        try:
            child = os.fork()
            if child == 0:  # pragma: no cover - stopped exec-only child
                try:
                    _child_hardening()
                    os.setsid()
                    os.setgroups([])
                    os.setgid(identity.pw_gid)
                    os.setuid(identity.pw_uid)
                    if input_fd != 0:
                        os.dup2(input_fd, 0)
                    if permit_fd != policy.PROJECTION_PERMIT_FD:
                        os.dup2(permit_fd, policy.PROJECTION_PERMIT_FD)
                    os.set_inheritable(policy.PROJECTION_PERMIT_FD, True)
                    maximum = os.sysconf("SC_OPEN_MAX")
                    os.closerange(4, maximum if maximum > 4 else 1024)
                    os.kill(os.getpid(), 19)  # SIGSTOP before any vendor exec
                    os.execve(launcher_path, [str(launcher_path)], {})
                except BaseException:
                    os._exit(126)
            os.close(permit_fd)
            permit_fd = -1
            waited, status = os.waitpid(child, os.WUNTRACED)
            if (waited != child or not os.WIFSTOPPED(status)
                    or os.WSTOPSIG(status) != 19):
                raise NativeCodexSessionError("native_codex_child_gate_failed")
            scope_starter(unit, child, busctl=busctl_path)
            scope_verifier(
                unit, launcher_uid=identity.pw_uid,
                systemctl=systemctl_path, cgroup_root=cgroup_root)
            os.kill(child, 18)  # SIGCONT only after exact scope/UID readback
            _, status = os.waitpid(child, 0)
            child = -1
            result = os.waitstatus_to_exitcode(status)
            readback = subprocess.run(
                [str(systemctl_path), "is-active", unit], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if readback.returncode not in {3, 4} or readback.stdout.strip() == b"active":
                raise NativeCodexSessionError("native_codex_scope_teardown_ambiguous")
            return result
        except Exception:
            subprocess.run(
                [str(systemctl_path), "stop", unit], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if child > 0:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
            raise
        finally:
            if permit_fd >= 0:
                os.close(permit_fd)
            if session.exists() and not session.is_symlink():
                shutil.rmtree(session)
            try:
                (control_root / AUTHORITY_PATH.name).unlink()
            except FileNotFoundError:
                pass
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def launch_and_wait(
    authority_value: object, *, projection_id: str,
    access_token_sha256: str,
    lifecycle_root: Path = native_lifecycle_fence.ROOT,
    **options: object,
) -> int:
    """Launch exactly one session under the durable publication exclusion.

    The caller's token-bearing input descriptor is passed unchanged to the C
    launcher.  This controller handles only its digest and never reads or
    buffers the stream.
    """
    trusted_uid = options.get("trusted_uid", 0)
    trusted_gid = options.get("trusted_gid", 0)
    if not isinstance(trusted_uid, int) or not isinstance(trusted_gid, int):
        raise NativeCodexSessionError("native_codex_trusted_identity_invalid")
    try:
        with native_lifecycle_fence.admission_open(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ):
            return _launch_and_wait_admitted(
                authority_value, projection_id=projection_id,
                access_token_sha256=access_token_sha256, **options)
    except native_lifecycle_fence.NativeLifecycleFenceError as error:
        raise NativeCodexSessionError(str(error)) from error


def main() -> int:
    # The token-bearing transport must call ``launch_and_wait`` in-process with
    # an already-open stdin. A broad argv/JSON CLI would defeat that boundary.
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
