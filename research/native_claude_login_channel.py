#!/usr/bin/env python3
"""One-time no-capture PTY channel for unmodified Claude subscription login.

The byte stream is relayed opaquely between the operator terminal and the
vendor harness. It is never parsed, logged, persisted, hashed, or included in a
receipt. Only the subsequent bounded ``claude auth status --json`` observation
is parsed inside Research and reduced to HMAC bindings before publication.
"""

from __future__ import annotations

import errno
import fcntl
import os
import pty
import re
import selectors
import stat
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path
from typing import Callable

from research import native_claude_adapter
from research import native_codex_session_controller
from research import native_lifecycle_fence
from research import native_provider_controller as controller


HANDLE_ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller/login-handles")
PROOF_ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller/login-proofs")
MAXIMUM_SECONDS = 300


class NativeClaudeLoginError(RuntimeError):
    """Stable fail-closed login-channel error."""


def _claim_handle(
    *, operation_id: str, plan_sha256: str, authorization_sha256: str,
    stack_sha256: str, catalog_sha256: str, root: Path = HANDLE_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != trusted_uid or info.st_gid != trusted_gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise NativeClaudeLoginError("native_claude_login_handle_root_untrusted")
    body = {"operation_id": operation_id, "plan_sha256": plan_sha256,
            "authorization_sha256": authorization_sha256,
            "stack_sha256": stack_sha256, "catalog_sha256": catalog_sha256}
    value = {"schema": "secure-sandbox-native-claude-login-handle-v1", **body,
             "handle_sha256": controller.digest(body)}
    path = root / f"{operation_id}.json"
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600)
    try:
        os.fchown(descriptor, trusted_uid, trusted_gid)
        os.fchmod(descriptor, 0o600)
        payload = controller.canonical(value)
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise NativeClaudeLoginError("native_claude_login_handle_write_failed")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _copy_terminal_size(source: int, target: int) -> None:
    try:
        size = fcntl.ioctl(source, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(target, termios.TIOCSWINSZ, size)
    except OSError:
        pass


def relay_opaque_pty(
    pid: int, master: int, *,
    input_fd: int = 0, output_fd: int = 1,
    maximum_seconds: int = MAXIMUM_SECONDS,
) -> int:
    """Relay bounded chunks without interpreting or retaining their contents."""
    selector = selectors.DefaultSelector()
    selector.register(master, selectors.EVENT_READ, "vendor")
    selector.register(input_fd, selectors.EVENT_READ, "operator")
    deadline = time.monotonic() + maximum_seconds
    exit_status: int | None = None
    try:
        while time.monotonic() < deadline:
            _copy_terminal_size(input_fd, master)
            if exit_status is None:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    exit_status = status
            if exit_status is not None:
                # Drain any final terminal output without waiting indefinitely.
                timeout = 0
            else:
                timeout = min(0.1, deadline - time.monotonic())
            events = selector.select(max(0, timeout))
            if not events and exit_status is not None:
                break
            for key, _mask in events:
                try:
                    block = os.read(key.fd, 16 * 1024)
                except OSError as error:
                    if error.errno == errno.EIO and key.data == "vendor":
                        selector.unregister(key.fd)
                        continue
                    raise
                if not block:
                    selector.unregister(key.fd)
                    if key.data == "operator":
                        try:
                            os.write(master, b"\x04")
                        except OSError:
                            pass
                    continue
                destination = output_fd if key.data == "vendor" else master
                view = memoryview(block)
                while view:
                    count = os.write(destination, view)
                    if count <= 0:
                        raise NativeClaudeLoginError(
                            "native_claude_login_transport_failed")
                    view = view[count:]
        if exit_status is None:
            raise NativeClaudeLoginError("native_claude_login_timeout")
        return os.waitstatus_to_exitcode(exit_status)
    finally:
        selector.close()


def _run_login_channel_admitted(
    *, operation_id: str, plan_sha256: str, authorization_sha256: str,
    stack_sha256: str, catalog_sha256: str,
    catalog_path: Path = controller.CATALOG_PATH,
    binding_key_path: Path = controller.BINDING_KEY_PATH,
    handle_root: Path = HANDLE_ROOT, proof_root: Path = PROOF_ROOT,
    input_fd: int = 0, output_fd: int = 1,
    trusted_uid: int = 0, trusted_gid: int = 0,
    runtime_loader: Callable[[str], dict[str, str]] = controller.generation_runtime,
    scope_verifier: Callable[..., dict[str, object]] = (
        native_codex_session_controller.verify_transient_scope),
    scope_starter: Callable[..., None] = (
        native_codex_session_controller.start_transient_scope),
    busctl: Path = native_codex_session_controller.BUSCTL,
    systemctl: Path = native_codex_session_controller.SYSTEMCTL,
    cgroup_root: Path = native_codex_session_controller.CGROUP_ROOT,
    now: Callable[[], int] = lambda: int(time.time()),
) -> str:
    if os.geteuid() != trusted_uid:
        raise NativeClaudeLoginError("native_claude_login_root_required")
    for value, pattern, label in (
        (operation_id, controller.UUID4, "operation_id"),
        (plan_sha256, controller.SHA256, "plan_sha256"),
        (authorization_sha256, controller.SHA256, "authorization_sha256"),
        (stack_sha256, controller.SHA256, "stack_sha256"),
        (catalog_sha256, controller.SHA256, "catalog_sha256"),
    ):
        if pattern.fullmatch(value) is None:
            raise NativeClaudeLoginError(f"native_claude_login_{label}_invalid")
    _claim_handle(
        operation_id=operation_id, plan_sha256=plan_sha256,
        authorization_sha256=authorization_sha256,
        stack_sha256=stack_sha256, catalog_sha256=catalog_sha256,
        root=handle_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    stack, _ = controller.load_stack(
        stack_sha256, catalog_sha256=catalog_sha256, catalog_path=catalog_path)
    generation = stack["harness"]["generation_id"]
    if generation is None:
        raise NativeClaudeLoginError("native_claude_login_harness_not_selected")
    harness = runtime_loader(generation)
    executable = native_claude_adapter.executable_for_harness(harness)
    service = controller._identity()
    environment = native_claude_adapter.login_environment(
        stack, harness, home=controller.CLAUDE_HOME,
        config_root=controller.CLAUDE_CONFIG_ROOT)
    master, slave = pty.openpty()
    _copy_terminal_size(input_fd, slave)
    unit = "secure-sandbox-native-run-" + operation_id.replace("-", "") + ".scope"
    command = native_claude_adapter.login_command(executable)
    child = -1
    try:
        child = os.fork()
        if child == 0:  # pragma: no cover - stopped exec-only child
            try:
                native_codex_session_controller._child_hardening()
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                os.setgroups([])
                os.setgid(service.pw_gid)
                os.setuid(service.pw_uid)
                for descriptor in (0, 1, 2):
                    if slave != descriptor:
                        os.dup2(slave, descriptor)
                maximum = os.sysconf("SC_OPEN_MAX")
                os.closerange(3, maximum if maximum > 3 else 1024)
                os.kill(os.getpid(), 19)  # SIGSTOP before any vendor exec
                os.execve(executable, command, environment)
            except BaseException:
                os._exit(126)
        os.close(slave)
        slave = -1
        waited, status = os.waitpid(child, os.WUNTRACED)
        if (waited != child or not os.WIFSTOPPED(status)
                or os.WSTOPSIG(status) != 19):
            raise NativeClaudeLoginError("native_claude_login_child_gate_failed")
        scope_starter(unit, child, busctl=busctl)
        scope_verifier(
            unit, launcher_uid=service.pw_uid,
            systemctl=systemctl, cgroup_root=cgroup_root)
        os.kill(child, 18)  # SIGCONT only after exact scope/UID readback
        if relay_opaque_pty(
            child, master, input_fd=input_fd, output_fd=output_fd) != 0:
            raise NativeClaudeLoginError("native_claude_login_process_failed")
        child = -1
        readback = subprocess.run(
            [str(systemctl), "is-active", unit], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        if (readback.returncode not in {3, 4}
                or readback.stdout.strip() == b"active"):
            raise NativeClaudeLoginError(
                "native_claude_login_scope_teardown_ambiguous")
    except Exception:
        subprocess.run(
            [str(systemctl), "stop", unit], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10)
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
        if slave >= 0:
            os.close(slave)
        os.close(master)
    prefix = controller._command_prefix(service)
    observed = native_claude_adapter.observe_status(
        executable, environment, now=now(),
        binding_key=controller.load_binding_key(binding_key_path),
        command_prefix=prefix)
    if (observed["state"] != "signed-in"
            or observed["account_subject_sha256"] is None
            or observed["workspace_sha256"] is None):
        raise NativeClaudeLoginError("native_claude_login_status_not_verified")
    configured = stack["account_binding"]
    binding_state = (
        "observed"
        if configured["account_subject_sha256"] is None
        and configured["workspace_sha256"] is None
        else "bound"
        if configured["account_subject_sha256"] == observed["account_subject_sha256"]
        and configured["workspace_sha256"] == observed["workspace_sha256"]
        else "mismatch"
    )
    if binding_state == "mismatch":
        raise NativeClaudeLoginError("native_claude_login_account_mismatch")
    authentication = {"state": "signed-in", "observed_at": observed["observed_at"],
                      "evidence_sha256": observed["evidence_sha256"]}
    account = {"state": binding_state,
               "account_subject_sha256": observed["account_subject_sha256"],
               "workspace_sha256": observed["workspace_sha256"],
               "observed_at": observed["observed_at"],
               "evidence_sha256": observed["evidence_sha256"]}
    return controller.write_login_proof(
        operation_id=operation_id, plan_sha256=plan_sha256,
        authorization_sha256=authorization_sha256,
        stack_sha256=stack_sha256, harness_generation_id=generation,
        authentication=authentication, account_binding=account,
        proof_root=proof_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)


def run_login_channel(
    *, operation_id: str, plan_sha256: str, authorization_sha256: str,
    stack_sha256: str, catalog_sha256: str,
    lifecycle_root: Path = native_lifecycle_fence.ROOT,
    **options: object,
) -> str:
    """Hold publication exclusion for the complete interactive login run."""
    trusted_uid = options.get("trusted_uid", 0)
    trusted_gid = options.get("trusted_gid", 0)
    if not isinstance(trusted_uid, int) or not isinstance(trusted_gid, int):
        raise NativeClaudeLoginError("native_claude_login_identity_invalid")
    try:
        with native_lifecycle_fence.admission_open(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ):
            return _run_login_channel_admitted(
                operation_id=operation_id, plan_sha256=plan_sha256,
                authorization_sha256=authorization_sha256,
                stack_sha256=stack_sha256, catalog_sha256=catalog_sha256,
                **options)
    except native_lifecycle_fence.NativeLifecycleFenceError as error:
        raise NativeClaudeLoginError(str(error)) from error


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != 5:
        return 64
    try:
        run_login_channel(
            operation_id=values[0], plan_sha256=values[1],
            authorization_sha256=values[2], stack_sha256=values[3],
            catalog_sha256=values[4])
        os.write(1, b"\r\nSecureSandbox login verification complete.\r\n")
        return 0
    except (NativeClaudeLoginError, controller.NativeProviderControllerError,
            native_claude_adapter.NativeClaudeAdapterError, OSError):
        # The terminal receives only one fixed failure. Provider details remain
        # inside the credential compartment and no interactive bytes are kept.
        os.write(1, b"\r\nSecureSandbox login verification failed.\r\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
