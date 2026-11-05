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
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path
from typing import Callable

from research import native_claude_adapter
from research import native_claude_login_replay
from research import native_codex_session_controller
from research import native_lifecycle_fence
from research import native_provider_controller as controller


HANDLE_ROOT = native_claude_login_replay.HANDLE_ROOT
PROOF_ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller/login-proofs")
MAXIMUM_SECONDS = 300
MAXIMUM_RELAY_BYTES = 64 * 1024 * 1024
MAX_RETAINED_HANDLES = native_claude_login_replay.MAX_RETAINED_HANDLES


class NativeClaudeLoginError(RuntimeError):
    """Stable fail-closed login-channel error."""


def _claim_handle(
    *, operation_id: str, plan_sha256: str, authorization_sha256: str,
    stack_sha256: str, catalog_sha256: str, root: Path = HANDLE_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    try:
        native_claude_login_replay.claim_handle(
            operation_id=operation_id, plan_sha256=plan_sha256,
            authorization_sha256=authorization_sha256,
            stack_sha256=stack_sha256, catalog_sha256=catalog_sha256,
            root=root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    except native_claude_login_replay.NativeClaudeReplayError as error:
        raise NativeClaudeLoginError(str(error)) from error


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
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Relay bounded chunks without interpreting or retaining their contents."""
    original_flags: dict[int, int] = {}
    for descriptor in {master, input_fd, output_fd}:
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        original_flags[descriptor] = flags
        fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    selector = selectors.DefaultSelector()
    selector.register(master, selectors.EVENT_READ, "vendor")
    selector.register(input_fd, selectors.EVENT_READ, "operator")
    if deadline is None:
        deadline = monotonic() + maximum_seconds
    exit_status: int | None = None
    transferred = 0
    try:
        while monotonic() < deadline:
            _copy_terminal_size(input_fd, master)
            if exit_status is None:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    exit_status = status
            if exit_status is not None:
                # Drain any final terminal output without waiting indefinitely.
                timeout = 0
            else:
                timeout = min(0.1, deadline - monotonic())
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
                        _write_before_deadline(
                            master, b"\x04", deadline, monotonic=monotonic
                        )
                    continue
                transferred += len(block)
                if transferred > MAXIMUM_RELAY_BYTES:
                    raise NativeClaudeLoginError(
                        "native_claude_login_relay_byte_limit_exceeded"
                    )
                destination = output_fd if key.data == "vendor" else master
                _write_before_deadline(
                    destination, block, deadline, monotonic=monotonic
                )
        if exit_status is None:
            raise NativeClaudeLoginError("native_claude_login_timeout")
        return os.waitstatus_to_exitcode(exit_status)
    finally:
        selector.close()
        for descriptor, flags in original_flags.items():
            try:
                fcntl.fcntl(descriptor, fcntl.F_SETFL, flags)
            except OSError:
                pass


def _write_before_deadline(
    descriptor: int, block: bytes, deadline: float, *,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Write a bounded opaque block without outliving login authority."""
    remaining = memoryview(block)
    selector = selectors.DefaultSelector()
    try:
        selector.register(descriptor, selectors.EVENT_WRITE)
        while remaining:
            timeout = deadline - monotonic()
            if timeout <= 0:
                raise NativeClaudeLoginError("native_claude_login_timeout")
            if not selector.select(min(0.1, timeout)):
                continue
            if monotonic() >= deadline:
                raise NativeClaudeLoginError("native_claude_login_timeout")
            try:
                count = os.write(descriptor, remaining)
            except BlockingIOError:
                continue
            if count <= 0:
                raise NativeClaudeLoginError(
                    "native_claude_login_transport_failed"
                )
            remaining = remaining[count:]
    finally:
        selector.close()


def _remaining_runtime_usec(
    deadline: float, *, monotonic: Callable[[], float] = time.monotonic,
) -> int:
    remaining = int((deadline - monotonic()) * 1_000_000)
    if remaining <= 0:
        raise NativeClaudeLoginError("native_claude_login_timeout")
    return remaining


def _terminate_direct_child(
    process_id: int, *,
    waitpid: Callable[[int, int], tuple[int, int]] = os.waitpid,
    kill: Callable[[int, int], None] = os.kill,
) -> None:
    """Signal only a still-owned direct child; never a reused numeric PID."""
    try:
        waited, _status = waitpid(process_id, os.WNOHANG)
    except ChildProcessError:
        return
    if waited == process_id:
        return
    if waited != 0:
        raise NativeClaudeLoginError("native_claude_login_child_reap_ambiguous")
    try:
        kill(process_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        waited, _status = waitpid(process_id, 0)
    except ChildProcessError:
        return
    if waited != process_id:
        raise NativeClaudeLoginError("native_claude_login_child_reap_ambiguous")


def _prove_scope_absent(
    unit: str, *, process_id: int, process_start_time: int | None,
    systemctl: Path, cgroup_root: Path, proc_root: Path = Path("/proc"),
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    deadline_seconds: float = 5.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Require two stable exact scope/process-generation absence snapshots."""
    if (deadline_seconds <= 0 or process_id <= 1
            or re.fullmatch(
                r"secure-sandbox-native-run-[0-9a-f]{32}\.scope",
                unit) is None):
        raise NativeClaudeLoginError(
            "native_claude_login_scope_teardown_ambiguous")
    deadline = monotonic() + deadline_seconds
    consecutive = 0
    last_error = "native_claude_login_scope_teardown_ambiguous"
    properties = {"LoadState", "ActiveState", "SubState", "ControlGroup"}
    while monotonic() < deadline:
        absent = False
        result = runner(
            [str(systemctl), "show", unit, "--all",
             "--property=" + ",".join(sorted(properties))],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "LC_ALL": "C.UTF-8"},
        )
        if result.returncode == 4 and not result.stdout:
            absent = True
        elif result.returncode == 0 and len(result.stdout) <= 16 * 1024:
            try:
                fields: dict[str, str] = {}
                for line in result.stdout.decode("ascii").splitlines():
                    if "=" not in line:
                        raise ValueError
                    name, content = line.split("=", 1)
                    if name in fields:
                        raise ValueError
                    fields[name] = content
                if (set(fields) != properties
                        or fields["LoadState"] not in {"loaded", "not-found"}
                        or fields["ActiveState"] not in {"inactive", "failed"}
                        or fields["SubState"] not in {"dead", "failed"}):
                    raise ValueError
                cgroup = fields["ControlGroup"]
                if cgroup:
                    if (not cgroup.startswith("/")
                            or ".." in Path(cgroup).parts
                            or not cgroup.endswith("/" + unit)):
                        raise ValueError
                    try:
                        processes = (
                            cgroup_root / cgroup.lstrip("/") / "cgroup.procs"
                        ).read_bytes()
                    except FileNotFoundError:
                        processes = b""
                    if processes.strip():
                        raise ValueError
                absent = True
            except (OSError, UnicodeDecodeError, ValueError):
                absent = False
        if absent and process_start_time is not None:
            try:
                observed_start = (
                    native_codex_session_controller.run_journal
                    .process_start_time(process_id, proc_root=proc_root)
                )
            except FileNotFoundError:
                observed_start = None
            except (OSError, ValueError,
                    native_codex_session_controller.run_journal
                    .NativeCodexRunJournalError):
                absent = False
            else:
                if observed_start == process_start_time:
                    absent = False
                    last_error = "native_claude_login_process_live"
        if absent:
            consecutive += 1
            if consecutive == 2:
                return
        else:
            consecutive = 0
        sleeper(0.02)
    raise NativeClaudeLoginError(last_error)


def _resume_owned_login_child(
    child: int, owner_custody: object, *, deadline: float,
    trusted_uid: int, trusted_gid: int, systemctl: Path,
    cgroup_root: Path, proc_root: Path,
    owner_scope_verifier: Callable[..., dict[str, object]],
    monotonic: Callable[[], float] = time.monotonic,
    signaler: Callable[[int, int], None] = os.kill,
) -> None:
    """Revalidate exact owner lifetime and deadline at the resume boundary."""
    owner_readback = owner_scope_verifier(
        owner_custody.unit,
        watcher_pid=owner_custody.watcher_pid,
        watcher_start_time_ticks=owner_custody.watcher_start_time_ticks,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        expected_runtime_max_usec=owner_custody.runtime_max_usec,
        systemctl=systemctl, cgroup_root=cgroup_root, proc_root=proc_root)
    if owner_readback.get("cgroup") != owner_custody.cgroup:
        raise NativeClaudeLoginError(
            "native_claude_login_owner_scope_changed")
    _remaining_runtime_usec(deadline, monotonic=monotonic)
    signaler(child, signal.SIGCONT)


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
    owner_scope_factory: Callable[..., object] = (
        native_codex_session_controller.create_controller_owner_scope),
    owner_scope_verifier: Callable[..., dict[str, object]] = (
        native_codex_session_controller.verify_controller_owner_scope),
    owner_scope_releaser: Callable[..., None] = (
        native_codex_session_controller.release_controller_owner_scope),
    busctl: Path = native_codex_session_controller.BUSCTL,
    systemctl: Path = native_codex_session_controller.SYSTEMCTL,
    cgroup_root: Path = native_codex_session_controller.CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    now: Callable[[], int] = lambda: int(time.time()),
    monotonic: Callable[[], float] = time.monotonic,
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
    deadline = monotonic() + MAXIMUM_SECONDS
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
    service = controller._identity(controller.CLAUDE_IDENTITY)
    environment = native_claude_adapter.login_environment(
        stack, harness, home=controller.CLAUDE_HOME,
        config_root=controller.CLAUDE_CONFIG_ROOT)
    master, slave = pty.openpty()
    _copy_terminal_size(input_fd, slave)
    unit = "secure-sandbox-native-run-" + operation_id.replace("-", "") + ".scope"
    owner_unit = (
        "secure-sandbox-native-owner-" + operation_id.replace("-", "")
        + ".scope"
    )
    command = native_claude_adapter.login_command(executable)
    child = -1
    child_identity = -1
    process_start_time: int | None = None
    owner_custody: object | None = None
    transport_error: BaseException | None = None
    containment_errors: list[BaseException] = []
    try:
        owner_runtime_max_usec = _remaining_runtime_usec(
            deadline, monotonic=monotonic)
        owner_custody = owner_scope_factory(
            owner_unit, runtime_max_usec=owner_runtime_max_usec,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            busctl=busctl, systemctl=systemctl,
            cgroup_root=cgroup_root, proc_root=proc_root)
        expected_vendor_parent_pid = os.getpid()
        child = os.fork()
        if child == 0:  # pragma: no cover - stopped exec-only child
            try:
                native_codex_session_controller._arm_vendor_parent_death_signal(
                    expected_vendor_parent_pid)
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                os.setgroups([])
                os.setgid(service.pw_gid)
                os.setuid(service.pw_uid)
                native_codex_session_controller._arm_vendor_parent_death_signal(
                    expected_vendor_parent_pid)
                for descriptor in (0, 1, 2):
                    if slave != descriptor:
                        os.dup2(slave, descriptor)
                maximum = os.sysconf("SC_OPEN_MAX")
                os.closerange(3, maximum if maximum > 3 else 1024)
                os.kill(os.getpid(), 19)  # SIGSTOP before any vendor exec
                os.execve(executable, command, environment)
            except BaseException:
                os._exit(126)
        child_identity = child
        os.close(slave)
        slave = -1
        waited, status = os.waitpid(child, os.WUNTRACED)
        if (waited != child or not os.WIFSTOPPED(status)
                or os.WSTOPSIG(status) != 19):
            raise NativeClaudeLoginError("native_claude_login_child_gate_failed")
        process_start_time = (
            native_codex_session_controller.run_journal.process_start_time(
                child, proc_root=proc_root
            )
        )
        runtime_max_usec = _remaining_runtime_usec(
            deadline, monotonic=monotonic
        )
        scope_starter(
            unit, child, owner_unit=owner_unit,
            runtime_max_usec=runtime_max_usec, busctl=busctl
        )
        scope_verifier(
            unit, owner_unit=owner_unit, launcher_uid=service.pw_uid,
            launcher_gid=service.pw_gid,
            systemctl=systemctl, cgroup_root=cgroup_root,
            proc_root=proc_root,
            expected_runtime_max_usec=runtime_max_usec)
        _remaining_runtime_usec(deadline, monotonic=monotonic)
        if owner_custody is None:
            raise NativeClaudeLoginError(
                "native_claude_login_owner_scope_missing")
        _resume_owned_login_child(
            child, owner_custody, deadline=deadline,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            systemctl=systemctl, cgroup_root=cgroup_root,
            proc_root=proc_root, owner_scope_verifier=owner_scope_verifier,
            monotonic=monotonic)
        if relay_opaque_pty(
            child, master, input_fd=input_fd, output_fd=output_fd,
            deadline=deadline, monotonic=monotonic) != 0:
            raise NativeClaudeLoginError("native_claude_login_process_failed")
        child = -1
    except BaseException as error:
        transport_error = error
    finally:
        try:
            stopped = subprocess.run(
                [str(systemctl), "stop", unit], check=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if stopped.returncode not in {0, 3, 4, 5}:
                containment_errors.append(NativeClaudeLoginError(
                    "native_claude_login_scope_stop_failed"))
        except (OSError, subprocess.SubprocessError) as error:
            containment_errors.append(error)
        if child > 0:
            try:
                _terminate_direct_child(child)
            except BaseException as error:
                containment_errors.append(error)
        if slave >= 0:
            try:
                os.close(slave)
            except OSError as error:
                containment_errors.append(error)
        try:
            os.close(master)
        except OSError as error:
            containment_errors.append(error)
    absence_error: BaseException | None = None
    if child_identity > 0:
        try:
            _prove_scope_absent(
                unit, process_id=child_identity,
                process_start_time=process_start_time, systemctl=systemctl,
                cgroup_root=cgroup_root, proc_root=proc_root)
        except BaseException as error:
            absence_error = error
    try:
        if owner_custody is not None:
            owner_scope_releaser(
                owner_custody, systemctl=systemctl,
                cgroup_root=cgroup_root, proc_root=proc_root)
            owner_custody = None
    except BaseException as error:
        containment_errors.append(error)
    if absence_error is not None and child_identity > 0:
        # Releasing the independently bound owner is a second fail-closed stop
        # trigger. Re-read absence after that trigger, but retain the original
        # cleanup ambiguity so no proof is published from an abnormal path.
        try:
            _prove_scope_absent(
                unit, process_id=child_identity,
                process_start_time=process_start_time, systemctl=systemctl,
                cgroup_root=cgroup_root, proc_root=proc_root)
        except BaseException as error:
            containment_errors.append(error)
        containment_errors.append(absence_error)
    if owner_custody is not None:
        try:
            owner_scope_releaser(
                owner_custody, systemctl=systemctl,
                cgroup_root=cgroup_root, proc_root=proc_root)
        except BaseException as error:
            containment_errors.append(error)
    if containment_errors:
        failure = containment_errors[0]
        if transport_error is not None:
            raise failure from transport_error
        raise failure
    if transport_error is not None:
        raise transport_error
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
            native_claude_adapter.NativeClaudeAdapterError,
            native_codex_session_controller.NativeCodexSessionError,
            OSError, subprocess.SubprocessError):
        # The terminal receives only one fixed failure. Provider details remain
        # inside the credential compartment and no interactive bytes are kept.
        os.write(1, b"\r\nSecureSandbox login verification failed.\r\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
