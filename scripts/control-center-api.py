#!/usr/bin/env python3
"""Bounded, versioned host bridge for the Control Center app."""

from __future__ import annotations

import argparse
import hashlib
import io
import importlib.util
import json
import os
import plistlib
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from gateway import run_lease as run_lease_contract  # noqa: E402
from shared import native_program_attestation  # noqa: E402
from shared import native_projection_identity_recovery  # noqa: E402
from shared import native_projection_reconciliation  # noqa: E402
from shared import native_codex_ui_handle  # noqa: E402
from shared import native_deployment  # noqa: E402
from shared import native_stack_catalog_promotion  # noqa: E402
from shared import native_stack_operations  # noqa: E402
from shared import native_stack_session  # noqa: E402
from shared import native_terminal_handle  # noqa: E402
from shared import native_vendor_stack  # noqa: E402

LABCTL = ROOT / "scripts" / "labctl"
SCHEMA = "secure-sandbox-control-center-v1"
MAX_OUTPUT = 8 * 1024 * 1024
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MODEL_PROFILE_CONFIG = ROOT / "scripts/model-profile-config.py"
NATIVE_VENDOR_STACK_CONFIG = ROOT / "scripts/native-vendor-stack-config.py"
NATIVE_STACK_OPERATION = ROOT / "scripts/native-stack-operation.py"
NATIVE_STACK_STAGED_CATALOG = ROOT / "config/native-vendor-stacks.json"
NATIVE_STACK_PLAN_ROOT = ROOT / "runs/native-stack-operation-plans"
NATIVE_STACK_PROMOTION_PLAN_ROOT = ROOT / "runs/native-stack-catalog-promotion-plans"
NATIVE_PRIVILEGED_OPERATION_TIMEOUT_SECONDS = 60 * 60 + 300
NATIVE_AUTHORIZATION_REQUEST_TTL_SECONDS = 180
NATIVE_AUTHORIZATION_COMPLETION_MARGIN_SECONDS = 60
NATIVE_PRIVILEGED_AUTHORIZATION_TIMEOUT_SECONDS = (
    NATIVE_PRIVILEGED_OPERATION_TIMEOUT_SECONDS
    + NATIVE_AUTHORIZATION_REQUEST_TTL_SECONDS
    + NATIVE_AUTHORIZATION_COMPLETION_MARGIN_SECONDS
)
# The Control Center request must outlive the complete authorization client:
# request ceremony, bounded root operation, and terminal-result handoff.
NATIVE_PRIVILEGED_CLIENT_TIMEOUT_SECONDS = (
    NATIVE_PRIVILEGED_AUTHORIZATION_TIMEOUT_SECONDS + 60
)
NATIVE_PRIVILEGED_STDERR_LIMIT = 64 * 1024
NATIVE_PROGRAM_ATTESTATION_PLAN_ROOT = (
    ROOT / "runs/native-program-attestation-plans"
)
HOST_CONTROLLER_CURRENT = Path("/usr/local/libexec/secure-sandbox-host/current")
NATIVE_STACK_CATALOG_PROMOTER = HOST_CONTROLLER_CURRENT / "native_stack_catalog_promoter"
AUTHORIZATION_BROKER = HOST_CONTROLLER_CURRENT / "authorization_broker"
AUTHORIZATION_REQUEST_ROOT = (
    Path.home()
    / "Library/Application Support/SecureSandbox/authorization-requests"
)
HARNESS_LIFECYCLE_OPERATION = ROOT / "scripts/harness-lifecycle-operation.py"
HARNESS_PLAN_ROOT = ROOT / "runs/harness-lifecycle-plans"
HARNESS_ACCEPTANCE = ROOT / "scripts/harness-lifecycle-acceptance.py"
HARNESS_ACCEPTANCE_ROOT = (Path.home() / "Library/Application Support/SecureSandbox"
                           / "harness-acceptance")
NATIVE_DEPLOYMENT_QUERY_SCHEMAS = {
    "plan": "secure-sandbox-native-deployment-plan-request-v1",
    "status": "secure-sandbox-native-deployment-status-request-v1",
    "recovery-plan": (
        "secure-sandbox-native-deployment-recovery-plan-request-v1"
    ),
}
NATIVE_DEPLOYMENT_REPLY_SCHEMAS = {
    "plan": "secure-sandbox-native-deployment-plan-reply-v1",
    "status": "secure-sandbox-native-deployment-status-reply-v1",
    "recovery-plan": (
        "secure-sandbox-native-deployment-recovery-plan-reply-v1"
    ),
}
NATIVE_DEPLOYMENT_QUERY_ERROR_SCHEMA = (
    "secure-sandbox-native-deployment-query-error-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_COMMAND = "catalog-promotion-gate"
NATIVE_CATALOG_PROMOTION_GATE_REQUEST_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-request-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_REPLY_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-reply-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_ERROR_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-error-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-state-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND = (
    "catalog-promotion-recover-active"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_REQUEST_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-request-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_REPLY_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-reply-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_ERROR_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-error-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_TERMINAL_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-terminal-v1"
)


class HarnessBridgeError(RuntimeError):
    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def host_error(raw: bytes, status: int) -> str:
    messages = {
        "github_status_422": "GitHub did not accept that ref. Check the branch or tag name.",
        "github_status_404": "The public repository or ref was not found.",
        "github_status_403": "GitHub denied the source lookup. Try again after its rate limit resets.",
        "endpoint_unavailable": "The Gateway could not reach its pinned source endpoint.",
        "fetcher_failed": "The Gateway source fetcher failed. Check source acquisition diagnostics.",
        "operation_invalid": "The installed host controller does not recognize this operation. Check its deployed release before retrying.",
    }
    for line in reversed(raw.decode("utf-8", "replace").splitlines()[-12:]):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == "secure-sandbox-host-lifecycle-v1":
            phase = value.get("phase")
            failures = value.get("action_failures")
            if (isinstance(phase, str) and re.fullmatch(r"[a-z_]{1,40}", phase)
                    and isinstance(failures, list) and 0 < len(failures) <= 10
                    and all(isinstance(item, str) and re.fullmatch(r"[a-z_]{1,80}", item) for item in failures)):
                if phase == "boundary_verification" and failures == ["boundary_verification_failed"]:
                    return ("The VMs started, but boundary acceptance failed. Refresh live VM status, "
                            "then run Boundary Verification in Maintenance to see the failed checks.")
                if phase == "readback" and failures == ["parallels_service_unavailable"]:
                    return "Parallels Desktop needs to be started."
                if phase == "readback" and failures == ["parallels_service_response_invalid"]:
                    return ("Parallels Desktop returned an invalid service response. VM state remains "
                            "untrusted; restart Parallels Desktop, quit it, and refresh SecureSandbox.")
                return (f"The VM transition stopped during {phase}: {', '.join(failures)}. "
                        "Refresh live status before another action.")
        code = value.get("error") if isinstance(value, dict) else None
        if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,80}", code):
            return messages.get(code, f"The host rejected the operation ({code}).")
    return f"The host operation failed with status {status}."


def run_labctl(*args: str) -> str:
    # No shell. Callers validate every variable argument before this boundary.
    timeout = (1200 if args in (("start",), ("stop",))
               else 600 if args[:2] in (("source", "apply"), ("dependencies", "apply"), ("corpus", "index"), ("codegraph", "index")) or args == ("verify",)
               else 330 if args[:2] == ("source", "plan")
               else 300 if args[:1] == ("transcript",)
               else 180 if args == ("artifacts",) or args[:1] == ("artifact",)
               else 30)
    completed = bounded_command([str(LABCTL), *args], timeout=timeout)
    if completed.returncode:
        raise RuntimeError(host_error(completed.stderr[-4096:], completed.returncode))
    return completed.stdout.decode("utf-8", "strict")


PROCESS_GROUP_ENV = "SECURE_SANDBOX_OWNED_PROCESS_GROUP"
PARENT_LIVENESS_ENV = "SECURE_SANDBOX_PARENT_LIVENESS_FD"
PARENT_INPUT_LENGTH_ENV = "SECURE_SANDBOX_PARENT_INPUT_LENGTH"
SUPERVISOR_LIVENESS_ENV = "SECURE_SANDBOX_SUPERVISOR_LIVENESS_FD"
SUPERVISOR_DISARM = b"D"
MAX_PARENT_INPUT = 64 * 1024 * 1024


class ControlCenterInterrupted(BaseException):
    """Owner-lifetime revocation that ordinary catalog recovery cannot catch."""


def _start_parent_liveness_monitor() -> threading.Thread | None:
    """Stage exact input, then unwind normally if the Swift owner vanishes."""
    marker = os.environ.pop(PARENT_LIVENESS_ENV, None)
    length_marker = os.environ.pop(PARENT_INPUT_LENGTH_ENV, None)
    if marker is None:
        if length_marker is not None:
            raise RuntimeError("control_center_parent_input_length_invalid")
        return None
    if marker != "0" or length_marker is None:
        raise RuntimeError("control_center_parent_liveness_fd_invalid")
    if (not length_marker.isascii() or not length_marker.isdecimal()
            or len(length_marker) > 8):
        raise RuntimeError("control_center_parent_input_length_invalid")
    input_length = int(length_marker)
    if str(input_length) != length_marker or input_length > MAX_PARENT_INPUT:
        raise RuntimeError("control_center_parent_input_length_invalid")
    try:
        info = os.fstat(0)
    except OSError as error:
        raise RuntimeError("control_center_parent_liveness_fd_invalid") from error
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError("control_center_parent_liveness_fd_invalid")
    probe: socket.socket | None = None
    probe_descriptor = -1
    try:
        probe_descriptor = os.dup(0)
        probe = socket.socket(fileno=probe_descriptor)
        probe_descriptor = -1
        if (probe.family != socket.AF_UNIX
                or probe.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                    != socket.SOCK_STREAM):
            raise RuntimeError("control_center_parent_liveness_fd_invalid")
    except OSError as error:
        raise RuntimeError("control_center_parent_liveness_fd_invalid") from error
    finally:
        if probe is not None:
            probe.close()
        elif probe_descriptor >= 0:
            os.close(probe_descriptor)
    monitor_descriptor = -1
    try:
        os.set_inheritable(0, False)
        monitor_descriptor = os.dup(0)
        os.set_inheritable(monitor_descriptor, False)
    except OSError as error:
        if monitor_descriptor >= 0:
            os.close(monitor_descriptor)
        raise RuntimeError("control_center_parent_liveness_fd_invalid") from error

    staged = bytearray()
    try:
        while len(staged) < input_length:
            try:
                block = os.read(0, min(64 * 1024, input_length - len(staged)))
            except InterruptedError:
                continue
            if not block:
                raise RuntimeError("control_center_parent_input_truncated")
            staged.extend(block)
    except BaseException:
        os.close(monitor_descriptor)
        raise

    # Command parsing reads from this bounded private copy. fd 0 and its
    # duplicate now carry only the silent owner-liveness protocol; neither is
    # inheritable across an exec.
    sys.stdin = io.TextIOWrapper(
        io.BytesIO(bytes(staged)), encoding="utf-8", errors="strict"
    )

    def monitor() -> None:
        # Cancellation signals belong to the main-thread unwind handler. Do not
        # let this auxiliary reader become their delivery thread during spawn.
        signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
        )
        try:
            # After the exact staged byte count, the protocol is silence while
            # Swift is alive. EOF or any extra byte revokes this invocation.
            os.read(monitor_descriptor, 1)
        except OSError:
            pass
        finally:
            try:
                os.close(monitor_descriptor)
            except OSError:
                pass
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except ProcessLookupError:
            pass

    thread = threading.Thread(
        target=monitor, name="control-center-parent-liveness", daemon=True,
    )
    thread.start()
    return thread


def _command_group_exists(group: int) -> bool:
    """Read back group presence without treating a teardown race as live.

    macOS can transiently return ``EPERM`` when the last member disappears
    between process-group lookup and ``kill(2)``.  A second independent
    readback distinguishes that race from a persistently unsignalable group;
    persistent ambiguity remains fail closed.
    """
    for attempt in range(2):
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return False
        except PermissionError as error:
            if attempt == 0:
                time.sleep(0.02)
                continue
            raise RuntimeError(
                "bounded_command_process_group_readback_denied"
            ) from error
        return True
    raise RuntimeError("bounded_command_process_group_readback_denied")


def _signal_owned_command_group(group: int, signum: int) -> None:
    try:
        os.killpg(group, signum)
    except ProcessLookupError:
        return
    except PermissionError as error:
        # The final member may have disappeared after our preceding readback.
        # Suppress only when two subsequent observations prove absence.
        if not _command_group_exists(group):
            return
        raise RuntimeError(
            "bounded_command_process_group_signal_denied"
        ) from error


def _terminate_owned_command_group(process: subprocess.Popen[bytes]) -> None:
    """Stop an owned command group, including descendants of a dead leader."""
    _signal_owned_command_group(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    if _command_group_exists(process.pid):
        _signal_owned_command_group(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("bounded_command_process_unreaped") from error
    deadline = time.monotonic() + 2
    while _command_group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    if _command_group_exists(process.pid):
        raise RuntimeError("bounded_command_process_group_unreaped")


def _new_authorization_request_id() -> str:
    return str(uuid.uuid4())


def _invalidate_authorization_request(request_id: str) -> None:
    """Revoke a UI challenge by removing the exact one-shot request.

    The root broker's ``execute_request`` rereads this file after the UI returns
    its biometric decision. Thus even a LaunchServices-owned GUI that outlives
    its launcher has no mutation authority after this supervisor cancels it.
    """
    if UUID4.fullmatch(request_id) is None:
        raise ValueError("authorization_request_id_invalid")
    try:
        descriptor = os.open(
            AUTHORIZATION_REQUEST_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("authorization_request_directory_untrusted")
        name = f"{request_id}.json"
        try:
            os.unlink(name, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.fsync(descriptor)
        try:
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError("authorization_request_invalidation_failed")
    finally:
        os.close(descriptor)


def bounded_authorization_command(
    command: list[str], *, timeout: int, env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    request_id = str(uuid.uuid4())
    try:
        return bounded_command(
            [*command, "--request-id", request_id], timeout=timeout, env=env,
            supervise_on_parent_exit=True,
        )
    finally:
        # LaunchServices owns the GUI process lifetime. Authority remains ours:
        # the root broker rereads this one-shot file immediately before commit.
        _invalidate_authorization_request(request_id)


def native_stack_authorization_timeout(action: str) -> int:
    """Outlive the unprivileged wrapper by at least one delivery margin."""
    if action == "signin-begin":
        return 1560
    if action in {"entitlement-verify", "logout"}:
        return 960
    return 720


def bounded_command(command: list[str], *, timeout: int,
                    env: dict[str, str] | None = None,
                    supervise_on_parent_exit: bool = False,
                    ) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ) if env is None else dict(env)
    environment.pop(PARENT_LIVENESS_ENV, None)
    environment.pop(PARENT_INPUT_LENGTH_ENV, None)
    environment.pop(SUPERVISOR_LIVENESS_ENV, None)
    environment[PROCESS_GROUP_ENV] = "bootstrap"
    custody_read = -1
    custody_write = -1
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    custody_disarmed = False
    if supervise_on_parent_exit:
        custody_read, custody_write = os.pipe()
        environment[SUPERVISOR_LIVENESS_ENV] = str(custody_read)
    try:
        # A TERM/INT must not raise between Popen returning and the child object
        # becoming cleanup-owned. Briefly defer the Python handler instead of
        # masking the signal: a POSIX signal mask would be inherited across exec
        # and could make the new command group immune to our TERM cleanup.
        deferred_signals: list[int] = []
        previous_handlers = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }

        def defer_spawn_signal(signum: int, _frame: object) -> None:
            if not deferred_signals:
                deferred_signals.append(signum)

        for signum in previous_handlers:
            signal.signal(signum, defer_spawn_signal)
        try:
            process = subprocess.Popen(
                command, cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                pass_fds=(() if custody_read < 0 else (custody_read,)),
                env=environment, start_new_session=True,
            )
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        if deferred_signals:
            signum = deferred_signals[0]
            handler = previous_handlers[signum]
            if callable(handler):
                handler(signum, None)
            raise RuntimeError(f"bounded_command_interrupted_{signum}")
        if custody_read >= 0:
            os.close(custody_read)
            custody_read = -1
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("bounded_command_stream_unavailable")
        stdout = bytearray()
        stderr = bytearray()
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is process.stdout:
                    stdout.extend(chunk)
                    if len(stdout) > MAX_OUTPUT:
                        raise ValueError("catalog response exceeds its size limit")
                else:
                    stderr.extend(chunk)
                    if len(stderr) > 4096:
                        del stderr[:-4096]
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if _command_group_exists(process.pid):
            _terminate_owned_command_group(process)
            raise RuntimeError("bounded_command_descendant_unreaped")
        custody_disarmed = True
        return subprocess.CompletedProcess(command, process.returncode, bytes(stdout), bytes(stderr))
    except BaseException as original_error:
        if process is not None:
            try:
                # This try begins before Popen, so signals and setup failures in
                # every post-spawn window synchronously terminate and prove the
                # exact private session absent before the original error escapes.
                _terminate_owned_command_group(process)
                custody_disarmed = True
            except BaseException as cleanup_error:
                # Loss of exact group-absence proof is more security-significant
                # than the triggering error. Keep the custody pipe armed while
                # it closes, and preserve the original as the explicit cause.
                # Owner revocation is the one exception to changing exception
                # type: converting it back to RuntimeError would let a catalog
                # recovery block swallow the revocation and launch more work.
                if isinstance(original_error, ControlCenterInterrupted):
                    raise ControlCenterInterrupted(
                        "control_center_interrupted_cleanup_unverified"
                    ) from cleanup_error
                raise cleanup_error from original_error
        raise
    finally:
        if custody_write >= 0:
            if custody_disarmed:
                try:
                    os.write(custody_write, SUPERVISOR_DISARM)
                except OSError:
                    pass
            try:
                os.close(custody_write)
            except OSError:
                pass
        if custody_read >= 0:
            try:
                os.close(custody_read)
            except OSError:
                pass
        if selector is not None:
            try:
                selector.close()
            except OSError:
                pass
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


def table(raw: str, width: int, header: str | None = None) -> list[list[str]]:
    lines = raw.splitlines()
    if header is not None:
        if not lines or lines.pop(0) != header:
            raise ValueError("catalog header is invalid")
    rows = [line.split("\t") for line in lines]
    if any(len(row) != width for row in rows) or len(rows) > 10_000:
        raise ValueError("catalog row is invalid")
    return rows


def catalog(name: str) -> list[dict] | dict:
    if name == "maintenance":
        return maintenance()
    raw = run_labctl({"overview": "status", "sessions": "sessions", "sources": "sources", "findings": "findings", "activity": "logs", "artifacts": "artifacts"}[name])
    if name == "overview":
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-host-lifecycle-v1":
            raise ValueError("host status schema is invalid")
        observed = value.get("observed")
        if not isinstance(observed, dict) or any(observed.get(vm) not in ("running", "stopped", "paused", "suspended") for vm in ("gateway", "research", "target")):
            raise ValueError("VM status is invalid")
        if value.get("status") not in ("verified", "degraded", "failed"):
            raise ValueError("host status is invalid")
        return value
    if name == "sessions":
        rows = table(raw, 7, "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL")
        if any(UUID.fullmatch(row[0]) is None for row in rows):
            raise ValueError("session ID is invalid")
        return [dict(zip(("id", "created_at", "last_at", "turns", "compacts", "runs", "label"), row)) for row in rows]
    if name == "sources":
        rows = table(raw, 5)
        if any(UUID.fullmatch(row[1]) is None or SHA.fullmatch(row[3]) is None for row in rows):
            raise ValueError("source identity is invalid")
        return [dict(zip(("imported_at", "id", "repository", "commit", "worktree"), row)) for row in rows]
    if name == "artifacts":
        rows = table(raw, 6)
        if any(UUID.fullmatch(row[1]) is None or (row[4] != "preflight" and UUID.fullmatch(row[4]) is None)
               or re.fullmatch(r"v[1-9][0-9]{0,8}", row[2]) is None
               or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(md|txt|json)", row[3]) is None
               or re.fullmatch(r"[0-9a-f]{64}", row[5]) is None for row in rows):
            raise ValueError("Artifact catalog identity is invalid")
        return [dict(zip(("captured_at", "id", "version", "file_name", "run_id", "sha256"), row)) for row in rows]
    if name == "activity":
        lines = raw.splitlines()
        if len(lines) > 1_000:
            raise ValueError("activity catalog exceeds its record limit")
        events = []
        for sequence, line in enumerate(lines):
            row = json.loads(line)
            if (not isinstance(row, dict) or not isinstance(row.get("TimeGenerated"), str)
                    or not isinstance(row.get("EventType"), str)
                    or not isinstance(row.get("Severity"), str)):
                raise ValueError("activity record is invalid")
            event = {key: row.get(key) for key in
                     ("TimeGenerated", "EventType", "Severity", "Decision", "Status", "VmId", "Message")}
            event["sequence"] = sequence
            if any(isinstance(value, str) and len(value) > 500 for value in event.values()):
                raise ValueError("activity field exceeds its size limit")
            events.append(event)
        return events
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) > 10_000 or any(not isinstance(row, dict) or UUID.fullmatch(str(row.get("finding_id", ""))) is None for row in value):
        raise ValueError("findings catalog is invalid")
    return value


def maintenance() -> dict[str, str]:
    result = {}
    try:
        check_time_output(run_labctl("time-sync"))
        result["time_sync"] = "verified"
    except (RuntimeError, ValueError):
        result["time_sync"] = "attention"
    try:
        raw = run_labctl("snapshots")
        if len(raw.splitlines()) != 3:
            raise ValueError("snapshot response is invalid")
        result["snapshot_policy"] = "verified"
    except (RuntimeError, ValueError):
        result["snapshot_policy"] = "attention"
    return result


def check_time_output(raw: str) -> None:
    lines = raw.splitlines()
    names = ("sandbox-gateway", "sandbox-research-admin", "sandbox-target-admin")
    matches = [re.fullmatch(re.escape(name) + r": skew=([0-9]+)s", line)
               for name, line in zip(names, lines[:3])]
    if (len(lines) != 4 or len(matches) != 3 or any(match is None or int(match[1]) > 5 for match in matches)
            or lines[-1] != "SecureSandbox guest clocks are within 5s of the Mac."):
        raise ValueError("Time synchronization response is invalid")


def _harness_json(command: tuple[str, ...], *, timeout: int = 60) -> dict:
    completed = bounded_command([str(LABCTL), "harness", *command], timeout=timeout)
    if completed.returncode:
        raw = completed.stderr[-4096:]
        code = None
        for line in reversed(raw.decode("utf-8", "replace").splitlines()[-12:]):
            try:
                rejected = json.loads(line)
            except json.JSONDecodeError:
                continue
            candidate = rejected.get("error") if isinstance(rejected, dict) else None
            if isinstance(candidate, str) and re.fullmatch(r"[a-z0-9_]{1,80}", candidate):
                code = candidate
                break
        raise HarnessBridgeError(host_error(raw, completed.returncode), code)
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Harness response is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("Harness response is invalid")
    return value


def _harness_sha(value: object) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def harness_status() -> dict:
    value = _harness_json(("status",))
    expected = {"authority", "automatic_download", "automatic_install", "floor",
                "generations", "policy_configured", "policy_sha256", "schema"}
    if (set(value) != expected
            or value.get("schema") != "secure-sandbox-harness-lifecycle-status-v1"
            or value.get("authority") != "none"
            or value.get("automatic_download") is not False
            or value.get("automatic_install") is not False
            or not isinstance(value.get("policy_configured"), bool)
            or not isinstance(value.get("generations"), list)
            or len(value["generations"]) > 64):
        raise ValueError("Harness lifecycle status is invalid")
    for generation in value["generations"]:
        if (not isinstance(generation, dict)
                or set(generation) != {"artifact_present", "generation_id", "manifest_present", "state"}
                or not _harness_sha(generation.get("generation_id"))
                or generation.get("state") != "quarantined"
                or not isinstance(generation.get("artifact_present"), bool)
                or not isinstance(generation.get("manifest_present"), bool)):
            raise ValueError("Harness quarantine generation is invalid")
    if value["policy_configured"] != _harness_sha(value.get("policy_sha256")):
        raise ValueError("Harness policy status is invalid")
    floor = value.get("floor")
    if floor is not None and (not isinstance(floor, dict)
            or set(floor) != {"envelope_sha256", "policy_sha256", "schema", "sequence"}
            or floor.get("schema") != "secure-sandbox-harness-metadata-floor-v1"
            or not isinstance(floor.get("sequence"), int) or floor["sequence"] < 1
            or not _harness_sha(floor.get("envelope_sha256"))
            or not _harness_sha(floor.get("policy_sha256"))):
        raise ValueError("Harness metadata floor is invalid")
    protected: dict
    try:
        protected_value = _harness_json(("protected-status",), timeout=30)
        active = protected_value.get("active_generation_id")
        predecessor = protected_value.get("predecessor_generation_id")
        revoked = protected_value.get("revoked_generation_ids")
        if (protected_value.get("schema") != "secure-sandbox-harness-generation-status-v1"
                or protected_value.get("status") != "verified"
                or protected_value.get("admission") not in {"open", "fenced"}
                or not isinstance(protected_value.get("recovery_pending"), bool)
                or (active is not None and not _harness_sha(active))
                or (predecessor is not None and not _harness_sha(predecessor))
                or not isinstance(protected_value.get("selector_epoch"), int)
                or not isinstance(protected_value.get("highest_release_sequence"), int)
                or not isinstance(revoked, list) or any(not _harness_sha(item) for item in revoked)
                or not isinstance(protected_value.get("generations"), list)
                or len(protected_value["generations"]) > 64):
            raise ValueError("Protected harness generation status is invalid")
        protected = {"availability": "available", "reason": None, "status": protected_value}
    except HarnessBridgeError as error:
        if error.code == "operation_invalid":
            protected = {"availability": "unavailable",
                         "reason": "protected_generation_consumer_not_deployed", "status": None}
        else:
            protected = {"availability": "rejected",
                         "reason": "protected_status_verification_failed", "status": None}
    protected_value = protected.get("status") if protected.get("availability") == "available" else None
    active = protected_value.get("active_generation_id") if protected_value else None
    predecessor = protected_value.get("predecessor_generation_id") if protected_value else None
    retained = [item for item in protected_value.get("generations", [])
                if item.get("status") == "retained"] if protected_value else []
    eligible_management = [item for item in retained
                           if item.get("generation_id") not in {active, predecessor}]
    qualified_candidate = any(
        all((ROOT / ".private/harness-lifecycle/admission" / item["generation_id"] / name).is_file()
            for name in ("artifact", "manifest.json", "verification.json",
                         "qualification.json", "adapter.json"))
        for item in value["generations"]
    )
    usable = protected_value is not None and protected_value.get("admission") == "open"
    return {"schema": "secure-sandbox-harness-control-center-status-v1",
            "lifecycle": value, "protected": protected,
            "protected_actions": {
                "activate": bool(usable and qualified_candidate),
                "rollback": bool(usable and predecessor),
                "retire": bool(usable and eligible_management),
                "revoke": bool(usable and eligible_management),
                "recover": bool(protected_value and protected_value.get("recovery_pending")),
                "requires_touch_id": True, "password_fallback": False,
            }}


def harness_action(action: str, generation_id: str | None = None) -> dict:
    if action == "check":
        value = _harness_json(("check",), timeout=90)
        if (value.get("schema") != "secure-sandbox-harness-lifecycle-receipt-v1"
                or value.get("action") != "check" or value.get("status") != "metadata_verified"
                or UUID4.fullmatch(str(value.get("receipt_id", ""))) is None):
            raise ValueError("Harness metadata receipt is invalid")
        return value
    if action in {"acquire", "verify"}:
        if generation_id is None or not _harness_sha(generation_id):
            raise ValueError("Harness generation identity is invalid")
        value = _harness_json((action, generation_id), timeout=600 if action == "acquire" else 90)
        accepted_status = ({"artifact_quarantined", "already_acquired"} if action == "acquire"
                           else {"artifact_and_evidence_bindings_verified"})
        if (value.get("schema") != "secure-sandbox-harness-lifecycle-receipt-v1"
                or value.get("action") != action
                or value.get("status") not in accepted_status
                or value.get("generation_id") != generation_id
                or UUID4.fullmatch(str(value.get("receipt_id", ""))) is None):
            raise ValueError("Harness lifecycle receipt is invalid")
        return value
    if action == "qualify-self-test":
        value = _harness_json((action,), timeout=300)
        cases = value.get("case_results")
        if (value.get("schema") != "secure-sandbox-harness-qualification-report-v1"
                or value.get("status") != "fixture_qualified" or value.get("authority") != "none"
                or value.get("note") != "fixture_qualified_not_admitted"
                or not isinstance(cases, list) or not 1 <= len(cases) <= 64
                or any(not isinstance(item, dict) or item.get("status") != "passed"
                       or not isinstance(item.get("failures"), list)
                       or item.get("failures") for item in cases)
                or not _harness_sha(value.get("report_sha256"))):
            raise ValueError("Harness qualification self-test report is invalid")
        return value
    raise ValueError("Harness lifecycle action is invalid")


def harness_releases() -> dict:
    value = _harness_json(("releases",), timeout=60)
    releases = value.get("releases")
    if (value.get("schema") != "secure-sandbox-harness-release-catalog-v1"
            or value.get("authority") != "signed-metadata-only"
            or not isinstance(value.get("sequence"), int) or value["sequence"] < 1
            or not _harness_sha(value.get("envelope_sha256"))
            or not _harness_sha(value.get("policy_sha256"))
            or not isinstance(releases, list) or not 1 <= len(releases) <= 64):
        raise ValueError("Harness release catalog is invalid")
    for release in releases:
        if (not isinstance(release, dict)
                or not _harness_sha(release.get("generation_id"))
                or not isinstance(release.get("evidence"), list)
                or not isinstance(release.get("compatibility"), dict)
                or not isinstance(release.get("artifact"), dict)
                or not _harness_sha(release["artifact"].get("sha256"))
                or not _harness_sha(release["compatibility"].get("adapter_sha256"))):
            raise ValueError("Harness release entry is invalid")
    return value


def _harness_operation(arguments: list[str], timeout: int = 300) -> dict:
    completed = bounded_command(["/usr/bin/python3", str(HARNESS_LIFECYCLE_OPERATION),
                                 *arguments], timeout=timeout)
    if completed.returncode != 0:
        raise ValueError("Harness lifecycle plan or authorization was rejected")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Harness lifecycle response is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("Harness lifecycle response is invalid")
    return value


def _store_harness_plan(value: dict, identifier: str) -> None:
    HARNESS_PLAN_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    HARNESS_PLAN_ROOT.chmod(0o700)
    path = HARNESS_PLAN_ROOT / f"{identifier}.json"
    temporary = HARNESS_PLAN_ROOT / f".{identifier}.{os.getpid()}.new"
    payload = (json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def harness_generation_plan(action: str, generation_id: str | None, reason: str | None) -> dict:
    if action not in {"activate", "rollback", "retire", "revoke", "recover"}:
        raise ValueError("Harness lifecycle action is invalid")
    if action == "recover":
        value = _harness_operation(["recovery-status"])
        if (value.get("schema") != "secure-sandbox-harness-consumer-recovery-v1"
                or value.get("pending") is not True
                or not _harness_sha(value.get("journal_sha256"))):
            raise ValueError("Harness recovery is not pending")
        identifier = value["journal_sha256"]
    else:
        if generation_id is None or not _harness_sha(generation_id):
            raise ValueError("Harness generation identity is invalid")
        arguments = (["plan-activate", str(ROOT / ".private/harness-lifecycle/admission"
                                           / generation_id)] if action == "activate"
                     else [f"plan-{action}", generation_id])
        if action in {"retire", "revoke"}:
            if reason is None: raise ValueError("A retirement or revocation reason is required")
            arguments.append(reason)
        value = _harness_operation(arguments)
        if (value.get("schema") != "secure-sandbox-harness-consumer-plan-v1"
                or not _harness_sha(value.get("wrapper_sha256"))
                or not isinstance(value.get("stage_id"), str)
                or UUID4.fullmatch(value["stage_id"]) is None):
            raise ValueError("Harness lifecycle plan is invalid")
        identifier = value["stage_id"]
    _store_harness_plan(value, identifier)
    if action == "recover":
        generation = None; expires_at = int(time.time()) + 180; plan_sha = identifier
        active_count = resumable_count = None
    else:
        plan = value["plan"]
        generation = plan.get("generation_id") or plan.get("candidate", {}).get("generation_id")
        expires_at = plan.get("expires_at"); plan_sha = value["wrapper_sha256"]
        reference = value.get("reference") or {}
        active_count = reference.get("active_run_count")
        resumable_count = reference.get("resumable_session_count")
    return {"schema":"secure-sandbox-harness-control-center-plan-v1",
            "identifier":identifier, "plan_sha256":plan_sha, "operation":action,
            "generation_id":generation, "expires_at":expires_at,
            "active_run_count":active_count, "resumable_session_count":resumable_count}


def harness_generation_authorize(action: str, identifier: str, expected_sha256: str,
                                 agent: str, session: str) -> dict:
    if action == "recover":
        if not _harness_sha(identifier) or expected_sha256 != identifier:
            raise ValueError("Harness recovery identity is invalid")
    elif UUID4.fullmatch(identifier) is None or not _harness_sha(expected_sha256):
        raise ValueError("Harness lifecycle plan identity is invalid")
    path = HARNESS_PLAN_ROOT / f"{identifier}.json"
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_OUTPUT):
        raise ValueError("Harness lifecycle plan is untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle: raw = handle.read(MAX_OUTPUT + 1)
    value = json.loads(raw)
    observed = (value.get("journal_sha256") if action == "recover"
                else value.get("wrapper_sha256"))
    if observed != expected_sha256:
        raise ValueError("Harness lifecycle plan digest changed")
    result = _harness_operation(["authorize", action, str(path), "--agent", agent,
                                 "--session", session], timeout=300)
    if result.get("schema") != "secure-sandbox-harness-lifecycle-host-result-v1":
        raise ValueError("Harness lifecycle authorization result is invalid")
    path.unlink()
    status = result.get("status", {})
    boundary = result.get("boundary", {})
    mutation = result.get("result", {})
    if (status.get("schema") != "secure-sandbox-harness-generation-status-v1"
            or status.get("status") != "verified" or boundary.get("status") != "verified"
            or not isinstance(mutation, dict)):
        raise ValueError("Harness lifecycle postcondition is invalid")
    return {"schema":"secure-sandbox-harness-control-center-result-v1",
            "operation":action, "status":str(mutation.get("status", "committed")),
            "active_generation_id":status.get("active_generation_id"),
            "selector_epoch":status.get("selector_epoch"), "boundary":"verified"}


def apply_time_sync() -> dict[str, str]:
    overview = catalog("overview")
    if overview["status"] != "verified" or any(
            overview["observed"][vm] != "running" for vm in ("gateway", "research", "target")):
        raise ValueError("All three VMs must be running before clock synchronization")
    check_time_output(run_labctl("time-sync", "--apply"))
    check_time_output(run_labctl("time-sync"))
    return {"status": "verified", "operation": "time-sync"}


def safety_audit() -> dict[str, str | bool | int]:
    completed = subprocess.run([str(LABCTL), "safety-audit"], cwd=ROOT,
                               stdin=subprocess.DEVNULL, capture_output=True,
                               check=False, timeout=600)
    if len(completed.stdout) > MAX_OUTPUT:
        raise ValueError("Safety audit response exceeds its size limit")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-external-containment-audit-v1":
        raise ValueError("Safety audit schema is invalid")
    host = value.get("host_direct")
    secure = value.get("secure_sandbox_launch_path")
    if (not isinstance(host, dict) or not isinstance(secure, dict)
            or not isinstance(host.get("posture_tier"), int)
            or not isinstance(secure.get("verified"), bool)):
        raise ValueError("Safety audit posture is invalid")
    verified = secure["verified"] and completed.returncode == 0
    error = secure.get("error", "")
    if verified:
        detail = "The protected launch path and off-host evidence are verified."
    elif isinstance(error, str) and "active_release_source_mismatch" in error:
        detail = "The installed protected controller differs from reviewed source; deployment and verification are pending."
    else:
        detail = "The complete protected launch posture is not verified; inspect the operator audit."
    return {"verified": verified, "host_direct_tier": host["posture_tier"], "detail": detail}


def snapshot_policy() -> dict[str, str | bool]:
    completed = bounded_command([str(LABCTL), "snapshots"], timeout=60)
    if completed.returncode:
        diagnostic = completed.stderr.decode("utf-8", "replace")
        if "Retention milestone missing or duplicated" in diagnostic:
            detail = "A required retained snapshot is missing or duplicated. Policy maintenance is unavailable."
        elif "Current snapshot is not retained" in diagnostic:
            detail = "The current snapshot is outside the retained set. Policy maintenance is unavailable."
        else:
            detail = "Snapshot policy could not be verified."
        return {"verified": False, "detail": detail}
    lines = completed.stdout.decode("utf-8", "strict").splitlines()
    if len(lines) != 3 or any(not line.startswith(f"SecureSandbox-{role}: ")
                              for line, role in zip(lines, ("Gateway", "Research", "Target"))):
        raise ValueError("Snapshot policy response is invalid")
    return {"verified": True, "detail": "All three VM snapshot inventories match retained policy milestones."}


def snapshot_preview() -> dict:
    policy = json.loads((ROOT / "config/snapshot-retention.json").read_text(encoding="utf-8"))
    if (not isinstance(policy, dict) or policy.get("schema") != "secure-sandbox-snapshot-retention-v1"
            or type(policy.get("minimum_free_gib_for_apply")) is not int
            or not 1 <= policy["minimum_free_gib_for_apply"] <= 1000
            or type(policy.get("maximum_snapshots_per_vm")) is not int
            or not 1 <= policy["maximum_snapshots_per_vm"] <= 40
            or policy.get("virtual_machines") != [f"SecureSandbox-{role}" for role in ("Gateway", "Research", "Target")]
            or not isinstance(policy.get("retain_names"), list)
            or len(policy["retain_names"]) != policy["maximum_snapshots_per_vm"]
            or any(not isinstance(name, str) or not name or len(name) > 100 for name in policy["retain_names"])
            or len(set(policy["retain_names"])) != len(policy["retain_names"])):
        raise ValueError("Snapshot retention policy is invalid")
    minimum_bytes = policy["minimum_free_gib_for_apply"] * 1024**3
    statvfs = os.statvfs("/System/Volumes/Data")
    free_bytes = statvfs.f_bavail * statvfs.f_frsize
    observed = catalog("overview")
    stopped = observed["status"] == "verified" and all(
        observed["observed"][role] == "stopped" for role in ("gateway", "research", "target"))
    gui = subprocess.run(["/usr/bin/pgrep", "-x", "prl_client_app"],
                         stdin=subprocess.DEVNULL, capture_output=True,
                         check=False, timeout=5)
    if gui.returncode not in (0, 1):
        raise ValueError("Parallels GUI state is unavailable")
    completed = bounded_command([str(LABCTL), "snapshots"], timeout=60)
    policy_verified = completed.returncode == 0
    rows = []
    if policy_verified:
        lines = completed.stdout.decode("utf-8", "strict").splitlines()
        if len(lines) != 3:
            raise ValueError("Snapshot inventory response is invalid")
        for role, line in zip(("Gateway", "Research", "Target"), lines):
            match = re.fullmatch(rf"SecureSandbox-{role}: ([0-9]+) snapshots; retain ([0-9]+); remove ([0-9]+)", line)
            if match is None:
                raise ValueError("Snapshot inventory response is invalid")
            count, retain, remove = map(int, match.groups())
            if (count > 40 or retain != policy["maximum_snapshots_per_vm"]
                    or remove > count or count - remove != retain):
                raise ValueError("Snapshot inventory count is invalid")
            rows.append({"vm": role.lower(), "count": count, "retain": retain, "remove": remove})
    return {"policy_verified": policy_verified, "rows": rows,
            "free_bytes": free_bytes, "minimum_bytes": minimum_bytes,
            "stack_stopped": stopped, "gui_closed": gui.returncode == 1,
            "ready": policy_verified and stopped and gui.returncode == 1
            and free_bytes >= minimum_bytes and any(row["remove"] > 0 for row in rows)}


def apply_snapshot_retention() -> dict:
    before = snapshot_preview()
    if not before["ready"]:
        raise ValueError("Snapshot retention preflight is not ready")
    completed = bounded_command([str(LABCTL), "snapshots", "--apply"], timeout=1200)
    after = snapshot_preview()
    verified = (after["policy_verified"] and after["stack_stopped"] and after["gui_closed"]
                and len(after["rows"]) == 3
                and all(row["count"] == row["retain"] and row["remove"] == 0
                        for row in after["rows"]))
    return {"status": "verified" if verified else "incomplete",
            "command_status": completed.returncode, "rows": after["rows"]}


def normalize_github_url(raw: str) -> str:
    if len(raw) > 500 or raw != raw.strip():
        raise ValueError("Paste a plain GitHub repository URL")
    parsed = urlsplit(raw)
    if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query
            or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("Only plain https://github.com/owner/repository URLs are supported")
    segments = parsed.path.split("/")
    if len(segments) != 3 or not all(segments[1:]):
        raise ValueError("The URL must name one GitHub repository")
    slug = "/".join(segments[1:])
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,98}", slug) is None or slug.endswith(".git"):
        raise ValueError("The GitHub repository name is unsupported")
    return slug


def plan_source(url: str, ref: str) -> dict[str, str]:
    slug = normalize_github_url(url)
    if (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", ref) is None
            or ref.startswith(".") or ref.endswith(("/", ".")) or ".." in ref
            or "//" in ref or "@{" in ref):
        raise ValueError("The Git ref is unsupported")
    raw = run_labctl("source", "plan", slug, ref)
    lines = [line.split(":", 1) for line in raw.splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("Source plan response is invalid")
    fields = {key.strip(): value.strip() for key, value in lines}
    if (set(fields) != {"Plan", "Repository", "Requested", "Commit", "Expires"}
            or UUID.fullmatch(fields["Plan"]) is None
            or fields["Repository"] != slug or fields["Requested"] != ref
            or SHA.fullmatch(fields["Commit"]) is None):
        raise ValueError("Source plan identity is invalid")
    return {"plan_id": fields["Plan"], "repository": slug, "requested_ref": ref,
            "resolved_commit": fields["Commit"], "expires_at": fields["Expires"]}


def plan_npm(package: str, version: str) -> dict[str, str]:
    if (re.fullmatch(r"(@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}", package) is None
            or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?", version) is None):
        raise ValueError("Enter an exact npm package name and semantic version")
    raw = run_labctl("source", "npm-plan", package, version)
    lines = [line.split(":", 1) for line in raw.splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("npm plan response is invalid")
    fields = {key.strip(): value.strip() for key, value in lines}
    if (set(fields) != {"Plan", "Package", "Version", "Integrity", "Expires"}
            or UUID.fullmatch(fields["Plan"]) is None
            or fields["Package"] != package or fields["Version"] != version
            or SHA.fullmatch(fields["Integrity"]) is None):
        raise ValueError("npm plan identity is invalid")
    repository = f"npm/{package[1:].replace('/', '--') if package.startswith('@') else package}"
    return {"plan_id": fields["Plan"], "repository": repository,
            "requested_ref": version, "resolved_commit": fields["Integrity"],
            "expires_at": fields["Expires"]}


def label_session(session_id: str, label: str) -> dict[str, str]:
    if UUID.fullmatch(session_id) is None:
        raise ValueError("A canonical session ID is required")
    if (not label or label != label.strip() or len(label.encode("utf-8")) > 120
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)):
        raise ValueError("The label must be 1–120 UTF-8 bytes without control characters")
    raw = run_labctl("session", "label", session_id, label)
    if raw != f"labeled\t{session_id}\t{label}\n":
        raise ValueError("Session label response is invalid")
    return {"session_id": session_id, "label": label}


def unlabel_session(session_id: str) -> dict[str, str]:
    if UUID.fullmatch(session_id) is None:
        raise ValueError("A canonical session ID is required")
    raw = run_labctl("session", "unlabel", session_id)
    if raw != f"unlabeled\t{session_id}\n":
        raise ValueError("Session unlabel response is invalid")
    return {"session_id": session_id, "label": ""}


def source_status(plan_id: str) -> dict[str, str]:
    if UUID.fullmatch(plan_id) is None:
        raise ValueError("A canonical plan ID is required")
    value = json.loads(run_labctl("source", "status", plan_id))
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-source-plan-status-v1"
            or value.get("plan_id") != plan_id
            or value.get("state") not in {"planned", "claimed", "fetched", "exported", "failed", "expired", "completed"}
            or SHA.fullmatch(str(value.get("resolved_commit", ""))) is None):
        raise ValueError("Source plan status is invalid")
    if value["state"] == "completed" and UUID.fullmatch(str(value.get("source_id", ""))) is None:
        raise ValueError("Completed source identity is invalid")
    return value


def apply_source(plan_id: str) -> dict[str, str]:
    before = source_status(plan_id)
    if before["state"] != "planned":
        raise ValueError("This source plan is no longer available for import")
    existing = [row for row in catalog("sources")
                if row.get("repository") == before["repository"]
                and row.get("commit") == before["resolved_commit"]]
    if existing:
        raise ValueError("This exact source is already imported. Use the existing Sources entry.")
    raw = run_labctl("source", "apply", plan_id)
    lines = [line.split(":", 1) for line in raw.splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("Source import response is invalid; inspect the plan status before another action")
    fields = {key.strip(): value.strip() for key, value in lines}
    after = source_status(plan_id)
    if (set(fields) != {"Source", "Baseline", "Repository", "Index", "Evidence"}
            or after["state"] != "completed" or fields["Source"] != after["source_id"]
            or fields["Index"] != "repos/INDEX.json"
            or fields["Evidence"] != "archived and verified"):
        raise ValueError("Source import outcome is ambiguous; inspect the plan status")
    return {"plan_id": plan_id, "source_id": after["source_id"], "repository": after["repository"]}


def finding_detail(finding_id: str) -> dict:
    if UUID.fullmatch(finding_id) is None:
        raise ValueError("A canonical finding ID is required")
    value = json.loads(run_labctl("finding", "show", finding_id))
    if not isinstance(value, dict) or set(value) != {"candidate", "amendments", "events", "current_state"}:
        raise ValueError("Finding detail response is invalid")
    candidate = value["candidate"]
    if (not isinstance(candidate, dict) or candidate.get("finding_id") != finding_id
            or not isinstance(value["amendments"], list)
            or not isinstance(value["events"], list)
            or not isinstance(value["current_state"], str)
            or not isinstance(candidate.get("evidence"), list)
            or len(value["amendments"]) > 1_000 or len(value["events"]) > 1_000):
        raise ValueError("Finding identity or history is invalid")
    fields = ("claim", "counterargument", "limitations", "claim_evidence_support",
              "proposed_severity", "submitted_at")
    if any(not isinstance(candidate.get(key), str) or len(candidate[key]) > 32_000 for key in fields):
        raise ValueError("Finding text is invalid")
    if not isinstance(candidate.get("content_sha256"), str) or SHA256.fullmatch(candidate["content_sha256"]) is None:
        raise ValueError("Finding content digest is invalid")
    evidence = []
    for record in [candidate, *value["amendments"]]:
        if not isinstance(record, dict) or not isinstance(record.get("evidence"), list):
            raise ValueError("Finding amendment evidence is invalid")
        for item in record["evidence"]:
            if (not isinstance(item, dict) or item.get("class") not in {
                    "static_source_review", "exhaustive_corpus_search", "static_graph_reachability",
                    "measured_execution", "report_reference", "operator_reported"}):
                raise ValueError("Finding evidence is invalid")
            if len(evidence) >= 272:
                raise ValueError("Finding evidence exceeds its limit")
            rendered = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            source_id, receipt_id, path = item.get("source_id"), item.get("receipt_id"), item.get("path")
            if (source_id is not None and (not isinstance(source_id, str) or UUID.fullmatch(source_id) is None)
                    or receipt_id is not None and (not isinstance(receipt_id, str) or UUID.fullmatch(receipt_id) is None)
                    or path is not None and (not isinstance(path, str) or len(path) > 512)):
                raise ValueError("Finding evidence reference is invalid")
            evidence.append({"class": item["class"], "sha256": hashlib.sha256(rendered).hexdigest(),
                             "source_id": source_id, "receipt_id": receipt_id, "path": path,
                             "line": item.get("line") if type(item.get("line")) is int else None})
    history = []
    for event in value["events"]:
        if not isinstance(event, dict) or event.get("finding_id") != finding_id:
            raise ValueError("Finding event identity is invalid")
        projected = {"event": event.get("event"), "recorded_at": event.get("recorded_at"),
                     "actor": event.get("actor"), "to_state": event.get("to_state"),
                     "verification_method": event.get("verification_method"),
                     "rationale": event.get("rationale")}
        if projected["event"] not in {"state_changed", "relation_added", "reopened"} or not isinstance(projected["recorded_at"], str):
            raise ValueError("Finding event is invalid")
        if any(value is not None and (not isinstance(value, str) or len(value) > 4096)
               for value in projected.values()):
            raise ValueError("Finding event text is invalid")
        history.append(projected)
    return {"finding_id": finding_id, "current_state": value["current_state"],
            "content_sha256": candidate["content_sha256"],
            "claim_requires_execution": candidate.get("claim_requires_execution") is True,
            **{key: candidate[key] for key in fields},
            "evidence_count": len(candidate.get("evidence", [])),
            "amendment_count": len(value["amendments"]), "event_count": len(value["events"]),
            "evidence": evidence, "history": history}


def submit_finding_action(action: dict) -> dict:
    payload = json.dumps(action, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > 16384:
        raise ValueError("Finding action request exceeds its limit")
    private = ROOT / ".private"
    if not private.is_dir() or private.is_symlink():
        raise ValueError("Private request staging is unavailable")
    with tempfile.NamedTemporaryFile(mode="wb", prefix="finding-action-", suffix=".json",
                                     dir=private, delete=True) as staged:
        staged.write(payload)
        staged.flush()
        os.fsync(staged.fileno())
        completed = bounded_command([str(LABCTL), "finding", "apply", staged.name], timeout=90)
    if completed.returncode != 0:
        raise ValueError("Finding action outcome is unclear; refresh the finding before another action")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("Finding action receipt is invalid")
    return value


def apply_finding_transition(request: dict) -> dict:
    required = {"schema", "finding_id", "expected_content_sha256", "expected_state",
                "to_state", "verification_method", "consulted_evidence", "actor_id",
                "actor_role", "rationale", "conflict_note"}
    transitions = {"candidate": {"needs_evidence", "disputed", "validated", "rejected", "withdrawn"},
                   "needs_evidence": {"disputed", "validated", "rejected", "withdrawn"},
                   "disputed": {"needs_evidence", "validated", "rejected", "withdrawn"}}
    if (not isinstance(request, dict) or set(request) != required
            or request["schema"] != "secure-sandbox-control-center-finding-transition-v1"
            or not isinstance(request["finding_id"], str) or UUID.fullmatch(request["finding_id"]) is None
            or not isinstance(request["expected_content_sha256"], str)
            or SHA256.fullmatch(request["expected_content_sha256"]) is None
            or any(not isinstance(request[name], str) for name in
                   ("expected_state", "to_state", "verification_method", "actor_role"))
            or request["to_state"] not in transitions.get(request["expected_state"], set())
            or request["verification_method"] not in {"re_executed", "inspected_evidence", "reasoning_only"}
            or request["actor_role"] not in {"research_lead", "architect", "independent_reviewer"}
            or not isinstance(request["actor_id"], str) or not 1 <= len(request["actor_id"].encode("utf-8")) <= 96
            or any(char in request["actor_id"] for char in "\r\n\t")
            or not isinstance(request["rationale"], str) or not 1 <= len(request["rationale"].encode("utf-8")) <= 4096
            or not isinstance(request["conflict_note"], str) or not 1 <= len(request["conflict_note"].encode("utf-8")) <= 1024
            or not isinstance(request["consulted_evidence"], list)
            or len(request["consulted_evidence"]) > 16
            or any(not isinstance(digest, str) or SHA256.fullmatch(digest) is None
                   for digest in request["consulted_evidence"])
            or len(set(request["consulted_evidence"])) != len(request["consulted_evidence"])):
        raise ValueError("Finding transition review is invalid")
    before = finding_detail(request["finding_id"])
    if (before["content_sha256"] != request["expected_content_sha256"]
            or before["current_state"] != request["expected_state"]
            or not set(request["consulted_evidence"]).issubset(
                {item["sha256"] for item in before["evidence"]})):
        raise ValueError("Finding content, state, or evidence changed since review")
    if request["to_state"] == "validated" and (not request["consulted_evidence"]
            or request["verification_method"] == "reasoning_only"
            or before["claim_requires_execution"] and request["verification_method"] != "re_executed"):
        raise ValueError("Validation requires reviewed evidence and the required verification method")
    action = {"action": "transition", "finding_id": request["finding_id"],
              "to_state": request["to_state"], "verification_method": request["verification_method"],
              "consulted_evidence": request["consulted_evidence"],
              "actor": {"id": request["actor_id"], "role": request["actor_role"]},
              "rationale": request["rationale"], "conflict_note": request["conflict_note"]}
    receipt = submit_finding_action(action)
    if (not isinstance(receipt, dict) or receipt.get("status") != "recorded"
            or receipt.get("finding_id") != request["finding_id"]
            or not isinstance(receipt.get("event_id"), str) or UUID.fullmatch(receipt["event_id"]) is None
            or not isinstance(receipt.get("entry_sha256"), str)
            or SHA256.fullmatch(receipt["entry_sha256"]) is None):
        raise ValueError("Finding transition receipt is invalid; refresh the finding")
    after = json.loads(run_labctl("finding", "show", request["finding_id"]))
    if not isinstance(after, dict) or not isinstance(after.get("events"), list):
        raise ValueError("Finding transition readback is invalid")
    events = after["events"]
    matched = [event for event in events or [] if isinstance(event, dict)
               and event.get("event_id") == receipt["event_id"]
               and event.get("entry_sha256") == receipt["entry_sha256"]]
    if (len(matched) != 1 or matched[0].get("to_state") != request["to_state"]
            or matched[0].get("consulted_evidence") != request["consulted_evidence"]
            or after.get("current_state") != request["to_state"]):
        raise ValueError("Finding transition readback does not match the reviewed action")
    return {"status": "verified", "finding_id": request["finding_id"],
            "state": request["to_state"], "event_id": receipt["event_id"],
            "entry_sha256": receipt["entry_sha256"]}


def apply_finding_relation(request: dict) -> dict:
    required = {"schema", "finding_id", "expected_content_sha256", "expected_state",
                "relation", "target_finding_id", "actor_id", "actor_role",
                "rationale", "conflict_note"}
    if (not isinstance(request, dict) or set(request) != required
            or request["schema"] != "secure-sandbox-control-center-finding-relation-v1"
            or not isinstance(request["finding_id"], str) or UUID.fullmatch(request["finding_id"]) is None
            or not isinstance(request["target_finding_id"], str)
            or UUID.fullmatch(request["target_finding_id"]) is None
            or request["target_finding_id"] == request["finding_id"]
            or not isinstance(request["expected_content_sha256"], str)
            or SHA256.fullmatch(request["expected_content_sha256"]) is None
            or not isinstance(request["expected_state"], str)
            or request["relation"] not in ("duplicate_of", "supersedes", "disputes")
            or request["actor_role"] not in ("research_lead", "architect", "independent_reviewer")
            or not isinstance(request["actor_id"], str) or not 1 <= len(request["actor_id"].encode()) <= 96
            or any(char in request["actor_id"] for char in "\r\n\t")
            or not isinstance(request["rationale"], str) or not 1 <= len(request["rationale"].encode()) <= 4096
            or not isinstance(request["conflict_note"], str) or not 1 <= len(request["conflict_note"].encode()) <= 1024):
        raise ValueError("Finding relation review is invalid")
    before = finding_detail(request["finding_id"])
    target = finding_detail(request["target_finding_id"])
    if (before["content_sha256"] != request["expected_content_sha256"]
            or before["current_state"] != request["expected_state"]
            or target["finding_id"] != request["target_finding_id"]):
        raise ValueError("Finding or target changed since review")
    action = {"action": "relation", "finding_id": request["finding_id"],
              "relation": request["relation"], "target_finding_id": request["target_finding_id"],
              "actor": {"id": request["actor_id"], "role": request["actor_role"]},
              "rationale": request["rationale"], "conflict_note": request["conflict_note"]}
    receipt = submit_finding_action(action)
    if (receipt.get("status") != "recorded" or receipt.get("finding_id") != request["finding_id"]
            or not isinstance(receipt.get("event_id"), str) or UUID.fullmatch(receipt["event_id"]) is None
            or not isinstance(receipt.get("entry_sha256"), str)
            or SHA256.fullmatch(receipt["entry_sha256"]) is None):
        raise ValueError("Finding relation receipt is invalid; refresh the finding")
    after = json.loads(run_labctl("finding", "show", request["finding_id"]))
    if not isinstance(after, dict) or not isinstance(after.get("events"), list):
        raise ValueError("Finding relation readback is invalid")
    matches = [event for event in after["events"] if isinstance(event, dict)
               and event.get("event_id") == receipt["event_id"]
               and event.get("entry_sha256") == receipt["entry_sha256"]]
    if (len(matches) != 1 or matches[0].get("relation") != request["relation"]
            or matches[0].get("target_finding_id") != request["target_finding_id"]
            or after.get("current_state") != request["expected_state"]):
        raise ValueError("Finding relation readback does not match the reviewed action")
    return {"status": "verified", "finding_id": request["finding_id"],
            "relation": request["relation"], "target_finding_id": request["target_finding_id"],
            "event_id": receipt["event_id"], "entry_sha256": receipt["entry_sha256"]}


def finding_reopen_options(finding_id: str) -> dict:
    detail = finding_detail(finding_id)
    if detail["current_state"] not in {"validated", "rejected", "withdrawn"}:
        raise ValueError("Finding is not terminal")
    raw = json.loads(run_labctl("finding", "show", finding_id))
    if (not isinstance(raw, dict) or not isinstance(raw.get("events"), list)
            or not isinstance(raw.get("candidate"), dict)
            or not isinstance(raw.get("amendments"), list)):
        raise ValueError("Finding reopen inventory is invalid")
    terminal = next((event for event in reversed(raw["events"])
                     if isinstance(event, dict) and event.get("event") == "state_changed"
                     and event.get("to_state") in {"validated", "rejected", "withdrawn"}), None)
    if terminal is None:
        raise ValueError("Terminal event is unavailable")
    records = [raw["candidate"], *raw["amendments"]]
    available = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("evidence"), list):
            raise ValueError("Finding reopen evidence is invalid")
        for item in record["evidence"]:
            if not isinstance(item, dict):
                raise ValueError("Finding reopen evidence is invalid")
            digest = hashlib.sha256(json.dumps(item, ensure_ascii=False, sort_keys=True,
                                               separators=(",", ":")).encode()).hexdigest()
            available[digest] = item
    earlier = terminal.get("terminal_evidence_sha256")
    earlier_reports = terminal.get("terminal_report_content_sha256")
    if earlier is None:
        try:
            cutoff = datetime.fromisoformat(terminal["recorded_at"].replace("Z", "+00:00"))
            earlier_records = [raw["candidate"]] + [item for item in raw["amendments"]
                if datetime.fromisoformat(item["submitted_at"].replace("Z", "+00:00")) <= cutoff]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Legacy terminal evidence inventory is invalid") from error
        earlier = []
        earlier_reports = []
        for record in earlier_records:
            for item in record["evidence"]:
                earlier.append(hashlib.sha256(json.dumps(item, ensure_ascii=False, sort_keys=True,
                                                     separators=(",", ":")).encode()).hexdigest())
                if item.get("class") == "report_reference":
                    earlier_reports.append(item.get("content_sha256"))
    if (not isinstance(earlier, list) or not isinstance(earlier_reports, list)
            or len(earlier) > 272 or len(earlier_reports) > 272
            or any(not isinstance(digest, str) or SHA256.fullmatch(digest) is None
                   for digest in [*earlier, *earlier_reports])):
        raise ValueError("Terminal evidence inventory is invalid")
    earlier_set, report_set = set(earlier), set(earlier_reports)
    eligible = {digest for digest, item in available.items()
                if digest not in earlier_set and (item.get("class") != "report_reference"
                or item.get("content_sha256") not in report_set)}
    options = [item for item in detail["evidence"] if item["sha256"] in eligible]
    return {"finding_id": finding_id, "content_sha256": detail["content_sha256"],
            "current_state": detail["current_state"], "options": options}


def apply_finding_reopen(request: dict) -> dict:
    required = {"schema", "finding_id", "expected_content_sha256", "expected_state",
                "new_evidence_sha256", "actor_id", "actor_role", "rationale", "conflict_note"}
    if (not isinstance(request, dict) or set(request) != required
            or request["schema"] != "secure-sandbox-control-center-finding-reopen-v1"
            or not isinstance(request["finding_id"], str) or UUID.fullmatch(request["finding_id"]) is None
            or not isinstance(request["expected_content_sha256"], str)
            or SHA256.fullmatch(request["expected_content_sha256"]) is None
            or request["expected_state"] not in ("validated", "rejected", "withdrawn")
            or not isinstance(request["new_evidence_sha256"], str)
            or SHA256.fullmatch(request["new_evidence_sha256"]) is None
            or request["actor_role"] not in ("research_lead", "architect", "independent_reviewer")
            or not isinstance(request["actor_id"], str) or not 1 <= len(request["actor_id"].encode()) <= 96
            or any(char in request["actor_id"] for char in "\r\n\t")
            or not isinstance(request["rationale"], str) or not 1 <= len(request["rationale"].encode()) <= 4096
            or not isinstance(request["conflict_note"], str) or not 1 <= len(request["conflict_note"].encode()) <= 1024):
        raise ValueError("Finding reopen review is invalid")
    options = finding_reopen_options(request["finding_id"])
    if (options["content_sha256"] != request["expected_content_sha256"]
            or options["current_state"] != request["expected_state"]
            or request["new_evidence_sha256"] not in {item["sha256"] for item in options["options"]}):
        raise ValueError("Finding or new evidence changed since review")
    action = {"action": "reopen", "finding_id": request["finding_id"],
              "new_evidence_sha256": request["new_evidence_sha256"],
              "actor": {"id": request["actor_id"], "role": request["actor_role"]},
              "rationale": request["rationale"], "conflict_note": request["conflict_note"]}
    receipt = submit_finding_action(action)
    if (receipt.get("status") != "recorded" or receipt.get("finding_id") != request["finding_id"]
            or not isinstance(receipt.get("event_id"), str) or UUID.fullmatch(receipt["event_id"]) is None
            or not isinstance(receipt.get("entry_sha256"), str)
            or SHA256.fullmatch(receipt["entry_sha256"]) is None):
        raise ValueError("Finding reopen receipt is invalid; refresh the finding")
    after = json.loads(run_labctl("finding", "show", request["finding_id"]))
    if not isinstance(after, dict) or not isinstance(after.get("events"), list):
        raise ValueError("Finding reopen readback is invalid")
    matches = [event for event in after["events"] if isinstance(event, dict)
               and event.get("event_id") == receipt["event_id"]
               and event.get("entry_sha256") == receipt["entry_sha256"]]
    if (len(matches) != 1 or matches[0].get("event") != "reopened"
            or matches[0].get("new_evidence_sha256") != request["new_evidence_sha256"]
            or after.get("current_state") != "needs_evidence"):
        raise ValueError("Finding reopen readback does not match the reviewed action")
    return {"status": "verified", "finding_id": request["finding_id"],
            "state": "needs_evidence", "event_id": receipt["event_id"],
            "entry_sha256": receipt["entry_sha256"]}


def apply_finding_disposition(request: dict) -> dict:
    required = {"schema", "finding_id", "expected_content_sha256", "expected_state",
                "actor_id", "actor_role", "rationale", "conflict_note"}
    if (not isinstance(request, dict) or set(request) != required
            or request["schema"] != "secure-sandbox-control-center-finding-disposition-v1"
            or not isinstance(request["finding_id"], str) or UUID.fullmatch(request["finding_id"]) is None
            or not isinstance(request["expected_content_sha256"], str)
            or SHA256.fullmatch(request["expected_content_sha256"]) is None
            or request["expected_state"] not in ("validated", "rejected", "withdrawn")
            or request["actor_role"] not in ("research_lead", "architect", "independent_reviewer")
            or not isinstance(request["actor_id"], str) or not 1 <= len(request["actor_id"].encode()) <= 96
            or any(char in request["actor_id"] for char in "\r\n\t")
            or not isinstance(request["rationale"], str) or not 1 <= len(request["rationale"].encode()) <= 4096
            or not isinstance(request["conflict_note"], str) or not 1 <= len(request["conflict_note"].encode()) <= 1024):
        raise ValueError("Finding disposition review is invalid")
    before = finding_detail(request["finding_id"])
    if (before["content_sha256"] != request["expected_content_sha256"]
            or before["current_state"] != request["expected_state"]):
        raise ValueError("Finding changed since disposition review")
    listed = [row for row in catalog("findings") if row.get("finding_id") == request["finding_id"]]
    if (len(listed) != 1 or listed[0].get("disposition") != "active"
            or listed[0].get("content_sha256") != request["expected_content_sha256"]):
        raise ValueError("Finding is no longer active for disposition")
    action = {"action": "dispose", "finding_id": request["finding_id"],
              "actor": {"id": request["actor_id"], "role": request["actor_role"]},
              "rationale": request["rationale"], "conflict_note": request["conflict_note"]}
    receipt = submit_finding_action(action)
    if (receipt.get("status") != "disposed" or receipt.get("finding_id") != request["finding_id"]
            or receipt.get("terminal_state") != request["expected_state"]
            or not isinstance(receipt.get("content_sha256"), str)
            or SHA256.fullmatch(receipt["content_sha256"]) is None):
        raise ValueError("Finding disposition receipt is invalid; inspect archive state")
    observed = json.loads(run_labctl("finding", "disposition-status", request["finding_id"]))
    if (not isinstance(observed, dict)
            or observed.get("schema") != "secure-sandbox-finding-disposition-status-v1"
            or observed.get("finding_id") != request["finding_id"]
            or observed.get("state") != request["expected_state"]
            or observed.get("content_sha256") != receipt["content_sha256"]
            or observed.get("candidate_sha256") != request["expected_content_sha256"]):
        raise ValueError("Finding disposition archive readback does not match the reviewed action")
    return {"status": "verified", "finding_id": request["finding_id"],
            "state": request["expected_state"], "archive_sha256": receipt["content_sha256"]}


def artifact_detail(artifact_id: str) -> dict[str, str]:
    if UUID.fullmatch(artifact_id) is None:
        raise ValueError("A canonical artifact ID is required")
    raw = run_labctl("artifact", artifact_id)
    lines = raw.split("\n", 6)
    if len(lines) != 7 or lines[0] != f"Artifact: {artifact_id}" or lines[5] != "---":
        raise ValueError("Artifact rendering is invalid")
    fields = [line.split(": ", 1) for line in lines[1:5]]
    if any(len(field) != 2 for field in fields) or [field[0] for field in fields] != ["Captured", "Source", "Run", "SHA-256"]:
        raise ValueError("Artifact metadata is invalid")
    source = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(?:md|txt|json)) \(version ([1-9][0-9]{0,8})\)", fields[1][1])
    if (source is None or (fields[2][1] != "preflight" and UUID.fullmatch(fields[2][1]) is None)
            or re.fullmatch(r"[0-9a-f]{64}", fields[3][1]) is None
            or len(lines[6].encode("utf-8")) > 4 * 1024 * 1024):
        raise ValueError("Artifact content or identity is invalid")
    return {"id": artifact_id, "captured_at": fields[0][1], "file_name": source[1],
            "version": source[2], "run_id": fields[2][1], "sha256": fields[3][1],
            "content": lines[6]}


def dependency_rows(raw: str) -> list[dict[str, str]]:
    rows = table(raw, 4)
    if len(rows) > 1_000:
        raise ValueError("Dependency plan exceeds its row limit")
    for state, package, version, source_id in rows:
        if (state not in {"READY", "MISSING"}
                or re.fullmatch(r"(@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}", package) is None
                or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?", version) is None
                or (source_id != "-" and UUID.fullmatch(source_id) is None)
                or (state == "READY") != (source_id != "-")):
            raise ValueError("Dependency row is invalid")
    return [dict(zip(("state", "package", "version", "source_id"), row)) for row in rows]


def dependency_plan(source_id: str) -> dict:
    if UUID.fullmatch(source_id) is None:
        raise ValueError("A canonical source ID is required")
    lines = run_labctl("dependencies", "plan", source_id).splitlines()
    if len(lines) < 4:
        raise ValueError("Dependency plan is incomplete")
    header = [line.split(":", 1) for line in lines[:4]]
    if any(len(field) != 2 for field in header):
        raise ValueError("Dependency plan header is invalid")
    fields = {key.strip(): value.strip() for key, value in header}
    root = fields.get("Root", "").rsplit("@", 1)
    if (set(fields) != {"Plan", "Root", "Set SHA256", "Expires"}
            or UUID.fullmatch(fields["Plan"]) is None
            or len(root) != 2 or not root[0] or not root[1]
            or re.fullmatch(r"[0-9a-f]{64}", fields["Set SHA256"]) is None):
        raise ValueError("Dependency plan identity is invalid")
    return {"plan_id": fields["Plan"], "root": fields["Root"],
            "dependency_set_sha256": fields["Set SHA256"], "expires_at": fields["Expires"],
            "dependencies": dependency_rows("\n".join(lines[4:]))}


def dependency_status(plan_id: str) -> dict:
    if UUID.fullmatch(plan_id) is None:
        raise ValueError("A canonical dependency plan ID is required")
    return {"plan_id": plan_id,
            "dependencies": dependency_rows(run_labctl("dependencies", "status", plan_id))}


def dependency_bundles() -> list[dict[str, str]]:
    rows = table(run_labctl("dependencies", "list"), 5)
    if any(UUID.fullmatch(row[1]) is None or re.fullmatch(r"[0-9]{1,5}", row[3]) is None
           or re.fullmatch(r"[0-9a-f]{64}", row[4]) is None for row in rows):
        raise ValueError("Dependency bundle catalog is invalid")
    return [dict(zip(("created_at", "id", "root", "dependency_count", "dependency_set_sha256"), row)) for row in rows]


def dependency_apply(plan_id: str, expected_digest: str) -> dict[str, str]:
    if UUID.fullmatch(plan_id) is None or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise ValueError("Dependency plan identity is invalid")
    before = dependency_status(plan_id)
    if any(item["state"] != "READY" for item in before["dependencies"]):
        raise ValueError("Import the missing exact package versions before assembling the bundle")
    lines = [line.split(":", 1) for line in run_labctl("dependencies", "apply", plan_id).splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("Dependency assembly response is invalid; inspect bundle catalog")
    fields = {key.strip(): value.strip() for key, value in lines}
    if (set(fields) != {"Bundle", "Root", "Dependencies", "Set SHA256", "Lifecycle"}
            or UUID.fullmatch(fields["Bundle"]) is None
            or fields["Set SHA256"] != expected_digest or fields["Lifecycle"] != "disabled"
            or not fields["Dependencies"].isdigit()
            or int(fields["Dependencies"]) != len(before["dependencies"])):
        raise ValueError("Dependency assembly outcome is invalid; inspect bundle catalog")
    matches = [item for item in dependency_bundles() if item["id"] == fields["Bundle"]]
    if len(matches) != 1 or matches[0]["dependency_set_sha256"] != expected_digest:
        raise ValueError("Dependency bundle readback did not match the plan")
    return {"bundle_id": fields["Bundle"], "root": fields["Root"],
            "dependency_set_sha256": expected_digest, "dependency_count": fields["Dependencies"]}


def index_source(kind: str, source_id: str) -> dict[str, str | int]:
    if kind not in {"corpus", "codegraph"} or UUID.fullmatch(source_id) is None:
        raise ValueError("A selected source and supported index are required")
    value = json.loads(run_labctl(kind, "index", source_id))
    schema = ("secure-sandbox-corpus-index-v1" if kind == "corpus"
              else "secure-sandbox-codegraph-index-v1")
    digest_key = "index_content_sha256" if kind == "corpus" else "codegraph_index_sha256"
    count_key = "indexed_documents" if kind == "corpus" else "nodes_created"
    if (not isinstance(value, dict) or value.get("schema") != schema
            or value.get("source_id") != source_id or value.get("status") != "indexed"
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get(digest_key, ""))) is None
            or not isinstance(value.get(count_key), int) or value[count_key] < 0):
        raise ValueError("Sealed index result is invalid")
    return {"kind": kind, "source_id": source_id, "status": "indexed",
            "digest": value[digest_key], "item_count": value[count_key]}


def index_source_status(kind: str, source_id: str) -> dict[str, str | int]:
    if kind not in {"corpus", "codegraph"} or UUID.fullmatch(source_id) is None:
        raise ValueError("A selected source and supported index are required")
    value = json.loads(run_labctl(kind, "status", source_id))
    schema = ("secure-sandbox-corpus-index-status-v1" if kind == "corpus"
              else "secure-sandbox-codegraph-index-status-v1")
    if (not isinstance(value, dict) or value.get("schema") != schema
            or value.get("source_id") != source_id
            or value.get("status") not in {"indexed", "not_indexed"}):
        raise ValueError("Sealed index status is invalid")
    if value["status"] == "not_indexed":
        return {"kind": kind, "source_id": source_id, "status": "not_indexed",
                "digest": "", "item_count": 0}
    digest_key = "index_content_sha256" if kind == "corpus" else "codegraph_index_sha256"
    count_key = "indexed_documents" if kind == "corpus" else "nodes_created"
    if (re.fullmatch(r"[0-9a-f]{64}", str(value.get(digest_key, ""))) is None
            or not isinstance(value.get(count_key), int) or value[count_key] < 0):
        raise ValueError("Sealed index status is invalid")
    return {"kind": kind, "source_id": source_id, "status": "indexed",
            "digest": value[digest_key], "item_count": value[count_key]}


def vm_footprint() -> dict[str, int]:
    result = {}
    for role in ("Gateway", "Research", "Target"):
        root = ROOT / "vms" / f"SecureSandbox-{role}.pvm"
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("A VM bundle is missing or is not a directory")
        total = 0
        for base, directories, files in os.walk(root, followlinks=False):
            for name in directories + files:
                mode = (Path(base) / name).lstat().st_mode
                if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise ValueError("A VM bundle contains an unsupported entry")
                if stat.S_ISREG(mode):
                    total += (Path(base) / name).lstat().st_size
        result[role.lower()] = total
    return result


def destination_volume(path: Path) -> dict[str, str | bool]:
    output = subprocess.run(
        ["/bin/df", "-P", str(path)], stdin=subprocess.DEVNULL,
        capture_output=True, check=True, timeout=10,
    ).stdout.decode("ascii", "strict").splitlines()
    if len(output) != 2:
        raise ValueError("Destination volume could not be identified")
    device = output[1].split()[0]
    if re.fullmatch(r"/dev/disk[0-9]+s[0-9]+", device) is None:
        raise ValueError("Destination must be on a local APFS volume")
    info = plistlib.loads(subprocess.run(
        ["/usr/sbin/diskutil", "info", "-plist", device],
        stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=10,
    ).stdout)
    if not isinstance(info, dict) or info.get("FilesystemName") != "APFS":
        raise ValueError("Destination must be on APFS")
    volume_id = info.get("VolumeUUID")
    if not isinstance(volume_id, str) or re.fullmatch(
            r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", volume_id) is None:
        raise ValueError("Destination volume identity is unavailable")
    encrypted = (info.get("Encryption") is True
                 and info.get("EncryptionThisVolumeProper") is True
                 and info.get("FileVault") is True)
    return {"volume_uuid": volume_id, "encrypted": encrypted}


def backup_preflight(destination: str) -> dict:
    if not destination.startswith("/") or len(destination) > 1024:
        raise ValueError("Select an existing absolute destination folder")
    if Path(destination).is_symlink():
        raise ValueError("Select a destination folder, not a symbolic link")
    path = Path(destination).resolve(strict=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError("Select an existing destination folder")
    vms = ROOT / "vms"
    if path == vms or vms in path.parents:
        raise ValueError("A VM bundle cannot contain its own backup")
    sizes = vm_footprint()
    host_files = backup_operations().backup.host_config_inventory(ROOT / "config")
    host_config_bytes = sum(item["bytes"] for item in host_files)
    logical_bytes = sum(sizes.values()) + host_config_bytes
    free_bytes = os.statvfs(path).f_bavail * os.statvfs(path).f_frsize
    reserve_bytes = max(10 * 1024**3, logical_bytes // 10)
    volume = destination_volume(path)
    observed = catalog("overview")
    stopped = observed["status"] == "verified" and all(
        observed["observed"][role] == "stopped" for role in ("gateway", "research", "target"))
    return {"destination": str(path), "volume_uuid": volume["volume_uuid"],
            "encrypted": volume["encrypted"], "free_bytes": free_bytes,
            "logical_bytes": logical_bytes, "reserve_bytes": reserve_bytes,
            "vm_bytes": sizes, "host_config_bytes": host_config_bytes, "stack_stopped": stopped,
            "ready": bool(volume["encrypted"] and free_bytes >= logical_bytes + reserve_bytes and stopped)}


def backup_operations():
    path = ROOT / "scripts/control_center_backup_operation.py"
    spec = importlib.util.spec_from_file_location("control_center_backup_operations", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Backup operation service is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plan_backup(destination: str) -> dict:
    preflight = backup_preflight(destination)
    if not preflight["ready"]:
        raise ValueError("Backup destination or stopped-stack preflight is not ready")
    operations = backup_operations()
    key = operations.backup.read_backup_key()
    identities = operations.vm_identities(ROOT)
    plan = operations.create_plan(operations.default_root(), Path(preflight["destination"]),
                                  preflight["volume_uuid"], identities, key,
                                  logical_bytes=preflight["logical_bytes"])
    return {"plan_id": plan["plan_id"], "destination": plan["destination"],
            "volume_uuid": plan["volume_uuid"], "expires_unix": plan["expires_unix"],
            "logical_bytes": preflight["logical_bytes"]}


def submit_backup(plan_id: str) -> dict[str, str]:
    if UUID.fullmatch(plan_id) is None:
        raise ValueError("A canonical backup plan ID is required")
    operations = backup_operations()
    key = operations.backup.read_backup_key()
    return operations.submit_backup(operations.default_root(), ROOT, plan_id, key)


def backup_plan_detail(plan_id: str) -> dict:
    if UUID.fullmatch(plan_id) is None:
        raise ValueError("A canonical backup plan ID is required")
    operations = backup_operations()
    key = operations.backup.read_backup_key()
    return operations.plan_detail(operations.default_root(), plan_id, key)


def backup_operation_status(plan_id: str) -> dict:
    if UUID.fullmatch(plan_id) is None:
        raise ValueError("A canonical backup plan ID is required")
    operations = backup_operations()
    key = operations.backup.read_backup_key()
    return operations.operation_status(operations.default_root(), plan_id, key)


def backup_inventory(destination: str) -> dict:
    if not destination.startswith("/") or len(destination) > 1024:
        raise ValueError("Select an existing absolute backup folder")
    selected = Path(destination)
    if selected.is_symlink():
        raise ValueError("Select a backup folder, not a symbolic link")
    path = selected.resolve(strict=True)
    if not path.is_dir():
        raise ValueError("Select an existing backup folder")
    volume = destination_volume(path)
    entries = []
    for item in sorted(path.iterdir(), key=lambda entry: entry.name):
        if len(entries) >= 200:
            raise ValueError("Backup inventory exceeds the display limit")
        match = re.fullmatch(r"(\.)?secure-sandbox-backup-([0-9a-f-]{36})(\.incomplete)?", item.name)
        if match is None or UUID.fullmatch(match.group(2)) is None:
            continue
        if item.is_symlink() or not item.is_dir():
            raise ValueError("Backup generation entry is not a directory")
        entries.append({"generation_id": match.group(2), "state": "incomplete" if match.group(1) else "unverified",
                        "name": item.name})
    return {"destination": str(path), "volume_uuid": volume["volume_uuid"],
            "encrypted": volume["encrypted"], "entries": entries}


def restore_preview(destination: str, generation_id: str) -> dict:
    if UUID.fullmatch(generation_id) is None:
        raise ValueError("A canonical backup generation ID is required")
    inventory_result = backup_inventory(destination)
    if not inventory_result["encrypted"]:
        raise ValueError("Backup source must be an encrypted APFS volume")
    path = Path(inventory_result["destination"])
    generation = path / f"secure-sandbox-backup-{generation_id}"
    stage = path / f".secure-sandbox-backup-{generation_id}.incomplete"
    if stage.exists() or stage.is_symlink():
        raise ValueError("Selected backup generation is ambiguous or incomplete")
    if generation.is_symlink() or not generation.is_dir():
        raise ValueError("Selected backup generation is unavailable")
    operations = backup_operations()
    key = operations.backup.read_backup_key()
    manifest = operations.backup.verify_backup(generation, key)
    if manifest["volume_uuid"] != inventory_result["volume_uuid"]:
        raise ValueError("Backup volume identity changed")
    observed = catalog("overview")
    stopped = observed["status"] == "verified" and all(
        observed["observed"][role] == "stopped" for role in ("gateway", "research", "target"))
    free_bytes = os.statvfs(ROOT / "vms").f_bavail * os.statvfs(ROOT / "vms").f_frsize
    reserve_bytes = max(10 * 1024**3, manifest["logical_bytes"] // 10)
    identities = operations.vm_identities(ROOT) if stopped else None
    current_host = operations.backup.host_config_inventory(ROOT / "config")
    archived_host = {item["path"]: item for item in manifest["host_files"]}
    differing_host = [item["path"] for item in current_host if item != archived_host.get(item["path"])]
    return {"generation_id": generation_id, "destination": str(path),
            "volume_uuid": manifest["volume_uuid"], "vm_uuids": manifest["vm_uuids"],
            "current_vm_uuids": ({name: value["uuid"] for name, value in identities.items()}
                                 if identities else None),
            "file_count": manifest["file_count"], "logical_bytes": manifest["logical_bytes"],
            "manifest_hmac_sha256": manifest["manifest_hmac_sha256"],
            "host_config_matches": not differing_host, "differing_host_config": differing_host,
            "host_free_bytes": free_bytes, "reserve_bytes": reserve_bytes,
            "stack_stopped": stopped,
            "ready": stopped and not differing_host
            and free_bytes >= manifest["logical_bytes"] + reserve_bytes}


def memory_proposals() -> list[dict]:
    raw = run_labctl("memory", "proposals")
    lines = raw.splitlines()
    if len(lines) > 1024:
        raise ValueError("Memory proposal catalog exceeds its limit")
    proposals = []
    for line in lines:
        value = json.loads(line)
        if (not isinstance(value, dict) or set(value) != {
                "proposal_id", "run_id", "created_at", "category", "title", "content_sha256", "status", "authority"}
                or UUID.fullmatch(str(value["proposal_id"])) is None
                or UUID.fullmatch(str(value["run_id"])) is None
                or value["authority"] != "untrusted_proposal"
                or re.fullmatch(r"[0-9a-f]{64}", str(value["content_sha256"])) is None
                or any(not isinstance(value[field], str) or len(value[field]) > limit
                       for field, limit in (("created_at", 40), ("category", 80),
                                            ("title", 200), ("status", 80)))):
            raise ValueError("Memory proposal catalog is invalid")
        proposals.append(value)
    return proposals


def transcript_detail(run_id: str) -> dict:
    if UUID.fullmatch(run_id) is None:
        raise ValueError("A canonical run ID is required")
    raw = run_labctl("transcript", run_id)
    lines = raw.splitlines()
    if not lines or len(lines) > 10_000:
        raise ValueError("Transcript is empty or exceeds the display limit")
    rendered = []
    for line in lines:
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("Transcript record is invalid")
        rendered.append(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    content = "\n".join(rendered) + "\n"
    if len(content.encode("utf-8")) > MAX_OUTPUT:
        raise ValueError("Transcript exceeds the display limit")
    return {"run_id": run_id, "record_count": len(rendered), "content": content}


def export_transcript(run_id: str, destination: str) -> dict:
    """Export a selected archive without routing its plaintext through the JSON bridge."""
    if UUID.fullmatch(run_id) is None:
        raise ValueError("A canonical run ID is required")
    target = Path(destination)
    if not target.is_absolute() or target.name in {"", ".", ".."}:
        raise ValueError("An absolute export file is required")
    parent = target.parent
    if not parent.is_dir() or target.is_dir():
        raise ValueError("The export destination is unavailable")
    if target.is_symlink():
        raise ValueError("The export destination must not be a symbolic link")
    fd, temporary = tempfile.mkstemp(prefix=".secure-sandbox-transcript-", suffix=".tmp", dir=parent)
    process = None
    selector = None
    try:
        os.fchmod(fd, 0o600)
        digest = hashlib.sha256()
        count = 0
        byte_count = 0
        process = subprocess.Popen([str(LABCTL), "transcript", run_id], cwd=ROOT,
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True)
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        pending = bytearray()
        stderr = bytearray()
        deadline = time.monotonic() + 300
        with os.fdopen(fd, "wb") as output:
            fd = -1
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, 300)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.fileobj is process.stderr:
                        stderr.extend(chunk)
                        if len(stderr) > 4096:
                            del stderr[:-4096]
                        continue
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        if len(line) > 8 * 1024 * 1024:
                            raise ValueError("Transcript record exceeds its size limit")
                        value = json.loads(line)
                        if not isinstance(value, dict):
                            raise ValueError("Transcript record is invalid")
                        rendered = (json.dumps(value, ensure_ascii=True, sort_keys=True,
                                               separators=(",", ":")) + "\n").encode("ascii")
                        byte_count += len(rendered)
                        count += 1
                        if byte_count > 512 * 1024 * 1024 or count > 1_000_000:
                            raise ValueError("Transcript export exceeds its size limit")
                        output.write(rendered)
                        digest.update(rendered)
                    if len(pending) > 8 * 1024 * 1024:
                        raise ValueError("Transcript record exceeds its size limit")
            if pending:
                raise ValueError("Transcript ended mid-record")
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if process.returncode:
                raise RuntimeError(host_error(bytes(stderr), process.returncode))
            if count == 0:
                raise ValueError("Transcript is empty")
            output.flush()
            os.fsync(output.fileno())
        if target.is_symlink():
            raise ValueError("The export destination changed")
        os.replace(temporary, target)
        return {"run_id": run_id, "record_count": count, "byte_count": byte_count,
                "sha256": digest.hexdigest(), "status": "verified"}
    finally:
        if selector is not None:
            selector.close()
        if fd >= 0:
            os.close(fd)
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _harness_acceptance_json(*arguments: str) -> dict:
    completed = bounded_command(
        ["/usr/bin/python3", str(HARNESS_ACCEPTANCE), *arguments], timeout=30,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
        raise ValueError("harness_acceptance_status_rejected")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("harness_acceptance_status_invalid") from error
    if not isinstance(value, dict):
        raise ValueError("harness_acceptance_status_invalid")
    return value


def harness_acceptance_status(root: Path = HARNESS_ACCEPTANCE_ROOT) -> dict:
    catalog_value = _harness_acceptance_json("catalog")
    cases = catalog_value.get("cases")
    if (catalog_value.get("schema") != "secure-sandbox-harness-lifecycle-acceptance-catalog-v1"
            or catalog_value.get("suite_id") != "secure-sandbox-disposable-mac-harness-lifecycle-v4"
            or SHA256.fullmatch(str(catalog_value.get("suite_sha256", ""))) is None
            or catalog_value.get("authority") != "none"
            or not isinstance(cases, list) or len(cases) != catalog_value.get("case_count")
            or len(cases) != 91):
        raise ValueError("harness_acceptance_catalog_invalid")
    observation_count = 0
    for case in cases:
        procedure = case.get("procedure") if isinstance(case, dict) else None
        if (not isinstance(case, dict)
                or set(case) != {"case_id", "category", "expected", "evidence_kinds", "collectors",
                                 "procedure",
                                 "requires_touch_id", "requires_reboot", "destructive"}
                or not isinstance(case.get("case_id"), str) or not case["case_id"]
                or case.get("expected") not in {"passed", "rejected"}
                or not isinstance(case.get("evidence_kinds"), list)
                or not 1 <= len(case["evidence_kinds"]) <= 16
                or not isinstance(case.get("collectors"), dict)
                or set(case["collectors"]) != set(case["evidence_kinds"])
                or any(value not in {
                    "secure-sandbox-host-controller-v1",
                    "secure-sandbox-research-controller-v1",
                    "secure-sandbox-privileged-control-v1",
                    "secure-sandbox-touchid-broker-v1",
                    "secure-sandbox-disposable-supervisor-v1",
                    "secure-sandbox-cold-boot-supervisor-v1",
                    "secure-sandbox-evidence-exporter-v1",
                } for value in case["collectors"].values())
                or not isinstance(procedure, dict)
                or set(procedure) != {"schema", "case_id", "driver", "baseline", "action",
                                      "interaction", "network", "interruption_checkpoint",
                                      "postcondition", "reset", "procedure_sha256"}
                or procedure.get("schema")
                    != "secure-sandbox-harness-lifecycle-acceptance-procedure-v1"
                or procedure.get("case_id") != case["case_id"]
                or any(not isinstance(procedure.get(name), str) or not procedure[name]
                       for name in ("driver", "baseline", "action", "interaction", "network",
                                    "postcondition", "reset"))
                or (procedure.get("interruption_checkpoint") is not None
                    and (not isinstance(procedure["interruption_checkpoint"], str)
                         or not procedure["interruption_checkpoint"]))
                or SHA256.fullmatch(str(procedure.get("procedure_sha256", ""))) is None):
            raise ValueError("harness_acceptance_catalog_invalid")
        unsigned_procedure = {key: value for key, value in procedure.items()
                              if key != "procedure_sha256"}
        procedure_digest = hashlib.sha256((json.dumps(
            unsigned_procedure, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")).hexdigest()
        if procedure["procedure_sha256"] != procedure_digest:
            raise ValueError("harness_acceptance_catalog_invalid")
        observation_count += len(case["evidence_kinds"])
    if observation_count != 198:
        raise ValueError("harness_acceptance_catalog_invalid")
    base = {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-availability-v2",
        "suite_id": catalog_value["suite_id"],
        "suite_sha256": catalog_value["suite_sha256"],
        "case_count": catalog_value["case_count"],
        "observation_count": observation_count,
        "authority": "none",
    }
    if not os.path.lexists(root):
        return {**base, "availability": "not-enrolled", "reason": "campaign_absent",
                "status": None, "next": None}
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        return {**base, "availability": "rejected", "reason": "campaign_root_untrusted",
                "status": None, "next": None}
    campaign = root / "campaign.json"
    observations = root / "observations"
    if not campaign.is_file() or campaign.is_symlink() or not observations.is_dir() or observations.is_symlink():
        return {**base, "availability": "not-enrolled", "reason": "campaign_incomplete",
                "status": None, "next": None}
    try:
        status_value = _harness_acceptance_json(
            "status", "--campaign", str(campaign), "--observations", str(observations),
        )
    except ValueError:
        return {**base, "availability": "rejected", "reason": "campaign_verification_failed",
                "status": None, "next": None}
    completed = status_value.get("completed_cases")
    missing = status_value.get("missing")
    ready = status_value.get("ready_for_assembly")
    if (status_value.get("schema") != "secure-sandbox-harness-lifecycle-acceptance-status-v1"
            or not isinstance(status_value.get("campaign_id"), str) or not status_value["campaign_id"]
            or status_value.get("suite_sha256") != base["suite_sha256"]
            or status_value.get("case_count") != base["case_count"]
            or status_value.get("observation_count") != observation_count
            or status_value.get("authority") != "none"
            or not isinstance(status_value.get("completed_case_count"), int)
            or isinstance(status_value.get("completed_case_count"), bool)
            or not 0 <= status_value["completed_case_count"] <= base["case_count"]
            or not isinstance(completed, list)
            or len(completed) != status_value["completed_case_count"]
            or len(set(completed)) != len(completed)
            or any(not isinstance(item, str) or not item for item in completed)
            or not isinstance(missing, list)
            or len(missing) != base["case_count"] - len(completed)
            or any(not isinstance(item, dict)
                   or set(item) != {"case_id", "evidence_kinds"}
                   or not isinstance(item["case_id"], str) or not item["case_id"]
                   or not isinstance(item["evidence_kinds"], list) or not item["evidence_kinds"]
                   for item in missing)
            or not isinstance(ready, bool) or ready != (not missing)
            or status_value.get("next_case") != (missing[0]["case_id"] if missing else None)):
        return {**base, "availability": "rejected", "reason": "campaign_status_invalid",
                "status": None, "next": None}
    try:
        next_value = _harness_acceptance_json(
            "next", "--campaign", str(campaign), "--observations", str(observations),
        )
    except ValueError:
        return {**base, "availability": "rejected", "reason": "campaign_protocol_failed",
                "status": None, "next": None}
    next_case = next_value.get("case")
    missing_evidence = next_value.get("missing_evidence")
    expected_next = status_value.get("next_case")
    expected_missing_evidence = []
    if expected_next is not None:
        catalog_case = next(item for item in cases if item["case_id"] == expected_next)
        status_missing = next(item["evidence_kinds"] for item in missing
                              if item["case_id"] == expected_next)
        expected_missing_evidence = [
            {"kind": kind, "collector": catalog_case["collectors"][kind]}
            for kind in status_missing
        ]
    if (next_value.get("schema") != "secure-sandbox-harness-lifecycle-acceptance-next-v1"
            or next_value.get("campaign_id") != status_value["campaign_id"]
            or next_value.get("suite_sha256") != base["suite_sha256"]
            or next_value.get("authority") != "none"
            or not isinstance(missing_evidence, list)
            or (expected_next is None and (
                next_value.get("status") != "complete" or next_case is not None
                or missing_evidence != []))
            or (expected_next is not None and (
                next_value.get("status") != "pending" or not isinstance(next_case, dict)
                or next_case.get("case_id") != expected_next or not missing_evidence
                or next_case not in cases
                or missing_evidence != expected_missing_evidence))):
        return {**base, "availability": "rejected", "reason": "campaign_protocol_invalid",
                "status": None, "next": None}
    return {**base, "availability": "available", "reason": None,
            "status": status_value, "next": next_value}


def session_runs(session_id: str) -> dict:
    if UUID.fullmatch(session_id) is None:
        raise ValueError("A canonical session ID is required")
    value = json.loads(run_labctl("session", "runs", session_id))
    run_pattern = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
    if (not isinstance(value, dict) or set(value) != {"schema", "session_id", "total_runs", "run_ids"}
            or value["schema"] != "secure-sandbox-session-runs-v2" or value["session_id"] != session_id
            or not isinstance(value["total_runs"], int) or isinstance(value["total_runs"], bool)
            or not 0 <= value["total_runs"] <= 1_000_000 or not isinstance(value["run_ids"], list)
            or len(value["run_ids"]) > min(value["total_runs"], 1000)
            or any(not isinstance(item, str) or run_pattern.fullmatch(item) is None
                   for item in value["run_ids"])
            or len(set(value["run_ids"])) != len(value["run_ids"])):
        raise ValueError("Session run catalog is invalid")
    return value


RUN_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def immutable_lease_sha256(lease: dict) -> str:
    immutable = {name: value for name, value in lease.items()
                 if name not in {"expires_at", "renewals"}}
    return hashlib.sha256(run_lease_contract.canonical_json_line(immutable)).hexdigest()


def lease_status(run_id: str) -> dict:
    if RUN_UUID.fullmatch(run_id) is None:
        raise ValueError("A canonical run ID is required")
    value = json.loads(run_labctl("lease", "status", run_id))
    if not isinstance(value, dict) or set(value) != {"lease", "counters", "summary"}:
        raise ValueError("Lease response is invalid")
    lease, counters, summary = value["lease"], value["counters"], value["summary"]
    if not isinstance(lease, dict) or not isinstance(counters, dict):
        raise ValueError("Lease identity or schema is invalid")
    try:
        run_lease_contract.validate_active_state(lease, counters, run_id)
        if summary is not None:
            validated_summary = run_lease_contract.validate_summary(summary, run_id)
            if (validated_summary["lease"] != lease
                    or validated_summary["final_counters"] != counters):
                raise ValueError("summary state mismatch")
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Lease identity or schema is invalid") from error

    authority = lease["runtime_authority"]
    model_stack = authority["model_stack_binding"]
    if model_stack["mode"] != "brokered-model-profile":
        raise ValueError("Lease transport mode is invalid")
    brokered = model_stack["authority"]
    harness = authority["harness_binding"]
    context = authority["session_context_binding"]
    fields = {"expires_at": lease.get("expires_at"),
              "maximum_expires_at": lease.get("maximum_expires_at"),
              "renewals": lease.get("renewals"),
              "requests": counters.get("requests"),
              "input_tokens": counters.get("input_tokens"),
              "output_tokens": counters.get("output_tokens")}
    if any(not isinstance(number, int) or isinstance(number, bool) or number < 0
           for number in fields.values()):
        raise ValueError("Lease counters are invalid")
    if fields["expires_at"] > fields["maximum_expires_at"]:
        raise ValueError("Lease expiry exceeds its maximum")
    return {"run_id": run_id, "lease_id": lease["lease_id"],
            "state": "closed" if summary is not None else "active",
            "immutable_lease_sha256": immutable_lease_sha256(lease),
            "runtime_authority_sha256": authority["binding_sha256"],
            "mode": model_stack["mode"],
            "adapter": brokered["adapter"], "model": brokered["model"],
            "profile_id": brokered["profile_id"],
            "profile_sha256": brokered["profile_sha256"],
            "provider_mode": brokered["provider_mode"],
            "vendor_id": brokered["vendor_id"],
            "harness_id": harness["harness_id"],
            "harness_generation_id": harness["harness_generation_id"],
            "harness_adapter_id": harness["harness_adapter_id"],
            "session_id": context["session_id"], "source_id": context["source_id"],
            **fields}


def renew_lease(run_id: str, seconds: int) -> dict:
    if seconds not in (300, 900):
        raise ValueError("Choose a five or fifteen minute renewal")
    before = lease_status(run_id)
    if (before["state"] != "active" or before["expires_at"] + seconds > before["maximum_expires_at"]):
        raise ValueError("The selected lease cannot be renewed within its maximum")
    raw = json.loads(run_labctl("lease", "renew", run_id, str(seconds)))
    after = lease_status(run_id)
    try:
        if not isinstance(raw, dict):
            raise ValueError("invalid renewal")
        synthetic_counter = {
            "schema": run_lease_contract.COUNTER_SCHEMA,
            "lease_id": raw.get("lease_id"), "run_id": run_id,
            "requests": 0, "input_tokens": 0, "output_tokens": 0,
            "cost_microusd": 0, "reservations": {}, "settled_reservations": [],
            "updated_at": raw.get("issued_at"),
        }
        run_lease_contract.validate_active_state(raw, synthetic_counter, run_id)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Lease renewal response is invalid") from error
    if (raw.get("lease_id") != before["lease_id"]
            or raw.get("expires_at") != after["expires_at"]
            or after["lease_id"] != before["lease_id"]
            or after["expires_at"] != before["expires_at"] + seconds
            or after["renewals"] != before["renewals"] + 1
            or raw.get("renewals") != after["renewals"]
            or immutable_lease_sha256(raw) != before["immutable_lease_sha256"]
            or after["immutable_lease_sha256"] != before["immutable_lease_sha256"]
            or raw.get("runtime_authority", {}).get("binding_sha256")
               != before["runtime_authority_sha256"]
            or after["runtime_authority_sha256"] != before["runtime_authority_sha256"]):
        raise ValueError("Lease renewal readback is ambiguous; refresh before another action")
    return after


def reconcile_plan(run_id: str) -> dict:
    if RUN_UUID.fullmatch(run_id) is None:
        raise ValueError("A canonical run ID is required")
    value = json.loads(run_labctl("lease", "reconcile-plan", run_id))
    if (not isinstance(value, dict)
            or set(value) != {"schema", "run_id", "lease_id", "gateway_summary_sha256"}
            or value["schema"] != "secure-sandbox-lease-reconcile-plan-v1"
            or value["run_id"] != run_id
            or not isinstance(value["lease_id"], str)
            or RUN_UUID.fullmatch(value["lease_id"]) is None
            or not isinstance(value["gateway_summary_sha256"], str)
            or SHA256.fullmatch(value["gateway_summary_sha256"]) is None):
        raise ValueError("Lease reconciliation plan is invalid")
    gateway = lease_status(run_id)
    if gateway["state"] != "closed" or gateway["lease_id"] != value["lease_id"]:
        raise ValueError("Gateway lease is not finalized for reconciliation")
    return value


def completed_lease(run_id: str) -> dict:
    if RUN_UUID.fullmatch(run_id) is None:
        raise ValueError("A canonical run ID is required")
    value = json.loads(run_labctl("lease", "completed", run_id))
    if (not isinstance(value, dict) or value.get("schema") != "secure-sandbox-run-lifecycle-v2"
            or value.get("phase") != "committed" or value.get("run_id") != run_id
            or not isinstance(value.get("lease_id"), str)
            or RUN_UUID.fullmatch(value["lease_id"]) is None
            or not isinstance(value.get("gateway_summary_sha256"), str)
            or SHA256.fullmatch(value["gateway_summary_sha256"]) is None):
        raise ValueError("Completed lease readback is invalid")
    return {"run_id": run_id, "lease_id": value["lease_id"], "phase": "committed",
            "gateway_summary_sha256": value["gateway_summary_sha256"]}


def reconcile_lease(run_id: str, expected_digest: str) -> dict:
    if SHA256.fullmatch(expected_digest) is None:
        raise ValueError("A reviewed Gateway summary digest is required")
    plan = reconcile_plan(run_id)
    if plan["gateway_summary_sha256"] != expected_digest:
        raise ValueError("Gateway summary changed since review")
    completed = bounded_command([str(LABCTL), "lease", "reconcile", run_id], timeout=60)
    try:
        result = completed_lease(run_id)
    except (ValueError, RuntimeError) as error:
        raise ValueError("Lease reconciliation outcome is unclear; inspect the completed run before another action") from error
    if (result["lease_id"] != plan["lease_id"]
            or result["gateway_summary_sha256"] != expected_digest):
        raise ValueError("Lease reconciliation readback does not match the reviewed plan")
    if completed.returncode != 0:
        # The durable Research completed record is authoritative after a lost response.
        return result
    return result


def archived_tool_results(run_id: str, selected_tool_id: str | None = None) -> tuple[list[dict], dict[str, str]]:
    uses: dict[str, str] = {}
    results = []
    contents = {}
    result_ids: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="secure-sandbox-tool-results-") as directory:
        transcript = Path(directory) / "verified.jsonl"
        export_transcript(run_id, str(transcript))
        with transcript.open("r", encoding="ascii") as stream:
            for line in stream:
                record = json.loads(line)
                message = record.get("message")
                blocks = message.get("content") if isinstance(message, dict) else None
                if not isinstance(blocks, list):
                    continue
                if len(blocks) > 10_000:
                    raise ValueError("Archived message has too many content blocks")
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    if record.get("type") == "assistant" and block.get("type") == "tool_use":
                        identifier, name = block.get("id"), block.get("name")
                        if (not isinstance(identifier, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier) is None
                                or not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) is None
                                or identifier in uses or len(uses) >= 10_000):
                            raise ValueError("Archived tool use identity is invalid")
                        uses[identifier] = name
                    if record.get("type") == "user" and block.get("type") == "tool_result":
                        identifier = block.get("tool_use_id")
                        if (not isinstance(identifier, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier) is None
                                or identifier in result_ids):
                            raise ValueError("Archived tool result identity is invalid")
                        rendered = json.dumps(block, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
                        encoded = rendered.encode("utf-8")
                        if len(encoded) > 4 * 1024 * 1024 or len(results) >= 2000:
                            raise ValueError("Archived tool result exceeds its limit")
                        digest = hashlib.sha256(encoded).hexdigest()
                        results.append({"tool_use_id": identifier, "name": uses.get(identifier, "Unmatched tool"),
                                        "ordinal": len(results) + 1, "bytes": len(encoded),
                                        "sha256": digest, "is_error": block.get("is_error") is True})
                        result_ids.add(identifier)
                        if identifier == selected_tool_id:
                            contents[identifier] = rendered
    return results, contents


def tool_result_catalog(run_id: str) -> dict:
    rows, _ = archived_tool_results(run_id)
    return {"run_id": run_id, "results": rows}


def tool_result_detail(run_id: str, tool_use_id: str, expected_sha256: str) -> dict:
    if (re.fullmatch(r"[A-Za-z0-9_-]{1,128}", tool_use_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None):
        raise ValueError("A selected tool result identity and digest are required")
    rows, contents = archived_tool_results(run_id, selected_tool_id=tool_use_id)
    selected = next((row for row in rows if row["tool_use_id"] == tool_use_id), None)
    if selected is None or selected["sha256"] != expected_sha256:
        raise ValueError("Selected tool result digest changed")
    return {"run_id": run_id, **selected, "content": contents[tool_use_id]}


def restore_operations():
    path = ROOT / "scripts/control_center_restore_operation.py"
    spec = importlib.util.spec_from_file_location("control_center_restore_operations", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Restore operation service is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plan_restore(source: str, generation_id: str) -> dict:
    preview = restore_preview(source, generation_id)
    if not preview["ready"]:
        raise ValueError("Restore source, host configuration, capacity, or stopped-stack preflight is not ready")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    identities = operations.base.vm_identities(ROOT)
    plan = operations.create_plan(
        operations.default_root(), Path(preview["destination"]), generation_id,
        preview["volume_uuid"], preview["manifest_hmac_sha256"], identities,
        preview["file_count"], preview["logical_bytes"], key)
    return operations.plan_detail(operations.default_root(), plan["restore_id"], key)


def restore_plan_detail(restore_id: str) -> dict:
    if UUID.fullmatch(restore_id) is None:
        raise ValueError("A canonical restore plan ID is required")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    return operations.plan_detail(operations.default_root(), restore_id, key)


def submit_restore(restore_id: str) -> dict:
    if UUID.fullmatch(restore_id) is None:
        raise ValueError("A canonical restore plan ID is required")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    return operations.submit(operations.default_root(), ROOT, restore_id, key)


def restore_operation_status(restore_id: str) -> dict:
    if UUID.fullmatch(restore_id) is None:
        raise ValueError("A canonical restore plan ID is required")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    return operations.operation_status(operations.default_root(), ROOT, restore_id, key)


def recover_restore(restore_id: str) -> dict:
    if UUID.fullmatch(restore_id) is None:
        raise ValueError("A canonical restore plan ID is required")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    return operations.submit_recovery(operations.default_root(), ROOT, restore_id, key)


def restore_retirement_preview(restore_id: str) -> dict:
    if UUID.fullmatch(restore_id) is None:
        raise ValueError("A canonical restore plan ID is required")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    return operations.retirement_preview(
        operations.default_root(), ROOT, restore_id, key)


def restore_retirement_status(restore_id: str) -> dict:
    if UUID.fullmatch(restore_id) is None:
        raise ValueError("A canonical restore plan ID is required")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    return operations.retirement_status(
        operations.default_root(), ROOT, restore_id, key)


def retire_restore_generation(restore_id: str) -> dict:
    if UUID.fullmatch(restore_id) is None:
        raise ValueError("A canonical restore plan ID is required")
    operations = restore_operations()
    key = operations.backup.read_backup_key()
    return operations.submit_retirement(
        operations.default_root(), ROOT, restore_id, key)


def verify_boundaries() -> dict:
    completed = bounded_command([str(LABCTL), "verify"], timeout=600)
    lines = completed.stdout.decode("utf-8", "strict").splitlines()
    if not lines:
        raise ValueError("Boundary verification returned no result")
    passed = sum(line.startswith("PASS  ") for line in lines)
    gates = sum(line.startswith("GATE  ") for line in lines)
    failures = [line[6:] for line in lines if line.startswith("FAIL  ")]
    if (len(failures) > 128 or any(not label or len(label) > 180
                                   or not all(32 <= ord(character) <= 126 for character in label)
                                   for label in failures)):
        raise ValueError("Boundary verification returned invalid failure labels")
    if completed.returncode == 0:
        if (lines[-1] != "BOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use."
                or failures or passed < 1):
            raise ValueError("Boundary verification did not return its success marker")
        return {"status": "verified", "passed_checks": passed, "gate_notices": gates,
                "failed_checks": 0, "failure_labels": []}
    if (lines[-1] != f"BOUNDARY VERIFICATION FAILED: {len(failures)} check(s)"
            or not failures):
        raise RuntimeError(host_error(completed.stderr[-4096:], completed.returncode))
    return {"status": "rejected", "passed_checks": passed, "gate_notices": gates,
            "failed_checks": len(failures), "failure_labels": failures}


def lifecycle(operation: str) -> dict[str, str]:
    if operation not in ("start", "stop"):
        raise ValueError("Unsupported lifecycle action")
    before = catalog("overview")
    if before["status"] != "verified":
        raise ValueError("The current VM state is not verified")
    gui = subprocess.run(["/usr/bin/pgrep", "-x", "prl_client_app"],
                         stdin=subprocess.DEVNULL, capture_output=True,
                         timeout=5, check=False)
    if gui.returncode == 0:
        raise ValueError("Quit Parallels Desktop before changing VM state")
    if gui.returncode != 1:
        raise ValueError("Parallels Desktop state could not be checked")
    raw = run_labctl(operation)
    try:
        result = json.loads(raw.splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise ValueError("Lifecycle completion record is missing") from error
    if (not isinstance(result, dict) or result.get("schema") != "secure-sandbox-host-lifecycle-v1"
            or result.get("operation") != operation or result.get("status") != "verified"
            or result.get("phase") != "complete"):
        raise ValueError("Lifecycle completion was not verified")
    after = catalog("overview")
    expected = "running" if operation == "start" else "stopped"
    if (after["status"] != "verified"
            or any(after["observed"][vm] != expected for vm in ("gateway", "research", "target"))):
        raise ValueError("The independent VM state readback did not match the requested state")
    if operation == "start" and (after["observed"].get("gateway_net0") != "connected"
            or any(after.get("reachability", {}).get(vm) != "reachable"
                   for vm in ("gateway", "research", "target"))):
        raise ValueError("Start completed but uplink or guest reachability is incomplete")
    response = {"operation": operation, "status": "verified", "gateway": expected,
                "research": expected, "target": expected}
    if operation == "start":
        response.update({"gateway_net0": after["observed"]["gateway_net0"],
                         "guest_reachability": "verified", "clock_sync": "verified",
                         "boundary_verification": "verified"})
    return response


def lifecycle_progress() -> dict[str, str]:
    value = json.loads(run_labctl("lifecycle-progress"))
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-host-lifecycle-progress-v1"
            or value.get("state") not in {"idle", "starting", "active"}):
        raise ValueError("Lifecycle progress is invalid")
    if value["state"] == "active":
        if (value.get("operation") not in {"start", "stop"}
                or value.get("phase") not in {"preflight", "vm_start", "gateway_uplink",
                                              "guest_readiness", "guest_shutdown", "time_sync",
                                              "boundary_verification"}
                or value.get("target") not in {"", "gateway", "research", "target"}
                or UUID.fullmatch(str(value.get("transition_id", ""))) is None
                or not isinstance(value.get("observed_at"), str)
                or len(value["observed_at"]) > 40):
            raise ValueError("Lifecycle progress is invalid")
    elif set(value) != {"schema", "state"}:
        raise ValueError("Lifecycle progress is invalid")
    return value


def panic() -> dict:
    completed = bounded_command([str(LABCTL), "panic"], timeout=120)
    records = (completed.stdout + b"\n" + completed.stderr).decode("utf-8", "replace").splitlines()
    parsed = []
    for line in records:
        if line.startswith("{"):
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    matches = [value for value in parsed if isinstance(value, dict)
               and value.get("schema") == "secure-sandbox-host-lifecycle-v1"
               and value.get("operation") == "panic"]
    if len(matches) != 1:
        raise ValueError("Panic completion record is unavailable; refresh VM status before another action")
    record = matches[0]
    if (not isinstance(record, dict) or record.get("schema") != "secure-sandbox-host-lifecycle-v1"
            or record.get("operation") != "panic" or record.get("status") not in ("verified", "rejected")
            or not isinstance(record.get("observed"), dict)):
        raise ValueError("Panic completion record is invalid")
    observed = catalog("overview")
    states = observed.get("observed", {})
    verified = (completed.returncode == 0 and record["status"] == "verified"
                and observed.get("status") == "verified"
                and states.get("research") == "stopped" and states.get("target") == "stopped"
                and states.get("gateway_net0") == "disconnected")
    return {"status": "verified" if verified else "incomplete",
            "research": states.get("research", "unknown"),
            "target": states.get("target", "unknown"),
            "gateway_net0": states.get("gateway_net0", "unknown")}


def reload_control_identities() -> dict[str, str]:
    completed = bounded_command([str(LABCTL), "key-load"], timeout=120)
    if completed.returncode != 0:
        raise ValueError("Identity reload did not complete; inspect the host key agents before retrying")
    sockets = (("provisioning", "/tmp/secure-sandbox-ssh-agent.sock"),
               ("control", "/tmp/secure-sandbox-control-ssh-agent.sock"))
    for label, socket in sockets:
        observed = bounded_command(["/usr/bin/ssh-add", "-l"], timeout=10,
                                   env={**os.environ, "SSH_AUTH_SOCK": socket})
        if observed.returncode != 0 or b"SHA256:" not in observed.stdout:
            raise ValueError(f"{label.capitalize()} identity readback failed")
    return {"status": "verified", "provisioning": "loaded", "control": "loaded"}


def model_profile_settings(stage: bytes | None = None) -> dict:
    command = ["/usr/bin/python3", str(MODEL_PROFILE_CONFIG),
               "stage" if stage is not None else "status"]
    if stage is not None and len(stage) > 64 * 1024:
        raise ValueError("Model profile catalog exceeds its size limit")
    completed = subprocess.run(
        command, cwd=ROOT, input=stage if stage is not None else b"",
        capture_output=True, check=False,
        timeout=10, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    if completed.returncode != 0:
        try:
            rejected = json.loads(completed.stdout)
            code = rejected.get("error") if isinstance(rejected, dict) else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            code = None
        raise ValueError(code if isinstance(code, str) else "model_profile_settings_unavailable")
    value = json.loads(completed.stdout)
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-model-profile-catalog-status-v1"
            or value.get("status") != "verified"
            or value.get("source") not in {"example", "staged"}
            or SHA256.fullmatch(str(value.get("catalog_sha256", ""))) is None
            or not isinstance(value.get("profiles"), list)
            or not 1 <= len(value["profiles"]) <= 16):
        raise ValueError("model_profile_settings_invalid")
    return value


def native_vendor_stack_settings(stage: bytes | None = None) -> dict:
    command = ["/usr/bin/python3", str(NATIVE_VENDOR_STACK_CONFIG),
               "stage" if stage is not None else "status"]
    if stage is not None and len(stage) > 64 * 1024:
        raise ValueError("Native vendor stack catalog exceeds its size limit")
    completed = subprocess.run(
        command, cwd=ROOT, input=stage if stage is not None else b"",
        capture_output=True, check=False,
        timeout=10, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    if completed.returncode != 0:
        try:
            rejected = json.loads(completed.stdout)
            code = rejected.get("error") if isinstance(rejected, dict) else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            code = None
        raise ValueError(code if isinstance(code, str) else "native_stack_settings_unavailable")
    value = json.loads(completed.stdout)
    entries = value.get("stacks") if isinstance(value, dict) else None
    catalog = value.get("catalog") if isinstance(value, dict) else None
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-native-vendor-stack-catalog-status-v1"
            or value.get("status") != "verified"
            or value.get("source") not in {"example", "staged"}
            or SHA256.fullmatch(str(value.get("catalog_sha256", ""))) is None
            or not isinstance(catalog, dict)
            or catalog.get("schema") != "secure-sandbox-native-vendor-stack-catalog-v1"
            or not isinstance(catalog.get("stacks"), list)
            or not isinstance(entries, list)
            or not 1 <= len(entries) == len(catalog["stacks"]) <= 8
            or any(not isinstance(item, dict)
                   or SHA256.fullmatch(str(item.get("revision_sha256", ""))) is None
                   or not isinstance(item.get("readiness"), dict)
                   or item["readiness"].get("schema")
                       != "secure-sandbox-native-vendor-stack-readiness-v1"
                   or item["readiness"].get("status") not in {
                       "configuration-required", "login-required", "content-ready"
                   }
                   or not isinstance(item.get("stack"), dict)
                   or item["stack"] != catalog["stacks"][index]
                   or item["readiness"].get("stack_id") != item["stack"].get("stack_id")
                   or item["readiness"].get("stack_sha256") != item["revision_sha256"]
                   for index, item in enumerate(entries))):
        raise ValueError("native_stack_settings_invalid")
    return value


def _write_private_plan(root: Path, identifier: str, raw: bytes) -> Path:
    if UUID4.fullmatch(identifier) is None or not 2 <= len(raw) <= 1024 * 1024:
        raise ValueError("native_stack_plan_invalid")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("native_stack_plan_root_untrusted")
    if len(list(root.glob("*.json"))) >= 256:
        raise ValueError("native_stack_plan_retention_full")
    path = root / f"{identifier}.json"
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


def _read_private_plan(path: Path, expected_sha256: str) -> tuple[dict, bytes]:
    if SHA256.fullmatch(expected_sha256) is None:
        raise ValueError("native_stack_plan_identity_invalid")
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, 1024 * 1024 + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != os.geteuid() or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not 2 <= opened.st_size <= 1024 * 1024
            or len(raw) != opened.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                opened.st_ctime_ns)
            or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise ValueError("native_stack_plan_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_stack_plan_invalid") from error
    if (not isinstance(value, dict)
            or raw != native_stack_operations.canonical_bytes(value)
            or value.get("plan_sha256") != expected_sha256):
        raise ValueError("native_stack_plan_changed")
    return value, raw


def native_deployment_query_request(
    command: str, *, query_id: str | None = None,
) -> dict:
    schema = NATIVE_DEPLOYMENT_QUERY_SCHEMAS.get(command)
    identifier = str(uuid.uuid4()) if query_id is None else query_id
    if schema is None or UUID4.fullmatch(identifier) is None:
        raise ValueError("native_deployment_query_invalid")
    body = {"query_id": identifier, "command": command}
    return {
        "schema": schema,
        "query_id": identifier,
        "request_sha256": native_deployment.digest(body),
    }


def _native_deployment_plan_response(
    value: object, *, require_fresh: bool,
    expected_host_release_id: str | None = None,
) -> dict:
    fields = {
        "schema", "plan", "prior_gateway", "prior_research",
        "payload_container_sha256", "response_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("native_deployment_plan_response_invalid")
    try:
        plan = native_deployment.validate_plan(
            value["plan"], now=int(time.time()), require_fresh=require_fresh)
        gateway, research = native_deployment.validate_plan_predecessor_statuses(
            plan, gateway_status=value["prior_gateway"],
            research_status=value["prior_research"])
    except native_deployment.NativeDeploymentError as error:
        raise ValueError("native_deployment_plan_response_invalid") from error
    body = {
        "plan": plan, "prior_gateway": gateway,
        "prior_research": research,
        "payload_container_sha256": value["payload_container_sha256"],
    }
    if (
        value.get("schema")
        != "secure-sandbox-native-deployment-plan-response-v1"
        or SHA256.fullmatch(str(value.get("payload_container_sha256", "")))
        is None
        or value.get("response_sha256") != native_deployment.digest(body)
        or (
            expected_host_release_id is not None
            and plan["host_release_id"] != expected_host_release_id
        )
    ):
        raise ValueError("native_deployment_plan_response_invalid")
    return {
        "schema": "secure-sandbox-native-deployment-plan-response-v1",
        **body, "response_sha256": value["response_sha256"],
    }


def _native_deployment_status(
    value: object, *, expected_host_release_id: str,
) -> dict:
    fields = {
        "schema", "state", "phase", "deployment_id", "host_release_id",
        "active_journal_sha256", "error_sha256", "status_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("native_deployment_status_invalid")
    body = {key: value[key] for key in fields - {"schema", "status_sha256"}}
    state = value.get("state")
    if state == "ready":
        valid = all(value[name] is None for name in (
            "phase", "deployment_id", "host_release_id",
            "active_journal_sha256", "error_sha256"))
    elif state == "recovery-required" and value.get("phase") == "state-invalid":
        valid = (
            value.get("deployment_id") is None
            and value.get("host_release_id") is None
            and value.get("active_journal_sha256") is None
            and SHA256.fullmatch(str(value.get("error_sha256", ""))) is not None
        )
    elif state == "recovery-required":
        valid = (
            isinstance(value.get("phase"), str)
            and re.fullmatch(r"[a-z][a-z-]{0,63}", value["phase"]) is not None
            and UUID4.fullmatch(str(value.get("deployment_id", ""))) is not None
            and value.get("host_release_id") == expected_host_release_id
            and SHA256.fullmatch(
                str(value.get("active_journal_sha256", ""))) is not None
            and value.get("error_sha256") is None
        )
    else:
        valid = False
    if (
        value.get("schema")
        != "secure-sandbox-native-deployment-public-status-v1"
        or not valid
        or value.get("status_sha256") != native_deployment.digest(body)
    ):
        raise ValueError("native_deployment_status_invalid")
    return dict(value)


def _native_deployment_recovery_plan(
    value: object, *, expected_host_release_id: str,
) -> dict:
    fields = {
        "schema", "active_journal_sha256", "deployment_id",
        "host_release_id", "phase", "observed_pair", "allowed_actions",
        "plan_response", "gateway_status_sha256", "research_status_sha256",
        "recovery_plan_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("native_deployment_recovery_plan_invalid")
    plan_response = _native_deployment_plan_response(
        value["plan_response"], require_fresh=False,
        expected_host_release_id=expected_host_release_id)
    plan = plan_response["plan"]
    body = {key: value[key] for key in fields - {
        "schema", "recovery_plan_sha256"}}
    if (
        value.get("schema")
        != "secure-sandbox-native-deployment-recovery-plan-v1"
        or SHA256.fullmatch(str(value.get("active_journal_sha256", "")))
        is None
        or value.get("deployment_id") != plan["deployment_id"]
        or value.get("host_release_id") != expected_host_release_id
        or not isinstance(value.get("phase"), str)
        or re.fullmatch(r"[a-z][a-z-]{0,63}", value["phase"]) is None
        or value.get("observed_pair") not in {
            "prior-prior", "candidate-prior", "candidate-candidate",
            "unavailable"}
        or value.get("allowed_actions") not in (
            [], ["resume"], ["rollback"], ["rollback", "resume"])
        or any(
            item is not None
            and (not isinstance(item, str) or SHA256.fullmatch(item) is None)
            for item in (
                value.get("gateway_status_sha256"),
                value.get("research_status_sha256")))
        or ((value.get("gateway_status_sha256") is None)
            != (value.get("research_status_sha256") is None))
        or value.get("recovery_plan_sha256")
        != native_deployment.digest(body)
    ):
        raise ValueError("native_deployment_recovery_plan_invalid")
    admitted = dict(value)
    admitted["plan_response"] = plan_response
    return admitted


def native_deployment_query_reply(
    command: str, request: dict, raw: bytes,
) -> dict:
    schema = NATIVE_DEPLOYMENT_REPLY_SCHEMAS.get(command)
    if (
        schema is None or not 2 <= len(raw) <= 4 * 1024 * 1024
        or request != native_deployment_query_request(
            command, query_id=request.get("query_id"))
    ):
        raise ValueError("native_deployment_query_reply_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_deployment_query_reply_invalid") from error
    if isinstance(value, dict) and value.get("schema") == (
        NATIVE_DEPLOYMENT_QUERY_ERROR_SCHEMA
    ):
        if set(value) != {"schema", "command", "status", "error"}:
            raise ValueError("native_deployment_query_reply_invalid")
        raise ValueError(str(value.get("error", "native_deployment_query_rejected")))
    fields = {
        "schema", "query_id", "command", "request_sha256",
        "host_release_id", "result", "reply_sha256",
    }
    if (
        not isinstance(value, dict) or set(value) != fields
        or value.get("schema") != schema
        or value.get("query_id") != request["query_id"]
        or value.get("command") != command
        or value.get("request_sha256") != request["request_sha256"]
        or SHA256.fullmatch(str(value.get("host_release_id", ""))) is None
    ):
        raise ValueError("native_deployment_query_reply_invalid")
    host_release_id = value["host_release_id"]
    if command == "plan":
        result = _native_deployment_plan_response(
            value["result"], require_fresh=True,
            expected_host_release_id=host_release_id)
    elif command == "status":
        result = _native_deployment_status(
            value["result"], expected_host_release_id=host_release_id)
    else:
        result = _native_deployment_recovery_plan(
            value["result"], expected_host_release_id=host_release_id)
    body = {
        "query_id": value["query_id"], "command": command,
        "request_sha256": value["request_sha256"],
        "host_release_id": host_release_id, "result": result,
    }
    if (
        value.get("reply_sha256") != native_deployment.digest(body)
        or raw != native_deployment.canonical(value, maximum=4 * 1024 * 1024)
    ):
        raise ValueError("native_deployment_query_reply_invalid")
    return result


def _native_deployment_terminal_result(
    value: object, *, plan_response: dict, operation: str, action: str,
) -> dict:
    fields = {
        "schema", "deployment_id", "sequence", "phase", "plan",
        "apply_authorization_sha256", "authorization_sha256",
        "host_release_id", "payload_container_sha256", "prior_gateway",
        "prior_research", "event", "evidence", "transport",
        "prior_record_sha256", "updated_at", "record_sha256",
    }
    evidence_fields = {
        "gateway_status", "research_status", "gateway_status_sha256",
        "research_status_sha256", "fence_evidence_sha256", "result_sha256",
        "terminal_sha256", "outcome",
    }
    if (
        not isinstance(value, dict) or set(value) != fields
        or not isinstance(value.get("evidence"), dict)
        or set(value["evidence"]) != evidence_fields
    ):
        raise ValueError("native_deployment_result_invalid")
    plan = plan_response["plan"]
    try:
        admitted_plan = native_deployment.validate_plan(
            value["plan"], require_fresh=False)
        native_deployment.validate_plan_predecessor_statuses(
            admitted_plan, gateway_status=value["prior_gateway"],
            research_status=value["prior_research"])
        gateway = native_deployment.validate_status_projection(
            value["evidence"]["gateway_status"])
        research = native_deployment.validate_status_projection(
            value["evidence"]["research_status"])
    except native_deployment.NativeDeploymentError as error:
        raise ValueError("native_deployment_result_invalid") from error
    gateway_sha = native_deployment.status_projection_sha256(gateway)
    research_sha = native_deployment.status_projection_sha256(research)
    gateway_prior = gateway_sha == plan["previous_gateway_status_sha256"]
    research_prior = research_sha == plan["previous_research_status_sha256"]
    gateway_candidate = (
        gateway["state"] == "verified"
        and gateway["generation_kind"] == "protected"
        and gateway["package_sha256"] == plan["gateway_package_sha256"]
        and gateway["catalog_sha256"] is None)
    research_candidate = (
        research["state"] == "verified"
        and research["generation_kind"] == "protected"
        and research["package_sha256"] == plan["research_package_sha256"]
        and research["catalog_sha256"] == plan["catalog_sha256"])
    gateway_forward = gateway_candidate or (
        gateway_prior and plan["gateway_package_sha256"]
        == plan["previous_gateway_package_sha256"])
    research_forward = research_candidate or (
        research_prior and plan["research_package_sha256"]
        == plan["previous_research_package_sha256"]
        and research["catalog_sha256"] == plan["catalog_sha256"])
    expected_phase = "rolled-back" if action == "rollback" else "committed"
    body = {key: item for key, item in value.items()
            if key not in {"schema", "record_sha256"}}
    if (
        operation not in native_deployment.OPERATIONS
        or action not in {"apply", "resume", "rollback"}
        or value.get("schema")
        != "secure-sandbox-native-deployment-journal-record-v1"
        or admitted_plan != plan
        or value.get("deployment_id") != plan["deployment_id"]
        or value.get("host_release_id") != plan["host_release_id"]
        or value.get("payload_container_sha256")
        != plan_response["payload_container_sha256"]
        or value.get("phase") != expected_phase
        or value.get("event") != expected_phase
        or value["evidence"].get("outcome") != expected_phase
        or value.get("transport") is not None
        or SHA256.fullmatch(str(value.get("apply_authorization_sha256", "")))
        is None
        or SHA256.fullmatch(str(value.get("authorization_sha256", "")))
        is None
        or SHA256.fullmatch(str(value.get("prior_record_sha256", ""))) is None
        or not isinstance(value.get("sequence"), int)
        or isinstance(value.get("sequence"), bool) or value["sequence"] < 1
        or gateway["role"] != "gateway" or research["role"] != "research"
        or gateway_sha != value["evidence"].get("gateway_status_sha256")
        or research_sha != value["evidence"].get("research_status_sha256")
        or SHA256.fullmatch(
            str(value["evidence"].get("terminal_sha256", ""))) is None
        or value["evidence"].get("fence_evidence_sha256") is not None
        or value["evidence"].get("result_sha256") is not None
        or (expected_phase == "committed"
            and not (gateway_forward and research_forward))
        or (expected_phase == "rolled-back"
            and not (gateway_prior and research_prior))
        or value.get("record_sha256") != native_deployment.digest(body)
    ):
        raise ValueError("native_deployment_result_invalid")
    return dict(value)


def native_deployment_authorize(
    action: str, expected_sha256: str, agent: str, session: str,
    query_request: dict, query_reply_raw: bytes,
) -> dict:
    if (
        action not in {"apply", "resume", "rollback"}
        or SHA256.fullmatch(expected_sha256) is None
        or agent != "Control Center" or UUID4.fullmatch(session) is None
    ):
        raise ValueError("native_deployment_authorization_identity_invalid")
    query_command = "plan" if action == "apply" else "recovery-plan"
    result = native_deployment_query_reply(
        query_command, query_request, query_reply_raw)
    if action == "apply":
        plan_response = result
        if plan_response["response_sha256"] != expected_sha256:
            raise ValueError("native_deployment_authorization_plan_changed")
        operation = native_deployment.APPLY_OPERATION
        parameters = {"plan": plan_response}
    else:
        recovery = result
        if (
            recovery["recovery_plan_sha256"] != expected_sha256
            or action not in recovery["allowed_actions"]
        ):
            raise ValueError("native_deployment_authorization_plan_changed")
        plan_response = recovery["plan_response"]
        operation = native_deployment.RECOVER_OPERATION
        parameters = {"recovery": recovery, "action": action}
    completed = bounded_authorization_command(
        [
            str(AUTHORIZATION_BROKER), "request",
            "--agent", agent, "--session", session,
            "--purpose", f"Authorize exact native deployment {action}",
            "--resource", native_deployment.RESOURCE,
            "--operation", operation,
            "--parameters-json",
            native_deployment.canonical(parameters).decode("ascii").rstrip("\n"),
        ],
        timeout=NATIVE_PRIVILEGED_CLIENT_TIMEOUT_SECONDS,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
    )
    if (
        completed.returncode != 0
        or len(completed.stderr) > NATIVE_PRIVILEGED_STDERR_LIMIT
        or not 2 <= len(completed.stdout) <= 4 * 1024 * 1024
    ):
        raise ValueError("native_deployment_authorization_rejected")
    try:
        terminal = _native_deployment_terminal_result(
            json.loads(completed.stdout), plan_response=plan_response,
            operation=operation, action=action)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_deployment_result_invalid") from error
    if completed.stdout != native_deployment.canonical(
        terminal, maximum=4 * 1024 * 1024
    ):
        raise ValueError("native_deployment_result_invalid")
    return terminal


def native_catalog_promotion_gate_request(
    *, query_id: str | None = None,
) -> dict:
    identifier = str(uuid.uuid4()) if query_id is None else query_id
    if UUID4.fullmatch(identifier) is None:
        raise ValueError("native_catalog_promotion_gate_query_invalid")
    body = {
        "query_id": identifier,
        "command": NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
    }
    return {
        "schema": NATIVE_CATALOG_PROMOTION_GATE_REQUEST_SCHEMA,
        "query_id": identifier,
        "request_sha256": native_deployment.digest(body),
    }


def _native_catalog_promotion_gate(value: object) -> dict:
    fields = {
        "schema", "state", "active_promotion_id",
        "active_state_sha256", "gate_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("native_catalog_promotion_gate_invalid")
    body = {
        "state": value["state"],
        "active_promotion_id": value["active_promotion_id"],
        "active_state_sha256": value["active_state_sha256"],
    }
    if value["state"] == "active":
        valid = (
            UUID4.fullmatch(str(value["active_promotion_id"])) is not None
            and SHA256.fullmatch(str(value["active_state_sha256"])) is not None
        )
    elif value["state"] in {"ready", "invalid"}:
        valid = (
            value["active_promotion_id"] is None
            and value["active_state_sha256"] is None
        )
    else:
        valid = False
    if (
        value["schema"] != NATIVE_CATALOG_PROMOTION_GATE_SCHEMA
        or not valid
        or value["gate_sha256"] != native_deployment.digest(body)
    ):
        raise ValueError("native_catalog_promotion_gate_invalid")
    return dict(value)


def native_catalog_promotion_gate_reply(
    request: dict, raw: bytes,
) -> dict:
    if (
        not 2 <= len(raw) <= 1024 * 1024
        or request != native_catalog_promotion_gate_request(
            query_id=request.get("query_id"))
    ):
        raise ValueError("native_catalog_promotion_gate_reply_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_catalog_promotion_gate_reply_invalid") from error
    if (
        isinstance(value, dict)
        and value.get("schema") == NATIVE_CATALOG_PROMOTION_GATE_ERROR_SCHEMA
    ):
        if set(value) != {"schema", "command", "status", "error"}:
            raise ValueError("native_catalog_promotion_gate_reply_invalid")
        raise ValueError(str(value.get(
            "error", "native_catalog_promotion_gate_query_rejected")))
    fields = {
        "schema", "query_id", "command", "request_sha256",
        "host_release_id", "gate", "reply_sha256",
    }
    if (
        not isinstance(value, dict) or set(value) != fields
        or value.get("schema") != NATIVE_CATALOG_PROMOTION_GATE_REPLY_SCHEMA
        or value.get("query_id") != request["query_id"]
        or value.get("command") != NATIVE_CATALOG_PROMOTION_GATE_COMMAND
        or value.get("request_sha256") != request["request_sha256"]
        or SHA256.fullmatch(str(value.get("host_release_id", ""))) is None
    ):
        raise ValueError("native_catalog_promotion_gate_reply_invalid")
    gate = _native_catalog_promotion_gate(value["gate"])
    body = {
        "query_id": value["query_id"],
        "command": NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
        "request_sha256": value["request_sha256"],
        "host_release_id": value["host_release_id"],
        "gate": gate,
    }
    if (
        value["reply_sha256"] != native_deployment.digest(body)
        or raw != native_deployment.canonical(value, maximum=1024 * 1024)
    ):
        raise ValueError("native_catalog_promotion_gate_reply_invalid")
    return gate


def native_catalog_promotion_recovery_request(
    expected_gate_sha256: str, *, recovery_id: str | None = None,
) -> dict:
    identifier = str(uuid.uuid4()) if recovery_id is None else recovery_id
    if (
        UUID4.fullmatch(identifier) is None
        or SHA256.fullmatch(expected_gate_sha256) is None
    ):
        raise ValueError("native_catalog_recovery_request_invalid")
    body = {
        "recovery_id": identifier,
        "command": NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
        "expected_gate_sha256": expected_gate_sha256,
    }
    return {
        "schema": NATIVE_CATALOG_PROMOTION_RECOVERY_REQUEST_SCHEMA,
        "recovery_id": identifier,
        "expected_gate_sha256": expected_gate_sha256,
        "request_sha256": native_deployment.digest(body),
    }


def _native_catalog_recovery_terminal(
    value: object, *, expected_host_release_id: str | None = None,
) -> dict:
    fields = {
        "schema", "state", "promotion_id", "catalog_sha256",
        "host_release_id", "promotion_receipt_sha256",
        "replay_authority_sha256", "expected_gate_sha256",
        "recovery_intent_sha256", "terminal_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("native_catalog_recovery_terminal_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "terminal_sha256"}
    }
    if (
        value["schema"]
        != NATIVE_CATALOG_PROMOTION_RECOVERY_TERMINAL_SCHEMA
        or value["state"] != "finalized"
        or UUID4.fullmatch(str(value["promotion_id"])) is None
        or (
            expected_host_release_id is not None
            and value["host_release_id"] != expected_host_release_id
        )
        or any(
            SHA256.fullmatch(str(value[name])) is None for name in (
                "catalog_sha256", "host_release_id",
                "promotion_receipt_sha256", "replay_authority_sha256",
                "expected_gate_sha256", "recovery_intent_sha256",
                "terminal_sha256",
            )
        )
        or value["terminal_sha256"] != native_deployment.digest(body)
    ):
        raise ValueError("native_catalog_recovery_terminal_invalid")
    return dict(value)


def native_catalog_promotion_recovery_reply(
    request: dict, raw: bytes,
) -> dict:
    if (
        not 2 <= len(raw) <= 1024 * 1024
        or request != native_catalog_promotion_recovery_request(
            request.get("expected_gate_sha256", ""),
            recovery_id=request.get("recovery_id"))
    ):
        raise ValueError("native_catalog_recovery_reply_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_catalog_recovery_reply_invalid") from error
    if (
        isinstance(value, dict)
        and value.get("schema") == NATIVE_CATALOG_PROMOTION_RECOVERY_ERROR_SCHEMA
    ):
        if set(value) != {"schema", "command", "status", "error"}:
            raise ValueError("native_catalog_recovery_reply_invalid")
        raise ValueError(str(value.get(
            "error", "native_catalog_recovery_rejected")))
    fields = {
        "schema", "recovery_id", "command", "request_sha256",
        "host_release_id", "terminal", "reply_sha256",
    }
    if (
        not isinstance(value, dict) or set(value) != fields
        or value.get("schema") != NATIVE_CATALOG_PROMOTION_RECOVERY_REPLY_SCHEMA
        or value.get("recovery_id") != request["recovery_id"]
        or value.get("command") != NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND
        or value.get("request_sha256") != request["request_sha256"]
        or SHA256.fullmatch(str(value.get("host_release_id", ""))) is None
    ):
        raise ValueError("native_catalog_recovery_reply_invalid")
    terminal = _native_catalog_recovery_terminal(value["terminal"])
    if terminal["expected_gate_sha256"] != request["expected_gate_sha256"]:
        raise ValueError("native_catalog_recovery_reply_invalid")
    body = {
        "recovery_id": value["recovery_id"],
        "command": NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
        "request_sha256": value["request_sha256"],
        "host_release_id": value["host_release_id"],
        "terminal": terminal,
    }
    if (
        value["reply_sha256"] != native_deployment.digest(body)
        or raw != native_deployment.canonical(value, maximum=1024 * 1024)
    ):
        raise ValueError("native_catalog_recovery_reply_invalid")
    return terminal


def native_stack_action_plan(
    action: str,
    stack_id: str,
    status_raw: bytes,
    observed_account_subject_sha256: str | None,
    observed_workspace_sha256: str | None,
) -> dict:
    if (action not in native_stack_operations.ACTIONS
            or native_vendor_stack.IDENTIFIER.fullmatch(stack_id) is None
            or len(status_raw) > 1024 * 1024):
        raise ValueError("native_stack_action_request_invalid")
    try:
        status_value = json.loads(status_raw)
        status = native_stack_operations.validate_status(status_value)
    except (UnicodeDecodeError, json.JSONDecodeError,
            native_stack_operations.NativeStackOperationError) as error:
        raise ValueError("native_stack_status_invalid") from error
    if status_raw != native_stack_operations.canonical_bytes(status):
        raise ValueError("native_stack_status_not_canonical")
    if status["stack_id"] != stack_id:
        raise ValueError("native_stack_status_identity_mismatch")
    if not NATIVE_STACK_STAGED_CATALOG.is_file():
        raise ValueError("native_stack_staged_catalog_required")
    NATIVE_STACK_PLAN_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    NATIVE_STACK_PLAN_ROOT.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".status.", dir=NATIVE_STACK_PLAN_ROOT
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(status_raw)
            handle.flush()
            os.fsync(handle.fileno())
        command = [
            "/usr/bin/python3", str(NATIVE_STACK_OPERATION), "plan", action,
            "--catalog", str(NATIVE_STACK_STAGED_CATALOG),
            "--status", str(temporary), "--stack-id", stack_id,
        ]
        if observed_account_subject_sha256 is not None:
            command.extend([
                "--observed-account-subject-sha256",
                observed_account_subject_sha256,
            ])
        if observed_workspace_sha256 is not None:
            command.extend([
                "--observed-workspace-sha256", observed_workspace_sha256,
            ])
        completed = subprocess.run(
            command, cwd=ROOT, stdin=subprocess.DEVNULL,
            capture_output=True, check=False, timeout=15,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if completed.returncode != 0 or not 2 <= len(completed.stdout) <= 1024 * 1024:
        raise ValueError("native_stack_action_plan_rejected")
    try:
        plan = native_stack_operations.validate_plan(json.loads(completed.stdout))
    except (UnicodeDecodeError, json.JSONDecodeError,
            native_stack_operations.NativeStackOperationError) as error:
        raise ValueError("native_stack_action_plan_invalid") from error
    raw = native_stack_operations.canonical_bytes(plan)
    if (completed.stdout != raw or plan["action"] != action
            or plan["identity"]["stack_id"] != stack_id
            or plan["current_status_sha256"] != status["status_sha256"]):
        raise ValueError("native_stack_action_plan_mismatch")
    _write_private_plan(NATIVE_STACK_PLAN_ROOT, plan["action_id"], raw)
    return plan


def native_stack_action_authorize(
    action_id: str, expected_sha256: str, agent: str, session: str
) -> dict:
    if (UUID4.fullmatch(action_id) is None or UUID4.fullmatch(session) is None
            or agent != "Control Center"):
        raise ValueError("native_stack_action_authorization_identity_invalid")
    path = NATIVE_STACK_PLAN_ROOT / f"{action_id}.json"
    plan, _raw = _read_private_plan(path, expected_sha256)
    plan = native_stack_operations.validate_plan(plan, require_fresh=True)
    if plan["action_id"] != action_id:
        raise ValueError("native_stack_action_authorization_mismatch")
    try:
        completed = bounded_authorization_command(
            [
                "/usr/bin/python3", str(NATIVE_STACK_OPERATION), "authorize",
                str(path), "--expected-plan-sha256", expected_sha256,
                "--agent", agent, "--session", session,
            ],
            # The wrapper grants the broker 1500 seconds for sign-in and 900
            # for entitlement/logout. Keep a distinct outer margin so it,
            # rather than this supervisor, owns normal deadline expiry.
            timeout=native_stack_authorization_timeout(plan["action"]),
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if completed.returncode != 0 or not 2 <= len(completed.stdout) <= 1024 * 1024:
        raise ValueError("native_stack_action_authorization_rejected")
    try:
        receipt = native_stack_operations.validate_receipt(json.loads(completed.stdout))
    except (UnicodeDecodeError, json.JSONDecodeError,
            native_stack_operations.NativeStackOperationError) as error:
        raise ValueError("native_stack_action_receipt_invalid") from error
    if (completed.stdout != native_stack_operations.canonical_bytes(receipt)
            or receipt["action_id"] != action_id
            or receipt["plan_sha256"] != expected_sha256
            or receipt["action"] != plan["action"]):
        raise ValueError("native_stack_action_receipt_mismatch")
    return receipt


def native_session_authorize(
    action_id: str, expected_sha256: str, agent: str, session: str,
    plan_raw: bytes,
) -> dict:
    """Run the distinct Touch ID ceremony for one broker-produced plan."""
    if (UUID4.fullmatch(action_id) is None
            or SHA256.fullmatch(expected_sha256) is None
            or UUID4.fullmatch(session) is None
            or agent != "Control Center"
            or not 2 <= len(plan_raw) <= 1024 * 1024):
        raise ValueError("native_session_authorization_identity_invalid")
    try:
        plan = native_stack_session.validate_plan(
            json.loads(plan_raw), now=int(time.time()), require_fresh=True
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_stack_session.NativeStackSessionError,
    ) as error:
        raise ValueError("native_session_authorization_plan_invalid") from error
    if (plan_raw != native_stack_session.canonical_bytes(plan)
            or plan["action_id"] != action_id
            or plan["plan_sha256"] != expected_sha256):
        raise ValueError("native_session_authorization_plan_changed")
    parameters = native_stack_session.canonical_bytes(
        {"plan": plan}
    ).decode("ascii").rstrip("\n")
    completed = bounded_authorization_command(
        [
            str(AUTHORIZATION_BROKER), "request",
            "--agent", agent, "--session", session,
            "--purpose", f"Authorize exact native {plan['action']}",
            "--resource", "Native vendor harness session authority",
            "--operation", f"native-{plan['action']}",
            "--parameters-json", parameters,
        ],
        timeout=720,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8",
        },
    )
    if completed.returncode != 0 or not 2 <= len(completed.stdout) <= 1024 * 1024:
        raise ValueError("native_session_authorization_rejected")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_session_authorization_result_invalid") from error
    native = plan["runtime_authority"]["model_stack_binding"]["authority"]
    if plan["action"] == "session-start":
        if native["vendor_id"] == "anthropic":
            try:
                result = native_terminal_handle.validate_public(value)
            except native_terminal_handle.NativeTerminalHandleError as error:
                raise ValueError(
                    "native_session_authorization_result_invalid"
                ) from error
            canonical_result = native_terminal_handle.canonical_bytes(result)
            expected_kind = "claude-session"
        elif native["vendor_id"] == "openai":
            try:
                result = native_codex_ui_handle.validate_public(value)
            except native_codex_ui_handle.NativeCodexUIHandleError as error:
                raise ValueError(
                    "native_session_authorization_result_invalid"
                ) from error
            canonical_result = native_codex_ui_handle.canonical_bytes(result)
            expected_kind = native_codex_ui_handle.KIND
            if (result["runtime_authority_sha256"]
                    != plan["runtime_authority_sha256"]):
                raise ValueError("native_session_authorization_result_mismatch")
        else:
            raise ValueError("native_session_authorization_result_invalid")
        if (result["kind"] != expected_kind
                or result["operation_id"] != plan["action_id"]
                or result["session_id"] != plan["session_id"]
                or completed.stdout != canonical_result):
            raise ValueError("native_session_authorization_result_mismatch")
        return result
    vendor = (
        "claude" if native["vendor_id"] == "anthropic" else
        "codex" if native["vendor_id"] == "openai" else None
    )
    expected = {
        "schema", "operation_id", "session_id", "state",
        "final_summary_sha256", "evidence_sha256",
    }
    if (vendor is None or not isinstance(value, dict) or set(value) != expected
            or value.get("schema")
                != f"secure-sandbox-native-{vendor}-session-stop-reply-v1"
            or value.get("operation_id") != plan["action_id"]
            or value.get("session_id") != plan["session_id"]
            or value.get("state") != "absent"
            or SHA256.fullmatch(
                str(value.get("final_summary_sha256", ""))
            ) is None
            or SHA256.fullmatch(str(value.get("evidence_sha256", ""))) is None
            or completed.stdout != native_stack_session.canonical_bytes(value)):
        raise ValueError("native_session_authorization_result_invalid")
    return value


def native_projection_reconciliation_authorize(
    recovery_operation_id: str, expected_sha256: str,
    agent: str, session: str, plan_raw: bytes,
) -> dict:
    """Run the distinct Touch ID ceremony for one broker-observed recovery."""
    if (UUID4.fullmatch(recovery_operation_id) is None
            or SHA256.fullmatch(expected_sha256) is None
            or UUID4.fullmatch(session) is None
            or agent != "Control Center"
            or not 2 <= len(plan_raw) <= 1024 * 1024):
        raise ValueError(
            "native_projection_reconciliation_authorization_identity_invalid"
        )
    try:
        plan = native_projection_reconciliation.validate_plan(
            json.loads(plan_raw), now=int(time.time()), require_fresh=True
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_projection_reconciliation.NativeProjectionReconciliationError,
    ) as error:
        raise ValueError(
            "native_projection_reconciliation_authorization_plan_invalid"
        ) from error
    if (plan_raw != native_projection_reconciliation.canonical_bytes(plan)
            or plan["recovery_operation_id"] != recovery_operation_id
            or plan["plan_sha256"] != expected_sha256):
        raise ValueError(
            "native_projection_reconciliation_authorization_plan_changed"
        )
    parameters = native_projection_reconciliation.canonical_bytes({
        "plan": plan,
    }).decode("ascii").rstrip("\n")
    completed = bounded_authorization_command(
        [
            str(AUTHORIZATION_BROKER), "request",
            "--agent", agent, "--session", session,
            "--purpose", "Reconcile one exact stranded credential projection",
            "--resource", native_projection_reconciliation.RESOURCE,
            "--operation", native_projection_reconciliation.OPERATION,
            "--parameters-json", parameters,
        ],
        timeout=720,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
    )
    if completed.returncode != 0 or not 2 <= len(completed.stdout) <= 1024 * 1024:
        raise ValueError(
            "native_projection_reconciliation_authorization_rejected"
        )
    try:
        result = native_projection_reconciliation.validate_reply(
            json.loads(completed.stdout), plan_value=plan
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_projection_reconciliation.NativeProjectionReconciliationError,
    ) as error:
        raise ValueError(
            "native_projection_reconciliation_result_invalid"
        ) from error
    if (completed.stdout
            != native_projection_reconciliation.canonical_bytes(result)):
        raise ValueError(
            "native_projection_reconciliation_result_not_canonical"
        )
    return result


def native_projection_identity_recovery_authorize(
    recovery_operation_id: str, expected_sha256: str,
    agent: str, session: str, plan_raw: bytes,
) -> dict:
    """Touch ID-authorize content-free identity import; never clear custody."""
    if (UUID4.fullmatch(recovery_operation_id) is None
            or SHA256.fullmatch(expected_sha256) is None
            or UUID4.fullmatch(session) is None
            or agent != "Control Center"
            or not 2 <= len(plan_raw) <= 1024 * 1024):
        raise ValueError(
            "native_projection_identity_recovery_authorization_identity_invalid"
        )
    try:
        plan = native_projection_identity_recovery.validate_plan(
            json.loads(plan_raw), now=int(time.time()), require_fresh=True
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_projection_identity_recovery
        .NativeProjectionIdentityRecoveryError,
    ) as error:
        raise ValueError(
            "native_projection_identity_recovery_authorization_plan_invalid"
        ) from error
    if (plan_raw != native_projection_identity_recovery.canonical_bytes(plan)
            or plan["recovery_operation_id"] != recovery_operation_id
            or plan["plan_sha256"] != expected_sha256):
        raise ValueError(
            "native_projection_identity_recovery_authorization_plan_changed"
        )
    parameters = native_projection_identity_recovery.canonical_bytes({
        "plan": plan,
    }).decode("ascii").rstrip("\n")
    completed = bounded_authorization_command(
        [
            str(AUTHORIZATION_BROKER), "request",
            "--agent", agent, "--session", session,
            "--purpose", "Recover exact committed projection identity",
            "--resource", native_projection_identity_recovery.RESOURCE,
            "--operation", native_projection_identity_recovery.OPERATION,
            "--parameters-json", parameters,
        ],
        timeout=720,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
    )
    if completed.returncode != 0 or not 2 <= len(completed.stdout) <= 1024 * 1024:
        raise ValueError(
            "native_projection_identity_recovery_authorization_rejected"
        )
    try:
        result = native_projection_identity_recovery.validate_reply(
            json.loads(completed.stdout), plan_value=plan
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_projection_identity_recovery
        .NativeProjectionIdentityRecoveryError,
    ) as error:
        raise ValueError(
            "native_projection_identity_recovery_result_invalid"
        ) from error
    if (completed.stdout
            != native_projection_identity_recovery.canonical_bytes(result)):
        raise ValueError(
            "native_projection_identity_recovery_result_not_canonical"
        )
    return result


def native_program_attestation_plan(
    stack_id: str, catalog_sha256: str, status_raw: bytes,
) -> dict:
    """Build a distinct operator-external program declaration plan.

    The protected catalog digest and canonical status are supplied by the
    signed read-only Control Center client.  The staged catalog must be the
    byte-for-byte catalog named by that protected digest; a locally edited or
    not-yet-promoted catalog can therefore never become attestation authority.
    The root backend independently repeats these bindings during execution.
    """
    if (native_vendor_stack.IDENTIFIER.fullmatch(stack_id) is None
            or SHA256.fullmatch(catalog_sha256) is None
            or not 2 <= len(status_raw) <= 1024 * 1024):
        raise ValueError("native_program_attestation_request_invalid")
    try:
        status = native_stack_operations.validate_status(json.loads(status_raw))
        catalog = native_vendor_stack.load_catalog(
            NATIVE_STACK_STAGED_CATALOG, private=True
        )
        catalog_raw = native_vendor_stack.canonical_bytes(catalog)
        stack = native_vendor_stack.stack_by_id(catalog, stack_id)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_stack_operations.NativeStackOperationError,
        native_vendor_stack.NativeVendorStackError,
    ) as error:
        raise ValueError("native_program_attestation_input_invalid") from error
    if (status_raw != native_stack_operations.canonical_bytes(status)
            or hashlib.sha256(catalog_raw).hexdigest() != catalog_sha256
            or status["stack_id"] != stack_id):
        raise ValueError("native_program_attestation_input_changed")
    try:
        plan = native_program_attestation.make_plan(
            stack=stack, catalog_sha256=catalog_sha256,
            status_value=status, attestation_id=str(uuid.uuid4()),
            created_at=int(time.time()),
        )
    except native_program_attestation.NativeProgramAttestationError as error:
        raise ValueError("native_program_attestation_plan_rejected") from error
    raw = native_program_attestation.canonical_bytes(plan)
    _write_private_plan(
        NATIVE_PROGRAM_ATTESTATION_PLAN_ROOT, plan["attestation_id"], raw
    )
    return plan


def _validate_program_attestation_result(value: object, plan: dict) -> dict:
    fields = {
        "schema", "action_id", "action", "plan_sha256",
        "authorization_sha256", "status", "evidence_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema")
                != "secure-sandbox-native-stack-provider-result-v1"
            or value.get("action_id") != plan["attestation_id"]
            or value.get("action") != "program-attest"
            or value.get("plan_sha256") != plan["plan_sha256"]
            or SHA256.fullmatch(
                str(value.get("authorization_sha256", ""))
            ) is None
            or value.get("status") != "verified"
            or SHA256.fullmatch(str(value.get("evidence_sha256", ""))) is None):
        raise ValueError("native_program_attestation_result_invalid")
    return value


def native_program_attestation_authorize(
    attestation_id: str, expected_sha256: str, agent: str, session: str,
) -> dict:
    if (UUID4.fullmatch(attestation_id) is None
            or UUID4.fullmatch(session) is None
            or agent != "Control Center"):
        raise ValueError(
            "native_program_attestation_authorization_identity_invalid"
        )
    path = NATIVE_PROGRAM_ATTESTATION_PLAN_ROOT / f"{attestation_id}.json"
    plan, _raw = _read_private_plan(path, expected_sha256)
    try:
        plan = native_program_attestation.validate_plan(
            plan, now=int(time.time()), require_fresh=True
        )
    except native_program_attestation.NativeProgramAttestationError as error:
        raise ValueError(
            "native_program_attestation_authorization_plan_invalid"
        ) from error
    if plan["attestation_id"] != attestation_id:
        raise ValueError("native_program_attestation_authorization_mismatch")
    parameters = native_program_attestation.canonical_bytes({
        "plan": plan,
    }).decode("ascii").rstrip("\n")
    try:
        completed = bounded_authorization_command(
            [
                str(AUTHORIZATION_BROKER), "request",
                "--agent", agent, "--session", session,
                "--purpose", (
                    "Declare this exact external cyber-program enrollment"
                ),
                "--resource", native_program_attestation.RESOURCE,
                "--operation", native_program_attestation.OPERATION,
                "--parameters-json", parameters,
            ],
            timeout=720,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if completed.returncode != 0 or not 2 <= len(completed.stdout) <= 1024 * 1024:
        raise ValueError("native_program_attestation_authorization_rejected")
    try:
        result = _validate_program_attestation_result(
            json.loads(completed.stdout), plan
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_program_attestation_result_invalid") from error
    if completed.stdout != native_program_attestation.canonical_bytes(result):
        raise ValueError("native_program_attestation_result_not_canonical")
    return result


def native_stack_catalog_promotion_plan(
    previous_catalog_sha256: str, host_release_id: str
) -> dict:
    if (SHA256.fullmatch(previous_catalog_sha256) is None
            or SHA256.fullmatch(host_release_id) is None
            or not NATIVE_STACK_STAGED_CATALOG.is_file()):
        raise ValueError("native_catalog_promotion_identity_invalid")
    completed = subprocess.run(
        [
            str(NATIVE_STACK_CATALOG_PROMOTER), "plan",
            "--source", str(NATIVE_STACK_STAGED_CATALOG),
            "--source-uid", str(os.geteuid()),
            "--previous-catalog-sha256", previous_catalog_sha256,
            "--host-release-id", host_release_id,
        ],
        cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
        check=False, timeout=30,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
    )
    if completed.returncode != 0 or not 2 <= len(completed.stdout) <= 1024 * 1024:
        raise ValueError("native_catalog_promotion_plan_rejected")
    try:
        plan = native_stack_catalog_promotion.validate_plan(
            json.loads(completed.stdout), require_fresh=True
        )
    except (UnicodeDecodeError, json.JSONDecodeError,
            native_stack_catalog_promotion.NativeStackCatalogPromotionError) as error:
        raise ValueError("native_catalog_promotion_plan_invalid") from error
    raw = native_stack_catalog_promotion.canonical_bytes(plan)
    if (completed.stdout != raw
            or plan["previous_catalog_sha256"] != previous_catalog_sha256
            or plan["host_release_id"] != host_release_id):
        raise ValueError("native_catalog_promotion_plan_mismatch")
    _write_private_plan(
        NATIVE_STACK_PROMOTION_PLAN_ROOT, plan["promotion_id"], raw
    )
    return plan


def _validate_catalog_promotion_receipt(value: object, plan: dict) -> dict:
    fields = {
        "schema", "promotion_id", "plan_sha256", "authorization_sha256",
        "authorization_receipt_sha256", "source_sha256",
        "previous_catalog_sha256", "catalog_sha256", "host_release_id",
        "promoted_at", "status", "receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("native_catalog_promotion_receipt_invalid")
    body = {key: item for key, item in value.items()
            if key not in {"schema", "receipt_sha256"}}
    if (value["schema"] != native_stack_catalog_promotion.RECEIPT_SCHEMA
            or value["promotion_id"] != plan["promotion_id"]
            or value["plan_sha256"] != plan["plan_sha256"]
            or value["source_sha256"] != plan["source_sha256"]
            or value["previous_catalog_sha256"] != plan["previous_catalog_sha256"]
            or value["catalog_sha256"] != plan["catalog_sha256"]
            or value["host_release_id"] != plan["host_release_id"]
            or value["status"] != "authorized-for-publication"
            or not isinstance(value["promoted_at"], int)
            or any(SHA256.fullmatch(str(value[name])) is None for name in (
                "authorization_sha256", "authorization_receipt_sha256",
                "receipt_sha256",
            ))
            or value["receipt_sha256"]
            != native_stack_catalog_promotion.sha256(body)):
        raise ValueError("native_catalog_promotion_receipt_invalid")
    return value


def native_stack_catalog_promotion_authorize(
    promotion_id: str, expected_sha256: str, agent: str, session: str
) -> dict:
    if (UUID4.fullmatch(promotion_id) is None or UUID4.fullmatch(session) is None
            or agent != "Control Center"):
        raise ValueError("native_catalog_promotion_authorization_identity_invalid")
    path = NATIVE_STACK_PROMOTION_PLAN_ROOT / f"{promotion_id}.json"
    plan, _raw = _read_private_plan(path, expected_sha256)
    plan = native_stack_catalog_promotion.validate_plan(plan, require_fresh=True)
    if plan["promotion_id"] != promotion_id:
        raise ValueError("native_catalog_promotion_authorization_mismatch")
    parameters = native_stack_catalog_promotion.canonical_bytes({
        "plan": plan,
        "source": str(NATIVE_STACK_STAGED_CATALOG),
    }).decode("ascii").rstrip("\n")
    try:
        completed = bounded_authorization_command(
            [
                str(AUTHORIZATION_BROKER), "request",
                "--agent", agent, "--session", session,
                "--purpose", "Admit this exact inert native stack catalog",
                "--resource", native_stack_catalog_promotion.RESOURCE,
                "--operation", native_stack_catalog_promotion.OPERATION,
                "--parameters-json", parameters,
            ],
            timeout=NATIVE_PRIVILEGED_CLIENT_TIMEOUT_SECONDS,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if (
        completed.returncode != 0
        or len(completed.stderr) > NATIVE_PRIVILEGED_STDERR_LIMIT
        or not 2 <= len(completed.stdout) <= 1024 * 1024
    ):
        raise ValueError("native_catalog_promotion_authorization_rejected")
    try:
        receipt = _validate_catalog_promotion_receipt(
            json.loads(completed.stdout), plan
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native_catalog_promotion_receipt_invalid") from error
    if completed.stdout != native_stack_catalog_promotion.canonical_bytes(receipt):
        raise ValueError("native_catalog_promotion_receipt_not_canonical")
    return receipt


def model_profile_activation_module():
    path = ROOT / "scripts/model_profile_activation.py"
    spec = importlib.util.spec_from_file_location("model_profile_activation", path)
    if spec is None or spec.loader is None:
        raise ValueError("model_profile_activation_unavailable")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def model_profile_activation_plan(profile_id: str, mode: str) -> dict:
    module = model_profile_activation_module()
    plan = module.create_plan(profile_id, mode)
    directory = ROOT / "runs/model-profile-activation-plans"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700); directory.chmod(0o700)
    path = directory / f"{plan['activation_id']}.json"
    temporary = path.with_suffix(f".{os.getpid()}.new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(module.canonical(plan) + b"\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass
    return plan


def activate_model_profile(activation_id: str, expected_sha256: str,
                           agent: str, session: str) -> dict:
    if UUID4.fullmatch(activation_id) is None or SHA256.fullmatch(expected_sha256) is None:
        raise ValueError("model_profile_activation_identity_invalid")
    path = ROOT / "runs/model-profile-activation-plans" / f"{activation_id}.json"
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size > 256 * 1024):
        raise ValueError("model_profile_activation_plan_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle: plan = json.load(handle)
    if plan.get("plan_sha256") != expected_sha256:
        raise ValueError("model_profile_activation_digest_mismatch")
    module = model_profile_activation_module()
    status = module.submit(plan, agent, session)
    if status != 0: raise ValueError("model_profile_activation_rejected")
    return {"activation_id":activation_id, "plan_sha256":expected_sha256,
            "schema":"secure-sandbox-model-profile-activation-submit-v1", "status":"submitted"}


def _main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    catalog_parser = subparsers.add_parser("catalog")
    catalog_parser.add_argument("name", choices=("overview", "sessions", "sources", "findings", "artifacts", "activity", "maintenance"))
    plan_parser = subparsers.add_parser("plan-source")
    plan_parser.add_argument("url")
    plan_parser.add_argument("ref")
    npm_parser = subparsers.add_parser("plan-npm")
    npm_parser.add_argument("package")
    npm_parser.add_argument("version")
    label_parser = subparsers.add_parser("label-session")
    label_parser.add_argument("session_id")
    label_parser.add_argument("label")
    unlabel_parser = subparsers.add_parser("unlabel-session")
    unlabel_parser.add_argument("session_id")
    status_parser = subparsers.add_parser("source-status")
    status_parser.add_argument("plan_id")
    apply_parser = subparsers.add_parser("apply-source")
    apply_parser.add_argument("plan_id")
    finding_parser = subparsers.add_parser("finding-detail")
    finding_parser.add_argument("finding_id")
    subparsers.add_parser("finding-transition")
    subparsers.add_parser("finding-relation")
    reopen_options_parser = subparsers.add_parser("finding-reopen-options")
    reopen_options_parser.add_argument("finding_id")
    subparsers.add_parser("finding-reopen")
    subparsers.add_parser("finding-disposition")
    artifact_parser = subparsers.add_parser("artifact-detail")
    artifact_parser.add_argument("artifact_id")
    subparsers.add_parser("verify-boundaries")
    lifecycle_parser = subparsers.add_parser("lifecycle")
    lifecycle_parser.add_argument("operation", choices=("start", "stop"))
    subparsers.add_parser("lifecycle-progress")
    dependency_parser = subparsers.add_parser("dependency-plan")
    dependency_parser.add_argument("source_id")
    dependency_status_parser = subparsers.add_parser("dependency-status")
    dependency_status_parser.add_argument("plan_id")
    dependency_apply_parser = subparsers.add_parser("dependency-apply")
    dependency_apply_parser.add_argument("plan_id")
    dependency_apply_parser.add_argument("expected_digest")
    subparsers.add_parser("dependency-bundles")
    index_parser = subparsers.add_parser("index-source")
    index_parser.add_argument("kind", choices=("corpus", "codegraph"))
    index_parser.add_argument("source_id")
    index_status_parser = subparsers.add_parser("index-source-status")
    index_status_parser.add_argument("kind", choices=("corpus", "codegraph"))
    index_status_parser.add_argument("source_id")
    backup_parser = subparsers.add_parser("backup-preflight")
    backup_parser.add_argument("destination")
    backup_plan_parser = subparsers.add_parser("backup-plan")
    backup_plan_parser.add_argument("destination")
    backup_submit_parser = subparsers.add_parser("backup-submit")
    backup_submit_parser.add_argument("plan_id")
    backup_status_parser = subparsers.add_parser("backup-status")
    backup_status_parser.add_argument("plan_id")
    backup_detail_parser = subparsers.add_parser("backup-plan-detail")
    backup_detail_parser.add_argument("plan_id")
    backup_inventory_parser = subparsers.add_parser("backup-inventory")
    backup_inventory_parser.add_argument("destination")
    restore_preview_parser = subparsers.add_parser("restore-preview")
    restore_preview_parser.add_argument("destination")
    restore_preview_parser.add_argument("generation_id")
    restore_plan_parser = subparsers.add_parser("restore-plan")
    restore_plan_parser.add_argument("source")
    restore_plan_parser.add_argument("generation_id")
    restore_detail_parser = subparsers.add_parser("restore-plan-detail")
    restore_detail_parser.add_argument("restore_id")
    restore_submit_parser = subparsers.add_parser("restore-submit")
    restore_submit_parser.add_argument("restore_id")
    restore_status_parser = subparsers.add_parser("restore-status")
    restore_status_parser.add_argument("restore_id")
    restore_recover_parser = subparsers.add_parser("restore-recover")
    restore_recover_parser.add_argument("restore_id")
    retirement_preview_parser = subparsers.add_parser("restore-retirement-preview")
    retirement_preview_parser.add_argument("restore_id")
    retirement_submit_parser = subparsers.add_parser("restore-retirement-submit")
    retirement_submit_parser.add_argument("restore_id")
    retirement_status_parser = subparsers.add_parser("restore-retirement-status")
    retirement_status_parser.add_argument("restore_id")
    subparsers.add_parser("memory-proposals")
    transcript_parser = subparsers.add_parser("transcript-detail")
    transcript_parser.add_argument("run_id")
    transcript_export_parser = subparsers.add_parser("transcript-export")
    transcript_export_parser.add_argument("run_id")
    transcript_export_parser.add_argument("destination")
    tool_catalog_parser = subparsers.add_parser("tool-results")
    tool_catalog_parser.add_argument("run_id")
    tool_detail_parser = subparsers.add_parser("tool-result-detail")
    tool_detail_parser.add_argument("run_id")
    tool_detail_parser.add_argument("tool_use_id")
    tool_detail_parser.add_argument("expected_sha256")
    session_runs_parser = subparsers.add_parser("session-runs")
    session_runs_parser.add_argument("session_id")
    lease_status_parser = subparsers.add_parser("lease-status")
    lease_status_parser.add_argument("run_id")
    lease_renew_parser = subparsers.add_parser("lease-renew")
    lease_renew_parser.add_argument("run_id")
    lease_renew_parser.add_argument("seconds", type=int)
    lease_reconcile_plan_parser = subparsers.add_parser("lease-reconcile-plan")
    lease_reconcile_plan_parser.add_argument("run_id")
    lease_reconcile_parser = subparsers.add_parser("lease-reconcile")
    lease_reconcile_parser.add_argument("run_id")
    lease_reconcile_parser.add_argument("expected_digest")
    lease_completed_parser = subparsers.add_parser("lease-completed")
    lease_completed_parser.add_argument("run_id")
    subparsers.add_parser("apply-time-sync")
    subparsers.add_parser("safety-audit")
    subparsers.add_parser("snapshot-policy")
    subparsers.add_parser("snapshot-preview")
    subparsers.add_parser("snapshot-apply")
    subparsers.add_parser("panic")
    subparsers.add_parser("reload-control-identities")
    subparsers.add_parser("model-profiles")
    subparsers.add_parser("model-profiles-save")
    subparsers.add_parser("native-vendor-stacks")
    subparsers.add_parser("native-vendor-stacks-save")
    native_action_plan_parser = subparsers.add_parser("native-stack-action-plan")
    native_action_plan_parser.add_argument(
        "operation", choices=sorted(native_stack_operations.ACTIONS)
    )
    native_action_plan_parser.add_argument("stack_id")
    native_action_plan_parser.add_argument("--observed-account-subject-sha256")
    native_action_plan_parser.add_argument("--observed-workspace-sha256")
    native_action_authorize_parser = subparsers.add_parser(
        "native-stack-action-authorize"
    )
    native_action_authorize_parser.add_argument("action_id")
    native_action_authorize_parser.add_argument("expected_sha256")
    native_action_authorize_parser.add_argument("agent")
    native_action_authorize_parser.add_argument("session")
    native_deployment_query_parser = subparsers.add_parser(
        "native-deployment-query-request")
    native_deployment_query_parser.add_argument(
        "command", choices=sorted(NATIVE_DEPLOYMENT_QUERY_SCHEMAS))
    native_deployment_query_parser.add_argument("query_id")
    native_deployment_validate_parser = subparsers.add_parser(
        "native-deployment-query-validate")
    native_deployment_validate_parser.add_argument(
        "command", choices=sorted(NATIVE_DEPLOYMENT_QUERY_SCHEMAS))
    native_deployment_validate_parser.add_argument("request_json")
    native_deployment_authorize_parser = subparsers.add_parser(
        "native-deployment-authorize")
    native_deployment_authorize_parser.add_argument(
        "operation", choices=("apply", "resume", "rollback"))
    native_deployment_authorize_parser.add_argument("expected_sha256")
    native_deployment_authorize_parser.add_argument("agent")
    native_deployment_authorize_parser.add_argument("session")
    native_deployment_authorize_parser.add_argument("request_json")
    native_program_plan_parser = subparsers.add_parser(
        "native-program-attestation-plan"
    )
    native_program_plan_parser.add_argument("stack_id")
    native_program_plan_parser.add_argument("catalog_sha256")
    native_program_authorize_parser = subparsers.add_parser(
        "native-program-attestation-authorize"
    )
    native_program_authorize_parser.add_argument("attestation_id")
    native_program_authorize_parser.add_argument("expected_sha256")
    native_program_authorize_parser.add_argument("agent")
    native_program_authorize_parser.add_argument("session")
    native_session_authorize_parser = subparsers.add_parser(
        "native-session-authorize"
    )
    native_session_authorize_parser.add_argument("action_id")
    native_session_authorize_parser.add_argument("expected_sha256")
    native_session_authorize_parser.add_argument("agent")
    native_session_authorize_parser.add_argument("session")
    native_projection_authorize_parser = subparsers.add_parser(
        "native-projection-reconciliation-authorize"
    )
    native_projection_authorize_parser.add_argument("recovery_operation_id")
    native_projection_authorize_parser.add_argument("expected_sha256")
    native_projection_authorize_parser.add_argument("agent")
    native_projection_authorize_parser.add_argument("session")
    native_projection_identity_authorize_parser = subparsers.add_parser(
        "native-projection-identity-recovery-authorize"
    )
    native_projection_identity_authorize_parser.add_argument(
        "recovery_operation_id"
    )
    native_projection_identity_authorize_parser.add_argument(
        "expected_sha256"
    )
    native_projection_identity_authorize_parser.add_argument("agent")
    native_projection_identity_authorize_parser.add_argument("session")
    native_promotion_plan_parser = subparsers.add_parser(
        "native-stack-catalog-promotion-plan"
    )
    native_promotion_plan_parser.add_argument("previous_catalog_sha256")
    native_promotion_plan_parser.add_argument("host_release_id")
    native_promotion_authorize_parser = subparsers.add_parser(
        "native-stack-catalog-promotion-authorize"
    )
    native_promotion_authorize_parser.add_argument("promotion_id")
    native_promotion_authorize_parser.add_argument("expected_sha256")
    native_promotion_authorize_parser.add_argument("agent")
    native_promotion_authorize_parser.add_argument("session")
    model_plan_parser = subparsers.add_parser("model-profile-activation-plan")
    model_plan_parser.add_argument("profile_id")
    model_plan_parser.add_argument("mode", choices=("mock", "production"))
    model_activate_parser = subparsers.add_parser("model-profile-activate")
    model_activate_parser.add_argument("activation_id")
    model_activate_parser.add_argument("expected_sha256")
    model_activate_parser.add_argument("agent")
    model_activate_parser.add_argument("session")
    subparsers.add_parser("harness-status")
    subparsers.add_parser("harness-releases")
    subparsers.add_parser("harness-acceptance-status")
    subparsers.add_parser("harness-check")
    harness_acquire_parser = subparsers.add_parser("harness-acquire")
    harness_acquire_parser.add_argument("generation_id")
    harness_verify_parser = subparsers.add_parser("harness-verify")
    harness_verify_parser.add_argument("generation_id")
    subparsers.add_parser("harness-qualification-self-test")
    harness_plan_parser = subparsers.add_parser("harness-generation-plan")
    harness_plan_parser.add_argument("operation", choices=("activate", "rollback", "retire", "revoke", "recover"))
    harness_plan_parser.add_argument("generation_id", nargs="?")
    harness_plan_parser.add_argument("reason", nargs="?")
    harness_authorize_parser = subparsers.add_parser("harness-generation-authorize")
    harness_authorize_parser.add_argument("operation", choices=("activate", "rollback", "retire", "revoke", "recover"))
    harness_authorize_parser.add_argument("identifier")
    harness_authorize_parser.add_argument("expected_sha256")
    harness_authorize_parser.add_argument("agent")
    harness_authorize_parser.add_argument("session")
    args = parser.parse_args()
    name = {"catalog": getattr(args, "name", None), "plan-source": "source-plan",
            "plan-npm": "source-plan",
            "label-session": "session-label", "unlabel-session": "session-label",
            "source-status": "source-status",
            "apply-source": "source-import", "finding-detail": "finding-detail",
            "finding-transition": "finding-transition",
            "finding-relation": "finding-relation",
            "finding-reopen-options": "finding-reopen-options",
            "finding-reopen": "finding-reopen",
            "finding-disposition": "finding-disposition",
            "artifact-detail": "artifact-detail", "verify-boundaries": "boundary-verification",
            "lifecycle": "lifecycle", "lifecycle-progress": "lifecycle-progress",
            "dependency-plan": "dependency-plan",
            "dependency-status": "dependency-status", "dependency-apply": "dependency-apply",
            "dependency-bundles": "dependency-bundles", "index-source": "source-index",
            "index-source-status": "source-index-status",
            "backup-preflight": "backup-preflight", "backup-plan": "backup-plan",
            "backup-submit": "backup-submit", "backup-status": "backup-status",
            "backup-plan-detail": "backup-plan-detail",
            "backup-inventory": "backup-inventory", "restore-preview": "restore-preview",
            "restore-plan": "restore-plan", "restore-plan-detail": "restore-plan-detail",
            "restore-submit": "restore-submit", "restore-status": "restore-status",
            "restore-recover": "restore-recover",
            "restore-retirement-preview": "restore-retirement-preview",
            "restore-retirement-submit": "restore-retirement-submit",
            "restore-retirement-status": "restore-retirement-status",
            "memory-proposals": "memory-proposals",
            "transcript-detail": "transcript-detail",
            "transcript-export": "transcript-export",
            "tool-results": "tool-results", "tool-result-detail": "tool-result-detail",
            "session-runs": "session-runs",
            "lease-status": "lease-status", "lease-renew": "lease-renew",
            "lease-reconcile-plan": "lease-reconcile-plan", "lease-reconcile": "lease-reconcile",
            "lease-completed": "lease-completed",
            "apply-time-sync": "time-sync",
            "safety-audit": "safety-audit", "snapshot-policy": "snapshot-policy",
            "snapshot-preview": "snapshot-preview", "snapshot-apply": "snapshot-apply",
            "panic": "panic",
            "reload-control-identities": "key-load",
            "model-profiles": "model-profiles",
            "model-profiles-save": "model-profiles-save",
            "native-vendor-stacks": "native-vendor-stacks",
            "native-vendor-stacks-save": "native-vendor-stacks-save",
            "native-stack-action-plan": "native-stack-action-plan",
            "native-stack-action-authorize": "native-stack-action-receipt",
            "native-deployment-query-request": "native-deployment-query-request",
            "native-deployment-query-validate": "native-deployment-query-result",
            "native-deployment-authorize": "native-deployment-terminal",
            "native-program-attestation-plan": "native-program-attestation-plan",
            "native-program-attestation-authorize": "native-program-attestation-result",
            "native-session-authorize": "native-session-authorize-result",
            "native-projection-reconciliation-authorize": (
                "native-projection-reconciliation-result"
            ),
            "native-projection-identity-recovery-authorize": (
                "native-projection-identity-recovery-result"
            ),
            "native-stack-catalog-promotion-plan": "native-stack-catalog-promotion-plan",
            "native-stack-catalog-promotion-authorize": "native-stack-catalog-promotion-receipt",
            "model-profile-activation-plan": "model-profile-activation-plan",
            "model-profile-activate": "model-profile-activate",
            "harness-status": "harness-status", "harness-releases": "harness-releases",
            "harness-acceptance-status": "harness-acceptance-status",
            "harness-check": "harness-receipt",
            "harness-acquire": "harness-receipt", "harness-verify": "harness-receipt",
            "harness-qualification-self-test": "harness-qualification",
            "harness-generation-plan": "harness-generation-plan",
            "harness-generation-authorize": "harness-generation-authorize"}[args.action]
    try:
        if args.action == "catalog":
            data = catalog(name)
        elif args.action == "plan-source":
            data = plan_source(args.url, args.ref)
        elif args.action == "plan-npm":
            data = plan_npm(args.package, args.version)
        elif args.action == "label-session":
            data = label_session(args.session_id, args.label)
        elif args.action == "unlabel-session":
            data = unlabel_session(args.session_id)
        elif args.action == "source-status":
            data = source_status(args.plan_id)
        elif args.action == "apply-source":
            data = apply_source(args.plan_id)
        elif args.action == "finding-detail":
            data = finding_detail(args.finding_id)
        elif args.action == "finding-transition":
            incoming = sys.stdin.buffer.read(16385)
            if len(incoming) > 16384:
                raise ValueError("Finding transition request exceeds its limit")
            data = apply_finding_transition(json.loads(incoming))
        elif args.action == "finding-relation":
            incoming = sys.stdin.buffer.read(16385)
            if len(incoming) > 16384:
                raise ValueError("Finding relation request exceeds its limit")
            data = apply_finding_relation(json.loads(incoming))
        elif args.action == "finding-reopen-options":
            data = finding_reopen_options(args.finding_id)
        elif args.action == "finding-reopen":
            incoming = sys.stdin.buffer.read(16385)
            if len(incoming) > 16384:
                raise ValueError("Finding reopen request exceeds its limit")
            data = apply_finding_reopen(json.loads(incoming))
        elif args.action == "finding-disposition":
            incoming = sys.stdin.buffer.read(16385)
            if len(incoming) > 16384:
                raise ValueError("Finding disposition request exceeds its limit")
            data = apply_finding_disposition(json.loads(incoming))
        elif args.action == "artifact-detail":
            data = artifact_detail(args.artifact_id)
        elif args.action == "lifecycle":
            data = lifecycle(args.operation)
        elif args.action == "lifecycle-progress":
            data = lifecycle_progress()
        elif args.action == "dependency-plan":
            data = dependency_plan(args.source_id)
        elif args.action == "dependency-status":
            data = dependency_status(args.plan_id)
        elif args.action == "dependency-apply":
            data = dependency_apply(args.plan_id, args.expected_digest)
        elif args.action == "dependency-bundles":
            data = dependency_bundles()
        elif args.action == "index-source":
            data = index_source(args.kind, args.source_id)
        elif args.action == "index-source-status":
            data = index_source_status(args.kind, args.source_id)
        elif args.action == "backup-preflight":
            data = backup_preflight(args.destination)
        elif args.action == "backup-plan":
            data = plan_backup(args.destination)
        elif args.action == "backup-submit":
            data = submit_backup(args.plan_id)
        elif args.action == "backup-status":
            data = backup_operation_status(args.plan_id)
        elif args.action == "backup-plan-detail":
            data = backup_plan_detail(args.plan_id)
        elif args.action == "backup-inventory":
            data = backup_inventory(args.destination)
        elif args.action == "restore-preview":
            data = restore_preview(args.destination, args.generation_id)
        elif args.action == "restore-plan":
            data = plan_restore(args.source, args.generation_id)
        elif args.action == "restore-plan-detail":
            data = restore_plan_detail(args.restore_id)
        elif args.action == "restore-submit":
            data = submit_restore(args.restore_id)
        elif args.action == "restore-status":
            data = restore_operation_status(args.restore_id)
        elif args.action == "restore-recover":
            data = recover_restore(args.restore_id)
        elif args.action == "restore-retirement-preview":
            data = restore_retirement_preview(args.restore_id)
        elif args.action == "restore-retirement-submit":
            data = retire_restore_generation(args.restore_id)
        elif args.action == "restore-retirement-status":
            data = restore_retirement_status(args.restore_id)
        elif args.action == "memory-proposals":
            data = memory_proposals()
        elif args.action == "transcript-detail":
            data = transcript_detail(args.run_id)
        elif args.action == "transcript-export":
            data = export_transcript(args.run_id, args.destination)
        elif args.action == "tool-results":
            data = tool_result_catalog(args.run_id)
        elif args.action == "tool-result-detail":
            data = tool_result_detail(args.run_id, args.tool_use_id, args.expected_sha256)
        elif args.action == "session-runs":
            data = session_runs(args.session_id)
        elif args.action == "lease-status":
            data = lease_status(args.run_id)
        elif args.action == "lease-renew":
            data = renew_lease(args.run_id, args.seconds)
        elif args.action == "lease-reconcile-plan":
            data = reconcile_plan(args.run_id)
        elif args.action == "lease-reconcile":
            data = reconcile_lease(args.run_id, args.expected_digest)
        elif args.action == "lease-completed":
            data = completed_lease(args.run_id)
        elif args.action == "apply-time-sync":
            data = apply_time_sync()
        elif args.action == "safety-audit":
            data = safety_audit()
        elif args.action == "snapshot-policy":
            data = snapshot_policy()
        elif args.action == "snapshot-preview":
            data = snapshot_preview()
        elif args.action == "snapshot-apply":
            data = apply_snapshot_retention()
        elif args.action == "panic":
            data = panic()
        elif args.action == "reload-control-identities":
            data = reload_control_identities()
        elif args.action == "model-profiles":
            data = model_profile_settings()
        elif args.action == "model-profiles-save":
            incoming = sys.stdin.buffer.read(64 * 1024 + 1)
            data = model_profile_settings(incoming)
        elif args.action == "native-vendor-stacks":
            data = native_vendor_stack_settings()
        elif args.action == "native-vendor-stacks-save":
            incoming = sys.stdin.buffer.read(64 * 1024 + 1)
            data = native_vendor_stack_settings(incoming)
        elif args.action == "native-stack-action-plan":
            incoming = sys.stdin.buffer.read(1024 * 1024 + 1)
            data = native_stack_action_plan(
                args.operation, args.stack_id, incoming,
                args.observed_account_subject_sha256,
                args.observed_workspace_sha256,
            )
        elif args.action == "native-stack-action-authorize":
            data = native_stack_action_authorize(
                args.action_id, args.expected_sha256, args.agent, args.session
            )
        elif args.action == "native-deployment-query-request":
            data = native_deployment_query_request(
                args.command, query_id=args.query_id)
        elif args.action == "native-deployment-query-validate":
            incoming = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
            if len(incoming) > 4 * 1024 * 1024:
                raise ValueError("native_deployment_query_reply_oversized")
            data = native_deployment_query_reply(
                args.command, json.loads(args.request_json), incoming)
        elif args.action == "native-deployment-authorize":
            incoming = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
            if len(incoming) > 4 * 1024 * 1024:
                raise ValueError("native_deployment_query_reply_oversized")
            data = native_deployment_authorize(
                args.operation, args.expected_sha256, args.agent,
                args.session, json.loads(args.request_json), incoming)
        elif args.action == "native-program-attestation-plan":
            incoming = sys.stdin.buffer.read(1024 * 1024 + 1)
            data = native_program_attestation_plan(
                args.stack_id, args.catalog_sha256, incoming
            )
        elif args.action == "native-program-attestation-authorize":
            data = native_program_attestation_authorize(
                args.attestation_id, args.expected_sha256,
                args.agent, args.session,
            )
        elif args.action == "native-session-authorize":
            incoming = sys.stdin.buffer.read(1024 * 1024 + 1)
            data = native_session_authorize(
                args.action_id, args.expected_sha256,
                args.agent, args.session, incoming,
            )
        elif args.action == "native-projection-reconciliation-authorize":
            incoming = sys.stdin.buffer.read(1024 * 1024 + 1)
            data = native_projection_reconciliation_authorize(
                args.recovery_operation_id, args.expected_sha256,
                args.agent, args.session, incoming,
            )
        elif args.action == "native-projection-identity-recovery-authorize":
            incoming = sys.stdin.buffer.read(1024 * 1024 + 1)
            data = native_projection_identity_recovery_authorize(
                args.recovery_operation_id, args.expected_sha256,
                args.agent, args.session, incoming,
            )
        elif args.action == "native-stack-catalog-promotion-plan":
            data = native_stack_catalog_promotion_plan(
                args.previous_catalog_sha256, args.host_release_id
            )
        elif args.action == "native-stack-catalog-promotion-authorize":
            data = native_stack_catalog_promotion_authorize(
                args.promotion_id, args.expected_sha256,
                args.agent, args.session,
            )
        elif args.action == "model-profile-activation-plan":
            data = model_profile_activation_plan(args.profile_id, args.mode)
        elif args.action == "model-profile-activate":
            data = activate_model_profile(args.activation_id, args.expected_sha256,
                                          args.agent, args.session)
        elif args.action == "harness-status":
            data = harness_status()
        elif args.action == "harness-releases":
            data = harness_releases()
        elif args.action == "harness-acceptance-status":
            data = harness_acceptance_status()
        elif args.action == "harness-check":
            data = harness_action("check")
        elif args.action == "harness-acquire":
            data = harness_action("acquire", args.generation_id)
        elif args.action == "harness-verify":
            data = harness_action("verify", args.generation_id)
        elif args.action == "harness-qualification-self-test":
            data = harness_action("qualify-self-test")
        elif args.action == "harness-generation-plan":
            data = harness_generation_plan(args.operation, args.generation_id, args.reason)
        elif args.action == "harness-generation-authorize":
            data = harness_generation_authorize(
                args.operation, args.identifier, args.expected_sha256, args.agent, args.session
            )
        else:
            data = verify_boundaries()
        payload = {"schema": SCHEMA, "catalog": name, "data": data}
        print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"schema": SCHEMA, "catalog": name, "error": str(error)[:500]}, ensure_ascii=True))
        return 1


def main() -> int:
    previous = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }

    def interrupted(_signum: int, _frame: object) -> None:
        # One-shot: keep a duplicate TERM from interrupting synchronous group
        # termination and one-shot request invalidation.
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        # This deliberately derives directly from BaseException. Read-only
        # catalog helpers such as maintenance() recover from ordinary
        # RuntimeError/ValueError failures and may continue to a second child;
        # owner loss must cross those recovery boundaries without being
        # mistaken for a component-level attention state.
        raise ControlCenterInterrupted("control_center_interrupted")

    try:
        for signum in previous:
            signal.signal(signum, interrupted)
        _start_parent_liveness_monitor()
        try:
            return _main()
        except ControlCenterInterrupted:
            return 130
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
