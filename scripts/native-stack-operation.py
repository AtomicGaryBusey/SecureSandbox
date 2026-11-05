#!/usr/bin/env python3
"""Unprivileged content-free native-stack plan and authorization client."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / "shared/native_stack_operations.py").is_file():
    sys.path.insert(0, str(ROOT))

from shared import native_stack_operations as operations
from shared import native_vendor_stack


MAX_JSON = 1024 * 1024
BROKER = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
RESOURCE = "Native vendor harness and model stack authority"


class NativeStackOperationClientError(RuntimeError):
    pass


PROCESS_GROUP_ENV = "SECURE_SANDBOX_OWNED_PROCESS_GROUP"
SUPERVISOR_LIVENESS_ENV = "SECURE_SANDBOX_SUPERVISOR_LIVENESS_FD"
SUPERVISOR_DISARM = b"D"


def start_supervisor_liveness_monitor() -> threading.Thread | None:
    marker = os.environ.pop(SUPERVISOR_LIVENESS_ENV, None)
    if marker is None:
        return None
    if not marker.isascii() or not marker.isdecimal():
        raise NativeStackOperationClientError(
            "native_stack_supervisor_liveness_fd_invalid"
        )
    descriptor = int(marker)
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise NativeStackOperationClientError(
            "native_stack_supervisor_liveness_fd_invalid"
        ) from error
    group = os.getpgrp()
    if (
        descriptor < 3
        or not stat.S_ISFIFO(info.st_mode)
        or os.getpid() != group
        or os.getsid(0) != group
    ):
        raise NativeStackOperationClientError(
            "native_stack_supervisor_liveness_fd_invalid"
        )

    def monitor() -> None:
        try:
            decision = os.read(descriptor, 1)
        except OSError:
            decision = b""
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if decision == SUPERVISOR_DISARM:
            return
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                break
            time.sleep(0.05)
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    thread = threading.Thread(
        target=monitor, name="native-stack-supervisor-liveness", daemon=True,
    )
    thread.start()
    return thread


def _owned_group() -> int | None:
    marker = os.environ.get(PROCESS_GROUP_ENV, "")
    group = os.getpgrp()
    if marker == "bootstrap":
        return group if os.getpid() == group == os.getsid(0) else None
    if (marker.isascii() and marker.isdecimal()
            and int(marker) == group == os.getsid(0)):
        return group
    return None


def _group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate(process: subprocess.Popen[bytes], *, owns_group: bool) -> None:
    if owns_group:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    if owns_group and _group_exists(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif not owns_group and process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise NativeStackOperationClientError(
            "native_stack_authorization_process_unreaped"
        ) from error
    if owns_group:
        deadline = time.monotonic() + 2
        while _group_exists(process.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        if _group_exists(process.pid):
            raise NativeStackOperationClientError(
                "native_stack_authorization_process_group_unreaped"
            )


def run_bounded_authorization(
    command: list[str], *, timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    inherited = _owned_group()
    starts_owned_group = inherited is None
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8",
        PROCESS_GROUP_ENV: (
            "bootstrap" if starts_owned_group else str(inherited)
        ),
    }
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True,
        start_new_session=starts_owned_group, env=environment,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _mask in selector.select(remaining):
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is process.stdout:
                    output.extend(block)
                    if len(output) > MAX_JSON:
                        raise NativeStackOperationClientError(
                            "native_stack_authorization_response_oversized"
                        )
                else:
                    errors.extend(block)
                    if len(errors) > 64 * 1024:
                        del errors[:-64 * 1024]
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if starts_owned_group and _group_exists(process.pid):
            _terminate(process, owns_group=True)
            raise NativeStackOperationClientError(
                "native_stack_authorization_descendant_unreaped"
            )
        return subprocess.CompletedProcess(
            command, process.returncode, bytes(output), bytes(errors)
        )
    except BaseException:
        _terminate(process, owns_group=starts_owned_group)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def authorization_timeout(action: str) -> int:
    """Outlive the broker's complete ceremony+mutation budget by 60 seconds."""
    if action == "signin-begin":
        return 1500  # broker: 1200 execution + 180 request TTL + 60 completion
    if action in {"entitlement-verify", "logout"}:
        return 900  # broker: 600 execution + 180 request TTL + 60 completion
    return 480  # broker: 180 execution + 180 request TTL + 60 completion


def trusted_read(path: Path, maximum: int = MAX_JSON) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not 2 <= before.st_size <= maximum
    ):
        raise NativeStackOperationClientError("native_stack_input_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        or len(data) != opened.st_size
        or len(data) > maximum
    ):
        raise NativeStackOperationClientError("native_stack_input_changed")
    return bytes(data)


def read_json(path: Path) -> object:
    try:
        return json.loads(trusted_read(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackOperationClientError("native_stack_input_invalid") from error


def load_stack(path: Path, stack_id: str) -> dict:
    catalog = native_vendor_stack.validate_catalog(read_json(path))
    for stack in catalog["stacks"]:
        if stack["stack_id"] == stack_id:
            return stack
    raise NativeStackOperationClientError("native_stack_not_found")


def create_plan(
    *,
    catalog: Path,
    status: Path,
    stack_id: str,
    action: str,
    observed_account_subject_sha256: str | None = None,
    observed_workspace_sha256: str | None = None,
    created_at: int | None = None,
) -> dict:
    return operations.make_plan(
        stack=load_stack(catalog, stack_id),
        status=operations.validate_status(read_json(status)),
        action=action,
        observed_account_subject_sha256=observed_account_subject_sha256,
        observed_workspace_sha256=observed_workspace_sha256,
        created_at=created_at,
    )


def authorize(
    plan: object,
    *,
    expected_plan_sha256: str,
    agent: str,
    session: str,
    request_id: str | None = None,
    broker: Path = BROKER,
    runner=subprocess.run,
) -> dict:
    validated = operations.validate_plan(plan)
    if validated["plan_sha256"] != expected_plan_sha256:
        raise NativeStackOperationClientError("native_stack_plan_changed")
    if (request_id is not None
            and operations.UUID4.fullmatch(request_id) is None):
        raise NativeStackOperationClientError(
            "native_stack_authorization_request_id_invalid"
        )
    command = [
        str(broker), "request",
        "--agent", agent,
        "--session", session,
        "--purpose", f"Apply exact native stack {validated['action']} plan",
        "--resource", RESOURCE,
        "--operation", f"native-stack-{validated['action']}",
        "--parameters-json",
        operations.canonical_bytes({"plan": validated}).decode("ascii").rstrip("\n"),
    ]
    if request_id is not None:
        command.extend(["--request-id", request_id])
    # These bounds are deliberately longer than the broker's complete
    # ceremony+root-operation budget (1440/840/420 seconds respectively).
    # The outer Control Center supervisor is longer again, so only one layer
    # owns an ordinary deadline at a time.
    timeout = authorization_timeout(validated["action"])
    if runner is subprocess.run:
        result = run_bounded_authorization(command, timeout=timeout)
    else:
        result = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    if result.returncode != 0 or not 2 <= len(result.stdout) <= MAX_JSON:
        raise NativeStackOperationClientError("native_stack_authorization_rejected")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackOperationClientError("native_stack_authorization_response_invalid") from error
    return operations.validate_receipt(value)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    commands = value.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("action", choices=sorted(operations.ACTIONS))
    plan.add_argument("--catalog", type=Path, required=True)
    plan.add_argument("--status", type=Path, required=True)
    plan.add_argument("--stack-id", required=True)
    plan.add_argument("--observed-account-subject-sha256")
    plan.add_argument("--observed-workspace-sha256")
    auth = commands.add_parser("authorize")
    auth.add_argument("plan", type=Path)
    auth.add_argument("--expected-plan-sha256", required=True)
    auth.add_argument("--agent", required=True)
    auth.add_argument("--session", required=True)
    auth.add_argument("--request-id")
    return value


def _main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        if args.command == "plan":
            result = create_plan(
                catalog=args.catalog,
                status=args.status,
                stack_id=args.stack_id,
                action=args.action,
                observed_account_subject_sha256=args.observed_account_subject_sha256,
                observed_workspace_sha256=args.observed_workspace_sha256,
            )
        else:
            result = authorize(
                read_json(args.plan), expected_plan_sha256=args.expected_plan_sha256,
                agent=args.agent, session=args.session,
                request_id=args.request_id,
            )
        sys.stdout.buffer.write(operations.canonical_bytes(result))
        return 0
    except (
        NativeStackOperationClientError,
        operations.NativeStackOperationError,
        native_vendor_stack.NativeVendorStackError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        code = str(error)
        if not code.startswith("native_stack_"):
            code = "native_stack_operation_failed"
        output = {
            "schema": "secure-sandbox-native-stack-operation-error-v1",
            "status": "rejected",
            "error": code,
        }
        sys.stderr.write(json.dumps(output, separators=(",", ":"), sort_keys=True) + "\n")
        return 1


def main(arguments: list[str] | None = None) -> int:
    previous = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }

    def interrupted(signum: int, _frame: object) -> None:
        for pending in previous:
            signal.signal(pending, signal.SIG_IGN)
        raise NativeStackOperationClientError(
            f"native_stack_operation_interrupted_{signum}"
        )

    try:
        for signum in previous:
            signal.signal(signum, interrupted)
        start_supervisor_liveness_monitor()
        return _main(arguments)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
