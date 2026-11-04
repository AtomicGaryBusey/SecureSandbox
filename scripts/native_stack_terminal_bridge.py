#!/usr/bin/env python3
"""Fixed no-capture bridge for one root-authorized native terminal stream.

The one-time authority is accepted only as an inherited, unlinked, root-owned
file description at fd 3.  stdin and stdout must be duplicate descriptions of
the same authenticated Unix stream supplied by the root authorization broker.
After validation this process emits one fixed readiness marker and execs the
reviewed privileged-control client.  It never parses, buffers, hashes, logs, or
persists any subsequent vendor/operator terminal bytes.
"""

from __future__ import annotations

import os
import resource
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SUPPORT = HERE / "native_stack_support"
if SUPPORT.is_file():
    sys.path.insert(0, str(SUPPORT))
elif (HERE.parent / "shared/native_terminal_handle.py").is_file():
    sys.path.insert(0, str(HERE.parent))

from shared import native_terminal_handle


HANDLE_FD = 3
READY = b"SSTERM1\n"
CONTROL_CLIENT = HERE / "control_client"
SSH_CONFIG = HERE / "ssh_config"


class NativeStackTerminalBridgeError(RuntimeError):
    """Stable fail-closed bridge rejection."""


def close_unrelated_descriptors() -> None:
    """Close every inherited descriptor except stdin/stdout/stderr/authority."""
    soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (not isinstance(soft, int) or soft == resource.RLIM_INFINITY
            or not 4 <= soft <= 1_048_576):
        raise NativeStackTerminalBridgeError(
            "native_terminal_bridge_fd_limit_invalid"
        )
    os.closerange(4, soft)


def _unix_stream_identity(descriptor: int) -> tuple[int, int, object, object]:
    try:
        info = os.fstat(descriptor)
        duplicate = socket.socket(fileno=os.dup(descriptor))
        try:
            family = duplicate.family
            socket_type = duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            local = duplicate.getsockname()
            peer = duplicate.getpeername()
        finally:
            duplicate.close()
    except OSError as error:
        raise NativeStackTerminalBridgeError(
            "native_terminal_bridge_stream_invalid"
        ) from error
    if (not stat.S_ISSOCK(info.st_mode) or os.isatty(descriptor)
            or family != socket.AF_UNIX or socket_type != socket.SOCK_STREAM):
        raise NativeStackTerminalBridgeError(
            "native_terminal_bridge_stream_invalid"
        )
    return info.st_dev, info.st_ino, local, peer


def validated_command(
    *, handle_fd: int = HANDLE_FD, input_fd: int = 0, output_fd: int = 1,
    now: int | None = None, trusted_uid: int = 0, trusted_gid: int = 0,
    control_client: Path = CONTROL_CLIENT, ssh_config: Path = SSH_CONFIG,
) -> tuple[list[str], dict[str, Any]]:
    if os.geteuid() != trusted_uid:
        raise NativeStackTerminalBridgeError(
            "native_terminal_bridge_root_required"
        )
    input_identity = _unix_stream_identity(input_fd)
    output_identity = _unix_stream_identity(output_fd)
    if input_identity != output_identity:
        raise NativeStackTerminalBridgeError(
            "native_terminal_bridge_stream_substituted"
        )
    timestamp = int(time.time()) if now is None else now
    try:
        record = native_terminal_handle.read_unlinked_fd(
            handle_fd, now=timestamp, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
    except native_terminal_handle.NativeTerminalHandleError as error:
        raise NativeStackTerminalBridgeError(str(error)) from error
    command = [
        str(control_client), "client", "--ssh-config", str(ssh_config),
        "--timeout-seconds", "14400", "sandbox-research-control", "stream",
        record["remote_operation"], *record["remote_arguments"],
    ]
    return command, record


def main() -> int:
    try:
        close_unrelated_descriptors()
        command, _record = validated_command()
        os.close(HANDLE_FD)
        os.write(1, READY)
        os.execve(
            command[0], command,
            {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    except (NativeStackTerminalBridgeError, OSError, ValueError):
        try:
            os.write(1, b"\r\nSecureSandbox terminal stream failed closed.\r\n")
        except OSError:
            pass
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
