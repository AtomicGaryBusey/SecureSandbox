#!/usr/bin/env python3
"""Root-owned supervisor for one leased Claude process."""

from __future__ import annotations

import fcntl
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


RUN_DIRECTORY = Path("/run/secure-sandbox")
RUN_ID_FILE = RUN_DIRECTORY / "run-id"
LEASE_FILE = RUN_DIRECTORY / "run-lease.json"
PROCESS_FILE = RUN_DIRECTORY / "run-process.json"
LOCK_FILE = RUN_DIRECTORY / "run-lease.lock"
SESSION_REGISTRY = Path("/var/lib/secure-sandbox/claude-sessions.txt")
WORKSPACE = "/home/agent/research-workspace"
CLAUDE = "/usr/local/bin/claude"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SETPRIV = "/usr/bin/setpriv"
LEASE_SCHEMA = "secure-sandbox-research-run-lease-v1"
PROCESS_SCHEMA = "secure-sandbox-run-process-v1"
TERM_RE = re.compile(r"^[A-Za-z0-9+_.-]{1,64}$")


def canonical_run_id(value: str) -> str:
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError("run ID must be a canonical UUIDv4")
    return str(parsed)


def validate_arguments(arguments: list[str]) -> tuple[str, list[str], str | None]:
    if len(arguments) < 2:
        raise ValueError("run ID and Claude command are required")
    run_id = canonical_run_id(arguments[0])
    source_id = None
    remaining_arguments = arguments[1:]
    if remaining_arguments[:1] == ["--source"]:
        if len(remaining_arguments) < 3:
            raise ValueError("source UUID and fixed Claude command are required")
        source_id = canonical_run_id(remaining_arguments[1])
        remaining_arguments = remaining_arguments[2:]
    command = remaining_arguments
    if not command or command[0] != CLAUDE:
        raise ValueError("only the fixed Claude binary is allowed")
    options = command[1:]
    fixed = ["--append-system-prompt-file", "/etc/claude-code/secure-sandbox-persona.md",
             "--no-chrome", "--restricted", "--permission-mode", "manual"]
    if options[:len(fixed)] != fixed:
        raise ValueError("fixed Claude options are required")
    remaining = options[len(fixed):]
    if remaining:
        if len(remaining) != 2 or remaining[0] not in {"--resume", "--session-id"}:
            raise ValueError("only --resume or --session-id SESSION_UUID is allowed")
        canonical_run_id(remaining[1])
    if source_id is not None and (not remaining or remaining[0] != "--session-id"):
        raise ValueError("selected source requires a new session")
    if RUN_ID_FILE.read_text(encoding="ascii").strip() != run_id:
        raise PermissionError("run marker mismatch")
    return run_id, command, source_id


def source_working_directory(source_id: str) -> str:
    from source_integrity import fixed_tree_path, registered_source, verify_source

    result = verify_source(source_id, scope="worktree")
    if result.get("overall_status") != "match":
        raise PermissionError("selected source integrity is not verified")
    record = registered_source(source_id)
    return fixed_tree_path(record.get("worktree_path"), "repos")


def load_root_json(path: Path, schema: str) -> dict[str, Any]:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
        raise PermissionError(f"invalid {path.name} ownership or mode")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError(f"invalid {path.name} schema")
    return value


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.chown(temporary, 0, 0); os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def process_fields(pid: int) -> tuple[int, int, int]:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(")") + 2:].split()
    return int(fields[1]), int(fields[2]), int(fields[19])


def validate_invoker(agent: pwd.struct_passwd) -> None:
    if os.geteuid() != 0:
        raise PermissionError("run supervisor must run as root")
    if os.environ.get("SUDO_USER") != "agent":
        raise PermissionError("run supervisor requires the agent sudo rule")
    if int(os.environ.get("SUDO_UID", "-1")) != agent.pw_uid:
        raise PermissionError("run supervisor UID mismatch")
    if int(os.environ.get("SUDO_GID", "-1")) != agent.pw_gid:
        raise PermissionError("run supervisor GID mismatch")


def validate_resume(command: list[str]) -> None:
    if "--resume" not in command:
        return
    session_id = command[-1]
    metadata = SESSION_REGISTRY.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o644 or metadata.st_nlink != 1):
        raise PermissionError("invalid session registry ownership or mode")
    descriptor = os.open(SESSION_REGISTRY, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        content = os.read(descriptor, 8 * 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(content) > 8 * 1024 * 1024:
        raise ValueError("session registry exceeds limit")
    prefix = (session_id + "\t").encode("ascii")
    if not any(line.startswith(prefix) for line in content.splitlines()):
        raise PermissionError("resume session is not registered")


def child_environment(agent: pwd.struct_passwd) -> dict[str, str]:
    term = os.environ.get("TERM", "xterm-256color")
    if not TERM_RE.fullmatch(term):
        term = "xterm-256color"
    return {
        "HOME": agent.pw_dir, "USER": agent.pw_name, "LOGNAME": agent.pw_name,
        "SHELL": "/bin/bash", "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8", "TERM": term,
        "ANTHROPIC_BASE_URL": "http://127.0.0.1:18080",
        # Claude Code 2.1.300 requires explicit gateway mode plus a bearer
        # token when ANTHROPIC_BASE_URL selects a non-Anthropic endpoint.  The
        # token is deliberately non-secret: the loopback relay authenticates
        # to the Gateway with its root-owned mTLS identity, and the managed
        # sandbox strips these variables from tool subprocesses.
        "ANTHROPIC_AUTH_TOKEN": "sandbox-relay-nonsecret",
        "CLAUDE_CODE_USE_GATEWAY": "1",
        "ANTHROPIC_DEFAULT_MODEL": "abliterated-model-large-v2[1m]",
        "ANTHROPIC_DEFAULT_OPUS_MODEL": "abliterated-model-large-v2[1m]",
        "ANTHROPIC_DEFAULT_SONNET_MODEL": "abliterated-model-large-v2[1m]",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": "abliterated-model-large-v2[1m]",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_MCP_ALLOWLIST_ENV": "1",
        "CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS": "1",
        "DISABLE_UPDATES": "1", "DISABLE_UPGRADE_COMMAND": "1",
        "DISABLE_LOGIN_COMMAND": "1", "DISABLE_LOGOUT_COMMAND": "1",
    }


def scope_unit(run_id: str) -> str:
    return f"secure-sandbox-run-{canonical_run_id(run_id)}.scope"


def registration_belongs_to(registration: dict[str, Any], supervisor_pid: int,
                            supervisor_start: int) -> bool:
    return (registration.get("supervisor_pid") == supervisor_pid
            and registration.get("supervisor_start_time") == supervisor_start)


def scope_command(agent: pwd.struct_passwd, run_id: str, command: list[str],
                  working_directory: str = WORKSPACE) -> list[str]:
    environment = child_environment(agent)
    result = [
        SYSTEMD_RUN, "--scope", "--quiet", f"--unit={scope_unit(run_id)}",
        f"--working-directory={working_directory}",
        "--property=Delegate=no", "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes", "--property=TasksMax=256",
        "--property=MemoryMax=8G", "--property=CPUQuota=400%",
    ]
    result.extend(f"--setenv={name}={value}" for name, value in sorted(environment.items()))
    # systemd-run --scope --uid changes the primary identity but may retain the
    # root caller's supplementary groups.  Enter the root-created scope first,
    # then make one explicit, irreversible identity transition in setpriv.
    return result + ["--", SETPRIV, f"--reuid={agent.pw_uid}",
                     f"--regid={agent.pw_gid}", "--clear-groups",
                     "--inh-caps=-all", "--ambient-caps=-all",
                     "--bounding-set=-all", "--no-new-privs", "--"] + command


def main() -> int:
    agent = pwd.getpwnam("agent")
    validate_invoker(agent)
    run_id, command, source_id = validate_arguments(sys.argv[1:])
    validate_resume(command)
    working_directory = source_working_directory(source_id) if source_id is not None else WORKSPACE
    lock_descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    child: subprocess.Popen[bytes] | None = None
    claimed = False
    claimed_supervisor_start: int | None = None

    def forward(signum: int, _frame: object) -> None:
        if child is None:
            return
        try: child.send_signal(signum)
        except ProcessLookupError: pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGHUP, forward)
    blocked = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        lease = load_root_json(LEASE_FILE, LEASE_SCHEMA)
        seed = load_root_json(PROCESS_FILE, PROCESS_SCHEMA)
        if (lease.get("run_id") != run_id or seed.get("run_id") != run_id
                or seed.get("lease_id") != lease.get("lease_id") or seed.get("ready") is not False):
            raise PermissionError("run process registration mismatch")
        if not isinstance(lease.get("expires_at"), int) or lease["expires_at"] <= int(time.time()):
            raise PermissionError("run lease is expired")
        _, _, supervisor_start = process_fields(os.getpid())
        pending = {**seed, "supervisor_pid": os.getpid(), "supervisor_start_time": supervisor_start}
        atomic_json(PROCESS_FILE, pending)
        claimed = True
        claimed_supervisor_start = supervisor_start
        expected_unit = scope_unit(run_id)
        if seed.get("unit") != expected_unit:
            raise PermissionError("run scope identity mismatch")
        child = subprocess.Popen(
            scope_command(agent, run_id, command, working_directory),
            env={"PATH":"/usr/bin:/bin", "LANG":"C.UTF-8"},
            preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, set()),
        )
        ready = {**pending, "ready": True, "scope_pid": child.pid, "unit":expected_unit}
        atomic_json(PROCESS_FILE, ready)
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    except Exception as error:
        if child is not None:
            try: child.kill()
            except ProcessLookupError: pass
            child.wait()
        if claimed:
            try:
                registration = load_root_json(PROCESS_FILE, PROCESS_SCHEMA)
                if registration_belongs_to(registration, os.getpid(), int(claimed_supervisor_start)):
                    terminal = {**registration, "launch_failed":type(error).__name__,
                                "exited_at":int(time.time())}
                    if child is None:
                        terminal["scope_empty"] = True
                    atomic_json(PROCESS_FILE, terminal)
            except (FileNotFoundError, PermissionError, ValueError, json.JSONDecodeError):
                pass
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    assert child is not None
    status = child.wait()
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
    try:
        registration = load_root_json(PROCESS_FILE, PROCESS_SCHEMA)
        if (registration.get("supervisor_pid") == os.getpid()
                and registration.get("scope_pid") == child.pid
                and registration.get("unit") == scope_unit(run_id)):
            atomic_json(PROCESS_FILE, {**registration, "scope_empty":True,
                                      "exit_status":status,"exited_at":int(time.time())})
    except (FileNotFoundError, PermissionError, ValueError, json.JSONDecodeError):
        pass
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
