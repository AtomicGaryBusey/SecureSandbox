#!/usr/bin/env python3
"""Root-owned supervisor for one runtime-authority-bound harness process."""

from __future__ import annotations

import fcntl
import hashlib
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

from session_policy_runtime import SessionPolicyRuntimeError, measure as measure_session_policy
from shared.harness_runtime_binding import HarnessBindingError, validate_binding as validate_harness_binding
from shared.model_stack_runtime_binding import BROKERED_MODE
from shared.runtime_authority import RuntimeAuthorityError, validate_binding as validate_runtime_authority


RUN_DIRECTORY = Path("/run/secure-sandbox")
RUN_ID_FILE = RUN_DIRECTORY / "run-id"
LEASE_FILE = RUN_DIRECTORY / "run-lease.json"
PROCESS_FILE = RUN_DIRECTORY / "run-process.json"
LOCK_FILE = RUN_DIRECTORY / "run-lease.lock"
SESSION_REGISTRY = Path("/var/lib/secure-sandbox/claude-sessions.txt")
WORKSPACE = "/home/agent/research-workspace"
HARNESS_RELEASE_ROOT = Path("/usr/local/libexec/secure-sandbox-harnesses/releases")
HARNESS_INSPECTOR = "/usr/local/libexec/secure-sandbox/harness-generation.py"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SETPRIV = "/usr/bin/setpriv"
LEASE_SCHEMA = "secure-sandbox-research-run-lease-v3"
PROCESS_SCHEMA = "secure-sandbox-run-process-v3"
GATEWAY_LEASE_SCHEMA = "secure-sandbox-run-lease-v3"
SESSION_POLICY_SCHEMA = "secure-sandbox-session-policy-runtime-v1"
TRUSTED_UID = 0
MAX_STATE_BYTES = 512 * 1024
MAX_REGISTRY_BYTES = 8 * 1024 * 1024
TERM_RE = re.compile(r"^[A-Za-z0-9+_.-]{1,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
ERROR_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}$")
SESSION_POLICY_FIELDS = {
    "schema", "source_id", "source_manifest_sha256", "persona_sha256",
    "tool_catalog_sha256", "extension_set_sha256",
}

GATEWAY_LEASE_FIELDS = {
    "schema", "lease_id", "run_id", "profile", "issued_at", "expires_at",
    "maximum_expires_at", "runtime_authority", "brokered_transport", "limits",
    "pricing", "renewals",
}
LEASE_FIELDS = {
    "schema", "run_id", "lease_id", "expires_at", "maximum_expires_at",
    "runtime_authority", "gateway_lease", "gateway_lease_sha256",
}
PROCESS_SEED_FIELDS = {
    "schema", "run_id", "lease_id", "ready", "unit", "runtime_authority",
    "gateway_lease_sha256",
}
PROCESS_CLAIMED_FIELDS = PROCESS_SEED_FIELDS | {
    "supervisor_pid", "supervisor_start_time",
}
PROCESS_READY_FIELDS = PROCESS_CLAIMED_FIELDS | {"scope_pid"}
PROCESS_FAILED_FIELDS = PROCESS_CLAIMED_FIELDS | {
    "launch_failed", "scope_empty", "exited_at",
}
PROCESS_TERMINAL_FIELDS = PROCESS_READY_FIELDS | {
    "scope_empty", "exit_status", "exited_at",
}


def canonical_uuid4(value: str, name: str) -> str:
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError(f"{name} must be a canonical UUIDv4")
    return str(parsed)


def canonical_json_line(value: object) -> bytes:
    return (
        json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _integer(value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"invalid {name}")
    return value


def read_harness_binding(generation_id: str) -> dict[str, str]:
    result = subprocess.run(
        [HARNESS_INSPECTOR, "generation-runtime", generation_id],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, check=False, timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 32 * 1024:
        raise PermissionError("protected harness runtime binding is unavailable")
    try:
        return validate_harness_binding(json.loads(result.stdout))
    except (HarnessBindingError, json.JSONDecodeError) as error:
        raise PermissionError("protected harness runtime binding is invalid") from error


def validate_gateway_lease(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != GATEWAY_LEASE_FIELDS
            or value.get("schema") != GATEWAY_LEASE_SCHEMA):
        raise ValueError("invalid embedded Gateway lease fields")
    run_id = canonical_uuid4(str(value.get("run_id", "")), "Gateway run ID")
    lease_id = canonical_uuid4(str(value.get("lease_id", "")), "Gateway lease ID")
    profile = value.get("profile")
    if not isinstance(profile, str) or NAME_RE.fullmatch(profile) is None:
        raise ValueError("invalid embedded Gateway lease profile")
    issued_at = _integer(value.get("issued_at"), "Gateway lease issue time")
    expires_at = _integer(value.get("expires_at"), "Gateway lease expiry", minimum=1)
    maximum_expires_at = _integer(
        value.get("maximum_expires_at"), "Gateway lease maximum expiry", minimum=1
    )
    renewals = _integer(value.get("renewals"), "Gateway lease renewals")
    if not issued_at <= expires_at <= maximum_expires_at:
        raise ValueError("invalid embedded Gateway lease time bounds")
    try:
        authority = validate_runtime_authority(value.get("runtime_authority"))
    except RuntimeAuthorityError as error:
        raise ValueError("invalid embedded Gateway runtime authority") from error
    transport = value.get("brokered_transport")
    if (not isinstance(transport, dict)
            or set(transport) != {"schema", "relay_sha256", "policy_sha256"}
            or transport.get("schema") != "secure-sandbox-brokered-run-transport-v1"
            or any(not isinstance(transport.get(name), str)
                   or SHA256_RE.fullmatch(transport[name]) is None
                   for name in ("relay_sha256", "policy_sha256"))):
        raise ValueError("invalid embedded Gateway transport")
    limits = value.get("limits")
    limit_fields = {"max_requests", "max_input_tokens", "max_output_tokens", "max_cost_microusd"}
    if not isinstance(limits, dict) or set(limits) != limit_fields:
        raise ValueError("invalid embedded Gateway limits")
    for name in limit_fields:
        _integer(limits.get(name), f"Gateway {name}", minimum=1)
    pricing = value.get("pricing")
    price_fields = {
        "input_microusd_per_million_tokens",
        "output_microusd_per_million_tokens",
    }
    if not isinstance(pricing, dict) or set(pricing) != price_fields:
        raise ValueError("invalid embedded Gateway pricing")
    for name in price_fields:
        _integer(pricing.get(name), f"Gateway {name}", minimum=1)
    return {
        "schema": GATEWAY_LEASE_SCHEMA, "lease_id": lease_id, "run_id": run_id,
        "profile": profile, "issued_at": issued_at, "expires_at": expires_at,
        "maximum_expires_at": maximum_expires_at, "runtime_authority": authority,
        "brokered_transport": transport, "limits": limits, "pricing": pricing,
        "renewals": renewals,
    }


def validate_research_lease(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != LEASE_FIELDS or value.get("schema") != LEASE_SCHEMA:
        raise ValueError("invalid Research lease fields")
    run_id = canonical_uuid4(str(value.get("run_id", "")), "run ID")
    lease_id = canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    expires_at = _integer(value.get("expires_at"), "Research lease expiry", minimum=1)
    maximum_expires_at = _integer(
        value.get("maximum_expires_at"), "Research lease maximum expiry", minimum=1
    )
    if expires_at > maximum_expires_at:
        raise ValueError("invalid Research lease time bounds")
    gateway_digest = value.get("gateway_lease_sha256")
    if not isinstance(gateway_digest, str) or SHA256_RE.fullmatch(gateway_digest) is None:
        raise ValueError("invalid Gateway lease digest")
    try:
        authority = validate_runtime_authority(value.get("runtime_authority"))
    except RuntimeAuthorityError as error:
        raise ValueError("invalid Research runtime authority") from error
    gateway_lease = validate_gateway_lease(value.get("gateway_lease"))
    if (gateway_lease["run_id"] != run_id or gateway_lease["lease_id"] != lease_id
            or gateway_lease["expires_at"] != expires_at
            or gateway_lease["maximum_expires_at"] != maximum_expires_at
            or gateway_lease["runtime_authority"] != authority
            or hashlib.sha256(canonical_json_line(gateway_lease)).hexdigest() != gateway_digest):
        raise ValueError("embedded Gateway lease does not match Research lease")
    return {
        "schema": LEASE_SCHEMA, "run_id": run_id, "lease_id": lease_id,
        "expires_at": expires_at, "maximum_expires_at": maximum_expires_at,
        "runtime_authority": authority, "gateway_lease": gateway_lease,
        "gateway_lease_sha256": gateway_digest,
    }


def validate_process_record(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != PROCESS_SCHEMA:
        raise ValueError("invalid run process schema")
    fields = set(value)
    allowed = (
        PROCESS_SEED_FIELDS, PROCESS_CLAIMED_FIELDS, PROCESS_READY_FIELDS,
        PROCESS_FAILED_FIELDS, PROCESS_TERMINAL_FIELDS,
    )
    if not any(fields == candidate for candidate in allowed):
        raise ValueError("invalid run process fields")
    run_id = canonical_uuid4(str(value.get("run_id", "")), "run ID")
    lease_id = canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    if value.get("unit") != scope_unit(run_id):
        raise ValueError("invalid run process scope")
    gateway_digest = value.get("gateway_lease_sha256")
    if not isinstance(gateway_digest, str) or SHA256_RE.fullmatch(gateway_digest) is None:
        raise ValueError("invalid run process Gateway lease digest")
    try:
        authority = validate_runtime_authority(value.get("runtime_authority"))
    except RuntimeAuthorityError as error:
        raise ValueError("invalid run process runtime authority") from error
    ready = value.get("ready")
    if not isinstance(ready, bool):
        raise ValueError("invalid run process ready state")
    if fields == PROCESS_SEED_FIELDS:
        if ready is not False:
            raise ValueError("invalid run process seed state")
    else:
        _integer(value.get("supervisor_pid"), "supervisor PID", minimum=1)
        _integer(value.get("supervisor_start_time"), "supervisor start time")
        if fields == PROCESS_CLAIMED_FIELDS:
            if ready is not False:
                raise ValueError("invalid claimed process state")
        elif fields == PROCESS_READY_FIELDS:
            if ready is not True:
                raise ValueError("invalid ready process state")
            _integer(value.get("scope_pid"), "scope PID", minimum=1)
        elif fields == PROCESS_FAILED_FIELDS:
            if ready is not False or value.get("scope_empty") is not True:
                raise ValueError("invalid failed process state")
            error_name = value.get("launch_failed")
            if not isinstance(error_name, str) or ERROR_NAME_RE.fullmatch(error_name) is None:
                raise ValueError("invalid launch failure identity")
            _integer(value.get("exited_at"), "process exit time", minimum=1)
        else:
            if ready is not True or value.get("scope_empty") is not True:
                raise ValueError("invalid terminal process state")
            _integer(value.get("scope_pid"), "scope PID", minimum=1)
            exit_status = value.get("exit_status")
            if isinstance(exit_status, bool) or not isinstance(exit_status, int):
                raise ValueError("invalid process exit status")
            _integer(value.get("exited_at"), "process exit time", minimum=1)
    return {**value, "run_id": run_id, "lease_id": lease_id,
            "runtime_authority": authority}


def require_brokered_runtime(authority_value: object) -> dict[str, Any]:
    try:
        authority = validate_runtime_authority(authority_value)
    except RuntimeAuthorityError as error:
        raise PermissionError("run runtime authority is invalid") from error
    if authority["model_stack_binding"]["mode"] != BROKERED_MODE:
        raise PermissionError("native runtime transport is unavailable")
    return authority


def executable_for_binding(authority_value: object) -> Path:
    authority = require_brokered_runtime(authority_value)
    carried = authority["harness_binding"]
    generation_id = carried["harness_generation_id"]
    observed = read_harness_binding(generation_id)
    if carried != observed:
        raise PermissionError("run lease harness binding mismatch")
    executable = HARNESS_RELEASE_ROOT / generation_id / "harness"
    metadata = executable.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != TRUSTED_UID or stat.S_IMODE(metadata.st_mode) != 0o555
            or metadata.st_nlink != 1 or metadata.st_size <= 0):
        raise PermissionError("protected harness executable is untrusted")
    descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError("protected harness executable changed during open")
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    if digest != carried["harness_executable_sha256"]:
        raise PermissionError("protected harness executable mismatch")
    return executable


def canonical_run_id(value: str) -> str:
    return canonical_uuid4(value, "run ID")


def read_run_marker(run_id: str) -> None:
    metadata = RUN_ID_FILE.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != TRUSTED_UID or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1 or metadata.st_size != 37):
        raise PermissionError("run marker ownership or mode is invalid")
    descriptor = os.open(RUN_ID_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError("run marker changed during open")
        raw = os.read(descriptor, 38)
    finally:
        os.close(descriptor)
    if raw != (run_id + "\n").encode("ascii"):
        raise PermissionError("run marker mismatch")


def validate_arguments(arguments: list[str]) -> tuple[str, list[str], str | None]:
    if len(arguments) < 2:
        raise ValueError("run ID and harness command are required")
    run_id = canonical_run_id(arguments[0])
    source_id = None
    remaining_arguments = arguments[1:]
    if remaining_arguments[:1] == ["--source"]:
        if len(remaining_arguments) < 3:
            raise ValueError("source UUID and fixed harness command are required")
        source_id = canonical_uuid4(remaining_arguments[1], "source ID")
        remaining_arguments = remaining_arguments[2:]
    options = remaining_arguments
    fixed = ["--append-system-prompt-file", "/etc/claude-code/secure-sandbox-persona.md",
             "--no-chrome", "--restricted", "--permission-mode", "manual"]
    if options[:len(fixed)] != fixed:
        raise ValueError("fixed harness options are required")
    remaining = options[len(fixed):]
    if len(remaining) != 2 or remaining[0] not in {"--resume", "--session-id"}:
        raise ValueError("an exact --resume or --session-id SESSION_UUID is required")
    canonical_uuid4(remaining[1], "session ID")
    if source_id is not None and remaining[0] != "--session-id":
        raise ValueError("selected source requires a new session")
    read_run_marker(run_id)
    return run_id, options, source_id


def source_working_directory(source_id: str) -> str:
    from source_integrity import fixed_tree_path, registered_source, verify_source

    result = verify_source(source_id, scope="worktree")
    if result.get("overall_status") != "match":
        raise PermissionError("selected source integrity is not verified")
    record = registered_source(source_id)
    return fixed_tree_path(record.get("worktree_path"), "repos")


def validate_bound_launch(authority_value: object, options: list[str],
                          requested_source_id: str | None) -> str | None:
    authority = require_brokered_runtime(authority_value)
    context = authority["session_context_binding"]
    if len(options) < 2 or options[-2] not in {"--resume", "--session-id"}:
        raise PermissionError("run command lacks a bound session identity")
    if options[-1] != context["session_id"]:
        raise PermissionError("run command session does not match runtime authority")
    bound_source_id = context["source_id"]
    if options[-2] == "--session-id" and requested_source_id != bound_source_id:
        raise PermissionError("run command source does not match runtime authority")
    if options[-2] == "--resume" and requested_source_id is not None:
        raise PermissionError("resume cannot substitute a source identity")
    try:
        measured = measure_session_policy(bound_source_id or "none")
    except (OSError, SessionPolicyRuntimeError) as error:
        raise PermissionError("Research session policy measurement failed") from error
    if (not isinstance(measured, dict) or set(measured) != SESSION_POLICY_FIELDS
            or measured.get("schema") != SESSION_POLICY_SCHEMA):
        raise PermissionError("Research session policy measurement is invalid")
    expected = {
        "source_id": context["source_id"],
        "source_manifest_sha256": context["source_manifest_sha256"],
        "persona_sha256": context["persona_sha256"],
        "tool_catalog_sha256": context["tool_catalog_sha256"],
        "extension_set_sha256": context["extension_set_sha256"],
    }
    observed = {name: measured.get(name) for name in expected}
    if observed != expected:
        raise PermissionError("Research session policy does not match runtime authority")
    return bound_source_id


def load_root_json(path: Path, schema: str) -> dict[str, Any]:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != TRUSTED_UID or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1 or not 0 < metadata.st_size <= MAX_STATE_BYTES):
        raise PermissionError(f"invalid {path.name} ownership or mode")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError(f"invalid {path.name} opened identity")
        raw = handle.read(MAX_STATE_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(raw) > MAX_STATE_BYTES or (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ) != (
        opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns
    ):
        raise PermissionError(f"invalid {path.name} stable identity")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {path.name} JSON") from error
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError(f"invalid {path.name} schema")
    try:
        canonical = canonical_json_line(value)
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError(f"invalid {path.name} canonical form") from error
    if raw != canonical:
        raise ValueError(f"noncanonical {path.name}")
    return value


def load_lease() -> dict[str, Any]:
    return validate_research_lease(load_root_json(LEASE_FILE, LEASE_SCHEMA))


def load_process() -> dict[str, Any]:
    return validate_process_record(load_root_json(PROCESS_FILE, PROCESS_SCHEMA))


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_line(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != TRUSTED_UID or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1 or not 0 < metadata.st_size <= MAX_REGISTRY_BYTES):
        raise PermissionError("invalid session registry ownership or mode")
    descriptor = os.open(SESSION_REGISTRY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PermissionError("session registry changed during open")
        content = os.read(descriptor, MAX_REGISTRY_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(content) > MAX_REGISTRY_BYTES:
        raise ValueError("session registry exceeds limit")
    prefix = (session_id + "\t").encode("ascii")
    if not any(line.startswith(prefix) for line in content.splitlines()):
        raise PermissionError("resume session is not registered")


def child_environment(agent: pwd.struct_passwd, authority_value: object) -> dict[str, str]:
    authority = require_brokered_runtime(authority_value)
    model = authority["model_stack_binding"]["authority"]["model"]
    term = os.environ.get("TERM", "xterm-256color")
    if not TERM_RE.fullmatch(term):
        term = "xterm-256color"
    return {
        "HOME": agent.pw_dir, "USER": agent.pw_name, "LOGNAME": agent.pw_name,
        "SHELL": "/bin/bash", "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8", "TERM": term,
        "ANTHROPIC_BASE_URL": "http://127.0.0.1:18080",
        # The bearer is deliberately non-secret. The loopback relay authenticates
        # to Gateway with its root-owned mTLS identity.
        "ANTHROPIC_AUTH_TOKEN": "sandbox-relay-nonsecret",
        "CLAUDE_CODE_USE_GATEWAY": "1",
        "ANTHROPIC_DEFAULT_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
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
                  authority_value: object, working_directory: str = WORKSPACE) -> list[str]:
    environment = child_environment(agent, authority_value)
    result = [
        SYSTEMD_RUN, "--scope", "--quiet", f"--unit={scope_unit(run_id)}",
        f"--working-directory={working_directory}",
        "--property=Delegate=no", "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes", "--property=TasksMax=256",
        "--property=MemoryMax=8G", "--property=CPUQuota=400%",
    ]
    result.extend(f"--setenv={name}={value}" for name, value in sorted(environment.items()))
    return result + ["--", SETPRIV, f"--reuid={agent.pw_uid}",
                     f"--regid={agent.pw_gid}", "--clear-groups",
                     "--inh-caps=-all", "--ambient-caps=-all",
                     "--bounding-set=-all", "--no-new-privs", "--"] + command


def main() -> int:
    agent = pwd.getpwnam("agent")
    validate_invoker(agent)
    run_id, options, requested_source_id = validate_arguments(sys.argv[1:])
    lock_descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    child: subprocess.Popen[bytes] | None = None
    claimed = False
    claimed_supervisor_start: int | None = None

    def forward(signum: int, _frame: object) -> None:
        if child is None:
            return
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGHUP, forward)
    blocked = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        # Repeat the marker proof after acquiring the lock that protects the
        # lease/process pair so admission cannot race a close.
        read_run_marker(run_id)
        lease = load_lease()
        authority = require_brokered_runtime(lease["runtime_authority"])
        bound_source_id = validate_bound_launch(authority, options, requested_source_id)
        validate_resume(options)
        working_directory = (
            source_working_directory(bound_source_id)
            if bound_source_id is not None else WORKSPACE
        )
        executable = executable_for_binding(authority)
        command = [str(executable), *options]
        seed = load_process()
        if (set(seed) != PROCESS_SEED_FIELDS or lease["run_id"] != run_id
                or seed["run_id"] != run_id or seed["lease_id"] != lease["lease_id"]
                or seed["ready"] is not False
                or seed["runtime_authority"] != authority
                or seed["gateway_lease_sha256"] != lease["gateway_lease_sha256"]):
            raise PermissionError("run process registration mismatch")
        if lease["expires_at"] <= int(time.time()):
            raise PermissionError("run lease is expired")
        expected_unit = scope_unit(run_id)
        if seed["unit"] != expected_unit:
            raise PermissionError("run scope identity mismatch")
        _, _, supervisor_start = process_fields(os.getpid())
        pending = validate_process_record({
            **seed,
            "supervisor_pid": os.getpid(),
            "supervisor_start_time": supervisor_start,
        })
        atomic_json(PROCESS_FILE, pending)
        claimed = True
        claimed_supervisor_start = supervisor_start
        child = subprocess.Popen(
            scope_command(agent, run_id, command, authority, working_directory),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, set()),
        )
        ready = validate_process_record({
            **pending, "ready": True, "scope_pid": child.pid,
        })
        atomic_json(PROCESS_FILE, ready)
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    except Exception as error:
        if child is not None:
            try:
                child.kill()
            except ProcessLookupError:
                pass
            child.wait()
        if claimed:
            try:
                registration = load_process()
                if registration_belongs_to(
                    registration, os.getpid(), int(claimed_supervisor_start)
                ):
                    if set(registration) == PROCESS_CLAIMED_FIELDS:
                        terminal = validate_process_record({
                            **registration,
                            "launch_failed": type(error).__name__,
                            "scope_empty": True,
                            "exited_at": int(time.time()),
                        })
                    elif set(registration) == PROCESS_READY_FIELDS and child is not None:
                        terminal = validate_process_record({
                            **registration,
                            "scope_empty": True,
                            "exit_status": child.returncode,
                            "exited_at": int(time.time()),
                        })
                    else:
                        raise ValueError("run process changed during launch failure")
                    atomic_json(PROCESS_FILE, terminal)
            except (FileNotFoundError, PermissionError, ValueError):
                pass
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        os.close(lock_descriptor)
        raise
    assert child is not None
    status = child.wait()
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
    try:
        registration = load_process()
        if (registration.get("supervisor_pid") == os.getpid()
                and registration.get("scope_pid") == child.pid
                and registration.get("unit") == scope_unit(run_id)):
            terminal = validate_process_record({
                **registration,
                "scope_empty": True,
                "exit_status": status,
                "exited_at": int(time.time()),
            })
            atomic_json(PROCESS_FILE, terminal)
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
