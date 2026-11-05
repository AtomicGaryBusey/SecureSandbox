#!/usr/bin/env python3
"""Exact Claude Code subscription-OAuth adapter for one admitted native stack.

This adapter never reads or copies Claude's credential file.  It supplies a
dedicated configuration directory to the unmodified admitted executable and
observes only Claude Code's bounded, content-free authentication status.  The
provider connection remains TLS end-to-end through the separate opaque proxy.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import selectors
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from shared.native_stack_runtime_binding import (
    NativeStackBindingError,
    validate_binding as validate_native_binding,
)
from shared.harness_runtime_binding import (
    HarnessBindingError,
    validate_binding as validate_harness_binding,
)
from shared import native_vendor_stack
from shared.runtime_authority import RuntimeAuthorityError, validate_binding as validate_authority


STATUS_SCHEMA = "secure-sandbox-claude-native-status-v2"
ENTITLEMENT_SCHEMA = "secure-sandbox-claude-native-entitlement-v2"
CLAUDE_HARNESS_ID = "claude-code"
CLAUDE_ADAPTER_ID = "claude-native-oauth-v1"
CLAUDE_VENDOR_ID = "anthropic"
CLAUDE_AUTH_MODE = "anthropic-claude-subscription-oauth"
CLAUDE_MODEL_ID = "claude-mythos-5-1"
PROXY = "http://172.30.10.1:8643"
CONFIG_ROOT = Path("/var/lib/secure-sandbox/native-vendor/anthropic")
RELEASE_ROOT = Path("/usr/local/libexec/secure-sandbox-harnesses/releases")
MANAGED_SETTINGS = Path("/etc/claude-code/native-claude-session-settings.json")
PERSONA = Path("/etc/claude-code/secure-sandbox-persona.md")
MAX_STATUS_BYTES = 16 * 1024
MAX_ENTITLEMENT_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
TERM = re.compile(r"[A-Za-z0-9+_.-]{1,64}")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
PYTHON = Path("/usr/bin/python3")
COMMAND_SUPERVISOR = Path(
    "/usr/local/libexec/secure-sandbox/native_provider_controller.py"
)
COMMAND_SUPERVISOR_MODE = "native-claude-command-supervisor"
COMMAND_UNIT = re.compile(
    r"secure-sandbox-native-claude-command-[0-9a-f]{32}\.service"
)
COMMAND_REQUEST_SCHEMA = "secure-sandbox-native-claude-command-request-v1"
COMMAND_HANDSHAKE_SCHEMA = "secure-sandbox-native-claude-command-handshake-v1"
COMMAND_RESPONSE_SCHEMA = "secure-sandbox-native-claude-command-response-v1"
COMMAND_REQUEST_MAXIMUM = 64 * 1024
COMMAND_HANDSHAKE_MAXIMUM = 16 * 1024
COMMAND_RESPONSE_OVERHEAD = 64 * 1024
CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_ROOT = Path("/proc")
SUPERVISOR_RUNTIME_MARGIN = 10
SUPERVISOR_STOP_SECONDS = 2
SUPERVISOR_TASKS_MAX = 128
SUPERVISOR_CAPABILITY_MASK = (
    (1 << 6) | (1 << 7) | (1 << 8)
)  # CAP_SETGID | CAP_SETUID | CAP_SETPCAP
SUPERVISOR_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class NativeClaudeAdapterError(ValueError):
    """Stable fail-closed native Claude adapter error."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeClaudeAdapterError("native_claude_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_claude_authority(value: object) -> dict[str, Any]:
    try:
        authority = validate_authority(value)
    except RuntimeAuthorityError as error:
        raise NativeClaudeAdapterError("native_claude_runtime_authority_invalid") from error
    stack_wrapper = authority["model_stack_binding"]
    if stack_wrapper["mode"] != "native-vendor-harness-model-stack":
        raise NativeClaudeAdapterError("native_claude_runtime_mode_invalid")
    try:
        native = validate_native_binding(stack_wrapper["authority"])
    except NativeStackBindingError as error:
        raise NativeClaudeAdapterError("native_claude_stack_binding_invalid") from error
    harness = authority["harness_binding"]
    expected = {
        "vendor_id": CLAUDE_VENDOR_ID,
        "harness_id": CLAUDE_HARNESS_ID,
        "harness_adapter_id": CLAUDE_ADAPTER_ID,
        "authentication_mode": CLAUDE_AUTH_MODE,
        "credential_custody": "vendor-harness",
        "program_id": "anthropic-cvp",
        "program_tier": "defense",
        "program_requirements_version": "anthropic-cvp-defense-2026-10-31",
        "model_id": CLAUDE_MODEL_ID,
        "network_policy_id": "anthropic-claude-native-oauth-v1",
    }
    if any(native.get(name) != expected_value for name, expected_value in expected.items()):
        raise NativeClaudeAdapterError("native_claude_stack_pairing_invalid")
    if any(
        native[native_name] != harness[harness_name]
        for native_name, harness_name in (
            ("harness_id", "harness_id"),
            ("harness_generation_id", "harness_generation_id"),
            ("harness_adapter_id", "harness_adapter_id"),
        )
    ):
        raise NativeClaudeAdapterError("native_claude_harness_binding_mismatch")
    return authority


def _hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def executable_for_authority(
    authority_value: object,
    *,
    release_root: Path = RELEASE_ROOT,
    trusted_uid: int = 0,
) -> Path:
    authority = require_claude_authority(authority_value)
    return executable_for_harness(
        authority["harness_binding"], release_root=release_root,
        trusted_uid=trusted_uid,
    )


def executable_for_harness(
    harness_value: object,
    *,
    release_root: Path = RELEASE_ROOT,
    trusted_uid: int = 0,
) -> Path:
    try:
        harness = validate_harness_binding(harness_value)
    except HarnessBindingError as error:
        raise NativeClaudeAdapterError("native_claude_harness_binding_invalid") from error
    if (
        harness["harness_id"] != CLAUDE_HARNESS_ID
        or harness["harness_adapter_id"] != CLAUDE_ADAPTER_ID
    ):
        raise NativeClaudeAdapterError("native_claude_harness_binding_mismatch")
    generation = harness["harness_generation_id"]
    path = release_root / generation / "harness"
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != trusted_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or metadata.st_size <= 0
    ):
        raise NativeClaudeAdapterError("native_claude_executable_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise NativeClaudeAdapterError("native_claude_executable_identity_changed")
        observed = _hash_fd(descriptor)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        or observed != harness["harness_executable_sha256"]
    ):
        raise NativeClaudeAdapterError("native_claude_executable_digest_mismatch")
    return path


def login_environment(
    stack_value: object,
    harness_value: object,
    *,
    home: Path,
    config_root: Path = CONFIG_ROOT,
    term: str | None = None,
) -> dict[str, str]:
    """Build the exact pre-binding environment for unmodified OAuth login."""
    try:
        stack = native_vendor_stack.validate_stack(stack_value)
        harness = validate_harness_binding(harness_value)
    except (native_vendor_stack.NativeVendorStackError,
            HarnessBindingError) as error:
        raise NativeClaudeAdapterError("native_claude_login_stack_invalid") from error
    if (
        stack["vendor_id"] != CLAUDE_VENDOR_ID
        or stack["harness"]["harness_id"] != CLAUDE_HARNESS_ID
        or stack["harness"]["adapter_id"] != CLAUDE_ADAPTER_ID
        or stack["harness"]["generation_id"] != harness["harness_generation_id"]
        or stack["authentication"]["mode"] != CLAUDE_AUTH_MODE
        or stack["authentication"]["credential_custody"] != "vendor-harness"
        or stack["model"]["model_id"] != CLAUDE_MODEL_ID
        or stack["network_policy_id"] != "anthropic-claude-native-oauth-v1"
        or harness["harness_id"] != CLAUDE_HARNESS_ID
        or harness["harness_adapter_id"] != CLAUDE_ADAPTER_ID
    ):
        raise NativeClaudeAdapterError("native_claude_login_pairing_invalid")
    selected_term = term or os.environ.get("TERM", "xterm-256color")
    if TERM.fullmatch(selected_term) is None:
        selected_term = "xterm-256color"
    environment = {
        "HOME": str(home), "USER": "claude-native", "LOGNAME": "claude-native",
        "SHELL": "/bin/bash", "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8", "TERM": selected_term,
        "CLAUDE_CONFIG_DIR": str(config_directory(stack, root=config_root)),
        "HTTPS_PROXY": PROXY, "HTTP_PROXY": PROXY,
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_UPDATES": "1", "DISABLE_UPGRADE_COMMAND": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        "CLAUDE_CODE_DISABLE_ARTIFACT": "1",
        "CLAUDE_CODE_DISABLE_AGENT_VIEW": "1",
        "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS": "1",
        "CLAUDE_CODE_MCP_ALLOWLIST_ENV": "1",
        "ANTHROPIC_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": CLAUDE_MODEL_ID,
    }
    validate_environment(environment)
    return environment


def config_directory(native_binding: Mapping[str, Any], *, root: Path = CONFIG_ROOT) -> Path:
    stack_id = native_binding.get("stack_id")
    if not isinstance(stack_id, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", stack_id) is None:
        raise NativeClaudeAdapterError("native_claude_stack_id_invalid")
    return root / stack_id / "claude-config"


def child_environment(
    authority_value: object,
    *,
    home: Path,
    cache: Path | None = None,
    temporary: Path | None = None,
    config_root: Path = CONFIG_ROOT,
    term: str | None = None,
) -> dict[str, str]:
    authority = require_claude_authority(authority_value)
    native = authority["model_stack_binding"]["authority"]
    selected_term = term or os.environ.get("TERM", "xterm-256color")
    if TERM.fullmatch(selected_term) is None:
        selected_term = "xterm-256color"
    effort_by_digest = native["model_settings_sha256"]
    # The settings digest is bound by the authority. The caller separately
    # supplies and validates the selected effort when constructing a command;
    # it is intentionally not reverse-engineered from the digest here.
    if SHA256.fullmatch(effort_by_digest) is None:
        raise NativeClaudeAdapterError("native_claude_model_settings_invalid")
    environment = {
        "HOME": str(home),
        "USER": "claude-native",
        "LOGNAME": "claude-native",
        "SHELL": "/bin/bash",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TERM": selected_term,
        "CLAUDE_CONFIG_DIR": str(config_directory(native, root=config_root)),
        "HTTPS_PROXY": PROXY,
        "HTTP_PROXY": PROXY,
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_UPDATES": "1",
        "DISABLE_UPGRADE_COMMAND": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        "CLAUDE_CODE_DISABLE_ARTIFACT": "1",
        "CLAUDE_CODE_DISABLE_AGENT_VIEW": "1",
        "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS": "1",
        "CLAUDE_CODE_MCP_ALLOWLIST_ENV": "1",
        "ANTHROPIC_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": CLAUDE_MODEL_ID,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": CLAUDE_MODEL_ID,
    }
    if cache is not None:
        environment["XDG_CACHE_HOME"] = str(cache)
    if temporary is not None:
        environment["TMPDIR"] = str(temporary)
    validate_environment(environment)
    return environment


FORBIDDEN_ENVIRONMENT = {
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_OAUTH_SCOPES",
    "CLAUDE_CODE_USE_GATEWAY",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "AWS_BEARER_TOKEN_BEDROCK",
}

FIXED_ENVIRONMENT = {
    "USER": "claude-native",
    "LOGNAME": "claude-native",
    "SHELL": "/bin/bash",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "HTTPS_PROXY": PROXY,
    "HTTP_PROXY": PROXY,
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_UPDATES": "1",
    "DISABLE_UPGRADE_COMMAND": "1",
    "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    "CLAUDE_CODE_DISABLE_ARTIFACT": "1",
    "CLAUDE_CODE_DISABLE_AGENT_VIEW": "1",
    "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
    "CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS": "1",
    "CLAUDE_CODE_MCP_ALLOWLIST_ENV": "1",
    "ANTHROPIC_MODEL": CLAUDE_MODEL_ID,
    "ANTHROPIC_DEFAULT_MODEL": CLAUDE_MODEL_ID,
    "ANTHROPIC_DEFAULT_OPUS_MODEL": CLAUDE_MODEL_ID,
    "ANTHROPIC_DEFAULT_SONNET_MODEL": CLAUDE_MODEL_ID,
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": CLAUDE_MODEL_ID,
}
REQUIRED_ENVIRONMENT = set(FIXED_ENVIRONMENT) | {
    "HOME", "TERM", "CLAUDE_CONFIG_DIR",
}
OPTIONAL_ENVIRONMENT = {"XDG_CACHE_HOME", "TMPDIR"}


def validate_environment(environment: Mapping[str, str]) -> None:
    if FORBIDDEN_ENVIRONMENT.intersection(environment):
        raise NativeClaudeAdapterError("native_claude_forbidden_environment")
    if environment.get("HTTPS_PROXY") != PROXY or environment.get("HTTP_PROXY") != PROXY:
        raise NativeClaudeAdapterError("native_claude_proxy_invalid")
    if environment.get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB") != "1":
        raise NativeClaudeAdapterError("native_claude_environment_scrub_missing")
    if environment.get("DISABLE_UPDATES") != "1":
        raise NativeClaudeAdapterError("native_claude_updates_not_disabled")
    if (
        set(environment) - REQUIRED_ENVIRONMENT - OPTIONAL_ENVIRONMENT
        or REQUIRED_ENVIRONMENT - set(environment)
        or any(environment.get(name) != value
               for name, value in FIXED_ENVIRONMENT.items())
    ):
        raise NativeClaudeAdapterError("native_claude_environment_invalid")
    if any(
        not isinstance(name, str) or not isinstance(value, str)
        or not name or not value or "\x00" in name or "\x00" in value
        or any(ord(character) < 32 for character in value)
        for name, value in environment.items()
    ):
        raise NativeClaudeAdapterError("native_claude_environment_invalid")
    if TERM.fullmatch(environment["TERM"]) is None:
        raise NativeClaudeAdapterError("native_claude_environment_invalid")
    for name in {"HOME", "CLAUDE_CONFIG_DIR"} | (
        OPTIONAL_ENVIRONMENT & set(environment)
    ):
        path = Path(environment[name])
        if not path.is_absolute() or ".." in path.parts:
            raise NativeClaudeAdapterError("native_claude_environment_invalid")


def status_command(executable: Path) -> list[str]:
    return [str(executable), "auth", "status", "--json"]


def login_command(executable: Path) -> list[str]:
    return [str(executable), "auth", "login", "--claudeai"]


def logout_command(executable: Path) -> list[str]:
    return [str(executable), "auth", "logout"]


def session_command(
    executable: Path,
    *,
    session_id: str,
    effort: str,
    resume: bool,
    managed_settings: Path = MANAGED_SETTINGS,
    persona: Path = PERSONA,
) -> list[str]:
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        session_id,
    ) is None:
        raise NativeClaudeAdapterError("native_claude_session_id_invalid")
    if effort not in {"low", "medium", "high"}:
        raise NativeClaudeAdapterError("native_claude_effort_invalid")
    return [
        str(executable),
        "--append-system-prompt-file", str(persona),
        "--settings", str(managed_settings),
        "--no-chrome",
        "--restricted",
        "--tools", "",
        "--disallowedTools", "*",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--model", CLAUDE_MODEL_ID,
        "--effort", effort,
        "--permission-mode", "manual",
        "--resume" if resume else "--session-id", session_id,
    ]


def entitlement_command(
    executable: Path,
    *,
    effort: str,
    managed_settings: Path = MANAGED_SETTINGS,
) -> list[str]:
    if effort not in {"low", "medium", "high"}:
        raise NativeClaudeAdapterError("native_claude_effort_invalid")
    return [
        str(executable),
        "--print",
        "--output-format", "json",
        "--no-session-persistence",
        "--tools", "",
        "--disallowedTools", "*",
        "--permission-prompts", "none",
        "--settings", str(managed_settings),
        "--no-chrome",
        "--restricted",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--model", CLAUDE_MODEL_ID,
        "--effort", effort,
        "--max-budget-usd", "0.05",
        "Return exactly SECURE_SANDBOX_ENTITLEMENT_READY and use no tools.",
    ]


@dataclass(frozen=True)
class _SystemdTestHooks:
    """Explicit test-only replacement for Linux systemd and procfs controls."""

    popen: Callable[..., Any]
    runner: Callable[..., subprocess.CompletedProcess[bytes]]
    cgroup_root: Path
    proc_root: Path
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


def _validate_command(command: Sequence[str]) -> list[str]:
    value = list(command)
    if not value or any(
        not isinstance(item, str) or "\x00" in item
        or (not item and (index == 0 or value[index - 1] != "--tools"))
        for index, item in enumerate(value)
    ):
        raise NativeClaudeAdapterError("native_claude_command_invalid")
    return value


def _identity_from_prefix(command_prefix: Sequence[str]) -> tuple[int, int]:
    value = tuple(command_prefix)
    if (
        len(value) != 9
        or value[0] != "/usr/bin/setpriv"
        or re.fullmatch(r"--reuid=[1-9][0-9]{0,9}", value[1]) is None
        or re.fullmatch(r"--regid=[1-9][0-9]{0,9}", value[2]) is None
        or value[3:] != (
            "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
            "--bounding-set=-all", "--no-new-privs", "--",
        )
    ):
        raise NativeClaudeAdapterError("native_claude_identity_prefix_invalid")
    uid = int(value[1].split("=", 1)[1])
    gid = int(value[2].split("=", 1)[1])
    if uid > 2 ** 31 - 1 or gid > 2 ** 31 - 1:
        raise NativeClaudeAdapterError("native_claude_identity_prefix_invalid")
    return uid, gid


def _trusted_command_digest(
    executable: Path, *, release_root: Path = RELEASE_ROOT, trusted_uid: int = 0,
) -> str:
    if (
        not executable.is_absolute()
        or ".." in executable.parts
        or executable.name != "harness"
        or executable.parent.parent != release_root
        or SHA256.fullmatch(executable.parent.name) is None
    ):
        raise NativeClaudeAdapterError("native_claude_command_executable_invalid")
    try:
        before = executable.lstat()
        descriptor = os.open(
            executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeClaudeAdapterError(
            "native_claude_command_executable_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != trusted_uid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o555
            or opened.st_size <= 0
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise NativeClaudeAdapterError(
                "native_claude_command_executable_untrusted")
        digest = _hash_fd(descriptor)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
         opened.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns)
    ):
        raise NativeClaudeAdapterError(
            "native_claude_command_executable_changed")
    return digest


def _validate_installed_supervisor() -> None:
    expected_module = Path(
        "/usr/local/libexec/secure-sandbox/research/native_claude_adapter.py"
    )
    for path, mode in (
        (COMMAND_SUPERVISOR, 0o755),
        (expected_module, 0o444),
        (expected_module.with_name("native_provider_controller.py"), 0o444),
    ):
        try:
            before = path.lstat()
        except OSError as error:
            raise NativeClaudeAdapterError(
                "native_claude_supervisor_untrusted") from error
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
        ):
            raise NativeClaudeAdapterError("native_claude_supervisor_untrusted")
    try:
        python = PYTHON.stat()
    except OSError as error:
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_untrusted") from error
    if (
        not stat.S_ISREG(python.st_mode)
        or python.st_uid != 0
        or stat.S_IMODE(python.st_mode) & 0o022
        or not stat.S_IMODE(python.st_mode) & 0o111
    ):
        raise NativeClaudeAdapterError("native_claude_supervisor_untrusted")


def _systemd_command(unit: str, timeout: int) -> list[str]:
    if COMMAND_UNIT.fullmatch(unit) is None:
        raise NativeClaudeAdapterError("native_claude_service_unit_invalid")
    runtime = timeout + SUPERVISOR_RUNTIME_MARGIN
    environment = " ".join(
        f"{name}={value}" for name, value in sorted({
            **SUPERVISOR_ENVIRONMENT,
            "SECURE_SANDBOX_CLAUDE_COMMAND_UNIT": unit,
        }.items())
    )
    return [
        str(SYSTEMD_RUN), "--system", "--quiet", "--wait", "--pipe",
        "--collect", "--service-type=exec", f"--unit={unit}",
        "--working-directory=/", "--property=User=root",
        "--property=Group=root",
        "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes",
        "--property=ExitType=main",
        "--property=Restart=no",
        f"--property=RuntimeMaxSec={runtime}",
        f"--property=TimeoutStopSec={SUPERVISOR_STOP_SECONDS}",
        f"--property=TasksMax={SUPERVISOR_TASKS_MAX}",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_SETPCAP",
        "--property=AmbientCapabilities=",
        "--property=SupplementaryGroups=",
        "--property=Delegate=no",
        "--property=ProtectControlGroups=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes",
        "--property=UMask=0077",
        "--property=BindsTo=native-harness-supervisor.service",
        "--property=After=native-harness-supervisor.service",
        "--property=PartOf=native-harness-supervisor.service",
        f"--property=Environment={environment}",
        str(PYTHON), str(COMMAND_SUPERVISOR), COMMAND_SUPERVISOR_MODE,
    ]


def _parse_properties(raw: bytes, expected: set[str]) -> dict[str, str]:
    if len(raw) > 64 * 1024:
        raise NativeClaudeAdapterError("native_claude_service_readback_invalid")
    try:
        fields: dict[str, str] = {}
        for line in raw.decode("ascii").splitlines():
            if "=" not in line:
                raise ValueError
            name, value = line.split("=", 1)
            if name in fields:
                raise ValueError
            fields[name] = value
    except (UnicodeDecodeError, ValueError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_service_readback_invalid") from error
    if set(fields) != expected:
        raise NativeClaudeAdapterError("native_claude_service_readback_invalid")
    return fields


def _systemd_duration_usec(value: str) -> int:
    """Parse the bounded duration rendering emitted by ``systemctl show``."""
    if value.isdigit():
        return int(value)
    units = {
        "us": 1,
        "ms": 1_000,
        "s": 1_000_000,
        "min": 60 * 1_000_000,
        "h": 60 * 60 * 1_000_000,
        "d": 24 * 60 * 60 * 1_000_000,
    }
    total = 0
    tokens = value.split()
    if not tokens:
        raise ValueError
    for token in tokens:
        match = re.fullmatch(r"([0-9]+)(us|ms|s|min|h|d)", token)
        if match is None:
            raise ValueError
        total += int(match.group(1)) * units[match.group(2)]
    if total <= 0:
        raise ValueError
    return total


def _systemctl_show(
    unit: str, properties: set[str], *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
    accepted: set[int] = {0},
) -> tuple[int, dict[str, str] | None]:
    try:
        result = runner(
            [str(SYSTEMCTL), "show", unit,
             "--all", "--property=" + ",".join(sorted(properties))],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_systemd_unavailable") from error
    if result.returncode not in accepted:
        raise NativeClaudeAdapterError("native_claude_systemd_unavailable")
    if result.returncode == 4:
        if result.stdout:
            raise NativeClaudeAdapterError(
                "native_claude_service_readback_invalid")
        return result.returncode, None
    return result.returncode, _parse_properties(result.stdout, properties)


def _read_small(path: Path, maximum: int = 64 * 1024) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise NativeClaudeAdapterError("native_claude_proc_readback_invalid")
    return bytes(raw)


def _process_start_time(pid: int, *, proc_root: Path) -> int:
    raw = _read_small(proc_root / str(pid) / "stat")
    try:
        closing = raw.rindex(b")")
        fields = raw[closing + 2:].split()
        value = int(fields[19])
    except (ValueError, IndexError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_proc_readback_invalid") from error
    if value <= 0:
        raise NativeClaudeAdapterError("native_claude_proc_readback_invalid")
    return value


def _validate_process_identity(
    pid: int, cgroup: str, *, proc_root: Path,
) -> int:
    try:
        status = _read_small(proc_root / str(pid) / "status").decode("ascii")
        values: dict[str, str] = {}
        for line in status.splitlines():
            if ":" in line:
                name, value = line.split(":", 1)
                values[name] = value.strip()
        if values.get("Uid", "").split() != ["0"] * 4:
            raise ValueError
        if values.get("Gid", "").split() != ["0"] * 4:
            raise ValueError
        if values.get("NoNewPrivs") != "1":
            raise ValueError
        if (
            any(int(values.get(name, "-1"), 16) != 0
                for name in ("CapInh", "CapAmb"))
            or any(
                int(values.get(name, "-1"), 16) != SUPERVISOR_CAPABILITY_MASK
                for name in ("CapPrm", "CapEff", "CapBnd")
            )
        ):
            raise ValueError
        observed_cgroup = _read_small(
            proc_root / str(pid) / "cgroup").decode("ascii")
        if observed_cgroup != f"0::{cgroup}\n":
            raise ValueError
        command = _read_small(proc_root / str(pid) / "cmdline")
        expected = b"\0".join((
            str(PYTHON).encode("ascii"),
            str(COMMAND_SUPERVISOR).encode("ascii"),
            COMMAND_SUPERVISOR_MODE.encode("ascii"), b"",
        ))
        if command != expected:
            raise ValueError
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_service_identity_invalid") from error
    return _process_start_time(pid, proc_root=proc_root)


_ACTIVE_PROPERTIES = {
    "LoadState", "ActiveState", "SubState", "MainPID", "ControlGroup",
    "User", "Group", "KillMode", "SendSIGKILL", "RuntimeMaxUSec",
    "TimeoutStopUSec", "TasksMax", "NoNewPrivileges", "UMask", "Type",
    "ExecStart", "FragmentPath", "Transient", "SupplementaryGroups",
    "CapabilityBoundingSet", "AmbientCapabilities", "Delegate",
    "ProtectControlGroups", "RestrictSUIDSGID", "LockPersonality",
    "BindsTo", "After", "PartOf", "Environment", "ExitType", "Restart",
}


def _verify_active_service(
    unit: str, timeout: int, handshake: Mapping[str, Any], *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
    cgroup_root: Path, proc_root: Path,
) -> tuple[int, int, str]:
    _returncode, fields = _systemctl_show(
        unit, _ACTIVE_PROPERTIES, runner=runner)
    if fields is None:
        raise NativeClaudeAdapterError("native_claude_service_not_active")
    expected_environment = {
        f"{name}={value}" for name, value in {
            **SUPERVISOR_ENVIRONMENT,
            "SECURE_SANDBOX_CLAUDE_COMMAND_UNIT": unit,
        }.items()
    }
    try:
        pid = int(fields["MainPID"])
        cgroup = fields["ControlGroup"]
        exec_start = fields["ExecStart"]
        expected_exec = (
            f"argv[]={PYTHON} {COMMAND_SUPERVISOR} "
            f"{COMMAND_SUPERVISOR_MODE} ;"
        )
        if (
            fields["LoadState"] != "loaded"
            or fields["ActiveState"] != "active"
            or fields["SubState"] != "running"
            or pid <= 1
            or not cgroup.startswith("/")
            or ".." in Path(cgroup).parts
            or not cgroup.endswith("/" + unit)
            or fields["User"] not in {"0", "root"}
            or fields["Group"] not in {"0", "root"}
            or fields["KillMode"] != "control-group"
            or fields["SendSIGKILL"] != "yes"
            or fields["ExitType"] != "main"
            or fields["Restart"] != "no"
            or _systemd_duration_usec(fields["RuntimeMaxUSec"])
               != (timeout + SUPERVISOR_RUNTIME_MARGIN) * 1_000_000
            or _systemd_duration_usec(fields["TimeoutStopUSec"])
               != SUPERVISOR_STOP_SECONDS * 1_000_000
            or fields["TasksMax"] != str(SUPERVISOR_TASKS_MAX)
            or fields["NoNewPrivileges"] != "yes"
            or fields["UMask"] != "0077"
            or fields["Type"] != "exec"
            or fields["FragmentPath"]
               != f"/run/systemd/transient/{unit}"
            or fields["Transient"] != "yes"
            or fields["SupplementaryGroups"]
            or set(fields["CapabilityBoundingSet"].split())
               != {"cap_setgid", "cap_setuid", "cap_setpcap"}
            or fields["AmbientCapabilities"]
            or fields["Delegate"] != "no"
            or fields["ProtectControlGroups"] != "yes"
            or fields["RestrictSUIDSGID"] != "yes"
            or fields["LockPersonality"] != "yes"
            or f"path={PYTHON} ;" not in exec_start
            or expected_exec not in exec_start
            or "native-harness-supervisor.service" not in fields["BindsTo"].split()
            or "native-harness-supervisor.service" not in fields["After"].split()
            or "native-harness-supervisor.service" not in fields["PartOf"].split()
            or set(fields["Environment"].split()) != expected_environment
        ):
            raise ValueError
        if (
            set(handshake) != {"schema", "unit", "pid", "uid", "gid", "cgroup"}
            or handshake["schema"] != COMMAND_HANDSHAKE_SCHEMA
            or handshake["unit"] != unit
            or handshake["pid"] != pid
            or handshake["uid"] != 0
            or handshake["gid"] != 0
            or handshake["cgroup"] != cgroup
        ):
            raise ValueError
        processes = _read_small(
            cgroup_root / cgroup.lstrip("/") / "cgroup.procs", 4096)
        if processes != f"{pid}\n".encode("ascii"):
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_service_identity_invalid") from error
    return pid, _validate_process_identity(
        pid, cgroup, proc_root=proc_root), cgroup


def _read_canonical_line(
    stream: Any, maximum: int, deadline: float, *,
    monotonic: Callable[[], float],
) -> dict[str, Any]:
    selector = selectors.DefaultSelector()
    raw = bytearray()
    try:
        descriptor = stream.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise NativeClaudeAdapterError("native_claude_service_timeout")
            if not selector.select(min(remaining, 0.1)):
                continue
            try:
                block = os.read(
                    descriptor, min(65536, maximum + 1 - len(raw)))
            except BlockingIOError:
                continue
            if not block:
                raise NativeClaudeAdapterError(
                    "native_claude_service_transport_closed")
            raw.extend(block)
            if len(raw) > maximum:
                raise NativeClaudeAdapterError(
                    "native_claude_service_response_oversized")
            newline = raw.find(b"\n")
            if newline >= 0:
                if newline != len(raw) - 1:
                    raise NativeClaudeAdapterError(
                        "native_claude_service_protocol_invalid")
                break
    finally:
        selector.close()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_service_protocol_invalid") from error
    if not isinstance(value, dict) or bytes(raw) != canonical_bytes(value):
        raise NativeClaudeAdapterError("native_claude_service_protocol_invalid")
    return value


def _write_before_deadline(
    stream: Any, raw: bytes, deadline: float, *,
    monotonic: Callable[[], float],
) -> None:
    selector = selectors.DefaultSelector()
    try:
        descriptor = stream.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_WRITE)
        remaining = memoryview(raw)
        while remaining:
            timeout = deadline - monotonic()
            if timeout <= 0:
                raise NativeClaudeAdapterError("native_claude_service_timeout")
            if not selector.select(min(timeout, 0.1)):
                continue
            try:
                count = os.write(descriptor, remaining)
            except BlockingIOError:
                continue
            if count <= 0:
                raise NativeClaudeAdapterError(
                    "native_claude_service_transport_closed")
            remaining = remaining[count:]
    finally:
        selector.close()


def _unit_absence_snapshot(
    unit: str, *, observed_cgroup: str | None, process_id: int | None,
    process_start_time: int | None,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
    cgroup_root: Path, proc_root: Path,
) -> None:
    properties = {"LoadState", "ActiveState", "SubState", "MainPID", "ControlGroup"}
    returncode, fields = _systemctl_show(
        unit, properties, runner=runner, accepted={0, 4})
    reported_cgroup: str | None = None
    if returncode == 0:
        if fields is None:
            raise NativeClaudeAdapterError(
                "native_claude_service_teardown_ambiguous")
        reported_cgroup = fields["ControlGroup"] or None
        if (
            fields["LoadState"] not in {"loaded", "not-found"}
            or fields["ActiveState"] not in {"inactive", "failed"}
            or fields["SubState"] not in {"dead", "failed"}
            or fields["MainPID"] != "0"
        ):
            raise NativeClaudeAdapterError(
                "native_claude_service_teardown_ambiguous")
    for cgroup in {observed_cgroup, reported_cgroup} - {None}:
        if (
            not isinstance(cgroup, str)
            or not cgroup.startswith("/")
            or ".." in Path(cgroup).parts
            or not cgroup.endswith("/" + unit)
        ):
            raise NativeClaudeAdapterError(
                "native_claude_service_teardown_ambiguous")
        try:
            processes = _read_small(
                cgroup_root / cgroup.lstrip("/") / "cgroup.procs", 4096)
        except FileNotFoundError:
            processes = b""
        if processes.strip():
            raise NativeClaudeAdapterError(
                "native_claude_service_processes_live")
    if process_id is not None and process_start_time is not None:
        try:
            current = _process_start_time(process_id, proc_root=proc_root)
        except FileNotFoundError:
            current = None
        if current == process_start_time:
            raise NativeClaudeAdapterError(
                "native_claude_service_process_live")


def _stop_and_prove_service_absent(
    unit: str, process: Any | None, *, observed_cgroup: str | None,
    process_id: int | None, process_start_time: int | None,
    hooks: _SystemdTestHooks,
) -> None:
    errors: list[BaseException] = []
    if process is not None and process.stdin is not None:
        try:
            process.stdin.close()
        except BaseException as error:
            errors.append(error)
    try:
        result = hooks.runner(
            [str(SYSTEMCTL), "stop", unit], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "LC_ALL": "C.UTF-8"},
        )
        if not isinstance(result.returncode, int):
            raise NativeClaudeAdapterError("native_claude_systemd_unavailable")
    except BaseException as error:
        errors.append(error)
    if process is not None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.terminate()
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
            except BaseException as error:
                errors.append(error)
        except BaseException as error:
            errors.append(error)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as error:
                    errors.append(error)
    try:
        for index in range(2):
            _unit_absence_snapshot(
                unit, observed_cgroup=observed_cgroup,
                process_id=process_id, process_start_time=process_start_time,
                runner=hooks.runner, cgroup_root=hooks.cgroup_root,
                proc_root=hooks.proc_root)
            if index == 0:
                hooks.sleep(0.02)
    except BaseException as error:
        errors.append(error)
    if errors:
        raise NativeClaudeAdapterError(
            "native_claude_service_cleanup_failed") from errors[0]


def _run_bounded(
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    maximum: int,
    timeout: int,
    command_prefix: Sequence[str] = (),
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    _systemd_test_hooks: _SystemdTestHooks | None = None,
) -> subprocess.CompletedProcess[bytes]:
    validate_environment(environment)
    if not 1 <= maximum <= MAX_ENTITLEMENT_BYTES or not 1 <= timeout <= 120:
        raise NativeClaudeAdapterError("native_claude_process_bounds_invalid")
    vendor_command = _validate_command(command)
    complete_command = _validate_command([*command_prefix, *vendor_command])
    if runner is not None:
        # Explicit dependency injection is the only non-systemd path and is
        # retained solely for content-parser unit tests on non-Linux hosts.
        result = runner(
            complete_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=dict(environment), check=False,
            timeout=timeout,
        )
        if len(result.stdout) > maximum:
            raise NativeClaudeAdapterError("native_claude_output_oversized")
        return result

    uid, gid = _identity_from_prefix(command_prefix)
    if _systemd_test_hooks is None:
        _validate_installed_supervisor()
    executable_sha256 = _trusted_command_digest(Path(vendor_command[0]))
    unit = f"secure-sandbox-native-claude-command-{uuid.uuid4().hex}.service"
    nonce = uuid.uuid4().hex
    request = {
        "schema": COMMAND_REQUEST_SCHEMA,
        "unit": unit,
        "nonce": nonce,
        "command": vendor_command,
        "environment": dict(environment),
        "executable_sha256": executable_sha256,
        "vendor_uid": uid,
        "vendor_gid": gid,
        "maximum": maximum,
        "timeout": timeout,
    }
    request_raw = canonical_bytes(request)
    if len(request_raw) > COMMAND_REQUEST_MAXIMUM:
        raise NativeClaudeAdapterError("native_claude_command_request_oversized")
    hooks = _systemd_test_hooks or _SystemdTestHooks(
        popen=subprocess.Popen, runner=subprocess.run,
        cgroup_root=CGROUP_ROOT, proc_root=PROC_ROOT)
    process: Any | None = None
    process_id: int | None = None
    process_start_time: int | None = None
    observed_cgroup: str | None = None
    response: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        process = hooks.popen(
            _systemd_command(unit, timeout),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "LC_ALL": "C.UTF-8"},
        )
        if process.stdin is None or process.stdout is None:
            raise NativeClaudeAdapterError(
                "native_claude_service_transport_unavailable")
        handshake = _read_canonical_line(
            process.stdout, COMMAND_HANDSHAKE_MAXIMUM,
            hooks.monotonic() + 5, monotonic=hooks.monotonic)
        process_id, process_start_time, observed_cgroup = _verify_active_service(
            unit, timeout, handshake, runner=hooks.runner,
            cgroup_root=hooks.cgroup_root, proc_root=hooks.proc_root)
        _write_before_deadline(
            process.stdin, request_raw, hooks.monotonic() + 5,
            monotonic=hooks.monotonic)
        response = _read_canonical_line(
            process.stdout,
            4 * ((maximum + 2) // 3) + COMMAND_RESPONSE_OVERHEAD,
            hooks.monotonic() + timeout + 2, monotonic=hooks.monotonic)
    except BaseException as error:
        primary_error = error
    try:
        _stop_and_prove_service_absent(
            unit, process, observed_cgroup=observed_cgroup,
            process_id=process_id, process_start_time=process_start_time,
            hooks=hooks)
    except BaseException as error:
        raise error from primary_error
    if primary_error is not None:
        if isinstance(primary_error, subprocess.TimeoutExpired):
            raise NativeClaudeAdapterError(
                "native_claude_process_timeout") from primary_error
        if isinstance(primary_error, NativeClaudeAdapterError):
            raise primary_error
        if isinstance(primary_error, Exception):
            raise NativeClaudeAdapterError(
                "native_claude_service_failed") from primary_error
        raise primary_error
    if response is None or set(response) != {
        "schema", "status", "nonce", "returncode", "stdout_b64",
        "stdout_sha256", "error",
    } or response.get("schema") != COMMAND_RESPONSE_SCHEMA or response.get(
        "nonce") != nonce:
        raise NativeClaudeAdapterError("native_claude_service_protocol_invalid")
    if response["status"] != "completed" or response["error"] is not None:
        raise NativeClaudeAdapterError("native_claude_supervisor_rejected")
    if (
        not isinstance(response["returncode"], int)
        or isinstance(response["returncode"], bool)
        or not -255 <= response["returncode"] <= 255
        or not isinstance(response["stdout_b64"], str)
        or not isinstance(response["stdout_sha256"], str)
        or SHA256.fullmatch(response["stdout_sha256"]) is None
    ):
        raise NativeClaudeAdapterError("native_claude_service_protocol_invalid")
    try:
        output = base64.b64decode(response["stdout_b64"], validate=True)
    except (ValueError, TypeError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_service_protocol_invalid") from error
    if (
        len(output) > maximum
        or hashlib.sha256(output).hexdigest() != response["stdout_sha256"]
    ):
        raise NativeClaudeAdapterError("native_claude_service_protocol_invalid")
    return subprocess.CompletedProcess(
        complete_command, response["returncode"], output, b"")


def _supervisor_context(
    *, proc_root: Path = PROC_ROOT, cgroup_root: Path = CGROUP_ROOT,
) -> dict[str, Any]:
    """Prove this is the root-owned main process of our exact transient unit."""
    unit = os.environ.get("SECURE_SANDBOX_CLAUDE_COMMAND_UNIT", "")
    uid, gid, pid = os.getuid(), os.getgid(), os.getpid()
    if (
        COMMAND_UNIT.fullmatch(unit) is None
        or uid != 0 or gid != 0
        or os.geteuid() != 0 or os.getegid() != 0
        or os.getgroups()
    ):
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_context_invalid")
    try:
        raw_cgroup = _read_small(proc_root / "self" / "cgroup", 4096)
        if not raw_cgroup.startswith(b"0::/") or not raw_cgroup.endswith(b"\n"):
            raise ValueError
        if raw_cgroup.count(b"\n") != 1:
            raise ValueError
        cgroup = raw_cgroup[3:-1].decode("ascii")
        if (
            not cgroup.startswith("/")
            or ".." in Path(cgroup).parts
            or not cgroup.endswith("/" + unit)
        ):
            raise ValueError
        status = _read_small(proc_root / "self" / "status")
        values: dict[str, str] = {}
        for line in status.decode("ascii").splitlines():
            if ":" in line:
                name, value = line.split(":", 1)
                values[name] = value.strip()
        if (
            values.get("Uid", "").split() != [str(uid)] * 4
            or values.get("Gid", "").split() != [str(gid)] * 4
            or values.get("NoNewPrivs") != "1"
            or any(int(values.get(name, "-1"), 16) != 0
                   for name in ("CapInh", "CapAmb"))
            or any(
                int(values.get(name, "-1"), 16)
                != SUPERVISOR_CAPABILITY_MASK
                for name in ("CapPrm", "CapEff", "CapBnd")
            )
        ):
            raise ValueError
        processes = _read_small(
            cgroup_root / cgroup.lstrip("/") / "cgroup.procs", 4096)
        observed = {
            int(line) for line in processes.decode("ascii").splitlines()
        }
        if observed != {pid}:
            raise ValueError
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_context_invalid") from error
    for name in os.environ:
        if (
            name in FORBIDDEN_ENVIRONMENT
            or name.startswith("LD_")
            or name in {"PYTHONPATH", "PYTHONHOME"}
        ):
            raise NativeClaudeAdapterError(
                "native_claude_supervisor_environment_invalid")
    return {"unit": unit, "pid": pid, "uid": uid, "gid": gid,
            "cgroup": cgroup}


def _read_supervisor_request(input_fd: int) -> dict[str, Any]:
    raw = bytearray()
    while len(raw) <= COMMAND_REQUEST_MAXIMUM:
        block = os.read(
            input_fd, min(4096, COMMAND_REQUEST_MAXIMUM + 1 - len(raw)))
        if not block:
            raise NativeClaudeAdapterError(
                "native_claude_controller_liveness_lost")
        raw.extend(block)
        newline = raw.find(b"\n")
        if newline >= 0:
            if newline != len(raw) - 1:
                raise NativeClaudeAdapterError(
                    "native_claude_supervisor_protocol_invalid")
            break
    if not raw or len(raw) > COMMAND_REQUEST_MAXIMUM or raw[-1:] != b"\n":
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_protocol_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_protocol_invalid") from error
    if not isinstance(value, dict) or bytes(raw) != canonical_bytes(value):
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_protocol_invalid")
    return value


def _validate_supervisor_request(
    value: object, context: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "unit", "nonce", "command", "environment",
        "executable_sha256", "vendor_uid", "vendor_gid", "maximum", "timeout",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_request_invalid")
    if (
        value["schema"] != COMMAND_REQUEST_SCHEMA
        or value["unit"] != context["unit"]
        or not isinstance(value["nonce"], str)
        or re.fullmatch(r"[0-9a-f]{32}", value["nonce"]) is None
        or not isinstance(value["maximum"], int)
        or isinstance(value["maximum"], bool)
        or not isinstance(value["timeout"], int)
        or isinstance(value["timeout"], bool)
        or not isinstance(value["executable_sha256"], str)
        or SHA256.fullmatch(value["executable_sha256"]) is None
        or not isinstance(value["environment"], dict)
        or not isinstance(value["vendor_uid"], int)
        or isinstance(value["vendor_uid"], bool)
        or not 1 <= value["vendor_uid"] <= 2 ** 31 - 1
        or not isinstance(value["vendor_gid"], int)
        or isinstance(value["vendor_gid"], bool)
        or not 1 <= value["vendor_gid"] <= 2 ** 31 - 1
    ):
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_request_invalid")
    command = _validate_command(value["command"])
    environment = value["environment"]
    validate_environment(environment)
    config = Path(environment["CLAUDE_CONFIG_DIR"])
    if (
        environment["HOME"] != "/var/empty"
        or config.parent.parent != CONFIG_ROOT
        or config.name != "claude-config"
        or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", config.parent.name) is None
    ):
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_environment_invalid")
    executable = Path(command[0])
    if _trusted_command_digest(executable) != value["executable_sha256"]:
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_executable_mismatch")
    status = status_command(executable)
    logout = logout_command(executable)
    entitlements = {
        tuple(entitlement_command(executable, effort=effort))
        for effort in ("low", "medium", "high")
    }
    if command == status:
        expected_bounds = (MAX_STATUS_BYTES, 15)
    elif command == logout:
        expected_bounds = (MAX_STATUS_BYTES, 30)
    elif tuple(command) in entitlements:
        expected_bounds = (MAX_ENTITLEMENT_BYTES, 120)
    else:
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_command_invalid")
    if (value["maximum"], value["timeout"]) != expected_bounds:
        raise NativeClaudeAdapterError(
            "native_claude_supervisor_bounds_invalid")
    return {**value, "command": command, "environment": dict(environment)}


def _controller_live(input_fd: int) -> None:
    selector = selectors.DefaultSelector()
    try:
        os.set_blocking(input_fd, False)
        selector.register(input_fd, selectors.EVENT_READ)
        if selector.select(0):
            try:
                block = os.read(input_fd, 1)
            except BlockingIOError:
                return
            if not block:
                raise NativeClaudeAdapterError(
                    "native_claude_controller_liveness_lost")
            raise NativeClaudeAdapterError(
                "native_claude_supervisor_protocol_invalid")
    finally:
        selector.close()


def _terminate_direct_process(process: Any) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
    else:
        process.wait(timeout=0)


def _execute_supervised_command(
    request: Mapping[str, Any], *, input_fd: int,
    popen: Callable[..., Any] = subprocess.Popen,
    selector_factory: Callable[[], Any] = selectors.DefaultSelector,
    monotonic: Callable[[], float] = time.monotonic,
) -> subprocess.CompletedProcess[bytes]:
    """Run the vendor only after cgroup custody and liveness are established."""
    _controller_live(input_fd)
    process: Any | None = None
    selector: Any | None = None
    output = bytearray()
    primary_error: BaseException | None = None
    result: subprocess.CompletedProcess[bytes] | None = None
    try:
        drop_command = [
            "/usr/bin/setpriv", f"--reuid={request['vendor_uid']}",
            f"--regid={request['vendor_gid']}", "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all",
            "--bounding-set=-all", "--no-new-privs", "--",
            *request["command"],
        ]
        process = popen(
            drop_command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(request["environment"]), close_fds=True)
        if process.stdout is None:
            raise NativeClaudeAdapterError(
                "native_claude_supervisor_transport_unavailable")
        selector = selector_factory()
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(input_fd, selectors.EVENT_READ, "controller")
        selector.register(process.stdout.fileno(), selectors.EVENT_READ, "vendor")
        deadline = monotonic() + request["timeout"]
        stdout_open = True
        while True:
            returncode = process.poll()
            if returncode is not None:
                if stdout_open:
                    while True:
                        try:
                            block = os.read(
                                process.stdout.fileno(),
                                min(65536, max(
                                    1, request["maximum"] + 1 - len(output))))
                        except BlockingIOError:
                            break
                        if not block:
                            stdout_open = False
                            break
                        output.extend(block)
                        if len(output) > request["maximum"]:
                            raise NativeClaudeAdapterError(
                                "native_claude_output_oversized")
                result = subprocess.CompletedProcess(
                    list(request["command"]), returncode, bytes(output), b"")
                break
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise NativeClaudeAdapterError(
                    "native_claude_process_timeout")
            events = selector.select(min(remaining, 0.1))
            # Liveness revocation always wins over simultaneous vendor output.
            for key, _mask in events:
                if key.data == "controller":
                    try:
                        block = os.read(input_fd, 1)
                    except BlockingIOError:
                        continue
                    if not block:
                        raise NativeClaudeAdapterError(
                            "native_claude_controller_liveness_lost")
                    raise NativeClaudeAdapterError(
                        "native_claude_supervisor_protocol_invalid")
            for key, _mask in events:
                if key.data != "vendor":
                    continue
                try:
                    block = os.read(
                        process.stdout.fileno(),
                        min(65536, max(
                            1, request["maximum"] + 1 - len(output))))
                except BlockingIOError:
                    continue
                if not block:
                    stdout_open = False
                    selector.unregister(process.stdout.fileno())
                    continue
                output.extend(block)
                if len(output) > request["maximum"]:
                    raise NativeClaudeAdapterError(
                        "native_claude_output_oversized")
    except BaseException as error:
        primary_error = error
    finally:
        if selector is not None:
            try:
                selector.close()
            except BaseException as error:
                if primary_error is None:
                    primary_error = error
        if process is not None:
            try:
                _terminate_direct_process(process)
            except BaseException as error:
                if primary_error is None:
                    primary_error = error
            if process.stdout is not None:
                try:
                    process.stdout.close()
                except BaseException as error:
                    if primary_error is None:
                        primary_error = error
    if primary_error is not None:
        raise primary_error
    if result is None:
        raise NativeClaudeAdapterError("native_claude_supervisor_failed")
    return result


def _write_fd(descriptor: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        count = os.write(descriptor, remaining)
        if count <= 0:
            raise NativeClaudeAdapterError(
                "native_claude_supervisor_transport_closed")
        remaining = remaining[count:]


def command_supervisor_main(
    *, input_fd: int = 0, output_fd: int = 1,
    _test_context: Mapping[str, Any] | None = None,
    _test_popen: Callable[..., Any] = subprocess.Popen,
    _test_selector_factory: Callable[[], Any] = selectors.DefaultSelector,
    _test_monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Hidden root systemd supervisor main; never a public controller action."""
    request: dict[str, Any] | None = None
    try:
        context = dict(_test_context) if _test_context is not None else (
            _supervisor_context())
        if set(context) != {"unit", "pid", "uid", "gid", "cgroup"}:
            raise NativeClaudeAdapterError(
                "native_claude_supervisor_context_invalid")
        _write_fd(output_fd, canonical_bytes({
            "schema": COMMAND_HANDSHAKE_SCHEMA, **context,
        }))
        request = _validate_supervisor_request(
            _read_supervisor_request(input_fd), context)
        result = _execute_supervised_command(
            request, input_fd=input_fd, popen=_test_popen,
            selector_factory=_test_selector_factory,
            monotonic=_test_monotonic)
        response = {
            "schema": COMMAND_RESPONSE_SCHEMA,
            "status": "completed",
            "nonce": request["nonce"],
            "returncode": result.returncode,
            "stdout_b64": base64.b64encode(result.stdout).decode("ascii"),
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "error": None,
        }
        _write_fd(output_fd, canonical_bytes(response))
        return 0
    except BaseException:
        if request is not None:
            try:
                _write_fd(output_fd, canonical_bytes({
                    "schema": COMMAND_RESPONSE_SCHEMA,
                    "status": "rejected",
                    "nonce": request["nonce"],
                    "returncode": None,
                    "stdout_b64": "",
                    "stdout_sha256": None,
                    "error": "native_claude_command_rejected",
                }))
            except BaseException:
                pass
        return 1


def observe_status(
    executable: Path,
    environment: Mapping[str, str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    now: int | None = None,
    binding_key: bytes | None = None,
    command_prefix: Sequence[str] = (),
) -> dict[str, Any]:
    if not isinstance(binding_key, bytes) or len(binding_key) != 32:
        raise NativeClaudeAdapterError("native_claude_binding_key_invalid")
    result = _run_bounded(
        status_command(executable), environment,
        maximum=MAX_STATUS_BYTES, timeout=15, command_prefix=command_prefix,
        runner=runner,
    )
    state = "ambiguous"
    provider = "unknown"
    account_subject_sha256: str | None = None
    workspace_sha256: str | None = None
    subscription_class_sha256: str | None = None
    # Claude 2.1.318 returns 1 for the exact signed-out JSON record and 0 for
    # signed-in. No other nonzero status is interpreted.
    if result.returncode in {0, 1}:
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = None
        base = {
            "loggedIn", "authMethod", "apiProvider", "analyticsDisabled",
            "projectsDirectory", "configDirectory", "loginExpiresAt",
        }
        signed_in = {"email", "orgId", "orgName", "subscriptionType"}
        optional = {
            "forcedLoginMethod", "gatewaySignInOffered", "allowedProviders",
            "apiKeySource",
        }
        if (
            isinstance(value, dict)
            and base.issubset(value)
            and set(value).issubset(base | signed_in | optional)
        ):
            expected_config = environment["CLAUDE_CONFIG_DIR"]
            expected_projects = str(Path(expected_config) / "projects")
            expires = value["loginExpiresAt"]
            common = (
                value["configDirectory"] == expected_config
                and value["projectsDirectory"] == expected_projects
                and value["apiProvider"] == "firstParty"
                and value["analyticsDisabled"] is True
                and (expires is None or (
                    isinstance(expires, int) and not isinstance(expires, bool) and expires > 0
                ))
            )
            if (
                common
                and value["loggedIn"] is False
                and value["authMethod"] == "none"
                and not signed_in.intersection(value)
                and result.returncode in {0, 1}
            ):
                state, provider = "signed-out", "none"
            elif (
                common
                and value["loggedIn"] is True
                and value["authMethod"] == "claude.ai"
                and result.returncode == 0
                and signed_in.issubset(value)
                and all(
                    isinstance(value[field], str)
                    and 1 <= len(value[field].encode("utf-8")) <= 512
                    and all(ord(character) >= 32 for character in value[field])
                    for field in signed_in
                )
            ):
                email = value["email"].strip().casefold().encode("utf-8")
                organization = value["orgId"].strip().encode("utf-8")
                subscription = value["subscriptionType"].strip().casefold().encode("utf-8")
                if email and organization and subscription:
                    account_subject_sha256 = hmac.new(
                        binding_key, b"anthropic-account-v1\x00" + email, hashlib.sha256
                    ).hexdigest()
                    workspace_sha256 = hmac.new(
                        binding_key,
                        b"anthropic-workspace-v1\x00" + organization,
                        hashlib.sha256,
                    ).hexdigest()
                    subscription_class_sha256 = hmac.new(
                        binding_key,
                        b"anthropic-subscription-v1\x00" + subscription,
                        hashlib.sha256,
                    ).hexdigest()
                    state, provider = "signed-in", "first-party-subscription"
    reduced = {
        "state": state,
        "provider_class": provider,
        "account_subject_sha256": account_subject_sha256,
        "workspace_sha256": workspace_sha256,
        "subscription_class_sha256": subscription_class_sha256,
        "observed_at": int(time.time()) if now is None else now,
    }
    body = {**reduced, "evidence_sha256": hmac.new(
        binding_key,
        b"anthropic-status-evidence-v1\x00" + canonical_bytes(reduced),
        hashlib.sha256,
    ).hexdigest()}
    return {"schema": STATUS_SCHEMA, **body, "status_sha256": sha256(body)}


def observe_entitlement_result(
    raw: bytes, *, binding_key: bytes, now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(binding_key, bytes) or len(binding_key) != 32:
        raise NativeClaudeAdapterError("native_claude_binding_key_invalid")
    if len(raw) > MAX_ENTITLEMENT_BYTES:
        raise NativeClaudeAdapterError("native_claude_entitlement_output_oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeClaudeAdapterError("native_claude_entitlement_output_invalid") from error
    if not isinstance(value, dict):
        raise NativeClaudeAdapterError("native_claude_entitlement_output_invalid")
    model_usage = value.get("modelUsage")
    success = (
        value.get("subtype") == "success"
        and value.get("is_error") is False
        and value.get("result") == "SECURE_SANDBOX_ENTITLEMENT_READY"
        and isinstance(model_usage, dict)
        and set(model_usage) == {CLAUDE_MODEL_ID}
    )
    reduced = {
        "state": "verified" if success else "denied",
        # A successful model invocation proves only model availability. Claude
        # Code 2.1.318 exposes no independently attestable CVP enrollment/tier
        # field, so program authority remains an external operator gate.
        "program_state": "unknown",
        "model_id": CLAUDE_MODEL_ID,
        "observed_at": int(time.time()) if now is None else now,
    }
    body = {**reduced, "evidence_sha256": hmac.new(
        binding_key,
        b"anthropic-entitlement-evidence-v1\x00" + canonical_bytes(reduced),
        hashlib.sha256,
    ).hexdigest()}
    return {"schema": ENTITLEMENT_SCHEMA, **body, "receipt_sha256": sha256(body)}


def verify_entitlement(
    executable: Path,
    environment: Mapping[str, str],
    *,
    effort: str,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    now: int | None = None,
    binding_key: bytes,
    command_prefix: Sequence[str] = (),
) -> dict[str, Any]:
    result = _run_bounded(
        entitlement_command(executable, effort=effort),
        environment,
        maximum=MAX_ENTITLEMENT_BYTES,
        timeout=120,
        command_prefix=command_prefix,
        runner=runner,
    )
    if result.returncode != 0:
        raise NativeClaudeAdapterError("native_claude_entitlement_request_failed")
    return observe_entitlement_result(
        result.stdout, binding_key=binding_key, now=now)


def main() -> int:
    # Protected deployment invokes the library through a separate root-owned
    # manager. A broad argv interface here would create an alternate login or
    # logout path, so the standalone program is intentionally non-operational.
    print(json.dumps({"error": "native_claude_manager_required", "schema": STATUS_SCHEMA},
                     separators=(",", ":"), sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
