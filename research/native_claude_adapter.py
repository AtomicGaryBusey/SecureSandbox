#!/usr/bin/env python3
"""Exact Claude Code subscription-OAuth adapter for one admitted native stack.

This adapter never reads or copies Claude's credential file.  It supplies a
dedicated configuration directory to the unmodified admitted executable and
observes only Claude Code's bounded, content-free authentication status.  The
provider connection remains TLS end-to-end through the separate opaque proxy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from shared.native_stack_runtime_binding import (
    NativeStackBindingError,
    validate_binding as validate_native_binding,
)
from shared.runtime_authority import RuntimeAuthorityError, validate_binding as validate_authority


STATUS_SCHEMA = "secure-sandbox-claude-native-status-v1"
ENTITLEMENT_SCHEMA = "secure-sandbox-claude-native-entitlement-v1"
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
    harness = authority["harness_binding"]
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


def config_directory(native_binding: Mapping[str, Any], *, root: Path = CONFIG_ROOT) -> Path:
    stack_id = native_binding.get("stack_id")
    if not isinstance(stack_id, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", stack_id) is None:
        raise NativeClaudeAdapterError("native_claude_stack_id_invalid")
    return root / stack_id / "claude-config"


def child_environment(
    authority_value: object,
    *,
    home: Path,
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
    return {
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


def validate_environment(environment: Mapping[str, str]) -> None:
    if FORBIDDEN_ENVIRONMENT.intersection(environment):
        raise NativeClaudeAdapterError("native_claude_forbidden_environment")
    if environment.get("HTTPS_PROXY") != PROXY or environment.get("HTTP_PROXY") != PROXY:
        raise NativeClaudeAdapterError("native_claude_proxy_invalid")
    if environment.get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB") != "1":
        raise NativeClaudeAdapterError("native_claude_environment_scrub_missing")
    if environment.get("DISABLE_UPDATES") != "1":
        raise NativeClaudeAdapterError("native_claude_updates_not_disabled")


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


def _run_bounded(
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    maximum: int,
    timeout: int,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> subprocess.CompletedProcess[bytes]:
    validate_environment(environment)
    result = runner(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=dict(environment),
        check=False,
        timeout=timeout,
    )
    if len(result.stdout) > maximum:
        raise NativeClaudeAdapterError("native_claude_output_oversized")
    return result


def observe_status(
    executable: Path,
    environment: Mapping[str, str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    now: int | None = None,
) -> dict[str, Any]:
    result = _run_bounded(
        status_command(executable), environment,
        maximum=MAX_STATUS_BYTES, timeout=15, runner=runner,
    )
    state = "ambiguous"
    provider = "unknown"
    if result.returncode == 0:
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = None
        if isinstance(value, dict) and set(value) == {
            "apiProvider", "authMethod", "configDirectory", "projectsDirectory"
        }:
            expected_config = environment["CLAUDE_CONFIG_DIR"]
            if value["configDirectory"] == expected_config:
                if value["apiProvider"] == "firstParty" and value["authMethod"] == "oauth":
                    state, provider = "signed-in", "first-party-subscription"
                elif value["authMethod"] == "none":
                    state, provider = "signed-out", "none"
    body = {
        "state": state,
        "provider_class": provider,
        "observed_at": int(time.time()) if now is None else now,
        "evidence_sha256": hashlib.sha256(result.stdout).hexdigest(),
    }
    return {"schema": STATUS_SCHEMA, **body, "status_sha256": sha256(body)}


def observe_entitlement_result(raw: bytes, *, now: int | None = None) -> dict[str, Any]:
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
    body = {
        "state": "verified" if success else "denied",
        "model_id": CLAUDE_MODEL_ID,
        "program_id": "anthropic-cvp",
        "program_tier": "defense",
        "observed_at": int(time.time()) if now is None else now,
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return {"schema": ENTITLEMENT_SCHEMA, **body, "receipt_sha256": sha256(body)}


def verify_entitlement(
    executable: Path,
    environment: Mapping[str, str],
    *,
    effort: str,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    now: int | None = None,
) -> dict[str, Any]:
    result = _run_bounded(
        entitlement_command(executable, effort=effort),
        environment,
        maximum=MAX_ENTITLEMENT_BYTES,
        timeout=120,
        runner=runner,
    )
    if result.returncode != 0:
        raise NativeClaudeAdapterError("native_claude_entitlement_request_failed")
    return observe_entitlement_result(result.stdout, now=now)


def main() -> int:
    # Protected deployment invokes the library through a separate root-owned
    # manager. A broad argv interface here would create an alternate login or
    # logout path, so the standalone program is intentionally non-operational.
    print(json.dumps({"error": "native_claude_manager_required", "schema": STATUS_SCHEMA},
                     separators=(",", ":"), sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
