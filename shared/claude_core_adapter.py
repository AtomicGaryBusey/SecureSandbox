#!/usr/bin/env python3
"""First-party Claude core adapter projection for disposable qualification."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any


ADAPTER_SCHEMA = "secure-sandbox-claude-core-adapter-v1"
ADAPTER_ID = "claude-core-v1"
MAX_EVENT_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
FIXED_ARGUMENTS = (
    "--append-system-prompt-file",
    "/etc/claude-code/secure-sandbox-persona.md",
    "--no-chrome",
    "--restricted",
    "--permission-mode",
    "manual",
)
REQUIRED_ENVIRONMENT = {
    "CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "CLAUDE_CODE_MCP_ALLOWLIST_ENV": "1",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "DISABLE_LOGIN_COMMAND": "1",
    "DISABLE_LOGOUT_COMMAND": "1",
    "DISABLE_UPDATES": "1",
    "DISABLE_UPGRADE_COMMAND": "1",
}
FORBIDDEN_ARGUMENTS = frozenset({
    "--dangerously-skip-permissions", "--plugin-dir", "--mcp-config",
    "--allowedTools", "--disallowedTools", "--settings", "--add-dir",
})
FORBIDDEN_ENVIRONMENT = frozenset({
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN",
    "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
    "NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
})
ALLOWED_ENVIRONMENT = frozenset(REQUIRED_ENVIRONMENT) | {
    "HOME", "USER", "LOGNAME", "SHELL", "PATH", "LANG", "TERM",
}
AMBIENT_PROJECT_PATHS = (
    ".claude", ".mcp.json", "CLAUDE.md", ".agents", ".codex", ".gemini",
    ".grok", ".kimi-code",
)


class ClaudeAdapterError(RuntimeError):
    """Stable adapter failure without vendor content."""


def _uuid(value: object) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError) as error:
        raise ClaudeAdapterError("session_id_invalid") from error
    if str(parsed) != str(value).lower():
        raise ClaudeAdapterError("session_id_invalid")
    return str(parsed)


def launch_vector(executable: str, session_id: str, mode: str) -> list[str]:
    if executable != "/usr/local/bin/claude":
        raise ClaudeAdapterError("executable_not_fixed")
    session = _uuid(session_id)
    if mode not in {"new", "resume"}:
        raise ClaudeAdapterError("launch_mode_invalid")
    selector = "--session-id" if mode == "new" else "--resume"
    return [executable, *FIXED_ARGUMENTS, selector, session]


def validate_launch_vector(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ClaudeAdapterError("launch_vector_invalid")
    if len(value) != 1 + len(FIXED_ARGUMENTS) + 2:
        raise ClaudeAdapterError("launch_vector_invalid")
    if value[0] != "/usr/local/bin/claude" or tuple(value[1:1 + len(FIXED_ARGUMENTS)]) != FIXED_ARGUMENTS:
        raise ClaudeAdapterError("launch_vector_invalid")
    if value[-2] not in {"--session-id", "--resume"}:
        raise ClaudeAdapterError("launch_vector_invalid")
    _uuid(value[-1])
    if any(argument in FORBIDDEN_ARGUMENTS for argument in value):
        raise ClaudeAdapterError("launch_vector_forbidden")
    return value


def validate_environment(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise ClaudeAdapterError("environment_invalid")
    if FORBIDDEN_ENVIRONMENT.intersection(value):
        raise ClaudeAdapterError("credential_or_loader_environment_forbidden")
    if set(value) - ALLOWED_ENVIRONMENT:
        raise ClaudeAdapterError("environment_key_not_allowed")
    for name, expected in REQUIRED_ENVIRONMENT.items():
        if value.get(name) != expected:
            raise ClaudeAdapterError("required_environment_missing")
    return value


def projection(adapter_sha256: str, tool_catalog_sha256: str,
               managed_settings_sha256: str, managed_mcp_sha256: str) -> dict[str, Any]:
    for value in (adapter_sha256, tool_catalog_sha256, managed_settings_sha256, managed_mcp_sha256):
        if SHA256_RE.fullmatch(value) is None:
            raise ClaudeAdapterError("projection_digest_invalid")
    result = {
        "schema": ADAPTER_SCHEMA,
        "adapter_id": ADAPTER_ID,
        "adapter_sha256": adapter_sha256,
        "executable": "/usr/local/bin/claude",
        "fixed_arguments": list(FIXED_ARGUMENTS),
        "required_environment": dict(sorted(REQUIRED_ENVIRONMENT.items())),
        "forbidden_arguments": sorted(FORBIDDEN_ARGUMENTS),
        "forbidden_environment": sorted(FORBIDDEN_ENVIRONMENT),
        "allowed_environment": sorted(ALLOWED_ENVIRONMENT),
        "ambient_project_paths": list(AMBIENT_PROJECT_PATHS),
        "tool_catalog_sha256": tool_catalog_sha256,
        "managed_settings_sha256": managed_settings_sha256,
        "managed_mcp_sha256": managed_mcp_sha256,
        "semantic_loss": [],
        "authority": "none",
    }
    result["projection_sha256"] = hashlib.sha256(
        (json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        .encode("ascii")
    ).hexdigest()
    return result


def translate_stream_event(value: object, expected_session_id: str) -> dict[str, Any]:
    """Translate a deliberately small, fail-closed Claude stream projection."""
    session = _uuid(expected_session_id)
    try:
        size = len((json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii"))
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ClaudeAdapterError("event_invalid") from error
    if size > MAX_EVENT_BYTES or not isinstance(value, dict):
        raise ClaudeAdapterError("event_invalid")
    if value.get("session_id") != session:
        raise ClaudeAdapterError("event_session_mismatch")
    event_type = value.get("type")
    subtype = value.get("subtype")
    mapping = {
        ("system", "init"): "session_started",
        ("system", "compact_boundary"): "compaction_completed",
        ("assistant", None): "assistant_output",
        ("user", None): "prompt_accepted",
        ("result", "success"): "run_completed",
        ("result", "error"): "run_failed",
    }
    neutral = mapping.get((event_type, subtype))
    if neutral is None:
        raise ClaudeAdapterError("event_unknown")
    return {
        "event": neutral,
        "session_id": session,
        "vendor_type": str(event_type),
        "vendor_subtype": subtype,
    }
