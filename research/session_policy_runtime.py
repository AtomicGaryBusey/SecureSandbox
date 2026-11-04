#!/usr/bin/env python3
"""Measure the Research session policy without exposing source or prompt content."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


SCHEMA = "secure-sandbox-session-policy-runtime-v1"
PERSONA = Path("/etc/claude-code/secure-sandbox-persona.md")
MANAGED_SETTINGS = Path("/etc/claude-code/managed-settings.json")
MANAGED_MCP = Path("/etc/claude-code/managed-mcp.json")
MAX_POLICY_BYTES = 1024 * 1024
TRUSTED_UID = 0
EMPTY_EXTENSION_PATHS = (
    Path("/home/agent/.claude/plugins"),
    Path("/home/agent/.claude/commands"),
    Path("/home/agent/.claude/skills"),
    Path("/home/agent/.claude/agents"),
)
REQUIRED_EXTENSION_FENCES = {
    "allowManagedHooksOnly": True,
    "allowManagedMcpServersOnly": True,
    "disableAllHooks": True,
    "disableClaudeAiConnectors": True,
    "disableCommandPluginSources": True,
    "disableSideloadFlags": True,
    "disableSkillShellExecution": True,
    "enableAllProjectMcpServers": False,
    "strictKnownMarketplaces": [],
    "strictPluginOnlyCustomization": True,
}


class SessionPolicyRuntimeError(RuntimeError):
    """Stable fail-closed Research policy measurement failure."""


def canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise SessionPolicyRuntimeError("session_policy_not_canonicalizable") from error


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_control_file(path: Path, expected_mode: int) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != TRUSTED_UID
        or stat.S_IMODE(before.st_mode) != expected_mode
        or before.st_nlink != 1
        or not 0 < before.st_size <= MAX_POLICY_BYTES
    ):
        raise SessionPolicyRuntimeError(f"session_policy_{path.name}_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SessionPolicyRuntimeError("session_policy_open_race")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_POLICY_BYTES:
                raise SessionPolicyRuntimeError("session_policy_file_oversized")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise SessionPolicyRuntimeError("session_policy_file_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SessionPolicyRuntimeError(f"session_policy_{label}_invalid") from error
    if not isinstance(value, dict):
        raise SessionPolicyRuntimeError(f"session_policy_{label}_invalid")
    return value


def validate_extension_fences(settings: dict[str, Any]) -> None:
    if any(settings.get(name) != expected for name, expected in REQUIRED_EXTENSION_FENCES.items()):
        raise SessionPolicyRuntimeError("session_policy_extension_fence_invalid")
    for path in EMPTY_EXTENSION_PATHS:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SessionPolicyRuntimeError("session_policy_extension_path_untrusted")
        if any(path.iterdir()):
            raise SessionPolicyRuntimeError("session_policy_extension_set_not_empty")


def source_identity(source_id: str) -> tuple[str | None, str | None]:
    if source_id == "none":
        return None, None
    try:
        from source_integrity import registered_source, verify_source

        verification = verify_source(source_id, scope="worktree")
        record = registered_source(source_id)
    except Exception as error:
        raise SessionPolicyRuntimeError("session_policy_source_unverified") from error
    tree_digest = record.get("tree_manifest_sha256")
    if (
        verification.get("overall_status") != "match"
        or verification.get("registered_tree_manifest_sha256") != tree_digest
        or not isinstance(tree_digest, str)
        or len(tree_digest) != 64
        or any(character not in "0123456789abcdef" for character in tree_digest)
    ):
        raise SessionPolicyRuntimeError("session_policy_source_unverified")
    return source_id, tree_digest


def measure(source_id: str) -> dict[str, Any]:
    persona = read_control_file(PERSONA, 0o444)
    settings_raw = read_control_file(MANAGED_SETTINGS, 0o644)
    mcp_raw = read_control_file(MANAGED_MCP, 0o644)
    settings = parse_object(settings_raw, "managed_settings")
    mcp = parse_object(mcp_raw, "managed_mcp")
    if not isinstance(mcp.get("mcpServers"), dict):
        raise SessionPolicyRuntimeError("session_policy_managed_mcp_invalid")
    validate_extension_fences(settings)
    resolved_source, source_manifest = source_identity(source_id)
    tool_catalog = {
        "managed_mcp_sha256": hashlib.sha256(mcp_raw).hexdigest(),
        "managed_settings_sha256": hashlib.sha256(settings_raw).hexdigest(),
    }
    return {
        "schema": SCHEMA,
        "source_id": resolved_source,
        "source_manifest_sha256": source_manifest,
        "persona_sha256": hashlib.sha256(persona).hexdigest(),
        "tool_catalog_sha256": digest(tool_catalog),
        "extension_set_sha256": digest({"extensions": []}),
    }


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        raise SessionPolicyRuntimeError("session_policy_source_argument_invalid")
    print(json.dumps(measure(arguments[0]), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, SessionPolicyRuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
