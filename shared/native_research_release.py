#!/usr/bin/env python3
"""Name-bound release identity for the complete Research native runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "secure-sandbox-native-research-release-v1"
MANIFEST = Path("/etc/secure-sandbox/native-research-release.json")
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
ROOT = "/usr/local/libexec/secure-sandbox"
RESEARCH = ROOT + "/research"
SHARED = ROOT + "/shared"

# Exact names prevent a manifest from silently omitting a control or config.
EXPECTED_ARTIFACTS: Mapping[str, int] = {
    f"{ROOT}/privileged_control.py": 0o755,
    f"{ROOT}/native_guest_control.py": 0o755,
    f"{ROOT}/render_research_firewall.py": 0o755,
    f"{ROOT}/native_provider_controller.py": 0o755,
    f"{ROOT}/native_claude_login_channel.py": 0o755,
    f"{ROOT}/native_claude_session_controller.py": 0o755,
    f"{ROOT}/native_codex_session_controller.py": 0o755,
    f"{ROOT}/native_harness_supervisor.py": 0o755,
    f"{ROOT}/native_codex_protocol_firewall.py": 0o555,
    f"{ROOT}/native_codex_isolation_qualification.py": 0o555,
    f"{ROOT}/native-codex-isolation-probe": 0o555,
    f"{ROOT}/native-codex-launcher": 0o555,
    f"{RESEARCH}/native_claude_adapter.py": 0o444,
    f"{RESEARCH}/native_claude_login_channel.py": 0o444,
    f"{RESEARCH}/native_claude_login_replay.py": 0o444,
    f"{RESEARCH}/native_claude_session_controller.py": 0o444,
    f"{RESEARCH}/native_codex_isolation_qualification.py": 0o444,
    f"{RESEARCH}/native_codex_policy.py": 0o444,
    f"{RESEARCH}/native_codex_protocol_firewall.py": 0o444,
    f"{RESEARCH}/native_codex_run_journal.py": 0o444,
    f"{RESEARCH}/native_codex_session_controller.py": 0o444,
    f"{RESEARCH}/native_harness_supervisor.py": 0o444,
    f"{RESEARCH}/native_lifecycle_fence.py": 0o444,
    f"{RESEARCH}/native_projection_isolation.py": 0o444,
    f"{RESEARCH}/native_provider_controller.py": 0o444,
    f"{RESEARCH}/session_policy_runtime.py": 0o444,
    f"{SHARED}/__init__.py": 0o444,
    f"{SHARED}/harness_generation_store.py": 0o444,
    f"{SHARED}/harness_runtime_binding.py": 0o444,
    f"{SHARED}/model_stack_runtime_binding.py": 0o444,
    f"{SHARED}/native_egress.py": 0o444,
    f"{SHARED}/native_guest_control.py": 0o444,
    f"{SHARED}/native_research_release.py": 0o444,
    f"{SHARED}/native_stack_operations.py": 0o444,
    f"{SHARED}/native_stack_runtime_binding.py": 0o444,
    f"{SHARED}/native_vendor_stack.py": 0o444,
    f"{SHARED}/privileged_workflow.py": 0o444,
    f"{SHARED}/runtime_authority.py": 0o444,
    f"{SHARED}/session_context_binding.py": 0o444,
    "/etc/secure-sandbox/native-codex-policy/config.toml": 0o444,
    "/etc/secure-sandbox/native-egress-installed": 0o600,
    "/etc/secure-sandbox/native-egress-role": 0o600,
    "/etc/claude-code/native-claude-session-settings.json": 0o444,
    "/etc/claude-code/secure-sandbox-persona.md": 0o444,
    "/etc/claude-code/managed-settings.json": 0o644,
    "/etc/claude-code/managed-mcp.json": 0o644,
    "/etc/systemd/system/native-harness-supervisor.service": 0o644,
    "/etc/tmpfiles.d/secure-sandbox-native.conf": 0o644,
}


class NativeResearchReleaseError(RuntimeError):
    """Stable fail-closed native release error."""


def canonical(value: object) -> bytes:
    try:
        raw = (json.dumps(value, allow_nan=False, ensure_ascii=True,
                          separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeResearchReleaseError(
            "native_research_release_value_invalid") from error
    if len(raw) > MAX_MANIFEST_BYTES:
        raise NativeResearchReleaseError(
            "native_research_release_manifest_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _artifact(path: Path, mode: int, *, trusted_uid: int,
              trusted_gid: int) -> dict[str, Any]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeResearchReleaseError(
            "native_research_release_artifact_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        content = hashlib.sha256()
        total = 0
        while total <= MAX_ARTIFACT_BYTES:
            block = os.read(
                descriptor, min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            content.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_nlink != 1 or opened.st_uid != trusted_uid
            or opened.st_gid != trusted_gid
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_size < 1 or total != opened.st_size
            or total > MAX_ARTIFACT_BYTES
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)):
        raise NativeResearchReleaseError(
            "native_research_release_artifact_untrusted")
    return {"path": str(path), "mode": mode, "sha256": content.hexdigest()}


def observe(*, trusted_uid: int = 0, trusted_gid: int = 0) -> dict[str, Any]:
    artifacts = [
        _artifact(Path(name), mode, trusted_uid=trusted_uid,
                  trusted_gid=trusted_gid)
        for name, mode in sorted(EXPECTED_ARTIFACTS.items())
    ]
    body = {"schema": SCHEMA, "artifacts": artifacts}
    return {**body, "release_id": digest(body)}


def validate(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != {"schema", "artifacts", "release_id"}
            or value.get("schema") != SCHEMA
            or not isinstance(value.get("artifacts"), list)
            or len(value["artifacts"]) != len(EXPECTED_ARTIFACTS)):
        raise NativeResearchReleaseError(
            "native_research_release_manifest_invalid")
    expected_names = sorted(EXPECTED_ARTIFACTS)
    observed_names: list[str] = []
    for item in value["artifacts"]:
        if (not isinstance(item, dict)
                or set(item) != {"path", "mode", "sha256"}
                or item.get("path") not in EXPECTED_ARTIFACTS
                or item.get("mode") != EXPECTED_ARTIFACTS[item["path"]]
                or not isinstance(item.get("sha256"), str)
                or SHA256.fullmatch(item["sha256"]) is None):
            raise NativeResearchReleaseError(
                "native_research_release_manifest_invalid")
        observed_names.append(item["path"])
    body = {"schema": SCHEMA, "artifacts": value["artifacts"]}
    if (observed_names != expected_names
            or not isinstance(value.get("release_id"), str)
            or value["release_id"] != digest(body)):
        raise NativeResearchReleaseError(
            "native_research_release_manifest_invalid")
    return value


def verify_installed(
    *, manifest: Path = MANIFEST, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    try:
        before = manifest.lstat()
        descriptor = os.open(
            manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            raw = bytearray()
            while len(raw) <= MAX_MANIFEST_BYTES:
                block = os.read(
                    descriptor,
                    min(65536, MAX_MANIFEST_BYTES + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeResearchReleaseError(
            "native_research_release_manifest_unavailable") from error
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
            or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o444
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or len(raw) != opened.st_size or len(raw) > MAX_MANIFEST_BYTES
            or bytes(raw) != canonical(value)):
        raise NativeResearchReleaseError(
            "native_research_release_manifest_untrusted")
    admitted = validate(value)
    observed = observe(trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if observed != admitted:
        raise NativeResearchReleaseError(
            "native_research_release_readback_mismatch")
    return observed
