#!/usr/bin/env python3
"""Deterministic, exact source payloads for protected native deployment."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import zipfile
from pathlib import Path
from typing import Mapping

from shared import native_deployment


class NativeDeploymentPayloadError(RuntimeError):
    """Stable fail-closed payload error."""


# archive name, repository-relative source, transport mode
GATEWAY_SOURCES = (
    ("install-native-egress-gateway.sh", "scripts/install-native-egress-gateway.sh", 0o700),
    ("native_guest_control.py", "shared/native_guest_control.py", 0o600),
    ("native_egress.py", "shared/native_egress.py", 0o600),
    ("shared_init.py", "shared/__init__.py", 0o600),
    ("render_gateway_firewall.py", "gateway/render_gateway_firewall.py", 0o600),
    ("native_opaque_tunnel.py", "gateway/native_opaque_tunnel.py", 0o600),
    ("native-opaque-tunnel.service", "gateway/native-opaque-tunnel.service", 0o600),
    ("update-policy-hash.sh", "scripts/update-policy-hash.sh", 0o700),
    ("native_vendor_stack.py", "shared/native_vendor_stack.py", 0o600),
    ("native_stack_runtime_binding.py", "shared/native_stack_runtime_binding.py", 0o600),
    ("model_stack_runtime_binding.py", "shared/model_stack_runtime_binding.py", 0o600),
    ("runtime_authority.py", "shared/runtime_authority.py", 0o600),
    ("harness_runtime_binding.py", "shared/harness_runtime_binding.py", 0o600),
    ("session_context_binding.py", "shared/session_context_binding.py", 0o600),
    ("native_install_transaction.py", "shared/native_install_transaction.py", 0o600),
    ("native-egress-watchdog.service", "research/native-egress-watchdog.service", 0o600),
    ("nftables-native-watchdog.conf", "research/nftables-native-watchdog.conf", 0o600),
    ("privileged_control.py", "scripts/privileged_control.py", 0o600),
    ("native_gateway_release.py", "shared/native_gateway_release.py", 0o600),
    ("native_deployment.py", "shared/native_deployment.py", 0o600),
    ("install-native-deployment-probe.sh", "scripts/install-native-deployment-probe.sh", 0o700),
    ("native_deployment_probe.py", "scripts/native_deployment_probe.py", 0o600),
    ("install-native-gateway-compensation.sh", "scripts/install-native-gateway-compensation.sh", 0o700),
    ("native_gateway_compensation.py", "scripts/native_gateway_compensation.py", 0o600),
)


RESEARCH_SOURCES = (
    ("install-native-research-runtime.sh", "scripts/install-native-research-runtime.sh", 0o700),
    ("native_research_installer.py", "scripts/native_research_installer.py", 0o600),
    ("install-native-deployment-probe.sh", "scripts/install-native-deployment-probe.sh", 0o700),
    ("native_deployment_probe.py", "scripts/native_deployment_probe.py", 0o600),
    ("native_install_transaction.py", "shared/native_install_transaction.py", 0o600),
    ("native_runtime_entry.py", "research/native_runtime_entry.py", 0o600),
    ("native_codex_launcher.c", "research/native_codex_launcher.c", 0o600),
    ("native-codex-config.toml", "research/native-codex-config.toml", 0o600),
    ("native-claude-session-settings.json", "research/native-claude-session-settings.json", 0o600),
    ("native-harness-supervisor.service", "research/native-harness-supervisor.service", 0o600),
    ("native-egress-watchdog.service", "research/native-egress-watchdog.service", 0o600),
    ("nftables-native-watchdog.conf", "research/nftables-native-watchdog.conf", 0o600),
    ("secure-sandbox-native.conf", "research/secure-sandbox-native.conf", 0o600),
    ("privileged_control.py", "scripts/privileged_control.py", 0o600),
    ("native_guest_control.py", "shared/native_guest_control.py", 0o600),
    ("render_research_firewall.py", "research/render_research_firewall.py", 0o600),
    ("native_claude_adapter.py", "research/native_claude_adapter.py", 0o600),
    ("native_claude_login_channel.py", "research/native_claude_login_channel.py", 0o600),
    ("native_claude_login_replay.py", "research/native_claude_login_replay.py", 0o600),
    ("native_claude_session_controller.py", "research/native_claude_session_controller.py", 0o600),
    ("native_codex_isolation_qualification.py", "research/native_codex_isolation_qualification.py", 0o600),
    ("native_codex_policy.py", "research/native_codex_policy.py", 0o600),
    ("native_codex_protocol_firewall.py", "research/native_codex_protocol_firewall.py", 0o600),
    ("native_codex_run_journal.py", "research/native_codex_run_journal.py", 0o600),
    ("native_codex_runtime_driver.py", "research/native_codex_runtime_driver.py", 0o600),
    ("native_codex_session_controller.py", "research/native_codex_session_controller.py", 0o600),
    ("native_harness_supervisor.py", "research/native_harness_supervisor.py", 0o600),
    ("native_lifecycle_fence.py", "research/native_lifecycle_fence.py", 0o600),
    ("native_projection_isolation.py", "research/native_projection_isolation.py", 0o600),
    ("native_provider_controller.py", "research/native_provider_controller.py", 0o600),
    ("session_policy_runtime.py", "research/session_policy_runtime.py", 0o600),
    ("shared_init.py", "shared/__init__.py", 0o600),
    ("harness_generation_store.py", "shared/harness_generation_store.py", 0o600),
    ("harness_runtime_binding.py", "shared/harness_runtime_binding.py", 0o600),
    ("model_stack_runtime_binding.py", "shared/model_stack_runtime_binding.py", 0o600),
    ("native_codex_projection.py", "shared/native_codex_projection.py", 0o600),
    ("native_deployment.py", "shared/native_deployment.py", 0o600),
    ("native_deployment_lifecycle.py", "shared/native_deployment_lifecycle.py", 0o600),
    ("native_egress.py", "shared/native_egress.py", 0o600),
    ("native_research_release.py", "shared/native_research_release.py", 0o600),
    ("native_stack_operations.py", "shared/native_stack_operations.py", 0o600),
    ("native_stack_runtime_binding.py", "shared/native_stack_runtime_binding.py", 0o600),
    ("native_stack_session.py", "shared/native_stack_session.py", 0o600),
    ("native_vendor_stack.py", "shared/native_vendor_stack.py", 0o600),
    ("privileged_workflow.py", "shared/privileged_workflow.py", 0o600),
    ("runtime_authority.py", "shared/runtime_authority.py", 0o600),
    ("session_context_binding.py", "shared/session_context_binding.py", 0o600),
)

RESEARCH_FENCE_COMMON_SOURCES = (
    ("native_deployment_fence_bootstrap.py", "scripts/native_deployment_fence_bootstrap.py", 0o600),
    ("native_deployment.py", "shared/native_deployment.py", 0o600),
    ("native_deployment_lifecycle.py", "shared/native_deployment_lifecycle.py", 0o600),
    ("native_lifecycle_fence.py", "research/native_lifecycle_fence.py", 0o600),
    ("native_research_release.py", "shared/native_research_release.py", 0o600),
    ("native_guest_control.py", "shared/native_guest_control.py", 0o600),
    ("native_vendor_stack.py", "shared/native_vendor_stack.py", 0o600),
    ("harness_runtime_binding.py", "shared/harness_runtime_binding.py", 0o600),
    ("session_context_binding.py", "shared/session_context_binding.py", 0o600),
    ("native_stack_runtime_binding.py",
     "shared/native_stack_runtime_binding.py", 0o600),
    ("model_stack_runtime_binding.py",
     "shared/model_stack_runtime_binding.py", 0o600),
    ("runtime_authority.py", "shared/runtime_authority.py", 0o600),
    ("native_egress.py", "shared/native_egress.py", 0o600),
)

RESEARCH_FENCE_ACQUIRE_SOURCES = (
    ("install-native-deployment-fence-bootstrap.sh",
     "scripts/install-native-deployment-fence-bootstrap.sh", 0o700),
    *RESEARCH_FENCE_COMMON_SOURCES,
)

RESEARCH_FENCE_RELEASE_SOURCES = (
    ("install-native-deployment-fence-bootstrap-release.sh",
     "scripts/install-native-deployment-fence-bootstrap-release.sh", 0o700),
    *RESEARCH_FENCE_COMMON_SOURCES,
)

DYNAMIC_SOURCES = {
    "gateway": (),
    "research": ("native-vendor-stacks.json",),
    "research-fence-acquire": (
        "native-deployment-fence-request.json",
        "native-vendor-stacks.json",
    ),
    "research-fence-release": (
        "native-deployment-release-request.json",
        "native-vendor-stacks.json",
    ),
}
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
CONTAINER_MEMBERS = {
    "gateway.zip": "gateway",
    "research.zip": "research",
    "research-fence-acquire.zip": "research-fence-acquire",
    "research-fence-release.zip": "research-fence-release",
}
MAX_CONTAINER_BYTES = 256 * 1024 * 1024


def inventory(role: str) -> tuple[tuple[str, str, int], ...]:
    if role == "gateway":
        return GATEWAY_SOURCES
    if role == "research":
        return RESEARCH_SOURCES
    if role == "research-fence-acquire":
        return RESEARCH_FENCE_ACQUIRE_SOURCES
    if role == "research-fence-release":
        return RESEARCH_FENCE_RELEASE_SOURCES
    raise NativeDeploymentPayloadError("native_deployment_payload_role_invalid")


def _validate_inventory(role: str) -> tuple[tuple[str, str, int], ...]:
    values = inventory(role)
    names = [value[0] for value in values]
    paths = [value[1] for value in values]
    if (len(names) != len(set(names)) or len(paths) != len(set(paths))
            or any(native_deployment.SAFE_NAME.fullmatch(name) is None
                   for name in names)
            or any(mode not in {0o600, 0o700} for _, _, mode in values)):
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_inventory_invalid")
    return tuple(sorted(values, key=lambda value: value[0]))


def _read_source(path: Path) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_source_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= 16 * 1024 * 1024:
            block = os.read(
                descriptor, min(1024 * 1024, 16 * 1024 * 1024 + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_nlink != 1 or opened.st_mode & 0o022
            or not 1 <= opened.st_size <= 16 * 1024 * 1024
            or len(raw) != opened.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)):
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_source_changed")
    return bytes(raw)


def build_base_archive(repository: Path, role: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, relative, mode in _validate_inventory(role):
            path = repository / relative
            raw = _read_source(path)
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.compress_type = zipfile.ZIP_STORED
            member.external_attr = ((stat.S_IFREG | mode) & 0xFFFF) << 16
            archive.writestr(member, raw)
    raw = output.getvalue()
    if not 1 <= len(raw) <= MAX_ARCHIVE_BYTES:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_archive_oversized")
    return raw


def build_payload_container(repository: Path) -> bytes:
    """Build the one immutable Host payload containing all guest bases."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, role in sorted(CONTAINER_MEMBERS.items()):
            raw = build_base_archive(repository, role)
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.compress_type = zipfile.ZIP_STORED
            member.external_attr = ((stat.S_IFREG | 0o444) & 0xFFFF) << 16
            archive.writestr(member, raw)
    raw = output.getvalue()
    if not 1 <= len(raw) <= MAX_CONTAINER_BYTES:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_container_oversized")
    read_payload_container(raw)
    return raw


def read_payload_container(raw: bytes) -> dict[str, bytes]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_CONTAINER_BYTES:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_container_invalid")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), "r")
    except (OSError, zipfile.BadZipFile) as error:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_container_invalid") from error
    result: dict[str, bytes] = {}
    with archive:
        if archive.comment or [item.filename for item in archive.infolist()] != sorted(
            CONTAINER_MEMBERS
        ):
            raise NativeDeploymentPayloadError(
                "native_deployment_payload_container_inventory_mismatch")
        for item in archive.infolist():
            mode = (item.external_attr >> 16) & 0o7777
            file_type = (item.external_attr >> 16) & 0o170000
            if (
                item.filename not in CONTAINER_MEMBERS
                or item.date_time != (1980, 1, 1, 0, 0, 0)
                or item.compress_type != zipfile.ZIP_STORED
                or file_type != stat.S_IFREG
                or mode != 0o444
                or not 1 <= item.file_size <= MAX_ARCHIVE_BYTES
            ):
                raise NativeDeploymentPayloadError(
                    "native_deployment_payload_container_member_invalid")
            content = archive.read(item)
            read_base_archive(content, CONTAINER_MEMBERS[item.filename])
            result[item.filename] = content
    return result


def read_base_archive(raw: bytes, role: str) -> dict[str, tuple[bytes, int]]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ARCHIVE_BYTES:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_archive_invalid")
    expected = {name: mode for name, _relative, mode in _validate_inventory(role)}
    result: dict[str, tuple[bytes, int]] = {}
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), "r")
    except (OSError, zipfile.BadZipFile) as error:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_archive_invalid") from error
    with archive:
        if archive.comment or [item.filename for item in archive.infolist()] != sorted(expected):
            raise NativeDeploymentPayloadError(
                "native_deployment_payload_archive_inventory_mismatch")
        for item in archive.infolist():
            mode = (item.external_attr >> 16) & 0o7777
            file_type = (item.external_attr >> 16) & 0o170000
            if (item.filename not in expected or item.date_time != (1980, 1, 1, 0, 0, 0)
                    or item.compress_type != zipfile.ZIP_STORED
                    or file_type != stat.S_IFREG or mode != expected[item.filename]
                    or item.file_size < 1 or item.file_size > 16 * 1024 * 1024):
                raise NativeDeploymentPayloadError(
                    "native_deployment_payload_archive_member_invalid")
            content = archive.read(item)
            if len(content) != item.file_size:
                raise NativeDeploymentPayloadError(
                    "native_deployment_payload_archive_member_invalid")
            result[item.filename] = (content, mode)
    return result


def complete_package(
    raw: bytes, role: str, *, dynamic: Mapping[str, bytes],
) -> tuple[dict[str, tuple[bytes, int]], dict]:
    files = read_base_archive(raw, role)
    expected_dynamic = set(DYNAMIC_SOURCES[role])
    if set(dynamic) != expected_dynamic:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_dynamic_inventory_mismatch")
    for name, content in dynamic.items():
        if not isinstance(content, bytes) or not 1 <= len(content) <= 16 * 1024 * 1024:
            raise NativeDeploymentPayloadError(
                "native_deployment_payload_dynamic_source_invalid")
        files[name] = (content, 0o600)
    package = native_deployment.make_package(role, [
        {"name": name, "size": len(content),
         "sha256": hashlib.sha256(content).hexdigest(),
         # Research snapshots every transported source into a mode-0600
         # transaction bundle before computing its package identity. Gateway
         # retains each authenticated transport mode.
         "mode": 0o600 if role == "research" else mode}
        for name, (content, mode) in files.items()
    ])
    return files, package


def complete_fence_payload(
    raw: bytes, operation: str, *, dynamic: Mapping[str, bytes],
) -> tuple[dict[str, tuple[bytes, int]], dict]:
    role = f"research-fence-{operation}"
    if operation not in {"acquire", "release"}:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_fence_operation_invalid")
    files = read_base_archive(raw, role)
    expected_dynamic = set(DYNAMIC_SOURCES[role])
    if set(dynamic) != expected_dynamic:
        raise NativeDeploymentPayloadError(
            "native_deployment_payload_dynamic_inventory_mismatch")
    for name, content in dynamic.items():
        if (not isinstance(content, bytes)
                or not 1 <= len(content) <= 16 * 1024 * 1024):
            raise NativeDeploymentPayloadError(
                "native_deployment_payload_dynamic_source_invalid")
        files[name] = (content, 0o600)
    # The authenticated deployment transport targets Research.  The exact
    # member names distinguish acquire and release while the ordinary package
    # contract supplies a canonical digest for the Host recovery journal.
    package = native_deployment.make_package("research", [
        {"name": name, "size": len(content),
         "sha256": hashlib.sha256(content).hexdigest(), "mode": mode}
        for name, (content, mode) in files.items()
    ])
    return files, package
