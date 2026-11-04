#!/usr/bin/env python3
"""Publish, verify, and roll back immutable host-controller releases."""

from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import hmac
import io
import json
import os
import plistlib
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "secure-sandbox-host-controller-release-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PAYLOAD_SOURCES = {
    "authorization_broker": Path("scripts/operator-authorization.py"),
    "authorization_service": Path("config/org.zebeth.securesandbox.authorization.plist"),
    "authorization_ui_bundle": Path("artifacts/host/SecureSandboxAuthorizationUI.bundle.json"),
    "authorization_ui_sources": Path("artifacts/host/SecureSandboxAuthorizationUI.sources.json"),
    "control_client": Path("scripts/privileged_control.py"),
    "controller": Path("scripts/claude-run-controller.sh"),
    "harness_lifecycle_manager": Path("scripts/harness_lifecycle_manager.py"),
    "installer_verifier": Path("scripts/verify_ubuntu_installer.py"),
    "model_profile_manager": Path("scripts/model_profile_manager.py"),
    "native_stack_manager": Path("scripts/native_stack_manager.py"),
    "native_stack_session_manager": Path(
        "scripts/native_stack_session_manager.py"
    ),
    "native_stack_backend": Path("scripts/native_stack_backend.py"),
    "native_stack_terminal_bridge": Path(
        "scripts/native_stack_terminal_bridge.py"
    ),
    "native_stack_catalog_promoter": Path("scripts/native-stack-catalog-promote.py"),
    "native_stack_credential_client": Path(
        "artifacts/host/SecureSandboxNativeStackBackend"
    ),
    "native_projection_consumer": Path(
        "artifacts/host/SecureSandboxNativeProjectionConsumer"
    ),
    "native_credential_helper_bundle": Path(
        "artifacts/host/SecureSandboxNativeComponents.bundle.json"
    ),
    "native_credential_helper_service": Path(
        "macos/ControlCenter/Sources/SecureSandboxNativeCredentialHelper/"
        "org.zebeth.SecureSandbox.NativeCredentialHelper.plist.template"
    ),
    "native_host_products_container": Path(
        "artifacts/host/SecureSandboxNativeHostProducts.dmg"
    ),
    "native_host_products_manifest": Path(
        "artifacts/host/SecureSandboxNativeHostProducts.manifest.json"
    ),
    "native_host_products_notarization": Path(
        "artifacts/host/SecureSandboxNativeHostProducts.notarization.json"
    ),
    "pki_anchor": Path("scripts/pki-host-anchor.py"),
    "release_manager": Path("scripts/host-controller-release.py"),
    "seed_verifier": Path("scripts/verify-autoinstall-seed.py"),
    "seed_gateway": Path("seeds/gateway-cidata.iso"),
    "seed_research": Path("seeds/research-cidata.iso"),
    "seed_target": Path("seeds/target-cidata.iso"),
    "ssh_config": Path("config/ssh_config"),
    "vm_maintenance": Path("scripts/vm-maintenance.py"),
}
NATIVE_STACK_SUPPORT_SOURCES = {
    "shared/__init__.py": Path("shared/__init__.py"),
    "shared/harness_runtime_binding.py": Path("shared/harness_runtime_binding.py"),
    "shared/model_stack_runtime_binding.py": Path("shared/model_stack_runtime_binding.py"),
    "shared/native_codex_projection.py": Path("shared/native_codex_projection.py"),
    "shared/native_codex_ui_handle.py": Path("shared/native_codex_ui_handle.py"),
    "shared/native_egress.py": Path("shared/native_egress.py"),
    "shared/native_stack_operations.py": Path("shared/native_stack_operations.py"),
    "shared/native_stack_catalog_promotion.py": Path("shared/native_stack_catalog_promotion.py"),
    "shared/native_stack_session.py": Path("shared/native_stack_session.py"),
    "shared/native_terminal_handle.py": Path("shared/native_terminal_handle.py"),
    "shared/native_stack_runtime_binding.py": Path("shared/native_stack_runtime_binding.py"),
    "shared/native_vendor_stack.py": Path("shared/native_vendor_stack.py"),
    "shared/native_program_attestation.py": Path("shared/native_program_attestation.py"),
    "shared/native_projection_reconciliation.py": Path(
        "shared/native_projection_reconciliation.py"
    ),
    "shared/native_projection_identity_recovery.py": Path(
        "shared/native_projection_identity_recovery.py"
    ),
    "shared/runtime_authority.py": Path("shared/runtime_authority.py"),
    "shared/session_context_binding.py": Path("shared/session_context_binding.py"),
}
PAYLOAD_NAMES = {*PAYLOAD_SOURCES, "gpgv", "native_stack_support"}
NATIVE_CREDENTIAL_PAYLOAD_NAMES = {
    "native_stack_credential_client", "native_projection_consumer",
    "native_credential_helper_bundle", "native_credential_helper_service",
    "native_host_products_container", "native_host_products_manifest",
    "native_host_products_notarization",
}
NATIVE_HOST_PRODUCT_CONTAINER_PAYLOAD_NAMES = {
    "native_host_products_container", "native_host_products_manifest",
    "native_host_products_notarization",
}
PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES = PAYLOAD_NAMES - {
    "native_stack_session_manager"
}
PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES = (
    PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES - {
    "native_stack_terminal_bridge"
    }
)
PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES = (
    PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES
    - NATIVE_CREDENTIAL_PAYLOAD_NAMES
)
PRE_NATIVE_STACK_PAYLOAD_NAMES = PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES - {
    "native_stack_manager", "native_stack_backend",
    "native_stack_catalog_promoter", "native_stack_support"
}
PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES = (
    PRE_NATIVE_STACK_PAYLOAD_NAMES - {"harness_lifecycle_manager"}
)
PRE_MODEL_PROFILE_PAYLOAD_NAMES = PRE_NATIVE_STACK_PAYLOAD_NAMES - {"model_profile_manager"}
PRE_HARNESS_LIFECYCLE_PRE_MODEL_PROFILE_PAYLOAD_NAMES = (
    PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES - {"model_profile_manager"}
)
LAUNCHER_SOURCE = Path("scripts/secure-sandbox-claude-launcher.py")
DEFAULT_OP_BINARY = Path("/opt/homebrew/bin/op")
DEFAULT_GPGV_BINARY = Path("/opt/homebrew/bin/gpgv")
MAX_RELEASES = 32
MAX_RELEASE_DIRECTORY_ENTRIES = 64
MAX_ARCHIVED_RELEASES = 128
MAX_ACTIVE_MARKERS = 64
EXECUTION_APPROVAL_FLOOR = Path(
    "/usr/local/var/lib/secure-sandbox/execution-approval/minimum-floor.json"
)
EXECUTION_APPROVAL_V2_CAPABILITY = b"secure-sandbox-execution-approval-floor-enforcement-v2"
DEVELOPER_ID_TEAM_FLOOR_NAME = "developer-id-team-floor.json"
DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME = ".developer-id-team-floor.pending"
DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME = (
    "developer-id-migration-predecessor"
)
DEVELOPER_ID_TEAM_FLOOR_SCHEMA = (
    "secure-sandbox-developer-id-team-floor-v1"
)
# Exact immutable release accidentally published with a pre-execution NameError
# in the v2 Touch ID challenge path. This is the sole predecessor accepted by
# the terminal-bound broker recovery below.
BROKEN_CEREMONY_BROKER_RELEASE_ID = (
    "4b727d78dd242fa9d0334fd6ea5113e653f9a4ea2944ce072c7cf2c26735dfb3"
)
BROKEN_CEREMONY_BROKER_SHA256 = (
    "52f65a960932ec624be529779f5b8491569d7cb39cd4549b58abd84d092e5400"
)
EXPECTED_MODES = {
    "authorization_broker": 0o755,
    "authorization_service": 0o444,
    "authorization_ui_bundle": 0o444,
    "authorization_ui": 0o555,
    "authorization_ui_sources": 0o444,
    "control_client": 0o755,
    "controller": 0o755,
    "gpgv": 0o555,
    "harness_lifecycle_manager": 0o755,
    "installer_verifier": 0o755,
    "model_profile_manager": 0o755,
    "native_stack_manager": 0o755,
    "native_stack_session_manager": 0o755,
    "native_stack_backend": 0o755,
    "native_stack_terminal_bridge": 0o755,
    "native_stack_catalog_promoter": 0o755,
    "native_stack_credential_client": 0o555,
    "native_projection_consumer": 0o555,
    "native_credential_helper_bundle": 0o444,
    "native_credential_helper_service": 0o444,
    "native_host_products_container": 0o444,
    "native_host_products_manifest": 0o444,
    "native_host_products_notarization": 0o444,
    "native_stack_support": 0o444,
    "pki_anchor": 0o755,
    "release_manager": 0o755,
    "seed_verifier": 0o755,
    "seed_gateway": 0o444,
    "seed_research": 0o444,
    "seed_target": 0o444,
    "ssh_config": 0o444,
    "vm_maintenance": 0o755,
    "manifest.json": 0o444,
    # Read only while validating an installed pre-v1 release during migration.
    "op_agents": 0o755,
}
AUTHORIZATION_UI_APP_SOURCE = Path("artifacts/host/SecureSandboxAuthorizationUI.app")
AUTHORIZATION_UI_APP_NAME = "SecureSandboxAuthorizationUI.app"
AUTHORIZATION_UI_EXECUTABLE = Path("Contents/MacOS/SecureSandboxAuthorizationUI")
NATIVE_CREDENTIAL_HELPER_APP_SOURCE = Path(
    "artifacts/host/SecureSandboxNativeCredentialHelper.app"
)
NATIVE_CREDENTIAL_HELPER_APP_NAME = "SecureSandboxNativeCredentialHelper.app"
NATIVE_CREDENTIAL_HELPER_EXECUTABLE = Path(
    "Contents/MacOS/SecureSandboxNativeCredentialXPCService"
)
NATIVE_CREDENTIAL_HELPER_LABEL = (
    "org.zebeth.SecureSandbox.NativeCredentialHelper"
)
NATIVE_CREDENTIAL_HANDOFF_SCHEMA = (
    "secure-sandbox-native-credential-client-handoff-v1"
)
NATIVE_CREDENTIAL_REPLY_SCHEMA = (
    "secure-sandbox-native-credential-client-reply-v1"
)
NATIVE_PROJECTION_AUTHORITY_FIELDS = (
    "consumer_executable_path", "consumer_executable_sha256",
    "host_release_id", "session_id", "runtime_authority_sha256",
    "native_stack_binding_sha256", "harness_binding_sha256",
    "harness_generation_id", "harness_executable_sha256", "model_id",
    "reasoning_effort", "cyber_access_program", "policy_manifest_sha256",
    "probe_executable_sha256", "protocol_version",
    "launch_descriptor_sha256", "research_release_id", "boot_id_sha256",
    "qualification_subject_sha256", "qualification_evidence_sha256",
    "qualification_observed_at", "qualification_expires_at",
    "qualification_readback_sha256",
)
NATIVE_CREDENTIAL_BACKEND_IDENTIFIER = (
    "org.zebeth.SecureSandbox.NativeStackBackend"
)
NATIVE_PROJECTION_CONSUMER_IDENTIFIER = (
    "org.zebeth.SecureSandbox.NativeProjectionConsumer"
)
NATIVE_HOST_PRODUCTS_CONTAINER_IDENTIFIER = (
    "org.zebeth.SecureSandbox.NativeHostProducts"
)
NATIVE_HOST_PRODUCTS_INNER_MANIFEST_NAME = (
    "SecureSandboxNativeHostProducts.manifest.json"
)
NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH = (
    "/usr/local/libexec/secure-sandbox-host/current/"
    + NATIVE_CREDENTIAL_HELPER_APP_NAME
    + "/"
    + NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix()
)
PRE_AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES = {
    "Package.swift",
    "AuthorizationUI.entitlements",
    "Info.plist",
    "SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj",
    "Sources/AuthorizationCore/AuthorizationRequest.swift",
    "Sources/AuthorizationCore/ExecutionApprovalCrypto.swift",
    "Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift",
    "Sources/SecureSandboxAuthorizationUI/main.swift",
}
AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES = (
    PRE_AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES | {
        "Artwork/AppIcon.icon/icon.json",
        "Artwork/AppIcon.icon/Assets/AuthorizationLock.svg",
        "Artwork/AppIcon.icon/Assets/ControlStack.svg",
        "Artwork/AppIcon.icon/Assets/DiagonalAccent.svg",
    }
)
PRE_PROFILED_TOUCHID_PAYLOAD_NAMES = {
    "authorization_broker", "authorization_service", "authorization_ui",
    "authorization_ui_sources", "control_client", "controller", "gpgv",
    "installer_verifier", "pki_anchor", "release_manager", "seed_gateway",
    "seed_research", "seed_target", "seed_verifier", "ssh_config", "vm_maintenance",
}
PRE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES = (
    PRE_PROFILED_TOUCHID_PAYLOAD_NAMES | {"model_profile_manager"}
)
PRE_HARNESS_LIFECYCLE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES = (
    PRE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES | {"harness_lifecycle_manager"}
)
LEGACY_PAYLOAD_NAMES = {"controller", "op_agents", "ssh_config"}
PRE_INSTALLER_PAYLOAD_NAMES = {"controller", "op_agents", "pki_anchor", "ssh_config"}
PRE_CONTROL_PAYLOAD_NAMES = {
    "controller",
    "gpgv",
    "installer_verifier",
    "op_agents",
    "pki_anchor",
    "ssh_config",
}
PRE_AUTHORIZATION_PAYLOAD_NAMES = {
    "control_client",
    "controller",
    "gpgv",
    "installer_verifier",
    "pki_anchor",
    "ssh_config",
}
PRE_MAINTENANCE_PAYLOAD_NAMES = {
    "authorization_broker",
    "control_client",
    "controller",
    "gpgv",
    "installer_verifier",
    "pki_anchor",
    "release_manager",
    "ssh_config",
}
PRE_TOUCHID_PAYLOAD_NAMES = {
    "authorization_broker", "control_client", "controller", "gpgv",
    "installer_verifier", "pki_anchor", "release_manager", "seed_verifier",
    "seed_gateway", "seed_research", "seed_target", "ssh_config", "vm_maintenance",
}
PRE_SECURE_ENCLAVE_TOUCHID_SOURCE_NAMES = {
    "Package.swift",
    "Sources/AuthorizationCore/AuthorizationRequest.swift",
    "Sources/SecureSandboxAuthorizationUI/main.swift",
}
VULNERABLE_TOUCHID_MAIN_SOURCE_SHA256 = {
    "b519a8abaf84c1ba80a1a6b94426702e8d9c69ea11c8914b4b75c481137666a3",
}
RECOVERED_TOUCHID_MAIN_SOURCE_SHA256 = (
    "7050f9babbdb592b1ab2187fc229abc3c2215ab566255bf915cfcf7e6ce9eb8f"
)
RECOVERED_TOUCHID_UI_SHA256 = (
    "56937bb37bed4f854392c0aeaa8b6945622910ee3982a9eb81b64d7347f5bf7f"
)
RECOVERED_TOUCHID_SOURCES_SHA256 = (
    "0fe447b66cf8986337771503c4a28d5bc4d50e29ba928dd7654158f46f79fe8b"
)
DEFAULT_INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
DEFAULT_AUTHORIZATION_PLIST = Path(
    "/Library/LaunchDaemons/org.zebeth.securesandbox.authorization.plist"
)
AUTHORIZATION_LABEL = "org.zebeth.securesandbox.authorization"
DEFAULT_NATIVE_CREDENTIAL_PLIST = Path(
    "/Library/LaunchAgents/"
    + NATIVE_CREDENTIAL_HELPER_LABEL
    + ".plist"
)
HOST_SERVICE_STOP_TIMEOUT_SECONDS = 5.0
HOST_SERVICE_STOP_POLL_SECONDS = 0.02
INSTALL_TRANSITION_SCHEMA = "secure-sandbox-host-install-transition-v1"
INSTALL_TERMINAL_SCHEMA = "secure-sandbox-host-install-terminal-v1"
INSTALL_TRANSITION_PENDING_NAME = ".install-transition.json"
INSTALL_TRANSITION_DIRECTORY_NAME = "install-transitions"
DEFAULT_AUTHORIZATION_RECEIPT_ROOT = Path(
    "/usr/local/var/log/secure-sandbox/authorization-receipts"
)
INSTALL_TRANSITION_TTL_SECONDS = 600
INSTALL_TRANSITION_RECORD_LIMIT = 64 * 1024
DEFAULT_AUTHORIZATION_SOCKET = Path(
    "/var/run/secure-sandbox-authorization.sock"
)


class ReleaseFailure(RuntimeError):
    pass


class _ProcBSDInfo(ctypes.Structure):
    """Darwin proc_bsdinfo used to bind a PID to its exact generation."""

    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_all(descriptor: int, data: bytes, label: str) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ReleaseFailure(label + "_short_write")
        view = view[written:]


def release_identity(payloads: dict[str, str]) -> str:
    identity = bytearray()
    for name in sorted(payloads):
        identity.extend(f"{name}\0{payloads[name]}\n".encode("ascii"))
    return sha256_bytes(bytes(identity))


def read_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except (FileNotFoundError, OSError) as error:
        raise ReleaseFailure(f"source_not_regular:{path}") from error
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ReleaseFailure(f"source_not_regular:{path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ReleaseFailure(f"source_changed_during_read:{path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def authorization_ui_bundle_manifest(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("authorization_ui_bundle_manifest_invalid") from error
    files = value.get("files") if isinstance(value, dict) else None
    schema = value.get("schema") if isinstance(value, dict) else None
    expected_keys = ({"bundle", "files", "schema"} if schema == "secure-sandbox-touchid-ui-bundle-v1"
                     else {"bundle", "files", "schema", "signing_policy"})
    if (schema not in {"secure-sandbox-touchid-ui-bundle-v1", "secure-sandbox-touchid-ui-bundle-v2"}
            or set(value) != expected_keys
            or value.get("bundle") != AUTHORIZATION_UI_APP_NAME
            or not isinstance(files, dict) or not 4 <= len(files) <= 16
            or AUTHORIZATION_UI_EXECUTABLE.as_posix() not in files
            or "Contents/embedded.provisionprofile" not in files):
        raise ReleaseFailure("authorization_ui_bundle_manifest_invalid")
    if schema == "secure-sandbox-touchid-ui-bundle-v2":
        authorization_ui_signing_policy(value)
    for relative, record in files.items():
        path = Path(relative)
        if (not isinstance(relative, str) or path.is_absolute() or ".." in path.parts
                or len(path.parts) < 2 or not isinstance(record, dict)
                or set(record) != {"mode", "sha256", "size"}
                or record["mode"] not in {0o444, 0o555}
                or not isinstance(record["size"], int) or isinstance(record["size"], bool)
                or not 0 <= record["size"] <= 16 * 1024 * 1024
                or not isinstance(record["sha256"], str)
                or SHA256.fullmatch(record["sha256"]) is None):
            raise ReleaseFailure("authorization_ui_bundle_manifest_invalid")
    if files[AUTHORIZATION_UI_EXECUTABLE.as_posix()]["mode"] != 0o555:
        raise ReleaseFailure("authorization_ui_bundle_manifest_invalid")
    return value


def authorization_ui_signing_policy(manifest: dict[str, Any]) -> dict[str, str] | None:
    if manifest.get("schema") == "secure-sandbox-touchid-ui-bundle-v1":
        return None
    policy = manifest.get("signing_policy")
    if (not isinstance(policy, dict)
            or set(policy) != {"access_group", "application_identifier", "bundle_id", "team_id"}
            or not isinstance(policy.get("team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", policy["team_id"]) is None
            or policy.get("bundle_id") != "org.zebeth.SecureSandbox.AuthorizationUI"
            or policy.get("application_identifier") != policy["team_id"] + "." + policy["bundle_id"]
            or policy.get("access_group") != policy["application_identifier"]):
        raise ReleaseFailure("authorization_ui_signing_policy_invalid")
    return policy


def verified_authorization_ui_signing_policy(
    root: Path, manifest_data: bytes, expected_uid: int | None = None,
) -> dict[str, str]:
    """Bind a v2 manifest policy to the bundle's live Developer ID signature."""
    manifest = authorization_ui_bundle_manifest(manifest_data)
    policy = authorization_ui_signing_policy(manifest)
    if policy is None:
        raise ReleaseFailure("authorization_ui_signing_policy_below_floor")
    verify_authorization_ui_bundle(root, manifest_data, expected_uid)
    requirement = (
        f'identifier "{policy["bundle_id"]}" and anchor apple generic '
        f'and certificate leaf[subject.OU] = "{policy["team_id"]}" '
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )
    signature = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2",
         str(root)],
        check=False, capture_output=True, text=True,
    )
    designated = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
         f"-R={requirement}", str(root)],
        check=False, capture_output=True, text=True,
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(root)],
        check=False, capture_output=True, text=True,
    )
    if (signature.returncode != 0 or designated.returncode != 0
            or details.returncode != 0
            or f'Identifier={policy["bundle_id"]}' not in details.stderr
            or f'TeamIdentifier={policy["team_id"]}' not in details.stderr
            or "runtime" not in details.stderr
            or "Signature=adhoc" in details.stderr):
        raise ReleaseFailure("authorization_ui_live_signing_policy_invalid")
    return policy


def verified_existing_authorization_ui_anchor_policy(
    root: Path, manifest_data: bytes, expected_uid: int,
) -> dict[str, str]:
    """Observe the immutable pre-floor v2 UI without upgrading its authority.

    This is used only by the one-time Developer ID migration.  The old bundle
    may carry an Apple Development leaf, so it is never accepted as a new
    candidate.  Its root-owned release bytes, v2 policy, identifier, team and
    entitlements must nevertheless agree exactly.
    """
    manifest = authorization_ui_bundle_manifest(manifest_data)
    policy = authorization_ui_signing_policy(manifest)
    if policy is None:
        raise ReleaseFailure("authorization_ui_anchor_below_v2")
    verify_authorization_ui_bundle(root, manifest_data, expected_uid)
    details = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(root)],
        check=False, capture_output=True, text=True,
    )
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(root)],
        check=False, capture_output=True,
    )
    try:
        entitlement_value = plistlib.loads(entitlements.stdout)
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("authorization_ui_anchor_entitlements_invalid") from error
    expected_entitlements = {
        "com.apple.application-identifier": policy["application_identifier"],
        "com.apple.developer.team-identifier": policy["team_id"],
        "keychain-access-groups": [policy["access_group"]],
    }
    if (details.returncode != 0 or entitlements.returncode != 0
            or f'Identifier={policy["bundle_id"]}' not in details.stderr
            or f'TeamIdentifier={policy["team_id"]}' not in details.stderr
            or "Signature=adhoc" in details.stderr
            or entitlement_value != expected_entitlements):
        raise ReleaseFailure("authorization_ui_anchor_identity_invalid")
    return policy


def _developer_id_floor_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReleaseFailure("developer_id_team_floor_invalid") from error


def validate_developer_id_team_floor(value: object) -> dict[str, Any]:
    fields = {
        "schema", "team_id", "authorization_ui_bundle_id",
        "established_from_release_id",
        "established_from_authorization_manifest_sha256", "established_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("developer_id_team_floor_invalid")
    established_at = value.get("established_at")
    if (value.get("schema") != DEVELOPER_ID_TEAM_FLOOR_SCHEMA
            or not isinstance(value.get("team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["team_id"]) is None
            or value.get("authorization_ui_bundle_id")
                != "org.zebeth.SecureSandbox.AuthorizationUI"
            or not isinstance(value.get("established_from_release_id"), str)
            or SHA256.fullmatch(value["established_from_release_id"]) is None
            or not isinstance(
                value.get("established_from_authorization_manifest_sha256"),
                str,
            )
            or SHA256.fullmatch(
                value["established_from_authorization_manifest_sha256"]
            ) is None
            or not isinstance(established_at, int)
            or isinstance(established_at, bool) or established_at < 0):
        raise ReleaseFailure("developer_id_team_floor_invalid")
    return {key: value[key] for key in sorted(fields)}


def developer_id_team_floor(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    path = install_root / DEVELOPER_ID_TEAM_FLOOR_NAME
    try:
        root_info = install_root.lstat()
        info = path.lstat()
    except FileNotFoundError:
        if allow_absent:
            return None
        raise ReleaseFailure("developer_id_team_floor_missing")
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != expected_uid
            or stat.S_IMODE(root_info.st_mode) != 0o755
            or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or info.st_gid != root_info.st_gid
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or not 2 <= info.st_size <= 2048):
        raise ReleaseFailure("developer_id_team_floor_untrusted")
    raw = read_regular(path)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("developer_id_team_floor_invalid") from error
    validated = validate_developer_id_team_floor(value)
    if raw != _developer_id_floor_bytes(validated):
        raise ReleaseFailure("developer_id_team_floor_not_canonical")
    return validated, sha256_bytes(raw)


def developer_id_floor_record(
    *, release_id: str, authorization_manifest: bytes,
    policy: Mapping[str, str], established_at: int,
) -> dict[str, Any]:
    return validate_developer_id_team_floor({
        "schema": DEVELOPER_ID_TEAM_FLOOR_SCHEMA,
        "team_id": policy["team_id"],
        "authorization_ui_bundle_id": policy["bundle_id"],
        "established_from_release_id": release_id,
        "established_from_authorization_manifest_sha256": sha256_bytes(
            authorization_manifest
        ),
        "established_at": established_at,
    })


def reconcile_developer_id_team_floor_publication(
    install_root: Path, expected_uid: int,
) -> tuple[dict[str, Any], str] | None:
    """Finish only the proven hard-link publication crash state.

    The permanent floor is published by hard-linking a fully fsynced pending
    inode to its final name, fsyncing the directory, and then removing the
    pending name.  A crash in that final interval legitimately leaves the same
    canonical inode under both names with nlink=2.  Ordinary readers remain
    strict; the one-time migration entry point calls this reconciler so it can
    remove only that exact second name and resume while still fenced.
    """
    descriptor = os.open(
        install_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        root_info = os.fstat(descriptor)
        current = install_root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or (root_info.st_dev, root_info.st_ino)
                    != (current.st_dev, current.st_ino)
                or root_info.st_uid != expected_uid
                or stat.S_IMODE(root_info.st_mode) != 0o755):
            raise ReleaseFailure("developer_id_team_floor_parent_untrusted")
        try:
            final_info = os.stat(
                DEVELOPER_ID_TEAM_FLOOR_NAME,
                dir_fd=descriptor, follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        if final_info.st_nlink == 1:
            return developer_id_team_floor(install_root, expected_uid)
        try:
            pending_info = os.stat(
                DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                dir_fd=descriptor, follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise ReleaseFailure("developer_id_team_floor_untrusted") from error
        if (not stat.S_ISREG(final_info.st_mode)
                or stat.S_ISLNK(final_info.st_mode)
                or (final_info.st_dev, final_info.st_ino)
                    != (pending_info.st_dev, pending_info.st_ino)
                or final_info.st_nlink != 2 or pending_info.st_nlink != 2
                or final_info.st_uid != expected_uid
                or final_info.st_gid != root_info.st_gid
                or stat.S_IMODE(final_info.st_mode) != 0o600
                or not 2 <= final_info.st_size <= 2048):
            raise ReleaseFailure("developer_id_team_floor_untrusted")
        floor_descriptor = os.open(
            DEVELOPER_ID_TEAM_FLOOR_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=descriptor,
        )
        try:
            opened = os.fstat(floor_descriptor)
            if ((opened.st_dev, opened.st_ino)
                    != (final_info.st_dev, final_info.st_ino)):
                raise ReleaseFailure("developer_id_team_floor_changed")
            raw = os.read(floor_descriptor, 2049)
            if len(raw) > 2048 or os.read(floor_descriptor, 1):
                raise ReleaseFailure("developer_id_team_floor_invalid")
        finally:
            os.close(floor_descriptor)
        try:
            record = validate_developer_id_team_floor(json.loads(raw))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseFailure("developer_id_team_floor_invalid") from error
        if raw != _developer_id_floor_bytes(record):
            raise ReleaseFailure("developer_id_team_floor_not_canonical")
        os.unlink(DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return developer_id_team_floor(install_root, expected_uid)


def create_developer_id_team_floor(
    install_root: Path, expected_uid: int, value: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    record = validate_developer_id_team_floor(dict(value))
    raw = _developer_id_floor_bytes(record)
    descriptor = os.open(
        install_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        root_info = os.fstat(descriptor)
        current = install_root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or (root_info.st_dev, root_info.st_ino)
                    != (current.st_dev, current.st_ino)
                or root_info.st_uid != expected_uid
                or stat.S_IMODE(root_info.st_mode) != 0o755):
            raise ReleaseFailure("developer_id_team_floor_parent_untrusted")

        def information(name: str) -> os.stat_result | None:
            try:
                return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return None

        final_info = information(DEVELOPER_ID_TEAM_FLOOR_NAME)
        pending_info = information(DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME)
        if final_info is not None:
            if pending_info is not None:
                if ((final_info.st_dev, final_info.st_ino)
                        != (pending_info.st_dev, pending_info.st_ino)
                        or final_info.st_nlink != 2
                        or pending_info.st_nlink != 2):
                    raise ReleaseFailure("developer_id_team_floor_conflict")
                os.unlink(DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME, dir_fd=descriptor)
                os.fsync(descriptor)
            existing = developer_id_team_floor(install_root, expected_uid)
            if existing is None or existing[0] != record:
                raise ReleaseFailure("developer_id_team_floor_conflict")
            return existing

        pending_valid = False
        if pending_info is not None:
            pending_descriptor = -1
            try:
                pending_descriptor = os.open(
                    DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                opened = os.fstat(pending_descriptor)
                observed = os.read(pending_descriptor, len(raw) + 1)
                pending_valid = (
                    stat.S_ISREG(opened.st_mode)
                    and opened.st_uid == expected_uid
                    and opened.st_gid == root_info.st_gid
                    and opened.st_nlink == 1
                    and stat.S_IMODE(opened.st_mode) == 0o600
                    and observed == raw
                    and not os.read(pending_descriptor, 1)
                )
            except OSError:
                pending_valid = False
            finally:
                if pending_descriptor >= 0:
                    os.close(pending_descriptor)
            if not pending_valid:
                # The pending name is never authority.  With no final floor,
                # a root-owned interrupted write is safely discarded and the
                # exact operator-bound record is reconstructed.
                if (not stat.S_ISREG(pending_info.st_mode)
                        or pending_info.st_uid != expected_uid
                        or pending_info.st_gid != root_info.st_gid
                        or pending_info.st_nlink != 1):
                    raise ReleaseFailure(
                        "developer_id_team_floor_pending_untrusted"
                    )
                os.unlink(DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME, dir_fd=descriptor)
                os.fsync(descriptor)
                pending_info = None

        if pending_info is None:
            pending_descriptor = os.open(
                DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600, dir_fd=descriptor,
            )
            try:
                os.fchown(pending_descriptor, expected_uid, root_info.st_gid)
                os.fchmod(pending_descriptor, 0o600)
                write_all(
                    pending_descriptor, raw, "developer_id_team_floor"
                )
                os.fsync(pending_descriptor)
            finally:
                os.close(pending_descriptor)
            os.fsync(descriptor)

        try:
            os.link(
                DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                DEVELOPER_ID_TEAM_FLOOR_NAME,
                src_dir_fd=descriptor, dst_dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = developer_id_team_floor(install_root, expected_uid)
            if existing is None or existing[0] != record:
                raise ReleaseFailure("developer_id_team_floor_conflict")
        else:
            os.fsync(descriptor)
        os.unlink(DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    observed = developer_id_team_floor(install_root, expected_uid)
    if observed is None or observed[0] != record:
        raise ReleaseFailure("developer_id_team_floor_readback_failed")
    return observed


def verify_authorization_ui_bundle(root: Path, manifest_data: bytes,
                                   expected_uid: int | None = None) -> None:
    manifest = authorization_ui_bundle_manifest(manifest_data)
    expected_files = set(manifest["files"])
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    if root.is_symlink() or not root.is_dir():
        raise ReleaseFailure("authorization_ui_bundle_invalid")
    root_info = root.lstat()
    if stat.S_IMODE(root_info.st_mode) != 0o555:
        raise ReleaseFailure("authorization_ui_bundle_mode_invalid")
    if expected_uid is not None and root_info.st_uid != expected_uid:
        raise ReleaseFailure("authorization_ui_bundle_owner_invalid")
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReleaseFailure("authorization_ui_bundle_invalid")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
            if stat.S_IMODE(info.st_mode) != 0o555:
                raise ReleaseFailure("authorization_ui_bundle_mode_invalid")
        elif stat.S_ISREG(info.st_mode):
            actual_files.add(relative)
        else:
            raise ReleaseFailure("authorization_ui_bundle_invalid")
        if expected_uid is not None and info.st_uid != expected_uid:
            raise ReleaseFailure("authorization_ui_bundle_owner_invalid")
    expected_directories = {
        Path(*Path(relative).parts[:index]).as_posix()
        for relative in expected_files for index in range(1, len(Path(relative).parts))
    }
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ReleaseFailure("authorization_ui_bundle_entries_invalid")
    for relative, record in manifest["files"].items():
        path = root / relative
        info = path.lstat()
        data = read_regular(path)
        if (stat.S_IMODE(info.st_mode) != record["mode"]
                or len(data) != record["size"]
                or sha256_bytes(data) != record["sha256"]):
            raise ReleaseFailure("authorization_ui_bundle_member_invalid:" + relative)


def copy_authorization_ui_bundle(source: Path, destination: Path,
                                 manifest_data: bytes, expected_uid: int) -> None:
    verify_authorization_ui_bundle(source, manifest_data)
    manifest = authorization_ui_bundle_manifest(manifest_data)
    destination.mkdir(mode=0o755)
    directories = sorted({
        Path(*Path(relative).parts[:index])
        for relative in manifest["files"] for index in range(1, len(Path(relative).parts))
    }, key=lambda path: (len(path.parts), path.as_posix()))
    for relative in directories:
        (destination / relative).mkdir(mode=0o755)
    for relative, record in manifest["files"].items():
        data = read_regular(source / relative)
        path = destination / relative
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, record["mode"])
        try:
            write_all(descriptor, data, "authorization_ui_bundle_member")
            os.fsync(descriptor)
            os.fchmod(descriptor, record["mode"])
        finally:
            os.close(descriptor)
    for relative in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        os.chmod(destination / relative, 0o555)
        fsync_directory(destination / relative)
    os.chmod(destination, 0o555)
    verify_authorization_ui_bundle(destination, manifest_data, expected_uid)


def native_components_manifest(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
        canonical = (json.dumps(
            value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True
        ) + "\n").encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError,
            json.JSONDecodeError) as error:
        raise ReleaseFailure("native_components_manifest_invalid") from error
    if (not isinstance(value, dict)
            or data != canonical
            or set(value) != {"backend", "consumer", "helper", "schema", "signing_policy"}
            or value.get("schema") != "secure-sandbox-native-components-bundle-v1"):
        raise ReleaseFailure("native_components_manifest_invalid")
    policy = value.get("signing_policy")
    if (not isinstance(policy, dict) or set(policy) != {"team_id"}
            or not isinstance(policy.get("team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", policy["team_id"]) is None):
        raise ReleaseFailure("native_components_signing_policy_invalid")
    for label, identifier in (
        ("backend", NATIVE_CREDENTIAL_BACKEND_IDENTIFIER),
        ("consumer", NATIVE_PROJECTION_CONSUMER_IDENTIFIER),
    ):
        record = value.get(label)
        if (not isinstance(record, dict)
                or set(record) != {"identifier", "mode", "sha256", "size"}
                or record.get("identifier") != identifier
                or record.get("mode") != 0o555
                or not isinstance(record.get("size"), int)
                or isinstance(record.get("size"), bool)
                or not 1 <= record["size"] <= 64 * 1024 * 1024
                or not isinstance(record.get("sha256"), str)
                or SHA256.fullmatch(record["sha256"]) is None):
            raise ReleaseFailure("native_components_manifest_invalid")
    helper = value.get("helper")
    files = helper.get("files") if isinstance(helper, dict) else None
    if (not isinstance(helper, dict)
            or set(helper) != {"bundle", "files", "identifier"}
            or helper.get("bundle") != NATIVE_CREDENTIAL_HELPER_APP_NAME
            or helper.get("identifier") != NATIVE_CREDENTIAL_HELPER_LABEL
            or not isinstance(files, dict) or not 2 <= len(files) <= 32
            or NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix() not in files
            or "Contents/Info.plist" not in files):
        raise ReleaseFailure("native_components_manifest_invalid")
    for relative, record in files.items():
        path = Path(relative)
        if (not isinstance(relative, str) or path.is_absolute() or ".." in path.parts
                or len(path.parts) < 2 or not isinstance(record, dict)
                or set(record) != {"mode", "sha256", "size"}
                or record.get("mode") not in {0o444, 0o555}
                or not isinstance(record.get("size"), int)
                or isinstance(record.get("size"), bool)
                or not 0 <= record["size"] <= 64 * 1024 * 1024
                or not isinstance(record.get("sha256"), str)
                or SHA256.fullmatch(record["sha256"]) is None):
            raise ReleaseFailure("native_components_manifest_invalid")
    if sum(record["size"] for record in files.values()) > 128 * 1024 * 1024:
        raise ReleaseFailure("native_components_manifest_invalid")
    if files[NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix()]["mode"] != 0o555:
        raise ReleaseFailure("native_components_manifest_invalid")
    return value


def native_host_products_manifest(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
        canonical = (json.dumps(
            value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True,
        ) + "\n").encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError,
            json.JSONDecodeError) as error:
        raise ReleaseFailure("native_host_products_manifest_invalid") from error
    entries = value.get("entries") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or data != canonical
            or set(value) != {"entries", "schema"}
            or value.get("schema")
                != "secure-sandbox-native-host-products-manifest-v1"
            or not isinstance(entries, dict)
            or not 6 <= len(entries) <= 256):
        raise ReleaseFailure("native_host_products_manifest_invalid")
    total = 0
    for relative, record in entries.items():
        path = Path(relative) if isinstance(relative, str) else Path("/")
        if (not isinstance(relative, str) or not relative
                or path.is_absolute() or ".." in path.parts
                or len(path.parts) > 12 or len(relative) > 512
                or relative == NATIVE_HOST_PRODUCTS_INNER_MANIFEST_NAME
                or not isinstance(record, dict)
                or set(record) != {"mode", "sha256", "size"}
                or record.get("mode") not in {0o444, 0o555}
                or not isinstance(record.get("size"), int)
                or isinstance(record.get("size"), bool)
                or not 0 <= record["size"] <= 128 * 1024 * 1024
                or not isinstance(record.get("sha256"), str)
                or SHA256.fullmatch(record["sha256"]) is None):
            raise ReleaseFailure("native_host_products_manifest_invalid")
        total += record["size"]
    if total > 384 * 1024 * 1024:
        raise ReleaseFailure("native_host_products_manifest_invalid")
    return value


def native_host_products_notarization(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
        canonical = (json.dumps(
            value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True,
        ) + "\n").encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError,
            json.JSONDecodeError) as error:
        raise ReleaseFailure("native_host_products_notarization_invalid") from error
    if (not isinstance(value, dict) or data != canonical
            or set(value) != {
                "container_sha256", "container_size", "gatekeeper_assessed",
                "notary_log_sha256", "notary_status",
                "notary_submission_id", "schema", "stapler_validated",
                "team_id",
            }
            or value.get("schema")
                != "secure-sandbox-native-host-products-notarization-v1"
            or not isinstance(value.get("container_sha256"), str)
            or SHA256.fullmatch(value["container_sha256"]) is None
            or not isinstance(value.get("notary_log_sha256"), str)
            or SHA256.fullmatch(value["notary_log_sha256"]) is None
            or not isinstance(value.get("container_size"), int)
            or isinstance(value.get("container_size"), bool)
            or not 1 <= value["container_size"] <= 512 * 1024 * 1024
            or value.get("notary_status") != "accepted"
            or value.get("gatekeeper_assessed") is not True
            or value.get("stapler_validated") is not True
            or not isinstance(value.get("notary_submission_id"), str)
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                value["notary_submission_id"],
            ) is None
            or not isinstance(value.get("team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["team_id"]) is None):
        raise ReleaseFailure("native_host_products_notarization_invalid")
    return value


def expected_native_host_product_entries(
    values: Mapping[str, bytes],
) -> dict[str, dict[str, Any]]:
    authorization = authorization_ui_bundle_manifest(
        values["authorization_ui_bundle"]
    )
    native = native_components_manifest(
        values["native_credential_helper_bundle"]
    )
    entries: dict[str, dict[str, Any]] = {}
    for relative, record in authorization["files"].items():
        entries[f"{AUTHORIZATION_UI_APP_NAME}/{relative}"] = record
    for relative, record in native["helper"]["files"].items():
        entries[f"{NATIVE_CREDENTIAL_HELPER_APP_NAME}/{relative}"] = record
    for name, payload, mode in (
        ("SecureSandboxAuthorizationUI.bundle.json",
         "authorization_ui_bundle", 0o444),
        ("SecureSandboxNativeComponents.bundle.json",
         "native_credential_helper_bundle", 0o444),
        ("SecureSandboxNativeStackBackend",
         "native_stack_credential_client", 0o555),
        ("SecureSandboxNativeProjectionConsumer",
         "native_projection_consumer", 0o555),
    ):
        raw = values[payload]
        entries[name] = {
            "mode": mode, "sha256": sha256_bytes(raw), "size": len(raw),
        }
    return entries


_VERIFIED_NATIVE_HOST_PRODUCT_CONTAINERS: set[tuple[str, ...]] = set()


def verify_native_host_products_container(
    values: Mapping[str, bytes],
) -> None:
    """Verify the exact stapled carrier and its independently bound contents.

    The JSON receipt is audit metadata only.  Authority comes from the exact
    Developer-ID-signed DMG, its stapled ticket, the inner canonical manifest,
    and independent signature/hash verification of every mounted product.
    """
    container = values["native_host_products_container"]
    manifest_data = values["native_host_products_manifest"]
    receipt_data = values["native_host_products_notarization"]
    manifest = native_host_products_manifest(manifest_data)
    receipt = native_host_products_notarization(receipt_data)
    expected_entries = expected_native_host_product_entries(values)
    if manifest["entries"] != expected_entries:
        raise ReleaseFailure("native_host_products_inventory_mismatch")
    authorization = authorization_ui_bundle_manifest(
        values["authorization_ui_bundle"]
    )
    native = native_components_manifest(
        values["native_credential_helper_bundle"]
    )
    enforce_native_component_signer_alignment(native, authorization)
    team = native["signing_policy"]["team_id"]
    if (receipt["container_sha256"] != sha256_bytes(container)
            or receipt["container_size"] != len(container)
            or receipt["team_id"] != team):
        raise ReleaseFailure("native_host_products_notarization_mismatch")
    cache_key = tuple(sha256_bytes(values[name]) for name in (
        "native_host_products_container", "native_host_products_manifest",
        "native_host_products_notarization", "authorization_ui_bundle",
        "native_credential_helper_bundle", "native_stack_credential_client",
        "native_projection_consumer",
    ))
    if cache_key in _VERIFIED_NATIVE_HOST_PRODUCT_CONTAINERS:
        return

    requirement = (
        f'identifier "{NATIVE_HOST_PRODUCTS_CONTAINER_IDENTIFIER}" '
        "and anchor apple generic "
        f'and certificate leaf[subject.OU] = "{team}" '
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )
    with tempfile.TemporaryDirectory(
        prefix="secure-sandbox-native-host-products-"
    ) as temporary:
        root = Path(temporary)
        snapshot = root / "SecureSandboxNativeHostProducts.dmg"
        descriptor = os.open(
            snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400,
        )
        try:
            write_all(descriptor, container, "native_host_products_container")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
        for command, failure in (
            (["/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
              f"-R={requirement}", str(snapshot)],
             "native_host_products_container_signature_invalid"),
            (["/usr/bin/xcrun", "stapler", "validate", str(snapshot)],
             "native_host_products_container_ticket_invalid"),
            (["/usr/bin/hdiutil", "verify", str(snapshot)],
             "native_host_products_container_image_invalid"),
            (["/usr/sbin/spctl", "--assess", "--type", "open",
              "--context", "context:primary-signature", "--verbose=4",
              str(snapshot)],
             "native_host_products_gatekeeper_rejected"),
        ):
            completed = subprocess.run(
                command, check=False, capture_output=True, timeout=120,
            )
            if completed.returncode != 0:
                raise ReleaseFailure(failure)

        mount = root / "mount"
        mount.mkdir(mode=0o700)
        attached_device: str | None = None
        try:
            attached = subprocess.run(
                ["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse",
                 "-noautoopen", "-mountpoint", str(mount), "-plist",
                 str(snapshot)],
                check=False, capture_output=True, timeout=120,
            )
            if attached.returncode != 0:
                raise ReleaseFailure("native_host_products_mount_failed")
            try:
                attach_value = plistlib.loads(attached.stdout)
            except plistlib.InvalidFileException as error:
                raise ReleaseFailure("native_host_products_mount_invalid") from error
            entities = (attach_value.get("system-entities")
                        if isinstance(attach_value, dict) else None)
            mounted = [
                entity for entity in entities or []
                if isinstance(entity, dict) and "mount-point" in entity
            ]
            if (len(mounted) != 1
                    or mounted[0].get("mount-point") != str(mount)
                    or not isinstance(mounted[0].get("dev-entry"), str)
                    or re.fullmatch(
                        r"/dev/disk[0-9]+(?:s[0-9]+)?",
                        mounted[0]["dev-entry"],
                    ) is None):
                raise ReleaseFailure("native_host_products_mount_invalid")
            attached_device = mounted[0]["dev-entry"]
            actual_files: set[str] = set()
            actual_directories: set[str] = set()
            for item in mount.rglob("*"):
                relative = item.relative_to(mount).as_posix()
                info = item.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise ReleaseFailure("native_host_products_entry_invalid")
                if stat.S_ISDIR(info.st_mode):
                    actual_directories.add(relative)
                elif stat.S_ISREG(info.st_mode):
                    actual_files.add(relative)
                else:
                    raise ReleaseFailure("native_host_products_entry_invalid")
            expected_files = set(expected_entries) | {
                NATIVE_HOST_PRODUCTS_INNER_MANIFEST_NAME
            }
            expected_directories = {
                Path(*Path(relative).parts[:index]).as_posix()
                for relative in expected_files
                for index in range(1, len(Path(relative).parts))
            }
            if (actual_files != expected_files
                    or actual_directories != expected_directories):
                raise ReleaseFailure("native_host_products_entries_invalid")
            if read_regular(
                mount / NATIVE_HOST_PRODUCTS_INNER_MANIFEST_NAME
            ) != manifest_data:
                raise ReleaseFailure("native_host_products_manifest_mismatch")
            for relative, record in expected_entries.items():
                path = mount / relative
                info = path.lstat()
                raw = read_regular(path)
                if (stat.S_IMODE(info.st_mode) != record["mode"]
                        or len(raw) != record["size"]
                        or sha256_bytes(raw) != record["sha256"]):
                    raise ReleaseFailure(
                        "native_host_products_member_invalid:" + relative
                    )
            verified_authorization_ui_signing_policy(
                mount / AUTHORIZATION_UI_APP_NAME,
                values["authorization_ui_bundle"],
            )
            verify_native_credential_helper_bundle(
                mount / NATIVE_CREDENTIAL_HELPER_APP_NAME,
                values["native_credential_helper_bundle"],
            )
            verify_native_component_signature(
                mount / "SecureSandboxNativeStackBackend",
                NATIVE_CREDENTIAL_BACKEND_IDENTIFIER, team,
            )
            verify_native_component_signature(
                mount / "SecureSandboxNativeProjectionConsumer",
                NATIVE_PROJECTION_CONSUMER_IDENTIFIER, team,
            )
        finally:
            if attached_device is not None:
                detached = subprocess.run(
                    ["/usr/bin/hdiutil", "detach", attached_device],
                    check=False, capture_output=True, timeout=120,
                )
                if detached.returncode != 0:
                    raise ReleaseFailure("native_host_products_detach_failed")
    _VERIFIED_NATIVE_HOST_PRODUCT_CONTAINERS.add(cache_key)


def enforce_native_component_signer_alignment(
    native_manifest: dict[str, Any], authorization_manifest: dict[str, Any],
) -> None:
    """Keep every privileged Host product in one explicit Developer ID team."""
    authorization_policy = authorization_ui_signing_policy(
        authorization_manifest
    )
    native_policy = native_manifest.get("signing_policy")
    if (authorization_policy is None
            or not isinstance(native_policy, dict)
            or native_policy.get("team_id")
                != authorization_policy.get("team_id")):
        raise ReleaseFailure("native_component_signer_mismatch")


def verify_native_component_signature(path: Path, identifier: str, team: str) -> None:
    requirement = (
        f'identifier "{identifier}" and anchor apple generic '
        f'and certificate leaf[subject.OU] = "{team}" '
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )
    signature = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)],
        check=False, capture_output=True, text=True,
    )
    requirement_result = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
         f"-R={requirement}", str(path)],
        check=False, capture_output=True, text=True,
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
        check=False, capture_output=True, text=True,
    )
    if (signature.returncode != 0 or requirement_result.returncode != 0
            or details.returncode != 0
            or f"Identifier={identifier}" not in details.stderr
            or f"TeamIdentifier={team}" not in details.stderr
            or "flags=0x10000(runtime)" not in details.stderr
            or "Signature=adhoc" in details.stderr):
        raise ReleaseFailure("native_component_signature_invalid:" + identifier)


def verify_native_credential_helper_bundle(
    root: Path, manifest_data: bytes, expected_uid: int | None = None,
) -> None:
    manifest = native_components_manifest(manifest_data)
    files = manifest["helper"]["files"]
    if root.is_symlink() or not root.is_dir():
        raise ReleaseFailure("native_credential_helper_bundle_invalid")
    root_info = root.lstat()
    if stat.S_IMODE(root_info.st_mode) != 0o555:
        raise ReleaseFailure("native_credential_helper_bundle_mode_invalid")
    if expected_uid is not None and root_info.st_uid != expected_uid:
        raise ReleaseFailure("native_credential_helper_bundle_owner_invalid")
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReleaseFailure("native_credential_helper_bundle_invalid")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
            if stat.S_IMODE(info.st_mode) != 0o555:
                raise ReleaseFailure("native_credential_helper_bundle_mode_invalid")
        elif stat.S_ISREG(info.st_mode):
            actual_files.add(relative)
        else:
            raise ReleaseFailure("native_credential_helper_bundle_invalid")
        if expected_uid is not None and info.st_uid != expected_uid:
            raise ReleaseFailure("native_credential_helper_bundle_owner_invalid")
    expected_files = set(files)
    expected_directories = {
        Path(*Path(relative).parts[:index]).as_posix()
        for relative in expected_files for index in range(1, len(Path(relative).parts))
    }
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ReleaseFailure("native_credential_helper_bundle_entries_invalid")
    for relative, record in files.items():
        path = root / relative
        info = path.lstat()
        data = read_regular(path)
        if (stat.S_IMODE(info.st_mode) != record["mode"]
                or len(data) != record["size"]
                or sha256_bytes(data) != record["sha256"]):
            raise ReleaseFailure("native_credential_helper_bundle_member_invalid:" + relative)
    try:
        information = plistlib.loads(read_regular(root / "Contents/Info.plist"))
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("native_credential_helper_info_invalid") from error
    if (set(information) != {
            "CFBundleDevelopmentRegion", "CFBundleDisplayName",
            "CFBundleExecutable", "CFBundleIdentifier",
            "CFBundleInfoDictionaryVersion", "CFBundleName",
            "CFBundlePackageType", "CFBundleShortVersionString",
            "CFBundleVersion", "LSBackgroundOnly", "LSUIElement",
        }
            or information.get("CFBundleIdentifier") != NATIVE_CREDENTIAL_HELPER_LABEL
            or information.get("CFBundleExecutable")
                != NATIVE_CREDENTIAL_HELPER_EXECUTABLE.name
            or information.get("CFBundlePackageType") != "APPL"
            or information.get("LSBackgroundOnly") is not True
            or information.get("LSUIElement") is not True):
        raise ReleaseFailure("native_credential_helper_info_invalid")
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(root)],
        check=False, capture_output=True,
    )
    try:
        entitlement_value = plistlib.loads(entitlements.stdout)
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("native_credential_helper_entitlements_invalid") from error
    if entitlement_value != {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.client": True,
        "com.apple.security.network.server": True,
        "com.apple.security.temporary-exception.files.absolute-path.read-only": [
            "/usr/local/libexec/secure-sandbox-host/",
            "/usr/local/var/lib/secure-sandbox/native-credential-tickets/",
        ],
    }:
        raise ReleaseFailure("native_credential_helper_entitlements_invalid")
    verify_native_component_signature(
        root, NATIVE_CREDENTIAL_HELPER_LABEL, manifest["signing_policy"]["team_id"]
    )


def copy_native_credential_helper_bundle(
    source: Path, destination: Path, manifest_data: bytes, expected_uid: int,
) -> None:
    verify_native_credential_helper_bundle(source, manifest_data)
    manifest = native_components_manifest(manifest_data)
    destination.mkdir(mode=0o755)
    directories = sorted({
        Path(*Path(relative).parts[:index])
        for relative in manifest["helper"]["files"]
        for index in range(1, len(Path(relative).parts))
    }, key=lambda path: (len(path.parts), path.as_posix()))
    for relative in directories:
        (destination / relative).mkdir(mode=0o755)
    for relative, record in manifest["helper"]["files"].items():
        data = read_regular(source / relative)
        path = destination / relative
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, record["mode"])
        try:
            write_all(descriptor, data, "native_credential_bundle_member")
            os.fsync(descriptor)
            os.fchmod(descriptor, record["mode"])
        finally:
            os.close(descriptor)
    for relative in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        os.chmod(destination / relative, 0o555)
        fsync_directory(destination / relative)
    os.chmod(destination, 0o555)
    verify_native_credential_helper_bundle(destination, manifest_data, expected_uid)


def enforce_release_developer_id_team_floor(
    install_root: Path, release_path: Path, payloads: Mapping[str, str],
    expected_uid: int,
) -> tuple[dict[str, Any], str]:
    observed = developer_id_team_floor(install_root, expected_uid)
    if observed is None:
        raise ReleaseFailure("developer_id_team_floor_missing")
    floor, floor_sha256 = observed
    if ("authorization_ui_bundle" not in payloads
            or not NATIVE_HOST_PRODUCT_CONTAINER_PAYLOAD_NAMES
                <= set(payloads)):
        raise ReleaseFailure("release_below_developer_id_team_floor")
    manifest_data = read_regular(release_path / "authorization_ui_bundle")
    policy = verified_authorization_ui_signing_policy(
        release_path / AUTHORIZATION_UI_APP_NAME,
        manifest_data,
        expected_uid,
    )
    if policy["team_id"] != floor["team_id"]:
        raise ReleaseFailure("release_developer_id_team_mismatch")
    return floor, floor_sha256


def prepare_developer_id_team_floor(
    repo: Path, install_root: Path, expected_uid: int,
    values: Mapping[str, bytes], release_id: str, *, now: int | None = None,
) -> tuple[dict[str, Any], str]:
    """Establish only from the already-installed signed v2 release.

    An empty machine is intentionally not trust-on-first-use.  Its initial
    Developer ID team requires a separate out-of-band bootstrap ceremony.
    """
    candidate_manifest = values.get("authorization_ui_bundle")
    if not isinstance(candidate_manifest, bytes):
        raise ReleaseFailure("candidate_authorization_ui_missing")
    candidate_policy = verified_authorization_ui_signing_policy(
        repo / AUTHORIZATION_UI_APP_SOURCE, candidate_manifest,
    )
    existing = developer_id_team_floor(
        install_root, expected_uid, allow_absent=True,
    )
    current = install_root / "current"
    if existing is None:
        if not current.is_symlink():
            if current.exists():
                raise ReleaseFailure("release_link_invalid:current")
            raise ReleaseFailure("developer_id_team_floor_bootstrap_required")
        trusted_path, trusted_manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
        )
        trusted_manifest_data = read_regular(
            trusted_path / "authorization_ui_bundle"
        )
        trusted_policy = verified_authorization_ui_signing_policy(
            trusted_path / AUTHORIZATION_UI_APP_NAME,
            trusted_manifest_data,
            expected_uid,
        )
        if candidate_policy["team_id"] != trusted_policy["team_id"]:
            raise ReleaseFailure("release_developer_id_team_mismatch")
        record = developer_id_floor_record(
            release_id=trusted_manifest["release_id"],
            authorization_manifest=trusted_manifest_data,
            policy=trusted_policy,
            established_at=int(time.time()) if now is None else now,
        )
        existing = create_developer_id_team_floor(
            install_root, expected_uid, record,
        )
    floor, floor_sha256 = existing
    if candidate_policy["team_id"] != floor["team_id"]:
        raise ReleaseFailure("release_developer_id_team_mismatch")
    if current.is_symlink():
        verified_release(install_root, current, expected_uid, allow_legacy=True)
    elif current.exists():
        raise ReleaseFailure("release_link_invalid:current")
    return floor, floor_sha256


def require_developer_id_team_floor_unchanged(
    install_root: Path, expected_uid: int, expected_sha256: str,
) -> tuple[dict[str, Any], str]:
    observed = developer_id_team_floor(install_root, expected_uid)
    if observed is None or not hmac.compare_digest(observed[1], expected_sha256):
        raise ReleaseFailure("developer_id_team_floor_changed")
    return observed


def validate_native_components_payload(repo: Path, values: dict[str, bytes]) -> None:
    manifest_data = values["native_credential_helper_bundle"]
    manifest = native_components_manifest(manifest_data)
    authorization_manifest = authorization_ui_bundle_manifest(
        values["authorization_ui_bundle"]
    )
    enforce_native_component_signer_alignment(
        manifest, authorization_manifest
    )
    for payload, record_name, identifier in (
        ("native_stack_credential_client", "backend", NATIVE_CREDENTIAL_BACKEND_IDENTIFIER),
        ("native_projection_consumer", "consumer", NATIVE_PROJECTION_CONSUMER_IDENTIFIER),
    ):
        value = values[payload]
        record = manifest[record_name]
        if len(value) != record["size"] or sha256_bytes(value) != record["sha256"]:
            raise ReleaseFailure("native_component_payload_mismatch:" + payload)
        verify_native_component_signature(
            repo / PAYLOAD_SOURCES[payload], identifier,
            manifest["signing_policy"]["team_id"],
        )
    verify_native_credential_helper_bundle(
        repo / NATIVE_CREDENTIAL_HELPER_APP_SOURCE, manifest_data
    )
    try:
        service = plistlib.loads(values["native_credential_helper_service"])
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("native_credential_helper_service_invalid") from error
    if (set(service) != {
            "Label", "ProgramArguments", "MachServices",
            "LimitLoadToSessionType", "ProcessType", "RunAtLoad",
        }
            or service.get("Label") != NATIVE_CREDENTIAL_HELPER_LABEL
            or service.get("ProgramArguments")
                != [NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH]
            or service.get("MachServices")
                != {NATIVE_CREDENTIAL_HELPER_LABEL: True}
            or service.get("LimitLoadToSessionType") != ["Aqua"]
            or service.get("ProcessType") != "Interactive"
            or service.get("RunAtLoad") is not False):
        raise ReleaseFailure("native_credential_helper_service_invalid")


def execution_approval_floor(expected_uid: int = 0,
                             path: Path | None = None) -> tuple[int, int]:
    path = EXECUTION_APPROVAL_FLOOR if path is None else path
    try:
        info = path.lstat()
    except FileNotFoundError:
        return 1, 0
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        expected = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    except (OSError, UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("execution_approval_floor_invalid") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or raw != expected
            or not isinstance(value, dict)
            or set(value) != {"schema", "minimum_protocol", "minimum_epoch", "updated_at"}
            or value.get("schema") != "secure-sandbox-execution-approval-floor-v1"
            or value.get("minimum_protocol") not in {1, 2}
            or not isinstance(value.get("minimum_epoch"), int)
            or isinstance(value.get("minimum_epoch"), bool)
            or value["minimum_epoch"] < 0):
        raise ReleaseFailure("execution_approval_floor_invalid")
    return value["minimum_protocol"], value["minimum_epoch"]


def enforce_execution_approval_floor(broker: bytes, expected_uid: int = 0) -> None:
    minimum_protocol, _minimum_epoch = execution_approval_floor(expected_uid)
    if minimum_protocol >= 2 and EXECUTION_APPROVAL_V2_CAPABILITY not in broker:
        raise ReleaseFailure("release_below_execution_approval_floor")


def native_stack_support_archive(repo: Path) -> bytes:
    """Build the deterministic immutable Python closure for native actions."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for archive_name, relative in sorted(NATIVE_STACK_SUPPORT_SOURCES.items()):
            data = read_regular(repo / relative)
            try:
                compile(data, str(repo / relative), "exec")
            except SyntaxError as error:
                raise ReleaseFailure("native_stack_support_syntax_invalid") from error
            info = zipfile.ZipInfo(archive_name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o444) << 16
            info.flag_bits = 0
            archive.writestr(info, data)
    value = output.getvalue()
    if not 1024 <= len(value) <= 2 * 1024 * 1024:
        raise ReleaseFailure("native_stack_support_size_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(value), "r") as archive:
            if archive.namelist() != sorted(NATIVE_STACK_SUPPORT_SOURCES):
                raise ReleaseFailure("native_stack_support_inventory_invalid")
            if any(
                archive.read(name) != read_regular(repo / NATIVE_STACK_SUPPORT_SOURCES[name])
                for name in archive.namelist()
            ):
                raise ReleaseFailure("native_stack_support_content_invalid")
    except zipfile.BadZipFile as error:
        raise ReleaseFailure("native_stack_support_archive_invalid") from error
    return value


def source_payload(
    repo: Path,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> tuple[dict[str, bytes], dict[str, str], str]:
    values = {name: read_regular(repo / relative) for name, relative in PAYLOAD_SOURCES.items()}
    values["native_stack_support"] = native_stack_support_archive(repo)
    try:
        config_path = repo / ".private/secure-enclave-ddd.json"
        repo_info = repo.lstat()
        config_info = config_path.lstat()
        config = json.loads(read_regular(config_path))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("secure_enclave_local_config_invalid") from error
    legacy_digest = config.get("legacy_launchservices_ui_bundle_sha256")
    if (not stat.S_ISDIR(repo_info.st_mode) or stat.S_ISLNK(repo_info.st_mode)
            or repo_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not stat.S_ISREG(config_info.st_mode) or stat.S_ISLNK(config_info.st_mode)
            or config_info.st_uid != repo_info.st_uid or config_info.st_nlink != 1
            or stat.S_IMODE(config_info.st_mode) != 0o600
            or config.get("schema") != "secure-sandbox-secure-enclave-ddd-local-config-v1"
            or not isinstance(legacy_digest, str) or SHA256.fullmatch(legacy_digest) is None):
        raise ReleaseFailure("secure_enclave_local_config_invalid")
    broker = values["authorization_broker"]
    marker = b"__LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256__"
    if broker.count(marker) != 1:
        raise ReleaseFailure("authorization_broker_template_invalid")
    values["authorization_broker"] = broker.replace(marker, legacy_digest.encode("ascii"))
    resolved_gpgv = gpgv_binary.resolve(strict=True)
    gpgv_bytes = read_regular(resolved_gpgv)
    values["gpgv"] = gpgv_bytes
    verifier = values["installer_verifier"]
    if verifier.count(b"__GPGV_SHA256__") != 1:
        raise ReleaseFailure("installer_verifier_template_invalid")
    values["installer_verifier"] = verifier.replace(
        b"__GPGV_SHA256__", sha256_bytes(gpgv_bytes).encode("ascii")
    )
    native_service_marker = (
        b"__SECURE_SANDBOX_NATIVE_CREDENTIAL_HELPER_EXECUTABLE__"
    )
    native_service = values["native_credential_helper_service"]
    if native_service.count(native_service_marker) != 1:
        raise ReleaseFailure("native_credential_helper_service_template_invalid")
    values["native_credential_helper_service"] = native_service.replace(
        native_service_marker,
        NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH.encode("ascii"),
    )
    validate_touchid_payload(repo, values)
    validate_native_components_payload(repo, values)
    verify_native_host_products_container(values)
    try:
        compile(values["control_client"], str(repo / PAYLOAD_SOURCES["control_client"]), "exec")
        compile(values["authorization_broker"], str(repo / PAYLOAD_SOURCES["authorization_broker"]), "exec")
        compile(values["harness_lifecycle_manager"], str(repo / PAYLOAD_SOURCES["harness_lifecycle_manager"]), "exec")
        compile(values["native_stack_manager"], str(repo / PAYLOAD_SOURCES["native_stack_manager"]), "exec")
        compile(
            values["native_stack_session_manager"],
            str(repo / PAYLOAD_SOURCES["native_stack_session_manager"]),
            "exec",
        )
        compile(values["native_stack_backend"], str(repo / PAYLOAD_SOURCES["native_stack_backend"]), "exec")
        compile(values["native_stack_terminal_bridge"], str(repo / PAYLOAD_SOURCES["native_stack_terminal_bridge"]), "exec")
        compile(values["native_stack_catalog_promoter"], str(repo / PAYLOAD_SOURCES["native_stack_catalog_promoter"]), "exec")
        compile(values["pki_anchor"], str(repo / PAYLOAD_SOURCES["pki_anchor"]), "exec")
        compile(values["release_manager"], str(repo / PAYLOAD_SOURCES["release_manager"]), "exec")
        compile(values["installer_verifier"], str(repo / PAYLOAD_SOURCES["installer_verifier"]), "exec")
        compile(values["seed_verifier"], str(repo / PAYLOAD_SOURCES["seed_verifier"]), "exec")
        compile(values["vm_maintenance"], str(repo / PAYLOAD_SOURCES["vm_maintenance"]), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("python_payload_syntax_invalid") from error
    hashes = {name: sha256_bytes(value) for name, value in values.items()}
    return values, hashes, release_identity(hashes)


def validate_touchid_payload(repo: Path, values: dict[str, bytes]) -> None:
    try:
        source_manifest = json.loads(values["authorization_ui_sources"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("authorization_ui_source_manifest_invalid") from error
    if (source_manifest.get("schema") != "secure-sandbox-touchid-ui-source-v1"
            or set(source_manifest.get("sources", {}))
            != AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES):
        raise ReleaseFailure("authorization_ui_source_manifest_invalid")
    package = repo / "macos/TouchIDAuthorization"
    for name, expected in source_manifest["sources"].items():
        if (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or sha256_bytes(read_regular(package / name)) != expected):
            raise ReleaseFailure(f"authorization_ui_source_mismatch:{name}")
    try:
        service = plistlib.loads(values["authorization_service"])
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("authorization_service_plist_invalid") from error
    expected_arguments = [
        "/usr/bin/python3", "-I",
        "/usr/local/libexec/secure-sandbox-host/current/authorization_broker",
        "serve-touchid",
    ]
    if (service.get("Label") != AUTHORIZATION_LABEL
            or service.get("ProgramArguments") != expected_arguments
            or service.get("RunAtLoad") is not True or service.get("KeepAlive") is not True):
        raise ReleaseFailure("authorization_service_plist_invalid")
    bundle = repo / AUTHORIZATION_UI_APP_SOURCE
    bundle_manifest = authorization_ui_bundle_manifest(values["authorization_ui_bundle"])
    verify_authorization_ui_bundle(bundle, values["authorization_ui_bundle"])
    binary = bundle / AUTHORIZATION_UI_EXECUTABLE
    signature = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(bundle)],
        check=False, capture_output=True, text=True,
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(bundle)],
        check=False, capture_output=True, text=True,
    )
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(bundle)],
        check=False, capture_output=True,
    )
    try:
        entitlement_value = plistlib.loads(entitlements.stdout)
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("authorization_ui_entitlements_invalid") from error
    policy = authorization_ui_signing_policy(bundle_manifest)
    if policy is None:
        team = entitlement_value.get("com.apple.developer.team-identifier")
        bundle_id = "org.zebeth.SecureSandbox.AuthorizationUI"
        application_identifier = team + "." + bundle_id if isinstance(team, str) else ""
        if not isinstance(team, str) or re.fullmatch(r"[A-Z0-9]{10}", team) is None:
            raise ReleaseFailure("authorization_ui_signature_invalid")
        policy = {"team_id":team, "bundle_id":bundle_id,
                  "application_identifier":application_identifier,
                  "access_group":application_identifier}
    expected_entitlements = {
        "com.apple.application-identifier":policy["application_identifier"],
        "com.apple.developer.team-identifier":policy["team_id"],
        "keychain-access-groups":[policy["access_group"]],
    }
    requirement = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
         f'-R=identifier "{policy["bundle_id"]}" and anchor apple generic and certificate leaf[subject.OU] = "{policy["team_id"]}"',
         str(bundle)],
        check=False, capture_output=True, text=True,
    )
    profile = subprocess.run(
        ["/usr/bin/security", "cms", "-D", "-i",
         str(bundle / "Contents/embedded.provisionprofile")],
        check=False, capture_output=True,
    )
    try:
        profile_value = plistlib.loads(profile.stdout)
        profile_entitlements = profile_value["Entitlements"]
        expiration = profile_value["ExpirationDate"]
    except (KeyError, TypeError, plistlib.InvalidFileException) as error:
        raise ReleaseFailure("authorization_ui_profile_invalid") from error
    profile_valid = (
        profile.returncode == 0
        and profile_value.get("Platform") == ["OSX"]
        and profile_value.get("ApplicationIdentifierPrefix") == [policy["team_id"]]
        and profile_value.get("TeamIdentifier") == [policy["team_id"]]
        and profile_entitlements.get("com.apple.application-identifier")
            == policy["application_identifier"]
        and profile_entitlements.get("com.apple.developer.team-identifier") == policy["team_id"]
        and profile_entitlements.get("keychain-access-groups") == [policy["team_id"] + ".*"]
        and isinstance(expiration, datetime.datetime)
        and expiration.replace(tzinfo=datetime.timezone.utc) >
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=48)
    )
    if (signature.returncode != 0 or details.returncode != 0
            or requirement.returncode != 0 or entitlements.returncode != 0
            or "runtime" not in details.stderr
            or f'TeamIdentifier={policy["team_id"]}' not in details.stderr
            or f'Identifier={policy["bundle_id"]}' not in details.stderr
            or entitlement_value != expected_entitlements or not profile_valid):
        raise ReleaseFailure("authorization_ui_signature_invalid")


def invoking_home() -> Path:
    name = os.environ.get("SUDO_USER")
    if name:
        return Path(pwd.getpwnam(name).pw_dir)
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def active_markers(state_root: Path) -> list[str]:
    if state_root.exists() and (state_root.is_symlink() or not state_root.is_dir()):
        raise ReleaseFailure("controller_state_directory_invalid")
    active = state_root / "active"
    if not active.exists():
        return []
    if active.is_symlink() or not active.is_dir():
        raise ReleaseFailure("active_marker_directory_invalid")
    markers = list(active.iterdir())
    if len(markers) > MAX_ACTIVE_MARKERS:
        raise ReleaseFailure("active_marker_limit_exceeded")
    live: list[str] = []
    for marker in markers:
        if marker.is_symlink() or not marker.is_file():
            raise ReleaseFailure("active_marker_invalid")
        try:
            value = json.loads(marker.read_text(encoding="ascii"))
            pid = value["pid"]
            release_id = value["release_id"]
            if not isinstance(pid, int) or pid <= 1 or not isinstance(release_id, str) or not SHA256.fullmatch(release_id):
                raise ValueError
            os.kill(pid, 0)
            live.append(marker.name)
        except ProcessLookupError:
            marker.unlink()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            raise ReleaseFailure(f"active_marker_unreadable:{marker.name}") from error
    return live


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def canonical_state_record(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReleaseFailure("install_transition_record_invalid") from error


def open_trusted_absolute_directory(
    path: Path, expected_uid: int, *, final_mode: int = 0o755,
) -> int:
    """Open a root-anchored directory chain without following mutable links."""
    if not path.is_absolute() or path == Path("/"):
        raise ReleaseFailure("install_transition_parent_untrusted")
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise ReleaseFailure("install_transition_parent_untrusted")
        info = os.fstat(descriptor)
        current = path.lstat()
        if ((info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
                or stat.S_ISLNK(current.st_mode)
                or stat.S_IMODE(info.st_mode) != final_mode):
            raise ReleaseFailure("install_transition_parent_untrusted")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_state_record_at(
    directory_descriptor: int,
    name: str,
    expected_uid: int,
    mode: int,
    *,
    limit: int = INSTALL_TRANSITION_RECORD_LIMIT,
) -> tuple[dict[str, Any], bytes, os.stat_result]:
    if (not isinstance(name, str) or len(name) > 160
            or re.fullmatch(r"[A-Za-z0-9._-]+", name) is None
            or name in {".", ".."}):
        raise ReleaseFailure("install_transition_record_name_invalid")
    try:
        before = os.stat(
            name, dir_fd=directory_descriptor, follow_symlinks=False,
        )
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise ReleaseFailure("install_transition_record_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        parent = os.fstat(directory_descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                    != (before.st_dev, before.st_ino)
                or opened.st_uid != expected_uid or opened.st_gid != parent.st_gid
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != mode
                or not 2 <= opened.st_size <= limit):
            raise ReleaseFailure("install_transition_record_untrusted")
        raw = os.read(descriptor, limit + 1)
        if len(raw) != opened.st_size or len(raw) > limit or os.read(descriptor, 1):
            raise ReleaseFailure("install_transition_record_untrusted")
    finally:
        os.close(descriptor)
    after = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or after.st_nlink != 1):
        raise ReleaseFailure("install_transition_record_changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("install_transition_record_invalid") from error
    if not isinstance(value, dict) or canonical_state_record(value) != raw:
        raise ReleaseFailure("install_transition_record_invalid")
    return value, raw, opened


def write_new_state_record_at(
    directory_descriptor: int,
    name: str,
    value: Mapping[str, Any],
    expected_uid: int,
    mode: int,
) -> bytes:
    if (not isinstance(name, str) or len(name) > 160
            or re.fullmatch(r"[A-Za-z0-9._-]+", name) is None
            or name in {".", ".."}):
        raise ReleaseFailure("install_transition_record_name_invalid")
    raw = canonical_state_record(dict(value))
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=directory_descriptor,
    )
    try:
        parent = os.fstat(directory_descriptor)
        os.fchown(descriptor, expected_uid, parent.st_gid)
        os.fchmod(descriptor, mode)
        write_all(descriptor, raw, "install_transition_record")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_descriptor)
    return raw


def replace_state_record_at(
    directory_descriptor: int,
    name: str,
    value: Mapping[str, Any],
    expected_uid: int,
    mode: int,
) -> bytes:
    if (not isinstance(name, str) or len(name) > 160
            or re.fullmatch(r"[A-Za-z0-9._-]+", name) is None
            or name in {".", ".."}):
        raise ReleaseFailure("install_transition_record_name_invalid")
    raw = canonical_state_record(dict(value))
    temporary = f".{name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=directory_descriptor,
    )
    try:
        parent = os.fstat(directory_descriptor)
        os.fchown(descriptor, expected_uid, parent.st_gid)
        os.fchmod(descriptor, mode)
        write_all(descriptor, raw, "install_transition_record")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(
            temporary, name,
            src_dir_fd=directory_descriptor, dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        raise
    return raw


def open_install_transition_directory(
    install_root_descriptor: int, expected_uid: int,
) -> int:
    try:
        os.mkdir(
            INSTALL_TRANSITION_DIRECTORY_NAME, 0o755,
            dir_fd=install_root_descriptor,
        )
        os.fsync(install_root_descriptor)
    except FileExistsError:
        pass
    descriptor = os.open(
        INSTALL_TRANSITION_DIRECTORY_NAME,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=install_root_descriptor,
    )
    info = os.fstat(descriptor)
    parent = os.fstat(install_root_descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or info.st_gid != parent.st_gid or stat.S_IMODE(info.st_mode) != 0o755):
        os.close(descriptor)
        raise ReleaseFailure("install_transition_directory_untrusted")
    return descriptor


def publish_terminal_state_record(
    install_root_descriptor: int,
    terminal: Mapping[str, Any],
    expected_uid: int,
) -> bytes:
    transition_id = _validated_uuid4(
        terminal.get("transition_id"), "install_transition_id",
    )
    final_name = f"{transition_id}.json"
    directory = open_install_transition_directory(
        install_root_descriptor, expected_uid,
    )
    try:
        raw = canonical_state_record(dict(terminal))
        pending_name = f".{transition_id}.pending"
        parent = os.fstat(directory)

        def information(name: str) -> os.stat_result | None:
            try:
                return os.stat(
                    name, dir_fd=directory, follow_symlinks=False,
                )
            except FileNotFoundError:
                return None

        def exact_inode(name: str, info: os.stat_result, links: int) -> bool:
            descriptor = -1
            try:
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory,
                )
                opened = os.fstat(descriptor)
                observed = os.read(descriptor, len(raw) + 1)
                return (
                    stat.S_ISREG(opened.st_mode)
                    and (opened.st_dev, opened.st_ino)
                        == (info.st_dev, info.st_ino)
                    and opened.st_uid == expected_uid
                    and opened.st_gid == parent.st_gid
                    and opened.st_nlink == links
                    and stat.S_IMODE(opened.st_mode) == 0o444
                    and observed == raw and not os.read(descriptor, 1)
                )
            except OSError:
                return False
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

        final_info = information(final_name)
        pending_info = information(pending_name)
        if final_info is not None:
            if final_info.st_nlink == 2:
                if (pending_info is None
                        or (final_info.st_dev, final_info.st_ino)
                            != (pending_info.st_dev, pending_info.st_ino)
                        or not exact_inode(final_name, final_info, 2)):
                    raise ReleaseFailure("install_transition_terminal_conflict")
                os.unlink(pending_name, dir_fd=directory)
                os.fsync(directory)
            else:
                if (not exact_inode(final_name, final_info, 1)
                        or pending_info is not None):
                    raise ReleaseFailure("install_transition_terminal_conflict")
            existing, existing_raw, _ = read_state_record_at(
                directory, final_name, expected_uid, 0o444,
            )
            if existing != dict(terminal) or existing_raw != raw:
                raise ReleaseFailure("install_transition_terminal_conflict")
            return raw

        staging_name = f".{transition_id}.staging"
        staging_info = information(staging_name)
        if pending_info is not None and pending_info.st_nlink == 2:
            if (staging_info is None
                    or (pending_info.st_dev, pending_info.st_ino)
                        != (staging_info.st_dev, staging_info.st_ino)
                    or not exact_inode(pending_name, pending_info, 2)):
                raise ReleaseFailure("install_transition_terminal_conflict")
            os.unlink(staging_name, dir_fd=directory)
            os.fsync(directory)
            pending_info = information(pending_name)
            staging_info = None
        if pending_info is None:
            if staging_info is not None:
                if (not stat.S_ISREG(staging_info.st_mode)
                        or staging_info.st_uid != expected_uid
                        or staging_info.st_gid != parent.st_gid
                        or staging_info.st_nlink != 1):
                    raise ReleaseFailure("install_transition_terminal_conflict")
                # A staging inode is never authority.  A partial crash write is
                # safely discarded; a complete one may be rebuilt identically.
                os.unlink(staging_name, dir_fd=directory)
                os.fsync(directory)
            write_new_state_record_at(
                directory, staging_name, terminal, expected_uid, 0o600,
            )
            staging_descriptor = os.open(
                staging_name,
                os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            try:
                staging_opened = os.fstat(staging_descriptor)
                staging_raw = os.read(staging_descriptor, len(raw) + 1)
                if (staging_raw != raw or os.read(staging_descriptor, 1)
                        or staging_opened.st_nlink != 1):
                    raise ReleaseFailure("install_transition_terminal_conflict")
                os.fchmod(staging_descriptor, 0o444)
                os.fsync(staging_descriptor)
            finally:
                os.close(staging_descriptor)
            os.link(
                staging_name, pending_name,
                src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False,
            )
            os.fsync(directory)
            os.unlink(staging_name, dir_fd=directory)
            os.fsync(directory)
            pending_info = information(pending_name)
        if (pending_info is None or not stat.S_ISREG(pending_info.st_mode)
                or pending_info.st_uid != expected_uid
                or pending_info.st_gid != parent.st_gid
                or pending_info.st_nlink != 1
                or stat.S_IMODE(pending_info.st_mode) != 0o444
                or not exact_inode(pending_name, pending_info, 1)):
            raise ReleaseFailure("install_transition_terminal_conflict")
        pending_descriptor = os.open(
            pending_name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
        try:
            opened = os.fstat(pending_descriptor)
            observed = os.read(pending_descriptor, len(raw) + 1)
            if ((opened.st_dev, opened.st_ino)
                    != (pending_info.st_dev, pending_info.st_ino)
                    or observed != raw or os.read(pending_descriptor, 1)):
                raise ReleaseFailure("install_transition_terminal_conflict")
        finally:
            os.close(pending_descriptor)
        os.link(
            pending_name, final_name,
            src_dir_fd=directory, dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.fsync(directory)
        os.unlink(pending_name, dir_fd=directory)
        os.fsync(directory)
        observed, observed_raw, _ = read_state_record_at(
            directory, final_name, expected_uid, 0o444,
        )
        if observed != dict(terminal) or observed_raw != raw:
            raise ReleaseFailure("install_transition_terminal_readback_failed")
        return raw
    finally:
        os.close(directory)


def manages_live_touchid_service(install_root: Path, expected_uid: int) -> bool:
    return expected_uid == 0 and install_root == DEFAULT_INSTALL_ROOT


def stop_touchid_service(plist_path: Path = DEFAULT_AUTHORIZATION_PLIST) -> None:
    stop_launchd_service_exact(
        "system", AUTHORIZATION_LABEL, plist_path,
    )


def touchid_service_is_loaded() -> bool:
    inspected = subprocess.run(
        ["/bin/launchctl", "print", f"system/{AUTHORIZATION_LABEL}"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return inspected.returncode == 0


def restart_touchid_service() -> None:
    restarted = subprocess.run(
        ["/bin/launchctl", "kickstart", "-k", f"system/{AUTHORIZATION_LABEL}"],
        check=False, capture_output=True, text=True,
    )
    if restarted.returncode != 0:
        raise ReleaseFailure(
            "authorization_service_restart_failed:" + restarted.stderr.strip()[:240]
        )
    if not touchid_service_is_loaded():
        raise ReleaseFailure("authorization_service_restart_verification_failed")


def install_touchid_service(release: Path,
                            plist_path: Path = DEFAULT_AUTHORIZATION_PLIST) -> None:
    source = release / "authorization_service"
    data = read_regular(source)
    temporary = plist_path.parent / f".{plist_path.name}.new-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise ReleaseFailure("authorization_service_short_write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
    finally:
        os.close(descriptor)
    os.replace(temporary, plist_path)
    fsync_directory(plist_path.parent)
    # Never terminate the daemon that is authorizing this release update.  Its
    # broker notices the current-release transition after it has sent the bound
    # response, exits cleanly, and launchd then starts this newly selected
    # release.  A first installation still needs an explicit bootstrap.
    if touchid_service_is_loaded():
        return
    subprocess.run(
        ["/bin/launchctl", "bootout", f"system/{AUTHORIZATION_LABEL}"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    loaded = subprocess.run(
        ["/bin/launchctl", "bootstrap", "system", str(plist_path)],
        check=False, capture_output=True, text=True,
    )
    if loaded.returncode != 0:
        raise ReleaseFailure("authorization_service_bootstrap_failed:" + loaded.stderr.strip()[:240])


def console_user_uid(console: Path = Path("/dev/console")) -> int:
    try:
        uid = console.stat().st_uid
        pwd.getpwuid(uid)
    except (OSError, KeyError) as error:
        raise ReleaseFailure("native_credential_console_user_unavailable") from error
    if uid <= 0:
        raise ReleaseFailure("native_credential_console_user_unavailable")
    return uid


def native_credential_service_is_loaded(uid: int) -> bool:
    inspected = subprocess.run(
        ["/bin/launchctl", "print",
         f"gui/{uid}/{NATIVE_CREDENTIAL_HELPER_LABEL}"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return inspected.returncode == 0


def stop_native_credential_service(
    uid: int | None = None,
    plist_path: Path = DEFAULT_NATIVE_CREDENTIAL_PLIST,
) -> None:
    uid = console_user_uid() if uid is None else uid
    stop_launchd_service_exact(
        f"gui/{uid}", NATIVE_CREDENTIAL_HELPER_LABEL, plist_path,
    )


def install_native_credential_service(
    release: Path,
    uid: int | None = None,
    plist_path: Path = DEFAULT_NATIVE_CREDENTIAL_PLIST,
) -> None:
    uid = console_user_uid() if uid is None else uid
    source = release / "native_credential_helper_service"
    data = read_regular(source)
    try:
        service = plistlib.loads(data)
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("native_credential_helper_service_invalid") from error
    if (set(service) != {
            "Label", "ProgramArguments", "MachServices",
            "LimitLoadToSessionType", "ProcessType", "RunAtLoad",
        }
            or service.get("Label") != NATIVE_CREDENTIAL_HELPER_LABEL
            or service.get("ProgramArguments")
                != [NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH]
            or service.get("MachServices")
                != {NATIVE_CREDENTIAL_HELPER_LABEL: True}
            or service.get("LimitLoadToSessionType") != ["Aqua"]
            or service.get("ProcessType") != "Interactive"
            or service.get("RunAtLoad") is not False):
        raise ReleaseFailure("native_credential_helper_service_invalid")
    # launchd does not reload a LaunchAgent definition on kickstart.  Fence the
    # exact old generation and bootstrap the candidate plist so terminal
    # verification covers the settings launchd actually admitted.
    stop_launchd_service_exact(
        f"gui/{uid}", NATIVE_CREDENTIAL_HELPER_LABEL, plist_path,
    )
    temporary = plist_path.parent / f".{plist_path.name}.new-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise ReleaseFailure("native_credential_service_short_write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)
    os.replace(temporary, plist_path)
    fsync_directory(plist_path.parent)
    loaded = subprocess.run(
        ["/bin/launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
        check=False, capture_output=True, text=True,
    )
    if loaded.returncode != 0:
        raise ReleaseFailure(
            "native_credential_service_bootstrap_failed:"
            + loaded.stderr.strip()[:240]
        )
    if not native_credential_service_is_loaded(uid):
        raise ReleaseFailure("native_credential_service_verification_failed")


def rollback_transition_checkpoint(name: str) -> None:
    """Test seam for exercising every durable rollback transition."""
    if not isinstance(name, str) or not name:
        raise ReleaseFailure("rollback_transition_invalid")


def unchanged_developer_id_floor(
    install_root: Path,
    expected_uid: int,
    signing_floor: Mapping[str, Any],
    signing_floor_sha256: str,
) -> None:
    observed = developer_id_team_floor(install_root, expected_uid)
    if (observed is None or observed[0] != signing_floor
            or observed[1] != signing_floor_sha256):
        raise ReleaseFailure("developer_id_team_floor_changed")


def selector_target(link: Path, name: str) -> str | None:
    if link.is_symlink():
        target = os.readlink(link)
        if (not isinstance(target, str)
                or not re.fullmatch(r"releases/[0-9a-f]{64}", target)):
            raise ReleaseFailure(f"release_link_invalid:{name}")
        return target
    if os.path.lexists(link):
        raise ReleaseFailure(f"release_link_invalid:{name}")
    return None


def restore_selector(link: Path, target: str | None) -> None:
    if target is None:
        if os.path.lexists(link):
            link.unlink()
            fsync_directory(link.parent)
        return
    atomic_symlink(target, link)


def launchd_service_pid_or_absent(domain: str, label: str) -> int | None:
    """Read one exact launchd-owned PID or launchd's exact absent result."""
    inspected = subprocess.run(
        ["/bin/launchctl", "print", f"{domain}/{label}"],
        check=False, capture_output=True, text=True,
    )
    if (len(inspected.stdout) > 512 * 1024
            or len(inspected.stderr) > 64 * 1024):
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    # launchctl maps the absent-service bootstrap error to EX_UNAVAILABLE.
    # No other nonzero result is safe to interpret as absence.
    if inspected.returncode == 113:
        return None
    if inspected.returncode != 0:
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    matches = re.findall(
        r"(?m)^\s*pid\s*=\s*([1-9][0-9]*)\s*$", inspected.stdout,
    )
    if len(matches) != 1:
        raise ReleaseFailure(f"host_service_pid_unproven:{label}")
    return int(matches[0])


def launchd_service_pid(domain: str, label: str) -> int:
    """Read one exact launchd-owned PID without treating argv as identity."""
    pid = launchd_service_pid_or_absent(domain, label)
    if pid is None:
        raise ReleaseFailure(f"host_service_not_loaded:{label}")
    return pid


def process_generation_or_absent(
    pid: int, label: str,
) -> tuple[int, int, int] | None:
    """Read one kernel process generation or prove that PID is absent."""
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = libproc.proc_pidinfo
        function.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
            ctypes.c_void_p, ctypes.c_int,
        ]
        function.restype = ctypes.c_int
        information = _ProcBSDInfo()
        size = ctypes.sizeof(information)
        length = function(pid, 3, 0, ctypes.byref(information), size)
    except (OSError, AttributeError) as error:
        raise ReleaseFailure(
            f"host_service_process_unproven:{label}"
        ) from error
    if length == 0:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return None
        except OSError as error:
            raise ReleaseFailure(
                f"host_service_process_unproven:{label}"
            ) from error
        raise ReleaseFailure(f"host_service_process_unproven:{label}")
    if (length != size or information.pbi_pid != pid
            or information.pbi_start_tvsec <= 0
            or information.pbi_start_tvusec >= 1_000_000):
        raise ReleaseFailure(f"host_service_process_unproven:{label}")
    return (
        int(information.pbi_uid),
        int(information.pbi_start_tvsec),
        int(information.pbi_start_tvusec),
    )


def process_generation(pid: int, label: str) -> tuple[int, int, int]:
    """Read euid and microsecond start generation in one kernel record."""
    generation = process_generation_or_absent(pid, label)
    if generation is None:
        raise ReleaseFailure(f"host_service_process_unproven:{label}")
    return generation


def stop_launchd_service_exact(
    domain: str,
    label: str,
    plist_path: Path,
    *,
    timeout: float = HOST_SERVICE_STOP_TIMEOUT_SECONDS,
) -> None:
    """Boot out one service and prove its captured process generation is gone."""
    pid = launchd_service_pid_or_absent(domain, label)
    generation: tuple[int, int, int] | None = None
    if pid is not None:
        generation = process_generation(pid, label)
        if launchd_service_pid_or_absent(domain, label) != pid:
            raise ReleaseFailure(f"host_service_process_changed:{label}")
        stopped = subprocess.run(
            ["/bin/launchctl", "bootout", f"{domain}/{label}"],
            check=False, capture_output=True, text=True,
        )
        if (stopped.returncode != 0 or len(stopped.stdout) > 64 * 1024
                or len(stopped.stderr) > 64 * 1024):
            raise ReleaseFailure(f"host_service_bootout_failed:{label}")

        deadline = time.monotonic() + timeout
        while True:
            observed_pid = launchd_service_pid_or_absent(domain, label)
            observed_generation = process_generation_or_absent(pid, label)
            if (observed_pid is None
                    and (observed_generation is None
                         or observed_generation != generation)):
                break
            if time.monotonic() >= deadline:
                raise ReleaseFailure(f"host_service_exit_unproven:{label}")
            time.sleep(HOST_SERVICE_STOP_POLL_SECONDS)
    elif launchd_service_pid_or_absent(domain, label) is not None:
        raise ReleaseFailure(f"host_service_state_changed:{label}")

    try:
        plist_path.unlink()
        fsync_directory(plist_path.parent)
    except FileNotFoundError:
        pass


def process_executable_path(pid: int, label: str) -> str:
    """Resolve the kernel's executable vnode path for an exact live PID."""
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = libproc.proc_pidpath
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        length = function(pid, buffer, len(buffer))
        if length <= 0 or length >= len(buffer):
            raise OSError(ctypes.get_errno(), "proc_pidpath")
        value = buffer.raw[:length].decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError, AttributeError) as error:
        raise ReleaseFailure(
            f"host_service_executable_unproven:{label}"
        ) from error
    if not value.startswith("/") or "\x00" in value or "\n" in value:
        raise ReleaseFailure(f"host_service_executable_unproven:{label}")
    return value


def process_arguments(pid: int, label: str) -> list[str]:
    """Read the kernel's exact argc/argv vector without shell re-parsing."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.sysctl
        function.argtypes = [
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p, ctypes.c_size_t,
        ]
        function.restype = ctypes.c_int
        mib = (ctypes.c_int * 3)(1, 49, pid)
        size = ctypes.c_size_t()
        if function(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "sysctl")
        if size.value < 5 or size.value > 1024 * 1024:
            raise OSError(0, "procargs2 size")
        buffer = ctypes.create_string_buffer(size.value)
        if function(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "sysctl")
        data = buffer.raw[:size.value]
        argc = int.from_bytes(
            data[:4], byteorder=sys.byteorder, signed=True,
        )
        if not 1 <= argc <= 4096:
            raise OSError(0, "procargs2 argc")
        offset = data.find(b"\0", 4)
        if offset < 0:
            raise OSError(0, "procargs2 executable")
        offset += 1
        while offset < len(data) and data[offset] == 0:
            offset += 1
        arguments: list[str] = []
        for _ in range(argc):
            end = data.find(b"\0", offset)
            if end < offset:
                raise OSError(0, "procargs2 argv")
            arguments.append(
                data[offset:end].decode("utf-8", errors="strict")
            )
            offset = end + 1
    except (OSError, UnicodeDecodeError, AttributeError) as error:
        raise ReleaseFailure(f"host_service_process_unproven:{label}") from error
    if (not arguments or any(
        not argument or "\x00" in argument or "\n" in argument
        for argument in arguments
    )):
        raise ReleaseFailure(f"host_service_process_unproven:{label}")
    return arguments


def system_python_runtime() -> Path:
    """Resolve the Apple-selected runtime behind the /usr/bin/python3 stub."""
    resolved = subprocess.run(
        [
            "/usr/bin/python3", "-I", "-c",
            (
                "import os,sys;print(os.path.realpath(os.path.join("
                "sys.base_prefix,'Resources/Python.app/Contents/MacOS/Python')))"
            ),
        ],
        check=False, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
    )
    value = resolved.stdout.strip()
    if (resolved.returncode != 0 or not value or len(value) > 4096
            or "\x00" in value or "\n" in value or not value.startswith("/")):
        raise ReleaseFailure("authorization_python_runtime_unproven")
    path = Path(value)
    try:
        information = path.stat()
    except OSError as error:
        raise ReleaseFailure("authorization_python_runtime_unproven") from error
    if not stat.S_ISREG(information.st_mode):
        raise ReleaseFailure("authorization_python_runtime_unproven")
    return path


def process_live_identity(pid: int, label: str) -> dict[str, Any]:
    """Bracket path and argv observation with one exact process generation."""
    before = process_generation(pid, label)
    executable = process_executable_path(pid, label)
    arguments = process_arguments(pid, label)
    after = process_generation(pid, label)
    if before != after:
        raise ReleaseFailure(f"host_service_process_changed:{label}")
    return {
        "pid": pid,
        "euid": before[0],
        "start_generation": [before[1], before[2]],
        "executable": executable,
        "arguments": arguments,
    }


def verify_live_native_code(
    pid: int, label: str, identifier: str, team: str,
) -> None:
    """Validate the running SecCode, not only an executable pathname."""
    requirement = (
        f'identifier "{identifier}" and anchor apple generic '
        f'and certificate leaf[subject.OU] = "{team}" '
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )
    # A bare decimal is the documented dynamic-code form.  Prefixing '+'
    # asks codesign for a pid disk representation and does not perform the
    # full live hosting/resource validation required here.
    process = str(pid)
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4",
         f"-R={requirement}", process],
        check=False, capture_output=True, text=True,
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", process],
        check=False, capture_output=True, text=True,
    )
    evidence = details.stderr
    if (verified.returncode != 0 or details.returncode != 0
            or len(verified.stderr) > 64 * 1024
            or len(evidence) > 64 * 1024
            or "dynamically valid" not in verified.stderr
            or f"Identifier={identifier}" not in evidence
            or f"TeamIdentifier={team}" not in evidence
            or "flags=0x10000(runtime)" not in evidence
            or "Signature=adhoc" in evidence):
        raise ReleaseFailure(f"host_service_live_code_invalid:{label}")


def launchd_live_identity(
    domain: str,
    label: str,
    expected_arguments: list[str],
    expected_executable: Path,
    expected_euid: int,
    native_code_identity: tuple[str, str] | None = None,
    script_binding: tuple[Path, Path, str] | None = None,
) -> dict[str, Any]:
    """Prove one stable launchd process generation and its bound authority."""
    pid = launchd_service_pid(domain, label)
    first = process_live_identity(pid, label)
    try:
        live_executable = Path(first["executable"]).resolve(strict=True)
        required_executable = expected_executable.resolve(strict=True)
    except OSError as error:
        raise ReleaseFailure(
            f"host_service_executable_unproven:{label}"
        ) from error
    if (first["euid"] != expected_euid
            or live_executable != required_executable
            or first["arguments"] != expected_arguments):
        raise ReleaseFailure(f"host_service_executable_mismatch:{label}")

    if native_code_identity is not None:
        verify_live_native_code(pid, label, *native_code_identity)
    if script_binding is not None:
        selected, release_script, expected_sha256 = script_binding
        try:
            selected_before = selected.resolve(strict=True)
            release_resolved = release_script.resolve(strict=True)
        except OSError as error:
            raise ReleaseFailure(
                f"host_service_script_binding_unproven:{label}"
            ) from error
        if (selected_before != release_resolved
                or sha256_bytes(read_regular(selected)) != expected_sha256
                or sha256_bytes(read_regular(release_script)) != expected_sha256
                or selected.resolve(strict=True) != selected_before):
            raise ReleaseFailure(
                f"host_service_script_binding_unproven:{label}"
            )

    second = process_live_identity(pid, label)
    reread_pid = launchd_service_pid(domain, label)
    third = process_live_identity(pid, label)
    if first != second or first != third or reread_pid != pid:
        raise ReleaseFailure(f"host_service_process_changed:{label}")
    return first


def stop_and_fence_host_services(native_uid: int) -> None:
    stop_touchid_service()
    stop_native_credential_service(uid=native_uid)
    if (launchd_service_pid_or_absent("system", AUTHORIZATION_LABEL) is not None
            or launchd_service_pid_or_absent(
                f"gui/{native_uid}", NATIVE_CREDENTIAL_HELPER_LABEL,
            ) is not None):
        raise ReleaseFailure("host_service_fence_unproven")


def install_release_host_services(
    release: Path,
    manifest: Mapping[str, Any],
    native_uid: int,
) -> None:
    payloads = set(manifest.get("payloads", {}))
    if (release / "authorization_service").is_file():
        install_touchid_service(release)
    else:
        stop_touchid_service()
    if NATIVE_CREDENTIAL_PAYLOAD_NAMES <= payloads:
        install_native_credential_service(release, uid=native_uid)
    else:
        stop_native_credential_service(uid=native_uid)


def verify_release_authorization_service(
    release: Path,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    expected_authorization = release / "authorization_service"
    broker_sha256 = manifest.get("payloads", {}).get("authorization_broker")
    if (not expected_authorization.is_file()
            or not isinstance(broker_sha256, str)
            or SHA256.fullmatch(broker_sha256) is None):
        raise ReleaseFailure("authorization_service_binding_invalid")
    broker_path = Path(
        "/usr/local/libexec/secure-sandbox-host/current/authorization_broker"
    )
    if read_regular(DEFAULT_AUTHORIZATION_PLIST) != read_regular(
        expected_authorization
    ):
        raise ReleaseFailure("authorization_service_install_mismatch")
    python_runtime = system_python_runtime()
    return launchd_live_identity(
        "system", AUTHORIZATION_LABEL,
        [
            str(python_runtime), "-I",
            "/usr/local/libexec/secure-sandbox-host/current/authorization_broker",
            "serve-touchid",
        ],
        python_runtime, 0,
        script_binding=(
            broker_path, release / "authorization_broker", broker_sha256,
        ),
    )


def verify_release_host_services(
    release: Path,
    manifest: Mapping[str, Any],
    native_uid: int,
) -> dict[str, Any]:
    payloads = set(manifest.get("payloads", {}))
    result: dict[str, Any] = {}
    expected_authorization = release / "authorization_service"
    if expected_authorization.is_file():
        result["authorization"] = verify_release_authorization_service(
            release, manifest,
        )
    elif (touchid_service_is_loaded()
            or os.path.lexists(DEFAULT_AUTHORIZATION_PLIST)):
        raise ReleaseFailure("authorization_service_fence_unproven")

    if NATIVE_CREDENTIAL_PAYLOAD_NAMES <= payloads:
        native_manifest = native_components_manifest(
            read_regular(release / "native_credential_helper_bundle")
        )
        if read_regular(DEFAULT_NATIVE_CREDENTIAL_PLIST) != read_regular(
            release / "native_credential_helper_service"
        ):
            raise ReleaseFailure("native_credential_service_install_mismatch")
        result["native_credential"] = launchd_live_identity(
            f"gui/{native_uid}",
            NATIVE_CREDENTIAL_HELPER_LABEL,
            [NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH],
            release / NATIVE_CREDENTIAL_HELPER_APP_NAME
                / NATIVE_CREDENTIAL_HELPER_EXECUTABLE,
            native_uid,
            native_code_identity=(
                NATIVE_CREDENTIAL_HELPER_LABEL,
                native_manifest["signing_policy"]["team_id"],
            ),
        )
    elif (native_credential_service_is_loaded(native_uid)
            or os.path.lexists(DEFAULT_NATIVE_CREDENTIAL_PLIST)):
        raise ReleaseFailure("native_credential_service_fence_unproven")
    return result


def _validated_uuid4(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ReleaseFailure(f"{label}_invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ReleaseFailure(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise ReleaseFailure(f"{label}_invalid")
    return value


def install_transition_digest(value: Mapping[str, Any]) -> str:
    immutable = {
        key: item for key, item in value.items()
        if key not in {"terminal", "transition_sha256"}
    }
    return sha256_bytes(canonical_state_record(immutable))


def terminal_transition_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_state_record({
        key: item for key, item in value.items()
        if key != "terminal_sha256"
    }))


def validate_install_transition(value: object) -> dict[str, Any]:
    fields = {
        "schema", "transition_id", "transition_sha256", "created_at",
        "expires_at", "authorization_request_id",
        "authorization_request_sha256",
        "authorization_pending_receipt_sha256", "candidate_release_id",
        "candidate_manifest_sha256",
        "candidate_authorization_manifest_sha256",
        "developer_id_team_id", "developer_id_team_floor_sha256",
        "fallback_release_id", "old_current_target", "old_previous_target",
        "native_uid", "old_services", "old_services_sha256", "terminal",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("install_transition_record_invalid")
    transition_id = _validated_uuid4(
        value.get("transition_id"), "install_transition_id",
    )
    request_id = _validated_uuid4(
        value.get("authorization_request_id"), "authorization_request_id",
    )
    del transition_id, request_id
    created = value.get("created_at")
    expires = value.get("expires_at")
    old_services = value.get("old_services")
    fallback = value.get("fallback_release_id")
    old_current = value.get("old_current_target")
    old_previous = value.get("old_previous_target")
    if (value.get("schema") != INSTALL_TRANSITION_SCHEMA
            or not isinstance(created, int) or isinstance(created, bool)
            or not isinstance(expires, int) or isinstance(expires, bool)
            or created < 0
            or expires - created != INSTALL_TRANSITION_TTL_SECONDS
            or not isinstance(value.get("native_uid"), int)
            or isinstance(value.get("native_uid"), bool)
            or value["native_uid"] <= 0
            or not isinstance(old_services, dict)
            or "authorization" not in old_services
            or fallback is not None and (
                not isinstance(fallback, str) or SHA256.fullmatch(fallback) is None
            )
            or old_current != (
                None if fallback is None else f"releases/{fallback}"
            )
            or old_previous is not None and (
                not isinstance(old_previous, str)
                or re.fullmatch(r"releases/[0-9a-f]{64}", old_previous) is None
            )
            or value.get("terminal") is not None
                and not isinstance(value["terminal"], dict)):
        raise ReleaseFailure("install_transition_record_invalid")
    old_authorization = old_services.get("authorization")
    if (not isinstance(old_authorization, dict)
            or not isinstance(old_authorization.get("pid"), int)
            or old_authorization["pid"] <= 1
            or not isinstance(
                old_authorization.get("start_generation"), list,
            )
            or len(old_authorization["start_generation"]) != 2
            or any(
                not isinstance(item, int) or item < 0
                for item in old_authorization["start_generation"]
            )):
        raise ReleaseFailure("install_transition_record_invalid")
    for name in (
        "transition_sha256", "authorization_request_sha256",
        "authorization_pending_receipt_sha256", "candidate_release_id",
        "candidate_manifest_sha256",
        "candidate_authorization_manifest_sha256",
        "developer_id_team_floor_sha256", "old_services_sha256",
    ):
        if (not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None):
            raise ReleaseFailure("install_transition_record_invalid")
    if (not isinstance(value.get("developer_id_team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["developer_id_team_id"])
                is None
            or sha256_bytes(canonical_state_record(old_services))
                != value["old_services_sha256"]
            or install_transition_digest(value) != value["transition_sha256"]):
        raise ReleaseFailure("install_transition_record_invalid")
    if value["terminal"] is not None:
        validate_install_finalization(value["terminal"], value)
    return {key: value[key] for key in sorted(fields)}


def authorization_receipt_for_transition(
    request_id: str, request_sha256: str, expected_uid: int,
) -> tuple[dict[str, Any], bytes]:
    directory = open_trusted_absolute_directory(
        DEFAULT_AUTHORIZATION_RECEIPT_ROOT, expected_uid, final_mode=0o700,
    )
    try:
        receipt, raw, _ = read_state_record_at(
            directory, f"{request_id}.json", expected_uid, 0o600,
        )
    finally:
        os.close(directory)
    if (receipt.get("schema")
            != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != request_id
            or receipt.get("request_sha256") != request_sha256
            or receipt.get("operation") != "host-controller-install"):
        raise ReleaseFailure("install_transition_receipt_invalid")
    return receipt, raw


def begin_install_transition(
    install_root: Path,
    expected_uid: int,
    candidate: Path,
    candidate_manifest: Mapping[str, Any],
    old_release: Path,
    old_manifest: Mapping[str, Any],
    old_current_target: str,
    old_previous_target: str | None,
    native_uid: int,
    signing_floor: Mapping[str, Any],
    signing_floor_sha256: str,
    authorization_request_id: str,
    authorization_request_sha256: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    _validated_uuid4(authorization_request_id, "authorization_request_id")
    if SHA256.fullmatch(authorization_request_sha256) is None:
        raise ReleaseFailure("authorization_request_sha256_invalid")
    if (read_regular(candidate / "authorization_service")
            != read_regular(old_release / "authorization_service")):
        raise ReleaseFailure(
            "authorization_service_change_requires_explicit_migration"
        )
    receipt, receipt_raw = authorization_receipt_for_transition(
        authorization_request_id, authorization_request_sha256, expected_uid,
    )
    if receipt.get("status") != "executing":
        raise ReleaseFailure("install_transition_receipt_invalid")
    services = verify_release_host_services(
        old_release, old_manifest, native_uid,
    )
    created = int(time.time()) if now is None else now
    value: dict[str, Any] = {
        "schema": INSTALL_TRANSITION_SCHEMA,
        "transition_id": str(uuid.uuid4()),
        "created_at": created,
        "expires_at": created + INSTALL_TRANSITION_TTL_SECONDS,
        "authorization_request_id": authorization_request_id,
        "authorization_request_sha256": authorization_request_sha256,
        "authorization_pending_receipt_sha256": sha256_bytes(receipt_raw),
        "candidate_release_id": candidate.name,
        "candidate_manifest_sha256": sha256_bytes(
            read_regular(candidate / "manifest.json")
        ),
        "candidate_authorization_manifest_sha256": candidate_manifest[
            "payloads"
        ]["authorization_ui_bundle"],
        "developer_id_team_id": signing_floor["team_id"],
        "developer_id_team_floor_sha256": signing_floor_sha256,
        "fallback_release_id": old_release.name,
        "old_current_target": old_current_target,
        "old_previous_target": old_previous_target,
        "native_uid": native_uid,
        "old_services": services,
        "old_services_sha256": sha256_bytes(canonical_state_record(services)),
        "terminal": None,
    }
    value["transition_sha256"] = install_transition_digest(value)
    validated = validate_install_transition(value)
    root = open_trusted_absolute_directory(install_root, expected_uid)
    try:
        write_new_state_record_at(
            root, INSTALL_TRANSITION_PENDING_NAME, validated,
            expected_uid, 0o600,
        )
    finally:
        os.close(root)
    return validated


def read_pending_install_transition(
    install_root: Path, expected_uid: int,
) -> tuple[dict[str, Any], int]:
    root = open_trusted_absolute_directory(install_root, expected_uid)
    try:
        value, _raw, _ = read_state_record_at(
            root, INSTALL_TRANSITION_PENDING_NAME, expected_uid, 0o600,
        )
        return validate_install_transition(value), root
    except BaseException:
        os.close(root)
        raise


def validate_terminal_transition(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseFailure("install_transition_terminal_invalid")
    fields = {
        "schema", "status", "transition_id", "transition_sha256",
        "authorization_request_id", "authorization_request_sha256",
        "candidate_release_id", "candidate_manifest_sha256",
        "candidate_authorization_manifest_sha256",
        "developer_id_team_id", "developer_id_team_floor_sha256",
        "old_authorization_pid", "old_authorization_start_generation",
        "authorization_pid", "authorization_start_generation",
        "native_credential_pid", "native_credential_start_generation",
        "service_evidence_sha256", "authorization_receipt_sha256",
        "completed_at", "error", "terminal_sha256",
    }
    if set(value) != fields:
        raise ReleaseFailure("install_transition_terminal_invalid")
    _validated_uuid4(value.get("transition_id"), "install_transition_id")
    _validated_uuid4(
        value.get("authorization_request_id"), "authorization_request_id",
    )
    for name in (
        "transition_sha256", "authorization_request_sha256",
        "candidate_release_id", "candidate_manifest_sha256",
        "candidate_authorization_manifest_sha256",
        "developer_id_team_floor_sha256", "service_evidence_sha256",
        "authorization_receipt_sha256", "terminal_sha256",
    ):
        if (not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None):
            raise ReleaseFailure("install_transition_terminal_invalid")
    generation_names = (
        "old_authorization_start_generation",
        "authorization_start_generation",
        "native_credential_start_generation",
    )
    if (value.get("schema") != INSTALL_TERMINAL_SCHEMA
            or value.get("status") not in {
                "deployed_verified", "failed_fenced",
                "failure_fence_unproven", "failed_rolled_back",
            }
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value.get("completed_at"), bool)
            or not isinstance(value.get("developer_id_team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["developer_id_team_id"])
                is None
            or any(
                not isinstance(value.get(name), int)
                or isinstance(value.get(name), bool) or value[name] < 0
                for name in (
                    "old_authorization_pid", "authorization_pid",
                    "native_credential_pid",
                )
            )
            or any(
                not isinstance(value.get(name), list)
                or len(value[name]) != 2
                or any(not isinstance(item, int) or item < 0 for item in value[name])
                for name in generation_names
            )
            or value.get("error") is not None and (
                not isinstance(value["error"], str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value["error"])
                    is None
            )
            or terminal_transition_digest(value) != value["terminal_sha256"]):
        raise ReleaseFailure("install_transition_terminal_invalid")
    if value["status"] == "deployed_verified":
        if (value["error"] is not None
                or value["authorization_pid"] <= 1
                or value["native_credential_pid"] <= 1
                or any(
                    generation[0] <= 0
                    or not 0 <= generation[1] < 1_000_000
                    for generation in (
                        value["authorization_start_generation"],
                        value["native_credential_start_generation"],
                    )
                )):
            raise ReleaseFailure("install_transition_terminal_invalid")
    elif value["error"] is None:
        raise ReleaseFailure("install_transition_terminal_invalid")
    return {key: value[key] for key in sorted(fields)}


def install_finalization_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_state_record({
        key: item for key, item in value.items()
        if key != "finalization_sha256"
    }))


def validate_install_finalization(
    value: object, transition: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "status", "transition_id", "transition_sha256",
        "completed_at", "error", "authorization_pid",
        "authorization_start_generation", "native_credential_pid",
        "native_credential_start_generation", "service_evidence_sha256",
        "superseded_finalization_sha256", "finalization_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("install_transition_finalization_invalid")
    if (value.get("schema")
            != "secure-sandbox-host-install-finalization-v1"
            or value.get("status") not in {
                "deployed_verified", "failed_fenced", "failure_fence_unproven",
                "failed_rolled_back",
            }
            or value.get("transition_id") != transition["transition_id"]
            or value.get("transition_sha256") != transition["transition_sha256"]
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value.get("completed_at"), bool)
            or value["completed_at"] < transition["created_at"]
            or not isinstance(value.get("authorization_pid"), int)
            or isinstance(value.get("authorization_pid"), bool)
            or value["authorization_pid"] < 0
            or not isinstance(value.get("native_credential_pid"), int)
            or isinstance(value.get("native_credential_pid"), bool)
            or value["native_credential_pid"] < 0
            or any(
                not isinstance(value.get(name), list)
                or len(value[name]) != 2
                or any(
                    not isinstance(item, int) or item < 0
                    for item in value[name]
                )
                for name in (
                    "authorization_start_generation",
                    "native_credential_start_generation",
                )
            )
            or not isinstance(value.get("service_evidence_sha256"), str)
            or SHA256.fullmatch(value["service_evidence_sha256"]) is None
            or not isinstance(value.get("finalization_sha256"), str)
            or SHA256.fullmatch(value["finalization_sha256"]) is None
            or value.get("superseded_finalization_sha256") is not None and (
                not isinstance(value["superseded_finalization_sha256"], str)
                or SHA256.fullmatch(value["superseded_finalization_sha256"])
                    is None
            )
            or value.get("error") is not None and (
                not isinstance(value["error"], str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value["error"])
                    is None
            )
            or install_finalization_digest(value)
                != value["finalization_sha256"]):
        raise ReleaseFailure("install_transition_finalization_invalid")
    if (value["status"] == "deployed_verified"
            and (value["error"] is not None
                 or value["superseded_finalization_sha256"] is not None
                 or value["authorization_pid"] <= 1
                 or value["native_credential_pid"] <= 1)):
        raise ReleaseFailure("install_transition_finalization_invalid")
    if value["status"] != "deployed_verified" and value["error"] is None:
        raise ReleaseFailure("install_transition_finalization_invalid")
    return {key: value[key] for key in sorted(fields)}


def stage_install_finalization(
    install_root_descriptor: int,
    transition: Mapping[str, Any],
    finalization: Mapping[str, Any],
    expected_uid: int,
) -> dict[str, Any]:
    validated = validate_install_finalization(finalization, transition)
    updated = dict(transition)
    updated["terminal"] = validated
    validate_install_transition(updated)
    replace_state_record_at(
        install_root_descriptor, INSTALL_TRANSITION_PENDING_NAME,
        updated, expected_uid, 0o600,
    )
    reread, _raw, _ = read_state_record_at(
        install_root_descriptor, INSTALL_TRANSITION_PENDING_NAME,
        expected_uid, 0o600,
    )
    validated_transition = validate_install_transition(reread)
    if validated_transition != updated:
        raise ReleaseFailure("install_transition_finalization_readback_failed")
    return validated_transition


def complete_install_authorization_receipt(
    transition: Mapping[str, Any],
    finalization: Mapping[str, Any],
    expected_uid: int,
) -> tuple[dict[str, Any], bytes]:
    directory = open_trusted_absolute_directory(
        DEFAULT_AUTHORIZATION_RECEIPT_ROOT, expected_uid, final_mode=0o700,
    )
    name = f"{transition['authorization_request_id']}.json"
    try:
        receipt, receipt_raw, _ = read_state_record_at(
            directory, name, expected_uid, 0o600,
        )
        if (receipt.get("schema")
                != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt.get("request_id")
                    != transition["authorization_request_id"]
                or receipt.get("request_sha256")
                    != transition["authorization_request_sha256"]
                or receipt.get("operation") != "host-controller-install"):
            raise ReleaseFailure("install_transition_receipt_invalid")
        source_executing_receipt = receipt.get("status") == "executing"
        if source_executing_receipt:
            # The transition durably binds the exact pre-exec receipt before
            # selector mutation.  A power loss can prevent the predecessor
            # broker from promoting it to activation_pending.  The successor
            # may consume only those exact bytes; no synthesized or relabelled
            # executing receipt is accepted.
            if (sha256_bytes(receipt_raw)
                    != transition["authorization_pending_receipt_sha256"]
                    or receipt.get("completed_at") is not None
                    or receipt.get("exit_status") is not None
                    or any(name in receipt for name in (
                        "transition_id", "transition_sha256",
                        "candidate_release_id",
                        "authorization_pending_receipt_sha256",
                    ))):
                raise ReleaseFailure("install_transition_receipt_invalid")
        elif (receipt.get("transition_id") != transition["transition_id"]
              or receipt.get("transition_sha256")
                  != transition["transition_sha256"]
              or receipt.get("candidate_release_id")
                  != transition["candidate_release_id"]):
            raise ReleaseFailure("install_transition_receipt_invalid")
        terminal_status = finalization["status"]
        expected_status = (
            "succeeded" if terminal_status == "deployed_verified" else "failed"
        )
        superseded_receipt_sha256: str | None = None
        if receipt.get("status") == expected_status:
            if (receipt.get("host_install_terminal_status") != terminal_status
                    or receipt.get("host_install_service_evidence_sha256")
                        != finalization["service_evidence_sha256"]
                    or receipt.get("host_install_finalization_sha256")
                        != finalization["finalization_sha256"]
                    or receipt.get("completed_at")
                        != finalization["completed_at"]):
                if (expected_status != "failed"
                        or finalization["superseded_finalization_sha256"]
                            != receipt.get(
                                "host_install_finalization_sha256"
                            )):
                    raise ReleaseFailure("install_transition_receipt_conflict")
                superseded_receipt_sha256 = sha256_bytes(receipt_raw)
            else:
                return receipt, canonical_state_record(receipt)
        elif (receipt.get("status") == "succeeded"
                and expected_status == "failed"
                and receipt.get("host_install_terminal_status")
                    == "deployed_verified"
                and receipt.get("host_install_finalization_sha256")
                    == finalization["superseded_finalization_sha256"]
                and isinstance(
                    receipt.get("host_install_service_evidence_sha256"), str,
                )
                and SHA256.fullmatch(
                    receipt["host_install_service_evidence_sha256"]
                ) is not None
                and isinstance(receipt.get("completed_at"), int)):
            superseded_receipt_sha256 = sha256_bytes(receipt_raw)
        elif (not source_executing_receipt
              and (receipt.get("status") != "activation_pending"
              or receipt.get("completed_at") is not None
              or receipt.get("exit_status") is not None
              or receipt.get("authorization_pending_receipt_sha256")
                  != transition["authorization_pending_receipt_sha256"])):
            raise ReleaseFailure("install_transition_receipt_invalid")
        completed = dict(receipt)
        completed.update({
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "candidate_release_id": transition["candidate_release_id"],
            "authorization_pending_receipt_sha256": transition[
                "authorization_pending_receipt_sha256"
            ],
            "status": expected_status,
            "completed_at": finalization["completed_at"],
            "exit_status": 0 if expected_status == "succeeded" else 1,
            "host_install_terminal_status": terminal_status,
            "host_install_service_evidence_sha256": finalization[
                "service_evidence_sha256"
            ],
            "host_install_finalization_sha256": finalization[
                "finalization_sha256"
            ],
            "stderr_sha256": sha256_bytes(
                b"" if expected_status == "succeeded"
                else b"host_install_activation_failed\n"
            ),
        })
        if source_executing_receipt:
            completed["stdout_sha256"] = sha256_bytes(b"")
        if superseded_receipt_sha256 is not None:
            completed["host_install_superseded_receipt_sha256"] = (
                superseded_receipt_sha256
            )
        raw = replace_state_record_at(
            directory, name, completed, expected_uid, 0o600,
        )
        observed, observed_raw, _ = read_state_record_at(
            directory, name, expected_uid, 0o600,
        )
        if observed != completed or observed_raw != raw:
            raise ReleaseFailure("install_transition_receipt_readback_failed")
        return completed, raw
    finally:
        os.close(directory)


def make_install_finalization(
    transition: Mapping[str, Any],
    *,
    status: str,
    error: str | None,
    authorization: Mapping[str, Any] | None,
    native_credential: Mapping[str, Any] | None,
    service_evidence: Mapping[str, Any],
    completed_at: int,
    superseded_finalization_sha256: str | None = None,
) -> dict[str, Any]:
    result = {
        "schema": "secure-sandbox-host-install-finalization-v1",
        "status": status,
        "transition_id": transition["transition_id"],
        "transition_sha256": transition["transition_sha256"],
        "completed_at": completed_at,
        "error": error,
        "authorization_pid": (
            authorization["pid"] if authorization is not None else 0
        ),
        "authorization_start_generation": (
            authorization["start_generation"]
            if authorization is not None else [0, 0]
        ),
        "native_credential_pid": (
            native_credential["pid"] if native_credential is not None else 0
        ),
        "native_credential_start_generation": (
            native_credential["start_generation"]
            if native_credential is not None else [0, 0]
        ),
        "service_evidence_sha256": sha256_bytes(
            canonical_state_record(service_evidence)
        ),
        "superseded_finalization_sha256": superseded_finalization_sha256,
    }
    result["finalization_sha256"] = install_finalization_digest(result)
    return validate_install_finalization(result, transition)


def make_install_terminal(
    transition: Mapping[str, Any],
    finalization: Mapping[str, Any],
    authorization_receipt_sha256: str,
) -> dict[str, Any]:
    old_authorization = transition["old_services"]["authorization"]
    result = {
        "schema": INSTALL_TERMINAL_SCHEMA,
        "status": finalization["status"],
        "transition_id": transition["transition_id"],
        "transition_sha256": transition["transition_sha256"],
        "authorization_request_id": transition["authorization_request_id"],
        "authorization_request_sha256": transition[
            "authorization_request_sha256"
        ],
        "candidate_release_id": transition["candidate_release_id"],
        "candidate_manifest_sha256": transition["candidate_manifest_sha256"],
        "candidate_authorization_manifest_sha256": transition[
            "candidate_authorization_manifest_sha256"
        ],
        "developer_id_team_id": transition["developer_id_team_id"],
        "developer_id_team_floor_sha256": transition[
            "developer_id_team_floor_sha256"
        ],
        "old_authorization_pid": old_authorization["pid"],
        "old_authorization_start_generation": old_authorization[
            "start_generation"
        ],
        "authorization_pid": finalization["authorization_pid"],
        "authorization_start_generation": finalization[
            "authorization_start_generation"
        ],
        "native_credential_pid": finalization["native_credential_pid"],
        "native_credential_start_generation": finalization[
            "native_credential_start_generation"
        ],
        "service_evidence_sha256": finalization[
            "service_evidence_sha256"
        ],
        "authorization_receipt_sha256": authorization_receipt_sha256,
        "completed_at": finalization["completed_at"],
        "error": finalization["error"],
    }
    result["terminal_sha256"] = terminal_transition_digest(result)
    return validate_terminal_transition(result)


def native_credential_status_handoff(
    operation_id: str | None = None,
) -> dict[str, Any]:
    operation_id = str(uuid.uuid4()) if operation_id is None else operation_id
    _validated_uuid4(operation_id, "native_credential_status_operation_id")
    body: dict[str, Any] = {
        "operation_id": operation_id,
        "operation": "status",
        "authorization_ticket_id": None,
        "plan_sha256": None,
        "operator_request_sha256": None,
        "stack_sha256": None,
        "session_authority_sha256": None,
        "authorization_receipt_sha256": None,
    }
    body.update({name: None for name in NATIVE_PROJECTION_AUTHORITY_FIELDS})
    return {
        "schema": NATIVE_CREDENTIAL_HANDOFF_SCHEMA,
        **body,
        "handoff_sha256": sha256_bytes(canonical_state_record(body)),
    }


def validate_zero_projection_custody_reply(
    value: object,
    *,
    operation_id: str,
) -> dict[str, Any]:
    fields = {
        "schema", "operation_id", "verified", "status", "projection",
        "error_code", "response_sha256", "reply_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("native_credential_custody_reply_invalid")
    body = {name: value[name] for name in fields - {"schema", "reply_sha256"}}
    status = value.get("status")
    status_fields = {
        "provider", "state", "client_id_sha256",
        "account_subject_sha256", "workspace_sha256", "scope_sha256",
        "access_expires_at_ms", "earliest_refresh_at_ms",
        "refresh_expires_at_ms", "custody_state",
        "custody_tombstone_sha256", "custody_projection_count",
    }
    digest_fields = (
        "client_id_sha256", "account_subject_sha256", "workspace_sha256",
        "scope_sha256",
    )
    time_fields = (
        "access_expires_at_ms", "earliest_refresh_at_ms",
        "refresh_expires_at_ms",
    )
    if (value.get("schema") != NATIVE_CREDENTIAL_REPLY_SCHEMA
            or value.get("operation_id") != operation_id
            or value.get("verified") is not True
            or value.get("projection") is not None
            or value.get("error_code") is not None
            or not isinstance(value.get("response_sha256"), str)
            or SHA256.fullmatch(value["response_sha256"]) is None
            or not isinstance(value.get("reply_sha256"), str)
            or SHA256.fullmatch(value["reply_sha256"]) is None
            or sha256_bytes(canonical_state_record(body))
                != value["reply_sha256"]
            or not isinstance(status, dict) or set(status) != status_fields
            or status.get("provider") != "openAIChatGPT"
            or status.get("state") not in {
                "loggedOut", "ready", "refreshRequired", "blocked",
            }
            or status.get("custody_state") not in {
                "absent", "retained", "ambiguous",
            }
            or status.get("custody_projection_count") != 0
            or isinstance(status.get("custody_projection_count"), bool)
            or any(
                item is not None and (
                    not isinstance(item, str) or SHA256.fullmatch(item) is None
                )
                for item in (status.get(name) for name in digest_fields)
            )
            or any(
                item is not None and (
                    not isinstance(item, int) or isinstance(item, bool)
                    or item < 1
                )
                for item in (status.get(name) for name in time_fields)
            )
            or status.get("custody_tombstone_sha256") is not None and (
                not isinstance(status["custody_tombstone_sha256"], str)
                or SHA256.fullmatch(status["custody_tombstone_sha256"])
                    is None
            )):
        raise ReleaseFailure("native_credential_custody_reply_invalid")
    state = status["state"]
    identity_values = [status[name] for name in digest_fields]
    time_values = [status[name] for name in time_fields]
    if (state == "loggedOut" and (
            any(item is not None for item in identity_values + time_values)
            or status["custody_state"] not in {"absent", "ambiguous"})
            or state in {"ready", "refreshRequired"} and (
                any(item is None for item in identity_values + time_values)
                or status["custody_state"] == "absent")
            or status["custody_state"] == "absent" and (
                state != "loggedOut"
                or status["custody_tombstone_sha256"] is None)
            or status["custody_state"] in {"retained", "ambiguous"}
                and status["custody_tombstone_sha256"] is not None):
        raise ReleaseFailure("native_credential_custody_reply_invalid")
    return {
        "schema": "secure-sandbox-native-credential-install-custody-evidence-v1",
        "operation_id": operation_id,
        "custody_state": status["custody_state"],
        "custody_projection_count": 0,
        "response_sha256": value["response_sha256"],
        "reply_sha256": value["reply_sha256"],
    }


def zero_projection_custody_evidence(
    install_root: Path,
    release: Path,
    native_uid: int,
    expected_uid: int,
    *,
    operation_id: str | None = None,
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    handoff = native_credential_status_handoff(operation_id)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".native-credential-install-status-", dir=install_root,
    )
    try:
        os.fchown(descriptor, expected_uid, -1)
        os.fchmod(descriptor, 0o400)
        write_all(
            descriptor, canonical_state_record(handoff),
            "native_credential_status_handoff",
        )
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.unlink(temporary)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                or info.st_nlink != 0 or stat.S_IMODE(info.st_mode) != 0o400):
            raise ReleaseFailure("native_credential_status_handoff_untrusted")
        try:
            completed = runner(
                [
                    "/bin/launchctl", "asuser", str(native_uid),
                    str(release / "native_stack_credential_client"),
                    "--request-fd", str(descriptor),
                ],
                stdin=subprocess.DEVNULL, capture_output=True, check=False,
                timeout=30, pass_fds=(descriptor,),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseFailure(
                "native_credential_custody_status_unavailable"
            ) from error
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    if (completed.returncode != 0 or completed.stderr
            or len(completed.stdout) > 32 * 1024):
        raise ReleaseFailure("native_credential_custody_status_unavailable")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("native_credential_custody_reply_invalid") from error
    if (not isinstance(value, dict)
            or completed.stdout != canonical_state_record(value)):
        raise ReleaseFailure("native_credential_custody_reply_invalid")
    return validate_zero_projection_custody_reply(
        value, operation_id=handoff["operation_id"],
    )


def authorization_listener_evidence(
    descriptor: int,
    readiness_descriptor: int,
    readiness_nonce: str,
    expected_authorization_pid: int,
    socket_path: Path = DEFAULT_AUTHORIZATION_SOCKET,
    *,
    expected_uid: int = 0,
) -> dict[str, Any]:
    if (not isinstance(descriptor, int) or isinstance(descriptor, bool)
            or descriptor < 0):
        raise ReleaseFailure("install_transition_listener_invalid")
    try:
        duplicate = os.dup(descriptor)
    except OSError as error:
        raise ReleaseFailure("install_transition_listener_invalid") from error
    listener: socket.socket | None = None
    try:
        opened = os.fstat(duplicate)
        observed = socket_path.lstat()
        listener = socket.socket(fileno=duplicate)
        duplicate = -1
        address = listener.getsockname()
        if isinstance(address, bytes):
            address = address.decode("utf-8", errors="strict")
        socket_type = listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        if (not stat.S_ISSOCK(opened.st_mode)
                or not stat.S_ISSOCK(observed.st_mode)
                or observed.st_uid != expected_uid
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != 0o666
                or listener.family != socket.AF_UNIX
                or socket_type != socket.SOCK_STREAM
                or address != str(socket_path)):
            raise ReleaseFailure("install_transition_listener_unready")
        if (not isinstance(readiness_descriptor, int)
                or isinstance(readiness_descriptor, bool)
                or readiness_descriptor < 0
                or not isinstance(readiness_nonce, str)
                or re.fullmatch(r"[0-9a-f]{64}", readiness_nonce) is None):
            raise ReleaseFailure("install_transition_readiness_invalid")
        try:
            readiness_duplicate = os.dup(readiness_descriptor)
        except OSError as error:
            raise ReleaseFailure(
                "install_transition_readiness_invalid"
            ) from error
        readiness = socket.socket(fileno=readiness_duplicate)
        try:
            readiness.settimeout(5.0)
            challenge = {
                "schema": "secure-sandbox-install-readiness-challenge-v1",
                "nonce_sha256": sha256_bytes(bytes.fromhex(readiness_nonce)),
            }
            readiness.sendall(canonical_state_record(challenge))
            response_raw = b""
            while not response_raw.endswith(b"\n") and len(response_raw) <= 4096:
                chunk = readiness.recv(4097 - len(response_raw))
                if not chunk:
                    break
                response_raw += chunk
            response = json.loads(response_raw)
            reread = socket_path.lstat()
            expected_response = {
                "schema": "secure-sandbox-install-readiness-response-v1",
                "nonce_sha256": challenge["nonce_sha256"],
                "broker_pid": expected_authorization_pid,
                "path": str(socket_path),
                "device": reread.st_dev,
                "inode": reread.st_ino,
                "mode": stat.S_IMODE(reread.st_mode),
                "uid": reread.st_uid,
            }
            if (response_raw != canonical_state_record(expected_response)
                    or response != expected_response
                    or (reread.st_dev, reread.st_ino, reread.st_mode)
                    != (observed.st_dev, observed.st_ino, observed.st_mode)
                    or listener.getsockname() != address):
                raise ReleaseFailure("install_transition_listener_changed")
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise ReleaseFailure(
                "install_transition_readiness_unproven"
            ) from error
        finally:
            readiness.close()
        return {
            "schema": "secure-sandbox-authorization-listener-evidence-v1",
            "path": str(socket_path),
            "device": observed.st_dev,
            "inode": observed.st_ino,
            "private_readiness_challenge": True,
            "broker_readiness_sha256": sha256_bytes(response_raw),
        }
    except (OSError, UnicodeDecodeError) as error:
        raise ReleaseFailure("install_transition_listener_unready") from error
    finally:
        if listener is not None:
            listener.close()
        elif duplicate >= 0:
            os.close(duplicate)


def successful_install_finalization(
    install_root: Path,
    transition: Mapping[str, Any],
    expected_authorization_pid: int,
    expected_uid: int,
    now: int,
    expected_listener_fd: int,
    expected_readiness_fd: int,
    expected_readiness_nonce: str,
) -> dict[str, Any]:
    if (now >= transition["expires_at"]
            or expected_authorization_pid <= 1
            or transition["candidate_release_id"]
                != (install_root / "current").resolve(strict=True).name):
        raise ReleaseFailure("install_transition_expired_or_changed")
    old_authorization = transition["old_services"]["authorization"]
    old_pid = old_authorization["pid"]
    observed_old = process_generation_or_absent(
        old_pid, AUTHORIZATION_LABEL,
    )
    old_generation = (
        old_authorization["euid"],
        old_authorization["start_generation"][0],
        old_authorization["start_generation"][1],
    )
    if observed_old == old_generation:
        raise ReleaseFailure("install_transition_old_broker_still_live")
    current = install_root / "current"
    if os.readlink(current) != (
        f"releases/{transition['candidate_release_id']}"
    ):
        raise ReleaseFailure("install_transition_selector_changed")
    release, manifest = verified_release(
        install_root, current, expected_uid,
    )
    if (release.name != transition["candidate_release_id"]
            or sha256_bytes(read_regular(release / "manifest.json"))
                != transition["candidate_manifest_sha256"]
            or manifest["payloads"]["authorization_ui_bundle"]
                != transition["candidate_authorization_manifest_sha256"]):
        raise ReleaseFailure("install_transition_candidate_changed")
    observed_floor = developer_id_team_floor(install_root, expected_uid)
    if (observed_floor is None
            or observed_floor[0]["team_id"]
                != transition["developer_id_team_id"]
            or observed_floor[1]
                != transition["developer_id_team_floor_sha256"]):
        raise ReleaseFailure("install_transition_floor_changed")
    if console_user_uid() != transition["native_uid"]:
        raise ReleaseFailure("install_transition_console_user_changed")
    services = verify_release_host_services(
        release, manifest, transition["native_uid"],
    )
    authorization = services.get("authorization")
    native_credential = services.get("native_credential")
    if (not isinstance(authorization, dict)
            or authorization.get("pid") != expected_authorization_pid
            or not isinstance(native_credential, dict)):
        raise ReleaseFailure("install_transition_service_identity_mismatch")
    custody_evidence = zero_projection_custody_evidence(
        install_root, release, transition["native_uid"], expected_uid,
        operation_id=transition["transition_id"],
    )
    evidence = {
        "schema": "secure-sandbox-host-install-service-evidence-v1",
        "transition_sha256": transition["transition_sha256"],
        "current_target": os.readlink(current),
        "candidate_manifest_sha256": transition["candidate_manifest_sha256"],
        "developer_id_team_floor_sha256": transition[
            "developer_id_team_floor_sha256"
        ],
        "services": services,
        "native_credential_custody": custody_evidence,
        "authorization_listener": authorization_listener_evidence(
            expected_listener_fd, expected_readiness_fd,
            expected_readiness_nonce, expected_authorization_pid,
            expected_uid=expected_uid,
        ),
    }
    return make_install_finalization(
        transition, status="deployed_verified", error=None,
        authorization=authorization, native_credential=native_credential,
        service_evidence=evidence, completed_at=now,
    )


def rolled_back_install_finalization(
    install_root: Path,
    transition: Mapping[str, Any],
    expected_authorization_pid: int,
    expected_uid: int,
    now: int,
    expected_listener_fd: int,
    expected_readiness_fd: int,
    expected_readiness_nonce: str,
    *,
    superseded_finalization_sha256: str | None = None,
) -> dict[str, Any]:
    current = install_root / "current"
    if (expected_authorization_pid <= 1
            or transition["candidate_release_id"]
                == transition["fallback_release_id"]
            or os.readlink(current) != transition["old_current_target"]
            or current.resolve(strict=True).name
                != transition["fallback_release_id"]):
        raise ReleaseFailure("install_transition_rollback_selector_invalid")
    restore_selector(
        install_root / "previous", transition["old_previous_target"],
    )
    release, manifest = verified_release(
        install_root, current, expected_uid,
    )
    observed_floor = developer_id_team_floor(install_root, expected_uid)
    if (release.name != transition["fallback_release_id"]
            or observed_floor is None
            or observed_floor[0]["team_id"]
                != transition["developer_id_team_id"]
            or observed_floor[1]
                != transition["developer_id_team_floor_sha256"]
            or console_user_uid() != transition["native_uid"]):
        raise ReleaseFailure("install_transition_rollback_identity_invalid")
    try:
        services = verify_release_host_services(
            release, manifest, transition["native_uid"],
        )
    except BaseException:
        install_native_credential_service(
            release, uid=transition["native_uid"],
        )
        services = verify_release_host_services(
            release, manifest, transition["native_uid"],
        )
    authorization = services.get("authorization")
    native_credential = services.get("native_credential")
    if (not isinstance(authorization, dict)
            or authorization.get("pid") != expected_authorization_pid
            or not isinstance(native_credential, dict)):
        raise ReleaseFailure("install_transition_rollback_service_invalid")
    custody_evidence = zero_projection_custody_evidence(
        install_root, release, transition["native_uid"], expected_uid,
        operation_id=transition["transition_id"],
    )
    evidence = {
        "schema": "secure-sandbox-host-install-rollback-evidence-v1",
        "transition_sha256": transition["transition_sha256"],
        "current_target": os.readlink(current),
        "previous_target": selector_target(
            install_root / "previous", "previous",
        ),
        "services": services,
        "native_credential_custody": custody_evidence,
        "authorization_listener": authorization_listener_evidence(
            expected_listener_fd, expected_readiness_fd,
            expected_readiness_nonce, expected_authorization_pid,
            expected_uid=expected_uid,
        ),
    }
    return make_install_finalization(
        transition, status="failed_rolled_back",
        error="activation_rolled_back", authorization=authorization,
        native_credential=native_credential, service_evidence=evidence,
        completed_at=now,
        superseded_finalization_sha256=superseded_finalization_sha256,
    )


def failed_install_finalization(
    install_root: Path,
    transition: Mapping[str, Any],
    expected_authorization_pid: int,
    expected_uid: int,
    now: int,
    *,
    superseded_finalization_sha256: str | None = None,
) -> dict[str, Any]:
    current = install_root / "current"
    # Keep an immutable broker path selected while the protected transition is
    # fenced.  Removing ``current`` here made a crash between the unlink and
    # terminal publication unrecoverable: launchd had no executable from which
    # to resume the durable transition.  The pending record prevents this
    # broker from serving ordinary operations, while the selected candidate or
    # fallback remains available to finish or explicitly repair the fence.
    try:
        current_target = selector_target(current, "current")
    except ReleaseFailure:
        if os.path.lexists(current):
            raise
        current_target = None
    status = "failed_fenced"
    error = "activation_verification_failed"
    try:
        stop_native_credential_service(uid=transition["native_uid"])
        if launchd_service_pid_or_absent(
            f"gui/{transition['native_uid']}",
            NATIVE_CREDENTIAL_HELPER_LABEL,
        ) is not None:
            raise ReleaseFailure("native_credential_service_fence_unproven")
    except BaseException:
        status = "failure_fence_unproven"
        error = "activation_failure_fence_unproven"
    authorization: dict[str, Any] | None = None
    try:
        identity = process_live_identity(
            expected_authorization_pid, AUTHORIZATION_LABEL,
        )
        if identity["pid"] == expected_authorization_pid:
            authorization = identity
    except BaseException:
        pass
    evidence = {
        "schema": "secure-sandbox-host-install-failure-evidence-v1",
        "transition_sha256": transition["transition_sha256"],
        "current_absent": current_target is None,
        "current_target": current_target,
        "native_service_absent": launchd_service_pid_or_absent(
            f"gui/{transition['native_uid']}",
            NATIVE_CREDENTIAL_HELPER_LABEL,
        ) is None,
        "status": status,
    }
    return make_install_finalization(
        transition, status=status, error=error,
        authorization=authorization, native_credential=None,
        service_evidence=evidence, completed_at=now,
        superseded_finalization_sha256=superseded_finalization_sha256,
    )


def ensure_install_failure_selector(
    install_root: Path,
    transition: Mapping[str, Any],
    expected_uid: int,
) -> None:
    """Keep one exact immutable broker launchable for fenced recovery.

    New transitions select the bound fallback before a failed terminal can be
    staged.  The missing/candidate cases repair only crash states created by
    the earlier unlink-first protocol; no unrelated selector is accepted.
    """
    current = install_root / "current"
    fallback_target = transition["old_current_target"]
    fallback_release_id = transition["fallback_release_id"]
    candidate_target = f"releases/{transition['candidate_release_id']}"
    if (not isinstance(fallback_target, str)
            or not isinstance(fallback_release_id, str)
            or fallback_target != f"releases/{fallback_release_id}"):
        raise ReleaseFailure("install_transition_fallback_invalid")
    selected = selector_target(current, "current")
    if selected == fallback_target:
        return
    if selected not in {None, candidate_target}:
        raise ReleaseFailure("install_transition_selector_changed")

    recovery_link = install_root / (
        f".install-failure-fallback-{os.getpid()}-{uuid.uuid4()}"
    )
    if os.path.lexists(recovery_link):
        raise ReleaseFailure("install_transition_recovery_link_exists")
    recovery_link.symlink_to(fallback_target)
    try:
        fallback, _manifest = verified_release(
            install_root, recovery_link, expected_uid, allow_legacy=True,
        )
        if fallback.name != fallback_release_id:
            raise ReleaseFailure("install_transition_fallback_changed")
    finally:
        recovery_link.unlink(missing_ok=True)
    atomic_symlink(fallback_target, current)
    if (selector_target(current, "current") != fallback_target
            or current.resolve(strict=True).name != fallback_release_id):
        raise ReleaseFailure("install_transition_fallback_readback_failed")


def verify_finalized_services_still_live(
    finalization: Mapping[str, Any],
    native_uid: int,
    socket_path: Path = DEFAULT_AUTHORIZATION_SOCKET,
) -> None:
    authorization_pid = finalization["authorization_pid"]
    native_pid = finalization["native_credential_pid"]
    if (launchd_service_pid_or_absent("system", AUTHORIZATION_LABEL)
            != authorization_pid
            or process_generation(authorization_pid, AUTHORIZATION_LABEL)
                != (
                    0,
                    finalization["authorization_start_generation"][0],
                    finalization["authorization_start_generation"][1],
                )
            or launchd_service_pid_or_absent(
                f"gui/{native_uid}", NATIVE_CREDENTIAL_HELPER_LABEL,
            ) != native_pid
            or process_generation(native_pid, NATIVE_CREDENTIAL_HELPER_LABEL)
                != (
                    native_uid,
                    finalization["native_credential_start_generation"][0],
                    finalization["native_credential_start_generation"][1],
                )):
        raise ReleaseFailure("install_transition_service_changed")
    before = socket_path.lstat()
    if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o666):
        raise ReleaseFailure("install_transition_listener_unready")
    after = socket_path.lstat()
    if ((after.st_dev, after.st_ino, after.st_mode, after.st_uid)
            != (before.st_dev, before.st_ino, before.st_mode, before.st_uid)
            or launchd_service_pid_or_absent(
                "system", AUTHORIZATION_LABEL,
            ) != authorization_pid
            or process_generation(authorization_pid, AUTHORIZATION_LABEL)
                != (
                    0,
                    finalization["authorization_start_generation"][0],
                    finalization["authorization_start_generation"][1],
                )
            or launchd_service_pid_or_absent(
                f"gui/{native_uid}", NATIVE_CREDENTIAL_HELPER_LABEL,
            ) != native_pid
            or process_generation(native_pid, NATIVE_CREDENTIAL_HELPER_LABEL)
                != (
                    native_uid,
                    finalization["native_credential_start_generation"][0],
                    finalization["native_credential_start_generation"][1],
                )):
        raise ReleaseFailure("install_transition_listener_changed")


def finalize_install_transition(
    install_root: Path,
    expected_current_release_id: str,
    expected_authorization_pid: int,
    expected_uid: int,
    expected_listener_fd: int,
    expected_readiness_fd: int,
    expected_readiness_nonce: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    if SHA256.fullmatch(expected_current_release_id) is None:
        raise ReleaseFailure("expected_current_release_id_invalid")
    transition, root = read_pending_install_transition(
        install_root, expected_uid,
    )
    listener_open = True
    readiness_open = True
    try:
        candidate_selected = (
            transition["candidate_release_id"] == expected_current_release_id
        )
        fallback_selected = (
            transition["fallback_release_id"] == expected_current_release_id
            and transition["candidate_release_id"]
                != transition["fallback_release_id"]
        )
        if not candidate_selected and not fallback_selected:
            raise ReleaseFailure("install_transition_candidate_mismatch")
        instant = int(time.time()) if now is None else now
        finalization = transition["terminal"]
        failure_selector_ready = False
        if finalization is None:
            if fallback_selected:
                try:
                    finalization = rolled_back_install_finalization(
                        install_root, transition, expected_authorization_pid,
                        expected_uid, instant, expected_listener_fd,
                        expected_readiness_fd, expected_readiness_nonce,
                    )
                except BaseException:
                    # The exact fallback is already selected.  Preserve that
                    # launch path and persist a recovery-only fence rather than
                    # deleting the only broker that can resume this transition.
                    finalization = failed_install_finalization(
                        install_root, transition, expected_authorization_pid,
                        expected_uid, instant,
                    )
            else:
                current = install_root / "current"
                if not os.path.lexists(current):
                    # Compatibility recovery for the earlier crash window that
                    # removed current before staging its failure.  Restore the
                    # exact bound fallback first so every later crash retains
                    # a launchable recovery broker.  Only a failure may be
                    # reconstructed from this state.
                    ensure_install_failure_selector(
                        install_root, transition, expected_uid,
                    )
                    failure_selector_ready = True
                    finalization = failed_install_finalization(
                        install_root, transition, expected_authorization_pid,
                        expected_uid, instant,
                    )
                else:
                    try:
                        finalization = successful_install_finalization(
                            install_root, transition,
                            expected_authorization_pid, expected_uid, instant,
                            expected_listener_fd, expected_readiness_fd,
                            expected_readiness_nonce,
                        )
                    except BaseException as error:
                        # Candidate verification failure is a rollback request,
                        # not authority to destroy the selected launch path.
                        raise ReleaseFailure(
                            "install_transition_rollback_required"
                        ) from error
            transition = stage_install_finalization(
                root, transition, finalization, expected_uid,
            )
        else:
            finalization = validate_install_finalization(
                finalization, transition,
            )
            if finalization["status"] in {
                "deployed_verified", "failed_rolled_back",
            }:
                refreshed: dict[str, Any] | None = None
                try:
                    if (finalization["status"] == "deployed_verified"
                            and fallback_selected):
                        refreshed = rolled_back_install_finalization(
                            install_root, transition,
                            expected_authorization_pid, expected_uid, instant,
                            expected_listener_fd, expected_readiness_fd,
                            expected_readiness_nonce,
                            superseded_finalization_sha256=finalization[
                                "finalization_sha256"
                            ],
                        )
                    elif finalization["status"] == "failed_rolled_back":
                        if not fallback_selected:
                            raise ReleaseFailure(
                                "install_transition_rollback_selector_invalid"
                            )
                        refreshed = rolled_back_install_finalization(
                            install_root, transition,
                            expected_authorization_pid, expected_uid, instant,
                            expected_listener_fd,
                            expected_readiness_fd,
                            expected_readiness_nonce,
                            superseded_finalization_sha256=finalization[
                                "finalization_sha256"
                            ],
                        )
                    else:
                        if not candidate_selected:
                            raise ReleaseFailure(
                                "install_transition_candidate_mismatch"
                            )
                        refreshed = successful_install_finalization(
                            install_root, transition,
                            expected_authorization_pid, expected_uid, instant,
                            expected_listener_fd,
                            expected_readiness_fd,
                            expected_readiness_nonce,
                        )
                    stable = (
                        finalization["status"] == "deployed_verified"
                        and fallback_selected
                    ) or all(
                        refreshed[name] == finalization[name]
                        for name in (
                            "authorization_pid",
                            "authorization_start_generation",
                            "native_credential_pid",
                            "native_credential_start_generation",
                            "service_evidence_sha256",
                        )
                    )
                except BaseException:
                    stable = False
                if not stable:
                    if (finalization["status"] == "failed_rolled_back"
                            and fallback_selected
                            and refreshed is not None):
                        finalization = refreshed
                    elif candidate_selected:
                        raise ReleaseFailure(
                            "install_transition_rollback_required"
                        )
                    else:
                        finalization = failed_install_finalization(
                            install_root, transition,
                            expected_authorization_pid, expected_uid, instant,
                            superseded_finalization_sha256=finalization[
                                "finalization_sha256"
                            ],
                        )
                    transition = stage_install_finalization(
                        root, transition, finalization, expected_uid,
                    )
                elif (refreshed is not None
                      and finalization["status"] == "deployed_verified"
                      and fallback_selected):
                    # A selected fallback supersedes the candidate's staged
                    # success with an exact failed_rolled_back finalization.
                    finalization = refreshed
                    transition = stage_install_finalization(
                        root, transition, finalization, expected_uid,
                    )
        if (not failure_selector_ready and finalization["status"] in {
            "failed_fenced", "failure_fence_unproven",
        }):
            # Crash-stranded terminals from the earlier unlink-first protocol
            # can be resumed only after an exact immutable fallback is again
            # selected.  The current protocol reaches this call with fallback
            # already selected, making it an idempotent readback.
            ensure_install_failure_selector(
                install_root, transition, expected_uid,
            )
        descriptor_close_failed = False
        for descriptor, label in (
            (expected_listener_fd, "listener"),
            (expected_readiness_fd, "readiness"),
        ):
            try:
                os.close(descriptor)
                if label == "listener":
                    listener_open = False
                else:
                    readiness_open = False
            except OSError:
                descriptor_close_failed = True
        if descriptor_close_failed:
            if finalization["status"] in {
                "deployed_verified", "failed_rolled_back",
            }:
                if candidate_selected:
                    raise ReleaseFailure(
                        "install_transition_rollback_required"
                    )
                finalization = failed_install_finalization(
                    install_root, transition, expected_authorization_pid,
                    expected_uid, instant,
                    superseded_finalization_sha256=finalization[
                        "finalization_sha256"
                    ],
                )
                transition = stage_install_finalization(
                    root, transition, finalization, expected_uid,
                )
        if finalization["status"] in {
            "deployed_verified", "failed_rolled_back",
        }:
            try:
                verify_finalized_services_still_live(
                    finalization, transition["native_uid"],
                )
            except BaseException:
                if candidate_selected:
                    raise ReleaseFailure(
                        "install_transition_rollback_required"
                    )
                finalization = failed_install_finalization(
                    install_root, transition, expected_authorization_pid,
                    expected_uid, instant,
                    superseded_finalization_sha256=finalization[
                        "finalization_sha256"
                    ],
                )
                transition = stage_install_finalization(
                    root, transition, finalization, expected_uid,
                )
        _receipt, receipt_raw = complete_install_authorization_receipt(
            transition, finalization, expected_uid,
        )
        if finalization["status"] in {
            "deployed_verified", "failed_rolled_back",
        }:
            try:
                verify_finalized_services_still_live(
                    finalization, transition["native_uid"],
                )
            except BaseException:
                if candidate_selected:
                    raise ReleaseFailure(
                        "install_transition_rollback_required"
                    )
                finalization = failed_install_finalization(
                    install_root, transition, expected_authorization_pid,
                    expected_uid, instant,
                    superseded_finalization_sha256=finalization[
                        "finalization_sha256"
                    ],
                )
                transition = stage_install_finalization(
                    root, transition, finalization, expected_uid,
                )
                _receipt, receipt_raw = complete_install_authorization_receipt(
                    transition, finalization, expected_uid,
                )
        terminal = make_install_terminal(
            transition, finalization, sha256_bytes(receipt_raw),
        )
        publish_terminal_state_record(root, terminal, expected_uid)
        if finalization["status"] in {
            "deployed_verified", "failed_rolled_back",
        }:
            os.unlink(INSTALL_TRANSITION_PENDING_NAME, dir_fd=root)
            os.fsync(root)
        return terminal
    finally:
        if listener_open:
            try:
                os.close(expected_listener_fd)
            except OSError:
                pass
        if readiness_open:
            try:
                os.close(expected_readiness_fd)
            except OSError:
                pass
        os.close(root)


def prepare_install_transition_rollback(
    install_root: Path,
    expected_current_release_id: str,
    expected_authorization_pid: int,
    expected_uid: int,
) -> dict[str, Any]:
    if (SHA256.fullmatch(expected_current_release_id) is None
            or expected_authorization_pid <= 1):
        raise ReleaseFailure("install_transition_binding_required")
    transition, root = read_pending_install_transition(
        install_root, expected_uid,
    )
    try:
        terminal = transition["terminal"]
        if (transition["candidate_release_id"]
                != expected_current_release_id
                or transition["fallback_release_id"]
                    == transition["candidate_release_id"]
                or terminal is not None
                    and terminal["status"] != "deployed_verified"):
            raise ReleaseFailure("install_transition_rollback_not_required")
        current = install_root / "current"
        selected = selector_target(current, "current")
        candidate_target = f"releases/{transition['candidate_release_id']}"
        if selected == candidate_target:
            release, manifest = verified_release(
                install_root, current, expected_uid,
            )
            authorization = verify_release_authorization_service(
                release, manifest,
            )
            if authorization.get("pid") != expected_authorization_pid:
                raise ReleaseFailure(
                    "install_transition_service_identity_mismatch"
                )
            # Publish the fallback selector first.  A crash now starts the
            # predecessor, which idempotently restores ``previous`` while
            # terminalizing failed_rolled_back.  Mutating previous first could
            # let the candidate later succeed with the wrong rollback target.
            atomic_symlink(transition["old_current_target"], current)
        elif selected != transition["old_current_target"]:
            raise ReleaseFailure("install_transition_selector_changed")
        reread = selector_target(current, "current")
        if reread != transition["old_current_target"]:
            raise ReleaseFailure("install_transition_rollback_readback_failed")
        return {
            "schema": SCHEMA,
            "status": "rollback_prepared",
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "candidate_release_id": transition["candidate_release_id"],
            "fallback_release_id": transition["fallback_release_id"],
        }
    finally:
        os.close(root)


def atomic_symlink(target: str, link: Path) -> None:
    temporary = link.parent / f".{link.name}.new-{os.getpid()}"
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    temporary.symlink_to(target)
    # The authorization broker runs with a restrictive umask. On macOS that
    # umask is reflected in symlink modes and can prevent the unprivileged
    # launcher and verifiers from traversing an otherwise public selector.
    os.chmod(temporary, 0o755, follow_symlinks=False)
    os.replace(temporary, link)
    fsync_directory(link.parent)


def ensure_root(default_layout: bool) -> None:
    if default_layout and os.geteuid() != 0:
        raise ReleaseFailure("root_required")


def prepare_release_root(install_root: Path, expected_uid: int) -> Path:
    releases = install_root / "releases"
    if install_root.exists():
        info = install_root.lstat()
        if install_root.is_symlink() or not install_root.is_dir() or info.st_uid != expected_uid:
            raise ReleaseFailure("install_root_untrusted")
    if releases.exists():
        info = releases.lstat()
        if releases.is_symlink() or not releases.is_dir() or info.st_uid != expected_uid:
            raise ReleaseFailure("release_root_untrusted")
    releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(install_root, 0o755)
    os.chmod(releases, 0o755)
    entries = list(releases.iterdir())
    if len(entries) > MAX_RELEASE_DIRECTORY_ENTRIES:
        raise ReleaseFailure("release_root_entry_limit_exceeded")
    release_count = 0
    for entry in entries:
        if entry.name.startswith(".staging-"):
            info = entry.lstat()
            if entry.is_symlink() or not entry.is_dir() or info.st_uid != expected_uid:
                raise ReleaseFailure("release_root_untrusted")
            os.chmod(entry, 0o755)
            shutil.rmtree(entry)
            continue
        if not SHA256.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            raise ReleaseFailure("release_root_untrusted")
        release_count += 1
    if release_count > MAX_RELEASES:
        raise ReleaseFailure("release_count_limit_exceeded")
    return releases


def release_archive_plan(install_root: Path, expected_uid: int) -> dict[str, Any]:
    releases = install_root / "releases"
    info = releases.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o755):
        raise ReleaseFailure("release_root_untrusted")
    entries = sorted(releases.iterdir(), key=lambda path: path.name)
    if len(entries) > MAX_RELEASE_DIRECTORY_ENTRIES:
        raise ReleaseFailure("release_root_entry_limit_exceeded")
    release_ids: list[str] = []
    release_modes: dict[str, int] = {}
    for entry in entries:
        entry_info = entry.lstat()
        if (not SHA256.fullmatch(entry.name) or not stat.S_ISDIR(entry_info.st_mode)
                or stat.S_ISLNK(entry_info.st_mode) or entry_info.st_uid != expected_uid
                or stat.S_IMODE(entry_info.st_mode) not in {0o555, 0o755}):
            raise ReleaseFailure("release_root_untrusted")
        release_ids.append(entry.name)
        release_modes[entry.name] = stat.S_IMODE(entry_info.st_mode)
    if len(release_ids) < MAX_RELEASES:
        raise ReleaseFailure("release_capacity_recovery_not_required")
    current_path, _ = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    previous_id: str | None = None
    previous = install_root / "previous"
    if previous.is_symlink():
        previous_path, _ = verified_release(
            install_root, previous, expected_uid, allow_legacy=True,
        )
        previous_id = previous_path.name
    elif previous.exists():
        raise ReleaseFailure("release_link_invalid:previous")
    protected = {current_path.name}
    if previous_id is not None:
        protected.add(previous_id)
    if any(release_modes[release_id] != 0o555 for release_id in protected):
        raise ReleaseFailure("release_root_untrusted")
    archive_ids = [release_id for release_id in release_ids if release_id not in protected]
    if not archive_ids:
        raise ReleaseFailure("release_capacity_recovery_unsafe")
    plan = {
        "schema": "secure-sandbox-host-release-archive-plan-v1",
        "current_release_id": current_path.name,
        "previous_release_id": previous_id,
        "archive_release_ids": archive_ids,
    }
    plan["plan_sha256"] = sha256_bytes(
        json.dumps(plan, separators=(",", ":"), sort_keys=True).encode("ascii")
    )
    return plan


def archive_inactive_releases(
    install_root: Path, state_root: Path, expected_uid: int,
    expected_current_release_id: str, expected_previous_release_id: str,
    expected_plan_sha256: str,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    plan = release_archive_plan(install_root, expected_uid)
    expected_previous = plan["previous_release_id"] or "none"
    if (plan["current_release_id"] != expected_current_release_id
            or expected_previous != expected_previous_release_id
            or plan["plan_sha256"] != expected_plan_sha256):
        raise ReleaseFailure("release_archive_plan_changed")
    archive = install_root / "release-archive"
    try:
        archive.mkdir(mode=0o755)
        fsync_directory(install_root)
    except FileExistsError:
        pass
    archive_info = archive.lstat()
    if (not stat.S_ISDIR(archive_info.st_mode) or stat.S_ISLNK(archive_info.st_mode)
            or archive_info.st_uid != expected_uid
            or stat.S_IMODE(archive_info.st_mode) != 0o755):
        raise ReleaseFailure("release_archive_untrusted")
    existing = list(archive.iterdir())
    if len(existing) + len(plan["archive_release_ids"]) > MAX_ARCHIVED_RELEASES:
        raise ReleaseFailure("release_archive_count_limit_exceeded")
    for entry in existing:
        entry_info = entry.lstat()
        if (not SHA256.fullmatch(entry.name) or not stat.S_ISDIR(entry_info.st_mode)
                or stat.S_ISLNK(entry_info.st_mode) or entry_info.st_uid != expected_uid
                or stat.S_IMODE(entry_info.st_mode) not in {0o555, 0o755}):
            raise ReleaseFailure("release_archive_untrusted")
        if stat.S_IMODE(entry_info.st_mode) == 0o755:
            os.chmod(entry, 0o555)
    releases = install_root / "releases"
    for release_id in plan["archive_release_ids"]:
        source = releases / release_id
        destination = archive / release_id
        if destination.exists() or destination.is_symlink():
            raise ReleaseFailure("release_archive_collision")
        if stat.S_IMODE(source.lstat().st_mode) == 0o755:
            os.chmod(source, 0o555)
        verification_link = install_root / f".archive-verify-{os.getpid()}"
        verification_link.symlink_to(f"releases/{release_id}")
        try:
            # An inactive historical release may legitimately predate the
            # current monotonic activation floor.  It must still pass every
            # immutable payload, ownership, mode, bundle, and digest check
            # before it is moved out of the selectable release directory.
            verified_release(
                install_root, verification_link, expected_uid,
                allow_legacy=True, allow_below_floor=True,
            )
        finally:
            verification_link.unlink(missing_ok=True)
        # macOS requires write permission on a directory being renamed even
        # when both parents are writable.  No controller is active, and the
        # directory is unreferenced; restore immutable mode on either outcome.
        os.chmod(source, 0o755)
        try:
            os.rename(source, destination)
        except BaseException:
            os.chmod(source, 0o555)
            raise
        os.chmod(destination, 0o555)
        fsync_directory(archive)
        fsync_directory(releases)
    return {
        "schema": "secure-sandbox-host-release-archive-v1",
        "status": "archived",
        "archived": len(plan["archive_release_ids"]),
        "retained_release_ids": sorted(filter(None, (
            plan["current_release_id"], plan["previous_release_id"],
        ))),
        "plan_sha256": plan["plan_sha256"],
    }


def exact_mode(path: Path, mode: int) -> None:
    os.chmod(path, mode, follow_symlinks=False)


def validate_shell_payload(value: bytes, label: str) -> None:
    with tempfile.NamedTemporaryFile(prefix=f"secure-sandbox-{label}-", suffix=".sh") as syntax_copy:
        syntax_copy.write(value)
        syntax_copy.flush()
        syntax_result = subprocess.run(
            ["/bin/bash", "-n", syntax_copy.name], check=False, capture_output=True, text=True
        )
        if syntax_result.returncode != 0:
            raise ReleaseFailure(f"{label}_syntax_invalid")


def install(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
    expected_source_release_id: str | None = None,
    payload_override: tuple[dict[str, bytes], dict[str, str], str] | None = None,
    verify_against_source: bool = True,
    _developer_id_migration_current_release_id: str | None = None,
    authorization_request_id: str | None = None,
    authorization_request_sha256: str | None = None,
) -> dict[str, Any]:
    if (authorization_request_id is None) != (
        authorization_request_sha256 is None
    ):
        raise ReleaseFailure("install_transition_authorization_incomplete")
    if (authorization_request_id is not None
            and not manages_live_touchid_service(install_root, expected_uid)):
        raise ReleaseFailure("install_transition_layout_invalid")
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if payload_override is None:
        values, hashes, release_id = source_payload(repo, op_binary, gpgv_binary)
    else:
        values, hashes, release_id = payload_override
        if (set(values) != PAYLOAD_NAMES or set(hashes) != PAYLOAD_NAMES
                or hashes != {name: sha256_bytes(value) for name, value in values.items()}
                or release_id != release_identity(hashes)):
            raise ReleaseFailure("payload_override_invalid")
    if expected_source_release_id is not None:
        if not SHA256.fullmatch(expected_source_release_id) or release_id != expected_source_release_id:
            raise ReleaseFailure("source_release_id_unexpected")
    enforce_execution_approval_floor(values["authorization_broker"], expected_uid)
    launcher_bytes = read_regular(repo / LAUNCHER_SOURCE)
    try:
        compile(launcher_bytes, str(repo / LAUNCHER_SOURCE), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("stable_launcher_syntax_invalid") from error
    validate_shell_payload(values["controller"], "controller")
    releases = prepare_release_root(install_root, expected_uid)
    if _developer_id_migration_current_release_id is None:
        signing_floor, signing_floor_sha256 = prepare_developer_id_team_floor(
            repo, install_root, expected_uid, values, release_id,
        )
    else:
        if (not SHA256.fullmatch(_developer_id_migration_current_release_id)
                or not (
                    install_root / DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
                ).is_symlink()):
            raise ReleaseFailure("developer_id_migration_current_invalid")
        observed_floor = developer_id_team_floor(install_root, expected_uid)
        if observed_floor is None:
            raise ReleaseFailure("developer_id_team_floor_missing")
        signing_floor, signing_floor_sha256 = observed_floor
        candidate_policy = verified_authorization_ui_signing_policy(
            repo / AUTHORIZATION_UI_APP_SOURCE,
            values["authorization_ui_bundle"],
        )
        if candidate_policy["team_id"] != signing_floor["team_id"]:
            raise ReleaseFailure("release_developer_id_team_mismatch")
        predecessor_link = (
            install_root / DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
        )
        predecessor_path, _predecessor_manifest = verified_release(
            install_root, predecessor_link, expected_uid, allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
        )
        if predecessor_path.name != _developer_id_migration_current_release_id:
            raise ReleaseFailure("developer_id_migration_current_changed")
        predecessor_authorization_manifest = read_regular(
            predecessor_path / "authorization_ui_bundle"
        )
        predecessor_policy = verified_existing_authorization_ui_anchor_policy(
            predecessor_path / AUTHORIZATION_UI_APP_NAME,
            predecessor_authorization_manifest,
            expected_uid,
        )
        if predecessor_policy["team_id"] != signing_floor["team_id"]:
            raise ReleaseFailure("release_developer_id_team_mismatch")
    final = releases / release_id
    if not final.exists():
        if sum(1 for entry in releases.iterdir() if SHA256.fullmatch(entry.name)) >= MAX_RELEASES:
            raise ReleaseFailure("release_count_limit_exceeded")
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
        try:
            for name, value in values.items():
                path = staging / name
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                mode = EXPECTED_MODES[name]
                descriptor = os.open(path, flags, mode)
                try:
                    write_all(descriptor, value, "release_payload")
                    os.fsync(descriptor)
                    os.fchmod(descriptor, mode)
                finally:
                    os.close(descriptor)
            copy_authorization_ui_bundle(
                repo / AUTHORIZATION_UI_APP_SOURCE,
                staging / AUTHORIZATION_UI_APP_NAME,
                values["authorization_ui_bundle"], expected_uid,
            )
            copy_native_credential_helper_bundle(
                repo / NATIVE_CREDENTIAL_HELPER_APP_SOURCE,
                staging / NATIVE_CREDENTIAL_HELPER_APP_NAME,
                values["native_credential_helper_bundle"], expected_uid,
            )
            manifest = {"schema": SCHEMA, "release_id": release_id, "payloads": hashes}
            manifest_path = staging / "manifest.json"
            descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
            try:
                write_all(
                    descriptor,
                    (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                    "release_manifest",
                )
                os.fsync(descriptor)
                os.fchmod(descriptor, EXPECTED_MODES["manifest.json"])
            finally:
                os.close(descriptor)
            os.chmod(staging, 0o555)
            fsync_directory(staging)
            os.rename(staging, final)
            fsync_directory(releases)
        except BaseException:
            if staging.exists():
                os.chmod(staging, 0o755)
                shutil.rmtree(staging)
            raise
    candidate = install_root / f".candidate-{os.getpid()}"
    candidate.symlink_to(f"releases/{release_id}")
    try:
        verified_release(install_root, candidate, expected_uid)
    finally:
        candidate.unlink()
    current = install_root / "current"
    old_current: str | None = None
    old_path: Path | None = None
    old_manifest: dict[str, Any] | None = None
    if current.is_symlink():
        if _developer_id_migration_current_release_id is not None:
            raise ReleaseFailure("developer_id_migration_current_not_fenced")
        old_path, old_manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True,
        )
        if set(old_manifest["payloads"]) in (
            PAYLOAD_NAMES, PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES,
            PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES,
            PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES,
            PRE_NATIVE_STACK_PAYLOAD_NAMES,
            PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES, PRE_MODEL_PROFILE_PAYLOAD_NAMES,
            PRE_HARNESS_LIFECYCLE_PRE_MODEL_PROFILE_PAYLOAD_NAMES,
            PRE_PROFILED_TOUCHID_PAYLOAD_NAMES,
            PRE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES,
            PRE_HARNESS_LIFECYCLE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES,
            PRE_TOUCHID_PAYLOAD_NAMES,
        ):
            old_current = f"releases/{old_path.name}"
    elif current.exists():
        raise ReleaseFailure("release_link_invalid:current")
    observed_floor = developer_id_team_floor(install_root, expected_uid)
    if (observed_floor is None
            or observed_floor[0] != signing_floor
            or observed_floor[1] != signing_floor_sha256):
        raise ReleaseFailure("developer_id_team_floor_changed")
    enforce_release_developer_id_team_floor(
        install_root, final, hashes, expected_uid,
    )
    launcher_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if launcher_path.exists():
        installed_launcher = read_regular(launcher_path)
        launcher_info = launcher_path.stat()
        if launcher_info.st_uid != expected_uid or launcher_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReleaseFailure("launcher_permissions_invalid")
        if installed_launcher != launcher_bytes:
            raise ReleaseFailure("stable_launcher_change_requires_migration")
    else:
        launcher_tmp = launcher_path.parent / f".{launcher_path.name}.new-{os.getpid()}"
        descriptor = os.open(launcher_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        try:
            write_all(descriptor, launcher_bytes, "stable_launcher")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o755)
        finally:
            os.close(descriptor)
        os.replace(launcher_tmp, launcher_path)
        fsync_directory(launcher_path.parent)
    observed_floor = developer_id_team_floor(install_root, expected_uid)
    if (observed_floor is None
            or observed_floor[0] != signing_floor
            or observed_floor[1] != signing_floor_sha256):
        raise ReleaseFailure("developer_id_team_floor_changed")
    enforce_release_developer_id_team_floor(
        install_root, final, hashes, expected_uid,
    )
    old_previous = selector_target(install_root / "previous", "previous")
    native_uid: int | None = None
    transition: dict[str, Any] | None = None
    if authorization_request_id is not None:
        if (old_path is None or old_manifest is None or old_current is None):
            raise ReleaseFailure("install_transition_predecessor_missing")
        native_uid = console_user_uid()
        transition = begin_install_transition(
            install_root, expected_uid, final,
            {"schema": SCHEMA, "release_id": release_id, "payloads": hashes},
            old_path, old_manifest, old_current, old_previous, native_uid,
            signing_floor, signing_floor_sha256,
            authorization_request_id, authorization_request_sha256,
        )
    if (manages_live_touchid_service(install_root, expected_uid)
            and native_uid is None):
        native_uid = console_user_uid()
    try:
        if old_current and old_current != f"releases/{release_id}":
            atomic_symlink(old_current, install_root / "previous")
        elif not old_current and (install_root / "previous").is_symlink():
            (install_root / "previous").unlink()
            fsync_directory(install_root)
        observed_floor = developer_id_team_floor(install_root, expected_uid)
        if (observed_floor is None
                or observed_floor[0] != signing_floor
                or observed_floor[1] != signing_floor_sha256):
            raise ReleaseFailure("developer_id_team_floor_changed")
        atomic_symlink(f"releases/{release_id}", current)
        if verify_against_source:
            result = verify(repo, install_root, launcher_path, expected_uid, op_binary, gpgv_binary)
        else:
            verified_path, verified_manifest = verified_release(
                install_root, current, expected_uid,
            )
            if (verified_path.name != release_id
                    or verified_manifest["payloads"] != hashes
                    or sha256_bytes(read_regular(launcher_path)) != sha256_bytes(launcher_bytes)):
                raise ReleaseFailure("recovery_release_verification_failed")
            result = {
                "schema": SCHEMA,
                "status": "verified",
                "release_id": release_id,
                "launcher_sha256": sha256_bytes(launcher_bytes),
                "payloads": hashes,
            }
        if manages_live_touchid_service(install_root, expected_uid):
            observed_floor = developer_id_team_floor(install_root, expected_uid)
            if (observed_floor is None
                    or observed_floor[0] != signing_floor
                    or observed_floor[1] != signing_floor_sha256):
                raise ReleaseFailure("developer_id_team_floor_changed")
            install_touchid_service(final)
            install_native_credential_service(final, uid=native_uid)
    except BaseException:
        if (transition is not None and native_uid is not None
                and old_path is not None and old_manifest is not None
                and old_current is not None):
            try:
                stop_native_credential_service(uid=native_uid)
                restore_selector(install_root / "previous", old_previous)
                atomic_symlink(old_current, current)
                install_touchid_service(old_path)
                install_native_credential_service(old_path, uid=native_uid)
                verify_release_host_services(
                    old_path, old_manifest, native_uid,
                )
                root = open_trusted_absolute_directory(
                    install_root, expected_uid,
                )
                try:
                    os.unlink(INSTALL_TRANSITION_PENDING_NAME, dir_fd=root)
                    os.fsync(root)
                finally:
                    os.close(root)
            except BaseException as recovery_error:
                current.unlink(missing_ok=True)
                fsync_directory(install_root)
                try:
                    stop_native_credential_service(uid=native_uid)
                except BaseException:
                    pass
                raise ReleaseFailure(
                    "host_service_rollback_unproven"
                ) from recovery_error
            raise
        if manages_live_touchid_service(install_root, expected_uid):
            stop_touchid_service()
            stop_native_credential_service(uid=native_uid)
        if (old_current
                and _developer_id_migration_current_release_id is None):
            atomic_symlink(old_current, current)
        else:
            current.unlink(missing_ok=True)
            fsync_directory(install_root)
        if (manages_live_touchid_service(install_root, expected_uid)
                and old_path is not None
                and _developer_id_migration_current_release_id is None):
            try:
                if (old_path / "authorization_service").is_file():
                    install_touchid_service(old_path)
                if ((old_path / "native_credential_helper_service").is_file()
                        and (old_path / NATIVE_CREDENTIAL_HELPER_APP_NAME).is_dir()):
                    install_native_credential_service(old_path)
            except BaseException as recovery_error:
                stop_touchid_service()
                stop_native_credential_service()
                raise ReleaseFailure(
                    "host_service_rollback_unproven"
                ) from recovery_error
        raise
    if transition is None:
        result["status"] = "deployed"
    else:
        result.update({
            "status": "activation_pending",
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "authorization_request_id": transition[
                "authorization_request_id"
            ],
            "candidate_release_id": transition["candidate_release_id"],
            "expires_at": transition["expires_at"],
        })
    result["developer_id_team_id"] = signing_floor["team_id"]
    result["developer_id_team_floor_sha256"] = signing_floor_sha256
    result["developer_id_team_floor_release_id"] = signing_floor[
        "established_from_release_id"
    ]
    return result


def verified_release(
    install_root: Path, link: Path, expected_uid: int, allow_legacy: bool = False,
    allow_below_floor: bool = False,
    *, _bootstrap_without_developer_id_floor: bool = False,
) -> tuple[Path, dict[str, Any]]:
    releases = install_root / "releases"
    if not link.is_symlink():
        raise ReleaseFailure(f"release_link_missing:{link.name}")
    path = link.resolve(strict=True)
    try:
        relative = path.relative_to(releases.resolve(strict=True))
    except ValueError as error:
        raise ReleaseFailure(f"release_link_escapes_root:{link.name}") from error
    if len(relative.parts) != 1 or not SHA256.fullmatch(relative.name):
        raise ReleaseFailure("release_id_invalid")
    manifest_path = path / "manifest.json"
    manifest = json.loads(read_regular(manifest_path).decode("utf-8"))
    if manifest.get("schema") != SCHEMA or manifest.get("release_id") != relative.name:
        raise ReleaseFailure("release_manifest_identity_mismatch")
    payloads = manifest.get("payloads")
    valid_names = PAYLOAD_NAMES
    if not isinstance(payloads, dict) or (
        set(payloads) != valid_names and not (
            allow_legacy and set(payloads) in (
                LEGACY_PAYLOAD_NAMES,
                PRE_INSTALLER_PAYLOAD_NAMES,
                PRE_CONTROL_PAYLOAD_NAMES,
                PRE_AUTHORIZATION_PAYLOAD_NAMES,
                PRE_MAINTENANCE_PAYLOAD_NAMES,
                PRE_TOUCHID_PAYLOAD_NAMES,
                PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES,
                PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES,
                PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES,
                PRE_NATIVE_STACK_PAYLOAD_NAMES,
                PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES, PRE_MODEL_PROFILE_PAYLOAD_NAMES,
                PRE_HARNESS_LIFECYCLE_PRE_MODEL_PROFILE_PAYLOAD_NAMES,
                PRE_PROFILED_TOUCHID_PAYLOAD_NAMES,
                PRE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES,
                PRE_HARNESS_LIFECYCLE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES,
            )
        )
    ):
        raise ReleaseFailure("release_manifest_payloads_invalid")
    for item in [install_root, releases, path, manifest_path, *(path / name for name in payloads)]:
        info = item.stat()
        if info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReleaseFailure(f"release_permissions_invalid:{item.name}")
    if stat.S_IMODE(install_root.stat().st_mode) != 0o755 or stat.S_IMODE(releases.stat().st_mode) != 0o755:
        raise ReleaseFailure("release_root_mode_invalid")
    if stat.S_IMODE(path.stat().st_mode) != 0o555:
        raise ReleaseFailure("release_directory_mode_invalid")
    for name in [*payloads, "manifest.json"]:
        expected_mode = EXPECTED_MODES[name]
        if stat.S_IMODE((path / name).stat().st_mode) != expected_mode:
            raise ReleaseFailure(f"release_mode_invalid:{name}")
    for name, expected in payloads.items():
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise ReleaseFailure("release_manifest_hash_invalid")
        if sha256_bytes(read_regular(path / name)) != expected:
            raise ReleaseFailure(f"release_payload_hash_mismatch:{name}")
    if (not _bootstrap_without_developer_id_floor
            and developer_id_team_floor(
                install_root, expected_uid, allow_absent=True,
            ) is not None):
        enforce_release_developer_id_team_floor(
            install_root, path, payloads, expected_uid,
        )
    if NATIVE_CREDENTIAL_PAYLOAD_NAMES <= set(payloads):
        verify_native_host_products_container({
            name: read_regular(path / name)
            for name in (
                "native_host_products_container",
                "native_host_products_manifest",
                "native_host_products_notarization",
                "authorization_ui_bundle",
                "native_credential_helper_bundle",
                "native_stack_credential_client",
                "native_projection_consumer",
            )
        })
        verify_authorization_ui_bundle(
            path / AUTHORIZATION_UI_APP_NAME,
            read_regular(path / "authorization_ui_bundle"), expected_uid,
        )
        verify_native_credential_helper_bundle(
            path / NATIVE_CREDENTIAL_HELPER_APP_NAME,
            read_regular(path / "native_credential_helper_bundle"), expected_uid,
        )
        manifest = native_components_manifest(
            read_regular(path / "native_credential_helper_bundle")
        )
        enforce_native_component_signer_alignment(
            manifest,
            authorization_ui_bundle_manifest(
                read_regular(path / "authorization_ui_bundle")
            ),
        )
        verify_native_component_signature(
            path / "native_stack_credential_client",
            NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
            manifest["signing_policy"]["team_id"],
        )
        verify_native_component_signature(
            path / "native_projection_consumer",
            NATIVE_PROJECTION_CONSUMER_IDENTIFIER,
            manifest["signing_policy"]["team_id"],
        )
    if release_identity(payloads) != relative.name:
        raise ReleaseFailure("release_digest_mismatch")
    if "authorization_broker" in payloads and not allow_below_floor:
        enforce_execution_approval_floor(
            read_regular(path / "authorization_broker"), expected_uid
        )
    return path, manifest


def verify(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    path, manifest = verified_release(install_root, install_root / "current", expected_uid)
    observed_floor = developer_id_team_floor(install_root, expected_uid)
    if observed_floor is None:
        raise ReleaseFailure("developer_id_team_floor_missing")
    signing_floor, signing_floor_sha256 = observed_floor
    launcher = read_regular(launcher_path)
    source_launcher = read_regular(repo / LAUNCHER_SOURCE)
    if sha256_bytes(launcher) != sha256_bytes(source_launcher):
        raise ReleaseFailure("launcher_source_mismatch")
    info = launcher_path.stat()
    if (info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or stat.S_IMODE(info.st_mode) != 0o755):
        raise ReleaseFailure("launcher_permissions_invalid")
    _, source_hashes, source_id = source_payload(repo, op_binary, gpgv_binary)
    if manifest["payloads"] != source_hashes or manifest["release_id"] != source_id:
        raise ReleaseFailure("active_release_source_mismatch")
    return {
        "schema": SCHEMA,
        "status": "verified",
        "release_id": path.name,
        "launcher_sha256": sha256_bytes(launcher),
        "payloads": manifest["payloads"],
        "developer_id_team_id": signing_floor["team_id"],
        "developer_id_team_floor_sha256": signing_floor_sha256,
        "developer_id_team_floor_release_id": signing_floor[
            "established_from_release_id"
        ],
    }


def rollback(
    repo: Path,
    install_root: Path,
    state_root: Path,
    target_id: str | None,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    observed_floor = developer_id_team_floor(install_root, expected_uid)
    if observed_floor is None:
        raise ReleaseFailure("developer_id_team_floor_missing")
    signing_floor, signing_floor_sha256 = observed_floor
    current = install_root / "current"
    previous = install_root / "previous"
    current_path, current_manifest = verified_release(
        install_root, current, expected_uid,
    )
    old_current_target = os.readlink(current)
    if old_current_target != f"releases/{current_path.name}":
        raise ReleaseFailure("rollback_current_selector_not_exact")
    if previous.is_symlink():
        old_previous_target: str | None = os.readlink(previous)
        previous_path, _ = verified_release(
            install_root, previous, expected_uid, allow_legacy=True,
        )
        if old_previous_target != f"releases/{previous_path.name}":
            raise ReleaseFailure("rollback_previous_selector_not_exact")
    elif os.path.lexists(previous):
        raise ReleaseFailure("release_link_invalid:previous")
    else:
        old_previous_target = None
    if target_id is None:
        target_path, target_manifest = verified_release(
            install_root, install_root / "previous", expected_uid, allow_legacy=True,
        )
    else:
        if not SHA256.fullmatch(target_id):
            raise ReleaseFailure("rollback_release_id_invalid")
        target_link = install_root / f".rollback-{os.getpid()}"
        target_link.symlink_to(f"releases/{target_id}")
        try:
            target_path, target_manifest = verified_release(
                install_root, target_link, expected_uid, allow_legacy=True,
            )
        finally:
            target_link.unlink()
    if target_path == current_path:
        raise ReleaseFailure("rollback_target_already_current")
    try:
        _, _, source_id = source_payload(repo, op_binary, gpgv_binary)
        repo_match: bool | None = target_path.name == source_id
    except (ReleaseFailure, OSError):
        repo_match = None
    unchanged_developer_id_floor(
        install_root, expected_uid, signing_floor, signing_floor_sha256,
    )
    enforce_release_developer_id_team_floor(
        install_root, target_path, target_manifest["payloads"], expected_uid,
    )
    manages_services = manages_live_touchid_service(install_root, expected_uid)
    native_uid = console_user_uid() if manages_services else -1
    try:
        if manages_services:
            stop_and_fence_host_services(native_uid)
            rollback_transition_checkpoint("services-fenced")
        unchanged_developer_id_floor(
            install_root, expected_uid, signing_floor,
            signing_floor_sha256,
        )
        old_readback, old_readback_manifest = verified_release(
            install_root, current, expected_uid,
        )
        if (old_readback != current_path
                or old_readback_manifest != current_manifest
                or os.readlink(current) != old_current_target):
            raise ReleaseFailure("rollback_current_changed")
        enforce_release_developer_id_team_floor(
            install_root, target_path, target_manifest["payloads"],
            expected_uid,
        )

        atomic_symlink(f"releases/{current_path.name}", previous)
        rollback_transition_checkpoint("previous-selected")
        unchanged_developer_id_floor(
            install_root, expected_uid, signing_floor,
            signing_floor_sha256,
        )
        atomic_symlink(f"releases/{target_path.name}", current)
        rollback_transition_checkpoint("current-selected")
        selected_path, selected_manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True,
        )
        if (selected_path != target_path
                or selected_manifest != target_manifest
                or os.readlink(current) != f"releases/{target_path.name}"):
            raise ReleaseFailure("rollback_selector_readback_failed")
        unchanged_developer_id_floor(
            install_root, expected_uid, signing_floor,
            signing_floor_sha256,
        )

        if manages_services:
            if (target_path / "authorization_service").is_file():
                install_touchid_service(target_path)
            else:
                stop_touchid_service()
            rollback_transition_checkpoint("authorization-service-selected")
            if NATIVE_CREDENTIAL_PAYLOAD_NAMES <= set(
                target_manifest["payloads"]
            ):
                install_native_credential_service(
                    target_path, uid=native_uid,
                )
            else:
                stop_native_credential_service(uid=native_uid)
            rollback_transition_checkpoint("native-service-selected")
            verify_release_host_services(
                target_path, target_manifest, native_uid,
            )
            rollback_transition_checkpoint("service-identity-readback")

        final_path, final_manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True,
        )
        if (final_path != target_path or final_manifest != target_manifest
                or os.readlink(current) != f"releases/{target_path.name}"):
            raise ReleaseFailure("rollback_final_readback_failed")
        unchanged_developer_id_floor(
            install_root, expected_uid, signing_floor,
            signing_floor_sha256,
        )
        rollback_transition_checkpoint("transaction-verified")
    except BaseException:
        fence_error: BaseException | None = None
        if manages_services:
            try:
                stop_and_fence_host_services(native_uid)
            except BaseException as error:
                fence_error = error
        current.unlink(missing_ok=True)
        fsync_directory(install_root)
        try:
            if fence_error is not None:
                raise fence_error
            unchanged_developer_id_floor(
                install_root, expected_uid, signing_floor,
                signing_floor_sha256,
            )
            recovery_link = install_root / f".rollback-recovery-{os.getpid()}"
            if os.path.lexists(recovery_link):
                raise ReleaseFailure("rollback_recovery_link_exists")
            recovery_link.symlink_to(old_current_target)
            try:
                recovered_path, recovered_manifest = verified_release(
                    install_root, recovery_link, expected_uid,
                    allow_legacy=True,
                )
            finally:
                recovery_link.unlink(missing_ok=True)
            if (recovered_path != current_path
                    or recovered_manifest != current_manifest):
                raise ReleaseFailure("rollback_recovery_release_changed")
            enforce_release_developer_id_team_floor(
                install_root, recovered_path,
                recovered_manifest["payloads"], expected_uid,
            )
            restore_selector_target = old_previous_target
            restore_selector(previous, restore_selector_target)
            atomic_symlink(old_current_target, current)
            restored_path, restored_manifest = verified_release(
                install_root, current, expected_uid,
                allow_legacy=True,
            )
            if (restored_path != current_path
                    or restored_manifest != current_manifest
                    or os.readlink(current) != old_current_target):
                raise ReleaseFailure("rollback_recovery_selector_unproven")
            unchanged_developer_id_floor(
                install_root, expected_uid, signing_floor,
                signing_floor_sha256,
            )
            if manages_services:
                install_release_host_services(
                    current_path, current_manifest, native_uid,
                )
                verify_release_host_services(
                    current_path, current_manifest, native_uid,
                )
        except BaseException as recovery_error:
            if manages_services:
                stop_touchid_service()
                stop_native_credential_service(uid=native_uid)
            current.unlink(missing_ok=True)
            fsync_directory(install_root)
            try:
                restore_selector(previous, old_previous_target)
            except BaseException:
                pass
            raise ReleaseFailure(
                "rollback_transaction_recovery_unproven"
            ) from recovery_error
        raise
    return {
        "schema": SCHEMA,
        "status": "rolled_back",
        "release_id": target_path.name,
        "repo_match": repo_match,
        "warning": None if repo_match is True else "active_release_source_mismatch_until_repository_realigns",
        "developer_id_team_id": signing_floor["team_id"],
        "developer_id_team_floor_sha256": signing_floor_sha256,
        "developer_id_team_floor_release_id": signing_floor[
            "established_from_release_id"
        ],
    }


def migrate_launcher(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    expected_installed_sha256: str,
    expected_replacement_sha256: str,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if not SHA256.fullmatch(expected_installed_sha256) or not SHA256.fullmatch(expected_replacement_sha256):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    verified_release(install_root, install_root / "current", expected_uid, allow_legacy=True)
    installed = read_regular(launcher_path)
    installed_hash = sha256_bytes(installed)
    if installed_hash != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    info = launcher_path.stat()
    if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o755:
        raise ReleaseFailure("launcher_permissions_invalid")
    replacement = read_regular(repo / LAUNCHER_SOURCE)
    try:
        compile(replacement, str(repo / LAUNCHER_SOURCE), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("stable_launcher_syntax_invalid") from error
    replacement_hash = sha256_bytes(replacement)
    if replacement_hash != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    if replacement_hash == installed_hash:
        raise ReleaseFailure("launcher_migration_not_required")
    backup_root = install_root / "launcher-backups"
    if backup_root.exists():
        backup_info = backup_root.lstat()
        if backup_root.is_symlink() or not backup_root.is_dir() or backup_info.st_uid != expected_uid:
            raise ReleaseFailure("launcher_backup_root_untrusted")
    backup_root.mkdir(mode=0o555, exist_ok=True)
    exact_mode(backup_root, 0o555)
    backup = backup_root / installed_hash
    if not backup.exists():
        exact_mode(backup_root, 0o755)
        descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o555)
        try:
            write_all(descriptor, installed, "launcher_backup")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o555)
        finally:
            os.close(descriptor)
        exact_mode(backup_root, 0o555)
        fsync_directory(backup_root)
    else:
        backup_info = backup.stat()
        if (backup_info.st_uid != expected_uid or stat.S_IMODE(backup_info.st_mode) != 0o555
                or sha256_bytes(read_regular(backup)) != installed_hash):
            raise ReleaseFailure("launcher_backup_mismatch")
    temporary = launcher_path.parent / f".{launcher_path.name}.migration-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    try:
        write_all(descriptor, replacement, "launcher_migration")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o755)
    finally:
        os.close(descriptor)
    os.replace(temporary, launcher_path)
    fsync_directory(launcher_path.parent)
    if sha256_bytes(read_regular(launcher_path)) != replacement_hash:
        raise ReleaseFailure("launcher_migration_verification_failed")
    return {
        "schema": SCHEMA,
        "status": "launcher_migrated",
        "previous_launcher_sha256": installed_hash,
        "launcher_sha256": replacement_hash,
        "backup": str(backup),
    }


def bootstrap_authorization(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    expected_source_release_id: str,
    expected_installed_sha256: str,
    expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """Install the first broker while preserving explicit launcher migration."""
    if not SHA256.fullmatch(expected_source_release_id):
        raise ReleaseFailure("expected_source_release_id_required")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if source_release_id != expected_source_release_id:
        raise ReleaseFailure("source_release_id_unexpected")
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    if "authorization_broker" in current_manifest["payloads"]:
        raise ReleaseFailure("authorization_broker_already_deployed")
    if not SHA256.fullmatch(expected_installed_sha256):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    result.update({
        "status": "authorization_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def recover_terminal_schema_service(
    repo: Path, current_path: Path, install_root: Path, launcher_path: Path,
    expected_uid: int, expected_source_release_id: str,
    op_binary: Path, gpgv_binary: Path,
) -> dict[str, Any] | None:
    """Finish a schema bootstrap that committed `current` before daemon re-exec."""
    if current_path.name != expected_source_release_id:
        return None
    result = verify(
        repo, install_root, launcher_path, expected_uid, op_binary, gpgv_binary,
    )
    if result.get("release_id") != expected_source_release_id:
        raise ReleaseFailure("schema_bootstrap_recovery_release_mismatch")
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result["recovered_existing_release"] = True
    return result


def bootstrap_maintenance_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time, content-bound migration from the eight-payload broker release."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"maintenance_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_MAINTENANCE_PAYLOAD_NAMES:
        raise ReleaseFailure("maintenance_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({"status": "maintenance_schema_bootstrapped",
                   "launcher_migrated": launcher_migrated})
    return result


def bootstrap_touchid_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time, content-bound migration to the signed Touch ID payload schema."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"touchid_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_TOUCHID_PAYLOAD_NAMES:
        raise ReleaseFailure("touchid_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status": "touchid_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def bootstrap_secure_enclave_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration to the Secure Enclave UI source schema."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"secure_enclave_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PAYLOAD_NAMES:
        raise ReleaseFailure("secure_enclave_schema_predecessor_invalid")
    try:
        installed_sources = json.loads(
            read_regular(current_path / "authorization_ui_sources").decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("secure_enclave_schema_predecessor_invalid") from error
    if (installed_sources.get("schema") != "secure-sandbox-touchid-ui-source-v1"
            or set(installed_sources.get("sources", {}))
            != PRE_SECURE_ENCLAVE_TOUCHID_SOURCE_NAMES):
        raise ReleaseFailure("secure_enclave_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status": "secure_enclave_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def bootstrap_profiled_touchid_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration from a flat UI to a provisioned app bundle."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"profiled_touchid_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if frozenset(current_manifest["payloads"]) not in {
            frozenset(PRE_PROFILED_TOUCHID_PAYLOAD_NAMES),
            frozenset(PRE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES),
            frozenset(PRE_HARNESS_LIFECYCLE_PROFILED_TOUCHID_MODEL_PROFILE_PAYLOAD_NAMES)}:
        raise ReleaseFailure("profiled_touchid_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    # This migration is authorized by the terminal-bound bootstrap, not by the
    # launchd broker.  No broker request remains to answer after install(), so
    # re-exec the already-loaded service now.  Otherwise it keeps the old
    # Python module in memory while resolving files through the new `current`
    # selector and rejects every provisioned UI handshake.
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status": "profiled_touchid_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def bootstrap_touchid_bundle_v2_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration from the v1 to v2 bundle manifest."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"touchid_bundle_v2_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PAYLOAD_NAMES:
        raise ReleaseFailure("touchid_bundle_v2_schema_predecessor_invalid")
    installed_bundle = authorization_ui_bundle_manifest(
        read_regular(current_path / "authorization_ui_bundle")
    )
    replacement_bundle = authorization_ui_bundle_manifest(
        values["authorization_ui_bundle"]
    )
    if (installed_bundle.get("schema") != "secure-sandbox-touchid-ui-bundle-v1"
            or replacement_bundle.get("schema") != "secure-sandbox-touchid-ui-bundle-v2"):
        raise ReleaseFailure("touchid_bundle_v2_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status":"touchid_bundle_v2_schema_bootstrapped",
        "launcher_migrated":launcher_migrated,
        "previous_release_id":current_path.name,
    })
    return result


def bootstrap_model_profile_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration adding the model-profile manager."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"model_profile_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_MODEL_PROFILE_PAYLOAD_NAMES:
        raise ReleaseFailure("model_profile_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status":"model_profile_schema_bootstrapped",
        "launcher_migrated":launcher_migrated,
        "previous_release_id":current_path.name,
    })
    return result


def bootstrap_native_stack_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration adding native-stack protected code."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    if (
        not SHA256.fullmatch(expected_current_release_id)
        or current_path.name != expected_current_release_id
    ):
        raise ReleaseFailure("current_release_id_unexpected")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (
        not SHA256.fullmatch(expected_source_release_id)
        or source_release_id != expected_source_release_id
    ):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"native_stack_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_NATIVE_STACK_PAYLOAD_NAMES:
        raise ReleaseFailure("native_stack_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status":"native_stack_schema_bootstrapped",
        "launcher_migrated":launcher_migrated,
        "previous_release_id":current_path.name,
    })
    return result


def bootstrap_native_vendor_developer_id_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str, expected_installed_sha256: str,
    expected_replacement_sha256: str, expected_developer_id_team_id: str,
    expected_current_authorization_manifest_sha256: str,
    expected_candidate_authorization_manifest_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact migration from the trusted development-signed release.

    The ordinary installer never trusts a candidate to nominate its own Apple
    team.  This terminal-bound migration instead binds the already installed
    immutable v2 release, the operator-reviewed team, and one exact
    Developer-ID-signed source release before creating the permanent floor.
    """
    if active_markers(state_root):
        raise ReleaseFailure("active_controller_invocations")
    if (not SHA256.fullmatch(expected_source_release_id)
            or not SHA256.fullmatch(expected_current_release_id)
            or not SHA256.fullmatch(expected_installed_sha256)
            or not SHA256.fullmatch(expected_replacement_sha256)
            or not SHA256.fullmatch(
                expected_current_authorization_manifest_sha256
            )
            or not SHA256.fullmatch(
                expected_candidate_authorization_manifest_sha256
            )
            or re.fullmatch(
                r"[A-Z0-9]{10}", expected_developer_id_team_id
            ) is None):
        raise ReleaseFailure("developer_id_schema_binding_invalid")
    current_link = install_root / "current"
    predecessor_link = (
        install_root / DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
    )
    selected_link = (
        current_link if current_link.is_symlink() else predecessor_link
    )
    current_path, current_manifest = verified_release(
        install_root, selected_link, expected_uid,
        allow_legacy=True, _bootstrap_without_developer_id_floor=True,
    )
    values, _hashes, source_release_id = source_payload(
        repo, op_binary, gpgv_binary,
    )
    if source_release_id != expected_source_release_id:
        raise ReleaseFailure("source_release_id_unexpected")
    candidate_manifest = values["authorization_ui_bundle"]
    if sha256_bytes(candidate_manifest) != (
        expected_candidate_authorization_manifest_sha256
    ):
        raise ReleaseFailure("candidate_authorization_manifest_changed")
    candidate_policy = verified_authorization_ui_signing_policy(
        repo / AUTHORIZATION_UI_APP_SOURCE, candidate_manifest,
    )
    if candidate_policy["team_id"] != expected_developer_id_team_id:
        raise ReleaseFailure("candidate_developer_id_team_unexpected")

    existing_floor = reconcile_developer_id_team_floor_publication(
        install_root, expected_uid,
    )
    if current_path.name == source_release_id:
        if existing_floor is None:
            raise ReleaseFailure("developer_id_migration_floor_missing")
        verified = verify(
            repo, install_root, launcher_path, expected_uid,
            op_binary, gpgv_binary,
        )
        if manages_live_touchid_service(install_root, expected_uid):
            restart_touchid_service()
            install_native_credential_service(current_path)
        if predecessor_link.is_symlink():
            predecessor_link.unlink()
            fsync_directory(install_root)
        verified.update({
            "status": "native_vendor_developer_id_schema_bootstrapped",
            "recovered_existing_release": True,
            "previous_release_id": expected_current_release_id,
        })
        return verified

    if current_path.name != expected_current_release_id:
        raise ReleaseFailure("current_release_id_unexpected")
    if set(current_manifest["payloads"]) != PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES:
        raise ReleaseFailure("native_vendor_schema_predecessor_invalid")
    current_authorization_manifest = read_regular(
        current_path / "authorization_ui_bundle"
    )
    if sha256_bytes(current_authorization_manifest) != (
        expected_current_authorization_manifest_sha256
    ):
        raise ReleaseFailure("current_authorization_manifest_changed")
    anchor_policy = verified_existing_authorization_ui_anchor_policy(
        current_path / AUTHORIZATION_UI_APP_NAME,
        current_authorization_manifest,
        expected_uid,
    )
    if (anchor_policy["team_id"] != expected_developer_id_team_id
            or candidate_policy["team_id"] != anchor_policy["team_id"]):
        raise ReleaseFailure("release_developer_id_team_mismatch")

    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 == expected_installed_sha256:
        if installed_sha256 != replacement_sha256:
            migrate_launcher(
                repo, install_root, launcher_path, state_root, expected_uid,
                installed_sha256, replacement_sha256,
            )
            launcher_migrated = True
    elif installed_sha256 != replacement_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")

    if manages_live_touchid_service(install_root, expected_uid):
        stop_touchid_service()
        stop_native_credential_service()
    if predecessor_link.is_symlink():
        predecessor_path, _predecessor_manifest = verified_release(
            install_root, predecessor_link, expected_uid, allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
        )
        if predecessor_path.name != current_path.name:
            raise ReleaseFailure("developer_id_migration_predecessor_changed")
    elif predecessor_link.exists():
        raise ReleaseFailure("developer_id_migration_predecessor_invalid")
    else:
        atomic_symlink(
            f"releases/{current_path.name}", predecessor_link,
        )
    if current_link.is_symlink():
        current_recheck, _current_recheck_manifest = verified_release(
            install_root, current_link, expected_uid, allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
        )
        if current_recheck.name != current_path.name:
            raise ReleaseFailure("developer_id_migration_current_changed")
        current_link.unlink()
        fsync_directory(install_root)
    elif current_link.exists():
        raise ReleaseFailure("release_link_invalid:current")
    if existing_floor is None:
        floor_record = developer_id_floor_record(
            release_id=current_path.name,
            authorization_manifest=current_authorization_manifest,
            policy=anchor_policy,
            established_at=int(time.time()),
        )
        existing_floor = create_developer_id_team_floor(
            install_root, expected_uid, floor_record,
        )
    floor, _floor_sha256 = existing_floor
    if (floor["team_id"] != expected_developer_id_team_id
            or floor["established_from_release_id"] != current_path.name
            or floor["established_from_authorization_manifest_sha256"]
                != expected_current_authorization_manifest_sha256):
        raise ReleaseFailure("developer_id_migration_floor_mismatch")
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
        _developer_id_migration_current_release_id=current_path.name,
    )
    predecessor_link.unlink()
    fsync_directory(install_root)
    result.update({
        "status": "native_vendor_developer_id_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def bootstrap_authorization_icon_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration adding attested authorization icon sources."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"authorization_icon_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PAYLOAD_NAMES:
        raise ReleaseFailure("authorization_icon_schema_predecessor_invalid")
    try:
        installed_sources = json.loads(
            read_regular(current_path / "authorization_ui_sources").decode("utf-8")
        )
        replacement_sources = json.loads(values["authorization_ui_sources"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("authorization_icon_schema_predecessor_invalid") from error
    if (installed_sources.get("schema") != "secure-sandbox-touchid-ui-source-v1"
            or set(installed_sources.get("sources", {}))
            != PRE_AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES
            or replacement_sources.get("schema")
            != "secure-sandbox-touchid-ui-source-v1"
            or set(replacement_sources.get("sources", {}))
            != AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES):
        raise ReleaseFailure("authorization_icon_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status":"authorization_icon_schema_bootstrapped",
        "launcher_migrated":launcher_migrated,
        "previous_release_id":current_path.name,
    })
    return result


def recover_operator_ceremony_broker(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """Replace only the exact immutable pre-execution ceremony-broker defect."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    current_broker_sha256 = sha256_bytes(
        read_regular(current_path / "authorization_broker")
    )
    if (expected_current_release_id != BROKEN_CEREMONY_BROKER_RELEASE_ID
            or current_path.name != expected_current_release_id
            or current_broker_sha256 != BROKEN_CEREMONY_BROKER_SHA256):
        raise ReleaseFailure("operator_ceremony_broker_recovery_predecessor_invalid")
    values, _hashes, source_release_id = source_payload(
        repo, op_binary, gpgv_binary
    )
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id
            or source_release_id == current_path.name):
        raise ReleaseFailure("operator_ceremony_broker_recovery_source_invalid")
    current_bundle = authorization_ui_bundle_manifest(
        read_regular(current_path / "authorization_ui_bundle")
    )
    source_bundle = authorization_ui_bundle_manifest(
        values["authorization_ui_bundle"]
    )
    if (set(current_manifest["payloads"]) != PAYLOAD_NAMES
            or current_bundle.get("schema")
            != "secure-sandbox-touchid-ui-bundle-v2"
            or source_bundle.get("schema")
            != "secure-sandbox-touchid-ui-bundle-v2"):
        raise ReleaseFailure("operator_ceremony_broker_recovery_schema_invalid")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if (installed_sha256 != expected_installed_sha256
            or replacement_sha256 != expected_replacement_sha256
            or installed_sha256 != replacement_sha256):
        raise ReleaseFailure("operator_ceremony_broker_recovery_launcher_invalid")
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status":"operator_ceremony_broker_recovered",
        "previous_release_id":current_path.name,
    })
    return result


def recover_touchid_ui(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time, content-bound recovery from the known no-window AppKit build."""
    current_path, _current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    values, hashes, source_release_id = touchid_ui_recovery_payload(
        repo, install_root, expected_uid, op_binary, gpgv_binary,
    )
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    if installed_sha256 != replacement_sha256:
        raise ReleaseFailure("touchid_ui_recovery_launcher_change_forbidden")
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
        payload_override=(values, hashes, source_release_id),
        verify_against_source=False,
    )
    result.update({
        "status": "touchid_ui_recovered",
        "launcher_migrated": False,
        "previous_release_id": current_path.name,
    })
    return result


def touchid_ui_recovery_payload(
    repo: Path, install_root: Path, expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> tuple[dict[str, bytes], dict[str, str], str]:
    verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    raise ReleaseFailure("touchid_ui_recovery_superseded_by_profiled_schema")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "command",
        choices=("install", "verify", "rollback", "migrate-launcher",
                 "finalize-install-transition",
                 "prepare-install-transition-rollback",
                 "bootstrap-authorization",
                 "bootstrap-maintenance-schema", "bootstrap-touchid-schema",
                 "bootstrap-secure-enclave-schema", "bootstrap-profiled-touchid-schema",
                 "bootstrap-touchid-bundle-v2-schema",
                 "bootstrap-model-profile-schema",
                 "bootstrap-native-stack-schema",
                 "bootstrap-native-vendor-developer-id-schema",
                 "bootstrap-authorization-icon-schema",
                 "recover-operator-ceremony-broker",
                 "recover-touchid-ui",
                 "archive-inactive-releases"),
    )
    result.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    result.add_argument("--install-root", type=Path, default=Path("/usr/local/libexec/secure-sandbox-host"))
    result.add_argument("--launcher", type=Path, default=Path("/usr/local/bin/secure-sandbox-claude"))
    result.add_argument("--state-root", type=Path)
    result.add_argument("--release-id")
    result.add_argument("--expected-launcher-sha256")
    result.add_argument("--expected-replacement-sha256")
    result.add_argument("--expected-source-release-id")
    result.add_argument("--authorization-request-id")
    result.add_argument("--authorization-request-sha256")
    result.add_argument("--expected-authorization-pid", type=int)
    result.add_argument("--expected-listener-fd", type=int)
    result.add_argument("--expected-readiness-fd", type=int)
    result.add_argument("--expected-readiness-nonce")
    result.add_argument("--expected-current-release-id")
    result.add_argument("--expected-developer-id-team-id")
    result.add_argument("--expected-current-authorization-manifest-sha256")
    result.add_argument("--expected-candidate-authorization-manifest-sha256")
    result.add_argument("--expected-previous-release-id")
    result.add_argument("--expected-plan-sha256")
    result.add_argument("--op-binary", type=Path, default=DEFAULT_OP_BINARY)
    result.add_argument("--gpgv-binary", type=Path, default=DEFAULT_GPGV_BINARY)
    result.add_argument("--json", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    default_layout = args.install_root == Path("/usr/local/libexec/secure-sandbox-host")
    if args.state_root is None:
        state_root = invoking_home() / "Library/Application Support/SecureSandbox/controller-state"
    else:
        state_root = args.state_root
    expected_uid = 0 if default_layout else os.geteuid()
    try:
        if args.command == "install":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if default_layout and not args.expected_source_release_id:
                raise ReleaseFailure("expected_source_release_id_required")
            result = install(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.op_binary, args.gpgv_binary,
                args.expected_source_release_id,
                authorization_request_id=args.authorization_request_id,
                authorization_request_sha256=args.authorization_request_sha256,
            )
        elif args.command == "finalize-install-transition":
            ensure_root(default_layout)
            if (not args.expected_current_release_id
                    or args.expected_authorization_pid is None
                    or args.expected_listener_fd is None
                    or args.expected_readiness_fd is None
                    or not args.expected_readiness_nonce):
                raise ReleaseFailure("install_transition_binding_required")
            result = finalize_install_transition(
                args.install_root, args.expected_current_release_id,
                args.expected_authorization_pid, expected_uid,
                args.expected_listener_fd, args.expected_readiness_fd,
                args.expected_readiness_nonce,
            )
        elif args.command == "prepare-install-transition-rollback":
            ensure_root(default_layout)
            if (not args.expected_current_release_id
                    or args.expected_authorization_pid is None):
                raise ReleaseFailure("install_transition_binding_required")
            result = prepare_install_transition_rollback(
                args.install_root, args.expected_current_release_id,
                args.expected_authorization_pid, expected_uid,
            )
        elif args.command == "verify":
            result = verify(
                args.repo.resolve(), args.install_root, args.launcher,
                expected_uid, args.op_binary, args.gpgv_binary,
            )
        elif args.command == "rollback":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            result = rollback(
                args.repo.resolve(), args.install_root, state_root, args.release_id,
                expected_uid, args.op_binary, args.gpgv_binary,
            )
        elif args.command == "migrate-launcher":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if not args.expected_launcher_sha256 or not args.expected_replacement_sha256:
                raise ReleaseFailure("expected_launcher_hash_required")
            result = migrate_launcher(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_launcher_sha256, args.expected_replacement_sha256,
            )
        elif args.command == "archive-inactive-releases":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if not all((args.expected_current_release_id,
                        args.expected_previous_release_id,
                        args.expected_plan_sha256)):
                raise ReleaseFailure("release_archive_binding_required")
            if (SHA256.fullmatch(args.expected_current_release_id) is None
                    or (args.expected_previous_release_id != "none"
                        and SHA256.fullmatch(args.expected_previous_release_id) is None)
                    or SHA256.fullmatch(args.expected_plan_sha256) is None):
                raise ReleaseFailure("release_archive_binding_invalid")
            result = archive_inactive_releases(
                args.install_root, state_root, expected_uid,
                args.expected_current_release_id,
                args.expected_previous_release_id,
                args.expected_plan_sha256,
            )
        elif args.command == "bootstrap-authorization":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("bootstrap_binding_required")
            result = bootstrap_authorization(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-maintenance-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("maintenance_schema_binding_required")
            result = bootstrap_maintenance_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-touchid-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("touchid_schema_binding_required")
            result = bootstrap_touchid_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-secure-enclave-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("secure_enclave_schema_binding_required")
            result = bootstrap_secure_enclave_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-profiled-touchid-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("profiled_touchid_schema_binding_required")
            result = bootstrap_profiled_touchid_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-touchid-bundle-v2-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("touchid_bundle_v2_schema_binding_required")
            result = bootstrap_touchid_bundle_v2_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-model-profile-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("model_profile_schema_binding_required")
            result = bootstrap_model_profile_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-native-stack-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("native_stack_schema_binding_required")
            result = bootstrap_native_stack_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-native-vendor-developer-id-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id
                    or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256
                    or not args.expected_developer_id_team_id
                    or not args.expected_current_authorization_manifest_sha256
                    or not args.expected_candidate_authorization_manifest_sha256):
                raise ReleaseFailure(
                    "native_vendor_developer_id_schema_binding_required"
                )
            result = bootstrap_native_vendor_developer_id_schema(
                args.repo.resolve(), args.install_root, args.launcher,
                state_root, expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256,
                args.expected_replacement_sha256,
                args.expected_developer_id_team_id,
                args.expected_current_authorization_manifest_sha256,
                args.expected_candidate_authorization_manifest_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-authorization-icon-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("authorization_icon_schema_binding_required")
            result = bootstrap_authorization_icon_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "recover-operator-ceremony-broker":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("operator_ceremony_broker_recovery_binding_required")
            result = recover_operator_ceremony_broker(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        else:
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("touchid_ui_recovery_binding_required")
            result = recover_touchid_ui(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        print(json.dumps(result, indent=2 if args.json else None, sort_keys=True))
        if (args.command == "finalize-install-transition"
                and result.get("status") not in {
                    "deployed_verified", "failed_rolled_back",
                }):
            return 1
        return 0
    except (ReleaseFailure, OSError, subprocess.CalledProcessError, json.JSONDecodeError, SyntaxError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
