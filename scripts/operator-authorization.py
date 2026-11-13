#!/usr/bin/env python3
"""Operator-visible, replay-resistant authorization for host mutations."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import plistlib
import pwd
import re
import resource
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, NamedTuple


_NATIVE_STACK_SUPPORT = Path(__file__).with_name("native_stack_support")
if _NATIVE_STACK_SUPPORT.is_file():
    sys.path.insert(0, str(_NATIVE_STACK_SUPPORT))
elif Path(__file__).resolve().parent.name == "scripts":
    _NATIVE_STACK_SOURCE_ROOT = Path(__file__).resolve().parent.parent
    if (_NATIVE_STACK_SOURCE_ROOT / "shared/native_stack_operations.py").is_file():
        sys.path.insert(0, str(_NATIVE_STACK_SOURCE_ROOT))

from shared import native_stack_catalog_promotion
from shared import native_codex_ui_handle
from shared import native_deployment
from shared import native_stack_operations
from shared import native_stack_session
from shared import native_program_attestation
from shared import native_projection_identity_recovery
from shared import native_projection_reconciliation
from shared import native_terminal_handle
from shared import native_vendor_stack


SCHEMA = "secure-sandbox-operator-authorization-v1"
RECEIPT_SCHEMA = "secure-sandbox-operator-authorization-receipt-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
NATIVE_HOST_CANDIDATE_SCHEMA = (
    "secure-sandbox-native-host-candidate-record-v2"
)
NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA = (
    "secure-sandbox-native-host-release-preimage-v1"
)
NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME = (
    "SecureSandboxHostReleasePreimage.tar"
)
HOST_RELEASE_TARGET_PLAN_SCHEMA = (
    "secure-sandbox-host-release-target-plan-v1"
)
HOST_RELEASE_ROLLBACK_PLAN_SCHEMA = (
    "secure-sandbox-host-release-rollback-plan-v1"
)
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0
_ACL_LIBC = ctypes.CDLL(None, use_errno=True)
_ACL_GET_FD_NP = getattr(_ACL_LIBC, "acl_get_fd_np", None)
_ACL_GET_FILE = getattr(_ACL_LIBC, "acl_get_file", None)
_ACL_GET_ENTRY = getattr(_ACL_LIBC, "acl_get_entry", None)
_ACL_FREE = getattr(_ACL_LIBC, "acl_free", None)
if _ACL_GET_FD_NP is not None:
    _ACL_GET_FD_NP.argtypes = [ctypes.c_int, ctypes.c_int]
    _ACL_GET_FD_NP.restype = ctypes.c_void_p
if _ACL_GET_FILE is not None:
    _ACL_GET_FILE.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _ACL_GET_FILE.restype = ctypes.c_void_p
if _ACL_GET_ENTRY is not None:
    _ACL_GET_ENTRY.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
    ]
    _ACL_GET_ENTRY.restype = ctypes.c_int
if _ACL_FREE is not None:
    _ACL_FREE.argtypes = [ctypes.c_void_p]
    _ACL_FREE.restype = ctypes.c_int
SAFE_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:/+-]{0,79}$")
SAFE_SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")
CONTROL_CENTER_BUNDLE_ID = "org.zebeth.SecureSandbox.ControlCenter"
DEVELOPER_ID_APPLICATION_OID = "1.2.840.113635.100.6.1.13"
# ``SecCodeCheckValidityWithErrors`` accepts the dynamic strict-validation bit,
# but rejects the static all-architectures/nested-code bits.  Kernel-side
# requirement matching also rejects the complete Developer ID certificate
# requirement.  Keep live-process and full-bundle validation as two separate
# Security.framework operations.
CONTROL_CENTER_DYNAMIC_VALIDATION_FLAGS = 1 << 4
CONTROL_CENTER_STATIC_COPY_FLAGS = 1 << 0
CONTROL_CENTER_STATIC_VALIDATION_FLAGS = (1 << 0) | (1 << 3) | (1 << 4)
MAX_PURPOSE = 240
MAX_RESOURCE = 240
REQUEST_TTL_SECONDS = 180
LOCK_TIMEOUT_SECONDS = 5
DIALOG_TIMEOUT_SECONDS = 90
AUTH_TIMEOUT_SECONDS = 180
OPERATION_TIMEOUT_SECONDS = 120
NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS = 60 * 60 + 300
AUTHORIZATION_COMPLETION_MARGIN_SECONDS = 60
TOUCHID_SOCKET = Path("/var/run/secure-sandbox-authorization.sock")
HOST_INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
HOST_INSTALL_PENDING = HOST_INSTALL_ROOT / ".install-transition.json"
HOST_PAIR_PUBLIC = HOST_INSTALL_ROOT / "host-release-launcher-pair.json"
HOST_INSTALL_TRANSITION_TTL_SECONDS = 600
HOST_INSTALL_TRANSITION_FIELDS = {
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
HOST_INSTALL_TERMINAL_FIELDS = {
    "schema", "status", "transition_id", "transition_sha256",
    "authorization_request_id", "authorization_request_sha256",
    "candidate_release_id", "candidate_manifest_sha256",
    "candidate_authorization_manifest_sha256", "developer_id_team_id",
    "developer_id_team_floor_sha256", "old_authorization_pid",
    "old_authorization_start_generation", "authorization_pid",
    "authorization_start_generation", "native_credential_pid",
    "native_credential_start_generation", "service_evidence_sha256",
    "authorization_receipt_sha256", "completed_at", "error",
    "terminal_sha256",
}
HOST_PAIR_TRANSITION_SCHEMA = "secure-sandbox-host-pair-transition-v2"
HOST_PAIR_TERMINAL_SCHEMA = "secure-sandbox-host-pair-terminal-v1"
HOST_PAIR_STABLE_SCHEMA = "secure-sandbox-host-release-launcher-pair-v1"
HOST_PAIR_PENDING_SCHEMA = (
    "secure-sandbox-host-release-launcher-pair-transition-v1"
)
HOST_PAIR_REQUIRED_FEATURE = "host-release-launcher-pair-fence-v1"
HOST_PAIR_BOOTSTRAP_ADMISSION_SCHEMA = (
    "secure-sandbox-host-pair-bootstrap-admission-v1"
)
HOST_PAIR_BOOTSTRAP_MODES = {
    "authorization-bootstrap", "candidate-schema-bootstrap",
}
HOST_PAIR_TRANSITION_FIELDS = {
    "schema", "operation", "bootstrap", "bootstrap_admission",
    "transition_id",
    "transition_sha256", "created_at", "expires_at",
    "authorization_request_id", "authorization_request_sha256",
    "authorization_pending_receipt_sha256",
    "authorized_target_plan_sha256", "source_stable_sha256",
    "source_pair", "target_pair", "target_candidate_authority_sha256",
    "source_launcher_generation_sha256",
    "target_launcher_generation_sha256", "old_current_target",
    "old_previous_target", "native_uid", "old_services",
    "old_services_sha256", "developer_id_team_id",
    "developer_id_team_floor_sha256", "finalization", "terminal",
}
HOST_PAIR_TERMINAL_FIELDS = {
    "schema", "status", "operation", "transition_id",
    "transition_sha256", "committed_pair", "authorization_request_id",
    "authorization_request_sha256", "authorized_target_plan_sha256",
    "completed_at", "service_evidence", "service_evidence_sha256", "error",
    "authorization_receipt_sha256", "finalization_sha256",
    "terminal_sha256",
}
HOST_PAIR_FINALIZATION_SCHEMA = "secure-sandbox-host-pair-finalization-v1"
HOST_PAIR_SERVICE_EVIDENCE_SCHEMA = (
    "secure-sandbox-host-pair-service-evidence-v1"
)
TOUCHID_SCHEMA = "secure-sandbox-touchid-approval-v1"
NATIVE_INSPECT_QUERY_SCHEMA = "secure-sandbox-native-stack-inspect-request-v1"
NATIVE_INSPECT_REPLY_SCHEMA = "secure-sandbox-native-stack-inspect-query-reply-v1"
NATIVE_SESSION_PLAN_QUERY_SCHEMA = (
    "secure-sandbox-native-stack-session-plan-request-v1"
)
NATIVE_SESSION_PLAN_REPLY_SCHEMA = (
    "secure-sandbox-native-stack-session-plan-query-reply-v1"
)
NATIVE_PROJECTION_PLAN_QUERY_SCHEMA = (
    "secure-sandbox-native-projection-reconciliation-plan-request-v1"
)
NATIVE_PROJECTION_PLAN_REPLY_SCHEMA = (
    "secure-sandbox-native-projection-reconciliation-plan-query-reply-v1"
)
NATIVE_PROJECTION_IDENTITY_PLAN_QUERY_SCHEMA = (
    "secure-sandbox-native-projection-identity-recovery-plan-request-v1"
)
NATIVE_PROJECTION_IDENTITY_PLAN_REPLY_SCHEMA = (
    "secure-sandbox-native-projection-identity-recovery-plan-query-reply-v1"
)
NATIVE_DEPLOYMENT_QUERY_SCHEMAS = {
    "plan": "secure-sandbox-native-deployment-plan-request-v1",
    "status": "secure-sandbox-native-deployment-status-request-v1",
    "recovery-plan": (
        "secure-sandbox-native-deployment-recovery-plan-request-v1"
    ),
}
NATIVE_DEPLOYMENT_REPLY_SCHEMAS = {
    "plan": "secure-sandbox-native-deployment-plan-reply-v1",
    "status": "secure-sandbox-native-deployment-status-reply-v1",
    "recovery-plan": (
        "secure-sandbox-native-deployment-recovery-plan-reply-v1"
    ),
}
NATIVE_DEPLOYMENT_QUERY_ERROR_SCHEMA = (
    "secure-sandbox-native-deployment-query-error-v1"
)
NATIVE_DEPLOYMENT_PLAN_RESPONSE_SCHEMA = (
    "secure-sandbox-native-deployment-plan-response-v1"
)
NATIVE_DEPLOYMENT_STATUS_SCHEMA = (
    "secure-sandbox-native-deployment-public-status-v1"
)
NATIVE_DEPLOYMENT_RECOVERY_PLAN_SCHEMA = (
    "secure-sandbox-native-deployment-recovery-plan-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_COMMAND = "catalog-promotion-gate"
NATIVE_CATALOG_PROMOTION_GATE_REQUEST_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-request-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_REPLY_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-reply-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_ERROR_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-error-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-state-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND = (
    "catalog-promotion-recover-active"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_REQUEST_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-request-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_REPLY_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-reply-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_ERROR_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-error-v1"
)
NATIVE_CATALOG_PROMOTION_RECOVERY_TERMINAL_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-terminal-v1"
)
NATIVE_CATALOG_PUBLIC_STATUS_SCHEMA = (
    "secure-sandbox-native-stack-catalog-public-status-v1"
)
NATIVE_TERMINAL_HANDLE_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-terminal-handles"
)
NATIVE_CODEX_UI_HANDLE_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-codex-ui-handles"
)
TOUCHID_UI_APP_NAME = "SecureSandboxAuthorizationUI.app"
TOUCHID_UI_EXECUTABLE = Path("Contents/MacOS/SecureSandboxAuthorizationUI")
DEFAULT_TOUCHID_UI = (Path("/usr/local/libexec/secure-sandbox-host/current")
                      / TOUCHID_UI_APP_NAME / TOUCHID_UI_EXECUTABLE)
LSREGISTER = Path(
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
    "LaunchServices.framework/Support/lsregister"
)
TOUCHID_PASSWORD_FALLBACK_EXIT = 10
TOUCHID_CANCELLED_EXIT = 20
TOUCHID_EXPIRED_EXIT = 22
TOUCHID_RESPONSE_LIMIT = 16 * 1024 * 1024
DIAGNOSTIC_SCHEMA = "secure-sandbox-operator-diagnostic-v1"
CEREMONIES = {"approve", "cancel-test"}
# Exact bundle-manifest identity of the already-deployed pre-result-channel UI.
# It is accepted only for the successful, schema-checked responses needed to
# finish and rotate the already-active migration.  Missing output is never
# interpreted as cancellation or success.
LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256 = (
    "__LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256__"
)
DEFAULT_RECEIPT_ROOT = Path("/usr/local/var/log/secure-sandbox/authorization-receipts")
DEFAULT_PUBLIC_RECEIPT_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/operator-authorization-receipts"
)
NATIVE_PROGRAM_ATTESTATION_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-program-attestations"
)
PROTECTED_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
EXECUTION_APPROVAL_ROOT = Path("/usr/local/var/lib/secure-sandbox/execution-approval")
EXECUTION_APPROVAL_KEY = EXECUTION_APPROVAL_ROOT / "id_ed25519"
EXECUTION_APPROVAL_PENDING = EXECUTION_APPROVAL_ROOT / "secure-enclave-pending.json"
EXECUTION_APPROVAL_ACTIVE = EXECUTION_APPROVAL_ROOT / "secure-enclave-active.json"
EXECUTION_APPROVAL_PUBLIC = EXECUTION_APPROVAL_ROOT / "secure-enclave-public.json"
EXECUTION_APPROVAL_FLOOR = EXECUTION_APPROVAL_ROOT / "minimum-floor.json"
EXECUTION_APPROVAL_PUBLIC_FLOOR = EXECUTION_APPROVAL_ROOT / "minimum-floor.public.json"
EXECUTION_APPROVAL_COMPLETIONS = EXECUTION_APPROVAL_ROOT / "completion-receipts"
EXECUTION_APPROVAL_NAMESPACE = "secure-sandbox-execution-approval-v1"
EXECUTION_APPROVAL_V2_ALGORITHM = "ecdsa-p256-sha256-x962-low-s"
EXECUTION_APPROVAL_V2_NAMESPACE = "secure-sandbox-execution-approval-v2"
EXECUTION_APPROVAL_V2_ATTESTATION = "secure-sandbox-execution-approval-attestation-v2"
EXECUTION_APPROVAL_V2_ENVELOPE = "secure-sandbox-execution-approval-envelope-v2"
# Release-floor capability marker consumed by the immutable release manager.
EXECUTION_APPROVAL_V2_FLOOR_CAPABILITY = "secure-sandbox-execution-approval-floor-enforcement-v2"
APPLE_TEAM_ID = re.compile(r"[A-Z0-9]{10}")
MAX_HOST_PREPARE_RELEASE_REBINDS = 3
MAX_RESEARCH_PREPARE_RELEASE_REBINDS = 3
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
P256_HALF_ORDER = P256_ORDER // 2
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
EXPECTED_RELEASE_MODES = {
    "authorization_broker": 0o755,
    "authorization_service": 0o444,
    "authorization_ui_bundle": 0o444,
    "authorization_ui_sources": 0o444,
    "control_client": 0o755,
    "controller": 0o755,
    "gpgv": 0o555,
    "installer_verifier": 0o755,
    "model_profile_manager": 0o755,
    "native_stack_manager": 0o755,
    "native_stack_session_manager": 0o755,
    "native_stack_catalog_promoter": 0o755,
    "native_stack_deployer": 0o755,
    "native_stack_backend": 0o755,
    "native_stack_terminal_bridge": 0o755,
    "native_stack_credential_client": 0o555,
    "native_projection_consumer": 0o555,
    "native_credential_helper_bundle": 0o444,
    "native_credential_helper_service": 0o444,
    "native_host_products_container": 0o444,
    "native_host_products_manifest": 0o444,
    "native_host_products_notarization": 0o444,
    "native_host_products_notarization_signature": 0o444,
    "native_stack_support": 0o444,
    "native_deployment_payloads": 0o444,
    "native_stack_coordination_contract": 0o444,
    "harness_lifecycle_manager": 0o755,
    "pki_anchor": 0o755,
    "release_manager": 0o755,
    "seed_verifier": 0o755,
    "seed_gateway": 0o444,
    "seed_research": 0o444,
    "seed_target": 0o444,
    "ssh_config": 0o444,
    "vm_maintenance": 0o755,
}
PRE_NATIVE_HOST_RECEIPT_SIGNATURE_RELEASE_MODES = {
    name: mode for name, mode in EXPECTED_RELEASE_MODES.items()
    if name != "native_host_products_notarization_signature"
}
PRE_NATIVE_STACK_COORDINATION_RELEASE_MODES = {
    name: mode
    for name, mode in PRE_NATIVE_HOST_RECEIPT_SIGNATURE_RELEASE_MODES.items()
    if name != "native_stack_coordination_contract"
}
NATIVE_STACK_COORDINATION_CONTRACT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-contract-v1"
)
NATIVE_STACK_COORDINATION_FLOOR_NAME = (
    "native-stack-coordination-minimum.json"
)
NATIVE_STACK_COORDINATION_FLOOR_SCHEMA = (
    "secure-sandbox-native-stack-coordination-minimum-v1"
)
NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME = (
    "native-stack-coordination-enforcement.json"
)
NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-enforcement-v1"
)
NATIVE_STACK_COORDINATION_REQUIRED_FEATURES = {
    "catalog-promotion-gate-v1",
    "deployment-promotion-admission-v1",
    "host-install-transition-fence-v1",
    "host-selector-two-way-gate-v1",
}
NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE = (
    "native-host-candidate-admission-v1"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME = (
    "native-host-candidate-enforcement.json"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME = (
    ".native-host-candidate-enforcement.pending"
)
NATIVE_HOST_CANDIDATE_FLOOR_NAME = (
    "native-host-candidate-minimum.json"
)
NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME = (
    ".native-host-candidate-minimum.pending"
)
NATIVE_HOST_CANDIDATE_FLOOR_SCHEMA = (
    "secure-sandbox-native-host-candidate-minimum-v1"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-native-host-candidate-enforcement-v1"
)
NATIVE_HOST_CANDIDATE_INVENTORY_SCHEMA = (
    "secure-sandbox-native-host-candidate-inventory-v1"
)
NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID = (
    "c5a743994359cd4af0d9b56fa9385afbcbf52370d96d6c97a47b188d8c88844c"
)
OPERATION_RESOURCES = {
    "authorization-probe": "/usr/local/libexec/secure-sandbox-host",
    "execution-approval-key-init": "/usr/local/var/lib/secure-sandbox/execution-approval",
    "execution-approval-sign": "Disposable execution in SecureSandbox-Target",
    "execution-approval-migration-activate": "/usr/local/var/lib/secure-sandbox/execution-approval",
    "execution-approval-migration-authorize-acceptance": "/usr/local/var/lib/secure-sandbox/execution-approval",
    "execution-approval-migration-verify-acceptance": "/usr/local/var/lib/secure-sandbox/execution-approval",
    "execution-approval-migration-commit": "/usr/local/var/lib/secure-sandbox/execution-approval",
    "execution-approval-software-retire": "/usr/local/var/lib/secure-sandbox/execution-approval",
    "host-controller-install": "/usr/local/libexec/secure-sandbox-host",
    "host-controller-rollback": "/usr/local/libexec/secure-sandbox-host",
    "pki-anchor-begin": "/usr/local/var/lib/secure-sandbox/pki",
    "pki-anchor-commit": "/usr/local/var/lib/secure-sandbox/pki",
    "installer-promote-canonical": "/Library/Application Support/SecureSandbox/installers",
    "installer-promote-autoinstall": "/Library/Application Support/SecureSandbox/installers",
    "installer-repair-store-access": "/Library/Application Support/SecureSandbox/installers",
    "vm-create": "SecureSandbox-Gateway,SecureSandbox-Research,SecureSandbox-Target",
    "vm-reprovision": "SecureSandbox-Gateway,SecureSandbox-Research,SecureSandbox-Target",
    "vm-preserve-legacy": "SecureSandbox quarantined VM data preservation",
    "model-profile-activate": "Gateway broker and Research harness model authority",
    "native-stack-signin-begin": "Native vendor harness and model stack authority",
    "native-stack-binding-commit": "Native vendor harness and model stack authority",
    "native-stack-status-verify": "Native vendor harness and model stack authority",
    "native-stack-entitlement-verify": "Native vendor harness and model stack authority",
    "native-stack-activate": "Native vendor harness and model stack authority",
    "native-stack-rollback": "Native vendor harness and model stack authority",
    "native-stack-logout": "Native vendor harness and model stack authority",
    "native-stack-credential-destroy": "Native vendor harness and model stack authority",
    "native-stack-recover": "Native vendor harness and model stack authority",
    native_deployment.APPLY_OPERATION: native_deployment.RESOURCE,
    native_deployment.RECOVER_OPERATION: native_deployment.RESOURCE,
    native_stack_catalog_promotion.OPERATION: native_stack_catalog_promotion.RESOURCE,
    native_program_attestation.OPERATION: native_program_attestation.RESOURCE,
    "native-session-start": "Native vendor harness session authority",
    "native-session-stop": "Native vendor harness session authority",
    native_projection_reconciliation.OPERATION: (
        native_projection_reconciliation.RESOURCE
    ),
    native_projection_identity_recovery.OPERATION: (
        native_projection_identity_recovery.RESOURCE
    ),
    "harness-generation-activate": "Protected Research harness generation selector",
    "harness-generation-rollback": "Protected Research harness generation selector",
    "harness-generation-retire": "Protected Research harness generation selector",
    "harness-generation-revoke": "Protected Research harness generation selector",
    "harness-generation-recover": "Protected Research harness generation recovery journal",
    "harness-acceptance-authorize": "Disposable harness lifecycle acceptance plan",
}

TOUCHID_ONLY_OPERATIONS = frozenset({
    "host-controller-install", "host-controller-rollback",
    "native-session-start", "native-session-stop",
    "execution-approval-key-init", "execution-approval-sign",
    "execution-approval-migration-activate",
    "execution-approval-migration-authorize-acceptance",
    "execution-approval-migration-verify-acceptance",
    "execution-approval-migration-commit",
    "execution-approval-software-retire",
    "model-profile-activate",
    "harness-acceptance-authorize",
    native_deployment.APPLY_OPERATION,
    native_deployment.RECOVER_OPERATION,
    native_program_attestation.OPERATION,
    native_projection_identity_recovery.OPERATION,
    native_projection_reconciliation.OPERATION,
})


def operation_requires_touchid(operation: object) -> bool:
    return (
        isinstance(operation, str)
        and (
            operation in TOUCHID_ONLY_OPERATIONS
            or operation.startswith("native-stack-")
            or operation.startswith("harness-generation-")
        )
    )
CANONICAL_INSTALLER_SHA256 = "af78753c94b924c85c4964c670692a853f7c80299a4064e317edad95462e3168"
AUTOINSTALL_INSTALLER_SHA256 = "c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804"
PRESERVATION_TOOL_NAMES = {
    "control_policy", "deployment", "exporter", "guest_preserver",
    "archive_verifier", "continuity_planner", "continuity_importer",
    "continuity_control", "preservation_executor", "preservation_planner",
    "session_registry",
}


class AuthorizationError(RuntimeError):
    pass


class AuthorizationTerminalError(AuthorizationError):
    def __init__(self, code: str, request_id: str | None = None,
                 operation: str | None = None):
        super().__init__(code)
        self.code = code
        self.request_id = request_id
        self.operation = operation


PROCESS_GROUP_ENV = "SECURE_SANDBOX_OWNED_PROCESS_GROUP"
SUPERVISOR_LIVENESS_ENV = "SECURE_SANDBOX_SUPERVISOR_LIVENESS_FD"
SUPERVISOR_DISARM = b"D"


def start_supervisor_liveness_monitor() -> threading.Thread | None:
    marker = os.environ.pop(SUPERVISOR_LIVENESS_ENV, None)
    if marker is None:
        return None
    if not marker.isascii() or not marker.isdecimal():
        raise AuthorizationError("authorization_supervisor_liveness_fd_invalid")
    descriptor = int(marker)
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise AuthorizationError(
            "authorization_supervisor_liveness_fd_invalid"
        ) from error
    group = os.getpgrp()
    if (
        descriptor < 3
        or not stat.S_ISFIFO(info.st_mode)
        or os.getpid() != group
        or os.getsid(0) != group
    ):
        raise AuthorizationError("authorization_supervisor_liveness_fd_invalid")

    def monitor() -> None:
        try:
            decision = os.read(descriptor, 1)
        except OSError:
            decision = b""
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if decision == SUPERVISOR_DISARM:
            return
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                break
            time.sleep(0.05)
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    thread = threading.Thread(
        target=monitor, name="authorization-supervisor-liveness", daemon=True,
    )
    thread.start()
    return thread


def request_with_supervisor_custody(args: argparse.Namespace) -> int:
    previous = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }

    def interrupted(signum: int, _frame: object) -> None:
        for pending in previous:
            signal.signal(pending, signal.SIG_IGN)
        raise AuthorizationError(f"authorization_interrupted_{signum}")

    try:
        for signum in previous:
            signal.signal(signum, interrupted)
        start_supervisor_liveness_monitor()
        return request_authorization(
            args.agent, args.session, args.purpose, args.resource,
            args.operation, json.loads(args.parameters_json),
            ceremony=args.ceremony, request_id=args.request_id,
        )
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def inherited_owned_process_group() -> int | None:
    marker = os.environ.get(PROCESS_GROUP_ENV, "")
    group = os.getpgrp()
    if marker == "bootstrap":
        return group if os.getpid() == group == os.getsid(0) else None
    if (marker.isascii() and marker.isdecimal()
            and int(marker) == group == os.getsid(0)):
        return group
    return None


def child_process_policy() -> tuple[bool, dict[str, str]]:
    inherited = inherited_owned_process_group()
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C.UTF-8",
        PROCESS_GROUP_ENV: (
            str(inherited) if inherited is not None else "bootstrap"
        ),
    }
    return inherited is None, environment


def process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate_bounded_process(
    process: subprocess.Popen[Any], *, owns_group: bool,
) -> None:
    if owns_group:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    if owns_group:
        if process_group_exists(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    elif process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise AuthorizationError("authorization_process_unreaped") from error
    if owns_group:
        deadline = time.monotonic() + 2
        while process_group_exists(process.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        if process_group_exists(process.pid):
            raise AuthorizationError("authorization_process_group_unreaped")


def terminate_residual_process_group(group: int) -> None:
    """Remove descendants after an already-reaped process-group leader."""
    if not process_group_exists(group):
        return
    try:
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 1
    while process_group_exists(group) and time.monotonic() < deadline:
        time.sleep(0.02)
    if process_group_exists(group):
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            return
    deadline = time.monotonic() + 2
    while process_group_exists(group) and time.monotonic() < deadline:
        time.sleep(0.02)
    if process_group_exists(group):
        raise AuthorizationError("authorization_process_group_unreaped")


class TouchIDApplicationResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str
    outcome: str


def diagnostic_policy(code: str) -> tuple[str, str, str, str]:
    """Return outcome, phase, retry disposition, and bounded operator action."""
    if code == "operator_cancelled":
        return "cancelled", "ceremony", "new-request", "start_new_request_when_ready"
    if code == "authorization_window_dismissed":
        return "dismissed", "ceremony", "new-request", "start_new_request_when_ready"
    if code in {"request_expired", "execution_approval_time_invalid"}:
        return "expired", "ceremony", "new-request", "start_new_request_promptly"
    if code == "authorization_request_in_progress":
        return "blocked", "ceremony", "wait", "wait_for_active_request"
    if code in {
        "touchid_ui_result_missing", "touchid_ui_result_invalid",
        "touchid_ui_result_untrusted", "touchid_ui_launch_failed",
        "touchid_operation_result_missing", "request_already_consumed",
        "privileged_operation_outcome_ambiguous", "privileged_operation_timeout",
        "authorization_dialog_timeout", "touchid_lifecycle_timeout",
    }:
        return "ambiguous", "result", "forbidden", "inspect_authorization_receipt_before_retry"
    if code in {
        "touchid_required", "touchid_ui_required", "touchid_authorization_rejected",
        "touch_id_unavailable", "touch_id_rejected", "cancel_test_ui_required",
    }:
        return "rejected", "authorization", "new-request", "restore_touch_id_then_start_new_request"
    if (code.endswith("_untrusted") or code.endswith("_mismatch")
            or code.endswith("_invalid")):
        return "rejected", "validation", "forbidden", "repair_or_verify_protected_state"
    if code == "privileged_operation_failed":
        return "failed", "operation", "forbidden", "inspect_authorization_receipt_before_retry"
    return "rejected", "authorization", "forbidden", "inspect_diagnostic_code_before_retry"


def diagnostic_record(code: str, request_id: str | None = None,
                      operation: str | None = None) -> dict[str, Any]:
    if re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code) is None:
        code = "authorization_internal_error"
    outcome, phase, retry, action = diagnostic_policy(code)
    return {
        "action": action,
        "code": code,
        "operation": operation,
        "outcome": outcome,
        "phase": phase,
        "request_id": request_id,
        "retry": retry,
        "schema": DIAGNOSTIC_SCHEMA,
    }


def canonical(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def canonical_v2(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise AuthorizationError("execution_approval_v2_json_invalid") from error
    if b"\n" in encoded or b"\r" in encoded:
        raise AuthorizationError("execution_approval_v2_json_invalid")
    return encoded


def validate_native_deployment_plan_response(
    value: object, *, now: int | None = None, require_fresh: bool = True,
    expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    fields = {
        "schema", "plan", "prior_gateway", "prior_research",
        "payload_container_sha256", "response_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizationError("native_deployment_plan_response_invalid")
    try:
        plan = native_deployment.validate_plan(
            value["plan"], now=now, require_fresh=require_fresh,
        )
        gateway, research = native_deployment.validate_plan_predecessor_statuses(
            plan, gateway_status=value["prior_gateway"],
            research_status=value["prior_research"],
        )
    except native_deployment.NativeDeploymentError as error:
        raise AuthorizationError(
            "native_deployment_plan_response_invalid"
        ) from error
    body = {
        "plan": plan,
        "prior_gateway": gateway,
        "prior_research": research,
        "payload_container_sha256": value["payload_container_sha256"],
    }
    if (
        value.get("schema") != NATIVE_DEPLOYMENT_PLAN_RESPONSE_SCHEMA
        or SHA256.fullmatch(str(value.get("payload_container_sha256", "")))
        is None
        or value.get("response_sha256") != native_deployment.digest(body)
        or (
            expected_host_release_id is not None
            and plan["host_release_id"] != expected_host_release_id
        )
    ):
        raise AuthorizationError("native_deployment_plan_response_invalid")
    admitted = {
        "schema": NATIVE_DEPLOYMENT_PLAN_RESPONSE_SCHEMA,
        **body,
        "response_sha256": value["response_sha256"],
    }
    if native_deployment.canonical(admitted) != native_deployment.canonical(value):
        raise AuthorizationError("native_deployment_plan_response_invalid")
    return admitted


def validate_native_deployment_status(
    value: object, *, expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    fields = {
        "schema", "state", "phase", "deployment_id", "host_release_id",
        "active_journal_sha256", "error_sha256", "status_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizationError("native_deployment_status_invalid")
    state = value.get("state")
    phase = value.get("phase")
    deployment_id = value.get("deployment_id")
    host_release_id = value.get("host_release_id")
    active = value.get("active_journal_sha256")
    error = value.get("error_sha256")
    if state == "ready":
        valid_state = all(
            item is None for item in (
                phase, deployment_id, host_release_id, active, error,
            )
        )
    elif state == "recovery-required":
        if phase == "state-invalid":
            valid_state = (
                deployment_id is None and host_release_id is None
                and active is None and isinstance(error, str)
                and SHA256.fullmatch(error) is not None
            )
        else:
            valid_state = (
                isinstance(phase, str)
                and re.fullmatch(r"[a-z][a-z-]{0,63}", phase) is not None
                and isinstance(deployment_id, str)
                and UUID4.fullmatch(deployment_id) is not None
                and isinstance(host_release_id, str)
                and SHA256.fullmatch(host_release_id) is not None
                and isinstance(active, str)
                and SHA256.fullmatch(active) is not None
                and error is None
            )
    else:
        valid_state = False
    body = {key: value[key] for key in fields - {"schema", "status_sha256"}}
    if (
        value.get("schema") != NATIVE_DEPLOYMENT_STATUS_SCHEMA
        or not valid_state
        or value.get("status_sha256") != native_deployment.digest(body)
        or (
            expected_host_release_id is not None
            and host_release_id not in {None, expected_host_release_id}
        )
    ):
        raise AuthorizationError("native_deployment_status_invalid")
    return dict(value)


def validate_native_deployment_recovery_plan(
    value: object, *, expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    fields = {
        "schema", "active_journal_sha256", "deployment_id",
        "host_release_id", "phase", "observed_pair", "allowed_actions",
        "plan_response", "gateway_status_sha256", "research_status_sha256",
        "recovery_plan_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizationError("native_deployment_recovery_plan_invalid")
    plan_response = validate_native_deployment_plan_response(
        value["plan_response"], require_fresh=False,
        expected_host_release_id=expected_host_release_id,
    )
    plan = plan_response["plan"]
    actions = value.get("allowed_actions")
    allowed_action_lists = (
        [], ["resume"], ["rollback"], ["rollback", "resume"],
    )
    body = {key: value[key] for key in fields - {"schema", "recovery_plan_sha256"}}
    if (
        value.get("schema") != NATIVE_DEPLOYMENT_RECOVERY_PLAN_SCHEMA
        or SHA256.fullmatch(str(value.get("active_journal_sha256", "")))
        is None
        or value.get("deployment_id") != plan["deployment_id"]
        or value.get("host_release_id") != plan["host_release_id"]
        or not isinstance(value.get("phase"), str)
        or re.fullmatch(r"[a-z][a-z-]{0,63}", value["phase"]) is None
        or value.get("observed_pair") not in {
            "prior-prior", "candidate-prior", "candidate-candidate",
            "unavailable",
        }
        or actions not in allowed_action_lists
        or any(
            item is not None
            and (not isinstance(item, str) or SHA256.fullmatch(item) is None)
            for item in (
                value.get("gateway_status_sha256"),
                value.get("research_status_sha256"),
            )
        )
        or (
            (value.get("gateway_status_sha256") is None)
            != (value.get("research_status_sha256") is None)
        )
        or value.get("recovery_plan_sha256") != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_deployment_recovery_plan_invalid")
    admitted = dict(value)
    admitted["plan_response"] = plan_response
    return admitted


def validate_native_deployment_terminal(
    value: object, *, plan_response: dict[str, Any],
    authorization: dict[str, Any],
) -> dict[str, Any]:
    plan = plan_response["plan"]
    fields = {
        "schema", "deployment_id", "sequence", "phase", "plan",
        "apply_authorization_sha256", "authorization_sha256",
        "host_release_id", "payload_container_sha256", "prior_gateway",
        "prior_research", "event", "evidence", "transport",
        "prior_record_sha256", "updated_at", "record_sha256",
    }
    evidence_fields = {
        "gateway_status", "research_status", "gateway_status_sha256",
        "research_status_sha256", "fence_evidence_sha256", "result_sha256",
        "terminal_sha256", "outcome",
    }
    if (
        not isinstance(value, dict) or set(value) != fields
        or not isinstance(value.get("evidence"), dict)
        or set(value["evidence"]) != evidence_fields
    ):
        raise AuthorizationError("native_deployment_result_invalid")
    try:
        admitted_plan = native_deployment.validate_plan(
            value["plan"], require_fresh=False)
        gateway, research = native_deployment.validate_plan_predecessor_statuses(
            admitted_plan, gateway_status=value["prior_gateway"],
            research_status=value["prior_research"])
        gateway_projection = native_deployment.validate_status_projection(
            value["evidence"]["gateway_status"])
        research_projection = native_deployment.validate_status_projection(
            value["evidence"]["research_status"])
    except native_deployment.NativeDeploymentError as error:
        raise AuthorizationError("native_deployment_result_invalid") from error
    phase = value.get("phase")
    outcome = value["evidence"].get("outcome")
    expected_phase = (
        "rolled-back"
        if authorization["operation"] == native_deployment.RECOVER_OPERATION
        and authorization["recovery_action"] == "rollback"
        else "committed"
    )
    gateway_prior = (
        native_deployment.status_projection_sha256(gateway_projection)
        == plan["previous_gateway_status_sha256"]
    )
    research_prior = (
        native_deployment.status_projection_sha256(research_projection)
        == plan["previous_research_status_sha256"]
    )
    gateway_candidate = (
        gateway_projection["state"] == "verified"
        and gateway_projection["generation_kind"] == "protected"
        and gateway_projection["package_sha256"]
        == plan["gateway_package_sha256"]
        and gateway_projection["catalog_sha256"] is None
    )
    research_candidate = (
        research_projection["state"] == "verified"
        and research_projection["generation_kind"] == "protected"
        and research_projection["package_sha256"]
        == plan["research_package_sha256"]
        and research_projection["catalog_sha256"] == plan["catalog_sha256"]
    )
    gateway_forward = gateway_candidate or (
        gateway_prior
        and plan["gateway_package_sha256"]
        == plan["previous_gateway_package_sha256"]
    )
    research_forward = research_candidate or (
        research_prior
        and plan["research_package_sha256"]
        == plan["previous_research_package_sha256"]
        and research_projection["catalog_sha256"] == plan["catalog_sha256"]
    )
    body = {key: item for key, item in value.items()
            if key not in {"schema", "record_sha256"}}
    if (
        value.get("schema")
        != "secure-sandbox-native-deployment-journal-record-v1"
        or admitted_plan != plan
        or value.get("deployment_id") != plan["deployment_id"]
        or value.get("host_release_id") != plan["host_release_id"]
        or phase != expected_phase
        or value.get("event") != phase
        or outcome != phase
        or not isinstance(value.get("sequence"), int)
        or isinstance(value.get("sequence"), bool)
        or value["sequence"] < 1
        or not isinstance(value.get("updated_at"), int)
        or isinstance(value.get("updated_at"), bool)
        or value["updated_at"] <= 0
        or value.get("authorization_sha256")
        != authorization["authorization_sha256"]
        or (
            authorization["operation"] == native_deployment.APPLY_OPERATION
            and value.get("apply_authorization_sha256")
            != authorization["authorization_sha256"]
        )
        or SHA256.fullmatch(str(value.get("apply_authorization_sha256", "")))
        is None
        or value.get("payload_container_sha256")
        != plan_response["payload_container_sha256"]
        or SHA256.fullmatch(str(value.get("prior_record_sha256", ""))) is None
        or value.get("transport") is not None
        or gateway_projection["role"] != "gateway"
        or research_projection["role"] != "research"
        or native_deployment.status_projection_sha256(gateway_projection)
        != value["evidence"]["gateway_status_sha256"]
        or native_deployment.status_projection_sha256(research_projection)
        != value["evidence"]["research_status_sha256"]
        or any(
            not isinstance(value["evidence"].get(name), str)
            or SHA256.fullmatch(value["evidence"][name]) is None
            for name in (
                "gateway_status_sha256", "research_status_sha256",
                "terminal_sha256",
            )
        )
        or value["evidence"].get("fence_evidence_sha256") is not None
        or value["evidence"].get("result_sha256") is not None
        or (phase == "committed" and not (
            gateway_forward and research_forward))
        or (phase == "rolled-back" and not (
            gateway_prior and research_prior))
        or value.get("record_sha256") != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_deployment_result_invalid")
    return dict(value)


def validate_native_catalog_promotion_gate(value: object) -> dict[str, Any]:
    fields = {
        "schema", "state", "active_promotion_id",
        "active_state_sha256", "gate_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizationError("native_catalog_promotion_gate_invalid")
    body = {
        "state": value["state"],
        "active_promotion_id": value["active_promotion_id"],
        "active_state_sha256": value["active_state_sha256"],
    }
    if value["state"] == "active":
        identity_valid = (
            UUID4.fullmatch(str(value["active_promotion_id"])) is not None
            and SHA256.fullmatch(str(value["active_state_sha256"])) is not None
        )
    elif value["state"] in {"ready", "invalid"}:
        identity_valid = (
            value["active_promotion_id"] is None
            and value["active_state_sha256"] is None
        )
    else:
        identity_valid = False
    if (
        value["schema"] != NATIVE_CATALOG_PROMOTION_GATE_SCHEMA
        or not identity_valid
        or value["gate_sha256"] != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_catalog_promotion_gate_invalid")
    return dict(value)


def validate_native_catalog_recovery_terminal(
    value: object, *, expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    fields = {
        "schema", "state", "promotion_id", "catalog_sha256",
        "host_release_id", "promotion_receipt_sha256",
        "replay_authority_sha256", "expected_gate_sha256",
        "recovery_intent_sha256", "terminal_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizationError("native_catalog_recovery_terminal_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "terminal_sha256"}
    }
    if (
        value["schema"] != NATIVE_CATALOG_PROMOTION_RECOVERY_TERMINAL_SCHEMA
        or value["state"] != "finalized"
        or UUID4.fullmatch(str(value["promotion_id"])) is None
        or (
            expected_host_release_id is not None
            and value["host_release_id"] != expected_host_release_id
        )
        or any(
            SHA256.fullmatch(str(value[name])) is None for name in (
                "catalog_sha256", "host_release_id",
                "promotion_receipt_sha256", "replay_authority_sha256",
                "expected_gate_sha256", "recovery_intent_sha256",
                "terminal_sha256",
            )
        )
        or value["terminal_sha256"] != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_catalog_recovery_terminal_invalid")
    return dict(value)


def validate_native_catalog_public_status(
    value: object, *, expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    fields = {
        "schema", "promotion_id", "catalog_sha256", "host_release_id",
        "promotion_receipt_sha256", "published_at", "stacks",
        "status_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizationError("native_catalog_public_status_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "status_sha256"}
    }
    stacks = value["stacks"]
    if (
        value["schema"] != NATIVE_CATALOG_PUBLIC_STATUS_SCHEMA
        or UUID4.fullmatch(str(value["promotion_id"])) is None
        or (
            expected_host_release_id is not None
            and value["host_release_id"] != expected_host_release_id
        )
        or any(
            SHA256.fullmatch(str(value[name])) is None for name in (
                "catalog_sha256", "host_release_id",
                "promotion_receipt_sha256", "status_sha256",
            )
        )
        or not isinstance(value["published_at"], int)
        or isinstance(value["published_at"], bool)
        or value["published_at"] <= 0
        or not isinstance(stacks, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"stack_id", "stack_sha256"}
            or native_vendor_stack.IDENTIFIER.fullmatch(
                str(item.get("stack_id", ""))) is None
            or SHA256.fullmatch(str(item.get("stack_sha256", ""))) is None
            for item in stacks
        )
        or value["status_sha256"] != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_catalog_public_status_invalid")
    return dict(value)


def validate_native_catalog_promotion_receipt(
    value: object, *, plan: dict[str, Any], authorization: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "promotion_id", "plan_sha256", "authorization_sha256",
        "authorization_receipt_sha256", "source_sha256",
        "previous_catalog_sha256", "catalog_sha256", "host_release_id",
        "promoted_at", "status", "receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorizationError("native_catalog_promotion_receipt_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "receipt_sha256"}
    }
    if (
        value["schema"] != native_stack_catalog_promotion.RECEIPT_SCHEMA
        or value["promotion_id"] != plan["promotion_id"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or value["authorization_sha256"]
        != authorization["authorization_sha256"]
        or value["authorization_receipt_sha256"]
        != authorization["pending_receipt_sha256"]
        or value["source_sha256"] != plan["source_sha256"]
        or value["previous_catalog_sha256"]
        != plan["previous_catalog_sha256"]
        or value["catalog_sha256"] != plan["catalog_sha256"]
        or value["host_release_id"] != plan["host_release_id"]
        or value["status"] != "authorized-for-publication"
        or not isinstance(value["promoted_at"], int)
        or isinstance(value["promoted_at"], bool)
        or value["promoted_at"] <= 0
        or any(
            SHA256.fullmatch(str(value[name])) is None for name in (
                "authorization_sha256", "authorization_receipt_sha256",
                "receipt_sha256",
            )
        )
        or value["receipt_sha256"]
        != native_stack_catalog_promotion.sha256(body)
    ):
        raise AuthorizationError("native_catalog_promotion_receipt_invalid")
    return dict(value)


def host_boot_identity() -> str:
    result = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "kern.boottime"],
        stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=5,
    )
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise AuthorizationError("host_boot_identity_invalid") from error
    if (result.returncode != 0 or not 1 <= len(value) <= 256
            or any(ord(character) < 32 or ord(character) > 126 for character in value)):
        raise AuthorizationError("host_boot_identity_invalid")
    return value


def canonical_base64_decode(value: object, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AuthorizationError(f"{label}_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise AuthorizationError(f"{label}_invalid") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise AuthorizationError(f"{label}_invalid")
    return decoded


def parse_p256_der(signature: bytes, require_low_s: bool = True) -> tuple[int, int]:
    if len(signature) < 8 or len(signature) > 72 or signature[0] != 0x30:
        raise AuthorizationError("execution_approval_signature_invalid")
    if signature[1] >= 0x80 or signature[1] != len(signature) - 2:
        raise AuthorizationError("execution_approval_signature_invalid")
    offset = 2

    def integer() -> int:
        nonlocal offset
        if offset + 2 > len(signature) or signature[offset] != 0x02:
            raise AuthorizationError("execution_approval_signature_invalid")
        length = signature[offset + 1]
        offset += 2
        if length < 1 or length > 33 or offset + length > len(signature):
            raise AuthorizationError("execution_approval_signature_invalid")
        raw = signature[offset:offset + length]
        offset += length
        if raw[0] & 0x80 or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80):
            raise AuthorizationError("execution_approval_signature_invalid")
        value = int.from_bytes(raw, "big")
        if not 1 <= value < P256_ORDER:
            raise AuthorizationError("execution_approval_signature_invalid")
        return value

    r_value, s_value = integer(), integer()
    if offset != len(signature) or (require_low_s and s_value > P256_HALF_ORDER):
        raise AuthorizationError("execution_approval_signature_invalid")
    if encode_p256_der(r_value, s_value) != signature:
        raise AuthorizationError("execution_approval_signature_invalid")
    return r_value, s_value


def encode_p256_der(r_value: int, s_value: int) -> bytes:
    def integer(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\0" + raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = integer(r_value) + integer(s_value)
    return b"\x30" + bytes([len(body)]) + body


def validate_p256_spki(der: bytes) -> str:
    if len(der) != 91 or not der.startswith(P256_SPKI_PREFIX):
        raise AuthorizationError("execution_approval_public_key_invalid")
    point = der[len(P256_SPKI_PREFIX):]
    if len(point) != 65 or point[0] != 0x04 or point[1:] == bytes(64):
        raise AuthorizationError("execution_approval_public_key_invalid")
    return hashlib.sha256(der).hexdigest()


def p256_public_pem(der: bytes) -> bytes:
    validate_p256_spki(der)
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index:index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines)
            + "\n-----END PUBLIC KEY-----\n").encode("ascii")


def verify_p256_signature(public_spki: bytes, message: bytes, signature: bytes) -> None:
    parse_p256_der(signature, require_low_s=True)
    with tempfile.TemporaryDirectory(prefix="secure-sandbox-p256-") as directory:
        root = Path(directory)
        public_path = root / "public.pem"
        signature_path = root / "signature.der"
        for path, content in ((public_path, p256_public_pem(public_spki)),
                              (signature_path, signature)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                write_all(descriptor, content)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        result = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(public_path),
             "-signature", str(signature_path)],
            input=message, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        if result.returncode:
            raise AuthorizationError("execution_approval_signature_invalid")


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("short_write")
        written += count


def clean_text(value: str, label: str, maximum: int) -> str:
    if (not value or len(value) > maximum
            or any(ord(character) < 32 or ord(character) > 126 for character in value)):
        raise AuthorizationError(f"{label}_invalid")
    return value


def read_native_promotion_catalog(
    path: Path, *, expected_uid: int, expected_sha256: str
) -> tuple[dict[str, Any], bytes]:
    """Read an operator-owned staged catalog while the broker runs as root."""
    if expected_uid <= 0 or SHA256.fullmatch(expected_sha256) is None:
        raise AuthorizationError("native_catalog_promotion_source_invalid")
    try:
        parent = path.parent.lstat()
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise AuthorizationError(
            "native_catalog_promotion_source_invalid"
        ) from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= native_vendor_stack.MAX_CATALOG_BYTES:
            block = os.read(
                descriptor,
                min(
                    65536,
                    native_vendor_stack.MAX_CATALOG_BYTES + 1 - len(raw),
                ),
            )
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != expected_uid
        or parent.st_mode & 0o022
        or not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or opened.st_gid != parent.st_gid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or not 2 <= opened.st_size <= native_vendor_stack.MAX_CATALOG_BYTES
        or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or len(raw) != opened.st_size
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        raise AuthorizationError("native_catalog_promotion_source_invalid")
    try:
        value = json.loads(raw)
        catalog = native_vendor_stack.validate_catalog(value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_vendor_stack.NativeVendorStackError,
    ) as error:
        raise AuthorizationError(
            "native_catalog_promotion_source_invalid"
        ) from error
    canonical_catalog = native_vendor_stack.canonical_bytes(catalog)
    if bytes(raw) != canonical_catalog:
        raise AuthorizationError("native_catalog_promotion_source_invalid")
    return catalog, canonical_catalog


def valid_uuid4(value: str, label: str = "request_id") -> str:
    if not UUID4.fullmatch(value):
        raise AuthorizationError(f"{label}_invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise AuthorizationError(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise AuthorizationError(f"{label}_invalid")
    return value


def validate_identity(agent: str, session: str) -> tuple[str, str]:
    if not SAFE_AGENT.fullmatch(agent):
        raise AuthorizationError("declared_agent_invalid")
    if not SAFE_SESSION.fullmatch(session):
        raise AuthorizationError("declared_session_invalid")
    return agent, session


def validate_native_host_candidate_binding(
    value: object, repo: Path, operator_uid: int,
) -> dict[str, Any]:
    required = {
        "schema", "build_custody", "generation_path", "generation_device",
        "generation_inode", "generation_tree_sha256", "release_commit",
        "host_release_preimage_path", "host_release_preimage_device",
        "host_release_preimage_inode", "host_release_preimage_size",
        "host_release_preimage_sha256", "host_release_preimage_schema",
        "signing_config_sha256", "source_archive_sha256",
        "source_tree_sha256", "developer_id_certificate_sha1",
        "notary_submission_id",
    }
    if (not isinstance(value, dict) or set(value) != required
            or value.get("schema") != NATIVE_HOST_CANDIDATE_SCHEMA
            or value.get("build_custody")
                != "trusted-login-principal-v1"):
        raise AuthorizationError("native_host_candidate_invalid")
    for name in (
        "generation_tree_sha256", "signing_config_sha256",
        "source_archive_sha256", "source_tree_sha256",
        "host_release_preimage_sha256",
    ):
        if not isinstance(value.get(name), str) or SHA256.fullmatch(value[name]) is None:
            raise AuthorizationError("native_host_candidate_invalid")
    if (not isinstance(value.get("release_commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", value["release_commit"]) is None
            or not isinstance(value.get("developer_id_certificate_sha1"), str)
            or re.fullmatch(
                r"[0-9a-f]{40}", value["developer_id_certificate_sha1"],
            ) is None
            or not isinstance(value.get("notary_submission_id"), str)
            or UUID.fullmatch(value["notary_submission_id"]) is None
            or not isinstance(value.get("generation_device"), int)
            or isinstance(value.get("generation_device"), bool)
            or value["generation_device"] <= 0
            or not isinstance(value.get("generation_inode"), int)
            or isinstance(value.get("generation_inode"), bool)
            or value["generation_inode"] <= 0
            or not isinstance(value.get("host_release_preimage_device"), int)
            or isinstance(value.get("host_release_preimage_device"), bool)
            or value["host_release_preimage_device"] <= 0
            or not isinstance(value.get("host_release_preimage_inode"), int)
            or isinstance(value.get("host_release_preimage_inode"), bool)
            or value["host_release_preimage_inode"] <= 0
            or not isinstance(value.get("host_release_preimage_size"), int)
            or isinstance(value.get("host_release_preimage_size"), bool)
            or not 1024 <= value["host_release_preimage_size"]
                <= 1024 * 1024 * 1024
            or value.get("host_release_preimage_schema")
                != NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA):
        raise AuthorizationError("native_host_candidate_invalid")
    raw_path = value.get("generation_path")
    if not isinstance(raw_path, str):
        raise AuthorizationError("native_host_candidate_invalid")
    generation = Path(raw_path)
    candidates = repo / ".private/native-host-product-candidates"
    try:
        before = generation.lstat()
        descriptor = os.open(
            generation,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            opened = os.fstat(descriptor)
            named = generation.lstat()
        finally:
            os.close(descriptor)
        resolved_repo = repo.resolve(strict=True)
        resolved_candidates = candidates.resolve(strict=True)
        resolved_generation = generation.resolve(strict=True)
    except OSError as error:
        raise AuthorizationError("native_host_candidate_invalid") from error
    identity = lambda info: (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )
    parent_pattern = (
        re.escape(value["release_commit"])
        + r"-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
          r"[0-9a-f]{4}-[0-9a-f]{12}"
    )
    if (not generation.is_absolute() or generation.name != "generation"
            or generation.parent.parent != candidates
            or re.fullmatch(parent_pattern, generation.parent.name) is None
            or resolved_candidates
                != resolved_repo / ".private/native-host-product-candidates"
            or resolved_generation
                != resolved_candidates / generation.parent.name / "generation"
            or not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(named.st_mode)
            or identity(before) != identity(opened)
            or identity(opened) != identity(named)
            or opened.st_uid != operator_uid
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or opened.st_dev != value["generation_device"]
            or opened.st_ino != value["generation_inode"]):
        raise AuthorizationError("native_host_candidate_invalid")
    preimage = Path(str(value["host_release_preimage_path"]))
    expected_preimage = (
        generation.parent / "evidence"
        / NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
    )
    resolved_expected_preimage = (
        resolved_generation.parent / "evidence"
        / NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
    )
    try:
        evidence_before = expected_preimage.parent.lstat()
        preimage_before = preimage.lstat()
        preimage_descriptor = os.open(
            preimage,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            preimage_opened = os.fstat(preimage_descriptor)
            preimage_named = preimage.lstat()
        finally:
            os.close(preimage_descriptor)
        evidence_after = expected_preimage.parent.lstat()
        resolved_preimage = preimage.resolve(strict=True)
    except OSError as error:
        raise AuthorizationError("native_host_candidate_invalid") from error
    if (not preimage.is_absolute() or preimage != expected_preimage
            or resolved_preimage != resolved_expected_preimage
            or not stat.S_ISDIR(evidence_before.st_mode)
            or stat.S_ISLNK(evidence_before.st_mode)
            or evidence_before.st_uid != operator_uid
            or stat.S_IMODE(evidence_before.st_mode) != 0o700
            or identity(evidence_before) != identity(evidence_after)
            or not stat.S_ISREG(preimage_opened.st_mode)
            or stat.S_ISLNK(preimage_before.st_mode)
            or stat.S_ISLNK(preimage_named.st_mode)
            or identity(preimage_before) != identity(preimage_opened)
            or identity(preimage_opened) != identity(preimage_named)
            or preimage_opened.st_uid != operator_uid
            or preimage_opened.st_nlink != 1
            or stat.S_IMODE(preimage_opened.st_mode) not in {0o400, 0o600}
            or preimage_opened.st_dev
                != value["host_release_preimage_device"]
            or preimage_opened.st_ino
                != value["host_release_preimage_inode"]
            or preimage_opened.st_size
                != value["host_release_preimage_size"]):
        raise AuthorizationError("native_host_candidate_invalid")
    return value


def host_release_identity(payloads: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name in sorted(payloads):
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(payloads[name].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def validate_host_release_authorized_target_plan(
    operation: str,
    plan: object,
    plan_sha256: object,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (not isinstance(plan, dict)
            or not isinstance(plan_sha256, str)
            or SHA256.fullmatch(plan_sha256) is None
            or hashlib.sha256(canonical(plan)).hexdigest() != plan_sha256):
        raise AuthorizationError("authorized_target_plan_invalid")
    if operation == "host-controller-install":
        fields = {
            "candidate_record_sha256", "payloads", "release_id", "schema",
            "source_stable_sha256", "target_launcher_sha256",
        }
        payloads = plan.get("payloads")
        if (set(plan) != fields
                or plan.get("schema") != HOST_RELEASE_TARGET_PLAN_SCHEMA
                or candidate is None
                or not isinstance(payloads, dict)
                or set(payloads) != set(EXPECTED_RELEASE_MODES)
                or any(
                    not isinstance(value, str)
                    or SHA256.fullmatch(value) is None
                    for value in payloads.values()
                )
                or plan.get("release_id")
                    != host_release_identity(payloads)
                or any(
                    not isinstance(plan.get(name), str)
                    or SHA256.fullmatch(plan[name]) is None
                    for name in (
                        "candidate_record_sha256", "source_stable_sha256",
                        "target_launcher_sha256",
                    )
                )
                or plan["candidate_record_sha256"] != hashlib.sha256(
                    canonical_v2(candidate)
                ).hexdigest()):
            raise AuthorizationError("authorized_target_plan_invalid")
        return plan
    if operation == "host-controller-rollback":
        fields = {
            "operation", "schema", "source_stable_sha256",
            "target_candidate_authority_sha256", "target_launcher_sha256",
            "target_release_id", "target_release_tree_identity_sha256",
        }
        if (set(plan) != fields
                or plan.get("schema") != HOST_RELEASE_ROLLBACK_PLAN_SCHEMA
                or plan.get("operation") != "rollback"
                or any(
                    not isinstance(plan.get(name), str)
                    or SHA256.fullmatch(plan[name]) is None
                    for name in fields - {"operation", "schema"}
                )):
            raise AuthorizationError("authorized_target_plan_invalid")
        return plan
    raise AuthorizationError("operation_parameters_invalid")


def validate_host_pair_manager_result(
    value: object, operation: str, parameters: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationError("host_pair_transition_result_invalid")
    plan = parameters["authorized_target_plan"]
    common = {
        "schema", "status", "release_id", "transition_id",
        "transition_sha256", "host_release_launcher_pair_sha256",
        "candidate_authority_sha256", "release_tree_identity_sha256",
        "developer_id_team_id", "developer_id_team_floor_sha256",
        "developer_id_team_floor_release_id",
    }
    if operation == "host-controller-install":
        fields = common | {"launcher_sha256", "payloads"}
        valid = (
            set(value) == fields
            and value.get("status") == "deployed"
            and value.get("release_id") == plan["release_id"]
            and value.get("launcher_sha256")
                == plan["target_launcher_sha256"]
            and value.get("payloads") == plan["payloads"]
        )
    elif operation == "host-controller-rollback":
        fields = common | {"repo_match", "warning"}
        valid = (
            set(value) == fields
            and value.get("status") == "rolled_back"
            and value.get("release_id") == plan["target_release_id"]
            and value.get("candidate_authority_sha256")
                == plan["target_candidate_authority_sha256"]
            and value.get("release_tree_identity_sha256")
                == plan["target_release_tree_identity_sha256"]
            and value.get("repo_match") is True
            and value.get("warning") is None
        )
    else:
        valid = False
    if (not valid
            or value.get("schema")
                != "secure-sandbox-host-controller-release-v1"
            or not isinstance(value.get("transition_id"), str)
            or any(
                not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None
                for name in (
                    "transition_sha256",
                    "host_release_launcher_pair_sha256",
                    "candidate_authority_sha256",
                    "release_tree_identity_sha256",
                    "developer_id_team_floor_sha256",
                    "developer_id_team_floor_release_id",
                )
            )
            or not isinstance(value.get("developer_id_team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["developer_id_team_id"])
                is None):
        raise AuthorizationError("host_pair_transition_result_invalid")
    valid_uuid4(value["transition_id"], "transition_id")
    return value


def validate_host_pair_pending_result(
    value: object, operation: str, request_id: str,
    parameters: dict[str, Any], *, now: int,
) -> dict[str, Any]:
    fields = {
        "schema", "status", "operation", "transition_id",
        "transition_sha256", "authorization_request_id",
        "authorized_target_plan_sha256", "target_release_id", "expires_at",
        "recovered_after_child_failure",
    }
    expected_operation = (
        "install" if operation == "host-controller-install" else "rollback"
    )
    plan = parameters["authorized_target_plan"]
    expected_release = plan[
        "release_id" if expected_operation == "install"
        else "target_release_id"
    ]
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema")
                != "secure-sandbox-host-controller-release-v1"
            or value.get("status") != "host_pair_transition_pending"
            or value.get("operation") != expected_operation
            or value.get("authorization_request_id") != request_id
            or value.get("authorized_target_plan_sha256")
                != parameters["authorized_target_plan_sha256"]
            or value.get("target_release_id") != expected_release
            or value.get("recovered_after_child_failure") is not True
            or not isinstance(value.get("transition_id"), str)
            or not isinstance(value.get("transition_sha256"), str)
            or SHA256.fullmatch(value["transition_sha256"]) is None
            or not isinstance(value.get("expires_at"), int)
            or isinstance(value["expires_at"], bool)
            or value["expires_at"] <= now):
        raise AuthorizationError("host_pair_transition_pending_invalid")
    valid_uuid4(value["transition_id"], "transition_id")
    return value


def validate_parameters(operation: str, parameters: dict[str, Any], home: Path, *,
                        allow_expired_acceptance: bool = False) -> None:
    if not isinstance(parameters, dict):
        raise AuthorizationError("operation_parameters_invalid")
    expected_state = home / "Library/Application Support/SecureSandbox/controller-state"
    if operation == "authorization-probe":
        if set(parameters) != {"challenge"}:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["challenge"], "challenge")
        return
    if operation == "model-profile-activate":
        if set(parameters) != {"plan"} or not isinstance(parameters["plan"], dict):
            raise AuthorizationError("operation_parameters_invalid")
        plan = parameters["plan"]
        claimed = plan.get("plan_sha256")
        unsigned = {key:item for key, item in plan.items() if key != "plan_sha256"}
        broker = plan.get("broker")
        current = plan.get("current")
        now = int(time.time())
        if (plan.get("schema") != "secure-sandbox-model-profile-activation-plan-v1"
                or not isinstance(claimed, str) or not SHA256.fullmatch(claimed)
                or claimed != hashlib.sha256(canonical_v2(unsigned)).hexdigest()
                or not isinstance(plan.get("created_at"), int)
                or not isinstance(plan.get("expires_at"), int)
                or not plan["created_at"] <= now < plan["expires_at"]
                or plan["expires_at"] - plan["created_at"] > 300
                or not isinstance(broker, dict) or not isinstance(current, dict)
                or plan.get("current_generation_sha256")
                    != hashlib.sha256(canonical_v2(current)).hexdigest()
                or not UUID4.fullmatch(str(plan.get("activation_id", "")))
                or broker.get("adapter") not in {
                    "anthropic-messages-v1", "openai-responses-v1", "google-openai-chat-v1"}
                or broker.get("mode") not in {"mock", "production"}
                or not isinstance(broker.get("allowed_models"), list)
                or len(broker["allowed_models"]) != 1
                or not isinstance(plan.get("lease_profiles"), dict)
                or not isinstance(plan.get("credential_reference"), str)
                or len(plan["credential_reference"]) > 512):
            raise AuthorizationError("model_profile_plan_invalid")
        return
    if operation == native_stack_catalog_promotion.OPERATION:
        if set(parameters) != {"plan", "source"} or not isinstance(
            parameters["plan"], dict
        ) or not isinstance(parameters["source"], str):
            raise AuthorizationError("operation_parameters_invalid")
        try:
            plan = native_stack_catalog_promotion.validate_plan(
                parameters["plan"], now=int(time.time()), require_fresh=True
            )
            source = Path(parameters["source"])
            source_info = source.lstat()
            parent_info = source.parent.lstat()
            resolved_home = home.resolve(strict=True)
            resolved_source = source.resolve(strict=True)
            _catalog, catalog_raw = read_native_promotion_catalog(
                source,
                expected_uid=plan["source_uid"],
                expected_sha256=plan["source_sha256"],
            )
        except (
            OSError,
            AuthorizationError,
            native_stack_catalog_promotion.NativeStackCatalogPromotionError,
            native_vendor_stack.NativeVendorStackError,
        ) as error:
            raise AuthorizationError("native_catalog_promotion_plan_invalid") from error
        if (
            not source.is_absolute()
            or source.is_symlink()
            or resolved_source != source
            or not source.is_relative_to(resolved_home)
            or not stat.S_ISREG(source_info.st_mode)
            or source_info.st_uid != plan["source_uid"]
            or source_info.st_uid != resolved_home.stat().st_uid
            or source_info.st_nlink != 1
            or stat.S_IMODE(source_info.st_mode) != 0o600
            or not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != plan["source_uid"]
            or parent_info.st_mode & 0o022
            or hashlib.sha256(catalog_raw).hexdigest() != plan["source_sha256"]
        ):
            raise AuthorizationError("native_catalog_promotion_source_invalid")
        return
    if operation == native_program_attestation.OPERATION:
        if set(parameters) != {"plan"} or not isinstance(parameters["plan"], dict):
            raise AuthorizationError("operation_parameters_invalid")
        try:
            native_program_attestation.validate_plan(
                parameters["plan"], now=int(time.time()), require_fresh=True
            )
        except native_program_attestation.NativeProgramAttestationError as error:
            raise AuthorizationError(
                "native_program_attestation_plan_invalid"
            ) from error
        return
    if operation == native_projection_reconciliation.OPERATION:
        if set(parameters) != {"plan"} or not isinstance(
            parameters["plan"], dict
        ):
            raise AuthorizationError("operation_parameters_invalid")
        try:
            native_projection_reconciliation.validate_plan(
                parameters["plan"], now=int(time.time()), require_fresh=True
            )
        except native_projection_reconciliation.NativeProjectionReconciliationError as error:
            raise AuthorizationError(
                "native_projection_reconciliation_plan_invalid"
            ) from error
        return
    if operation == native_projection_identity_recovery.OPERATION:
        if set(parameters) != {"plan"} or not isinstance(
            parameters["plan"], dict
        ):
            raise AuthorizationError("operation_parameters_invalid")
        try:
            native_projection_identity_recovery.validate_plan(
                parameters["plan"], now=int(time.time()), require_fresh=True
            )
        except native_projection_identity_recovery.NativeProjectionIdentityRecoveryError as error:
            raise AuthorizationError(
                "native_projection_identity_recovery_plan_invalid"
            ) from error
        return
    if operation == native_deployment.APPLY_OPERATION:
        if set(parameters) != {"plan"}:
            raise AuthorizationError("operation_parameters_invalid")
        validate_native_deployment_plan_response(
            parameters["plan"], now=int(time.time()), require_fresh=True,
        )
        return
    if operation == native_deployment.RECOVER_OPERATION:
        if set(parameters) != {"recovery", "action"}:
            raise AuthorizationError("operation_parameters_invalid")
        recovery = validate_native_deployment_recovery_plan(
            parameters["recovery"])
        if parameters["action"] not in recovery["allowed_actions"]:
            raise AuthorizationError(
                "native_deployment_recovery_action_invalid")
        return
    if operation in {"native-session-start", "native-session-stop"}:
        if set(parameters) != {"plan"} or not isinstance(
            parameters["plan"], dict
        ):
            raise AuthorizationError("operation_parameters_invalid")
        try:
            plan = native_stack_session.validate_plan(
                parameters["plan"], now=int(time.time()), require_fresh=True
            )
        except native_stack_session.NativeStackSessionError as error:
            raise AuthorizationError(
                "native_stack_session_plan_invalid"
            ) from error
        if operation != f"native-{plan['action']}":
            raise AuthorizationError(
                "native_stack_session_operation_mismatch"
            )
        return
    if operation.startswith("native-stack-"):
        if set(parameters) != {"plan"} or not isinstance(parameters["plan"], dict):
            raise AuthorizationError("operation_parameters_invalid")
        try:
            plan = native_stack_operations.validate_plan(
                parameters["plan"], now=int(time.time()), require_fresh=True
            )
        except native_stack_operations.NativeStackOperationError as error:
            raise AuthorizationError("native_stack_plan_invalid") from error
        if operation != f"native-stack-{plan['action']}":
            raise AuthorizationError("native_stack_operation_mismatch")
        return
    if operation == "harness-acceptance-authorize":
        if set(parameters) != {"plan"} or not isinstance(parameters["plan"], dict):
            raise AuthorizationError("operation_parameters_invalid")
        plan = parameters["plan"]
        expected = {
            "schema", "plan_id", "transaction_id", "campaign_id", "campaign_sha256",
            "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
            "category", "operation", "generation_id", "operator_uid",
            "created_at", "expires_at",
            "candidate_authority", "production_material_used", "production_store_access",
            "plan_sha256",
        }
        unsigned = {key:item for key, item in plan.items() if key != "plan_sha256"}
        now = int(time.time())
        acceptance_actions = {
            "touchid-approve-exact-plan": ("authorization", "authorize"),
            "touchid-cancel": ("authorization", "authorize"),
            "touchid-expired-plan": ("authorization", "authorize"),
            "touchid-replay": ("authorization", "authorize"),
            "touchid-changed-plan": ("authorization", "authorize"),
            "touchid-wrong-generation": ("authorization", "authorize"),
            "legacy-session-touchid-migration": ("runtime", "migrate"),
            "rollback-explicit": ("management", "rollback"),
            "retire-zero-reference": ("management", "retire"),
            "reject-retire-referenced": ("management", "retire"),
            "revoke-generation": ("management", "revoke"),
        }
        case_id = plan.get("case_id")
        expected_action = acceptance_actions.get(case_id)
        if (set(plan) != expected
                or plan.get("schema")
                   != "secure-sandbox-harness-lifecycle-acceptance-interactive-plan-v1"
                or UUID4.fullmatch(str(plan.get("plan_id", ""))) is None
                or UUID4.fullmatch(str(plan.get("transaction_id", ""))) is None
                or UUID4.fullmatch(str(plan.get("campaign_id", ""))) is None
                or SHA256.fullmatch(str(plan.get("campaign_sha256", ""))) is None
                or SHA256.fullmatch(str(plan.get("machine_identity_sha256", ""))) is None
                or not isinstance(plan.get("source_commit"), str)
                or re.fullmatch(r"[0-9a-f]{40}", plan["source_commit"]) is None
                or expected_action is None
                or SHA256.fullmatch(str(plan.get("procedure_sha256", ""))) is None
                or (plan.get("category"), plan.get("operation")) != expected_action
                or SHA256.fullmatch(str(plan.get("generation_id", ""))) is None
                or not isinstance(plan.get("operator_uid"), int)
                or isinstance(plan.get("operator_uid"), bool)
                or not 1 <= plan["operator_uid"] < 2 ** 31
                or not isinstance(plan.get("created_at"), int)
                or isinstance(plan.get("created_at"), bool)
                or not isinstance(plan.get("expires_at"), int)
                or isinstance(plan.get("expires_at"), bool)
                or not (
                    plan["created_at"] <= now < plan["expires_at"]
                    or (allow_expired_acceptance
                        and plan.get("case_id") == "touchid-expired-plan"
                        and plan["expires_at"] <= now
                        and now - plan["expires_at"] <= REQUEST_TTL_SECONDS)
                )
                or plan["expires_at"] - plan["created_at"] > 300
                or plan.get("candidate_authority") != "none"
                or plan.get("production_material_used") is not False
                or plan.get("production_store_access") is not False
                or plan.get("plan_sha256")
                   != hashlib.sha256(canonical(unsigned)).hexdigest()):
            raise AuthorizationError("harness_acceptance_plan_invalid")
        return
    if operation in {
        "harness-generation-activate", "harness-generation-rollback",
        "harness-generation-retire", "harness-generation-revoke",
    }:
        if set(parameters) != {"plan"} or not isinstance(parameters["plan"], dict):
            raise AuthorizationError("operation_parameters_invalid")
        wrapper = parameters["plan"]
        if set(wrapper) != {"schema", "stage_id", "plan", "reference", "wrapper_sha256"}:
            raise AuthorizationError("harness_plan_wrapper_invalid")
        unsigned_wrapper = {key:item for key, item in wrapper.items() if key != "wrapper_sha256"}
        plan = wrapper.get("plan")
        expected = operation.removeprefix("harness-generation-")
        expected_schema = ("secure-sandbox-harness-activation-plan-v1"
                           if expected in {"activate", "rollback"}
                           else "secure-sandbox-harness-management-plan-v1")
        if (wrapper.get("schema") != "secure-sandbox-harness-consumer-plan-v1"
                or UUID4.fullmatch(str(wrapper.get("stage_id", ""))) is None
                or not isinstance(wrapper.get("wrapper_sha256"), str)
                or wrapper["wrapper_sha256"]
                    != hashlib.sha256(canonical(unsigned_wrapper)).hexdigest()
                or not isinstance(plan, dict) or plan.get("schema") != expected_schema
                or plan.get("operation") != expected
                or not isinstance(plan.get("plan_sha256"), str)
                or plan["plan_sha256"] != hashlib.sha256(canonical(
                    {key:item for key, item in plan.items() if key != "plan_sha256"}
                )).hexdigest()
                or not isinstance(plan.get("created_at"), int)
                or not isinstance(plan.get("expires_at"), int)
                or not plan["created_at"] <= int(time.time()) < plan["expires_at"]
                or plan["expires_at"] - plan["created_at"] > 300
                or (expected in {"activate", "rollback"} and wrapper.get("reference") is not None)
                or (expected in {"retire", "revoke"}
                    and not isinstance(wrapper.get("reference"), dict))):
            raise AuthorizationError("harness_plan_wrapper_invalid")
        return
    if operation == "harness-generation-recover":
        recovery = parameters.get("recovery")
        if (set(parameters) != {"recovery"} or not isinstance(recovery, dict)
                or set(recovery) != {"schema", "pending", "journal_sha256"}
                or recovery.get("schema") != "secure-sandbox-harness-consumer-recovery-v1"
                or recovery.get("pending") is not True
                or SHA256.fullmatch(str(recovery.get("journal_sha256", ""))) is None):
            raise AuthorizationError("harness_recovery_state_invalid")
        return
    if operation == "execution-approval-key-init":
        if (set(parameters) != {"research_release_id"}
                or not isinstance(parameters["research_release_id"], str)
                or not SHA256.fullmatch(parameters["research_release_id"])):
            raise AuthorizationError("operation_parameters_invalid")
        return
    if operation == "execution-approval-migration-activate":
        if set(parameters) != {"transaction_id", "research_fence"}:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["transaction_id"], "transaction_id")
        if not isinstance(parameters["research_fence"], dict):
            raise AuthorizationError("research_fence_invalid")
        return
    if operation == "execution-approval-migration-authorize-acceptance":
        if set(parameters) != {"transaction_id", "acceptance"}:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["transaction_id"], "transaction_id")
        validate_acceptance_attempt(parameters["acceptance"], parameters["transaction_id"])
        return
    if operation == "execution-approval-migration-verify-acceptance":
        if set(parameters) != {"research_evidence"} or not isinstance(
                parameters["research_evidence"], dict):
            raise AuthorizationError("operation_parameters_invalid")
        return
    if operation == "execution-approval-migration-commit":
        required = {"transaction_id", "research_activation", "cold_boot_acceptance_sha256",
                    "acceptance_verifier_sha256"}
        if set(parameters) != required:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["transaction_id"], "transaction_id")
        if not isinstance(parameters["research_activation"], dict):
            raise AuthorizationError("research_activation_invalid")
        if (not isinstance(parameters["cold_boot_acceptance_sha256"], str)
                or not SHA256.fullmatch(parameters["cold_boot_acceptance_sha256"])):
            raise AuthorizationError("cold_boot_acceptance_sha256_invalid")
        if (not isinstance(parameters["acceptance_verifier_sha256"], str)
                or not SHA256.fullmatch(parameters["acceptance_verifier_sha256"])):
            raise AuthorizationError("acceptance_verifier_sha256_invalid")
        return
    if operation == "execution-approval-software-retire":
        if set(parameters) != {"transaction_id"}:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["transaction_id"], "transaction_id")
        return
    if operation == "execution-approval-sign":
        required = {
            "schema", "approval_id", "created_at", "expires_at", "run_id", "session_id",
            "source_id", "source_manifest_sha256", "code_sha256", "fixture_manifest",
            "fixture_manifest_sha256", "timeout_seconds",
            "runtime_image_id",
        }
        if set(parameters) != required or parameters.get("schema") != "secure-sandbox-execution-approval-request-v1":
            raise AuthorizationError("operation_parameters_invalid")
        for name in ("approval_id", "run_id", "session_id", "source_id"):
            valid_uuid4(parameters[name], name)
        for name in ("source_manifest_sha256", "code_sha256", "fixture_manifest_sha256"):
            if not isinstance(parameters[name], str) or not SHA256.fullmatch(parameters[name]):
                raise AuthorizationError(f"{name}_invalid")
        fixtures = parameters["fixture_manifest"]
        if not isinstance(fixtures, list) or len(fixtures) > 16:
            raise AuthorizationError("fixture_manifest_invalid")
        for fixture in fixtures:
            if (not isinstance(fixture, dict)
                    or set(fixture) != {"path", "bytes", "sha256"}
                    or not isinstance(fixture["path"], str)
                    or not 1 <= len(fixture["path"].encode("utf-8")) <= 512
                    or any(ord(character) < 32 or ord(character) > 126
                           for character in fixture["path"])
                    or not isinstance(fixture["bytes"], int) or isinstance(fixture["bytes"], bool)
                    or not 0 <= fixture["bytes"] <= 1024 * 1024
                    or not isinstance(fixture["sha256"], str)
                    or not SHA256.fullmatch(fixture["sha256"])):
                raise AuthorizationError("fixture_manifest_invalid")
        expected_fixture_hash = hashlib.sha256(json.dumps(
            fixtures, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
        if expected_fixture_hash != parameters["fixture_manifest_sha256"]:
            raise AuthorizationError("fixture_manifest_hash_mismatch")
        created = parameters["created_at"]
        expires = parameters["expires_at"]
        if (not isinstance(created, int) or isinstance(created, bool)
                or not isinstance(expires, int) or isinstance(expires, bool)
                or expires - created != 90):
            raise AuthorizationError("execution_approval_time_invalid")
        timeout = parameters["timeout_seconds"]
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 10:
            raise AuthorizationError("invalid_timeout")
        image = parameters["runtime_image_id"]
        if not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise AuthorizationError("runtime_image_id_invalid")
        return
    if operation in {"host-controller-install", "host-controller-rollback"}:
        common = {"repo", "state_root"}
        extras = {
            "host-controller-install": {
                "authorized_target_plan", "authorized_target_plan_sha256",
                "native_host_candidate",
            },
            "host-controller-rollback": {
                "authorized_target_plan", "authorized_target_plan_sha256",
            },
        }[operation]
        if set(parameters) != common | extras:
            raise AuthorizationError("operation_parameters_invalid")
        repo = Path(parameters["repo"])
        state_root = Path(parameters["state_root"])
        try:
            repo_info = repo.lstat()
            resolved_repo = repo.resolve(strict=True)
            resolved_home = home.resolve(strict=True)
        except OSError as error:
            raise AuthorizationError("repository_path_invalid") from error
        if (not repo.is_absolute() or repo == Path("/") or stat.S_ISLNK(repo_info.st_mode)
                or not stat.S_ISDIR(repo_info.st_mode) or not resolved_repo.is_relative_to(resolved_home)):
            raise AuthorizationError("repository_path_invalid")
        if state_root != expected_state:
            raise AuthorizationError("controller_state_path_invalid")
        candidate = None
        if operation == "host-controller-install":
            try:
                operator_uid = home.lstat().st_uid
            except OSError as error:
                raise AuthorizationError("native_host_candidate_invalid") from error
            candidate = validate_native_host_candidate_binding(
                parameters["native_host_candidate"], repo, operator_uid,
            )
        validate_host_release_authorized_target_plan(
            operation,
            parameters["authorized_target_plan"],
            parameters["authorized_target_plan_sha256"],
            candidate=candidate,
        )
        return
    if operation == "pki-anchor-begin":
        if set(parameters) != {"generation_id"}:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["generation_id"], "generation_id")
        return
    if operation == "pki-anchor-commit":
        if set(parameters) != {"generation_id", "manifest_sha256", "expected_current"}:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["generation_id"], "generation_id")
        if not isinstance(parameters["manifest_sha256"], str) or not SHA256.fullmatch(parameters["manifest_sha256"]):
            raise AuthorizationError("manifest_sha256_invalid")
        current = parameters["expected_current"]
        if current is not None:
            valid_uuid4(current, "expected_current")
        return
    if operation in {"installer-promote-canonical", "installer-promote-autoinstall",
                     "installer-repair-store-access"}:
        if set(parameters) != {"repo", "release_directory", "expected_sha256"}:
            raise AuthorizationError("operation_parameters_invalid")
        repo = Path(parameters["repo"])
        release_directory = Path(parameters["release_directory"])
        try:
            repo_info = repo.lstat()
            resolved_repo = repo.resolve(strict=True)
            resolved_home = home.resolve(strict=True)
            resolved_release = release_directory.resolve(strict=True)
        except OSError as error:
            raise AuthorizationError("installer_release_path_invalid") from error
        expected_release = resolved_repo / "artifacts/ubuntu-26.04.1"
        if (not repo.is_absolute() or stat.S_ISLNK(repo_info.st_mode)
                or not stat.S_ISDIR(repo_info.st_mode)
                or not resolved_repo.is_relative_to(resolved_home)
                or release_directory != resolved_release
                or resolved_release != expected_release
                or release_directory.is_symlink() or not release_directory.is_dir()):
            raise AuthorizationError("installer_release_path_invalid")
        expected = (AUTOINSTALL_INSTALLER_SHA256 if operation == "installer-promote-autoinstall"
                    else CANONICAL_INSTALLER_SHA256)
        if parameters["expected_sha256"] != expected:
            raise AuthorizationError("installer_expected_sha256_invalid")
        return
    if operation in {"vm-create", "vm-reprovision"}:
        if set(parameters) != {"repo", "plan_sha256", "prlctl_sha256", "installer_sha256", "seed_sha256",
                               "layout_profile", "layout", "host_memory_bytes"}:
            raise AuthorizationError("operation_parameters_invalid")
        repo = Path(parameters["repo"])
        try:
            info = repo.lstat()
            resolved = repo.resolve(strict=True)
            resolved_home = home.resolve(strict=True)
        except OSError as error:
            raise AuthorizationError("repository_path_invalid") from error
        if (not repo.is_absolute() or repo.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or resolved != repo or not resolved.is_relative_to(resolved_home)):
            raise AuthorizationError("repository_path_invalid")
        for name in ("plan_sha256", "prlctl_sha256"):
            if not isinstance(parameters[name], str) or not SHA256.fullmatch(parameters[name]):
                raise AuthorizationError(f"{name}_invalid")
        if parameters["installer_sha256"] != AUTOINSTALL_INSTALLER_SHA256:
            raise AuthorizationError("installer_expected_sha256_invalid")
        seeds = parameters["seed_sha256"]
        if (not isinstance(seeds, dict) or set(seeds) != {"gateway", "research", "target"}
                or any(not isinstance(value, str) or not SHA256.fullmatch(value) for value in seeds.values())):
            raise AuthorizationError("seed_sha256_invalid")
        profile = parameters["layout_profile"]
        layouts = {
            "standard": {"gateway": (1, 2048, 12288), "research": (4, 6144, 51200), "target": (2, 4096, 40960)},
            "neo-8gb": {"gateway": (1, 1536, 12288), "research": (2, 2560, 51200), "target": (1, 1536, 40960)},
        }
        if profile not in layouts or not isinstance(parameters["layout"], dict):
            raise AuthorizationError("vm_layout_invalid")
        expected_layout = {role: {"cpus": values[0], "memory_mib": values[1], "disk_mib": values[2]}
                           for role, values in layouts[profile].items()}
        if parameters["layout"] != expected_layout:
            raise AuthorizationError("vm_layout_invalid")
        memory = parameters["host_memory_bytes"]
        if (type(memory) is not int or profile == "neo-8gb" and not 8 * 1024**3 <= memory < 12 * 1024**3
                or profile == "standard" and memory < 16 * 1024**3):
            raise AuthorizationError("vm_layout_host_memory_invalid")
        return
    if operation == "vm-preserve-legacy":
        required = {
            "repo", "generation", "plan_sha256", "prlctl_sha256",
            "protected_control_client_sha256", "protected_ssh_config_sha256",
            "legacy_vm_uuid", "source_tree_sha256", "transport_vm_uuid", "tools",
            "plan_operation", "recovery_transaction_sha256",
        }
        if set(parameters) != required:
            raise AuthorizationError("operation_parameters_invalid")
        repo = Path(parameters["repo"])
        try:
            info = repo.lstat()
            resolved = repo.resolve(strict=True)
            resolved_home = home.resolve(strict=True)
        except OSError as error:
            raise AuthorizationError("repository_path_invalid") from error
        if (not repo.is_absolute() or repo.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or resolved != repo or not resolved.is_relative_to(resolved_home)):
            raise AuthorizationError("repository_path_invalid")
        if (not isinstance(parameters["generation"], str)
                or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", parameters["generation"])):
            raise AuthorizationError("legacy_generation_invalid")
        if parameters["plan_operation"] not in {"preserve", "recover"}:
            raise AuthorizationError("legacy_plan_operation_invalid")
        recovery = parameters["recovery_transaction_sha256"]
        if ((parameters["plan_operation"] == "preserve" and recovery is not None)
                or (parameters["plan_operation"] == "recover"
                    and (not isinstance(recovery, str) or not SHA256.fullmatch(recovery)))):
            raise AuthorizationError("legacy_recovery_binding_invalid")
        for name in (
            "plan_sha256", "prlctl_sha256", "protected_control_client_sha256",
            "protected_ssh_config_sha256",
        ):
            if not isinstance(parameters[name], str) or not SHA256.fullmatch(parameters[name]):
                raise AuthorizationError(f"{name}_invalid")
        roles = {"gateway", "research", "target"}
        for name in ("legacy_vm_uuid", "source_tree_sha256"):
            value = parameters[name]
            if not isinstance(value, dict) or set(value) != roles:
                raise AuthorizationError(f"{name}_invalid")
        if any(not isinstance(value, str) or not SHA256.fullmatch(value)
               for value in parameters["source_tree_sha256"].values()):
            raise AuthorizationError("source_tree_sha256_invalid")
        if any(not isinstance(value, str) or not re.fullmatch(
                r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", value)
               for value in parameters["legacy_vm_uuid"].values()):
            raise AuthorizationError("legacy_vm_uuid_invalid")
        transports = parameters["transport_vm_uuid"]
        if (not isinstance(transports, dict)
                or set(transports) != {"SecureSandbox-Gateway", "SecureSandbox-Research"}
                or any(not isinstance(value, str) or not re.fullmatch(
                    r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", value)
                    for value in transports.values())):
            raise AuthorizationError("transport_vm_uuid_invalid")
        tools = parameters["tools"]
        if (not isinstance(tools, dict) or set(tools) != PRESERVATION_TOOL_NAMES
                or any(not isinstance(name, str) or not re.fullmatch(r"[a-z_]+", name)
                       or not isinstance(value, str) or not SHA256.fullmatch(value)
                       for name, value in tools.items())):
            raise AuthorizationError("preservation_tools_invalid")
        return
    raise AuthorizationError("operation_not_allowed")


def request_directory(home: Path) -> Path:
    return home / "Library/Application Support/SecureSandbox/authorization-requests"


def secure_user_directory(path: Path, uid: int) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
        raise AuthorizationError("request_directory_untrusted")
    os.chmod(path, 0o700)


def write_request(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = canonical(value)
        write_all(descriptor, data)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


class RequestBinding(NamedTuple):
    path: Path
    directory_descriptor: int
    request_descriptor: int
    directory_identity: tuple[int, int, int, int, int, int]
    request_identity: tuple[int, int, int, int, int]
    expected_uid: int
    expected_digest: str


def _decode_bound_request(data: bytes, expected_digest: str) -> dict[str, Any]:
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise AuthorizationError("request_digest_mismatch")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("request_json_invalid") from error
    if not isinstance(value, dict) or canonical(value) != data:
        raise AuthorizationError("request_not_canonical")
    return value


def read_bound_request(binding: RequestBinding) -> dict[str, Any]:
    """Reread one exact request object through held directory/file handles."""
    directory = os.fstat(binding.directory_descriptor)
    request = os.fstat(binding.request_descriptor)
    try:
        directory_path = binding.path.parent.lstat()
        request_path = binding.path.lstat()
        request_at = os.stat(
            binding.path.name,
            dir_fd=binding.directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise AuthorizationError("request_revoked") from error
    directory_identity = (
        directory.st_dev, directory.st_ino,
        directory.st_uid, stat.S_IMODE(directory.st_mode),
        directory.st_mtime_ns, directory.st_ctime_ns,
    )
    path_directory_identity = (
        directory_path.st_dev, directory_path.st_ino,
        directory_path.st_uid, stat.S_IMODE(directory_path.st_mode),
        directory_path.st_mtime_ns, directory_path.st_ctime_ns,
    )
    request_identity = (
        request.st_dev, request.st_ino, request.st_size,
        request.st_mtime_ns, request.st_ctime_ns,
    )
    if (
        not stat.S_ISDIR(directory.st_mode)
        or stat.S_ISLNK(directory_path.st_mode)
        or directory_identity != binding.directory_identity
        or path_directory_identity != binding.directory_identity
        or directory.st_uid != binding.expected_uid
        or stat.S_IMODE(directory.st_mode) != 0o700
    ):
        raise AuthorizationError("request_directory_changed")
    for observed in (request, request_path, request_at):
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or observed.st_uid != binding.expected_uid
            or observed.st_nlink != 1
            or stat.S_IMODE(observed.st_mode) != 0o600
            or (observed.st_dev, observed.st_ino)
                != binding.request_identity[:2]
        ):
            raise AuthorizationError("request_file_changed")
    if request_identity != binding.request_identity:
        raise AuthorizationError("request_changed_during_read")
    data = os.pread(binding.request_descriptor, 65537, 0)
    if len(data) > 65536 or len(data) != request.st_size:
        raise AuthorizationError("request_file_too_large")
    after = os.fstat(binding.request_descriptor)
    if (
        after.st_nlink != 1
        or (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ) != binding.request_identity
    ):
        raise AuthorizationError("request_changed_during_read")
    return _decode_bound_request(data, binding.expected_digest)


def open_request_binding(
    path: Path, expected_uid: int, expected_digest: str,
) -> tuple[dict[str, Any], RequestBinding]:
    if SHA256.fullmatch(expected_digest) is None or path.name in {"", ".", ".."}:
        raise AuthorizationError("request_identity_invalid")
    directory_descriptor = -1
    request_descriptor = -1
    try:
        directory_before = path.parent.lstat()
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        directory_opened = os.fstat(directory_descriptor)
        directory_identity = (
            directory_opened.st_dev, directory_opened.st_ino,
            directory_opened.st_uid, stat.S_IMODE(directory_opened.st_mode),
            directory_opened.st_mtime_ns, directory_opened.st_ctime_ns,
        )
        if (
            not stat.S_ISDIR(directory_opened.st_mode)
            or stat.S_ISLNK(directory_before.st_mode)
            or (directory_before.st_dev, directory_before.st_ino)
                != directory_identity[:2]
            or directory_opened.st_uid != expected_uid
            or stat.S_IMODE(directory_opened.st_mode) != 0o700
        ):
            raise AuthorizationError("request_directory_untrusted")
        request_before = os.stat(
            path.name, dir_fd=directory_descriptor, follow_symlinks=False
        )
        request_descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
        request_opened = os.fstat(request_descriptor)
        request_identity = (
            request_opened.st_dev, request_opened.st_ino,
            request_opened.st_size, request_opened.st_mtime_ns,
            request_opened.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(request_opened.st_mode)
            or stat.S_ISLNK(request_before.st_mode)
            or request_opened.st_uid != expected_uid
            or request_opened.st_nlink != 1
            or stat.S_IMODE(request_opened.st_mode) != 0o600
            or (request_before.st_dev, request_before.st_ino)
                != request_identity[:2]
        ):
            raise AuthorizationError("request_file_untrusted")
        binding = RequestBinding(
            path, directory_descriptor, request_descriptor,
            directory_identity, request_identity, expected_uid, expected_digest,
        )
        value = read_bound_request(binding)
        return value, binding
    except BaseException:
        if request_descriptor >= 0:
            os.close(request_descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        raise


def close_request_binding(binding: RequestBinding | None) -> None:
    if binding is None:
        return
    for descriptor in (
        binding.request_descriptor, binding.directory_descriptor,
    ):
        try:
            os.close(descriptor)
        except OSError:
            pass


def read_request(path: Path, expected_uid: int, expected_digest: str) -> dict[str, Any]:
    binding: RequestBinding | None = None
    try:
        value, binding = open_request_binding(path, expected_uid, expected_digest)
        return value
    finally:
        close_request_binding(binding)


def verify_request(value: dict[str, Any], uid: int, request_id: str, now: int) -> Path:
    required = {
        "schema", "request_id", "created_at", "expires_at", "invoking_uid", "declared_agent",
        "declared_session", "identity_evidence", "purpose", "resource", "operation", "parameters",
        "ceremony",
    }
    if set(value) != required or value.get("schema") != SCHEMA:
        raise AuthorizationError("request_schema_invalid")
    if value["request_id"] != request_id or value["invoking_uid"] != uid:
        raise AuthorizationError("request_identity_mismatch")
    if value["identity_evidence"] != "operator-declared":
        raise AuthorizationError("identity_evidence_invalid")
    if value["ceremony"] not in CEREMONIES:
        raise AuthorizationError("ceremony_invalid")
    validate_identity(value["declared_agent"], value["declared_session"])
    clean_text(value["purpose"], "purpose", MAX_PURPOSE)
    clean_text(value["resource"], "resource", MAX_RESOURCE)
    if value["resource"] != OPERATION_RESOURCES.get(value["operation"]):
        raise AuthorizationError("operation_resource_mismatch")
    if not isinstance(value["created_at"], int) or not isinstance(value["expires_at"], int):
        raise AuthorizationError("request_time_invalid")
    if value["expires_at"] - value["created_at"] != REQUEST_TTL_SECONDS:
        raise AuthorizationError("request_ttl_invalid")
    if now < value["created_at"] - 5 or now > value["expires_at"]:
        raise AuthorizationError("request_expired")
    home = Path(pwd.getpwuid(uid).pw_dir)
    validate_parameters(
        value["operation"], value["parameters"], home,
        allow_expired_acceptance=(
            value["operation"] == "harness-acceptance-authorize"
            and value["parameters"].get("plan", {}).get("case_id")
            == "touchid-expired-plan"
        ),
    )
    return home


def validate_native_stack_coordination_contract(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError(
            "native_stack_coordination_contract_invalid") from error
    features = value.get("features") if isinstance(value, dict) else None
    epoch = value.get("epoch") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "epoch", "features"}
        or value.get("schema") != NATIVE_STACK_COORDINATION_CONTRACT_SCHEMA
        or not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1
        or not isinstance(features, list)
        or any(
            not isinstance(feature, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", feature) is None
            for feature in features
        )
        or features != sorted(set(features))
        or not NATIVE_STACK_COORDINATION_REQUIRED_FEATURES <= set(features)
        or raw != canonical(value)
    ):
        raise AuthorizationError("native_stack_coordination_contract_invalid")
    return value


def reject_extended_acl(descriptor: int, failure: str) -> None:
    """Require mode bits to be the complete authority for a trusted inode."""
    if (_ACL_GET_FD_NP is None or _ACL_GET_ENTRY is None
            or _ACL_FREE is None):
        if sys.platform != "darwin":
            return
        raise AuthorizationError("extended_acl_api_unavailable")
    ctypes.set_errno(0)
    acl = _ACL_GET_FD_NP(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise AuthorizationError(failure)
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = _ACL_GET_ENTRY(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0:
            raise AuthorizationError(failure)
        if ctypes.get_errno() not in {errno.ENOENT, errno.EINVAL}:
            raise AuthorizationError(failure)
    finally:
        if _ACL_FREE(acl) != 0:
            raise AuthorizationError("extended_acl_release_failed")


def reject_path_extended_acl(path: Path, failure: str) -> None:
    """Reject a named inode's extended ACL without opening private content.

    The login-user broker cannot open a root-owned mode-0600 marker, including
    with Darwin O_EVTONLY.  The marker lives directly in the independently
    verified root-owned mode-0755 install directory, so the login user cannot
    substitute its pathname.  Bracketing this ACL query with stable lstat
    identities therefore preserves the no-content-authority boundary.
    """
    if (_ACL_GET_FILE is None or _ACL_GET_ENTRY is None
            or _ACL_FREE is None):
        if sys.platform != "darwin":
            return
        raise AuthorizationError("extended_acl_api_unavailable")
    ctypes.set_errno(0)
    acl = _ACL_GET_FILE(os.fsencode(path), ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise AuthorizationError(failure)
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = _ACL_GET_ENTRY(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0:
            raise AuthorizationError(failure)
        if ctypes.get_errno() not in {errno.ENOENT, errno.EINVAL}:
            raise AuthorizationError(failure)
    finally:
        if _ACL_FREE(acl) != 0:
            raise AuthorizationError("extended_acl_release_failed")


def acl_stat_identity(item: os.stat_result) -> tuple[int, ...]:
    return (
        item.st_dev, item.st_ino, item.st_size, item.st_mode,
        item.st_uid, item.st_gid, item.st_nlink, item.st_mtime_ns,
        item.st_ctime_ns,
    )


def verify_acl_free_directory(
    path: Path, expected_uid: int, expected_mode: int, failure: str,
) -> os.stat_result:
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise AuthorizationError(failure) from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, failure)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named = path.lstat()
    except OSError as error:
        raise AuthorizationError(failure) from error
    if (
        not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or acl_stat_identity(before) != acl_stat_identity(opened)
        or acl_stat_identity(opened) != acl_stat_identity(after)
        or acl_stat_identity(after) != acl_stat_identity(named)
    ):
        raise AuthorizationError(failure)
    return opened


def verify_acl_free_install_root(
    install_root: Path, expected_uid: int, failure: str,
) -> os.stat_result:
    return verify_acl_free_directory(
        install_root, expected_uid, 0o755, failure,
    )


def read_acl_free_regular(
    path: Path, expected_uid: int, expected_mode: int, failure: str, *,
    maximum: int = 1024 * 1024 * 1024,
    expected_nlink: int | None = None,
) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise AuthorizationError(failure) from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, failure)
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(
                descriptor, min(1024 * 1024, maximum + 1 - size),
            )
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > maximum:
                raise AuthorizationError(failure)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named = path.lstat()
    except OSError as error:
        raise AuthorizationError(failure) from error
    raw = b"".join(chunks)
    if (
        not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or (expected_nlink is not None
            and opened.st_nlink != expected_nlink)
        or len(raw) != opened.st_size
        or acl_stat_identity(before) != acl_stat_identity(opened)
        or acl_stat_identity(opened) != acl_stat_identity(after)
        or acl_stat_identity(after) != acl_stat_identity(named)
    ):
        raise AuthorizationError(failure)
    return raw


def verify_acl_free_private_marker(
    path: Path, failure: str,
) -> os.stat_result:
    """Inspect private marker metadata without acquiring content authority."""
    try:
        before = path.lstat()
        reject_path_extended_acl(path, failure)
        after = path.lstat()
    except OSError as error:
        raise AuthorizationError(failure) from error
    try:
        named = path.lstat()
    except OSError as error:
        raise AuthorizationError(failure) from error
    if (
        stat.S_ISLNK(before.st_mode)
        or acl_stat_identity(before) != acl_stat_identity(after)
        or acl_stat_identity(after) != acl_stat_identity(named)
    ):
        raise AuthorizationError(failure)
    return after


def native_stack_coordination_floor(
    install_root: Path, expected_uid: int,
) -> dict[str, Any]:
    """Verify the private marker without acquiring its content authority.

    The login-user broker validates the root-owned 0444 enforcement projection
    and the private marker's stable metadata/ACL only.  The privileged release
    manager independently reads the mode-0600 floor, verifies its canonical
    bytes and cross-binds its digest to this projection before any mutation.
    """
    path = install_root / NATIVE_STACK_COORDINATION_FLOOR_NAME
    root = verify_acl_free_install_root(
        install_root, expected_uid,
        "native_stack_coordination_floor_untrusted",
    )
    try:
        info = verify_acl_free_private_marker(
            path, "native_stack_coordination_floor_untrusted",
        )
    except OSError as error:
        raise AuthorizationError(
            "native_stack_coordination_floor_untrusted") from error
    if (
        not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
        or root.st_uid != expected_uid or stat.S_IMODE(root.st_mode) != 0o755
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid or info.st_gid != root.st_gid
        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
        or not 2 <= info.st_size <= 2048
    ):
        raise AuthorizationError("native_stack_coordination_floor_untrusted")
    enforcement = native_stack_coordination_enforcement(
        install_root, expected_uid)
    return enforcement


def native_stack_coordination_enforcement(
    install_root: Path, expected_uid: int,
) -> dict[str, Any]:
    path = install_root / NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME
    root = verify_acl_free_install_root(
        install_root, expected_uid,
        "native_stack_coordination_enforcement_untrusted",
    )
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise AuthorizationError(
            "native_stack_coordination_enforcement_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor,
            "native_stack_coordination_enforcement_untrusted",
        )
        raw = bytearray()
        while len(raw) <= 2048:
            block = os.read(descriptor, min(2049 - len(raw), 2048))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = path.lstat()
    except OSError as error:
        raise AuthorizationError(
            "native_stack_coordination_enforcement_untrusted") from error

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev, item.st_ino, item.st_size, item.st_mode,
            item.st_uid, item.st_gid, item.st_nlink, item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if (
        not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
        or root.st_uid != expected_uid or stat.S_IMODE(root.st_mode) != 0o755
        or not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid or opened.st_gid != root.st_gid
        or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o444
        or not 2 <= opened.st_size <= 2048 or len(raw) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or identity(after) != identity(current)
    ):
        raise AuthorizationError(
            "native_stack_coordination_enforcement_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError(
            "native_stack_coordination_enforcement_invalid") from error
    features = value.get("minimum_features") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "minimum_epoch", "minimum_features",
            "authoritative_floor_sha256",
        }
        or value.get("schema")
        != NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA
        or not isinstance(value.get("minimum_epoch"), int)
        or isinstance(value.get("minimum_epoch"), bool)
        or value["minimum_epoch"] < 1
        or not isinstance(features, list)
        or any(
            not isinstance(feature, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", feature) is None
            for feature in features
        )
        or features != sorted(set(features))
        or not NATIVE_STACK_COORDINATION_REQUIRED_FEATURES <= set(features)
        or SHA256.fullmatch(str(value.get(
            "authoritative_floor_sha256", ""))) is None
        or bytes(raw) != canonical(value)
    ):
        raise AuthorizationError(
            "native_stack_coordination_enforcement_invalid")
    return value


def native_host_candidate_enforcement(
    install_root: Path, expected_uid: int,
    payload_names: set[str],
) -> dict[str, Any]:
    path = install_root / NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME
    root = verify_acl_free_install_root(
        install_root, expected_uid,
        "native_host_candidate_enforcement_untrusted",
    )
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise AuthorizationError(
            "native_host_candidate_enforcement_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "native_host_candidate_enforcement_untrusted")
        raw = bytearray()
        while len(raw) <= 2048:
            block = os.read(descriptor, min(2049 - len(raw), 2048))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = path.lstat()
    except OSError as error:
        raise AuthorizationError(
            "native_host_candidate_enforcement_untrusted") from error

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev, item.st_ino, item.st_size, item.st_mode,
            item.st_uid, item.st_gid, item.st_nlink, item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if (
        not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
        or root.st_uid != expected_uid or stat.S_IMODE(root.st_mode) != 0o755
        or not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid or opened.st_gid != root.st_gid
        or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o444
        or not 2 <= opened.st_size <= 2048 or len(raw) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or identity(after) != identity(current)
    ):
        raise AuthorizationError(
            "native_host_candidate_enforcement_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError(
            "native_host_candidate_enforcement_invalid") from error
    expected_inventory = hashlib.sha256(canonical({
        "payload_names": sorted(payload_names),
        "schema": NATIVE_HOST_CANDIDATE_INVENTORY_SCHEMA,
    })).hexdigest()
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "required_feature",
            "required_payload_inventory_sha256",
            "authoritative_floor_sha256",
        }
        or value.get("schema")
            != NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA
        or value.get("required_feature")
            != NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
        or value.get("required_payload_inventory_sha256")
            != expected_inventory
        or SHA256.fullmatch(str(value.get(
            "authoritative_floor_sha256", ""))) is None
        or bytes(raw) != canonical(value)
    ):
        raise AuthorizationError(
            "native_host_candidate_enforcement_invalid")
    return value


def native_host_candidate_floor(
    install_root: Path, expected_uid: int,
    payload_names: set[str],
) -> dict[str, Any]:
    """Require the private floor marker, then enforce its public projection.

    The authorization broker is deliberately invoked by the login user and
    must not acquire read authority over the root-only 0600 floor.  Its
    independent admission decision is therefore based on the canonical 0444
    projection.  The private path is checked only as a root-owned, one-link,
    regular marker so a public-first crash cannot admit requests before the
    authoritative floor has been published.
    """
    path = install_root / NATIVE_HOST_CANDIDATE_FLOOR_NAME
    root = verify_acl_free_install_root(
        install_root, expected_uid,
        "native_host_candidate_floor_untrusted",
    )
    try:
        marker = verify_acl_free_private_marker(
            path, "native_host_candidate_floor_untrusted")
    except OSError as error:
        raise AuthorizationError(
            "native_host_candidate_floor_untrusted") from error
    if (
        not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
        or root.st_uid != expected_uid or stat.S_IMODE(root.st_mode) != 0o755
        or not stat.S_ISREG(marker.st_mode) or stat.S_ISLNK(marker.st_mode)
        or marker.st_uid != expected_uid or marker.st_gid != root.st_gid
        or marker.st_nlink != 1 or stat.S_IMODE(marker.st_mode) != 0o600
        or not 2 <= marker.st_size <= 4096
    ):
        raise AuthorizationError("native_host_candidate_floor_untrusted")
    return native_host_candidate_enforcement(
        install_root, expected_uid, payload_names,
    )


def protected_release_directory(
    path: Path, expected_uid: int = 0, *,
    allow_coordination_predecessor: bool = False,
) -> Path:
    requested_path = path
    release = path.resolve(strict=True).parent
    verify_acl_free_install_root(
        release.parent.parent, expected_uid,
        "authorization_broker_release_untrusted",
    )
    verify_acl_free_directory(
        release.parent, expected_uid, 0o755,
        "authorization_broker_release_untrusted",
    )
    verify_acl_free_directory(
        release, expected_uid, 0o555,
        "authorization_broker_release_untrusted",
    )
    manifest_path = release / "manifest.json"
    manifest_raw = read_acl_free_regular(
        manifest_path, expected_uid, 0o444,
        "authorization_manifest_untrusted", maximum=2 * 1024 * 1024,
    )
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("authorization_manifest_invalid") from error
    payloads = manifest.get("payloads", {})
    payload_names = set(payloads) if isinstance(payloads, dict) else set()
    if payload_names == set(EXPECTED_RELEASE_MODES):
        release_modes = EXPECTED_RELEASE_MODES
    elif payload_names == set(PRE_NATIVE_HOST_RECEIPT_SIGNATURE_RELEASE_MODES):
        release_modes = PRE_NATIVE_HOST_RECEIPT_SIGNATURE_RELEASE_MODES
    elif (
        allow_coordination_predecessor
        and payload_names == set(PRE_NATIVE_STACK_COORDINATION_RELEASE_MODES)
    ):
        predecessor = requested_path.parent
        try:
            predecessor_info = predecessor.lstat()
            predecessor_target = os.readlink(predecessor)
            predecessor_release_root = (
                predecessor.parent / "releases").resolve(strict=True)
        except OSError as error:
            raise AuthorizationError(
                "authorization_coordination_predecessor_invalid") from error
        if (
            requested_path.name != "authorization_broker"
            or predecessor.name != "previous"
            or not stat.S_ISLNK(predecessor_info.st_mode)
            or predecessor_info.st_uid != expected_uid
            or predecessor_target != f"releases/{release.name}"
            or release.parent != predecessor_release_root
        ):
            raise AuthorizationError(
                "authorization_coordination_predecessor_invalid")
        release_modes = PRE_NATIVE_STACK_COORDINATION_RELEASE_MODES
    else:
        release_modes = None
    if (manifest.get("schema") != "secure-sandbox-host-controller-release-v1"
            or not isinstance(payloads, dict) or release_modes is None):
        raise AuthorizationError("authorization_manifest_invalid")
    identity = bytearray()
    for name in sorted(payloads):
        expected = payloads[name]
        if not isinstance(name, str) or not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise AuthorizationError("authorization_manifest_invalid")
        identity.extend(f"{name}\0{expected}\n".encode("ascii"))
    release_id = hashlib.sha256(bytes(identity)).hexdigest()
    if manifest.get("release_id") != release_id or release.name != release_id:
        raise AuthorizationError("authorization_release_identity_invalid")
    coordination_contract_raw = None
    authorization_ui_bundle_raw = None
    for name, expected_mode in release_modes.items():
        candidate = release / name
        expected = payloads.get(name)
        candidate_raw = read_acl_free_regular(
            candidate, expected_uid, expected_mode,
            f"protected_payload_invalid:{name}",
        )
        if (not isinstance(expected, str)
                or hashlib.sha256(candidate_raw).hexdigest() != expected):
            raise AuthorizationError(f"protected_payload_invalid:{name}")
        if name == "native_stack_coordination_contract":
            coordination_contract_raw = candidate_raw
        elif name == "authorization_ui_bundle":
            authorization_ui_bundle_raw = candidate_raw
    if coordination_contract_raw is not None:
        contract = validate_native_stack_coordination_contract(
            coordination_contract_raw)
        candidate_enforcement_path = (
            release.parent.parent / NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME
        )
        candidate_floor_path = (
            release.parent.parent / NATIVE_HOST_CANDIDATE_FLOOR_NAME
        )
        candidate_enforcement_pending_path = (
            release.parent.parent
            / NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME
        )
        candidate_floor_pending_path = (
            release.parent.parent
            / NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME
        )
        candidate_feature = (
            NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
            in contract["features"]
        )
        # The pending names are the first durable crash-replay fence.  They
        # are never admissible broker state, even if an older final projection
        # also happens to exist: only the terminal/root bootstrap may reconcile
        # that transition and remove the pending names.
        if (os.path.lexists(candidate_enforcement_pending_path)
                or os.path.lexists(candidate_floor_pending_path)):
            raise AuthorizationError(
                "native_host_candidate_floor_untrusted")
        if (candidate_feature or os.path.lexists(candidate_enforcement_path)
                or os.path.lexists(candidate_floor_path)
                ):
            native_host_candidate_floor(
                release.parent.parent, expected_uid,
                set(EXPECTED_RELEASE_MODES),
            )
            if (not candidate_feature
                    or payload_names != set(EXPECTED_RELEASE_MODES)):
                raise AuthorizationError(
                    "native_host_candidate_contract_below_floor")
        enforcement = native_stack_coordination_floor(
            release.parent.parent, expected_uid)
        if (
            contract["epoch"] < enforcement["minimum_epoch"]
            or not set(enforcement["minimum_features"]) <= set(
                contract["features"])
        ):
            raise AuthorizationError(
                "native_stack_coordination_contract_below_floor")
    try:
        bundle_manifest = json.loads(authorization_ui_bundle_raw)
        bundle_files = bundle_manifest["files"]
    except (KeyError, TypeError, UnicodeDecodeError,
            json.JSONDecodeError) as error:
        raise AuthorizationError("authorization_ui_bundle_invalid") from error
    bundle_schema = bundle_manifest.get("schema") if isinstance(bundle_manifest, dict) else None
    bundle_keys = ({"bundle", "files", "schema"}
                   if bundle_schema == "secure-sandbox-touchid-ui-bundle-v1"
                   else {"bundle", "files", "schema", "signing_policy"})
    if (bundle_schema not in {"secure-sandbox-touchid-ui-bundle-v1", "secure-sandbox-touchid-ui-bundle-v2"}
            or set(bundle_manifest) != bundle_keys
            or bundle_manifest.get("bundle") != TOUCHID_UI_APP_NAME
            or not isinstance(bundle_files, dict)):
        raise AuthorizationError("authorization_ui_bundle_invalid")
    if bundle_schema == "secure-sandbox-touchid-ui-bundle-v2":
        manifest_signing_policy(bundle_manifest)
    bundle = release / TOUCHID_UI_APP_NAME
    verify_acl_free_directory(
        bundle, expected_uid, 0o555, "authorization_ui_bundle_invalid",
    )
    actual_files: set[str] = set()
    for item in bundle.rglob("*"):
        try:
            info = item.lstat()
        except OSError as error:
            raise AuthorizationError(
                "authorization_ui_bundle_invalid") from error
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            verify_acl_free_directory(
                item, expected_uid, 0o555,
                "authorization_ui_bundle_invalid",
            )
        elif stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            actual_files.add(item.relative_to(bundle).as_posix())
        else:
            raise AuthorizationError("authorization_ui_bundle_invalid")
    if actual_files != set(bundle_files):
        raise AuthorizationError("authorization_ui_bundle_invalid")
    for relative, record in bundle_files.items():
        candidate = bundle / relative
        if (not isinstance(record, dict)
                or set(record) != {"mode", "sha256", "size"}
                or not isinstance(record.get("mode"), int)
                or isinstance(record.get("mode"), bool)):
            raise AuthorizationError("authorization_ui_bundle_invalid")
        raw = read_acl_free_regular(
            candidate, expected_uid, record["mode"],
            "authorization_ui_bundle_invalid",
        )
        if (len(raw) != record.get("size")
                or hashlib.sha256(raw).hexdigest() != record.get("sha256")):
            raise AuthorizationError("authorization_ui_bundle_invalid")
    return release


def manifest_signing_policy(manifest: dict[str, Any]) -> dict[str, str] | None:
    if manifest.get("schema") == "secure-sandbox-touchid-ui-bundle-v1":
        return None
    policy = manifest.get("signing_policy")
    if (not isinstance(policy, dict)
            or set(policy) != {"access_group", "application_identifier", "bundle_id", "team_id"}
            or not isinstance(policy.get("team_id"), str)
            or APPLE_TEAM_ID.fullmatch(policy["team_id"]) is None
            or policy.get("bundle_id") != "org.zebeth.SecureSandbox.AuthorizationUI"
            or policy.get("application_identifier") != policy["team_id"] + "." + policy["bundle_id"]
            or policy.get("access_group") != policy["application_identifier"]):
        raise AuthorizationError("authorization_ui_signing_policy_invalid")
    return policy


def touchid_signing_policy(release: Path) -> dict[str, str]:
    try:
        manifest = json.loads((release / "authorization_ui_bundle").read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("authorization_ui_bundle_invalid") from error
    policy = manifest_signing_policy(manifest)
    if policy is not None:
        return policy
    bundle = release / TOUCHID_UI_APP_NAME
    result = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(bundle)],
        check=False, capture_output=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    try:
        entitlements = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise AuthorizationError("touchid_ui_entitlements_invalid") from error
    team = entitlements.get("com.apple.developer.team-identifier")
    bundle_id = "org.zebeth.SecureSandbox.AuthorizationUI"
    application_identifier = team + "." + bundle_id if isinstance(team, str) else ""
    policy = {"team_id":team, "bundle_id":bundle_id,
              "application_identifier":application_identifier,
              "access_group":application_identifier}
    if (result.returncode != 0 or not isinstance(team, str)
            or APPLE_TEAM_ID.fullmatch(team) is None
            or entitlements != {
                "com.apple.application-identifier":application_identifier,
                "com.apple.developer.team-identifier":team,
                "keychain-access-groups":[application_identifier],
            }):
        raise AuthorizationError("touchid_ui_signature_invalid")
    return policy


def operation_command(value: dict[str, Any], release: Path, *, operator_uid: int | None = None,
                      authorization: dict[str, Any] | None = None) -> list[str]:
    operation = value["operation"]
    parameters = value["parameters"]
    if operation == "authorization-probe":
        return ["/usr/bin/printf", "touchid-authorization-probe:%s\\n", parameters["challenge"]]
    if operation == "model-profile-activate":
        return [str(release / "model_profile_manager"), "activate", "--plan-json",
                canonical(parameters["plan"]).decode("ascii")]
    if operation == native_stack_catalog_promotion.OPERATION:
        raise AuthorizationError(
            "native_catalog_promotion_inherited_host_lock_required")
    if operation == native_program_attestation.OPERATION:
        if authorization is None:
            raise AuthorizationError(
                "native_program_attestation_authorization_missing"
            )
        return [
            "/usr/bin/python3", "-I", str(release / "native_stack_backend"),
            "program-attest",
        ]
    if operation == native_projection_reconciliation.OPERATION:
        if authorization is None:
            raise AuthorizationError(
                "native_projection_reconciliation_authorization_missing"
            )
        return [
            "/usr/bin/python3", "-I",
            str(release / "native_stack_session_manager"),
            "projection-reconcile",
            "--plan-json", canonical_v2(parameters["plan"]).decode("ascii"),
            "--authorization-json", canonical_v2(authorization).decode("ascii"),
        ]
    if operation == native_projection_identity_recovery.OPERATION:
        if authorization is None:
            raise AuthorizationError(
                "native_projection_identity_recovery_authorization_missing"
            )
        return [
            "/usr/bin/python3", "-I",
            str(release / "native_stack_session_manager"),
            "projection-identity-recover",
            "--plan-json", canonical_v2(parameters["plan"]).decode("ascii"),
            "--authorization-json", canonical_v2(authorization).decode("ascii"),
        ]
    if operation in native_deployment.OPERATIONS:
        raise AuthorizationError(
            "native_deployment_inherited_host_lock_required")
    if operation in {"native-session-start", "native-session-stop"}:
        if authorization is None:
            raise AuthorizationError(
                "native_stack_session_authorization_missing"
            )
        return [
            "/usr/bin/python3", "-I",
            str(release / "native_stack_session_manager"),
            "prepare" if operation == "native-session-start" else "stop",
            "--plan-json", canonical_v2(parameters["plan"]).decode("ascii"),
            "--authorization-json", canonical_v2(authorization).decode("ascii"),
        ]
    if operation.startswith("native-stack-"):
        if authorization is None:
            raise AuthorizationError("native_stack_authorization_missing")
        manager_command = (
            "prepare-interactive"
            if (operation == "native-stack-signin-begin"
                and parameters["plan"]["identity"]["vendor_id"]
                    == "anthropic")
            else "apply"
        )
        return [
            "/usr/bin/python3", "-I", str(release / "native_stack_manager"),
            manager_command,
            "--plan-json", canonical_v2(parameters["plan"]).decode("ascii"),
            "--authorization-json", canonical_v2(authorization).decode("ascii"),
        ]
    if operation == "harness-acceptance-authorize":
        if operator_uid is None or authorization is None:
            raise AuthorizationError("harness_authorization_missing")
        plan = parameters["plan"]
        if plan.get("operator_uid") != operator_uid:
            raise AuthorizationError("harness_operator_uid_mismatch")
        consumer_name = {
            "authorization": "harness-lifecycle-acceptance-authorization.py",
            "runtime": "harness-lifecycle-acceptance-runtime.py",
            "management": "harness-lifecycle-acceptance-management.py",
        }.get(plan.get("category"))
        if consumer_name is None:
            raise AuthorizationError("harness_acceptance_category_invalid")
        consumer = (Path("/usr/local/libexec/secure-sandbox-harness-acceptance/releases")
                    / plan["source_commit"] / "scripts" / consumer_name)
        return [
            "/usr/bin/python3", "-I", str(consumer), "consume",
            "--plan-json", canonical_v2(plan).decode("ascii"),
            "--authorization-json", canonical_v2(authorization).decode("ascii"),
            "--operator-uid", str(operator_uid),
        ]
    if operation.startswith("harness-generation-"):
        action = operation.removeprefix("harness-generation-")
        command = [str(release / "harness_lifecycle_manager")]
        if action == "recover":
            return command + ["recover", "--recovery-json",
                              canonical_v2(parameters["recovery"]).decode("ascii")]
        if operator_uid is None or authorization is None:
            raise AuthorizationError("harness_authorization_missing")
        return command + [
            "apply", action, "--wrapper-json", canonical_v2(parameters["plan"]).decode("ascii"),
            "--authorization-json", canonical_v2(authorization).decode("ascii"),
            "--operator-uid", str(operator_uid),
        ]
    if operation == "execution-approval-key-init":
        return [str(release / "authorization_broker"), "execution-approval-key-init"]
    if operation == "execution-approval-sign":
        return [
            str(release / "authorization_broker"), "execution-approval-sign",
            "--authorization-request-id", value["request_id"],
            "--host-release-id", release.name,
            "--parameters-json", canonical(parameters).decode("ascii").strip(),
        ]
    if operation in {
        "execution-approval-migration-activate",
        "execution-approval-migration-authorize-acceptance",
        "execution-approval-migration-verify-acceptance",
        "execution-approval-migration-commit",
        "execution-approval-software-retire",
    }:
        command = [str(release / "authorization_broker")]
        if operation == "execution-approval-migration-activate":
            return command + [
                "execution-approval-migration-activate",
                "--transaction-id", parameters["transaction_id"],
                "--research-fence-json", canonical_v2(parameters["research_fence"]).decode("ascii"),
            ]
        if operation == "execution-approval-migration-authorize-acceptance":
            return command + [
                "execution-approval-migration-authorize-acceptance",
                "--transaction-id", parameters["transaction_id"],
                "--acceptance-json", canonical_v2(parameters["acceptance"]).decode("ascii"),
            ]
        if operation == "execution-approval-migration-verify-acceptance":
            return command + [
                "execution-approval-acceptance-verify",
                "--research-evidence-json",
                canonical_v2(parameters["research_evidence"]).decode("ascii"),
            ]
        if operation == "execution-approval-migration-commit":
            return command + [
                "execution-approval-migration-commit",
                "--transaction-id", parameters["transaction_id"],
                "--research-activation-json", canonical_v2(parameters["research_activation"]).decode("ascii"),
                "--cold-boot-acceptance-sha256", parameters["cold_boot_acceptance_sha256"],
                "--acceptance-verifier-sha256", parameters["acceptance_verifier_sha256"],
            ]
        return command + [
            "execution-approval-software-retire",
            "--transaction-id", parameters["transaction_id"],
        ]
    if operation in {"host-controller-install", "host-controller-rollback"}:
        action = operation.removeprefix("host-controller-")
        target_plan = parameters["authorized_target_plan"]
        command = [
            "/usr/bin/python3", "-I", str(release / "release_manager"),
            action,
            "--repo", parameters["repo"], "--state-root",
            parameters["state_root"], "--authorized-target-plan-sha256",
            parameters["authorized_target_plan_sha256"], "--json",
        ]
        if action == "rollback":
            command.extend([
                "--release-id", target_plan["target_release_id"],
                "--authorization-request-id", value["request_id"],
                "--authorization-request-sha256",
                hashlib.sha256(canonical(value)).hexdigest(),
            ])
        if action == "install":
            command.extend([
                "--expected-source-release-id",
                target_plan["release_id"],
                "--native-host-candidate-json",
                canonical(parameters["native_host_candidate"])
                    .decode("ascii").strip(),
                "--authorization-request-id", value["request_id"],
                "--authorization-request-sha256",
                hashlib.sha256(canonical(value)).hexdigest(),
            ])
        return command
    if operation.startswith("installer-"):
        action = {
            "installer-promote-canonical": "--promote",
            "installer-promote-autoinstall": "--promote-autoinstall",
            "installer-repair-store-access": "--repair-store-access",
        }[operation]
        return [
            "/usr/bin/python3", "-I", str(release / "installer_verifier"),
            "--release-directory", parameters["release_directory"], action, "--path-only",
        ]
    if operation in {"vm-create", "vm-reprovision"}:
        return [
            "/usr/bin/python3", "-I", str(release / "vm_maintenance"),
            operation.removeprefix("vm-"), "--repo", parameters["repo"],
            "--invoking-uid", str(value["invoking_uid"]),
            "--expected-plan-sha256", parameters["plan_sha256"],
            "--expected-prlctl-sha256", parameters["prlctl_sha256"],
            "--expected-installer-sha256", parameters["installer_sha256"],
            "--expected-seed-gateway-sha256", parameters["seed_sha256"]["gateway"],
            "--expected-seed-research-sha256", parameters["seed_sha256"]["research"],
            "--expected-seed-target-sha256", parameters["seed_sha256"]["target"],
            "--layout-profile", parameters["layout_profile"],
            "--expected-layout-profile", parameters["layout_profile"],
            "--expected-layout-sha256", hashlib.sha256(canonical(parameters["layout"])).hexdigest(),
            "--expected-host-memory-bytes", str(parameters["host_memory_bytes"]),
        ]
    if operation == "vm-preserve-legacy":
        return [
            "/usr/bin/python3", "-I", str(release / "vm_maintenance"),
            "preserve-legacy", "--repo", parameters["repo"],
            "--generation", parameters["generation"],
            "--invoking-uid", str(value["invoking_uid"]),
            "--expected-plan-sha256", parameters["plan_sha256"],
            "--expected-preservation-planner-sha256", parameters["tools"]["preservation_planner"],
            "--expected-preservation-executor-sha256", parameters["tools"]["preservation_executor"],
        ]
    command = [str(release / "pki_anchor")]
    if operation == "pki-anchor-begin":
        return command + ["begin", parameters["generation_id"]]
    command.extend(["commit", parameters["generation_id"], parameters["manifest_sha256"]])
    if parameters["expected_current"]:
        command.extend(["--expected-current", parameters["expected_current"]])
    return command


def native_deployment_operation_arguments(
    value: dict[str, Any], release: Path,
    authorization: dict[str, Any] | None,
) -> list[str]:
    operation = value["operation"]
    parameters = value["parameters"]
    if authorization is None or operation not in native_deployment.OPERATIONS:
        raise AuthorizationError("native_deployment_authorization_missing")
    if operation == native_deployment.APPLY_OPERATION:
        plan_response = validate_native_deployment_plan_response(
            parameters["plan"], now=authorization["authorized_at"],
            require_fresh=True, expected_host_release_id=release.name,
        )
        command = "consume"
        plan_argument = [
            "--plan-json",
            native_deployment.canonical(plan_response).decode("ascii").rstrip("\n"),
        ]
    else:
        recovery = validate_native_deployment_recovery_plan(
            parameters["recovery"], expected_host_release_id=release.name,
        )
        if parameters["action"] != authorization["recovery_action"]:
            raise AuthorizationError(
                "native_deployment_recovery_action_invalid")
        command = "recover"
        plan_argument = [
            "--recovery-json",
            native_deployment.canonical(recovery).decode("ascii").rstrip("\n"),
        ]
    return [
        command, *plan_argument, "--authorization-json",
        native_deployment.canonical(authorization).decode("ascii").rstrip("\n"),
    ]


def atomic_receipt(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        write_all(descriptor, canonical(value))
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_public_record(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        write_all(descriptor, canonical(value))
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_privileged_operation(
    command: list[str], timeout: int = OPERATION_TIMEOUT_SECONDS,
    input_bytes: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    starts_owned_group, environment = child_process_policy()
    process = subprocess.Popen(
        command,
        stdin=(subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, start_new_session=starts_owned_group,
        pass_fds=pass_fds,
    )
    try:
        stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
        if starts_owned_group and process_group_exists(process.pid):
            terminate_bounded_process(process, owns_group=True)
            return subprocess.CompletedProcess(
                command, 125, stdout,
                stderr + b"privileged_operation_descendant_unreaped\n",
            )
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        terminate_bounded_process(process, owns_group=starts_owned_group)
        stdout, stderr = process.communicate()
        return subprocess.CompletedProcess(
            command, 124, stdout, stderr + b"privileged_operation_timeout\n"
        )
    except BaseException:
        terminate_bounded_process(process, owns_group=starts_owned_group)
        raise


def _validate_selected_host_release(
    descriptor: int, release: Path, *, install_root: Path,
    expected_uid: int,
) -> None:
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "native_deployment_host_release_untrusted")
        current_root = install_root.lstat()
        current = install_root / "current"
        current_info = current.lstat()
        target = os.readlink(current)
        selected = current.resolve(strict=True)
        releases = (install_root / "releases").resolve(strict=True)
        release_info = release.lstat()
    except OSError as error:
        raise AuthorizationError("native_deployment_host_release_untrusted") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(current_root.st_mode)
        or (opened.st_dev, opened.st_ino)
        != (current_root.st_dev, current_root.st_ino)
        or opened.st_uid != expected_uid
        or stat.S_IMODE(opened.st_mode) != 0o755
        or not stat.S_ISLNK(current_info.st_mode)
        or current_info.st_uid != expected_uid
        or target != f"releases/{release.name}"
        or selected != release
        or release.parent != releases
        or not stat.S_ISDIR(release_info.st_mode)
        or stat.S_ISLNK(release_info.st_mode)
        or release_info.st_uid != expected_uid
        or stat.S_IMODE(release_info.st_mode) != 0o555
    ):
        raise AuthorizationError("native_deployment_host_release_untrusted")


_NATIVE_DEPLOYER_FD_BOOTSTRAP = r'''
import os
import sys

descriptor = int(sys.argv[1])
path = sys.argv[2]
source = bytearray()
while len(source) <= 16 * 1024 * 1024:
    block = os.read(
        descriptor, min(1024 * 1024, 16 * 1024 * 1024 + 1 - len(source)))
    if not block:
        break
    source.extend(block)
if not 1 <= len(source) <= 16 * 1024 * 1024:
    raise RuntimeError("native_deployment_deployer_invalid")
sys.argv = [path, *sys.argv[3:]]
namespace = {
    "__name__": "__main__", "__file__": path, "__package__": None,
    "__cached__": None,
}
exec(compile(bytes(source), path, "exec", dont_inherit=True, optimize=0),
     namespace, namespace)
'''


def _verified_release_manifest_payload_sha256(
    release: Path, payload_name: str, *, expected_uid: int,
) -> str:
    manifest_path = release / "manifest.json"
    try:
        before = manifest_path.lstat()
        descriptor = os.open(
            manifest_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise AuthorizationError("authorization_manifest_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, "authorization_manifest_untrusted")
        raw = bytearray()
        while len(raw) <= 2 * 1024 * 1024:
            block = os.read(
                descriptor,
                min(65536, 2 * 1024 * 1024 + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = manifest_path.lstat()
    except OSError as error:
        raise AuthorizationError("authorization_manifest_untrusted") from error

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev, item.st_ino, item.st_size, item.st_mode,
            item.st_uid, item.st_gid, item.st_nlink, item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if (
        not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o444
        or not 2 <= opened.st_size <= 2 * 1024 * 1024
        or len(raw) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or identity(after) != identity(current)
    ):
        raise AuthorizationError("authorization_manifest_untrusted")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("authorization_manifest_invalid") from error
    payloads = manifest.get("payloads") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema")
        != "secure-sandbox-host-controller-release-v1"
        or not isinstance(payloads, dict)
        or set(payloads) != set(EXPECTED_RELEASE_MODES)
        or payload_name not in payloads
        or any(
            not isinstance(name, str) or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            for name, digest in payloads.items()
        )
    ):
        raise AuthorizationError("authorization_manifest_invalid")
    identity_bytes = b"".join(
        f"{name}\0{payloads[name]}\n".encode("ascii")
        for name in sorted(payloads)
    )
    if (
        hashlib.sha256(identity_bytes).hexdigest() != release.name
        or manifest.get("release_id") != release.name
    ):
        raise AuthorizationError("authorization_release_identity_invalid")
    return payloads[payload_name]


def run_native_deployment_driver(
    release: Path, arguments: list[str], *, timeout: int,
    expected_uid: int = 0, install_root: Path = HOST_INSTALL_ROOT,
) -> subprocess.CompletedProcess[bytes]:
    """Run the exact selected deployer under one caller-held Host flock."""
    try:
        before = install_root.lstat()
        descriptor = os.open(
            install_root,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise AuthorizationError("native_deployment_host_lock_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o755
        ):
            raise AuthorizationError("native_deployment_host_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_selected_host_release(
            descriptor, release, install_root=install_root,
            expected_uid=expected_uid,
        )
        verified = protected_release_directory(
            release / "authorization_broker", expected_uid)
        if verified != release:
            raise AuthorizationError(
                "native_deployment_host_release_untrusted")
        try:
            expected_deployer_sha256 = (
                _verified_release_manifest_payload_sha256(
                    release, "native_stack_deployer",
                    expected_uid=expected_uid)
            )
            deployer = release / "native_stack_deployer"
            before_deployer = deployer.lstat()
            deployer_fd = os.open(
                deployer,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except (OSError, KeyError, TypeError, UnicodeDecodeError,
                json.JSONDecodeError, AuthorizationError) as error:
            raise AuthorizationError(
                "native_deployment_deployer_untrusted") from error
        try:
            opened_deployer = os.fstat(deployer_fd)
            reject_extended_acl(
                deployer_fd, "native_deployment_deployer_untrusted")
            source = bytearray()
            while len(source) <= 16 * 1024 * 1024:
                block = os.read(
                    deployer_fd,
                    min(1024 * 1024, 16 * 1024 * 1024 + 1 - len(source)))
                if not block:
                    break
                source.extend(block)
            after_read = os.fstat(deployer_fd)
            current_deployer = deployer.lstat()
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_size, item.st_mode,
                item.st_uid, item.st_gid, item.st_nlink, item.st_mtime_ns,
                item.st_ctime_ns,
            )
            if (
                not stat.S_ISREG(opened_deployer.st_mode)
                or stat.S_ISLNK(before_deployer.st_mode)
                or opened_deployer.st_uid != expected_uid
                or opened_deployer.st_nlink != 1
                or stat.S_IMODE(opened_deployer.st_mode) != 0o755
                or not 1 <= opened_deployer.st_size <= 16 * 1024 * 1024
                or len(source) != opened_deployer.st_size
                or identity(before_deployer) != identity(opened_deployer)
                or identity(opened_deployer) != identity(after_read)
                or identity(after_read) != identity(current_deployer)
                or hashlib.sha256(source).hexdigest()
                != expected_deployer_sha256
            ):
                raise AuthorizationError(
                    "native_deployment_deployer_untrusted")
            os.lseek(deployer_fd, 0, os.SEEK_SET)
            result = run_privileged_operation(
                [
                    "/usr/bin/python3", "-I", "-B", "-c",
                    _NATIVE_DEPLOYER_FD_BOOTSTRAP, str(deployer_fd),
                    str(deployer), "--host-install-fd", str(descriptor),
                    *arguments,
                ],
                timeout, pass_fds=(descriptor, deployer_fd),
            )
            after_child = os.fstat(deployer_fd)
            final_deployer = deployer.lstat()
            if (
                identity(opened_deployer) != identity(after_child)
                or identity(after_child) != identity(final_deployer)
            ):
                raise AuthorizationError(
                    "native_deployment_deployer_changed")
        finally:
            os.close(deployer_fd)
        _validate_selected_host_release(
            descriptor, release, install_root=install_root,
            expected_uid=expected_uid,
        )
        return result
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _invoke_native_catalog_promoter_locked(
    descriptor: int, release: Path, arguments: list[str], *,
    expected_uid: int, install_root: Path, timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    if (
        not arguments
        or arguments[0]
        not in {"gate-status", "recover-active", "status", "consume"}
    ):
        raise AuthorizationError("native_catalog_promotion_command_invalid")
    _validate_selected_host_release(
        descriptor, release, install_root=install_root,
        expected_uid=expected_uid,
    )
    verified = protected_release_directory(
        release / "authorization_broker", expected_uid)
    if verified != release:
        raise AuthorizationError("native_catalog_host_release_untrusted")
    try:
        expected_sha256 = _verified_release_manifest_payload_sha256(
            release, "native_stack_catalog_promoter",
            expected_uid=expected_uid)
        promoter = release / "native_stack_catalog_promoter"
        before = promoter.lstat()
        promoter_fd = os.open(
            promoter,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except (OSError, KeyError, TypeError, UnicodeDecodeError,
            json.JSONDecodeError, AuthorizationError) as error:
        raise AuthorizationError(
            "native_catalog_promoter_untrusted") from error
    try:
        opened = os.fstat(promoter_fd)
        reject_extended_acl(
            promoter_fd, "native_catalog_promoter_untrusted")
        source = bytearray()
        while len(source) <= 16 * 1024 * 1024:
            block = os.read(
                promoter_fd,
                min(1024 * 1024, 16 * 1024 * 1024 + 1 - len(source)))
            if not block:
                break
            source.extend(block)
        after_read = os.fstat(promoter_fd)
        current = promoter.lstat()

        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev, item.st_ino, item.st_size, item.st_mode,
                item.st_uid, item.st_gid, item.st_nlink, item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o755
            or not 1 <= opened.st_size <= 16 * 1024 * 1024
            or len(source) != opened.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after_read)
            or identity(after_read) != identity(current)
            or hashlib.sha256(source).hexdigest() != expected_sha256
        ):
            raise AuthorizationError("native_catalog_promoter_untrusted")
        os.lseek(promoter_fd, 0, os.SEEK_SET)
        result = run_privileged_operation(
            [
                "/usr/bin/python3", "-I", "-B", "-c",
                _NATIVE_DEPLOYER_FD_BOOTSTRAP, str(promoter_fd),
                str(promoter), "--host-install-fd", str(descriptor),
                *arguments,
            ],
            timeout, pass_fds=(descriptor, promoter_fd),
        )
        after_child = os.fstat(promoter_fd)
        final = promoter.lstat()
        if (
            identity(opened) != identity(after_child)
            or identity(after_child) != identity(final)
        ):
            raise AuthorizationError("native_catalog_promoter_changed")
    finally:
        os.close(promoter_fd)
    _validate_selected_host_release(
        descriptor, release, install_root=install_root,
        expected_uid=expected_uid,
    )
    return result


def _run_native_catalog_promoter_locked(
    descriptor: int, release: Path, command: str, *, expected_uid: int,
    install_root: Path, timeout: int = AUTH_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    result = _invoke_native_catalog_promoter_locked(
        descriptor, release, [command], expected_uid=expected_uid,
        install_root=install_root, timeout=timeout)
    if (
        result.returncode != 0 or result.stderr
        or not 2 <= len(result.stdout) <= 4 * 1024 * 1024
    ):
        raise AuthorizationError(
            f"native_catalog_{command.replace('-', '_')}_failed")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("native_catalog_result_invalid") from error
    if command == "gate-status":
        admitted = validate_native_catalog_promotion_gate(value)
    elif command == "recover-active":
        admitted = validate_native_catalog_recovery_terminal(value)
    else:
        admitted = validate_native_catalog_public_status(value)
    if result.stdout != native_deployment.canonical(
        admitted, maximum=4 * 1024 * 1024
    ):
        raise AuthorizationError("native_catalog_result_invalid")
    return admitted


def _open_locked_selected_host_release(
    release: Path, *, expected_uid: int, install_root: Path,
) -> int:
    try:
        before = install_root.lstat()
        descriptor = os.open(
            install_root,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise AuthorizationError("native_catalog_host_lock_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o755
        ):
            raise AuthorizationError("native_catalog_host_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_selected_host_release(
            descriptor, release, install_root=install_root,
            expected_uid=expected_uid,
        )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def native_catalog_promotion_gate_result(
    release: Path, *, expected_uid: int = 0,
    install_root: Path = HOST_INSTALL_ROOT,
) -> dict[str, Any]:
    descriptor = _open_locked_selected_host_release(
        release, expected_uid=expected_uid, install_root=install_root)
    try:
        return _run_native_catalog_promoter_locked(
            descriptor, release, "gate-status", expected_uid=expected_uid,
            install_root=install_root)
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def run_native_catalog_promotion_consume(
    release: Path, source: str, request: dict[str, Any], *, timeout: int,
    expected_uid: int = 0, install_root: Path = HOST_INSTALL_ROOT,
) -> subprocess.CompletedProcess[bytes]:
    try:
        plan, authorization = native_stack_catalog_promotion.validate_request(
            request, now=int(time.time()), require_fresh=False,
            expected_host_release_id=release.name)
    except native_stack_catalog_promotion.NativeStackCatalogPromotionError as error:
        raise AuthorizationError(
            "native_catalog_promotion_request_invalid") from error
    descriptor = _open_locked_selected_host_release(
        release, expected_uid=expected_uid, install_root=install_root)
    try:
        result = _invoke_native_catalog_promoter_locked(
            descriptor, release,
            [
                "consume", "--source", source, "--request-json",
                canonical_v2(request).decode("ascii").strip(),
            ],
            expected_uid=expected_uid, install_root=install_root,
            timeout=timeout,
        )
        if result.returncode != 0:
            return result
        if (
            result.stderr or not 2 <= len(result.stdout) <= 4 * 1024 * 1024
        ):
            raise AuthorizationError("native_catalog_promotion_result_invalid")
        try:
            receipt = validate_native_catalog_promotion_receipt(
                json.loads(result.stdout), plan=plan,
                authorization=authorization)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuthorizationError(
                "native_catalog_promotion_result_invalid") from error
        if result.stdout != native_deployment.canonical(
            receipt, maximum=4 * 1024 * 1024
        ):
            raise AuthorizationError("native_catalog_promotion_result_invalid")
        gate = _run_native_catalog_promoter_locked(
            descriptor, release, "gate-status", expected_uid=expected_uid,
            install_root=install_root)
        if gate["state"] != "ready":
            raise AuthorizationError("native_catalog_promotion_incomplete")
        public_status = _run_native_catalog_promoter_locked(
            descriptor, release, "status", expected_uid=expected_uid,
            install_root=install_root)
        if any((
            public_status["promotion_id"] != receipt["promotion_id"],
            public_status["catalog_sha256"] != receipt["catalog_sha256"],
            public_status["host_release_id"] != receipt["host_release_id"],
            public_status["promotion_receipt_sha256"]
            != receipt["receipt_sha256"],
        )):
            raise AuthorizationError("native_catalog_promotion_result_invalid")
        return result
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def native_catalog_promotion_recover_result(
    release: Path, expected_gate_sha256: str, *, expected_uid: int = 0,
    install_root: Path = HOST_INSTALL_ROOT,
) -> dict[str, Any]:
    if SHA256.fullmatch(expected_gate_sha256) is None:
        raise AuthorizationError("native_catalog_recovery_request_invalid")
    descriptor = _open_locked_selected_host_release(
        release, expected_uid=expected_uid, install_root=install_root)
    try:
        initial = _run_native_catalog_promoter_locked(
            descriptor, release, "gate-status", expected_uid=expected_uid,
            install_root=install_root)
        if initial["state"] == "active":
            if initial["gate_sha256"] != expected_gate_sha256:
                raise AuthorizationError("native_catalog_recovery_gate_changed")
        elif initial["state"] != "ready":
            raise AuthorizationError("native_catalog_recovery_gate_changed")
        terminal = _run_native_catalog_promoter_locked(
            descriptor, release, "recover-active", expected_uid=expected_uid,
            install_root=install_root,
            timeout=NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS)
        if (
            terminal["expected_gate_sha256"] != expected_gate_sha256
            or (
                initial["state"] == "active"
                and (
                    terminal["promotion_id"]
                    != initial["active_promotion_id"]
                    or terminal["host_release_id"] != release.name
                )
            )
        ):
            raise AuthorizationError("native_catalog_recovery_terminal_mismatch")
        final_gate = _run_native_catalog_promoter_locked(
            descriptor, release, "gate-status", expected_uid=expected_uid,
            install_root=install_root)
        if final_gate["state"] != "ready":
            raise AuthorizationError("native_catalog_recovery_incomplete")
        public_status = _run_native_catalog_promoter_locked(
            descriptor, release, "status", expected_uid=expected_uid,
            install_root=install_root)
        if any((
            public_status["promotion_id"] != terminal["promotion_id"],
            public_status["catalog_sha256"] != terminal["catalog_sha256"],
            public_status["host_release_id"] != terminal["host_release_id"],
            public_status["promotion_receipt_sha256"]
            != terminal["promotion_receipt_sha256"],
        )):
            raise AuthorizationError("native_catalog_recovery_terminal_mismatch")
        return terminal
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def native_deployment_driver_result(
    release: Path, command: str, *, expected_uid: int = 0,
) -> dict[str, Any]:
    if command not in {"plan", "status", "recovery-plan"}:
        raise AuthorizationError("native_deployment_query_invalid")
    result = run_native_deployment_driver(
        release, [command], timeout=AUTH_TIMEOUT_SECONDS,
        expected_uid=expected_uid,
    )
    if (
        result.returncode != 0 or result.stderr
        or not 2 <= len(result.stdout) <= 4 * 1024 * 1024
    ):
        raise AuthorizationError(f"native_deployment_{command.replace('-', '_')}_failed")
    try:
        value = json.loads(result.stdout)
        if command == "plan":
            admitted = validate_native_deployment_plan_response(
                value, now=int(time.time()), require_fresh=True,
                expected_host_release_id=release.name,
            )
        elif command == "status":
            admitted = validate_native_deployment_status(
                value, expected_host_release_id=release.name,
            )
        else:
            admitted = validate_native_deployment_recovery_plan(
                value, expected_host_release_id=release.name,
            )
    except (UnicodeDecodeError, json.JSONDecodeError,
            native_deployment.NativeDeploymentError) as error:
        raise AuthorizationError("native_deployment_query_result_invalid") from error
    if result.stdout != native_deployment.canonical(admitted, maximum=4 * 1024 * 1024):
        raise AuthorizationError("native_deployment_query_result_invalid")
    return admitted


def native_deployment_query(
    message: dict[str, Any], release: Path, command: str,
    *, expected_uid: int = 0,
) -> dict[str, Any]:
    schema = NATIVE_DEPLOYMENT_QUERY_SCHEMAS.get(command)
    reply_schema = NATIVE_DEPLOYMENT_REPLY_SCHEMAS.get(command)
    if schema is None or reply_schema is None:
        raise AuthorizationError("native_deployment_query_invalid")
    expected = {"schema", "query_id", "request_sha256"}
    body = {"query_id": message.get("query_id"), "command": command}
    if (
        set(message) != expected or message.get("schema") != schema
        or UUID4.fullmatch(str(body["query_id"])) is None
        or message.get("request_sha256")
        != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_deployment_query_invalid")
    try:
        result = native_deployment_driver_result(
            release, command, expected_uid=expected_uid)
    except Exception as error:
        if command != "status":
            raise
        status_body = {
            "state": "recovery-required",
            "phase": "state-invalid",
            "deployment_id": None,
            "host_release_id": None,
            "active_journal_sha256": None,
            "error_sha256": hashlib.sha256(
                str(error).encode("utf-8", "replace")).hexdigest(),
        }
        result = {
            "schema": NATIVE_DEPLOYMENT_STATUS_SCHEMA,
            **status_body,
            "status_sha256": native_deployment.digest(status_body),
        }
    reply_body = {
        "query_id": body["query_id"],
        "command": command,
        "request_sha256": message["request_sha256"],
        "host_release_id": release.name,
        "result": result,
    }
    return {
        "schema": reply_schema,
        **reply_body,
        "reply_sha256": native_deployment.digest(reply_body),
    }


def native_catalog_promotion_gate_query(
    message: dict[str, Any], release: Path, *, expected_uid: int = 0,
) -> dict[str, Any]:
    fields = {"schema", "query_id", "request_sha256"}
    body = {
        "query_id": message.get("query_id"),
        "command": NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
    }
    if (
        set(message) != fields
        or message.get("schema")
        != NATIVE_CATALOG_PROMOTION_GATE_REQUEST_SCHEMA
        or UUID4.fullmatch(str(body["query_id"])) is None
        or message.get("request_sha256")
        != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_catalog_promotion_gate_query_invalid")
    gate = native_catalog_promotion_gate_result(
        release, expected_uid=expected_uid)
    reply_body = {
        "query_id": body["query_id"],
        "command": NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
        "request_sha256": message["request_sha256"],
        "host_release_id": release.name,
        "gate": gate,
    }
    return {
        "schema": NATIVE_CATALOG_PROMOTION_GATE_REPLY_SCHEMA,
        **reply_body,
        "reply_sha256": native_deployment.digest(reply_body),
    }


def native_catalog_promotion_recovery_query(
    message: dict[str, Any], release: Path, *, expected_uid: int = 0,
) -> dict[str, Any]:
    fields = {
        "schema", "recovery_id", "expected_gate_sha256",
        "request_sha256",
    }
    body = {
        "recovery_id": message.get("recovery_id"),
        "command": NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
        "expected_gate_sha256": message.get("expected_gate_sha256"),
    }
    if (
        set(message) != fields
        or message.get("schema")
        != NATIVE_CATALOG_PROMOTION_RECOVERY_REQUEST_SCHEMA
        or UUID4.fullmatch(str(body["recovery_id"])) is None
        or SHA256.fullmatch(str(body["expected_gate_sha256"])) is None
        or message.get("request_sha256")
        != native_deployment.digest(body)
    ):
        raise AuthorizationError("native_catalog_recovery_request_invalid")
    terminal = native_catalog_promotion_recover_result(
        release, body["expected_gate_sha256"], expected_uid=expected_uid)
    terminal = validate_native_catalog_recovery_terminal(terminal)
    if terminal["expected_gate_sha256"] != body["expected_gate_sha256"]:
        raise AuthorizationError("native_catalog_recovery_terminal_mismatch")
    reply_body = {
        "recovery_id": body["recovery_id"],
        "command": NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
        "request_sha256": message["request_sha256"],
        "host_release_id": release.name,
        "terminal": terminal,
    }
    return {
        "schema": NATIVE_CATALOG_PROMOTION_RECOVERY_REPLY_SCHEMA,
        **reply_body,
        "reply_sha256": native_deployment.digest(reply_body),
    }


def native_deployment_recovery_required(
    release: Path, *, expected_uid: int = 0,
) -> bool:
    try:
        status = native_deployment_driver_result(
            release, "status", expected_uid=expected_uid)
    except Exception:
        # An unreadable or invalid durable gate is never equivalent to ready.
        return True
    return status["state"] != "ready"


def native_catalog_promotion_recovery_required(
    release: Path, *, expected_uid: int = 0,
) -> bool:
    try:
        gate = native_catalog_promotion_gate_result(
            release, expected_uid=expected_uid)
    except Exception:
        # Missing, malformed, or unreadable durable promotion state can never
        # be interpreted as ready for another native mutation.
        return True
    return gate["state"] != "ready"


def host_pair_generation(value: object) -> dict[str, Any]:
    fields = {
        "candidate_authority_sha256", "launcher_sha256", "release_id",
        "release_tree_identity_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or any(
                not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None
                for name in fields
            )):
        raise AuthorizationError("host_pair_identity_invalid")
    return {name: value[name] for name in sorted(fields)}


def host_pair_identity(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or "launcher_identity" not in value:
        raise AuthorizationError("host_pair_identity_invalid")
    generation = host_pair_generation({
        name: item for name, item in value.items()
        if name != "launcher_identity"
    })
    identity = value.get("launcher_identity")
    fields = {
        "ctime_ns", "dev", "gid", "ino", "kind", "mode", "mtime_ns",
        "nlink", "sha256", "size", "uid",
    }
    if (not isinstance(identity, dict) or set(identity) != fields
            or identity.get("kind") != "file"
            or any(
                not isinstance(identity.get(name), int)
                or isinstance(identity[name], bool) or identity[name] < 0
                for name in fields - {"kind", "sha256"}
            )
            or not isinstance(identity.get("sha256"), str)
            or SHA256.fullmatch(identity["sha256"]) is None
            or identity["sha256"] != generation["launcher_sha256"]):
        raise AuthorizationError("host_pair_identity_invalid")
    return {**generation, "launcher_identity": {
        name: identity[name] for name in sorted(fields)
    }}


def host_pair_transition_digest(value: dict[str, Any]) -> str:
    body = {
        name: item for name, item in value.items()
        if name not in {"finalization", "terminal", "transition_sha256"}
    }
    return hashlib.sha256(canonical(body)).hexdigest()


def validate_host_pair_bootstrap_admission(value: object) -> dict[str, Any]:
    fields = {
        "schema", "establishment_mode", "established_from_release_id",
        "established_from_predecessor_release_id", "candidate_record_sha256",
        "native_host_candidate_floor_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != HOST_PAIR_BOOTSTRAP_ADMISSION_SCHEMA
            or value.get("establishment_mode") not in HOST_PAIR_BOOTSTRAP_MODES
            or any(
                not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None
                for name in (
                    "established_from_release_id",
                    "established_from_predecessor_release_id",
                    "candidate_record_sha256",
                    "native_host_candidate_floor_sha256",
                )
            )):
        raise AuthorizationError("host_pair_bootstrap_admission_invalid")
    return {name: value[name] for name in sorted(fields)}


def host_pair_terminal_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({
        name: item for name, item in value.items()
        if name != "terminal_sha256"
    })).hexdigest()


def host_pair_finalization_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({
        name: item for name, item in value.items()
        if name != "finalization_sha256"
    })).hexdigest()


def validate_host_pair_service_evidence(
    value: object, transition: dict[str, Any], committed_pair: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "committed_pair_sha256", "current_target", "operation",
        "previous_target", "schema", "services", "transition_sha256",
    }
    committed = host_pair_identity(committed_pair)
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != HOST_PAIR_SERVICE_EVIDENCE_SCHEMA
            or value.get("operation") != transition.get("operation")
            or value.get("transition_sha256")
                != transition.get("transition_sha256")
            or value.get("committed_pair_sha256") != hashlib.sha256(
                canonical(committed)
            ).hexdigest()
            or value.get("current_target")
                != f"releases/{committed['release_id']}"
            or (value.get("previous_target") is not None and re.fullmatch(
                r"releases/[0-9a-f]{64}",
                str(value["previous_target"]),
            ) is None)
            or not isinstance(value.get("services"), dict)):
        raise AuthorizationError("host_pair_service_evidence_invalid")
    return {name: value[name] for name in sorted(fields)}


def validate_host_pair_finalization(
    value: object, transition: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "status", "committed_pair", "completed_at",
        "service_evidence", "service_evidence_sha256", "error",
        "finalization_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != HOST_PAIR_FINALIZATION_SCHEMA
            or value.get("status") not in {
                "target_committed", "source_restored",
            }
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value["completed_at"], bool)
            or value["completed_at"] < transition["created_at"]
            or not isinstance(value.get("service_evidence_sha256"), str)
            or SHA256.fullmatch(value["service_evidence_sha256"]) is None
            or (value.get("error") is not None and (
                not isinstance(value["error"], str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value["error"])
                    is None
            ))
            or host_pair_finalization_digest(value)
                != value.get("finalization_sha256")):
        raise AuthorizationError("host_pair_finalization_invalid")
    committed = host_pair_identity(value.get("committed_pair"))
    evidence = validate_host_pair_service_evidence(
        value.get("service_evidence"), transition, committed,
    )
    expected = (
        transition["target_pair"]
        if value["status"] == "target_committed"
        else transition["source_pair"]
    )
    expected_generation = None if expected is None else {
        name: expected[name] for name in (
            "candidate_authority_sha256", "launcher_sha256", "release_id",
            "release_tree_identity_sha256",
        )
    }
    if (expected_generation is None
            or {name: committed[name] for name in expected_generation}
                != expected_generation
            or (value["status"] == "target_committed"
                and value["error"] is not None)
            or (value["status"] == "source_restored"
                and value["error"] is None)
            or hashlib.sha256(canonical(evidence)).hexdigest()
                != value["service_evidence_sha256"]):
        raise AuthorizationError("host_pair_finalization_invalid")
    result = {name: value[name] for name in sorted(fields)}
    result["committed_pair"] = committed
    result["service_evidence"] = evidence
    return result


def validate_host_pair_terminal(
    value: object, transition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != HOST_PAIR_TERMINAL_FIELDS
            or value.get("schema") != HOST_PAIR_TERMINAL_SCHEMA
            or value.get("status") not in {
                "target_committed", "source_restored",
            }
            or value.get("operation") not in {"install", "rollback"}
            or not isinstance(value.get("transition_id"), str)
            or not isinstance(value.get("transition_sha256"), str)
            or SHA256.fullmatch(value["transition_sha256"]) is None
            or not isinstance(value.get("authorized_target_plan_sha256"), str)
            or SHA256.fullmatch(value["authorized_target_plan_sha256"])
                is None
            or not isinstance(value.get("service_evidence_sha256"), str)
            or SHA256.fullmatch(value["service_evidence_sha256"]) is None
            or not isinstance(value.get("finalization_sha256"), str)
            or SHA256.fullmatch(value["finalization_sha256"]) is None
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value["completed_at"], bool)
            or (value.get("error") is not None and (
                not isinstance(value["error"], str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value["error"])
                    is None
            ))
            or (value.get("authorization_receipt_sha256") is not None and (
                not isinstance(value["authorization_receipt_sha256"], str)
                or SHA256.fullmatch(value["authorization_receipt_sha256"])
                    is None
            ))
            or host_pair_terminal_digest(value)
                != value.get("terminal_sha256")):
        raise AuthorizationError("host_pair_terminal_invalid")
    valid_uuid4(value["transition_id"], "transition_id")
    committed = host_pair_identity(value.get("committed_pair"))
    evidence = validate_host_pair_service_evidence(
        value.get("service_evidence"), value, committed,
    )
    if hashlib.sha256(canonical(evidence)).hexdigest() != value[
        "service_evidence_sha256"
    ]:
        raise AuthorizationError("host_pair_terminal_invalid")
    if transition is not None:
        expected = (
            transition["target_pair"]
            if value["status"] == "target_committed"
            else transition["source_pair"]
        )
        if (value["operation"] != transition["operation"]
                or value["transition_id"] != transition["transition_id"]
                or value["transition_sha256"]
                    != transition["transition_sha256"]
                or value.get("authorization_request_id")
                    != transition["authorization_request_id"]
                or value.get("authorization_request_sha256")
                    != transition["authorization_request_sha256"]
                or value["authorized_target_plan_sha256"]
                    != transition["authorized_target_plan_sha256"]
                or transition.get("finalization") is None
                or value["finalization_sha256"]
                    != transition["finalization"]["finalization_sha256"]
                or value["completed_at"] < transition["created_at"]
                or expected is None
                or {name: committed[name] for name in (
                    "candidate_authority_sha256", "launcher_sha256",
                    "release_id", "release_tree_identity_sha256",
                )} != {name: expected[name] for name in (
                    "candidate_authority_sha256", "launcher_sha256",
                    "release_id", "release_tree_identity_sha256",
                )}
                or (value["status"] == "target_committed"
                    and value["error"] is not None)
                or (value["status"] == "source_restored"
                    and value["error"] is None)
                or (transition["bootstrap"]
                    and value["authorization_receipt_sha256"] is not None)
                or (not transition["bootstrap"]
                    and (
                        not isinstance(
                            value["authorization_receipt_sha256"], str,
                        )
                        or SHA256.fullmatch(
                            value["authorization_receipt_sha256"]
                        ) is None
                    ))):
            raise AuthorizationError("host_pair_terminal_invalid")
    result = {name: value[name] for name in sorted(HOST_PAIR_TERMINAL_FIELDS)}
    result["committed_pair"] = committed
    result["service_evidence"] = evidence
    return result


def validate_host_pair_transition(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != HOST_PAIR_TRANSITION_FIELDS
            or value.get("schema") != HOST_PAIR_TRANSITION_SCHEMA
            or value.get("operation") not in {"install", "rollback"}
            or not isinstance(value.get("bootstrap"), bool)
            or not isinstance(value.get("created_at"), int)
            or isinstance(value["created_at"], bool)
            or not isinstance(value.get("expires_at"), int)
            or isinstance(value["expires_at"], bool)
            or value["created_at"] < 0
            or value["expires_at"] - value["created_at"]
                != HOST_INSTALL_TRANSITION_TTL_SECONDS
            or not isinstance(value.get("native_uid"), int)
            or isinstance(value["native_uid"], bool)
            or value["native_uid"] < -1
            or not isinstance(value.get("old_services"), dict)
            or (value.get("finalization") is not None
                and not isinstance(value["finalization"], dict))
            or (value.get("terminal") is not None
                and not isinstance(value["terminal"], dict))):
        raise AuthorizationError("host_pair_transition_invalid")
    valid_uuid4(value.get("transition_id"), "transition_id")
    target = host_pair_generation(value.get("target_pair"))
    if value["bootstrap"]:
        bootstrap_admission = validate_host_pair_bootstrap_admission(
            value.get("bootstrap_admission")
        )
        if (value["operation"] != "install"
                or value.get("source_pair") is not None
                or value.get("source_stable_sha256") is not None
                or bootstrap_admission["established_from_release_id"]
                    != target["release_id"]
                or any(value.get(name) is not None for name in (
                    "authorization_request_id",
                    "authorization_request_sha256",
                    "authorization_pending_receipt_sha256",
                ))):
            raise AuthorizationError("host_pair_transition_invalid")
        source = None
    else:
        if value.get("bootstrap_admission") is not None:
            raise AuthorizationError("host_pair_transition_invalid")
        bootstrap_admission = None
        source = host_pair_identity(value.get("source_pair"))
        if (not isinstance(value.get("source_stable_sha256"), str)
                or SHA256.fullmatch(value["source_stable_sha256"]) is None
                or not isinstance(value.get("authorization_request_id"), str)):
            raise AuthorizationError("host_pair_transition_invalid")
        valid_uuid4(value["authorization_request_id"], "request_id")
        for name in (
            "authorization_request_sha256",
            "authorization_pending_receipt_sha256",
        ):
            if (not isinstance(value.get(name), str)
                    or SHA256.fullmatch(value[name]) is None):
                raise AuthorizationError("host_pair_transition_invalid")
    for name in (
        "transition_sha256", "authorized_target_plan_sha256",
        "target_candidate_authority_sha256",
        "target_launcher_generation_sha256", "old_services_sha256",
        "developer_id_team_floor_sha256",
    ):
        if (not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None):
            raise AuthorizationError("host_pair_transition_invalid")
    source_launcher = value.get("source_launcher_generation_sha256")
    if ((value["bootstrap"] and source_launcher is not None)
            or (not value["bootstrap"] and (
                not isinstance(source_launcher, str)
                or SHA256.fullmatch(source_launcher) is None
            ))
            or value["target_candidate_authority_sha256"]
                != target["candidate_authority_sha256"]
            or value["target_launcher_generation_sha256"]
                != target["launcher_sha256"]
            or (source is not None
                and source_launcher != source["launcher_sha256"])
            or value.get("old_current_target") != (
                None if source is None
                else f"releases/{source['release_id']}"
            )
            or (value.get("old_previous_target") is not None
                and re.fullmatch(
                    r"releases/[0-9a-f]{64}",
                    str(value["old_previous_target"]),
                ) is None)
            or hashlib.sha256(canonical(value["old_services"])).hexdigest()
                != value["old_services_sha256"]
            or not isinstance(value.get("developer_id_team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["developer_id_team_id"])
                is None
            or host_pair_transition_digest(value)
                != value["transition_sha256"]):
        raise AuthorizationError("host_pair_transition_invalid")
    result = {name: value[name] for name in sorted(HOST_PAIR_TRANSITION_FIELDS)}
    result["bootstrap_admission"] = bootstrap_admission
    result["source_pair"] = source
    result["target_pair"] = target
    if value["finalization"] is not None:
        result["finalization"] = validate_host_pair_finalization(
            value["finalization"], result,
        )
    if value["terminal"] is not None and value["finalization"] is None:
        raise AuthorizationError("host_pair_transition_invalid")
    if value["terminal"] is not None:
        result["terminal"] = validate_host_pair_terminal(
            value["terminal"], result,
        )
    return result


def validate_public_host_pair_record(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationError("host_pair_public_invalid")
    if value.get("schema") == HOST_PAIR_PENDING_SCHEMA:
        fields = {
            "operation", "prior_stable_sha256", "required_feature", "schema",
            "source_pair", "target_pair", "transition_id",
            "transition_sha256",
        }
        if (set(value) != fields
                or value.get("required_feature") != HOST_PAIR_REQUIRED_FEATURE
                or value.get("operation") not in {"install", "rollback"}
                or not isinstance(value.get("transition_id"), str)
                or not isinstance(value.get("transition_sha256"), str)
                or SHA256.fullmatch(value["transition_sha256"]) is None):
            raise AuthorizationError("host_pair_public_invalid")
        valid_uuid4(value["transition_id"], "transition_id")
        target = host_pair_generation(value.get("target_pair"))
        if value.get("source_pair") is None:
            source = None
            if (value.get("prior_stable_sha256") is not None
                    or value["operation"] != "install"):
                raise AuthorizationError("host_pair_public_invalid")
        else:
            source = host_pair_identity(value["source_pair"])
            if (not isinstance(value.get("prior_stable_sha256"), str)
                    or SHA256.fullmatch(value["prior_stable_sha256"]) is None):
                raise AuthorizationError("host_pair_public_invalid")
        result = {name: value[name] for name in sorted(fields)}
        result["source_pair"] = source
        result["target_pair"] = target
        return result
    if value.get("schema") == HOST_PAIR_STABLE_SCHEMA:
        fields = {
            "committed_terminal_sha256", "committed_transition_id",
            "committed_transition_sha256", "pair", "required_feature",
            "schema",
        }
        if (set(value) != fields
                or value.get("required_feature") != HOST_PAIR_REQUIRED_FEATURE):
            raise AuthorizationError("host_pair_public_invalid")
        trio = (
            value.get("committed_transition_id"),
            value.get("committed_transition_sha256"),
            value.get("committed_terminal_sha256"),
        )
        if any(item is None for item in trio) != all(
            item is None for item in trio
        ):
            raise AuthorizationError("host_pair_public_invalid")
        if trio[0] is not None:
            valid_uuid4(trio[0], "transition_id")
            if any(
                not isinstance(item, str) or SHA256.fullmatch(item) is None
                for item in trio[1:]
            ):
                raise AuthorizationError("host_pair_public_invalid")
        result = {name: value[name] for name in sorted(fields)}
        result["pair"] = host_pair_identity(value.get("pair"))
        return result
    raise AuthorizationError("host_pair_public_invalid")


def public_host_pair_record(
    *, expected_uid: int = 0, path: Path = HOST_PAIR_PUBLIC,
) -> tuple[dict[str, Any], str] | None:
    try:
        raw = read_acl_free_regular(
            path, expected_uid, 0o444, "host_pair_public_untrusted",
            maximum=64 * 1024, expected_nlink=1,
        )
    except AuthorizationError as error:
        if not os.path.lexists(path):
            return None
        raise error
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("host_pair_public_untrusted") from error
    validated = validate_public_host_pair_record(value)
    if canonical(validated) != raw:
        raise AuthorizationError("host_pair_public_untrusted")
    return validated, hashlib.sha256(raw).hexdigest()


def manager_completed_host_pair_receipt(
    receipt_path: Path, pending: dict[str, Any], *, expected_uid: int,
    install_root: Path = HOST_INSTALL_ROOT,
) -> dict[str, Any] | None:
    raw = read_acl_free_regular(
        receipt_path, expected_uid, 0o600,
        "host_pair_transition_receipt_untrusted", maximum=64 * 1024,
        expected_nlink=1,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError(
            "host_pair_transition_receipt_untrusted"
        ) from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise AuthorizationError("host_pair_transition_receipt_untrusted")
    if value == pending:
        return None
    extra = {
        "host_pair_committed_pair_sha256",
        "host_pair_finalization_sha256",
        "host_pair_service_evidence_sha256",
        "host_pair_transition_id", "host_pair_transition_sha256",
    }
    immutable = set(pending) - {
        "status", "completed_at", "exit_status", "stdout_sha256",
        "stderr_sha256",
    }
    if (set(value) != set(pending) | extra
            or any(value.get(name) != pending[name] for name in immutable)
            or value.get("status") not in {"succeeded", "failed"}
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value["completed_at"], bool)
            or value["completed_at"] < pending["started_at"]
            or value.get("exit_status") != (
                0 if value["status"] == "succeeded" else 1
            )
            or (value.get("stdout_sha256") is not None and (
                not isinstance(value["stdout_sha256"], str)
                or SHA256.fullmatch(value["stdout_sha256"]) is None
            ))
            or not isinstance(value.get("stderr_sha256"), str)
            or SHA256.fullmatch(value["stderr_sha256"]) is None
            or any(
                not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None
                for name in extra - {"host_pair_transition_id"}
            )
            or not isinstance(value.get("host_pair_transition_id"), str)):
        raise AuthorizationError("host_pair_transition_receipt_untrusted")
    valid_uuid4(value["host_pair_transition_id"], "transition_id")
    observed = public_host_pair_record(
        expected_uid=expected_uid,
        path=install_root / "host-release-launcher-pair.json",
    )
    if observed is None or observed[0]["schema"] != HOST_PAIR_STABLE_SCHEMA:
        raise AuthorizationError("host_pair_transition_receipt_untrusted")
    stable = observed[0]
    if (stable["committed_transition_id"]
            != value["host_pair_transition_id"]
            or stable["committed_transition_sha256"]
                != value["host_pair_transition_sha256"]):
        raise AuthorizationError("host_pair_transition_receipt_untrusted")
    terminal_path = (
        install_root / "install-transitions"
        / f"{value['host_pair_transition_id']}.json"
    )
    terminal_raw = read_acl_free_regular(
        terminal_path, expected_uid, 0o444,
        "host_pair_terminal_untrusted", maximum=64 * 1024,
        expected_nlink=1,
    )
    try:
        terminal_value = json.loads(terminal_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("host_pair_terminal_untrusted") from error
    terminal = validate_host_pair_terminal(terminal_value)
    committed_sha256 = hashlib.sha256(
        canonical(terminal["committed_pair"])
    ).hexdigest()
    if (canonical(terminal) != terminal_raw
            or hashlib.sha256(terminal_raw).hexdigest()
                != stable["committed_terminal_sha256"]
            or terminal["transition_id"] != value["host_pair_transition_id"]
            or terminal["transition_sha256"]
                != value["host_pair_transition_sha256"]
            or terminal["authorization_request_id"] != pending["request_id"]
            or terminal["authorization_request_sha256"]
                != pending["request_sha256"]
            or terminal["authorized_target_plan_sha256"]
                != pending["host_pair_authorized_target_plan_sha256"]
            or terminal["authorization_receipt_sha256"]
                != hashlib.sha256(raw).hexdigest()
            or terminal["finalization_sha256"]
                != value["host_pair_finalization_sha256"]
            or terminal["service_evidence_sha256"]
                != value["host_pair_service_evidence_sha256"]
            or committed_sha256
                != value["host_pair_committed_pair_sha256"]
            or stable["pair"] != terminal["committed_pair"]
            or (terminal["status"] == "target_committed")
                != (value["status"] == "succeeded")):
        raise AuthorizationError("host_pair_transition_receipt_untrusted")
    return value


def match_public_pending_host_pair(
    transition: dict[str, Any], *, expected_uid: int = 0,
    path: Path = HOST_PAIR_PUBLIC,
) -> dict[str, Any]:
    observed = public_host_pair_record(expected_uid=expected_uid, path=path)
    if observed is None or observed[0]["schema"] != HOST_PAIR_PENDING_SCHEMA:
        raise AuthorizationError("host_pair_public_pending_missing")
    pending = observed[0]
    if (pending["operation"] != transition["operation"]
            or pending["transition_id"] != transition["transition_id"]
            or pending["transition_sha256"]
                != transition["transition_sha256"]
            or pending["prior_stable_sha256"]
                != transition["source_stable_sha256"]
            or pending["source_pair"] != transition["source_pair"]
            or pending["target_pair"] != transition["target_pair"]):
        raise AuthorizationError("host_pair_public_pending_conflict")
    return observed[0]


def match_public_host_pair_transition_state(
    transition: dict[str, Any], *, expected_uid: int = 0,
    path: Path = HOST_PAIR_PUBLIC,
) -> str:
    observed = public_host_pair_record(expected_uid=expected_uid, path=path)
    if observed is None:
        if transition["bootstrap"] and transition["terminal"] is None:
            return "prepared"
        raise AuthorizationError("host_pair_public_pending_conflict")
    public, public_sha256 = observed
    if public["schema"] == HOST_PAIR_PENDING_SCHEMA:
        match_public_pending_host_pair(
            transition, expected_uid=expected_uid, path=path,
        )
        return "public_pending"
    terminal = transition["terminal"]
    if (terminal is None
            and transition["source_pair"] is not None
            and public_sha256 == transition["source_stable_sha256"]
            and public["pair"] == transition["source_pair"]):
        return "prepared"
    if (terminal is not None
            and public["committed_transition_id"]
                == transition["transition_id"]
            and public["committed_transition_sha256"]
                == transition["transition_sha256"]
            and public["committed_terminal_sha256"] == hashlib.sha256(
                canonical(terminal)
            ).hexdigest()
            and public["pair"] == terminal["committed_pair"]):
        return "stable_published"
    raise AuthorizationError("host_pair_public_pending_conflict")


def recoverable_host_install_activation(
    request_id: str,
    request_sha256: str,
    executing_receipt: dict[str, Any],
    *,
    expected_uid: int,
    path: Path = HOST_INSTALL_PENDING,
    pair_path: Path | None = None,
) -> dict[str, Any] | None:
    try:
        path_info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(path_info.st_mode) or stat.S_ISLNK(path_info.st_mode)
            or path_info.st_uid != expected_uid or path_info.st_nlink != 1
            or stat.S_IMODE(path_info.st_mode) != 0o600
            or path_info.st_size <= 0 or path_info.st_size > 64 * 1024):
        raise AuthorizationError("host_install_transition_untrusted")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, "host_install_transition_untrusted")
        if ((opened.st_dev, opened.st_ino)
                != (path_info.st_dev, path_info.st_ino)):
            raise AuthorizationError("host_install_transition_changed")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, 64 * 1024 + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 64 * 1024:
                raise AuthorizationError("host_install_transition_untrusted")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    reread = path.lstat()
    if ((reread.st_dev, reread.st_ino, reread.st_size, reread.st_mtime_ns)
            != (path_info.st_dev, path_info.st_ino, path_info.st_size,
                path_info.st_mtime_ns)):
        raise AuthorizationError("host_install_transition_changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("host_install_transition_untrusted") from error
    if (isinstance(value, dict)
            and value.get("schema") == HOST_PAIR_TRANSITION_SCHEMA):
        if canonical(value) != raw:
            raise AuthorizationError("host_pair_transition_untrusted")
        transition = validate_host_pair_transition(value)
        match_public_pending_host_pair(
            transition, expected_uid=expected_uid,
            path=(path.parent / "host-release-launcher-pair.json"
                  if pair_path is None else pair_path),
        )
        receipt_plan = executing_receipt.get(
            "host_pair_authorized_target_plan_sha256"
        )
        expected_operation = (
            "host-controller-install"
            if transition["operation"] == "install"
            else "host-controller-rollback"
        )
        if (transition["bootstrap"]
                or transition["authorization_request_id"] != request_id
                or transition["authorization_request_sha256"]
                    != request_sha256
                or transition["authorization_pending_receipt_sha256"]
                    != hashlib.sha256(canonical(executing_receipt)).hexdigest()
                or transition["authorized_target_plan_sha256"]
                    != receipt_plan
                or executing_receipt.get("operation") != expected_operation
                or transition["terminal"] is not None):
            raise AuthorizationError("host_pair_transition_untrusted")
        return {
            "schema": "secure-sandbox-host-controller-release-v1",
            "status": "host_pair_transition_pending",
            "operation": transition["operation"],
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "authorization_request_id": request_id,
            "authorized_target_plan_sha256": transition[
                "authorized_target_plan_sha256"
            ],
            "target_release_id": transition["target_pair"]["release_id"],
            "expires_at": transition["expires_at"],
            "recovered_after_child_failure": True,
        }
    if os.path.lexists(
        path.parent / "host-release-launcher-pair.json"
        if pair_path is None else pair_path
    ):
        raise AuthorizationError("host_pair_transition_legacy_active")
    if (not isinstance(value, dict)
            or set(value) != HOST_INSTALL_TRANSITION_FIELDS
            or canonical(value) != raw
            or value.get("schema")
                != "secure-sandbox-host-install-transition-v1"):
        raise AuthorizationError("host_install_transition_untrusted")
    valid_uuid4(value.get("transition_id"), "transition_id")
    valid_uuid4(value.get("authorization_request_id"), "request_id")
    created = value.get("created_at")
    expires = value.get("expires_at")
    immutable = {
        name: item for name, item in value.items()
        if name not in {"terminal", "transition_sha256"}
    }
    old_services = value.get("old_services")
    fallback = value.get("fallback_release_id")
    if (value.get("authorization_request_id") != request_id
            or value.get("authorization_request_sha256") != request_sha256
            or value.get("authorization_pending_receipt_sha256")
                != hashlib.sha256(canonical(executing_receipt)).hexdigest()
            or value.get("terminal") is not None
            or not isinstance(created, int) or isinstance(created, bool)
            or not isinstance(expires, int) or isinstance(expires, bool)
            or expires - created != HOST_INSTALL_TRANSITION_TTL_SECONDS
            or not isinstance(old_services, dict)
            or hashlib.sha256(canonical(old_services)).hexdigest()
                != value.get("old_services_sha256")
            or not isinstance(fallback, str) or SHA256.fullmatch(fallback) is None
            or value.get("old_current_target") != f"releases/{fallback}"
            or any(
                not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None
                for name in (
                    "transition_sha256", "candidate_release_id",
                    "candidate_manifest_sha256",
                    "candidate_authorization_manifest_sha256",
                    "developer_id_team_floor_sha256",
                )
            )
            or hashlib.sha256(canonical(immutable)).hexdigest()
                != value["transition_sha256"]):
        raise AuthorizationError("host_install_transition_untrusted")
    return {
        "schema": "secure-sandbox-host-controller-release-v1",
        "status": "activation_pending",
        "transition_id": value["transition_id"],
        "transition_sha256": value["transition_sha256"],
        "authorization_request_id": request_id,
        "candidate_release_id": value["candidate_release_id"],
        "expires_at": value["expires_at"],
        "recovered_after_child_failure": True,
    }


def execute_request(uid: int, request_id: str, expected_digest: str,
                    receipt_root: Path = DEFAULT_RECEIPT_ROOT, now: int | None = None,
                    program_attestation_root: Path = NATIVE_PROGRAM_ATTESTATION_ROOT,
                    broker_path: Path | None = None, expected_root_uid: int = 0,
                    authorization_method: str = "administrator-password",
                    emit_output: bool = True,
                    result_capture: list[subprocess.CompletedProcess[bytes]] | None = None,
                    result_override: subprocess.CompletedProcess[bytes] | None = None,
                    request_binding: RequestBinding | None = None) -> int:
    if os.geteuid() != expected_root_uid:
        raise AuthorizationError("root_required")
    if authorization_method not in {"administrator-password", "touch-id"}:
        raise AuthorizationError("authorization_method_invalid")
    if uid <= 0 or not SHA256.fullmatch(expected_digest):
        raise AuthorizationError("execution_identity_invalid")
    valid_uuid4(request_id)
    home = Path(pwd.getpwuid(uid).pw_dir)
    path = request_directory(home) / f"{request_id}.json"
    # This is the commit-boundary read, not a reuse of the UI challenge's
    # earlier copy. Touch ID holds the exact directory and file objects from
    # begin through final, so unlink/replacement, directory substitution, or a
    # new hardlink cannot turn a cancelled challenge back into authority.
    if request_binding is None:
        value = read_request(path, uid, expected_digest)
    else:
        if (
            request_binding.path != path
            or request_binding.expected_uid != uid
            or request_binding.expected_digest != expected_digest
        ):
            raise AuthorizationError("request_binding_identity_mismatch")
        value = read_bound_request(request_binding)
    verify_request(value, uid, request_id, int(time.time()) if now is None else now)
    if value["ceremony"] != "approve":
        raise AuthorizationError("ceremony_execution_forbidden")
    if (operation_requires_touchid(value["operation"])
            and authorization_method != "touch-id"):
        raise AuthorizationError("touchid_required")
    release = protected_release_directory(Path(__file__) if broker_path is None else broker_path,
                                          expected_root_uid)
    if (
        value["operation"] == native_stack_catalog_promotion.OPERATION
        and value["parameters"]["plan"]["host_release_id"] != release.name
    ):
        raise AuthorizationError("native_catalog_promotion_release_mismatch")
    if value["operation"] in native_deployment.OPERATIONS:
        deployment_plan_response = (
            value["parameters"]["plan"]
            if value["operation"] == native_deployment.APPLY_OPERATION
            else value["parameters"]["recovery"]["plan_response"]
        )
        validate_native_deployment_plan_response(
            deployment_plan_response,
            require_fresh=(
                value["operation"] == native_deployment.APPLY_OPERATION
            ),
            expected_host_release_id=release.name,
        )
    receipt_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_info = receipt_root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != expected_root_uid):
        raise AuthorizationError("receipt_directory_untrusted")
    os.chmod(receipt_root, 0o700)
    receipt_path = receipt_root / f"{request_id}.json"
    try:
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as error:
        raise AuthorizationError("request_already_consumed") from error
    started = int(time.time()) if now is None else now
    pending = {
        "schema": RECEIPT_SCHEMA, "request_id": request_id, "request_sha256": expected_digest,
        "status": "executing", "started_at": started, "completed_at": None,
        "operation": value["operation"], "declared_agent": value["declared_agent"],
        "declared_session": value["declared_session"], "identity_evidence": "operator-declared",
        "authorization_method": authorization_method,
        "ceremony": value["ceremony"],
        "purpose": value["purpose"], "resource": value["resource"], "exit_status": None,
        "stdout_sha256": None, "stderr_sha256": None,
    }
    if value["operation"] in {
        "host-controller-install", "host-controller-rollback",
    }:
        pending["host_pair_authorized_target_plan_sha256"] = value[
            "parameters"
        ]["authorized_target_plan_sha256"]
    if value["operation"] == "harness-acceptance-authorize":
        plan = value["parameters"]["plan"]
        pending.update({
            "acceptance_campaign_sha256":plan["campaign_sha256"],
            "acceptance_case_id":plan["case_id"],
            "acceptance_generation_id":plan["generation_id"],
            "acceptance_operator_uid":plan["operator_uid"],
            "acceptance_plan_sha256":plan["plan_sha256"],
            "acceptance_source_commit":plan["source_commit"],
            "host_release_id":release.name,
        })
    if value["operation"] == native_stack_catalog_promotion.OPERATION:
        catalog_plan = value["parameters"]["plan"]
        pending.update({
            "native_catalog_promotion_id": catalog_plan["promotion_id"],
            "native_catalog_plan_sha256": catalog_plan["plan_sha256"],
            "host_release_id": release.name,
        })
    elif value["operation"] in native_deployment.OPERATIONS:
        if value["operation"] == native_deployment.APPLY_OPERATION:
            deployment_plan_response = value["parameters"]["plan"]
            recovery_action = "apply"
            active_journal_sha256 = None
        else:
            recovery = value["parameters"]["recovery"]
            deployment_plan_response = recovery["plan_response"]
            recovery_action = value["parameters"]["action"]
            active_journal_sha256 = recovery["active_journal_sha256"]
        deployment_plan = deployment_plan_response["plan"]
        pending.update({
            "native_deployment_id": deployment_plan["deployment_id"],
            "native_deployment_plan_sha256": deployment_plan["plan_sha256"],
            "native_deployment_operation": value["operation"],
            "native_deployment_recovery_action": recovery_action,
            "native_deployment_active_journal_sha256": (
                active_journal_sha256
            ),
            "host_release_id": release.name,
        })
    elif value["operation"] == native_program_attestation.OPERATION:
        program_plan = value["parameters"]["plan"]
        pending.update({
            "native_program_attestation_id": program_plan["attestation_id"],
            "native_program_plan_sha256": program_plan["plan_sha256"],
            "host_release_id": release.name,
        })
    elif value["operation"] == native_projection_reconciliation.OPERATION:
        recovery_plan = value["parameters"]["plan"]
        pending.update({
            "native_projection_recovery_operation_id": recovery_plan[
                "recovery_operation_id"
            ],
            "native_projection_original_operation_id": recovery_plan[
                "original_operation_id"
            ],
            "native_projection_reconciliation_plan_sha256": recovery_plan[
                "plan_sha256"
            ],
            "host_release_id": release.name,
        })
    elif value["operation"] == native_projection_identity_recovery.OPERATION:
        identity_plan = value["parameters"]["plan"]
        pending.update({
            "native_projection_recovery_operation_id": identity_plan[
                "recovery_operation_id"
            ],
            "native_projection_original_operation_id": identity_plan[
                "original_operation_id"
            ],
            "native_projection_identity_recovery_plan_sha256": identity_plan[
                "plan_sha256"
            ],
            "host_release_id": release.name,
        })
    elif value["operation"] in {"native-session-start", "native-session-stop"}:
        session_plan = value["parameters"]["plan"]
        pending.update({
            "native_session_action_id": session_plan["action_id"],
            "native_session_id": session_plan["session_id"],
            "native_session_plan_sha256": session_plan["plan_sha256"],
            "host_release_id": release.name,
        })
    elif value["operation"].startswith("native-stack-"):
        native_plan = value["parameters"]["plan"]
        pending.update({
            "native_action_id":native_plan["action_id"],
            "native_plan_sha256":native_plan["plan_sha256"],
            "host_release_id":release.name,
        })
    try:
        write_all(descriptor, canonical(pending))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(receipt_root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    harness_authorization = None
    harness_preflight_result = None
    if ((value["operation"].startswith("harness-generation-")
         and value["operation"] != "harness-generation-recover")
            or value["operation"] == "harness-acceptance-authorize"):
        plan = (value["parameters"]["plan"]
                if value["operation"] == "harness-acceptance-authorize"
                else value["parameters"]["plan"]["plan"])
        expires_at = min(value["expires_at"], plan["expires_at"], started + 120)
        if expires_at <= started:
            harness_preflight_result = subprocess.CompletedProcess(
                ["harness-authorization-preflight"], 1, b"",
                canonical(diagnostic_record(
                    "harness_authorization_expired", request_id, value["operation"],
                )),
            )
        else:
            harness_authorization = {
                "schema":"secure-sandbox-harness-touchid-authorization-v1",
                "authorization_id":request_id, "plan_id":plan["plan_id"],
                "plan_sha256":plan["plan_sha256"], "transaction_id":plan["transaction_id"],
                "operation":plan["operation"], "method":"touch-id", "password_fallback":False,
                "authorized_at":started, "expires_at":expires_at,
                "requesting_agent_sha256":hashlib.sha256(
                    value["declared_agent"].encode("utf-8")
                ).hexdigest(),
                "requesting_session_sha256":hashlib.sha256(
                    value["declared_session"].encode("utf-8")
                ).hexdigest(),
            }
            harness_authorization["authorization_sha256"] = hashlib.sha256(
                canonical(harness_authorization)
            ).hexdigest()
    native_authorization = None
    if value["operation"] in native_deployment.OPERATIONS:
        if value["operation"] == native_deployment.APPLY_OPERATION:
            deployment_plan = value["parameters"]["plan"]["plan"]
            recovery_action = "apply"
            active_journal_sha256 = None
            authorization_expiry = min(
                value["expires_at"], deployment_plan["expires_at"],
                started + 120,
            )
        else:
            recovery = value["parameters"]["recovery"]
            deployment_plan = recovery["plan_response"]["plan"]
            recovery_action = value["parameters"]["action"]
            active_journal_sha256 = recovery["active_journal_sha256"]
            authorization_expiry = min(value["expires_at"], started + 120)
        try:
            native_authorization = native_deployment.make_authorization(
                deployment_plan,
                authorization_id=request_id,
                request_sha256=expected_digest,
                pending_receipt_sha256=hashlib.sha256(
                    canonical(pending)).hexdigest(),
                requesting_agent_sha256=hashlib.sha256(
                    value["declared_agent"].encode("utf-8")).hexdigest(),
                requesting_session_sha256=hashlib.sha256(
                    value["declared_session"].encode("utf-8")).hexdigest(),
                authorized_at=started, expires_at=authorization_expiry,
                operation=value["operation"],
                recovery_action=recovery_action,
                active_journal_sha256=active_journal_sha256,
            )
        except native_deployment.NativeDeploymentError as error:
            raise AuthorizationError(
                "native_deployment_authorization_invalid") from error
    elif value["operation"] == native_stack_catalog_promotion.OPERATION:
        plan = value["parameters"]["plan"]
        native_authorization = {
            "schema": native_stack_catalog_promotion.AUTHORIZATION_SCHEMA,
            "authorization_id": request_id,
            "request_sha256": expected_digest,
            "pending_receipt_sha256": hashlib.sha256(canonical(pending)).hexdigest(),
            "promotion_id": plan["promotion_id"],
            "plan_sha256": plan["plan_sha256"],
            "method": "touch-id",
            "password_fallback": False,
            "authorized_at": started,
            "expires_at": min(value["expires_at"], plan["expires_at"], started + 120),
            "host_release_id": release.name,
            "requesting_agent_sha256": hashlib.sha256(
                value["declared_agent"].encode("utf-8")
            ).hexdigest(),
            "requesting_session_sha256": hashlib.sha256(
                value["declared_session"].encode("utf-8")
            ).hexdigest(),
        }
        native_authorization["authorization_sha256"] = (
            native_stack_catalog_promotion.sha256(native_authorization)
        )
    elif value["operation"] == native_program_attestation.OPERATION:
        plan = value["parameters"]["plan"]
        native_authorization = {
            "schema": native_program_attestation.AUTHORIZATION_SCHEMA,
            "authorization_id": request_id,
            "attestation_id": plan["attestation_id"],
            "plan_sha256": plan["plan_sha256"],
            "request_sha256": expected_digest,
            "pending_receipt_sha256": hashlib.sha256(
                canonical(pending)
            ).hexdigest(),
            "host_release_id": release.name,
            "method": "touch-id",
            "password_fallback": False,
            "requesting_agent_sha256": hashlib.sha256(
                value["declared_agent"].encode("utf-8")
            ).hexdigest(),
            "requesting_session_sha256": hashlib.sha256(
                value["declared_session"].encode("utf-8")
            ).hexdigest(),
            "authorized_at": started,
            "expires_at": min(
                value["expires_at"], plan["expires_at"], started + 120
            ),
            "status": "authorized",
        }
        native_authorization["authorization_sha256"] = (
            native_program_attestation.sha256({
                key: item for key, item in native_authorization.items()
                if key != "schema"
            })
        )
    elif value["operation"] == native_projection_reconciliation.OPERATION:
        plan = value["parameters"]["plan"]
        native_authorization = {
            "schema": native_projection_reconciliation.AUTHORIZATION_SCHEMA,
            "authorization_id": request_id,
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "plan_sha256": plan["plan_sha256"],
            "request_sha256": expected_digest,
            "pending_receipt_sha256": hashlib.sha256(
                canonical(pending)
            ).hexdigest(),
            "host_release_id": release.name,
            "method": "touch-id", "password_fallback": False,
            "requesting_agent_sha256": hashlib.sha256(
                value["declared_agent"].encode("utf-8")
            ).hexdigest(),
            "requesting_session_sha256": hashlib.sha256(
                value["declared_session"].encode("utf-8")
            ).hexdigest(),
            "authorized_at": started,
            "expires_at": min(
                value["expires_at"], plan["expires_at"], started + 120
            ),
            "status": "authorized",
        }
        native_authorization["authorization_sha256"] = (
            native_projection_reconciliation.sha256({
                key: item for key, item in native_authorization.items()
                if key != "schema"
            })
        )
    elif value["operation"] == native_projection_identity_recovery.OPERATION:
        plan = value["parameters"]["plan"]
        native_authorization = {
            "schema": native_projection_identity_recovery.AUTHORIZATION_SCHEMA,
            "authorization_id": request_id,
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "plan_sha256": plan["plan_sha256"],
            "request_sha256": expected_digest,
            "pending_receipt_sha256": hashlib.sha256(
                canonical(pending)
            ).hexdigest(),
            "host_release_id": release.name,
            "method": "touch-id", "password_fallback": False,
            "requesting_agent_sha256": hashlib.sha256(
                value["declared_agent"].encode("utf-8")
            ).hexdigest(),
            "requesting_session_sha256": hashlib.sha256(
                value["declared_session"].encode("utf-8")
            ).hexdigest(),
            "authorized_at": started,
            "expires_at": min(
                value["expires_at"], plan["expires_at"], started + 120
            ),
            "status": "authorized",
        }
        native_authorization["authorization_sha256"] = (
            native_projection_identity_recovery.sha256({
                key: item for key, item in native_authorization.items()
                if key != "schema"
            })
        )
    elif value["operation"] in {"native-session-start", "native-session-stop"}:
        plan = value["parameters"]["plan"]
        native_authorization = {
            "schema": native_stack_session.AUTHORIZATION_SCHEMA,
            "authorization_id": request_id,
            "plan_sha256": plan["plan_sha256"],
            "action": plan["action"], "session_id": plan["session_id"],
            "runtime_authority_sha256": plan["runtime_authority_sha256"],
            "request_sha256": expected_digest,
            "pending_receipt_sha256": hashlib.sha256(
                canonical(pending)
            ).hexdigest(),
            "host_release_id": release.name, "method": "touch-id",
            "password_fallback": False,
            "requesting_agent_sha256": hashlib.sha256(
                value["declared_agent"].encode("utf-8")
            ).hexdigest(),
            "requesting_session_sha256": hashlib.sha256(
                value["declared_session"].encode("utf-8")
            ).hexdigest(),
            "authorized_at": started,
            "expires_at": min(
                value["expires_at"], plan["expires_at"], started + 120
            ),
            "status": "authorized",
        }
        native_authorization["authorization_sha256"] = (
            native_stack_session.sha256({
                key: item for key, item in native_authorization.items()
                if key != "schema"
            })
        )
    elif value["operation"].startswith("native-stack-"):
        plan = value["parameters"]["plan"]
        native_authorization = {
            "schema":"secure-sandbox-native-stack-touchid-authorization-v1",
            "authorization_id":request_id,
            "request_sha256":expected_digest,
            "pending_receipt_sha256":hashlib.sha256(canonical(pending)).hexdigest(),
            "action_id":plan["action_id"],
            "action":plan["action"],
            "plan_sha256":plan["plan_sha256"],
            "method":"touch-id",
            "password_fallback":False,
            "authorized_at":started,
            "expires_at":min(value["expires_at"], plan["expires_at"], started + 120),
            "host_release_id":release.name,
            "requesting_agent_sha256":hashlib.sha256(
                value["declared_agent"].encode("utf-8")
            ).hexdigest(),
            "requesting_session_sha256":hashlib.sha256(
                value["declared_session"].encode("utf-8")
            ).hexdigest(),
        }
        native_authorization["authorization_sha256"] = hashlib.sha256(
            canonical_v2(native_authorization)
        ).hexdigest()
    deployment_arguments = None
    catalog_promotion_request = None
    if value["operation"] == native_stack_catalog_promotion.OPERATION:
        if native_authorization is None:
            raise AuthorizationError(
                "native_catalog_promotion_authorization_missing")
        catalog_promotion_request = native_stack_catalog_promotion.make_request(
            value["parameters"]["plan"], native_authorization)
        command = [str(release / "native_stack_catalog_promoter"), "consume"]
    elif value["operation"] in native_deployment.OPERATIONS:
        deployment_arguments = native_deployment_operation_arguments(
            value, release, native_authorization)
        command = [str(release / "native_stack_deployer"), *deployment_arguments]
    else:
        command = (["harness-authorization-preflight"]
                   if harness_preflight_result is not None
                   else operation_command(
                       value, release, operator_uid=uid,
                       authorization=(native_authorization
                                      if native_authorization is not None
                                      else harness_authorization)))
    operation_input = None
    if value["operation"] == native_program_attestation.OPERATION:
        if native_authorization is None:
            raise AuthorizationError(
                "native_program_attestation_authorization_missing"
            )
        ticket_body = {
            "schema": "secure-sandbox-native-program-attestation-host-ticket-v1",
            "plan": value["parameters"]["plan"],
            "authorization": native_authorization,
        }
        operation_input = canonical_v2({
            **ticket_body,
            "ticket_sha256": hashlib.sha256(
                canonical_v2(ticket_body)
            ).hexdigest(),
        })
    if value["operation"] == "vm-preserve-legacy":
        timeout = 8 * 60 * 60
    elif value["operation"] in {"vm-create", "vm-reprovision"}:
        timeout = 3600
    elif value["operation"].startswith("installer-"):
        timeout = 1800
    elif (value["operation"].startswith("native-stack-")
          or value["operation"] in native_deployment.OPERATIONS
          or value["operation"] in {"native-session-start", "native-session-stop"}
          or value["operation"] in {
              native_program_attestation.OPERATION,
              native_projection_reconciliation.OPERATION,
              native_projection_identity_recovery.OPERATION,
          }):
        timeout = authorization_execution_timeout(value["operation"])
    else:
        timeout = OPERATION_TIMEOUT_SECONDS
    if harness_preflight_result is not None:
        result = harness_preflight_result
    elif catalog_promotion_request is not None:
        if result_override is not None:
            raise AuthorizationError(
                "native_catalog_promotion_result_override_forbidden")
        result = run_native_catalog_promotion_consume(
            release, value["parameters"]["source"],
            catalog_promotion_request, timeout=timeout,
            expected_uid=expected_root_uid,
        )
    elif deployment_arguments is not None:
        if result_override is not None:
            raise AuthorizationError("native_deployment_result_override_forbidden")
        result = run_native_deployment_driver(
            release, deployment_arguments, timeout=timeout,
            expected_uid=expected_root_uid,
        )
    else:
        result = (result_override if result_override is not None
                  else run_privileged_operation(
                      command, timeout, input_bytes=operation_input
                  ))
    completed_at: int | None = None
    host_pair_result: dict[str, Any] | None = None
    if value["operation"] in {
        "host-controller-install", "host-controller-rollback",
    }:
        try:
            host_result = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            host_result = None
        if result.returncode != 0:
            recovered = recoverable_host_install_activation(
                request_id, expected_digest, pending,
                expected_uid=expected_root_uid,
            )
            if recovered is not None:
                result = subprocess.CompletedProcess(
                    command, 0, canonical(recovered), b"",
                )
                host_result = recovered
        if result.returncode == 0:
            if (isinstance(host_result, dict)
                    and host_result.get("status")
                        == "host_pair_transition_pending"):
                completed_at = int(time.time()) if now is None else now
                host_pair_result = validate_host_pair_pending_result(
                    host_result, value["operation"], request_id,
                    value["parameters"], now=completed_at,
                )
            else:
                host_pair_result = validate_host_pair_manager_result(
                    host_result, value["operation"], value["parameters"],
                )
    deployment_terminal = None
    if value["operation"] in native_deployment.OPERATIONS and result.returncode == 0:
        if result.stderr or not 2 <= len(result.stdout) <= 4 * 1024 * 1024:
            raise AuthorizationError("native_deployment_result_invalid")
        try:
            deployment_terminal = validate_native_deployment_terminal(
                json.loads(result.stdout),
                plan_response=deployment_plan_response,
                authorization=native_authorization,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuthorizationError("native_deployment_result_invalid") from error
        if result.stdout != native_deployment.canonical(
            deployment_terminal, maximum=4 * 1024 * 1024
        ):
            raise AuthorizationError("native_deployment_result_invalid")
    if completed_at is None:
        completed_at = int(time.time()) if now is None else now
    completed = dict(pending)
    completed.update({
        "status": "succeeded" if result.returncode == 0 else "failed",
        "completed_at": completed_at,
        "exit_status": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    })
    if deployment_terminal is not None:
        completed.update({
            "native_deployment_terminal_phase": deployment_terminal["phase"],
            "native_deployment_terminal_sha256": deployment_terminal[
                "record_sha256"
            ],
        })
    if (host_pair_result is not None
            and host_pair_result["status"]
                == "host_pair_transition_pending"):
        completed.update({
            "status": "activation_pending",
            "completed_at": None,
            "exit_status": None,
            "host_pair_transition_id": host_pair_result["transition_id"],
            "host_pair_transition_sha256": host_pair_result[
                "transition_sha256"
            ],
            "authorization_pending_receipt_sha256": hashlib.sha256(
                canonical(pending)
            ).hexdigest(),
        })
    manager_host_pair_receipt = None
    if (value["operation"] in {
            "host-controller-install", "host-controller-rollback",
        }
            and not (host_pair_result is not None
                     and host_pair_result["status"]
                        == "host_pair_transition_pending")):
        manager_host_pair_receipt = manager_completed_host_pair_receipt(
            receipt_path, pending, expected_uid=expected_root_uid,
        )
        if host_pair_result is not None:
            if (manager_host_pair_receipt is None
                    or manager_host_pair_receipt[
                        "host_pair_transition_id"
                    ] != host_pair_result["transition_id"]
                    or manager_host_pair_receipt[
                        "host_pair_transition_sha256"
                    ] != host_pair_result["transition_sha256"]
                    or manager_host_pair_receipt["status"] != "succeeded"):
                raise AuthorizationError(
                    "host_pair_transition_receipt_untrusted"
                )
        if manager_host_pair_receipt is not None:
            completed = manager_host_pair_receipt
    if value["operation"] == "execution-approval-sign":
        completed["approval_id"] = value["parameters"]["approval_id"]
        completed["outcome"] = "approved" if result.returncode == 0 else "rejected"
        if result.returncode == 0:
            try:
                envelope = json.loads(result.stdout)
                attestation = envelope["attestation"]
                completed.update({
                    "approval_key_generation_id":attestation["key_generation_id"],
                    "approval_key_generation_epoch":attestation["key_generation_epoch"],
                    "approval_public_key_sha256":attestation["public_key_sha256"],
                    "approval_signature_algorithm":attestation["signature_algorithm"],
                    "approval_attestation_sha256":hashlib.sha256(
                        canonical_v2(attestation)
                    ).hexdigest(),
                })
            except (KeyError, TypeError, json.JSONDecodeError) as error:
                raise AuthorizationError("execution_approval_receipt_invalid") from error
    elif value["operation"] == "execution-approval-migration-verify-acceptance":
        completed["outcome"] = "succeeded" if result.returncode == 0 else "rejected"
        if result.returncode == 0:
            try:
                verified = json.loads(result.stdout)
                completed.update({name:verified[name] for name in (
                    "transaction_id", "generation_id", "generation_epoch", "host_release_id",
                    "research_release_id", "run_id", "session_id", "approval_id",
                    "acceptance_attempt_id", "acceptance_attempt_number",
                    "approval_attestation_sha256", "research_receipt_id",
                    "research_receipt_sha256", "consumed_marker_sha256",
                    "acceptance_binding_sha256", "host_receipt_sha256", "verifier_sha256",
                    "prepared_host_boot_sha256", "verified_host_boot_sha256",
                )})
            except (KeyError, TypeError, json.JSONDecodeError) as error:
                raise AuthorizationError("execution_approval_receipt_invalid") from error
    elif (value["operation"] == "execution-approval-key-init"
          or value["operation"].startswith("execution-approval-migration-")
          or value["operation"] == "execution-approval-software-retire"):
        completed["outcome"] = "succeeded" if result.returncode == 0 else "rejected"
        if "transaction_id" in value["parameters"]:
            completed["transaction_id"] = value["parameters"]["transaction_id"]
        if result.returncode == 0:
            try:
                migration = json.loads(result.stdout)
                completed.update({
                    "transaction_id":migration["transaction_id"],
                    "migration_phase":migration["status"],
                    "approval_key_generation_id":migration["generation_id"],
                    "approval_key_generation_epoch":migration["generation_epoch"],
                    "approval_public_key_sha256":migration["public_key_sha256"],
                    "approval_signature_algorithm":migration["algorithm"],
                    "operator_uid":migration["operator_uid"],
                    "host_release_id":migration["host_release_id"],
                    "research_release_id":migration["research_release_id"],
                    "previous_generation_id":migration["previous_generation_id"],
                    "previous_generation_epoch":migration["previous_generation_epoch"],
                })
                for name in (
                    "preparation_attestation_sha256", "research_fence_sha256",
                    "research_activation_sha256", "cold_boot_acceptance_sha256",
                    "prior_record_sha256", "phase_receipt_sha256",
                    "acceptance_binding_sha256",
                    "acceptance_verifier_sha256",
                    "acceptance_attempt_id", "acceptance_attempt_number",
                    "previous_acceptance_binding_sha256",
                ):
                    if name in migration:
                        completed[name] = migration[name]
            except (KeyError, TypeError, json.JSONDecodeError) as error:
                raise AuthorizationError("execution_approval_receipt_invalid") from error
    elif value["operation"] == native_program_attestation.OPERATION:
        if result.returncode == 0:
            try:
                provider_result = json.loads(result.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise AuthorizationError(
                    "native_program_attestation_result_invalid"
                ) from error
            plan = value["parameters"]["plan"]
            if (not isinstance(provider_result, dict)
                    or set(provider_result) != {
                        "schema", "action_id", "action", "plan_sha256",
                        "authorization_sha256", "status", "evidence_sha256",
                    }
                    or provider_result["schema"]
                        != "secure-sandbox-native-stack-provider-result-v1"
                    or provider_result["action_id"] != plan["attestation_id"]
                    or provider_result["action"] != "program-attest"
                    or provider_result["plan_sha256"] != plan["plan_sha256"]
                    or provider_result["authorization_sha256"]
                        != native_authorization["authorization_sha256"]
                    or provider_result["status"] != "verified"
                    or SHA256.fullmatch(
                        str(provider_result["evidence_sha256"])
                    ) is None
                    or canonical_v2(provider_result) != result.stdout):
                raise AuthorizationError(
                    "native_program_attestation_result_invalid"
                )
            completed["native_program_provider_evidence_sha256"] = (
                provider_result["evidence_sha256"]
            )
    elif value["operation"] == native_projection_reconciliation.OPERATION:
        if result.returncode == 0:
            try:
                reconciliation_result = (
                    native_projection_reconciliation.validate_reply(
                        json.loads(result.stdout),
                        plan_value=value["parameters"]["plan"],
                    )
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                native_projection_reconciliation.NativeProjectionReconciliationError,
            ) as error:
                raise AuthorizationError(
                    "native_projection_reconciliation_result_invalid"
                ) from error
            if (result.stdout
                    != native_projection_reconciliation.canonical_bytes(
                        reconciliation_result
                    )):
                raise AuthorizationError(
                    "native_projection_reconciliation_result_invalid"
                )
            completed["native_projection_reconciliation_evidence_sha256"] = (
                reconciliation_result["reconciliation_evidence_sha256"]
            )
    elif value["operation"] == native_projection_identity_recovery.OPERATION:
        if result.returncode == 0:
            try:
                identity_result = (
                    native_projection_identity_recovery.validate_reply(
                        json.loads(result.stdout),
                        plan_value=value["parameters"]["plan"],
                    )
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                native_projection_identity_recovery
                .NativeProjectionIdentityRecoveryError,
            ) as error:
                raise AuthorizationError(
                    "native_projection_identity_recovery_result_invalid"
                ) from error
            if (result.stdout
                    != native_projection_identity_recovery.canonical_bytes(
                        identity_result
                    )):
                raise AuthorizationError(
                    "native_projection_identity_recovery_result_invalid"
                )
            completed["native_projection_identity_evidence_sha256"] = (
                identity_result["identity_evidence_sha256"]
            )
    elif value["operation"] in {"native-session-start", "native-session-stop"}:
        if result.returncode == 0:
            plan = value["parameters"]["plan"]
            try:
                session_result = json.loads(result.stdout)
                if value["operation"] == "native-session-start":
                    if session_result.get("schema") == (
                        native_terminal_handle.PUBLIC_SCHEMA
                    ):
                        session_result = native_terminal_handle.validate_public(
                            session_result
                        )
                        valid = session_result["kind"] == "claude-session"
                        canonical_result = native_terminal_handle.canonical_bytes(
                            session_result
                        )
                    else:
                        session_result = native_codex_ui_handle.validate_public(
                            session_result
                        )
                        valid = (
                            session_result["kind"]
                                == native_codex_ui_handle.KIND
                            and session_result["runtime_authority_sha256"]
                                == plan["runtime_authority_sha256"]
                        )
                        canonical_result = native_codex_ui_handle.canonical_bytes(
                            session_result
                        )
                    valid = (
                        valid
                        and session_result["operation_id"] == plan["action_id"]
                        and session_result["session_id"] == plan["session_id"]
                        and session_result["expires_at"]
                            <= native_authorization["expires_at"]
                    )
                else:
                    expected = {
                        "schema", "operation_id", "session_id", "state",
                        "final_summary_sha256", "evidence_sha256",
                    }
                    valid = (
                        isinstance(session_result, dict)
                        and set(session_result) == expected
                        and session_result.get("schema")
                            in {
                                "secure-sandbox-native-claude-session-stop-reply-v1",
                                "secure-sandbox-native-codex-session-stop-reply-v1",
                            }
                        and session_result.get("operation_id")
                            == plan["action_id"]
                        and session_result.get("session_id")
                            == plan["session_id"]
                        and session_result.get("state") == "absent"
                        and SHA256.fullmatch(str(session_result.get(
                            "final_summary_sha256", ""
                        ))) is not None
                        and SHA256.fullmatch(str(session_result.get(
                            "evidence_sha256", ""
                        ))) is not None
                    )
                    canonical_result = canonical_v2(session_result)
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                native_terminal_handle.NativeTerminalHandleError,
                native_codex_ui_handle.NativeCodexUIHandleError,
            ) as error:
                raise AuthorizationError(
                    "native_stack_session_result_invalid"
                ) from error
            if not valid or result.stdout != canonical_result:
                raise AuthorizationError(
                    "native_stack_session_result_invalid"
                )
    elif value["operation"] == "native-stack-signin-begin" and (
        value["parameters"]["plan"]["identity"]["vendor_id"] == "anthropic"
    ):
        if result.returncode == 0:
            try:
                terminal_handle = native_terminal_handle.validate_public(
                    json.loads(result.stdout)
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                native_terminal_handle.NativeTerminalHandleError,
            ) as error:
                raise AuthorizationError(
                    "native_stack_terminal_handle_invalid"
                ) from error
            plan = value["parameters"]["plan"]
            if (result.stdout != native_terminal_handle.canonical_bytes(
                    terminal_handle
                )
                    or terminal_handle["kind"] != "claude-login"
                    or terminal_handle["handle_id"] != plan["action_id"]
                    or terminal_handle["operation_id"] != plan["action_id"]
                    or terminal_handle["session_id"] != plan["action_id"]
                    or terminal_handle["expires_at"]
                        > native_authorization["expires_at"]):
                raise AuthorizationError(
                    "native_stack_terminal_handle_invalid"
                )
    if manager_host_pair_receipt is None:
        atomic_receipt(receipt_path, completed)
    if (value["operation"] == native_program_attestation.OPERATION
            and result.returncode == 0):
        try:
            program_attestation_root.mkdir(
                mode=0o700, parents=False, exist_ok=True
            )
            program_root_info = program_attestation_root.lstat()
            if (not stat.S_ISDIR(program_root_info.st_mode)
                    or stat.S_ISLNK(program_root_info.st_mode)
                    or program_root_info.st_uid != expected_root_uid
                    or stat.S_IMODE(program_root_info.st_mode) != 0o700):
                raise AuthorizationError(
                    "native_program_attestation_root_untrusted"
                )
            plan = value["parameters"]["plan"]
            commit = native_program_attestation.make_commit(
                plan_value=plan,
                authorization_value=native_authorization,
                operator_receipt_sha256=hashlib.sha256(
                    canonical(completed)
                ).hexdigest(),
                provider_evidence_sha256=completed[
                    "native_program_provider_evidence_sha256"
                ],
                committed_at=completed["completed_at"],
            )
            atomic_receipt(
                program_attestation_root / f"{plan['stack_sha256']}.json",
                commit,
            )
        except (
            OSError,
            AuthorizationError,
            native_program_attestation.NativeProgramAttestationError,
        ):
            failure = b"native_program_attestation_commit_failed\n"
            result = subprocess.CompletedProcess(
                command, 1, b"", failure
            )
            completed.update({
                "status": "failed", "exit_status": 1,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stderr_sha256": hashlib.sha256(failure).hexdigest(),
            })
            atomic_receipt(receipt_path, completed)
    try:
        path.unlink()
    except OSError:
        pass
    if result_capture is not None:
        result_capture.append(result)
    if emit_output:
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
    return result.returncode


def run_process(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    starts_owned_group, environment = child_process_policy()
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=starts_owned_group, env=environment,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        terminate_bounded_process(process, owns_group=starts_owned_group)
        process.communicate()
        raise AuthorizationError("authorization_dialog_timeout") from error
    except BaseException:
        terminate_bounded_process(process, owns_group=starts_owned_group)
        raise
    if starts_owned_group and process_group_exists(process.pid):
        terminate_bounded_process(process, owns_group=True)
        raise AuthorizationError("authorization_dialog_descendant_unreaped")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def register_touchid_ui(ui_path: Path, runner=subprocess.run) -> None:
    """Register the exact signed bundle in the invoking user's LS database."""
    try:
        executable = ui_path.resolve(strict=True)
        bundle = executable.parents[2]
    except (OSError, IndexError) as error:
        raise AuthorizationError("touchid_ui_bundle_unavailable") from error
    if (bundle.name != TOUCHID_UI_APP_NAME
            or executable != bundle / TOUCHID_UI_EXECUTABLE
            or not (bundle / "Contents/Info.plist").is_file()):
        raise AuthorizationError("touchid_ui_bundle_invalid")
    try:
        result = runner(
            [str(LSREGISTER), "-f", str(bundle)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=15, check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuthorizationError("touchid_ui_registration_failed") from error
    if result.returncode != 0:
        raise AuthorizationError("touchid_ui_registration_failed")


def read_touchid_ui_file(path: Path, uid: int, limit: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise AuthorizationError("touchid_ui_result_missing") from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
            raise AuthorizationError("touchid_ui_result_untrusted")
        data = os.read(descriptor, limit + 1)
        if len(data) != info.st_size or len(data) > limit:
            raise AuthorizationError("touchid_ui_result_untrusted")
        return data
    finally:
        os.close(descriptor)


def legacy_launchservices_success(operation: object, output: object) -> bool:
    """Validate the narrow successful responses emitted by the pinned old UI."""
    if not isinstance(operation, str) or not isinstance(output, dict):
        return False
    schema = output.get("schema")
    status = output.get("status")
    if operation == "execution-approval-migration-authorize-acceptance":
        return (schema
                == "secure-sandbox-execution-approval-acceptance-authorization-v1"
                and status in {"authorized", "not_issued_expired"})
    if operation == "execution-approval-migration-verify-acceptance":
        return (schema
                == "secure-sandbox-execution-approval-acceptance-verifier-v1"
                and status == "verified")
    if operation == "execution-approval-sign":
        return (schema == EXECUTION_APPROVAL_V2_ENVELOPE
                and isinstance(output.get("attestation"), dict)
                and isinstance(output.get("signature_der_b64"), str))
    if operation == "execution-approval-migration-commit":
        return (schema == "secure-sandbox-execution-approval-migration-result-v2"
                and status == "committed")
    return False


def legacy_launchservices_rejection(output: object) -> bool:
    """Recognize only the protected broker's bounded structured rejection."""
    return (isinstance(output, dict)
            and set(output) == {"error", "schema", "status"}
            and output.get("schema") == SCHEMA
            and output.get("status") == "rejected"
            and isinstance(output.get("error"), str)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,127}", output["error"]) is not None)


def run_touchid_app(
    ui_path: Path, request_path: Path, request_sha256: str, socket_path: Path,
    timeout: int, uid: int,
) -> TouchIDApplicationResult:
    # The broker consumes the one-time request before the UI exits.  The exact
    # predecessor UI has no result sidecar, so retain only the already verified
    # operation name needed to schema-check its stdout after consumption.
    request_operation = read_request(
        request_path, uid, request_sha256
    ).get("operation")
    register_touchid_ui(ui_path)
    directory = request_path.parent
    token = uuid.uuid4().hex
    stdout_path = directory / f".{request_path.stem}.{token}.stdout"
    stderr_path = directory / f".{request_path.stem}.{token}.stderr"
    result_path = directory / f".{request_path.stem}.{token}.result"
    for output in (stdout_path, stderr_path):
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
    executable = ui_path.resolve(strict=True)
    bundle = executable.parents[2]
    command = [
        "/usr/bin/open", "-n", "-W", "-F",
        "-o", str(stdout_path), "--stderr", str(stderr_path), str(bundle), "--args",
        "--request-path", str(request_path), "--request-sha256", request_sha256,
        "--socket-path", str(socket_path), "--result-path", str(result_path),
    ]
    try:
        try:
            launched = run_process(command, timeout + 5)
        except AuthorizationError as error:
            if str(error) == "authorization_dialog_timeout":
                raise AuthorizationError("touchid_lifecycle_timeout") from error
            raise
        stdout = read_touchid_ui_file(stdout_path, uid, TOUCHID_RESPONSE_LIMIT).decode(
            "utf-8", "replace"
        )
        stderr = read_touchid_ui_file(stderr_path, uid, TOUCHID_RESPONSE_LIMIT).decode(
            "utf-8", "replace"
        )
        if launched.returncode != 0:
            raise AuthorizationError("touchid_ui_launch_failed")
        try:
            encoded = read_touchid_ui_file(result_path, uid, 4096)
        except AuthorizationError as error:
            if str(error) != "touchid_ui_result_missing":
                raise
            release = protected_release_directory(bundle.parent / "authorization_broker", 0)
            manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
            try:
                legacy_output = json.loads(stdout)
            except json.JSONDecodeError:
                legacy_output = None
            try:
                legacy_error = json.loads(stderr)
            except json.JSONDecodeError:
                legacy_error = None
            if (not isinstance(manifest, dict)
                    or not isinstance(manifest.get("payloads"), dict)
                    or manifest["payloads"].get("authorization_ui_bundle")
                    != LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256):
                raise
            if not stderr and legacy_launchservices_success(
                    request_operation, legacy_output):
                return TouchIDApplicationResult(0, stdout, stderr, "broker-result")
            # The predecessor multiplexes operation and broker failure bytes.
            # Never use either stream as policy control data.
            if not stdout and legacy_launchservices_rejection(legacy_error):
                return TouchIDApplicationResult(1, stdout, stderr, "legacy-ambiguous")
            raise
        try:
            result = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuthorizationError("touchid_ui_result_invalid") from error
        if (canonical(result) != encoded
                or set(result) != {
                    "outcome", "request_id", "request_sha256", "schema", "status",
                }
                or result.get("schema") != "secure-sandbox-touchid-ui-result-v2"
                or result.get("request_id") != request_path.stem
                or result.get("request_sha256") != request_sha256
                or not isinstance(result.get("status"), int)
                or isinstance(result.get("status"), bool)
                or not 0 <= result["status"] <= 255
                or result.get("outcome") not in {
                    "biometric-rejected", "broker-result", "cancelled", "dismissed",
                    "expired", "password-fallback", "ui-error",
                }):
            raise AuthorizationError("touchid_ui_result_invalid")
        return TouchIDApplicationResult(
            result["status"], stdout, stderr, result["outcome"]
        )
    finally:
        for candidate in (stdout_path, stderr_path, result_path):
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass


def execution_approval_key_initialize(
    root: Path = EXECUTION_APPROVAL_ROOT,
    key: Path = EXECUTION_APPROVAL_KEY,
    expected_uid: int = 0,
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    if secure_enclave_floor(root, expected_uid)["minimum_protocol"] >= 2:
        raise AuthorizationError("execution_approval_v1_retired")
    # The unprivileged deployment coordinator must be able to traverse this
    # directory to read the explicitly public key. Directory listing remains
    # disabled and the private key remains root-only.
    root.mkdir(mode=0o711, parents=True, exist_ok=True)
    info = root.lstat()
    if (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == expected_uid and stat.S_IMODE(info.st_mode) == 0o700):
        os.chmod(root, 0o711)
        info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorizationError("execution_approval_key_directory_untrusted")
    public = key.with_suffix(".pub")
    if key.exists() or public.exists():
        for path, mode in ((key, 0o600), (public, 0o644)):
            metadata = path.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != mode
                    or metadata.st_nlink != 1):
                raise AuthorizationError("execution_approval_key_untrusted")
    else:
        temporary = root / f".id_ed25519.{os.getpid()}"
        temporary_public = Path(str(temporary) + ".pub")
        result = subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
             "secure-sandbox-execution-approval", "-f", str(temporary)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=30,
        )
        if result.returncode:
            raise AuthorizationError("execution_approval_key_generation_failed")
        try:
            os.chown(temporary, expected_uid, 0); os.chmod(temporary, 0o600)
            os.chown(temporary_public, expected_uid, 0)
            os.chmod(temporary_public, 0o644)
            os.replace(temporary, key)
            os.replace(temporary_public, public)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            for path in (temporary, temporary_public):
                try: path.unlink()
                except FileNotFoundError: pass
    public_text = public.read_text(encoding="ascii").strip()
    fields = public_text.split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise AuthorizationError("execution_approval_public_key_invalid")
    return {
        "schema": "secure-sandbox-execution-approval-key-v1",
        "public_key": " ".join(fields[:2]),
        "public_key_sha256": hashlib.sha256((" ".join(fields[:2]) + "\n").encode("ascii")).hexdigest(),
        "status": "ready",
    }


def sign_execution_approval(parameters_json: str, authorization_request_id: str,
                            host_release_id: str,
                            root: Path = EXECUTION_APPROVAL_ROOT,
                            key: Path = EXECUTION_APPROVAL_KEY,
                            expected_uid: int = 0) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    if secure_enclave_floor(root, expected_uid)["minimum_protocol"] >= 2:
        raise AuthorizationError("execution_approval_v1_retired")
    valid_uuid4(authorization_request_id, "authorization_request_id")
    if not SHA256.fullmatch(host_release_id):
        raise AuthorizationError("host_release_id_invalid")
    try:
        parameters = json.loads(parameters_json)
    except json.JSONDecodeError as error:
        raise AuthorizationError("operation_parameters_invalid") from error
    home = Path(pwd.getpwuid(expected_uid).pw_dir)
    validate_parameters("execution-approval-sign", parameters, home)
    now = int(time.time())
    if now < parameters["created_at"] - 5 or now > parameters["expires_at"]:
        raise AuthorizationError("execution_approval_expired")
    execution_approval_key_initialize(root, key, expected_uid)
    attestation = {
        "schema": "secure-sandbox-execution-approval-attestation-v1",
        "approval": parameters,
        "approval_request_sha256": hashlib.sha256(canonical(parameters)).hexdigest(),
        "authorization_request_id": authorization_request_id,
        "host_release_id": host_release_id,
        "approved_at": now,
    }
    process = subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key), "-n",
         EXECUTION_APPROVAL_NAMESPACE],
        input=canonical(attestation), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=30,
    )
    if process.returncode or not process.stdout.startswith(b"-----BEGIN SSH SIGNATURE-----"):
        raise AuthorizationError("execution_approval_signing_failed")
    return {
        "schema": "secure-sandbox-execution-approval-envelope-v1",
        "attestation": attestation,
        "signature_b64": base64.b64encode(process.stdout).decode("ascii"),
    }


def secure_enclave_state_root(root: Path = EXECUTION_APPROVAL_ROOT,
                              expected_uid: int = 0) -> Path:
    root.mkdir(mode=0o711, parents=True, exist_ok=True)
    verify_acl_free_directory(
        root, expected_uid, 0o711,
        "execution_approval_key_directory_untrusted",
    )
    return root


def read_secure_enclave_state(path: Path, schema: str,
                              expected_uid: int = 0) -> dict[str, Any]:
    try:
        raw = read_acl_free_regular(
            path, expected_uid, 0o600,
            "execution_approval_state_invalid", maximum=16 * 1024,
            expected_nlink=1,
        )
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("execution_approval_state_invalid") from error
    if (not isinstance(value, dict) or value.get("schema") != schema
            or canonical(value) != raw):
        raise AuthorizationError("execution_approval_state_invalid")
    return value


def completion_receipt_value(pending: dict[str, Any],
                             verifier: dict[str, Any]) -> dict[str, Any]:
    if pending.get("phase") not in {"committed", "software_retired"}:
        raise AuthorizationError("execution_approval_completion_unavailable")
    recorded_verifier = verifier.get("verifier_sha256")
    unsigned_verifier = dict(verifier)
    unsigned_verifier.pop("verifier_sha256", None)
    if (verifier.get("schema")
            != "secure-sandbox-execution-approval-acceptance-verifier-v1"
            or verifier.get("status") != "verified"
            or recorded_verifier != pending.get("acceptance_verifier_sha256")
            or recorded_verifier
            != hashlib.sha256(canonical_v2(unsigned_verifier)).hexdigest()
            or any(verifier.get(name) != pending.get(name) for name in (
                "transaction_id", "generation_id", "generation_epoch",
                "host_release_id", "research_release_id",
                "acceptance_binding_sha256",
            ))):
        raise AuthorizationError("execution_approval_completion_verifier_invalid")
    required = (
        "transaction_id", "generation_id", "generation_epoch", "algorithm",
        "public_key_sha256", "operator_uid", "host_release_id",
        "research_release_id", "previous_generation_id",
        "previous_generation_epoch", "research_activation_sha256",
        "cold_boot_acceptance_sha256", "acceptance_verifier_sha256",
        "acceptance_binding_sha256",
    )
    result = {
        "schema":"secure-sandbox-execution-approval-completion-receipt-v1",
        "status":pending["phase"],
        **{name:pending[name] for name in required},
        "acceptance_verifier":verifier,
    }
    if pending.get("software_retired_at") is not None:
        result["software_retired_at"] = pending["software_retired_at"]
    result["receipt_sha256"] = hashlib.sha256(canonical_v2(result)).hexdigest()
    return result


def publish_completion_receipt(pending: dict[str, Any], verifier: dict[str, Any],
                               root: Path, expected_uid: int = 0) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    value = completion_receipt_value(pending, verifier)
    directory = root / EXECUTION_APPROVAL_COMPLETIONS.name
    try:
        directory.mkdir(mode=0o711)
        fsync_directory(root)
    except FileExistsError:
        pass
    info = directory.lstat()
    if (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == expected_uid
            and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_nlink == 2):
        # Early v2 builds created this future public-receipt directory as
        # private 0700 before any completion receipt existed.  Commit is the
        # only authorized writer and may migrate exactly that empty,
        # root-owned directory to the specified non-listable 0711 lookup
        # surface.  Any contents or other metadata remain fail-closed.
        try:
            empty = next(directory.iterdir(), None) is None
        except OSError as error:
            raise AuthorizationError(
                "execution_approval_completion_directory_untrusted"
            ) from error
        if empty:
            os.chmod(directory, 0o711)
            fsync_directory(directory)
            fsync_directory(root)
            info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorizationError("execution_approval_completion_directory_untrusted")
    path = directory / f"{pending['transaction_id']}.json"
    if path.exists():
        existing = read_public_completion_receipt(
            pending["transaction_id"], root, expected_uid
        )
        if existing != value:
            # A committed receipt may advance exactly once to software-retired.
            if (existing.get("status") != "committed"
                    or value.get("status") != "software_retired"
                    or any(existing.get(name) != value.get(name) for name in existing
                           if name not in {"status", "receipt_sha256"})):
                raise AuthorizationError("execution_approval_completion_conflict")
    atomic_public_record(path, value)
    return value


def read_public_completion_receipt(transaction_id: str,
                                   root: Path = EXECUTION_APPROVAL_ROOT,
                                   expected_uid: int = 0) -> dict[str, Any]:
    valid_uuid4(transaction_id, "transaction_id")
    directory = root / EXECUTION_APPROVAL_COMPLETIONS.name
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorizationError("execution_approval_completion_directory_untrusted")
    path = directory / f"{transaction_id}.json"
    metadata = path.lstat()
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("execution_approval_completion_untrusted") from error
    recorded = value.get("receipt_sha256") if isinstance(value, dict) else None
    unsigned = dict(value) if isinstance(value, dict) else {}
    unsigned.pop("receipt_sha256", None)
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1 or len(raw) > 32 * 1024
            or canonical(value) != raw
            or value.get("schema")
            != "secure-sandbox-execution-approval-completion-receipt-v1"
            or value.get("transaction_id") != transaction_id
            or value.get("status") not in {"committed", "software_retired"}
            or not isinstance(recorded, str) or not SHA256.fullmatch(recorded)
            or recorded != hashlib.sha256(canonical_v2(unsigned)).hexdigest()):
        raise AuthorizationError("execution_approval_completion_untrusted")
    # Re-run the cross-field verifier validation using the protected receipt data.
    rebuilt_pending = dict(value)
    rebuilt_pending["phase"] = value["status"]
    rebuilt_pending.pop("schema", None)
    rebuilt_pending.pop("status", None)
    rebuilt_pending.pop("receipt_sha256", None)
    verifier = rebuilt_pending.pop("acceptance_verifier", None)
    if not isinstance(verifier, dict):
        raise AuthorizationError("execution_approval_completion_untrusted")
    if completion_receipt_value(rebuilt_pending, verifier) != value:
        raise AuthorizationError("execution_approval_completion_untrusted")
    return value


def next_secure_enclave_epoch(root: Path, expected_uid: int = 0) -> int:
    floor_path = root / EXECUTION_APPROVAL_FLOOR.name
    if not floor_path.exists():
        return 1
    floor = read_secure_enclave_state(
        floor_path, "secure-sandbox-execution-approval-floor-v1", expected_uid
    )
    if (set(floor) != {"schema", "minimum_protocol", "minimum_epoch", "updated_at"}
            or floor.get("minimum_protocol") not in {1, 2}
            or not isinstance(floor.get("minimum_epoch"), int)
            or isinstance(floor.get("minimum_epoch"), bool)
            or floor["minimum_epoch"] < 0):
        raise AuthorizationError("execution_approval_state_invalid")
    return floor["minimum_epoch"] + 1


def secure_enclave_floor(root: Path = EXECUTION_APPROVAL_ROOT,
                         expected_uid: int = 0) -> dict[str, Any]:
    path = root / EXECUTION_APPROVAL_FLOOR.name
    if not path.exists():
        return {
            "schema":"secure-sandbox-execution-approval-floor-v1",
            "minimum_protocol":1,
            "minimum_epoch":0,
            "updated_at":0,
        }
    verify_acl_free_directory(
        root, expected_uid, 0o711,
        "execution_approval_key_directory_untrusted",
    )
    value = read_secure_enclave_state(
        path, "secure-sandbox-execution-approval-floor-v1", expected_uid
    )
    if (set(value) != {"schema", "minimum_protocol", "minimum_epoch", "updated_at"}
            or value.get("minimum_protocol") not in {1, 2}
            or not isinstance(value.get("minimum_epoch"), int)
            or isinstance(value.get("minimum_epoch"), bool)
            or value["minimum_epoch"] < 0
            or not isinstance(value.get("updated_at"), int)
            or isinstance(value.get("updated_at"), bool)
            or value["updated_at"] < 0):
        raise AuthorizationError("execution_approval_state_invalid")
    return value


def prepare_secure_enclave_challenge(value: dict[str, Any], request_sha256: str,
                                     release: Path, expected_uid: int = 0,
                                     now: int | None = None) -> dict[str, Any]:
    root = secure_enclave_state_root(EXECUTION_APPROVAL_ROOT, expected_uid)
    expected_access_group = touchid_signing_policy(release)["access_group"]
    pending_path = root / EXECUTION_APPROVAL_PENDING.name
    current_time = int(time.time()) if now is None else now
    if pending_path.exists():
        pending = read_secure_enclave_state(
            pending_path, "secure-sandbox-execution-approval-migration-v2", expected_uid
        )
        if (pending.get("phase") not in {"committed", "software_retired"}
                and pending.get("access_group") != expected_access_group):
            raise AuthorizationError("execution_approval_migration_conflict")
        if pending.get("phase") in {"committed", "software_retired"}:
            history = root / "history"
            try:
                history.mkdir(mode=0o700)
                directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            except FileExistsError:
                pass
            history_info = history.lstat()
            if (not stat.S_ISDIR(history_info.st_mode) or stat.S_ISLNK(history_info.st_mode)
                    or history_info.st_uid != expected_uid
                    or stat.S_IMODE(history_info.st_mode) != 0o700):
                raise AuthorizationError("execution_approval_history_untrusted")
            archive = history / f"{pending['transaction_id']}.json"
            if archive.exists():
                archived = read_secure_enclave_state(
                    archive, "secure-sandbox-execution-approval-migration-v2", expected_uid
                )
                if archived != pending:
                    raise AuthorizationError("execution_approval_history_conflict")
            else:
                atomic_receipt(archive, pending)
            verifier_path = root / "acceptance-verifier.json"
            verifier_archive = history / (
                f"{pending['transaction_id']}.acceptance-verifier.json"
            )
            if verifier_path.exists():
                verifier = read_secure_enclave_state(
                    verifier_path,
                    "secure-sandbox-execution-approval-acceptance-verifier-v1",
                    expected_uid,
                )
            else:
                verifier = read_secure_enclave_state(
                    verifier_archive,
                    "secure-sandbox-execution-approval-acceptance-verifier-v1",
                    expected_uid,
                )
            publish_completion_receipt(pending, verifier, root, expected_uid)
            if verifier_archive.exists():
                archived_verifier = read_secure_enclave_state(
                    verifier_archive,
                    "secure-sandbox-execution-approval-acceptance-verifier-v1",
                    expected_uid,
                )
                if archived_verifier != verifier:
                    raise AuthorizationError("execution_approval_history_conflict")
            else:
                atomic_receipt(verifier_archive, verifier)
            if verifier_path.exists():
                verifier_path.unlink()
                fsync_directory(root)
            pending_path.unlink()
            fsync_directory(root)
            pending = {}
        if pending and (pending.get("operator_uid") != value["invoking_uid"]
                or pending.get("phase") not in {"host_prepare_requested", "host_prepared"}):
            raise AuthorizationError("execution_approval_migration_conflict")
        rebindings = []
        if pending:
            legacy_rebinding = pending.get("host_prepare_release_rebinding")
            stored_rebindings = pending.get("host_prepare_release_rebindings")
            if legacy_rebinding is not None and stored_rebindings is not None:
                raise AuthorizationError("execution_approval_migration_conflict")
            if legacy_rebinding is not None:
                rebindings = [legacy_rebinding]
            elif stored_rebindings is not None:
                if not isinstance(stored_rebindings, list):
                    raise AuthorizationError("execution_approval_migration_conflict")
                rebindings = stored_rebindings
            if len(rebindings) > MAX_HOST_PREPARE_RELEASE_REBINDS:
                raise AuthorizationError("execution_approval_migration_conflict")
            prior_target = None
            for rebinding in rebindings:
                if (not isinstance(rebinding, dict)
                        or set(rebinding) != {
                            "from_host_release_id", "to_host_release_id", "rebound_at",
                        }
                        or not SHA256.fullmatch(rebinding.get("from_host_release_id", ""))
                        or not SHA256.fullmatch(rebinding.get("to_host_release_id", ""))
                        or rebinding["from_host_release_id"] == rebinding["to_host_release_id"]
                        or not isinstance(rebinding.get("rebound_at"), int)
                        or isinstance(rebinding.get("rebound_at"), bool)
                        or rebinding["rebound_at"] < 0
                        or (prior_target is not None
                            and rebinding["from_host_release_id"] != prior_target)):
                    raise AuthorizationError("execution_approval_migration_conflict")
                prior_target = rebinding["to_host_release_id"]
            if rebindings and prior_target != pending.get("host_release_id"):
                raise AuthorizationError("execution_approval_migration_conflict")
        research_rebindings = []
        if pending:
            stored_research_rebindings = pending.get("research_prepare_release_rebindings")
            if stored_research_rebindings is not None:
                if not isinstance(stored_research_rebindings, list):
                    raise AuthorizationError("execution_approval_migration_conflict")
                research_rebindings = stored_research_rebindings
            if len(research_rebindings) > MAX_RESEARCH_PREPARE_RELEASE_REBINDS:
                raise AuthorizationError("execution_approval_migration_conflict")
            prior_target = None
            for rebinding in research_rebindings:
                if (not isinstance(rebinding, dict)
                        or set(rebinding) != {
                            "from_research_release_id", "to_research_release_id", "rebound_at",
                        }
                        or not SHA256.fullmatch(rebinding.get("from_research_release_id", ""))
                        or not SHA256.fullmatch(rebinding.get("to_research_release_id", ""))
                        or rebinding["from_research_release_id"]
                        == rebinding["to_research_release_id"]
                        or not isinstance(rebinding.get("rebound_at"), int)
                        or isinstance(rebinding.get("rebound_at"), bool)
                        or rebinding["rebound_at"] < 0
                        or (prior_target is not None
                            and rebinding["from_research_release_id"] != prior_target)):
                    raise AuthorizationError("execution_approval_migration_conflict")
                prior_target = rebinding["to_research_release_id"]
            if research_rebindings and prior_target != pending.get("research_release_id"):
                raise AuthorizationError("execution_approval_migration_conflict")
        rebound = dict(pending) if pending else {}
        rebound_changed = False
        if pending and pending.get("host_release_id") != release.name:
            # A terminal-bound host release repair may be needed after the UI
            # has created the permanent Secure Enclave key but before its
            # possession proof is accepted.  Permit a bounded pre-activation
            # rebind chain, and only when each old binding is the independently
            # verified rollback selector.  The application tag/generation are
            # preserved so the repaired UI must find and prove the same key.
            if (pending.get("phase") not in {"host_prepare_requested", "host_prepared"}
                    or len(rebindings) >= MAX_HOST_PREPARE_RELEASE_REBINDS
                    or secure_enclave_floor(root, expected_uid)["minimum_protocol"] >= 2):
                raise AuthorizationError("execution_approval_migration_conflict")
            try:
                previous = protected_release_directory(
                    release.parent.parent / "previous" / "authorization_broker",
                    expected_uid,
                    allow_coordination_predecessor=True,
                )
            except (AuthorizationError, OSError) as error:
                raise AuthorizationError("execution_approval_migration_conflict") from error
            if previous.name != pending.get("host_release_id"):
                raise AuthorizationError("execution_approval_migration_conflict")
            rebound.pop("host_prepare_release_rebinding", None)
            rebound["host_prepare_release_rebindings"] = [*rebindings, {
                "from_host_release_id":pending["host_release_id"],
                "to_host_release_id":release.name,
                "rebound_at":current_time,
            }]
            rebound["host_release_id"] = release.name
            rebound_changed = True
        desired_research_release = value["parameters"]["research_release_id"]
        if pending and pending.get("research_release_id") != desired_research_release:
            if (len(research_rebindings) >= MAX_RESEARCH_PREPARE_RELEASE_REBINDS
                    or secure_enclave_floor(root, expected_uid)["minimum_protocol"] >= 2):
                raise AuthorizationError("execution_approval_migration_conflict")
            rebound["research_prepare_release_rebindings"] = [*research_rebindings, {
                "from_research_release_id":pending["research_release_id"],
                "to_research_release_id":desired_research_release,
                "rebound_at":current_time,
            }]
            rebound["research_release_id"] = desired_research_release
            rebound_changed = True
        if rebound_changed:
            if pending.get("phase") == "host_prepared":
                rebound["preparation_rebind_pending"] = {
                    "host_release_id":rebound["host_release_id"],
                    "research_release_id":rebound["research_release_id"],
                    "prior_preparation_attestation_sha256":pending[
                        "preparation_attestation_sha256"
                    ],
                    "requested_at":current_time,
                }
            atomic_receipt(pending_path, rebound)
            pending = rebound
        if pending:
            marker = pending.get("preparation_rebind_pending")
            if marker is not None and (
                    not isinstance(marker, dict)
                    or set(marker) != {
                        "host_release_id", "research_release_id",
                        "prior_preparation_attestation_sha256", "requested_at",
                    }
                    or marker.get("host_release_id") != pending.get("host_release_id")
                    or marker.get("research_release_id") != pending.get("research_release_id")
                    or marker.get("prior_preparation_attestation_sha256")
                    != pending.get("preparation_attestation_sha256")
                    or not isinstance(marker.get("requested_at"), int)
                    or isinstance(marker.get("requested_at"), bool)
                    or marker["requested_at"] < 1):
                raise AuthorizationError("execution_approval_migration_conflict")
    if not pending_path.exists():
        generation_id = str(uuid.uuid4())
        prior = active_secure_enclave_state(expected_uid, root)
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":str(uuid.uuid4()),
            "generation_id":generation_id,
            "generation_epoch":next_secure_enclave_epoch(root, expected_uid),
            "operator_uid":value["invoking_uid"],
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation_id,
            "access_group":expected_access_group,
            "algorithm":EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":release.name,
            "research_release_id":value["parameters"]["research_release_id"],
            "previous_generation_id": prior["generation_id"] if prior else None,
            "previous_generation_epoch": prior["generation_epoch"] if prior else None,
            "phase":"host_prepare_requested",
            "created_at":current_time,
            "prepared_host_boot":host_boot_identity(),
        }
        atomic_receipt(pending_path, pending)
    challenge = {
        "schema":"secure-sandbox-touchid-challenge-v2",
        "mode":"secure-enclave-prepare",
        "request_id":value["request_id"],
        "request_sha256":request_sha256,
        "transaction_id":pending["transaction_id"],
        "generation_id":pending["generation_id"],
        "generation_epoch":pending["generation_epoch"],
        "operator_uid":pending["operator_uid"],
        "application_tag":pending["application_tag"],
        "access_group":pending["access_group"],
        "algorithm":pending["algorithm"],
        "host_release_id":pending["host_release_id"],
        "research_release_id":pending["research_release_id"],
        "allow_creation":pending["phase"] == "host_prepare_requested",
    }
    if pending["phase"] == "host_prepared":
        challenge.update({
            "public_key_spki_der_b64":pending["public_key_spki_der_b64"],
            "public_key_sha256":pending["public_key_sha256"],
        })
    return challenge


def active_secure_enclave_state(expected_uid: int = 0,
                                root: Path = EXECUTION_APPROVAL_ROOT) -> dict[str, Any] | None:
    path = root / EXECUTION_APPROVAL_ACTIVE.name
    if not path.exists():
        return None
    value = read_secure_enclave_state(
        path, "secure-sandbox-execution-approval-key-v2", expected_uid
    )
    required = {
        "schema", "generation_id", "generation_epoch", "operator_uid",
        "application_tag", "access_group", "algorithm", "host_release_id",
        "research_release_id",
        "public_key_spki_der_b64", "public_key_sha256", "activated_at", "status",
    }
    access_group = value.get("access_group")
    if (set(value) != required or value.get("status") != "active"
            or value.get("algorithm") != EXECUTION_APPROVAL_V2_ALGORITHM
            or not isinstance(access_group, str)
            or re.fullmatch(r"[A-Z0-9]{10}\.[A-Za-z0-9][A-Za-z0-9.-]+", access_group) is None):
        raise AuthorizationError("execution_approval_state_invalid")
    spki = canonical_base64_decode(value["public_key_spki_der_b64"], "public_key", 256)
    if validate_p256_spki(spki) != value.get("public_key_sha256"):
        raise AuthorizationError("execution_approval_state_invalid")
    floor = secure_enclave_floor(root, expected_uid)
    if (floor["minimum_protocol"] >= 2
            and value["generation_epoch"] < floor["minimum_epoch"]):
        raise AuthorizationError("execution_approval_generation_below_floor")
    return value


def touchid_v2_challenge(value: dict[str, Any], request_sha256: str, release: Path,
                         expected_uid: int = 0) -> dict[str, Any]:
    if value["operation"] == "execution-approval-key-init":
        return prepare_secure_enclave_challenge(
            value, request_sha256, release, expected_uid
        )
    active = active_secure_enclave_state(expected_uid)
    if value["operation"] == "execution-approval-sign" and active is not None:
        if active["access_group"] != touchid_signing_policy(release)["access_group"]:
            raise AuthorizationError("execution_approval_state_invalid")
        if active["operator_uid"] != value["invoking_uid"]:
            raise AuthorizationError("execution_approval_operator_mismatch")
        return {
            "schema":"secure-sandbox-touchid-challenge-v2",
            "mode":"secure-enclave-sign",
            "request_id":value["request_id"],
            "request_sha256":request_sha256,
            "generation_id":active["generation_id"],
            "generation_epoch":active["generation_epoch"],
            "operator_uid":active["operator_uid"],
            "application_tag":active["application_tag"],
            "access_group":active["access_group"],
            "algorithm":active["algorithm"],
            "host_release_id":release.name,
            "research_release_id":active["research_release_id"],
            "public_key_spki_der_b64":active["public_key_spki_der_b64"],
            "public_key_sha256":active["public_key_sha256"],
        }
    if (value["operation"] == "execution-approval-sign"
            and secure_enclave_floor(EXECUTION_APPROVAL_ROOT, expected_uid)["minimum_protocol"] >= 2):
        raise AuthorizationError("execution_approval_v2_authority_unavailable")
    return {
        "schema":"secure-sandbox-touchid-challenge-v2",
        "mode":"legacy-touch-id",
        "request_id":value["request_id"],
        "request_sha256":request_sha256,
        "host_release_id":release.name,
    }


def touchid_ui_bundle_sha256(release: Path) -> str:
    try:
        manifest = json.loads(
            (release / "manifest.json").read_text(encoding="utf-8")
        )
        digest = manifest["payloads"]["authorization_ui_bundle"]
    except (OSError, UnicodeDecodeError, KeyError, TypeError,
            json.JSONDecodeError) as error:
        raise AuthorizationError("authorization_release_identity_invalid") from error
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise AuthorizationError("authorization_release_identity_invalid")
    return digest


def cancellation_only_challenge(value: dict[str, Any], request_sha256: str,
                                release: Path) -> dict[str, Any]:
    """Build the cancellation ceremony without consulting or mutating operation state."""
    return {
        "schema":"secure-sandbox-touchid-challenge-v2",
        "mode":"cancel-only",
        "request_id":value["request_id"],
        "request_sha256":request_sha256,
        "host_release_id":release.name,
        "authorization_ui_bundle_sha256":touchid_ui_bundle_sha256(release),
    }


def verify_secure_enclave_preparation(final: dict[str, Any], challenge: dict[str, Any],
                                      now: int | None = None,
                                      expected_uid: int = 0) -> dict[str, Any]:
    if set(final) != {"schema", "attestation", "signature_der_b64"} or final.get(
        "schema"
    ) != "secure-sandbox-execution-approval-preparation-envelope-v2":
        raise AuthorizationError("execution_approval_preparation_invalid")
    attestation = final.get("attestation")
    expected = {
        "schema":"secure-sandbox-execution-approval-preparation-v2",
        "authorization_request_id":challenge["request_id"],
        "authorization_request_sha256":challenge["request_sha256"],
        "transaction_id":challenge["transaction_id"],
        "generation_id":challenge["generation_id"],
        "generation_epoch":challenge["generation_epoch"],
        "operator_uid":challenge["operator_uid"],
        "application_tag":challenge["application_tag"],
        "access_group":challenge["access_group"],
        "algorithm":challenge["algorithm"],
        "host_release_id":challenge["host_release_id"],
        "research_release_id":challenge["research_release_id"],
    }
    if (not isinstance(attestation, dict)
            or set(attestation) != set(expected) | {
                "public_key_spki_der_b64", "public_key_sha256", "prepared_at"
            }
            or any(attestation.get(name) != expected_value
                   for name, expected_value in expected.items())
            or not isinstance(attestation.get("prepared_at"), int)
            or isinstance(attestation.get("prepared_at"), bool)
            or abs((int(time.time()) if now is None else now) - attestation["prepared_at"]) > 180):
        raise AuthorizationError("execution_approval_preparation_invalid")
    spki = canonical_base64_decode(attestation["public_key_spki_der_b64"], "public_key", 256)
    if validate_p256_spki(spki) != attestation.get("public_key_sha256"):
        raise AuthorizationError("execution_approval_preparation_invalid")
    signature = canonical_base64_decode(final["signature_der_b64"], "signature", 128)
    verify_p256_signature(spki, canonical_v2(attestation), signature)
    pending_path = EXECUTION_APPROVAL_ROOT / EXECUTION_APPROVAL_PENDING.name
    pending = read_secure_enclave_state(
        pending_path, "secure-sandbox-execution-approval-migration-v2", expected_uid
    )
    for name in ("transaction_id", "generation_id", "generation_epoch", "operator_uid",
                 "application_tag", "access_group", "algorithm", "host_release_id",
                 "research_release_id"):
        if pending.get(name) != attestation.get(name):
            raise AuthorizationError("execution_approval_migration_conflict")
    if pending.get("phase") not in {"host_prepare_requested", "host_prepared"}:
        raise AuthorizationError("execution_approval_migration_conflict")
    if pending["phase"] == "host_prepared":
        if (pending.get("public_key_spki_der_b64")
                != attestation["public_key_spki_der_b64"]
                or pending.get("public_key_sha256") != attestation["public_key_sha256"]):
            raise AuthorizationError("execution_approval_key_substitution")
        if "preparation_rebind_pending" in pending:
            prepared = dict(pending)
            prepared.pop("preparation_rebind_pending")
            prepared.update({
                "prepared_at":attestation["prepared_at"],
                "preparation_attestation_sha256":hashlib.sha256(
                    canonical_v2(attestation)
                ).hexdigest(),
            })
            atomic_receipt(pending_path, prepared)
        else:
            prepared = pending
    else:
        prepared = dict(pending)
        prepared.update({
            "phase":"host_prepared",
            "prepared_at":attestation["prepared_at"],
            "public_key_spki_der_b64":attestation["public_key_spki_der_b64"],
            "public_key_sha256":attestation["public_key_sha256"],
            "preparation_attestation_sha256":hashlib.sha256(canonical_v2(attestation)).hexdigest(),
        })
        atomic_receipt(pending_path, prepared)
    return {
        "schema":"secure-sandbox-execution-approval-key-v2",
        "status":"prepared",
        "transaction_id":prepared["transaction_id"],
        "generation_id":prepared["generation_id"],
        "generation_epoch":prepared["generation_epoch"],
        "operator_uid":prepared["operator_uid"],
        "algorithm":prepared["algorithm"],
        "host_release_id":prepared["host_release_id"],
        "research_release_id":prepared["research_release_id"],
        "previous_generation_id":prepared["previous_generation_id"],
        "previous_generation_epoch":prepared["previous_generation_epoch"],
        "public_key_spki_der_b64":prepared["public_key_spki_der_b64"],
        "public_key_sha256":prepared["public_key_sha256"],
        "preparation_attestation_sha256":prepared["preparation_attestation_sha256"],
    }


def verify_secure_enclave_execution(final: dict[str, Any], challenge: dict[str, Any],
                                    value: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    if (set(final) != {"schema", "attestation", "signature_der_b64"}
            or final.get("schema") != EXECUTION_APPROVAL_V2_ENVELOPE):
        raise AuthorizationError("execution_approval_envelope_invalid")
    attestation = final.get("attestation")
    required = {
        "schema", "approval", "approval_request_sha256", "authorization_request_id",
        "host_release_id", "approved_at", "key_generation_id",
        "key_generation_epoch", "public_key_sha256", "signature_algorithm",
    }
    parameters = value["parameters"]
    if (not isinstance(attestation, dict) or set(attestation) != required
            or attestation.get("schema") != EXECUTION_APPROVAL_V2_ATTESTATION
            or attestation.get("approval") != parameters
            or attestation.get("approval_request_sha256")
            != hashlib.sha256(canonical(parameters)).hexdigest()
            or attestation.get("authorization_request_id") != challenge["request_id"]
            or attestation.get("host_release_id") != challenge["host_release_id"]
            or attestation.get("key_generation_id") != challenge["generation_id"]
            or attestation.get("key_generation_epoch") != challenge["generation_epoch"]
            or attestation.get("public_key_sha256") != challenge["public_key_sha256"]
            or attestation.get("signature_algorithm") != EXECUTION_APPROVAL_V2_ALGORITHM
            or not isinstance(attestation.get("approved_at"), int)
            or isinstance(attestation.get("approved_at"), bool)
            or not parameters["created_at"] <= attestation["approved_at"] <= parameters["expires_at"]
            or (int(time.time()) if now is None else now) > parameters["expires_at"]):
        raise AuthorizationError("execution_approval_envelope_invalid")
    spki = canonical_base64_decode(challenge["public_key_spki_der_b64"], "public_key", 256)
    signature = canonical_base64_decode(final["signature_der_b64"], "signature", 128)
    verify_p256_signature(spki, canonical_v2(attestation), signature)
    return final


def validate_research_transition_proof(proof: object, pending: dict[str, Any],
                                       status: str, expected_prior_phase: str) -> str:
    required = {
        "schema", "status", "transaction_id", "generation_id", "generation_epoch",
        "previous_generation_id", "previous_generation_epoch", "operator_uid",
        "algorithm", "public_key_sha256", "host_release_id", "research_release_id",
        "expected_prior_phase", "prior_record_sha256", "journal_sha256",
        "phase_receipt_sha256",
        "acceptance_binding_sha256",
    }
    if (not isinstance(proof, dict) or set(proof) != required
            or proof.get("schema") != "secure-sandbox-execution-approval-transition-result-v2"
            or proof.get("status") != status
            or proof.get("expected_prior_phase") != expected_prior_phase
            or not isinstance(proof.get("journal_sha256"), str)
            or not SHA256.fullmatch(proof["journal_sha256"])
            or not isinstance(proof.get("phase_receipt_sha256"), str)
            or not SHA256.fullmatch(proof["phase_receipt_sha256"])
            or (proof.get("prior_record_sha256") is not None
                and (not isinstance(proof["prior_record_sha256"], str)
                     or not SHA256.fullmatch(proof["prior_record_sha256"])))
            or (proof.get("acceptance_binding_sha256") is not None
                and (not isinstance(proof["acceptance_binding_sha256"], str)
                     or not SHA256.fullmatch(proof["acceptance_binding_sha256"])))):
        raise AuthorizationError(f"research_{status}_invalid")
    for name in (
        "transaction_id", "generation_id", "generation_epoch", "previous_generation_id",
        "previous_generation_epoch", "operator_uid", "algorithm", "public_key_sha256",
        "host_release_id", "research_release_id",
    ):
        if proof.get(name) != pending.get(name):
            raise AuthorizationError("execution_approval_migration_conflict")
    return hashlib.sha256(canonical_v2(proof)).hexdigest()


def validate_acceptance_attempt(value: object, transaction_id: str) -> dict[str, Any]:
    required = {
        "transaction_id", "generation_id", "generation_epoch",
        "acceptance_attempt_id", "acceptance_attempt_number",
        "previous_acceptance_binding_sha256", "run_id", "session_id", "source_id",
        "code_sha256", "fixture_manifest_sha256", "timeout_seconds",
        "runtime_image_id", "expires_at",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise AuthorizationError("execution_approval_acceptance_attempt_invalid")
    if value.get("transaction_id") != transaction_id:
        raise AuthorizationError("execution_approval_acceptance_attempt_invalid")
    for name in ("transaction_id", "generation_id", "acceptance_attempt_id",
                 "run_id", "session_id", "source_id"):
        valid_uuid4(value.get(name), name)
    prior = value.get("previous_acceptance_binding_sha256")
    if (not isinstance(value.get("generation_epoch"), int)
            or isinstance(value.get("generation_epoch"), bool)
            or value["generation_epoch"] < 1
            or not isinstance(value.get("acceptance_attempt_number"), int)
            or isinstance(value.get("acceptance_attempt_number"), bool)
            or value["acceptance_attempt_number"] < 1
            or (prior is not None and (
                not isinstance(prior, str) or SHA256.fullmatch(prior) is None
            ))
            or any(not isinstance(value.get(name), str) or SHA256.fullmatch(value[name]) is None
                   for name in ("code_sha256", "fixture_manifest_sha256"))
            or not isinstance(value.get("timeout_seconds"), int)
            or isinstance(value.get("timeout_seconds"), bool)
            or not 1 <= value["timeout_seconds"] <= 10
            or not isinstance(value.get("runtime_image_id"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value["runtime_image_id"]) is None
            or not isinstance(value.get("expires_at"), int)
            or isinstance(value.get("expires_at"), bool)):
        raise AuthorizationError("execution_approval_acceptance_attempt_invalid")
    return value


def acceptance_attempt_binding(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def execution_approval_authorize_acceptance(
    transaction_id: str, acceptance: dict[str, Any],
    root: Path = EXECUTION_APPROVAL_ROOT, expected_uid: int = 0,
    now: int | None = None,
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    valid_uuid4(transaction_id, "transaction_id")
    acceptance = validate_acceptance_attempt(acceptance, transaction_id)
    root = secure_enclave_state_root(root, expected_uid)
    pending_path = root / EXECUTION_APPROVAL_PENDING.name
    pending = read_secure_enclave_state(
        pending_path, "secure-sandbox-execution-approval-migration-v2", expected_uid
    )
    if (pending.get("transaction_id") != transaction_id
            or pending.get("phase") != "host_activated"
            or acceptance.get("generation_id") != pending.get("generation_id")
            or acceptance.get("generation_epoch") != pending.get("generation_epoch")):
        raise AuthorizationError("execution_approval_migration_conflict")
    if (root / "acceptance-verifier.json").exists():
        raise AuthorizationError("execution_approval_acceptance_already_verified")
    prior_number = pending.get("acceptance_attempt_number", 0)
    prior_binding = pending.get("acceptance_binding_sha256")
    binding = acceptance_attempt_binding(acceptance)
    attempts = root / "acceptance-attempts"
    if (acceptance["acceptance_attempt_number"] == prior_number
            and binding == prior_binding):
        artifact = attempts / f"{transaction_id}.{prior_number}.json"
        existing = read_secure_enclave_state(
            artifact, "secure-sandbox-execution-approval-acceptance-authorization-v1",
            expected_uid,
        )
        if (existing.get("acceptance_attempt_id") != acceptance["acceptance_attempt_id"]
                or existing.get("acceptance_binding_sha256") != binding):
            raise AuthorizationError("execution_approval_acceptance_history_conflict")
        return existing
    if (acceptance["acceptance_attempt_number"] != prior_number + 1
            or acceptance.get("previous_acceptance_binding_sha256") != prior_binding):
        raise AuthorizationError("execution_approval_acceptance_attempt_conflict")
    current_time = int(time.time()) if now is None else now
    try:
        attempts.mkdir(mode=0o700)
        fsync_directory(root)
    except FileExistsError:
        pass
    info = attempts.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise AuthorizationError("execution_approval_acceptance_history_untrusted")
    expected_authorization = {
        "schema":"secure-sandbox-execution-approval-acceptance-authorization-v1",
        "status":"authorized", "transaction_id":transaction_id,
        "generation_id":pending["generation_id"],
        "generation_epoch":pending["generation_epoch"],
        "algorithm":pending["algorithm"],
        "public_key_sha256":pending["public_key_sha256"],
        "operator_uid":pending["operator_uid"],
        "previous_generation_id":pending["previous_generation_id"],
        "previous_generation_epoch":pending["previous_generation_epoch"],
        "acceptance_attempt_id":acceptance["acceptance_attempt_id"],
        "acceptance_attempt_number":acceptance["acceptance_attempt_number"],
        "previous_acceptance_binding_sha256":acceptance["previous_acceptance_binding_sha256"],
        "acceptance_binding_sha256":binding,
        "host_release_id":pending["host_release_id"],
        "research_release_id":pending["research_release_id"],
    }
    artifact = attempts / (
        f"{transaction_id}.{acceptance['acceptance_attempt_number']}.json"
    )
    if artifact.exists():
        existing = read_secure_enclave_state(
            artifact, expected_authorization["schema"], expected_uid
        )
        if (set(existing) != {*expected_authorization, "authorized_at"}
                or any(existing.get(name) != value
                       for name, value in expected_authorization.items())
                or not isinstance(existing.get("authorized_at"), int)
                or isinstance(existing.get("authorized_at"), bool)
                or existing["authorized_at"] < 1
                or existing["authorized_at"] >= acceptance["expires_at"]
                or acceptance["expires_at"] > existing["authorized_at"] + 3600):
            raise AuthorizationError("execution_approval_acceptance_history_conflict")
        result = existing
    else:
        if (acceptance["expires_at"] <= current_time
                or acceptance["expires_at"] > current_time + 3600):
            return {
                **expected_authorization,
                "status":"not_issued_expired",
                "authorized_at":current_time,
            }
        result = {**expected_authorization, "authorized_at":current_time}
        atomic_receipt(artifact, result)
    updated = dict(pending)
    updated.update({
        "acceptance_attempt_id":acceptance["acceptance_attempt_id"],
        "acceptance_attempt_number":acceptance["acceptance_attempt_number"],
        "acceptance_binding_sha256":binding,
    })
    atomic_receipt(pending_path, updated)
    return result


def execution_approval_migration_activate(transaction_id: str,
                                            research_fence: dict[str, Any],
                                            root: Path = EXECUTION_APPROVAL_ROOT,
                                            expected_uid: int = 0,
                                            now: int | None = None) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    valid_uuid4(transaction_id, "transaction_id")
    root = secure_enclave_state_root(root, expected_uid)
    pending_path = root / EXECUTION_APPROVAL_PENDING.name
    pending = read_secure_enclave_state(
        pending_path, "secure-sandbox-execution-approval-migration-v2", expected_uid
    )
    if (pending.get("transaction_id") != transaction_id
            or pending.get("phase") not in {"host_prepared", "host_activated"}):
        raise AuthorizationError("execution_approval_migration_conflict")
    research_fence_sha256 = validate_research_transition_proof(
        research_fence, pending, "fenced", "prepared"
    )
    if (pending.get("phase") == "host_activated"
            and pending.get("research_fence_sha256") != research_fence_sha256):
        raise AuthorizationError("execution_approval_migration_conflict")
    current_time = int(time.time()) if now is None else now
    active = {
        "schema":"secure-sandbox-execution-approval-key-v2",
        "generation_id":pending["generation_id"],
        "generation_epoch":pending["generation_epoch"],
        "operator_uid":pending["operator_uid"],
        "application_tag":pending["application_tag"],
        "access_group":pending["access_group"],
        "algorithm":pending["algorithm"],
        "host_release_id":pending["host_release_id"],
        "research_release_id":pending["research_release_id"],
        "public_key_spki_der_b64":pending["public_key_spki_der_b64"],
        "public_key_sha256":pending["public_key_sha256"],
        "activated_at":pending.get("activated_at", current_time),
        "status":"active",
    }
    floor = secure_enclave_floor(root, expected_uid)
    if (floor["minimum_protocol"] > 2
            or floor["minimum_epoch"] > pending["generation_epoch"]):
        raise AuthorizationError("execution_approval_generation_below_floor")
    existing = active_secure_enclave_state(expected_uid, root)
    if existing is not None:
        if existing["generation_id"] == active["generation_id"]:
            active["activated_at"] = existing["activated_at"]
            if existing != active:
                raise AuthorizationError("execution_approval_active_generation_conflict")
        elif existing["generation_epoch"] >= active["generation_epoch"]:
            raise AuthorizationError("execution_approval_active_generation_conflict")
    public = {
        "schema":"secure-sandbox-execution-approval-key-v2",
        "status":"active",
        "generation_id":active["generation_id"],
        "generation_epoch":active["generation_epoch"],
        "algorithm":active["algorithm"],
        "public_key_spki_der_b64":active["public_key_spki_der_b64"],
        "public_key_sha256":active["public_key_sha256"],
    }
    private_floor = {
        "schema":"secure-sandbox-execution-approval-floor-v1",
        "minimum_protocol":2,
        "minimum_epoch":pending["generation_epoch"],
        "updated_at":current_time,
    }
    public_floor = {
        "schema":"secure-sandbox-execution-approval-public-floor-v1",
        "minimum_protocol":2,
        "minimum_epoch":pending["generation_epoch"],
        "generation_id":pending["generation_id"],
        "public_key_sha256":pending["public_key_sha256"],
    }
    if floor["minimum_protocol"] < 2:
        atomic_receipt(root / EXECUTION_APPROVAL_FLOOR.name, private_floor)
        atomic_public_record(root / EXECUTION_APPROVAL_PUBLIC_FLOOR.name, public_floor)
    atomic_receipt(root / EXECUTION_APPROVAL_ACTIVE.name, active)
    atomic_public_record(root / EXECUTION_APPROVAL_PUBLIC.name, public)
    if floor["minimum_protocol"] >= 2:
        atomic_receipt(root / EXECUTION_APPROVAL_FLOOR.name, private_floor)
        atomic_public_record(root / EXECUTION_APPROVAL_PUBLIC_FLOOR.name, public_floor)
    updated = dict(pending)
    updated.update({
        "phase":"host_activated",
        "activated_at":active["activated_at"],
        "research_fence_sha256":research_fence_sha256,
        "prior_record_sha256":research_fence["prior_record_sha256"],
        "phase_receipt_sha256":research_fence["phase_receipt_sha256"],
        "acceptance_binding_sha256":research_fence["acceptance_binding_sha256"],
    })
    atomic_receipt(pending_path, updated)
    return {
        "schema":"secure-sandbox-execution-approval-migration-result-v2",
        "status":"host_activated",
        "transaction_id":transaction_id,
        "generation_id":active["generation_id"],
        "generation_epoch":active["generation_epoch"],
        "algorithm":active["algorithm"],
        "public_key_sha256":active["public_key_sha256"],
        "operator_uid":active["operator_uid"],
        "host_release_id":active["host_release_id"],
        "research_release_id":active["research_release_id"],
        "previous_generation_id":pending["previous_generation_id"],
        "previous_generation_epoch":pending["previous_generation_epoch"],
        "research_fence_sha256":research_fence_sha256,
    }


def execution_approval_migration_commit(transaction_id: str,
                                         research_activation: dict[str, Any],
                                         cold_boot_acceptance_sha256: str,
                                         acceptance_verifier_sha256: str,
                                         root: Path = EXECUTION_APPROVAL_ROOT,
                                         expected_uid: int = 0,
                                         now: int | None = None) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    valid_uuid4(transaction_id, "transaction_id")
    if not SHA256.fullmatch(cold_boot_acceptance_sha256):
        raise AuthorizationError("execution_approval_migration_evidence_invalid")
    if not SHA256.fullmatch(acceptance_verifier_sha256):
        raise AuthorizationError("execution_approval_migration_evidence_invalid")
    pending_path = root / EXECUTION_APPROVAL_PENDING.name
    pending = read_secure_enclave_state(
        pending_path, "secure-sandbox-execution-approval-migration-v2", expected_uid
    )
    active = active_secure_enclave_state(expected_uid, root)
    if (pending.get("transaction_id") != transaction_id
            or pending.get("phase") not in {"host_activated", "committed", "software_retired"}
            or active is None
            or active["generation_id"] != pending.get("generation_id")
            or active["generation_epoch"] != pending.get("generation_epoch")):
        raise AuthorizationError("execution_approval_migration_conflict")
    acceptance_attempt_number = pending.get("acceptance_attempt_number")
    if (not isinstance(acceptance_attempt_number, int)
            or isinstance(acceptance_attempt_number, bool)
            or acceptance_attempt_number < 1):
        raise AuthorizationError("execution_approval_acceptance_attempt_invalid")
    # The first acceptance advances active -> acceptance.  Every append-only
    # replacement advances acceptance -> acceptance and must retain that exact
    # predecessor in the Research proof rather than masquerading as attempt 1.
    acceptance_prior_phase = (
        "active" if acceptance_attempt_number == 1 else "acceptance"
    )
    research_activation_sha256 = validate_research_transition_proof(
        research_activation, pending, "acceptance", acceptance_prior_phase
    )
    verifier = read_secure_enclave_state(
        root / "acceptance-verifier.json",
        "secure-sandbox-execution-approval-acceptance-verifier-v1", expected_uid,
    )
    recorded_verifier_sha256 = verifier.get("verifier_sha256")
    unsigned_verifier = dict(verifier)
    unsigned_verifier.pop("verifier_sha256", None)
    if (recorded_verifier_sha256 != acceptance_verifier_sha256
            or recorded_verifier_sha256 != hashlib.sha256(
                canonical_v2(unsigned_verifier)
            ).hexdigest()
            or any(verifier.get(name) != pending.get(name) for name in (
                "transaction_id", "generation_id", "generation_epoch",
                "host_release_id", "research_release_id",
            ))
            or verifier.get("acceptance_binding_sha256")
            != research_activation.get("acceptance_binding_sha256")
            or not isinstance(pending.get("prepared_host_boot"), str)
            or not pending["prepared_host_boot"]
            or verifier.get("prepared_host_boot_sha256")
            != hashlib.sha256(str(pending.get("prepared_host_boot", "")).encode("ascii")).hexdigest()
            or verifier.get("prepared_host_boot_sha256")
            == verifier.get("verified_host_boot_sha256")):
        raise AuthorizationError("execution_approval_acceptance_verifier_invalid")
    if pending.get("phase") in {"committed", "software_retired"} and (
            pending.get("research_activation_sha256") != research_activation_sha256
            or pending.get("cold_boot_acceptance_sha256") != cold_boot_acceptance_sha256
            or pending.get("acceptance_verifier_sha256") != acceptance_verifier_sha256):
        raise AuthorizationError("execution_approval_migration_conflict")
    updated = dict(pending)
    updated.update({
        "phase":"committed",
        "committed_at":pending.get("committed_at", int(time.time()) if now is None else now),
        "research_activation_sha256":research_activation_sha256,
        "cold_boot_acceptance_sha256":cold_boot_acceptance_sha256,
        "acceptance_verifier_sha256":acceptance_verifier_sha256,
        "prior_record_sha256":research_activation["prior_record_sha256"],
        "phase_receipt_sha256":research_activation["phase_receipt_sha256"],
        "acceptance_binding_sha256":research_activation["acceptance_binding_sha256"],
    })
    if pending.get("phase") != "software_retired":
        atomic_receipt(pending_path, updated)
        completion_pending = updated
    else:
        completion_pending = pending
    publish_completion_receipt(completion_pending, verifier, root, expected_uid)
    return {
        "schema":"secure-sandbox-execution-approval-migration-result-v2",
        "status":"committed",
        "transaction_id":transaction_id,
        "generation_id":active["generation_id"],
        "generation_epoch":active["generation_epoch"],
        "algorithm":active["algorithm"],
        "public_key_sha256":active["public_key_sha256"],
        "operator_uid":active["operator_uid"],
        "host_release_id":active["host_release_id"],
        "research_release_id":active["research_release_id"],
        "previous_generation_id":pending["previous_generation_id"],
        "previous_generation_epoch":pending["previous_generation_epoch"],
        "research_activation_sha256":research_activation_sha256,
        "cold_boot_acceptance_sha256":cold_boot_acceptance_sha256,
        "acceptance_verifier_sha256":acceptance_verifier_sha256,
    }


def execution_approval_acceptance_verify(
    research_evidence: dict[str, Any], root: Path = EXECUTION_APPROVAL_ROOT,
    receipt_root: Path = DEFAULT_RECEIPT_ROOT, expected_uid: int = 0,
    now: int | None = None,
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    required = {
        "schema", "status", "transaction_id", "generation_id", "generation_epoch",
        "host_release_id", "research_release_id", "run_id", "session_id", "approval_id",
        "acceptance_attempt_id", "acceptance_attempt_number",
        "approval_attestation_sha256", "research_receipt_id", "research_receipt_sha256",
        "consumed_marker_sha256", "acceptance_binding_sha256", "verified_at",
    }
    if (not isinstance(research_evidence, dict) or set(research_evidence) != required
            or research_evidence.get("schema")
            != "secure-sandbox-execution-approval-acceptance-evidence-v1"
            or research_evidence.get("status") != "verified"
            or not isinstance(research_evidence.get("generation_epoch"), int)
            or isinstance(research_evidence.get("generation_epoch"), bool)
            or research_evidence["generation_epoch"] < 1
            or not isinstance(research_evidence.get("acceptance_attempt_number"), int)
            or isinstance(research_evidence.get("acceptance_attempt_number"), bool)
            or research_evidence["acceptance_attempt_number"] < 1
            or not isinstance(research_evidence.get("verified_at"), int)
            or isinstance(research_evidence.get("verified_at"), bool)
            or research_evidence["verified_at"] < 1):
        raise AuthorizationError("execution_approval_acceptance_invalid")
    for name in (
        "transaction_id", "generation_id", "run_id", "session_id", "approval_id",
        "acceptance_attempt_id",
        "research_receipt_id",
    ):
        valid_uuid4(research_evidence[name], name)
    for name in (
        "host_release_id", "research_release_id", "approval_attestation_sha256",
        "research_receipt_sha256", "consumed_marker_sha256", "acceptance_binding_sha256",
    ):
        if not isinstance(research_evidence.get(name), str) or not SHA256.fullmatch(research_evidence[name]):
            raise AuthorizationError("execution_approval_acceptance_invalid")
    active = active_secure_enclave_state(expected_uid, root)
    pending = read_secure_enclave_state(
        root / EXECUTION_APPROVAL_PENDING.name,
        "secure-sandbox-execution-approval-migration-v2", expected_uid,
    )
    if (active is None or pending.get("phase") not in {
            "host_activated", "committed", "software_retired"
        }
            or any(research_evidence.get(name) != pending.get(name) for name in (
                "transaction_id", "generation_id", "generation_epoch",
                "host_release_id", "research_release_id",
            ))
            or research_evidence.get("acceptance_attempt_number")
            != pending.get("acceptance_attempt_number")
            or research_evidence.get("acceptance_attempt_id")
            != pending.get("acceptance_attempt_id")
            or research_evidence.get("acceptance_binding_sha256")
            != pending.get("acceptance_binding_sha256")):
        raise AuthorizationError("execution_approval_acceptance_conflict")
    prepared_host_boot = pending.get("prepared_host_boot")
    artifact = root / "acceptance-verifier.json"
    if artifact.exists():
        existing = read_secure_enclave_state(
            artifact, "secure-sandbox-execution-approval-acceptance-verifier-v1", expected_uid,
        )
        recorded = existing.get("verifier_sha256")
        unsigned = dict(existing)
        unsigned.pop("verifier_sha256", None)
        if (not isinstance(recorded, str) or not SHA256.fullmatch(recorded)
                or recorded != hashlib.sha256(canonical_v2(unsigned)).hexdigest()
                or any(existing.get(name) != research_evidence.get(name) for name in (
                    "transaction_id", "generation_id", "generation_epoch", "host_release_id",
                    "research_release_id", "run_id", "session_id", "approval_id",
                    "acceptance_attempt_id", "acceptance_attempt_number",
                    "approval_attestation_sha256", "research_receipt_id",
                    "research_receipt_sha256", "consumed_marker_sha256",
                    "acceptance_binding_sha256",
                ))
                or not isinstance(prepared_host_boot, str) or not prepared_host_boot
                or existing.get("prepared_host_boot_sha256")
                != hashlib.sha256(str(prepared_host_boot).encode("ascii")).hexdigest()
                or existing.get("prepared_host_boot_sha256")
                == existing.get("verified_host_boot_sha256")):
            raise AuthorizationError("execution_approval_acceptance_verifier_invalid")
        return existing
    verified_host_boot = host_boot_identity()
    if (not isinstance(prepared_host_boot, str) or not prepared_host_boot
            or prepared_host_boot == verified_host_boot):
        raise AuthorizationError("actual_host_reboot_required")
    approval_id = valid_uuid4(research_evidence["approval_id"], "approval_id")
    matches = []
    for receipt_path in receipt_root.iterdir():
        if re.fullmatch(r"[0-9a-f-]{36}\.json", receipt_path.name):
            candidate = read_secure_enclave_state(receipt_path, RECEIPT_SCHEMA, expected_uid)
            if (candidate.get("operation") == "execution-approval-sign"
                    and candidate.get("approval_id") == approval_id):
                matches.append(candidate)
    if len(matches) != 1:
        raise AuthorizationError("execution_approval_acceptance_receipt_ambiguous")
    receipt = matches[0]
    if (receipt.get("status") != "succeeded" or receipt.get("outcome") != "approved"
            or receipt.get("approval_id") != approval_id
            or receipt.get("approval_key_generation_id") != active["generation_id"]
            or receipt.get("approval_key_generation_epoch") != active["generation_epoch"]
            or receipt.get("approval_public_key_sha256") != active["public_key_sha256"]
            or receipt.get("approval_signature_algorithm") != active["algorithm"]
            or receipt.get("approval_attestation_sha256")
            != research_evidence["approval_attestation_sha256"]):
        raise AuthorizationError("execution_approval_acceptance_receipt_mismatch")
    result = {
        "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
        "status":"verified", **{name:research_evidence[name] for name in (
            "transaction_id", "generation_id", "generation_epoch", "host_release_id",
            "research_release_id", "run_id", "session_id", "approval_id",
            "acceptance_attempt_id", "acceptance_attempt_number",
            "approval_attestation_sha256", "research_receipt_id", "research_receipt_sha256",
            "consumed_marker_sha256", "acceptance_binding_sha256",
        )},
        "host_receipt_sha256":hashlib.sha256(canonical(receipt)).hexdigest(),
        "prepared_host_boot_sha256":hashlib.sha256(
            prepared_host_boot.encode("ascii")
        ).hexdigest(),
        "verified_host_boot_sha256":hashlib.sha256(
            verified_host_boot.encode("ascii")
        ).hexdigest(),
        "verified_at":int(time.time()) if now is None else now,
    }
    result["verifier_sha256"] = hashlib.sha256(canonical_v2(result)).hexdigest()
    atomic_receipt(artifact, result)
    return result


def execution_approval_software_retire(transaction_id: str,
                                       root: Path = EXECUTION_APPROVAL_ROOT,
                                       key: Path = EXECUTION_APPROVAL_KEY,
                                       expected_uid: int = 0,
                                       now: int | None = None) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise AuthorizationError("root_required")
    valid_uuid4(transaction_id, "transaction_id")
    pending = read_secure_enclave_state(
        root / EXECUTION_APPROVAL_PENDING.name,
        "secure-sandbox-execution-approval-migration-v2", expected_uid,
    )
    active = active_secure_enclave_state(expected_uid, root)
    if (pending.get("transaction_id") != transaction_id
            or pending.get("phase") not in {"committed", "software_retired"}
            or active is None):
        raise AuthorizationError("execution_approval_migration_conflict")
    for path in (key, key.with_suffix(".pub")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != expected_uid or info.st_nlink != 1):
            raise AuthorizationError("execution_approval_software_key_untrusted")
        path.unlink()
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    updated = dict(pending)
    updated.update({
        "phase":"software_retired",
        "software_retired_at":pending.get(
            "software_retired_at", int(time.time()) if now is None else now
        ),
    })
    atomic_receipt(root / EXECUTION_APPROVAL_PENDING.name, updated)
    verifier = read_secure_enclave_state(
        root / "acceptance-verifier.json",
        "secure-sandbox-execution-approval-acceptance-verifier-v1", expected_uid,
    )
    publish_completion_receipt(updated, verifier, root, expected_uid)
    return {
        "schema":"secure-sandbox-execution-approval-migration-result-v2",
        "status":"software_retired",
        "transaction_id":transaction_id,
        "generation_id":active["generation_id"],
        "generation_epoch":active["generation_epoch"],
        "algorithm":active["algorithm"],
        "public_key_sha256":active["public_key_sha256"],
        "operator_uid":active["operator_uid"],
        "host_release_id":active["host_release_id"],
        "research_release_id":active["research_release_id"],
        "previous_generation_id":pending["previous_generation_id"],
        "previous_generation_epoch":pending["previous_generation_epoch"],
    }


def peer_audit_identity(connection: socket.socket) -> tuple[int, bytes, Path]:
    try:
        token = connection.getsockopt(0, 0x006, 32)  # SOL_LOCAL, LOCAL_PEERTOKEN
    except OSError as error:
        raise AuthorizationError("touchid_peer_token_unavailable") from error
    if len(token) != 32:
        raise AuthorizationError("touchid_peer_token_invalid")
    fields = struct.unpack("=8I", token)
    effective_uid = fields[1]
    if effective_uid <= 0:
        raise AuthorizationError("touchid_peer_uid_invalid")
    audit_token = (ctypes.c_uint32 * 8).from_buffer_copy(token)
    buffer = ctypes.create_string_buffer(4096)
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = libproc.proc_pidpath_audittoken
    function.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p, ctypes.c_uint32]
    function.restype = ctypes.c_int
    if function(audit_token, buffer, len(buffer)) <= 0:
        raise AuthorizationError("touchid_peer_path_unavailable")
    try:
        path = Path(buffer.value.decode("utf-8")).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as error:
        raise AuthorizationError("touchid_peer_path_invalid") from error
    return effective_uid, token, path


def verify_touchid_peer(process_path: Path, release: Path, expected_uid: int = 0) -> None:
    bundle = (release / TOUCHID_UI_APP_NAME).resolve(strict=True)
    expected = (bundle / TOUCHID_UI_EXECUTABLE).resolve(strict=True)
    try:
        info = expected.lstat()
    except OSError as error:
        raise AuthorizationError("touchid_ui_missing") from error
    if (process_path != expected or expected.is_symlink() or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o555):
        raise AuthorizationError("touchid_peer_identity_mismatch")
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(bundle)],
        check=False, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(bundle)],
        check=False, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(bundle)],
        check=False, capture_output=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    try:
        entitlement_value = plistlib.loads(entitlements.stdout)
    except plistlib.InvalidFileException as error:
        raise AuthorizationError("touchid_ui_entitlements_invalid") from error
    policy = touchid_signing_policy(release)
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
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if (verified.returncode != 0 or details.returncode != 0
            or requirement.returncode != 0 or entitlements.returncode != 0
            or "runtime" not in details.stderr
            or f'TeamIdentifier={policy["team_id"]}' not in details.stderr
            or f'Identifier={policy["bundle_id"]}' not in details.stderr
            or entitlement_value != expected_entitlements):
        raise AuthorizationError("touchid_ui_signature_invalid")


def verify_live_control_center_code(
    audit_token: bytes, team: str, peer_uid: int,
) -> None:
    """Validate the running SecCode guest selected by its audit token."""
    if (len(audit_token) != 32 or peer_uid <= 0
            or APPLE_TEAM_ID.fullmatch(team) is None
            or struct.unpack("=8I", audit_token)[1] != peer_uid):
        raise AuthorizationError("control_center_live_identity_invalid")
    security = ctypes.CDLL(
        "/System/Library/Frameworks/Security.framework/Security"
    )
    core = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    reference = ctypes.c_void_p
    core.CFDataCreate.argtypes = [reference, ctypes.c_void_p, ctypes.c_long]
    core.CFDataCreate.restype = reference
    core.CFStringCreateWithCString.argtypes = [
        reference, ctypes.c_char_p, ctypes.c_uint32,
    ]
    core.CFStringCreateWithCString.restype = reference
    core.CFDictionaryCreate.argtypes = [
        reference, ctypes.POINTER(reference), ctypes.POINTER(reference),
        ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p,
    ]
    core.CFDictionaryCreate.restype = reference
    core.CFDictionaryGetValue.argtypes = [reference, reference]
    core.CFDictionaryGetValue.restype = reference
    core.CFStringGetCString.argtypes = [
        reference, ctypes.c_void_p, ctypes.c_long, ctypes.c_uint32,
    ]
    core.CFStringGetCString.restype = ctypes.c_bool
    core.CFNumberGetValue.argtypes = [reference, ctypes.c_int, ctypes.c_void_p]
    core.CFNumberGetValue.restype = ctypes.c_bool
    core.CFRelease.argtypes = [reference]
    security.SecCodeCopyGuestWithAttributes.argtypes = [
        reference, reference, ctypes.c_uint32, ctypes.POINTER(reference),
    ]
    security.SecCodeCopyGuestWithAttributes.restype = ctypes.c_int32
    security.SecRequirementCreateWithString.argtypes = [
        reference, ctypes.c_uint32, ctypes.POINTER(reference),
    ]
    security.SecRequirementCreateWithString.restype = ctypes.c_int32
    security.SecCodeCheckValidityWithErrors.argtypes = [
        reference, ctypes.c_uint32, reference, ctypes.POINTER(reference),
    ]
    security.SecCodeCheckValidityWithErrors.restype = ctypes.c_int32
    security.SecCodeCopyStaticCode.argtypes = [
        reference, ctypes.c_uint32, ctypes.POINTER(reference),
    ]
    security.SecCodeCopyStaticCode.restype = ctypes.c_int32
    security.SecStaticCodeCheckValidityWithErrors.argtypes = [
        reference, ctypes.c_uint32, reference, ctypes.POINTER(reference),
    ]
    security.SecStaticCodeCheckValidityWithErrors.restype = ctypes.c_int32
    security.SecCodeCopySigningInformation.argtypes = [
        reference, ctypes.c_uint32, ctypes.POINTER(reference),
    ]
    security.SecCodeCopySigningInformation.restype = ctypes.c_int32
    retained: list[ctypes.c_void_p] = []
    try:
        token_buffer = (ctypes.c_ubyte * len(audit_token)).from_buffer_copy(
            audit_token
        )
        token_data = core.CFDataCreate(None, token_buffer, len(audit_token))
        if not token_data:
            raise AuthorizationError("control_center_live_identity_invalid")
        retained.append(token_data)
        audit_key = reference.in_dll(
            security, "kSecGuestAttributeAudit"
        ).value
        keys = (reference * 1)(audit_key)
        values = (reference * 1)(token_data)
        attributes = core.CFDictionaryCreate(
            None, keys, values, 1, None, None
        )
        if not attributes:
            raise AuthorizationError("control_center_live_identity_invalid")
        retained.append(attributes)
        guest = reference()
        if security.SecCodeCopyGuestWithAttributes(
            None, attributes, 0, ctypes.byref(guest)
        ) != 0 or not guest.value:
            raise AuthorizationError("control_center_live_identity_invalid")
        retained.append(guest)
        source = (
            f'identifier "{CONTROL_CENTER_BUNDLE_ID}" '
            'and anchor apple generic '
            f'and certificate leaf[subject.OU] = "{team}" '
            f'and certificate leaf[field.{DEVELOPER_ID_APPLICATION_OID}] exists'
        )
        source_ref = core.CFStringCreateWithCString(
            None, source.encode("utf-8"), 0x08000100
        )
        if not source_ref:
            raise AuthorizationError("control_center_live_identity_invalid")
        retained.append(source_ref)
        requirement = reference()
        if security.SecRequirementCreateWithString(
            source_ref, 0, ctypes.byref(requirement)
        ) != 0 or not requirement.value:
            raise AuthorizationError("control_center_live_identity_invalid")
        retained.append(requirement)
        validation_error = reference()
        if security.SecCodeCheckValidityWithErrors(
            guest, CONTROL_CENTER_DYNAMIC_VALIDATION_FLAGS, requirement,
            ctypes.byref(validation_error),
        ) != 0:
            if validation_error.value:
                core.CFRelease(validation_error)
            raise AuthorizationError("control_center_live_identity_invalid")
        static_code = reference()
        if security.SecCodeCopyStaticCode(
            guest, CONTROL_CENTER_STATIC_COPY_FLAGS,
            ctypes.byref(static_code),
        ) != 0 or not static_code.value:
            raise AuthorizationError("control_center_live_identity_invalid")
        retained.append(static_code)
        static_validation_error = reference()
        if security.SecStaticCodeCheckValidityWithErrors(
            static_code, CONTROL_CENTER_STATIC_VALIDATION_FLAGS, requirement,
            ctypes.byref(static_validation_error),
        ) != 0:
            if static_validation_error.value:
                core.CFRelease(static_validation_error)
            raise AuthorizationError("control_center_live_identity_invalid")
        information = reference()
        if security.SecCodeCopySigningInformation(
            guest, (1 << 1) | (1 << 3), ctypes.byref(information)
        ) != 0 or not information.value:
            raise AuthorizationError("control_center_live_identity_invalid")
        retained.append(information)

        def exported(name: str) -> int:
            value = reference.in_dll(security, name).value
            if value is None:
                raise AuthorizationError("control_center_live_identity_invalid")
            return value

        def string_value(name: str) -> str:
            value = core.CFDictionaryGetValue(information, exported(name))
            buffer = ctypes.create_string_buffer(512)
            if not value or not core.CFStringGetCString(
                value, buffer, len(buffer), 0x08000100
            ):
                raise AuthorizationError("control_center_live_identity_invalid")
            return buffer.value.decode("utf-8")

        status_value = core.CFDictionaryGetValue(
            information, exported("kSecCodeInfoStatus")
        )
        numeric_status = ctypes.c_int64()
        if (not status_value or not core.CFNumberGetValue(
                status_value, 4, ctypes.byref(numeric_status)
        )):
            raise AuthorizationError("control_center_live_identity_invalid")
        require_live_control_center_signing_record({
            "identifier": string_value("kSecCodeInfoIdentifier"),
            "team_identifier": string_value("kSecCodeInfoTeamIdentifier"),
            "dynamic_status": numeric_status.value,
        }, expected_team=team)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise AuthorizationError("control_center_live_identity_invalid") from error
    finally:
        for value in reversed(retained):
            if value:
                core.CFRelease(value)


def require_live_control_center_signing_record(
    value: object, *, expected_team: str,
) -> None:
    """Require hardened runtime from dynamic SecCode state, never disk flags."""
    if (not isinstance(value, dict)
            or value.get("identifier") != CONTROL_CENTER_BUNDLE_ID
            or value.get("team_identifier") != expected_team
            or not isinstance(value.get("dynamic_status"), int)
            or isinstance(value.get("dynamic_status"), bool)
            or value["dynamic_status"] & 0x0001_0000 == 0):
        raise AuthorizationError("control_center_live_identity_invalid")


def verify_control_center_peer(
    process_path: Path, release: Path, peer_uid: int, audit_token: bytes,
    *, live_validator: Callable[[bytes, str, int], None] = (
        verify_live_control_center_code),
) -> None:
    try:
        macos = process_path.parent
        contents = macos.parent
        bundle = contents.parent
        executable_info = process_path.lstat()
        bundle_info = bundle.lstat()
        info = plistlib.loads((contents / "Info.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise AuthorizationError("control_center_peer_identity_invalid") from error
    if (
        macos.name != "MacOS"
        or contents.name != "Contents"
        or bundle.suffix != ".app"
        or bundle.is_symlink()
        or process_path.is_symlink()
        or not stat.S_ISDIR(bundle_info.st_mode)
        or not stat.S_ISREG(executable_info.st_mode)
        or executable_info.st_uid not in {0, peer_uid}
        or executable_info.st_mode & 0o022
        or info.get("CFBundleIdentifier")
        != "org.zebeth.SecureSandbox.ControlCenter"
        or info.get("CFBundleExecutable") != process_path.name
    ):
        raise AuthorizationError("control_center_peer_identity_invalid")
    team = touchid_signing_policy(release)["team_id"]
    live_validator(audit_token, team, peer_uid)


def reconcile_native_sessions(release: Path) -> bool:
    """Recover every nonterminal native session before accepting broker work."""
    result = run_privileged_operation([
        "/usr/bin/python3", "-I",
        str(release / "native_stack_session_manager"), "recover",
    ], AUTH_TIMEOUT_SECONDS)
    if result.returncode != 0:
        try:
            error = json.loads(result.stderr)
        except (UnicodeDecodeError, json.JSONDecodeError) as failure:
            raise AuthorizationError(
                "native_stack_session_startup_recovery_failed"
            ) from failure
        if (set(error) == {"schema", "status", "error"}
                and error.get("schema")
                    == "secure-sandbox-native-stack-session-manager-error-v1"
                and error.get("status") == "rejected"
                and error.get("error")
                    == "native_stack_session_recovery_required"
                and result.stdout == b""):
            # Keep the broker alive only so the operator can request and
            # authorize the distinct projection-reconciliation ceremony.
            # Every native mutation/session admission re-runs this gate.
            return False
        raise AuthorizationError(
            "native_stack_session_startup_recovery_failed"
        )
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError(
            "native_stack_session_startup_recovery_failed"
        ) from error
    expected = {
        "schema", "state", "active_session_count", "reconciled_at",
        "evidence_sha256",
    }
    body = {
        "state": value.get("state"),
        "active_session_count": value.get("active_session_count"),
        "reconciled_at": value.get("reconciled_at"),
    }
    if (set(value) != expected
            or value.get("schema")
                != "secure-sandbox-native-stack-session-recovery-v1"
            or value.get("state") != "closed"
            or value.get("active_session_count") != 0
            or not isinstance(value.get("reconciled_at"), int)
            or isinstance(value.get("reconciled_at"), bool)
            or value["reconciled_at"] < 1
            or value.get("evidence_sha256")
                != hashlib.sha256(canonical(body)).hexdigest()
            or result.stdout != canonical(value)):
        raise AuthorizationError(
            "native_stack_session_startup_recovery_failed"
        )
    return True


def authorization_peer_kind(process_path: Path) -> str:
    """Classify only enough bundle metadata to select one exact verifier.

    This metadata is not trusted as identity.  The selected verifier still
    enforces the full designated requirement before any protocol bytes are
    read.  Unknown or malformed paths take the narrower Touch ID verifier and
    therefore fail closed for every other executable.
    """
    try:
        contents = process_path.parent.parent
        value = plistlib.loads((contents / "Info.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException):
        return "touch-id-ui"
    if (
        value.get("CFBundleIdentifier")
        == "org.zebeth.SecureSandbox.ControlCenter"
        and value.get("CFBundleExecutable") == process_path.name
    ):
        return "control-center"
    return "touch-id-ui"


def native_inspect_query(
    message: dict[str, Any], release: Path
) -> dict[str, Any]:
    expected = {
        "schema", "operation_id", "stack_id", "stack_sha256",
        "catalog_sha256", "request_sha256",
    }
    body = {
        key: message.get(key)
        for key in ("operation_id", "stack_id", "stack_sha256", "catalog_sha256")
    }
    if (
        set(message) != expected
        or message.get("schema") != NATIVE_INSPECT_QUERY_SCHEMA
        or UUID4.fullmatch(str(message.get("operation_id", ""))) is None
        or native_vendor_stack.IDENTIFIER.fullmatch(str(message.get("stack_id", "")))
        is None
        or SHA256.fullmatch(str(message.get("stack_sha256", ""))) is None
        or SHA256.fullmatch(str(message.get("catalog_sha256", ""))) is None
        or message.get("request_sha256")
        != hashlib.sha256(canonical(body)).hexdigest()
    ):
        raise AuthorizationError("native_stack_inspect_query_invalid")
    command = [str(release / "native_stack_backend"), "inspect-status"]
    starts_owned_group, environment = child_process_policy()
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=starts_owned_group,
        close_fds=True,
        env=environment,
    )
    try:
        output, _ = process.communicate(input=canonical(message), timeout=180)
    except subprocess.TimeoutExpired as error:
        terminate_bounded_process(process, owns_group=starts_owned_group)
        process.communicate()
        raise AuthorizationError("native_stack_inspect_query_timeout") from error
    if process.returncode != 0 or not 2 <= len(output) <= 1024 * 1024:
        raise AuthorizationError("native_stack_inspect_query_failed")
    try:
        status = json.loads(output)
        status = native_stack_operations.validate_status(status)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_stack_operations.NativeStackOperationError,
    ) as error:
        raise AuthorizationError("native_stack_inspect_reply_invalid") from error
    if output != native_stack_operations.canonical_bytes(status):
        raise AuthorizationError("native_stack_inspect_reply_invalid")
    reply_body = {
        "operation_id": message["operation_id"],
        "request_sha256": message["request_sha256"],
        "status": status,
    }
    return {
        "schema": NATIVE_INSPECT_REPLY_SCHEMA,
        **reply_body,
        "reply_sha256": hashlib.sha256(canonical(reply_body)).hexdigest(),
    }


def native_session_plan_query(
    message: dict[str, Any], release: Path,
) -> dict[str, Any]:
    expected = {
        "schema", "action", "action_id", "session_id", "stack_id",
        "stack_sha256", "catalog_sha256", "source_id",
        "resume_session_id", "lease_profile_id", "request_sha256",
    }
    body = {
        key: message.get(key) for key in expected
        if key not in {"schema", "request_sha256"}
    }
    if (set(message) != expected
            or message.get("schema") != NATIVE_SESSION_PLAN_QUERY_SCHEMA
            or message.get("request_sha256")
                != hashlib.sha256(canonical(body)).hexdigest()):
        raise AuthorizationError("native_stack_session_plan_query_invalid")
    starts_owned_group, environment = child_process_policy()
    process = subprocess.Popen(
        [str(release / "native_stack_backend"), "session-plan"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=starts_owned_group,
        close_fds=True, env=environment,
    )
    try:
        output, _ = process.communicate(input=canonical(message), timeout=180)
    except subprocess.TimeoutExpired as error:
        terminate_bounded_process(process, owns_group=starts_owned_group)
        process.communicate()
        raise AuthorizationError(
            "native_stack_session_plan_query_timeout"
        ) from error
    try:
        plan = native_stack_session.validate_plan(
            json.loads(output), now=int(time.time()), require_fresh=True
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_stack_session.NativeStackSessionError,
    ) as error:
        raise AuthorizationError(
            "native_stack_session_plan_reply_invalid"
        ) from error
    if (process.returncode != 0
            or not 2 <= len(output) <= 1024 * 1024
            or output != native_stack_session.canonical_bytes(plan)
            or plan["action"] != message["action"]
            or plan["action_id"] != message["action_id"]
            or plan["session_id"] != message["session_id"]
            or plan["stack_id"] != message["stack_id"]
            or plan["stack_sha256"] != message["stack_sha256"]
            or plan["catalog_sha256"] != message["catalog_sha256"]
            or plan["source_id"] != message["source_id"]
            or plan["resume_session_id"] != message["resume_session_id"]
            or plan["lease_profile_id"] != message["lease_profile_id"]):
        raise AuthorizationError(
            "native_stack_session_plan_reply_invalid"
        )
    reply_body = {
        "action_id": message["action_id"],
        "request_sha256": message["request_sha256"],
        "plan": plan,
    }
    return {
        "schema": NATIVE_SESSION_PLAN_REPLY_SCHEMA,
        **reply_body,
        "reply_sha256": hashlib.sha256(canonical(reply_body)).hexdigest(),
    }


def native_projection_recovery_plan_query(
    message: dict[str, Any], release: Path,
) -> dict[str, Any]:
    expected = {
        "schema", "recovery_operation_id", "original_operation_id",
        "request_sha256",
    }
    body = {
        "recovery_operation_id": message.get("recovery_operation_id"),
        "original_operation_id": message.get("original_operation_id"),
    }
    if (set(message) != expected
            or message.get("schema") != NATIVE_PROJECTION_PLAN_QUERY_SCHEMA
            or UUID4.fullmatch(str(body["recovery_operation_id"])) is None
            or UUID4.fullmatch(str(body["original_operation_id"])) is None
            or body["recovery_operation_id"] == body["original_operation_id"]
            or message.get("request_sha256")
                != hashlib.sha256(canonical(body)).hexdigest()):
        raise AuthorizationError(
            "native_projection_reconciliation_plan_query_invalid"
        )
    result = run_privileged_operation([
        "/usr/bin/python3", "-I",
        str(release / "native_stack_session_manager"),
        "projection-recovery-plan",
        "--original-operation-id", body["original_operation_id"],
        "--recovery-operation-id", body["recovery_operation_id"],
    ], AUTH_TIMEOUT_SECONDS)
    try:
        plan = native_projection_reconciliation.validate_plan(
            json.loads(result.stdout), now=int(time.time()),
            require_fresh=True,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_projection_reconciliation.NativeProjectionReconciliationError,
    ) as error:
        raise AuthorizationError(
            "native_projection_reconciliation_plan_reply_invalid"
        ) from error
    if (result.returncode != 0
            or result.stderr
            or result.stdout
                != native_projection_reconciliation.canonical_bytes(plan)
            or plan["recovery_operation_id"]
                != body["recovery_operation_id"]
            or plan["original_operation_id"]
                != body["original_operation_id"]
            or plan["host_release_id"] != release.name):
        raise AuthorizationError(
            "native_projection_reconciliation_plan_reply_invalid"
        )
    reply_body = {
        "recovery_operation_id": body["recovery_operation_id"],
        "request_sha256": message["request_sha256"],
        "plan": plan,
    }
    return {
        "schema": NATIVE_PROJECTION_PLAN_REPLY_SCHEMA,
        **reply_body,
        "reply_sha256": hashlib.sha256(canonical(reply_body)).hexdigest(),
    }


def native_projection_identity_recovery_plan_query(
    message: dict[str, Any], release: Path,
) -> dict[str, Any]:
    expected = {
        "schema", "recovery_operation_id", "original_operation_id",
        "request_sha256",
    }
    body = {
        "recovery_operation_id": message.get("recovery_operation_id"),
        "original_operation_id": message.get("original_operation_id"),
    }
    if (set(message) != expected
            or message.get("schema")
                != NATIVE_PROJECTION_IDENTITY_PLAN_QUERY_SCHEMA
            or UUID4.fullmatch(str(body["recovery_operation_id"])) is None
            or UUID4.fullmatch(str(body["original_operation_id"])) is None
            or body["recovery_operation_id"] == body["original_operation_id"]
            or message.get("request_sha256")
                != hashlib.sha256(canonical(body)).hexdigest()):
        raise AuthorizationError(
            "native_projection_identity_recovery_plan_query_invalid"
        )
    result = run_privileged_operation([
        "/usr/bin/python3", "-I",
        str(release / "native_stack_session_manager"),
        "projection-identity-recovery-plan",
        "--original-operation-id", body["original_operation_id"],
        "--recovery-operation-id", body["recovery_operation_id"],
    ], AUTH_TIMEOUT_SECONDS)
    try:
        plan = native_projection_identity_recovery.validate_plan(
            json.loads(result.stdout), now=int(time.time()),
            require_fresh=True,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        native_projection_identity_recovery
        .NativeProjectionIdentityRecoveryError,
    ) as error:
        raise AuthorizationError(
            "native_projection_identity_recovery_plan_reply_invalid"
        ) from error
    if (result.returncode != 0
            or result.stderr
            or result.stdout
                != native_projection_identity_recovery.canonical_bytes(plan)
            or plan["recovery_operation_id"]
                != body["recovery_operation_id"]
            or plan["original_operation_id"]
                != body["original_operation_id"]
            or plan["host_release_id"] != release.name):
        raise AuthorizationError(
            "native_projection_identity_recovery_plan_reply_invalid"
        )
    reply_body = {
        "recovery_operation_id": body["recovery_operation_id"],
        "request_sha256": message["request_sha256"],
        "plan": plan,
    }
    return {
        "schema": NATIVE_PROJECTION_IDENTITY_PLAN_REPLY_SCHEMA,
        **reply_body,
        "reply_sha256": hashlib.sha256(canonical(reply_body)).hexdigest(),
    }


def read_touchid_line(connection: socket.socket, timeout: int = 5,
                      limit: int = 65536) -> dict[str, Any]:
    connection.settimeout(timeout)
    data = bytearray()
    while b"\n" not in data:
        chunk = connection.recv(limit + 1 - len(data))
        if not chunk:
            raise AuthorizationError("touchid_protocol_incomplete")
        data.extend(chunk)
        if len(data) > limit:
            raise AuthorizationError("touchid_protocol_too_large")
    line, remainder = bytes(data).split(b"\n", 1)
    if remainder:
        raise AuthorizationError("touchid_protocol_trailing_data")
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("touchid_protocol_invalid") from error
    if not isinstance(value, dict):
        raise AuthorizationError("touchid_protocol_invalid")
    expected = canonical(value)
    if expected != line + b"\n":
        raise AuthorizationError("touchid_protocol_not_canonical")
    return value


def read_touchid_message(connection: socket.socket) -> dict[str, str]:
    value = read_touchid_line(connection, 5, 4096)
    if (set(value) != {"schema", "request_id", "request_sha256"}
            or value.get("schema") != TOUCHID_SCHEMA):
        raise AuthorizationError("touchid_protocol_invalid")
    valid_uuid4(value["request_id"])
    if not isinstance(value["request_sha256"], str) or not SHA256.fullmatch(value["request_sha256"]):
        raise AuthorizationError("touchid_protocol_invalid")
    if connection.recv(1):
        raise AuthorizationError("touchid_protocol_trailing_data")
    return value


def touchid_response(status: int, stdout: bytes, stderr: bytes) -> bytes:
    if len(stdout) > TOUCHID_RESPONSE_LIMIT or len(stderr) > TOUCHID_RESPONSE_LIMIT:
        raise AuthorizationError("touchid_response_too_large")
    return struct.pack("!4sIII", b"SSAR", status & 0xffffffff, len(stdout), len(stderr)) + stdout + stderr


def record_touchid_cancellation(value: dict[str, Any], request_sha256: str,
                                challenge: dict[str, Any],
                                receipt_root: Path = DEFAULT_RECEIPT_ROOT,
                                public_receipt_root: Path = DEFAULT_PUBLIC_RECEIPT_ROOT,
                                expected_uid: int = 0,
                                now: int | None = None) -> None:
    receipt_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = receipt_root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid):
        raise AuthorizationError("receipt_directory_untrusted")
    os.chmod(receipt_root, 0o700)
    completed_at = int(time.time()) if now is None else now
    receipt = {
        "schema":RECEIPT_SCHEMA,
        "request_id":value["request_id"],
        "request_sha256":request_sha256,
        "status":"cancelled",
        "started_at":completed_at,
        "completed_at":completed_at,
        "operation":value["operation"],
        "declared_agent":value["declared_agent"],
        "declared_session":value["declared_session"],
        "identity_evidence":"operator-declared",
        "authorization_method":"touch-id",
        "ceremony":value["ceremony"],
        "host_release_id":challenge["host_release_id"],
        "authorization_ui_bundle_sha256":challenge[
            "authorization_ui_bundle_sha256"
        ],
        "purpose":value["purpose"],
        "resource":value["resource"],
        "exit_status":TOUCHID_CANCELLED_EXIT,
        "stdout_sha256":hashlib.sha256(b"").hexdigest(),
        "stderr_sha256":hashlib.sha256(b"").hexdigest(),
        "outcome":"cancelled",
    }
    if value["operation"] == "harness-acceptance-authorize":
        plan = value["parameters"]["plan"]
        receipt.update({
            "acceptance_campaign_sha256":plan["campaign_sha256"],
            "acceptance_case_id":plan["case_id"],
            "acceptance_generation_id":plan["generation_id"],
            "acceptance_operator_uid":plan["operator_uid"],
            "acceptance_plan_sha256":plan["plan_sha256"],
            "acceptance_source_commit":plan["source_commit"],
        })
    if value["operation"] == "execution-approval-sign":
        receipt["approval_id"] = value["parameters"]["approval_id"]
        if challenge.get("mode") == "secure-enclave-sign":
            receipt.update({
                "approval_key_generation_id":challenge["generation_id"],
                "approval_key_generation_epoch":challenge["generation_epoch"],
                "approval_public_key_sha256":challenge["public_key_sha256"],
                "approval_signature_algorithm":challenge["algorithm"],
            })
    path = receipt_root / f"{value['request_id']}.json"
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
    except FileExistsError as error:
        raise AuthorizationError("request_already_consumed") from error
    try:
        write_all(descriptor, canonical(receipt))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(receipt_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    public_receipt_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    # launchd runs this broker with umask 077. This directory intentionally
    # exposes only content-free receipt projections, so set the reviewed mode
    # explicitly before validating it.
    os.chmod(public_receipt_root, 0o755)
    public_info = public_receipt_root.lstat()
    if (not stat.S_ISDIR(public_info.st_mode) or stat.S_ISLNK(public_info.st_mode)
            or public_info.st_uid != expected_uid
            or stat.S_IMODE(public_info.st_mode) != 0o755):
        raise AuthorizationError("public_receipt_directory_untrusted")
    public_receipt = {
        "schema":"secure-sandbox-operator-cancellation-receipt-v1",
        "status":"cancelled",
        "request_id":value["request_id"],
        "request_sha256":request_sha256,
        "operation":value["operation"],
        "ceremony":value["ceremony"],
        "authorization_method":"touch-id",
        "host_release_id":challenge["host_release_id"],
        "authorization_ui_bundle_sha256":challenge[
            "authorization_ui_bundle_sha256"
        ],
        "authorization_receipt_sha256":hashlib.sha256(canonical(receipt)).hexdigest(),
        "approval_key_generation_id":receipt.get("approval_key_generation_id"),
        "approval_key_generation_epoch":receipt.get("approval_key_generation_epoch"),
        "approval_public_key_sha256":receipt.get("approval_public_key_sha256"),
        "approval_signature_algorithm":receipt.get("approval_signature_algorithm"),
        "completed_at":completed_at,
    }
    if value["operation"] == "harness-acceptance-authorize":
        public_receipt.update({
            name:receipt[name] for name in (
                "acceptance_campaign_sha256", "acceptance_case_id",
                "acceptance_generation_id", "acceptance_operator_uid",
                "acceptance_plan_sha256", "acceptance_source_commit",
            )
        })
    atomic_public_record(
        public_receipt_root / f"{value['request_id']}.json", public_receipt
    )


def selected_release_changed(release: Path) -> bool:
    try:
        return ((release.parent.parent / "current").resolve(strict=True)
                != release.resolve(strict=True))
    except OSError:
        # Keep the already verified broker alive if the selector is damaged.
        return False


def operation_result_requires_broker_restart(
    release: Path,
    operation: str,
    status: int,
    result: subprocess.CompletedProcess[bytes],
) -> bool:
    if selected_release_changed(release):
        return True
    if operation not in {
        "host-controller-install", "host-controller-rollback",
    }:
        return False
    try:
        activation = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        activation = None
    if (
        isinstance(activation, dict)
        and activation.get("status") == "host_pair_transition_pending"
    ):
        return True
    if status == 0:
        return False
    try:
        return pending_host_install_record() is not None
    except AuthorizationError:
        # Restart into the startup recovery fence; a malformed or conflicting
        # journal must not leave the pre-transition broker serving requests.
        return True


def close_unrelated_spawn_actions() -> list[tuple[int, int]]:
    """Close every currently open broker descriptor above the fixed ABI."""
    soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (soft_limit == resource.RLIM_INFINITY or soft_limit < 4
            or soft_limit > 1_048_576):
        raise AuthorizationError("native_spawn_descriptor_limit_invalid")
    try:
        names = os.listdir("/dev/fd")
    except OSError as error:
        raise AuthorizationError(
            "native_spawn_descriptor_inventory_unavailable"
        ) from error
    descriptors: list[int] = []
    for name in names:
        if not name.isascii() or not name.isdecimal():
            raise AuthorizationError(
                "native_spawn_descriptor_inventory_invalid"
            )
        descriptor = int(name)
        if descriptor < 4 or descriptor >= soft_limit:
            continue
        try:
            os.fstat(descriptor)
        except OSError:
            # /dev/fd may have included its own already-closed enumeration fd.
            continue
        descriptors.append(descriptor)
    return [(os.POSIX_SPAWN_CLOSE, value) for value in sorted(set(descriptors))]


def run_terminal_bridge(
    connection: socket.socket, release: Path, handle_fd: int, *,
    timeout: int = 20 * 60,
) -> int:
    """Spawn the fixed no-capture bridge with authority only at inherited fd 3."""
    bridge = release / "native_stack_terminal_bridge"
    if handle_fd < 3 or handle_fd == connection.fileno():
        raise AuthorizationError("native_terminal_bridge_fd_invalid")
    actions: list[tuple[Any, ...]] = [
        (os.POSIX_SPAWN_DUP2, connection.fileno(), 0),
        (os.POSIX_SPAWN_DUP2, connection.fileno(), 1),
        (os.POSIX_SPAWN_DUP2, handle_fd, 3),
        (os.POSIX_SPAWN_OPEN, 2, "/dev/null", os.O_WRONLY, 0),
    ]
    actions.extend(close_unrelated_spawn_actions())
    try:
        child = os.posix_spawn(
            str(bridge), [str(bridge)],
            {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8",
                PROCESS_GROUP_ENV: "bootstrap",
            },
            file_actions=actions, setsid=True,
        )
    except OSError as error:
        raise AuthorizationError("native_terminal_bridge_launch_failed") from error
    deadline = time.monotonic() + timeout
    status: int | None = None
    try:
        while time.monotonic() < deadline:
            waited, observed = os.waitpid(child, os.WNOHANG)
            if waited == child:
                status = observed
                break
            time.sleep(0.05)
        if status is None:
            try:
                os.killpg(child, signal.SIGTERM)
            except ProcessLookupError:
                pass
            stop_deadline = time.monotonic() + 2
            while time.monotonic() < stop_deadline:
                waited, observed = os.waitpid(child, os.WNOHANG)
                if waited == child:
                    status = observed
                    break
                time.sleep(0.05)
        if status is None:
            try:
                os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            waited, status = os.waitpid(child, 0)
            if waited != child:
                raise AuthorizationError(
                    "native_terminal_bridge_reap_failed"
                )
        if process_group_exists(child):
            terminate_residual_process_group(child)
            raise AuthorizationError(
                "native_terminal_bridge_descendant_unreaped"
            )
        return os.waitstatus_to_exitcode(status)
    except (ChildProcessError, OSError) as error:
        try:
            os.killpg(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(child, 0)
        except (ChildProcessError, OSError):
            pass
        raise AuthorizationError("native_terminal_bridge_failed") from error


def handle_native_terminal_claim(
    connection: socket.socket, message: dict[str, Any], release: Path,
    *, expected_root_uid: int = 0, expected_root_gid: int = 0,
    terminal_root: Path = NATIVE_TERMINAL_HANDLE_ROOT,
) -> None:
    descriptor = -1
    record: dict[str, Any] | None = None
    bridge_error: BaseException | None = None
    result: int | None = None
    session_begun = False
    try:
        descriptor, record = native_terminal_handle.claim_unlinked_fd(
            message, root=terminal_root, now=int(time.time()),
            trusted_uid=expected_root_uid, trusted_gid=expected_root_gid,
        )
        if record["kind"] not in {"claude-login", "claude-session"}:
            raise AuthorizationError(
                "native_terminal_handle_kind_unavailable"
            )
        bridge_timeout = 20 * 60
        if record["kind"] == "claude-session":
            begin = run_privileged_operation([
                "/usr/bin/python3", "-I",
                str(release / "native_stack_session_manager"),
                "begin", "--action-id", record["operation_id"],
            ], AUTH_TIMEOUT_SECONDS)
            try:
                begun = json.loads(begin.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise AuthorizationError(
                    "native_terminal_session_begin_invalid"
                ) from error
            expected = {
                "schema", "action_id", "session_id",
                "runtime_authority_sha256", "session_lease_sha256",
                "session_expires_at", "evidence_sha256", "begin_sha256",
            }
            body = {
                key: begun.get(key) for key in expected
                if key not in {"schema", "begin_sha256"}
            }
            timestamp = int(time.time())
            if (begin.returncode != 0 or set(begun) != expected
                    or begun.get("schema")
                        != "secure-sandbox-native-stack-session-stream-begin-v1"
                    or begun.get("action_id") != record["operation_id"]
                    or begun.get("session_id") != record["session_id"]
                    or any(SHA256.fullmatch(str(begun.get(field, ""))) is None
                           for field in (
                               "runtime_authority_sha256",
                               "session_lease_sha256",
                               "evidence_sha256", "begin_sha256",
                           ))
                    or not isinstance(begun.get("session_expires_at"), int)
                    or isinstance(begun.get("session_expires_at"), bool)
                    or not timestamp < begun["session_expires_at"]
                        <= timestamp + 4 * 60 * 60
                    or begun["begin_sha256"] != hashlib.sha256(
                        canonical(body)
                    ).hexdigest()
                    or begin.stdout != canonical(begun)):
                raise AuthorizationError(
                    "native_terminal_session_begin_invalid"
                )
            session_begun = True
            bridge_timeout = begun["session_expires_at"] - timestamp
        try:
            result = run_terminal_bridge(
                connection, release, descriptor, timeout=bridge_timeout
            )
        except BaseException as error:
            bridge_error = error
    except native_terminal_handle.NativeTerminalHandleError as error:
        bridge_error = AuthorizationError(str(error))
    except BaseException as error:
        bridge_error = error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if record is None:
        if isinstance(bridge_error, AuthorizationError):
            raise bridge_error
        raise AuthorizationError(
            "native_terminal_handle_unavailable"
        ) from bridge_error
    if record["kind"] == "claude-session":
        manager = [
            "/usr/bin/python3", "-I",
            str(release / "native_stack_session_manager"),
            "complete" if (session_begun and result == 0
                            and bridge_error is None) else "abort",
            "--action-id", record["operation_id"],
        ]
    else:
        manager = [
            "/usr/bin/python3", "-I", str(release / "native_stack_manager"),
            "finalize-interactive" if result == 0 and bridge_error is None
            else "abort-interactive",
            "--action-id", record["operation_id"],
        ]
    completion = run_privileged_operation(manager, AUTH_TIMEOUT_SECONDS)
    if completion.returncode != 0:
        raise AuthorizationError(
            "native_terminal_completion_failed"
        ) from bridge_error
    if bridge_error is not None:
        raise AuthorizationError(
            "native_terminal_bridge_failed"
        ) from bridge_error
    if result != 0:
        raise AuthorizationError("native_terminal_stream_failed")


def handle_native_codex_ui_claim(
    connection: socket.socket, message: dict[str, Any], release: Path, *,
    expected_root_uid: int = 0, expected_root_gid: int = 0,
    handle_root: Path = NATIVE_CODEX_UI_HANDLE_ROOT,
) -> None:
    """Consume one typed-UI handle; first returned bytes are Research READY."""
    descriptor = -1
    record: dict[str, Any] | None = None
    child = -1
    child_group = -1
    successful = False
    try:
        descriptor, record = native_codex_ui_handle.claim_unlinked_fd(
            message, root=handle_root, now=int(time.time()),
            trusted_uid=expected_root_uid, trusted_gid=expected_root_gid,
        )
        actions: list[tuple[Any, ...]] = [
            (os.POSIX_SPAWN_DUP2, connection.fileno(), 0),
            (os.POSIX_SPAWN_DUP2, connection.fileno(), 1),
            (os.POSIX_SPAWN_DUP2, descriptor, 3),
            (os.POSIX_SPAWN_OPEN, 2, "/dev/null", os.O_WRONLY, 0),
        ]
        actions.extend(close_unrelated_spawn_actions())
        manager = release / "native_stack_session_manager"
        child = os.posix_spawn(
            str(manager), [
                str(manager), "codex-run", "--action-id",
                record["operation_id"],
            ],
            {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8",
                PROCESS_GROUP_ENV: "bootstrap",
            },
            file_actions=actions, setsid=True,
        )
        child_group = child
        deadline = time.monotonic() + max(
            1, record["session_lease"]["expires_at"] - int(time.time()) + 60
        )
        status: int | None = None
        while time.monotonic() < deadline:
            waited, observed = os.waitpid(child, os.WNOHANG)
            if waited == child:
                status = observed
                child = -1
                break
            time.sleep(0.05)
        if status is None:
            raise AuthorizationError("native_codex_ui_session_timeout")
        if process_group_exists(child_group):
            terminate_residual_process_group(child_group)
            raise AuthorizationError(
                "native_codex_ui_session_descendant_unreaped"
            )
        if os.waitstatus_to_exitcode(status) != 0:
            raise AuthorizationError("native_codex_ui_session_failed")
        successful = True
    except (OSError, native_codex_ui_handle.NativeCodexUIHandleError) as error:
        raise AuthorizationError("native_codex_ui_handle_unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if child > 0:
            try:
                os.killpg(child, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    waited, _status = os.waitpid(child, os.WNOHANG)
                except (ChildProcessError, OSError):
                    waited = child
                if waited == child:
                    child = -1
                    break
                time.sleep(0.05)
            if child > 0:
                try:
                    os.killpg(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                except (ProcessLookupError, ChildProcessError, OSError):
                    pass
        if record is not None and not successful:
            # A consumed claim can never reopen. Best-effort cleanup leaves the
            # durable journal recovery-required if exact absence is unavailable.
            try:
                run_privileged_operation([
                    "/usr/bin/python3", "-I",
                    str(release / "native_stack_session_manager"), "abort",
                    "--action-id", record["operation_id"],
                ], AUTH_TIMEOUT_SECONDS)
            except Exception:
                pass
        if child_group > 0:
            terminate_residual_process_group(child_group)


def handle_touchid_connection(connection: socket.socket, broker_path: Path | None = None,
                              expected_root_uid: int = 0,
                              receipt_root: Path = DEFAULT_RECEIPT_ROOT,
                              public_receipt_root: Path = DEFAULT_PUBLIC_RECEIPT_ROOT,
                              recovery_only: bool = False,
                              deployment_recovery_only: bool = False,
                              catalog_promotion_recovery_only: bool = False,
                              host_install_fenced: bool = False) -> bool:
    restart_after_response = False
    inspect_query = False
    session_plan_query = False
    projection_plan_query = False
    projection_identity_plan_query = False
    deployment_query_command = None
    catalog_promotion_gate_query = False
    catalog_promotion_recovery_query = False
    terminal_query = False
    codex_ui_query = False
    request_binding: RequestBinding | None = None
    try:
        uid, audit_token, process_path = peer_audit_identity(connection)
        release = protected_release_directory(
            Path(__file__) if broker_path is None else broker_path, expected_root_uid
        )
        peer_kind = authorization_peer_kind(process_path)
        if peer_kind == "control-center":
            verify_control_center_peer(
                process_path, release, uid, audit_token
            )
        else:
            verify_touchid_peer(process_path, release, expected_root_uid)
        message = read_touchid_line(connection, 5, 65536)
        inspect_query = message.get("schema") == NATIVE_INSPECT_QUERY_SCHEMA
        session_plan_query = (
            message.get("schema") == NATIVE_SESSION_PLAN_QUERY_SCHEMA
        )
        projection_plan_query = (
            message.get("schema") == NATIVE_PROJECTION_PLAN_QUERY_SCHEMA
        )
        projection_identity_plan_query = (
            message.get("schema")
            == NATIVE_PROJECTION_IDENTITY_PLAN_QUERY_SCHEMA
        )
        deployment_query_command = next((
            command for command, schema in NATIVE_DEPLOYMENT_QUERY_SCHEMAS.items()
            if message.get("schema") == schema
        ), None)
        catalog_promotion_gate_query = (
            message.get("schema")
            == NATIVE_CATALOG_PROMOTION_GATE_REQUEST_SCHEMA
        )
        catalog_promotion_recovery_query = (
            message.get("schema")
            == NATIVE_CATALOG_PROMOTION_RECOVERY_REQUEST_SCHEMA
        )
        terminal_query = message.get("schema") == native_terminal_handle.CLAIM_SCHEMA
        codex_ui_query = message.get("schema") == native_codex_ui_handle.CLAIM_SCHEMA
        if host_install_fenced:
            # A failed host activation deliberately leaves this immutable
            # broker launchable so the durable transition can be inspected and
            # repaired.  It is not authority to call a helper whose generation
            # is absent or unproven, including credential-recovery operations.
            raise AuthorizationError("host_install_recovery_required")
        if inspect_query:
            if peer_kind != "control-center":
                raise AuthorizationError("control_center_peer_identity_invalid")
            if connection.recv(1):
                raise AuthorizationError("native_stack_inspect_query_trailing_data")
            connection.sendall(canonical(native_inspect_query(message, release)))
            return selected_release_changed(release)
        if catalog_promotion_gate_query:
            if peer_kind != "control-center":
                raise AuthorizationError("control_center_peer_identity_invalid")
            if connection.recv(1):
                raise AuthorizationError(
                    "native_catalog_promotion_gate_query_trailing_data")
            connection.sendall(canonical(
                native_catalog_promotion_gate_query(
                    message, release, expected_uid=expected_root_uid)
            ))
            return selected_release_changed(release)
        if catalog_promotion_recovery_query:
            if peer_kind != "control-center":
                raise AuthorizationError("control_center_peer_identity_invalid")
            if recovery_only:
                raise AuthorizationError(
                    "native_projection_reconciliation_required")
            if deployment_recovery_only:
                raise AuthorizationError("native_deployment_recovery_required")
            if connection.recv(1):
                raise AuthorizationError(
                    "native_catalog_recovery_query_trailing_data")
            connection.sendall(canonical(
                native_catalog_promotion_recovery_query(
                    message, release, expected_uid=expected_root_uid)
            ))
            return selected_release_changed(release)
        if deployment_query_command is not None:
            if peer_kind != "control-center":
                raise AuthorizationError("control_center_peer_identity_invalid")
            if (
                deployment_recovery_only
                and deployment_query_command == "plan"
            ):
                raise AuthorizationError("native_deployment_recovery_required")
            if (
                catalog_promotion_recovery_only
                and deployment_query_command == "plan"
            ):
                raise AuthorizationError(
                    "native_catalog_promotion_recovery_required")
            if recovery_only and deployment_query_command != "status":
                raise AuthorizationError(
                    "native_projection_reconciliation_required")
            if connection.recv(1):
                raise AuthorizationError(
                    "native_deployment_query_trailing_data")
            connection.sendall(canonical(native_deployment_query(
                message, release, deployment_query_command,
                expected_uid=expected_root_uid)))
            return selected_release_changed(release)
        if session_plan_query:
            if peer_kind != "control-center":
                raise AuthorizationError("control_center_peer_identity_invalid")
            if recovery_only:
                raise AuthorizationError(
                    "native_projection_reconciliation_required"
                )
            if deployment_recovery_only:
                raise AuthorizationError("native_deployment_recovery_required")
            if catalog_promotion_recovery_only:
                raise AuthorizationError(
                    "native_catalog_promotion_recovery_required")
            if connection.recv(1):
                raise AuthorizationError(
                    "native_stack_session_plan_query_trailing_data"
                )
            connection.sendall(canonical(
                native_session_plan_query(message, release)
            ))
            return selected_release_changed(release)
        if projection_plan_query:
            if peer_kind != "control-center":
                raise AuthorizationError(
                    "control_center_peer_identity_invalid"
                )
            if deployment_recovery_only:
                raise AuthorizationError("native_deployment_recovery_required")
            if catalog_promotion_recovery_only:
                raise AuthorizationError(
                    "native_catalog_promotion_recovery_required")
            if connection.recv(1):
                raise AuthorizationError(
                    "native_projection_reconciliation_plan_query_trailing_data"
                )
            connection.sendall(canonical(
                native_projection_recovery_plan_query(message, release)
            ))
            return selected_release_changed(release)
        if projection_identity_plan_query:
            if peer_kind != "control-center":
                raise AuthorizationError(
                    "control_center_peer_identity_invalid"
                )
            if deployment_recovery_only:
                raise AuthorizationError("native_deployment_recovery_required")
            if catalog_promotion_recovery_only:
                raise AuthorizationError(
                    "native_catalog_promotion_recovery_required")
            if connection.recv(1):
                raise AuthorizationError(
                    "native_projection_identity_recovery_plan_query_trailing_data"
                )
            connection.sendall(canonical(
                native_projection_identity_recovery_plan_query(
                    message, release
                )
            ))
            return selected_release_changed(release)
        if terminal_query:
            if peer_kind != "control-center":
                raise AuthorizationError(
                    "control_center_peer_identity_invalid"
                )
            if recovery_only:
                raise AuthorizationError(
                    "native_projection_reconciliation_required"
                )
            if deployment_recovery_only:
                raise AuthorizationError("native_deployment_recovery_required")
            if catalog_promotion_recovery_only:
                raise AuthorizationError(
                    "native_catalog_promotion_recovery_required")
            handle_native_terminal_claim(
                connection, message, release,
                expected_root_uid=expected_root_uid,
            )
            return selected_release_changed(release)
        if codex_ui_query:
            if peer_kind != "control-center":
                raise AuthorizationError(
                    "control_center_peer_identity_invalid"
                )
            if recovery_only:
                raise AuthorizationError(
                    "native_projection_reconciliation_required"
                )
            if deployment_recovery_only:
                raise AuthorizationError("native_deployment_recovery_required")
            if catalog_promotion_recovery_only:
                raise AuthorizationError(
                    "native_catalog_promotion_recovery_required")
            handle_native_codex_ui_claim(
                connection, message, release,
                expected_root_uid=expected_root_uid,
            )
            return selected_release_changed(release)
        if peer_kind != "touch-id-ui":
            raise AuthorizationError("touchid_peer_identity_mismatch")
        if message.get("schema") == TOUCHID_SCHEMA:
            if set(message) != {"schema", "request_id", "request_sha256"}:
                raise AuthorizationError("touchid_protocol_invalid")
            valid_uuid4(message["request_id"])
            if (not isinstance(message["request_sha256"], str)
                    or not SHA256.fullmatch(message["request_sha256"])):
                raise AuthorizationError("touchid_protocol_invalid")
            if connection.recv(1):
                raise AuthorizationError("touchid_protocol_trailing_data")
            home = Path(pwd.getpwuid(uid).pw_dir)
            request_path = request_directory(home) / f"{message['request_id']}.json"
            value, request_binding = open_request_binding(
                request_path, uid, message["request_sha256"]
            )
            verify_request(value, uid, message["request_id"], int(time.time()))
            if (recovery_only and value["operation"] not in {
                    native_projection_reconciliation.OPERATION,
                    native_projection_identity_recovery.OPERATION,
            }):
                raise AuthorizationError(
                    "native_projection_reconciliation_required"
                )
            if (deployment_recovery_only
                    and value["operation"] != native_deployment.RECOVER_OPERATION):
                raise AuthorizationError("native_deployment_recovery_required")
            if catalog_promotion_recovery_only:
                raise AuthorizationError(
                    "native_catalog_promotion_recovery_required")
            if value["ceremony"] != "approve":
                raise AuthorizationError("ceremony_protocol_mismatch")
            captured: list[subprocess.CompletedProcess[bytes]] = []
            status = execute_request(
                uid, message["request_id"], message["request_sha256"],
                receipt_root=receipt_root, broker_path=broker_path,
                expected_root_uid=expected_root_uid, authorization_method="touch-id",
                emit_output=False, result_capture=captured,
                request_binding=request_binding,
            )
            if len(captured) != 1:
                raise AuthorizationError("touchid_operation_result_missing")
            response = touchid_response(status, captured[0].stdout, captured[0].stderr)
            restart_after_response = operation_result_requires_broker_restart(
                release, value.get("operation", ""), status, captured[0],
            )
            connection.sendall(response)
            return restart_after_response
        if (message.get("schema") != "secure-sandbox-touchid-approval-v2"
                or set(message) != {"schema", "phase", "request_id", "request_sha256"}
                or message.get("phase") != "begin"):
            raise AuthorizationError("touchid_protocol_invalid")
        valid_uuid4(message["request_id"])
        if (not isinstance(message["request_sha256"], str)
                or not SHA256.fullmatch(message["request_sha256"])):
            raise AuthorizationError("touchid_protocol_invalid")
        home = Path(pwd.getpwuid(uid).pw_dir)
        request_path = request_directory(home) / f"{message['request_id']}.json"
        value, request_binding = open_request_binding(
            request_path, uid, message["request_sha256"]
        )
        verify_request(value, uid, message["request_id"], int(time.time()))
        if (recovery_only and value["operation"] not in {
                native_projection_reconciliation.OPERATION,
                native_projection_identity_recovery.OPERATION,
        }):
            raise AuthorizationError(
                "native_projection_reconciliation_required"
            )
        if (deployment_recovery_only
                and value["operation"] != native_deployment.RECOVER_OPERATION):
            raise AuthorizationError("native_deployment_recovery_required")
        if catalog_promotion_recovery_only:
            raise AuthorizationError(
                "native_catalog_promotion_recovery_required")
        if value["ceremony"] == "cancel-test":
            challenge = cancellation_only_challenge(
                value, message["request_sha256"], release
            )
        else:
            challenge = touchid_v2_challenge(
                value, message["request_sha256"], release, expected_root_uid
            )
            challenge["authorization_ui_bundle_sha256"] = (
                touchid_ui_bundle_sha256(release)
            )
        connection.sendall(canonical(challenge))
        final = read_touchid_line(connection, AUTH_TIMEOUT_SECONDS, 65536)
        cancellation = {
            "schema":"secure-sandbox-touchid-decision-v2",
            "status":"cancelled",
            "request_id":message["request_id"],
            "request_sha256":message["request_sha256"],
        }
        if value["ceremony"] == "cancel-test" and final != cancellation:
            raise AuthorizationError("ceremony_decision_mismatch")
        if final == cancellation:
            receipt_challenge = challenge
            # Cancellation must be selected before any operation-specific state
            # access. Once the operator has actually cancelled, enrich only the
            # read-only signing receipt with the active generation identity.
            if value["operation"] == "execution-approval-sign":
                receipt_challenge = touchid_v2_challenge(
                    value, message["request_sha256"], release,
                    expected_root_uid,
                )
                receipt_challenge["authorization_ui_bundle_sha256"] = (
                    challenge["authorization_ui_bundle_sha256"]
                )
            record_touchid_cancellation(
                value, message["request_sha256"], receipt_challenge,
                receipt_root=receipt_root,
                public_receipt_root=public_receipt_root,
                expected_uid=expected_root_uid,
            )
            try:
                request_path.unlink()
            except OSError:
                pass
            connection.sendall(touchid_response(TOUCHID_CANCELLED_EXIT, b"", b""))
            return selected_release_changed(release)
        if challenge["mode"] == "legacy-touch-id":
            if final != {
                "schema":"secure-sandbox-touchid-authorization-v2",
                "phase":"authorize",
                "request_id":message["request_id"],
                "request_sha256":message["request_sha256"],
            }:
                raise AuthorizationError("touchid_protocol_invalid")
            override = None
        elif challenge["mode"] == "secure-enclave-prepare":
            prepared = verify_secure_enclave_preparation(
                final, challenge, expected_uid=expected_root_uid
            )
            override = subprocess.CompletedProcess(
                ["secure-enclave-prepare"], 0, canonical(prepared), b""
            )
        elif challenge["mode"] == "secure-enclave-sign":
            envelope = verify_secure_enclave_execution(final, challenge, value)
            override = subprocess.CompletedProcess(
                ["secure-enclave-sign"], 0, canonical(envelope), b""
            )
        else:
            raise AuthorizationError("touchid_protocol_invalid")
        captured: list[subprocess.CompletedProcess[bytes]] = []
        status = execute_request(
            uid, message["request_id"], message["request_sha256"],
            receipt_root=receipt_root, broker_path=broker_path,
            expected_root_uid=expected_root_uid, authorization_method="touch-id",
            emit_output=False, result_capture=captured, result_override=override,
            request_binding=request_binding,
        )
        if len(captured) != 1:
            raise AuthorizationError("touchid_operation_result_missing")
        response = touchid_response(status, captured[0].stdout, captured[0].stderr)
        restart_after_response = operation_result_requires_broker_restart(
            release, value.get("operation", ""), status, captured[0],
        )
    except (AuthorizationError, OSError, KeyError, TypeError, ValueError) as error:
        if inspect_query:
            body = {
                "schema": "secure-sandbox-native-stack-inspect-query-error-v1",
                "status": "rejected",
                "error": str(error),
            }
            response = canonical(body)
        elif session_plan_query:
            response = canonical({
                "schema": (
                    "secure-sandbox-native-stack-session-plan-query-error-v1"
                ),
                "status": "rejected", "error": str(error),
            })
        elif projection_plan_query:
            response = canonical({
                "schema": (
                    "secure-sandbox-native-projection-reconciliation-"
                    "plan-query-error-v1"
                ),
                "status": "rejected", "error": str(error),
            })
        elif projection_identity_plan_query:
            response = canonical({
                "schema": (
                    "secure-sandbox-native-projection-identity-recovery-"
                    "plan-query-error-v1"
                ),
                "status": "rejected", "error": str(error),
            })
        elif deployment_query_command is not None:
            response = canonical({
                "schema": NATIVE_DEPLOYMENT_QUERY_ERROR_SCHEMA,
                "command": deployment_query_command,
                "status": "rejected", "error": str(error),
            })
        elif catalog_promotion_gate_query:
            response = canonical({
                "schema": NATIVE_CATALOG_PROMOTION_GATE_ERROR_SCHEMA,
                "command": NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
                "status": "rejected", "error": str(error),
            })
        elif catalog_promotion_recovery_query:
            response = canonical({
                "schema": NATIVE_CATALOG_PROMOTION_RECOVERY_ERROR_SCHEMA,
                "command": NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
                "status": "rejected", "error": str(error),
            })
        elif terminal_query:
            response = canonical({
                "schema": "secure-sandbox-native-terminal-stream-error-v1",
                "status": "rejected", "error": str(error),
            })
        else:
            body = canonical({"schema": TOUCHID_SCHEMA, "status": "rejected", "error": str(error)})
            response = touchid_response(1, b"", body)
    finally:
        close_request_binding(request_binding)
    try:
        connection.sendall(response)
    except OSError:
        pass
    return restart_after_response


def broker_readiness_responder(
    channel: socket.socket,
    listener: socket.socket,
    nonce: bytes,
) -> None:
    try:
        channel.settimeout(25.0)
        request = b""
        while not request.endswith(b"\n") and len(request) <= 4096:
            chunk = channel.recv(4097 - len(request))
            if not chunk:
                return
            request += chunk
        expected = {
            "schema": "secure-sandbox-install-readiness-challenge-v1",
            "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
        }
        if request != canonical(expected):
            return
        # Reassert listen state inside the live broker immediately before the
        # finalizer attests it. The private socketpair cannot be backlog-starved
        # through the public authorization socket.
        listener.listen(4)
        path = Path(listener.getsockname())
        info = path.lstat()
        channel.sendall(canonical({
            "schema": "secure-sandbox-install-readiness-response-v1",
            "nonce_sha256": expected["nonce_sha256"],
            "broker_pid": os.getpid(),
            "path": str(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
        }))
    except (OSError, TypeError, ValueError):
        return


def validate_host_install_terminal(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != HOST_INSTALL_TERMINAL_FIELDS
            or value.get("schema")
                != "secure-sandbox-host-install-terminal-v1"
            or value.get("status") not in {
                "deployed_verified", "failed_rolled_back",
            }):
        raise AuthorizationError("host_install_committed_terminal_invalid")
    valid_uuid4(value.get("transition_id"), "transition_id")
    valid_uuid4(value.get("authorization_request_id"), "request_id")
    digest_names = (
        "transition_sha256", "authorization_request_sha256",
        "candidate_release_id", "candidate_manifest_sha256",
        "candidate_authorization_manifest_sha256",
        "developer_id_team_floor_sha256", "service_evidence_sha256",
        "authorization_receipt_sha256", "terminal_sha256",
    )
    if (any(
            not isinstance(value.get(name), str)
            or SHA256.fullmatch(value[name]) is None
            for name in digest_names)
            or not isinstance(value.get("developer_id_team_id"), str)
            or re.fullmatch(
                r"[A-Z0-9]{10}", value["developer_id_team_id"]
            ) is None
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value.get("completed_at"), bool)
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
                or any(
                    not isinstance(item, int) or isinstance(item, bool)
                    or item < 0
                    for item in value[name]
                )
                for name in (
                    "old_authorization_start_generation",
                    "authorization_start_generation",
                    "native_credential_start_generation",
                )
            )
            or (value["status"] == "deployed_verified"
                and (value.get("error") is not None
                     or value["authorization_pid"] <= 1
                     or value["native_credential_pid"] <= 1))
            or (value["status"] == "failed_rolled_back"
                and (not isinstance(value.get("error"), str)
                     or re.fullmatch(
                         r"[a-z][a-z0-9_]{0,127}", value["error"]
                     ) is None))):
        raise AuthorizationError("host_install_committed_terminal_invalid")
    body = {name: item for name, item in value.items()
            if name != "terminal_sha256"}
    if hashlib.sha256(canonical(body)).hexdigest() != value["terminal_sha256"]:
        raise AuthorizationError("host_install_committed_terminal_invalid")
    return value


def committed_host_install_terminal(
    value: object,
    *,
    expected_uid: int = 0,
    install_root: Path = HOST_INSTALL_ROOT,
) -> dict[str, Any]:
    """Independently read one committed public install terminal.

    This is the sole exception to the live broker-PID equality check.  The
    release manager must already have retired and fsynced the matching pending
    record, and the root-owned public record must exactly equal its stdout.
    """
    value = validate_host_install_terminal(value)

    root_descriptor = -1
    directory_descriptor = -1
    terminal_descriptor = -1
    try:
        root_descriptor = os.open(
            install_root,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        root_info = os.fstat(root_descriptor)
        reject_extended_acl(
            root_descriptor, "host_install_committed_terminal_untrusted")
        if (not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != expected_uid
                or stat.S_IMODE(root_info.st_mode) != 0o755):
            raise AuthorizationError("host_install_committed_terminal_untrusted")
        try:
            os.stat(
                ".install-transition.json", dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise AuthorizationError("host_install_transition_still_pending")
        directory_descriptor = os.open(
            "install-transitions",
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        directory_info = os.fstat(directory_descriptor)
        reject_extended_acl(
            directory_descriptor,
            "host_install_committed_terminal_untrusted",
        )
        if (not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != expected_uid
                or directory_info.st_gid != root_info.st_gid
                or stat.S_IMODE(directory_info.st_mode) != 0o755):
            raise AuthorizationError("host_install_committed_terminal_untrusted")
        name = f"{value['transition_id']}.json"
        before = os.stat(
            name, dir_fd=directory_descriptor, follow_symlinks=False,
        )
        terminal_descriptor = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        opened = os.fstat(terminal_descriptor)
        reject_extended_acl(
            terminal_descriptor,
            "host_install_committed_terminal_untrusted",
        )
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                    != (before.st_dev, before.st_ino)
                or opened.st_uid != expected_uid
                or opened.st_gid != directory_info.st_gid
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o444
                or not 2 <= opened.st_size <= 64 * 1024):
            raise AuthorizationError("host_install_committed_terminal_untrusted")
        raw = os.read(terminal_descriptor, 64 * 1024 + 1)
        if len(raw) != opened.st_size or os.read(terminal_descriptor, 1):
            raise AuthorizationError("host_install_committed_terminal_untrusted")
        try:
            observed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuthorizationError(
                "host_install_committed_terminal_untrusted"
            ) from error
        if observed != value or canonical(observed) != raw:
            raise AuthorizationError("host_install_committed_terminal_invalid")
        after = os.stat(
            name, dir_fd=directory_descriptor, follow_symlinks=False,
        )
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns)
                or after.st_nlink != 1):
            raise AuthorizationError("host_install_committed_terminal_changed")
        try:
            os.stat(
                ".install-transition.json", dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise AuthorizationError("host_install_transition_still_pending")
    except (OSError, UnicodeDecodeError) as error:
        raise AuthorizationError(
            "host_install_committed_terminal_untrusted"
        ) from error
    finally:
        for descriptor in (
            terminal_descriptor, directory_descriptor, root_descriptor,
        ):
            if descriptor >= 0:
                os.close(descriptor)
    return value


def preexisting_host_install_terminal(
    release: Path,
    *,
    expected_uid: int = 0,
    install_root: Path | None = None,
    pending_path: Path | None = None,
) -> dict[str, Any] | None:
    """Snapshot an exact public commit before invoking the release manager."""
    install_root = HOST_INSTALL_ROOT if install_root is None else install_root
    pending_path = HOST_INSTALL_PENDING if pending_path is None else pending_path
    transition = pending_host_install_record(
        expected_uid=expected_uid, path=pending_path,
    )
    if transition is None:
        return None
    verify_acl_free_install_root(
        install_root, expected_uid,
        "host_install_committed_terminal_untrusted",
    )
    verify_acl_free_directory(
        install_root / "install-transitions", expected_uid, 0o755,
        "host_install_committed_terminal_untrusted",
    )
    candidate = transition["candidate_release_id"]
    fallback = transition["fallback_release_id"]
    if (release.name != candidate
            and not (candidate != fallback and release.name == fallback)):
        raise AuthorizationError("host_install_transition_release_mismatch")
    path = (
        install_root / "install-transitions"
        / f"{transition['transition_id']}.json"
    )
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != expected_uid or before.st_nlink not in {1, 2}
            or stat.S_IMODE(before.st_mode) != 0o444
            or not 2 <= before.st_size <= 64 * 1024):
        raise AuthorizationError("host_install_committed_terminal_untrusted")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "host_install_committed_terminal_untrusted")
        raw = os.read(descriptor, 64 * 1024 + 1)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_nlink not in {1, 2}
                or len(raw) != opened.st_size or len(raw) > 64 * 1024
                or os.read(descriptor, 1)):
            raise AuthorizationError(
                "host_install_committed_terminal_changed"
            )
    finally:
        os.close(descriptor)
    after = path.lstat()
    if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns)
            or after.st_nlink not in {1, 2}):
        raise AuthorizationError("host_install_committed_terminal_changed")
    try:
        observed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError(
            "host_install_committed_terminal_untrusted"
        ) from error
    observed = validate_host_install_terminal(observed)
    if (canonical(observed) != raw
            or observed["transition_id"] != transition["transition_id"]
            or observed["transition_sha256"]
                != transition["transition_sha256"]
            or observed["candidate_release_id"] != candidate):
        raise AuthorizationError("host_install_committed_terminal_invalid")
    return observed


def committed_host_pair_terminal_for_transition(
    transition: dict[str, Any], *, expected_uid: int = 0,
    install_root: Path = HOST_INSTALL_ROOT,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    observed = public_host_pair_record(
        expected_uid=expected_uid,
        path=install_root / "host-release-launcher-pair.json",
    )
    if observed is None or observed[0]["schema"] != HOST_PAIR_STABLE_SCHEMA:
        raise AuthorizationError("host_pair_transition_recovery_unverified")
    stable, stable_sha256 = observed
    if (stable["committed_transition_id"] != transition["transition_id"]
            or stable["committed_transition_sha256"]
                != transition["transition_sha256"]):
        raise AuthorizationError("host_pair_transition_recovery_unverified")
    path = (
        install_root / "install-transitions"
        / f"{transition['transition_id']}.json"
    )
    raw = read_acl_free_regular(
        path, expected_uid, 0o444, "host_pair_terminal_untrusted",
        maximum=64 * 1024, expected_nlink=1,
    )
    try:
        terminal_value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("host_pair_terminal_untrusted") from error
    terminal = validate_host_pair_terminal(terminal_value, transition)
    if (canonical(terminal) != raw
            or hashlib.sha256(raw).hexdigest()
                != stable["committed_terminal_sha256"]
            or stable["pair"] != terminal["committed_pair"]
            or os.path.lexists(install_root / ".install-transition.json")):
        raise AuthorizationError("host_pair_transition_recovery_unverified")
    return terminal, stable, stable_sha256


def recover_pending_host_pair_transition(
    release: Path, transition: dict[str, Any], *, expected_uid: int = 0,
    install_root: Path = HOST_INSTALL_ROOT,
    launcher_path: Path = Path("/usr/local/bin/secure-sandbox-claude"),
    state_root: Path | None = None,
) -> dict[str, Any]:
    if transition.get("schema") != HOST_PAIR_TRANSITION_SCHEMA:
        raise AuthorizationError("host_pair_transition_recovery_invalid")
    if state_root is None:
        native_uid = transition["native_uid"]
        if native_uid <= 0:
            raise AuthorizationError("host_pair_transition_state_root_invalid")
        try:
            home = Path(pwd.getpwuid(native_uid).pw_dir)
            home_info = home.lstat()
        except (KeyError, OSError) as error:
            raise AuthorizationError(
                "host_pair_transition_state_root_invalid"
            ) from error
        if (not home.is_absolute() or not stat.S_ISDIR(home_info.st_mode)
                or home_info.st_uid != native_uid):
            raise AuthorizationError("host_pair_transition_state_root_invalid")
        state_root = (
            home / "Library/Application Support/SecureSandbox/controller-state"
        )
    completed = run_privileged_operation([
        "/usr/bin/python3", "-I", str(release / "release_manager"),
        "recover-host-pair-transition", "--install-root", str(install_root),
        "--launcher", str(launcher_path), "--state-root", str(state_root),
        "--json",
    ], timeout=OPERATION_TIMEOUT_SECONDS)
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        value = None
    if completed.returncode != 0:
        # Source restoration deliberately reports the original activation
        # failure.  Accept it only through the independently committed public
        # terminal and stable pair; otherwise recovery remains unproven.
        terminal, stable, stable_sha256 = (
            committed_host_pair_terminal_for_transition(
                transition, expected_uid=expected_uid,
                install_root=install_root,
            )
        )
        if terminal["status"] != "source_restored":
            raise AuthorizationError("host_pair_transition_recovery_unverified")
        return {
            "candidate_authority_sha256": stable["pair"][
                "candidate_authority_sha256"
            ],
            "host_release_launcher_pair_sha256": stable_sha256,
            "operation": transition["operation"],
            "release_id": stable["pair"]["release_id"],
            "release_tree_identity_sha256": stable["pair"][
                "release_tree_identity_sha256"
            ],
            "schema": "secure-sandbox-host-controller-release-v1",
            "status": "host_pair_transition_recovered",
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
        }
    fields = {
        "candidate_authority_sha256", "host_release_launcher_pair_sha256",
        "operation", "release_id", "release_tree_identity_sha256", "schema",
        "status", "transition_id", "transition_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema")
                != "secure-sandbox-host-controller-release-v1"
            or value.get("status") != "host_pair_transition_recovered"
            or value.get("operation") != transition["operation"]
            or value.get("transition_id") != transition["transition_id"]
            or value.get("transition_sha256")
                != transition["transition_sha256"]
            or any(
                not isinstance(value.get(name), str)
                or SHA256.fullmatch(value[name]) is None
                for name in (
                    "candidate_authority_sha256",
                    "host_release_launcher_pair_sha256", "release_id",
                    "release_tree_identity_sha256", "transition_sha256",
                )
            )):
        raise AuthorizationError("host_pair_transition_recovery_unverified")
    terminal, stable, stable_sha256 = committed_host_pair_terminal_for_transition(
        transition, expected_uid=expected_uid, install_root=install_root,
    )
    if (terminal["status"] != "target_committed"
            or value["release_id"] != stable["pair"]["release_id"]
            or value["candidate_authority_sha256"]
                != stable["pair"]["candidate_authority_sha256"]
            or value["release_tree_identity_sha256"]
                != stable["pair"]["release_tree_identity_sha256"]
            or value["host_release_launcher_pair_sha256"] != stable_sha256):
        raise AuthorizationError("host_pair_transition_recovery_unverified")
    return value


def await_parent_host_pair_publication(
    transition: dict[str, Any], *, timeout: float = 5.0,
    poll_interval: float = 0.05,
) -> bool:
    """Let the live parent manager finish before attempting crash replay.

    During an ordinary pair activation the manager selects and starts the new
    broker before it can publish the terminal and stable records.  Immediate
    broker-side replay would contend with that manager's mutation fence and
    turn a healthy activation into a launchd crash loop.  A bounded grace
    period lets the parent publish.  Absence of the private pending record is
    accepted only with the independently verified terminal and stable pair;
    otherwise the broker falls through to the existing exact recovery path.
    """
    deadline = time.monotonic() + timeout
    while True:
        observed = pending_host_install_record()
        if observed is None:
            committed_host_pair_terminal_for_transition(transition)
            return True
        if observed != transition:
            raise AuthorizationError("host_pair_transition_changed")
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_interval)


def finalize_pending_host_install(
    release: Path, listener: socket.socket,
) -> dict[str, Any] | None:
    transition = pending_host_install_record()
    if (transition is not None
            and transition["schema"] == HOST_PAIR_TRANSITION_SCHEMA):
        return recover_pending_host_pair_transition(release, transition)
    try:
        pending = HOST_INSTALL_PENDING.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(pending.st_mode) or stat.S_ISLNK(pending.st_mode)
            or pending.st_uid != 0 or pending.st_nlink != 1
            or stat.S_IMODE(pending.st_mode) != 0o600):
        raise AuthorizationError("host_install_transition_untrusted")
    preexisting_terminal = preexisting_host_install_terminal(release)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    nonce = os.urandom(32)
    responder = threading.Thread(
        target=broker_readiness_responder,
        args=(parent, listener, nonce), daemon=True,
    )
    responder.start()
    try:
        completed = run_privileged_operation([
            "/usr/bin/python3", "-I", str(release / "release_manager"),
            "finalize-install-transition", "--install-root",
            str(HOST_INSTALL_ROOT),
            "--expected-current-release-id", release.name,
            "--expected-authorization-pid", str(os.getpid()),
            "--expected-listener-fd", str(listener.fileno()),
            "--expected-readiness-fd", str(child.fileno()),
            "--expected-readiness-nonce", nonce.hex(), "--json",
        ], timeout=30, pass_fds=(listener.fileno(), child.fileno()))
    finally:
        child.close()
        responder.join(timeout=1.0)
        parent.close()
    try:
        terminal = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("host_install_activation_unverified") from error
    success = (
        isinstance(terminal, dict)
        and terminal.get("status") == "deployed_verified"
        and terminal.get("candidate_release_id") == release.name
    )
    recovered_rollback = (
        isinstance(terminal, dict)
        and terminal.get("status") == "failed_rolled_back"
        and terminal.get("candidate_release_id") != release.name
    )
    fenced_failure = (
        isinstance(terminal, dict)
        and terminal.get("status") in {
            "failed_fenced", "failure_fence_unproven",
        }
    )
    if (completed.returncode != 0
            or not isinstance(terminal, dict)
            or terminal.get("schema")
                != "secure-sandbox-host-install-terminal-v1"
            or not (success or recovered_rollback or fenced_failure)
            or not isinstance(terminal.get("terminal_sha256"), str)
            or SHA256.fullmatch(terminal["terminal_sha256"]) is None):
        raise AuthorizationError("host_install_activation_unverified")
    if not fenced_failure:
        try:
            committed = committed_host_install_terminal(terminal)
        except AuthorizationError as error:
            raise AuthorizationError(
                "host_install_activation_unverified"
            ) from error
        # A prior PID is accepted only through the exact committed readback
        # above.  A fresh but uncommitted result has no exception to the
        # ordinary current-PID rule and is rejected by that readback.
        if committed != terminal:
            raise AuthorizationError("host_install_activation_unverified")
        if (terminal.get("authorization_pid") != os.getpid()
                and preexisting_terminal != terminal):
            raise AuthorizationError("host_install_activation_unverified")
    return terminal


def prepare_failed_host_install_rollback(release: Path) -> bool:
    transition = pending_host_install_record()
    if (transition is not None
            and transition["schema"] == HOST_PAIR_TRANSITION_SCHEMA):
        return False
    try:
        pending = HOST_INSTALL_PENDING.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(pending.st_mode) or stat.S_ISLNK(pending.st_mode)
            or pending.st_uid != 0 or pending.st_nlink != 1
            or stat.S_IMODE(pending.st_mode) != 0o600):
        raise AuthorizationError("host_install_transition_untrusted")
    completed = run_privileged_operation([
        "/usr/bin/python3", "-I", str(release / "release_manager"),
        "prepare-install-transition-rollback",
        "--install-root", str(HOST_INSTALL_ROOT),
        "--expected-current-release-id", release.name,
        "--expected-authorization-pid", str(os.getpid()), "--json",
    ], timeout=30)
    try:
        prepared = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("host_install_rollback_unverified") from error
    if (completed.returncode != 0 or not isinstance(prepared, dict)
            or set(prepared) != {
                "schema", "status", "transition_id", "transition_sha256",
                "candidate_release_id", "fallback_release_id",
            }
            or prepared.get("schema")
                != "secure-sandbox-host-controller-release-v1"
            or prepared.get("status") not in {
                "rollback_prepared", "failure_fence_prepared",
            }
            or prepared.get("candidate_release_id") != release.name
            or any(
                not isinstance(prepared.get(name), str)
                or SHA256.fullmatch(prepared[name]) is None
                for name in (
                    "transition_sha256", "candidate_release_id",
                    "fallback_release_id",
                )
            )):
        raise AuthorizationError("host_install_rollback_unverified")
    valid_uuid4(prepared.get("transition_id"), "transition_id")
    return True


def pending_host_install_record(
    *, expected_uid: int = 0, path: Path = HOST_INSTALL_PENDING,
    pair_path: Path | None = None,
) -> dict[str, Any] | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != expected_uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 2 <= before.st_size <= 64 * 1024):
        raise AuthorizationError("host_install_transition_untrusted")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, "host_install_transition_untrusted")
        raw = os.read(descriptor, 64 * 1024 + 1)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or len(raw) != opened.st_size or len(raw) > 64 * 1024
                or os.read(descriptor, 1)):
            raise AuthorizationError("host_install_transition_changed")
    finally:
        os.close(descriptor)
    after = path.lstat()
    if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns)):
        raise AuthorizationError("host_install_transition_changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("host_install_transition_untrusted") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise AuthorizationError("host_install_transition_untrusted")
    if value.get("schema") == HOST_PAIR_TRANSITION_SCHEMA:
        transition = validate_host_pair_transition(value)
        public_state = match_public_host_pair_transition_state(
            transition, expected_uid=expected_uid,
            path=(path.parent / "host-release-launcher-pair.json"
                  if pair_path is None else pair_path),
        )
        if (public_state == "prepared" and not transition["bootstrap"]
                and transition["finalization"] is None
                and transition["terminal"] is None):
            current = int(time.time())
            if (current < transition["created_at"]
                    or current >= transition["expires_at"]):
                raise AuthorizationError("host_pair_transition_expired")
        return transition
    public_path = (
        path.parent / "host-release-launcher-pair.json"
        if pair_path is None else pair_path
    )
    if os.path.lexists(public_path):
        # Once pair evidence exists, a legacy private journal can never be
        # interpreted as an authorized pair transition.
        public_host_pair_record(
            expected_uid=expected_uid, path=public_path,
        )
        raise AuthorizationError("host_pair_transition_legacy_active")
    immutable = (
        {name: item for name, item in value.items()
         if name not in {"terminal", "transition_sha256"}}
        if isinstance(value, dict) else {}
    )
    candidate = value.get("candidate_release_id") if isinstance(value, dict) else None
    fallback = value.get("fallback_release_id") if isinstance(value, dict) else None
    if (set(value) != HOST_INSTALL_TRANSITION_FIELDS
            or value.get("schema")
                != "secure-sandbox-host-install-transition-v1"
            or not isinstance(candidate, str) or SHA256.fullmatch(candidate) is None
            or not isinstance(fallback, str) or SHA256.fullmatch(fallback) is None
            or value.get("old_current_target") != f"releases/{fallback}"
            or not isinstance(value.get("transition_sha256"), str)
            or SHA256.fullmatch(value["transition_sha256"]) is None
            or hashlib.sha256(canonical(immutable)).hexdigest()
                != value["transition_sha256"]):
        raise AuthorizationError("host_install_transition_untrusted")
    return value


def pending_host_install_role(
    release: Path,
    *,
    expected_uid: int = 0,
    path: Path = HOST_INSTALL_PENDING,
) -> str | None:
    value = pending_host_install_record(
        expected_uid=expected_uid, path=path,
    )
    if value is None:
        return None
    if value["schema"] == HOST_PAIR_TRANSITION_SCHEMA:
        if release.name == value["target_pair"]["release_id"]:
            return "target"
        source = value["source_pair"]
        if source is not None and release.name == source["release_id"]:
            return "source"
        if (value["bootstrap"] and source is None
                and release.name == value["bootstrap_admission"][
                    "established_from_predecessor_release_id"
                ]):
            # The sole pre-floor pair bootstrap has no stable source identity
            # to name in the v2 journal.  The already protected, selected
            # predecessor broker may nevertheless drive replay of that exact
            # typed bootstrap; the manager can only commit its journaled target.
            return "source"
        raise AuthorizationError("host_pair_transition_release_mismatch")
    candidate = value["candidate_release_id"]
    fallback = value["fallback_release_id"]
    if release.name == candidate:
        return "candidate"
    if candidate != fallback and release.name == fallback:
        return "fallback"
    raise AuthorizationError("host_install_transition_release_mismatch")


def serve_touchid(socket_path: Path = TOUCHID_SOCKET) -> int:
    if os.geteuid() != 0:
        raise AuthorizationError("root_required")
    parent = socket_path.parent.resolve(strict=True)
    parent_info = parent.stat()
    if parent_info.st_uid != 0 or not stat.S_ISDIR(parent_info.st_mode):
        raise AuthorizationError("touchid_socket_directory_untrusted")
    release = protected_release_directory(Path(__file__), 0)
    transition = pending_host_install_record()
    if (transition is not None
            and transition["schema"] == HOST_PAIR_TRANSITION_SCHEMA):
        pending_host_install_role(release)
        parent_published = await_parent_host_pair_publication(transition)
        if not parent_published:
            recovered = recover_pending_host_pair_transition(
                release, transition,
            )
            if (recovered["release_id"] != release.name
                    or selected_release_changed(release)):
                return 0
            if pending_host_install_record() is not None:
                raise AuthorizationError(
                    "host_pair_transition_recovery_unverified"
                )
        elif selected_release_changed(release):
            return 0
        transition_role = None
    else:
        transition_role = pending_host_install_role(release)
        if transition is None:
            public = public_host_pair_record()
            if (public is not None
                    and public[0]["schema"] == HOST_PAIR_PENDING_SCHEMA):
                raise AuthorizationError("host_pair_public_pending_orphaned")
    if socket_path.exists() or socket_path.is_symlink():
        info = socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise AuthorizationError("touchid_socket_path_untrusted")
        socket_path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o666)
        listener.listen(4)
        host_install_fenced = False
        if transition_role == "fallback":
            # The failed candidate may have left its helper generation live.
            # Terminalize the exact rollback first; the release manager repairs
            # and verifies the predecessor services before reconciliation uses
            # them.
            terminal = finalize_pending_host_install(release, listener)
            if terminal is not None and terminal["status"] in {
                "failed_fenced", "failure_fence_unproven",
            }:
                recovery_only = True
                host_install_fenced = True
            else:
                recovery_only = not reconcile_native_sessions(release)
        else:
            reconciled = reconcile_native_sessions(release)
            if transition_role == "candidate" and not reconciled:
                raise AuthorizationError(
                    "host_install_candidate_reconciliation_failed"
                )
            recovery_only = not reconciled
            terminal = finalize_pending_host_install(release, listener)
            if terminal is not None and terminal["status"] in {
                "failed_fenced", "failure_fence_unproven",
            }:
                recovery_only = True
                host_install_fenced = True
        deployment_recovery_only = native_deployment_recovery_required(
            release, expected_uid=0)
        catalog_promotion_recovery_only = (
            native_catalog_promotion_recovery_required(
                release, expected_uid=0)
        )
        while True:
            deployment_recovery_only = native_deployment_recovery_required(
                release, expected_uid=0)
            catalog_promotion_recovery_only = (
                native_catalog_promotion_recovery_required(
                    release, expected_uid=0)
            )
            connection, _ = listener.accept()
            with connection:
                restart = handle_touchid_connection(
                    connection, recovery_only=recovery_only,
                    deployment_recovery_only=deployment_recovery_only,
                    catalog_promotion_recovery_only=(
                        catalog_promotion_recovery_only
                    ),
                    host_install_fenced=host_install_fenced,
                )
            if recovery_only and not host_install_fenced:
                recovery_only = not reconcile_native_sessions(release)
            if restart:
                break
    finally:
        listener.close()
        try:
            socket_path.unlink()
        except OSError:
            pass


def authorization_execution_timeout(operation: str) -> int:
    if operation == "vm-preserve-legacy":
        return 8 * 60 * 60 + 300
    if operation in {"vm-create", "vm-reprovision"}:
        return 3600 + 300
    if operation.startswith("installer-"):
        return 1800 + 300
    if operation == native_stack_catalog_promotion.OPERATION:
        return NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS
    if operation in native_deployment.OPERATIONS:
        # Ordered Gateway + Research publication, independent readbacks, and
        # bounded compensation can legitimately span both guest timeouts.
        return 60 * 60 + 300
    if operation == "native-stack-signin-begin":
        return 20 * 60
    if operation in {"native-stack-entitlement-verify", "native-stack-logout"}:
        return 10 * 60
    if operation in {
        native_program_attestation.OPERATION,
        native_projection_identity_recovery.OPERATION,
        native_projection_reconciliation.OPERATION,
    }:
        return AUTH_TIMEOUT_SECONDS
    if operation in {"native-session-start", "native-session-stop"}:
        return AUTH_TIMEOUT_SECONDS
    return AUTH_TIMEOUT_SECONDS


def authorization_client_timeout(operation: str) -> int:
    """Bound the whole ceremony while leaving the root child its full budget."""
    return (
        authorization_execution_timeout(operation)
        + REQUEST_TTL_SECONDS
        + AUTHORIZATION_COMPLETION_MARGIN_SECONDS
    )


def preflight_message(value: dict[str, Any], request_sha256: str) -> str:
    cancel_test = value["ceremony"] == "cancel-test"
    lines = [
        ("SecureSandbox cancellation test — CANCEL; do not authenticate"
         if cancel_test else "SecureSandbox approval request — APPROVE only if exact"),
        "",
        f"Ceremony: {'CANCEL TEST' if cancel_test else 'APPROVAL'}",
        f"Declared agent: {value['declared_agent']}",
        f"Declared session: {value['declared_session']}",
        f"Purpose: {value['purpose']}",
        f"Resource: {value['resource']}",
        f"Operation: {value['operation']}",
    ]
    lines.extend(operation_details(value))
    lines.extend([
        f"Request digest: {request_sha256}",
        f"One-time nonce: {value['request_id']}",
        f"Expires (Unix): {value['expires_at']}",
        "",
        ("This is a cancellation test. Cancel the authorization window; do not use Touch ID."
         if cancel_test else
         "Approve only if these details exactly match the agent conversation you intend to authorize."),
    ])
    return "\n".join(lines)


def operation_details(value: dict[str, Any]) -> list[str]:
    operation = value["operation"]
    parameters = value["parameters"]
    if operation == "authorization-probe":
        return [f"Acceptance challenge: {parameters['challenge']}"]
    if operation == "model-profile-activate":
        plan = parameters["plan"]
        broker = plan["broker"]
        return [
            f"Activation ID: {plan['activation_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Profile: {broker['profile_id']} @ {broker['profile_sha256']}",
            f"Vendor / model: {broker['vendor_id']} / {broker['allowed_models'][0]}",
            f"Current Gateway authority: {plan['current']['gateway']['profile_id']} / {plan['current']['gateway']['model']} [{plan['current']['gateway']['mode']}]",
            ("Current Research authority: legacy session binding unavailable"
             if plan["current"]["research"].get("state") == "legacy_unbound" else
             f"Current Research authority: {plan['current']['research']['profile_id']} / {plan['current']['research']['model']} [{plan['current']['research']['mode']}]") ,
            f"Current generation SHA-256: {plan['current_generation_sha256']}",
            f"Adapter: {broker['adapter']}",
            f"Mode / origin: {broker['mode']} / {broker['upstream_origin']}",
            "Pinned IPv4: " + (", ".join(broker["upstream_ipv4"]) or "none (mock)"),
            "OAuth IPv4: " + (", ".join(broker.get("oauth_ipv4", [])) or "not used"),
            f"Credential: {broker['credential_scheme']} / {plan['credential_reference']}",
            "Settings: " + canonical(broker["settings"]).decode("ascii"),
            "Broker limits: request={max_request_bytes}, response={max_response_bytes}, tokens={max_tokens}, rate={rate_limit_requests}/{rate_limit_window_seconds}s, timeouts={client_timeout_seconds}/{upstream_timeout_seconds}s".format(**broker),
            f"Lease/pricing SHA-256: {hashlib.sha256(canonical(plan['lease_profiles'])).hexdigest()}",
            "Action: atomically replace Gateway and Research model authority",
        ]
    if operation == native_stack_catalog_promotion.OPERATION:
        plan = native_stack_catalog_promotion.validate_plan(parameters["plan"])
        catalog, _raw = read_native_promotion_catalog(
            Path(parameters["source"]),
            expected_uid=plan["source_uid"],
            expected_sha256=plan["source_sha256"],
        )
        details = [
            "Catalog promotion is inert: it does not authenticate, open egress, activate a stack, or start a harness.",
            f"Promotion ID: {plan['promotion_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Staged source: {parameters['source']}",
            f"Source/catalog SHA-256: {plan['catalog_sha256']}",
            f"Previous protected catalog SHA-256: {plan['previous_catalog_sha256'] or 'none'}",
            f"Source owner UID: {plan['source_uid']}",
            f"Protected host release: {plan['host_release_id']}",
        ]
        for stack in catalog["stacks"]:
            binding = stack["account_binding"]
            details.extend([
                f"Catalog stack: {stack['stack_id']} @ {native_vendor_stack.stack_revision(stack)}",
                f"  Vendor / harness / model: {stack['vendor_id']} / {stack['harness']['harness_id']} / {stack['model']['model_id']}",
                f"  Account subject SHA-256: {binding['account_subject_sha256'] or 'unbound'}",
                f"  Workspace SHA-256: {binding['workspace_sha256'] or 'unbound'}",
                f"  Program / tier: {binding['program_id']} / {binding['program_tier']}",
            ])
        details.extend([
            "Precondition: no native-stack transaction or Research native run may be active.",
            "Action: atomically promote only this exact reviewed canonical catalog",
        ])
        return details
    if operation == native_program_attestation.OPERATION:
        plan = native_program_attestation.validate_plan(parameters["plan"])
        return [
            "External-program declaration: operator attestation only; the provider does not verify this program enrollment.",
            f"Attestation ID: {plan['attestation_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Stack: {plan['stack_id']} @ {plan['stack_sha256']}",
            f"Protected catalog SHA-256: {plan['catalog_sha256']}",
            f"Observed status SHA-256: {plan['status_sha256']}",
            f"Harness generation: {plan['harness_generation_id']}",
            f"Account subject SHA-256: {plan['account_subject_sha256']}",
            f"Workspace SHA-256: {plan['workspace_sha256']}",
            f"Program / tier: {plan['program_id']} / {plan['program_tier']}",
            f"Requirements snapshot: {plan['program_requirements_version']}",
            "Assurance classification: operator-external (never provider-verified)",
            "Precondition: authentication and account binding are exact; network is closed; no native run is active.",
            "Action: persist only this exact external-program declaration for the bound Anthropic stack.",
        ]
    if operation == native_projection_reconciliation.OPERATION:
        plan = native_projection_reconciliation.validate_plan(
            parameters["plan"]
        )
        return [
            "Credential recovery: clear exactly one stranded OpenAI projection only after independent guest-absence and egress-closure proof.",
            f"Recovery operation ID: {plan['recovery_operation_id']}",
            f"Original session operation ID: {plan['original_operation_id']}",
            f"Session ID: {plan['session_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Stack: {plan['stack_id']} @ {plan['stack_sha256']}",
            f"Session authority SHA-256: {plan['session_authority_sha256']}",
            f"Credential consumer PID/start: {plan['process_identifier']} / {plan['process_start_time_us']}",
            f"Credential consumer executable SHA-256: {plan['consumer_executable_sha256']}",
            f"Guest absence evidence SHA-256: {plan['guest_absence_evidence_sha256']}",
            f"Closed egress evidence SHA-256: {plan['egress_closed_evidence_sha256']}",
            f"Protected host release: {plan['host_release_id']}",
            "The helper independently rechecks exact PID-generation absence; elapsed time or PID absence alone never clears custody.",
            "Action: consume one exact recovery ticket and terminalize only the matching stranded projection.",
        ]
    if operation == native_projection_identity_recovery.OPERATION:
        plan = native_projection_identity_recovery.validate_plan(
            parameters["plan"]
        )
        return [
            "Credential recovery phase one: disclose only the exact committed consumer identity; this does not clear credential custody.",
            f"Recovery operation ID: {plan['recovery_operation_id']}",
            f"Original session operation ID: {plan['original_operation_id']}",
            f"Session ID: {plan['session_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Stack: {plan['stack_id']} @ {plan['stack_sha256']}",
            f"Session authority SHA-256: {plan['session_authority_sha256']}",
            f"Protected host release: {plan['host_release_id']}",
            "The signed helper consumes one exact ticket, matches one committed ledger entry, and returns only PID/start/executable/session digests.",
            "Action: import the content-free identity into the root journal; a second Touch ID closure/reconciliation ceremony remains mandatory.",
        ]
    if operation in native_deployment.OPERATIONS:
        if operation == native_deployment.APPLY_OPERATION:
            plan_response = validate_native_deployment_plan_response(
                parameters["plan"])
            action = "apply"
            active = "none"
        else:
            recovery = validate_native_deployment_recovery_plan(
                parameters["recovery"])
            plan_response = recovery["plan_response"]
            action = parameters["action"]
            active = recovery["active_journal_sha256"]
        plan = plan_response["plan"]
        gateway = plan_response["prior_gateway"]
        research = plan_response["prior_research"]
        return [
            f"Native deployment action: {action}",
            f"Deployment ID: {plan['deployment_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Protected host release: {plan['host_release_id']}",
            f"Protected catalog SHA-256: {plan['catalog_sha256']}",
            f"Payload container SHA-256: {plan_response['payload_container_sha256']}",
            f"Gateway candidate package SHA-256: {plan['gateway_package_sha256']}",
            f"Research candidate package SHA-256: {plan['research_package_sha256']}",
            ("Gateway predecessor: "
             f"{gateway['generation_kind']} / {gateway['release_id'] or 'absent'} / "
             f"{plan['previous_gateway_status_sha256']}"),
            ("Gateway predecessor package / catalog / closed evidence: "
             f"{gateway['package_sha256'] or 'absent'} / "
             f"{gateway['catalog_sha256'] or 'none'} / "
             f"{gateway['closed_evidence_sha256'] or 'absent'}"),
            ("Research predecessor: "
             f"{research['generation_kind']} / {research['release_id'] or 'absent'} / "
             f"{plan['previous_research_status_sha256']}"),
            ("Research predecessor package / catalog / closed evidence: "
             f"{research['package_sha256'] or 'absent'} / "
             f"{research['catalog_sha256'] or 'none'} / "
             f"{research['closed_evidence_sha256'] or 'absent'}"),
            f"Active deployment journal SHA-256: {active}",
            "Authorization requires Touch ID; password fallback is forbidden.",
            "Action: execute only this exact release-authored deployment plan",
        ]
    if operation in {"native-session-start", "native-session-stop"}:
        plan = native_stack_session.validate_plan(parameters["plan"])
        context = plan["runtime_authority"]["session_context_binding"]
        harness = plan["runtime_authority"]["harness_binding"]
        native = plan["runtime_authority"]["model_stack_binding"]["authority"]
        return [
            f"Native session action: {plan['action']}",
            f"Action ID: {plan['action_id']}",
            f"Session ID: {plan['session_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Runtime authority SHA-256: {plan['runtime_authority_sha256']}",
            f"Stack: {plan['stack_id']} @ {plan['stack_sha256']}",
            f"Protected catalog SHA-256: {plan['catalog_sha256']}",
            f"Observed status SHA-256: {plan['status_sha256']}",
            f"Harness generation: {harness['harness_generation_id']}",
            f"Harness executable SHA-256: {harness['harness_executable_sha256']}",
            f"Model: {native['model_id']}",
            f"Source ID: {plan['source_id'] or 'none'}",
            f"Source manifest SHA-256: {plan['source_manifest_sha256'] or 'none'}",
            f"Persona SHA-256: {context['persona_sha256']}",
            f"Tool catalog SHA-256: {context['tool_catalog_sha256']}",
            f"Extension set SHA-256: {context['extension_set_sha256']}",
            f"Resume prior session: {plan['resume_session_id'] or 'none'}",
            f"Lease profile: {plan['lease_profile_id'] or 'none'}",
            "Session start prepares authority with egress closed; the one-shot terminal claim opens it.",
            "Session stop kills/reaps the exact Research scope before closing egress and proving absence.",
        ]
    if operation.startswith("native-stack-"):
        plan = native_stack_operations.validate_plan(parameters["plan"])
        identity = plan["identity"]
        impact = plan["impact"]
        return [
            f"Native action: {plan['action']}",
            f"Action ID: {plan['action_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Stack: {identity['stack_id']} @ {identity['stack_sha256']}",
            f"Vendor / harness: {identity['vendor_id']} / {identity['harness_id']}",
            f"Harness generation: {identity['harness_generation_id'] or 'unconfigured'}",
            f"Harness adapter: {identity['harness_adapter_id']}",
            f"Authentication / custody: {identity['authentication_mode']} / {identity['credential_custody']}",
            f"Account binding SHA-256: {identity['account_subject_sha256'] or 'unbound'}",
            f"Workspace binding SHA-256: {identity['workspace_sha256'] or 'unbound'}",
            f"Observed account SHA-256: {plan['observed_account_subject_sha256'] or 'not supplied'}",
            f"Observed workspace SHA-256: {plan['observed_workspace_sha256'] or 'not supplied'}",
            f"Program / tier: {identity['program_id']} / {identity['program_tier']}",
            f"Requirements snapshot: {identity['program_requirements_version']}",
            f"Model: {identity['model_id']}",
            f"Model settings SHA-256: {identity['model_settings_sha256']}",
            f"Network policy / phase: {identity['network_policy_id']} / {plan['requested_network_phase']}",
            f"Current status SHA-256: {plan['current_status_sha256']}",
            f"Stops bound runs: {impact['stops_bound_runs']}",
            f"Destroys credentials: {impact['destroys_credentials']}",
            f"Changes live authority: {impact['changes_live_authority']}",
            "Native mode gives the admitted vendor harness credential authority.",
            "Gateway cannot independently enforce native request bodies or selected models.",
            "Action: apply only this exact content-free native-stack plan",
        ]
    if operation.startswith("harness-generation-"):
        action = operation.removeprefix("harness-generation-")
        if action == "recover":
            recovery = parameters["recovery"]
            return [f"Pending journal SHA-256: {recovery['journal_sha256']}",
                    "Action: deterministically recover the exact interrupted transaction"]
        wrapper = parameters["plan"]; plan = wrapper["plan"]
        generation = (plan.get("candidate", {}).get("generation_id")
                      or plan.get("generation_id"))
        return [
            f"Lifecycle action: {action}", f"Generation: {generation}",
            f"Stage ID: {wrapper['stage_id']}", f"Plan ID: {plan['plan_id']}",
            f"Transaction ID: {plan['transaction_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Plan expires (Unix): {plan['expires_at']}",
            "Action: apply only this exact protected Research lifecycle plan",
        ]
    if operation == "harness-acceptance-authorize":
        plan = parameters["plan"]
        return [
            f"Lifecycle action: acceptance-only authorization ({plan['operation']})",
            f"Case: {plan['case_id']}", f"Generation: {plan['generation_id']}",
            f"Plan ID: {plan['plan_id']}",
            f"Transaction ID: {plan['transaction_id']}",
            f"Plan SHA-256: {plan['plan_sha256']}",
            f"Campaign SHA-256: {plan['campaign_sha256']}",
            f"Plan expires (Unix): {plan['expires_at']}",
            "Action: validate only in the isolated disposable acceptance store",
            "Production generation store access: forbidden",
        ]
    if operation == "execution-approval-key-init":
        return [
            f"Research release: {parameters['research_release_id']}",
            "Action: create and prove possession of a non-exportable Secure Enclave execution-approval key",
        ]
    if operation == "execution-approval-migration-activate":
        return [
            f"Migration transaction: {parameters['transaction_id']}",
            f"Research fence evidence SHA-256: {hashlib.sha256(canonical_v2(parameters['research_fence'])).hexdigest()}",
            "Action: irreversibly advance the Host approval floor to protocol v2",
        ]
    if operation == "execution-approval-migration-authorize-acceptance":
        acceptance = parameters["acceptance"]
        return [
            f"Migration transaction: {parameters['transaction_id']}",
            f"Acceptance attempt: {acceptance['acceptance_attempt_number']}",
            f"Attempt ID: {acceptance['acceptance_attempt_id']}",
            f"Run ID: {acceptance['run_id']}",
            f"Session ID: {acceptance['session_id']}",
            f"Source ID: {acceptance['source_id']}",
            f"Code SHA-256: {acceptance['code_sha256']}",
            f"Fixture manifest SHA-256: {acceptance['fixture_manifest_sha256']}",
            f"Timeout: {acceptance['timeout_seconds']} seconds",
            f"Runtime image: {acceptance['runtime_image_id']}",
            f"Acceptance binding SHA-256: {acceptance_attempt_binding(acceptance)}",
            "Action: authorize one exact replacement-safe migration acceptance attempt",
        ]
    if operation == "execution-approval-migration-verify-acceptance":
        evidence = parameters["research_evidence"]
        return [
            f"Migration transaction: {evidence.get('transaction_id')}",
            f"Acceptance run: {evidence.get('run_id')}",
            f"Acceptance session: {evidence.get('session_id')}",
            f"Research receipt SHA-256: {evidence.get('research_receipt_sha256')}",
            "Action: correlate the real execution, consumed marker, and Host authorization receipt",
        ]
    if operation == "execution-approval-migration-commit":
        return [
            f"Migration transaction: {parameters['transaction_id']}",
            f"Research activation evidence SHA-256: {hashlib.sha256(canonical_v2(parameters['research_activation'])).hexdigest()}",
            f"Cold-boot acceptance SHA-256: {parameters['cold_boot_acceptance_sha256']}",
            f"Acceptance verifier SHA-256: {parameters['acceptance_verifier_sha256']}",
            "Action: commit the verified v2 authority generation",
        ]
    if operation == "execution-approval-software-retire":
        return [
            f"Migration transaction: {parameters['transaction_id']}",
            "Action: remove the cryptographically revoked software signing key",
        ]
    if operation == "execution-approval-sign":
        return [
            f"Approval ID: {parameters['approval_id']}",
            f"Run ID: {parameters['run_id']}",
            f"Session ID: {parameters['session_id']}",
            f"Source ID: {parameters['source_id']}",
            f"Source manifest SHA-256: {parameters['source_manifest_sha256']}",
            f"Code SHA-256: {parameters['code_sha256']}",
            f"Fixture manifest SHA-256: {parameters['fixture_manifest_sha256']}",
            "Fixtures: " + (", ".join(
                f"{item['path']} ({item['bytes']} bytes, {item['sha256']})"
                for item in parameters["fixture_manifest"]
            ) or "(none)"),
            f"Timeout: {parameters['timeout_seconds']} seconds",
            f"Runtime image: {parameters['runtime_image_id']}",
            f"Approval expires (Unix): {parameters['expires_at']}",
        ]
    if operation == "host-controller-install":
        plan = parameters["authorized_target_plan"]
        return [
            f"Repository: {parameters['repo']}",
            "Transition operation: install",
            "Authorization scope: deterministic pre-install target plan",
            f"Pre-install target release: {plan['release_id']}",
            "Pre-install payload SHA-256 map: "
                f"{canonical(plan['payloads']).decode('ascii').strip()}",
            "Pre-install target launcher SHA-256: "
                f"{plan['target_launcher_sha256']}",
            "Retained candidate record SHA-256: "
                f"{plan['candidate_record_sha256']}",
            f"Source stable pair SHA-256: {plan['source_stable_sha256']}",
            "Authorized pre-install target plan SHA-256: "
                f"{parameters['authorized_target_plan_sha256']}",
            "Installed authority and tree identity are derived only after authorization; they are not facts in this prompt.",
        ]
    if operation == "host-controller-rollback":
        plan = parameters["authorized_target_plan"]
        return [
            f"Repository: {parameters['repo']}",
            "Transition operation: rollback",
            f"Installed target release: {plan['target_release_id']}",
            "Installed target launcher SHA-256: "
                f"{plan['target_launcher_sha256']}",
            "Installed target authority SHA-256: "
                f"{plan['target_candidate_authority_sha256']}",
            "Installed target tree identity SHA-256: "
                f"{plan['target_release_tree_identity_sha256']}",
            f"Source stable pair SHA-256: {plan['source_stable_sha256']}",
            "Authorized rollback target plan SHA-256: "
                f"{parameters['authorized_target_plan_sha256']}",
        ]
    if operation == "pki-anchor-begin":
        return [f"PKI generation: {parameters['generation_id']}"]
    if operation.startswith("installer-"):
        return [f"Repository: {parameters['repo']}",
                f"Release directory: {parameters['release_directory']}",
                f"Installer SHA-256: {parameters['expected_sha256']}"]
    if operation in {"vm-create", "vm-reprovision"}:
        return [f"Repository: {parameters['repo']}",
                f"VM set: {OPERATION_RESOURCES[operation]}",
                f"VM layout: {parameters['layout_profile']} ({parameters['host_memory_bytes']} host bytes)",
                "VM resources: " + ", ".join(
                    f"{role}={parameters['layout'][role]['cpus']} CPU/"
                    f"{parameters['layout'][role]['memory_mib']} MiB RAM/"
                    f"{parameters['layout'][role]['disk_mib']} MiB disk"
                    for role in ("gateway", "research", "target")
                ),
                f"Plan SHA-256: {parameters['plan_sha256']}",
                f"Parallels CLI SHA-256: {parameters['prlctl_sha256']}",
                f"Installer SHA-256: {parameters['installer_sha256']}",
                "Seed SHA-256 values: " + ", ".join(
                    f"{role}={parameters['seed_sha256'][role]}" for role in ("gateway", "research", "target")
                )]
    if operation == "vm-preserve-legacy":
        tool_set_sha256 = hashlib.sha256(canonical(parameters["tools"])).hexdigest()
        return [
            f"Repository: {parameters['repo']}",
            f"Quarantine generation: {parameters['generation']}",
            f"Plan operation: {parameters['plan_operation']}",
            f"Recovery transaction: {parameters['recovery_transaction_sha256'] or '(none)'}",
            f"Plan SHA-256: {parameters['plan_sha256']}",
            f"Parallels CLI SHA-256: {parameters['prlctl_sha256']}",
            f"Protected control client SHA-256: {parameters['protected_control_client_sha256']}",
            f"Protected SSH configuration SHA-256: {parameters['protected_ssh_config_sha256']}",
            f"Migration tool-set SHA-256: {tool_set_sha256}",
            f"Migration planner SHA-256: {parameters['tools']['preservation_planner']}",
            f"Migration executor SHA-256: {parameters['tools']['preservation_executor']}",
            "Legacy VM identities: " + ", ".join(
                f"{role}={parameters['legacy_vm_uuid'][role]}" for role in ("research", "gateway", "target")
            ),
            "Legacy disk-chain content trees: " + ", ".join(
                f"{role}={parameters['source_tree_sha256'][role]}" for role in ("research", "gateway", "target")
            ),
            "Fresh transport VMs: " + ", ".join(
                f"{name}={parameters['transport_vm_uuid'][name]}"
                for name in ("SecureSandbox-Gateway", "SecureSandbox-Research")
            ),
        ]
    return [f"PKI generation: {parameters['generation_id']}",
            f"Manifest SHA-256: {parameters['manifest_sha256']}",
            f"Expected current: {parameters['expected_current'] or '(none)'}"]


PREFLIGHT_SCRIPT = r'''
on run argv
  tell application "System Events"
    activate
    set answer to display dialog (item 1 of argv) with title "SecureSandbox Authorization" buttons {"Cancel", "Continue"} default button "Cancel" cancel button "Cancel" with icon caution giving up after 90
    if gave up of answer then error number -128
    return button returned of answer
  end tell
end run
'''


AUTH_SCRIPT = r'''
on run argv
  set brokerPath to item 1 of argv
  set invokingUid to item 2 of argv
  set requestId to item 3 of argv
  set requestDigest to item 4 of argv
  set promptText to item 5 of argv
  set commandText to quoted form of brokerPath & " execute --uid " & quoted form of invokingUid & " --request-id " & quoted form of requestId & " --request-sha256 " & quoted form of requestDigest
  do shell script commandText with administrator privileges with prompt promptText
end run
'''


def request_authorization(agent: str, session: str, purpose: str, resource: str,
                          operation: str, parameters: dict[str, Any], now: int | None = None,
                          runner=run_process, native_ui_path: Path | None = None,
                          ceremony: str = "approve",
                          request_id: str | None = None) -> int:
    agent, session = validate_identity(agent, session)
    purpose = clean_text(purpose, "purpose", MAX_PURPOSE)
    resource = clean_text(resource, "resource", MAX_RESOURCE)
    if ceremony not in CEREMONIES:
        raise AuthorizationTerminalError("ceremony_invalid", operation=operation)
    if request_id is not None:
        valid_uuid4(request_id)
    uid = os.geteuid()
    if uid == 0:
        raise AuthorizationError("unprivileged_request_required")
    home = Path(pwd.getpwuid(uid).pw_dir)
    validate_parameters(operation, parameters, home)
    if (operation == "harness-acceptance-authorize"
            and parameters["plan"].get("operator_uid") != uid):
        raise AuthorizationError("harness_operator_uid_mismatch")
    if resource != OPERATION_RESOURCES.get(operation):
        raise AuthorizationError("operation_resource_mismatch")
    directory = request_directory(home)
    secure_user_directory(directory, uid)
    lock_path = directory / "active.lock"
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        lock_info = os.fstat(lock_descriptor)
        if lock_info.st_uid != uid or stat.S_IMODE(lock_info.st_mode) != 0o600:
            raise AuthorizationError("authorization_lock_untrusted")
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise AuthorizationError("authorization_request_in_progress")
                time.sleep(0.05)
        created = int(time.time()) if now is None else now
        request_id = str(uuid.uuid4()) if request_id is None else request_id
        value = {
            "schema": SCHEMA, "request_id": request_id, "created_at": created,
            "expires_at": created + REQUEST_TTL_SECONDS, "invoking_uid": uid,
            "declared_agent": agent, "declared_session": session,
            "identity_evidence": "operator-declared", "purpose": purpose, "resource": resource,
            "operation": operation, "parameters": parameters, "ceremony": ceremony,
        }
        path = directory / f"{request_id}.json"
        write_request(path, value)
        request_sha256 = hashlib.sha256(canonical(value)).hexdigest()
        message = preflight_message(value, request_sha256)
        print(message, file=sys.stderr, flush=True)
        try:
            ui_path = DEFAULT_TOUCHID_UI if native_ui_path is None else native_ui_path
            if ui_path.is_file():
                if native_ui_path is None:
                    try:
                        native = run_touchid_app(
                            ui_path, path, request_sha256, TOUCHID_SOCKET,
                            authorization_client_timeout(operation), uid,
                        )
                    except AuthorizationError as error:
                        raise AuthorizationTerminalError(
                            str(error), request_id, operation
                        ) from error
                else:
                    native = runner([
                        str(ui_path), "--request-path", str(path),
                        "--request-sha256", request_sha256,
                        "--socket-path", str(TOUCHID_SOCKET),
                    ], authorization_client_timeout(operation))
                native_outcome = getattr(native, "outcome", None)
                if native_outcome == "broker-result" and native.returncode == 0:
                    if native.stdout:
                        sys.stdout.write(native.stdout)
                    if native.stderr:
                        sys.stderr.write(native.stderr)
                    return 0
                if (native_outcome == "cancelled"
                        and native.returncode == TOUCHID_CANCELLED_EXIT):
                    raise AuthorizationTerminalError("operator_cancelled", request_id, operation)
                if native_outcome == "expired" and native.returncode == TOUCHID_EXPIRED_EXIT:
                    raise AuthorizationTerminalError("request_expired", request_id, operation)
                if native_outcome == "dismissed":
                    raise AuthorizationTerminalError(
                        "authorization_window_dismissed", request_id, operation
                    )
                if native_outcome == "biometric-rejected":
                    raise AuthorizationTerminalError("touch_id_rejected", request_id, operation)
                if (native_outcome == "password-fallback"
                        and native.returncode == TOUCHID_PASSWORD_FALLBACK_EXIT
                        and ceremony != "approve"):
                    raise AuthorizationTerminalError(
                        "ceremony_execution_forbidden", request_id, operation
                    )
                if (native_outcome == "password-fallback"
                        and native.returncode == TOUCHID_PASSWORD_FALLBACK_EXIT
                        and operation_requires_touchid(operation)):
                    raise AuthorizationTerminalError("touchid_required", request_id, operation)
                if (native_outcome != "password-fallback"
                        or native.returncode != TOUCHID_PASSWORD_FALLBACK_EXIT):
                    raise AuthorizationTerminalError(
                        "privileged_operation_outcome_ambiguous",
                        request_id, operation,
                    )
            if not ui_path.is_file() and ceremony == "cancel-test":
                raise AuthorizationTerminalError(
                    "cancel_test_ui_required", request_id, operation
                )
            if (not ui_path.is_file()
                    and operation_requires_touchid(operation)):
                raise AuthorizationTerminalError("touchid_ui_required", request_id, operation)
            if not ui_path.is_file():
                preflight = runner(
                    ["/usr/bin/osascript", "-e", PREFLIGHT_SCRIPT, "--", message],
                    DIALOG_TIMEOUT_SECONDS,
                )
                if preflight.returncode != 0 or preflight.stdout.strip() != "Continue":
                    raise AuthorizationTerminalError("operator_cancelled", request_id, operation)
            native_prompt = (
                f"SecureSandbox request from {agent} [{session}]\n"
                f"Purpose: {purpose}\nOperation: {operation}\n"
                f"Nonce: {request_id}\nDigest: {request_sha256}"
            )
            native_prompt += "\n" + "\n".join(operation_details(value))
            broker = "/usr/local/libexec/secure-sandbox-host/current/authorization_broker"
            authorized = runner([
                "/usr/bin/osascript", "-e", AUTH_SCRIPT, "--", broker, str(uid), request_id,
                request_sha256, native_prompt,
            ], authorization_client_timeout(operation))
            if authorized.returncode != 0:
                raise AuthorizationTerminalError(
                    "privileged_operation_outcome_ambiguous",
                    request_id, operation,
                )
            if authorized.stdout:
                sys.stdout.write(authorized.stdout)
            if authorized.stderr:
                sys.stderr.write(authorized.stderr)
            return 0
        finally:
            try:
                path.unlink()
            except OSError:
                pass
    finally:
        os.close(lock_descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    request = sub.add_parser("request")
    request.add_argument("--agent", required=True)
    request.add_argument("--session", required=True)
    request.add_argument("--purpose", required=True)
    request.add_argument("--resource", required=True)
    request.add_argument("--operation", required=True)
    request.add_argument("--parameters-json", required=True)
    request.add_argument("--request-id")
    request.add_argument("--ceremony", choices=sorted(CEREMONIES), default="approve")
    execute = sub.add_parser("execute")
    execute.add_argument("--uid", type=int, required=True)
    execute.add_argument("--request-id", required=True)
    execute.add_argument("--request-sha256", required=True)
    sign = sub.add_parser("execution-approval-sign")
    sign.add_argument("--authorization-request-id", required=True)
    sign.add_argument("--host-release-id", required=True)
    sign.add_argument("--parameters-json", required=True)
    sub.add_parser("execution-approval-key-init")
    sub.add_parser("execution-approval-public-key")
    activate = sub.add_parser("execution-approval-migration-activate")
    activate.add_argument("--transaction-id", required=True)
    activate.add_argument("--research-fence-json", required=True)
    authorize_acceptance = sub.add_parser("execution-approval-migration-authorize-acceptance")
    authorize_acceptance.add_argument("--transaction-id", required=True)
    authorize_acceptance.add_argument("--acceptance-json", required=True)
    verify_acceptance = sub.add_parser("execution-approval-acceptance-verify")
    verify_acceptance.add_argument("--research-evidence-json", required=True)
    commit = sub.add_parser("execution-approval-migration-commit")
    commit.add_argument("--transaction-id", required=True)
    commit.add_argument("--research-activation-json", required=True)
    commit.add_argument("--cold-boot-acceptance-sha256", required=True)
    commit.add_argument("--acceptance-verifier-sha256", required=True)
    retire = sub.add_parser("execution-approval-software-retire")
    retire.add_argument("--transaction-id", required=True)
    completion = sub.add_parser("execution-approval-completion-status")
    completion.add_argument("--transaction-id", required=True)
    sub.add_parser("serve-touchid")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "request":
            return request_with_supervisor_custody(args)
        if SUPERVISOR_LIVENESS_ENV in os.environ:
            raise AuthorizationError(
                "authorization_supervisor_liveness_command_invalid"
            )
        if args.command == "serve-touchid":
            release = protected_release_directory(Path(__file__), 0)
            try:
                return serve_touchid()
            except BaseException:
                # A candidate that cannot finish reconciliation, bind, listen,
                # or finalize must not leave launchd retrying the same broken
                # selector forever.  The already authorized transition binds
                # its exact fallback; prepare it, then exit so launchd starts
                # that immutable predecessor and it terminalizes the rollback.
                if pending_host_install_role(release) == "candidate":
                    prepare_failed_host_install_rollback(release)
                raise
        if args.command == "execution-approval-key-init":
            print(json.dumps(execution_approval_key_initialize(), separators=(",", ":"), sort_keys=True))
            return 0
        if args.command == "execution-approval-public-key":
            active = active_secure_enclave_state() if os.geteuid() == 0 else None
            if active is not None:
                value = {
                    "schema":"secure-sandbox-execution-approval-key-v2",
                    "status":"active",
                    "generation_id":active["generation_id"],
                    "generation_epoch":active["generation_epoch"],
                    "algorithm":active["algorithm"],
                    "public_key_spki_der_b64":active["public_key_spki_der_b64"],
                    "public_key_sha256":active["public_key_sha256"],
                }
            else:
                value = execution_approval_key_initialize() if os.geteuid() == 0 else None
                public_v2 = EXECUTION_APPROVAL_ROOT / EXECUTION_APPROVAL_PUBLIC.name
                if value is None and public_v2.exists():
                    info = public_v2.lstat()
                    raw = public_v2.read_bytes()
                    candidate = json.loads(raw)
                    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o644
                            or info.st_nlink != 1 or canonical(candidate) != raw
                            or candidate.get("schema") != "secure-sandbox-execution-approval-key-v2"
                            or candidate.get("status") != "active"):
                        raise AuthorizationError("execution_approval_public_key_untrusted")
                    spki = canonical_base64_decode(
                        candidate.get("public_key_spki_der_b64"), "public_key", 256
                    )
                    if validate_p256_spki(spki) != candidate.get("public_key_sha256"):
                        raise AuthorizationError("execution_approval_public_key_invalid")
                    value = candidate
            if value is None:
                public_floor = EXECUTION_APPROVAL_ROOT / EXECUTION_APPROVAL_PUBLIC_FLOOR.name
                if public_floor.exists():
                    info = public_floor.lstat()
                    floor_raw = public_floor.read_bytes()
                    floor_value = json.loads(floor_raw)
                    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o644
                            or info.st_nlink != 1 or canonical(floor_value) != floor_raw
                            or floor_value.get("schema")
                            != "secure-sandbox-execution-approval-public-floor-v1"
                            or floor_value.get("minimum_protocol") != 2):
                        raise AuthorizationError("execution_approval_public_floor_untrusted")
                    raise AuthorizationError("execution_approval_v2_authority_unavailable")
                public = EXECUTION_APPROVAL_KEY.with_suffix(".pub")
                info = public.lstat()
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o644
                        or info.st_nlink != 1):
                    raise AuthorizationError("execution_approval_public_key_untrusted")
                fields = public.read_text(encoding="ascii").strip().split()
                if len(fields) < 2 or fields[0] != "ssh-ed25519":
                    raise AuthorizationError("execution_approval_public_key_invalid")
                normalized = " ".join(fields[:2])
                value = {"schema":"secure-sandbox-execution-approval-key-v1",
                         "public_key":normalized,
                         "public_key_sha256":hashlib.sha256((normalized + "\n").encode("ascii")).hexdigest(),
                         "status":"ready"}
            print(json.dumps(value, separators=(",", ":"), sort_keys=True))
            return 0
        if args.command == "execution-approval-completion-status":
            print(json.dumps(
                read_public_completion_receipt(args.transaction_id),
                separators=(",", ":"), sort_keys=True,
            ))
            return 0
        if args.command == "execution-approval-migration-activate":
            print(json.dumps(execution_approval_migration_activate(
                args.transaction_id, json.loads(args.research_fence_json),
            ), separators=(",", ":"), sort_keys=True))
            return 0
        if args.command == "execution-approval-migration-authorize-acceptance":
            print(json.dumps(execution_approval_authorize_acceptance(
                args.transaction_id, json.loads(args.acceptance_json),
            ), separators=(",", ":"), sort_keys=True))
            return 0
        if args.command == "execution-approval-acceptance-verify":
            print(json.dumps(execution_approval_acceptance_verify(
                json.loads(args.research_evidence_json),
            ), separators=(",", ":"), sort_keys=True))
            return 0
        if args.command == "execution-approval-migration-commit":
            print(json.dumps(execution_approval_migration_commit(
                args.transaction_id, json.loads(args.research_activation_json),
                args.cold_boot_acceptance_sha256,
                args.acceptance_verifier_sha256,
            ), separators=(",", ":"), sort_keys=True))
            return 0
        if args.command == "execution-approval-software-retire":
            print(json.dumps(execution_approval_software_retire(
                args.transaction_id,
            ), separators=(",", ":"), sort_keys=True))
            return 0
        if args.command == "execution-approval-sign":
            print(json.dumps(sign_execution_approval(
                args.parameters_json, args.authorization_request_id, args.host_release_id,
            ), separators=(",", ":"), sort_keys=True))
            return 0
        return execute_request(args.uid, args.request_id, args.request_sha256)
    except (AuthorizationError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        if isinstance(error, AuthorizationTerminalError):
            code = error.code
            request_id = error.request_id
            operation = error.operation
        elif isinstance(error, AuthorizationError):
            code = str(error)
            request_id = None
            operation = getattr(args, "operation", None)
        else:
            code = "authorization_internal_error"
            request_id = None
            operation = getattr(args, "operation", None)
        print(json.dumps(
            diagnostic_record(code, request_id, operation),
            separators=(",", ":"), sort_keys=True,
        ), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
