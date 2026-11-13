#!/usr/bin/env python3
"""Publish, verify, and roll back immutable host-controller releases."""

from __future__ import annotations

import argparse
import ast
import contextlib
import contextvars
import ctypes
import datetime
import errno
import fcntl
import functools
import hashlib
import hmac
import io
import inspect
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
import tarfile
import tempfile
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

SCHEMA = "secure-sandbox-host-controller-release-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0
_ACL_LIBC = ctypes.CDLL(None, use_errno=True)
_ACL_GET_FD_NP = getattr(_ACL_LIBC, "acl_get_fd_np", None)
_ACL_GET_ENTRY = getattr(_ACL_LIBC, "acl_get_entry", None)
_ACL_FREE = getattr(_ACL_LIBC, "acl_free", None)
if _ACL_GET_FD_NP is not None:
    _ACL_GET_FD_NP.argtypes = [ctypes.c_int, ctypes.c_int]
    _ACL_GET_FD_NP.restype = ctypes.c_void_p
if _ACL_GET_ENTRY is not None:
    _ACL_GET_ENTRY.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
    ]
    _ACL_GET_ENTRY.restype = ctypes.c_int
if _ACL_FREE is not None:
    _ACL_FREE.argtypes = [ctypes.c_void_p]
    _ACL_FREE.restype = ctypes.c_int
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
    "native_stack_deployer": Path("scripts/native-stack-deploy.py"),
    "native_stack_coordination_contract": Path(
        "config/native-stack-coordination-contract.json"
    ),
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
    "native_host_products_notarization_signature": Path(
        "artifacts/host/SecureSandboxNativeHostProducts.notarization.sig"
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
UNTRACKED_PAYLOAD_NAMES = {
    "authorization_ui_bundle", "authorization_ui_sources",
    "native_stack_credential_client", "native_projection_consumer",
    "native_credential_helper_bundle", "native_host_products_container",
    "native_host_products_manifest", "native_host_products_notarization",
    "native_host_products_notarization_signature", "seed_gateway",
    "seed_research", "seed_target", "ssh_config",
}
NATIVE_HOST_GENERATION_PAYLOAD_NAMES = {
    "authorization_ui_bundle", "authorization_ui_sources",
    "native_stack_credential_client", "native_projection_consumer",
    "native_credential_helper_bundle", "native_host_products_container",
    "native_host_products_manifest", "native_host_products_notarization",
    "native_host_products_notarization_signature",
}
LOCAL_UNTRACKED_PAYLOAD_NAMES = (
    UNTRACKED_PAYLOAD_NAMES - NATIVE_HOST_GENERATION_PAYLOAD_NAMES
)
NATIVE_HOST_SOURCE_ARCHIVE_NAME = (
    "SecureSandboxNativeHostProducts.source.tar"
)
NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME = (
    "SecureSandboxHostReleasePreimage.tar"
)
NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA = (
    "secure-sandbox-native-host-release-preimage-v1"
)
NATIVE_HOST_RETAINED_CANDIDATE_CLASSIFICATION_SCHEMA = (
    "secure-sandbox-native-host-retained-candidate-classification-v1"
)
NATIVE_HOST_SECURE_ENCLAVE_INPUT_SCHEMA = (
    "secure-sandbox-secure-enclave-release-input-v1"
)
NATIVE_HOST_RELEASE_PREIMAGE_PAYLOAD_NAMES = frozenset({
    "authorization_broker", "authorization_service", "control_client",
    "controller", "gpgv", "harness_lifecycle_manager",
    "installer_verifier", "model_profile_manager",
    "native_credential_helper_service", "native_deployment_payloads",
    "native_stack_backend", "native_stack_catalog_promoter",
    "native_stack_coordination_contract", "native_stack_deployer",
    "native_stack_manager", "native_stack_session_manager",
    "native_stack_support", "native_stack_terminal_bridge", "pki_anchor",
    "release_manager", "seed_gateway", "seed_research", "seed_target",
    "seed_verifier", "ssh_config", "vm_maintenance",
})
NATIVE_HOST_CANDIDATE_RECORD_V1_SCHEMA = (
    "secure-sandbox-native-host-candidate-record-v1"
)
NATIVE_HOST_CANDIDATE_RECORD_SCHEMA = (
    "secure-sandbox-native-host-candidate-record-v2"
)
NATIVE_HOST_BUILD_CUSTODY = "trusted-login-principal-v1"
NATIVE_HOST_GENERATION_TOP_LEVEL = {
    "SecureSandboxAuthorizationUI.app": "directory",
    "SecureSandboxAuthorizationUI.bundle.json": "file",
    "SecureSandboxAuthorizationUI.sources.json": "file",
    "SecureSandboxNativeCredentialHelper.app": "directory",
    "SecureSandboxNativeComponents.bundle.json": "file",
    "SecureSandboxNativeHostProducts.dmg": "file",
    "SecureSandboxNativeHostProducts.manifest.json": "file",
    "SecureSandboxNativeHostProducts.notarization.json": "file",
    "SecureSandboxNativeHostProducts.notarization.sig": "file",
    "SecureSandboxNativeProjectionConsumer": "file",
    "SecureSandboxNativeStackBackend": "file",
    NATIVE_HOST_SOURCE_ARCHIVE_NAME: "file",
}
NATIVE_STACK_SUPPORT_SOURCES = {
    "native_deployment_payload.py": Path("scripts/native_deployment_payload.py"),
    "shared/__init__.py": Path("shared/__init__.py"),
    "shared/harness_runtime_binding.py": Path("shared/harness_runtime_binding.py"),
    "shared/model_stack_runtime_binding.py": Path("shared/model_stack_runtime_binding.py"),
    "shared/native_codex_projection.py": Path("shared/native_codex_projection.py"),
    "shared/native_codex_ui_handle.py": Path("shared/native_codex_ui_handle.py"),
    "shared/native_deployment.py": Path("shared/native_deployment.py"),
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
PAYLOAD_NAMES = {
    *PAYLOAD_SOURCES, "gpgv", "native_stack_support",
    "native_deployment_payloads",
}
NATIVE_DEPLOYMENT_PAYLOAD_NAMES = {
    "native_stack_deployer", "native_deployment_payloads",
}
NATIVE_STACK_COORDINATION_PAYLOAD_NAMES = {
    "native_stack_coordination_contract",
}
PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES = PAYLOAD_NAMES - {
    "native_host_products_notarization_signature",
}
PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES = (
    PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES
    - NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
)
PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES = (
    PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
    - NATIVE_DEPLOYMENT_PAYLOAD_NAMES
)
LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES = {
    "native_stack_credential_client", "native_projection_consumer",
    "native_credential_helper_bundle", "native_credential_helper_service",
    "native_host_products_container", "native_host_products_manifest",
    "native_host_products_notarization",
}
NATIVE_CREDENTIAL_PAYLOAD_NAMES = LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES | {
    "native_host_products_notarization_signature",
}
NATIVE_HOST_PRODUCT_CONTAINER_PAYLOAD_NAMES = {
    "native_host_products_container", "native_host_products_manifest",
    "native_host_products_notarization",
}
SIGNED_NATIVE_HOST_PRODUCT_CONTAINER_PAYLOAD_NAMES = (
    NATIVE_HOST_PRODUCT_CONTAINER_PAYLOAD_NAMES | {
        "native_host_products_notarization_signature",
    }
)
PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES = PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES - {
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
DEFAULT_LAUNCHER_PATH = Path("/usr/local/bin/secure-sandbox-claude")
DEFAULT_OP_BINARY = Path("/opt/homebrew/bin/op")
DEFAULT_GPGV_BINARY = Path("/opt/homebrew/bin/gpgv")
GPGV_RUNTIME_DIRECTORY_NAME = "gpgv.runtime"
GPGV_RUNTIME_ARCHIVE_COMMENT = b"secure-sandbox-gpgv-runtime-v1"
GPGV_RUNTIME_LIBRARY_SOURCES = {
    "libassuan.9.dylib": Path("/opt/homebrew/opt/libassuan/lib/libassuan.9.dylib"),
    "libgcrypt.20.dylib": Path("/opt/homebrew/opt/libgcrypt/lib/libgcrypt.20.dylib"),
    "libgpg-error.0.dylib": Path("/opt/homebrew/opt/libgpg-error/lib/libgpg-error.0.dylib"),
    "libintl.8.dylib": Path("/opt/homebrew/opt/gettext/lib/libintl.8.dylib"),
    "libnpth.0.dylib": Path("/opt/homebrew/opt/npth/lib/libnpth.0.dylib"),
}
GPGV_RUNTIME_LIBRARY_NAMES = frozenset(GPGV_RUNTIME_LIBRARY_SOURCES)
GPGV_RUNTIME_SYSTEM_DEPENDENCY_PREFIXES = (
    "/System/Library/", "/usr/lib/",
)
OTOOL_BINARY = Path("/usr/bin/otool")
DEFAULT_INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
NATIVE_DEPLOYMENT_STATE_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-deployment"
)
NATIVE_DEPLOYMENT_GATE_SCHEMA = (
    "secure-sandbox-native-deployment-gate-state-v1"
)
NATIVE_CATALOG_PROMOTION_GATE_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-state-v1"
)
NATIVE_CATALOG_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-stack-catalog"
)
NATIVE_CATALOG_TRANSACTIONS = Path(
    "/usr/local/var/lib/secure-sandbox/native-stack-transactions"
)
NATIVE_CATALOG_PUBLIC_STATUS = Path(
    "/usr/local/var/lib/secure-sandbox/native-stack-public/status.json"
)
NATIVE_STACK_COORDINATION_CONTRACT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-contract-v1"
)
NATIVE_STACK_COORDINATION_REQUIRED_FEATURES = {
    "catalog-promotion-gate-v1",
    "deployment-promotion-admission-v1",
    "host-install-transition-fence-v1",
    "host-selector-two-way-gate-v1",
}
NATIVE_STACK_COORDINATION_FLOOR_SCHEMA = (
    "secure-sandbox-native-stack-coordination-minimum-v1"
)
NATIVE_STACK_COORDINATION_FLOOR_NAME = (
    "native-stack-coordination-minimum.json"
)
NATIVE_STACK_COORDINATION_FLOOR_PENDING_NAME = (
    ".native-stack-coordination-minimum.pending"
)
NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-enforcement-v1"
)
NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME = (
    "native-stack-coordination-enforcement.json"
)
NATIVE_STACK_COORDINATION_ENFORCEMENT_PENDING_NAME = (
    ".native-stack-coordination-enforcement.pending"
)
NATIVE_STACK_COORDINATION_PREDECESSOR_NAME = (
    "native-stack-coordination-predecessor"
)
NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE = (
    "native-host-candidate-admission-v1"
)
NATIVE_HOST_CANDIDATE_FLOOR_SCHEMA = (
    "secure-sandbox-native-host-candidate-minimum-v1"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-native-host-candidate-enforcement-v1"
)
NATIVE_HOST_CANDIDATE_FLOOR_NAME = "native-host-candidate-minimum.json"
NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME = (
    ".native-host-candidate-minimum.pending"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME = (
    "native-host-candidate-enforcement.json"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME = (
    ".native-host-candidate-enforcement.pending"
)
NATIVE_HOST_CANDIDATE_AUTHORITY_DIRECTORY = (
    "native-host-candidate-authorities"
)
NATIVE_HOST_CANDIDATE_AUTHORITY_SCHEMA = (
    "secure-sandbox-native-host-candidate-authority-v1"
)
NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA = (
    "secure-sandbox-native-host-candidate-authority-v2"
)
HOST_RELEASE_LAUNCHER_PAIR_FEATURE = (
    "host-release-launcher-pair-fence-v1"
)
HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA = (
    "secure-sandbox-host-release-launcher-pair-v1"
)
HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA = (
    "secure-sandbox-host-release-launcher-pair-transition-v1"
)
HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME = (
    "host-release-launcher-pair.json"
)
NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE = (
    "candidate-schema-bootstrap"
)
NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE = (
    "authorization-bootstrap"
)
HOST_PAIR_BOOTSTRAP_ADMISSION_SCHEMA = (
    "secure-sandbox-host-pair-bootstrap-admission-v1"
)
AUTHORIZATION_COORDINATION_PREDECESSOR_NAME = (
    "authorization-coordination-predecessor"
)
# The only pre-coordination release admitted by the terminal migration below.
# These are SHA-256 digests of the deterministic payloads built from d8653cb;
# the complete historical payload inventory is checked separately.  Ordinary
# Host mutations never use this compatibility authority.
D8653CB_NATIVE_COORDINATION_PAYLOAD_SHA256 = {
    # The exception also depends on d8653cb's single-request broker: after
    # launchd ingress is fenced, draining the two legacy locks accounts for
    # every promoter it could already have started.
    "authorization_broker": (
        "04ab28791376b9d982c485a6a33bfe62d1349bc9d0e2889764f1a2fa5fca6242"
    ),
    "authorization_service": (
        "523f50335f564d4cb705030a592eed9bdb3950b8a0e69513cea09588be93bb67"
    ),
    "release_manager": (
        "306d60395a4ea07090b355208017176f162a0f82e8d073ed59eb77aaeaed91a5"
    ),
    "native_stack_catalog_promoter": (
        "589b562d644812db156fb594b76b9ae2a06c98c98a9569bf36f0adf7bf92fd8e"
    ),
    "native_stack_deployer": (
        "e487d9af9f3cb1cc1586ad6c322ecae8554e47f4efdbb6f8d431df20878056c0"
    ),
    "native_stack_support": (
        "40b052f369f827d2b05521e00db5954062cd48fcaedbc848f93bf700bc11b2ea"
    ),
    "native_deployment_payloads": (
        "e1ef64cbe2598dfd00d4e40b0b972e4d70758c75abef7d4ee1e26859ef0cb328"
    ),
}
NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID = (
    "c5a743994359cd4af0d9b56fa9385afbcbf52370d96d6c97a47b188d8c88844c"
)
NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS = {
    "authorization_broker": "9627b3d3dbefb8887662f8d5113c997a2b5b520851bc69d1c63a2173b8b846d4",
    "authorization_service": "523f50335f564d4cb705030a592eed9bdb3950b8a0e69513cea09588be93bb67",
    "authorization_ui_bundle": "9a2cb2eb7e77255025526ac510644cae90b18087224047e6fd2b3740045794ea",
    "authorization_ui_sources": "876cf0b5407464f0a2f88271dc3189d8bfe125ee73a55e06142ed70b76d9cc89",
    "control_client": "916751f617a175cdd9847e96a9aff515147cb7c2b7c42045b16c5a020ad073bc",
    "controller": "e6dad9854b1da5ba81fc9b25f560a10ec82a3220a0f25a8a17bd0f1a1c5eb8c5",
    "gpgv": "463e36f6f62b7f489e2f80cf9c1019560ce76e48809d6fef49c9f44ea35147c0",
    "harness_lifecycle_manager": "a05d4f06b77628383f32b9948e9e3ab016bdf82586ab610958d70c6ebd2b815b",
    "installer_verifier": "bf4a832597b030b14966697a125135870925e39ad2708ab1ad9faa505905b4d7",
    "model_profile_manager": "8133898392f87648268388ff25417ccecda47116d13855cd4862e473aac225be",
    "native_credential_helper_bundle": "6675288e33f7101fb8aa8560e919ec3012fd6c71b6a66f2be5728690ceaad885",
    "native_credential_helper_service": "8aca1e65610003bbf8ac17edcb374a7feee2c662202c4b10ba150dad2e33b9a7",
    "native_deployment_payloads": "12b1f753510633badbc2daeb6672ec5e75f032efd4f8bfeb590f0456ed9f94ad",
    "native_host_products_container": "0099a576e6fd37e95b42150f6022ffcae7341ee80947dfa0cc2c820c455df375",
    "native_host_products_manifest": "4702af7178b47a918ed8c0c4539a5cc6195e52e58b7d3348c6c5c33819d66b76",
    "native_host_products_notarization": "a2d9b599777295da501c3041cc23f8cef05d633a8f9916a3393ac9e94a657a87",
    "native_projection_consumer": "efffda9bd503fcab35901573ad47e344de686fbfa9db06354e2c8d2d5478f6bd",
    "native_stack_backend": "5aef7f145ca832a21f609fbe9aaff19fb998a84def7ff6f99601b54291128d44",
    "native_stack_catalog_promoter": "b6acf1f8a4e96125408c826ef325a8e7d82052d187e765539c7bce80e0f8a173",
    "native_stack_coordination_contract": "b47a1f595f20595fead110e32a90a90dd36040d0b89c9ea48fc00430ec39c2c2",
    "native_stack_credential_client": "bac4a5a9d676ee75b2e62e71e9284167b84509d869d1e20182035e5dea17ad0e",
    "native_stack_deployer": "11c4f0198c0275c473d1940d2e7f7409118759f68d09dbcfcdac15acf5d2efeb",
    "native_stack_manager": "87498e3fafeeed9b72903cee11f8541be5ae773919efc3d56c53039483424043",
    "native_stack_session_manager": "7b9f764e8fd64c6bb3cdad30dbda22438dd2223d6b2967433115bfd9b0b40712",
    "native_stack_support": "40b052f369f827d2b05521e00db5954062cd48fcaedbc848f93bf700bc11b2ea",
    "native_stack_terminal_bridge": "c7022a111032fb437535dda596b4baf05ae0cbdd71d9763f25c4d8fbd0020f9e",
    "pki_anchor": "3270ed834c339986602763cab3b472f1f8135fa377f199764eacd1e33bc6252a",
    "release_manager": "488a32ebc87918a4720b6f45947c657e24e2a46065d93196043f0e0c3b91cae4",
    "seed_gateway": "0199e3efa00de9979fdbbec1c5345011803561fe55ef0a6479e1bd00a2947689",
    "seed_research": "73695a9fc55892f7c59b1e917552448d9074b512d5bc69d7e5d694536d3c96b3",
    "seed_target": "305a09da11f86dfc996b786c8e8299fec059523d29f739b27189e3e8cfe1026b",
    "seed_verifier": "50a9d2c7540b4662d3731abe3950fc014f0b15f486ebf87444c4fccf189c51d6",
    "ssh_config": "93f1c5c61f6227b01303bd948d3cdb2972fa0745232076556307ea588a1ac1f9",
    "vm_maintenance": "165474e5806714cbd1c0feebc7e87565b861b3d1beceed79e6d821830f7e408c",
}
_HOST_MUTATION_LOCK: contextvars.ContextVar[
    tuple[Path, int, int] | None
] = contextvars.ContextVar("secure_sandbox_host_mutation_lock", default=None)
_CONTROLLER_ADMISSION_FENCE: contextvars.ContextVar[
    tuple[Path, int, int] | None
] = contextvars.ContextVar(
    "secure_sandbox_controller_admission_fence", default=None)
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
DEVELOPER_ID_TEAM_ENFORCEMENT_NAME = (
    "developer-id-team-enforcement.json"
)
DEVELOPER_ID_TEAM_ENFORCEMENT_PENDING_NAME = (
    ".developer-id-team-enforcement.pending"
)
DEVELOPER_ID_TEAM_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-developer-id-team-enforcement-v1"
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
    "native_stack_deployer": 0o755,
    "native_stack_coordination_contract": 0o444,
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
NATIVE_HOST_PRODUCTS_RECEIPT_IDENTIFIER = (
    "org.zebeth.SecureSandbox.NativeHostProductsReceipt"
)
NATIVE_HOST_PRODUCTS_TEAM_ID = "389K3H8Y32"
NATIVE_HOST_PRODUCTS_RECEIPT_V1_SCHEMA = (
    "secure-sandbox-native-host-products-notarization-v1"
)
NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA = (
    "secure-sandbox-native-host-products-notarization-v2"
)
NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA = (
    "secure-sandbox-native-host-products-notarization-v3"
)
NATIVE_HOST_PRODUCTS_V2_PRODUCT_IDENTIFIERS = {
    "authorization_ui": "org.zebeth.SecureSandbox.AuthorizationUI",
    "credential_helper": NATIVE_CREDENTIAL_HELPER_LABEL,
    "native_projection_consumer": NATIVE_PROJECTION_CONSUMER_IDENTIFIER,
    "native_stack_backend": NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
}
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
HOST_PAIR_TRANSITION_SCHEMA = "secure-sandbox-host-pair-transition-v2"
HOST_PAIR_TERMINAL_SCHEMA = "secure-sandbox-host-pair-terminal-v1"
INSTALL_TERMINAL_SCHEMA = "secure-sandbox-host-install-terminal-v1"
INSTALL_TRANSITION_PENDING_NAME = ".install-transition.json"
INSTALL_TRANSITION_DIRECTORY_NAME = "install-transitions"
DEFAULT_AUTHORIZATION_RECEIPT_ROOT = Path(
    "/usr/local/var/log/secure-sandbox/authorization-receipts"
)
DEFAULT_AUTHORIZATION_RECEIPT_RECOVERY_ROOT = Path(
    "/usr/local/var/log/secure-sandbox/authorization-receipt-recoveries"
)
INSTALL_TRANSITION_TTL_SECONDS = 600
INSTALL_TRANSITION_RECORD_LIMIT = 64 * 1024
DEFAULT_AUTHORIZATION_SOCKET = Path(
    "/var/run/secure-sandbox-authorization.sock"
)


class ReleaseFailure(RuntimeError):
    pass


def reject_extended_acl(descriptor: int, failure: str) -> None:
    """Require mode bits to be the complete authority for a trusted inode."""
    if (_ACL_GET_FD_NP is None or _ACL_GET_ENTRY is None
            or _ACL_FREE is None):
        if sys.platform != "darwin":
            return
        raise ReleaseFailure("extended_acl_api_unavailable")
    ctypes.set_errno(0)
    acl = _ACL_GET_FD_NP(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ReleaseFailure(failure)
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = _ACL_GET_ENTRY(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0:
            raise ReleaseFailure(failure)
        if ctypes.get_errno() not in {errno.ENOENT, errno.EINVAL}:
            raise ReleaseFailure(failure)
    finally:
        if _ACL_FREE(acl) != 0:
            raise ReleaseFailure("extended_acl_release_failed")


def verify_acl_free_directory(
    path: Path, expected_uid: int, expected_mode: int, failure: str,
) -> os.stat_result:
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure(failure) from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, failure)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = path.lstat()
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure(failure)
    return opened


def read_acl_free_regular(
    path: Path, expected_uid: int, expected_mode: int, failure: str,
    *, maximum: int = 1024 * 1024 * 1024,
) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure(failure) from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, failure)
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > maximum:
                raise ReleaseFailure(failure)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = path.lstat()
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or size != opened.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure(failure)
    return b"".join(chunks)


def verify_stable_launcher_parent(
    path: Path, expected_uid: int,
) -> os.stat_result:
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure("stable_launcher_parent_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, "stable_launcher_parent_untrusted")
        after = path.lstat()
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) not in {0o700, 0o755}
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)):
        raise ReleaseFailure("stable_launcher_parent_untrusted")
    return opened


def read_trusted_stable_launcher_identity(
    path: Path, expected_uid: int,
) -> tuple[bytes, dict[str, Any]]:
    parent_before = verify_stable_launcher_parent(
        path.parent, expected_uid,
    )
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure("stable_launcher_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, "stable_launcher_untrusted")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(
                descriptor, min(1024 * 1024, 16 * 1024 * 1024 + 1 - size),
            )
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > 16 * 1024 * 1024:
                raise ReleaseFailure("stable_launcher_untrusted")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = path.lstat()
    parent_after = verify_stable_launcher_parent(
        path.parent, expected_uid,
    )
    parent_identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_mtime_ns, item.st_ctime_ns,
    )
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (parent_identity(parent_before) != parent_identity(parent_after)
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o755
            or size != opened.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure("stable_launcher_parent_changed")
    value = b"".join(chunks)
    return value, _installed_identity_record(
        after, "file", digest=sha256_bytes(value),
    )


def read_trusted_stable_launcher(path: Path, expected_uid: int) -> bytes:
    return read_trusted_stable_launcher_identity(path, expected_uid)[0]


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


def source_artifact_directory_identity(repo: Path) -> tuple[int, ...]:
    """Bind one complete transactional artifacts/host publication generation."""
    path = repo / "artifacts/host"
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ReleaseFailure("source_artifact_directory_untrusted") from error
    os.close(descriptor)
    if (not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(named.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
        raise ReleaseFailure("source_artifact_directory_untrusted")
    return (
        opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid,
        opened.st_gid, opened.st_nlink, opened.st_mtime_ns, opened.st_ctime_ns,
    )


def mutable_source_input_identity(repo: Path, relative: Path) -> tuple[object, ...]:
    """Bind one ignored source file and its containing namespace generation."""
    path = repo / relative
    repo_descriptor = -1
    parent_descriptor = -1
    file_descriptor = -1
    try:
        repo_info = repo.lstat()
        parent_info = path.parent.lstat()
        file_info = path.lstat()
        repo_descriptor = os.open(
            repo,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        file_descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        reject_extended_acl(repo_descriptor, "mutable_source_input_untrusted")
        reject_extended_acl(
            parent_descriptor, "mutable_source_input_untrusted",
        )
        reject_extended_acl(file_descriptor, "mutable_source_input_untrusted")
        if ((os.fstat(repo_descriptor).st_dev, os.fstat(repo_descriptor).st_ino)
                != (repo_info.st_dev, repo_info.st_ino)
                or (os.fstat(parent_descriptor).st_dev,
                    os.fstat(parent_descriptor).st_ino)
                != (parent_info.st_dev, parent_info.st_ino)
                or (os.fstat(file_descriptor).st_dev,
                    os.fstat(file_descriptor).st_ino)
                != (file_info.st_dev, file_info.st_ino)):
            raise ReleaseFailure("mutable_source_input_untrusted")
    except OSError as error:
        raise ReleaseFailure("mutable_source_input_untrusted") from error
    finally:
        for descriptor in (
            file_descriptor, parent_descriptor, repo_descriptor,
        ):
            if descriptor >= 0:
                os.close(descriptor)
    if (not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != repo_info.st_uid
            or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not stat.S_ISREG(file_info.st_mode)
            or stat.S_ISLNK(file_info.st_mode)
            or file_info.st_uid != repo_info.st_uid
            or file_info.st_nlink != 1
            or file_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise ReleaseFailure("mutable_source_input_untrusted")
    return (
        file_info.st_dev, file_info.st_ino, file_info.st_mode,
        file_info.st_uid, file_info.st_gid, file_info.st_nlink,
        file_info.st_size, file_info.st_mtime_ns, file_info.st_ctime_ns,
        parent_info.st_dev, parent_info.st_ino, parent_info.st_mode,
        parent_info.st_uid, parent_info.st_gid, parent_info.st_nlink,
        parent_info.st_mtime_ns, parent_info.st_ctime_ns,
    )


def read_mutable_source_input(
    repo: Path, relative: Path, expected: tuple[object, ...],
) -> bytes:
    """Read one ignored input through its already-authorized namespace identity."""
    parent = repo / relative.parent
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        parent_info = os.fstat(parent_descriptor)
        reject_extended_acl(
            parent_descriptor, "mutable_source_input_changed",
        )
        if (
            parent_info.st_dev, parent_info.st_ino, parent_info.st_mode,
            parent_info.st_uid, parent_info.st_gid, parent_info.st_nlink,
            parent_info.st_mtime_ns, parent_info.st_ctime_ns,
        ) != expected[9:]:
            raise ReleaseFailure("mutable_source_input_changed")
        descriptor = os.open(
            relative.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        reject_extended_acl(descriptor, "mutable_source_input_changed")
        opened_identity = (
            opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid,
            opened.st_gid, opened.st_nlink, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns,
        )
        if (opened_identity != expected[:9]
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1):
            raise ReleaseFailure("mutable_source_input_changed")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        named = os.stat(
            relative.name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
        named_parent = os.fstat(parent_descriptor)
        after_identity = (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid,
            after.st_gid, after.st_nlink, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        )
        named_identity = (
            named.st_dev, named.st_ino, named.st_mode, named.st_uid,
            named.st_gid, named.st_nlink, named.st_size,
            named.st_mtime_ns, named.st_ctime_ns,
        )
        parent_identity = (
            named_parent.st_dev, named_parent.st_ino, named_parent.st_mode,
            named_parent.st_uid, named_parent.st_gid, named_parent.st_nlink,
            named_parent.st_mtime_ns, named_parent.st_ctime_ns,
        )
        if (after_identity != expected[:9] or named_identity != expected[:9]
                or parent_identity != expected[9:]):
            raise ReleaseFailure("mutable_source_input_changed")
        return b"".join(chunks)
    except OSError as error:
        raise ReleaseFailure("mutable_source_input_changed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _native_host_generation_snapshot(
    repo: Path, generation: Path,
) -> tuple[tuple[int, ...], str, dict[str, bytes]]:
    """Read one complete generation through a held root descriptor."""
    repo = repo.absolute()
    generation = generation.absolute()
    try:
        expected_uid = repo.lstat().st_uid
        before = generation.lstat()
        root_descriptor = os.open(
            generation,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure("native_host_generation_untrusted") from error
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    entries: dict[str, dict[str, object]] = {}
    captured: dict[str, bytes] = {}
    total_bytes = 0
    try:
        opened_root = os.fstat(root_descriptor)
        if (not stat.S_ISDIR(opened_root.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or identity(before) != identity(opened_root)
                or opened_root.st_uid != expected_uid
                or opened_root.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ReleaseFailure("native_host_generation_untrusted")
        reject_extended_acl(
            root_descriptor, "native_host_generation_extended_acl",
        )

        def inspect(directory: int, prefix: tuple[str, ...]) -> None:
            nonlocal total_bytes
            directory_before = os.fstat(directory)
            try:
                names = sorted(item.name for item in os.scandir(directory))
            except OSError as error:
                raise ReleaseFailure(
                    "native_host_generation_inventory_invalid"
                ) from error
            for name in names:
                if (not name or name in {".", ".."} or "/" in name
                        or "\x00" in name):
                    raise ReleaseFailure(
                        "native_host_generation_inventory_invalid"
                    )
                parts = (*prefix, name)
                relative = "/".join(parts)
                if len(relative) > 1024 or len(entries) >= 4096:
                    raise ReleaseFailure(
                        "native_host_generation_inventory_invalid"
                    )
                try:
                    named = os.stat(
                        name, dir_fd=directory, follow_symlinks=False,
                    )
                except OSError as error:
                    raise ReleaseFailure(
                        "native_host_generation_inventory_invalid"
                    ) from error
                mode = stat.S_IMODE(named.st_mode)
                if (stat.S_ISLNK(named.st_mode)
                        or named.st_dev != opened_root.st_dev
                        or named.st_uid != expected_uid
                        or mode & 0o022):
                    raise ReleaseFailure(
                        "native_host_generation_entry_untrusted"
                    )
                if stat.S_ISDIR(named.st_mode):
                    try:
                        child = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC,
                            dir_fd=directory,
                        )
                        child_opened = os.fstat(child)
                    except OSError as error:
                        raise ReleaseFailure(
                            "native_host_generation_entry_untrusted"
                        ) from error
                    try:
                        if identity(named) != identity(child_opened):
                            raise ReleaseFailure(
                                "native_host_generation_entry_changed"
                            )
                        reject_extended_acl(
                            child,
                            "native_host_generation_entry_extended_acl",
                        )
                        entries[relative] = {
                            "kind": "directory", "mode": mode,
                        }
                        inspect(child, parts)
                        child_after = os.fstat(child)
                        current = os.stat(
                            name, dir_fd=directory, follow_symlinks=False,
                        )
                        if (identity(child_opened) != identity(child_after)
                                or identity(child_after) != identity(current)):
                            raise ReleaseFailure(
                                "native_host_generation_entry_changed"
                            )
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
                    raise ReleaseFailure(
                        "native_host_generation_entry_untrusted"
                    )
                try:
                    descriptor = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                    opened = os.fstat(descriptor)
                except OSError as error:
                    raise ReleaseFailure(
                        "native_host_generation_entry_untrusted"
                    ) from error
                digest = hashlib.sha256()
                size = 0
                blocks: list[bytes] | None = [] if not prefix else None
                try:
                    if identity(named) != identity(opened):
                        raise ReleaseFailure(
                            "native_host_generation_entry_changed"
                        )
                    reject_extended_acl(
                        descriptor,
                        "native_host_generation_entry_extended_acl",
                    )
                    while True:
                        block = os.read(descriptor, 1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                        size += len(block)
                        if blocks is not None:
                            blocks.append(block)
                        if total_bytes + size > 1024 * 1024 * 1024:
                            raise ReleaseFailure(
                                "native_host_generation_too_large"
                            )
                    after = os.fstat(descriptor)
                    current = os.stat(
                        name, dir_fd=directory, follow_symlinks=False,
                    )
                finally:
                    os.close(descriptor)
                if (identity(opened) != identity(after)
                        or identity(after) != identity(current)
                        or size != opened.st_size):
                    raise ReleaseFailure(
                        "native_host_generation_entry_changed"
                    )
                total_bytes += size
                entries[relative] = {
                    "kind": "file", "mode": mode,
                    "sha256": digest.hexdigest(), "size": size,
                }
                if blocks is not None:
                    captured[name] = b"".join(blocks)
            directory_after = os.fstat(directory)
            if identity(directory_before) != identity(directory_after):
                raise ReleaseFailure("native_host_generation_changed")

        inspect(root_descriptor, ())
        root_after = os.fstat(root_descriptor)
        root_named = generation.lstat()
        if (identity(opened_root) != identity(root_after)
                or identity(root_after) != identity(root_named)):
            raise ReleaseFailure("native_host_generation_changed")
    finally:
        os.close(root_descriptor)
    top_level = {
        relative: record["kind"]
        for relative, record in entries.items() if "/" not in relative
    }
    if top_level != NATIVE_HOST_GENERATION_TOP_LEVEL:
        raise ReleaseFailure("native_host_generation_inventory_invalid")
    record = {
        "entries": entries,
        "root_mode": stat.S_IMODE(opened_root.st_mode),
        "schema": "secure-sandbox-native-host-generation-tree-v1",
    }
    raw = (json.dumps(
        record, allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ) + "\n").encode("ascii")
    return identity(opened_root), sha256_bytes(raw), captured


def native_host_source_snapshot_from_generation(
    source_archive: bytes, receipt: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, bytes]]:
    """Derive tracked source solely from receipt-bound generation evidence."""
    provenance_names = (
        "release_commit", "source_archive_sha256", "source_tree_sha256",
        "signing_config_sha256",
    )
    if (receipt.get("schema") not in {
                NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
                NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
            }
            or any(not isinstance(receipt.get(name), str)
                   for name in provenance_names)
            or sha256_bytes(source_archive)
                != receipt["source_archive_sha256"]):
        raise ReleaseFailure("native_host_generation_source_invalid")
    archive_entries, archive_files = _native_host_archive_snapshot(
        source_archive
    )
    observed_tree = _native_host_source_tree_digest(
        archive_entries, receipt["signing_config_sha256"],
    )
    if observed_tree != receipt["source_tree_sha256"]:
        raise ReleaseFailure("native_host_generation_source_invalid")
    return ({name: receipt[name] for name in provenance_names}, archive_files)


def _encode_native_host_release_preimage(
    payloads: Mapping[str, bytes], metadata: bytes,
) -> bytes:
    values = dict(payloads)
    if (set(values) != NATIVE_HOST_RELEASE_PREIMAGE_PAYLOAD_NAMES
            or any(not isinstance(value, bytes) for value in values.values())
            or not isinstance(metadata, bytes)
            or any(len(value) > 256 * 1024 * 1024 for value in values.values())
            or len(metadata) > 4096
            or sum(len(value) for value in values.values()) + len(metadata)
                > 768 * 1024 * 1024):
        raise ReleaseFailure("native_host_release_preimage_invalid")
    manifest = {
        "metadata": {
            "sha256": sha256_bytes(metadata), "size": len(metadata),
        },
        "payloads": {
            name: {
                "mode": EXPECTED_MODES[name],
                "sha256": sha256_bytes(values[name]),
                "size": len(values[name]),
            }
            for name in sorted(values)
        },
        "schema": NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA,
    }
    manifest_raw = (json.dumps(
        manifest, allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ) + "\n").encode("ascii")
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w", format=tarfile.USTAR_FORMAT,
    ) as archive:
        for name, raw, mode in (
            ("manifest.json", manifest_raw, 0o444),
            ("metadata/secure-enclave.json", metadata, 0o444),
            *(
                (f"payloads/{name}", values[name], EXPECTED_MODES[name])
                for name in sorted(values)
            ),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def encode_gpgv_runtime_capsule(
    executable: bytes, libraries: Mapping[str, bytes],
) -> bytes:
    """Append one deterministic, hash-bound dylib closure to the Mach-O."""
    if (not isinstance(executable, bytes) or len(executable) < 4
            or executable[:4] not in {b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}
            or set(libraries) != GPGV_RUNTIME_LIBRARY_NAMES
            or any(not isinstance(value, bytes) or not value
                   or len(value) > 64 * 1024 * 1024
                   for value in libraries.values())):
        raise ReleaseFailure("native_host_release_gpgv_runtime_invalid")
    output = io.BytesIO(executable)
    with zipfile.ZipFile(
        output, mode="a", compression=zipfile.ZIP_STORED, allowZip64=False,
    ) as archive:
        archive.comment = GPGV_RUNTIME_ARCHIVE_COMMENT
        for name in sorted(libraries):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o444) << 16
            archive.writestr(info, libraries[name])
    return output.getvalue()


def validate_gpgv_runtime_dependency_closure(
    executable: bytes, libraries: Mapping[str, bytes],
    *, otool_binary: Path = OTOOL_BINARY,
) -> None:
    """Prove that every non-system Mach-O dependency is hash-bound."""
    if (set(libraries) != GPGV_RUNTIME_LIBRARY_NAMES
            or not isinstance(executable, bytes)
            or any(not isinstance(value, bytes)
                   for value in libraries.values())):
        raise ReleaseFailure("native_host_release_gpgv_runtime_invalid")
    with tempfile.TemporaryDirectory(
        prefix="secure-sandbox-gpgv-closure-",
    ) as directory:
        root = Path(directory)
        inputs = {"gpgv": executable, **dict(libraries)}
        paths: dict[str, Path] = {}
        for name, raw in sorted(inputs.items()):
            path = root / name
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
            )
            try:
                write_all(descriptor, raw, "gpgv_runtime_closure")
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o400)
            finally:
                os.close(descriptor)
            paths[name] = path
        for name, path in sorted(paths.items()):
            try:
                result = subprocess.run(
                    [str(otool_binary), "-L", str(path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=30,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    text=True,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise ReleaseFailure(
                    "native_host_release_gpgv_dependency_inspection_failed:"
                    + name
                ) from error
            lines = result.stdout.splitlines()
            if (result.returncode != 0 or not lines
                    or lines[0] != str(path) + ":"
                    or len(result.stdout.encode("utf-8")) > 1024 * 1024):
                raise ReleaseFailure(
                    "native_host_release_gpgv_dependency_inspection_failed:"
                    + name
                )
            for line in lines[1:]:
                stripped = line.strip()
                marker = " (compatibility version "
                if marker not in stripped:
                    raise ReleaseFailure(
                        "native_host_release_gpgv_dependency_invalid:" + name
                    )
                dependency = stripped.split(marker, 1)[0]
                parts = dependency.split("/")
                if (not dependency.startswith("/")
                        or dependency.startswith("//")
                        or "" in parts[1:]
                        or any(part in {".", ".."} for part in parts)):
                    raise ReleaseFailure(
                        "native_host_release_gpgv_dependency_path_invalid:"
                        + name
                    )
                if dependency.startswith(
                    GPGV_RUNTIME_SYSTEM_DEPENDENCY_PREFIXES
                ):
                    continue
                if (not dependency.startswith("/opt/homebrew/opt/")
                        or Path(dependency).name
                        not in GPGV_RUNTIME_LIBRARY_NAMES):
                    raise ReleaseFailure(
                        "native_host_release_gpgv_dependency_unbound:" + name
                    )


def gpgv_runtime_files(capsule: bytes) -> dict[str, bytes]:
    """Return the exact dylib closure, or empty for a legacy raw gpgv."""
    if not isinstance(capsule, bytes):
        raise ReleaseFailure("native_host_release_gpgv_runtime_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(capsule), mode="r") as archive:
            if archive.comment != GPGV_RUNTIME_ARCHIVE_COMMENT:
                return {}
            items = archive.infolist()
            if ([item.filename for item in items]
                    != sorted(GPGV_RUNTIME_LIBRARY_NAMES)):
                raise ReleaseFailure(
                    "native_host_release_gpgv_runtime_inventory_invalid"
                )
            values: dict[str, bytes] = {}
            for item in items:
                mode = item.external_attr >> 16
                if (item.date_time != (1980, 1, 1, 0, 0, 0)
                        or item.compress_type != zipfile.ZIP_STORED
                        or mode & 0o170000 != stat.S_IFREG
                        or mode & 0o7777 != 0o444
                        or not 1 <= item.file_size <= 64 * 1024 * 1024):
                    raise ReleaseFailure(
                        "native_host_release_gpgv_runtime_member_invalid"
                    )
                raw = archive.read(item)
                if len(raw) != item.file_size:
                    raise ReleaseFailure(
                        "native_host_release_gpgv_runtime_member_invalid"
                    )
                values[item.filename] = raw
            return values
    except zipfile.BadZipFile:
        return {}


def gpgv_runtime_hashes(capsule: bytes) -> dict[str, str]:
    return {
        name: sha256_bytes(value)
        for name, value in gpgv_runtime_files(capsule).items()
    }


def materialize_gpgv_runtime(release: Path, capsule: bytes) -> None:
    libraries = gpgv_runtime_files(capsule)
    if not libraries:
        return
    runtime = release / GPGV_RUNTIME_DIRECTORY_NAME
    os.mkdir(runtime, 0o755)
    try:
        for name, raw in sorted(libraries.items()):
            descriptor = os.open(
                runtime / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o444,
            )
            try:
                write_all(descriptor, raw, "gpgv_runtime")
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o444)
            finally:
                os.close(descriptor)
        os.chmod(runtime, 0o555)
        fsync_directory(runtime)
        fsync_directory(release)
    except BaseException:
        os.chmod(runtime, 0o755)
        raise


def verify_gpgv_runtime(
    release: Path, capsule: bytes, expected_uid: int,
) -> None:
    libraries = gpgv_runtime_files(capsule)
    runtime = release / GPGV_RUNTIME_DIRECTORY_NAME
    if not libraries:
        if os.path.lexists(runtime):
            raise ReleaseFailure("native_host_release_gpgv_runtime_unexpected")
        return
    verify_acl_free_directory(
        runtime, expected_uid, 0o555,
        "native_host_release_gpgv_runtime_untrusted",
    )
    try:
        names = set(os.listdir(runtime))
    except OSError as error:
        raise ReleaseFailure(
            "native_host_release_gpgv_runtime_untrusted"
        ) from error
    if names != set(libraries):
        raise ReleaseFailure(
            "native_host_release_gpgv_runtime_inventory_invalid"
        )
    for name, expected in sorted(libraries.items()):
        raw = read_acl_free_regular(
            runtime / name, expected_uid, 0o444,
            "native_host_release_gpgv_runtime_untrusted:" + name,
            maximum=64 * 1024 * 1024,
        )
        if not hmac.compare_digest(raw, expected):
            raise ReleaseFailure(
                "native_host_release_gpgv_runtime_mismatch:" + name
            )


def native_host_release_preimage_archive(
    repo: Path, source_archive: bytes,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
    *, _source_files: Mapping[str, bytes] | None = None,
) -> bytes:
    repo = repo.resolve(strict=True)
    if _source_files is None:
        _entries, source_files = _native_host_archive_snapshot(source_archive)
    else:
        source_files = dict(_source_files)
    if (NATIVE_HOST_RELEASE_PREIMAGE_PAYLOAD_NAMES
            != PAYLOAD_NAMES - NATIVE_HOST_GENERATION_PAYLOAD_NAMES):
        raise ReleaseFailure("native_host_release_preimage_inventory_invalid")
    identities = {
        name: mutable_source_input_identity(repo, PAYLOAD_SOURCES[name])
        for name in LOCAL_UNTRACKED_PAYLOAD_NAMES
    }
    values: dict[str, bytes] = {}
    for name in NATIVE_HOST_RELEASE_PREIMAGE_PAYLOAD_NAMES:
        if name in {"gpgv", "native_stack_support",
                    "native_deployment_payloads"}:
            continue
        if name in LOCAL_UNTRACKED_PAYLOAD_NAMES:
            values[name] = read_mutable_source_input(
                repo, PAYLOAD_SOURCES[name], identities[name],
            )
            continue
        value = source_files.get(PAYLOAD_SOURCES[name].as_posix())
        if not isinstance(value, bytes):
            raise ReleaseFailure("tracked_source_payload_missing:" + name)
        values[name] = value
    values["native_stack_support"] = native_stack_support_archive(
        repo, source_files=source_files,
    )
    values["native_deployment_payloads"] = native_deployment_payload_container(
        repo, support_archive=values["native_stack_support"],
        source_files=source_files,
    )
    config_relative = Path(".private/secure-enclave-ddd.json")
    config_identity = mutable_source_input_identity(repo, config_relative)
    config_path = repo / config_relative
    repo_info = repo.lstat()
    config_info = config_path.lstat()
    try:
        config = json.loads(read_mutable_source_input(
            repo, config_relative, config_identity,
        ))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("secure_enclave_local_config_invalid") from error
    legacy_digest = config.get("legacy_launchservices_ui_bundle_sha256")
    if (not stat.S_ISDIR(repo_info.st_mode) or stat.S_ISLNK(repo_info.st_mode)
            or repo_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not stat.S_ISREG(config_info.st_mode)
            or stat.S_ISLNK(config_info.st_mode)
            or config_info.st_uid != repo_info.st_uid
            or config_info.st_nlink != 1
            or stat.S_IMODE(config_info.st_mode) != 0o600
            or config.get("schema")
            != "secure-sandbox-secure-enclave-ddd-local-config-v1"
            or not isinstance(legacy_digest, str)
            or SHA256.fullmatch(legacy_digest) is None):
        raise ReleaseFailure("secure_enclave_local_config_invalid")
    metadata = (json.dumps({
        "legacy_launchservices_ui_bundle_sha256": legacy_digest,
        "schema": NATIVE_HOST_SECURE_ENCLAVE_INPUT_SCHEMA,
    }, allow_nan=False, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True) + "\n").encode("ascii")
    marker = b"__LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256__"
    if values["authorization_broker"].count(marker) != 1:
        raise ReleaseFailure("authorization_broker_template_invalid")
    values["authorization_broker"] = values["authorization_broker"].replace(
        marker, legacy_digest.encode("ascii"),
    )
    resolved_gpgv = gpgv_binary.resolve(strict=True)
    gpgv_before = resolved_gpgv.lstat()
    values["gpgv"] = read_acl_free_regular(
        resolved_gpgv, gpgv_before.st_uid,
        stat.S_IMODE(gpgv_before.st_mode),
        "native_host_release_gpgv_untrusted", maximum=64 * 1024 * 1024,
    )
    gpgv_after = resolved_gpgv.lstat()
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if (identity(gpgv_before) != identity(gpgv_after)
            or not stat.S_ISREG(gpgv_after.st_mode)
            or gpgv_after.st_nlink != 1
            or gpgv_after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise ReleaseFailure("native_host_release_gpgv_untrusted")
    if values["gpgv"][:4] in {b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        runtime_libraries: dict[str, bytes] = {}
        for name, source in sorted(GPGV_RUNTIME_LIBRARY_SOURCES.items()):
            resolved = source.resolve(strict=True)
            before = resolved.lstat()
            runtime_libraries[name] = read_acl_free_regular(
                resolved, before.st_uid, stat.S_IMODE(before.st_mode),
                "native_host_release_gpgv_runtime_untrusted:" + name,
                maximum=64 * 1024 * 1024,
            )
            after = resolved.lstat()
            if (identity(before) != identity(after)
                    or not stat.S_ISREG(after.st_mode)
                    or after.st_nlink != 1
                    or after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise ReleaseFailure(
                    "native_host_release_gpgv_runtime_untrusted:" + name
                )
        validate_gpgv_runtime_dependency_closure(
            values["gpgv"], runtime_libraries,
        )
        values["gpgv"] = encode_gpgv_runtime_capsule(
            values["gpgv"], runtime_libraries,
        )
    verifier_marker = b"__GPGV_SHA256__"
    if values["installer_verifier"].count(verifier_marker) != 1:
        raise ReleaseFailure("installer_verifier_template_invalid")
    values["installer_verifier"] = values["installer_verifier"].replace(
        verifier_marker,
        sha256_bytes(values["gpgv"]).encode("ascii"),
    )
    runtime_marker = b"__GPGV_RUNTIME_SHA256_JSON__"
    if values["installer_verifier"].count(runtime_marker) != 1:
        raise ReleaseFailure("installer_verifier_runtime_template_invalid")
    runtime_hashes = gpgv_runtime_hashes(values["gpgv"])
    values["installer_verifier"] = values["installer_verifier"].replace(
        runtime_marker,
        json.dumps(
            runtime_hashes, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ).encode("ascii"),
    )
    service_marker = (
        b"__SECURE_SANDBOX_NATIVE_CREDENTIAL_HELPER_EXECUTABLE__"
    )
    if values["native_credential_helper_service"].count(service_marker) != 1:
        raise ReleaseFailure("native_credential_helper_service_template_invalid")
    values["native_credential_helper_service"] = values[
        "native_credential_helper_service"
    ].replace(
        service_marker, NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH.encode("ascii"),
    )
    for name in (
        "control_client", "authorization_broker", "harness_lifecycle_manager",
        "native_stack_manager", "native_stack_session_manager",
    ):
        compile(values[name], str(PAYLOAD_SOURCES[name]), "exec")
    validate_shell_payload(values["controller"], "controller")
    if (any(mutable_source_input_identity(repo, PAYLOAD_SOURCES[name])
            != expected for name, expected in identities.items())
            or mutable_source_input_identity(repo, config_relative)
                != config_identity):
        raise ReleaseFailure("mutable_source_input_changed")
    return _encode_native_host_release_preimage(values, metadata)


def native_host_release_preimage_snapshot(
    archive_raw: bytes,
) -> tuple[dict[str, bytes], dict[str, object]]:
    payload_names = sorted(NATIVE_HOST_RELEASE_PREIMAGE_PAYLOAD_NAMES)
    expected_names = [
        "manifest.json", "metadata/secure-enclave.json",
        *(f"payloads/{name}" for name in payload_names),
    ]
    if (not isinstance(archive_raw, bytes)
            or not 1024 <= len(archive_raw) <= 1024 * 1024 * 1024):
        raise ReleaseFailure("native_host_release_preimage_invalid")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as archive:
            members = archive.getmembers()
            if [member.name for member in members] != expected_names:
                raise ReleaseFailure("native_host_release_preimage_invalid")
            extracted: dict[str, bytes] = {}
            for member in members:
                payload_name = (
                    member.name.removeprefix("payloads/")
                    if member.name.startswith("payloads/") else None
                )
                expected_mode = (
                    EXPECTED_MODES.get(payload_name)
                    if payload_name is not None else 0o444
                )
                if (not member.isfile() or member.linkname
                        or member.pax_headers or member.uid != 0
                        or member.gid != 0 or member.uname != ""
                        or member.gname != "" or member.mtime != 0
                        or expected_mode is None
                        or stat.S_IMODE(member.mode) != expected_mode
                        or member.size < 0
                        or member.size > 256 * 1024 * 1024):
                    raise ReleaseFailure("native_host_release_preimage_invalid")
                handle = archive.extractfile(member)
                if handle is None:
                    raise ReleaseFailure("native_host_release_preimage_invalid")
                value = handle.read(member.size + 1)
                if len(value) != member.size:
                    raise ReleaseFailure("native_host_release_preimage_invalid")
                extracted[member.name] = value
    except (OSError, tarfile.TarError, UnicodeError) as error:
        raise ReleaseFailure("native_host_release_preimage_invalid") from error
    payloads = {
        name: extracted[f"payloads/{name}"] for name in payload_names
    }
    metadata_raw = extracted["metadata/secure-enclave.json"]
    try:
        manifest = json.loads(extracted["manifest.json"])
        metadata = json.loads(metadata_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("native_host_release_preimage_invalid") from error
    rebuilt = _encode_native_host_release_preimage(payloads, metadata_raw)
    expected_manifest = {
        "metadata": {
            "sha256": sha256_bytes(metadata_raw), "size": len(metadata_raw),
        },
        "payloads": {
            name: {
                "mode": EXPECTED_MODES[name],
                "sha256": sha256_bytes(payloads[name]),
                "size": len(payloads[name]),
            }
            for name in payload_names
        },
        "schema": NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA,
    }
    if (rebuilt != archive_raw or manifest != expected_manifest
            or extracted["manifest.json"] != (json.dumps(
                manifest, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n").encode("ascii")
            or not isinstance(metadata, dict)
            or set(metadata) != {
                "schema", "legacy_launchservices_ui_bundle_sha256",
            }
            or metadata.get("schema")
                != NATIVE_HOST_SECURE_ENCLAVE_INPUT_SCHEMA
            or SHA256.fullmatch(str(metadata.get(
                "legacy_launchservices_ui_bundle_sha256", ""))) is None
            or metadata_raw != (json.dumps(
                metadata, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n").encode("ascii")):
        raise ReleaseFailure("native_host_release_preimage_invalid")
    return payloads, metadata


def _native_host_candidate_preimage(
    repo: Path, generation: Path, receipt: Mapping[str, Any],
) -> tuple[bytes, tuple[int, int, int]]:
    candidate_root = generation.parent
    retained_root = candidate_root.parent
    evidence = candidate_root / "evidence"
    path = evidence / NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
    for trusted_directory in (
        repo / ".private", retained_root, candidate_root, evidence,
    ):
        trusted_descriptor = -1
        try:
            trusted_descriptor = os.open(
                trusted_directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | os.O_CLOEXEC,
            )
            reject_extended_acl(
                trusted_descriptor,
                "native_host_candidate_directory_extended_acl",
            )
        except OSError as error:
            raise ReleaseFailure(
                "native_host_release_preimage_untrusted") from error
        finally:
            if trusted_descriptor >= 0:
                os.close(trusted_descriptor)
    try:
        repo_info = repo.lstat()
        retained_info = retained_root.lstat()
        root_info = candidate_root.lstat()
        generation_info = generation.lstat()
        root_entries = sorted(item.name for item in os.scandir(candidate_root))
        evidence_before = evidence.lstat()
        evidence_entries = sorted(item.name for item in os.scandir(evidence))
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure("native_host_release_preimage_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "native_host_release_preimage_extended_acl",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > 1024 * 1024 * 1024:
                raise ReleaseFailure("native_host_release_preimage_invalid")
            chunks.append(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    evidence_after = evidence.lstat()
    root_after = candidate_root.lstat()
    named = path.lstat()
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != repo_info.st_uid
            or stat.S_IMODE(root_info.st_mode) != 0o700
            or not stat.S_ISDIR(retained_info.st_mode)
            or stat.S_ISLNK(retained_info.st_mode)
            or retained_info.st_uid != repo_info.st_uid
            or stat.S_IMODE(retained_info.st_mode) != 0o700
            or root_info.st_dev != retained_info.st_dev
            or root_entries != ["evidence", "generation"]
            or identity(root_info) != identity(root_after)
            or not stat.S_ISDIR(generation_info.st_mode)
            or stat.S_ISLNK(generation_info.st_mode)
            or generation_info.st_uid != repo_info.st_uid
            or generation_info.st_dev != root_info.st_dev
            or stat.S_IMODE(generation_info.st_mode) != 0o755
            or not stat.S_ISDIR(evidence_before.st_mode)
            or stat.S_ISLNK(evidence_before.st_mode)
            or evidence_before.st_uid != repo_info.st_uid
            or evidence_before.st_dev != root_info.st_dev
            or stat.S_IMODE(evidence_before.st_mode) != 0o700
            or evidence_entries != [
                NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME,
                "notary-log.json", "notary-result.json",
            ]
            or identity(evidence_before) != identity(evidence_after)
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != repo_info.st_uid
            or opened.st_dev != evidence_before.st_dev
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o400
            or not 1024 <= opened.st_size <= 1024 * 1024 * 1024
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure("native_host_release_preimage_untrusted")
    raw = b"".join(chunks)
    if len(raw) != opened.st_size:
        raise ReleaseFailure("native_host_release_preimage_changed")
    native_host_release_preimage_snapshot(raw)

    def read_evidence(name: str) -> bytes:
        item = evidence / name
        try:
            item_before = item.lstat()
            item_fd = os.open(
                item, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as error:
            raise ReleaseFailure(
                "native_host_candidate_notary_evidence_untrusted") from error
        try:
            item_opened = os.fstat(item_fd)
            reject_extended_acl(
                item_fd, "native_host_candidate_notary_evidence_extended_acl",
            )
            item_raw = os.read(item_fd, 1024 * 1024 + 1)
            item_after = os.fstat(item_fd)
        finally:
            os.close(item_fd)
        item_named = item.lstat()
        if (not stat.S_ISREG(item_opened.st_mode)
                or stat.S_ISLNK(item_before.st_mode)
                or item_opened.st_uid != repo_info.st_uid
                or item_opened.st_dev != evidence_before.st_dev
                or item_opened.st_nlink != 1
                or stat.S_IMODE(item_opened.st_mode) != 0o600
                or not 2 <= item_opened.st_size <= 1024 * 1024
                or len(item_raw) != item_opened.st_size
                or identity(item_before) != identity(item_opened)
                or identity(item_opened) != identity(item_after)
                or identity(item_after) != identity(item_named)):
            raise ReleaseFailure(
                "native_host_candidate_notary_evidence_untrusted")
        return item_raw

    result_raw = read_evidence("notary-result.json")
    log_raw = read_evidence("notary-log.json")
    try:
        result = json.loads(result_raw)
        log = json.loads(log_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure(
            "native_host_candidate_notary_evidence_invalid") from error
    submission_id = str(receipt.get("notary_submission_id", ""))
    if (not isinstance(result, dict) or result.get("status") != "Accepted"
            or str(result.get("id", "")).lower() != submission_id
            or not isinstance(log, dict) or log.get("status") != "Accepted"
            or log.get("statusCode") != 0
            or isinstance(log.get("statusCode"), bool)
            or log.get("issues") not in (None, [])
            or str(log.get("jobId", "")).lower() != submission_id
            or str(log.get("sha256", "")).lower()
                != receipt.get("notary_submission_sha256")
            or sha256_bytes(log_raw) != receipt.get("notary_log_sha256")):
        raise ReleaseFailure(
            "native_host_candidate_notary_evidence_invalid")
    return raw, (opened.st_dev, opened.st_ino, opened.st_size)


def native_host_candidate_record(
    repo: Path, generation: Path,
    expected_certificate_sha1: str | None = None,
) -> dict[str, object]:
    """Return the closed authority record for one retained generation."""
    repo = repo.resolve(strict=True)
    generation = Path(generation)
    if (not generation.is_absolute()
            or generation != Path(os.path.realpath(generation))
            or generation.name != "generation"
            or generation.parent.parent
                != repo / ".private/native-host-product-candidates"):
        raise ReleaseFailure("native_host_candidate_path_invalid")
    root_identity, tree_sha256, captured = (
        _native_host_generation_snapshot(repo, generation)
    )
    required = {
        NATIVE_HOST_SOURCE_ARCHIVE_NAME,
        PAYLOAD_SOURCES["native_host_products_notarization"].name,
        PAYLOAD_SOURCES[
            "native_host_products_notarization_signature"
        ].name,
    }
    if not required <= set(captured):
        raise ReleaseFailure("native_host_generation_inventory_invalid")
    receipt_data = captured[
        PAYLOAD_SOURCES["native_host_products_notarization"].name
    ]
    receipt = native_host_products_notarization(receipt_data)
    if receipt.get("schema") != NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA:
        raise ReleaseFailure("native_host_candidate_receipt_below_v3")
    signature = captured[
        PAYLOAD_SOURCES[
            "native_host_products_notarization_signature"
        ].name
    ]
    verify_native_host_products_notarization_signature(
        receipt_data, signature, receipt,
        expected_certificate_sha1=expected_certificate_sha1,
    )
    native_host_source_snapshot_from_generation(
        captured[NATIVE_HOST_SOURCE_ARCHIVE_NAME], receipt,
    )
    preimage, preimage_identity = _native_host_candidate_preimage(
        repo, generation, receipt,
    )
    preimage_sha256 = sha256_bytes(preimage)
    if receipt.get("host_release_preimage_sha256") != preimage_sha256:
        raise ReleaseFailure("native_host_release_preimage_mismatch")
    expected_candidate_name = (
        receipt["release_commit"] + "-" + receipt["notary_submission_id"]
    )
    if generation.parent.name != expected_candidate_name:
        raise ReleaseFailure("native_host_candidate_path_invalid")
    return {
        "schema": NATIVE_HOST_CANDIDATE_RECORD_SCHEMA,
        "generation_path": str(generation),
        "generation_device": root_identity[0],
        "generation_inode": root_identity[1],
        "generation_tree_sha256": tree_sha256,
        "release_commit": receipt["release_commit"],
        "source_archive_sha256": receipt["source_archive_sha256"],
        "source_tree_sha256": receipt["source_tree_sha256"],
        "signing_config_sha256": receipt["signing_config_sha256"],
        "host_release_preimage_path": str(
            generation.parent / "evidence"
            / NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
        ),
        "host_release_preimage_device": preimage_identity[0],
        "host_release_preimage_inode": preimage_identity[1],
        "host_release_preimage_size": preimage_identity[2],
        "host_release_preimage_sha256": preimage_sha256,
        "host_release_preimage_schema": NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA,
        "developer_id_certificate_sha1": receipt[
            "developer_id_certificate_sha1"
        ],
        "notary_submission_id": receipt["notary_submission_id"],
        "build_custody": receipt["build_custody"],
    }


def _validate_native_host_historical_candidate_evidence(
    repo: Path, generation: Path, receipt: Mapping[str, Any],
) -> None:
    """Close the exact retained v2 container before classifying it history."""
    expected_uid = repo.lstat().st_uid
    candidate_root = generation.parent
    retained_root = candidate_root.parent
    evidence = candidate_root / "evidence"
    descriptors: list[int] = []
    try:
        for path, mode, failure in (
            (repo / ".private", 0o700,
             "native_host_candidate_private_root_untrusted"),
            (retained_root, 0o700,
             "native_host_candidate_retained_root_untrusted"),
            (candidate_root, 0o700,
             "native_host_candidate_root_untrusted"),
            (generation, 0o755,
             "native_host_generation_untrusted"),
            (evidence, 0o700,
             "native_host_candidate_evidence_untrusted"),
        ):
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | os.O_CLOEXEC,
            )
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            named = path.lstat()
            if (not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(named.st_mode)
                    or (opened.st_dev, opened.st_ino)
                        != (named.st_dev, named.st_ino)
                    or opened.st_uid != expected_uid
                    or stat.S_IMODE(opened.st_mode) != mode):
                raise ReleaseFailure(failure)
            reject_extended_acl(
                descriptor, "native_host_candidate_directory_extended_acl",
            )
        retained_info, root_info, generation_info, evidence_info = (
            os.fstat(descriptors[index]) for index in (1, 2, 3, 4)
        )
        if (root_info.st_dev != retained_info.st_dev
                or generation_info.st_dev != retained_info.st_dev
                or evidence_info.st_dev != retained_info.st_dev
                or sorted(os.listdir(descriptors[2]))
                    != ["evidence", "generation"]
                or sorted(os.listdir(descriptors[4]))
                    != ["notary-log.json", "notary-result.json"]):
            raise ReleaseFailure(
                "native_host_candidate_evidence_untrusted")

        def read_evidence(name: str) -> bytes:
            before = os.stat(
                name, dir_fd=descriptors[4], follow_symlinks=False,
            )
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptors[4],
            )
            try:
                opened = os.fstat(descriptor)
                reject_extended_acl(
                    descriptor,
                    "native_host_candidate_notary_evidence_extended_acl",
                )
                raw = os.read(descriptor, 1024 * 1024 + 1)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            named = os.stat(
                name, dir_fd=descriptors[4], follow_symlinks=False,
            )
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                item.st_gid, item.st_nlink, item.st_size,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != expected_uid
                    or opened.st_dev != retained_info.st_dev
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or not 2 <= opened.st_size <= 1024 * 1024
                    or len(raw) != opened.st_size
                    or identity(before) != identity(opened)
                    or identity(opened) != identity(after)
                    or identity(after) != identity(named)):
                raise ReleaseFailure(
                    "native_host_candidate_notary_evidence_untrusted")
            return raw

        result_raw = read_evidence("notary-result.json")
        log_raw = read_evidence("notary-log.json")
    except OSError as error:
        raise ReleaseFailure(
            "native_host_candidate_evidence_untrusted") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    try:
        result = json.loads(result_raw)
        log = json.loads(log_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure(
            "native_host_candidate_notary_evidence_invalid") from error
    submission_id = str(receipt.get("notary_submission_id", ""))
    if (not isinstance(result, dict) or result.get("status") != "Accepted"
            or str(result.get("id", "")).lower() != submission_id
            or not isinstance(log, dict) or log.get("status") != "Accepted"
            or log.get("statusCode") != 0
            or isinstance(log.get("statusCode"), bool)
            or log.get("issues") not in (None, [])
            or str(log.get("jobId", "")).lower() != submission_id
            or str(log.get("sha256", "")).lower()
                != receipt.get("notary_submission_sha256")
            or sha256_bytes(log_raw) != receipt.get("notary_log_sha256")):
        raise ReleaseFailure(
            "native_host_candidate_notary_evidence_invalid")


def classify_native_host_retained_candidate(
    repo: Path, generation: Path,
    expected_certificate_sha1: str | None = None,
) -> dict[str, object]:
    """Classify one exact retained generation without blind skip semantics.

    Receipt-v3 candidates return their full admissible candidate record.
    Receipt-v2 generations are reported as historical/ineligible only after
    their detached Developer-ID signature, source archive, stapled carrier,
    product inventory, and retained candidate pathname all verify.  Unsigned
    v1 or malformed/tampered generations always fail closed.
    """
    repo = repo.resolve(strict=True)
    generation = Path(generation)
    if (not generation.is_absolute()
            or generation != Path(os.path.realpath(generation))
            or generation.name != "generation"
            or generation.parent.parent
                != repo / ".private/native-host-product-candidates"):
        raise ReleaseFailure("native_host_candidate_path_invalid")
    root_identity, tree_sha256, captured = (
        _native_host_generation_snapshot(repo, generation)
    )
    receipt_name = PAYLOAD_SOURCES[
        "native_host_products_notarization"
    ].name
    signature_name = PAYLOAD_SOURCES[
        "native_host_products_notarization_signature"
    ].name
    required = {
        NATIVE_HOST_SOURCE_ARCHIVE_NAME, receipt_name, signature_name,
        *(PAYLOAD_SOURCES[name].name
          for name in NATIVE_HOST_GENERATION_PAYLOAD_NAMES),
    }
    if not required <= set(captured):
        raise ReleaseFailure("native_host_generation_inventory_invalid")
    receipt_data = captured[receipt_name]
    receipt = native_host_products_notarization(receipt_data)
    if receipt.get("schema") == NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA:
        record = native_host_candidate_record(
            repo, generation,
            expected_certificate_sha1=expected_certificate_sha1,
        )
        return {
            "candidate_record": record,
            "eligibility": "candidate-admission-eligible",
            "generation_device": root_identity[0],
            "generation_inode": root_identity[1],
            "generation_path": str(generation),
            "generation_tree_sha256": tree_sha256,
            "receipt_schema": NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
            "schema": NATIVE_HOST_RETAINED_CANDIDATE_CLASSIFICATION_SCHEMA,
        }
    if receipt.get("schema") != NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA:
        raise ReleaseFailure("native_host_retained_candidate_unsigned")
    verify_native_host_products_notarization_signature(
        receipt_data, captured[signature_name], receipt,
        expected_certificate_sha1=expected_certificate_sha1,
    )
    provenance, _tracked = native_host_source_snapshot_from_generation(
        captured[NATIVE_HOST_SOURCE_ARCHIVE_NAME], receipt,
    )
    _validate_native_host_historical_candidate_evidence(
        repo, generation, receipt,
    )
    expected_name = (
        receipt["release_commit"] + "-" + receipt["notary_submission_id"]
    )
    if generation.parent.name != expected_name:
        raise ReleaseFailure("native_host_candidate_path_invalid")
    values = {
        name: captured[PAYLOAD_SOURCES[name].name]
        for name in NATIVE_HOST_GENERATION_PAYLOAD_NAMES
    }
    verify_native_host_products_container(
        values, require_v2=True,
        expected_source_provenance=provenance,
        expected_certificate_sha1=expected_certificate_sha1,
    )
    return {
        "candidate_record": None,
        "eligibility": "historical-receipt-v2-ineligible",
        "generation_device": root_identity[0],
        "generation_inode": root_identity[1],
        "generation_path": str(generation),
        "generation_tree_sha256": tree_sha256,
        "receipt_schema": NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
        "schema": NATIVE_HOST_RETAINED_CANDIDATE_CLASSIFICATION_SCHEMA,
    }


def native_host_candidate_tracked_source(
    repo: Path, generation: Path,
    expected_candidate: Mapping[str, object], relative: Path,
) -> bytes:
    """Read one tracked source only from the exact retained candidate archive."""
    expected = dict(expected_candidate)
    if native_host_candidate_record(repo, generation) != expected:
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    identity, tree_sha256, captured = _native_host_generation_snapshot(
        repo, generation,
    )
    if (identity[0] != expected.get("generation_device")
            or identity[1] != expected.get("generation_inode")
            or tree_sha256 != expected.get("generation_tree_sha256")):
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    receipt_data = captured.get(
        PAYLOAD_SOURCES["native_host_products_notarization"].name
    )
    signature_data = captured.get(
        PAYLOAD_SOURCES[
            "native_host_products_notarization_signature"
        ].name
    )
    source_archive = captured.get(NATIVE_HOST_SOURCE_ARCHIVE_NAME)
    if (not isinstance(receipt_data, bytes)
            or not isinstance(signature_data, bytes)
            or not isinstance(source_archive, bytes)):
        raise ReleaseFailure("native_host_generation_source_invalid")
    receipt = native_host_products_notarization(receipt_data)
    verify_native_host_products_notarization_signature(
        receipt_data, signature_data, receipt,
        expected_certificate_sha1=str(
            expected.get("developer_id_certificate_sha1", "")
        ),
    )
    provenance, tracked = native_host_source_snapshot_from_generation(
        source_archive, receipt,
    )
    if any(provenance.get(name) != expected.get(name) for name in (
        "release_commit", "source_archive_sha256", "source_tree_sha256",
        "signing_config_sha256",
    )):
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    value = tracked.get(relative.as_posix())
    if not isinstance(value, bytes):
        raise ReleaseFailure("tracked_source_payload_missing:" + relative.as_posix())
    if native_host_candidate_record(repo, generation) != expected:
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    return value


def _native_host_git_environment() -> dict[str, str]:
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }


def _native_host_git(repo: Path, *arguments: str) -> bytes:
    command = [
        "/usr/bin/git", "-c", "core.attributesFile=/dev/null",
        "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
        "-c", f"safe.directory={repo}",
        "-C", str(repo), *arguments,
    ]
    try:
        completed = subprocess.run(
            command, check=False, capture_output=True,
            env=_native_host_git_environment(), timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseFailure("native_host_source_git_failed") from error
    if completed.returncode != 0 or len(completed.stderr) > 64 * 1024:
        raise ReleaseFailure("native_host_source_git_failed")
    return completed.stdout


def _native_host_signing_config_digest(repo: Path) -> str:
    path = repo / "macos/TouchIDAuthorization/Signing.local.xcconfig"
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        listing = subprocess.run(
            ["/bin/ls", "-lde", str(path)], check=False,
            capture_output=True, text=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=10,
        )
        named = path.lstat()
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseFailure("native_host_signing_config_untrusted") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    lines = listing.stdout.splitlines() if listing.returncode == 0 else []
    if (not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(named.st_mode)
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)
            or opened.st_uid != repo.lstat().st_uid or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode)
                not in {0o400, 0o440, 0o444, 0o600, 0o640, 0o644}
            or raw
                != b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
            or len(raw) != opened.st_size
            or len(lines) != 1 or "+" in lines[0].split()[0]):
        raise ReleaseFailure("native_host_signing_config_untrusted")
    return sha256_bytes(raw)


def _native_host_archive_snapshot(
    source_archive: bytes,
) -> tuple[dict[str, dict[str, object]], dict[str, bytes]]:
    """Parse the deterministic Git archive into one closed regular-file tree."""
    entries: dict[str, dict[str, object]] = {}
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:") as archive:
            members = archive.getmembers()
            if not 1 <= len(members) <= 20_000:
                raise ReleaseFailure("native_host_source_archive_invalid")
            for member in members:
                relative = PurePosixPath(member.name)
                if (not member.name or member.name.startswith("/")
                        or relative.is_absolute()
                        or "." in relative.parts or ".." in relative.parts
                        or len(member.name.encode("utf-8")) > 4096
                        or member.name in entries):
                    raise ReleaseFailure("native_host_source_archive_invalid")
                name = relative.as_posix()
                if member.isdir():
                    entries[name] = {"kind": "directory", "mode": 0o755}
                    continue
                if not member.isreg() or member.size < 0:
                    raise ReleaseFailure("native_host_source_archive_invalid")
                total += member.size
                if total > 512 * 1024 * 1024:
                    raise ReleaseFailure("native_host_source_archive_invalid")
                source = archive.extractfile(member)
                if source is None:
                    raise ReleaseFailure("native_host_source_archive_invalid")
                raw = source.read(member.size + 1)
                if len(raw) != member.size:
                    raise ReleaseFailure("native_host_source_archive_invalid")
                mode = 0o555 if member.mode & 0o111 else 0o444
                entries[name] = {
                    "kind": "file", "mode": mode,
                    "sha256": sha256_bytes(raw), "size": len(raw),
                }
                files[name] = raw
    except (OSError, tarfile.TarError, UnicodeError) as error:
        raise ReleaseFailure("native_host_source_archive_invalid") from error
    for relative in tuple(entries):
        parts = PurePosixPath(relative).parts
        for index in range(1, len(parts)):
            parent = PurePosixPath(*parts[:index]).as_posix()
            if entries.get(parent) != {"kind": "directory", "mode": 0o755}:
                raise ReleaseFailure("native_host_source_archive_invalid")
    return entries, files


def _native_host_source_tree_digest(
    entries: Mapping[str, Mapping[str, object]], signing_config_sha256: str,
) -> str:
    complete = {name: dict(record) for name, record in entries.items()}
    relative = "macos/TouchIDAuthorization/Signing.local.xcconfig"
    if relative in complete:
        raise ReleaseFailure("native_host_signing_config_tracked")
    complete[relative] = {
        "kind": "file", "mode": 0o444,
        "sha256": signing_config_sha256,
        "size": len(b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"),
    }
    raw = (json.dumps(
        {"entries": complete,
         "schema": "secure-sandbox-native-host-source-tree-v1"},
        allow_nan=False, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True,
    ) + "\n").encode("ascii")
    return sha256_bytes(raw)


def current_native_host_source_snapshot(
    repo: Path, *, _expected_signing_config_sha256: str | None = None,
) -> tuple[dict[str, str], dict[str, bytes]]:
    """Independently capture the clean exact source named by a v2 carrier."""
    repo = repo.absolute()
    git_directory = repo / ".git"
    try:
        repo_before = repo.lstat()
        git_before = git_directory.lstat()
    except OSError as error:
        raise ReleaseFailure("native_host_source_repository_untrusted") from error
    if (not stat.S_ISDIR(repo_before.st_mode) or stat.S_ISLNK(repo_before.st_mode)
            or (os.geteuid() != 0 and repo_before.st_uid != os.geteuid())
            or repo_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not stat.S_ISDIR(git_before.st_mode)
            or stat.S_ISLNK(git_before.st_mode)
            or git_before.st_uid != repo_before.st_uid
            or git_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise ReleaseFailure("native_host_source_repository_untrusted")
    for forbidden in (
        git_directory / "info/attributes", git_directory / "info/grafts",
    ):
        if forbidden.exists() or forbidden.is_symlink():
            raise ReleaseFailure("native_host_source_git_override_present")
    if _native_host_git(repo, "replace", "-l"):
        raise ReleaseFailure("native_host_source_git_replace_present")
    local_config = _native_host_git(
        repo, "config", "--local", "--null", "--list",
    ).split(b"\0")
    if any(
        record and record.split(b"\n", 1)[0].lower() == b"core.attributesfile"
        for record in local_config
    ):
        raise ReleaseFailure("native_host_source_git_override_present")
    branch = _native_host_git(
        repo, "symbolic-ref", "--quiet", "--short", "HEAD",
    ).decode("ascii", "strict").strip()
    release_commit = _native_host_git(
        repo, "rev-parse", "--verify", "HEAD^{commit}",
    ).decode("ascii", "strict").strip()
    if branch != "public-release" or re.fullmatch(
        r"[0-9a-f]{40}", release_commit,
    ) is None:
        raise ReleaseFailure("native_host_source_branch_invalid")
    index_records = _native_host_git(repo, "ls-files", "-v", "-z").split(b"\0")
    if any(record and not record.startswith(b"H ") for record in index_records):
        raise ReleaseFailure("native_host_source_index_flags_forbidden")
    if _native_host_git(
        repo, "status", "--porcelain=v1", "-z", "--untracked-files=all",
    ):
        raise ReleaseFailure("native_host_source_worktree_not_clean")
    tree_records = [record for record in _native_host_git(
        repo, "ls-tree", "-r", "-z", "--full-tree", release_commit,
    ).split(b"\0") if record]
    if not tree_records or any(
        not record.startswith((b"100644 blob ", b"100755 blob "))
        for record in tree_records
    ):
        raise ReleaseFailure("native_host_source_tree_entry_invalid")
    source_archive = _native_host_git(
        repo, "archive", "--format=tar", release_commit,
    )
    if not 1024 <= len(source_archive) <= 512 * 1024 * 1024:
        raise ReleaseFailure("native_host_source_archive_invalid")
    archive_entries, archive_files = _native_host_archive_snapshot(
        source_archive
    )
    if _expected_signing_config_sha256 is None:
        signing_config_sha256 = _native_host_signing_config_digest(repo)
    else:
        if SHA256.fullmatch(_expected_signing_config_sha256) is None:
            raise ReleaseFailure("native_host_signing_config_untrusted")
        signing_config_sha256 = _expected_signing_config_sha256
    source_tree_sha256 = _native_host_source_tree_digest(
        archive_entries, signing_config_sha256,
    )
    if (_native_host_git(
            repo, "symbolic-ref", "--quiet", "--short", "HEAD",
        ).decode("ascii", "strict").strip() != branch
            or _native_host_git(
                repo, "rev-parse", "--verify", "HEAD^{commit}",
            ).decode("ascii", "strict").strip() != release_commit
            or _native_host_git(
                repo, "status", "--porcelain=v1", "-z",
                "--untracked-files=all",
            )
            or (repo.lstat().st_dev, repo.lstat().st_ino)
                != (repo_before.st_dev, repo_before.st_ino)
            or (git_directory.lstat().st_dev, git_directory.lstat().st_ino)
                != (git_before.st_dev, git_before.st_ino)
            or (_expected_signing_config_sha256 is None
                and _native_host_signing_config_digest(repo)
                    != signing_config_sha256)):
        raise ReleaseFailure("native_host_source_changed_during_provenance")
    return ({
        "release_commit": release_commit,
        "signing_config_sha256": signing_config_sha256,
        "source_archive_sha256": sha256_bytes(source_archive),
        "source_tree_sha256": source_tree_sha256,
    }, archive_files)


def current_native_host_source_provenance(repo: Path) -> dict[str, str]:
    """Independently derive the clean exact source named by a v2 carrier."""
    provenance, _files = current_native_host_source_snapshot(repo)
    return provenance


def current_native_host_candidate_source_provenance(
    repo: Path, *, expected_signing_config_sha256: str,
) -> dict[str, str]:
    """Derive clean public source using a signed candidate config digest.

    A clean destination intentionally has no ignored Signing.local.xcconfig.
    Candidate admission has already authenticated its signing-configuration
    digest, so source matching may combine that digest with the independently
    derived public commit and Git archive without importing release secrets or
    mutable release-Mac configuration.
    """
    provenance, _files = current_native_host_source_snapshot(
        repo,
        _expected_signing_config_sha256=expected_signing_config_sha256,
    )
    return provenance


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


def developer_id_requirement(
    identifier: str, team: str, certificate_sha1: str | None = None,
) -> str:
    requirement = (
        f'identifier "{identifier}" and anchor apple generic '
        f'and certificate leaf[subject.OU] = "{team}" '
        "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    )
    if certificate_sha1 is not None:
        if re.fullmatch(r"[0-9a-f]{40}", certificate_sha1) is None:
            raise ReleaseFailure("developer_id_certificate_sha1_invalid")
        requirement += f' and certificate leaf = H"{certificate_sha1}"'
    return requirement


def verify_codesign_metadata(
    details: subprocess.CompletedProcess[str], *, identifier: str, team: str,
    expected_cdhash: str | None, failure: str,
) -> None:
    fields: dict[str, str] = {}
    lines = details.stderr.splitlines() if isinstance(details.stderr, str) else []
    for name in ("Identifier", "TeamIdentifier", "CDHash"):
        matches = [
            line[len(name) + 1:]
            for line in lines if line.startswith(name + "=")
        ]
        if len(matches) != 1:
            raise ReleaseFailure(failure)
        fields[name] = matches[0]
    if (details.returncode != 0
            or fields["Identifier"] != identifier
            or fields["TeamIdentifier"] != team
            or re.fullmatch(r"[0-9a-fA-F]{40}", fields["CDHash"]) is None
            or (expected_cdhash is not None
                and fields["CDHash"].lower() != expected_cdhash)):
        raise ReleaseFailure(failure)


def verified_authorization_ui_signing_policy(
    root: Path, manifest_data: bytes, expected_uid: int | None = None, *,
    expected_cdhash: str | None = None,
    developer_id_certificate_sha1: str | None = None,
) -> dict[str, str]:
    """Bind a v2 manifest policy to the bundle's live Developer ID signature."""
    manifest = authorization_ui_bundle_manifest(manifest_data)
    policy = authorization_ui_signing_policy(manifest)
    if policy is None:
        raise ReleaseFailure("authorization_ui_signing_policy_below_floor")
    verify_authorization_ui_bundle(root, manifest_data, expected_uid)
    requirement = developer_id_requirement(
        policy["bundle_id"], policy["team_id"], developer_id_certificate_sha1,
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
    verify_codesign_metadata(
        details, identifier=policy["bundle_id"], team=policy["team_id"],
        expected_cdhash=expected_cdhash,
        failure="authorization_ui_live_signing_policy_invalid",
    )
    if (signature.returncode != 0 or designated.returncode != 0
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


def validate_developer_id_team_enforcement(
    value: object,
) -> dict[str, Any]:
    fields = {
        "schema", "team_id", "established_from_release_id",
        "authoritative_floor_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != DEVELOPER_ID_TEAM_ENFORCEMENT_SCHEMA
            or not isinstance(value.get("team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["team_id"]) is None
            or SHA256.fullmatch(str(value.get(
                "established_from_release_id"))) is None
            or SHA256.fullmatch(str(value.get(
                "authoritative_floor_sha256"))) is None):
        raise ReleaseFailure("developer_id_team_enforcement_invalid")
    return {key: value[key] for key in sorted(fields)}


def developer_id_team_enforcement(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    path = install_root / DEVELOPER_ID_TEAM_ENFORCEMENT_NAME
    root_descriptor = -1
    descriptor = -1
    try:
        root = install_root.lstat()
        before = path.lstat()
        root_descriptor = os.open(
            install_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except FileNotFoundError:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if allow_absent:
            return None
        raise ReleaseFailure("developer_id_team_enforcement_missing")
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        raise ReleaseFailure(
            "developer_id_team_enforcement_untrusted") from error
    try:
        reject_extended_acl(
            root_descriptor,
            "developer_id_team_enforcement_parent_extended_acl",
        )
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "developer_id_team_enforcement_extended_acl",
        )
        raw = os.read(descriptor, 2049)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
        os.close(root_descriptor)
    named = path.lstat()
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
            or root.st_uid != expected_uid
            or stat.S_IMODE(root.st_mode) != 0o755
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid or opened.st_gid != root.st_gid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o444
            or not 2 <= opened.st_size <= 2048
            or len(raw) != opened.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure("developer_id_team_enforcement_untrusted")
    try:
        record = validate_developer_id_team_enforcement(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure(
            "developer_id_team_enforcement_invalid") from error
    expected = _developer_id_floor_bytes(record)
    if raw != expected:
        raise ReleaseFailure(
            "developer_id_team_enforcement_not_canonical")
    return record, sha256_bytes(raw)


def establish_developer_id_team_enforcement(
    install_root: Path, expected_uid: int,
    floor: Mapping[str, Any], floor_sha256: str,
) -> tuple[dict[str, Any], str]:
    validated_floor = validate_developer_id_team_floor(dict(floor))
    if (SHA256.fullmatch(floor_sha256) is None
            or sha256_bytes(_developer_id_floor_bytes(validated_floor))
                != floor_sha256):
        raise ReleaseFailure("developer_id_team_enforcement_invalid")
    record = validate_developer_id_team_enforcement({
        "schema": DEVELOPER_ID_TEAM_ENFORCEMENT_SCHEMA,
        "team_id": validated_floor["team_id"],
        "established_from_release_id": validated_floor[
            "established_from_release_id"
        ],
        "authoritative_floor_sha256": floor_sha256,
    })
    raw = _developer_id_floor_bytes(record)
    root_fd = os.open(
        install_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    final_name = DEVELOPER_ID_TEAM_ENFORCEMENT_NAME
    pending_name = DEVELOPER_ID_TEAM_ENFORCEMENT_PENDING_NAME
    stage_name = pending_name + ".stage-" + sha256_bytes(raw)
    try:
        root = os.fstat(root_fd)
        reject_extended_acl(
            root_fd, "developer_id_team_enforcement_parent_extended_acl",
        )
        named_root = install_root.lstat()
        if (not stat.S_ISDIR(root.st_mode)
                or stat.S_ISLNK(named_root.st_mode)
                or (root.st_dev, root.st_ino)
                    != (named_root.st_dev, named_root.st_ino)
                or root.st_uid != expected_uid
                or stat.S_IMODE(root.st_mode) != 0o755):
            raise ReleaseFailure(
                "developer_id_team_enforcement_parent_untrusted")

        def read_at(
            name: str, links: frozenset[int], *, staging: bool = False,
        ) -> tuple[os.stat_result, bytes] | None:
            try:
                before = os.stat(
                    name, dir_fd=root_fd, follow_symlinks=False)
                fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_fd,
                )
            except FileNotFoundError:
                return None
            try:
                opened = os.fstat(fd)
                reject_extended_acl(
                    fd, "developer_id_team_enforcement_extended_acl",
                )
                observed = os.read(fd, 2049)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                item.st_gid, item.st_nlink, item.st_size,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != expected_uid
                    or (not staging and opened.st_gid != root.st_gid)
                    or opened.st_nlink not in links
                    or stat.S_IMODE(opened.st_mode)
                        not in (
                            {0, 0o200, 0o400, 0o444, 0o600}
                            if staging else {0o444}
                        )
                    or opened.st_size > 2048
                    or len(observed) != opened.st_size
                    or identity(before) != identity(opened)
                    or identity(opened) != identity(after)
                    or identity(after) != identity(named)):
                raise ReleaseFailure(
                    "developer_id_team_enforcement_conflict")
            return opened, observed

        final = read_at(final_name, frozenset({1, 2}))
        pending = read_at(pending_name, frozenset({1, 2}))
        if (final is not None and final[1] != raw
                or pending is not None and pending[1] != raw
                or final is not None and pending is not None
                and (final[0].st_dev, final[0].st_ino)
                    != (pending[0].st_dev, pending[0].st_ino)):
            raise ReleaseFailure("developer_id_team_enforcement_conflict")
        staged = read_at(
            stage_name, frozenset({1, 2}), staging=True,
        )

        def retain_or_reconcile_stage(
            staged_value: tuple[os.stat_result, bytes],
            pending_value: tuple[os.stat_result, bytes] | None,
        ) -> None:
            if (pending_value is not None
                    and (staged_value[0].st_dev, staged_value[0].st_ino)
                        == (pending_value[0].st_dev,
                            pending_value[0].st_ino)):
                os.unlink(stage_name, dir_fd=root_fd)
                os.fsync(root_fd)
                return
            if not raw.startswith(staged_value[1]):
                raise ReleaseFailure(
                    "developer_id_team_enforcement_conflict")
            retained = (
                stage_name + ".retained-"
                + sha256_bytes(staged_value[1])
            )
            if staged_value[0].st_nlink == 2:
                evidence = read_at(
                    retained, frozenset({2}), staging=True,
                )
                if (evidence is None or evidence[1] != staged_value[1]
                        or (evidence[0].st_dev, evidence[0].st_ino)
                            != (staged_value[0].st_dev,
                                staged_value[0].st_ino)):
                    raise ReleaseFailure(
                        "developer_id_team_enforcement_conflict")
                os.unlink(stage_name, dir_fd=root_fd)
                os.fsync(root_fd)
                return
            if staged_value[0].st_nlink != 1:
                raise ReleaseFailure(
                    "developer_id_team_enforcement_conflict")
            try:
                os.link(
                    stage_name, retained,
                    src_dir_fd=root_fd, dst_dir_fd=root_fd,
                    follow_symlinks=False,
                )
                os.fsync(root_fd)
            except FileExistsError:
                evidence = read_at(
                    retained, frozenset({1, 2}), staging=True,
                )
                if evidence is None or evidence[1] != staged_value[1]:
                    raise ReleaseFailure(
                        "developer_id_team_enforcement_conflict")
            os.unlink(stage_name, dir_fd=root_fd)
            os.fsync(root_fd)

        if final is not None:
            if pending is not None:
                os.unlink(pending_name, dir_fd=root_fd)
                os.fsync(root_fd)
                pending = None
            if staged is not None:
                retain_or_reconcile_stage(staged, pending)
        else:
            if pending is None:
                if staged is not None and staged[1] != raw:
                    retain_or_reconcile_stage(staged, None)
                    staged = None
                elif staged is not None and (
                        staged[0].st_gid != root.st_gid
                        or stat.S_IMODE(staged[0].st_mode) != 0o444):
                    stage_fd = os.open(
                        stage_name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=root_fd,
                    )
                    try:
                        os.fchown(stage_fd, expected_uid, root.st_gid)
                        os.fchmod(stage_fd, 0o444)
                        os.fsync(stage_fd)
                    finally:
                        os.close(stage_fd)
                    staged = read_at(stage_name, frozenset({1}))
                if staged is None:
                    fd = os.open(
                        stage_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=root_fd,
                    )
                    try:
                        developer_id_team_enforcement_checkpoint(
                            "developer-id-enforcement-staging-opened")
                        os.fchown(fd, expected_uid, root.st_gid)
                        os.fchmod(fd, 0o600)
                        write_all(fd, raw, "developer_id_team_enforcement")
                        os.fsync(fd)
                        os.fchmod(fd, 0o444)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.link(
                    stage_name, pending_name,
                    src_dir_fd=root_fd, dst_dir_fd=root_fd,
                    follow_symlinks=False,
                )
                os.fsync(root_fd)
                linked = read_at(pending_name, frozenset({2}))
                staged = read_at(stage_name, frozenset({2}))
                if (linked is None or staged is None
                        or linked[1] != raw or staged[1] != raw
                        or (linked[0].st_dev, linked[0].st_ino)
                            != (staged[0].st_dev, staged[0].st_ino)):
                    raise ReleaseFailure(
                        "developer_id_team_enforcement_conflict")
                os.unlink(stage_name, dir_fd=root_fd)
                os.fsync(root_fd)
            elif staged is not None:
                retain_or_reconcile_stage(staged, pending)
                pending = read_at(pending_name, frozenset({1}))
            os.link(
                pending_name, final_name,
                src_dir_fd=root_fd, dst_dir_fd=root_fd,
                follow_symlinks=False,
            )
            os.fsync(root_fd)
            final = read_at(final_name, frozenset({2}))
            pending = read_at(pending_name, frozenset({2}))
            if (final is None or pending is None
                    or final[1] != raw or pending[1] != raw
                    or (final[0].st_dev, final[0].st_ino)
                        != (pending[0].st_dev, pending[0].st_ino)):
                raise ReleaseFailure(
                    "developer_id_team_enforcement_conflict")
            os.unlink(pending_name, dir_fd=root_fd)
            os.fsync(root_fd)
    finally:
        os.close(root_fd)
    observed = developer_id_team_enforcement(install_root, expected_uid)
    if observed is None or observed[0] != record:
        raise ReleaseFailure(
            "developer_id_team_enforcement_readback_failed")
    return observed


def developer_id_team_floor(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    path = install_root / DEVELOPER_ID_TEAM_FLOOR_NAME
    root_descriptor = -1
    descriptor = -1
    try:
        root_info = install_root.lstat()
        info = path.lstat()
        root_descriptor = os.open(
            install_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        descriptor = os.open(
            DEVELOPER_ID_TEAM_FLOOR_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_descriptor,
        )
    except FileNotFoundError:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if allow_absent:
            return None
        raise ReleaseFailure("developer_id_team_floor_missing")
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        raise ReleaseFailure("developer_id_team_floor_untrusted") from error
    try:
        opened_root = os.fstat(root_descriptor)
        opened = os.fstat(descriptor)
        reject_extended_acl(
            root_descriptor, "developer_id_team_floor_parent_extended_acl",
        )
        reject_extended_acl(
            descriptor, "developer_id_team_floor_extended_acl",
        )
        raw = os.read(descriptor, 2049)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
        os.close(root_descriptor)
    named = path.lstat()
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != expected_uid
            or stat.S_IMODE(root_info.st_mode) != 0o755
            or identity(root_info) != identity(opened_root)
            or not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(info.st_mode)
            or opened.st_uid != expected_uid
            or opened.st_gid != root_info.st_gid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not 2 <= opened.st_size <= 2048
            or len(raw) != opened.st_size
            or identity(info) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure("developer_id_team_floor_untrusted")
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
        reject_extended_acl(
            descriptor, "developer_id_team_floor_parent_extended_acl",
        )
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
            reject_extended_acl(
                floor_descriptor, "developer_id_team_floor_extended_acl",
            )
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

    def immutable_binding(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: item[key] for key in (
                "schema", "team_id", "authorization_ui_bundle_id",
                "established_from_release_id",
                "established_from_authorization_manifest_sha256",
            )
        }

    recovered = reconcile_developer_id_team_floor_publication(
        install_root, expected_uid,
    )
    if recovered is not None:
        if immutable_binding(recovered[0]) != immutable_binding(record):
            raise ReleaseFailure("developer_id_team_floor_conflict")
        establish_developer_id_team_enforcement(
            install_root, expected_uid, recovered[0], recovered[1],
        )
        return recovered
    descriptor = os.open(
        install_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        root_info = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "developer_id_team_floor_parent_extended_acl",
        )
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
            existing = developer_id_team_floor(install_root, expected_uid)
            if (existing is None
                    or immutable_binding(existing[0])
                        != immutable_binding(record)):
                raise ReleaseFailure("developer_id_team_floor_conflict")
            establish_developer_id_team_enforcement(
                install_root, expected_uid, existing[0], existing[1],
            )
            return existing

        def read_pending() -> tuple[os.stat_result, bytes] | None:
            try:
                before = os.stat(
                    DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                    dir_fd=descriptor, follow_symlinks=False,
                )
                pending_descriptor = os.open(
                    DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                return None
            try:
                opened = os.fstat(pending_descriptor)
                reject_extended_acl(
                    pending_descriptor,
                    "developer_id_team_floor_pending_extended_acl",
                )
                observed = os.read(pending_descriptor, 2049)
                after = os.fstat(pending_descriptor)
            finally:
                os.close(pending_descriptor)
            named = os.stat(
                DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                dir_fd=descriptor, follow_symlinks=False,
            )
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                item.st_gid, item.st_nlink, item.st_size,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != expected_uid
                    or opened.st_dev != root_info.st_dev
                    or opened.st_nlink not in {1, 2}
                    or stat.S_IMODE(opened.st_mode) & ~0o600
                    or len(observed) != opened.st_size
                    or opened.st_size > 2048
                    or identity(before) != identity(opened)
                    or identity(opened) != identity(after)
                    or identity(after) != identity(named)):
                raise ReleaseFailure(
                    "developer_id_team_floor_pending_untrusted")
            return opened, observed

        def normalize_pending() -> tuple[os.stat_result, bytes]:
            pending_descriptor = os.open(
                DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            try:
                os.fchown(pending_descriptor, expected_uid, root_info.st_gid)
                os.fchmod(pending_descriptor, 0o600)
                os.fsync(pending_descriptor)
            finally:
                os.close(pending_descriptor)
            normalized = read_pending()
            if normalized is None:
                raise ReleaseFailure(
                    "developer_id_team_floor_pending_untrusted")
            return normalized

        def retain_pending(
            pending: tuple[os.stat_result, bytes],
        ) -> None:
            normalized = normalize_pending()
            if normalized[1] != pending[1]:
                raise ReleaseFailure("developer_id_team_floor_conflict")
            retained_name = (
                DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME + ".retained-"
                + sha256_bytes(normalized[1])
            )
            if normalized[0].st_nlink == 2:
                try:
                    retained = os.stat(
                        retained_name, dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError as error:
                    raise ReleaseFailure(
                        "developer_id_team_floor_pending_untrusted"
                    ) from error
                if ((retained.st_dev, retained.st_ino)
                        != (normalized[0].st_dev, normalized[0].st_ino)):
                    raise ReleaseFailure(
                        "developer_id_team_floor_pending_untrusted")
            else:
                try:
                    os.link(
                        DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME, retained_name,
                        src_dir_fd=descriptor, dst_dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    os.fsync(descriptor)
                    developer_id_team_floor_checkpoint(
                        "developer-id-floor-partial-retained")
                except FileExistsError:
                    retained_descriptor = os.open(
                        retained_name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                    try:
                        retained = os.fstat(retained_descriptor)
                        retained_raw = os.read(retained_descriptor, 2049)
                    finally:
                        os.close(retained_descriptor)
                    if (retained_raw != normalized[1]
                            or not stat.S_ISREG(retained.st_mode)
                            or retained.st_uid != expected_uid
                            or retained.st_gid != root_info.st_gid
                            or stat.S_IMODE(retained.st_mode) != 0o600):
                        raise ReleaseFailure(
                            "developer_id_team_floor_pending_untrusted")
            os.unlink(
                DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME, dir_fd=descriptor,
            )
            os.fsync(descriptor)

        pending_valid = False
        if pending_info is not None:
            pending = read_pending()
            assert pending is not None
            pending = normalize_pending()
            try:
                pending_record = validate_developer_id_team_floor(
                    json.loads(pending[1]))
                pending_valid = (
                    pending[1] == _developer_id_floor_bytes(pending_record)
                    and pending[0].st_nlink == 1
                    and immutable_binding(pending_record)
                        == immutable_binding(record)
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ReleaseFailure):
                pending_valid = False
            if pending_valid:
                record = pending_record
                raw = pending[1]
            if not pending_valid:
                retain_pending(pending)
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
                developer_id_team_floor_checkpoint(
                    "developer-id-floor-pending-opened")
                write_all(
                    pending_descriptor, raw, "developer_id_team_floor"
                )
                os.fsync(pending_descriptor)
                developer_id_team_floor_checkpoint(
                    "developer-id-floor-pending-fsynced")
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
            developer_id_team_floor_checkpoint(
                "developer-id-floor-published")
        os.unlink(DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    observed = developer_id_team_floor(install_root, expected_uid)
    if (observed is None
            or immutable_binding(observed[0]) != immutable_binding(record)):
        raise ReleaseFailure("developer_id_team_floor_readback_failed")
    establish_developer_id_team_enforcement(
        install_root, expected_uid, observed[0], observed[1],
    )
    return observed


def verify_authorization_ui_bundle(root: Path, manifest_data: bytes,
                                   expected_uid: int | None = None) -> None:
    manifest = authorization_ui_bundle_manifest(manifest_data)
    expected_files = set(manifest["files"])
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    owner = root.lstat().st_uid if expected_uid is None else expected_uid
    verify_acl_free_directory(
        root, owner, 0o555, "authorization_ui_bundle_invalid",
    )
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReleaseFailure("authorization_ui_bundle_invalid")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
            if stat.S_IMODE(info.st_mode) != 0o555:
                raise ReleaseFailure("authorization_ui_bundle_mode_invalid")
            verify_acl_free_directory(
                item, owner, 0o555, "authorization_ui_bundle_invalid",
            )
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
        data = read_acl_free_regular(
            path, owner, record["mode"],
            "authorization_ui_bundle_member_invalid:" + relative,
        )
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
    if not isinstance(value, dict) or data != canonical:
        raise ReleaseFailure("native_host_products_notarization_invalid")
    schema = value.get("schema")
    if schema == NATIVE_HOST_PRODUCTS_RECEIPT_V1_SCHEMA:
        if (set(value) != {
                "container_sha256", "container_size", "gatekeeper_assessed",
                "notary_log_sha256", "notary_status",
                "notary_submission_id", "schema", "stapler_validated",
                "team_id",
            }
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
    if schema not in {
        NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
        NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
    }:
        raise ReleaseFailure("native_host_products_notarization_invalid")
    expected_fields = {
        "build_custody", "container_cdhash", "container_identifier",
        "container_manifest_sha256", "container_sha256", "container_size",
        "developer_id_certificate_sha1", "gatekeeper_assessed",
        "notary_log_sha256", "notary_status", "notary_submission_id",
        "notary_submission_sha256", "products", "release_commit", "schema",
        "signing_config_sha256", "source_archive_sha256",
        "source_tree_sha256",
        "stapler_validated", "team_id",
    }
    if schema == NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA:
        expected_fields.add("host_release_preimage_sha256")
    if set(value) != expected_fields:
        raise ReleaseFailure("native_host_products_notarization_invalid")
    sha256_fields = [
        "container_manifest_sha256", "container_sha256", "notary_log_sha256",
        "notary_submission_sha256", "signing_config_sha256",
        "source_archive_sha256", "source_tree_sha256",
    ]
    if schema == NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA:
        sha256_fields.append("host_release_preimage_sha256")
    sha1_fields = (
        "container_cdhash", "developer_id_certificate_sha1", "release_commit",
    )
    products = value.get("products")
    if (any(not isinstance(value.get(field), str)
            or SHA256.fullmatch(value[field]) is None
            for field in sha256_fields)
            or any(not isinstance(value.get(field), str)
                   or re.fullmatch(r"[0-9a-f]{40}", value[field]) is None
                   for field in sha1_fields)
            or value.get("container_identifier")
                != NATIVE_HOST_PRODUCTS_CONTAINER_IDENTIFIER
            or value.get("build_custody") != NATIVE_HOST_BUILD_CUSTODY
            or not isinstance(value.get("container_size"), int)
            or isinstance(value.get("container_size"), bool)
            or not 1 <= value["container_size"] <= 512 * 1024 * 1024
            or value.get("notary_status") != "accepted"
            or value.get("gatekeeper_assessed") is not True
            or value.get("stapler_validated") is not True
            or value.get("team_id") != NATIVE_HOST_PRODUCTS_TEAM_ID
            or not isinstance(value.get("notary_submission_id"), str)
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                value["notary_submission_id"],
            ) is None
            or not isinstance(products, dict)
            or set(products) != set(NATIVE_HOST_PRODUCTS_V2_PRODUCT_IDENTIFIERS)):
        raise ReleaseFailure("native_host_products_notarization_invalid")
    for name, identifier in NATIVE_HOST_PRODUCTS_V2_PRODUCT_IDENTIFIERS.items():
        product = products.get(name)
        if (not isinstance(product, dict)
                or set(product) != {"cdhash", "identifier"}
                or product.get("identifier") != identifier
                or not isinstance(product.get("cdhash"), str)
                or re.fullmatch(r"[0-9a-f]{40}", product["cdhash"]) is None):
            raise ReleaseFailure("native_host_products_notarization_invalid")
    return value


def verify_native_host_products_notarization_signature(
    receipt_data: bytes, signature_data: bytes, receipt: Mapping[str, Any], *,
    expected_certificate_sha1: str | None = None,
) -> None:
    """Verify the exact canonical signed receipt's Developer ID seal."""
    certificate_sha1 = receipt.get("developer_id_certificate_sha1")
    team = receipt.get("team_id")
    if (receipt.get("schema") not in {
                NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
                NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
            }
            or not isinstance(certificate_sha1, str)
            or re.fullmatch(r"[0-9a-f]{40}", certificate_sha1) is None
            or team != NATIVE_HOST_PRODUCTS_TEAM_ID
            or not 256 <= len(signature_data) <= 512 * 1024
            or (expected_certificate_sha1 is not None
                and certificate_sha1 != expected_certificate_sha1)):
        raise ReleaseFailure("native_host_products_receipt_signature_invalid")
    requirement = developer_id_requirement(
        NATIVE_HOST_PRODUCTS_RECEIPT_IDENTIFIER, team, certificate_sha1,
    )
    with tempfile.TemporaryDirectory(
        prefix="secure-sandbox-native-host-receipt-",
    ) as temporary:
        root = Path(temporary)
        receipt_path = root / "receipt.json"
        signature_path = root / "receipt.sig"
        for path, raw in (
            (receipt_path, receipt_data), (signature_path, signature_data),
        ):
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
            )
            try:
                write_all(descriptor, raw, "native_host_receipt_signature")
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o400)
            finally:
                os.close(descriptor)
        verified = subprocess.run(
            [
                "/usr/bin/codesign", "--verify", "--strict", "--verbose=4",
                f"--detached={signature_path}", f"-R={requirement}",
                str(receipt_path),
            ],
            check=False, capture_output=True, text=True, timeout=120,
        )
        details = subprocess.run(
            [
                "/usr/bin/codesign", "-d", "--verbose=4",
                f"--detached={signature_path}", str(receipt_path),
            ],
            check=False, capture_output=True, text=True, timeout=120,
        )
        verify_codesign_metadata(
            details, identifier=NATIVE_HOST_PRODUCTS_RECEIPT_IDENTIFIER,
            team=team, expected_cdhash=None,
            failure="native_host_products_receipt_signature_invalid",
        )
        detail_lines = details.stderr.splitlines()
        authorities = [
            line.removeprefix("Authority=")
            for line in detail_lines if line.startswith("Authority=")
        ]
        timestamps = [
            line.removeprefix("Timestamp=")
            for line in detail_lines if line.startswith("Timestamp=")
        ]
        if (verified.returncode != 0 or len(authorities) < 2
                or not authorities[0].startswith("Developer ID Application:")
                or not authorities[0].endswith(f" ({team})")
                or len(timestamps) != 1 or not timestamps[0]
                or "Signature=adhoc" in details.stderr):
            raise ReleaseFailure(
                "native_host_products_receipt_signature_invalid"
            )


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


def same_native_host_mount_identity(observed: object, expected: Path) -> bool:
    """Accept a kernel-canonical mount path only when it is the same inode."""
    if (not isinstance(observed, str) or not 1 <= len(observed) <= 4096
            or not observed.startswith("/")):
        return False
    observed_path = Path(observed)
    if not observed_path.is_absolute() or ".." in observed_path.parts:
        return False
    try:
        observed_info = observed_path.lstat()
        expected_info = expected.lstat()
    except (OSError, ValueError):
        return False
    return (
        stat.S_ISDIR(observed_info.st_mode)
        and stat.S_ISDIR(expected_info.st_mode)
        and (observed_info.st_dev, observed_info.st_ino)
        == (expected_info.st_dev, expected_info.st_ino)
    )


def verify_native_host_products_container(
    values: Mapping[str, bytes], *, require_v2: bool = False,
    expected_source_provenance: Mapping[str, str] | None = None,
    expected_certificate_sha1: str | None = None,
) -> None:
    """Verify the exact stapled carrier and its independently bound contents.

    The v2 receipt is an exact detached Developer-ID-signed provenance record;
    its status claims remain audit metadata.  Runtime authority still comes
    from the independently verified DMG signature, stapled ticket, inner
    canonical manifest, and every mounted product's live signature and hash.
    """
    container = values["native_host_products_container"]
    manifest_data = values["native_host_products_manifest"]
    receipt_data = values["native_host_products_notarization"]
    manifest = native_host_products_manifest(manifest_data)
    receipt = native_host_products_notarization(receipt_data)
    receipt_signed = receipt["schema"] in {
        NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
        NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
    }
    if require_v2 and not receipt_signed:
        raise ReleaseFailure("native_host_products_notarization_below_v2")
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
            or receipt["team_id"] != team
            or (receipt_signed
                and receipt["container_manifest_sha256"]
                    != sha256_bytes(manifest_data))):
        raise ReleaseFailure("native_host_products_notarization_mismatch")
    if receipt_signed:
        signature_data = values.get(
            "native_host_products_notarization_signature"
        )
        if not isinstance(signature_data, bytes):
            raise ReleaseFailure(
                "native_host_products_receipt_signature_missing"
            )
        verify_native_host_products_notarization_signature(
            receipt_data, signature_data, receipt,
            expected_certificate_sha1=expected_certificate_sha1,
        )
        if (expected_source_provenance is not None
                and any(
                    receipt.get(name) != expected_source_provenance.get(name)
                    for name in (
                        "release_commit", "source_archive_sha256",
                        "source_tree_sha256", "signing_config_sha256",
                    )
                )):
            raise ReleaseFailure("native_host_products_source_provenance_mismatch")
    cache_names = [
        "native_host_products_container", "native_host_products_manifest",
        "native_host_products_notarization", "authorization_ui_bundle",
        "native_credential_helper_bundle", "native_stack_credential_client",
        "native_projection_consumer",
    ]
    if receipt_signed:
        cache_names.append("native_host_products_notarization_signature")
    cache_key = tuple(sha256_bytes(values[name]) for name in cache_names)
    if cache_key in _VERIFIED_NATIVE_HOST_PRODUCT_CONTAINERS:
        return

    certificate_sha1 = (
        receipt["developer_id_certificate_sha1"] if receipt_signed else None
    )
    requirement = developer_id_requirement(
        NATIVE_HOST_PRODUCTS_CONTAINER_IDENTIFIER, team, certificate_sha1,
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
        container_details = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(snapshot)],
            check=False, capture_output=True, text=True, timeout=120,
        )
        verify_codesign_metadata(
            container_details,
            identifier=NATIVE_HOST_PRODUCTS_CONTAINER_IDENTIFIER,
            team=team,
            expected_cdhash=(
                receipt["container_cdhash"] if receipt_signed else None
            ),
            failure="native_host_products_container_signature_invalid",
        )

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
                    or not same_native_host_mount_identity(
                        mounted[0].get("mount-point"), mount,
                    )
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
            products = receipt["products"] if receipt_signed else {}
            verified_authorization_ui_signing_policy(
                mount / AUTHORIZATION_UI_APP_NAME,
                values["authorization_ui_bundle"],
                expected_cdhash=(
                    products["authorization_ui"]["cdhash"]
                    if receipt_signed else None
                ),
                developer_id_certificate_sha1=certificate_sha1,
            )
            verify_native_credential_helper_bundle(
                mount / NATIVE_CREDENTIAL_HELPER_APP_NAME,
                values["native_credential_helper_bundle"],
                expected_cdhash=(
                    products["credential_helper"]["cdhash"]
                    if receipt_signed else None
                ),
                developer_id_certificate_sha1=certificate_sha1,
            )
            verify_native_component_signature(
                mount / "SecureSandboxNativeStackBackend",
                NATIVE_CREDENTIAL_BACKEND_IDENTIFIER, team,
                expected_cdhash=(
                    products["native_stack_backend"]["cdhash"]
                    if receipt_signed else None
                ),
                developer_id_certificate_sha1=certificate_sha1,
            )
            verify_native_component_signature(
                mount / "SecureSandboxNativeProjectionConsumer",
                NATIVE_PROJECTION_CONSUMER_IDENTIFIER, team,
                expected_cdhash=(
                    products["native_projection_consumer"]["cdhash"]
                    if receipt_signed else None
                ),
                developer_id_certificate_sha1=certificate_sha1,
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


def verify_native_component_signature(
    path: Path, identifier: str, team: str, *,
    expected_cdhash: str | None = None,
    developer_id_certificate_sha1: str | None = None,
) -> None:
    requirement = developer_id_requirement(
        identifier, team, developer_id_certificate_sha1,
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
    verify_codesign_metadata(
        details, identifier=identifier, team=team,
        expected_cdhash=expected_cdhash,
        failure="native_component_signature_invalid:" + identifier,
    )
    if (signature.returncode != 0 or requirement_result.returncode != 0
            or "flags=0x10000(runtime)" not in details.stderr
            or "Signature=adhoc" in details.stderr):
        raise ReleaseFailure("native_component_signature_invalid:" + identifier)


def verify_native_credential_helper_bundle(
    root: Path, manifest_data: bytes, expected_uid: int | None = None, *,
    expected_cdhash: str | None = None,
    developer_id_certificate_sha1: str | None = None,
) -> None:
    manifest = native_components_manifest(manifest_data)
    files = manifest["helper"]["files"]
    owner = root.lstat().st_uid if expected_uid is None else expected_uid
    verify_acl_free_directory(
        root, owner, 0o555, "native_credential_helper_bundle_invalid",
    )
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
            verify_acl_free_directory(
                item, owner, 0o555,
                "native_credential_helper_bundle_invalid",
            )
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
        data = read_acl_free_regular(
            path, owner, record["mode"],
            "native_credential_helper_bundle_member_invalid:" + relative,
        )
        if (stat.S_IMODE(info.st_mode) != record["mode"]
                or len(data) != record["size"]
                or sha256_bytes(data) != record["sha256"]):
            raise ReleaseFailure("native_credential_helper_bundle_member_invalid:" + relative)
    try:
        information = plistlib.loads(read_acl_free_regular(
            root / "Contents/Info.plist", owner,
            files["Contents/Info.plist"]["mode"],
            "native_credential_helper_info_invalid",
        ))
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
    signature_options: dict[str, str] = {}
    if expected_cdhash is not None:
        signature_options["expected_cdhash"] = expected_cdhash
    if developer_id_certificate_sha1 is not None:
        signature_options["developer_id_certificate_sha1"] = (
            developer_id_certificate_sha1
        )
    verify_native_component_signature(
        root, NATIVE_CREDENTIAL_HELPER_LABEL,
        manifest["signing_policy"]["team_id"], **signature_options,
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
    native_host_generation: Path | None = None,
) -> tuple[dict[str, Any], str]:
    """Establish only from the already-installed signed v2 release.

    An empty machine is intentionally not trust-on-first-use.  Its initial
    Developer ID team requires a separate out-of-band bootstrap ceremony.
    """
    candidate_manifest = values.get("authorization_ui_bundle")
    if not isinstance(candidate_manifest, bytes):
        raise ReleaseFailure("candidate_authorization_ui_missing")
    candidate_policy = verified_authorization_ui_signing_policy(
        ((native_host_generation / AUTHORIZATION_UI_APP_NAME)
         if native_host_generation is not None
         else repo / AUTHORIZATION_UI_APP_SOURCE),
        candidate_manifest,
    )
    existing = reconcile_developer_id_team_floor_publication(
        install_root, expected_uid,
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


def bootstrap_developer_id_team_floor_from_candidate(
    repo: Path, install_root: Path, expected_uid: int,
    values: Mapping[str, bytes], release_id: str,
    generation: Path, candidate_record: Mapping[str, object],
    expected_team_id: str,
    expected_authorization_manifest_sha256: str,
) -> tuple[dict[str, Any], str]:
    """Establish the first Team floor only in the terminal root ceremony."""
    if (SHA256.fullmatch(release_id) is None
            or native_host_candidate_record(repo, generation)
                != dict(candidate_record)):
        raise ReleaseFailure("developer_id_team_floor_candidate_invalid")
    manifest_data = values.get("authorization_ui_bundle")
    certificate_sha1 = candidate_record.get(
        "developer_id_certificate_sha1")
    if (not isinstance(manifest_data, bytes)
            or not isinstance(certificate_sha1, str)
            or re.fullmatch(r"[0-9a-f]{40}", certificate_sha1) is None
            or re.fullmatch(r"[A-Z0-9]{10}", expected_team_id) is None
            or SHA256.fullmatch(
                expected_authorization_manifest_sha256) is None
            or sha256_bytes(manifest_data)
                != expected_authorization_manifest_sha256):
        raise ReleaseFailure("developer_id_team_floor_candidate_invalid")
    policy = verified_authorization_ui_signing_policy(
        generation / AUTHORIZATION_UI_APP_NAME,
        manifest_data, expected_uid=repo.lstat().st_uid,
        developer_id_certificate_sha1=certificate_sha1,
    )
    if (policy["team_id"] != NATIVE_HOST_PRODUCTS_TEAM_ID
            or policy["team_id"] != expected_team_id):
        raise ReleaseFailure("release_developer_id_team_mismatch")
    existing = reconcile_developer_id_team_floor_publication(
        install_root, expected_uid,
    )
    if existing is None:
        existing = create_developer_id_team_floor(
            install_root, expected_uid,
            developer_id_floor_record(
                release_id=release_id,
                authorization_manifest=manifest_data,
                policy=policy,
                established_at=int(time.time()),
            ),
        )
    floor, floor_sha256 = existing
    if (floor["team_id"] != policy["team_id"]
            or floor["authorization_ui_bundle_id"] != policy["bundle_id"]
            or floor["established_from_release_id"] != release_id
            or floor["established_from_authorization_manifest_sha256"]
                != sha256_bytes(manifest_data)):
        raise ReleaseFailure("developer_id_team_floor_candidate_conflict")
    establish_developer_id_team_enforcement(
        install_root, expected_uid, floor, floor_sha256,
    )
    return floor, floor_sha256


def require_developer_id_team_floor_unchanged(
    install_root: Path, expected_uid: int, expected_sha256: str,
) -> tuple[dict[str, Any], str]:
    observed = developer_id_team_floor(install_root, expected_uid)
    if observed is None or not hmac.compare_digest(observed[1], expected_sha256):
        raise ReleaseFailure("developer_id_team_floor_changed")
    return observed


def validate_native_components_payload(
    repo: Path, values: dict[str, bytes], *,
    native_host_generation: Path | None = None,
) -> None:
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
            ((native_host_generation / PAYLOAD_SOURCES[payload].name)
             if native_host_generation is not None
             else repo / PAYLOAD_SOURCES[payload]),
            identifier,
            manifest["signing_policy"]["team_id"],
        )
    verify_native_credential_helper_bundle(
        ((native_host_generation / NATIVE_CREDENTIAL_HELPER_APP_NAME)
         if native_host_generation is not None
         else repo / NATIVE_CREDENTIAL_HELPER_APP_SOURCE),
        manifest_data,
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
        raw = read_acl_free_regular(
            path, expected_uid, 0o600,
            "execution_approval_floor_invalid", maximum=4096,
        )
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


def validate_native_stack_coordination_contract(
    raw: bytes,
) -> dict[str, Any]:
    try:
        value = json.loads(raw)
        canonical = (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (
        UnicodeDecodeError, UnicodeEncodeError, TypeError, ValueError,
        json.JSONDecodeError,
    ) as error:
        raise ReleaseFailure(
            "native_stack_coordination_contract_invalid") from error
    features = value.get("features") if isinstance(value, dict) else None
    epoch = value.get("epoch") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "epoch", "features"}
        or value.get("schema")
            != NATIVE_STACK_COORDINATION_CONTRACT_SCHEMA
        or not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1
        or not isinstance(features, list)
        or any(
            not isinstance(feature, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", feature) is None
            for feature in features
        )
        or features != sorted(set(features))
        or not NATIVE_STACK_COORDINATION_REQUIRED_FEATURES <= set(features)
        or raw != canonical
    ):
        raise ReleaseFailure("native_stack_coordination_contract_invalid")
    return value


def _native_stack_coordination_floor_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReleaseFailure(
            "native_stack_coordination_floor_invalid") from error


def validate_native_stack_coordination_floor(
    value: object,
) -> dict[str, Any]:
    fields = {
        "schema", "minimum_epoch", "established_from_release_id",
        "established_from_contract_sha256",
    }
    if (
        not isinstance(value, dict) or set(value) != fields
        or value.get("schema") != NATIVE_STACK_COORDINATION_FLOOR_SCHEMA
        or not isinstance(value.get("minimum_epoch"), int)
        or isinstance(value.get("minimum_epoch"), bool)
        or value["minimum_epoch"] < 1
        or SHA256.fullmatch(str(value.get(
            "established_from_release_id"))) is None
        or SHA256.fullmatch(str(value.get(
            "established_from_contract_sha256"))) is None
    ):
        raise ReleaseFailure("native_stack_coordination_floor_invalid")
    return {key: value[key] for key in sorted(fields)}


def _native_stack_coordination_enforcement_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_invalid") from error


def validate_native_stack_coordination_enforcement(
    value: object,
) -> dict[str, Any]:
    fields = {
        "schema", "minimum_epoch", "minimum_features",
        "authoritative_floor_sha256",
    }
    features = value.get("minimum_features") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict) or set(value) != fields
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
            "authoritative_floor_sha256"))) is None
    ):
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_invalid")
    return {key: value[key] for key in sorted(fields)}


def native_stack_coordination_enforcement(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    path = install_root / NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME
    try:
        root = install_root.lstat()
        info = path.lstat()
    except FileNotFoundError:
        if allow_absent:
            return None
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_missing")
    if (
        not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
        or root.st_uid != expected_uid or stat.S_IMODE(root.st_mode) != 0o755
        or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != expected_uid or info.st_gid != root.st_gid
        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o444
        or not 2 <= info.st_size <= 2048
    ):
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_untrusted")
    verify_acl_free_directory(
        install_root, expected_uid, 0o755,
        "native_stack_coordination_enforcement_untrusted",
    )
    raw = read_acl_free_regular(
        path, expected_uid, 0o444,
        "native_stack_coordination_enforcement_untrusted", maximum=2048,
    )
    try:
        value = validate_native_stack_coordination_enforcement(
            json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_invalid") from error
    if raw != _native_stack_coordination_enforcement_bytes(value):
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_not_canonical")
    return value, sha256_bytes(raw)


def native_stack_coordination_floor(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    path = install_root / NATIVE_STACK_COORDINATION_FLOOR_NAME
    enforcement_path = (
        install_root / NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME)
    try:
        root = install_root.lstat()
        info = path.lstat()
    except FileNotFoundError:
        if os.path.lexists(enforcement_path):
            raise ReleaseFailure(
                "native_stack_coordination_floor_incomplete")
        if allow_absent:
            return None
        raise ReleaseFailure("native_stack_coordination_floor_missing")
    if not os.path.lexists(enforcement_path):
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_missing")
    if (
        not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
        or root.st_uid != expected_uid or stat.S_IMODE(root.st_mode) != 0o755
        or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != expected_uid or info.st_gid != root.st_gid
        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
        or not 2 <= info.st_size <= 2048
    ):
        raise ReleaseFailure("native_stack_coordination_floor_untrusted")
    verify_acl_free_directory(
        install_root, expected_uid, 0o755,
        "native_stack_coordination_floor_untrusted",
    )
    raw = read_acl_free_regular(
        path, expected_uid, 0o600,
        "native_stack_coordination_floor_untrusted", maximum=2048,
    )
    try:
        value = validate_native_stack_coordination_floor(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure(
            "native_stack_coordination_floor_invalid") from error
    if raw != _native_stack_coordination_floor_bytes(value):
        raise ReleaseFailure("native_stack_coordination_floor_not_canonical")
    enforcement = native_stack_coordination_enforcement(
        install_root, expected_uid)
    if (
        enforcement is None
        or enforcement[0]["minimum_epoch"] != value["minimum_epoch"]
        or enforcement[0]["authoritative_floor_sha256"]
            != sha256_bytes(raw)
    ):
        raise ReleaseFailure(
            "native_stack_coordination_enforcement_mismatch")
    return value, sha256_bytes(raw)


def establish_native_stack_coordination_floor(
    install_root: Path, expected_uid: int, *, release_id: str,
    contract_raw: bytes,
) -> tuple[dict[str, Any], str]:
    contract = validate_native_stack_coordination_contract(contract_raw)
    record = validate_native_stack_coordination_floor({
        "schema": NATIVE_STACK_COORDINATION_FLOOR_SCHEMA,
        "minimum_epoch": contract["epoch"],
        "established_from_release_id": release_id,
        "established_from_contract_sha256": sha256_bytes(contract_raw),
    })
    raw = _native_stack_coordination_floor_bytes(record)
    enforcement_record = validate_native_stack_coordination_enforcement({
        "schema": NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA,
        "minimum_epoch": contract["epoch"],
        "minimum_features": contract["features"],
        "authoritative_floor_sha256": sha256_bytes(raw),
    })
    enforcement_raw = _native_stack_coordination_enforcement_bytes(
        enforcement_record)
    descriptor = os.open(
        install_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        root = os.fstat(descriptor)
        observed_root = install_root.lstat()
        reject_extended_acl(
            descriptor, "native_stack_coordination_floor_parent_untrusted",
        )
        if (
            not stat.S_ISDIR(root.st_mode)
            or stat.S_ISLNK(observed_root.st_mode)
            or (root.st_dev, root.st_ino)
                != (observed_root.st_dev, observed_root.st_ino)
            or root.st_uid != expected_uid
            or stat.S_IMODE(root.st_mode) != 0o755
        ):
            raise ReleaseFailure(
                "native_stack_coordination_floor_parent_untrusted")

        def information(name: str) -> os.stat_result | None:
            try:
                return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return None

        def read_at(
            name: str, mode: int, *, maximum: int = 4096,
        ) -> tuple[os.stat_result, bytes] | None:
            observed = information(name)
            if observed is None:
                return None
            try:
                opened_descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
            except OSError as error:
                raise ReleaseFailure(
                    "native_stack_coordination_floor_conflict") from error
            try:
                opened = os.fstat(opened_descriptor)
                reject_extended_acl(
                    opened_descriptor,
                    "native_stack_coordination_floor_conflict",
                )
                chunks: list[bytes] = []
                remaining = maximum + 1
                while remaining > 0:
                    chunk = os.read(opened_descriptor, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                after = os.fstat(opened_descriptor)
            finally:
                os.close(opened_descriptor)
            value = b"".join(chunks)
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_size, item.st_mode,
                item.st_uid, item.st_gid, item.st_nlink,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != expected_uid
                or opened.st_gid != root.st_gid
                or opened.st_nlink not in {1, 2}
                or stat.S_IMODE(opened.st_mode) != mode
                or len(value) != opened.st_size or len(value) > maximum
                or identity(observed) != identity(opened)
                or identity(opened) != identity(after)
            ):
                raise ReleaseFailure(
                    "native_stack_coordination_floor_conflict")
            return opened, value

        def ensure_pending(name: str, value: bytes, mode: int) -> None:
            existing = read_at(name, mode)
            if existing is not None:
                if existing[1] != value:
                    raise ReleaseFailure(
                        "native_stack_coordination_floor_conflict")
                return
            pending_descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                mode, dir_fd=descriptor,
            )
            try:
                os.fchown(pending_descriptor, expected_uid, root.st_gid)
                os.fchmod(pending_descriptor, mode)
                reject_extended_acl(
                    pending_descriptor,
                    "native_stack_coordination_floor_conflict",
                )
                write_all(
                    pending_descriptor, value,
                    "native_stack_coordination_floor",
                )
                os.fsync(pending_descriptor)
                reject_extended_acl(
                    pending_descriptor,
                    "native_stack_coordination_floor_conflict",
                )
            finally:
                os.close(pending_descriptor)
            os.fsync(descriptor)

        def publish(pending: str, final: str) -> None:
            pending_record = read_at(
                pending,
                0o444 if "enforcement" in pending else 0o600,
            )
            if pending_record is None:
                raise ReleaseFailure(
                    "native_stack_coordination_floor_conflict")
            final_record = read_at(
                final,
                0o444 if "enforcement" in final else 0o600,
            )
            if final_record is None:
                os.link(
                    pending, final,
                    src_dir_fd=descriptor, dst_dir_fd=descriptor,
                    follow_symlinks=False,
                )
                os.fsync(descriptor)
                final_record = read_at(
                    final,
                    0o444 if "enforcement" in final else 0o600,
                )
            if (
                final_record is None
                or (pending_record[0].st_dev, pending_record[0].st_ino)
                    != (final_record[0].st_dev, final_record[0].st_ino)
            ):
                raise ReleaseFailure(
                    "native_stack_coordination_floor_conflict")

        floor_final = read_at(NATIVE_STACK_COORDINATION_FLOOR_NAME, 0o600)
        enforcement_final = read_at(
            NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME, 0o444)
        if floor_final is not None and enforcement_final is None:
            raise ReleaseFailure(
                "native_stack_coordination_floor_conflict")
        if floor_final is not None and floor_final[1] != raw:
            raise ReleaseFailure(
                "native_stack_coordination_floor_conflict")
        if (
            enforcement_final is not None
            and enforcement_final[1] != enforcement_raw
        ):
            raise ReleaseFailure(
                "native_stack_coordination_floor_conflict")

        if floor_final is None:
            ensure_pending(
                NATIVE_STACK_COORDINATION_FLOOR_PENDING_NAME, raw, 0o600)
        if enforcement_final is None:
            ensure_pending(
                NATIVE_STACK_COORDINATION_ENFORCEMENT_PENDING_NAME,
                enforcement_raw, 0o444,
            )
        if enforcement_final is None:
            native_coordination_bootstrap_checkpoint(
                "before-coordination-enforcement-publication")
            publish(
                NATIVE_STACK_COORDINATION_ENFORCEMENT_PENDING_NAME,
                NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME,
            )
            native_coordination_bootstrap_checkpoint(
                "coordination-enforcement-published")
        if floor_final is None:
            publish(
                NATIVE_STACK_COORDINATION_FLOOR_PENDING_NAME,
                NATIVE_STACK_COORDINATION_FLOOR_NAME,
            )
            native_coordination_bootstrap_checkpoint(
                "coordination-private-floor-published")

        for pending, final in (
            (
                NATIVE_STACK_COORDINATION_FLOOR_PENDING_NAME,
                NATIVE_STACK_COORDINATION_FLOOR_NAME,
            ),
            (
                NATIVE_STACK_COORDINATION_ENFORCEMENT_PENDING_NAME,
                NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME,
            ),
        ):
            pending_info = information(pending)
            final_info = information(final)
            if pending_info is None:
                continue
            if final_info is None or (
                pending_info.st_dev, pending_info.st_ino
            ) != (final_info.st_dev, final_info.st_ino):
                raise ReleaseFailure(
                    "native_stack_coordination_floor_conflict")
            os.unlink(pending, dir_fd=descriptor)
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    observed = native_stack_coordination_floor(install_root, expected_uid)
    if observed is None or observed[0] != record:
        raise ReleaseFailure(
            "native_stack_coordination_floor_readback_failed")
    return observed


def enforce_native_stack_coordination_floor(
    contract_raw: bytes, install_root: Path, expected_uid: int,
) -> dict[str, Any]:
    contract = validate_native_stack_coordination_contract(contract_raw)
    observed = native_stack_coordination_floor(
        install_root, expected_uid, allow_absent=True)
    if observed is None:
        raise ReleaseFailure("native_stack_coordination_floor_missing")
    enforcement = native_stack_coordination_enforcement(
        install_root, expected_uid)
    if (
        enforcement is None
        or contract["epoch"] < observed[0]["minimum_epoch"]
        or not set(enforcement[0]["minimum_features"])
            <= set(contract["features"])
    ):
        raise ReleaseFailure("release_below_native_stack_coordination_floor")
    return contract


def _native_host_candidate_floor_bytes(value: object) -> bytes:
    try:
        return (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReleaseFailure("native_host_candidate_floor_invalid") from error


def native_host_candidate_inventory_sha256() -> str:
    return sha256_bytes((json.dumps({
        "payload_names": sorted(PAYLOAD_NAMES),
        "schema": "secure-sandbox-native-host-candidate-inventory-v1",
    }, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii"))


def validate_native_host_candidate_floor(value: object) -> dict[str, Any]:
    fields = {
        "schema", "established_from_predecessor_release_id",
        "established_from_release_id", "establishment_mode",
        "candidate_record_sha256",
        "required_feature", "required_payload_inventory_sha256",
    }
    establishment_mode = (
        value.get("establishment_mode") if isinstance(value, dict) else None
    )
    predecessor_release_id = (
        value.get("established_from_predecessor_release_id")
        if isinstance(value, dict) else None
    )
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != NATIVE_HOST_CANDIDATE_FLOOR_SCHEMA
            or establishment_mode not in {
                NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE,
                NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE,
            }
            or SHA256.fullmatch(str(predecessor_release_id)) is None
            or (establishment_mode
                    == NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                and predecessor_release_id
                    != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID)
            or SHA256.fullmatch(str(value.get(
                "established_from_release_id", ""))) is None
            or SHA256.fullmatch(str(value.get(
                "candidate_record_sha256", ""))) is None
            or value.get("required_feature")
                != NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
            or value.get("required_payload_inventory_sha256")
                != native_host_candidate_inventory_sha256()):
        raise ReleaseFailure("native_host_candidate_floor_invalid")
    return {name: value[name] for name in sorted(fields)}


def validate_native_host_candidate_enforcement(
    value: object,
) -> dict[str, Any]:
    fields = {
        "schema", "required_feature", "required_payload_inventory_sha256",
        "authoritative_floor_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema")
                != NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA
            or value.get("required_feature")
                != NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
            or value.get("required_payload_inventory_sha256")
                != native_host_candidate_inventory_sha256()
            or SHA256.fullmatch(str(value.get(
                "authoritative_floor_sha256", ""))) is None):
        raise ReleaseFailure("native_host_candidate_enforcement_invalid")
    return {name: value[name] for name in sorted(fields)}


def _read_native_host_candidate_floor_file(
    install_root: Path, expected_uid: int, name: str, mode: int,
    *, allowed_link_counts: frozenset[int] = frozenset({1}),
) -> tuple[dict[str, Any], bytes, tuple[int, int]] | None:
    path = install_root / name
    root_descriptor = -1
    descriptor = -1
    try:
        root = install_root.lstat()
        before = path.lstat()
        root_descriptor = os.open(
            install_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except FileNotFoundError:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        return None
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        raise ReleaseFailure("native_host_candidate_floor_untrusted") from error
    try:
        reject_extended_acl(
            root_descriptor,
            "native_host_candidate_floor_parent_extended_acl",
        )
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "native_host_candidate_floor_extended_acl",
        )
        raw = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
        os.close(root_descriptor)
    named = path.lstat()
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
            or root.st_uid != expected_uid
            or stat.S_IMODE(root.st_mode) != 0o755
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid or opened.st_gid != root.st_gid
            or opened.st_nlink not in allowed_link_counts
            or stat.S_IMODE(opened.st_mode) != mode
            or not 2 <= opened.st_size <= 4096 or len(raw) != opened.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure("native_host_candidate_floor_untrusted")
    try:
        decoded = json.loads(raw)
        value = (
            validate_native_host_candidate_floor(decoded)
            if name == NATIVE_HOST_CANDIDATE_FLOOR_NAME
            else validate_native_host_candidate_enforcement(decoded)
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("native_host_candidate_floor_invalid") from error
    if raw != _native_host_candidate_floor_bytes(value):
        raise ReleaseFailure("native_host_candidate_floor_not_canonical")
    return value, raw, (opened.st_dev, opened.st_ino)


def native_host_candidate_floor(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    floor = _read_native_host_candidate_floor_file(
        install_root, expected_uid, NATIVE_HOST_CANDIDATE_FLOOR_NAME, 0o600,
    )
    enforcement = native_host_candidate_replay_enforcement(
        install_root, expected_uid, allow_absent=True,
    )
    if floor is None:
        if enforcement is not None:
            raise ReleaseFailure("native_host_candidate_floor_incomplete")
        if allow_absent:
            return None
        raise ReleaseFailure("native_host_candidate_floor_missing")
    if enforcement is None:
        raise ReleaseFailure("native_host_candidate_enforcement_missing")
    floor_sha256 = sha256_bytes(floor[1])
    if enforcement[0]["authoritative_floor_sha256"] != floor_sha256:
        raise ReleaseFailure("native_host_candidate_enforcement_mismatch")
    return floor[0], floor_sha256


def native_host_candidate_enforcement(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    observed = _read_native_host_candidate_floor_file(
        install_root, expected_uid,
        NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME, 0o444,
    )
    if observed is None:
        if allow_absent:
            return None
        raise ReleaseFailure("native_host_candidate_enforcement_missing")
    return observed[0], sha256_bytes(observed[1])


def native_host_candidate_replay_enforcement(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    """Read the earliest durable public candidate-admission fence.

    The pending projection is deliberately public and durable before any
    private or coordination state is created.  During replay, a final and a
    pending projection are valid together only when they are the same hard
    link; this makes a conflicting or independently substituted partial state
    fail closed instead of choosing one pathname as authority.
    """
    final = _read_native_host_candidate_floor_file(
        install_root, expected_uid,
        NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME, 0o444,
        allowed_link_counts=frozenset({1, 2}),
    )
    pending = _read_native_host_candidate_floor_file(
        install_root, expected_uid,
        NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME, 0o444,
        allowed_link_counts=frozenset({1, 2}),
    )
    if final is not None and pending is not None:
        if final[1] != pending[1] or final[2] != pending[2]:
            raise ReleaseFailure("native_host_candidate_enforcement_conflict")
    observed = final if final is not None else pending
    if observed is None:
        if allow_absent:
            return None
        raise ReleaseFailure("native_host_candidate_enforcement_missing")
    return observed[0], sha256_bytes(observed[1])


def native_host_candidate_floor_records(
    *, release_id: str, candidate_record: Mapping[str, object],
    establishment_mode: str, predecessor_release_id: str,
) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
    canonical_candidate = json.dumps(
        dict(candidate_record), allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    floor_record = validate_native_host_candidate_floor({
        "schema": NATIVE_HOST_CANDIDATE_FLOOR_SCHEMA,
        "establishment_mode": establishment_mode,
        "established_from_predecessor_release_id": predecessor_release_id,
        "established_from_release_id": release_id,
        "candidate_record_sha256": sha256_bytes(canonical_candidate),
        "required_feature": NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE,
        "required_payload_inventory_sha256":
            native_host_candidate_inventory_sha256(),
    })
    floor_raw = _native_host_candidate_floor_bytes(floor_record)
    enforcement_record = validate_native_host_candidate_enforcement({
        "schema": NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA,
        "required_feature": NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE,
        "required_payload_inventory_sha256":
            native_host_candidate_inventory_sha256(),
        "authoritative_floor_sha256": sha256_bytes(floor_raw),
    })
    enforcement_raw = _native_host_candidate_floor_bytes(
        enforcement_record
    )
    return floor_record, floor_raw, enforcement_record, enforcement_raw


def _installed_identity_record(
    information: os.stat_result, kind: str, *, digest: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ctime_ns": information.st_ctime_ns,
        "dev": information.st_dev,
        "gid": information.st_gid,
        "ino": information.st_ino,
        "kind": kind,
        "mode": stat.S_IMODE(information.st_mode),
        "mtime_ns": information.st_mtime_ns,
        "nlink": information.st_nlink,
        "size": information.st_size,
        "uid": information.st_uid,
    }
    if digest is not None:
        record["sha256"] = digest
    return record


def _validate_installed_identity_record(
    value: object, *, kind: str,
) -> dict[str, Any]:
    fields = {
        "ctime_ns", "dev", "gid", "ino", "kind", "mode", "mtime_ns",
        "nlink", "size", "uid",
    }
    if kind == "file":
        fields.add("sha256")
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("kind") != kind
            or any(
                not isinstance(value.get(name), int)
                or isinstance(value.get(name), bool) or value[name] < 0
                for name in fields - {"kind", "sha256"}
            )
            or (kind == "file"
                and SHA256.fullmatch(str(value.get("sha256"))) is None)):
        raise ReleaseFailure("native_host_release_tree_identity_invalid")
    return {name: value[name] for name in sorted(fields)}


def validate_native_host_release_tree_identity(
    value: object,
) -> dict[str, dict[str, Any]]:
    if (not isinstance(value, dict) or "." not in value
            or not 1 <= len(value) <= 8192):
        raise ReleaseFailure("native_host_release_tree_identity_invalid")
    result: dict[str, dict[str, Any]] = {}
    for relative, record in value.items():
        if (not isinstance(relative, str)
                or (relative != "." and (
                    not relative or relative.startswith("/")
                    or relative.endswith("/") or "//" in relative
                    or "\0" in relative
                    or any(part in {"", ".", ".."}
                           for part in relative.split("/"))
                ))):
            raise ReleaseFailure("native_host_release_tree_identity_invalid")
        kind = record.get("kind") if isinstance(record, dict) else None
        if kind not in {"directory", "file"}:
            raise ReleaseFailure("native_host_release_tree_identity_invalid")
        result[relative] = _validate_installed_identity_record(
            record, kind=kind,
        )
    if result["."]["kind"] != "directory":
        raise ReleaseFailure("native_host_release_tree_identity_invalid")
    return {name: result[name] for name in sorted(result)}


def native_host_release_tree_identity_sha256(
    value: Mapping[str, Mapping[str, Any]],
) -> str:
    canonical = validate_native_host_release_tree_identity(dict(value))
    return sha256_bytes(canonical_state_record(canonical))


RUNTIME_APP_DIRECTORY_CTIME_PATHS = frozenset({
    AUTHORIZATION_UI_APP_NAME,
    NATIVE_CREDENTIAL_HELPER_APP_NAME,
})


def comparable_native_host_release_tree_identity(
    value: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Normalize only LaunchServices-owned top-level app-directory ctime.

    macOS may attach ``com.apple.macl`` and ``com.apple.provenance`` to an app
    bundle the first time LaunchServices opens it.  That operation changes the
    bundle directory's ctime without changing its contents, permissions,
    inventory, or any descendant identity.  Keep the ctime tombstone for every
    payload file and every other directory; only these two exact top-level app
    containers are runtime-mutable OS metadata boundaries.
    """
    result = validate_native_host_release_tree_identity(dict(value))
    for relative in RUNTIME_APP_DIRECTORY_CTIME_PATHS:
        record = result.get(relative)
        if record is None or record["kind"] != "directory":
            raise ReleaseFailure(
                "native_host_release_tree_identity_inventory_invalid"
            )
        record = dict(record)
        record["ctime_ns"] = 0
        result[relative] = record
    return result


def installed_native_host_release_tree_identity(
    release: Path, expected_uid: int,
) -> tuple[dict[str, dict[str, Any]], str]:
    """Capture a closed, ACL-free identity/content projection of a release."""
    gpgv_raw = read_acl_free_regular(
        release / "gpgv", expected_uid, EXPECTED_MODES["gpgv"],
        "native_host_release_tree_identity_untrusted",
        maximum=64 * 1024 * 1024,
    )
    expected_root_entries = (
        set(PAYLOAD_NAMES)
        | {"manifest.json", AUTHORIZATION_UI_APP_NAME,
           NATIVE_CREDENTIAL_HELPER_APP_NAME}
    )
    if gpgv_runtime_files(gpgv_raw):
        expected_root_entries.add(GPGV_RUNTIME_DIRECTORY_NAME)
    entry_count = 0

    def snapshot_directory(
        path: Path, relative: str, expected_device: int | None,
    ) -> dict[str, dict[str, Any]]:
        nonlocal entry_count
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            opened = os.fstat(descriptor)
            reject_extended_acl(
                descriptor, "native_host_release_tree_identity_untrusted",
            )
            device = opened.st_dev if expected_device is None else expected_device
            if (not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or opened.st_uid != expected_uid
                    or opened.st_dev != device
                    or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or stat.S_IMODE(opened.st_mode) != 0o555):
                raise ReleaseFailure(
                    "native_host_release_tree_identity_untrusted"
                )
            names = sorted(os.listdir(descriptor))
            if (relative == "." and set(names) != expected_root_entries):
                raise ReleaseFailure(
                    "native_host_release_tree_identity_inventory_invalid"
                )
            records: dict[str, dict[str, Any]] = {}
            for name in names:
                if (not name or name in {".", ".."} or "/" in name
                        or "\0" in name):
                    raise ReleaseFailure(
                        "native_host_release_tree_identity_inventory_invalid"
                    )
                entry_count += 1
                if entry_count > 8191:
                    raise ReleaseFailure(
                        "native_host_release_tree_identity_inventory_invalid"
                    )
                child_relative = (
                    name if relative == "." else relative + "/" + name
                )
                named = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False,
                )
                child_path = path / name
                if stat.S_ISDIR(named.st_mode):
                    records.update(snapshot_directory(
                        child_path, child_relative, device,
                    ))
                    current = child_path.lstat()
                    if ((current.st_dev, current.st_ino)
                            != (named.st_dev, named.st_ino)):
                        raise ReleaseFailure(
                            "native_host_release_tree_identity_changed"
                        )
                elif stat.S_ISREG(named.st_mode):
                    child = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                    try:
                        child_opened = os.fstat(child)
                        reject_extended_acl(
                            child,
                            "native_host_release_tree_identity_untrusted",
                        )
                        digest = hashlib.sha256()
                        total = 0
                        while True:
                            block = os.read(child, 1024 * 1024)
                            if not block:
                                break
                            total += len(block)
                            if total > 1024 * 1024 * 1024:
                                raise ReleaseFailure(
                                    "native_host_release_tree_identity_oversize"
                                )
                            digest.update(block)
                        child_after = os.fstat(child)
                    finally:
                        os.close(child)
                    child_named = os.stat(
                        name, dir_fd=descriptor, follow_symlinks=False,
                    )
                    identity = lambda item: (
                        item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                        item.st_gid, item.st_nlink, item.st_size,
                        item.st_mtime_ns, item.st_ctime_ns,
                    )
                    if (child_opened.st_dev != device
                            or child_opened.st_uid != expected_uid
                            or child_opened.st_nlink != 1
                            or child_opened.st_mode
                                & (stat.S_IWGRP | stat.S_IWOTH)
                            or total != child_opened.st_size
                            or identity(named) != identity(child_opened)
                            or identity(child_opened) != identity(child_after)
                            or identity(child_after) != identity(child_named)):
                        raise ReleaseFailure(
                            "native_host_release_tree_identity_untrusted"
                        )
                    records[child_relative] = _installed_identity_record(
                        child_after, "file", digest=digest.hexdigest(),
                    )
                else:
                    raise ReleaseFailure(
                        "native_host_release_tree_identity_inventory_invalid"
                    )
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named_after = path.lstat()
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if (identity(before) != identity(opened)
                or identity(opened) != identity(after)
                or identity(after) != identity(named_after)):
            raise ReleaseFailure("native_host_release_tree_identity_changed")
        records[relative] = _installed_identity_record(after, "directory")
        return records

    result = validate_native_host_release_tree_identity(
        snapshot_directory(release, ".", None)
    )
    return result, native_host_release_tree_identity_sha256(result)


def native_host_candidate_authority_record(
    *, release_id: str, payloads: Mapping[str, str],
    candidate_record: Mapping[str, object], launcher_sha256: str,
    release_tree_identity: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    candidate_raw = json.dumps(
        dict(candidate_record), allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    )
    candidate = parse_native_host_candidate_json(candidate_raw)
    payload_map = dict(payloads)
    tree = validate_native_host_release_tree_identity(
        dict(release_tree_identity)
    )
    tree_sha256 = native_host_release_tree_identity_sha256(tree)
    if (candidate is None or SHA256.fullmatch(release_id) is None
            or SHA256.fullmatch(launcher_sha256) is None
            or set(payload_map) != PAYLOAD_NAMES
            or any(not isinstance(value, str)
                   or SHA256.fullmatch(value) is None
                   for value in payload_map.values())
            or release_identity(payload_map) != release_id):
        raise ReleaseFailure("native_host_candidate_authority_invalid")
    return {
        "candidate_record": candidate,
        "launcher_sha256": launcher_sha256,
        "payloads": {name: payload_map[name] for name in sorted(payload_map)},
        "release_id": release_id,
        "release_tree_identity": tree,
        "release_tree_identity_sha256": tree_sha256,
        "schema": NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA,
    }


def _validate_native_host_candidate_authority(value: object) -> dict[str, Any]:
    if (isinstance(value, dict)
            and value.get("schema") == NATIVE_HOST_CANDIDATE_AUTHORITY_SCHEMA):
        if (set(value) != {
                "schema", "release_id", "payloads", "candidate_record",
                "launcher_sha256",
        } or not isinstance(value.get("payloads"), dict)
                or not isinstance(value.get("candidate_record"), dict)):
            raise ReleaseFailure("native_host_candidate_authority_invalid")
        candidate_raw = json.dumps(
            value["candidate_record"], allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        )
        candidate = parse_native_host_candidate_json(candidate_raw)
        payloads = dict(value["payloads"])
        if (candidate is None
                or SHA256.fullmatch(str(value.get("release_id"))) is None
                or SHA256.fullmatch(str(value.get("launcher_sha256"))) is None
                or set(payloads) != PAYLOAD_NAMES
                or any(SHA256.fullmatch(str(item)) is None
                       for item in payloads.values())
                or release_identity(payloads) != value["release_id"]):
            raise ReleaseFailure("native_host_candidate_authority_invalid")
        return {
            "candidate_record": candidate,
            "launcher_sha256": value["launcher_sha256"],
            "payloads": {name: payloads[name] for name in sorted(payloads)},
            "release_id": value["release_id"],
            "schema": NATIVE_HOST_CANDIDATE_AUTHORITY_SCHEMA,
        }
    if (not isinstance(value, dict)
            or set(value) != {
                "schema", "release_id", "payloads", "candidate_record",
                "launcher_sha256", "release_tree_identity",
                "release_tree_identity_sha256",
            }
            or value.get("schema")
                != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA
            or not isinstance(value.get("payloads"), dict)
            or not isinstance(value.get("candidate_record"), dict)
            or not isinstance(value.get("release_tree_identity"), dict)):
        raise ReleaseFailure("native_host_candidate_authority_invalid")
    result = native_host_candidate_authority_record(
        release_id=value.get("release_id"),
        payloads=value["payloads"],
        candidate_record=value["candidate_record"],
        launcher_sha256=value.get("launcher_sha256"),
        release_tree_identity=value["release_tree_identity"],
    )
    if result["release_tree_identity_sha256"] != value.get(
        "release_tree_identity_sha256"
    ):
        raise ReleaseFailure("native_host_candidate_authority_invalid")
    return result


def _native_host_candidate_authority_bytes(value: object) -> bytes:
    try:
        return (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReleaseFailure("native_host_candidate_authority_invalid") from error


def native_host_candidate_authority(
    install_root: Path, release_id: str, expected_uid: int, *,
    public_only: bool = False,
) -> dict[str, Any]:
    if SHA256.fullmatch(release_id) is None:
        raise ReleaseFailure("native_host_candidate_authority_invalid")
    directory = install_root / NATIVE_HOST_CANDIDATE_AUTHORITY_DIRECTORY
    path = directory / f"{release_id}.json"
    directory_descriptor = -1
    descriptor = -1
    try:
        root = install_root.lstat()
        directory_before = directory.lstat()
        directory_descriptor = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        reject_extended_acl(
            directory_descriptor,
            "native_host_candidate_authority_parent_extended_acl",
        )
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        raise ReleaseFailure("native_host_candidate_authority_missing") from error
    try:
        opened = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "native_host_candidate_authority_extended_acl",
        )
        raw = os.read(descriptor, 1024 * 1024 + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
        os.close(directory_descriptor)
    directory_after = directory.lstat()
    named = path.lstat()
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
            or root.st_uid != expected_uid
            or stat.S_IMODE(root.st_mode) != 0o755
            or not stat.S_ISDIR(directory_before.st_mode)
            or stat.S_ISLNK(directory_before.st_mode)
            or directory_before.st_uid != expected_uid
            or directory_before.st_gid != root.st_gid
            or stat.S_IMODE(directory_before.st_mode) != 0o755
            or identity(directory_before) != identity(directory_after)
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or opened.st_uid != expected_uid
            or opened.st_gid != root.st_gid or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o444
            or not 2 <= opened.st_size <= 1024 * 1024
            or len(raw) != opened.st_size
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise ReleaseFailure("native_host_candidate_authority_untrusted")
    try:
        record = _validate_native_host_candidate_authority(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("native_host_candidate_authority_invalid") from error
    if raw != _native_host_candidate_authority_bytes(record):
        raise ReleaseFailure("native_host_candidate_authority_not_canonical")
    if (os.path.lexists(
            install_root / HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME)
            and record["schema"]
                != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA):
        raise ReleaseFailure("native_host_candidate_authority_below_pair_floor")
    if public_only:
        enforcement = native_host_candidate_replay_enforcement(
            install_root, expected_uid,
        )
        if (enforcement is None
                or enforcement[0]["required_feature"]
                    != NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
                or enforcement[0]["required_payload_inventory_sha256"]
                    != native_host_candidate_inventory_sha256()):
            raise ReleaseFailure(
                "native_host_candidate_authority_floor_mismatch")
        return record
    floor = native_host_candidate_floor(install_root, expected_uid)
    candidate_raw = json.dumps(
        record["candidate_record"], allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    if (floor is None
            or floor[0]["required_feature"]
                != NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
            or floor[0]["required_payload_inventory_sha256"]
                != native_host_candidate_inventory_sha256()
            or (floor[0]["established_from_release_id"] == release_id
                and floor[0]["candidate_record_sha256"]
                    != sha256_bytes(candidate_raw))):
        raise ReleaseFailure("native_host_candidate_authority_floor_mismatch")
    return record


def publish_native_host_candidate_authority(
    install_root: Path, expected_uid: int, *, release_id: str,
    payloads: Mapping[str, str], candidate_record: Mapping[str, object],
    launcher_sha256: str,
) -> dict[str, Any]:
    release = install_root / "releases" / release_id
    tree_before, tree_sha256 = installed_native_host_release_tree_identity(
        release, expected_uid,
    )
    tree_after, tree_after_sha256 = installed_native_host_release_tree_identity(
        release, expected_uid,
    )
    if tree_before != tree_after or tree_sha256 != tree_after_sha256:
        raise ReleaseFailure("native_host_release_tree_identity_changed")
    record = native_host_candidate_authority_record(
        release_id=release_id, payloads=payloads,
        candidate_record=candidate_record,
        launcher_sha256=launcher_sha256,
        release_tree_identity=tree_after,
    )
    raw = _native_host_candidate_authority_bytes(record)
    directory = install_root / NATIVE_HOST_CANDIDATE_AUTHORITY_DIRECTORY
    created_directory = False
    try:
        directory.mkdir(mode=0o755)
        created_directory = True
        fsync_directory(install_root)
    except FileExistsError:
        pass
    root_info = install_root.lstat()
    directory_named_before = directory.lstat()
    premetadata_directory = (
        stat.S_ISDIR(directory_named_before.st_mode)
        and not stat.S_ISLNK(directory_named_before.st_mode)
        and directory_named_before.st_uid == expected_uid
        and directory_named_before.st_dev == root_info.st_dev
        and stat.S_IMODE(directory_named_before.st_mode) != 0o755
        and stat.S_IMODE(directory_named_before.st_mode) & ~0o755 == 0
        and not directory_named_before.st_mode
            & (stat.S_IWGRP | stat.S_IWOTH)
    )
    if premetadata_directory:
        os.chmod(directory, 0o700, follow_symlinks=False)
        fsync_directory(install_root)
    directory_fd = os.open(
        directory,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    name = f"{release_id}.json"
    pending_name = f".{release_id}.pending"
    stage_name = pending_name + ".stage-" + sha256_bytes(raw)
    try:
        directory_info = os.fstat(directory_fd)
        reject_extended_acl(
            directory_fd,
            "native_host_candidate_authority_parent_extended_acl",
        )
        named_directory = directory.lstat()
        recover_created_directory = (
            (not created_directory or premetadata_directory)
            and stat.S_IMODE(directory_info.st_mode) == 0o700
            and os.listdir(directory_fd) == []
        )
        if (not stat.S_ISDIR(directory_info.st_mode)
                or stat.S_ISLNK(named_directory.st_mode)
                or (directory_info.st_dev, directory_info.st_ino)
                    != (named_directory.st_dev, named_directory.st_ino)
                or directory_info.st_uid != expected_uid
                or directory_info.st_dev != root_info.st_dev
                or stat.S_IMODE(directory_info.st_mode)
                    not in (
                        {stat.S_IMODE(directory_info.st_mode), 0o755}
                        if created_directory or recover_created_directory
                        else {0o755}
                    )):
            raise ReleaseFailure(
                "native_host_candidate_authority_parent_untrusted")
        if created_directory or recover_created_directory:
            os.fchown(directory_fd, expected_uid, root_info.st_gid)
            os.fchmod(directory_fd, 0o755)
            os.fsync(directory_fd)
            fsync_directory(install_root)
            directory_info = os.fstat(directory_fd)
        if (directory_info.st_gid != root_info.st_gid
                or stat.S_IMODE(directory_info.st_mode) != 0o755):
            raise ReleaseFailure(
                "native_host_candidate_authority_parent_untrusted")

        def read_at(
            item_name: str, allowed_links: frozenset[int], *,
            allowed_modes: frozenset[int] = frozenset({0o444}),
            allow_premetadata_gid: bool = False,
        ) -> tuple[os.stat_result, bytes] | None:
            try:
                before = os.stat(
                    item_name, dir_fd=directory_fd, follow_symlinks=False,
                )
                descriptor = os.open(
                    item_name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return None
            except OSError as error:
                raise ReleaseFailure(
                    "native_host_candidate_authority_conflict") from error
            try:
                opened = os.fstat(descriptor)
                reject_extended_acl(
                    descriptor,
                    "native_host_candidate_authority_extended_acl",
                )
                item_raw = os.read(descriptor, 1024 * 1024 + 1)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            named = os.stat(
                item_name, dir_fd=directory_fd, follow_symlinks=False,
            )
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                item.st_gid, item.st_nlink, item.st_size,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != expected_uid
                    or (not allow_premetadata_gid
                        and opened.st_gid != root_info.st_gid)
                    or opened.st_nlink not in allowed_links
                    or stat.S_IMODE(opened.st_mode) not in allowed_modes
                    or opened.st_size > 1024 * 1024
                    or len(item_raw) != opened.st_size
                    or identity(before) != identity(opened)
                    or identity(opened) != identity(after)
                    or identity(after) != identity(named)):
                raise ReleaseFailure(
                    "native_host_candidate_authority_conflict")
            return opened, item_raw

        def retain_staged(
            staged: tuple[os.stat_result, bytes],
        ) -> None:
            if not raw.startswith(staged[1]):
                raise ReleaseFailure(
                    "native_host_candidate_authority_conflict")
            retained_name = (
                stage_name + ".retained-" + sha256_bytes(staged[1])
            )
            if staged[0].st_nlink == 2:
                evidence = read_at(
                    retained_name, frozenset({2}),
                    allowed_modes=frozenset(
                        {0, 0o200, 0o400, 0o444, 0o600}),
                    allow_premetadata_gid=True,
                )
                if (evidence is None or evidence[1] != staged[1]
                        or (evidence[0].st_dev, evidence[0].st_ino)
                            != (staged[0].st_dev, staged[0].st_ino)):
                    raise ReleaseFailure(
                        "native_host_candidate_authority_conflict")
                os.unlink(stage_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                return
            if staged[0].st_nlink != 1:
                raise ReleaseFailure(
                    "native_host_candidate_authority_conflict")
            try:
                os.link(
                    stage_name, retained_name,
                    src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                os.fsync(directory_fd)
                native_host_candidate_authority_checkpoint(
                    "authority-partial-staging-retained")
            except FileExistsError:
                evidence = read_at(
                    retained_name, frozenset({1, 2}),
                    allowed_modes=frozenset(
                        {0, 0o200, 0o400, 0o444, 0o600}),
                    allow_premetadata_gid=True,
                )
                if evidence is None or evidence[1] != staged[1]:
                    raise ReleaseFailure(
                        "native_host_candidate_authority_conflict")
            os.unlink(stage_name, dir_fd=directory_fd)
            os.fsync(directory_fd)

        def reconcile_stage(
            pending: tuple[os.stat_result, bytes] | None,
            *, reuse_complete: bool = False,
        ) -> tuple[os.stat_result, bytes] | None:
            staged = read_at(
                stage_name, frozenset({1, 2}),
                allowed_modes=frozenset(
                    {0, 0o200, 0o400, 0o444, 0o600}),
                allow_premetadata_gid=True,
            )
            if staged is None:
                return None
            same_as_pending = (
                pending is not None
                and (pending[0].st_dev, pending[0].st_ino)
                    == (staged[0].st_dev, staged[0].st_ino)
            )
            if same_as_pending:
                os.unlink(stage_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                return None
            if (reuse_complete and staged[0].st_nlink == 1
                    and staged[1] == raw):
                if (staged[0].st_gid != root_info.st_gid
                        or stat.S_IMODE(staged[0].st_mode) != 0o444):
                    stage_fd = os.open(
                        stage_name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory_fd,
                    )
                    try:
                        os.fchown(
                            stage_fd, expected_uid, root_info.st_gid)
                        os.fchmod(stage_fd, 0o444)
                        os.fsync(stage_fd)
                    finally:
                        os.close(stage_fd)
                    staged = read_at(stage_name, frozenset({1}))
                    if staged is None or staged[1] != raw:
                        raise ReleaseFailure(
                            "native_host_candidate_authority_conflict")
                return staged
            retain_staged(staged)
            return None

        final = read_at(name, frozenset({1, 2}))
        pending = read_at(pending_name, frozenset({1, 2}))
        if (final is not None and final[1] != raw
                or pending is not None and pending[1] != raw
                or final is not None and pending is not None
                and (final[0].st_dev, final[0].st_ino)
                    != (pending[0].st_dev, pending[0].st_ino)):
            raise ReleaseFailure("native_host_candidate_authority_conflict")
        if final is not None:
            if pending is not None:
                os.unlink(pending_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                pending = None
            reconcile_stage(pending)
        else:
            if pending is None:
                staged = reconcile_stage(None, reuse_complete=True)
                if staged is None:
                    descriptor = os.open(
                        stage_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=directory_fd,
                    )
                    try:
                        native_host_candidate_authority_checkpoint(
                            "authority-staging-opened")
                        os.fchown(
                            descriptor, expected_uid, root_info.st_gid)
                        os.fchmod(descriptor, 0o600)
                        native_host_candidate_authority_checkpoint(
                            "authority-staging-created")
                        write_all(
                            descriptor, raw,
                            "native_host_candidate_authority",
                        )
                        os.fsync(descriptor)
                        os.fchmod(descriptor, 0o444)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    native_host_candidate_authority_checkpoint(
                        "authority-staging-fsynced")
                    staged = read_at(stage_name, frozenset({1}))
                if staged is None or staged[1] != raw:
                    raise ReleaseFailure(
                        "native_host_candidate_authority_conflict")
                os.link(
                    stage_name, pending_name,
                    src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                os.fsync(directory_fd)
                native_host_candidate_authority_checkpoint(
                    "authority-pending-linked")
                pending = read_at(pending_name, frozenset({2}))
                staged = read_at(stage_name, frozenset({2}))
                if (pending is None or staged is None
                        or pending[1] != raw or staged[1] != raw
                        or (pending[0].st_dev, pending[0].st_ino)
                            != (staged[0].st_dev, staged[0].st_ino)):
                    raise ReleaseFailure(
                        "native_host_candidate_authority_conflict")
                os.unlink(stage_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                native_host_candidate_authority_checkpoint(
                    "authority-pending-staged")
                pending = read_at(pending_name, frozenset({1}))
            else:
                reconcile_stage(pending)
                pending = read_at(pending_name, frozenset({1}))
            if pending is None or pending[1] != raw:
                raise ReleaseFailure(
                    "native_host_candidate_authority_conflict")
            native_host_candidate_authority_checkpoint(
                "before-authority-publication")
            descriptor = os.open(
                pending_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            try:
                if os.fstat(descriptor).st_nlink != 1:
                    raise ReleaseFailure(
                        "native_host_candidate_authority_conflict")
            finally:
                os.close(descriptor)
            os.link(
                pending_name, name,
                src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.fsync(directory_fd)
            native_host_candidate_authority_checkpoint(
                "authority-published")
            final = read_at(name, frozenset({2}))
            pending = read_at(pending_name, frozenset({2}))
            if (final is None or pending is None
                    or final[1] != raw or pending[1] != raw
                    or (final[0].st_dev, final[0].st_ino)
                        != (pending[0].st_dev, pending[0].st_ino)):
                raise ReleaseFailure(
                    "native_host_candidate_authority_conflict")
            os.unlink(pending_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            native_host_candidate_authority_checkpoint(
                "authority-pending-removed")
    finally:
        os.close(directory_fd)
    observed = native_host_candidate_authority(
        install_root, release_id, expected_uid,
    )
    if observed != record:
        raise ReleaseFailure("native_host_candidate_authority_readback_failed")
    return observed


def installed_native_host_candidate_binding(
    install_root: Path, release_id: str, expected_uid: int, *,
    public_only: bool = False,
) -> tuple[Path, Path, dict[str, object], dict[str, Any]]:
    authority = native_host_candidate_authority(
        install_root, release_id, expected_uid,
        public_only=public_only,
    )
    candidate = dict(authority["candidate_record"])
    generation = Path(str(candidate["generation_path"]))
    try:
        authority_repo = generation.parents[3]
    except IndexError as error:
        raise ReleaseFailure("native_host_candidate_authority_invalid") from error
    if authority["schema"] == NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA:
        release = install_root / "releases" / release_id
        tree, tree_sha256 = installed_native_host_release_tree_identity(
            release, expected_uid,
        )
        if (comparable_native_host_release_tree_identity(tree)
                != comparable_native_host_release_tree_identity(
                    authority["release_tree_identity"]
                )):
            raise ReleaseFailure(
                "native_host_candidate_authority_tree_mismatch"
            )
    elif os.path.lexists(
        install_root / HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
    ):
        raise ReleaseFailure("native_host_candidate_authority_below_pair_floor")
    if public_only:
        # The public verifier intentionally never traverses the operator's
        # private retained-candidate/preimage custody.  Root publication bound
        # this canonical 0444 authority to the private floor; read-only callers
        # compare it directly with immutable installed bytes instead.
        return authority_repo, generation, candidate, authority
    if native_host_candidate_record(authority_repo, generation) != candidate:
        raise ReleaseFailure("native_host_candidate_authority_stale")
    _values, hashes, observed_release_id = source_payload(
        authority_repo,
        native_host_generation=generation,
        expected_native_host_candidate=candidate,
    )
    if (observed_release_id != release_id
            or authority["release_id"] != release_id
            or authority["payloads"] != hashes):
        raise ReleaseFailure("native_host_candidate_authority_mismatch")
    return authority_repo, generation, candidate, authority


def native_host_candidate_authority_sha256(
    authority: Mapping[str, Any],
) -> str:
    validated = _validate_native_host_candidate_authority(dict(authority))
    return sha256_bytes(_native_host_candidate_authority_bytes(validated))


def host_release_launcher_pair_generation(
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    validated_authority = _validate_native_host_candidate_authority(
        dict(authority)
    )
    if (validated_authority["schema"]
            != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA):
        raise ReleaseFailure("host_release_launcher_pair_authority_invalid")
    return {
        "candidate_authority_sha256":
            native_host_candidate_authority_sha256(validated_authority),
        "launcher_sha256": validated_authority["launcher_sha256"],
        "release_id": validated_authority["release_id"],
        "release_tree_identity_sha256": validated_authority[
            "release_tree_identity_sha256"
        ],
    }


def validate_host_release_launcher_pair_generation(
    value: object,
) -> dict[str, Any]:
    fields = {
        "candidate_authority_sha256", "launcher_sha256", "release_id",
        "release_tree_identity_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or any(SHA256.fullmatch(str(value.get(name))) is None
                   for name in fields)):
        raise ReleaseFailure("host_release_launcher_pair_identity_invalid")
    return {name: value[name] for name in sorted(fields)}


def host_release_launcher_pair_identity(
    *, authority: Mapping[str, Any], launcher_identity: Mapping[str, Any],
) -> dict[str, Any]:
    generation = host_release_launcher_pair_generation(authority)
    launcher = _validate_installed_identity_record(
        dict(launcher_identity), kind="file",
    )
    if launcher["sha256"] != generation["launcher_sha256"]:
        raise ReleaseFailure("host_release_launcher_pair_launcher_invalid")
    return {**generation, "launcher_identity": launcher}


def validate_host_release_launcher_pair_identity(
    value: object,
) -> dict[str, Any]:
    if not isinstance(value, dict) or "launcher_identity" not in value:
        raise ReleaseFailure("host_release_launcher_pair_identity_invalid")
    generation = validate_host_release_launcher_pair_generation({
        name: item for name, item in value.items()
        if name != "launcher_identity"
    })
    launcher = _validate_installed_identity_record(
        value.get("launcher_identity"), kind="file",
    )
    if launcher["sha256"] != generation["launcher_sha256"]:
        raise ReleaseFailure("host_release_launcher_pair_identity_invalid")
    return {**generation, "launcher_identity": launcher}


def host_release_launcher_pair_stable_record(
    pair: Mapping[str, Any], *,
    committed_transition_id: str | None = None,
    committed_transition_sha256: str | None = None,
    committed_terminal_sha256: str | None = None,
) -> dict[str, Any]:
    identity = validate_host_release_launcher_pair_identity(dict(pair))
    committed = (
        committed_transition_id, committed_transition_sha256,
        committed_terminal_sha256,
    )
    if any(item is None for item in committed) != all(
        item is None for item in committed
    ):
        raise ReleaseFailure("host_release_launcher_pair_stable_invalid")
    if committed_transition_id is not None:
        _validated_uuid4(
            committed_transition_id, "host_release_pair_transition_id",
        )
        if SHA256.fullmatch(str(committed_transition_sha256)) is None:
            raise ReleaseFailure("host_release_launcher_pair_stable_invalid")
        if SHA256.fullmatch(str(committed_terminal_sha256)) is None:
            raise ReleaseFailure("host_release_launcher_pair_stable_invalid")
    return {
        "committed_terminal_sha256": committed_terminal_sha256,
        "committed_transition_id": committed_transition_id,
        "committed_transition_sha256": committed_transition_sha256,
        "pair": identity,
        "required_feature": HOST_RELEASE_LAUNCHER_PAIR_FEATURE,
        "schema": HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA,
    }


def host_release_launcher_pair_pending_record(
    *, operation: str, transition_id: str, transition_sha256: str,
    prior_stable_sha256: str | None,
    source_pair: Mapping[str, Any] | None,
    target_pair: Mapping[str, Any],
) -> dict[str, Any]:
    _validated_uuid4(transition_id, "host_release_pair_transition_id")
    if (operation not in {"install", "rollback"}
            or SHA256.fullmatch(transition_sha256) is None
            or (prior_stable_sha256 is not None
                and SHA256.fullmatch(prior_stable_sha256) is None)):
        raise ReleaseFailure("host_release_launcher_pair_pending_invalid")
    if source_pair is None:
        if prior_stable_sha256 is not None or operation != "install":
            raise ReleaseFailure("host_release_launcher_pair_pending_invalid")
        source = None
    else:
        if prior_stable_sha256 is None:
            raise ReleaseFailure("host_release_launcher_pair_pending_invalid")
        source = validate_host_release_launcher_pair_identity(
            dict(source_pair)
        )
    target = validate_host_release_launcher_pair_generation(dict(target_pair))
    if (source is not None
            and {name: source[name] for name in target} == target):
        raise ReleaseFailure("host_release_launcher_pair_pending_invalid")
    return {
        "operation": operation,
        "prior_stable_sha256": prior_stable_sha256,
        "required_feature": HOST_RELEASE_LAUNCHER_PAIR_FEATURE,
        "schema": HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
        "source_pair": source,
        "target_pair": target,
        "transition_id": transition_id,
        "transition_sha256": transition_sha256,
    }


def validate_host_release_launcher_pair_record(
    value: object,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseFailure("host_release_launcher_pair_invalid")
    if value.get("schema") == HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA:
        if set(value) != {
            "committed_terminal_sha256", "committed_transition_id",
            "committed_transition_sha256", "pair", "required_feature",
            "schema",
        } or value.get("required_feature") != HOST_RELEASE_LAUNCHER_PAIR_FEATURE:
            raise ReleaseFailure("host_release_launcher_pair_stable_invalid")
        return host_release_launcher_pair_stable_record(
            value.get("pair", {}),
            committed_transition_id=value.get("committed_transition_id"),
            committed_transition_sha256=value.get(
                "committed_transition_sha256"
            ),
            committed_terminal_sha256=value.get(
                "committed_terminal_sha256"
            ),
        )
    if value.get("schema") == HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA:
        if set(value) != {
            "operation", "prior_stable_sha256", "required_feature", "schema",
            "source_pair", "target_pair", "transition_id",
            "transition_sha256",
        } or value.get("required_feature") != HOST_RELEASE_LAUNCHER_PAIR_FEATURE:
            raise ReleaseFailure("host_release_launcher_pair_pending_invalid")
        return host_release_launcher_pair_pending_record(
            operation=value.get("operation"),
            transition_id=value.get("transition_id"),
            transition_sha256=value.get("transition_sha256"),
            prior_stable_sha256=value.get("prior_stable_sha256"),
            source_pair=value.get("source_pair", {}),
            target_pair=value.get("target_pair", {}),
        )
    raise ReleaseFailure("host_release_launcher_pair_invalid")


def host_release_launcher_pair_record_bytes(value: object) -> bytes:
    return canonical_state_record(
        validate_host_release_launcher_pair_record(value)
    )


def validate_public_host_pair_terminal(value: object) -> dict[str, Any]:
    fields = {
        "schema", "status", "operation", "transition_id",
        "transition_sha256", "committed_pair", "authorization_request_id",
        "authorization_request_sha256", "authorized_target_plan_sha256",
        "completed_at", "service_evidence", "service_evidence_sha256", "error",
        "authorization_receipt_sha256", "finalization_sha256",
        "terminal_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("host_pair_terminal_invalid")
    _validated_uuid4(value.get("transition_id"), "host_pair_transition_id")
    if (value.get("schema") != HOST_PAIR_TERMINAL_SCHEMA
            or value.get("status") not in {
                "target_committed", "source_restored",
            }
            or value.get("operation") not in {"install", "rollback"}
            or SHA256.fullmatch(str(value.get("transition_sha256"))) is None
            or SHA256.fullmatch(str(value.get(
                "authorized_target_plan_sha256"))) is None
            or SHA256.fullmatch(str(value.get(
                "service_evidence_sha256"))) is None
            or SHA256.fullmatch(str(value.get(
                "finalization_sha256"))) is None
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value.get("completed_at"), bool)
            or (value.get("error") is not None and (
                not isinstance(value["error"], str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value["error"])
                    is None
            ))
            or (value.get("authorization_receipt_sha256") is not None
                and SHA256.fullmatch(str(value[
                    "authorization_receipt_sha256"
                ])) is None)
            or host_pair_terminal_digest(value)
                != value.get("terminal_sha256")):
        raise ReleaseFailure("host_pair_terminal_invalid")
    committed = validate_host_release_launcher_pair_identity(
        value.get("committed_pair")
    )
    evidence = validate_host_pair_service_evidence(
        value.get("service_evidence"), value, committed,
    )
    if (sha256_bytes(canonical_state_record(evidence))
            != value["service_evidence_sha256"]):
        raise ReleaseFailure("host_pair_terminal_invalid")
    result = {name: value[name] for name in sorted(fields)}
    result["committed_pair"] = committed
    result["service_evidence"] = evidence
    return result


def verified_public_host_pair_terminal(
    install_root: Path, expected_uid: int, stable: Mapping[str, Any],
) -> tuple[dict[str, Any], str] | None:
    transition_id = stable.get("committed_transition_id")
    if transition_id is None:
        return None
    directory = install_root / INSTALL_TRANSITION_DIRECTORY_NAME
    verify_acl_free_directory(
        directory, expected_uid, 0o755,
        "host_pair_terminal_directory_untrusted",
    )
    raw = read_acl_free_regular(
        directory / f"{transition_id}.json", expected_uid, 0o444,
        "host_pair_terminal_untrusted", maximum=INSTALL_TRANSITION_RECORD_LIMIT,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("host_pair_terminal_invalid") from error
    terminal = validate_public_host_pair_terminal(value)
    if (raw != canonical_state_record(terminal)
            or sha256_bytes(raw) != stable.get(
                "committed_terminal_sha256"
            )
            or terminal["transition_id"] != transition_id
            or terminal["transition_sha256"]
                != stable.get("committed_transition_sha256")
            or terminal["committed_pair"] != stable.get("pair")):
        raise ReleaseFailure("host_pair_terminal_mismatch")
    return terminal, sha256_bytes(raw)


def host_release_launcher_pair_public(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], str] | None:
    path = install_root / HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
    if not os.path.lexists(path):
        if allow_absent:
            return None
        raise ReleaseFailure("host_release_launcher_pair_missing")
    descriptor = open_trusted_absolute_directory(
        install_root, expected_uid,
    )
    try:
        value, raw, _ = read_state_record_at(
            descriptor, HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME,
            expected_uid, 0o444,
        )
    finally:
        os.close(descriptor)
    record = validate_host_release_launcher_pair_record(value)
    if raw != host_release_launcher_pair_record_bytes(record):
        raise ReleaseFailure("host_release_launcher_pair_not_canonical")
    return record, sha256_bytes(raw)


def publish_host_release_launcher_pair_record(
    install_root: Path, expected_uid: int, record: Mapping[str, Any], *,
    expected_previous_sha256: str | None,
) -> tuple[dict[str, Any], str]:
    validated = validate_host_release_launcher_pair_record(dict(record))
    raw = host_release_launcher_pair_record_bytes(validated)
    descriptor = open_locked_install_root(install_root, expected_uid)
    try:
        public_path = install_root / HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
        if os.path.lexists(public_path):
            _previous, previous_raw, _ = read_state_record_at(
                descriptor, HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME,
                expected_uid, 0o444,
            )
            if (expected_previous_sha256 is None
                    or sha256_bytes(previous_raw)
                        != expected_previous_sha256):
                raise ReleaseFailure("host_release_launcher_pair_changed")
            replace_state_record_at(
                descriptor, HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME,
                validated, expected_uid, 0o444,
            )
        else:
            if expected_previous_sha256 is not None:
                raise ReleaseFailure("host_release_launcher_pair_changed")
            write_new_state_record_at(
                descriptor, HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME,
                validated, expected_uid, 0o444,
            )
        reread, reread_raw, _ = read_state_record_at(
            descriptor, HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME,
            expected_uid, 0o444,
        )
        if (validate_host_release_launcher_pair_record(reread) != validated
                or reread_raw != raw):
            raise ReleaseFailure("host_release_launcher_pair_readback_failed")
    finally:
        os.close(descriptor)
    return validated, sha256_bytes(raw)


def authorized_host_release_target_plan(
    *, release_id: str, payloads: Mapping[str, str],
    candidate_record: Mapping[str, object], target_launcher_sha256: str,
    source_stable_sha256: str | None,
) -> tuple[dict[str, Any], str]:
    candidate_raw = json.dumps(
        dict(candidate_record), allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    payload_map = dict(payloads)
    if (SHA256.fullmatch(release_id) is None
            or set(payload_map) != PAYLOAD_NAMES
            or release_identity(payload_map) != release_id
            or SHA256.fullmatch(target_launcher_sha256) is None
            or (source_stable_sha256 is not None
                and SHA256.fullmatch(source_stable_sha256) is None)
            or parse_native_host_candidate_json(
                candidate_raw.decode("ascii")
            ) is None):
        raise ReleaseFailure("host_release_target_plan_invalid")
    plan = {
        "candidate_record_sha256": sha256_bytes(candidate_raw),
        "payloads": {name: payload_map[name] for name in sorted(payload_map)},
        "release_id": release_id,
        "schema": "secure-sandbox-host-release-target-plan-v1",
        "source_stable_sha256": source_stable_sha256,
        "target_launcher_sha256": target_launcher_sha256,
    }
    return plan, sha256_bytes(canonical_state_record(plan))


def authorized_host_release_rollback_plan(
    *, source_stable_sha256: str, target_authority: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    authority = _validate_native_host_candidate_authority(
        dict(target_authority)
    )
    if (authority["schema"] != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA
            or SHA256.fullmatch(source_stable_sha256) is None):
        raise ReleaseFailure("host_release_rollback_plan_invalid")
    plan = {
        "operation": "rollback",
        "schema": "secure-sandbox-host-release-rollback-plan-v1",
        "source_stable_sha256": source_stable_sha256,
        "target_candidate_authority_sha256":
            native_host_candidate_authority_sha256(authority),
        "target_launcher_sha256": authority["launcher_sha256"],
        "target_release_id": authority["release_id"],
        "target_release_tree_identity_sha256": authority[
            "release_tree_identity_sha256"
        ],
    }
    return plan, sha256_bytes(canonical_state_record(plan))


def release_requires_host_pair_fence(
    release: Path, manifest: Mapping[str, Any], expected_uid: int,
) -> bool:
    """Derive the irreversible pair floor from the selected release bytes."""
    payloads = manifest.get("payloads")
    if (not isinstance(payloads, dict)
            or "native_stack_coordination_contract" not in payloads):
        return False
    raw = read_acl_free_regular(
        release / "native_stack_coordination_contract", expected_uid,
        EXPECTED_MODES["native_stack_coordination_contract"],
        "host_release_launcher_pair_contract_untrusted",
        maximum=1024 * 1024,
    )
    if sha256_bytes(raw) != payloads["native_stack_coordination_contract"]:
        raise ReleaseFailure("native_stack_coordination_contract_changed")
    contract = validate_native_stack_coordination_contract(raw)
    return HOST_RELEASE_LAUNCHER_PAIR_FEATURE in contract["features"]


def validate_host_pair_bootstrap_admission(value: object) -> dict[str, Any]:
    fields = {
        "schema", "establishment_mode", "established_from_release_id",
        "established_from_predecessor_release_id", "candidate_record_sha256",
        "native_host_candidate_floor_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != HOST_PAIR_BOOTSTRAP_ADMISSION_SCHEMA
            or value.get("establishment_mode") not in {
                NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE,
                NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE,
            }
            or SHA256.fullmatch(str(value.get(
                "established_from_release_id"))) is None
            or SHA256.fullmatch(str(value.get(
                "established_from_predecessor_release_id"))) is None
            or SHA256.fullmatch(str(value.get(
                "candidate_record_sha256"))) is None
            or SHA256.fullmatch(str(value.get(
                "native_host_candidate_floor_sha256"))) is None
            or (value["establishment_mode"]
                == NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                and value["established_from_predecessor_release_id"]
                    != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID)):
        raise ReleaseFailure("host_pair_bootstrap_admission_invalid")
    return {name: value[name] for name in sorted(fields)}


def validate_host_pair_bootstrap_admission_floor(
    install_root: Path, expected_uid: int, value: object, *,
    allow_selected_target: bool = False,
) -> dict[str, Any]:
    """Reprove the exact irreversible candidate floor on every replay."""
    admission = validate_host_pair_bootstrap_admission(value)
    current = selector_target(install_root / "current", "current")
    target = admission["established_from_release_id"]
    if (current is not None
            and (not allow_selected_target
                 or current != f"releases/{target}")):
        raise ReleaseFailure("host_pair_bootstrap_current_present")
    floor = native_host_candidate_floor(
        install_root, expected_uid, allow_absent=False,
    )
    if floor is None:
        raise ReleaseFailure("native_host_candidate_floor_missing")
    record, floor_sha256 = floor
    expected = {
        "candidate_record_sha256": record["candidate_record_sha256"],
        "established_from_predecessor_release_id": record[
            "established_from_predecessor_release_id"
        ],
        "established_from_release_id": record[
            "established_from_release_id"
        ],
        "establishment_mode": record["establishment_mode"],
        "native_host_candidate_floor_sha256": floor_sha256,
        "schema": HOST_PAIR_BOOTSTRAP_ADMISSION_SCHEMA,
    }
    if admission != expected:
        raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
    return admission


def validate_host_pair_bootstrap_mode(
    install_root: Path, expected_uid: int, *, mode: str | None,
    release_id: str, candidate_record: Mapping[str, object],
    allow_selected_target: bool = False,
) -> dict[str, Any]:
    """Admit pair creation only for one already-proven typed migration."""
    if mode not in {
        NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE,
        NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE,
    }:
        raise ReleaseFailure("host_release_launcher_pair_missing")
    current = selector_target(install_root / "current", "current")
    if (current is not None
            and (not allow_selected_target
                 or current != f"releases/{release_id}")):
        raise ReleaseFailure("host_pair_bootstrap_current_present")
    floor = native_host_candidate_floor(
        install_root, expected_uid, allow_absent=False,
    )
    if floor is None:
        raise ReleaseFailure("native_host_candidate_floor_missing")
    record, floor_sha256 = floor
    candidate_raw = json.dumps(
        dict(candidate_record), allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    if (record["establishment_mode"] != mode
            or record["established_from_release_id"] != release_id
            or record["candidate_record_sha256"]
                != sha256_bytes(candidate_raw)):
        raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
    predecessor = record["established_from_predecessor_release_id"]
    if mode == NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE:
        if predecessor != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID:
            raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
    else:
        selector = selector_target(
            install_root / AUTHORIZATION_COORDINATION_PREDECESSOR_NAME,
            AUTHORIZATION_COORDINATION_PREDECESSOR_NAME,
        )
        if (not allow_selected_target
                and selector != f"releases/{predecessor}"):
            raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
    return validate_host_pair_bootstrap_admission({
        "candidate_record_sha256": record["candidate_record_sha256"],
        "established_from_predecessor_release_id": predecessor,
        "established_from_release_id": record[
            "established_from_release_id"
        ],
        "establishment_mode": record["establishment_mode"],
        "native_host_candidate_floor_sha256": floor_sha256,
        "schema": HOST_PAIR_BOOTSTRAP_ADMISSION_SCHEMA,
    })


def recover_named_host_pair_bootstrap(
    install_root: Path, launcher_path: Path, expected_uid: int, *,
    mode: str, release_id: str,
    candidate_record: Mapping[str, object],
) -> bool:
    """Replay only the exact receipt-free transition of a named bootstrap."""
    outstanding = read_pending_host_pair_transition(
        install_root, expected_uid, allow_absent=True,
    )
    if outstanding is None:
        return False
    transition, root = outstanding
    os.close(root)
    if (not transition["bootstrap"]
            or transition["operation"] != "install"
            or transition["target_pair"]["release_id"] != release_id):
        raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
    admission = validate_host_pair_bootstrap_mode(
        install_root, expected_uid, mode=mode, release_id=release_id,
        candidate_record=candidate_record, allow_selected_target=True,
    )
    if transition["bootstrap_admission"] != admission:
        raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
    execute_host_pair_transition(
        install_root, launcher_path, expected_uid, transition,
        raise_after_source_restore=False,
    )
    return True


def verified_host_release_launcher_pair(
    install_root: Path, launcher_path: Path, expected_uid: int, *,
    public_only: bool = False,
) -> tuple[dict[str, Any], str, Path, dict[str, Any], dict[str, Any]]:
    observed = host_release_launcher_pair_public(
        install_root, expected_uid,
    )
    if observed is None:
        raise ReleaseFailure("host_release_launcher_pair_missing")
    stable, stable_sha256 = observed
    if stable["schema"] != HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA:
        raise ReleaseFailure("host_release_launcher_pair_transition_active")
    verified_public_host_pair_terminal(
        install_root, expected_uid, stable,
    )
    pair = stable["pair"]
    current = install_root / "current"
    release, manifest = verified_release(
        install_root, current, expected_uid,
        _public_enforcement_only=public_only,
        _skip_pair_validation=True,
    )
    if release.name != pair["release_id"]:
        raise ReleaseFailure("host_release_launcher_pair_selector_mismatch")
    contract = validate_native_stack_coordination_contract(
        read_acl_free_regular(
            release / "native_stack_coordination_contract",
            expected_uid, EXPECTED_MODES["native_stack_coordination_contract"],
            "host_release_launcher_pair_contract_untrusted",
            maximum=1024 * 1024,
        )
    )
    if HOST_RELEASE_LAUNCHER_PAIR_FEATURE not in contract["features"]:
        raise ReleaseFailure("host_release_launcher_pair_feature_missing")
    authority = native_host_candidate_authority(
        install_root, release.name, expected_uid, public_only=public_only,
    )
    if (authority["schema"] != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA
            or native_host_candidate_authority_sha256(authority)
                != pair["candidate_authority_sha256"]
            or authority["release_tree_identity_sha256"]
                != pair["release_tree_identity_sha256"]
            or authority["payloads"] != manifest["payloads"]):
        raise ReleaseFailure("host_release_launcher_pair_authority_mismatch")
    tree, tree_sha256 = installed_native_host_release_tree_identity(
        release, expected_uid,
    )
    if (comparable_native_host_release_tree_identity(tree)
            != comparable_native_host_release_tree_identity(
                authority["release_tree_identity"]
            )):
        raise ReleaseFailure("host_release_launcher_pair_tree_mismatch")
    launcher, launcher_identity = read_trusted_stable_launcher_identity(
        launcher_path, expected_uid,
    )
    if (sha256_bytes(launcher) != pair["launcher_sha256"]
            or launcher_identity != pair["launcher_identity"]):
        raise ReleaseFailure("host_release_launcher_pair_launcher_mismatch")
    closing = host_release_launcher_pair_public(install_root, expected_uid)
    if (closing is None or closing != (stable, stable_sha256)
            or selector_target(install_root / "current", "current")
                != f"releases/{pair['release_id']}"):
        raise ReleaseFailure("host_release_launcher_pair_changed")
    return stable, stable_sha256, release, manifest, authority


def establish_native_host_candidate_floor(
    install_root: Path, expected_uid: int, *, release_id: str,
    candidate_record: Mapping[str, object], establishment_mode: str,
    predecessor_release_id: str, _public_only: bool = False,
) -> tuple[dict[str, Any], str]:
    if not _public_only:
        signing_floor = developer_id_team_floor(
            install_root, expected_uid,
        )
        if signing_floor is None:
            raise ReleaseFailure("developer_id_team_floor_missing")
        establish_developer_id_team_enforcement(
            install_root, expected_uid, signing_floor[0], signing_floor[1],
        )
    floor_record, floor_raw, _enforcement_record, enforcement_raw = (
        native_host_candidate_floor_records(
            release_id=release_id, candidate_record=candidate_record,
            establishment_mode=establishment_mode,
            predecessor_release_id=predecessor_release_id,
        )
    )
    root_fd = os.open(
        install_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        root = os.fstat(root_fd)
        reject_extended_acl(
            root_fd, "native_host_candidate_floor_parent_extended_acl",
        )
        named_root = install_root.lstat()
        if (not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(named_root.st_mode)
                or (root.st_dev, root.st_ino)
                    != (named_root.st_dev, named_root.st_ino)
                or root.st_uid != expected_uid
                or stat.S_IMODE(root.st_mode) != 0o755):
            raise ReleaseFailure("native_host_candidate_floor_parent_untrusted")

        def read_at(
            name: str, mode: int, *, staging: bool = False,
        ) -> tuple[os.stat_result, bytes] | None:
            try:
                before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_fd,
                )
            except FileNotFoundError:
                return None
            except OSError as error:
                raise ReleaseFailure("native_host_candidate_floor_conflict") from error
            try:
                opened = os.fstat(descriptor)
                reject_extended_acl(
                    descriptor, "native_host_candidate_floor_extended_acl",
                )
                raw = os.read(descriptor, 4097)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                item.st_gid, item.st_nlink, item.st_size,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != expected_uid
                    or (not staging and opened.st_gid != root.st_gid)
                    or opened.st_nlink not in {1, 2}
                    or stat.S_IMODE(opened.st_mode)
                        not in (
                            {0, 0o200, 0o400, 0o600, mode}
                            if staging else {mode}
                        )
                    or len(raw) != opened.st_size or len(raw) > 4096
                    or identity(before) != identity(opened)
                    or identity(opened) != identity(after)):
                raise ReleaseFailure("native_host_candidate_floor_conflict")
            return opened, raw

        def ensure_pending(
            name: str, raw: bytes, mode: int, transition: str,
        ) -> None:
            stage = name + ".stage-" + sha256_bytes(raw)

            def retain_staged(
                staged: tuple[os.stat_result, bytes],
            ) -> None:
                if not raw.startswith(staged[1]):
                    raise ReleaseFailure(
                        "native_host_candidate_floor_conflict")
                retained = (
                    stage + ".retained-" + sha256_bytes(staged[1])
                )
                if staged[0].st_nlink == 2:
                    evidence = read_at(retained, mode, staging=True)
                    if (evidence is None or evidence[1] != staged[1]
                            or (evidence[0].st_dev, evidence[0].st_ino)
                                != (staged[0].st_dev, staged[0].st_ino)):
                        raise ReleaseFailure(
                            "native_host_candidate_floor_conflict")
                    os.unlink(stage, dir_fd=root_fd)
                    os.fsync(root_fd)
                    return
                if staged[0].st_nlink != 1:
                    raise ReleaseFailure(
                        "native_host_candidate_floor_conflict")
                try:
                    os.link(
                        stage, retained,
                        src_dir_fd=root_fd, dst_dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                    os.fsync(root_fd)
                    native_host_candidate_bootstrap_checkpoint(
                        transition + "-partial-staging-retained"
                    )
                except FileExistsError:
                    evidence = read_at(retained, mode, staging=True)
                    if evidence is None or evidence[1] != staged[1]:
                        raise ReleaseFailure(
                            "native_host_candidate_floor_conflict")
                os.unlink(stage, dir_fd=root_fd)
                os.fsync(root_fd)

            observed = read_at(name, mode)
            if observed is not None:
                if observed[1] != raw:
                    raise ReleaseFailure("native_host_candidate_floor_conflict")
                staged = read_at(stage, mode, staging=True)
                if staged is not None:
                    same_inode = (
                        (observed[0].st_dev, observed[0].st_ino)
                        == (staged[0].st_dev, staged[0].st_ino)
                    )
                    if (not same_inode and (
                            staged[0].st_nlink != 1
                            or not raw.startswith(staged[1]))):
                        raise ReleaseFailure(
                            "native_host_candidate_floor_conflict")
                    if same_inode:
                        os.unlink(stage, dir_fd=root_fd)
                        os.fsync(root_fd)
                    else:
                        retain_staged(staged)
                observed = read_at(name, mode)
                if (observed is None or observed[1] != raw
                        or observed[0].st_nlink != 1):
                    raise ReleaseFailure(
                        "native_host_candidate_floor_conflict")
                return
            staged = read_at(stage, mode, staging=True)
            if staged is not None:
                if staged[1] != raw:
                    retain_staged(staged)
                    staged = None
                elif (staged[0].st_gid != root.st_gid
                        or stat.S_IMODE(staged[0].st_mode) != mode):
                    stage_fd = os.open(
                        stage,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=root_fd,
                    )
                    try:
                        os.fchown(stage_fd, expected_uid, root.st_gid)
                        os.fchmod(stage_fd, mode)
                        os.fsync(stage_fd)
                    finally:
                        os.close(stage_fd)
                    staged = read_at(stage, mode)
            if staged is None:
                descriptor = os.open(
                    stage,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600, dir_fd=root_fd,
                )
                try:
                    native_host_candidate_bootstrap_checkpoint(
                        transition + "-staging-opened"
                    )
                    os.fchown(descriptor, expected_uid, root.st_gid)
                    os.fchmod(descriptor, 0o600)
                    native_host_candidate_bootstrap_checkpoint(
                        transition + "-staging-created"
                    )
                    write_all(
                        descriptor, raw, "native_host_candidate_floor")
                    os.fsync(descriptor)
                    os.fchmod(descriptor, mode)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                native_host_candidate_bootstrap_checkpoint(
                    transition + "-staging-fsynced"
                )
            staged = read_at(stage, mode)
            if (staged is None or staged[1] != raw
                    or staged[0].st_nlink != 1):
                raise ReleaseFailure("native_host_candidate_floor_conflict")
            try:
                os.link(
                    stage, name, src_dir_fd=root_fd, dst_dir_fd=root_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                observed = read_at(name, mode)
                if observed is None or observed[1] != raw:
                    raise ReleaseFailure(
                        "native_host_candidate_floor_conflict")
            os.fsync(root_fd)
            native_host_candidate_bootstrap_checkpoint(
                transition + "-pending-linked"
            )
            observed = read_at(name, mode)
            staged = read_at(stage, mode)
            if (observed is None or staged is None
                    or observed[1] != raw or staged[1] != raw
                    or (observed[0].st_dev, observed[0].st_ino)
                        != (staged[0].st_dev, staged[0].st_ino)):
                raise ReleaseFailure("native_host_candidate_floor_conflict")
            os.unlink(stage, dir_fd=root_fd)
            os.fsync(root_fd)
            native_host_candidate_bootstrap_checkpoint(
                transition + "-pending-staged"
            )

        def publish(pending: str, final: str, mode: int) -> None:
            source = read_at(pending, mode)
            if source is None:
                raise ReleaseFailure("native_host_candidate_floor_conflict")
            target = read_at(final, mode)
            if target is None:
                os.link(
                    pending, final, src_dir_fd=root_fd, dst_dir_fd=root_fd,
                    follow_symlinks=False,
                )
                os.fsync(root_fd)
                target = read_at(final, mode)
            if (target is None
                    or (source[0].st_dev, source[0].st_ino)
                        != (target[0].st_dev, target[0].st_ino)):
                raise ReleaseFailure("native_host_candidate_floor_conflict")

        floor_final = read_at(NATIVE_HOST_CANDIDATE_FLOOR_NAME, 0o600)
        floor_pending = read_at(
            NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME, 0o600,
        )
        enforcement_final = read_at(
            NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME, 0o444,
        )
        enforcement_pending = read_at(
            NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME, 0o444,
        )
        if (floor_final is not None and floor_final[1] != floor_raw
                or floor_pending is not None
                and floor_pending[1] != floor_raw
                or enforcement_final is not None
                and enforcement_final[1] != enforcement_raw
                or enforcement_pending is not None
                and enforcement_pending[1] != enforcement_raw
                or floor_final is not None and enforcement_final is None):
            raise ReleaseFailure("native_host_candidate_floor_conflict")
        if (enforcement_final is not None
                and enforcement_pending is not None
                and (enforcement_final[0].st_dev,
                     enforcement_final[0].st_ino)
                    != (enforcement_pending[0].st_dev,
                        enforcement_pending[0].st_ino)):
            raise ReleaseFailure("native_host_candidate_floor_conflict")
        if (floor_final is not None and floor_pending is not None
                and (floor_final[0].st_dev, floor_final[0].st_ino)
                    != (floor_pending[0].st_dev, floor_pending[0].st_ino)):
            raise ReleaseFailure("native_host_candidate_floor_conflict")
        if enforcement_final is None:
            ensure_pending(
                NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME,
                enforcement_raw, 0o444, "candidate-enforcement",
            )
            native_host_candidate_bootstrap_checkpoint(
                "candidate-enforcement-pending-created"
            )
        if floor_final is None and not _public_only:
            ensure_pending(
                NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME, floor_raw, 0o600,
                "candidate-private-floor",
            )
            native_host_candidate_bootstrap_checkpoint(
                "candidate-private-floor-pending-created"
            )
        if enforcement_final is None:
            native_host_candidate_bootstrap_checkpoint(
                "before-candidate-enforcement-publication"
            )
            publish(
                NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME,
                NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME, 0o444,
            )
            native_host_candidate_bootstrap_checkpoint(
                "candidate-enforcement-published"
            )
        if floor_final is None and not _public_only:
            publish(
                NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME,
                NATIVE_HOST_CANDIDATE_FLOOR_NAME, 0o600,
            )
            native_host_candidate_bootstrap_checkpoint(
                "candidate-private-floor-published"
            )
        for pending, final, mode in (
            (NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME,
             NATIVE_HOST_CANDIDATE_FLOOR_NAME, 0o600),
            (NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME,
             NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME, 0o444),
        ):
            source = read_at(pending, mode)
            if source is None:
                continue
            target = read_at(final, mode)
            if (target is None
                    or (source[0].st_dev, source[0].st_ino)
                        != (target[0].st_dev, target[0].st_ino)):
                raise ReleaseFailure("native_host_candidate_floor_conflict")
            os.unlink(pending, dir_fd=root_fd)
            os.fsync(root_fd)
    finally:
        os.close(root_fd)
    if _public_only:
        enforcement = native_host_candidate_enforcement(
            install_root, expected_uid,
        )
        if enforcement is None or enforcement[0] != _enforcement_record:
            raise ReleaseFailure(
                "native_host_candidate_enforcement_readback_failed")
        return floor_record, sha256_bytes(floor_raw)
    observed = native_host_candidate_floor(install_root, expected_uid)
    if observed is None or observed[0] != floor_record:
        raise ReleaseFailure("native_host_candidate_floor_readback_failed")
    return observed


def enforce_native_host_candidate_floor(
    contract_raw: bytes, payload_names: set[str],
    install_root: Path, expected_uid: int,
) -> None:
    contract = validate_native_stack_coordination_contract(contract_raw)
    observed = native_host_candidate_floor(
        install_root, expected_uid, allow_absent=True,
    )
    has_feature = (
        NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE in contract["features"]
    )
    if observed is None:
        if has_feature:
            raise ReleaseFailure("native_host_candidate_floor_missing")
        return
    if (not has_feature or payload_names != PAYLOAD_NAMES
            or observed[0]["required_payload_inventory_sha256"]
                != native_host_candidate_inventory_sha256()):
        raise ReleaseFailure("release_below_native_host_candidate_floor")


def ensure_developer_id_migration_coordination_floor(
    install_root: Path, expected_uid: int, *, release_id: str,
    contract_raw: bytes,
) -> tuple[tuple[dict[str, Any], str], bool]:
    """Establish an absent/partial floor or enforce an existing floor.

    An enforcement-first publication is the sole supported partial state.  It
    can be completed only by replaying the identical floor record; the
    descriptor-relative publisher rejects a changed release or contract.  A
    complete floor is permanent authority, so later reviewed retry material is
    admitted by the ordinary monotonic contract check instead of attempting to
    rewrite its audit origin.
    """
    try:
        observed = native_stack_coordination_floor(
            install_root, expected_uid, allow_absent=True,
        )
    except ReleaseFailure as error:
        # The descriptor-relative publisher is also the canonical reconciler
        # for its supported hard-link publication windows.  It accepts only
        # exact pending/final bytes and inode relationships, and rejects every
        # malformed or conflicting state.
        if error.args not in {
            ("native_stack_coordination_floor_incomplete",),
            ("native_stack_coordination_floor_untrusted",),
            ("native_stack_coordination_enforcement_untrusted",),
        }:
            raise
        return (
            establish_native_stack_coordination_floor(
                install_root, expected_uid, release_id=release_id,
                contract_raw=contract_raw,
            ),
            True,
        )
    if observed is None:
        return (
            establish_native_stack_coordination_floor(
                install_root, expected_uid, release_id=release_id,
                contract_raw=contract_raw,
            ),
            True,
        )
    enforce_native_stack_coordination_floor(
        contract_raw, install_root, expected_uid,
    )
    return observed, False


def native_stack_support_archive(
    repo: Path, *, source_files: Mapping[str, bytes] | None = None,
) -> bytes:
    """Build the deterministic immutable Python closure for native actions."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for archive_name, relative in sorted(NATIVE_STACK_SUPPORT_SOURCES.items()):
            data = (
                source_files.get(relative.as_posix())
                if source_files is not None else read_regular(repo / relative)
            )
            if not isinstance(data, bytes):
                raise ReleaseFailure("native_stack_support_source_missing")
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
                archive.read(name) != (
                    source_files.get(NATIVE_STACK_SUPPORT_SOURCES[name].as_posix())
                    if source_files is not None else
                    read_regular(repo / NATIVE_STACK_SUPPORT_SOURCES[name])
                )
                for name in archive.namelist()
            ):
                raise ReleaseFailure("native_stack_support_content_invalid")
    except zipfile.BadZipFile as error:
        raise ReleaseFailure("native_stack_support_archive_invalid") from error
    return value


NATIVE_DEPLOYMENT_CONTAINER_ROLES = {
    "gateway.zip": "gateway",
    "research.zip": "research",
    "research-fence-acquire.zip": "research-fence-acquire",
    "research-fence-release.zip": "research-fence-release",
    "research-fence-recovery-acquire.zip": (
        "research-fence-recovery-acquire"
    ),
}
NATIVE_DEPLOYMENT_CONTAINER_MEMBERS = set(
    NATIVE_DEPLOYMENT_CONTAINER_ROLES
)
NATIVE_DEPLOYMENT_CONTAINER_LIMIT = 256 * 1024 * 1024


def _native_deployment_literal(
    node: ast.AST, bindings: Mapping[str, object],
) -> object:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return node.value
    if isinstance(node, ast.Name) and node.id in bindings:
        return bindings[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        values: list[object] = []
        for item in node.elts:
            if isinstance(item, ast.Starred):
                expanded = _native_deployment_literal(item.value, bindings)
                if not isinstance(expanded, (tuple, list)):
                    raise ReleaseFailure(
                        "native_deployment_payload_inventory_invalid"
                    )
                values.extend(expanded)
            else:
                values.append(_native_deployment_literal(item, bindings))
        return tuple(values)
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            raise ReleaseFailure(
                "native_deployment_payload_inventory_invalid"
            )
        return {
            _native_deployment_literal(key, bindings):
            _native_deployment_literal(value, bindings)
            for key, value in zip(node.keys, node.values)
        }
    raise ReleaseFailure("native_deployment_payload_inventory_invalid")


def native_deployment_payload_inventories(
    repo: Path, *, source: bytes | None = None,
) -> dict[str, tuple[tuple[str, str, int], ...]]:
    """Parse only closed literal inventories; never execute candidate code."""
    source_path = repo / "scripts/native_deployment_payload.py"
    source = (
        read_native_deployment_source(source_path)
        if source is None else source
    )
    if not 1024 <= len(source) <= 1024 * 1024:
        raise ReleaseFailure(
            "native_deployment_payload_inventory_invalid"
        )
    try:
        tree = ast.parse(source, filename=str(source_path))
    except (SyntaxError, ValueError) as error:
        raise ReleaseFailure(
            "native_deployment_payload_inventory_invalid"
        ) from error
    wanted = {
        "GATEWAY_SOURCES", "RESEARCH_SOURCES",
        "RESEARCH_FENCE_COMMON_SOURCES",
        "RESEARCH_FENCE_ACQUIRE_SOURCES",
        "RESEARCH_FENCE_RELEASE_SOURCES",
        "RESEARCH_FENCE_RECOVERY_ACQUIRE_SOURCES",
        "CONTAINER_MEMBERS",
    }
    bindings: dict[str, object] = {}
    for statement in tree.body:
        if (not isinstance(statement, ast.Assign)
                or len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or statement.targets[0].id not in wanted):
            continue
        name = statement.targets[0].id
        if name in bindings:
            raise ReleaseFailure(
                "native_deployment_payload_inventory_invalid"
            )
        bindings[name] = _native_deployment_literal(
            statement.value, bindings,
        )
    if set(bindings) != wanted or bindings["CONTAINER_MEMBERS"] != (
        NATIVE_DEPLOYMENT_CONTAINER_ROLES
    ):
        raise ReleaseFailure("native_deployment_payload_inventory_invalid")
    assignments = {
        "gateway": "GATEWAY_SOURCES",
        "research": "RESEARCH_SOURCES",
        "research-fence-acquire": "RESEARCH_FENCE_ACQUIRE_SOURCES",
        "research-fence-release": "RESEARCH_FENCE_RELEASE_SOURCES",
        "research-fence-recovery-acquire": (
            "RESEARCH_FENCE_RECOVERY_ACQUIRE_SOURCES"
        ),
    }
    result: dict[str, tuple[tuple[str, str, int], ...]] = {}
    safe_name = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    safe_path_part = re.compile(r"[A-Za-z0-9_.-]{1,128}")
    for role, assignment in assignments.items():
        raw = bindings[assignment]
        if not isinstance(raw, tuple) or not 1 <= len(raw) <= 256:
            raise ReleaseFailure(
                "native_deployment_payload_inventory_invalid"
            )
        inventory: list[tuple[str, str, int]] = []
        for record in raw:
            if (not isinstance(record, tuple) or len(record) != 3):
                raise ReleaseFailure(
                    "native_deployment_payload_inventory_invalid"
                )
            name, relative, mode = record
            relative_path = Path(relative) if isinstance(relative, str) else None
            if (not isinstance(name, str) or safe_name.fullmatch(name) is None
                    or relative_path is None or relative_path.is_absolute()
                    or ".." in relative_path.parts
                    or not relative_path.parts
                    or any(
                        safe_path_part.fullmatch(part) is None
                        for part in relative_path.parts
                    )
                    or not isinstance(mode, int) or isinstance(mode, bool)
                    or mode not in {0o600, 0o700}):
                raise ReleaseFailure(
                    "native_deployment_payload_inventory_invalid"
                )
            inventory.append((name, relative, mode))
        if (len({item[0] for item in inventory}) != len(inventory)
                or len({item[1] for item in inventory}) != len(inventory)):
            raise ReleaseFailure(
                "native_deployment_payload_inventory_invalid"
            )
        result[role] = tuple(sorted(inventory))
    return result


def read_native_deployment_source(path: Path) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure(
            "native_deployment_payload_build_failed"
        ) from error
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= 16 * 1024 * 1024:
            block = os.read(
                descriptor,
                min(1024 * 1024, 16 * 1024 * 1024 + 1 - len(data)),
            )
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size,
        item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_nlink != 1 or opened.st_mode & 0o022
            or not 1 <= opened.st_size <= 16 * 1024 * 1024
            or len(data) != opened.st_size
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)):
        raise ReleaseFailure("native_deployment_payload_build_failed")
    return bytes(data)


def _native_deployment_base_archive(
    repo: Path, inventory: tuple[tuple[str, str, int], ...],
    source_cache: dict[str, bytes],
    support_sources: Mapping[str, bytes],
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, relative, mode in inventory:
            data = source_cache.get(relative)
            if data is None:
                data = read_native_deployment_source(repo / relative)
                source_cache[relative] = data
            if (relative in support_sources
                    and data != support_sources[relative]):
                raise ReleaseFailure(
                    "native_deployment_payload_source_changed"
                )
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.compress_type = zipfile.ZIP_STORED
            item.external_attr = ((stat.S_IFREG | mode) & 0xFFFF) << 16
            archive.writestr(item, data)
    value = output.getvalue()
    if not 1 <= len(value) <= 64 * 1024 * 1024:
        raise ReleaseFailure("native_deployment_payload_build_failed")
    return value


def native_deployment_payload_container(
    repo: Path, *, support_archive: bytes | None = None,
    source_files: Mapping[str, bytes] | None = None,
) -> bytes:
    """Build guest bases with trusted code and closed literal inventories."""
    inventory_source: bytes | None = None
    support_sources: dict[str, bytes] = {}
    if support_archive is not None:
        try:
            with zipfile.ZipFile(io.BytesIO(support_archive), "r") as support:
                if (support.comment
                        or support.namelist()
                        != sorted(NATIVE_STACK_SUPPORT_SOURCES)):
                    raise ReleaseFailure(
                        "native_stack_support_inventory_invalid"
                    )
                inventory_source = support.read(
                    "native_deployment_payload.py"
                )
                support_sources = {
                    relative.as_posix(): support.read(archive_name)
                    for archive_name, relative
                    in NATIVE_STACK_SUPPORT_SOURCES.items()
                }
        except (OSError, KeyError, zipfile.BadZipFile) as error:
            raise ReleaseFailure(
                "native_stack_support_archive_invalid"
            ) from error
    inventories = native_deployment_payload_inventories(
        repo, source=inventory_source,
    )
    if source_files is not None:
        required_sources = {
            relative
            for inventory in inventories.values()
            for _name, relative, _mode in inventory
        }
        if not required_sources <= set(source_files):
            raise ReleaseFailure(
                "native_deployment_payload_source_missing"
            )
    output = io.BytesIO()
    source_cache: dict[str, bytes] = dict(source_files or {})
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, role in sorted(NATIVE_DEPLOYMENT_CONTAINER_ROLES.items()):
            data = _native_deployment_base_archive(
                repo, inventories[role], source_cache, support_sources,
            )
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.compress_type = zipfile.ZIP_STORED
            item.external_attr = ((stat.S_IFREG | 0o444) & 0xFFFF) << 16
            archive.writestr(item, data)
    value = output.getvalue()
    if not 1 <= len(value) <= NATIVE_DEPLOYMENT_CONTAINER_LIMIT:
        raise ReleaseFailure("native_deployment_payload_build_failed")
    try:
        with zipfile.ZipFile(io.BytesIO(value), "r") as archive:
            items = archive.infolist()
            if (archive.comment
                    or [item.filename for item in items]
                    != sorted(NATIVE_DEPLOYMENT_CONTAINER_MEMBERS)):
                raise ReleaseFailure(
                    "native_deployment_payload_inventory_invalid"
                )
            for item in items:
                encoded_mode = item.external_attr >> 16
                if (item.date_time != (1980, 1, 1, 0, 0, 0)
                        or item.compress_type != zipfile.ZIP_STORED
                        or encoded_mode & 0o170000 != stat.S_IFREG
                        or encoded_mode & 0o7777 != 0o444
                        or not 1 <= item.file_size <= 64 * 1024 * 1024
                        or len(archive.read(item)) != item.file_size):
                    raise ReleaseFailure(
                        "native_deployment_payload_member_invalid"
                    )
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseFailure(
            "native_deployment_payload_archive_invalid"
        ) from error
    return value


def source_payload(
    repo: Path,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
    *, expected_native_host_certificate_sha1: str | None = None,
    native_host_generation: Path | None = None,
    expected_native_host_candidate: Mapping[str, object] | None = None,
) -> tuple[dict[str, bytes], dict[str, str], str]:
    repo = repo.absolute()
    if (os.geteuid() == 0
            and (native_host_generation is None
                 or expected_native_host_candidate is None)):
        raise ReleaseFailure("native_host_candidate_record_required")
    if native_host_generation is None:
        if expected_native_host_candidate is not None:
            raise ReleaseFailure("native_host_candidate_binding_incomplete")
        native_host_generation = repo / "artifacts/host"
    else:
        native_host_generation = Path(native_host_generation)
    if expected_native_host_candidate is not None:
        observed_candidate = native_host_candidate_record(
            repo, native_host_generation,
            expected_certificate_sha1=expected_native_host_certificate_sha1,
        )
        if dict(expected_native_host_candidate) != observed_candidate:
            raise ReleaseFailure("native_host_candidate_record_mismatch")
    generation_identity, generation_tree_sha256, generation_files = (
        _native_host_generation_snapshot(repo, native_host_generation)
    )
    if (expected_native_host_candidate is not None
            and (generation_identity[0]
                    != expected_native_host_candidate.get(
                        "generation_device")
                or generation_identity[1]
                    != expected_native_host_candidate.get(
                        "generation_inode")
                or generation_tree_sha256
                    != expected_native_host_candidate.get(
                        "generation_tree_sha256"))):
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    values: dict[str, bytes] = {}
    for name in NATIVE_HOST_GENERATION_PAYLOAD_NAMES:
        value = generation_files.get(PAYLOAD_SOURCES[name].name)
        if not isinstance(value, bytes):
            raise ReleaseFailure("native_host_generation_payload_missing:" + name)
        values[name] = value
    source_archive = generation_files.get(NATIVE_HOST_SOURCE_ARCHIVE_NAME)
    if not isinstance(source_archive, bytes):
        raise ReleaseFailure("native_host_generation_source_missing")
    receipt = native_host_products_notarization(
        values["native_host_products_notarization"]
    )
    if receipt["schema"] in {
        NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
        NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
    }:
        verify_native_host_products_notarization_signature(
            values["native_host_products_notarization"],
            values["native_host_products_notarization_signature"], receipt,
            expected_certificate_sha1=(
                str(expected_native_host_candidate[
                    "developer_id_certificate_sha1"
                ])
                if expected_native_host_candidate is not None
                else expected_native_host_certificate_sha1
            ),
        )
    source_provenance, tracked_source_files = (
        native_host_source_snapshot_from_generation(source_archive, receipt)
    )
    tracked_source_files = dict(tracked_source_files)
    tracked_source_files[
        "macos/TouchIDAuthorization/Signing.local.xcconfig"
    ] = b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
    if expected_native_host_candidate is not None:
        preimage_raw, preimage_identity = _native_host_candidate_preimage(
            repo, native_host_generation, receipt,
        )
        expected_preimage_path = (
            native_host_generation.parent / "evidence"
            / NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
        )
        if (expected_native_host_candidate.get(
                    "host_release_preimage_path")
                != str(expected_preimage_path)
                or expected_native_host_candidate.get(
                    "host_release_preimage_device") != preimage_identity[0]
                or expected_native_host_candidate.get(
                    "host_release_preimage_inode") != preimage_identity[1]
                or expected_native_host_candidate.get(
                    "host_release_preimage_size") != preimage_identity[2]
                or expected_native_host_candidate.get(
                    "host_release_preimage_sha256")
                    != sha256_bytes(preimage_raw)
                or expected_native_host_candidate.get(
                    "host_release_preimage_schema")
                    != NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA
                or receipt.get("host_release_preimage_sha256")
                    != sha256_bytes(preimage_raw)):
            raise ReleaseFailure("native_host_release_preimage_mismatch")
    else:
        preimage_raw = native_host_release_preimage_archive(
            repo, source_archive, gpgv_binary,
            _source_files=tracked_source_files,
        )
        if (receipt.get("schema") == NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA
                and receipt.get("host_release_preimage_sha256")
                    != sha256_bytes(preimage_raw)):
            raise ReleaseFailure("native_host_release_preimage_mismatch")
    preimage_payloads, _preimage_metadata = (
        native_host_release_preimage_snapshot(preimage_raw)
    )
    values.update(preimage_payloads)
    validate_touchid_payload(
        repo, values, source_files=tracked_source_files,
        native_host_generation=native_host_generation,
    )
    validate_native_components_payload(
        repo, values, native_host_generation=native_host_generation,
    )
    verify_native_host_products_container(
        values, require_v2=True,
        expected_source_provenance=source_provenance,
        expected_certificate_sha1=(
            str(expected_native_host_candidate[
                "developer_id_certificate_sha1"
            ])
            if expected_native_host_candidate is not None
            else expected_native_host_certificate_sha1
        ),
    )
    validate_native_stack_coordination_contract(
        values["native_stack_coordination_contract"])
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
        compile(values["native_stack_deployer"], str(repo / PAYLOAD_SOURCES["native_stack_deployer"]), "exec")
        compile(values["pki_anchor"], str(repo / PAYLOAD_SOURCES["pki_anchor"]), "exec")
        compile(values["release_manager"], str(repo / PAYLOAD_SOURCES["release_manager"]), "exec")
        compile(values["installer_verifier"], str(repo / PAYLOAD_SOURCES["installer_verifier"]), "exec")
        compile(values["seed_verifier"], str(repo / PAYLOAD_SOURCES["seed_verifier"]), "exec")
        compile(values["vm_maintenance"], str(repo / PAYLOAD_SOURCES["vm_maintenance"]), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("python_payload_syntax_invalid") from error
    final_identity, final_tree_sha256, _final_generation_files = (
        _native_host_generation_snapshot(repo, native_host_generation)
    )
    if (final_identity != generation_identity
            or final_tree_sha256 != generation_tree_sha256):
        raise ReleaseFailure("native_host_generation_changed")
    if expected_native_host_candidate is not None:
        if native_host_candidate_record(
            repo, native_host_generation,
            expected_certificate_sha1=expected_native_host_certificate_sha1,
        ) != dict(expected_native_host_candidate):
            raise ReleaseFailure("native_host_candidate_record_mismatch")
    hashes = {name: sha256_bytes(value) for name, value in values.items()}
    return values, hashes, release_identity(hashes)


def validate_touchid_payload(
    repo: Path, values: dict[str, bytes], *,
    source_files: Mapping[str, bytes] | None = None,
    native_host_generation: Path | None = None,
) -> None:
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
        relative = (Path("macos/TouchIDAuthorization") / name).as_posix()
        observed = (
            source_files.get(relative)
            if source_files is not None else read_regular(package / name)
        )
        if (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or not isinstance(observed, bytes)
                or sha256_bytes(observed) != expected):
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
    bundle = (
        native_host_generation / AUTHORIZATION_UI_APP_NAME
        if native_host_generation is not None
        else repo / AUTHORIZATION_UI_APP_SOURCE
    )
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


def _active_markers_at(
    state_fd: int, controller_uid: int,
) -> list[str]:
    try:
        active_fd, active_info = _open_controller_directory_at(
            state_fd, "active", "active_marker_directory")
    except FileNotFoundError:
        return []
    try:
        if (
            active_info.st_uid != controller_uid
            or stat.S_IMODE(active_info.st_mode) != 0o700
        ):
            raise ReleaseFailure("active_marker_directory_invalid")
        names = os.listdir(active_fd)
        if len(names) > MAX_ACTIVE_MARKERS:
            raise ReleaseFailure("active_marker_limit_exceeded")
        live: list[str] = []
        for name in names:
            try:
                before = os.stat(
                    name, dir_fd=active_fd, follow_symlinks=False)
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=active_fd,
                )
            except OSError as error:
                raise ReleaseFailure(
                    f"active_marker_unreadable:{name}") from error
            try:
                opened = os.fstat(descriptor)
                raw = os.read(descriptor, 4097)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            named = os.stat(
                name, dir_fd=active_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (before.st_dev, before.st_ino)
                    != (opened.st_dev, opened.st_ino)
                or (opened.st_dev, opened.st_ino)
                    != (after.st_dev, after.st_ino)
                or (after.st_dev, after.st_ino)
                    != (named.st_dev, named.st_ino)
                or opened.st_uid != controller_uid
                or opened.st_gid != active_info.st_gid
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or len(raw) != opened.st_size or len(raw) > 4096
            ):
                raise ReleaseFailure("active_marker_invalid")
            try:
                value = json.loads(raw)
                pid = value["pid"]
                release_id = value["release_id"]
                if (
                    not isinstance(pid, int) or pid <= 1
                    or not isinstance(release_id, str)
                    or SHA256.fullmatch(release_id) is None
                ):
                    raise ValueError
                os.kill(pid, 0)
                live.append(name)
            except ProcessLookupError:
                current = os.stat(
                    name, dir_fd=active_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (
                    opened.st_dev, opened.st_ino
                ):
                    raise ReleaseFailure("active_marker_changed")
                os.unlink(name, dir_fd=active_fd)
                os.fsync(active_fd)
            except (
                OSError, UnicodeDecodeError, ValueError, KeyError,
                json.JSONDecodeError,
            ) as error:
                raise ReleaseFailure(
                    f"active_marker_unreadable:{name}") from error
        return live
    finally:
        os.close(active_fd)


def active_markers(state_root: Path) -> list[str]:
    held = _CONTROLLER_ADMISSION_FENCE.get()
    if held is not None and held[0] == state_root:
        return _active_markers_at(held[2], held[1])
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


def _open_controller_directory_at(
    parent_fd: int, name: str, label: str,
) -> tuple[int, os.stat_result]:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ReleaseFailure(label + "_untrusted") from error
    opened = os.fstat(descriptor)
    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
    ):
        os.close(descriptor)
        raise ReleaseFailure(label + "_changed")
    return descriptor, opened


def _controller_lock_pid_at(
    lock_fd: int, lock_info: os.stat_result, controller_uid: int,
) -> int | None:
    try:
        before = os.stat("pid", dir_fd=lock_fd, follow_symlinks=False)
        descriptor = os.open(
            "pid", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=lock_fd,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ReleaseFailure("controller_coordination_lock_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, 64)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = os.stat("pid", dir_fd=lock_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
        or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_uid != controller_uid
        or opened.st_gid != lock_info.st_gid or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or len(raw) != opened.st_size
    ):
        raise ReleaseFailure("controller_coordination_lock_untrusted")
    try:
        pid = int(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as error:
        raise ReleaseFailure("controller_coordination_lock_untrusted") from error
    if pid <= 0:
        raise ReleaseFailure("controller_coordination_lock_untrusted")
    return pid


def _remove_controller_lock_at(
    state_fd: int, name: str, expected_identity: tuple[int, int],
    controller_uid: int,
) -> None:
    descriptor, info = _open_controller_directory_at(
        state_fd, name, "controller_coordination_tombstone")
    try:
        if (
            (info.st_dev, info.st_ino) != expected_identity
            or info.st_uid != controller_uid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ReleaseFailure(
                "controller_coordination_tombstone_changed")
        entries = os.listdir(descriptor)
        if len(entries) > 2 or not set(entries) <= {"pid", ".pid.new"}:
            raise ReleaseFailure(
                "controller_coordination_tombstone_untrusted")
        for entry in entries:
            item = os.stat(
                entry, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_uid != controller_uid or item.st_gid != info.st_gid
                or item.st_nlink != 1
                or stat.S_IMODE(item.st_mode) != 0o600
            ):
                raise ReleaseFailure(
                    "controller_coordination_tombstone_untrusted")
            os.unlink(entry, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    named = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
    if (named.st_dev, named.st_ino) != expected_identity:
        raise ReleaseFailure("controller_coordination_tombstone_changed")
    os.rmdir(name, dir_fd=state_fd)
    os.fsync(state_fd)


@contextlib.contextmanager
def controller_admission_fence(
    state_root: Path, controller_uid: int, *, timeout: float = 30.0,
):
    """Exclude the stable launcher's load-to-marker admission interval.

    Every supported stable launcher holds ``coordination.lock`` from before it
    resolves ``current`` until after it durably publishes its active marker.
    A Host migration holds the same lock while proving no active marker,
    removing the predecessor selector, and publishing the irreversible floor.
    """
    if (
        not isinstance(controller_uid, int) or isinstance(controller_uid, bool)
        or controller_uid < 0
    ):
        raise ReleaseFailure("controller_state_owner_invalid")
    parent_path = state_root.parent
    try:
        parent_before = parent_path.lstat()
        parent_fd = os.open(
            parent_path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure("controller_state_parent_untrusted") from error
    state_fd = -1
    opened_parent = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(opened_parent.st_mode)
        or stat.S_ISLNK(parent_before.st_mode)
        or (opened_parent.st_dev, opened_parent.st_ino)
            != (parent_before.st_dev, parent_before.st_ino)
        or opened_parent.st_uid != controller_uid
        or opened_parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        os.close(parent_fd)
        raise ReleaseFailure("controller_state_parent_untrusted")
    created_state: tuple[int, int] | None = None
    try:
        os.stat(state_root.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        try:
            os.mkdir(state_root.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        else:
            created_info = os.stat(
                state_root.name, dir_fd=parent_fd, follow_symlinks=False)
            created_state = (created_info.st_dev, created_info.st_ino)
        os.fsync(parent_fd)
    try:
        state_fd, opened_state = _open_controller_directory_at(
            parent_fd, state_root.name, "controller_state_directory")
    except BaseException:
        os.close(parent_fd)
        raise
    if created_state is not None:
        if (opened_state.st_dev, opened_state.st_ino) != created_state:
            os.close(state_fd)
            os.close(parent_fd)
            raise ReleaseFailure("controller_state_directory_changed")
        os.fchown(state_fd, controller_uid, opened_parent.st_gid)
        os.fchmod(state_fd, 0o700)
        os.fsync(state_fd)
        opened_state = os.fstat(state_fd)
    if (
        opened_state.st_uid != controller_uid
        or stat.S_IMODE(opened_state.st_mode) != 0o700
    ):
        os.close(state_fd)
        os.close(parent_fd)
        raise ReleaseFailure("controller_state_directory_invalid")
    lock_name = "coordination.lock"
    deadline = time.monotonic() + timeout
    acquired = False
    acquired_identity: tuple[int, int] | None = None
    try:
        opened_state = os.fstat(state_fd)
        named_state = os.stat(
            state_root.name, dir_fd=parent_fd, follow_symlinks=False)
        if (opened_state.st_dev, opened_state.st_ino) != (
            named_state.st_dev, named_state.st_ino
        ):
            raise ReleaseFailure("controller_state_directory_changed")
        while True:
            try:
                os.mkdir(lock_name, 0o700, dir_fd=state_fd)
                os.fsync(state_fd)
                lock_fd, lock_info = _open_controller_directory_at(
                    state_fd, lock_name, "controller_coordination_lock")
                try:
                    os.fchown(lock_fd, controller_uid, opened_state.st_gid)
                    os.fchmod(lock_fd, 0o700)
                    lock_info = os.fstat(lock_fd)
                    pid_fd = os.open(
                        ".pid.new",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                        | os.O_CLOEXEC,
                        0o600, dir_fd=lock_fd,
                    )
                    try:
                        os.fchown(
                            pid_fd, controller_uid, opened_state.st_gid)
                        os.fchmod(pid_fd, 0o600)
                        write_all(
                            pid_fd, f"{os.getpid()}\n".encode("ascii"),
                            "controller_coordination_fence_pid",
                        )
                        os.fsync(pid_fd)
                    finally:
                        os.close(pid_fd)
                    os.rename(
                        ".pid.new", "pid",
                        src_dir_fd=lock_fd, dst_dir_fd=lock_fd,
                    )
                    os.fsync(lock_fd)
                finally:
                    os.close(lock_fd)
                os.fsync(state_fd)
                named_lock = os.stat(
                    lock_name, dir_fd=state_fd, follow_symlinks=False)
                if (named_lock.st_dev, named_lock.st_ino) != (
                    lock_info.st_dev, lock_info.st_ino
                ):
                    raise ReleaseFailure(
                        "controller_coordination_lock_changed")
                acquired = True
                acquired_identity = (lock_info.st_dev, lock_info.st_ino)
                break
            except FileExistsError:
                stale = False
                try:
                    lock_fd, lock_info = _open_controller_directory_at(
                        state_fd, lock_name,
                        "controller_coordination_lock",
                    )
                    try:
                        if (
                            lock_info.st_uid != controller_uid
                            or stat.S_IMODE(lock_info.st_mode) != 0o700
                        ):
                            raise ReleaseFailure(
                                "controller_coordination_lock_untrusted")
                        pid = _controller_lock_pid_at(
                            lock_fd, lock_info, controller_uid)
                    finally:
                        os.close(lock_fd)
                    if (
                        pid is None
                        and time.time() - lock_info.st_mtime >= 30.0
                    ):
                        stale = True
                    elif pid is not None:
                        os.kill(pid, 0)
                except ProcessLookupError:
                    stale = True
                except FileNotFoundError:
                    continue
                if stale:
                    tombstone = (
                        f".coordination.lock.reclaim-{os.getpid()}-"
                        f"{uuid.uuid4()}"
                    )
                    try:
                        os.rename(
                            lock_name, tombstone,
                            src_dir_fd=state_fd, dst_dir_fd=state_fd,
                        )
                    except FileNotFoundError:
                        continue
                    os.fsync(state_fd)
                    _remove_controller_lock_at(
                        state_fd, tombstone,
                        (lock_info.st_dev, lock_info.st_ino),
                        controller_uid,
                    )
                    continue
                if time.monotonic() >= deadline:
                    raise ReleaseFailure(
                        "controller_coordination_lock_timeout")
                time.sleep(0.05)
        named_state = os.stat(
            state_root.name, dir_fd=parent_fd, follow_symlinks=False)
        named_lock = os.stat(
            lock_name, dir_fd=state_fd, follow_symlinks=False)
        if (
            (named_state.st_dev, named_state.st_ino)
                != (opened_state.st_dev, opened_state.st_ino)
            or acquired_identity is None
            or (named_lock.st_dev, named_lock.st_ino) != acquired_identity
        ):
            raise ReleaseFailure("controller_coordination_lock_changed")
        yield state_fd
    finally:
        cleanup_error: BaseException | None = None
        if acquired and acquired_identity is not None:
            tombstone = (
                f".coordination.lock.release-{os.getpid()}-{uuid.uuid4()}"
            )
            try:
                named_lock = os.stat(
                    lock_name, dir_fd=state_fd, follow_symlinks=False)
                if (named_lock.st_dev, named_lock.st_ino) != acquired_identity:
                    raise ReleaseFailure(
                        "controller_coordination_lock_changed")
                os.rename(
                    lock_name, tombstone,
                    src_dir_fd=state_fd, dst_dir_fd=state_fd,
                )
                os.fsync(state_fd)
            except FileNotFoundError:
                cleanup_error = ReleaseFailure(
                    "controller_coordination_lock_changed")
            except BaseException as error:
                cleanup_error = error
            else:
                try:
                    _remove_controller_lock_at(
                        state_fd, tombstone, acquired_identity,
                        controller_uid,
                    )
                except BaseException as error:
                    cleanup_error = error
        os.close(state_fd)
        os.close(parent_fd)
        if cleanup_error is not None and sys.exc_info()[0] is None:
            raise cleanup_error


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
    try:
        # macOS exposes trusted system aliases such as /var -> /private/var.
        # Traverse the canonical chain descriptor-relatively, then bind the
        # opened directory back to the operator-supplied final path below.
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise ReleaseFailure("install_transition_parent_untrusted") from error
    if not canonical.is_absolute() or canonical == Path("/"):
        raise ReleaseFailure("install_transition_parent_untrusted")
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for part in canonical.parts[1:]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            if (not stat.S_ISDIR(info.st_mode)
                    or info.st_uid not in {0, expected_uid}
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise ReleaseFailure("install_transition_parent_untrusted")
        info = os.fstat(descriptor)
        current = path.lstat()
        canonical_current = canonical.lstat()
        if ((info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
                or (info.st_dev, info.st_ino)
                    != (canonical_current.st_dev, canonical_current.st_ino)
                or stat.S_ISLNK(current.st_mode)
                or stat.S_ISLNK(canonical_current.st_mode)
                or stat.S_IMODE(info.st_mode) != final_mode):
            raise ReleaseFailure("install_transition_parent_untrusted")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_locked_install_root(
    install_root: Path, expected_uid: int,
) -> int:
    """Open and exclusively serialize every pending-record mutation."""
    held = _HOST_MUTATION_LOCK.get()
    if held is not None:
        held_root, held_uid, held_descriptor = held
        if install_root != held_root or expected_uid != held_uid:
            raise ReleaseFailure("host_release_lock_context_mismatch")
        try:
            opened = os.fstat(held_descriptor)
            current = install_root.lstat()
        except OSError as error:
            raise ReleaseFailure("host_release_lock_identity_changed") from error
        if (not stat.S_ISDIR(opened.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (current.st_dev, current.st_ino)
                or opened.st_uid != expected_uid
                or stat.S_IMODE(opened.st_mode) != 0o755):
            raise ReleaseFailure("host_release_lock_identity_changed")
        # Return an independently opened directory capability, not dup(2) of
        # the lock-owning descriptor. A nested consumer may close it or issue
        # LOCK_UN without releasing the outer open-file-description lock.
        return open_trusted_absolute_directory(install_root, expected_uid)
    descriptor = open_trusted_absolute_directory(install_root, expected_uid)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


_NATIVE_DEPLOYMENT_GATE_READER = """
import hashlib
import json
import os
import pathlib
import stat
import sys
import types

path = pathlib.Path(sys.argv[1])
before = path.lstat()
descriptor = os.open(
    path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    opened = os.fstat(descriptor)
    source = bytearray()
    while len(source) <= 16 * 1024 * 1024:
        block = os.read(
            descriptor,
            min(1024 * 1024, 16 * 1024 * 1024 + 1 - len(source)))
        if not block:
            break
        source.extend(block)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
current = path.lstat()
identity = lambda item: (
    item.st_dev, item.st_ino, item.st_size, item.st_mode, item.st_uid,
    item.st_gid, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
if (
    not stat.S_ISREG(opened.st_mode)
    or stat.S_ISLNK(before.st_mode)
    or opened.st_uid != int(sys.argv[5])
    or opened.st_nlink != 1
    or stat.S_IMODE(opened.st_mode) != 0o755
    or not 1 <= opened.st_size <= 16 * 1024 * 1024
    or len(source) != opened.st_size
    or identity(before) != identity(opened)
    or identity(opened) != identity(after)
    or identity(after) != identity(current)
    or hashlib.sha256(source).hexdigest() != sys.argv[7]
):
    raise RuntimeError("native_deployment_deployer_identity_invalid")
module = types.ModuleType("_secure_sandbox_native_deployment_gate")
module.__file__ = str(path)
module.__package__ = None
code = compile(
    bytes(source), str(path), "exec", dont_inherit=True, optimize=0)
exec(code, module.__dict__)
value = module.deployment_gate_state(
    int(sys.argv[4]), state_root=pathlib.Path(sys.argv[2]),
    host_install_root=pathlib.Path(sys.argv[3]),
    trusted_uid=int(sys.argv[5]), trusted_gid=int(sys.argv[6]),
    transition_release_id=(None if sys.argv[8] == "-" else sys.argv[8]))
sys.stdout.write(json.dumps(
    value, allow_nan=False, ensure_ascii=True,
    separators=(",", ":"), sort_keys=True) + "\\n")
"""


_NATIVE_CATALOG_PROMOTION_GATE_READER = """
import hashlib
import json
import os
import pathlib
import stat
import sys
import types

path = pathlib.Path(sys.argv[1])
before = path.lstat()
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    opened = os.fstat(descriptor)
    source = bytearray()
    while len(source) <= 16 * 1024 * 1024:
        block = os.read(descriptor, min(
            1024 * 1024, 16 * 1024 * 1024 + 1 - len(source)))
        if not block:
            break
        source.extend(block)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
current = path.lstat()
identity = lambda item: (
    item.st_dev, item.st_ino, item.st_size, item.st_mode, item.st_uid,
    item.st_gid, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
if (
    not stat.S_ISREG(opened.st_mode)
    or stat.S_ISLNK(before.st_mode)
    or opened.st_uid != int(sys.argv[7])
    or opened.st_nlink != 1
    or stat.S_IMODE(opened.st_mode) != 0o755
    or not 1 <= opened.st_size <= 16 * 1024 * 1024
    or len(source) != opened.st_size
    or identity(before) != identity(opened)
    or identity(opened) != identity(after)
    or identity(after) != identity(current)
    or hashlib.sha256(source).hexdigest() != sys.argv[9]
):
    raise RuntimeError("native_catalog_promoter_identity_invalid")
module = types.ModuleType("_secure_sandbox_native_catalog_gate")
module.__file__ = str(path)
module.__package__ = None
code = compile(bytes(source), str(path), "exec", dont_inherit=True, optimize=0)
exec(code, module.__dict__)
value = module.promotion_gate_state(
    int(sys.argv[6]), catalog_root=pathlib.Path(sys.argv[2]),
    transactions=pathlib.Path(sys.argv[3]),
    public_status=pathlib.Path(sys.argv[4]),
    host_install_root=pathlib.Path(sys.argv[5]),
    trusted_uid=int(sys.argv[7]), trusted_gid=int(sys.argv[8]),
    transition_release_id=(None if sys.argv[10] == "-" else sys.argv[10]))
sys.stdout.write(json.dumps(
    value, allow_nan=False, ensure_ascii=True,
    separators=(",", ":"), sort_keys=True) + "\\n")
"""


_D8653CB_NATIVE_COORDINATION_GATE_READER = """
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import sys
import types

uid = int(sys.argv[12])
gid = int(sys.argv[13])

def read_exact(path, expected_sha256, expected_mode):
    before = path.lstat()
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        source = bytearray()
        while len(source) <= 64 * 1024 * 1024:
            block = os.read(
                descriptor,
                min(1024 * 1024, 64 * 1024 * 1024 + 1 - len(source)))
            if not block:
                break
            source.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.lstat()
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mode, item.st_uid,
        item.st_gid, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != uid
        or opened.st_gid != gid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or not 1 <= opened.st_size <= 64 * 1024 * 1024
        or len(source) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or identity(after) != identity(current)
        or hashlib.sha256(source).hexdigest() != expected_sha256
    ):
        raise RuntimeError("native_coordination_candidate_payload_invalid")
    return bytes(source)

def require_lock(descriptor, path):
    opened = os.fstat(descriptor)
    current = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_uid != uid
        or opened.st_gid != gid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise RuntimeError("native_coordination_inherited_lock_invalid")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise RuntimeError(
            "native_coordination_inherited_lock_not_held") from error

promoter_path = pathlib.Path(sys.argv[1])
deployer_path = pathlib.Path(sys.argv[2])
support_path = pathlib.Path(sys.argv[3])
promoter_source = read_exact(promoter_path, sys.argv[15], 0o755)
deployer_source = read_exact(deployer_path, sys.argv[16], 0o755)
read_exact(support_path, sys.argv[17], 0o444)

host_root = pathlib.Path(sys.argv[8])
host_descriptor = int(sys.argv[9])
host_opened = os.fstat(host_descriptor)
host_current = host_root.lstat()
if (
    not stat.S_ISDIR(host_opened.st_mode)
    or stat.S_ISLNK(host_current.st_mode)
    or host_opened.st_uid != uid
    or stat.S_IMODE(host_opened.st_mode) != 0o755
    or (host_opened.st_dev, host_opened.st_ino)
        != (host_current.st_dev, host_current.st_ino)
):
    raise RuntimeError("native_coordination_host_lock_invalid")
try:
    fcntl.flock(host_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError as error:
    raise RuntimeError("native_coordination_host_lock_not_held") from error

transactions = pathlib.Path(sys.argv[5])
catalog_root = pathlib.Path(sys.argv[4])
require_lock(int(sys.argv[10]), transactions / ".lock")
require_lock(int(sys.argv[11]), catalog_root / ".promotion.lock")

promoter = types.ModuleType("_secure_sandbox_coordination_candidate_promoter")
promoter.__file__ = str(promoter_path)
promoter.__package__ = None
exec(compile(
    promoter_source, str(promoter_path), "exec", dont_inherit=True,
    optimize=0), promoter.__dict__)
catalog_body = promoter._promotion_gate_body_under_lock(
    catalog_root=catalog_root,
    public_status=pathlib.Path(sys.argv[6]),
    trusted_uid=uid,
    trusted_gid=gid,
    expected_host_release_id=sys.argv[14],
)
catalog_gate = promoter._gate_value(catalog_body)

deployer = types.ModuleType("_secure_sandbox_coordination_candidate_deployer")
deployer.__file__ = str(deployer_path)
deployer.__package__ = None
exec(compile(
    deployer_source, str(deployer_path), "exec", dont_inherit=True,
    optimize=0), deployer.__dict__)
deployer._activate_support(support_path, sys.argv[17], expected_uid=uid)
journal = deployer.Journal(
    pathlib.Path(sys.argv[7]), host_install_fd=host_descriptor,
    host_install_root=host_root, trusted_uid=uid, trusted_gid=gid)
journal.lock(create=False)
try:
    loaded = journal.load()
    deployment_body = {
        "state": "ready" if loaded is None else "active",
        "active_journal_sha256": (
            None if loaded is None else loaded[0]["record_sha256"]),
    }
finally:
    journal.unlock()
deployment_gate = {
    "schema": deployer.GATE_STATE_SCHEMA, **deployment_body,
    "gate_sha256": deployer.digest(deployment_body),
}
value = {
    "schema": "secure-sandbox-d8653cb-native-coordination-admission-v1",
    "catalog_gate": catalog_gate,
    "deployment_gate": deployment_gate,
}
sys.stdout.write(json.dumps(
    value, allow_nan=False, ensure_ascii=True,
    separators=(",", ":"), sort_keys=True) + "\\n")
"""


def native_deployment_state_root(install_root: Path) -> Path:
    """Keep tests isolated while binding the production root exactly."""
    if install_root == DEFAULT_INSTALL_ROOT:
        return NATIVE_DEPLOYMENT_STATE_ROOT
    return install_root.parent / f".{install_root.name}.native-deployment"


def native_catalog_gate_paths(
    install_root: Path,
) -> tuple[Path, Path, Path]:
    if install_root == DEFAULT_INSTALL_ROOT:
        return (
            NATIVE_CATALOG_ROOT, NATIVE_CATALOG_TRANSACTIONS,
            NATIVE_CATALOG_PUBLIC_STATUS,
        )
    prefix = install_root.parent / f".{install_root.name}"
    return (
        prefix.with_name(prefix.name + ".native-stack-catalog"),
        prefix.with_name(prefix.name + ".native-stack-transactions"),
        prefix.with_name(prefix.name + ".native-stack-public") / "status.json",
    )


def is_d8653cb_native_coordination_predecessor(
    manifest: Mapping[str, Any],
) -> bool:
    """Recognize only the exact pre-coordination gate implementation."""
    payloads = manifest.get("payloads")
    return (
        isinstance(payloads, dict)
        and set(payloads) == PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
        and all(
            payloads.get(name) == expected
            for name, expected
            in D8653CB_NATIVE_COORDINATION_PAYLOAD_SHA256.items()
        )
    )


def _open_or_create_coordination_directory(
    path: Path, expected_uid: int, expected_gid: int,
) -> int:
    """Open one exact root-owned 0700 legacy coordination directory."""
    parent_path = path.parent
    try:
        parent_before = parent_path.lstat()
        parent = os.open(
            parent_path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ReleaseFailure(
            "native_coordination_legacy_parent_untrusted") from error
    try:
        parent_opened = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or stat.S_ISLNK(parent_before.st_mode)
            or (parent_opened.st_dev, parent_opened.st_ino)
                != (parent_before.st_dev, parent_before.st_ino)
            or parent_opened.st_uid != expected_uid
            or parent_opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ReleaseFailure(
                "native_coordination_legacy_parent_untrusted")
        created = False
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        if created:
            os.fsync(parent)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            if created:
                os.fchown(descriptor, expected_uid, expected_gid)
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
            opened = os.fstat(descriptor)
            named = os.stat(
                path.name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                    != (named.st_dev, named.st_ino)
                or opened.st_uid != expected_uid
                or opened.st_gid != expected_gid
                or stat.S_IMODE(opened.st_mode) != 0o700
            ):
                raise ReleaseFailure(
                    "native_coordination_legacy_directory_untrusted")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(parent)


def _open_coordination_lock_at(
    directory: int, name: str, expected_uid: int, expected_gid: int,
) -> int:
    """Open or create one exact legacy lock without acquiring it yet."""
    created = False
    try:
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        created = True
    except FileExistsError:
        descriptor = os.open(
            name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
    try:
        if created:
            os.fchown(descriptor, expected_uid, expected_gid)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(directory)
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_uid != expected_uid
            or opened.st_gid != expected_gid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ReleaseFailure("native_coordination_legacy_lock_untrusted")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextlib.contextmanager
def _materialized_native_coordination_gate_candidate(
    values: Mapping[str, bytes], hashes: Mapping[str, str],
    expected_uid: int, expected_gid: int,
):
    required = {
        "native_stack_catalog_promoter": 0o755,
        "native_stack_deployer": 0o755,
        "native_stack_support": 0o444,
    }
    if any(
        name not in values or name not in hashes
        or sha256_bytes(values[name]) != hashes[name]
        for name in required
    ):
        raise ReleaseFailure("native_coordination_candidate_gate_invalid")
    with tempfile.TemporaryDirectory(
        prefix="secure-sandbox-native-coordination-gate-",
    ) as temporary:
        root = Path(temporary)
        os.chown(root, expected_uid, expected_gid)
        root.chmod(0o700)
        directory = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            paths: dict[str, Path] = {}
            for name, mode in required.items():
                path = root / name
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    mode,
                    dir_fd=directory,
                )
                try:
                    os.fchown(descriptor, expected_uid, expected_gid)
                    os.fchmod(descriptor, mode)
                    write_all(
                        descriptor, values[name],
                        "native_coordination_candidate_gate",
                    )
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                paths[name] = path
            os.fsync(directory)
        finally:
            os.close(directory)
        yield paths


def _validate_d8653cb_coordination_gate_reply(
    value: object,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "catalog_gate", "deployment_gate"}
        or value.get("schema")
            != "secure-sandbox-d8653cb-native-coordination-admission-v1"
    ):
        raise ReleaseFailure("native_coordination_legacy_gate_invalid")
    catalog = value["catalog_gate"]
    deployment = value["deployment_gate"]
    catalog_body = {
        "state": "ready", "active_promotion_id": None,
        "active_state_sha256": None,
    }
    deployment_body = {
        "state": "ready", "active_journal_sha256": None,
    }
    if (
        not isinstance(catalog, dict)
        or set(catalog) != {
            "schema", "state", "active_promotion_id",
            "active_state_sha256", "gate_sha256",
        }
        or catalog.get("schema") != NATIVE_CATALOG_PROMOTION_GATE_SCHEMA
        or catalog.get("state") not in {"ready", "active", "invalid"}
        or not isinstance(deployment, dict)
        or set(deployment) != {
            "schema", "state", "active_journal_sha256", "gate_sha256",
        }
        or deployment.get("schema") != NATIVE_DEPLOYMENT_GATE_SCHEMA
        or deployment.get("state") not in {"ready", "active", "invalid"}
    ):
        raise ReleaseFailure("native_coordination_legacy_gate_invalid")
    if catalog["state"] == "active":
        raise ReleaseFailure("native_catalog_promotion_active")
    if catalog != {
        "schema": NATIVE_CATALOG_PROMOTION_GATE_SCHEMA,
        **catalog_body,
        "gate_sha256": sha256_bytes(canonical_state_record(catalog_body)),
    }:
        raise ReleaseFailure("native_catalog_promotion_state_invalid")
    if deployment["state"] == "active":
        raise ReleaseFailure("native_deployment_active")
    if deployment != {
        "schema": NATIVE_DEPLOYMENT_GATE_SCHEMA,
        **deployment_body,
        "gate_sha256": sha256_bytes(canonical_state_record(deployment_body)),
    }:
        raise ReleaseFailure("native_deployment_state_invalid")
    return value


@contextlib.contextmanager
def d8653cb_native_coordination_admission(
    host_install_fd: int, repo: Path, install_root: Path,
    expected_uid: int, expected_current_release_id: str,
    expected_source_release_id: str,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
):
    """Fence and validate the sole historical two-way-gate predecessor."""
    if (
        SHA256.fullmatch(expected_current_release_id) is None
        or SHA256.fullmatch(expected_source_release_id) is None
    ):
        raise ReleaseFailure("native_coordination_legacy_binding_invalid")
    current = install_root / "current"
    predecessor = (
        install_root / NATIVE_STACK_COORDINATION_PREDECESSOR_NAME)
    if current.is_symlink():
        selected_link = current
    elif os.path.lexists(current):
        raise ReleaseFailure("release_link_invalid:current")
    else:
        if not predecessor.is_symlink():
            raise ReleaseFailure("native_coordination_predecessor_invalid")
        selected_link = predecessor
    selected, manifest = verified_release(
        install_root, selected_link, expected_uid, allow_legacy=True,
        _bootstrap_without_native_coordination_floor=True,
    )
    if selected.name != expected_current_release_id:
        raise ReleaseFailure("current_release_id_unexpected")
    if not is_d8653cb_native_coordination_predecessor(manifest):
        yield None
        return

    values, hashes, source_release_id = source_payload(
        repo, op_binary, gpgv_binary)
    if source_release_id != expected_source_release_id:
        raise ReleaseFailure("source_release_id_unexpected")
    # d8653cb promotion does not inherit the Host flock.  Fence its launchd
    # ingress before draining the legacy manager/promotion locks; otherwise a
    # child spawned after we acquired them could queue and resume old code when
    # this context releases the locks after selector publication.
    if manages_live_touchid_service(install_root, expected_uid):
        stop_and_fence_d8653cb_host_services(
            console_user_uid(), selected, manifest)
    host = os.fstat(host_install_fd)
    catalog_root, transactions, public_status = native_catalog_gate_paths(
        install_root)
    deployment_state = native_deployment_state_root(install_root)
    directories: list[int] = []
    manager_lock = -1
    promotion_lock = -1
    try:
        transaction_directory = _open_or_create_coordination_directory(
            transactions, expected_uid, host.st_gid)
        directories.append(transaction_directory)
        catalog_directory = _open_or_create_coordination_directory(
            catalog_root, expected_uid, host.st_gid)
        directories.append(catalog_directory)
        for name in (
            "promotion-receipts", "promotion-staging", "promotion-journals",
        ):
            directories.append(_open_or_create_coordination_directory(
                catalog_root / name, expected_uid, host.st_gid))
        manager_lock = _open_coordination_lock_at(
            transaction_directory, ".lock", expected_uid, host.st_gid)
        promotion_lock = _open_coordination_lock_at(
            catalog_directory, ".promotion.lock",
            expected_uid, host.st_gid)
        fcntl.flock(manager_lock, fcntl.LOCK_EX)
        fcntl.flock(promotion_lock, fcntl.LOCK_EX)
        with _materialized_native_coordination_gate_candidate(
            values, hashes, expected_uid, host.st_gid,
        ) as candidate:
            completed = subprocess.run(
                [
                    sys.executable, "-I", "-B", "-c",
                    _D8653CB_NATIVE_COORDINATION_GATE_READER,
                    str(candidate["native_stack_catalog_promoter"]),
                    str(candidate["native_stack_deployer"]),
                    str(candidate["native_stack_support"]),
                    str(catalog_root), str(transactions), str(public_status),
                    str(deployment_state), str(install_root),
                    str(host_install_fd), str(manager_lock),
                    str(promotion_lock), str(expected_uid), str(host.st_gid),
                    selected.name,
                    hashes["native_stack_catalog_promoter"],
                    hashes["native_stack_deployer"],
                    hashes["native_stack_support"],
                ],
                check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                pass_fds=(host_install_fd, manager_lock, promotion_lock),
            )
        try:
            value = json.loads(completed.stdout)
            canonical = canonical_state_record(value)
        except (UnicodeDecodeError, json.JSONDecodeError, ReleaseFailure) as error:
            raise ReleaseFailure(
                "native_coordination_legacy_gate_invalid") from error
        if completed.returncode != 0 or completed.stdout != canonical:
            raise ReleaseFailure("native_coordination_legacy_gate_invalid")
        admitted = _validate_d8653cb_coordination_gate_reply(value)
        # Retain both legacy locks for the entire selector/floor/install
        # transition: d8653cb promotion predates the inherited Host flock.
        yield admitted
    finally:
        if promotion_lock >= 0:
            fcntl.flock(promotion_lock, fcntl.LOCK_UN)
            os.close(promotion_lock)
        if manager_lock >= 0:
            fcntl.flock(manager_lock, fcntl.LOCK_UN)
            os.close(manager_lock)
        for descriptor in reversed(directories):
            os.close(descriptor)


def prepare_install_root_for_lock(
    install_root: Path, expected_uid: int,
) -> None:
    """Create only an absent final install root before its flock exists."""
    if (not install_root.is_absolute() or install_root == Path("/")
            or install_root.name in {"", ".", ".."}):
        raise ReleaseFailure("install_root_untrusted")
    try:
        current = install_root.lstat()
    except FileNotFoundError:
        parent_path = install_root.parent
        try:
            before = parent_path.lstat()
            parent = os.open(
                parent_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as error:
            raise ReleaseFailure("install_root_parent_untrusted") from error
        try:
            opened = os.fstat(parent)
            if (not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != (before.st_dev, before.st_ino)
                    or opened.st_uid != expected_uid
                    or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise ReleaseFailure("install_root_parent_untrusted")
            created = False
            try:
                os.mkdir(install_root.name, 0o755, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
            try:
                child = os.open(
                    install_root.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    dir_fd=parent,
                )
            except OSError as error:
                raise ReleaseFailure("install_root_untrusted") from error
            try:
                child_info = os.fstat(child)
                if (not stat.S_ISDIR(child_info.st_mode)
                        or child_info.st_uid != expected_uid
                        or child_info.st_mode
                            & (stat.S_IWGRP | stat.S_IWOTH)):
                    raise ReleaseFailure("install_root_untrusted")
                if created:
                    # mkdir(2) applies the process umask. Normalize only the
                    # directory this invocation created, through its open
                    # descriptor, before publishing the durable parent entry.
                    os.fchmod(child, 0o755)
                    os.fsync(child)
                elif stat.S_IMODE(child_info.st_mode) != 0o755:
                    raise ReleaseFailure("install_root_untrusted")
                os.fsync(parent)
            finally:
                os.close(child)
        finally:
            os.close(parent)
        try:
            current = install_root.lstat()
        except OSError as error:
            raise ReleaseFailure("install_root_untrusted") from error
    if (not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode)
            or current.st_uid != expected_uid
            or stat.S_IMODE(current.st_mode) != 0o755):
        raise ReleaseFailure("install_root_untrusted")


def ensure_native_deployment_inactive_locked(
    host_install_fd: int, install_root: Path, expected_uid: int,
    *, selector_release_id: str | None = None,
) -> dict[str, Any]:
    """Reject Host mutations unless the durable native journal is quiescent.

    The caller already owns the exact Host install-root flock. The installed
    deployment driver then takes the journal lock, preserving Host-before-
    journal lock order.
    """
    state_root = native_deployment_state_root(install_root)
    current = install_root / "current"
    ready_body = {"state": "ready", "active_journal_sha256": None}
    ready = {
        "schema": NATIVE_DEPLOYMENT_GATE_SCHEMA, **ready_body,
        "gate_sha256": sha256_bytes(canonical_state_record(ready_body)),
    }
    transition_release_id: str | None = None
    if not current.is_symlink():
        if os.path.lexists(current):
            raise ReleaseFailure("release_link_invalid:current")
        if not os.path.lexists(state_root):
            return ready
        if (selector_release_id is None
                or SHA256.fullmatch(selector_release_id) is None):
            raise ReleaseFailure("native_deployment_state_invalid")
        transition_release_id = selector_release_id
        selected, manifest = verified_release(
            install_root,
            install_root / "releases" / selector_release_id,
            expected_uid, allow_legacy=True,
            _direct_release_id=selector_release_id,
        )
    else:
        selected, manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True,
        )
    payload_names = set(manifest["payloads"])
    if not NATIVE_DEPLOYMENT_PAYLOAD_NAMES <= payload_names:
        if os.path.lexists(state_root):
            raise ReleaseFailure("native_deployment_state_invalid")
        return ready
    if not os.path.lexists(state_root):
        # Native deployment also takes the Host lock before creating its
        # state root, so absence is stable for this entire Host mutation.
        return ready
    try:
        host = os.fstat(host_install_fd)
        completed = subprocess.run(
            [
                sys.executable, "-I", "-B", "-c",
                _NATIVE_DEPLOYMENT_GATE_READER,
                str(selected / "native_stack_deployer"), str(state_root),
                str(install_root), str(host_install_fd), str(expected_uid),
                str(host.st_gid), manifest["payloads"]["native_stack_deployer"],
                "-" if transition_release_id is None
                else transition_release_id,
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            pass_fds=(host_install_fd,),
        )
        value = json.loads(completed.stdout)
        expected_raw = canonical_state_record(value)
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError,
            json.JSONDecodeError, ReleaseFailure) as error:
        raise ReleaseFailure("native_deployment_state_invalid") from error
    fields = {
        "schema", "state", "active_journal_sha256", "gate_sha256",
    }
    state = value.get("state") if isinstance(value, dict) else None
    active = (
        value.get("active_journal_sha256")
        if isinstance(value, dict) else None
    )
    body = {"state": state, "active_journal_sha256": active}
    if (completed.returncode != 0 or not isinstance(value, dict)
            or set(value) != fields
            or completed.stdout != expected_raw
            or value.get("schema") != NATIVE_DEPLOYMENT_GATE_SCHEMA
            or state not in {"ready", "active", "invalid"}
            or (state == "active") != (
                isinstance(active, str) and SHA256.fullmatch(active) is not None
            )
            or state != "active" and active is not None
            or value.get("gate_sha256")
            != sha256_bytes(canonical_state_record(body))):
        raise ReleaseFailure("native_deployment_state_invalid")
    if state == "active":
        raise ReleaseFailure("native_deployment_active")
    if state != "ready":
        raise ReleaseFailure("native_deployment_state_invalid")
    return value


def ensure_native_catalog_promotion_inactive_locked(
    host_install_fd: int, install_root: Path, expected_uid: int,
    *, selector_release_id: str | None = None,
) -> dict[str, Any]:
    """Reject Host selector mutations during active/invalid promotion state."""
    catalog_root, transactions, public_status = native_catalog_gate_paths(
        install_root)
    body = {
        "state": "ready", "active_promotion_id": None,
        "active_state_sha256": None,
    }
    ready = {
        "schema": NATIVE_CATALOG_PROMOTION_GATE_SCHEMA, **body,
        "gate_sha256": sha256_bytes(canonical_state_record(body)),
    }
    current = install_root / "current"
    state_exists = os.path.lexists(public_status) or any(
        os.path.lexists(catalog_root / name) for name in (
            ".promotion.lock", "promotion-replay-authorities",
            "promotion-receipts", "promotion-staging", "promotion-journals",
            "promotion-recovery-intents", "promotion-recovery-terminals",
        )
    )
    if not state_exists:
        return ready
    transition_release_id: str | None = None
    if not current.is_symlink():
        if os.path.lexists(current):
            raise ReleaseFailure("release_link_invalid:current")
        if selector_release_id is None:
            raise ReleaseFailure("native_catalog_promotion_state_invalid")
        if SHA256.fullmatch(selector_release_id) is None:
            raise ReleaseFailure("native_catalog_promotion_state_invalid")
        transition_release_id = selector_release_id
        selected, manifest = verified_release(
            install_root,
            install_root / "releases" / selector_release_id,
            expected_uid, allow_legacy=True,
            _direct_release_id=selector_release_id,
        )
    else:
        selected, manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True)
    payloads = manifest["payloads"]
    if "native_stack_catalog_promoter" not in payloads:
        if state_exists:
            raise ReleaseFailure("native_catalog_promotion_state_invalid")
        return ready
    if not state_exists:
        return ready
    try:
        host = os.fstat(host_install_fd)
        completed = subprocess.run(
            [
                sys.executable, "-I", "-B", "-c",
                _NATIVE_CATALOG_PROMOTION_GATE_READER,
                str(selected / "native_stack_catalog_promoter"),
                str(catalog_root), str(transactions), str(public_status),
                str(install_root), str(host_install_fd), str(expected_uid),
                str(host.st_gid), payloads["native_stack_catalog_promoter"],
                "-" if transition_release_id is None
                else transition_release_id,
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            pass_fds=(host_install_fd,),
        )
        value = json.loads(completed.stdout)
        expected_raw = canonical_state_record(value)
    except (
        OSError, subprocess.TimeoutExpired, UnicodeDecodeError,
        json.JSONDecodeError, ReleaseFailure,
    ) as error:
        raise ReleaseFailure(
            "native_catalog_promotion_state_invalid") from error
    fields = {
        "schema", "state", "active_promotion_id",
        "active_state_sha256", "gate_sha256",
    }
    state = value.get("state") if isinstance(value, dict) else None
    active_id = value.get("active_promotion_id") if isinstance(
        value, dict) else None
    active_sha = value.get("active_state_sha256") if isinstance(
        value, dict) else None
    gate_body = {
        "state": state, "active_promotion_id": active_id,
        "active_state_sha256": active_sha,
    }
    active_valid = (
        isinstance(active_id, str) and UUID4.fullmatch(active_id) is not None
        and isinstance(active_sha, str)
        and SHA256.fullmatch(active_sha) is not None
    )
    if (
        completed.returncode != 0 or not isinstance(value, dict)
        or set(value) != fields or completed.stdout != expected_raw
        or value.get("schema") != NATIVE_CATALOG_PROMOTION_GATE_SCHEMA
        or state not in {"ready", "active", "invalid"}
        or (state == "active") != active_valid
        or state != "active" and (active_id is not None or active_sha is not None)
        or value.get("gate_sha256")
        != sha256_bytes(canonical_state_record(gate_body))
    ):
        raise ReleaseFailure("native_catalog_promotion_state_invalid")
    if state == "active":
        raise ReleaseFailure("native_catalog_promotion_active")
    if state != "ready":
        raise ReleaseFailure("native_catalog_promotion_state_invalid")
    return value


def ensure_release_native_deployment_compatible(
    manifest: Mapping[str, Any], install_root: Path,
) -> None:
    payloads = manifest.get("payloads")
    if (not isinstance(payloads, dict)
            or not (
                NATIVE_DEPLOYMENT_PAYLOAD_NAMES
                | NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
            ) <= set(payloads)):
        if os.path.lexists(native_deployment_state_root(install_root)):
            raise ReleaseFailure("native_deployment_legacy_state_untrusted")


def ensure_release_id_native_deployment_compatible(
    install_root: Path, release_id: str, expected_uid: int,
) -> None:
    if not os.path.lexists(native_deployment_state_root(install_root)):
        return
    if not isinstance(release_id, str) or SHA256.fullmatch(release_id) is None:
        raise ReleaseFailure("native_deployment_legacy_state_untrusted")
    link = install_root / f".native-deployment-compat-{os.getpid()}"
    if os.path.lexists(link):
        raise ReleaseFailure("native_deployment_compatibility_link_exists")
    link.symlink_to(f"releases/{release_id}")
    try:
        _path, manifest = verified_release(
            install_root, link, expected_uid, allow_legacy=True,
        )
        ensure_release_native_deployment_compatible(manifest, install_root)
    finally:
        link.unlink(missing_ok=True)


def native_catalog_promotion_state_exists(install_root: Path) -> bool:
    catalog_root, _transactions, public_status = native_catalog_gate_paths(
        install_root)
    return os.path.lexists(public_status) or any(
        os.path.lexists(catalog_root / name) for name in (
            ".promotion.lock", "promotion-replay-authorities",
            "promotion-receipts", "promotion-staging", "promotion-journals",
            "promotion-recovery-intents", "promotion-recovery-terminals",
        )
    )


def ensure_release_native_catalog_compatible(
    manifest: Mapping[str, Any], install_root: Path,
) -> None:
    payloads = manifest.get("payloads")
    if (
        not isinstance(payloads, dict)
        or "native_stack_catalog_promoter" not in payloads
        or "native_stack_coordination_contract" not in payloads
    ) and native_catalog_promotion_state_exists(install_root):
        raise ReleaseFailure("native_catalog_promotion_legacy_state_untrusted")


def enforce_release_native_stack_coordination_compatible(
    release: Path, manifest: Mapping[str, Any], install_root: Path,
    expected_uid: int,
) -> dict[str, Any]:
    observed_floor = native_stack_coordination_floor(
        install_root, expected_uid, allow_absent=True)
    if observed_floor is None:
        return {}
    payloads = manifest.get("payloads")
    if (
        not isinstance(payloads, dict)
        or "native_stack_coordination_contract" not in payloads
    ):
        raise ReleaseFailure("release_below_native_stack_coordination_floor")
    raw = read_regular(release / "native_stack_coordination_contract")
    if sha256_bytes(raw) != payloads["native_stack_coordination_contract"]:
        raise ReleaseFailure("native_stack_coordination_contract_changed")
    return enforce_native_stack_coordination_floor(
        raw, install_root, expected_uid)


def enforce_release_id_native_stack_coordination_compatible(
    install_root: Path, release_id: str, expected_uid: int,
) -> None:
    if native_stack_coordination_floor(
        install_root, expected_uid, allow_absent=True
    ) is None:
        return
    if not isinstance(release_id, str) or SHA256.fullmatch(release_id) is None:
        raise ReleaseFailure("release_below_native_stack_coordination_floor")
    release, manifest = verified_release(
        install_root, install_root / "releases" / release_id,
        expected_uid, allow_legacy=True, _direct_release_id=release_id,
    )
    enforce_release_native_stack_coordination_compatible(
        release, manifest, install_root, expected_uid)


def ensure_release_id_native_catalog_compatible(
    install_root: Path, release_id: str, expected_uid: int,
) -> None:
    if not native_catalog_promotion_state_exists(install_root):
        return
    if not isinstance(release_id, str) or SHA256.fullmatch(release_id) is None:
        raise ReleaseFailure("native_catalog_promotion_legacy_state_untrusted")
    link = install_root / f".native-catalog-compat-{os.getpid()}"
    if os.path.lexists(link):
        raise ReleaseFailure("native_catalog_promotion_compatibility_link_exists")
    link.symlink_to(f"releases/{release_id}")
    try:
        _path, manifest = verified_release(
            install_root, link, expected_uid, allow_legacy=True)
        ensure_release_native_catalog_compatible(manifest, install_root)
    finally:
        link.unlink(missing_ok=True)


def host_release_mutation(
    *, initialize: bool = False, controller_fence: bool = False,
    legacy_native_coordination: bool = False,
):
    """Hold the Host lock and native-journal gate for a whole mutation."""
    def decorate(function):
        signature = inspect.signature(function)

        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            install_root = Path(bound.arguments["install_root"])
            expected_uid = bound.arguments["expected_uid"]
            held = _HOST_MUTATION_LOCK.get()
            if held is not None:
                if install_root != held[0] or expected_uid != held[1]:
                    raise ReleaseFailure("host_release_lock_context_mismatch")
                return function(*args, **kwargs)
            if initialize:
                prepare_install_root_for_lock(install_root, expected_uid)
            descriptor = open_locked_install_root(
                install_root, expected_uid,
            )
            token = _HOST_MUTATION_LOCK.set(
                (install_root, expected_uid, descriptor)
            )
            try:
                with contextlib.ExitStack() as stack:
                    if controller_fence:
                        controller_state_root = Path(
                            bound.arguments["state_root"])
                        controller_uid = console_user_uid()
                        controller_state_fd = stack.enter_context(
                            controller_admission_fence(
                                controller_state_root, controller_uid,
                            )
                        )
                        controller_token = _CONTROLLER_ADMISSION_FENCE.set((
                            controller_state_root, controller_uid,
                            controller_state_fd,
                        ))
                        stack.callback(
                            _CONTROLLER_ADMISSION_FENCE.reset,
                            controller_token,
                        )
                        live = active_markers(controller_state_root)
                        if live:
                            raise ReleaseFailure(
                                "active_controller_invocations:"
                                + ",".join(live)
                            )
                    legacy_admission = None
                    if legacy_native_coordination:
                        legacy_admission = stack.enter_context(
                            d8653cb_native_coordination_admission(
                                descriptor,
                                Path(bound.arguments["repo"]),
                                install_root,
                                expected_uid,
                                bound.arguments["expected_current_release_id"],
                                bound.arguments["expected_source_release_id"],
                                Path(bound.arguments.get(
                                    "op_binary", DEFAULT_OP_BINARY)),
                                Path(bound.arguments.get(
                                    "gpgv_binary", DEFAULT_GPGV_BINARY)),
                            )
                        )
                    if legacy_admission is None:
                        ensure_native_catalog_promotion_inactive_locked(
                            descriptor, install_root, expected_uid,
                            selector_release_id=(
                                bound.arguments.get(
                                    "expected_current_release_id")
                                if controller_fence else None
                            ),
                        )
                        ensure_native_deployment_inactive_locked(
                            descriptor, install_root, expected_uid,
                            selector_release_id=(
                                bound.arguments.get(
                                    "expected_current_release_id")
                                if controller_fence else None
                            ),
                        )
                    return function(*args, **kwargs)
            finally:
                _HOST_MUTATION_LOCK.reset(token)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

        return wrapped
    return decorate


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
    reject_extended_acl(
        directory_descriptor, "install_transition_record_untrusted",
    )
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
        reject_extended_acl(descriptor, "install_transition_record_untrusted")
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
    reject_extended_acl(
        directory_descriptor, "install_transition_record_untrusted",
    )
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
        reject_extended_acl(descriptor, "install_transition_record_untrusted")
        write_all(descriptor, raw, "install_transition_record")
        os.fsync(descriptor)
        reject_extended_acl(descriptor, "install_transition_record_untrusted")
    finally:
        os.close(descriptor)
    renameatx_np = getattr(_ACL_LIBC, "renameatx_np", None)
    if renameatx_np is None:
        try:
            os.unlink(temporary, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        raise ReleaseFailure("install_transition_atomic_publish_unavailable")
    renameatx_np.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx_np.restype = ctypes.c_int
    if renameatx_np(
        directory_descriptor, os.fsencode(temporary),
        directory_descriptor, os.fsencode(name),
        0x00000004 | 0x00000010 | 0x00000020,
    ) != 0:
        error = ctypes.get_errno()
        try:
            os.unlink(temporary, dir_fd=directory_descriptor)
            os.fsync(directory_descriptor)
        except FileNotFoundError:
            pass
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), name)
        raise ReleaseFailure("install_transition_atomic_publish_failed") \
            from OSError(error, os.strerror(error), name)
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
    reject_extended_acl(
        directory_descriptor, "install_transition_record_untrusted",
    )
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
        reject_extended_acl(descriptor, "install_transition_record_untrusted")
        write_all(descriptor, raw, "install_transition_record")
        os.fsync(descriptor)
        reject_extended_acl(descriptor, "install_transition_record_untrusted")
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
    reject_extended_acl(
        install_root_descriptor, "install_transition_directory_untrusted",
    )
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
    reject_extended_acl(
        descriptor, "install_transition_directory_untrusted",
    )
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or info.st_gid != parent.st_gid or mode & ~0o755):
        os.close(descriptor)
        raise ReleaseFailure("install_transition_directory_untrusted")
    if mode != 0o755:
        os.fchmod(descriptor, 0o755)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        reject_extended_acl(
            descriptor, "install_transition_directory_untrusted",
        )
        if stat.S_IMODE(info.st_mode) != 0o755:
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
                reject_extended_acl(
                    descriptor, "install_transition_terminal_conflict",
                )
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
            reject_extended_acl(
                pending_descriptor, "install_transition_terminal_conflict",
            )
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


def install_touchid_service(
    release: Path,
    plist_path: Path = DEFAULT_AUTHORIZATION_PLIST,
    *,
    activate: bool = True,
) -> None:
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
    if not activate:
        return
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
    *,
    post_bootout_fence: Callable[[], None] | None = None,
) -> None:
    uid = console_user_uid() if uid is None else uid
    stop_launchd_service_exact(
        f"gui/{uid}", NATIVE_CREDENTIAL_HELPER_LABEL, plist_path,
        post_bootout_fence=post_bootout_fence,
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


def host_pair_transition_checkpoint(name: str) -> None:
    """Test seam around each durable release/launcher pair state."""
    if name not in {
        "PREPARED", "PUBLIC_PENDING", "SERVICES_FENCED",
        "LAUNCHER_SELECTED", "PREVIOUS_SELECTED", "RELEASE_SELECTED",
        "SERVICES_SELECTED", "FINALIZATION_STAGED", "TERMINAL_PUBLISHED",
        "STABLE_PUBLISHED",
    }:
        raise ReleaseFailure("host_pair_transition_checkpoint_invalid")


def native_coordination_bootstrap_checkpoint(name: str) -> None:
    """Test seam around the irreversible coordination-floor transition."""
    if not isinstance(name, str) or not name:
        raise ReleaseFailure("native_coordination_bootstrap_transition_invalid")


def native_host_candidate_bootstrap_checkpoint(name: str) -> None:
    """Test seam around irreversible candidate-admission publication."""
    if not isinstance(name, str) or not name:
        raise ReleaseFailure("native_host_candidate_transition_invalid")


def native_host_candidate_authority_checkpoint(name: str) -> None:
    """Test seam around per-release candidate-authority publication."""
    if not isinstance(name, str) or not name:
        raise ReleaseFailure("native_host_candidate_authority_transition_invalid")


def developer_id_team_enforcement_checkpoint(name: str) -> None:
    """Test seam around public Developer-ID enforcement publication."""
    if not isinstance(name, str) or not name:
        raise ReleaseFailure("developer_id_team_enforcement_transition_invalid")


def developer_id_team_floor_checkpoint(name: str) -> None:
    """Test seam around private Developer-ID floor publication."""
    if not isinstance(name, str) or not name:
        raise ReleaseFailure("developer_id_team_floor_transition_invalid")


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


def launchd_service_snapshot(
    domain: str, label: str,
) -> tuple[str, int | None, str]:
    """Capture and classify one bounded, exact launchd job snapshot."""
    target = f"{domain}/{label}"
    inspected = subprocess.run(
        ["/bin/launchctl", "print", target],
        check=False, capture_output=True, text=True,
    )
    if (len(inspected.stdout) > 512 * 1024
            or len(inspected.stderr) > 64 * 1024):
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    # launchctl maps the absent-service bootstrap error to EX_UNAVAILABLE.
    # No other nonzero result is safe to interpret as absence.
    if inspected.returncode == 113:
        return "absent", None, ""
    if inspected.returncode != 0:
        raise ReleaseFailure(f"host_service_state_unproven:{label}")

    lines = inspected.stdout.splitlines()
    header = f"{target} = {{"
    if (not lines or lines[0] != header
            or sum(line == header for line in lines) != 1):
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    pid_lines = re.findall(
        r"(?m)^\tpid[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$", inspected.stdout,
    )
    active_counts = re.findall(
        r"(?m)^\tactive count[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$",
        inspected.stdout,
    )
    states = re.findall(
        r"(?m)^\tstate[ \t]*=[ \t]*([^\r\n]+?)[ \t]*$",
        inspected.stdout,
    )
    if len(active_counts) != 1 or len(states) != 1:
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    if re.fullmatch(r"0|[1-9][0-9]{0,18}", active_counts[0]) is None:
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    active_count = int(active_counts[0])
    state = states[0]
    if not pid_lines:
        if active_count == 0 and state == "not running":
            return "inactive", None, inspected.stdout
        # A KeepAlive job whose last process failed can be registered with
        # launchd, have no live PID, and sit at its exact retry boundary.  It
        # is neither inactive authority nor a running process.  Preserve that
        # distinction so verification paths reject it, while the exact
        # service-stop path can boot out the registered job and independently
        # prove launchd absence before proceeding.
        if active_count == 0 and state == "spawn scheduled":
            return "scheduled", None, inspected.stdout
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    if (len(pid_lines) != 1
            or re.fullmatch(r"[1-9][0-9]{0,9}", pid_lines[0]) is None
            or active_count < 1 or state != "running"):
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    pid = int(pid_lines[0])
    if pid > 2_147_483_647:
        raise ReleaseFailure(f"host_service_state_unproven:{label}")
    return "running", pid, inspected.stdout


def launchd_service_state(
    domain: str, label: str,
) -> tuple[str, int | None]:
    """Classify one exact launchd job as absent, inactive, scheduled, or running."""
    state, pid, _snapshot = launchd_service_snapshot(domain, label)
    return state, pid


def launchd_service_pid_or_absent(domain: str, label: str) -> int | None:
    """Read one exact running PID or launchd's exact absent result."""
    state, pid = launchd_service_state(domain, label)
    if state == "absent":
        return None
    if state != "running" or pid is None:
        raise ReleaseFailure(f"host_service_pid_unproven:{label}")
    return pid


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


def process_status_generation_or_absent(
    pid: int, label: str,
) -> tuple[int, int, int, int] | None:
    """Read status plus generation from one Darwin proc_bsdinfo record."""
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
            f"host_service_process_unproven:{label}") from error
    if length == 0:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return None
        except OSError as error:
            raise ReleaseFailure(
                f"host_service_process_unproven:{label}") from error
        raise ReleaseFailure(f"host_service_process_unproven:{label}")
    if (
        length != size or information.pbi_pid != pid
        or information.pbi_status not in {1, 2, 3, 4, 5}
        or information.pbi_start_tvsec <= 0
        or information.pbi_start_tvusec >= 1_000_000
    ):
        raise ReleaseFailure(f"host_service_process_unproven:{label}")
    return (
        int(information.pbi_uid),
        int(information.pbi_start_tvsec),
        int(information.pbi_start_tvusec),
        int(information.pbi_status),
    )


def process_child_pids(pid: int, label: str) -> tuple[int, ...]:
    """List every direct child while the caller keeps the parent stopped."""
    capacity = 64
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = libproc.proc_listchildpids
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        function.restype = ctypes.c_int
    except (OSError, AttributeError) as error:
        raise ReleaseFailure(
            f"host_service_children_unproven:{label}") from error

    def snapshot() -> tuple[int, ...]:
        children = (ctypes.c_int * capacity)()
        count = function(pid, children, ctypes.sizeof(children))
        if count < 0 or count >= capacity:
            raise ReleaseFailure(
                f"host_service_children_unproven:{label}")
        values = tuple(int(children[index]) for index in range(count))
        if (
            len(set(values)) != len(values)
            or any(child <= 1 or child == pid for child in values)
        ):
            raise ReleaseFailure(
                f"host_service_children_unproven:{label}")
        return tuple(sorted(values))

    first = snapshot()
    second = snapshot()
    if first != second:
        raise ReleaseFailure(f"host_service_children_unproven:{label}")
    return second


def process_ids(label: str, expected_uid: int) -> tuple[int, ...]:
    """Return one capacity-checked Darwin same-UID process snapshot."""
    capacity = 65_536
    processes = (ctypes.c_int * capacity)()
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = libproc.proc_listpids
        function.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_int,
        ]
        function.restype = ctypes.c_int
        length = function(
            4, expected_uid, processes, ctypes.sizeof(processes))
    except (OSError, AttributeError) as error:
        raise ReleaseFailure(
            f"host_service_process_inventory_unproven:{label}") from error
    width = ctypes.sizeof(ctypes.c_int)
    if (
        length < 0 or length >= ctypes.sizeof(processes)
        or length % width != 0
    ):
        raise ReleaseFailure(
            f"host_service_process_inventory_unproven:{label}")
    values = tuple(
        int(processes[index]) for index in range(length // width)
        if int(processes[index]) > 1
    )
    if len(set(values)) != len(values):
        raise ReleaseFailure(
            f"host_service_process_inventory_unproven:{label}")
    return tuple(sorted(values))


def d8653cb_release_processes(
    release: Path, install_root: Path, expected_uid: int, *,
    extra_aliases: tuple[Path, ...] = (),
) -> tuple[tuple[int, int, int], ...]:
    """Find live processes whose executable or argv binds the old release."""
    try:
        selected = release.resolve(strict=True)
    except OSError as error:
        raise ReleaseFailure(
            "native_coordination_legacy_process_inventory_unproven"
        ) from error
    aliases = (
        selected,
        install_root / "current",
        install_root / NATIVE_STACK_COORDINATION_PREDECESSOR_NAME,
        *extra_aliases,
    )
    relative_extra_alias_names = {
        alias.name for alias in extra_aliases
        if alias.is_absolute() and alias.name
    }

    def inside(value: str) -> bool:
        if "\x00" in value:
            return False
        path = Path(value)
        if not path.is_absolute():
            # A script launched through a relative spelling is reported by
            # KERN_PROCARGS2 exactly as invoked even though the kernel executes
            # the interpreter.  Only the explicitly supplied stable-launcher
            # aliases receive this basename treatment; historical release
            # aliases retain their exact absolute-path semantics.
            return path.name in relative_extra_alias_names
        if "\n" in value:
            return False
        candidates = [path]
        try:
            candidates.append(path.resolve(strict=False))
        except OSError:
            pass
        for candidate in candidates:
            for root in aliases:
                if candidate == root or root in candidate.parents:
                    return True
        return False

    matches: list[tuple[int, int, int]] = []
    for pid in process_ids("d8653cb", expected_uid):
        before = process_status_generation_or_absent(pid, "d8653cb")
        if before is None or before[0] != expected_uid or before[3] == 5:
            continue
        try:
            executable = process_executable_path(pid, "d8653cb")
            arguments = process_arguments_inventory(pid, "d8653cb")
        except ReleaseFailure as error:
            after = process_status_generation_or_absent(pid, "d8653cb")
            # A process can exit after the generation readback but before
            # proc_pidpath or KERN_PROCARGS2.  Darwin may retain that exact
            # generation briefly as a zombie, whose vnode/argv inventory is
            # no longer available and whose code cannot execute.  Treat only
            # that terminal state (or absence/generation change) as a benign
            # race; a still-live unchanged generation remains fail-closed.
            if (after is None or after[:3] != before[:3]
                    or after[3] == 5):
                continue
            raise ReleaseFailure(
                "native_coordination_legacy_process_inventory_unproven"
            ) from error
        after = process_status_generation_or_absent(pid, "d8653cb")
        if after is None or after[:3] != before[:3]:
            continue
        if inside(executable) or any(inside(argument) for argument in arguments):
            matches.append((pid, before[1], before[2]))
    return tuple(sorted(matches))


def ensure_no_d8653cb_release_processes(
    release: Path, install_root: Path, expected_uid: int, *,
    extra_aliases: tuple[Path, ...] = (),
) -> None:
    """Repeat the system-wide exact-release process absence proof."""
    first = d8653cb_release_processes(
        release, install_root, expected_uid,
        extra_aliases=extra_aliases,
    )
    second = d8653cb_release_processes(
        release, install_root, expected_uid,
        extra_aliases=extra_aliases,
    )
    if first or second:
        raise ReleaseFailure("native_coordination_legacy_operation_active")


def stop_launchd_service_exact(
    domain: str,
    label: str,
    plist_path: Path,
    *,
    timeout: float = HOST_SERVICE_STOP_TIMEOUT_SECONDS,
    post_bootout_fence: Callable[[], None] | None = None,
) -> None:
    """Boot out one service and prove its captured process generation is gone."""
    service_state, pid = launchd_service_state(domain, label)
    generation: tuple[int, int, int] | None = None
    booted_out = False
    if service_state == "running":
        if pid is None:
            raise ReleaseFailure(f"host_service_state_unproven:{label}")
        generation = process_generation(pid, label)
        if launchd_service_state(domain, label) != ("running", pid):
            raise ReleaseFailure(f"host_service_process_changed:{label}")
    if service_state != "absent":
        stopped = subprocess.run(
            ["/bin/launchctl", "bootout", f"{domain}/{label}"],
            check=False, capture_output=True, text=True,
        )
        if (stopped.returncode != 0 or len(stopped.stdout) > 64 * 1024
                or len(stopped.stderr) > 64 * 1024):
            raise ReleaseFailure(f"host_service_bootout_failed:{label}")
        booted_out = True

        deadline = time.monotonic() + timeout
        while True:
            observed_state, _observed_pid = launchd_service_state(
                domain, label,
            )
            observed_generation = (
                None if generation is None or pid is None
                else process_generation_or_absent(pid, label)
            )
            if (observed_state == "absent"
                    and (generation is None
                         or observed_generation is None
                         or observed_generation != generation)):
                break
            if time.monotonic() >= deadline:
                raise ReleaseFailure(f"host_service_exit_unproven:{label}")
            time.sleep(HOST_SERVICE_STOP_POLL_SECONDS)
        if launchd_service_state(domain, label) != ("absent", None):
            raise ReleaseFailure(f"host_service_state_changed:{label}")
    elif launchd_service_state(domain, label) != ("absent", None):
        raise ReleaseFailure(f"host_service_state_changed:{label}")

    if booted_out and post_bootout_fence is not None:
        post_bootout_fence()

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


def process_arguments_inventory(pid: int, label: str) -> list[str]:
    """Decode argc/argv for inventory, preserving every legal argument."""
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
    if not arguments:
        raise ReleaseFailure(f"host_service_process_unproven:{label}")
    return arguments


def process_arguments(pid: int, label: str) -> list[str]:
    """Read the strict launchd-service argc/argv identity."""
    arguments = process_arguments_inventory(pid, label)
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


def _launchd_top_level_value(
    snapshot: str, name: str, label: str,
) -> str:
    values = re.findall(
        rf"(?m)^\t{re.escape(name)}[ \t]*=[ \t]*"
        r"([^\r\n]*?)[ \t]*$", snapshot,
    )
    if len(values) != 1 or not values[0]:
        raise ReleaseFailure(f"host_service_definition_unproven:{label}")
    return values[0]


def _launchd_optional_top_level_value(
    snapshot: str, name: str, label: str,
) -> str | None:
    values = re.findall(
        rf"(?m)^\t{re.escape(name)}[ \t]*=[ \t]*"
        r"([^\r\n]*?)[ \t]*$", snapshot,
    )
    if (len(values) > 1 or values and re.fullmatch(
            r"[ -~]{1,240}", values[0],
    ) is None):
        raise ReleaseFailure(f"host_service_definition_unproven:{label}")
    return None if not values else values[0]


def inactive_launchd_service_definition(
    snapshot: str, domain: str, label: str, *,
    expected_plist: Path, expected_program: str,
) -> dict[str, Any]:
    """Prove the loaded definition of one exact demand-only LaunchAgent."""
    failure = f"host_service_definition_unproven:{label}"
    path = _launchd_top_level_value(snapshot, "path", label)
    service_type = _launchd_top_level_value(snapshot, "type", label)
    program = _launchd_top_level_value(snapshot, "program", label)
    loaded_domain = _launchd_top_level_value(snapshot, "domain", label)
    asid = _launchd_top_level_value(snapshot, "asid", label)
    spawn_type = _launchd_top_level_value(snapshot, "spawn type", label)
    last_exit_code = _launchd_optional_top_level_value(
        snapshot, "last exit code", label,
    )
    job_state = _launchd_optional_top_level_value(
        snapshot, "job state", label,
    )
    run_values = re.findall(
        r"(?m)^\truns[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$", snapshot,
    )
    if (len(run_values) > 1 or run_values and re.fullmatch(
            r"0|[1-9][0-9]{0,18}", run_values[0],
    ) is None):
        raise ReleaseFailure(failure)
    runs = None if not run_values else int(run_values[0])
    domain_match = re.fullmatch(
        re.escape(domain) + r" \[([1-9][0-9]{0,18})\]", loaded_domain,
    )
    if (path != str(expected_plist)
            or service_type != "LaunchAgent"
            or program != expected_program
            or domain_match is None
            or asid != domain_match.group(1)
            or spawn_type != "interactive (4)"):
        raise ReleaseFailure(failure)

    argument_headers = re.findall(
        r"(?m)^\targuments[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$", snapshot,
    )
    argument_blocks = re.findall(
        r"(?m)^\targuments[ \t]*=[ \t]*\{[ \t]*$\n"
        r"((?:\t\t[^\r\n]*\r?\n)*)^\t\}[ \t]*$",
        snapshot,
    )
    if len(argument_headers) != 1 or argument_headers != ["{"] \
            or len(argument_blocks) != 1:
        raise ReleaseFailure(failure)
    arguments = [
        line[2:] for line in argument_blocks[0].splitlines()
    ]
    if arguments != [expected_program]:
        raise ReleaseFailure(failure)

    endpoints_headers = re.findall(
        r"(?m)^\tendpoints[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$", snapshot,
    )
    endpoints_blocks = re.findall(
        r"(?m)^\tendpoints[ \t]*=[ \t]*\{[ \t]*$\n"
        r"((?:(?:\t\t|\t\t\t)[^\r\n]*\r?\n)*)^\t\}[ \t]*$",
        snapshot,
    )
    if len(endpoints_headers) != 1 or endpoints_headers != ["{"] \
            or len(endpoints_blocks) != 1:
        raise ReleaseFailure(failure)
    endpoint_name = json.dumps(label)
    endpoint_match = re.fullmatch(
        rf"\t\t{re.escape(endpoint_name)}[ \t]*=[ \t]*\{{[ \t]*\r?\n"
        r"((?:\t\t\t[^\r\n]*\r?\n)*)\t\t\}[ \t]*\r?\n?",
        endpoints_blocks[0],
    )
    if endpoint_match is None:
        raise ReleaseFailure(failure)
    endpoint = endpoint_match.group(1)
    active = re.findall(
        r"(?m)^\t\t\tactive[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$", endpoint,
    )
    managed = re.findall(
        r"(?m)^\t\t\tmanaged[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$", endpoint,
    )
    if active != ["0"] or managed != ["1"]:
        raise ReleaseFailure(failure)
    return {
        "arguments": arguments,
        "asid": int(asid),
        "domain": domain,
        "endpoint": {
            "active": 0, "managed": 1, "name": label,
        },
        "job_state": job_state,
        "last_exit_code": last_exit_code,
        "path": path,
        "program": program,
        "runs": runs,
        "spawn_type": spawn_type,
        "type": service_type,
    }


def inactive_native_credential_identity(
    release: Path, native_uid: int, native_manifest: Mapping[str, Any],
    first_snapshot: str,
) -> dict[str, Any]:
    """Attest an idle demand-only helper without inventing a live PID."""
    label = NATIVE_CREDENTIAL_HELPER_LABEL
    domain = f"gui/{native_uid}"
    expected_program = NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH
    expected_executable = (
        release / NATIVE_CREDENTIAL_HELPER_APP_NAME
        / NATIVE_CREDENTIAL_HELPER_EXECUTABLE
    )
    expected_bundle = release / NATIVE_CREDENTIAL_HELPER_APP_NAME
    manifest_path = NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix()
    executable_record = native_manifest.get("helper", {}).get(
        "files", {},
    ).get(manifest_path)
    if not isinstance(executable_record, dict):
        raise ReleaseFailure("native_credential_helper_manifest_invalid")

    first_definition = inactive_launchd_service_definition(
        first_snapshot, domain, label,
        expected_plist=DEFAULT_NATIVE_CREDENTIAL_PLIST,
        expected_program=expected_program,
    )
    expected_service = read_regular(
        release / "native_credential_helper_service"
    )
    installed_service = read_acl_free_regular(
        DEFAULT_NATIVE_CREDENTIAL_PLIST, 0, 0o444,
        "native_credential_service_install_untrusted", maximum=1024 * 1024,
    )
    if installed_service != expected_service:
        raise ReleaseFailure("native_credential_service_install_mismatch")
    try:
        selected_before = Path(expected_program).resolve(strict=True)
        executable_before = expected_executable.resolve(strict=True)
    except OSError as error:
        raise ReleaseFailure(
            "native_credential_service_selector_unproven"
        ) from error
    if selected_before != executable_before:
        raise ReleaseFailure("native_credential_service_selector_mismatch")
    executable = read_acl_free_regular(
        expected_executable, 0, int(executable_record.get("mode", -1)),
        "native_credential_helper_executable_untrusted",
        maximum=256 * 1024 * 1024,
    )
    executable_sha256 = sha256_bytes(executable)
    if (len(executable) != executable_record.get("size")
            or executable_sha256 != executable_record.get("sha256")):
        raise ReleaseFailure("native_credential_helper_executable_mismatch")
    team_id = native_manifest.get("signing_policy", {}).get("team_id")
    if (not isinstance(team_id, str)
            or re.fullmatch(r"[A-Z0-9]{10}", team_id) is None):
        raise ReleaseFailure("native_credential_helper_manifest_invalid")
    verify_native_component_signature(expected_bundle, label, team_id)

    installed_service_after = read_acl_free_regular(
        DEFAULT_NATIVE_CREDENTIAL_PLIST, 0, 0o444,
        "native_credential_service_install_untrusted", maximum=1024 * 1024,
    )
    executable_after = read_acl_free_regular(
        expected_executable, 0, int(executable_record.get("mode", -1)),
        "native_credential_helper_executable_untrusted",
        maximum=256 * 1024 * 1024,
    )
    try:
        selected_after = Path(expected_program).resolve(strict=True)
        executable_after_path = expected_executable.resolve(strict=True)
    except OSError as error:
        raise ReleaseFailure(
            "native_credential_service_selector_unproven"
        ) from error
    second_state, second_pid, second_snapshot = launchd_service_snapshot(
        domain, label,
    )
    if second_state != "inactive" or second_pid is not None:
        raise ReleaseFailure(f"host_service_state_changed:{label}")
    second_definition = inactive_launchd_service_definition(
        second_snapshot, domain, label,
        expected_plist=DEFAULT_NATIVE_CREDENTIAL_PLIST,
        expected_program=expected_program,
    )
    if (installed_service_after != expected_service
            or executable_after != executable
            or selected_after != selected_before
            or executable_after_path != executable_before
            or second_definition != first_definition):
        raise ReleaseFailure(f"host_service_definition_changed:{label}")
    return {
        "arguments": [expected_program],
        "attestation_mode": "inactive-static",
        "launchd_uid": native_uid,
        "executable": expected_program,
        "executable_sha256": executable_sha256,
        "launchd": first_definition,
        "service_plist_sha256": sha256_bytes(expected_service),
        "signing_identifier": label,
        "signing_team_id": team_id,
        "state": "inactive",
    }


def stop_and_fence_host_services(native_uid: int) -> None:
    stop_touchid_service()
    stop_native_credential_service(uid=native_uid)
    if (launchd_service_pid_or_absent("system", AUTHORIZATION_LABEL) is not None
            or launchd_service_pid_or_absent(
                f"gui/{native_uid}", NATIVE_CREDENTIAL_HELPER_LABEL,
            ) is not None):
        raise ReleaseFailure("host_service_fence_unproven")


def stop_and_fence_d8653cb_host_services(
    native_uid: int, release: Path, manifest: Mapping[str, Any], *,
    expected_release_id: str | None = None,
    expected_broker_sha256: str | None = None,
) -> None:
    """Fence the historical broker without stranding a detached operation.

    d8653cb's exact broker is sequential, but each privileged operation starts
    a new session.  launchd bootout therefore cannot prove that an already
    spawned promoter or deployer exited with the broker.  Stop the exact
    broker first, prove it reached Darwin SSTOP, and take a direct-child
    snapshot while it cannot fork.  A child (including a forked pre-exec
    child) makes migration fail closed and the broker is resumed so that the
    operation can finish before an operator retries.
    """
    if expected_release_id is None:
        expected_release_id = "d8653cb"
        expected_broker_sha256 = (
            D8653CB_NATIVE_COORDINATION_PAYLOAD_SHA256[
                "authorization_broker"
            ]
        )
    if (not isinstance(expected_release_id, str)
            or expected_broker_sha256 is None
            or SHA256.fullmatch(expected_broker_sha256) is None):
        raise ReleaseFailure("native_coordination_legacy_broker_invalid")
    broker_sha256 = manifest.get("payloads", {}).get("authorization_broker")
    if (
        broker_sha256 != expected_broker_sha256
        or release.name != manifest.get("release_id")
        or (expected_release_id == "d8653cb"
            and not is_d8653cb_native_coordination_predecessor(manifest))
        or (expected_release_id != "d8653cb"
            and release.name != expected_release_id)
    ):
        raise ReleaseFailure("native_coordination_legacy_broker_invalid")
    def signal_service(signal_name: str) -> None:
        signaled = subprocess.run(
            [
                "/bin/launchctl", "kill", signal_name,
                f"system/{AUTHORIZATION_LABEL}",
            ],
            check=False, capture_output=True, text=True,
        )
        if (
            signaled.returncode != 0
            or len(signaled.stdout) > 64 * 1024
            or len(signaled.stderr) > 64 * 1024
        ):
            raise ReleaseFailure(
                "native_coordination_legacy_broker_signal_failed:"
                + signal_name)

    suspended: tuple[int, tuple[int, int, int]] | None = None
    try:
        pid = launchd_service_pid_or_absent(
            "system", AUTHORIZATION_LABEL)
        if pid is not None:
            live = verify_release_authorization_service(release, manifest)
            generation = (
                live["euid"],
                live["start_generation"][0],
                live["start_generation"][1],
            )
            if live.get("pid") != pid or generation[0] != 0:
                raise ReleaseFailure(
                    "native_coordination_legacy_broker_invalid")
            suspended = (pid, generation)
            signal_service("SIGSTOP")
            deadline = time.monotonic() + HOST_SERVICE_STOP_TIMEOUT_SECONDS
            while True:
                observed = process_status_generation_or_absent(
                    pid, AUTHORIZATION_LABEL)
                if observed is None or observed[:3] != generation:
                    raise ReleaseFailure(
                        "native_coordination_legacy_broker_changed")
                # Darwin sys/proc.h SSTOP.
                if observed[3] == 4:
                    break
                if time.monotonic() >= deadline:
                    raise ReleaseFailure(
                        "native_coordination_legacy_broker_suspend_unproven")
                time.sleep(HOST_SERVICE_STOP_POLL_SECONDS)
            if launchd_service_pid_or_absent(
                "system", AUTHORIZATION_LABEL) != pid:
                raise ReleaseFailure(
                    "native_coordination_legacy_broker_changed")
            children = process_child_pids(pid, AUTHORIZATION_LABEL)
            observed = process_status_generation_or_absent(
                pid, AUTHORIZATION_LABEL)
            if (
                observed is None or observed[:3] != generation
                or observed[3] != 4
                or launchd_service_pid_or_absent(
                    "system", AUTHORIZATION_LABEL) != pid
            ):
                raise ReleaseFailure(
                    "native_coordination_legacy_broker_changed")
            if children:
                raise ReleaseFailure(
                    "native_coordination_legacy_operation_active")
        stop_touchid_service()
        suspended = None
        ensure_no_d8653cb_release_processes(
            release, release.parent.parent, 0)

        def fence_native_credential_processes() -> None:
            ensure_no_d8653cb_release_processes(
                release, release.parent.parent, native_uid,
            )

        stop_native_credential_service(
            uid=native_uid,
            post_bootout_fence=fence_native_credential_processes,
        )
        # Replay the same census when a prior fail-closed attempt already
        # booted out the job before it could remove the bound plist.
        fence_native_credential_processes()
        if (
            launchd_service_pid_or_absent(
                "system", AUTHORIZATION_LABEL) is not None
            or launchd_service_pid_or_absent(
                f"gui/{native_uid}", NATIVE_CREDENTIAL_HELPER_LABEL,
            ) is not None
        ):
            raise ReleaseFailure("host_service_fence_unproven")
    finally:
        if suspended is not None:
            pid, generation = suspended
            observed = process_generation_or_absent(
                pid, AUTHORIZATION_LABEL)
            if observed != generation:
                raise ReleaseFailure(
                    "native_coordination_legacy_broker_resume_failed")
            signal_service("SIGCONT")
            deadline = (
                time.monotonic() + HOST_SERVICE_STOP_TIMEOUT_SECONDS)
            while True:
                status = process_status_generation_or_absent(
                    pid, AUTHORIZATION_LABEL)
                if (
                    status is not None and status[:3] == generation
                    and status[3] != 4
                    and launchd_service_pid_or_absent(
                        "system", AUTHORIZATION_LABEL) == pid
                ):
                    break
                if (
                    status is None or status[:3] != generation
                    or time.monotonic() >= deadline
                ):
                    raise ReleaseFailure(
                        "native_coordination_legacy_broker_resume_failed")
                time.sleep(HOST_SERVICE_STOP_POLL_SECONDS)


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
    if LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES <= payloads:
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
    *,
    allow_inactive_native: bool = False,
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

    if LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES <= payloads:
        native_manifest = native_components_manifest(
            read_regular(release / "native_credential_helper_bundle")
        )
        if allow_inactive_native:
            state, pid, snapshot = launchd_service_snapshot(
                f"gui/{native_uid}", NATIVE_CREDENTIAL_HELPER_LABEL,
            )
            if state == "inactive" and pid is None:
                result["native_credential"] = (
                    inactive_native_credential_identity(
                        release, native_uid, native_manifest, snapshot,
                    )
                )
                return result
            if state != "running" or pid is None:
                raise ReleaseFailure(
                    f"host_service_not_loaded:{NATIVE_CREDENTIAL_HELPER_LABEL}"
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


def attest_pending_source_host_services(
    release: Path,
    manifest: Mapping[str, Any],
    native_uid: int,
) -> dict[str, Any]:
    """Attest exact inactive definitions while the pair fence is pending.

    A broker from an immutable predecessor cannot remain live while its own
    pair transition is pending: startup correctly attempts replay, but that
    replay cannot take the mutation fence held by the restoring manager.  The
    recovery path therefore proves the exact source definitions and binaries
    while launchd authority is absent, publishes only the already-journaled
    source restoration, and starts plus independently verifies both services
    after the public pending fence is gone.
    """
    if launchd_service_state(
        "system", AUTHORIZATION_LABEL,
    ) != ("absent", None):
        raise ReleaseFailure(
            f"host_service_state_changed:{AUTHORIZATION_LABEL}"
        )
    expected_service = read_regular(release / "authorization_service")
    installed_service = read_acl_free_regular(
        DEFAULT_AUTHORIZATION_PLIST, 0, 0o644,
        "authorization_service_install_untrusted", maximum=1024 * 1024,
    )
    broker = read_acl_free_regular(
        release / "authorization_broker", 0,
        EXPECTED_MODES["authorization_broker"],
        "authorization_broker_untrusted", maximum=2 * 1024 * 1024,
    )
    broker_sha256 = sha256_bytes(broker)
    if (installed_service != expected_service
            or broker_sha256
                != manifest.get("payloads", {}).get("authorization_broker")):
        raise ReleaseFailure("authorization_service_binding_invalid")
    result: dict[str, Any] = {
        "authorization": {
            "attestation_mode": "pending-transition-static",
            "executable": str(release / "authorization_broker"),
            "executable_sha256": broker_sha256,
            "launchd_domain": "system",
            "service_plist_sha256": sha256_bytes(expected_service),
            "signing_identifier": AUTHORIZATION_LABEL,
            "state": "absent",
        },
    }
    payloads = set(manifest.get("payloads", {}))
    if LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES <= payloads:
        state, pid, snapshot = launchd_service_snapshot(
            f"gui/{native_uid}", NATIVE_CREDENTIAL_HELPER_LABEL,
        )
        if state != "inactive" or pid is not None:
            raise ReleaseFailure(
                f"host_service_state_changed:{NATIVE_CREDENTIAL_HELPER_LABEL}"
            )
        native_manifest = native_components_manifest(
            read_regular(release / "native_credential_helper_bundle")
        )
        result["native_credential"] = inactive_native_credential_identity(
            release, native_uid, native_manifest, snapshot,
        )
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
    root = open_locked_install_root(install_root, expected_uid)
    try:
        write_new_state_record_at(
            root, INSTALL_TRANSITION_PENDING_NAME, validated,
            expected_uid, 0o600,
        )
    finally:
        os.close(root)
    return validated


def host_pair_transition_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_state_record({
        name: item for name, item in value.items()
        if name not in {"finalization", "terminal", "transition_sha256"}
    }))


def host_pair_terminal_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_state_record({
        name: item for name, item in value.items()
        if name != "terminal_sha256"
    }))


def host_pair_finalization_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_state_record({
        name: item for name, item in value.items()
        if name != "finalization_sha256"
    }))


def validate_host_pair_finalization(
    value: object, transition: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "status", "committed_pair", "completed_at",
        "service_evidence", "service_evidence_sha256", "error",
        "finalization_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("host_pair_finalization_invalid")
    if (value.get("schema")
            != "secure-sandbox-host-pair-finalization-v1"
            or value.get("status") not in {
                "target_committed", "source_restored",
            }
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value.get("completed_at"), bool)
            or value["completed_at"] < transition["created_at"]
            or SHA256.fullmatch(str(value.get(
                "service_evidence_sha256"))) is None
            or (value.get("error") is not None and (
                not isinstance(value["error"], str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value["error"])
                    is None
            ))
            or host_pair_finalization_digest(value)
                != value.get("finalization_sha256")):
        raise ReleaseFailure("host_pair_finalization_invalid")
    committed = validate_host_release_launcher_pair_identity(
        value.get("committed_pair")
    )
    evidence = validate_host_pair_service_evidence(
        value.get("service_evidence"), transition, committed,
    )
    expected = (
        transition["target_pair"]
        if value["status"] == "target_committed"
        else transition["source_pair"]
    )
    expected = None if expected is None else {
        name: expected[name] for name in (
            "candidate_authority_sha256", "launcher_sha256", "release_id",
            "release_tree_identity_sha256",
        )
    }
    if (expected is None
            or {name: committed[name] for name in expected} != expected
            or (value["status"] == "target_committed"
                and value["error"] is not None)
            or (value["status"] == "source_restored"
                and value["error"] is None)
            or sha256_bytes(canonical_state_record(evidence))
                != value["service_evidence_sha256"]):
        raise ReleaseFailure("host_pair_finalization_invalid")
    result = {name: value[name] for name in sorted(fields)}
    result["committed_pair"] = committed
    result["service_evidence"] = evidence
    return result


def validate_host_pair_terminal(
    value: object, transition: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "status", "operation", "transition_id",
        "transition_sha256", "committed_pair", "authorization_request_id",
        "authorization_request_sha256", "authorized_target_plan_sha256",
        "completed_at", "service_evidence", "service_evidence_sha256", "error",
        "authorization_receipt_sha256", "finalization_sha256",
        "terminal_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("host_pair_terminal_invalid")
    if (value.get("schema") != HOST_PAIR_TERMINAL_SCHEMA
            or value.get("status") not in {
                "target_committed", "source_restored",
            }
            or value.get("operation") != transition["operation"]
            or value.get("transition_id") != transition["transition_id"]
            or value.get("transition_sha256")
                != transition["transition_sha256"]
            or value.get("authorization_request_id")
                != transition["authorization_request_id"]
            or value.get("authorization_request_sha256")
                != transition["authorization_request_sha256"]
            or value.get("authorized_target_plan_sha256")
                != transition["authorized_target_plan_sha256"]
            or value.get("finalization_sha256")
                != transition["finalization"]["finalization_sha256"]
            or not isinstance(value.get("completed_at"), int)
            or isinstance(value.get("completed_at"), bool)
            or value["completed_at"] < transition["created_at"]
            or SHA256.fullmatch(str(value.get(
                "service_evidence_sha256"))) is None
            or (value.get("error") is not None and (
                not isinstance(value["error"], str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value["error"])
                    is None
            ))
            or host_pair_terminal_digest(value)
                != value.get("terminal_sha256")):
        raise ReleaseFailure("host_pair_terminal_invalid")
    receipt_sha256 = value.get("authorization_receipt_sha256")
    if ((transition["bootstrap"] and receipt_sha256 is not None)
            or (not transition["bootstrap"]
                and SHA256.fullmatch(str(receipt_sha256)) is None)):
        raise ReleaseFailure("host_pair_terminal_invalid")
    committed = validate_host_release_launcher_pair_identity(
        value.get("committed_pair")
    )
    evidence = validate_host_pair_service_evidence(
        value.get("service_evidence"), transition, committed,
    )
    expected_generation = (
        transition["target_pair"]
        if value["status"] == "target_committed"
        else transition["source_pair"]
    )
    expected_generation = (
        None if expected_generation is None
        else validate_host_release_launcher_pair_generation({
            name: expected_generation[name] for name in (
                "candidate_authority_sha256", "launcher_sha256",
                "release_id", "release_tree_identity_sha256",
            )
        })
    )
    if (expected_generation is None
            or {name: committed[name] for name in expected_generation}
                != expected_generation
            or (value["status"] == "target_committed"
                and value["error"] is not None)
            or (value["status"] == "source_restored"
                and value["error"] is None)
            or sha256_bytes(canonical_state_record(evidence))
                != value["service_evidence_sha256"]):
        raise ReleaseFailure("host_pair_terminal_invalid")
    result = {name: value[name] for name in sorted(fields)}
    result["committed_pair"] = committed
    result["service_evidence"] = evidence
    return result


def validate_host_pair_transition(value: object) -> dict[str, Any]:
    fields = {
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
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("host_pair_transition_invalid")
    _validated_uuid4(value.get("transition_id"), "host_pair_transition_id")
    created = value.get("created_at")
    expires = value.get("expires_at")
    bootstrap = value.get("bootstrap")
    if (value.get("schema") != HOST_PAIR_TRANSITION_SCHEMA
            or value.get("operation") not in {"install", "rollback"}
            or not isinstance(bootstrap, bool)
            or not isinstance(created, int) or isinstance(created, bool)
            or not isinstance(expires, int) or isinstance(expires, bool)
            or created < 0 or expires - created != INSTALL_TRANSITION_TTL_SECONDS
            or not isinstance(value.get("native_uid"), int)
            or isinstance(value.get("native_uid"), bool)
            or value["native_uid"] < -1
            or not isinstance(value.get("old_services"), dict)
            or not isinstance(value.get("target_pair"), dict)
            or (value.get("finalization") is not None
                and not isinstance(value["finalization"], dict))
            or (value.get("terminal") is not None
                and not isinstance(value["terminal"], dict))):
        raise ReleaseFailure("host_pair_transition_invalid")
    target = validate_host_release_launcher_pair_generation(
        value["target_pair"]
    )
    if bootstrap:
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
            raise ReleaseFailure("host_pair_transition_invalid")
        source = None
    else:
        if value.get("bootstrap_admission") is not None:
            raise ReleaseFailure("host_pair_transition_invalid")
        bootstrap_admission = None
        source = validate_host_release_launcher_pair_identity(
            value.get("source_pair")
        )
        if (SHA256.fullmatch(str(value.get("source_stable_sha256"))) is None
                or not isinstance(value.get("authorization_request_id"), str)
                or not isinstance(value.get(
                    "authorization_request_sha256"), str)
                or not isinstance(value.get(
                    "authorization_pending_receipt_sha256"), str)):
            raise ReleaseFailure("host_pair_transition_invalid")
        _validated_uuid4(
            value["authorization_request_id"], "authorization_request_id",
        )
        for name in (
            "authorization_request_sha256",
            "authorization_pending_receipt_sha256",
        ):
            if SHA256.fullmatch(value[name]) is None:
                raise ReleaseFailure("host_pair_transition_invalid")
    for name in (
        "transition_sha256", "authorized_target_plan_sha256",
        "target_candidate_authority_sha256",
        "target_launcher_generation_sha256", "old_services_sha256",
        "developer_id_team_floor_sha256",
    ):
        if SHA256.fullmatch(str(value.get(name))) is None:
            raise ReleaseFailure("host_pair_transition_invalid")
    if ((bootstrap
            and value.get("source_launcher_generation_sha256") is not None)
            or (not bootstrap and SHA256.fullmatch(str(value.get(
                "source_launcher_generation_sha256"))) is None)):
        raise ReleaseFailure("host_pair_transition_invalid")
    if (value["target_candidate_authority_sha256"]
            != target["candidate_authority_sha256"]
            or value["target_launcher_generation_sha256"]
                != target["launcher_sha256"]
            or (source is not None
                and value["source_launcher_generation_sha256"]
                    != source["launcher_sha256"])
            or value.get("old_current_target") != (
                None if source is None
                else f"releases/{source['release_id']}"
            )
            or (value.get("old_previous_target") is not None
                and re.fullmatch(
                    r"releases/[0-9a-f]{64}",
                    str(value["old_previous_target"]),
                ) is None)
            or sha256_bytes(canonical_state_record(value["old_services"]))
                != value["old_services_sha256"]
            or not isinstance(value.get("developer_id_team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["developer_id_team_id"])
                is None
            or host_pair_transition_digest(value)
                != value["transition_sha256"]):
        raise ReleaseFailure("host_pair_transition_invalid")
    result = {name: value[name] for name in sorted(fields)}
    result["bootstrap_admission"] = bootstrap_admission
    result["source_pair"] = source
    result["target_pair"] = target
    if value["finalization"] is not None:
        result["finalization"] = validate_host_pair_finalization(
            value["finalization"], result,
        )
    if value["terminal"] is not None and value["finalization"] is None:
        raise ReleaseFailure("host_pair_transition_invalid")
    if value["terminal"] is not None:
        result["terminal"] = validate_host_pair_terminal(
            value["terminal"], result,
        )
    return result


def authorization_receipt_for_host_pair(
    request_id: str, request_sha256: str, expected_uid: int,
    operation: str, authorized_target_plan_sha256: str,
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
    expected_operation = (
        "host-controller-install" if operation == "install"
        else "host-controller-rollback"
    )
    if (receipt.get("schema")
            != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != request_id
            or receipt.get("request_sha256") != request_sha256
            or receipt.get("operation") != expected_operation
            or receipt.get("host_pair_authorized_target_plan_sha256")
                != authorized_target_plan_sha256
            or receipt.get("status") != "executing"):
        raise ReleaseFailure("host_pair_transition_receipt_invalid")
    return receipt, raw


def reopen_runtime_metadata_failed_host_pair_receipt(
    request_id: str, request_sha256: str,
    authorized_target_plan_sha256: str, expected_uid: int, *,
    receipt_root: Path | None = None,
    recovery_root: Path | None = None,
    install_root: Path = DEFAULT_INSTALL_ROOT,
) -> tuple[dict[str, Any], str]:
    """Reopen only the exact pre-fix LaunchServices ctime false positive.

    The original Touch ID decision remains the authority.  Its terminal failed
    receipt is retained verbatim in a root-only archive before the standard
    executing receipt is reconstructed.  No other error, target plan, request,
    or receipt shape is recoverable through this path.
    """
    _validated_uuid4(request_id, "authorization_request_id")
    if (SHA256.fullmatch(request_sha256) is None
            or SHA256.fullmatch(authorized_target_plan_sha256) is None):
        raise ReleaseFailure(
            "runtime_metadata_receipt_recovery_binding_invalid"
        )
    receipt_root = (
        DEFAULT_AUTHORIZATION_RECEIPT_ROOT
        if receipt_root is None else receipt_root
    )
    recovery_root = (
        DEFAULT_AUTHORIZATION_RECEIPT_RECOVERY_ROOT
        if recovery_root is None else recovery_root
    )
    expected_fields = {
        "authorization_method", "ceremony", "completed_at",
        "declared_agent", "declared_session", "exit_status",
        "host_pair_authorized_target_plan_sha256", "identity_evidence",
        "operation", "purpose", "request_id", "request_sha256",
        "resource", "schema", "started_at", "status", "stderr_sha256",
        "stdout_sha256",
    }
    # ``main`` emits rejected results with json.dumps(sort_keys=True), not the
    # compact state-record encoder. Bind recovery to those exact historical
    # bytes rather than merely to an equivalent JSON object.
    known_error = (json.dumps({
        "error": "host_release_launcher_pair_tree_mismatch",
        "schema": SCHEMA,
        "status": "rejected",
    }, sort_keys=True) + "\n").encode("ascii")
    expected_stdout_sha256 = sha256_bytes(known_error)
    empty_sha256 = sha256_bytes(b"")

    receipt_directory = open_trusted_absolute_directory(
        receipt_root, expected_uid, final_mode=0o700,
    )
    try:
        receipt, raw, _ = read_state_record_at(
            receipt_directory, f"{request_id}.json", expected_uid, 0o600,
        )
        if raw != canonical_state_record(receipt):
            raise ReleaseFailure(
                "runtime_metadata_receipt_recovery_receipt_invalid"
            )
    finally:
        os.close(receipt_directory)

    pending = dict(receipt)
    pending.update({
        "completed_at": None,
        "exit_status": None,
        "status": "executing",
        "stderr_sha256": None,
        "stdout_sha256": None,
    })
    failed_sha256 = sha256_bytes(raw)
    if (set(receipt) != expected_fields
            or receipt.get("schema")
                != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != request_id
            or receipt.get("request_sha256") != request_sha256
            or receipt.get("operation") != "host-controller-install"
            or receipt.get("host_pair_authorized_target_plan_sha256")
                != authorized_target_plan_sha256
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("ceremony") != "approve"
            or receipt.get("status") not in {"failed", "executing"}
            or not isinstance(receipt.get("started_at"), int)
            or isinstance(receipt.get("started_at"), bool)):
        raise ReleaseFailure(
            "runtime_metadata_receipt_recovery_receipt_invalid"
        )
    if receipt["status"] == "failed":
        if (not isinstance(receipt.get("completed_at"), int)
                or isinstance(receipt.get("completed_at"), bool)
                or receipt["completed_at"] < receipt["started_at"]
                or receipt.get("exit_status") != 1
                or receipt.get("stdout_sha256")
                    != expected_stdout_sha256
                or receipt.get("stderr_sha256") != empty_sha256):
            raise ReleaseFailure(
                "runtime_metadata_receipt_recovery_error_mismatch"
            )
        failed = receipt
    else:
        if receipt != pending:
            raise ReleaseFailure(
                "runtime_metadata_receipt_recovery_receipt_invalid"
            )
        failed = None

    if os.path.lexists(install_root / INSTALL_TRANSITION_PENDING_NAME):
        raise ReleaseFailure(
            "runtime_metadata_receipt_recovery_transition_active"
        )
    try:
        recovery_root.mkdir(mode=0o700)
        fsync_directory(recovery_root.parent)
    except FileExistsError:
        pass
    verify_acl_free_directory(
        recovery_root, expected_uid, 0o700,
        "runtime_metadata_receipt_recovery_archive_untrusted",
    )
    archive_directory = open_trusted_absolute_directory(
        recovery_root, expected_uid, final_mode=0o700,
    )
    archive_name: str | None = None
    try:
        archives = [
            name for name in os.listdir(archive_directory)
            if name.startswith(request_id + "-") and name.endswith(".json")
        ]
        if len(archives) > 1:
            raise ReleaseFailure(
                "runtime_metadata_receipt_recovery_archive_conflict"
            )
        if failed is not None:
            archive_name = f"{request_id}-{failed_sha256}.json"
            if archives and archives != [archive_name]:
                raise ReleaseFailure(
                    "runtime_metadata_receipt_recovery_archive_conflict"
                )
            if not archives:
                write_new_state_record_at(
                    archive_directory, archive_name, failed,
                    expected_uid, 0o400,
                )
        else:
            if not archives:
                raise ReleaseFailure(
                    "runtime_metadata_receipt_recovery_archive_missing"
                )
            archive_name = archives[0]
        archived, archived_raw, _ = read_state_record_at(
            archive_directory, archive_name, expected_uid, 0o400,
        )
        if (archived_raw != canonical_state_record(archived)
                or archived.get("status") != "failed"
                or archived.get("request_id") != request_id
                or archived.get("request_sha256") != request_sha256
                or archived.get("host_pair_authorized_target_plan_sha256")
                    != authorized_target_plan_sha256
                or archived.get("stdout_sha256")
                    != expected_stdout_sha256
                or archived.get("stderr_sha256") != empty_sha256
                or archived.get("exit_status") != 1):
            raise ReleaseFailure(
                "runtime_metadata_receipt_recovery_archive_invalid"
            )
    finally:
        os.close(archive_directory)

    if failed is not None:
        receipt_directory = open_trusted_absolute_directory(
            receipt_root, expected_uid, final_mode=0o700,
        )
        try:
            current, current_raw, _ = read_state_record_at(
                receipt_directory, f"{request_id}.json",
                expected_uid, 0o600,
            )
            if current != failed or current_raw != raw:
                raise ReleaseFailure(
                    "runtime_metadata_receipt_recovery_receipt_changed"
                )
            replace_state_record_at(
                receipt_directory, f"{request_id}.json", pending,
                expected_uid, 0o600,
            )
        finally:
            os.close(receipt_directory)
    return pending, sha256_bytes(canonical_state_record(pending))


def begin_host_pair_transition(
    install_root: Path, expected_uid: int, *, operation: str,
    source_stable: Mapping[str, Any] | None,
    source_stable_sha256: str | None,
    target_pair: Mapping[str, Any],
    authorized_target_plan_sha256: str,
    old_previous_target: str | None, native_uid: int,
    old_services: Mapping[str, Any], signing_floor: Mapping[str, Any],
    signing_floor_sha256: str,
    authorization_request_id: str | None,
    authorization_request_sha256: str | None,
    bootstrap: bool = False,
    bootstrap_admission: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    target = validate_host_release_launcher_pair_generation(
        dict(target_pair)
    )
    if source_stable is None:
        source_pair = None
    else:
        validated_stable = validate_host_release_launcher_pair_record(
            dict(source_stable)
        )
        if validated_stable["schema"] != HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA:
            raise ReleaseFailure("host_pair_transition_source_invalid")
        source_pair = validated_stable["pair"]
    if bootstrap:
        admission = validate_host_pair_bootstrap_admission(
            bootstrap_admission
        )
        if admission["established_from_release_id"] != target["release_id"]:
            raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
        receipt_sha256 = None
    else:
        if bootstrap_admission is not None:
            raise ReleaseFailure("host_pair_transition_invalid")
        admission = None
        if (authorization_request_id is None
                or authorization_request_sha256 is None):
            raise ReleaseFailure("host_pair_transition_authorization_required")
        _receipt, receipt_raw = authorization_receipt_for_host_pair(
            authorization_request_id, authorization_request_sha256,
            expected_uid, operation, authorized_target_plan_sha256,
        )
        receipt_sha256 = sha256_bytes(receipt_raw)
    created = int(time.time()) if now is None else now
    value: dict[str, Any] = {
        "authorization_pending_receipt_sha256": receipt_sha256,
        "authorization_request_id": authorization_request_id,
        "authorization_request_sha256": authorization_request_sha256,
        "authorized_target_plan_sha256": authorized_target_plan_sha256,
        "bootstrap": bootstrap,
        "bootstrap_admission": admission,
        "created_at": created,
        "developer_id_team_floor_sha256": signing_floor_sha256,
        "developer_id_team_id": signing_floor["team_id"],
        "expires_at": created + INSTALL_TRANSITION_TTL_SECONDS,
        "finalization": None,
        "native_uid": native_uid,
        "old_current_target": (
            None if source_pair is None
            else f"releases/{source_pair['release_id']}"
        ),
        "old_previous_target": old_previous_target,
        "old_services": dict(old_services),
        "old_services_sha256": sha256_bytes(
            canonical_state_record(dict(old_services))
        ),
        "operation": operation,
        "schema": HOST_PAIR_TRANSITION_SCHEMA,
        "source_launcher_generation_sha256": (
            None if source_pair is None else source_pair["launcher_sha256"]
        ),
        "source_pair": source_pair,
        "source_stable_sha256": source_stable_sha256,
        "target_candidate_authority_sha256": target[
            "candidate_authority_sha256"
        ],
        "target_launcher_generation_sha256": target["launcher_sha256"],
        "target_pair": target,
        "terminal": None,
        "transition_id": str(uuid.uuid4()),
    }
    value["transition_sha256"] = host_pair_transition_digest(value)
    validated = validate_host_pair_transition(value)
    root = open_locked_install_root(install_root, expected_uid)
    try:
        write_new_state_record_at(
            root, INSTALL_TRANSITION_PENDING_NAME, validated,
            expected_uid, 0o600,
        )
    finally:
        os.close(root)
    host_pair_transition_checkpoint("PREPARED")
    return validated


def read_pending_host_pair_transition(
    install_root: Path, expected_uid: int, *, allow_absent: bool = False,
) -> tuple[dict[str, Any], int] | None:
    path = install_root / INSTALL_TRANSITION_PENDING_NAME
    if not os.path.lexists(path):
        if allow_absent:
            return None
        raise ReleaseFailure("host_pair_transition_missing")
    root = open_locked_install_root(install_root, expected_uid)
    try:
        value, _raw, _ = read_state_record_at(
            root, INSTALL_TRANSITION_PENDING_NAME, expected_uid, 0o600,
        )
        if value.get("schema") != HOST_PAIR_TRANSITION_SCHEMA:
            raise ReleaseFailure("host_pair_transition_legacy_active")
        return validate_host_pair_transition(value), root
    except BaseException:
        os.close(root)
        raise


def stage_host_pair_finalization(
    install_root_descriptor: int, transition: Mapping[str, Any],
    finalization: Mapping[str, Any], expected_uid: int,
) -> dict[str, Any]:
    validated_finalization = validate_host_pair_finalization(
        finalization, transition,
    )
    updated = dict(transition)
    updated["finalization"] = validated_finalization
    validated = validate_host_pair_transition(updated)
    replace_state_record_at(
        install_root_descriptor, INSTALL_TRANSITION_PENDING_NAME,
        validated, expected_uid, 0o600,
    )
    host_pair_transition_checkpoint("FINALIZATION_STAGED")
    return validated


def stage_host_pair_terminal(
    install_root_descriptor: int, transition: Mapping[str, Any],
    terminal: Mapping[str, Any], expected_uid: int,
) -> dict[str, Any]:
    if transition.get("finalization") is None:
        raise ReleaseFailure("host_pair_finalization_missing")
    validated_terminal = validate_host_pair_terminal(terminal, transition)
    updated = dict(transition)
    updated["terminal"] = validated_terminal
    validated = validate_host_pair_transition(updated)
    replace_state_record_at(
        install_root_descriptor, INSTALL_TRANSITION_PENDING_NAME,
        validated, expected_uid, 0o600,
    )
    return validated


def read_pending_install_transition(
    install_root: Path, expected_uid: int,
) -> tuple[dict[str, Any], int]:
    root = open_locked_install_root(install_root, expected_uid)
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


def completed_install_authorization_receipt(
    transition: Mapping[str, Any],
    finalization: Mapping[str, Any],
    expected_uid: int,
) -> tuple[dict[str, Any], bytes]:
    """Read, but never create or rewrite, one committed install receipt."""
    receipt, raw = authorization_receipt_for_transition(
        transition["authorization_request_id"],
        transition["authorization_request_sha256"],
        expected_uid,
    )
    expected_status = (
        "succeeded"
        if finalization["status"] == "deployed_verified"
        else "failed"
    )
    expected_stderr = sha256_bytes(
        b"" if expected_status == "succeeded"
        else b"host_install_activation_failed\n"
    )
    if (receipt.get("status") != expected_status
            or receipt.get("completed_at") != finalization["completed_at"]
            or receipt.get("exit_status")
                != (0 if expected_status == "succeeded" else 1)
            or receipt.get("transition_id") != transition["transition_id"]
            or receipt.get("transition_sha256")
                != transition["transition_sha256"]
            or receipt.get("candidate_release_id")
                != transition["candidate_release_id"]
            or receipt.get("authorization_pending_receipt_sha256")
                != transition["authorization_pending_receipt_sha256"]
            or receipt.get("host_install_terminal_status")
                != finalization["status"]
            or receipt.get("host_install_service_evidence_sha256")
                != finalization["service_evidence_sha256"]
            or receipt.get("host_install_finalization_sha256")
                != finalization["finalization_sha256"]
            or receipt.get("stderr_sha256") != expected_stderr
            or not isinstance(receipt.get("stdout_sha256"), str)
            or SHA256.fullmatch(receipt["stdout_sha256"]) is None):
        raise ReleaseFailure("install_transition_receipt_not_committed")
    return receipt, raw


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


def consume_published_install_terminal(
    install_root_descriptor: int,
    transition: Mapping[str, Any],
    expected_uid: int,
    expected_status: str,
) -> dict[str, Any] | None:
    """Finish an irrevocably published successful transition.

    The immutable public terminal is the commit point.  This path runs before
    successor-PID service revalidation so a crash after publication cannot
    reinterpret an already committed deployment as a rollback.  A staged
    finalization or completed receipt without the exact public record is not a
    commit and returns ``None``.
    """
    finalization = transition.get("terminal")
    if (not isinstance(finalization, dict)
            or finalization.get("status") not in {
                "deployed_verified", "failed_rolled_back",
            }):
        return None
    final_name = f"{transition['transition_id']}.json"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory = os.open(
            INSTALL_TRANSITION_DIRECTORY_NAME, flags,
            dir_fd=install_root_descriptor,
        )
    except FileNotFoundError:
        return None
    try:
        parent = os.fstat(install_root_descriptor)
        directory_info = os.fstat(directory)
        reject_extended_acl(
            directory, "install_transition_directory_untrusted",
        )
        if (not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != expected_uid
                or directory_info.st_gid != parent.st_gid
                or stat.S_IMODE(directory_info.st_mode) != 0o755):
            raise ReleaseFailure("install_transition_directory_untrusted")
        try:
            public_info = os.stat(
                final_name, dir_fd=directory, follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(public_info.st_mode)
                or public_info.st_uid != expected_uid
                or public_info.st_gid != directory_info.st_gid
                or public_info.st_nlink not in {1, 2}
                or stat.S_IMODE(public_info.st_mode) != 0o444):
            raise ReleaseFailure("install_transition_terminal_conflict")
    finally:
        os.close(directory)
    if finalization["status"] != expected_status:
        raise ReleaseFailure("install_transition_committed_selector_mismatch")

    _receipt, receipt_raw = completed_install_authorization_receipt(
        transition, finalization, expected_uid,
    )
    expected = make_install_terminal(
        transition, finalization, sha256_bytes(receipt_raw),
    )
    expected_raw = canonical_state_record(expected)
    if publish_terminal_state_record(
        install_root_descriptor, expected, expected_uid,
    ) != expected_raw:
        raise ReleaseFailure("install_transition_terminal_conflict")

    directory = open_install_transition_directory(
        install_root_descriptor, expected_uid,
    )
    try:
        observed, observed_raw, _ = read_state_record_at(
            directory, final_name, expected_uid, 0o444,
        )
    finally:
        os.close(directory)
    if (validate_terminal_transition(observed) != expected
            or observed_raw != expected_raw):
        raise ReleaseFailure("install_transition_terminal_conflict")

    pending, _pending_raw, _ = read_state_record_at(
        install_root_descriptor, INSTALL_TRANSITION_PENDING_NAME,
        expected_uid, 0o600,
    )
    if validate_install_transition(pending) != dict(transition):
        raise ReleaseFailure("install_transition_pending_changed")
    os.unlink(INSTALL_TRANSITION_PENDING_NAME, dir_fd=install_root_descriptor)
    os.fsync(install_root_descriptor)
    try:
        os.stat(
            INSTALL_TRANSITION_PENDING_NAME,
            dir_fd=install_root_descriptor, follow_symlinks=False,
        )
    except FileNotFoundError:
        return expected
    raise ReleaseFailure("install_transition_pending_retirement_failed")


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
        fallback, _manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True,
        )
        if fallback.name != fallback_release_id:
            raise ReleaseFailure("install_transition_fallback_changed")
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
        if expected_current_release_id not in {
            transition["candidate_release_id"],
            transition["fallback_release_id"],
        }:
            raise ReleaseFailure("install_transition_candidate_mismatch")
        ensure_native_catalog_promotion_inactive_locked(
            root, install_root, expected_uid,
            selector_release_id=expected_current_release_id,
        )
        ensure_native_deployment_inactive_locked(
            root, install_root, expected_uid,
            selector_release_id=expected_current_release_id,
        )
        ensure_release_id_native_deployment_compatible(
            install_root, transition["fallback_release_id"], expected_uid,
        )
        ensure_release_id_native_catalog_compatible(
            install_root, transition["fallback_release_id"], expected_uid,
        )
        enforce_release_id_native_stack_coordination_compatible(
            install_root, transition["fallback_release_id"], expected_uid,
        )
        candidate_selected = (
            transition["candidate_release_id"] == expected_current_release_id
        )
        fallback_selected = (
            transition["fallback_release_id"] == expected_current_release_id
            and transition["candidate_release_id"]
                != transition["fallback_release_id"]
        )
        same_release = (
            transition["candidate_release_id"]
            == transition["fallback_release_id"]
        )
        if not candidate_selected and not fallback_selected:
            raise ReleaseFailure("install_transition_candidate_mismatch")
        committed = consume_published_install_terminal(
            root, transition, expected_uid,
            "deployed_verified" if candidate_selected
            else "failed_rolled_back",
        )
        if committed is not None:
            return committed
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
                        if not same_release:
                            # Candidate verification failure is a rollback
                            # request, not authority to destroy the selected
                            # launch path.
                            raise ReleaseFailure(
                                "install_transition_rollback_required"
                            ) from error
                        finalization = failed_install_finalization(
                            install_root, transition,
                            expected_authorization_pid, expected_uid, instant,
                        )
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
                    elif candidate_selected and not same_release:
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
                if candidate_selected and not same_release:
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
                if candidate_selected and not same_release:
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
                if candidate_selected and not same_release:
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
        if expected_current_release_id != transition["candidate_release_id"]:
            raise ReleaseFailure("install_transition_rollback_not_required")
        ensure_native_catalog_promotion_inactive_locked(
            root, install_root, expected_uid,
            selector_release_id=expected_current_release_id,
        )
        ensure_native_deployment_inactive_locked(
            root, install_root, expected_uid,
            selector_release_id=expected_current_release_id,
        )
        ensure_release_id_native_deployment_compatible(
            install_root, transition["fallback_release_id"], expected_uid,
        )
        ensure_release_id_native_catalog_compatible(
            install_root, transition["fallback_release_id"], expected_uid,
        )
        enforce_release_id_native_stack_coordination_compatible(
            install_root, transition["fallback_release_id"], expected_uid,
        )
        terminal = transition["terminal"]
        same_release = (
            transition["fallback_release_id"]
            == transition["candidate_release_id"]
        )
        if (transition["candidate_release_id"]
                != expected_current_release_id
                or terminal is not None
                    and terminal["status"] not in {
                        "deployed_verified", "failed_fenced",
                        "failure_fence_unproven",
                    }):
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
            if same_release:
                if terminal is None or terminal["status"] == "deployed_verified":
                    finalization = failed_install_finalization(
                        install_root, transition, expected_authorization_pid,
                        expected_uid, int(time.time()),
                        superseded_finalization_sha256=(
                            None if terminal is None
                            else terminal["finalization_sha256"]
                        ),
                    )
                    transition = stage_install_finalization(
                        root, transition, finalization, expected_uid,
                    )
                return {
                    "schema": SCHEMA,
                    "status": "failure_fence_prepared",
                    "transition_id": transition["transition_id"],
                    "transition_sha256": transition["transition_sha256"],
                    "candidate_release_id": transition["candidate_release_id"],
                    "fallback_release_id": transition["fallback_release_id"],
                }
            # Publish the fallback selector first.  A crash now starts the
            # predecessor, which idempotently restores ``previous`` while
            # terminalizing failed_rolled_back.  Mutating previous first could
            # let the candidate later succeed with the wrong rollback target.
            atomic_symlink(transition["old_current_target"], current)
        elif selected != transition["old_current_target"]:
            raise ReleaseFailure("install_transition_selector_changed")
        elif same_release:
            raise ReleaseFailure("install_transition_service_identity_mismatch")
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
    verify_acl_free_directory(
        install_root, expected_uid, 0o755, "install_root_untrusted",
    )
    verify_acl_free_directory(
        releases, expected_uid, 0o755, "release_root_untrusted",
    )
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
    try:
        (install_root / INSTALL_TRANSITION_PENDING_NAME).lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ReleaseFailure(
            "release_capacity_recovery_transition_pending"
        ) from error
    else:
        # Archive planning is intentionally schema-agnostic here.  The private
        # journal belongs to transition recovery under the Host mutation lock;
        # its mere presence protects every retained release identity from
        # capacity recovery until that exact transition converges.
        raise ReleaseFailure("release_capacity_recovery_transition_pending")
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


def verified_inactive_release_for_archive(
    install_root: Path, release_id: str, expected_uid: int,
) -> tuple[Path, dict[str, Any]]:
    """Verify immutable evidence without treating it as activatable.

    Archival is the sole supported path that may inspect a release predating
    monotonic activation floors.  It retains every pathname, ACL, ownership,
    mode, content, bundle, and release-identity check; only the checks that
    answer "may this release become current?" are inapplicable because the
    next operation moves it out of the selectable release namespace.
    """
    if SHA256.fullmatch(release_id) is None:
        raise ReleaseFailure("release_archive_identity_invalid")
    release = install_root / "releases" / release_id
    return verified_release(
        install_root, release, expected_uid,
        allow_legacy=True, allow_below_floor=True,
        _bootstrap_without_developer_id_floor=True,
        _bootstrap_without_native_coordination_floor=True,
        _bootstrap_without_candidate_admission_floor=True,
        _direct_release_id=release_id,
        _skip_pair_validation=True,
    )


@host_release_mutation()
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
        # An inactive historical release may legitimately predate the current
        # monotonic activation floor.  It must still pass every immutable
        # payload, ownership, mode, bundle, and digest check through its exact
        # direct release identity before leaving the selectable namespace.
        verified_inactive_release_for_archive(
            install_root, release_id, expected_uid,
        )
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


def restore_failed_install_transition(
    install_root: Path,
    transition: Mapping[str, Any],
    old_path: Path,
    old_manifest: Mapping[str, Any],
    old_previous: str | None,
    native_uid: int,
    expected_uid: int,
) -> None:
    """Restore the bound predecessor without ever removing ``current``."""
    try:
        stop_native_credential_service(uid=native_uid)
        rollback_transition_checkpoint("install-recovery-helper-fenced")
        # The launchable fallback is the first durable recovery mutation.  A
        # crash in any later service or selector step can therefore restart an
        # immutable broker that understands the still-pending transition.
        ensure_install_failure_selector(
            install_root, transition, expected_uid,
        )
        rollback_transition_checkpoint("install-recovery-current-selected")
        restore_selector(install_root / "previous", old_previous)
        rollback_transition_checkpoint("install-recovery-previous-restored")
        install_touchid_service(old_path)
        rollback_transition_checkpoint(
            "install-recovery-authorization-restored"
        )
        install_native_credential_service(old_path, uid=native_uid)
        rollback_transition_checkpoint("install-recovery-credential-restored")
        verify_release_host_services(old_path, old_manifest, native_uid)
        rollback_transition_checkpoint("install-recovery-services-verified")
        root = open_locked_install_root(
            install_root, expected_uid,
        )
        try:
            pending, _pending_raw, _ = read_state_record_at(
                root, INSTALL_TRANSITION_PENDING_NAME,
                expected_uid, 0o600,
            )
            if validate_install_transition(pending) != dict(transition):
                raise ReleaseFailure("install_transition_pending_changed")
            os.unlink(INSTALL_TRANSITION_PENDING_NAME, dir_fd=root)
            os.fsync(root)
        finally:
            os.close(root)
    except BaseException as recovery_error:
        selector_error: BaseException | None = None
        try:
            ensure_install_failure_selector(
                install_root, transition, expected_uid,
            )
        except BaseException as error:
            selector_error = error
        try:
            stop_native_credential_service(uid=native_uid)
        except BaseException:
            pass
        if selector_error is not None:
            raise ReleaseFailure(
                "host_service_rollback_selector_unproven"
            ) from selector_error
        raise ReleaseFailure("host_service_rollback_unproven") from recovery_error


def verified_developer_id_migration_predecessor(
    install_root: Path, expected_uid: int, expected_release_id: str,
) -> tuple[Path, dict[str, Any]]:
    """Read the exact fenced predecessor beneath newly published floors.

    The one-time Developer ID migration can publish both permanent floors only
    after it has removed ``current``.  A retry must still be able to inspect the
    exact immutable predecessor, although that legacy release is intentionally
    below both floors.  Keep that exception bound to the dedicated selector and
    the operator-reviewed release identity; it never makes the predecessor
    executable again.
    """
    if SHA256.fullmatch(expected_release_id) is None:
        raise ReleaseFailure("developer_id_migration_current_invalid")
    predecessor = install_root / DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
    if not predecessor.is_symlink():
        if os.path.lexists(predecessor):
            raise ReleaseFailure(
                "developer_id_migration_predecessor_invalid")
        raise ReleaseFailure("developer_id_migration_predecessor_missing")
    path, manifest = verified_release(
        install_root, predecessor, expected_uid, allow_legacy=True,
        _bootstrap_without_developer_id_floor=True,
        _bootstrap_without_native_coordination_floor=True,
    )
    if path.name != expected_release_id:
        raise ReleaseFailure("developer_id_migration_predecessor_changed")
    return path, manifest


def enforce_developer_id_migration_predecessor_floor(
    signing_floor: Mapping[str, Any], predecessor_path: Path,
    predecessor_authorization_manifest: bytes,
    predecessor_policy: Mapping[str, str],
) -> None:
    """Bind the private below-floor read exception to its permanent anchor."""
    if (predecessor_policy.get("team_id") != signing_floor.get("team_id")
            or predecessor_policy.get("bundle_id")
                != signing_floor.get("authorization_ui_bundle_id")
            or signing_floor.get("established_from_release_id")
                != predecessor_path.name
            or signing_floor.get(
                "established_from_authorization_manifest_sha256"
            ) != sha256_bytes(predecessor_authorization_manifest)):
        raise ReleaseFailure("developer_id_migration_floor_mismatch")


def observed_host_release_launcher_pair(
    install_root: Path, launcher_path: Path, release_id: str,
    expected_uid: int,
) -> tuple[dict[str, Any], Path, dict[str, Any], dict[str, Any]]:
    """Derive one complete live pair from root-owned installed evidence."""
    if SHA256.fullmatch(release_id) is None:
        raise ReleaseFailure("host_release_launcher_pair_identity_invalid")
    release, manifest = verified_release(
        install_root, install_root / "releases" / release_id,
        expected_uid, _direct_release_id=release_id,
        _skip_pair_validation=True,
    )
    authority = installed_native_host_candidate_binding(
        install_root, release_id, expected_uid,
    )[3]
    if (authority["schema"]
            != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA
            or authority["payloads"] != manifest["payloads"]):
        raise ReleaseFailure("host_release_launcher_pair_authority_mismatch")
    launcher, launcher_identity = read_trusted_stable_launcher_identity(
        launcher_path, expected_uid,
    )
    if sha256_bytes(launcher) != authority["launcher_sha256"]:
        raise ReleaseFailure("host_release_launcher_pair_launcher_mismatch")
    pair = host_release_launcher_pair_identity(
        authority=authority, launcher_identity=launcher_identity,
    )
    return pair, release, manifest, authority


def host_pair_service_evidence(
    transition: Mapping[str, Any], committed_pair: Mapping[str, Any],
    services: Mapping[str, Any], install_root: Path,
) -> dict[str, Any]:
    value = {
        "committed_pair_sha256": sha256_bytes(
            canonical_state_record(dict(committed_pair))
        ),
        "current_target": selector_target(
            install_root / "current", "current",
        ),
        "operation": transition["operation"],
        "previous_target": selector_target(
            install_root / "previous", "previous",
        ),
        "schema": "secure-sandbox-host-pair-service-evidence-v1",
        "services": dict(services),
        "transition_sha256": transition["transition_sha256"],
    }
    return value


def validate_host_pair_service_evidence(
    value: object, transition: Mapping[str, Any],
    committed_pair: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "committed_pair_sha256", "current_target", "operation",
        "previous_target", "schema", "services", "transition_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseFailure("host_pair_service_evidence_invalid")
    committed = validate_host_release_launcher_pair_identity(
        dict(committed_pair)
    )
    expected_committed_sha256 = sha256_bytes(
        canonical_state_record(committed)
    )
    current_target = value.get("current_target")
    previous_target = value.get("previous_target")
    if (value.get("schema")
            != "secure-sandbox-host-pair-service-evidence-v1"
            or value.get("operation") != transition.get("operation")
            or value.get("transition_sha256")
                != transition.get("transition_sha256")
            or value.get("committed_pair_sha256")
                != expected_committed_sha256
            or current_target != f"releases/{committed['release_id']}"
            or (previous_target is not None and re.fullmatch(
                r"releases/[0-9a-f]{64}", str(previous_target),
            ) is None)
            or not isinstance(value.get("services"), dict)):
        raise ReleaseFailure("host_pair_service_evidence_invalid")
    return {name: value[name] for name in sorted(fields)}


def complete_host_pair_authorization_receipt(
    transition: Mapping[str, Any], *, status: str,
    committed_pair: Mapping[str, Any], service_evidence_sha256: str,
    finalization_sha256: str, completed_at: int, expected_uid: int,
) -> str | None:
    """Commit the already-authorized outcome without a terminal hash cycle."""
    if transition["bootstrap"]:
        return None
    request_id = transition["authorization_request_id"]
    directory = open_trusted_absolute_directory(
        DEFAULT_AUTHORIZATION_RECEIPT_ROOT, expected_uid, final_mode=0o700,
    )
    try:
        receipt, raw, _ = read_state_record_at(
            directory, f"{request_id}.json", expected_uid, 0o600,
        )
        expected_status = "succeeded" if status == "target_committed" else "failed"
        committed_sha256 = sha256_bytes(
            canonical_state_record(dict(committed_pair))
        )
        expected_operation = (
            "host-controller-install"
            if transition["operation"] == "install"
            else "host-controller-rollback"
        )
        if (receipt.get("schema")
                != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt.get("request_id") != request_id
                or receipt.get("request_sha256")
                    != transition["authorization_request_sha256"]
                or receipt.get("operation") != expected_operation
                or receipt.get("host_pair_authorized_target_plan_sha256")
                    != transition["authorized_target_plan_sha256"]):
            raise ReleaseFailure("host_pair_transition_receipt_invalid")
        if receipt.get("status") == expected_status:
            if (receipt.get("host_pair_transition_id")
                    != transition["transition_id"]
                    or receipt.get("host_pair_transition_sha256")
                        != transition["transition_sha256"]
                    or receipt.get("host_pair_committed_pair_sha256")
                        != committed_sha256
                    or receipt.get("host_pair_service_evidence_sha256")
                        != service_evidence_sha256
                    or receipt.get("host_pair_finalization_sha256")
                        != finalization_sha256
                    or receipt.get("completed_at") != completed_at):
                raise ReleaseFailure("host_pair_transition_receipt_conflict")
            return sha256_bytes(raw)
        if (receipt.get("status") not in {
                    "executing", "activation_pending",
                }
                or (receipt.get("status") == "executing"
                    and sha256_bytes(raw) != transition[
                        "authorization_pending_receipt_sha256"
                    ])):
            raise ReleaseFailure("host_pair_transition_receipt_invalid")
        completed = dict(receipt)
        completed.update({
            "completed_at": completed_at,
            "exit_status": 0 if expected_status == "succeeded" else 1,
            "host_pair_committed_pair_sha256": committed_sha256,
            "host_pair_finalization_sha256": finalization_sha256,
            "host_pair_service_evidence_sha256": service_evidence_sha256,
            "host_pair_transition_id": transition["transition_id"],
            "host_pair_transition_sha256": transition["transition_sha256"],
            "status": expected_status,
            "stderr_sha256": sha256_bytes(
                b"" if expected_status == "succeeded"
                else b"host_pair_activation_restored_source\n"
            ),
        })
        completed.setdefault("stdout_sha256", sha256_bytes(b""))
        completed_raw = replace_state_record_at(
            directory, f"{request_id}.json", completed,
            expected_uid, 0o600,
        )
        observed, observed_raw, _ = read_state_record_at(
            directory, f"{request_id}.json", expected_uid, 0o600,
        )
        if observed != completed or observed_raw != completed_raw:
            raise ReleaseFailure("host_pair_transition_receipt_readback_failed")
        return sha256_bytes(completed_raw)
    finally:
        os.close(directory)


def make_host_pair_finalization(
    transition: Mapping[str, Any], *, status: str,
    committed_pair: Mapping[str, Any], services: Mapping[str, Any],
    install_root: Path,
    error: str | None = None, completed_at: int | None = None,
) -> dict[str, Any]:
    pair = validate_host_release_launcher_pair_identity(dict(committed_pair))
    now = int(time.time()) if completed_at is None else completed_at
    evidence = host_pair_service_evidence(
        transition, pair, services, install_root,
    )
    evidence_sha256 = sha256_bytes(canonical_state_record(evidence))
    value: dict[str, Any] = {
        "committed_pair": pair,
        "completed_at": now,
        "error": error,
        "finalization_sha256": "",
        "schema": "secure-sandbox-host-pair-finalization-v1",
        "service_evidence": evidence,
        "service_evidence_sha256": evidence_sha256,
        "status": status,
    }
    value["finalization_sha256"] = host_pair_finalization_digest(value)
    return validate_host_pair_finalization(value, transition)


def make_host_pair_terminal(
    transition: Mapping[str, Any], finalization: Mapping[str, Any], *,
    expected_uid: int,
) -> dict[str, Any]:
    finalized = validate_host_pair_finalization(finalization, transition)
    receipt_sha256 = complete_host_pair_authorization_receipt(
        transition, status=finalized["status"],
        committed_pair=finalized["committed_pair"],
        service_evidence_sha256=finalized["service_evidence_sha256"],
        finalization_sha256=finalized["finalization_sha256"],
        completed_at=finalized["completed_at"], expected_uid=expected_uid,
    )
    value: dict[str, Any] = {
        "authorization_receipt_sha256": receipt_sha256,
        "authorization_request_id": transition["authorization_request_id"],
        "authorization_request_sha256": transition[
            "authorization_request_sha256"
        ],
        "authorized_target_plan_sha256": transition[
            "authorized_target_plan_sha256"
        ],
        "committed_pair": finalized["committed_pair"],
        "completed_at": finalized["completed_at"],
        "error": finalized["error"],
        "finalization_sha256": finalized["finalization_sha256"],
        "operation": transition["operation"],
        "schema": HOST_PAIR_TERMINAL_SCHEMA,
        "service_evidence": finalized["service_evidence"],
        "service_evidence_sha256": finalized["service_evidence_sha256"],
        "status": finalized["status"],
        "terminal_sha256": "",
        "transition_id": transition["transition_id"],
        "transition_sha256": transition["transition_sha256"],
    }
    value["terminal_sha256"] = host_pair_terminal_digest(value)
    return validate_host_pair_terminal(value, transition)


def publish_host_pair_terminal_and_stable(
    install_root: Path, expected_uid: int,
    transition: Mapping[str, Any], terminal: Mapping[str, Any],
    pending_sha256: str,
) -> tuple[dict[str, Any], str]:
    root = open_locked_install_root(install_root, expected_uid)
    try:
        staged = stage_host_pair_terminal(
            root, transition, terminal, expected_uid,
        )
        terminal_raw = publish_terminal_state_record(
            root, staged["terminal"], expected_uid,
        )
        host_pair_transition_checkpoint("TERMINAL_PUBLISHED")
    finally:
        os.close(root)
    stable = host_release_launcher_pair_stable_record(
        terminal["committed_pair"],
        committed_transition_id=transition["transition_id"],
        committed_transition_sha256=transition["transition_sha256"],
        committed_terminal_sha256=sha256_bytes(terminal_raw),
    )
    published, published_sha256 = publish_host_release_launcher_pair_record(
        install_root, expected_uid, stable,
        expected_previous_sha256=pending_sha256,
    )
    host_pair_transition_checkpoint("STABLE_PUBLISHED")
    root = open_locked_install_root(install_root, expected_uid)
    try:
        pending, _raw, _ = read_state_record_at(
            root, INSTALL_TRANSITION_PENDING_NAME, expected_uid, 0o600,
        )
        if validate_host_pair_transition(pending) != staged:
            raise ReleaseFailure("host_pair_transition_changed")
        os.unlink(INSTALL_TRANSITION_PENDING_NAME, dir_fd=root)
        os.fsync(root)
    finally:
        os.close(root)
    return published, published_sha256


def _select_host_pair_physical_state(
    install_root: Path, launcher_path: Path, expected_uid: int,
    transition: Mapping[str, Any], generation: Mapping[str, Any], *,
    previous_target: str | None, native_uid: int,
    old_process_release: Path | None,
    activation_deadline: int | None = None,
    defer_pending_source_authorization: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target = validate_host_release_launcher_pair_generation({
        name: generation[name] for name in (
            "candidate_authority_sha256", "launcher_sha256", "release_id",
            "release_tree_identity_sha256",
        )
    })
    release_id = target["release_id"]
    authority = installed_native_host_candidate_binding(
        install_root, release_id, expected_uid,
    )[3]
    if (native_host_candidate_authority_sha256(authority)
            != target["candidate_authority_sha256"]):
        raise ReleaseFailure("host_pair_transition_target_changed")
    if activation_deadline is not None:
        ensure_host_pair_transition_activation_current(transition)
    install_launcher_generation(
        install_root, launcher_path, target["launcher_sha256"], expected_uid,
    )
    host_pair_transition_checkpoint("LAUNCHER_SELECTED")
    if old_process_release is not None:
        ensure_no_d8653cb_release_processes(
            old_process_release, install_root,
            native_uid if native_uid >= 0 else expected_uid,
            extra_aliases=(launcher_path,),
        )
    restore_selector(install_root / "previous", previous_target)
    host_pair_transition_checkpoint("PREVIOUS_SELECTED")
    atomic_symlink(f"releases/{release_id}", install_root / "current")
    host_pair_transition_checkpoint("RELEASE_SELECTED")
    release, manifest = verified_release(
        install_root, install_root / "current", expected_uid,
        _skip_pair_validation=True,
    )
    if (release.name != release_id
            or manifest["payloads"] != authority["payloads"]):
        raise ReleaseFailure("host_pair_transition_selector_changed")
    services: dict[str, Any] = {}
    if native_uid >= 0:
        if defer_pending_source_authorization:
            install_touchid_service(release, activate=False)
            if (LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES
                    <= set(manifest.get("payloads", {}))):
                install_native_credential_service(release, uid=native_uid)
            else:
                stop_native_credential_service(uid=native_uid)
            services = attest_pending_source_host_services(
                release, manifest, native_uid,
            )
        else:
            install_release_host_services(release, manifest, native_uid)
            services = verify_release_host_services(
                release, manifest, native_uid, allow_inactive_native=True,
            )
    host_pair_transition_checkpoint("SERVICES_SELECTED")
    pair, observed_release, observed_manifest, observed_authority = (
        observed_host_release_launcher_pair(
            install_root, launcher_path, release_id, expected_uid,
        )
    )
    if (observed_release != release or observed_manifest != manifest
            or native_host_candidate_authority_sha256(observed_authority)
                != target["candidate_authority_sha256"]):
        raise ReleaseFailure("host_pair_transition_final_readback_failed")
    return pair, services


def _verify_committed_host_pair_physical_state(
    install_root: Path, launcher_path: Path, expected_uid: int,
    committed_pair: Mapping[str, Any], native_uid: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    committed = validate_host_release_launcher_pair_identity(
        dict(committed_pair)
    )
    current_target = selector_target(install_root / "current", "current")
    if current_target != f"releases/{committed['release_id']}":
        raise ReleaseFailure("host_pair_terminal_physical_mismatch")
    observed, release, manifest, _authority = (
        observed_host_release_launcher_pair(
            install_root, launcher_path, committed["release_id"],
            expected_uid,
        )
    )
    if observed != committed:
        raise ReleaseFailure("host_pair_terminal_physical_mismatch")
    services: dict[str, Any] = {}
    if native_uid >= 0:
        install_release_host_services(release, manifest, native_uid)
        services = verify_release_host_services(
            release, manifest, native_uid, allow_inactive_native=True,
        )
    return observed, services


def verify_host_pair_replay_prefix(
    install_root: Path, launcher_path: Path, expected_uid: int,
    transition: Mapping[str, Any],
) -> str:
    """Accept only the three crash prefixes authorized by one transition."""
    source = transition.get("source_pair")
    if source is None:
        return "bootstrap"
    source_identity = validate_host_release_launcher_pair_identity(source)
    target = validate_host_release_launcher_pair_generation(
        transition["target_pair"]
    )
    current_target = selector_target(install_root / "current", "current")
    launcher_raw = read_trusted_stable_launcher(launcher_path, expected_uid)
    launcher_sha256 = sha256_bytes(launcher_raw)
    physical = (current_target, launcher_sha256)
    source_source = (
        f"releases/{source_identity['release_id']}",
        source_identity["launcher_sha256"],
    )
    source_target = (
        f"releases/{source_identity['release_id']}",
        target["launcher_sha256"],
    )
    target_target = (
        f"releases/{target['release_id']}", target["launcher_sha256"],
    )
    target_source = (
        f"releases/{target['release_id']}",
        source_identity["launcher_sha256"],
    )
    if physical == source_source:
        return "source"
    if physical == source_target:
        return "launcher_selected"
    if physical == target_target:
        return "target"
    if physical == target_source:
        # A crash while restoring the source installs its launcher before
        # moving the selector.  The public PENDING fence still prevents use;
        # replay may safely retry the exact authorized transition.
        return "source_restore_launcher_selected"
    raise ReleaseFailure("host_pair_transition_physical_prefix_conflict")


def ensure_host_pair_transition_activation_current(
    transition: Mapping[str, Any], *, now: int | None = None,
) -> None:
    """Require live ordinary authorization before its first pair mutation."""
    if transition["bootstrap"]:
        return
    current = int(time.time()) if now is None else now
    if (current < transition["created_at"]
            or current >= transition["expires_at"]):
        raise ReleaseFailure("host_pair_transition_expired")


def execute_host_pair_transition(
    install_root: Path, launcher_path: Path, expected_uid: int,
    transition: Mapping[str, Any], *, raise_after_source_restore: bool = True,
) -> tuple[dict[str, Any], str]:
    """Run or replay one journaled pair transition to a durable terminal."""
    validated = validate_host_pair_transition(dict(transition))
    bootstrap_predecessor: Path | None = None
    if validated["bootstrap"]:
        admission = validate_host_pair_bootstrap_admission_floor(
            install_root, expected_uid,
            validated["bootstrap_admission"],
            allow_selected_target=True,
        )
        predecessor_id = admission[
            "established_from_predecessor_release_id"
        ]
        bootstrap_predecessor, predecessor_manifest = verified_release(
            install_root, install_root / "releases" / predecessor_id,
            expected_uid, allow_legacy=True, allow_below_floor=True,
            _bootstrap_without_developer_id_floor=True,
            _bootstrap_without_native_coordination_floor=True,
            _bootstrap_without_candidate_admission_floor=True,
            _direct_release_id=predecessor_id,
            _skip_pair_validation=True,
        )
        if (admission["establishment_mode"]
                == NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                and predecessor_manifest["payloads"]
                    != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS):
            raise ReleaseFailure("host_pair_bootstrap_predecessor_invalid")
        if (admission["establishment_mode"]
                == NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE
                and set(predecessor_manifest["payloads"])
                    != PRE_AUTHORIZATION_PAYLOAD_NAMES):
            raise ReleaseFailure("host_pair_bootstrap_predecessor_invalid")
        target_authority = native_host_candidate_authority(
            install_root,
            admission["established_from_release_id"], expected_uid,
        )
        candidate_raw = json.dumps(
            target_authority["candidate_record"], allow_nan=False,
            ensure_ascii=True, separators=(",", ":"), sort_keys=True,
        ).encode("ascii")
        if (sha256_bytes(candidate_raw)
                != admission["candidate_record_sha256"]
                or host_release_launcher_pair_generation(target_authority)
                    != validated["target_pair"]):
            raise ReleaseFailure("host_pair_bootstrap_binding_invalid")
    observed = host_release_launcher_pair_public(
        install_root, expected_uid, allow_absent=True,
    )
    pending_record = host_release_launcher_pair_pending_record(
        operation=validated["operation"],
        transition_id=validated["transition_id"],
        transition_sha256=validated["transition_sha256"],
        prior_stable_sha256=validated["source_stable_sha256"],
        source_pair=validated["source_pair"],
        target_pair=validated["target_pair"],
    )
    pending_sha256 = sha256_bytes(
        host_release_launcher_pair_record_bytes(pending_record)
    )
    if observed is None:
        if not validated["bootstrap"]:
            raise ReleaseFailure("host_release_launcher_pair_missing")
        _pending, observed_sha256 = publish_host_release_launcher_pair_record(
            install_root, expected_uid, pending_record,
            expected_previous_sha256=None,
        )
        host_pair_transition_checkpoint("PUBLIC_PENDING")
    elif observed[0]["schema"] == HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA:
        if (validated["terminal"] is not None
                and observed[0].get("committed_transition_id")
                    == validated["transition_id"]
                and observed[0].get("committed_transition_sha256")
                    == validated["transition_sha256"]):
            verified, verified_sha256, *_ = (
                verified_host_release_launcher_pair(
                    install_root, launcher_path, expected_uid,
                )
            )
            if verified != observed[0] or verified_sha256 != observed[1]:
                raise ReleaseFailure("host_release_launcher_pair_changed")
            public_terminal = verified_public_host_pair_terminal(
                install_root, expected_uid, observed[0],
            )
            expected_terminal = validated["terminal"]
            assert expected_terminal is not None
            expected_terminal_raw = canonical_state_record(
                expected_terminal
            )
            if (public_terminal is None
                    or public_terminal[0] != expected_terminal
                    or public_terminal[1]
                        != sha256_bytes(expected_terminal_raw)):
                raise ReleaseFailure("host_pair_terminal_mismatch")
            root = open_locked_install_root(install_root, expected_uid)
            try:
                pending, pending_raw, _ = read_state_record_at(
                    root, INSTALL_TRANSITION_PENDING_NAME,
                    expected_uid, 0o600,
                )
                if (validate_host_pair_transition(pending) != validated
                        or pending_raw
                            != canonical_state_record(validated)):
                    raise ReleaseFailure("host_pair_transition_changed")
                os.unlink(INSTALL_TRANSITION_PENDING_NAME, dir_fd=root)
                os.fsync(root)
            finally:
                os.close(root)
            return observed
        if (observed[1] != validated["source_stable_sha256"]
                or observed[0]["pair"] != validated["source_pair"]):
            raise ReleaseFailure("host_release_launcher_pair_changed")
        if (validated["finalization"] is None
                and validated["terminal"] is None):
            ensure_host_pair_transition_activation_current(validated)
        _pending, observed_sha256 = publish_host_release_launcher_pair_record(
            install_root, expected_uid, pending_record,
            expected_previous_sha256=observed[1],
        )
        host_pair_transition_checkpoint("PUBLIC_PENDING")
    else:
        if observed[0] != pending_record or observed[1] != pending_sha256:
            raise ReleaseFailure("host_release_launcher_pair_pending_conflict")
        observed_sha256 = observed[1]
    if observed_sha256 != pending_sha256:
        raise ReleaseFailure("host_release_launcher_pair_pending_conflict")

    replay_prefix = verify_host_pair_replay_prefix(
        install_root, launcher_path, expected_uid, validated,
    )

    terminal = validated["terminal"]
    if terminal is not None:
        committed = terminal["committed_pair"]
        pair, _services = _verify_committed_host_pair_physical_state(
            install_root, launcher_path, expected_uid, committed,
            validated["native_uid"],
        )
        if pair != committed:
            raise ReleaseFailure("host_pair_terminal_physical_mismatch")
        return publish_host_pair_terminal_and_stable(
            install_root, expected_uid, validated, terminal, pending_sha256,
        )

    finalization = validated["finalization"]
    if finalization is not None:
        committed = finalization["committed_pair"]
        pair, _services = _verify_committed_host_pair_physical_state(
            install_root, launcher_path, expected_uid, committed,
            validated["native_uid"],
        )
        if pair != committed:
            raise ReleaseFailure("host_pair_finalization_physical_mismatch")
        terminal = make_host_pair_terminal(
            validated, finalization, expected_uid=expected_uid,
        )
        return publish_host_pair_terminal_and_stable(
            install_root, expected_uid, validated, terminal, pending_sha256,
        )

    source_release = (
        bootstrap_predecessor
        if validated["source_pair"] is None
        else install_root / "releases" / validated["source_pair"]["release_id"]
    )
    activation_started = False
    try:
        if replay_prefix == "source":
            ensure_host_pair_transition_activation_current(validated)
        # The first freshness barrier begins the activation attempt.  From
        # here, service fencing or pair selection can change physical state;
        # expiry at the immediately-pre-launcher barrier therefore requires
        # exact source compensation rather than the pre-activation refusal.
        activation_started = True
        if validated["native_uid"] >= 0:
            stop_and_fence_host_services(validated["native_uid"])
        host_pair_transition_checkpoint("SERVICES_FENCED")
        pair, services = _select_host_pair_physical_state(
            install_root, launcher_path, expected_uid, validated,
            validated["target_pair"],
            previous_target=(
                None if validated["source_pair"] is None
                else f"releases/{validated['source_pair']['release_id']}"
            ),
            native_uid=validated["native_uid"],
            old_process_release=source_release,
            activation_deadline=(
                validated["expires_at"] if replay_prefix == "source" else None
            ),
        )
        finalization = make_host_pair_finalization(
            validated, status="target_committed", committed_pair=pair,
            services=services, install_root=install_root,
        )
        root = open_locked_install_root(install_root, expected_uid)
        try:
            validated = stage_host_pair_finalization(
                root, validated, finalization, expected_uid,
            )
        finally:
            os.close(root)
        terminal = make_host_pair_terminal(
            validated, validated["finalization"], expected_uid=expected_uid,
        )
    except Exception as activation_error:
        # Expiry before the first target mutation is an authorization refusal,
        # not an activation failure.  Preserve the pending fence for a
        # separately authorized recovery ceremony; generic compensation must
        # not convert stale authority into a source-restored terminal.
        if (not activation_started
                and isinstance(activation_error, ReleaseFailure)
                and str(activation_error)
                    == "host_pair_transition_expired"):
            raise
        # Once target finalization is durable, receipt/terminal publication is
        # replay-only.  Never turn a post-finalization I/O failure into a
        # different source-restored outcome: the completed authorization
        # receipt may already bind the target finalization.
        outstanding = read_pending_host_pair_transition(
            install_root, expected_uid, allow_absent=False,
        )
        assert outstanding is not None
        durable_transition, durable_root = outstanding
        os.close(durable_root)
        if (durable_transition["transition_id"]
                != validated["transition_id"]):
            raise ReleaseFailure("host_pair_transition_changed") \
                from activation_error
        if durable_transition["finalization"] is not None:
            raise
        if validated["source_pair"] is None:
            # No pre-pair authority exists to restore.  The durable public
            # pending fence remains and a retry may only resume this exact
            # journaled target.
            raise
        try:
            if validated["native_uid"] >= 0:
                stop_and_fence_host_services(validated["native_uid"])
            source_pair, services = _select_host_pair_physical_state(
                install_root, launcher_path, expected_uid, validated,
                validated["source_pair"],
                previous_target=validated["old_previous_target"],
                native_uid=validated["native_uid"],
                old_process_release=(
                    install_root / "releases"
                    / validated["target_pair"]["release_id"]
                ),
                defer_pending_source_authorization=True,
            )
            finalization = make_host_pair_finalization(
                validated, status="source_restored",
                committed_pair=source_pair, services=services,
                install_root=install_root,
                error="target_activation_failed",
            )
            root = open_locked_install_root(install_root, expected_uid)
            try:
                validated = stage_host_pair_finalization(
                    root, validated, finalization, expected_uid,
                )
            finally:
                os.close(root)
            terminal = make_host_pair_terminal(
                validated, validated["finalization"],
                expected_uid=expected_uid,
            )
        except Exception as recovery_error:
            recovery_code = (
                str(recovery_error)
                if isinstance(recovery_error, ReleaseFailure)
                and re.fullmatch(r"[A-Za-z0-9_.:-]{1,240}", str(recovery_error))
                else "unclassified"
            )
            raise ReleaseFailure(
                "host_pair_transition_recovery_unproven:"
                + recovery_code
            ) from recovery_error
        restored = publish_host_pair_terminal_and_stable(
            install_root, expected_uid, validated, terminal, pending_sha256,
        )
        if validated["native_uid"] >= 0:
            restored_release, restored_manifest = verified_release(
                install_root, install_root / "current", expected_uid,
            )
            install_release_host_services(
                restored_release, restored_manifest, validated["native_uid"],
            )
            verify_release_host_services(
                restored_release, restored_manifest, validated["native_uid"],
                allow_inactive_native=True,
            )
        if raise_after_source_restore:
            raise activation_error
        return restored
    return publish_host_pair_terminal_and_stable(
        install_root, expected_uid, validated, terminal, pending_sha256,
    )


@host_release_mutation(controller_fence=True)
def recover_host_pair_transition(
    install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, *,
    expected_public_pending_sha256: str | None = None,
    expected_transition_id: str | None = None,
    expected_transition_sha256: str | None = None,
    expected_operation: str | None = None,
    expected_target_release_id: str | None = None,
    expected_target_candidate_authority_sha256: str | None = None,
    expected_target_release_tree_identity_sha256: str | None = None,
    expected_target_launcher_sha256: str | None = None,
) -> dict[str, Any]:
    expected_binding = {
        "candidate_authority_sha256": (
            expected_target_candidate_authority_sha256
        ),
        "launcher_sha256": expected_target_launcher_sha256,
        "operation": expected_operation,
        "public_pending_sha256": expected_public_pending_sha256,
        "release_id": expected_target_release_id,
        "release_tree_identity_sha256": (
            expected_target_release_tree_identity_sha256
        ),
        "transition_id": expected_transition_id,
        "transition_sha256": expected_transition_sha256,
    }
    provided = [value is not None for value in expected_binding.values()]
    if any(provided) and not all(provided):
        raise ReleaseFailure("host_pair_transition_recovery_binding_incomplete")
    attributed_recovery = all(provided)
    if attributed_recovery:
        if (expected_operation not in {"install", "rollback"}
                or any(
                    SHA256.fullmatch(str(expected_binding[name])) is None
                    for name in (
                        "candidate_authority_sha256", "launcher_sha256",
                        "public_pending_sha256", "release_id",
                        "release_tree_identity_sha256", "transition_sha256",
                    )
                )):
            raise ReleaseFailure(
                "host_pair_transition_recovery_binding_invalid"
            )
        _validated_uuid4(
            expected_transition_id, "host_pair_transition_id",
        )
    outstanding = read_pending_host_pair_transition(
        install_root, expected_uid, allow_absent=False,
    )
    assert outstanding is not None
    transition, root = outstanding
    os.close(root)
    if attributed_recovery:
        observed = host_release_launcher_pair_public(
            install_root, expected_uid, allow_absent=False,
        )
        if observed is None:
            raise ReleaseFailure(
                "host_pair_transition_recovery_binding_changed"
            )
        pending, pending_sha256 = observed
        projected = host_release_launcher_pair_pending_record(
            operation=transition["operation"],
            transition_id=transition["transition_id"],
            transition_sha256=transition["transition_sha256"],
            prior_stable_sha256=transition["source_stable_sha256"],
            source_pair=transition["source_pair"],
            target_pair=transition["target_pair"],
        )
        target = transition["target_pair"]
        if (pending.get("schema")
                != HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA
                or pending != projected
                or pending_sha256 != expected_public_pending_sha256
                or transition["transition_id"] != expected_transition_id
                or transition["transition_sha256"]
                    != expected_transition_sha256
                or transition["operation"] != expected_operation
                or target["release_id"] != expected_target_release_id
                or target["candidate_authority_sha256"]
                    != expected_target_candidate_authority_sha256
                or target["release_tree_identity_sha256"]
                    != expected_target_release_tree_identity_sha256
                or target["launcher_sha256"]
                    != expected_target_launcher_sha256):
            raise ReleaseFailure(
                "host_pair_transition_recovery_binding_changed"
            )
    stable, stable_sha256 = execute_host_pair_transition(
        install_root, launcher_path, expected_uid, transition,
        raise_after_source_restore=False,
    )
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
        "schema": SCHEMA,
        "status": "host_pair_transition_recovered",
        "transition_id": transition["transition_id"],
        "transition_sha256": transition["transition_sha256"],
    }


@host_release_mutation(initialize=True, controller_fence=True)
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
    native_host_generation: Path | None = None,
    expected_native_host_candidate: Mapping[str, object] | None = None,
    _native_host_candidate_schema_predecessor_release_id: str | None = None,
    _host_pair_bootstrap_mode: str | None = None,
    authorized_target_plan_sha256: str | None = None,
) -> dict[str, Any]:
    if (install_root == DEFAULT_INSTALL_ROOT and expected_uid == 0
            and (native_host_generation is None
                 or expected_native_host_candidate is None)):
        raise ReleaseFailure("native_host_candidate_record_required")
    if (authorization_request_id is None) != (
        authorization_request_sha256 is None
    ):
        raise ReleaseFailure("install_transition_authorization_incomplete")
    if (authorization_request_id is not None
            and install_root == DEFAULT_INSTALL_ROOT
            and not manages_live_touchid_service(install_root, expected_uid)):
        raise ReleaseFailure("install_transition_layout_invalid")
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if payload_override is None:
        values, hashes, release_id = source_payload(
            repo, op_binary, gpgv_binary,
            native_host_generation=native_host_generation,
            expected_native_host_candidate=expected_native_host_candidate,
        )
    else:
        values, hashes, release_id = payload_override
        if (set(values) != PAYLOAD_NAMES or set(hashes) != PAYLOAD_NAMES
                or hashes != {name: sha256_bytes(value) for name, value in values.items()}
                or release_id != release_identity(hashes)):
            raise ReleaseFailure("payload_override_invalid")
    contract_raw = values["native_stack_coordination_contract"]
    contract = validate_native_stack_coordination_contract(contract_raw)
    coordination_floor = native_stack_coordination_floor(
        install_root, expected_uid, allow_absent=True)
    if coordination_floor is None:
        raise ReleaseFailure(
            "native_stack_coordination_floor_bootstrap_required")
    enforce_native_stack_coordination_floor(
        contract_raw, install_root, expected_uid)
    enforce_native_host_candidate_floor(
        contract_raw, set(values), install_root, expected_uid,
    )
    candidate_floor = native_host_candidate_floor(
        install_root, expected_uid, allow_absent=True,
    )
    if (candidate_floor is not None
            and (native_host_generation is None
                 or expected_native_host_candidate is None)):
        raise ReleaseFailure("native_host_candidate_record_required")
    if expected_source_release_id is not None:
        if not SHA256.fullmatch(expected_source_release_id) or release_id != expected_source_release_id:
            raise ReleaseFailure("source_release_id_unexpected")
    candidate_schema_migration = (
        _native_host_candidate_schema_predecessor_release_id is not None
    )
    if candidate_schema_migration:
        if (_native_host_candidate_schema_predecessor_release_id
                != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                or expected_source_release_id != release_id
                or payload_override is not None
                or expected_native_host_candidate is None
                or candidate_floor is None
                or candidate_floor[0]["establishment_mode"]
                    != NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                or candidate_floor[0][
                    "established_from_predecessor_release_id"
                ] != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                or candidate_floor[0]["established_from_release_id"]
                    != release_id):
            raise ReleaseFailure(
                "native_host_candidate_schema_install_binding_invalid"
            )
        predecessor_path, predecessor_manifest = verified_release(
            install_root,
            install_root / "releases"
                / NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID,
            expected_uid, allow_legacy=True,
            _bootstrap_without_candidate_admission_floor=True,
            _direct_release_id=(
                NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
            ),
        )
        if (predecessor_path.name
                != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                or predecessor_manifest["payloads"]
                    != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS):
            raise ReleaseFailure(
                "native_host_candidate_schema_predecessor_invalid"
            )
    enforce_execution_approval_floor(values["authorization_broker"], expected_uid)
    launcher_bytes = (
        native_host_candidate_tracked_source(
            repo, native_host_generation, expected_native_host_candidate,
            LAUNCHER_SOURCE,
        )
        if (native_host_generation is not None
            and expected_native_host_candidate is not None)
        else read_regular(repo / LAUNCHER_SOURCE)
    )
    try:
        compile(launcher_bytes, str(repo / LAUNCHER_SOURCE), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("stable_launcher_syntax_invalid") from error
    validate_shell_payload(values["controller"], "controller")

    pair_required = (
        HOST_RELEASE_LAUNCHER_PAIR_FEATURE in contract["features"]
    )
    current_selector = install_root / "current"
    if current_selector.is_symlink():
        selected_current, selected_manifest = verified_release(
            install_root, current_selector, expected_uid, allow_legacy=True,
            _skip_pair_validation=True,
        )
        if (release_requires_host_pair_fence(
                selected_current, selected_manifest, expected_uid)
                and not pair_required):
            raise ReleaseFailure("release_below_host_pair_floor")
    elif os.path.lexists(current_selector):
        raise ReleaseFailure("release_link_invalid:current")
    pair_source: dict[str, Any] | None = None
    pair_source_sha256: str | None = None
    pair_bootstrap = False
    recovered_pair_bootstrap = False
    pair_bootstrap_admission: dict[str, Any] | None = None
    pair_plan_sha256: str | None = None
    if pair_required:
        if expected_native_host_candidate is None:
            raise ReleaseFailure("native_host_candidate_record_required")
        outstanding = read_pending_host_pair_transition(
            install_root, expected_uid, allow_absent=True,
        )
        if outstanding is not None:
            outstanding_transition, outstanding_root = outstanding
            os.close(outstanding_root)
            if outstanding_transition["bootstrap"]:
                if (_host_pair_bootstrap_mode is None
                        or outstanding_transition["target_pair"]["release_id"]
                            != release_id):
                    raise ReleaseFailure(
                        "host_pair_bootstrap_binding_invalid"
                    )
                recovered_pair_bootstrap = True
                pair_bootstrap_admission = validate_host_pair_bootstrap_mode(
                    install_root, expected_uid,
                    mode=_host_pair_bootstrap_mode,
                    release_id=release_id,
                    candidate_record=expected_native_host_candidate,
                    allow_selected_target=True,
                )
                if (outstanding_transition["bootstrap_admission"]
                        != pair_bootstrap_admission):
                    raise ReleaseFailure(
                        "host_pair_bootstrap_binding_invalid"
                    )
            execute_host_pair_transition(
                install_root, launcher_path, expected_uid,
                outstanding_transition, raise_after_source_restore=False,
            )
        pair_observed = host_release_launcher_pair_public(
            install_root, expected_uid, allow_absent=True,
        )
        if pair_observed is None:
            pair_bootstrap_admission = validate_host_pair_bootstrap_mode(
                install_root, expected_uid,
                mode=_host_pair_bootstrap_mode,
                release_id=release_id,
                candidate_record=expected_native_host_candidate,
            )
            pair_bootstrap = True
        else:
            if (_host_pair_bootstrap_mode is not None
                    and not recovered_pair_bootstrap):
                raise ReleaseFailure("host_pair_bootstrap_not_required")
            if (pair_observed[0]["schema"]
                    != HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA):
                raise ReleaseFailure(
                    "host_release_launcher_pair_transition_active"
                )
            pair_source, pair_source_sha256 = pair_observed
            verified_source, verified_source_sha256, *_ = (
                verified_host_release_launcher_pair(
                    install_root, launcher_path, expected_uid,
                )
            )
            if (verified_source != pair_source
                    or verified_source_sha256 != pair_source_sha256):
                raise ReleaseFailure("host_release_launcher_pair_changed")
            source_generation = pair_source["pair"]
            if (source_generation["release_id"] == release_id
                    and source_generation["launcher_sha256"]
                        == sha256_bytes(launcher_bytes)):
                if (authorization_request_id is not None
                        or authorization_request_sha256 is not None
                        or authorized_target_plan_sha256 is not None):
                    raise ReleaseFailure(
                        "host_release_pair_target_already_current"
                    )
                result = verify(
                    repo, install_root, launcher_path, expected_uid,
                    op_binary, gpgv_binary,
                    native_host_generation=native_host_generation,
                    expected_native_host_candidate=(
                        expected_native_host_candidate
                    ),
                )
                result["status"] = "deployed"
                return result
        _pair_plan, pair_plan_sha256 = authorized_host_release_target_plan(
            release_id=release_id, payloads=hashes,
            candidate_record=expected_native_host_candidate,
            target_launcher_sha256=sha256_bytes(launcher_bytes),
            source_stable_sha256=pair_source_sha256,
        )
        if authorized_target_plan_sha256 is None:
            if not pair_bootstrap:
                raise ReleaseFailure("host_release_target_plan_required")
            authorized_target_plan_sha256 = pair_plan_sha256
        elif authorized_target_plan_sha256 != pair_plan_sha256:
            raise ReleaseFailure("host_release_target_plan_changed")
        if not pair_bootstrap:
            if (authorization_request_id is None
                    or authorization_request_sha256 is None):
                raise ReleaseFailure(
                    "host_pair_transition_authorization_required"
                )
            authorization_receipt_for_host_pair(
                authorization_request_id, authorization_request_sha256,
                expected_uid, "install", pair_plan_sha256,
            )
    releases = prepare_release_root(install_root, expected_uid)
    if _developer_id_migration_current_release_id is None:
        signing_floor, signing_floor_sha256 = prepare_developer_id_team_floor(
            repo, install_root, expected_uid, values, release_id,
            native_host_generation=native_host_generation,
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
            ((native_host_generation / AUTHORIZATION_UI_APP_NAME)
             if native_host_generation is not None
             else repo / AUTHORIZATION_UI_APP_SOURCE),
            values["authorization_ui_bundle"],
        )
        if candidate_policy["team_id"] != signing_floor["team_id"]:
            raise ReleaseFailure("release_developer_id_team_mismatch")
        predecessor_path, _predecessor_manifest = (
            verified_developer_id_migration_predecessor(
                install_root, expected_uid,
                _developer_id_migration_current_release_id,
            )
        )
        predecessor_authorization_manifest = read_regular(
            predecessor_path / "authorization_ui_bundle"
        )
        predecessor_policy = verified_existing_authorization_ui_anchor_policy(
            predecessor_path / AUTHORIZATION_UI_APP_NAME,
            predecessor_authorization_manifest,
            expected_uid,
        )
        enforce_developer_id_migration_predecessor_floor(
            signing_floor, predecessor_path,
            predecessor_authorization_manifest, predecessor_policy,
        )
    final = releases / release_id
    if not final.exists():
        if expected_native_host_candidate is not None:
            if (native_host_generation is None
                    or native_host_candidate_record(
                        repo, native_host_generation,
                    ) != dict(expected_native_host_candidate)):
                raise ReleaseFailure("native_host_candidate_record_mismatch")
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
            materialize_gpgv_runtime(staging, values["gpgv"])
            copy_authorization_ui_bundle(
                ((native_host_generation / AUTHORIZATION_UI_APP_NAME)
                 if native_host_generation is not None
                 else repo / AUTHORIZATION_UI_APP_SOURCE),
                staging / AUTHORIZATION_UI_APP_NAME,
                values["authorization_ui_bundle"], expected_uid,
            )
            copy_native_credential_helper_bundle(
                ((native_host_generation / NATIVE_CREDENTIAL_HELPER_APP_NAME)
                 if native_host_generation is not None
                 else repo / NATIVE_CREDENTIAL_HELPER_APP_SOURCE),
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
    if expected_native_host_candidate is not None:
        publish_native_host_candidate_authority(
            install_root, expected_uid, release_id=release_id,
            payloads=hashes,
            candidate_record=expected_native_host_candidate,
            launcher_sha256=sha256_bytes(launcher_bytes),
        )
        native_host_candidate_bootstrap_checkpoint(
            "candidate-authority-published"
        )
    current = install_root / "current"
    old_current: str | None = None
    old_path: Path | None = None
    old_manifest: dict[str, Any] | None = None
    if current.is_symlink():
        if _developer_id_migration_current_release_id is not None:
            raise ReleaseFailure("developer_id_migration_current_not_fenced")
        old_path, old_manifest = verified_release(
            install_root, current, expected_uid, allow_legacy=True,
            _bootstrap_without_candidate_admission_floor=(
                candidate_schema_migration
            ),
        )
        if (candidate_schema_migration
                and (old_path.name
                     != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                     or old_manifest["payloads"]
                        != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS)):
            raise ReleaseFailure(
                "native_host_candidate_schema_predecessor_invalid"
            )
        if set(old_manifest["payloads"]) in (
            PAYLOAD_NAMES, PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES,
            PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
            PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES,
            PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES,
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
    os.chmod(launcher_path.parent, 0o755)
    verify_acl_free_directory(
        launcher_path.parent, expected_uid, 0o755,
        "stable_launcher_parent_untrusted",
    )
    if pair_required:
        if launcher_path.exists():
            installed_launcher = read_trusted_stable_launcher(
                launcher_path, expected_uid,
            )
            retain_launcher_generation(
                install_root, installed_launcher, expected_uid,
            )
        retain_launcher_generation(
            install_root, launcher_bytes, expected_uid,
        )
    elif launcher_path.exists():
        installed_launcher = read_trusted_stable_launcher(
            launcher_path, expected_uid,
        )
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
            reject_extended_acl(descriptor, "stable_launcher_untrusted")
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
    if pair_required:
        authority = native_host_candidate_authority(
            install_root, release_id, expected_uid,
        )
        if (authority["schema"]
                != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA
                or authority["launcher_sha256"]
                    != sha256_bytes(launcher_bytes)
                or authority["payloads"] != hashes):
            raise ReleaseFailure("host_release_launcher_pair_authority_mismatch")
        target_generation = host_release_launcher_pair_generation(authority)
        if (pair_source is not None
                and {name: pair_source["pair"][name]
                     for name in target_generation}
                    == target_generation):
            result = verify(
                repo, install_root, launcher_path, expected_uid,
                op_binary, gpgv_binary,
                native_host_generation=native_host_generation,
                expected_native_host_candidate=expected_native_host_candidate,
            )
            result["status"] = "deployed"
            return result
        if manages_live_touchid_service(install_root, expected_uid):
            native_uid = console_user_uid()
        else:
            native_uid = -1
        old_services: dict[str, Any] = {}
        if pair_source is not None and native_uid >= 0:
            assert old_path is not None and old_manifest is not None
            old_services = verify_release_host_services(
                old_path, old_manifest, native_uid,
                allow_inactive_native=True,
            )
        assert pair_plan_sha256 is not None
        transition = begin_host_pair_transition(
            install_root, expected_uid, operation="install",
            source_stable=pair_source,
            source_stable_sha256=pair_source_sha256,
            target_pair=target_generation,
            authorized_target_plan_sha256=pair_plan_sha256,
            old_previous_target=old_previous, native_uid=native_uid,
            old_services=old_services, signing_floor=signing_floor,
            signing_floor_sha256=signing_floor_sha256,
            authorization_request_id=authorization_request_id,
            authorization_request_sha256=authorization_request_sha256,
            bootstrap=pair_bootstrap,
            bootstrap_admission=pair_bootstrap_admission,
        )
        stable, stable_sha256 = execute_host_pair_transition(
            install_root, launcher_path, expected_uid, transition,
        )
        result = verify(
            repo, install_root, launcher_path, expected_uid,
            op_binary, gpgv_binary,
            native_host_generation=native_host_generation,
            expected_native_host_candidate=expected_native_host_candidate,
        )
        result.update({
            "status": "deployed",
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "host_release_launcher_pair_sha256": stable_sha256,
            "candidate_authority_sha256": stable["pair"][
                "candidate_authority_sha256"
            ],
            "release_tree_identity_sha256": stable["pair"][
                "release_tree_identity_sha256"
            ],
        })
        return result
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
        if (old_current and old_current != f"releases/{release_id}"
                and not candidate_schema_migration):
            atomic_symlink(old_current, install_root / "previous")
        elif ((not old_current or candidate_schema_migration)
                and (install_root / "previous").is_symlink()):
            (install_root / "previous").unlink()
            fsync_directory(install_root)
        observed_floor = developer_id_team_floor(install_root, expected_uid)
        if (observed_floor is None
                or observed_floor[0] != signing_floor
                or observed_floor[1] != signing_floor_sha256):
            raise ReleaseFailure("developer_id_team_floor_changed")
        atomic_symlink(f"releases/{release_id}", current)
        if candidate_schema_migration:
            native_host_candidate_bootstrap_checkpoint(
                "candidate-release-selected"
            )
        if verify_against_source:
            result = verify(
                repo, install_root, launcher_path, expected_uid,
                op_binary, gpgv_binary,
                native_host_generation=native_host_generation,
                expected_native_host_candidate=expected_native_host_candidate,
            )
        else:
            verified_path, verified_manifest = verified_release(
                install_root, current, expected_uid,
            )
            if (verified_path.name != release_id
                    or verified_manifest["payloads"] != hashes
                    or sha256_bytes(read_trusted_stable_launcher(
                        launcher_path, expected_uid,
                    )) != sha256_bytes(launcher_bytes)):
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
            if candidate_schema_migration:
                native_host_candidate_bootstrap_checkpoint(
                    "candidate-services-installed"
                )
    except BaseException:
        if (transition is not None and native_uid is not None
                and old_path is not None and old_manifest is not None
                and old_current is not None):
            restore_failed_install_transition(
                install_root, transition, old_path, old_manifest,
                old_previous, native_uid, expected_uid,
            )
            raise
        if manages_live_touchid_service(install_root, expected_uid):
            stop_touchid_service()
            stop_native_credential_service(uid=native_uid)
        if (old_current
                and _developer_id_migration_current_release_id is None
                and not candidate_schema_migration):
            atomic_symlink(old_current, current)
        else:
            current.unlink(missing_ok=True)
            fsync_directory(install_root)
        if (manages_live_touchid_service(install_root, expected_uid)
                and old_path is not None
                and _developer_id_migration_current_release_id is None
                and not candidate_schema_migration):
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


def recover_runtime_metadata_authorized_install(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    native_host_generation: Path,
    expected_native_host_candidate: Mapping[str, object],
    authorization_request_id: str,
    authorization_request_sha256: str,
    authorized_target_plan_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """Resume one exact install whose old verifier rejected app ctime drift."""
    values, hashes, release_id = source_payload(
        repo, op_binary, gpgv_binary,
        native_host_generation=native_host_generation,
        expected_native_host_candidate=expected_native_host_candidate,
    )
    if (release_id != expected_source_release_id
            or sha256_bytes(read_regular(Path(__file__)))
                != hashes["release_manager"]):
        raise ReleaseFailure(
            "runtime_metadata_recovery_manager_candidate_mismatch"
        )
    source, source_sha256, *_ = verified_host_release_launcher_pair(
        install_root, launcher_path, expected_uid,
    )
    launcher_bytes = native_host_candidate_tracked_source(
        repo, native_host_generation,
        expected_native_host_candidate, LAUNCHER_SOURCE,
    )
    _plan, plan_sha256 = authorized_host_release_target_plan(
        release_id=release_id, payloads=hashes,
        candidate_record=expected_native_host_candidate,
        target_launcher_sha256=sha256_bytes(launcher_bytes),
        source_stable_sha256=source_sha256,
    )
    if plan_sha256 != authorized_target_plan_sha256:
        raise ReleaseFailure(
            "runtime_metadata_recovery_target_plan_mismatch"
        )
    reopen_runtime_metadata_failed_host_pair_receipt(
        authorization_request_id, authorization_request_sha256,
        authorized_target_plan_sha256, expected_uid,
        install_root=install_root,
    )
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
        native_host_generation=native_host_generation,
        expected_native_host_candidate=expected_native_host_candidate,
        authorization_request_id=authorization_request_id,
        authorization_request_sha256=authorization_request_sha256,
        authorized_target_plan_sha256=authorized_target_plan_sha256,
    )
    result["runtime_metadata_recovery"] = True
    return result


def verified_release(
    install_root: Path, link: Path, expected_uid: int, allow_legacy: bool = False,
    allow_below_floor: bool = False,
    *, _bootstrap_without_developer_id_floor: bool = False,
    _bootstrap_without_native_coordination_floor: bool = False,
    _bootstrap_without_candidate_admission_floor: bool = False,
    _direct_release_id: str | None = None,
    _public_enforcement_only: bool = False,
    _skip_pair_validation: bool = False,
) -> tuple[Path, dict[str, Any]]:
    releases = install_root / "releases"
    if _direct_release_id is None:
        if not link.is_symlink():
            raise ReleaseFailure(f"release_link_missing:{link.name}")
        path = link.resolve(strict=True)
    else:
        if (SHA256.fullmatch(_direct_release_id) is None
                or link != releases / _direct_release_id):
            raise ReleaseFailure("release_direct_identity_invalid")
        direct = link.lstat()
        if not stat.S_ISDIR(direct.st_mode) or stat.S_ISLNK(direct.st_mode):
            raise ReleaseFailure("release_direct_identity_invalid")
        path = link.resolve(strict=True)
    try:
        relative = path.relative_to(releases.resolve(strict=True))
    except ValueError as error:
        raise ReleaseFailure(f"release_link_escapes_root:{link.name}") from error
    if len(relative.parts) != 1 or not SHA256.fullmatch(relative.name):
        raise ReleaseFailure("release_id_invalid")
    if (_direct_release_id is not None
            and relative.name != _direct_release_id):
        raise ReleaseFailure("release_direct_identity_invalid")
    verify_acl_free_directory(
        install_root, expected_uid, 0o755,
        "release_permissions_invalid:" + install_root.name,
    )
    verify_acl_free_directory(
        releases, expected_uid, 0o755,
        "release_permissions_invalid:releases",
    )
    verify_acl_free_directory(
        path, expected_uid, 0o555,
        "release_permissions_invalid:" + path.name,
    )
    manifest_path = path / "manifest.json"
    manifest_raw = read_acl_free_regular(
        manifest_path, expected_uid, EXPECTED_MODES["manifest.json"],
        "release_permissions_invalid:manifest.json",
        maximum=1024 * 1024,
    )
    manifest = json.loads(manifest_raw.decode("utf-8"))
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
                PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES,
                PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
                PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES,
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
    payload_values = {
        name: read_acl_free_regular(
            path / name, expected_uid, EXPECTED_MODES[name],
            f"release_permissions_invalid:{name}",
        )
        for name in payloads
    }
    for name, expected in payloads.items():
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise ReleaseFailure("release_manifest_hash_invalid")
        if sha256_bytes(payload_values[name]) != expected:
            raise ReleaseFailure(f"release_payload_hash_mismatch:{name}")
    if "gpgv" in payload_values:
        verify_gpgv_runtime(path, payload_values["gpgv"], expected_uid)
    if "native_stack_coordination_contract" in payloads:
        validate_native_stack_coordination_contract(
            payload_values["native_stack_coordination_contract"])
    if _public_enforcement_only:
        coordination_enforcement = native_stack_coordination_enforcement(
            install_root, expected_uid, allow_absent=True,
        )
        if coordination_enforcement is not None:
            if "native_stack_coordination_contract" not in payloads:
                raise ReleaseFailure(
                    "release_below_native_stack_coordination_floor")
            contract = validate_native_stack_coordination_contract(
                payload_values["native_stack_coordination_contract"]
            )
            if (contract["epoch"]
                    < coordination_enforcement[0]["minimum_epoch"]
                    or not set(coordination_enforcement[0][
                        "minimum_features"
                    ]) <= set(contract["features"])):
                raise ReleaseFailure(
                    "release_below_native_stack_coordination_floor")
    elif not _bootstrap_without_native_coordination_floor:
        coordination_floor = native_stack_coordination_floor(
            install_root, expected_uid, allow_absent=True)
        if coordination_floor is not None:
            if "native_stack_coordination_contract" not in payloads:
                raise ReleaseFailure(
                    "release_below_native_stack_coordination_floor")
            enforce_native_stack_coordination_floor(
                payload_values["native_stack_coordination_contract"],
                install_root, expected_uid,
            )
    if _public_enforcement_only:
        candidate_enforcement = native_host_candidate_replay_enforcement(
            install_root, expected_uid, allow_absent=True,
        )
        if candidate_enforcement is not None:
            if "native_stack_coordination_contract" not in payloads:
                raise ReleaseFailure(
                    "release_below_native_host_candidate_floor")
            contract = validate_native_stack_coordination_contract(
                payload_values["native_stack_coordination_contract"]
            )
            if (candidate_enforcement[0]["required_feature"]
                    not in contract["features"]
                    or candidate_enforcement[0][
                        "required_payload_inventory_sha256"
                    ] != native_host_candidate_inventory_sha256()
                    or set(payloads) != PAYLOAD_NAMES):
                raise ReleaseFailure(
                    "release_below_native_host_candidate_floor")
    elif not _bootstrap_without_candidate_admission_floor:
        candidate_floor = native_host_candidate_floor(
            install_root, expected_uid, allow_absent=True,
        )
        if "native_stack_coordination_contract" in payloads:
            enforce_native_host_candidate_floor(
                payload_values["native_stack_coordination_contract"],
                set(payloads), install_root, expected_uid,
            )
        elif candidate_floor is not None:
            raise ReleaseFailure(
                "release_below_native_host_candidate_floor"
            )
    if (_public_enforcement_only
            and not _bootstrap_without_developer_id_floor):
        signing_enforcement = developer_id_team_enforcement(
            install_root, expected_uid,
        )
        manifest_data = payload_values["authorization_ui_bundle"]
        policy = authorization_ui_signing_policy(
            authorization_ui_bundle_manifest(manifest_data)
        )
        if (policy is None
                or policy["team_id"] != signing_enforcement[0]["team_id"]):
            raise ReleaseFailure("release_developer_id_team_mismatch")
    elif (not _bootstrap_without_developer_id_floor
            and developer_id_team_floor(
                install_root, expected_uid, allow_absent=True,
            ) is not None):
        enforce_release_developer_id_team_floor(
            install_root, path, payloads, expected_uid,
        )
    if LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES <= set(payloads):
        carrier_names = [
            "native_host_products_container",
            "native_host_products_manifest",
            "native_host_products_notarization",
            "authorization_ui_bundle",
            "native_credential_helper_bundle",
            "native_stack_credential_client",
            "native_projection_consumer",
        ]
        if "native_host_products_notarization_signature" in payloads:
            carrier_names.append(
                "native_host_products_notarization_signature"
            )
        verify_native_host_products_container({
            name: payload_values[name]
            for name in carrier_names
        }, require_v2=(
            "native_host_products_notarization_signature" in payloads
        ))
        verify_authorization_ui_bundle(
            path / AUTHORIZATION_UI_APP_NAME,
            payload_values["authorization_ui_bundle"], expected_uid,
        )
        verify_native_credential_helper_bundle(
            path / NATIVE_CREDENTIAL_HELPER_APP_NAME,
            payload_values["native_credential_helper_bundle"], expected_uid,
        )
        native_manifest = native_components_manifest(
            payload_values["native_credential_helper_bundle"]
        )
        enforce_native_component_signer_alignment(
            native_manifest,
            authorization_ui_bundle_manifest(
                payload_values["authorization_ui_bundle"]
            ),
        )
        verify_native_component_signature(
            path / "native_stack_credential_client",
            NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
            native_manifest["signing_policy"]["team_id"],
        )
        verify_native_component_signature(
            path / "native_projection_consumer",
            NATIVE_PROJECTION_CONSUMER_IDENTIFIER,
            native_manifest["signing_policy"]["team_id"],
        )
    if release_identity(payloads) != relative.name:
        raise ReleaseFailure("release_digest_mismatch")
    if ("authorization_broker" in payloads and not allow_below_floor
            and not _public_enforcement_only):
        enforce_execution_approval_floor(
            payload_values["authorization_broker"], expected_uid
        )
    return path, manifest


def verify(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
    *, native_host_generation: Path | None = None,
    expected_native_host_candidate: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    public_only = os.geteuid() != expected_uid
    pair_public = host_release_launcher_pair_public(
        install_root, expected_uid, allow_absent=True,
    )
    if (pair_public is not None
            and pair_public[0]["schema"]
                != HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA):
        raise ReleaseFailure("host_release_launcher_pair_transition_active")
    path, manifest = verified_release(
        install_root, install_root / "current", expected_uid,
        _public_enforcement_only=public_only,
    )
    if public_only:
        public_signing = developer_id_team_enforcement(
            install_root, expected_uid,
        )
        observed_floor = (
            None if public_signing is None else (
                public_signing[0],
                public_signing[0]["authoritative_floor_sha256"],
            )
        )
    else:
        observed_floor = developer_id_team_floor(
            install_root, expected_uid,
        )
    if observed_floor is None:
        raise ReleaseFailure("developer_id_team_floor_missing")
    signing_floor, signing_floor_sha256 = observed_floor
    if (native_host_generation is None) != (
        expected_native_host_candidate is None
    ):
        raise ReleaseFailure("native_host_candidate_binding_incomplete")
    candidate_floor = (
        native_host_candidate_replay_enforcement(
            install_root, expected_uid, allow_absent=True,
        )
        if public_only else native_host_candidate_floor(
            install_root, expected_uid, allow_absent=True,
        )
    )
    authority: dict[str, Any] | None = None
    if candidate_floor is not None:
        (
            authority_repo, authority_generation, authority_candidate,
            authority,
        ) = installed_native_host_candidate_binding(
            install_root, path.name, expected_uid,
            public_only=public_only,
        )
        if (native_host_generation is not None
                and (Path(native_host_generation) != authority_generation
                     or dict(expected_native_host_candidate or {})
                        != authority_candidate)):
            raise ReleaseFailure("native_host_candidate_authority_mismatch")
        repo = authority_repo
        native_host_generation = authority_generation
        expected_native_host_candidate = authority_candidate
    launcher = read_acl_free_regular(
        launcher_path, expected_uid, 0o755,
        "launcher_permissions_invalid",
        maximum=4 * 1024 * 1024,
    )
    if public_only and authority is not None:
        source_launcher = None
    else:
        source_launcher = (
            native_host_candidate_tracked_source(
                repo, native_host_generation, expected_native_host_candidate,
                LAUNCHER_SOURCE,
            )
            if (native_host_generation is not None
                and expected_native_host_candidate is not None)
            else read_regular(repo / LAUNCHER_SOURCE)
        )
    if (source_launcher is not None
            and sha256_bytes(launcher) != sha256_bytes(source_launcher)):
        raise ReleaseFailure("launcher_source_mismatch")
    if (authority is not None
            and (authority["launcher_sha256"] != sha256_bytes(launcher)
                 or authority["payloads"] != manifest["payloads"]
                 or authority["release_id"] != manifest["release_id"])):
        raise ReleaseFailure("native_host_candidate_authority_mismatch")
    if authority is None:
        _, source_hashes, source_id = source_payload(
            repo, op_binary, gpgv_binary,
            native_host_generation=native_host_generation,
            expected_native_host_candidate=expected_native_host_candidate,
        )
    else:
        source_hashes = authority["payloads"]
        source_id = authority["release_id"]
    if manifest["payloads"] != source_hashes or manifest["release_id"] != source_id:
        raise ReleaseFailure("active_release_source_mismatch")
    contract = validate_native_stack_coordination_contract(
        read_acl_free_regular(
            path / "native_stack_coordination_contract", expected_uid,
            EXPECTED_MODES["native_stack_coordination_contract"],
            "host_release_launcher_pair_contract_untrusted",
            maximum=1024 * 1024,
        )
    )
    has_pair_feature = HOST_RELEASE_LAUNCHER_PAIR_FEATURE in contract["features"]
    if has_pair_feature and pair_public is None:
        raise ReleaseFailure("host_release_launcher_pair_missing")
    pair_sha256: str | None = None
    pair_authority_sha256: str | None = None
    pair_tree_sha256: str | None = None
    if pair_public is not None:
        pair_record, pair_sha256, pair_path, pair_manifest, pair_authority = (
            verified_host_release_launcher_pair(
                install_root, launcher_path, expected_uid,
                public_only=public_only,
            )
        )
        if (pair_record != pair_public[0] or pair_path != path
                or pair_manifest != manifest):
            raise ReleaseFailure("host_release_launcher_pair_changed")
        pair_authority_sha256 = native_host_candidate_authority_sha256(
            pair_authority
        )
        pair_tree_sha256 = pair_authority[
            "release_tree_identity_sha256"
        ]
    return {
        "schema": SCHEMA,
        "status": "verified",
        "release_id": path.name,
        "launcher_sha256": sha256_bytes(launcher),
        "payloads": manifest["payloads"],
        "host_release_launcher_pair_sha256": pair_sha256,
        "candidate_authority_sha256": pair_authority_sha256,
        "release_tree_identity_sha256": pair_tree_sha256,
        "developer_id_team_id": signing_floor["team_id"],
        "developer_id_team_floor_sha256": signing_floor_sha256,
        "developer_id_team_floor_release_id": signing_floor[
            "established_from_release_id"
        ],
    }


@host_release_mutation(controller_fence=True)
def rollback(
    repo: Path,
    install_root: Path,
    state_root: Path,
    target_id: str | None,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
    *, launcher_path: Path = DEFAULT_LAUNCHER_PATH,
    authorization_request_id: str | None = None,
    authorization_request_sha256: str | None = None,
    authorized_target_plan_sha256: str | None = None,
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
    enforce_release_native_stack_coordination_compatible(
        target_path, target_manifest, install_root, expected_uid,
    )
    ensure_release_native_deployment_compatible(
        target_manifest, install_root,
    )
    ensure_release_native_catalog_compatible(target_manifest, install_root)
    pair_observed = host_release_launcher_pair_public(
        install_root, expected_uid, allow_absent=True,
    )
    pair_floor_active = (
        release_requires_host_pair_fence(
            current_path, current_manifest, expected_uid,
        )
        or release_requires_host_pair_fence(
            target_path, target_manifest, expected_uid,
        )
    )
    if pair_floor_active and pair_observed is None:
        raise ReleaseFailure("host_release_launcher_pair_missing")
    if pair_observed is not None:
        outstanding = read_pending_host_pair_transition(
            install_root, expected_uid, allow_absent=True,
        )
        if outstanding is not None:
            outstanding_transition, outstanding_root = outstanding
            os.close(outstanding_root)
            execute_host_pair_transition(
                install_root, launcher_path, expected_uid,
                outstanding_transition, raise_after_source_restore=False,
            )
            pair_observed = host_release_launcher_pair_public(
                install_root, expected_uid,
            )
        if (pair_observed is None
                or pair_observed[0]["schema"]
                    != HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA):
            raise ReleaseFailure(
                "host_release_launcher_pair_transition_active"
            )
        source_stable, source_stable_sha256, source_release, source_manifest, (
            source_authority
        ) = verified_host_release_launcher_pair(
            install_root, launcher_path, expected_uid,
        )
        if (source_stable != pair_observed[0]
                or source_stable_sha256 != pair_observed[1]
                or source_release != current_path
                or source_manifest != current_manifest):
            raise ReleaseFailure("host_release_launcher_pair_changed")
        (
            target_repo, target_generation_path, target_candidate,
            target_authority,
        ) = installed_native_host_candidate_binding(
            install_root, target_path.name, expected_uid,
        )
        if target_authority["schema"] \
                != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA:
            raise ReleaseFailure(
                "rollback_native_host_candidate_authority_mismatch"
            )
        target_launcher = native_host_candidate_tracked_source(
            target_repo, target_generation_path, target_candidate,
            LAUNCHER_SOURCE,
        )
        if sha256_bytes(target_launcher) != target_authority["launcher_sha256"]:
            raise ReleaseFailure(
                "rollback_native_host_candidate_authority_mismatch"
            )
        _plan, plan_sha256 = authorized_host_release_rollback_plan(
            source_stable_sha256=source_stable_sha256,
            target_authority=target_authority,
        )
        if (authorized_target_plan_sha256 is None
                or authorized_target_plan_sha256 != plan_sha256):
            raise ReleaseFailure("host_release_target_plan_changed")
        if (authorization_request_id is None
                or authorization_request_sha256 is None):
            raise ReleaseFailure("host_pair_transition_authorization_required")
        authorization_receipt_for_host_pair(
            authorization_request_id, authorization_request_sha256,
            expected_uid, "rollback", plan_sha256,
        )
        retain_launcher_generation(
            install_root,
            read_trusted_stable_launcher(launcher_path, expected_uid),
            expected_uid,
        )
        retain_launcher_generation(
            install_root, target_launcher, expected_uid,
        )
        manages_services = manages_live_touchid_service(
            install_root, expected_uid,
        )
        native_uid = console_user_uid() if manages_services else -1
        old_services = (
            verify_release_host_services(
                current_path, current_manifest, native_uid,
                allow_inactive_native=True,
            )
            if native_uid >= 0 else {}
        )
        transition = begin_host_pair_transition(
            install_root, expected_uid, operation="rollback",
            source_stable=source_stable,
            source_stable_sha256=source_stable_sha256,
            target_pair=host_release_launcher_pair_generation(
                target_authority
            ),
            authorized_target_plan_sha256=plan_sha256,
            old_previous_target=old_previous_target,
            native_uid=native_uid, old_services=old_services,
            signing_floor=signing_floor,
            signing_floor_sha256=signing_floor_sha256,
            authorization_request_id=authorization_request_id,
            authorization_request_sha256=authorization_request_sha256,
        )
        stable, stable_sha256 = execute_host_pair_transition(
            install_root, launcher_path, expected_uid, transition,
        )
        return {
            "schema": SCHEMA,
            "status": "rolled_back",
            "release_id": target_path.name,
            "repo_match": True,
            "warning": None,
            "developer_id_team_id": signing_floor["team_id"],
            "developer_id_team_floor_sha256": signing_floor_sha256,
            "developer_id_team_floor_release_id": signing_floor[
                "established_from_release_id"
            ],
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "host_release_launcher_pair_sha256": stable_sha256,
            "candidate_authority_sha256": stable["pair"][
                "candidate_authority_sha256"
            ],
            "release_tree_identity_sha256": stable["pair"][
                "release_tree_identity_sha256"
            ],
        }
    candidate_floor = native_host_candidate_floor(
        install_root, expected_uid, allow_absent=True,
    )
    def require_candidate_rollback_binding(
        release: Path, manifest: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if candidate_floor is None:
            return None
        authority = installed_native_host_candidate_binding(
            install_root, release.name, expected_uid,
        )[3]
        stable_launcher_sha256 = sha256_bytes(
            read_trusted_stable_launcher(launcher_path, expected_uid)
        )
        if (authority["release_id"] != release.name
                or authority["payloads"] != manifest["payloads"]
                or authority["launcher_sha256"]
                    != stable_launcher_sha256):
            raise ReleaseFailure(
                "rollback_native_host_candidate_authority_mismatch")
        return authority

    if candidate_floor is not None:
        require_candidate_rollback_binding(current_path, current_manifest)
        require_candidate_rollback_binding(target_path, target_manifest)
        repo_match: bool | None = True
    else:
        try:
            _, _, source_id = source_payload(repo, op_binary, gpgv_binary)
            repo_match = target_path.name == source_id
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
        require_candidate_rollback_binding(target_path, target_manifest)

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
        require_candidate_rollback_binding(target_path, target_manifest)
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
            if LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES <= set(
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
        require_candidate_rollback_binding(target_path, target_manifest)
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
            require_candidate_rollback_binding(
                recovered_path, recovered_manifest,
            )
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


def verify_launcher_migration_backup(
    install_root: Path, expected_uid: int, expected_sha256: str,
) -> None:
    if SHA256.fullmatch(expected_sha256) is None:
        raise ReleaseFailure("expected_launcher_hash_invalid")
    backup_root = install_root / "launcher-backups"
    backup = backup_root / expected_sha256
    try:
        root_info = backup_root.lstat()
        backup_info = backup.lstat()
    except OSError as error:
        raise ReleaseFailure("launcher_migration_backup_missing") from error
    verify_acl_free_directory(
        backup_root, expected_uid, 0o555,
        "launcher_migration_backup_invalid",
    )
    if (
        not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != expected_uid
        or stat.S_IMODE(root_info.st_mode) != 0o555
        or not stat.S_ISREG(backup_info.st_mode)
        or stat.S_ISLNK(backup_info.st_mode)
        or backup_info.st_uid != expected_uid or backup_info.st_nlink != 1
        or stat.S_IMODE(backup_info.st_mode) != 0o555
        or sha256_bytes(read_acl_free_regular(
            backup, expected_uid, 0o555,
            "launcher_migration_backup_invalid", maximum=16 * 1024 * 1024,
        )) != expected_sha256
    ):
        raise ReleaseFailure("launcher_migration_backup_invalid")


def retain_launcher_generation(
    install_root: Path, launcher: bytes, expected_uid: int,
) -> tuple[Path, str]:
    launcher_sha256 = sha256_bytes(launcher)
    backup_root = install_root / "launcher-backups"
    if not backup_root.exists():
        backup_root.mkdir(mode=0o755)
        os.chmod(backup_root, 0o555)
        fsync_directory(install_root)
    verify_acl_free_directory(
        backup_root, expected_uid, 0o555,
        "launcher_backup_root_untrusted",
    )
    backup = backup_root / launcher_sha256
    if not backup.exists():
        os.chmod(backup_root, 0o755)
        try:
            descriptor = os.open(
                backup,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                0o555,
            )
            try:
                write_all(descriptor, launcher, "launcher_backup")
                os.fchmod(descriptor, 0o555)
                reject_extended_acl(descriptor, "launcher_backup_mismatch")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(backup_root)
        finally:
            os.chmod(backup_root, 0o555)
            fsync_directory(install_root)
    verify_launcher_migration_backup(
        install_root, expected_uid, launcher_sha256,
    )
    return backup, launcher_sha256


def install_launcher_generation(
    install_root: Path, launcher_path: Path, launcher_sha256: str,
    expected_uid: int,
) -> tuple[bytes, dict[str, Any]]:
    verify_launcher_migration_backup(
        install_root, expected_uid, launcher_sha256,
    )
    source = read_acl_free_regular(
        install_root / "launcher-backups" / launcher_sha256,
        expected_uid, 0o555, "launcher_migration_backup_invalid",
        maximum=16 * 1024 * 1024,
    )
    temporary = launcher_path.parent / (
        f".{launcher_path.name}.pair-{os.getpid()}-{uuid.uuid4()}"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o755,
    )
    try:
        write_all(descriptor, source, "stable_launcher")
        os.fchmod(descriptor, 0o755)
        reject_extended_acl(descriptor, "stable_launcher_untrusted")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, launcher_path)
    fsync_directory(launcher_path.parent)
    observed, identity = read_trusted_stable_launcher_identity(
        launcher_path, expected_uid,
    )
    if sha256_bytes(observed) != launcher_sha256:
        raise ReleaseFailure("stable_launcher_generation_mismatch")
    return observed, identity


@host_release_mutation()
def migrate_launcher(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    expected_installed_sha256: str,
    expected_replacement_sha256: str,
    _selector: Path | None = None,
    *, native_host_generation: Path | None = None,
    expected_native_host_candidate: Mapping[str, object] | None = None,
    expected_source_release_id: str | None = None,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    pair_path_exists = os.path.lexists(
        install_root / HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
    )
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if not SHA256.fullmatch(expected_installed_sha256) or not SHA256.fullmatch(expected_replacement_sha256):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    selected_release, selected_manifest = verified_release(
        install_root,
        install_root / "current" if _selector is None else _selector,
        expected_uid, allow_legacy=True,
        _bootstrap_without_native_coordination_floor=_selector is not None,
    )
    if pair_path_exists:
        raise ReleaseFailure("stable_launcher_pair_transition_required")
    if release_requires_host_pair_fence(
        selected_release, selected_manifest, expected_uid,
    ):
        raise ReleaseFailure("host_release_launcher_pair_missing")
    candidate_floor = native_host_candidate_floor(
        install_root, expected_uid, allow_absent=True,
    )
    candidate_binding = (
        native_host_generation is not None,
        expected_native_host_candidate is not None,
        expected_source_release_id is not None,
    )
    if candidate_floor is not None or any(candidate_binding):
        if not all(candidate_binding):
            raise ReleaseFailure("native_host_candidate_record_required")
        assert native_host_generation is not None
        assert expected_native_host_candidate is not None
        assert expected_source_release_id is not None
        values, _hashes, source_release_id = source_payload(
            repo, op_binary, gpgv_binary,
            native_host_generation=native_host_generation,
            expected_native_host_candidate=expected_native_host_candidate,
        )
        if (SHA256.fullmatch(expected_source_release_id) is None
                or source_release_id != expected_source_release_id):
            raise ReleaseFailure("source_release_id_unexpected")
        if candidate_floor is not None:
            enforce_native_host_candidate_floor(
                values["native_stack_coordination_contract"], set(values),
                install_root, expected_uid,
            )
        replacement = native_host_candidate_tracked_source(
            repo, native_host_generation, expected_native_host_candidate,
            LAUNCHER_SOURCE,
        )
    else:
        replacement = read_regular(repo / LAUNCHER_SOURCE)
    installed = read_trusted_stable_launcher(launcher_path, expected_uid)
    installed_hash = sha256_bytes(installed)
    if installed_hash != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    info = launcher_path.stat()
    if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o755:
        raise ReleaseFailure("launcher_permissions_invalid")
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
    verify_acl_free_directory(
        backup_root, expected_uid, 0o555,
        "launcher_backup_root_untrusted",
    )
    backup = backup_root / installed_hash
    if not backup.exists():
        exact_mode(backup_root, 0o755)
        descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o555)
        try:
            write_all(descriptor, installed, "launcher_backup")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o555)
            reject_extended_acl(descriptor, "launcher_backup_mismatch")
        finally:
            os.close(descriptor)
        exact_mode(backup_root, 0o555)
        fsync_directory(backup_root)
        verify_acl_free_directory(
            backup_root, expected_uid, 0o555,
            "launcher_backup_root_untrusted",
        )
    else:
        backup_info = backup.stat()
        if (backup_info.st_uid != expected_uid or stat.S_IMODE(backup_info.st_mode) != 0o555
                or sha256_bytes(read_acl_free_regular(
                    backup, expected_uid, 0o555,
                    "launcher_backup_mismatch", maximum=16 * 1024 * 1024,
                )) != installed_hash):
            raise ReleaseFailure("launcher_backup_mismatch")
    temporary = launcher_path.parent / f".{launcher_path.name}.migration-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    try:
        write_all(descriptor, replacement, "launcher_migration")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o755)
        reject_extended_acl(descriptor, "stable_launcher_untrusted")
    finally:
        os.close(descriptor)
    os.replace(temporary, launcher_path)
    fsync_directory(launcher_path.parent)
    if sha256_bytes(read_trusted_stable_launcher(
        launcher_path, expected_uid,
    )) != replacement_hash:
        raise ReleaseFailure("launcher_migration_verification_failed")
    native_coordination_bootstrap_checkpoint(
        "launcher-replacement-published")
    return {
        "schema": SCHEMA,
        "status": "launcher_migrated",
        "previous_launcher_sha256": installed_hash,
        "launcher_sha256": replacement_hash,
        "backup": str(backup),
    }


def materialize_clean_authorization_predecessor(
    install_root: Path, launcher_path: Path, expected_uid: int,
    values: Mapping[str, bytes], expected_predecessor_release_id: str,
    launcher: bytes,
) -> Path:
    """Create or replay the exact candidate-derived clean-machine scaffold."""
    predecessor_values = {
        name: values[name] for name in PRE_AUTHORIZATION_PAYLOAD_NAMES
    }
    predecessor_hashes = {
        name: sha256_bytes(value)
        for name, value in predecessor_values.items()
    }
    predecessor_id = release_identity(predecessor_hashes)
    if (SHA256.fullmatch(expected_predecessor_release_id) is None
            or predecessor_id != expected_predecessor_release_id):
        raise ReleaseFailure("authorization_bootstrap_predecessor_changed")
    launcher_sha256 = sha256_bytes(launcher)
    launcher_present = os.path.lexists(launcher_path)
    if launcher_present and sha256_bytes(read_trusted_stable_launcher(
        launcher_path, expected_uid,
    )) != launcher_sha256:
        raise ReleaseFailure(
            "authorization_bootstrap_clean_state_ambiguous")
    current = install_root / "current"
    predecessor_link = (
        install_root / AUTHORIZATION_COORDINATION_PREDECESSOR_NAME)
    if current.is_symlink() or os.path.lexists(current):
        raise ReleaseFailure("authorization_bootstrap_clean_state_ambiguous")
    if not predecessor_link.is_symlink():
        if os.path.lexists(predecessor_link):
            raise ReleaseFailure(
                "authorization_coordination_predecessor_invalid")
        allowed = {"releases"}
        if any(entry.name not in allowed for entry in install_root.iterdir()):
            raise ReleaseFailure(
                "authorization_bootstrap_clean_state_ambiguous")
    releases = prepare_release_root(install_root, expected_uid)
    final = releases / predecessor_id
    if not final.exists():
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
        try:
            for name, value in predecessor_values.items():
                descriptor = os.open(
                    staging / name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    EXPECTED_MODES[name],
                )
                try:
                    write_all(
                        descriptor, value,
                        "authorization_bootstrap_predecessor_payload",
                    )
                    os.fchmod(descriptor, EXPECTED_MODES[name])
                    os.fsync(descriptor)
                    reject_extended_acl(
                        descriptor,
                        "authorization_bootstrap_predecessor_untrusted",
                    )
                finally:
                    os.close(descriptor)
            manifest = {
                "payloads": predecessor_hashes,
                "release_id": predecessor_id,
                "schema": SCHEMA,
            }
            descriptor = os.open(
                staging / "manifest.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                EXPECTED_MODES["manifest.json"],
            )
            try:
                write_all(
                    descriptor, canonical_state_record(manifest),
                    "authorization_bootstrap_predecessor_manifest",
                )
                os.fchmod(
                    descriptor, EXPECTED_MODES["manifest.json"])
                os.fsync(descriptor)
                reject_extended_acl(
                    descriptor,
                    "authorization_bootstrap_predecessor_untrusted",
                )
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
        native_coordination_bootstrap_checkpoint(
            "authorization-clean-predecessor-published")
    verified_path, manifest = verified_release(
        install_root, final, expected_uid, allow_legacy=True,
        _bootstrap_without_developer_id_floor=True,
        _bootstrap_without_native_coordination_floor=True,
        _bootstrap_without_candidate_admission_floor=True,
        _direct_release_id=predecessor_id,
    )
    if set(manifest["payloads"]) != PRE_AUTHORIZATION_PAYLOAD_NAMES:
        raise ReleaseFailure("authorization_bootstrap_predecessor_invalid")
    if predecessor_link.is_symlink():
        selected, _selected_manifest = verified_release(
            install_root, predecessor_link, expected_uid, allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
            _bootstrap_without_native_coordination_floor=True,
            _bootstrap_without_candidate_admission_floor=True,
        )
        if selected.name != predecessor_id:
            raise ReleaseFailure(
                "authorization_coordination_predecessor_changed")
    else:
        atomic_symlink(f"releases/{predecessor_id}", predecessor_link)
        native_coordination_bootstrap_checkpoint(
            "authorization-clean-predecessor-selected")
    if launcher_present:
        # Re-read after predecessor publication so a concurrent privileged
        # replacement cannot be accepted merely because the preflight matched.
        if sha256_bytes(read_trusted_stable_launcher(
            launcher_path, expected_uid,
        )) != launcher_sha256:
            raise ReleaseFailure(
                "authorization_bootstrap_clean_state_ambiguous")
    else:
        parent = open_trusted_absolute_directory(
            launcher_path.parent, expected_uid,
        )
        temporary = f".{launcher_path.name}.bootstrap-{os.getpid()}-{uuid.uuid4()}"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o755, dir_fd=parent,
            )
            write_all(
                descriptor, launcher,
                "authorization_bootstrap_clean_launcher",
            )
            os.fchmod(descriptor, 0o755)
            os.fsync(descriptor)
            reject_extended_acl(
                descriptor, "stable_launcher_untrusted")
            os.close(descriptor)
            descriptor = -1
            try:
                os.stat(
                    launcher_path.name, dir_fd=parent,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                os.rename(
                    temporary, launcher_path.name,
                    src_dir_fd=parent, dst_dir_fd=parent,
                )
                os.fsync(parent)
            else:
                raise ReleaseFailure(
                    "authorization_bootstrap_clean_state_ambiguous")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)
        if sha256_bytes(read_trusted_stable_launcher(
            launcher_path, expected_uid,
        )) != launcher_sha256:
            raise ReleaseFailure(
                "authorization_bootstrap_clean_launcher_failed")
        native_coordination_bootstrap_checkpoint(
            "authorization-clean-launcher-published")
    return verified_path


@host_release_mutation(initialize=True, controller_fence=True)
def bootstrap_authorization(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    expected_source_release_id: str,
    expected_installed_sha256: str,
    expected_replacement_sha256: str,
    native_host_candidate: Mapping[str, object],
    expected_developer_id_team_id: str,
    expected_candidate_authorization_manifest_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
    *, expected_bootstrap_predecessor_release_id: str = "",
    clean_machine_bootstrap: bool = False,
) -> dict[str, Any]:
    """Install the first broker behind the irreversible coordination fence."""
    if not SHA256.fullmatch(expected_source_release_id):
        raise ReleaseFailure("expected_source_release_id_required")
    generation_value = native_host_candidate.get("generation_path")
    if not isinstance(generation_value, str):
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    generation = Path(generation_value)
    values, _hashes, source_release_id = source_payload(
        repo, op_binary, gpgv_binary,
        native_host_generation=generation,
        expected_native_host_candidate=native_host_candidate,
    )
    if source_release_id != expected_source_release_id:
        raise ReleaseFailure("source_release_id_unexpected")
    candidate_authorization_manifest = values.get("authorization_ui_bundle")
    if (not isinstance(candidate_authorization_manifest, bytes)
            or re.fullmatch(
                r"[A-Z0-9]{10}", expected_developer_id_team_id) is None
            or expected_developer_id_team_id
                != NATIVE_HOST_PRODUCTS_TEAM_ID
            or SHA256.fullmatch(
                expected_candidate_authorization_manifest_sha256) is None
            or sha256_bytes(candidate_authorization_manifest)
                != expected_candidate_authorization_manifest_sha256):
        raise ReleaseFailure("bootstrap_developer_id_binding_invalid")
    current_link = install_root / "current"
    predecessor_link = (
        install_root / AUTHORIZATION_COORDINATION_PREDECESSOR_NAME)
    if (clean_machine_bootstrap and not current_link.is_symlink()):
        replacement_launcher = native_host_candidate_tracked_source(
            repo, generation, native_host_candidate, LAUNCHER_SOURCE,
        )
        replacement_launcher_sha256 = sha256_bytes(replacement_launcher)
        if (SHA256.fullmatch(expected_installed_sha256) is None
                or SHA256.fullmatch(expected_replacement_sha256) is None
                or expected_installed_sha256
                    != replacement_launcher_sha256
                or expected_replacement_sha256
                    != replacement_launcher_sha256):
            raise ReleaseFailure(
                "authorization_bootstrap_clean_launcher_binding_invalid")
        materialize_clean_authorization_predecessor(
            install_root, launcher_path, expected_uid, values,
            expected_bootstrap_predecessor_release_id,
            replacement_launcher,
        )
    current_was_present = current_link.is_symlink()
    selected_link = (
        current_link if current_was_present else predecessor_link)
    current_path, current_manifest = verified_release(
        install_root, selected_link, expected_uid, allow_legacy=True,
        _bootstrap_without_developer_id_floor=True,
        _bootstrap_without_native_coordination_floor=True,
        _bootstrap_without_candidate_admission_floor=True,
    )
    if (expected_bootstrap_predecessor_release_id
            and current_path.name != expected_bootstrap_predecessor_release_id):
        if current_path.name != source_release_id:
            raise ReleaseFailure(
                "authorization_bootstrap_predecessor_changed")
    if current_path.name == source_release_id:
        signing_floor = developer_id_team_floor(
            install_root, expected_uid,
        )
        if signing_floor is None:
            raise ReleaseFailure("developer_id_team_floor_missing")
        establish_developer_id_team_enforcement(
            install_root, expected_uid,
            signing_floor[0], signing_floor[1],
        )
        establish_native_stack_coordination_floor(
            install_root, expected_uid, release_id=source_release_id,
            contract_raw=values["native_stack_coordination_contract"],
        )
        recover_named_host_pair_bootstrap(
            install_root, launcher_path, expected_uid,
            mode=NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE,
            release_id=source_release_id,
            candidate_record=native_host_candidate,
        )
        recovered = recover_terminal_schema_service(
            repo, current_path, install_root, launcher_path, expected_uid,
            expected_source_release_id, op_binary, gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=native_host_candidate,
        )
        if recovered is None:
            raise ReleaseFailure("authorization_broker_already_deployed")
        recovered.update({
            "status": "authorization_bootstrapped",
            "launcher_migrated": False,
            "recovered_existing_release": True,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_AUTHORIZATION_PAYLOAD_NAMES:
        raise ReleaseFailure("authorization_bootstrap_predecessor_invalid")
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if (
        SHA256.fullmatch(expected_installed_sha256) is None
        or SHA256.fullmatch(expected_replacement_sha256) is None
    ):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
    replacement_launcher = native_host_candidate_tracked_source(
        repo, generation, native_host_candidate, LAUNCHER_SOURCE,
    )
    replacement_sha256 = sha256_bytes(replacement_launcher)
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    launcher_migration_recovered = False
    if installed_sha256 != expected_installed_sha256:
        if current_was_present or installed_sha256 != replacement_sha256:
            raise ReleaseFailure("installed_launcher_hash_unexpected")
        verify_launcher_migration_backup(
            install_root, expected_uid, expected_installed_sha256)
        launcher_migrated = True
        launcher_migration_recovered = True
    if predecessor_link.is_symlink():
        predecessor_path, _predecessor_manifest = verified_release(
            install_root, predecessor_link, expected_uid,
            allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
            _bootstrap_without_native_coordination_floor=True,
            _bootstrap_without_candidate_admission_floor=True,
        )
        if predecessor_path.name != current_path.name:
            raise ReleaseFailure(
                "authorization_coordination_predecessor_changed")
    elif os.path.lexists(predecessor_link):
        raise ReleaseFailure(
            "authorization_coordination_predecessor_invalid")
    else:
        atomic_symlink(f"releases/{current_path.name}", predecessor_link)
    if current_link.is_symlink():
        current_recheck, _current_manifest = verified_release(
            install_root, current_link, expected_uid, allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
            _bootstrap_without_native_coordination_floor=True,
            _bootstrap_without_candidate_admission_floor=True,
        )
        if current_recheck.name != current_path.name:
            raise ReleaseFailure("authorization_coordination_current_changed")
        if manages_live_touchid_service(install_root, expected_uid):
            stop_and_fence_host_services(console_user_uid())
        live = active_markers(state_root)
        if live:
            raise ReleaseFailure(
                "active_controller_invocations:" + ",".join(live))
        current_link.unlink()
        fsync_directory(install_root)
        native_coordination_bootstrap_checkpoint(
            "authorization-current-unlinked")
    elif os.path.lexists(current_link):
        raise ReleaseFailure("release_link_invalid:current")
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
            _selector=predecessor_link,
            native_host_generation=generation,
            expected_native_host_candidate=native_host_candidate,
            expected_source_release_id=source_release_id,
            op_binary=op_binary, gpgv_binary=gpgv_binary,
        )
        launcher_migrated = True
        native_coordination_bootstrap_checkpoint(
            "authorization-launcher-replaced")
    establish_native_host_candidate_floor(
        install_root, expected_uid, release_id=source_release_id,
        candidate_record=native_host_candidate,
        establishment_mode=(
            NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE
        ),
        predecessor_release_id=current_path.name,
        _public_only=True,
    )
    native_host_candidate_bootstrap_checkpoint(
        "authorization-candidate-enforcement-published"
    )
    signing_floor, signing_floor_sha256 = (
        bootstrap_developer_id_team_floor_from_candidate(
            repo, install_root, expected_uid, values, source_release_id,
            generation, native_host_candidate,
            expected_developer_id_team_id,
            expected_candidate_authorization_manifest_sha256,
        )
    )
    establish_developer_id_team_enforcement(
        install_root, expected_uid, signing_floor, signing_floor_sha256,
    )
    establish_native_stack_coordination_floor(
        install_root, expected_uid, release_id=source_release_id,
        contract_raw=values["native_stack_coordination_contract"],
    )
    establish_native_host_candidate_floor(
        install_root, expected_uid, release_id=source_release_id,
        candidate_record=native_host_candidate,
        establishment_mode=(
            NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE
        ),
        predecessor_release_id=current_path.name,
    )
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
        native_host_generation=generation,
        expected_native_host_candidate=native_host_candidate,
        _host_pair_bootstrap_mode=(
            NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE
        ),
    )
    result.update({
        "status": "authorization_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "launcher_migration_recovered": launcher_migration_recovered,
        "previous_release_id": current_path.name,
    })
    return result


def recover_terminal_schema_service(
    repo: Path, current_path: Path, install_root: Path, launcher_path: Path,
    expected_uid: int, expected_source_release_id: str,
    op_binary: Path, gpgv_binary: Path,
    *, native_host_generation: Path | None = None,
    expected_native_host_candidate: Mapping[str, object] | None = None,
) -> dict[str, Any] | None:
    """Finish a schema bootstrap that committed `current` before daemon re-exec."""
    if current_path.name != expected_source_release_id:
        return None
    result = verify(
        repo, install_root, launcher_path, expected_uid, op_binary, gpgv_binary,
        native_host_generation=native_host_generation,
        expected_native_host_candidate=expected_native_host_candidate,
    )
    if result.get("release_id") != expected_source_release_id:
        raise ReleaseFailure("schema_bootstrap_recovery_release_mismatch")
    if manages_live_touchid_service(install_root, expected_uid):
        if expected_native_host_candidate is not None:
            current_manifest = json.loads(
                read_regular(current_path / "manifest.json").decode("utf-8")
            )
            native_uid = console_user_uid()
            install_release_host_services(
                current_path, current_manifest, native_uid,
            )
            verify_release_host_services(
                current_path, current_manifest, native_uid,
            )
        else:
            restart_touchid_service()
    result["recovered_existing_release"] = True
    return result


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation(
    controller_fence=True, legacy_native_coordination=True)
def bootstrap_native_deployment_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time fenced migration to the two-way coordination contract."""
    current_link = install_root / "current"
    predecessor_link = (
        install_root / NATIVE_STACK_COORDINATION_PREDECESSOR_NAME
    )
    current_was_present = current_link.is_symlink()
    selected_link = (
        current_link if current_was_present else predecessor_link
    )
    current_path, current_manifest = verified_release(
        install_root, selected_link, expected_uid, allow_legacy=True,
        _bootstrap_without_native_coordination_floor=True,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    source_values, _hashes, source_release_id = source_payload(
        repo, op_binary, gpgv_binary,
    )
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    current_payload_names = set(current_manifest["payloads"])
    if current_path.name == source_release_id:
        if manages_live_touchid_service(install_root, expected_uid):
            stop_and_fence_host_services(console_user_uid())
        native_coordination_bootstrap_checkpoint(
            "before-floor-publication")
        establish_native_stack_coordination_floor(
            install_root, expected_uid, release_id=source_release_id,
            contract_raw=source_values[
                "native_stack_coordination_contract"],
        )
        native_coordination_bootstrap_checkpoint("floor-published")
        recovered = recover_terminal_schema_service(
            repo, current_path, install_root, launcher_path, expected_uid,
            expected_source_release_id, op_binary, gpgv_binary,
        )
        if recovered is None:
            raise ReleaseFailure(
                "native_deployment_schema_migration_not_required")
        establish_native_stack_coordination_floor(
            install_root, expected_uid, release_id=source_release_id,
            contract_raw=source_values[
                "native_stack_coordination_contract"],
        )
        recovered.update({
            "status": "native_deployment_schema_bootstrapped",
            "launcher_migrated": False,
        })
        return recovered
    if current_payload_names not in {
        frozenset(PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES),
        frozenset(PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES),
    }:
        raise ReleaseFailure(
            "native_deployment_schema_predecessor_invalid"
        )
    if (
        SHA256.fullmatch(expected_installed_sha256) is None
        or SHA256.fullmatch(expected_replacement_sha256) is None
    ):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    launcher_migration_recovered = False
    if installed_sha256 != expected_installed_sha256:
        if current_was_present or installed_sha256 != replacement_sha256:
            raise ReleaseFailure("installed_launcher_hash_unexpected")
        verify_launcher_migration_backup(
            install_root, expected_uid, expected_installed_sha256)
        launcher_migrated = True
        launcher_migration_recovered = True
    if predecessor_link.is_symlink():
        predecessor_path, _predecessor_manifest = verified_release(
            install_root, predecessor_link, expected_uid,
            allow_legacy=True,
            _bootstrap_without_native_coordination_floor=True,
        )
        if predecessor_path.name != current_path.name:
            raise ReleaseFailure(
                "native_coordination_predecessor_changed")
    elif os.path.lexists(predecessor_link):
        raise ReleaseFailure("native_coordination_predecessor_invalid")
    else:
        atomic_symlink(
            f"releases/{current_path.name}", predecessor_link)
    if current_link.is_symlink():
        current_recheck, _current_manifest = verified_release(
            install_root, current_link, expected_uid, allow_legacy=True,
            _bootstrap_without_native_coordination_floor=True,
        )
        if current_recheck.name != current_path.name:
            raise ReleaseFailure("native_coordination_current_changed")
        if manages_live_touchid_service(install_root, expected_uid):
            stop_and_fence_host_services(console_user_uid())
        native_coordination_bootstrap_checkpoint("predecessor-fenced")
        current_link.unlink()
        fsync_directory(install_root)
        native_coordination_bootstrap_checkpoint("current-unlinked")
    elif os.path.lexists(current_link):
        raise ReleaseFailure("release_link_invalid:current")
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
            _selector=predecessor_link,
        )
        launcher_migrated = True
        native_coordination_bootstrap_checkpoint(
            "native-coordination-launcher-replaced")
    native_coordination_bootstrap_checkpoint("before-floor-publication")
    establish_native_stack_coordination_floor(
        install_root, expected_uid, release_id=source_release_id,
        contract_raw=source_values["native_stack_coordination_contract"],
    )
    native_coordination_bootstrap_checkpoint("floor-published")
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status": "native_deployment_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "launcher_migration_recovered": launcher_migration_recovered,
        "previous_release_id": current_path.name,
        "coordination_floor_established": True,
    })
    return result


@host_release_mutation(controller_fence=True)
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
    current_was_present = current_link.is_symlink()
    if current_was_present:
        current_path, current_manifest = verified_release(
            install_root, current_link, expected_uid,
            allow_legacy=True, _bootstrap_without_developer_id_floor=True,
        )
    elif os.path.lexists(current_link):
        raise ReleaseFailure("release_link_invalid:current")
    else:
        current_path, current_manifest = (
            verified_developer_id_migration_predecessor(
                install_root, expected_uid, expected_current_release_id,
            )
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
        floor, _floor_sha256 = existing_floor
        if floor["team_id"] != expected_developer_id_team_id:
            raise ReleaseFailure("developer_id_migration_floor_mismatch")
        predecessor_recovered = False
        if predecessor_link.is_symlink():
            if (floor["established_from_release_id"]
                    != expected_current_release_id
                    or floor[
                        "established_from_authorization_manifest_sha256"
                    ] != expected_current_authorization_manifest_sha256):
                raise ReleaseFailure("developer_id_migration_floor_mismatch")
            predecessor_path, predecessor_manifest = (
                verified_developer_id_migration_predecessor(
                    install_root, expected_uid,
                    expected_current_release_id,
                )
            )
            if (set(predecessor_manifest["payloads"])
                    != PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES):
                raise ReleaseFailure(
                    "native_vendor_schema_predecessor_invalid")
            predecessor_authorization_manifest = read_regular(
                predecessor_path / "authorization_ui_bundle")
            if sha256_bytes(predecessor_authorization_manifest) != (
                expected_current_authorization_manifest_sha256
            ):
                raise ReleaseFailure(
                    "current_authorization_manifest_changed")
            predecessor_policy = (
                verified_existing_authorization_ui_anchor_policy(
                    predecessor_path / AUTHORIZATION_UI_APP_NAME,
                    predecessor_authorization_manifest, expected_uid,
                )
            )
            if (predecessor_policy["team_id"]
                    != expected_developer_id_team_id
                    or candidate_policy["team_id"]
                        != predecessor_policy["team_id"]):
                raise ReleaseFailure("release_developer_id_team_mismatch")
            predecessor_recovered = True
        elif os.path.lexists(predecessor_link):
            raise ReleaseFailure(
                "developer_id_migration_predecessor_invalid")
        elif expected_current_release_id == source_release_id:
            if expected_current_authorization_manifest_sha256 != (
                expected_candidate_authorization_manifest_sha256
            ):
                raise ReleaseFailure(
                    "developer_id_migration_completed_binding_invalid")
        elif (floor["established_from_release_id"]
                != expected_current_release_id
                or floor[
                    "established_from_authorization_manifest_sha256"
                ] != expected_current_authorization_manifest_sha256):
            raise ReleaseFailure("developer_id_migration_floor_mismatch")
        native_stack_coordination_floor(install_root, expected_uid)
        enforce_native_stack_coordination_floor(
            values["native_stack_coordination_contract"],
            install_root, expected_uid,
        )
        verified = verify(
            repo, install_root, launcher_path, expected_uid,
            op_binary, gpgv_binary,
        )
        if manages_live_touchid_service(install_root, expected_uid):
            native_uid = console_user_uid()
            try:
                install_release_host_services(
                    current_path, current_manifest, native_uid,
                )
                verify_release_host_services(
                    current_path, current_manifest, native_uid,
                )
            except BaseException as service_error:
                fence_errors: list[BaseException] = []
                for stop in (
                    stop_touchid_service,
                    lambda: stop_native_credential_service(uid=native_uid),
                ):
                    try:
                        stop()
                    except BaseException as error:
                        fence_errors.append(error)
                if fence_errors:
                    raise ReleaseFailure(
                        "developer_id_migration_service_fence_unproven"
                    ) from service_error
                raise
        if predecessor_recovered:
            predecessor_link.unlink()
            fsync_directory(install_root)
        verified.update({
            "status": "native_vendor_developer_id_schema_bootstrapped",
            "recovered_existing_release": True,
            "recovered_migration_predecessor": predecessor_recovered,
            "previous_release_id": floor[
                "established_from_release_id"],
            "coordination_floor_established": True,
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

    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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
        verified_developer_id_migration_predecessor(
            install_root, expected_uid, current_path.name,
        )
    elif os.path.lexists(predecessor_link):
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
    native_coordination_bootstrap_checkpoint(
        "developer-id-before-floor-publication")
    _coordination_floor, coordination_floor_published = (
        ensure_developer_id_migration_coordination_floor(
            install_root, expected_uid, release_id=source_release_id,
            contract_raw=values["native_stack_coordination_contract"],
        )
    )
    native_coordination_bootstrap_checkpoint("developer-id-floor-published")
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
        "coordination_floor_established": True,
        "coordination_floor_published": coordination_floor_published,
    })
    return result


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


@host_release_mutation(controller_fence=True)
def bootstrap_native_host_candidate_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    native_host_candidate: Mapping[str, object],
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """Migrate only the exact installed pre-candidate-record generation."""
    if (expected_current_release_id != "absent"
            and SHA256.fullmatch(expected_current_release_id) is None
            or not SHA256.fullmatch(expected_source_release_id)
            or not SHA256.fullmatch(expected_installed_sha256)
            or not SHA256.fullmatch(expected_replacement_sha256)):
        raise ReleaseFailure("native_host_candidate_schema_binding_invalid")
    generation_value = native_host_candidate.get("generation_path")
    if not isinstance(generation_value, str):
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    generation = Path(generation_value)
    if native_host_candidate_record(
        repo, generation,
    ) != dict(native_host_candidate):
        raise ReleaseFailure("native_host_candidate_record_mismatch")
    values, _hashes, source_release_id = source_payload(
        repo, op_binary, gpgv_binary,
        native_host_generation=generation,
        expected_native_host_candidate=native_host_candidate,
    )
    if (source_release_id != expected_source_release_id
            or set(values) != PAYLOAD_NAMES):
        raise ReleaseFailure("source_release_id_unexpected")
    if expected_current_release_id not in {
        NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID,
        source_release_id, "absent",
    }:
        raise ReleaseFailure("native_host_candidate_schema_binding_invalid")
    contract = validate_native_stack_coordination_contract(
        values["native_stack_coordination_contract"]
    )
    if NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE not in contract["features"]:
        raise ReleaseFailure("native_host_candidate_feature_missing")
    current_link = install_root / "current"
    current_was_selected = current_link.is_symlink()
    if current_was_selected:
        if expected_current_release_id == "absent":
            raise ReleaseFailure("current_release_id_unexpected")
        current_path, current_manifest = verified_release(
            install_root, current_link, expected_uid,
            allow_legacy=True,
            _bootstrap_without_candidate_admission_floor=True,
        )
        if current_path.name != expected_current_release_id:
            raise ReleaseFailure("current_release_id_unexpected")
    elif os.path.lexists(current_link):
        raise ReleaseFailure("release_link_invalid:current")
    else:
        if expected_current_release_id != "absent":
            raise ReleaseFailure("current_release_id_unexpected")
        current_path, current_manifest = verified_release(
            install_root,
            install_root / "releases"
                / NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID,
            expected_uid, allow_legacy=True,
            _bootstrap_without_candidate_admission_floor=True,
            _direct_release_id=(
                NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
            ),
        )
    predecessor_selected = (
        current_path.name
        == NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
    )
    candidate_selected = current_path.name == source_release_id
    if (predecessor_selected
            and current_manifest.get("payloads")
                != NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS
            or not predecessor_selected and not candidate_selected):
        raise ReleaseFailure(
            "native_host_candidate_schema_predecessor_invalid"
        )
    if candidate_selected and not current_was_selected:
        raise ReleaseFailure("current_release_id_unexpected")
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
    replacement_launcher = native_host_candidate_tracked_source(
        repo, generation, native_host_candidate, LAUNCHER_SOURCE,
    )
    replacement_sha256 = sha256_bytes(replacement_launcher)
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    native_uid = console_user_uid()
    if predecessor_selected and manages_live_touchid_service(
        install_root, expected_uid,
    ):
        stop_and_fence_d8653cb_host_services(
            native_uid, current_path, current_manifest,
            expected_release_id=(
                NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
            ),
            expected_broker_sha256=(
                NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS[
                    "authorization_broker"
                ]
            ),
        )
    if predecessor_selected:
        native_host_candidate_bootstrap_checkpoint(
            "candidate-services-fenced"
        )
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        if not current_was_selected:
            # The only supported selector-absent replay begins after the
            # candidate-aware stable launcher was durably installed and the
            # candidate floor was published.  Never invent a temporary
            # selector to make an old launcher migration possible after that
            # irreversible point.
            raise ReleaseFailure(
                "native_host_candidate_launcher_migration_selector_missing"
            )
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
            _selector=current_link,
            native_host_generation=generation,
            expected_native_host_candidate=native_host_candidate,
            expected_source_release_id=source_release_id,
            op_binary=op_binary, gpgv_binary=gpgv_binary,
        )
        launcher_migrated = True
        native_host_candidate_bootstrap_checkpoint(
            "candidate-launcher-migrated"
        )
    if predecessor_selected:
        # A predecessor launcher can have loaded its old Python program and
        # then blocked on the Host/controller admission locks before it has an
        # active marker.  Replacing the stable launcher first makes all new
        # admissions candidate-aware; this double process census rejects any
        # ambiguous already-loaded operator process before the irreversible
        # public enforcement record is published.
        ensure_no_d8653cb_release_processes(
            current_path, install_root, native_uid,
            extra_aliases=(launcher_path,),
        )
        native_host_candidate_bootstrap_checkpoint(
            "candidate-predecessor-processes-fenced"
        )
    establish_native_host_candidate_floor(
        install_root, expected_uid, release_id=source_release_id,
        candidate_record=native_host_candidate,
        establishment_mode=NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE,
        predecessor_release_id=(
            NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        ),
    )

    def remove_predecessor_selectors() -> None:
        for name in (
            "previous", NATIVE_STACK_COORDINATION_PREDECESSOR_NAME,
            AUTHORIZATION_COORDINATION_PREDECESSOR_NAME,
            DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME,
        ):
            link = install_root / name
            target = selector_target(link, name)
            if target == (
                "releases/"
                + NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
            ):
                link.unlink()
                fsync_directory(install_root)

    if candidate_selected:
        recover_named_host_pair_bootstrap(
            install_root, launcher_path, expected_uid,
            mode=NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE,
            release_id=source_release_id,
            candidate_record=native_host_candidate,
        )
        remove_predecessor_selectors()
        recovered = recover_terminal_schema_service(
            repo, current_path, install_root, launcher_path, expected_uid,
            expected_source_release_id, op_binary, gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=native_host_candidate,
        )
        if recovered is None:
            raise ReleaseFailure("native_host_candidate_recovery_invalid")
        recovered.update({
            "status": "native_host_candidate_schema_bootstrapped",
            "launcher_migrated": launcher_migrated,
            "previous_release_id": (
                NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
            ),
            "build_custody": native_host_candidate["build_custody"],
            "recovered_existing_release": True,
        })
        return recovered
    if current_was_selected:
        current_link.unlink()
        fsync_directory(install_root)
        native_host_candidate_bootstrap_checkpoint(
            "candidate-predecessor-selector-removed"
        )
    remove_predecessor_selectors()
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
        native_host_generation=generation,
        expected_native_host_candidate=native_host_candidate,
        _native_host_candidate_schema_predecessor_release_id=(
            NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        ),
        _host_pair_bootstrap_mode=(
            NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
        ),
    )
    remove_predecessor_selectors()
    result.update({
        "status": "native_host_candidate_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": (
            NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        ),
        "build_custody": native_host_candidate["build_custody"],
    })
    return result


@host_release_mutation()
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
    installed_sha256 = sha256_bytes(
        read_trusted_stable_launcher(launcher_path, expected_uid)
    )
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


def parse_native_host_candidate_json(raw: str | None) -> dict[str, object] | None:
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("native_host_candidate_json_invalid") from error
    fields = {
        "schema", "generation_path", "generation_device",
        "generation_inode", "generation_tree_sha256", "release_commit",
        "source_archive_sha256", "source_tree_sha256",
        "signing_config_sha256", "developer_id_certificate_sha1",
        "notary_submission_id", "build_custody",
        "host_release_preimage_path", "host_release_preimage_device",
        "host_release_preimage_inode", "host_release_preimage_size",
        "host_release_preimage_sha256", "host_release_preimage_schema",
    }
    canonical = (json.dumps(
        value, allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ) if isinstance(value, dict) else "")
    if (not isinstance(value, dict) or set(value) != fields
            or canonical != raw
            or value.get("schema") != NATIVE_HOST_CANDIDATE_RECORD_SCHEMA
            or value.get("build_custody") != NATIVE_HOST_BUILD_CUSTODY
            or not isinstance(value.get("generation_path"), str)
            or not Path(value["generation_path"]).is_absolute()
            or not isinstance(value.get("host_release_preimage_path"), str)
            or not Path(value["host_release_preimage_path"]).is_absolute()
            or value.get("host_release_preimage_schema")
                != NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA
            or any(not isinstance(value.get(name), int)
                   or isinstance(value.get(name), bool)
                   or value[name] <= 0
                   for name in (
                       "generation_device", "generation_inode",
                       "host_release_preimage_device",
                       "host_release_preimage_inode",
                       "host_release_preimage_size",
                   ))
            or re.fullmatch(
                r"[0-9a-f]{40}", str(value.get("release_commit", "")),
            ) is None
            or re.fullmatch(
                r"[0-9a-f]{40}",
                str(value.get("developer_id_certificate_sha1", "")),
            ) is None
            or any(SHA256.fullmatch(str(value.get(name, ""))) is None
                   for name in (
                       "generation_tree_sha256", "source_archive_sha256",
                       "source_tree_sha256", "signing_config_sha256",
                       "host_release_preimage_sha256",
                   ))
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}",
                str(value.get("notary_submission_id", "")),
            ) is None):
        raise ReleaseFailure("native_host_candidate_json_invalid")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "command",
        choices=("prepare-native-host-release-preimage",
                 "install", "recover-runtime-metadata-install",
                 "verify", "rollback", "migrate-launcher",
                 "recover-host-pair-transition",
                 "finalize-install-transition",
                 "prepare-install-transition-rollback",
                 "bootstrap-authorization",
                 "bootstrap-maintenance-schema", "bootstrap-touchid-schema",
                 "bootstrap-secure-enclave-schema", "bootstrap-profiled-touchid-schema",
                 "bootstrap-touchid-bundle-v2-schema",
                 "bootstrap-model-profile-schema",
                 "bootstrap-native-stack-schema",
                 "bootstrap-native-deployment-schema",
                 "bootstrap-native-vendor-developer-id-schema",
                 "bootstrap-native-host-candidate-schema",
                 "bootstrap-authorization-icon-schema",
                 "recover-operator-ceremony-broker",
                 "recover-touchid-ui",
                 "archive-inactive-releases"),
    )
    result.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    result.add_argument("--install-root", type=Path, default=Path("/usr/local/libexec/secure-sandbox-host"))
    result.add_argument(
        "--launcher", type=Path, default=DEFAULT_LAUNCHER_PATH,
    )
    result.add_argument("--state-root", type=Path)
    result.add_argument("--release-id")
    result.add_argument("--expected-launcher-sha256")
    result.add_argument("--expected-replacement-sha256")
    result.add_argument("--expected-source-release-id")
    result.add_argument("--authorization-request-id")
    result.add_argument("--authorization-request-sha256")
    result.add_argument("--authorized-target-plan-sha256")
    result.add_argument("--native-host-candidate-json")
    result.add_argument("--source-archive", type=Path)
    result.add_argument("--expected-source-archive-sha256")
    result.add_argument("--output", type=Path)
    result.add_argument("--expected-authorization-pid", type=int)
    result.add_argument("--expected-listener-fd", type=int)
    result.add_argument("--expected-readiness-fd", type=int)
    result.add_argument("--expected-readiness-nonce")
    result.add_argument("--expected-current-release-id")
    result.add_argument("--expected-developer-id-team-id")
    result.add_argument("--expected-current-authorization-manifest-sha256")
    result.add_argument("--expected-candidate-authorization-manifest-sha256")
    result.add_argument("--expected-bootstrap-predecessor-release-id")
    result.add_argument("--clean-machine-bootstrap", action="store_true")
    result.add_argument("--expected-public-pending-sha256")
    result.add_argument("--expected-transition-id")
    result.add_argument("--expected-transition-sha256")
    result.add_argument("--expected-operation", choices=("install", "rollback"))
    result.add_argument("--expected-target-release-id")
    result.add_argument("--expected-target-candidate-authority-sha256")
    result.add_argument("--expected-target-release-tree-identity-sha256")
    result.add_argument("--expected-target-launcher-sha256")
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
        if args.command == "prepare-native-host-release-preimage":
            if (args.source_archive is None or args.output is None
                    or SHA256.fullmatch(str(
                        args.expected_source_archive_sha256 or ""
                    )) is None):
                raise ReleaseFailure(
                    "native_host_release_preimage_binding_required"
                )
            source_archive_info = args.source_archive.lstat()
            source_archive = read_acl_free_regular(
                args.source_archive, os.geteuid(),
                stat.S_IMODE(source_archive_info.st_mode),
                "native_host_source_archive_untrusted",
                maximum=1024 * 1024 * 1024,
            )
            if (sha256_bytes(source_archive)
                    != args.expected_source_archive_sha256):
                raise ReleaseFailure(
                    "native_host_source_archive_digest_mismatch"
                )
            preimage = native_host_release_preimage_archive(
                args.repo.resolve(), source_archive, args.gpgv_binary,
            )
            descriptor = os.open(
                args.output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o400,
            )
            try:
                write_all(
                    descriptor, preimage, "native_host_release_preimage",
                )
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
                reject_extended_acl(
                    descriptor, "native_host_release_preimage_untrusted",
                )
            finally:
                os.close(descriptor)
            fsync_directory(args.output.parent)
            result = {
                "path": str(args.output.resolve(strict=True)),
                "schema": NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA,
                "sha256": sha256_bytes(preimage),
                "size": len(preimage),
                "status": "sealed",
            }
        elif args.command == "install":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if default_layout and not args.expected_source_release_id:
                raise ReleaseFailure("expected_source_release_id_required")
            candidate = parse_native_host_candidate_json(
                args.native_host_candidate_json
            )
            if default_layout and candidate is None:
                raise ReleaseFailure("native_host_candidate_record_required")
            if default_layout and not args.authorized_target_plan_sha256:
                raise ReleaseFailure("host_release_target_plan_required")
            result = install(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.op_binary, args.gpgv_binary,
                args.expected_source_release_id,
                authorization_request_id=args.authorization_request_id,
                authorization_request_sha256=args.authorization_request_sha256,
                native_host_generation=(
                    Path(candidate["generation_path"])
                    if candidate is not None else None
                ),
                expected_native_host_candidate=candidate,
                authorized_target_plan_sha256=(
                    args.authorized_target_plan_sha256
                ),
            )
        elif args.command == "recover-runtime-metadata-install":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure(
                    "state_root_required_for_privileged_mutation"
                )
            candidate = parse_native_host_candidate_json(
                args.native_host_candidate_json
            )
            if (candidate is None or not args.expected_source_release_id
                    or not args.authorization_request_id
                    or not args.authorization_request_sha256
                    or not args.authorized_target_plan_sha256):
                raise ReleaseFailure(
                    "runtime_metadata_recovery_binding_required"
                )
            result = recover_runtime_metadata_authorized_install(
                args.repo.resolve(), args.install_root, args.launcher,
                state_root, expected_uid, args.expected_source_release_id,
                Path(candidate["generation_path"]), candidate,
                args.authorization_request_id,
                args.authorization_request_sha256,
                args.authorized_target_plan_sha256,
                args.op_binary, args.gpgv_binary,
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
            candidate = parse_native_host_candidate_json(
                args.native_host_candidate_json
            )
            result = verify(
                args.repo.resolve(), args.install_root, args.launcher,
                expected_uid, args.op_binary, args.gpgv_binary,
                native_host_generation=(
                    Path(candidate["generation_path"])
                    if candidate is not None else None
                ),
                expected_native_host_candidate=candidate,
            )
        elif args.command == "rollback":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if default_layout and not args.authorized_target_plan_sha256:
                raise ReleaseFailure("host_release_target_plan_required")
            result = rollback(
                args.repo.resolve(), args.install_root, state_root, args.release_id,
                expected_uid, args.op_binary, args.gpgv_binary,
                launcher_path=args.launcher,
                authorization_request_id=args.authorization_request_id,
                authorization_request_sha256=args.authorization_request_sha256,
                authorized_target_plan_sha256=(
                    args.authorized_target_plan_sha256
                ),
            )
        elif args.command == "recover-host-pair-transition":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure(
                    "state_root_required_for_privileged_mutation"
                )
            result = recover_host_pair_transition(
                args.install_root, args.launcher, state_root, expected_uid,
                expected_public_pending_sha256=(
                    args.expected_public_pending_sha256
                ),
                expected_transition_id=args.expected_transition_id,
                expected_transition_sha256=args.expected_transition_sha256,
                expected_operation=args.expected_operation,
                expected_target_release_id=args.expected_target_release_id,
                expected_target_candidate_authority_sha256=(
                    args.expected_target_candidate_authority_sha256
                ),
                expected_target_release_tree_identity_sha256=(
                    args.expected_target_release_tree_identity_sha256
                ),
                expected_target_launcher_sha256=(
                    args.expected_target_launcher_sha256
                ),
            )
        elif args.command == "migrate-launcher":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            candidate = parse_native_host_candidate_json(
                args.native_host_candidate_json
            )
            if (not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256
                    or not args.expected_source_release_id
                    or candidate is None):
                raise ReleaseFailure("launcher_migration_binding_required")
            result = migrate_launcher(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_launcher_sha256, args.expected_replacement_sha256,
                native_host_generation=Path(candidate["generation_path"]),
                expected_native_host_candidate=candidate,
                expected_source_release_id=args.expected_source_release_id,
                op_binary=args.op_binary, gpgv_binary=args.gpgv_binary,
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
            candidate = parse_native_host_candidate_json(
                args.native_host_candidate_json
            )
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256
                    or not args.expected_developer_id_team_id
                    or not args.expected_candidate_authorization_manifest_sha256
                    or not args.expected_bootstrap_predecessor_release_id
                    or candidate is None):
                raise ReleaseFailure("bootstrap_binding_required")
            result = bootstrap_authorization(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                candidate,
                args.expected_developer_id_team_id,
                args.expected_candidate_authorization_manifest_sha256,
                args.op_binary, args.gpgv_binary,
                expected_bootstrap_predecessor_release_id=(
                    args.expected_bootstrap_predecessor_release_id
                ),
                clean_machine_bootstrap=args.clean_machine_bootstrap,
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
        elif args.command == "bootstrap-native-deployment-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure(
                    "state_root_required_for_privileged_mutation"
                )
            if (not args.expected_source_release_id
                    or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure(
                    "native_deployment_schema_binding_required"
                )
            result = bootstrap_native_deployment_schema(
                args.repo.resolve(), args.install_root, args.launcher,
                state_root, expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256,
                args.expected_replacement_sha256,
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
        elif args.command == "bootstrap-native-host-candidate-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure(
                    "state_root_required_for_privileged_mutation"
                )
            candidate = parse_native_host_candidate_json(
                args.native_host_candidate_json
            )
            if (not args.expected_source_release_id
                    or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256
                    or candidate is None):
                raise ReleaseFailure(
                    "native_host_candidate_schema_binding_required"
                )
            result = bootstrap_native_host_candidate_schema(
                args.repo.resolve(), args.install_root, args.launcher,
                state_root, expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256,
                args.expected_replacement_sha256, candidate,
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
