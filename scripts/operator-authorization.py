#!/usr/bin/env python3
"""Operator-visible, replay-resistant authorization for host mutations."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import fcntl
import hashlib
import json
import os
import plistlib
import pwd
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, NamedTuple


SCHEMA = "secure-sandbox-operator-authorization-v1"
RECEIPT_SCHEMA = "secure-sandbox-operator-authorization-receipt-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SAFE_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:/+-]{0,79}$")
SAFE_SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")
MAX_PURPOSE = 240
MAX_RESOURCE = 240
REQUEST_TTL_SECONDS = 180
LOCK_TIMEOUT_SECONDS = 5
DIALOG_TIMEOUT_SECONDS = 90
AUTH_TIMEOUT_SECONDS = 180
OPERATION_TIMEOUT_SECONDS = 120
TOUCHID_SOCKET = Path("/var/run/secure-sandbox-authorization.sock")
TOUCHID_SCHEMA = "secure-sandbox-touchid-approval-v1"
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
    "pki_anchor": 0o755,
    "release_manager": 0o755,
    "seed_verifier": 0o755,
    "seed_gateway": 0o444,
    "seed_research": 0o444,
    "seed_target": 0o444,
    "ssh_config": 0o444,
    "vm_maintenance": 0o755,
}
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
    "host-controller-migrate-launcher": "/usr/local/bin/secure-sandbox-claude",
    "pki-anchor-begin": "/usr/local/var/lib/secure-sandbox/pki",
    "pki-anchor-commit": "/usr/local/var/lib/secure-sandbox/pki",
    "installer-promote-canonical": "/Library/Application Support/SecureSandbox/installers",
    "installer-promote-autoinstall": "/Library/Application Support/SecureSandbox/installers",
    "installer-repair-store-access": "/Library/Application Support/SecureSandbox/installers",
    "vm-create": "SecureSandbox-Gateway,SecureSandbox-Research,SecureSandbox-Target",
    "vm-reprovision": "SecureSandbox-Gateway,SecureSandbox-Research,SecureSandbox-Target",
    "vm-preserve-legacy": "SecureSandbox quarantined VM data preservation",
}
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


def validate_parameters(operation: str, parameters: dict[str, Any], home: Path) -> None:
    if not isinstance(parameters, dict):
        raise AuthorizationError("operation_parameters_invalid")
    expected_state = home / "Library/Application Support/SecureSandbox/controller-state"
    if operation == "authorization-probe":
        if set(parameters) != {"challenge"}:
            raise AuthorizationError("operation_parameters_invalid")
        valid_uuid4(parameters["challenge"], "challenge")
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
    if operation in {"host-controller-install", "host-controller-rollback", "host-controller-migrate-launcher"}:
        common = {"repo", "state_root"}
        extras = {
            "host-controller-install": {"expected_source_release_id"},
            "host-controller-rollback": {"release_id"},
            "host-controller-migrate-launcher": {
                "expected_installed_sha256", "expected_replacement_sha256"
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
        if operation == "host-controller-rollback":
            release_id = parameters["release_id"]
            if not isinstance(release_id, str) or not SHA256.fullmatch(release_id):
                raise AuthorizationError("rollback_release_id_invalid")
        if operation == "host-controller-install":
            if (not isinstance(parameters["expected_source_release_id"], str)
                    or not SHA256.fullmatch(parameters["expected_source_release_id"])):
                raise AuthorizationError("expected_source_release_id_invalid")
        if operation == "host-controller-migrate-launcher":
            for name in ("expected_installed_sha256", "expected_replacement_sha256"):
                if not isinstance(parameters[name], str) or not SHA256.fullmatch(parameters[name]):
                    raise AuthorizationError("expected_launcher_hash_invalid")
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
        if set(parameters) != {"repo", "plan_sha256", "prlctl_sha256", "installer_sha256", "seed_sha256"}:
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


def read_request(path: Path, expected_uid: int, expected_digest: str) -> dict[str, Any]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != expected_uid
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise AuthorizationError("request_file_untrusted")
        data = os.read(descriptor, 65537)
        if len(data) > 65536 or os.read(descriptor, 1):
            raise AuthorizationError("request_file_too_large")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise AuthorizationError("request_changed_during_read")
    finally:
        os.close(descriptor)
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise AuthorizationError("request_digest_mismatch")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("request_json_invalid") from error
    if not isinstance(value, dict) or canonical(value) != data:
        raise AuthorizationError("request_not_canonical")
    return value


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
    validate_parameters(value["operation"], value["parameters"], home)
    return home


def protected_release_directory(path: Path, expected_uid: int = 0) -> Path:
    release = path.resolve(strict=True).parent
    info = release.stat()
    if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o555:
        raise AuthorizationError("authorization_broker_release_untrusted")
    manifest_path = release / "manifest.json"
    manifest_info = manifest_path.lstat()
    if (not stat.S_ISREG(manifest_info.st_mode) or stat.S_ISLNK(manifest_info.st_mode)
            or manifest_info.st_uid != expected_uid or stat.S_IMODE(manifest_info.st_mode) != 0o444):
        raise AuthorizationError("authorization_manifest_untrusted")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payloads = manifest.get("payloads", {})
    if (manifest.get("schema") != "secure-sandbox-host-controller-release-v1"
            or not isinstance(payloads, dict) or set(payloads) != set(EXPECTED_RELEASE_MODES)):
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
    for name, expected_mode in EXPECTED_RELEASE_MODES.items():
        candidate = release / name
        candidate_info = candidate.stat()
        expected = payloads.get(name)
        if (candidate.is_symlink() or not stat.S_ISREG(candidate_info.st_mode) or candidate_info.st_uid != expected_uid
                or stat.S_IMODE(candidate_info.st_mode) != expected_mode or not isinstance(expected, str)
                or hashlib.sha256(candidate.read_bytes()).hexdigest() != expected):
            raise AuthorizationError(f"protected_payload_invalid:{name}")
    try:
        bundle_manifest = json.loads((release / "authorization_ui_bundle").read_text("utf-8"))
        bundle_files = bundle_manifest["files"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
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
    if bundle.is_symlink() or not bundle.is_dir():
        raise AuthorizationError("authorization_ui_bundle_invalid")
    actual_files = {item.relative_to(bundle).as_posix() for item in bundle.rglob("*") if item.is_file()}
    if actual_files != set(bundle_files):
        raise AuthorizationError("authorization_ui_bundle_invalid")
    for relative, record in bundle_files.items():
        candidate = bundle / relative
        info = candidate.lstat()
        if (candidate.is_symlink() or not stat.S_ISREG(info.st_mode)
                or info.st_uid != expected_uid or not isinstance(record, dict)
                or set(record) != {"mode", "sha256", "size"}
                or stat.S_IMODE(info.st_mode) != record.get("mode")
                or info.st_size != record.get("size")
                or hashlib.sha256(candidate.read_bytes()).hexdigest() != record.get("sha256")):
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


def operation_command(value: dict[str, Any], release: Path) -> list[str]:
    operation = value["operation"]
    parameters = value["parameters"]
    if operation == "authorization-probe":
        return ["/usr/bin/printf", "touchid-authorization-probe:%s\\n", parameters["challenge"]]
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
    if operation.startswith("host-controller-"):
        action = operation.removeprefix("host-controller-")
        command = [
            "/usr/bin/python3", "-I", str(release / "release_manager"),
            "install" if action == "install" else action,
            "--repo", parameters["repo"], "--state-root", parameters["state_root"], "--json",
        ]
        if action == "rollback" and parameters["release_id"]:
            command.extend(["--release-id", parameters["release_id"]])
        if action == "install":
            command.extend(["--expected-source-release-id", parameters["expected_source_release_id"]])
        if action == "migrate-launcher":
            command.extend([
                "--expected-launcher-sha256", parameters["expected_installed_sha256"],
                "--expected-replacement-sha256", parameters["expected_replacement_sha256"],
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


def run_privileged_operation(command: list[str], timeout: int = OPERATION_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        return subprocess.CompletedProcess(
            command, 124, stdout, stderr + b"privileged_operation_timeout\n"
        )


def execute_request(uid: int, request_id: str, expected_digest: str,
                    receipt_root: Path = DEFAULT_RECEIPT_ROOT, now: int | None = None,
                    broker_path: Path | None = None, expected_root_uid: int = 0,
                    authorization_method: str = "administrator-password",
                    emit_output: bool = True,
                    result_capture: list[subprocess.CompletedProcess[bytes]] | None = None,
                    result_override: subprocess.CompletedProcess[bytes] | None = None) -> int:
    if os.geteuid() != expected_root_uid:
        raise AuthorizationError("root_required")
    if authorization_method not in {"administrator-password", "touch-id"}:
        raise AuthorizationError("authorization_method_invalid")
    if uid <= 0 or not SHA256.fullmatch(expected_digest):
        raise AuthorizationError("execution_identity_invalid")
    valid_uuid4(request_id)
    home = Path(pwd.getpwuid(uid).pw_dir)
    path = request_directory(home) / f"{request_id}.json"
    value = read_request(path, uid, expected_digest)
    verify_request(value, uid, request_id, int(time.time()) if now is None else now)
    if value["ceremony"] != "approve":
        raise AuthorizationError("ceremony_execution_forbidden")
    release = protected_release_directory(Path(__file__) if broker_path is None else broker_path,
                                          expected_root_uid)
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
    command = operation_command(value, release)
    if value["operation"] == "vm-preserve-legacy":
        timeout = 8 * 60 * 60
    elif value["operation"] in {"vm-create", "vm-reprovision"}:
        timeout = 3600
    elif value["operation"].startswith("installer-"):
        timeout = 1800
    else:
        timeout = OPERATION_TIMEOUT_SECONDS
    result = result_override if result_override is not None else run_privileged_operation(command, timeout)
    completed = dict(pending)
    completed.update({
        "status": "succeeded" if result.returncode == 0 else "failed",
        "completed_at": int(time.time()) if now is None else now,
        "exit_status": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    })
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
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.communicate()
        raise AuthorizationError("authorization_dialog_timeout") from error
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
    if operation == "host-controller-install":
        return (schema == "secure-sandbox-host-controller-release-v1"
                and status == "deployed"
                and isinstance(output.get("release_id"), str)
                and SHA256.fullmatch(output["release_id"]) is not None)
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
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorizationError("execution_approval_key_directory_untrusted")
    return root


def read_secure_enclave_state(path: Path, schema: str,
                              expected_uid: int = 0) -> dict[str, Any]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError("execution_approval_state_invalid") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1 or len(raw) > 16 * 1024
            or not isinstance(value, dict) or value.get("schema") != schema
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
        manifest = json.loads(read_regular(release / "manifest.json"))
        digest = manifest["payloads"]["authorization_ui_bundle"]
    except (AuthorizationError, KeyError, TypeError, json.JSONDecodeError) as error:
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
    atomic_public_record(
        public_receipt_root / f"{value['request_id']}.json", public_receipt
    )


def selected_release_changed(release: Path) -> bool:
    try:
        return (release.parent.parent / "current").resolve(strict=True) != release
    except OSError:
        # Keep the already verified broker alive if the selector is damaged.
        return False


def handle_touchid_connection(connection: socket.socket, broker_path: Path | None = None,
                              expected_root_uid: int = 0,
                              receipt_root: Path = DEFAULT_RECEIPT_ROOT,
                              public_receipt_root: Path = DEFAULT_PUBLIC_RECEIPT_ROOT) -> bool:
    restart_after_response = False
    try:
        uid, _token, process_path = peer_audit_identity(connection)
        release = protected_release_directory(
            Path(__file__) if broker_path is None else broker_path, expected_root_uid
        )
        verify_touchid_peer(process_path, release, expected_root_uid)
        message = read_touchid_line(connection, 5, 65536)
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
            value = read_request(request_path, uid, message["request_sha256"])
            verify_request(value, uid, message["request_id"], int(time.time()))
            if value["ceremony"] != "approve":
                raise AuthorizationError("ceremony_protocol_mismatch")
            captured: list[subprocess.CompletedProcess[bytes]] = []
            status = execute_request(
                uid, message["request_id"], message["request_sha256"],
                receipt_root=receipt_root, broker_path=broker_path,
                expected_root_uid=expected_root_uid, authorization_method="touch-id",
                emit_output=False, result_capture=captured,
            )
            if len(captured) != 1:
                raise AuthorizationError("touchid_operation_result_missing")
            response = touchid_response(status, captured[0].stdout, captured[0].stderr)
            restart_after_response = selected_release_changed(release)
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
        value = read_request(request_path, uid, message["request_sha256"])
        verify_request(value, uid, message["request_id"], int(time.time()))
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
        )
        if len(captured) != 1:
            raise AuthorizationError("touchid_operation_result_missing")
        response = touchid_response(status, captured[0].stdout, captured[0].stderr)
        restart_after_response = selected_release_changed(release)
    except (AuthorizationError, OSError, KeyError, TypeError, ValueError) as error:
        body = canonical({"schema": TOUCHID_SCHEMA, "status": "rejected", "error": str(error)})
        response = touchid_response(1, b"", body)
    try:
        connection.sendall(response)
    except OSError:
        pass
    return restart_after_response


def serve_touchid(socket_path: Path = TOUCHID_SOCKET) -> int:
    if os.geteuid() != 0:
        raise AuthorizationError("root_required")
    parent = socket_path.parent.resolve(strict=True)
    parent_info = parent.stat()
    if parent_info.st_uid != 0 or not stat.S_ISDIR(parent_info.st_mode):
        raise AuthorizationError("touchid_socket_directory_untrusted")
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
        while True:
            connection, _ = listener.accept()
            with connection:
                restart = handle_touchid_connection(connection)
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
    return AUTH_TIMEOUT_SECONDS


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
        return [f"Repository: {parameters['repo']}",
                f"Expected release: {parameters['expected_source_release_id']}"]
    if operation == "host-controller-rollback":
        return [f"Repository: {parameters['repo']}", f"Target release: {parameters['release_id']}"]
    if operation == "host-controller-migrate-launcher":
        return [f"Repository: {parameters['repo']}",
                f"Installed launcher: {parameters['expected_installed_sha256']}",
                f"Replacement launcher: {parameters['expected_replacement_sha256']}"]
    if operation == "pki-anchor-begin":
        return [f"PKI generation: {parameters['generation_id']}"]
    if operation.startswith("installer-"):
        return [f"Repository: {parameters['repo']}",
                f"Release directory: {parameters['release_directory']}",
                f"Installer SHA-256: {parameters['expected_sha256']}"]
    if operation in {"vm-create", "vm-reprovision"}:
        return [f"Repository: {parameters['repo']}",
                f"VM set: {OPERATION_RESOURCES[operation]}",
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
                          ceremony: str = "approve") -> int:
    agent, session = validate_identity(agent, session)
    purpose = clean_text(purpose, "purpose", MAX_PURPOSE)
    resource = clean_text(resource, "resource", MAX_RESOURCE)
    if ceremony not in CEREMONIES:
        raise AuthorizationTerminalError("ceremony_invalid", operation=operation)
    uid = os.geteuid()
    if uid == 0:
        raise AuthorizationError("unprivileged_request_required")
    home = Path(pwd.getpwuid(uid).pw_dir)
    validate_parameters(operation, parameters, home)
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
        request_id = str(uuid.uuid4())
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
                            authorization_execution_timeout(operation), uid,
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
                    ], authorization_execution_timeout(operation))
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
                        and operation in {
                            "execution-approval-key-init", "execution-approval-sign",
                            "execution-approval-migration-activate",
                            "execution-approval-migration-authorize-acceptance",
                            "execution-approval-migration-verify-acceptance",
                            "execution-approval-migration-commit",
                            "execution-approval-software-retire",
                        }):
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
                    and operation in {
                        "execution-approval-key-init", "execution-approval-sign",
                        "execution-approval-migration-activate",
                        "execution-approval-migration-authorize-acceptance",
                        "execution-approval-migration-verify-acceptance",
                        "execution-approval-migration-commit",
                        "execution-approval-software-retire",
                    }):
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
            ], authorization_execution_timeout(operation))
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
            parameters = json.loads(args.parameters_json)
            return request_authorization(
                args.agent, args.session, args.purpose, args.resource, args.operation, parameters,
                ceremony=args.ceremony,
            )
        if args.command == "serve-touchid":
            return serve_touchid()
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
