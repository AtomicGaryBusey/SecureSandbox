#!/usr/bin/env python3
"""Hostile live qualification for the native Codex 0.166 custody boundary.

This module is deliberately separate from the ordinary app-server firewall.
It has one fixed ``command/exec`` request used before a session is exposed to
an operator.  The request runs a root-owned probe under Codex's exact
workspace-write policy, without a PTY or streaming descriptors.  There is no
generic request or command API.

The resulting receipt is content-free: it contains booleans, bounded counts,
stable reason codes, and cryptographic digests, never environment values,
tokens, command output, canaries, or raw process metadata.  ``unsupported`` is
an honest terminal outcome and is never accepted as a pass.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import hashlib
import hmac
import json
import os
import posixpath
import re
import resource
import signal
import socket
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from research import native_codex_policy
from research.native_codex_protocol_firewall import (
    PINNED_APP_SERVER_VERSION,
    WORKSPACE,
    NativeCodexProtocolFirewall,
)


CHALLENGE_SCHEMA = "secure-sandbox-native-codex-isolation-challenge-v1"
ROOT_OBSERVATION_SCHEMA = (
    "secure-sandbox-native-codex-isolation-root-observation-v1")
TOOL_OBSERVATION_SCHEMA = (
    "secure-sandbox-native-codex-isolation-tool-observation-v1")
EVIDENCE_SCHEMA = "secure-sandbox-native-codex-isolation-evidence-v1"
JOURNAL_SCHEMA = "secure-sandbox-native-codex-isolation-journal-v2"
RECEIPT_ROOT = Path(
    "/var/lib/secure-sandbox/native-vendor/controller/qualification-receipts")
JOURNAL_ROOT = Path(
    "/var/lib/secure-sandbox/native-vendor/controller/qualification-journal")
QUALIFICATION_SCRATCH_ROOT = Path(
    "/run/secure-sandbox/native-codex/qualification")
PROBE_EXECUTABLE = Path(
    "/usr/local/libexec/secure-sandbox/native-codex-isolation-probe")
PROC_ROOT = Path("/proc")
CORE_PATTERN = Path("/proc/sys/kernel/core_pattern")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SUPERVISOR_CGROUP = "/system.slice/native-harness-supervisor.service"

MAX_CANONICAL_BYTES = 64 * 1024
MAX_PROBE_OUTPUT_BYTES = 64 * 1024
MAX_REASON_CODES = 64
MAX_REASON_CODE_BYTES = 96
MAX_VISIBLE_PROCESSES = 64
MAX_SERVICE_UID_PROCESSES = 128
MAX_ENVIRONMENT_BYTES = 1024 * 1024
MAX_ARGUMENT_BYTES = 24 * 1024
MAX_RECEIPT_AGE_SECONDS = 120
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}")
CGROUP_SHA256 = SHA256
NAMESPACE_NAMES = ("pid", "user", "mnt", "net")
DENIED_CREDENTIAL_ENVIRONMENT = (
    "ACCESS_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_ACCESS_TOKEN",
    "OPENAI_REFRESH_TOKEN",
    "CHATGPT_ACCESS_TOKEN",
    "CHATGPT_REFRESH_TOKEN",
)
_DENIED_ACCESS_RESULTS = frozenset({
    "denied-eacces", "denied-enoent", "denied-eperm", "denied-esrch",
})
_OUTCOMES = frozenset({"pass", "fail", "unsupported"})

DEFAULT_POLICY_COMPONENTS: Mapping[str, Path] = {
    "launcher": Path(
        "/usr/local/libexec/secure-sandbox/native-codex-launcher"),
    "protocol_firewall": Path(
        "/usr/local/libexec/secure-sandbox/native_codex_protocol_firewall.py"),
    "qualification": Path(
        "/usr/local/libexec/secure-sandbox/"
        "native_codex_isolation_qualification.py"),
    "session_controller": Path(
        "/usr/local/libexec/secure-sandbox/native_codex_session_controller.py"),
    "baseline_config": Path("/etc/secure-sandbox/native-codex-policy/config.toml"),
    "supervisor_unit": Path(
        "/etc/systemd/system/native-harness-supervisor.service"),
}


class NativeCodexIsolationError(RuntimeError):
    """Stable fail-closed isolation qualification error."""


def canonical_bytes(value: object) -> bytes:
    try:
        raw = (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_not_canonicalizable") from error
    if not 1 <= len(raw) <= MAX_CANONICAL_BYTES:
        raise NativeCodexIsolationError(
            "native_codex_isolation_canonical_size_invalid")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _require_sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeCodexIsolationError(code)
    return value


def _require_uuid4(value: object, code: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeCodexIsolationError(code)
    return value


def _reason_codes(values: Sequence[str]) -> list[str]:
    result = sorted(set(values))
    if (len(result) > MAX_REASON_CODES
            or any(not isinstance(value, str)
                   or not 1 <= len(value.encode("ascii")) <= MAX_REASON_CODE_BYTES
                   or re.fullmatch(r"[a-z0-9_]+", value) is None
                   for value in result)):
        raise NativeCodexIsolationError(
            "native_codex_isolation_reason_codes_invalid")
    return result


def _load_canonical(raw: bytes, *, maximum: int = MAX_CANONICAL_BYTES) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
        raise NativeCodexIsolationError(
            "native_codex_isolation_document_size_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_document_invalid") from error
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise NativeCodexIsolationError(
            "native_codex_isolation_document_not_canonical")
    return value


def _firewall_authority(
    firewall: NativeCodexProtocolFirewall,
    descriptor_value: object,
) -> tuple[dict[str, str], Any]:
    if not isinstance(firewall, NativeCodexProtocolFirewall) or firewall.failed:
        raise NativeCodexIsolationError(
            "native_codex_isolation_firewall_invalid")
    authority = firewall.qualification_authority
    if authority is None:
        raise NativeCodexIsolationError(
            "native_codex_isolation_firewall_not_ready")
    try:
        descriptor = native_codex_policy.validate_launch_descriptor(
            descriptor_value)
    except native_codex_policy.NativeCodexPolicyError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_descriptor_invalid") from error
    if (not hmac.compare_digest(
            authority.launch_descriptor_sha256,
            descriptor["descriptor_sha256"])
            or authority.model != descriptor["model_id"]
            or authority.reasoning_effort != descriptor["reasoning_effort"]):
        raise NativeCodexIsolationError(
            "native_codex_isolation_firewall_authority_mismatch")
    return descriptor, authority


def qualification_subject(
    descriptor_value: object,
    *,
    policy_manifest_sha256: str,
    probe_executable_sha256: str,
) -> dict[str, str]:
    try:
        descriptor = native_codex_policy.validate_launch_descriptor(
            descriptor_value)
    except native_codex_policy.NativeCodexPolicyError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_descriptor_invalid") from error
    policy_digest = _require_sha256(
        policy_manifest_sha256,
        "native_codex_isolation_policy_manifest_invalid")
    probe_digest = _require_sha256(
        probe_executable_sha256,
        "native_codex_isolation_probe_digest_invalid")
    body = {
        "provider": "codex",
        "harness_generation_id": descriptor["harness_generation_id"],
        "harness_executable_sha256": descriptor["harness_executable_sha256"],
        "model_id": descriptor["model_id"],
        "reasoning_effort": descriptor["reasoning_effort"],
        "cyber_access_program": descriptor["cyber_access_program"],
        "policy_manifest_sha256": policy_digest,
        "probe_executable_sha256": probe_digest,
        "protocol_version": PINNED_APP_SERVER_VERSION,
    }
    return {**body, "qualification_subject_sha256": digest(body)}


def _process_start_time(pid: int, *, proc_root: Path = PROC_ROOT) -> int:
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_unavailable") from error
    close = raw.rfind(") ")
    fields = raw[close + 2:].split() if close > 0 else []
    try:
        value = int(fields[19])
    except (IndexError, ValueError) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_stat_invalid") from error
    if value < 1:
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_stat_invalid")
    return value


def _namespace_inode(path: Path) -> int:
    try:
        target = os.readlink(path)
    except OSError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_namespace_unavailable") from error
    match = re.fullmatch(r"[a-z]+:\[([0-9]+)\]", target)
    if match is None or int(match.group(1)) < 1:
        raise NativeCodexIsolationError(
            "native_codex_isolation_namespace_invalid")
    return int(match.group(1))


def boot_id_sha256(*, path: Path = BOOT_ID) -> str:
    try:
        raw = path.read_bytes()
        value = raw.decode("ascii").strip()
    except (OSError, UnicodeError) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_boot_id_unavailable") from error
    if UUID4.fullmatch(value) is None or raw != (value + "\n").encode("ascii"):
        raise NativeCodexIsolationError(
            "native_codex_isolation_boot_id_invalid")
    return hashlib.sha256(raw).hexdigest()


def make_challenge(
    firewall: NativeCodexProtocolFirewall,
    descriptor_value: object,
    *,
    appserver_pid: int,
    service_uid: int,
    token_sha256: str,
    policy_manifest_sha256: str,
    probe_executable_sha256: str,
    scope_cgroup_sha256: str,
    allowed_service_cgroup_sha256s: Sequence[str],
    launcher_receipt_sha256: str,
    environment_proof_sha256: str,
    codex_home_sha256: str,
    attempt_id: str | None = None,
    qualification_root: Path = QUALIFICATION_SCRATCH_ROOT,
    proc_root: Path = PROC_ROOT,
    boot_id_path: Path = BOOT_ID,
) -> dict[str, Any]:
    descriptor, authority = _firewall_authority(firewall, descriptor_value)
    if (not isinstance(appserver_pid, int) or isinstance(appserver_pid, bool)
            or appserver_pid <= 1
            or not isinstance(service_uid, int) or isinstance(service_uid, bool)
            or service_uid <= 0):
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_identity_invalid")
    attempt = str(uuid.uuid4()) if attempt_id is None else _require_uuid4(
        attempt_id, "native_codex_isolation_attempt_id_invalid")
    token_digest = _require_sha256(
        token_sha256, "native_codex_isolation_token_digest_invalid")
    launcher_receipt_digest = _require_sha256(
        launcher_receipt_sha256,
        "native_codex_isolation_launcher_receipt_invalid")
    environment_digest = _require_sha256(
        environment_proof_sha256,
        "native_codex_isolation_environment_proof_invalid")
    home_digest = _require_sha256(
        codex_home_sha256,
        "native_codex_isolation_codex_home_digest_invalid")
    scope_digest = _require_sha256(
        scope_cgroup_sha256,
        "native_codex_isolation_scope_cgroup_invalid")
    supervisor_digest = hashlib.sha256(
        (SUPERVISOR_CGROUP + "\n").encode("ascii")).hexdigest()
    allowed = sorted(set(allowed_service_cgroup_sha256s))
    if (allowed != sorted({scope_digest, supervisor_digest})
            or any(SHA256.fullmatch(value) is None for value in allowed)):
        raise NativeCodexIsolationError(
            "native_codex_isolation_allowed_cgroups_invalid")
    subject = qualification_subject(
        descriptor, policy_manifest_sha256=policy_manifest_sha256,
        probe_executable_sha256=probe_executable_sha256)
    codex_home = authority.codex_home
    expected_home = (
        "/run/secure-sandbox/native-codex/session-state/"
        f"{descriptor['session_id']}/codex-home")
    if codex_home != expected_home:
        raise NativeCodexIsolationError(
            "native_codex_isolation_codex_home_mismatch")
    namespaces = {
        name: _namespace_inode(proc_root / str(appserver_pid) / "ns" / name)
        for name in NAMESPACE_NAMES
    }
    root = Path(qualification_root)
    if (not root.is_absolute() or ".." in root.parts
            or root == Path(WORKSPACE) or Path(WORKSPACE) in root.parents):
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_root_invalid")
    scratch = str(root / descriptor["session_id"] / attempt)
    escape_marker = f"{scratch}/raw-appserver-escape"
    raw_escape = json.dumps({
        "id": f"escape-{attempt}",
        "method": "process/spawn",
        "params": {"command": ["/usr/bin/touch", escape_marker]},
    }, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    body: dict[str, Any] = {
        "schema": CHALLENGE_SCHEMA,
        "attempt_id": attempt,
        "boot_id_sha256": boot_id_sha256(path=boot_id_path),
        "qualification_subject_sha256": subject[
            "qualification_subject_sha256"],
        "launch_descriptor_sha256": descriptor["descriptor_sha256"],
        "runtime_authority_sha256": descriptor["runtime_authority_sha256"],
        "session_id": descriptor["session_id"],
        "appserver_pid": appserver_pid,
        "process_start_time_ticks": _process_start_time(
            appserver_pid, proc_root=proc_root),
        "service_uid": service_uid,
        "codex_home": codex_home,
        "firewall_thread_id_sha256": hashlib.sha256(
            authority.thread_id.encode("ascii")).hexdigest(),
        "token_sha256": token_digest,
        "launcher_receipt_sha256": launcher_receipt_digest,
        "environment_proof_sha256": environment_digest,
        "codex_home_sha256": home_digest,
        "policy_manifest_sha256": subject["policy_manifest_sha256"],
        "probe_executable_sha256": subject["probe_executable_sha256"],
        "scope_cgroup_sha256": scope_digest,
        "allowed_service_cgroup_sha256s": allowed,
        "parent_namespaces": namespaces,
        "scratch_directory": scratch,
        "escape_marker": escape_marker,
        "raw_escape_payload": raw_escape,
        "raw_escape_payload_sha256": hashlib.sha256(
            raw_escape.encode("ascii")).hexdigest(),
    }
    return {**body, "challenge_sha256": digest(body)}


def validate_challenge(value: object) -> dict[str, Any]:
    fields = {
        "schema", "attempt_id", "boot_id_sha256",
        "qualification_subject_sha256", "launch_descriptor_sha256",
        "runtime_authority_sha256", "session_id", "appserver_pid",
        "process_start_time_ticks", "service_uid", "codex_home",
        "launcher_receipt_sha256", "environment_proof_sha256",
        "codex_home_sha256",
        "firewall_thread_id_sha256", "token_sha256",
        "policy_manifest_sha256", "probe_executable_sha256",
        "scope_cgroup_sha256", "allowed_service_cgroup_sha256s",
        "parent_namespaces", "scratch_directory", "escape_marker",
        "raw_escape_payload", "raw_escape_payload_sha256",
        "challenge_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexIsolationError(
            "native_codex_isolation_challenge_fields_invalid")
    if value["schema"] != CHALLENGE_SCHEMA:
        raise NativeCodexIsolationError(
            "native_codex_isolation_challenge_schema_invalid")
    _require_uuid4(
        value["attempt_id"], "native_codex_isolation_attempt_id_invalid")
    _require_uuid4(
        value["session_id"], "native_codex_isolation_session_id_invalid")
    for name in (
        "boot_id_sha256", "qualification_subject_sha256",
        "launch_descriptor_sha256", "runtime_authority_sha256",
        "firewall_thread_id_sha256", "token_sha256",
        "policy_manifest_sha256", "probe_executable_sha256",
        "scope_cgroup_sha256", "raw_escape_payload_sha256",
        "launcher_receipt_sha256", "environment_proof_sha256",
        "codex_home_sha256",
    ):
        _require_sha256(
            value[name], f"native_codex_isolation_{name}_invalid")
    for name in ("appserver_pid", "process_start_time_ticks", "service_uid"):
        if (not isinstance(value[name], int) or isinstance(value[name], bool)
                or value[name] <= (1 if name == "appserver_pid" else 0)):
            raise NativeCodexIsolationError(
                "native_codex_isolation_challenge_process_invalid")
    if (not isinstance(value["codex_home"], str)
            or not value["codex_home"].startswith(
                "/run/secure-sandbox/native-codex/session-state/")
            or not value["codex_home"].endswith("/codex-home")
            or posixpath.normpath(value["codex_home"]) != value["codex_home"]):
        raise NativeCodexIsolationError(
            "native_codex_isolation_challenge_home_invalid")
    namespaces = value["parent_namespaces"]
    if (not isinstance(namespaces, dict)
            or set(namespaces) != set(NAMESPACE_NAMES)
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 1
                   for item in namespaces.values())):
        raise NativeCodexIsolationError(
            "native_codex_isolation_challenge_namespaces_invalid")
    allowed = value["allowed_service_cgroup_sha256s"]
    if (not isinstance(allowed, list) or allowed != sorted(set(allowed))
            or not 1 <= len(allowed) <= 4
            or value["scope_cgroup_sha256"] not in allowed
            or any(not isinstance(item, str) or SHA256.fullmatch(item) is None
                   for item in allowed)):
        raise NativeCodexIsolationError(
            "native_codex_isolation_allowed_cgroups_invalid")
    scratch = value["scratch_directory"]
    scratch_path = Path(scratch) if isinstance(scratch, str) else Path(".")
    if (not isinstance(scratch, str) or not scratch_path.is_absolute()
            or ".." in scratch_path.parts
            or len(scratch_path.parts) < 3
            or scratch_path.parts[-2] != value["session_id"]
            or scratch_path.parts[-1] != value["attempt_id"]
            or scratch_path == Path(WORKSPACE)
            or Path(WORKSPACE) in scratch_path.parents
            or value["escape_marker"] != scratch + "/raw-appserver-escape"):
        raise NativeCodexIsolationError(
            "native_codex_isolation_challenge_paths_invalid")
    raw_escape = value["raw_escape_payload"]
    if (not isinstance(raw_escape, str)
            or len(raw_escape.encode("ascii", errors="ignore")) > 2048
            or hashlib.sha256(raw_escape.encode("ascii")).hexdigest()
               != value["raw_escape_payload_sha256"]):
        raise NativeCodexIsolationError(
            "native_codex_isolation_escape_payload_invalid")
    try:
        escape_request = json.loads(raw_escape)
    except json.JSONDecodeError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_escape_payload_invalid") from error
    expected_escape = {
        "id": f"escape-{value['attempt_id']}",
        "method": "process/spawn",
        "params": {
            "command": ["/usr/bin/touch", value["escape_marker"]]},
    }
    if (escape_request != expected_escape
            or raw_escape != json.dumps(
                expected_escape, ensure_ascii=True, separators=(",", ":"),
                sort_keys=True)):
        raise NativeCodexIsolationError(
            "native_codex_isolation_escape_payload_invalid")
    body = {name: value[name] for name in fields - {"challenge_sha256"}}
    if not hmac.compare_digest(value["challenge_sha256"], digest(body)):
        raise NativeCodexIsolationError(
            "native_codex_isolation_challenge_digest_mismatch")
    return value


def _open_scratch_root(
    root: Path, *, trusted_uid: int, service_gid: int,
) -> int:
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        current = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(current.st_mode)
                or (info.st_dev, info.st_ino)
                   != (current.st_dev, current.st_ino)
                or info.st_uid != trusted_uid or info.st_gid != service_gid
                or stat.S_IMODE(info.st_mode) != 0o710):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_root_untrusted")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def prepare_qualification_scratch(
    challenge_value: object,
    *,
    service_uid: int,
    service_gid: int,
    qualification_root: Path = QUALIFICATION_SCRATCH_ROOT,
    trusted_uid: int = 0,
) -> dict[str, Any]:
    """Create one session/attempt scratch leaf without following pathnames."""
    challenge = validate_challenge(challenge_value)
    if (service_uid != challenge["service_uid"] or service_uid <= 0
            or service_gid <= 0):
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_identity_invalid")
    expected = (
        qualification_root / challenge["session_id"] / challenge["attempt_id"])
    if Path(challenge["scratch_directory"]) != expected:
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_path_mismatch")
    root = _open_scratch_root(
        qualification_root, trusted_uid=trusted_uid, service_gid=service_gid)
    session = attempt = -1
    try:
        names = os.listdir(root)
        if len(names) > 4096 or any(UUID4.fullmatch(name) is None for name in names):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_inventory_invalid")
        try:
            os.mkdir(challenge["session_id"], 0o710, dir_fd=root)
            created_session = True
        except FileExistsError:
            created_session = False
        session = os.open(
            challenge["session_id"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root)
        if created_session:
            os.fchown(session, trusted_uid, service_gid)
            os.fchmod(session, 0o710)
            os.fsync(root)
        session_info = os.fstat(session)
        if (not stat.S_ISDIR(session_info.st_mode)
                or session_info.st_uid != trusted_uid
                or session_info.st_gid != service_gid
                or stat.S_IMODE(session_info.st_mode) != 0o710):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_session_untrusted")
        if os.listdir(session):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_session_busy")
        os.mkdir(challenge["attempt_id"], 0o700, dir_fd=session)
        attempt = os.open(
            challenge["attempt_id"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=session)
        # The leaf remains root-owned until its exact inode identity is
        # durably journaled.  Only then may the controller expose it to the
        # service UID used by the hostile one-shot probe.
        os.fchown(attempt, trusted_uid, service_gid)
        os.fchmod(attempt, 0o700)
        os.fsync(session)
        info = os.fstat(attempt)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != trusted_uid
                or info.st_gid != service_gid
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.listdir(attempt)):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_attempt_untrusted")
        return {
            "path": challenge["scratch_directory"],
            "device": info.st_dev,
            "inode": info.st_ino,
            "service_uid": service_uid,
            "service_gid": service_gid,
        }
    finally:
        if attempt >= 0:
            os.close(attempt)
        if session >= 0:
            os.close(session)
        os.close(root)


def activate_qualification_scratch(
    challenge_value: object,
    identity: Mapping[str, Any],
    *,
    qualification_root: Path = QUALIFICATION_SCRATCH_ROOT,
    journal_root: Path = JOURNAL_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> None:
    """Expose only the exact journaled empty scratch inode to the service."""
    challenge = validate_challenge(challenge_value)
    fields = {"path", "device", "inode", "service_uid", "service_gid"}
    if (not isinstance(identity, Mapping) or set(identity) != fields
            or identity["path"] != challenge["scratch_directory"]
            or identity["service_uid"] != challenge["service_uid"]):
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_identity_invalid")
    journal = _open_root(
        journal_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        try:
            prepared = _validate_journal_record(_load_canonical(
                _read_owned_file(
                    journal, f"{challenge['attempt_id']}-prepared.json",
                    trusted_uid=trusted_uid, trusted_gid=trusted_gid)))
        except FileNotFoundError as error:
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_activation_unjournaled") \
                from error
        if (prepared["phase"] != "prepared"
                or prepared["challenge_sha256"]
                   != challenge["challenge_sha256"]
                or prepared["scratch_path"] != identity["path"]
                or prepared["scratch_device"] != identity["device"]
                or prepared["scratch_inode"] != identity["inode"]
                or prepared["scratch_uid"] != identity["service_uid"]
                or prepared["scratch_gid"] != identity["service_gid"]):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_activation_unjournaled")
    finally:
        os.close(journal)
    root = _open_scratch_root(
        qualification_root, trusted_uid=trusted_uid,
        service_gid=identity["service_gid"])
    session = attempt = -1
    try:
        session = os.open(
            challenge["session_id"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root)
        attempt = os.open(
            challenge["attempt_id"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=session)
        before = os.fstat(attempt)
        if ((before.st_dev, before.st_ino)
                != (identity["device"], identity["inode"])
                or before.st_uid != trusted_uid
                or before.st_gid != identity["service_gid"]
                or stat.S_IMODE(before.st_mode) != 0o700
                or os.listdir(attempt)):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_activation_ambiguous")
        os.fchown(
            attempt, identity["service_uid"], identity["service_gid"])
        os.fchmod(attempt, 0o700)
        os.fsync(attempt)
        os.fsync(session)
        after = os.fstat(attempt)
        if ((after.st_dev, after.st_ino)
                != (identity["device"], identity["inode"])
                or after.st_uid != identity["service_uid"]
                or after.st_gid != identity["service_gid"]
                or stat.S_IMODE(after.st_mode) != 0o700
                or os.listdir(attempt)):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_activation_ambiguous")
    finally:
        if attempt >= 0:
            os.close(attempt)
        if session >= 0:
            os.close(session)
        os.close(root)


def cleanup_qualification_scratch(
    challenge_value: object,
    identity: Mapping[str, Any],
    *,
    qualification_root: Path = QUALIFICATION_SCRATCH_ROOT,
    trusted_uid: int = 0,
) -> None:
    """Remove only the exact empty attempt inode; ambiguity is terminal."""
    challenge = validate_challenge(challenge_value)
    fields = {"path", "device", "inode", "service_uid", "service_gid"}
    if not isinstance(identity, Mapping) or set(identity) != fields:
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_identity_invalid")
    if identity["path"] != challenge["scratch_directory"]:
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_identity_invalid")
    root = _open_scratch_root(
        qualification_root, trusted_uid=trusted_uid,
        service_gid=identity["service_gid"])
    session = attempt = -1
    try:
        session = os.open(
            challenge["session_id"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root)
        attempt = os.open(
            challenge["attempt_id"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=session)
        info = os.fstat(attempt)
        if ((info.st_dev, info.st_ino)
                != (identity["device"], identity["inode"])
                or info.st_uid not in {
                    trusted_uid, identity["service_uid"]}
                or info.st_gid != identity["service_gid"]
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.listdir(attempt)):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_cleanup_ambiguous")
        os.close(attempt)
        attempt = -1
        os.rmdir(challenge["attempt_id"], dir_fd=session)
        os.fsync(session)
        if os.listdir(session):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_cleanup_ambiguous")
        os.close(session)
        session = -1
        os.rmdir(challenge["session_id"], dir_fd=root)
        os.fsync(root)
    finally:
        if attempt >= 0:
            os.close(attempt)
        if session >= 0:
            os.close(session)
        os.close(root)


def build_probe_request(value: object) -> bytes:
    """Build the sole qualification-only app-server request.

    The opaque challenge is non-secret and digest-bound.  No user bytes,
    arbitrary command, environment value, PTY, stdin, or streaming descriptor
    can enter this request.
    """
    challenge = validate_challenge(value)
    encoded = base64.urlsafe_b64encode(canonical_bytes(challenge)).decode("ascii")
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise NativeCodexIsolationError(
            "native_codex_isolation_challenge_argument_oversized")
    request = {
        "id": f"secure-sandbox-isolation-{challenge['attempt_id']}",
        "method": "command/exec",
        "params": {
            "command": [str(PROBE_EXECUTABLE), "--encoded-challenge", encoded],
            "cwd": WORKSPACE,
            "env": {name: None for name in DENIED_CREDENTIAL_ENVIRONMENT},
            "outputBytesCap": MAX_PROBE_OUTPUT_BYTES,
            "sandboxPolicy": {
                "excludeSlashTmp": True,
                "excludeTmpdirEnvVar": True,
                "networkAccess": False,
                "type": "workspaceWrite",
                "writableRoots": [challenge["scratch_directory"]],
            },
            "streamStdin": False,
            "streamStdoutStderr": False,
            "timeoutMs": 30_000,
            "tty": False,
        },
    }
    return canonical_bytes(request)


def _denied_result(error: OSError) -> str:
    names = {
        errno.EACCES: "denied-eacces",
        errno.ENOENT: "denied-enoent",
        errno.EPERM: "denied-eperm",
        errno.ESRCH: "denied-esrch",
    }
    return names.get(error.errno or 0, f"unexpected-errno-{error.errno or 0}")


def _probe_read(path: Path, *, directory: bool = False) -> tuple[str, bytes | None]:
    try:
        if directory:
            os.listdir(path)
            return "readable", None
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = os.read(descriptor, MAX_ENVIRONMENT_BYTES + 1)
        finally:
            os.close(descriptor)
        return "readable", raw
    except OSError as error:
        return _denied_result(error), None


def _ptrace_probe(pid: int) -> str:
    # PTRACE_SEIZE establishes the authorization boundary without delivering
    # SIGSTOP.  A successful attach is immediately detached and is a failure.
    libc = ctypes.CDLL(None, use_errno=True)
    ptrace = getattr(libc, "ptrace", None)
    if ptrace is None:
        return "unsupported"
    ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                       ctypes.c_void_p, ctypes.c_void_p]
    ptrace.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = ptrace(0x4206, pid, None, None)  # PTRACE_SEIZE
    if result == 0:
        ptrace(17, pid, None, None)  # PTRACE_DETACH; best effort after failure
        return "attached"
    return _denied_result(OSError(ctypes.get_errno(), "ptrace"))


class _IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def _process_vm_readv_probe(pid: int) -> str:
    libc = ctypes.CDLL(None, use_errno=True)
    process_vm_readv = getattr(libc, "process_vm_readv", None)
    if process_vm_readv is None:
        return "unsupported"
    process_vm_readv.argtypes = [
        ctypes.c_int, ctypes.POINTER(_IOVec), ctypes.c_ulong,
        ctypes.POINTER(_IOVec), ctypes.c_ulong, ctypes.c_ulong,
    ]
    process_vm_readv.restype = ctypes.c_ssize_t
    byte = ctypes.c_ubyte()
    local = _IOVec(ctypes.cast(ctypes.pointer(byte), ctypes.c_void_p), 1)
    # Address zero is deliberately invalid.  EFAULT therefore means the
    # authorization gate was crossed and is a qualification failure.  Only a
    # permission or process-visibility denial passes.
    remote = _IOVec(ctypes.c_void_p(0), 1)
    ctypes.set_errno(0)
    result = process_vm_readv(
        pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    if result >= 0:
        return "readable"
    error = ctypes.get_errno()
    if error == errno.EFAULT:
        return "authorized-efault"
    if error == errno.ENOSYS:
        return "unsupported"
    return _denied_result(OSError(error, "process_vm_readv"))


def _proc_mount_restricted() -> tuple[bool, int]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="ascii").splitlines()
        entries = []
        for line in lines:
            before, separator, after = line.partition(" - ")
            fields = before.split()
            tail = after.split()
            if separator and len(fields) >= 6 and len(tail) >= 3 \
                    and fields[4] == "/proc":
                entries.append((fields, tail))
        visible = [name for name in os.listdir("/proc") if name.isdigit()]
    except (OSError, UnicodeError):
        return False, -1
    if len(entries) != 1:
        return False, len(visible)
    fields, tail = entries[0]
    options = set(fields[5].split(",")) | set(tail[2].split(","))
    restricted = (
        fields[3] == "/" and tail[0] == "proc"
        and {"nosuid", "nodev", "noexec"}.issubset(options)
        and 1 <= len(visible) <= MAX_VISIBLE_PROCESSES
    )
    return restricted, len(visible)


def _unexpected_descriptors() -> int:
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return -1
    count = 0
    for name in names:
        if not name.isdigit() or int(name) <= 2:
            continue
        try:
            os.readlink(f"/proc/self/fd/{name}")
        except FileNotFoundError:
            # The descriptor used by listdir is closed before this readback.
            continue
        except OSError:
            count += 1
        else:
            count += 1
    return count


def _stdio_descriptors_safe() -> bool:
    try:
        stdin = os.fstat(0)
        stdout = os.fstat(1)
        stderr = os.fstat(2)
        null = os.stat("/dev/null", follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISCHR(stdin.st_mode)
        and stdin.st_rdev == null.st_rdev
        and stat.S_ISFIFO(stdout.st_mode)
        and stat.S_ISFIFO(stderr.st_mode)
        and (stdout.st_dev, stdout.st_ino) != (stderr.st_dev, stderr.st_ino)
    )


def _network_blocked(family: int, address: tuple[Any, ...]) -> tuple[bool, bool]:
    """Return (blocked, supported)."""
    try:
        descriptor = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT,
                           errno.EPROTONOSUPPORT}:
            return True, True
        return False, False
    try:
        descriptor.settimeout(0.25)
        try:
            descriptor.connect(address)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EPERM, errno.ENETUNREACH,
                               errno.EHOSTUNREACH, errno.ENETDOWN}:
                return True, True
            return False, True
        return False, True
    finally:
        descriptor.close()


def _crash_probe(scratch: Path) -> tuple[bool, bool, int, int]:
    """Return (supported, core_absent, signal, host_pid)."""
    try:
        before = set(os.listdir(scratch))
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
    except (AttributeError, OSError):
        return False, False, 0, 0
    if pid == 0:
        try:
            os.close(write_fd)
            if os.read(read_fd, 1) != b"x":
                os._exit(120)
            os.close(read_fd)
            os.chdir(scratch)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.environ["SECURE_SANDBOX_CRASH_CANARY"] = "nonsecret"
            os.abort()
        except BaseException:
            os._exit(121)
    os.close(read_fd)
    host_pid = 0
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
        lines = [line for line in status.splitlines() if line.startswith("NSpid:")]
        values = lines[0].split()[1:] if len(lines) == 1 else []
        if values:
            host_pid = int(values[0])
    except (OSError, UnicodeError, ValueError):
        host_pid = 0
    try:
        os.write(write_fd, b"x")
    finally:
        os.close(write_fd)
    waited, status_value = os.waitpid(pid, 0)
    try:
        after = set(os.listdir(scratch))
    except OSError:
        after = before | {"unreadable"}
    crash_signal = (
        os.WTERMSIG(status_value) if waited == pid and os.WIFSIGNALED(status_value)
        else 0)
    return True, after == before, crash_signal, host_pid


def run_tool_probe(value: object) -> tuple[str, dict[str, Any]]:
    """Run inside the fixed Codex workspace-write command sandbox.

    The returned first line is an inert hostile JSON-RPC payload.  It must
    remain captured stdout inside the ``command/exec`` response.  The second
    line is the canonical observation.
    """
    challenge = validate_challenge(value)
    failure: list[str] = []
    unsupported: list[str] = []
    own_namespaces: dict[str, int] = {}
    namespace_separated: dict[str, bool] = {}
    for name in NAMESPACE_NAMES:
        try:
            own_namespaces[name] = _namespace_inode(Path("/proc/self/ns") / name)
            namespace_separated[name] = (
                own_namespaces[name] != challenge["parent_namespaces"][name])
        except NativeCodexIsolationError:
            own_namespaces[name] = 0
            namespace_separated[name] = False
            unsupported.append(f"{name}_namespace_unavailable")
        if not namespace_separated[name]:
            failure.append(f"{name}_namespace_not_separated")

    proc_restricted, visible_processes = _proc_mount_restricted()
    if visible_processes < 0:
        unsupported.append("proc_mount_unavailable")
    elif not proc_restricted:
        failure.append("proc_mount_not_restricted")

    parent = Path("/proc") / str(challenge["appserver_pid"])
    environ_access, environ_raw = _probe_read(parent / "environ")
    fd_access, _ = _probe_read(parent / "fd", directory=True)
    mem_access, _ = _probe_read(parent / "mem")
    ptrace_access = _ptrace_probe(challenge["appserver_pid"])
    vm_access = _process_vm_readv_probe(challenge["appserver_pid"])
    access_results = {
        "environ": environ_access,
        "fd": fd_access,
        "mem": mem_access,
        "process_vm_readv": vm_access,
        "ptrace": ptrace_access,
    }
    for name, result in access_results.items():
        if result == "unsupported":
            unsupported.append(f"{name}_unsupported")
        elif result not in _DENIED_ACCESS_RESULTS:
            failure.append(f"parent_{name}_accessible")
    canary = ("CODEX_HOME=" + challenge["codex_home"]).encode("ascii")
    canary_seen = environ_raw is not None and canary in environ_raw.split(b"\0")
    if canary_seen:
        failure.append("parent_canary_readable")

    credential_env_absent = all(
        name not in os.environ for name in DENIED_CREDENTIAL_ENVIRONMENT)
    token_value_absent = all(
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        != challenge["token_sha256"] for value in os.environ.values())
    canary_env_absent = os.environ.get("CODEX_HOME") != challenge["codex_home"]
    if not credential_env_absent:
        failure.append("credential_name_inherited")
    if not token_value_absent:
        failure.append("token_value_inherited")
    if not canary_env_absent:
        failure.append("parent_canary_inherited")
    unexpected_fds = _unexpected_descriptors()
    stdio_safe = _stdio_descriptors_safe()
    if unexpected_fds < 0:
        unsupported.append("fd_inventory_unavailable")
    elif unexpected_fds:
        failure.append("unexpected_descriptor_inherited")
    if not stdio_safe:
        failure.append("stdio_descriptor_boundary_invalid")

    ipv4_blocked, ipv4_supported = _network_blocked(
        socket.AF_INET, ("198.51.100.1", 9))
    ipv6_blocked, ipv6_supported = _network_blocked(
        socket.AF_INET6, ("2001:db8::1", 9, 0, 0))
    if not ipv4_supported:
        unsupported.append("ipv4_probe_unsupported")
    elif not ipv4_blocked:
        failure.append("ipv4_network_reachable")
    if not ipv6_supported:
        unsupported.append("ipv6_probe_unsupported")
    elif not ipv6_blocked:
        failure.append("ipv6_network_reachable")

    scratch = Path(challenge["scratch_directory"])
    marker = Path(challenge["escape_marker"])
    try:
        scratch_info = scratch.lstat()
        scratch_usable = (
            stat.S_ISDIR(scratch_info.st_mode) and not scratch.is_symlink()
            and marker.parent == scratch and not marker.exists())
    except OSError:
        scratch_usable = False
    if not scratch_usable:
        unsupported.append("scratch_directory_unavailable")
        crash_supported, crash_core_absent, crash_signal, crash_host_pid = (
            False, False, 0, 0)
    else:
        crash_supported, crash_core_absent, crash_signal, crash_host_pid = (
            _crash_probe(scratch))
    if not crash_supported:
        unsupported.append("forced_crash_unsupported")
    else:
        if crash_signal != signal.SIGABRT:
            failure.append("forced_crash_signal_invalid")
        if not crash_core_absent:
            failure.append("forced_crash_core_present")
    escape_marker_absent = not marker.exists()
    if not escape_marker_absent:
        failure.append("raw_appserver_escape_executed")

    failure = _reason_codes(failure)
    unsupported = _reason_codes(unsupported)
    outcome = "unsupported" if unsupported else ("fail" if failure else "pass")
    body: dict[str, Any] = {
        "schema": TOOL_OBSERVATION_SCHEMA,
        "attempt_id": challenge["attempt_id"],
        "challenge_sha256": challenge["challenge_sha256"],
        "outcome": outcome,
        "failure_codes": failure,
        "unsupported_codes": unsupported,
        "namespace_separated": namespace_separated,
        "child_namespaces": own_namespaces,
        "proc_mount_restricted": proc_restricted,
        "visible_process_count": visible_processes,
        "parent_access": access_results,
        "parent_canary_seen": canary_seen,
        "credential_environment_absent": credential_env_absent,
        "token_value_absent": token_value_absent,
        "parent_canary_environment_absent": canary_env_absent,
        "unexpected_descriptor_count": unexpected_fds,
        "stdio_descriptors_safe": stdio_safe,
        "ipv4_blocked": ipv4_blocked,
        "ipv6_blocked": ipv6_blocked,
        "forced_crash_signal": crash_signal,
        "forced_crash_host_pid": crash_host_pid,
        "forced_crash_core_absent": crash_core_absent,
        "escape_marker_absent": escape_marker_absent,
        "raw_escape_payload_sha256": challenge[
            "raw_escape_payload_sha256"],
    }
    observation = {**body, "observation_sha256": digest(body)}
    return challenge["raw_escape_payload"], observation


def validate_tool_observation(value: object, *, challenge: object) -> dict[str, Any]:
    admitted = validate_challenge(challenge)
    fields = {
        "schema", "attempt_id", "challenge_sha256", "outcome",
        "failure_codes", "unsupported_codes", "namespace_separated",
        "child_namespaces", "proc_mount_restricted", "visible_process_count",
        "parent_access", "parent_canary_seen",
        "credential_environment_absent", "token_value_absent",
        "parent_canary_environment_absent", "unexpected_descriptor_count",
        "stdio_descriptors_safe",
        "ipv4_blocked", "ipv6_blocked", "forced_crash_signal",
        "forced_crash_host_pid", "forced_crash_core_absent",
        "escape_marker_absent", "raw_escape_payload_sha256",
        "observation_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_observation_fields_invalid")
    if (value["schema"] != TOOL_OBSERVATION_SCHEMA
            or value["attempt_id"] != admitted["attempt_id"]
            or value["challenge_sha256"] != admitted["challenge_sha256"]
            or value["raw_escape_payload_sha256"]
               != admitted["raw_escape_payload_sha256"]
            or value["outcome"] not in _OUTCOMES):
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_observation_identity_invalid")
    failure = _reason_codes(value["failure_codes"])
    unsupported = _reason_codes(value["unsupported_codes"])
    if failure != value["failure_codes"] or unsupported != value["unsupported_codes"]:
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_observation_reasons_invalid")
    expected_outcome = (
        "unsupported" if unsupported else ("fail" if failure else "pass"))
    if value["outcome"] != expected_outcome:
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_observation_outcome_invalid")
    for name in ("namespace_separated", "child_namespaces"):
        item = value[name]
        if not isinstance(item, dict) or set(item) != set(NAMESPACE_NAMES):
            raise NativeCodexIsolationError(
                "native_codex_isolation_tool_namespaces_invalid")
    if (any(not isinstance(item, bool)
            for item in value["namespace_separated"].values())
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 0
                   for item in value["child_namespaces"].values())):
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_namespaces_invalid")
    access = value["parent_access"]
    if (not isinstance(access, dict)
            or set(access) != {
                "environ", "fd", "mem", "process_vm_readv", "ptrace"}
            or any(not isinstance(item, str) or len(item) > 32
                   for item in access.values())):
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_access_invalid")
    boolean_names = {
        "proc_mount_restricted", "parent_canary_seen",
        "credential_environment_absent", "token_value_absent",
        "parent_canary_environment_absent", "ipv4_blocked", "ipv6_blocked",
        "forced_crash_core_absent", "escape_marker_absent",
        "stdio_descriptors_safe",
    }
    if any(not isinstance(value[name], bool) for name in boolean_names):
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_boolean_invalid")
    for name in (
        "visible_process_count", "unexpected_descriptor_count",
        "forced_crash_signal", "forced_crash_host_pid",
    ):
        if (not isinstance(value[name], int) or isinstance(value[name], bool)
                or value[name] < -1 or value[name] > 2 ** 31 - 1):
            raise NativeCodexIsolationError(
                "native_codex_isolation_tool_count_invalid")
    body = {name: value[name] for name in fields - {"observation_sha256"}}
    if (not isinstance(value["observation_sha256"], str)
            or not hmac.compare_digest(value["observation_sha256"], digest(body))):
        raise NativeCodexIsolationError(
            "native_codex_isolation_tool_observation_digest_mismatch")
    return value


def accept_probe_response(
    raw: bytes,
    *,
    challenge: object,
) -> dict[str, Any]:
    """Accept only the response to :func:`build_probe_request`."""
    admitted = validate_challenge(challenge)
    message = _load_canonical(raw, maximum=MAX_PROBE_OUTPUT_BYTES * 2)
    expected_id = f"secure-sandbox-isolation-{admitted['attempt_id']}"
    if (set(message) != {"id", "result"} or message["id"] != expected_id
            or not isinstance(message["result"], dict)
            or set(message["result"]) != {"exitCode", "stderr", "stdout"}
            or message["result"]["exitCode"] != 0
            or message["result"]["stderr"] != ""
            or not isinstance(message["result"]["stdout"], str)):
        raise NativeCodexIsolationError(
            "native_codex_isolation_probe_response_invalid")
    stdout = message["result"]["stdout"]
    if len(stdout.encode("utf-8")) > MAX_PROBE_OUTPUT_BYTES:
        raise NativeCodexIsolationError(
            "native_codex_isolation_probe_output_oversized")
    lines = stdout.splitlines(keepends=True)
    expected_escape = admitted["raw_escape_payload"] + "\n"
    if len(lines) != 2 or lines[0] != expected_escape:
        raise NativeCodexIsolationError(
            "native_codex_isolation_escape_capture_invalid")
    try:
        observation_raw = lines[1].encode("ascii")
    except UnicodeEncodeError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_probe_output_invalid") from error
    return validate_tool_observation(
        _load_canonical(observation_raw), challenge=admitted)


def _read_limited(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not 0 <= info.st_size <= maximum:
            raise NativeCodexIsolationError(
                "native_codex_isolation_file_size_invalid")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum or os.read(descriptor, 1):
            raise NativeCodexIsolationError(
                "native_codex_isolation_file_size_invalid")
        return raw
    finally:
        os.close(descriptor)


def _status_uids(path: Path) -> tuple[int, int, int, int]:
    try:
        text = path.read_text(encoding="ascii")
        lines = [line for line in text.splitlines() if line.startswith("Uid:")]
        values = tuple(int(item) for item in lines[0].split()[1:]) \
            if len(lines) == 1 else ()
    except (OSError, UnicodeError, ValueError) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_status_invalid") from error
    if len(values) != 4:
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_status_invalid")
    return values  # type: ignore[return-value]


def _cgroup_digest(path: Path) -> str:
    try:
        raw = path.read_bytes()
        lines = raw.decode("ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_cgroup_invalid") from error
    matches = [line.removeprefix("0::") for line in lines
               if line.startswith("0::")]
    if (len(lines) != 1 or len(matches) != 1 or not matches[0].startswith("/")
            or ".." in Path(matches[0]).parts):
        raise NativeCodexIsolationError(
            "native_codex_isolation_process_cgroup_invalid")
    return hashlib.sha256((matches[0] + "\n").encode("ascii")).hexdigest()


def _limits_core_zero(path: Path) -> bool:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return False
    matches = [line for line in lines if line.startswith("Max core file size")]
    if len(matches) != 1:
        return False
    values = matches[0].split()
    return len(values) >= 6 and values[4:6] == ["0", "0"]


def _core_pattern_safe(path: Path) -> bool:
    try:
        raw = path.read_bytes()
        pattern = raw.decode("ascii").strip()
    except (OSError, UnicodeError):
        return False
    # core(5): RLIMIT_CORE is ignored when core_pattern is a pipe.  A pipe is
    # therefore an unconditional failure, not an unsupported platform result.
    return (raw == (pattern + "\n").encode("ascii")
            and bool(pattern) and not pattern.startswith("|"))


def _hash_open_file(descriptor: int) -> str:
    hasher = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def collect_root_observation(
    value: object,
    descriptor_value: object,
    *,
    expected_executable: Path,
    launcher_receipt: Mapping[str, Any],
    proc_root: Path = PROC_ROOT,
    core_pattern_path: Path = CORE_PATTERN,
    trusted_uid: int = 0,
) -> dict[str, Any]:
    """Collect root-side facts while the hostile tool probe is live."""
    challenge = validate_challenge(value)
    try:
        descriptor = native_codex_policy.validate_launch_descriptor(
            descriptor_value)
    except native_codex_policy.NativeCodexPolicyError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_descriptor_invalid") from error
    if os.geteuid() != trusted_uid:
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_required")
    pid = challenge["appserver_pid"]
    receipt_fields = {
        "process_id", "process_start_time_ticks", "access_token_sha256",
        "codex_home_sha256", "environment_proof_sha256",
        "receipt_sha256",
    }
    if (not isinstance(launcher_receipt, Mapping)
            or set(launcher_receipt) != receipt_fields):
        raise NativeCodexIsolationError(
            "native_codex_isolation_launcher_receipt_invalid")
    for name in (
            "access_token_sha256", "codex_home_sha256",
            "environment_proof_sha256", "receipt_sha256"):
        _require_sha256(
            launcher_receipt[name],
            "native_codex_isolation_launcher_receipt_invalid")
    launcher_receipt_identity_valid = (
        launcher_receipt["process_id"] == pid
        and launcher_receipt["process_start_time_ticks"]
            == challenge["process_start_time_ticks"]
        and hmac.compare_digest(
            launcher_receipt["receipt_sha256"],
            challenge["launcher_receipt_sha256"]))
    launcher_token_digest_valid = hmac.compare_digest(
        launcher_receipt["access_token_sha256"], challenge["token_sha256"])
    launcher_codex_home_valid = hmac.compare_digest(
        launcher_receipt["codex_home_sha256"],
        challenge["codex_home_sha256"])
    launcher_environment_proof_valid = hmac.compare_digest(
        launcher_receipt["environment_proof_sha256"],
        challenge["environment_proof_sha256"])
    process = proc_root / str(pid)
    start_time_valid = (
        _process_start_time(pid, proc_root=proc_root)
        == challenge["process_start_time_ticks"])
    uids = _status_uids(process / "status")
    process_uid_valid = all(uid == challenge["service_uid"] for uid in uids)

    executable_identity_valid = False
    executable_root_owned = False
    executable_descriptor = -1
    expected_descriptor = -1
    try:
        executable_descriptor = os.open(
            process / "exe", os.O_RDONLY | os.O_CLOEXEC)
        expected_descriptor = os.open(
            expected_executable,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        observed = os.fstat(executable_descriptor)
        expected = os.fstat(expected_descriptor)
        executable_root_owned = (
            stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
            and observed.st_uid == 0 and observed.st_gid == 0
            and not observed.st_mode & 0o022)
        executable_identity_valid = (
            (observed.st_dev, observed.st_ino)
            == (expected.st_dev, expected.st_ino)
            and _hash_open_file(executable_descriptor)
            == descriptor["harness_executable_sha256"])
    except OSError:
        executable_identity_valid = False
    finally:
        if expected_descriptor >= 0:
            os.close(expected_descriptor)
        if executable_descriptor >= 0:
            os.close(executable_descriptor)

    namespace_identity_valid = all(
        _namespace_inode(process / "ns" / name)
        == challenge["parent_namespaces"][name]
        for name in NAMESPACE_NAMES)
    scope_cgroup_valid = (
        _cgroup_digest(process / "cgroup")
        == challenge["scope_cgroup_sha256"])

    service_process_count = 0
    service_uid_single_tenant = True
    allowed_cgroups = set(challenge["allowed_service_cgroup_sha256s"])
    try:
        process_names = [name for name in os.listdir(proc_root) if name.isdigit()]
    except OSError:
        process_names = []
        service_uid_single_tenant = False
    for name in process_names:
        candidate = proc_root / name
        try:
            candidate_uids = _status_uids(candidate / "status")
        except NativeCodexIsolationError:
            if candidate.exists():
                service_uid_single_tenant = False
            continue
        if candidate_uids[0] != challenge["service_uid"]:
            continue
        service_process_count += 1
        try:
            candidate_cgroup = _cgroup_digest(candidate / "cgroup")
        except NativeCodexIsolationError:
            service_uid_single_tenant = False
            continue
        if candidate_cgroup not in allowed_cgroups:
            service_uid_single_tenant = False
    if (not 1 <= service_process_count <= MAX_SERVICE_UID_PROCESSES):
        service_uid_single_tenant = False

    core_pattern_safe = _core_pattern_safe(core_pattern_path)
    core_limit_zero = _limits_core_zero(process / "limits")

    checks = {
        "core_limit_zero": core_limit_zero,
        "core_pattern_safe": core_pattern_safe,
        "executable_identity_valid": executable_identity_valid,
        "executable_root_owned": executable_root_owned,
        "namespace_identity_valid": namespace_identity_valid,
        "launcher_receipt_identity_valid": launcher_receipt_identity_valid,
        "launcher_token_digest_valid": launcher_token_digest_valid,
        "launcher_codex_home_valid": launcher_codex_home_valid,
        "launcher_environment_proof_valid": launcher_environment_proof_valid,
        "process_start_time_valid": start_time_valid,
        "process_uid_valid": process_uid_valid,
        "scope_cgroup_valid": scope_cgroup_valid,
        "service_uid_single_tenant": service_uid_single_tenant,
    }
    body: dict[str, Any] = {
        "schema": ROOT_OBSERVATION_SCHEMA,
        "attempt_id": challenge["attempt_id"],
        "challenge_sha256": challenge["challenge_sha256"],
        "checks": checks,
        "service_uid_process_count": service_process_count,
    }
    return {**body, "observation_sha256": digest(body)}


_ROOT_CHECKS = frozenset({
    "core_limit_zero",
    "core_pattern_safe",
    "executable_identity_valid",
    "executable_root_owned",
    "namespace_identity_valid",
    "launcher_receipt_identity_valid",
    "launcher_token_digest_valid",
    "launcher_codex_home_valid",
    "launcher_environment_proof_valid",
    "process_start_time_valid",
    "process_uid_valid",
    "scope_cgroup_valid",
    "service_uid_single_tenant",
})

_EVIDENCE_CHECKS = frozenset({
    *_ROOT_CHECKS,
    "credential_environment_absent",
    "escape_marker_absent",
    "forced_crash_core_absent",
    "forced_crash_signal_valid",
    "ipv4_blocked",
    "ipv6_blocked",
    "mount_namespace_separated",
    "net_namespace_separated",
    "no_unexpected_descriptors",
    "parent_canary_environment_absent",
    "parent_canary_not_readable",
    "parent_environ_inaccessible",
    "parent_fd_inaccessible",
    "parent_mem_inaccessible",
    "parent_process_vm_readv_denied",
    "parent_ptrace_denied",
    "pid_namespace_separated",
    "proc_mount_restricted",
    "raw_escape_captured_as_content",
    "stdio_descriptors_safe",
    "token_value_absent",
    "user_namespace_separated",
})


def validate_root_observation(
    value: object,
    *,
    challenge: object,
) -> dict[str, Any]:
    admitted = validate_challenge(challenge)
    fields = {
        "schema", "attempt_id", "challenge_sha256", "checks",
        "service_uid_process_count", "observation_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_observation_fields_invalid")
    if (value["schema"] != ROOT_OBSERVATION_SCHEMA
            or value["attempt_id"] != admitted["attempt_id"]
            or value["challenge_sha256"] != admitted["challenge_sha256"]):
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_observation_identity_invalid")
    checks = value["checks"]
    if (not isinstance(checks, dict) or set(checks) != _ROOT_CHECKS
            or any(not isinstance(item, bool) for item in checks.values())):
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_checks_invalid")
    count = value["service_uid_process_count"]
    if (not isinstance(count, int) or isinstance(count, bool)
            or not 0 <= count <= MAX_SERVICE_UID_PROCESSES + 1):
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_process_count_invalid")
    body = {name: value[name] for name in fields - {"observation_sha256"}}
    if (not isinstance(value["observation_sha256"], str)
            or not hmac.compare_digest(value["observation_sha256"], digest(body))):
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_observation_digest_mismatch")
    return value


def _marker_absent(path: str) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def evaluate_qualification(
    firewall: NativeCodexProtocolFirewall,
    descriptor_value: object,
    *,
    challenge: object,
    root_observation: object,
    tool_observation: object,
    policy_manifest_sha256: str,
    probe_executable_sha256: str,
    observed_at_unix: int | None = None,
    marker_absent: bool | None = None,
) -> dict[str, Any]:
    """Reduce live hostile observations to a bounded content-free receipt."""
    admitted = validate_challenge(challenge)
    descriptor, authority = _firewall_authority(firewall, descriptor_value)
    root = validate_root_observation(root_observation, challenge=admitted)
    tool = validate_tool_observation(tool_observation, challenge=admitted)
    subject = qualification_subject(
        descriptor, policy_manifest_sha256=policy_manifest_sha256,
        probe_executable_sha256=probe_executable_sha256)
    if (admitted["qualification_subject_sha256"]
            != subject["qualification_subject_sha256"]
            or admitted["policy_manifest_sha256"]
               != subject["policy_manifest_sha256"]
            or admitted["probe_executable_sha256"]
               != subject["probe_executable_sha256"]
            or admitted["launch_descriptor_sha256"]
               != descriptor["descriptor_sha256"]
            or admitted["runtime_authority_sha256"]
               != descriptor["runtime_authority_sha256"]
            or admitted["firewall_thread_id_sha256"] != hashlib.sha256(
                authority.thread_id.encode("ascii")).hexdigest()):
        raise NativeCodexIsolationError(
            "native_codex_isolation_evaluation_authority_mismatch")
    observed_at = int(time.time()) if observed_at_unix is None else observed_at_unix
    if (not isinstance(observed_at, int) or isinstance(observed_at, bool)
            or observed_at < 1):
        raise NativeCodexIsolationError(
            "native_codex_isolation_observed_at_invalid")
    final_marker_absent = (
        _marker_absent(admitted["escape_marker"])
        if marker_absent is None else marker_absent)
    if not isinstance(final_marker_absent, bool):
        raise NativeCodexIsolationError(
            "native_codex_isolation_marker_result_invalid")

    access = tool["parent_access"]
    checks: dict[str, bool] = dict(root["checks"])
    checks.update({
        "credential_environment_absent": tool[
            "credential_environment_absent"],
        "escape_marker_absent": (
            tool["escape_marker_absent"] and final_marker_absent),
        "forced_crash_core_absent": tool["forced_crash_core_absent"],
        "forced_crash_signal_valid": (
            tool["forced_crash_signal"] == signal.SIGABRT
            and tool["forced_crash_host_pid"] > 1),
        "ipv4_blocked": tool["ipv4_blocked"],
        "ipv6_blocked": tool["ipv6_blocked"],
        "mount_namespace_separated": tool["namespace_separated"]["mnt"],
        "net_namespace_separated": tool["namespace_separated"]["net"],
        "no_unexpected_descriptors": (
            tool["unexpected_descriptor_count"] == 0),
        "stdio_descriptors_safe": tool["stdio_descriptors_safe"],
        "parent_canary_environment_absent": tool[
            "parent_canary_environment_absent"],
        "parent_canary_not_readable": not tool["parent_canary_seen"],
        "parent_environ_inaccessible": access["environ"] in _DENIED_ACCESS_RESULTS,
        "parent_fd_inaccessible": access["fd"] in _DENIED_ACCESS_RESULTS,
        "parent_mem_inaccessible": access["mem"] in _DENIED_ACCESS_RESULTS,
        "parent_process_vm_readv_denied": (
            access["process_vm_readv"] in _DENIED_ACCESS_RESULTS),
        "parent_ptrace_denied": access["ptrace"] in _DENIED_ACCESS_RESULTS,
        "pid_namespace_separated": tool["namespace_separated"]["pid"],
        "proc_mount_restricted": tool["proc_mount_restricted"],
        # The exact hostile JSON appeared only inside the bounded command
        # response, and its requested marker remained absent.
        "raw_escape_captured_as_content": (
            tool["raw_escape_payload_sha256"]
            == admitted["raw_escape_payload_sha256"]
            and final_marker_absent),
        "token_value_absent": tool["token_value_absent"],
        "user_namespace_separated": tool["namespace_separated"]["user"],
    })
    if set(checks) != _EVIDENCE_CHECKS:
        raise NativeCodexIsolationError(
            "native_codex_isolation_internal_check_set_invalid")
    reasons = [name for name, passed in checks.items() if not passed]
    reasons.extend(tool["failure_codes"])
    unsupported = list(tool["unsupported_codes"])
    reason_codes = _reason_codes(reasons + unsupported)
    outcome = (
        "unsupported" if unsupported else ("fail" if reasons else "pass"))
    body: dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "attempt_id": admitted["attempt_id"],
        "provider": "codex",
        "outcome": outcome,
        "reason_codes": reason_codes,
        "observed_at_unix": observed_at,
        "boot_id_sha256": admitted["boot_id_sha256"],
        "qualification_subject_sha256": subject[
            "qualification_subject_sha256"],
        "runtime_authority_sha256": descriptor["runtime_authority_sha256"],
        "harness_generation_id": descriptor["harness_generation_id"],
        "harness_executable_sha256": descriptor[
            "harness_executable_sha256"],
        "model_id": descriptor["model_id"],
        "reasoning_effort": descriptor["reasoning_effort"],
        "cyber_access_program": descriptor["cyber_access_program"],
        "policy_manifest_sha256": subject["policy_manifest_sha256"],
        "probe_executable_sha256": subject["probe_executable_sha256"],
        "launch_descriptor_sha256": descriptor["descriptor_sha256"],
        "appserver_pid": admitted["appserver_pid"],
        "process_start_time_ticks": admitted["process_start_time_ticks"],
        "firewall_thread_id_sha256": admitted[
            "firewall_thread_id_sha256"],
        "challenge_sha256": admitted["challenge_sha256"],
        "root_observation_sha256": root["observation_sha256"],
        "tool_observation_sha256": tool["observation_sha256"],
        "checks": checks,
    }
    return {**body, "evidence_sha256": digest(body)}


def validate_evidence(value: object) -> dict[str, Any]:
    fields = {
        "schema", "attempt_id", "provider", "outcome", "reason_codes",
        "observed_at_unix", "boot_id_sha256",
        "qualification_subject_sha256", "runtime_authority_sha256",
        "harness_generation_id", "harness_executable_sha256", "model_id",
        "reasoning_effort", "cyber_access_program",
        "policy_manifest_sha256", "probe_executable_sha256",
        "launch_descriptor_sha256", "appserver_pid",
        "process_start_time_ticks", "firewall_thread_id_sha256",
        "challenge_sha256", "root_observation_sha256",
        "tool_observation_sha256", "checks", "evidence_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexIsolationError(
            "native_codex_isolation_evidence_fields_invalid")
    if (value["schema"] != EVIDENCE_SCHEMA or value["provider"] != "codex"
            or value["outcome"] not in _OUTCOMES
            or not isinstance(value["observed_at_unix"], int)
            or isinstance(value["observed_at_unix"], bool)
            or value["observed_at_unix"] < 1
            or not isinstance(value["appserver_pid"], int)
            or isinstance(value["appserver_pid"], bool)
            or value["appserver_pid"] <= 1
            or not isinstance(value["process_start_time_ticks"], int)
            or isinstance(value["process_start_time_ticks"], bool)
            or value["process_start_time_ticks"] < 1):
        raise NativeCodexIsolationError(
            "native_codex_isolation_evidence_identity_invalid")
    _require_uuid4(
        value["attempt_id"], "native_codex_isolation_attempt_id_invalid")
    for name in (
        "boot_id_sha256", "qualification_subject_sha256",
        "runtime_authority_sha256", "harness_generation_id",
        "harness_executable_sha256", "policy_manifest_sha256",
        "probe_executable_sha256", "launch_descriptor_sha256",
        "firewall_thread_id_sha256", "challenge_sha256",
        "root_observation_sha256", "tool_observation_sha256",
    ):
        _require_sha256(
            value[name], f"native_codex_isolation_evidence_{name}_invalid")
    reasons = _reason_codes(value["reason_codes"])
    if reasons != value["reason_codes"]:
        raise NativeCodexIsolationError(
            "native_codex_isolation_evidence_reasons_invalid")
    checks = value["checks"]
    if (not isinstance(checks, dict) or set(checks) != _EVIDENCE_CHECKS
            or any(not isinstance(item, bool) for item in checks.values())):
        raise NativeCodexIsolationError(
            "native_codex_isolation_evidence_checks_invalid")
    expected_outcome = "pass" if all(checks.values()) and not reasons else "fail"
    # Unsupported reasons retain an explicit outcome and can never be treated
    # as a pass.  They are identified by their stable *_unsupported suffix.
    if any(reason.endswith("_unsupported")
           or "unavailable" in reason for reason in reasons):
        expected_outcome = "unsupported"
    if value["outcome"] != expected_outcome:
        raise NativeCodexIsolationError(
            "native_codex_isolation_evidence_outcome_invalid")
    for name in ("model_id", "reasoning_effort", "cyber_access_program"):
        if not isinstance(value[name], str) or not value[name]:
            raise NativeCodexIsolationError(
                "native_codex_isolation_evidence_identity_invalid")
    body = {name: value[name] for name in fields - {"evidence_sha256"}}
    if (not isinstance(value["evidence_sha256"], str)
            or not hmac.compare_digest(value["evidence_sha256"], digest(body))):
        raise NativeCodexIsolationError(
            "native_codex_isolation_evidence_digest_mismatch")
    return value


def _trusted_file_digest(path: Path, *, trusted_uid: int) -> tuple[str, int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != 0
                or mode & 0o022 or info.st_size < 1
                or info.st_size > 128 * 1024 * 1024):
            raise NativeCodexIsolationError(
                "native_codex_isolation_policy_component_untrusted")
        return _hash_open_file(descriptor), mode
    finally:
        os.close(descriptor)


def compute_policy_manifest(
    *,
    components: Mapping[str, Path] = DEFAULT_POLICY_COMPONENTS,
    trusted_uid: int = 0,
) -> str:
    if (not isinstance(components, Mapping) or not components
            or len(components) > 32):
        raise NativeCodexIsolationError(
            "native_codex_isolation_policy_components_invalid")
    manifest: dict[str, dict[str, Any]] = {}
    for name in sorted(components):
        path = components[name]
        if (not isinstance(name, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) is None
                or not isinstance(path, Path) or not path.is_absolute()):
            raise NativeCodexIsolationError(
                "native_codex_isolation_policy_components_invalid")
        file_digest, mode = _trusted_file_digest(path, trusted_uid=trusted_uid)
        manifest[name] = {"sha256": file_digest, "mode": mode}
    return digest(manifest)


def probe_executable_sha256(
    *,
    path: Path = PROBE_EXECUTABLE,
    trusted_uid: int = 0,
) -> str:
    result, _mode = _trusted_file_digest(path, trusted_uid=trusted_uid)
    return result


def _open_root(path: Path, *, trusted_uid: int, trusted_gid: int) -> int:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(current.st_mode)
                or (opened.st_dev, opened.st_ino)
                   != (current.st_dev, current.st_ino)
                or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
                or stat.S_IMODE(opened.st_mode) != 0o700):
            raise NativeCodexIsolationError(
                "native_codex_isolation_storage_root_untrusted")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _storage_name_valid(name: str) -> bool:
    return bool(
        re.fullmatch(r"[0-9a-f]{64}\.json", name)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}-"
            r"(?:reserved|prepared|terminal|reconciled)\.json",
            name))


def _read_owned_file(
    root_descriptor: int,
    name: str,
    *,
    trusted_uid: int,
    trusted_gid: int,
) -> bytes:
    if not _storage_name_valid(name):
        raise NativeCodexIsolationError(
            "native_codex_isolation_storage_name_invalid")
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=root_descriptor)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= MAX_CANONICAL_BYTES):
            raise NativeCodexIsolationError(
                "native_codex_isolation_storage_file_untrusted")
        raw = os.read(descriptor, info.st_size + 1)
        if len(raw) != info.st_size or os.read(descriptor, 1):
            raise NativeCodexIsolationError(
                "native_codex_isolation_storage_file_changed")
        return raw
    finally:
        os.close(descriptor)


def _atomic_publish(
    root_descriptor: int,
    name: str,
    raw: bytes,
    *,
    trusted_uid: int,
    trusted_gid: int,
    replace: bool,
) -> None:
    if not _storage_name_valid(name):
        raise NativeCodexIsolationError(
            "native_codex_isolation_storage_name_invalid")
    temporary = f".{name}.{uuid.uuid4().hex}"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        | os.O_CLOEXEC, 0o600, dir_fd=root_descriptor)
    try:
        os.fchown(descriptor, trusted_uid, trusted_gid)
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise NativeCodexIsolationError(
                    "native_codex_isolation_storage_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if replace:
            os.replace(temporary, name, src_dir_fd=root_descriptor,
                       dst_dir_fd=root_descriptor)
        else:
            try:
                os.link(
                    temporary, name, src_dir_fd=root_descriptor,
                    dst_dir_fd=root_descriptor, follow_symlinks=False)
            except FileExistsError:
                raise NativeCodexIsolationError(
                    "native_codex_isolation_storage_replay") from None
            os.unlink(temporary, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=root_descriptor)
        except FileNotFoundError:
            pass


def publish_pass_receipt(
    evidence_value: object,
    *,
    receipt_root: Path = RECEIPT_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> str:
    evidence = validate_evidence(evidence_value)
    if evidence["outcome"] != "pass" or not all(evidence["checks"].values()):
        raise NativeCodexIsolationError(
            "native_codex_isolation_receipt_not_passed")
    if os.geteuid() != trusted_uid:
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_required")
    root = _open_root(
        receipt_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        name = f"{evidence['qualification_subject_sha256']}.json"
        _atomic_publish(
            root, name, canonical_bytes(evidence), trusted_uid=trusted_uid,
            trusted_gid=trusted_gid, replace=True)
        observed = validate_evidence(_load_canonical(_read_owned_file(
            root, name, trusted_uid=trusted_uid, trusted_gid=trusted_gid)))
        if observed != evidence:
            raise NativeCodexIsolationError(
                "native_codex_isolation_receipt_readback_failed")
        return evidence["evidence_sha256"]
    finally:
        os.close(root)


def _live_qualification(
    authority: object, *, descriptor_value: object | None = None,
    provider: str = "codex", receipt_root: Path = RECEIPT_ROOT,
    policy_manifest_sha256: str | None = None,
    probe_sha256: str | None = None,
    current_boot_id_sha256: str | None = None,
    now: int | None = None, trusted_uid: int = 0, trusted_gid: int = 0,
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any], str, int]:
    """Load only the exact subject receipt selected by this authority."""
    if provider != "codex":
        raise NativeCodexIsolationError(
            "native_codex_isolation_provider_unsupported")
    try:
        descriptor = native_codex_policy.make_launch_descriptor(authority)
        if descriptor_value is not None:
            supplied = native_codex_policy.validate_launch_descriptor(
                descriptor_value)
            if supplied != descriptor:
                raise NativeCodexIsolationError(
                    "native_codex_isolation_descriptor_mismatch")
    except native_codex_policy.NativeCodexPolicyError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_authority_invalid") from error
    policy_digest = (
        compute_policy_manifest(trusted_uid=trusted_uid)
        if policy_manifest_sha256 is None else _require_sha256(
            policy_manifest_sha256,
            "native_codex_isolation_policy_manifest_invalid"))
    probe_digest = (
        probe_executable_sha256(trusted_uid=trusted_uid)
        if probe_sha256 is None else _require_sha256(
            probe_sha256, "native_codex_isolation_probe_digest_invalid"))
    subject = qualification_subject(
        descriptor, policy_manifest_sha256=policy_digest,
        probe_executable_sha256=probe_digest)
    boot_digest = (
        boot_id_sha256() if current_boot_id_sha256 is None else _require_sha256(
            current_boot_id_sha256,
            "native_codex_isolation_boot_digest_invalid"))
    observed_at = int(time.time()) if now is None else now
    if (not isinstance(observed_at, int) or isinstance(observed_at, bool)
            or observed_at < 1):
        raise NativeCodexIsolationError(
            "native_codex_isolation_observed_at_invalid")
    root = _open_root(
        receipt_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        name = f"{subject['qualification_subject_sha256']}.json"
        try:
            raw = _read_owned_file(
                root, name, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        except FileNotFoundError:
            raise NativeCodexIsolationError(
                "native_codex_isolation_receipt_missing") from None
    finally:
        os.close(root)
    evidence = validate_evidence(_load_canonical(raw))
    if (evidence["outcome"] != "pass"
            or not all(evidence["checks"].values())
            or evidence["qualification_subject_sha256"]
               != subject["qualification_subject_sha256"]
            or evidence["boot_id_sha256"] != boot_digest
            or evidence["harness_generation_id"]
               != descriptor["harness_generation_id"]
            or evidence["harness_executable_sha256"]
               != descriptor["harness_executable_sha256"]
            or evidence["model_id"] != descriptor["model_id"]
            or evidence["reasoning_effort"] != descriptor["reasoning_effort"]
            or evidence["cyber_access_program"]
               != descriptor["cyber_access_program"]
            or evidence["runtime_authority_sha256"]
               != descriptor["runtime_authority_sha256"]
            or evidence["launch_descriptor_sha256"]
               != descriptor["descriptor_sha256"]
            or evidence["policy_manifest_sha256"]
               != subject["policy_manifest_sha256"]
            or evidence["probe_executable_sha256"]
               != subject["probe_executable_sha256"]
            or not evidence["observed_at_unix"] <= observed_at
            or observed_at - evidence["observed_at_unix"]
               >= MAX_RECEIPT_AGE_SECONDS):
        raise NativeCodexIsolationError(
            "native_codex_isolation_receipt_not_current")
    return descriptor, subject, evidence, boot_digest, observed_at


def require_live_qualification(
    authority: object,
    provider: str = "codex",
    *,
    receipt_root: Path = RECEIPT_ROOT,
    policy_manifest_sha256: str | None = None,
    probe_sha256: str | None = None,
    current_boot_id_sha256: str | None = None,
    now: int | None = None,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> str:
    """Require an exact, current, root-owned hostile qualification receipt.

    This is the pre-launch controller gate.  The actual session must still run
    :func:`evaluate_qualification` before it accepts an operator turn.
    """
    _descriptor, _subject, evidence, _boot, _observed = _live_qualification(
        authority, provider=provider, receipt_root=receipt_root,
        policy_manifest_sha256=policy_manifest_sha256,
        probe_sha256=probe_sha256,
        current_boot_id_sha256=current_boot_id_sha256, now=now,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid,
    )
    return evidence["evidence_sha256"]


def projection_isolation_status_observation(
    authority: object, *, descriptor_value: object,
    research_release_id: str,
    receipt_root: Path = RECEIPT_ROOT,
    policy_manifest_sha256: str | None = None,
    probe_sha256: str | None = None,
    current_boot_id_sha256: str | None = None,
    now: int | None = None,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    """Return the exact short-lived Research projection status payload.

    Release identity discovery stays in the installed Research wrapper.  This
    function accepts only its already attested SHA-256 identity and never
    guesses it from a mutable working tree.
    """
    release = _require_sha256(
        research_release_id,
        "native_codex_isolation_research_release_invalid")
    descriptor, subject, evidence, boot_digest, _timestamp = (
        _live_qualification(
            authority, descriptor_value=descriptor_value,
            receipt_root=receipt_root,
            policy_manifest_sha256=policy_manifest_sha256,
            probe_sha256=probe_sha256,
            current_boot_id_sha256=current_boot_id_sha256, now=now,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        )
    )
    observed_at = evidence["observed_at_unix"]
    return {
        "research_release_id": release,
        "boot_id_sha256": boot_digest,
        "runtime_authority_sha256": descriptor[
            "runtime_authority_sha256"],
        "launch_descriptor_sha256": descriptor["descriptor_sha256"],
        "qualification_subject": subject,
        "qualification_evidence_sha256": evidence["evidence_sha256"],
        "observed_at": observed_at,
        "expires_at": observed_at + MAX_RECEIPT_AGE_SECONDS,
    }


def _journal_record(
    *,
    phase: str,
    challenge: Mapping[str, Any],
    evidence_sha256: str | None,
    outcome: str | None,
    reason: str | None,
    current_boot_id_sha256: str | None,
    scratch_identity: Mapping[str, Any],
) -> dict[str, Any]:
    scratch_fields = {"path", "device", "inode", "service_uid", "service_gid"}
    if (not isinstance(scratch_identity, Mapping)
            or set(scratch_identity) != scratch_fields
            or scratch_identity["path"] != challenge["scratch_directory"]
            or scratch_identity["service_uid"] != challenge["service_uid"]):
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_scratch_invalid")
    device = scratch_identity["device"]
    inode = scratch_identity["inode"]
    if ((device is None) != (inode is None)
            or (device is not None and (
                not isinstance(device, int) or isinstance(device, bool)
                or device < 0 or not isinstance(inode, int)
                or isinstance(inode, bool) or inode <= 0))
            or not isinstance(scratch_identity["service_gid"], int)
            or isinstance(scratch_identity["service_gid"], bool)
            or scratch_identity["service_gid"] <= 0):
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_scratch_invalid")
    body: dict[str, Any] = {
        "schema": JOURNAL_SCHEMA,
        "phase": phase,
        "attempt_id": challenge["attempt_id"],
        "session_id": challenge["session_id"],
        "boot_id_sha256": challenge["boot_id_sha256"],
        "current_boot_id_sha256": current_boot_id_sha256,
        "qualification_subject_sha256": challenge[
            "qualification_subject_sha256"],
        "challenge_sha256": challenge["challenge_sha256"],
        "appserver_pid": challenge["appserver_pid"],
        "process_start_time_ticks": challenge["process_start_time_ticks"],
        "scratch_path": scratch_identity["path"],
        "scratch_device": device,
        "scratch_inode": inode,
        "scratch_uid": scratch_identity["service_uid"],
        "scratch_gid": scratch_identity["service_gid"],
        "evidence_sha256": evidence_sha256,
        "outcome": outcome,
        "reason": reason,
    }
    return {**body, "record_sha256": digest(body)}


def _validate_journal_record(value: object) -> dict[str, Any]:
    fields = {
        "schema", "phase", "attempt_id", "session_id", "boot_id_sha256",
        "current_boot_id_sha256", "qualification_subject_sha256",
        "challenge_sha256", "appserver_pid", "process_start_time_ticks",
        "scratch_path", "scratch_device", "scratch_inode", "scratch_uid",
        "scratch_gid",
        "evidence_sha256", "outcome", "reason", "record_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_record_invalid")
    if value["schema"] != JOURNAL_SCHEMA or value["phase"] not in {
            "reserved", "prepared", "terminal", "reconciled"}:
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_record_invalid")
    _require_uuid4(
        value["attempt_id"],
        "native_codex_isolation_journal_record_invalid")
    _require_uuid4(
        value["session_id"],
        "native_codex_isolation_journal_record_invalid")
    for name in (
        "boot_id_sha256", "qualification_subject_sha256", "challenge_sha256",
        "record_sha256",
    ):
        _require_sha256(
            value[name], "native_codex_isolation_journal_record_invalid")
    for name in ("appserver_pid", "process_start_time_ticks"):
        if (not isinstance(value[name], int) or isinstance(value[name], bool)
                or value[name] <= (1 if name == "appserver_pid" else 0)):
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_record_invalid")
    scratch_path = value["scratch_path"]
    device, inode = value["scratch_device"], value["scratch_inode"]
    if (not isinstance(scratch_path, str)
            or not Path(scratch_path).is_absolute()
            or ".." in Path(scratch_path).parts
            or Path(scratch_path).name != value["attempt_id"]
            or Path(scratch_path).parent.name != value["session_id"]
            or not isinstance(value["scratch_uid"], int)
            or isinstance(value["scratch_uid"], bool)
            or value["scratch_uid"] <= 0
            or not isinstance(value["scratch_gid"], int)
            or isinstance(value["scratch_gid"], bool)
            or value["scratch_gid"] <= 0
            or (device is None) != (inode is None)
            or (device is not None and (
                not isinstance(device, int) or isinstance(device, bool)
                or device < 0 or not isinstance(inode, int)
                or isinstance(inode, bool) or inode <= 0))):
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_record_invalid")
    if value["phase"] == "reserved" and device is not None:
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_record_invalid")
    if value["phase"] in {"prepared", "terminal"} and device is None:
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_record_invalid")
    if value["phase"] in {"reserved", "prepared"}:
        optional = (
            value["current_boot_id_sha256"], value["evidence_sha256"],
            value["outcome"], value["reason"])
        if optional != (None, None, None, None):
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_record_invalid")
    elif value["phase"] == "terminal":
        if (value["current_boot_id_sha256"] != value["boot_id_sha256"]
                or not isinstance(value["evidence_sha256"], str)
                or SHA256.fullmatch(value["evidence_sha256"]) is None
                or value["outcome"] not in _OUTCOMES
                or value["reason"] is not None):
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_record_invalid")
    else:
        if (not isinstance(value["current_boot_id_sha256"], str)
                or SHA256.fullmatch(value["current_boot_id_sha256"]) is None
                or value["evidence_sha256"] is not None
                or value["outcome"] != "fail"
                or value["reason"] not in {
                    "qualification_reboot_interrupted",
                    "qualification_controller_interrupted"}):
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_record_invalid")
    body = {name: value[name] for name in fields - {"record_sha256"}}
    if not hmac.compare_digest(value["record_sha256"], digest(body)):
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_record_invalid")
    return value


def record_prepared(
    challenge_value: object,
    scratch_identity: Mapping[str, Any],
    *,
    journal_root: Path = JOURNAL_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> str:
    challenge = validate_challenge(challenge_value)
    record = _journal_record(
        phase="prepared", challenge=challenge, evidence_sha256=None,
        outcome=None, reason=None, current_boot_id_sha256=None,
        scratch_identity=scratch_identity)
    if os.geteuid() != trusted_uid:
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_required")
    root = _open_root(
        journal_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        reserved_name = f"{challenge['attempt_id']}-reserved.json"
        reserved = _validate_journal_record(_load_canonical(_read_owned_file(
            root, reserved_name, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)))
        if (reserved["phase"] != "reserved"
                or reserved["challenge_sha256"] != challenge["challenge_sha256"]
                or reserved["session_id"] != challenge["session_id"]
                or reserved["scratch_path"] != challenge["scratch_directory"]
                or reserved["scratch_uid"] != challenge["service_uid"]
                or reserved["scratch_gid"] != scratch_identity["service_gid"]):
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_reservation_mismatch")
        name = f"{challenge['attempt_id']}-prepared.json"
        _atomic_publish(
            root, name, canonical_bytes(record), trusted_uid=trusted_uid,
            trusted_gid=trusted_gid, replace=False)
        observed = _validate_journal_record(_load_canonical(_read_owned_file(
            root, name, trusted_uid=trusted_uid, trusted_gid=trusted_gid)))
        if observed != record:
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_readback_failed")
        return record["record_sha256"]
    finally:
        os.close(root)


def record_reserved(
    challenge_value: object,
    *,
    service_gid: int,
    journal_root: Path = JOURNAL_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> str:
    """Journal the exact path before any scratch directory is created."""
    challenge = validate_challenge(challenge_value)
    reservation = {
        "path": challenge["scratch_directory"],
        "device": None,
        "inode": None,
        "service_uid": challenge["service_uid"],
        "service_gid": service_gid,
    }
    record = _journal_record(
        phase="reserved", challenge=challenge, evidence_sha256=None,
        outcome=None, reason=None, current_boot_id_sha256=None,
        scratch_identity=reservation)
    if os.geteuid() != trusted_uid:
        raise NativeCodexIsolationError(
            "native_codex_isolation_root_required")
    root = _open_root(
        journal_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        name = f"{challenge['attempt_id']}-reserved.json"
        _atomic_publish(
            root, name, canonical_bytes(record), trusted_uid=trusted_uid,
            trusted_gid=trusted_gid, replace=False)
        observed = _validate_journal_record(_load_canonical(_read_owned_file(
            root, name, trusted_uid=trusted_uid, trusted_gid=trusted_gid)))
        if observed != record:
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_readback_failed")
        return record["record_sha256"]
    finally:
        os.close(root)


def record_terminal(
    challenge_value: object,
    evidence_value: object,
    *,
    journal_root: Path = JOURNAL_ROOT,
    qualification_root: Path = QUALIFICATION_SCRATCH_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> str:
    challenge = validate_challenge(challenge_value)
    evidence = validate_evidence(evidence_value)
    if (evidence["attempt_id"] != challenge["attempt_id"]
            or evidence["challenge_sha256"] != challenge["challenge_sha256"]):
        raise NativeCodexIsolationError(
            "native_codex_isolation_journal_evidence_mismatch")
    root = _open_root(
        journal_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        prepared_name = f"{challenge['attempt_id']}-prepared.json"
        prepared = _validate_journal_record(_load_canonical(_read_owned_file(
            root, prepared_name, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)))
        if (prepared["challenge_sha256"] != challenge["challenge_sha256"]
                or prepared["qualification_subject_sha256"]
                   != challenge["qualification_subject_sha256"]
                or prepared["appserver_pid"] != challenge["appserver_pid"]
                or prepared["process_start_time_ticks"]
                   != challenge["process_start_time_ticks"]):
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_prepared_mismatch")
        scratch_identity = {
            "path": prepared["scratch_path"],
            "device": prepared["scratch_device"],
            "inode": prepared["scratch_inode"],
            "service_uid": prepared["scratch_uid"],
            "service_gid": prepared["scratch_gid"],
        }
        # Enforce the cleanup-before-terminal invariant even if a caller
        # regresses the controller's explicit ordering.
        _cleanup_journaled_scratch(
            prepared, qualification_root=qualification_root,
            trusted_uid=trusted_uid)
        record = _journal_record(
            phase="terminal", challenge=challenge,
            evidence_sha256=evidence["evidence_sha256"],
            outcome=evidence["outcome"], reason=None,
            current_boot_id_sha256=challenge["boot_id_sha256"],
            scratch_identity=scratch_identity)
        name = f"{challenge['attempt_id']}-terminal.json"
        _atomic_publish(
            root, name, canonical_bytes(record), trusted_uid=trusted_uid,
            trusted_gid=trusted_gid, replace=False)
        observed = _validate_journal_record(_load_canonical(_read_owned_file(
            root, name, trusted_uid=trusted_uid, trusted_gid=trusted_gid)))
        if observed != record:
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_readback_failed")
        return record["record_sha256"]
    finally:
        os.close(root)


def _cleanup_journaled_scratch(
    record: Mapping[str, Any],
    *,
    qualification_root: Path,
    trusted_uid: int,
) -> None:
    """Remove only the exact empty journaled leaf, using held dirfds."""
    expected = (
        qualification_root / record["session_id"] / record["attempt_id"])
    if Path(record["scratch_path"]) != expected:
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_cleanup_ambiguous")
    root = _open_scratch_root(
        qualification_root, trusted_uid=trusted_uid,
        service_gid=record["scratch_gid"])
    session = attempt = -1
    try:
        try:
            session = os.open(
                record["session_id"],
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root)
        except FileNotFoundError:
            return
        session_info = os.fstat(session)
        if (session_info.st_uid != trusted_uid
                or session_info.st_gid != record["scratch_gid"]
                or stat.S_IMODE(session_info.st_mode) != 0o710):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_cleanup_ambiguous")
        try:
            attempt = os.open(
                record["attempt_id"],
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=session)
        except FileNotFoundError:
            if os.listdir(session):
                raise NativeCodexIsolationError(
                    "native_codex_isolation_scratch_cleanup_ambiguous")
            os.close(session)
            session = -1
            os.rmdir(record["session_id"], dir_fd=root)
            os.fsync(root)
            return
        info = os.fstat(attempt)
        if (record["scratch_device"] is not None
                and (info.st_dev, info.st_ino) != (
                    record["scratch_device"], record["scratch_inode"])):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_cleanup_ambiguous")
        permitted_uids = {trusted_uid}
        if record["scratch_device"] is not None:
            permitted_uids.add(record["scratch_uid"])
        if (info.st_uid not in permitted_uids
                or info.st_gid != record["scratch_gid"]
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.listdir(attempt)):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_cleanup_ambiguous")
        os.close(attempt)
        attempt = -1
        os.rmdir(record["attempt_id"], dir_fd=session)
        os.fsync(session)
        if os.listdir(session):
            raise NativeCodexIsolationError(
                "native_codex_isolation_scratch_cleanup_ambiguous")
        os.close(session)
        session = -1
        os.rmdir(record["session_id"], dir_fd=root)
        os.fsync(root)
    except NativeCodexIsolationError:
        raise
    except OSError as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_scratch_cleanup_ambiguous") from error
    finally:
        if attempt >= 0:
            os.close(attempt)
        if session >= 0:
            os.close(session)
        os.close(root)


def reconcile_interrupted(
    *,
    journal_root: Path = JOURNAL_ROOT,
    qualification_root: Path = QUALIFICATION_SCRATCH_ROOT,
    current_boot_id_sha256: str | None = None,
    proc_root: Path = PROC_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> list[str]:
    """Clean exact orphan scratch and terminalize unfinished attempts."""
    boot_digest = (
        boot_id_sha256() if current_boot_id_sha256 is None else _require_sha256(
            current_boot_id_sha256,
            "native_codex_isolation_boot_digest_invalid"))
    root = _open_root(
        journal_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    written: list[str] = []
    try:
        names = sorted(os.listdir(root))
        if len(names) > 8192 or any(re.fullmatch(
                r"[0-9a-f-]{36}-(?:reserved|prepared|terminal|reconciled)\.json",
                name) is None for name in names):
            raise NativeCodexIsolationError(
                "native_codex_isolation_journal_inventory_invalid")
        attempts = sorted({name[:36] for name in names})
        for attempt in attempts:
            prepared_name = f"{attempt}-prepared.json"
            reserved_name = f"{attempt}-reserved.json"
            source_name = (
                prepared_name if prepared_name in names else reserved_name)
            if source_name not in names:
                raise NativeCodexIsolationError(
                    "native_codex_isolation_journal_record_invalid")
            record = _validate_journal_record(_load_canonical(_read_owned_file(
                root, source_name, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)))
            if (record["phase"] not in {"reserved", "prepared"}
                    or record["attempt_id"] != attempt):
                raise NativeCodexIsolationError(
                    "native_codex_isolation_journal_record_invalid")
            if prepared_name in names and reserved_name not in names:
                raise NativeCodexIsolationError(
                    "native_codex_isolation_journal_record_invalid")
            if prepared_name in names:
                reserved = _validate_journal_record(_load_canonical(
                    _read_owned_file(
                        root, reserved_name, trusted_uid=trusted_uid,
                        trusted_gid=trusted_gid)))
                if (reserved["phase"] != "reserved"
                        or reserved["challenge_sha256"]
                           != record["challenge_sha256"]
                        or reserved["scratch_path"] != record["scratch_path"]
                        or reserved["scratch_uid"] != record["scratch_uid"]
                        or reserved["scratch_gid"] != record["scratch_gid"]):
                    raise NativeCodexIsolationError(
                        "native_codex_isolation_journal_record_invalid")
            terminal_name = f"{attempt}-terminal.json"
            reconciled_name = f"{attempt}-reconciled.json"
            if terminal_name in names or reconciled_name in names:
                if terminal_name in names and reconciled_name in names:
                    raise NativeCodexIsolationError(
                        "native_codex_isolation_journal_record_invalid")
                completed_name = (
                    terminal_name if terminal_name in names
                    else reconciled_name)
                completed = _validate_journal_record(_load_canonical(
                    _read_owned_file(
                        root, completed_name, trusted_uid=trusted_uid,
                        trusted_gid=trusted_gid)))
                expected_phase = (
                    "terminal" if terminal_name in names else "reconciled")
                if (completed["phase"] != expected_phase
                        or completed["attempt_id"] != attempt
                        or completed["challenge_sha256"]
                           != record["challenge_sha256"]
                        or completed["scratch_path"]
                           != record["scratch_path"]
                        or completed["scratch_device"]
                           != record["scratch_device"]
                        or completed["scratch_inode"]
                           != record["scratch_inode"]
                        or completed["scratch_uid"] != record["scratch_uid"]
                        or completed["scratch_gid"] != record["scratch_gid"]
                        or completed["appserver_pid"]
                           != record["appserver_pid"]
                        or completed["process_start_time_ticks"]
                           != record["process_start_time_ticks"]):
                    raise NativeCodexIsolationError(
                        "native_codex_isolation_journal_record_invalid")
                # New terminal records are published only after cleanup.  A
                # surviving path is therefore either an exact crash residue
                # or ambiguity, never something to silently skip.
                _cleanup_journaled_scratch(
                    record, qualification_root=qualification_root,
                    trusted_uid=trusted_uid)
                continue
            challenge_stub = {
                "attempt_id": attempt,
                "session_id": record["session_id"],
                "scratch_directory": record["scratch_path"],
                "service_uid": record["scratch_uid"],
                "boot_id_sha256": record["boot_id_sha256"],
                "qualification_subject_sha256": record[
                    "qualification_subject_sha256"],
                "challenge_sha256": record["challenge_sha256"],
                "appserver_pid": record["appserver_pid"],
                "process_start_time_ticks": record[
                    "process_start_time_ticks"],
            }
            reason = (
                "qualification_reboot_interrupted"
                if record["boot_id_sha256"] != boot_digest
                else "qualification_controller_interrupted")
            if record["boot_id_sha256"] == boot_digest:
                process_path = proc_root / str(record["appserver_pid"])
                if process_path.exists():
                    try:
                        observed_start = _process_start_time(
                            record["appserver_pid"], proc_root=proc_root)
                    except NativeCodexIsolationError:
                        raise NativeCodexIsolationError(
                            "native_codex_isolation_orphan_process_ambiguous") \
                            from None
                    if observed_start == record["process_start_time_ticks"]:
                        raise NativeCodexIsolationError(
                            "native_codex_isolation_orphan_process_active")
            _cleanup_journaled_scratch(
                record, qualification_root=qualification_root,
                trusted_uid=trusted_uid)
            scratch_identity = {
                "path": record["scratch_path"],
                "device": record["scratch_device"],
                "inode": record["scratch_inode"],
                "service_uid": record["scratch_uid"],
                "service_gid": record["scratch_gid"],
            }
            reconciled = _journal_record(
                phase="reconciled", challenge=challenge_stub,
                evidence_sha256=None, outcome="fail", reason=reason,
                current_boot_id_sha256=boot_digest,
                scratch_identity=scratch_identity)
            _atomic_publish(
                root, reconciled_name, canonical_bytes(reconciled),
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                replace=False)
            _validate_journal_record(_load_canonical(_read_owned_file(
                root, reconciled_name, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)))
            written.append(reconciled["record_sha256"])
    finally:
        os.close(root)
    return written


def decode_probe_challenge(encoded: str) -> dict[str, Any]:
    if (not isinstance(encoded, str) or not 1 <= len(encoded) <= MAX_ARGUMENT_BYTES
            or re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", encoded) is None):
        raise NativeCodexIsolationError(
            "native_codex_isolation_encoded_challenge_invalid")
    try:
        raw = base64.b64decode(
            encoded.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeError, binascii.Error) as error:
        raise NativeCodexIsolationError(
            "native_codex_isolation_encoded_challenge_invalid") from error
    return validate_challenge(_load_canonical(raw))


def _probe_main(arguments: Sequence[str]) -> int:
    if len(arguments) != 2 or arguments[0] != "--encoded-challenge":
        return 64
    try:
        challenge = decode_probe_challenge(arguments[1])
        escape, observation = run_tool_probe(challenge)
        output = escape.encode("ascii") + b"\n" + canonical_bytes(observation)
        if len(output) > MAX_PROBE_OUTPUT_BYTES:
            return 65
        view = memoryview(output)
        while view:
            written = os.write(1, view)
            if written <= 0:
                return 74
            view = view[written:]
        return 0
    except (NativeCodexIsolationError, OSError):
        return 70


if __name__ == "__main__":
    import sys
    raise SystemExit(_probe_main(sys.argv[1:]))
