#!/usr/bin/env python3
"""Host client and guest dispatcher for the SecureSandbox control plane.

The host side sends one length-prefixed JSON request followed by an optional,
bounded tar stream.  The guest side is reached only through a forced SSH
command and executes this module as root through one exact sudoers rule.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
import platform
import pwd
import re
import selectors
import signal
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import BinaryIO, Callable


SCHEMA = "secure-sandbox-privileged-control-request-v1"
MAX_HEADER = 64 * 1024
MAX_PAYLOAD = 256 * 1024 * 1024
MAX_FILES = 256
MAX_FILE = 128 * 1024 * 1024
MAX_ARGS = 24
MAX_ARG = 512
MAX_RECEIPTS = 4096
RECEIPTS_TO_KEEP = 512
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BACKUP_ID = re.compile(r"^[a-z][a-z0-9-]*-[0-9]{8}T[0-9]{6}Z-[0-9]+$")
PROFILE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
INTEGER = re.compile(r"^[0-9]{1,12}$")
EPOCH = re.compile(r"^[0-9]{10}$")
COMPLETION_STAGE = re.compile(
    r"^\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json)\.complete$"
)

HOST_SSH_TRUST_SCHEMA = "secure-sandbox-host-ssh-trust-v1"
HOST_SSH_TRUST_MATERIAL_SCHEMA = (
    "secure-sandbox-host-ssh-trust-material-v1"
)
HOST_SSH_TRUST_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/host-ssh-trust"
)
HOST_SSH_CONFIG = Path(
    "/usr/local/libexec/secure-sandbox-host/current/ssh_config"
)
HOST_VM_MAINTENANCE = Path(
    "/usr/local/libexec/secure-sandbox-host/current/vm_maintenance"
)
PROVISIONING_AGENT_SOCKET = Path(
    "/tmp/secure-sandbox-ssh-agent.sock"
)
CONTROL_AGENT_SOCKET = Path(
    "/tmp/secure-sandbox-control-ssh-agent.sock"
)
HOST_OPERATOR_REPOSITORY_NAME = "SecureSandbox"
HOST_GATEWAY_BUNDLE_RELATIVE = Path(
    "vms/SecureSandbox-Gateway.pvm"
)
HOST_SSH_TRUST_FILENAMES = {
    "provisioning": "provisioning_key.pub",
    "control": "control_key.pub",
    "known_hosts": "known_hosts",
    "manifest": "manifest.json",
}
HOST_KEY_ALIASES = (
    "SecureSandbox-Gateway",
    "SecureSandbox-Research",
    "SecureSandbox-Target",
)
HOST_SSH_TRUST_CONFIG_PATHS = (
    "/usr/local/var/lib/secure-sandbox/host-ssh-trust/current/"
    "provisioning_key.pub",
    "/usr/local/var/lib/secure-sandbox/host-ssh-trust/current/"
    "control_key.pub",
    "/usr/local/var/lib/secure-sandbox/host-ssh-trust/current/known_hosts",
)
HOST_GATEWAY_PROXY_COMMAND = (
    "/usr/bin/python3 -I "
    "/usr/local/libexec/secure-sandbox-host/current/control_client "
    "proxy-gateway --port %p"
)
SSH_ED25519_WIRE_NAME = b"ssh-ed25519"
SSH_TRUST_MAX_FILE = 64 * 1024
UUID_LINE = re.compile(rb'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"')
SERIAL_LINE = re.compile(
    rb'"IOPlatformSerialNumber"\s*=\s*"([^"\r\n]{1,128})"'
)
MODEL_LINE = re.compile(rb'"model"\s*=\s*<"([^"\r\n]{1,128})')

ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0
ACL_NEXT_ENTRY = -1
ACL_EXTENDED_ALLOW = 1
ACL_EXTENDED_DENY = 2
_ACL_LIBC = ctypes.CDLL(None, use_errno=True)
_ACL_GET_FD_NP = getattr(_ACL_LIBC, "acl_get_fd_np", None)
_ACL_GET_ENTRY = getattr(_ACL_LIBC, "acl_get_entry", None)
_ACL_GET_TAG_TYPE = getattr(_ACL_LIBC, "acl_get_tag_type", None)
_ACL_FREE = getattr(_ACL_LIBC, "acl_free", None)
if _ACL_GET_FD_NP is not None:
    _ACL_GET_FD_NP.argtypes = [ctypes.c_int, ctypes.c_int]
    _ACL_GET_FD_NP.restype = ctypes.c_void_p
if _ACL_GET_ENTRY is not None:
    _ACL_GET_ENTRY.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
    ]
    _ACL_GET_ENTRY.restype = ctypes.c_int
if _ACL_GET_TAG_TYPE is not None:
    _ACL_GET_TAG_TYPE.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
    ]
    _ACL_GET_TAG_TYPE.restype = ctypes.c_int
if _ACL_FREE is not None:
    _ACL_FREE.argtypes = [ctypes.c_void_p]
    _ACL_FREE.restype = ctypes.c_int


class ControlFailure(RuntimeError):
    pass


def memory_proposal_metadata(path: Path, trusted_uid: int = 0) -> dict:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != trusted_uid or metadata.st_size > 65536):
        raise ControlFailure("memory_proposal_untrusted")
    data = json.loads(path.read_text(encoding="utf-8"))
    request_fields = ("category", "title", "proposal", "rationale", "evidence_refs")
    if (not isinstance(data, dict)
            or path.name != f'{data.get("proposal_id")}.json'
            or data.get("schema") != "secure-sandbox-memory-proposal-v1"
            or data.get("authority") != "untrusted_proposal"
            or not isinstance(data.get("run_id"), str)
            or not UUID.fullmatch(data["run_id"])
            or not isinstance(data.get("proposal_id"), str)
            or not UUID.fullmatch(data["proposal_id"])
            or not isinstance(data.get("content_sha256"), str)
            or not SHA256.fullmatch(data["content_sha256"])
            or any(field not in data for field in request_fields)
            or hashlib.sha256(json.dumps(
                {field: data[field] for field in request_fields},
                separators=(",", ":"), sort_keys=True,
            ).encode()).hexdigest() != data["content_sha256"]):
        raise ControlFailure("memory_proposal_untrusted")
    return {key: data[key] for key in (
        "proposal_id", "run_id", "created_at", "category", "title",
        "content_sha256", "status", "authority",
    )}


def _exact(count: int, *patterns: re.Pattern[str]) -> Callable[[list[str]], bool]:
    return lambda args: len(args) == count and all(pattern.fullmatch(value) for pattern, value in zip(patterns, args))


def _none(args: list[str]) -> bool:
    return not args


def _session_policy_source(args: list[str]) -> bool:
    return len(args) == 1 and (
        args[0] == "none" or UUID.fullmatch(args[0]) is not None
    )


def _harness_management(args: list[str]) -> bool:
    return (len(args) == 4 and args[0] in {"retire", "revoke"}
            and SHA256.fullmatch(args[1]) is not None
            and SHA256.fullmatch(args[2]) is not None
            and INTEGER.fullmatch(args[3]) is not None
            and 0 <= int(args[3]) <= 10_000)


def _safe_args(args: list[str]) -> bool:
    return len(args) <= MAX_ARGS and all(0 < len(value) <= MAX_ARG and "\x00" not in value for value in args)


def ensure_state_root(state_root: Path) -> None:
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = state_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ControlFailure("control_state_untrusted")


def audit_event(state_root: Path, role: str, outcome: str, request: dict[str, object] | None, error: str = "") -> None:
    ensure_state_root(state_root)
    event = {
        "schema": "secure-sandbox-privileged-control-audit-v1",
        "timestamp": int(time.time()),
        "role": role,
        "outcome": outcome,
        "kind": request.get("kind") if request else "unparsed",
        "operation": request.get("operation", request.get("installer", "")) if request else "",
        "request_id": request.get("request_id", "") if request else "",
        "request_sha256": hashlib.sha256(canonical_json(request)).hexdigest() if request else "",
        "error": error,
    }
    path = state_root / "audit.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ControlFailure("control_audit_untrusted")
        remaining = memoryview(canonical_json(event) + b"\n")
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise ControlFailure("control_audit_write_failed")
            remaining = remaining[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


# Each entry is executable argv prefix, validator, and accepted guest roles.
# No shell participates in runtime dispatch.
OPERATIONS: dict[str, tuple[list[str], Callable[[list[str]], bool], set[str]]] = {
    "poweroff": (["/usr/bin/systemctl", "poweroff"], _none, {"gateway", "research", "target"}),
    "set-time": (["/usr/bin/date", "-u", "-s"], lambda a: len(a) == 1 and re.fullmatch(r"@[0-9]{10}", a[0]) is not None, {"gateway", "research", "target"}),
    "policy-hash": (["/usr/local/libexec/secure-sandbox/update-policy-hash.sh"], lambda a: len(a) == 1 and a[0] in {"gateway", "research", "target"}, {"gateway", "research", "target"}),
    "pki-verify": (["/usr/local/libexec/secure-sandbox/pki_generation.py", "verify"], _none, {"gateway", "research"}),
    "model-profile-status": (["/usr/local/libexec/secure-sandbox/model_profile_status.py"], _none, {"gateway"}),
    "model-profile-fence": (["/usr/local/libexec/secure-sandbox/model_profile_activate.py", "fence"], _exact(2, UUID, SHA256), {"gateway", "research"}),
    "model-profile-unfence": (["/usr/local/libexec/secure-sandbox/model_profile_activate.py", "unfence"], _exact(1, UUID), {"gateway", "research"}),
    "model-profile-rollback": (["/usr/local/libexec/secure-sandbox/model_profile_activate.py", "rollback"], _exact(1, UUID), {"gateway", "research"}),
    "model-profile-research-status": (["/usr/local/libexec/secure-sandbox/model_profile_activate.py", "status"], _none, {"research"}),
    "harness-active-runtime": (["/usr/local/libexec/secure-sandbox/harness-generation.py", "active-runtime"], _none, {"research"}),
    "harness-generation-runtime": (["/usr/local/libexec/secure-sandbox/harness-generation.py", "generation-runtime"], _exact(1, SHA256), {"research"}),
    "harness-generation-status": (["/usr/local/libexec/secure-sandbox/harness-generation.py", "status"], _none, {"research"}),
    "harness-generation-verify-boundary": (["/usr/local/libexec/secure-sandbox/harness-generation.py", "verify-boundary"], _none, {"research"}),
    "harness-lifecycle-prepare-rollback": (["/usr/local/libexec/secure-sandbox/harness-generation-manager.py", "prepare-rollback"], _exact(1, SHA256), {"research"}),
    "harness-lifecycle-plan-management": (["/usr/local/libexec/secure-sandbox/harness-generation-manager.py", "plan-management"], _harness_management, {"research"}),
    "harness-lifecycle-recovery-status": (["/usr/local/libexec/secure-sandbox/harness-generation-manager.py", "recovery-status"], _none, {"research"}),
    "harness-lifecycle-recover": (["/usr/local/libexec/secure-sandbox/harness-generation-manager.py", "recover"], _exact(1, SHA256), {"research"}),
    "lease-status": (["/usr/local/libexec/secure-sandbox/run_lease.py", "status"], _exact(1, RUN_ID), {"gateway"}),
    "lease-renew": (["/usr/local/libexec/secure-sandbox/run_lease.py", "renew"], _exact(2, RUN_ID, INTEGER), {"gateway"}),
    "lease-finalize": (["/usr/local/libexec/secure-sandbox/run_lease.py", "finalize"], _exact(2, RUN_ID, SAFE_NAME), {"gateway"}),
    "watchdog-close": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "close"], _exact(1, RUN_ID), {"research"}),
    "watchdog-commit": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "commit"], _exact(2, RUN_ID, SHA256), {"research"}),
    "watchdog-status": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "status"], _exact(1, RUN_ID), {"research"}),
    "watchdog-completed": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "completed"], _exact(1, RUN_ID), {"research"}),
    "execution-approval-next": (["/usr/local/libexec/secure-sandbox/execution_broker.py", "approval-next"], _exact(2, RUN_ID, UUID), {"research"}),
    "session-refresh": (["/usr/local/libexec/secure-sandbox/session_registry.py", "refresh"], _none, {"research"}),
    "session-refresh-contains": (["/usr/local/libexec/secure-sandbox/session_registry.py", "refresh-contains"], _exact(1, UUID), {"research"}),
    "session-policy-runtime": (["/usr/local/libexec/secure-sandbox/session_policy_runtime.py"], _session_policy_source, {"research"}),
    "session-contains": (["/usr/local/libexec/secure-sandbox/session_registry.py", "contains"], _exact(1, UUID), {"research"}),
    "session-list": (["/usr/local/libexec/secure-sandbox/session_registry.py", "list"], _none, {"research"}),
    "finding-list": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "list"], _none, {"research"}),
    "finding-show": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "show"], _exact(1, UUID), {"research"}),
    "finding-disposition-status": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "disposition-status"], _exact(1, UUID), {"research"}),
    "finding-apply": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "apply"], _exact(1, SAFE_NAME), {"research"}),
    "corpus-index": (["/usr/local/libexec/secure-sandbox/corpus_intelligence.py", "index"], _exact(1, UUID), {"research"}),
    "corpus-index-status": (["/usr/local/libexec/secure-sandbox/corpus_intelligence.py", "status"], _exact(1, UUID), {"research"}),
    "codegraph-index": (["/usr/local/libexec/secure-sandbox/codegraph_indexer.py", "index"], _exact(1, UUID), {"research"}),
    "codegraph-index-status": (["/usr/local/libexec/secure-sandbox/codegraph_indexer.py", "status"], _exact(1, UUID), {"research"}),
    "dependency-plan": (["/usr/local/libexec/secure-sandbox/dependency_orchestrator.py", "plan"], _exact(1, UUID), {"research"}),
    "dependency-status": (["/usr/local/libexec/secure-sandbox/dependency_orchestrator.py", "status"], _exact(1, UUID), {"research"}),
    "dependency-apply": (["/usr/local/libexec/secure-sandbox/dependency_orchestrator.py", "apply"], _exact(1, UUID), {"research"}),
    "dependency-list": (["/usr/local/libexec/secure-sandbox/dependency_orchestrator.py", "list"], _none, {"research"}),
    "source-plan": (["/usr/local/libexec/secure-sandbox/source_controller.py", "plan"], lambda a: len(a) == 2 and _safe_args(a), {"gateway"}),
    "source-status": (["/usr/local/libexec/secure-sandbox/source_controller.py", "status"], lambda a: len(a) == 1 and _safe_args(a), {"gateway"}),
    "source-plan-npm": (["/usr/local/libexec/secure-sandbox/source_controller.py", "plan-npm"], lambda a: len(a) == 2 and _safe_args(a), {"gateway"}),
    "source-apply": (["/usr/local/libexec/secure-sandbox/source_controller.py", "apply"], _exact(1, UUID), {"gateway"}),
    "source-export": (["/usr/local/libexec/secure-sandbox/source_controller.py", "export"], _exact(1, UUID), {"gateway"}),
    "source-complete": (["/usr/local/libexec/secure-sandbox/source_controller.py", "complete"], _exact(2, UUID, UUID), {"gateway"}),
    "source-import-publish": (["/usr/local/sbin/secure-sandbox-source-import", "publish"], _exact(1, UUID), {"research"}),
    "source-list": (["/usr/local/libexec/secure-sandbox/source_importer.py", "list"], _none, {"research"}),
    "rollback-source-integrity": (["/usr/local/libexec/secure-sandbox/rollback_source_integrity.sh"], lambda a: len(a) == 1 and BACKUP_ID.fullmatch(a[0]) is not None and a[0].startswith("source-integrity-"), {"research"}),
    "rollback-corpus-intelligence": (["/usr/local/libexec/secure-sandbox/rollback_corpus_intelligence.sh"], lambda a: len(a) == 1 and BACKUP_ID.fullmatch(a[0]) is not None and a[0].startswith("corpus-intelligence-"), {"research"}),
    "rollback-run-leases-gateway": (["/usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh"], lambda a: len(a) == 1 and BACKUP_ID.fullmatch(a[0]) is not None and a[0].startswith("run-leases-gateway-"), {"gateway"}),
    "rollback-run-leases-research": (["/usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh"], lambda a: len(a) == 1 and BACKUP_ID.fullmatch(a[0]) is not None and a[0].startswith("run-leases-research-"), {"research"}),
    "rollback-harness-lifecycle-consumer": (["/usr/local/libexec/secure-sandbox/rollback-harness-lifecycle-consumer.sh"], lambda a: len(a) == 1 and BACKUP_ID.fullmatch(a[0]) is not None and a[0].startswith("harness-lifecycle-consumer-"), {"research"}),
    "run-id-set-evidence": (["/usr/local/libexec/secure-sandbox/manage_run_id.py", "set-evidence"], _exact(1, RUN_ID), {"research"}),
    "run-id-clear-evidence": (["/usr/local/libexec/secure-sandbox/manage_run_id.py", "clear-evidence"], _exact(1, RUN_ID), {"research"}),
    "capture-ready": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "capture-ready"], _none, {"research"}),
    "telemetry-tail": (["/usr/bin/tail", "-n", "100", "/var/lib/secure-sandbox/telemetry/current.jsonl"], _none, {"gateway"}),
    "session-refresh-list": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "session-refresh-list"], _none, {"research"}),
    "lifecycle-idle": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "lifecycle-idle"], _none, {"research"}),
    "control-receipts-archive": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "control-receipts-archive"], _none, {"gateway", "research", "target"}),
    "memory-list": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "memory-list"], _none, {"research"}),
    "source-integrity-latest": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "source-integrity-latest"], _none, {"research"}),
    "rollback-approved-claude-policy": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "rollback-approved-claude-policy"], _exact(2, SHA256, SHA256), {"research"}),
    "legacy-inventory": (["/usr/local/libexec/secure-sandbox/legacy_guest_preserver.py", "inventory"], lambda a: len(a) == 1 and a[0] in {"gateway", "research", "target"}, {"research"}),
    "legacy-preserve": (["/usr/local/libexec/secure-sandbox/legacy_guest_preserver.py", "export"], lambda a: len(a) == 1 and a[0] in {"gateway", "research", "target"}, {"research"}),
    "legacy-import": (["/usr/local/libexec/secure-sandbox/legacy_continuity_control.py"], _exact(1, SHA256), {"research"}),
    "control-status": (["/usr/bin/true"], _none, {"gateway", "research", "target"}),
    "control-self-check": (["/usr/local/libexec/secure-sandbox/privileged_control.py", "internal", "control-self-check"], _none, {"gateway", "research", "target"}),
    "control-audit-tail": (["/usr/bin/tail", "-n", "20", "/var/lib/secure-sandbox/control/audit.jsonl"], _none, {"gateway", "research", "target"}),
}

# These operations consume a bounded, content-bound stdin payload.  Keep this
# surface separate from ordinary argv-only operations so adding an operation
# cannot accidentally grant it access to attacker-controlled stdin.
PIPE_OPERATIONS: dict[str, tuple[list[str], Callable[[list[str]], bool], set[str]]] = {
    "lease-issue-v3": (["/usr/local/libexec/secure-sandbox/run_lease.py", "issue-v3"], _exact(2, UUID, PROFILE), {"gateway"}),
    "watchdog-arm-v3": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "arm-v3"], _none, {"research"}),
    "watchdog-renew-v3": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "renew-v3"], _none, {"research"}),
    "source-import-stage": (["/usr/local/sbin/secure-sandbox-source-import", "stage"], _none, {"research"}),
    "execution-approval-deliver": (["/usr/local/libexec/secure-sandbox/execution_broker.py", "approval-deliver"], _none, {"research"}),
    "model-profile-activate": (["/usr/local/libexec/secure-sandbox/model_profile_activate.py"],
        lambda a: len(a) == 0 or (len(a) == 4 and a[0] == "stage-credential"
            and SHA256.fullmatch(a[1]) is not None and SHA256.fullmatch(a[2]) is not None
            and a[3] in {"bearer", "anthropic-api-key", "google-service-account-json"}),
        {"gateway", "research"}),
    "harness-lifecycle-stage-activate": (["/usr/local/libexec/secure-sandbox/harness-generation-manager.py", "stage-activate"], _none, {"research"}),
    "harness-lifecycle-apply": (["/usr/local/libexec/secure-sandbox/harness-generation-manager.py", "apply"], _none, {"research"}),
    # Native-stack rotation consumes one canonical, bounded request. Fixed
    # command prefixes prevent the caller from selecting a role, step, or
    # executable beyond the reviewed control operation.
    "native-harness-stop": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "research", "stop-research-native-harness"], _none, {"research"}),
    "native-tunnel-stop": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "gateway", "stop-gateway-native-tunnel"], _none, {"gateway"}),
    "native-egress-deny-only": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "installed", "deny-only"], _none, {"gateway", "research"}),
    "native-egress-conntrack-delete": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "installed", "conntrack-delete"], _none, {"gateway", "research"}),
    "native-egress-apply": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "installed", "successor-policy"], _none, {"gateway", "research"}),
    "native-tunnel-start": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "gateway", "start-gateway-native-tunnel"], _none, {"gateway"}),
    "native-harness-start": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "research", "start-research-native-harness"], _none, {"research"}),
    "native-runs-stop": (["/usr/local/libexec/secure-sandbox/native_guest_control.py", "research", "stop-bound-runs"], _none, {"research"}),
    # Native provider/status operations accept one bounded canonical request on
    # stdin. No token-bearing Codex stream is admitted here: that projection
    # uses the dedicated fd contract in native_codex_session_controller.py.
    "native-stack-status": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-stack-status"], _none, {"research"}),
    "native-stack-inspect-status": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-stack-inspect-status"], _none, {"research"}),
    "native-provider-action": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-provider-action"], _none, {"research"}),
    "native-qualification-authority": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-qualification-authority"], _none, {"research"}),
    "native-session-authority": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-session-authority"], _none, {"research"}),
    "native-session-plan-authority": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-session-plan-authority"], _none, {"research"}),
    "native-stack-lifecycle-idle": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-stack-lifecycle-idle"], _none, {"research"}),
    "native-stack-catalog-publish": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-stack-catalog-publish"], _none, {"research"}),
    "native-stack-catalog-readback": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-stack-catalog-readback"], _none, {"research"}),
    "native-stack-lifecycle-release": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-stack-lifecycle-release"], _none, {"research"}),
    "native-deployment-lifecycle-acquire": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-deployment-lifecycle-acquire"], _none, {"research"}),
    "native-deployment-lifecycle-recovery-acquire": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-deployment-lifecycle-recovery-acquire"], _none, {"research"}),
    "native-deployment-lifecycle-release": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-deployment-lifecycle-release"], _none, {"research"}),
    "native-program-attestation": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-program-attestation"], _none, {"research"}),
    "native-claude-login-compact": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-claude-login-compact"], _none, {"research"}),
    "native-projection-isolation-status": (["/usr/local/libexec/secure-sandbox/native_provider_controller.py", "native-projection-isolation-status"], _none, {"research"}),
    "native-codex-session-prepare": (["/usr/local/libexec/secure-sandbox/native_codex_session_controller.py", "prepare"], _none, {"research"}),
    "native-codex-session-stop": (["/usr/local/libexec/secure-sandbox/native_codex_session_controller.py", "stop"], _none, {"research"}),
    "native-codex-session-status": (["/usr/local/libexec/secure-sandbox/native_codex_session_controller.py", "status"], _none, {"research"}),
    "native-claude-session-prepare": (["/usr/local/libexec/secure-sandbox/native_claude_session_controller.py", "prepare"], _none, {"research"}),
    "native-claude-session-stop": (["/usr/local/libexec/secure-sandbox/native_claude_session_controller.py", "stop"], _none, {"research"}),
    "native-claude-session-status": (["/usr/local/libexec/secure-sandbox/native_claude_session_controller.py", "status"], _none, {"research"}),
}

# Interactive byte transports are deliberately separate from PIPE_OPERATIONS:
# neither dispatcher nor client may buffer, hash, parse, audit, or persist the
# vendor terminal stream. Only these non-secret binding arguments are audited.
STREAM_OPERATIONS: dict[
    str, tuple[list[str], Callable[[list[str]], bool], set[str]]
] = {
    "native-claude-login": (
        ["/usr/local/libexec/secure-sandbox/native_claude_login_channel.py"],
        _exact(5, UUID, SHA256, SHA256, SHA256, SHA256),
        {"research"},
    ),
    "native-codex-launch": (
        ["/usr/local/libexec/secure-sandbox/native_codex_session_controller.py", "launch"],
        _exact(2, UUID, SHA256),
        {"research"},
    ),
    "native-codex-ui": (
        ["/usr/local/libexec/secure-sandbox/native_codex_session_controller.py", "ui"],
        _exact(6, UUID, SHA256, SHA256, SHA256, SHA256, INTEGER),
        {"research"},
    ),
    "native-claude-launch": (
        ["/usr/local/libexec/secure-sandbox/native_claude_session_controller.py", "launch"],
        _exact(2, UUID, SHA256),
        {"research"},
    ),
}
STREAM_READY = b"SSSTRM1\n"


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def host_ssh_trust_digest(value: object) -> str:
    """Hash one compact, sorted, ASCII trust record including its newline."""
    return hashlib.sha256(canonical_json(value) + b"\n").hexdigest()


def _reject_extended_acl(descriptor: int, failure: str) -> None:
    """Require mode bits to be the complete authority for one trusted inode."""
    if (_ACL_GET_FD_NP is None or _ACL_GET_ENTRY is None
            or _ACL_FREE is None):
        if sys.platform != "darwin":
            return
        raise ControlFailure("host_ssh_trust_acl_api_unavailable")
    ctypes.set_errno(0)
    acl = _ACL_GET_FD_NP(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ControlFailure(failure)
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = _ACL_GET_ENTRY(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0:
            raise ControlFailure(failure)
        if ctypes.get_errno() not in {errno.ENOENT, errno.EINVAL}:
            raise ControlFailure(failure)
    finally:
        if _ACL_FREE(acl) != 0:
            raise ControlFailure("host_ssh_trust_acl_release_failed")


def _reject_allowing_acl(descriptor: int, failure: str) -> None:
    """Allow Darwin's standard deny-only home ACL, never an ACL grant.

    New macOS login homes normally carry ``group:everyone deny delete``.
    Rejecting every extended ACL would make the physical operator account
    unusable.  A deny entry can only remove mode-bit authority; an allow entry
    can add authority and is therefore forbidden on this parent boundary.
    """
    if (_ACL_GET_FD_NP is None or _ACL_GET_ENTRY is None
            or _ACL_GET_TAG_TYPE is None or _ACL_FREE is None):
        if sys.platform != "darwin":
            return
        raise ControlFailure("host_ssh_trust_acl_api_unavailable")
    ctypes.set_errno(0)
    acl = _ACL_GET_FD_NP(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ControlFailure(failure)
    try:
        entry = ctypes.c_void_p()
        entry_id = ACL_FIRST_ENTRY
        while True:
            ctypes.set_errno(0)
            result = _ACL_GET_ENTRY(
                acl, entry_id, ctypes.byref(entry),
            )
            if result != 0:
                if ctypes.get_errno() in {errno.ENOENT, errno.EINVAL}:
                    break
                raise ControlFailure(failure)
            tag = ctypes.c_int()
            if (_ACL_GET_TAG_TYPE(entry, ctypes.byref(tag)) != 0
                    or tag.value != ACL_EXTENDED_DENY):
                raise ControlFailure(failure)
            entry_id = ACL_NEXT_ENTRY
    finally:
        if _ACL_FREE(acl) != 0:
            raise ControlFailure("host_ssh_trust_acl_release_failed")


def _trusted_directory(
    path: Path, expected_uid: int, expected_gid: int, expected_mode: int,
    failure: str,
) -> os.stat_result:
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        after = path.lstat()
        _reject_extended_acl(descriptor, failure)
    except OSError as error:
        raise ControlFailure(failure) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(after.st_mode)
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or opened.st_uid != expected_uid
            or opened.st_gid != expected_gid
            or stat.S_IMODE(opened.st_mode) != expected_mode):
        raise ControlFailure(failure)
    return opened


def _trusted_regular_bytes(
    path: Path, expected_uid: int, expected_gid: int, expected_mode: int,
    failure: str, *, maximum: int = SSH_TRUST_MAX_FILE,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        _reject_extended_acl(descriptor, failure)
        if (not stat.S_ISREG(opened.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or (before.st_dev, before.st_ino)
                    != (opened.st_dev, opened.st_ino)
                or opened.st_uid != expected_uid
                or opened.st_gid != expected_gid
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != expected_mode
                or not 1 <= opened.st_size <= maximum):
            raise ControlFailure(failure)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after_open = os.fstat(descriptor)
        after_named = path.lstat()
    except OSError as error:
        raise ControlFailure(failure) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (len(data) != opened.st_size or len(data) > maximum
            or stat.S_ISLNK(after_named.st_mode)
            or identity(before) != identity(opened)
            or identity(opened) != identity(after_open)
            or identity(after_open) != identity(after_named)):
        raise ControlFailure(failure)
    return bytes(data), opened


def _decode_ssh_ed25519_blob(encoded: str, failure: str) -> bytes:
    if (not isinstance(encoded, str) or not encoded
            or re.fullmatch(r"[A-Za-z0-9+/]+", encoded) is None):
        raise ControlFailure(failure)
    try:
        blob = base64.b64decode(
            encoded + "=" * ((4 - len(encoded) % 4) % 4), validate=True,
        )
    except (ValueError, binascii.Error) as error:
        raise ControlFailure(failure) from error
    if base64.b64encode(blob).decode("ascii").rstrip("=") != encoded:
        raise ControlFailure(failure)

    def ssh_string(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(blob):
            raise ControlFailure(failure)
        length = struct.unpack(">I", blob[offset:offset + 4])[0]
        start = offset + 4; end = start + length
        if end > len(blob):
            raise ControlFailure(failure)
        return blob[start:end], end

    algorithm, offset = ssh_string(0)
    key, offset = ssh_string(offset)
    if (algorithm != SSH_ED25519_WIRE_NAME or len(key) != 32
            or offset != len(blob)):
        raise ControlFailure(failure)
    return blob


def _public_key(
    raw: bytes, failure: str, *, allow_comment: bool,
) -> tuple[bytes, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ControlFailure(failure) from error
    if "\r" in text or "\x00" in text:
        raise ControlFailure(failure)
    fields = text.strip().split()
    if (len(fields) < 2 or fields[0] != "ssh-ed25519"
            or (not allow_comment and len(fields) != 2)):
        raise ControlFailure(failure)
    blob = _decode_ssh_ed25519_blob(fields[1], failure)
    canonical = f"ssh-ed25519 {fields[1]}\n".encode("ascii")
    if not allow_comment and raw != canonical:
        raise ControlFailure(failure)
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest(),
    ).decode("ascii").rstrip("=")
    return blob, fingerprint


def _known_hosts(raw: bytes) -> tuple[bytes, dict[str, str]]:
    failure = "host_ssh_trust_known_hosts_invalid"
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ControlFailure(failure) from error
    if "\r" in text or "\x00" in text or not text.endswith("\n"):
        raise ControlFailure(failure)
    lines = text.splitlines()
    if len(lines) != len(HOST_KEY_ALIASES):
        raise ControlFailure(failure)
    fingerprints: dict[str, str] = {}
    canonical_lines: list[str] = []
    for expected, line in zip(HOST_KEY_ALIASES, lines):
        fields = line.split()
        if (len(fields) != 3 or fields[0] != expected
                or fields[1] != "ssh-ed25519"
                or any(item in fields[0] for item in (",", "*", "?", "|", "@"))):
            raise ControlFailure(failure)
        blob = _decode_ssh_ed25519_blob(fields[2], failure)
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(blob).digest(),
        ).decode("ascii").rstrip("=")
        if fingerprint in fingerprints.values():
            raise ControlFailure(failure)
        fingerprints[expected] = fingerprint
        canonical_lines.append(f"{expected} ssh-ed25519 {fields[2]}")
    canonical = ("\n".join(canonical_lines) + "\n").encode("ascii")
    if raw != canonical:
        raise ControlFailure(failure)
    return canonical, fingerprints


def current_host_machine_identity(
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> str:
    if platform.system() != "Darwin" or platform.machine() not in {
        "arm64", "x86_64",
    }:
        raise ControlFailure("host_ssh_trust_machine_invalid")
    try:
        result = runner(
            ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                 "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ControlFailure("host_ssh_trust_machine_invalid") from error
    if (result.returncode != 0 or len(result.stdout) > 1024 * 1024
            or len(result.stderr) > 64 * 1024):
        raise ControlFailure("host_ssh_trust_machine_invalid")
    platform_uuid = UUID_LINE.search(result.stdout)
    serial = SERIAL_LINE.search(result.stdout)
    model = MODEL_LINE.search(result.stdout)
    if platform_uuid is None or serial is None or model is None:
        raise ControlFailure("host_ssh_trust_machine_invalid")
    material = b"\0".join(
        (platform_uuid.group(1).lower(), serial.group(1), model.group(1)),
    )
    return hashlib.sha256(material).hexdigest()


def _path_lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _agent_identity(
    socket_path: Path, operator_uid: int, expected_blob: bytes,
    expected_fingerprint: str, agent_runner: Callable[..., subprocess.CompletedProcess[bytes]],
    socket_stat_reader: Callable[[Path], os.stat_result],
) -> None:
    failure = "host_ssh_trust_agent_invalid"
    try:
        before = socket_stat_reader(socket_path)
    except OSError as error:
        raise ControlFailure(failure) from error
    if (not stat.S_ISSOCK(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != operator_uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600):
        raise ControlFailure(failure)
    process_options: dict[str, object] = {}
    if os.geteuid() == 0:
        try:
            account = pwd.getpwuid(operator_uid)
        except (KeyError, AttributeError, TypeError, ValueError) as error:
            raise ControlFailure(failure) from error
        if (account.pw_uid != operator_uid
                or not isinstance(account.pw_gid, int)
                or isinstance(account.pw_gid, bool)
                or not 1 <= account.pw_gid < 2 ** 31):
            raise ControlFailure(failure)
        # Query an operator-owned agent as that operator.  This keeps the
        # agent peer identity exact on implementations that authenticate Unix
        # socket clients, and prevents a root client from becoming a second
        # agent principal.
        process_options = {
            "user": operator_uid,
            "group": account.pw_gid,
            "extra_groups": [],
        }
    try:
        result = agent_runner(
            ["/usr/bin/ssh-add", "-L"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                 "SSH_AUTH_SOCK": str(socket_path)},
            **process_options,
        )
        after = socket_stat_reader(socket_path)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ControlFailure(failure) from error
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (identity(before) != identity(after) or result.returncode != 0
            or not 1 <= len(result.stdout) <= 16 * 1024
            or len(result.stderr) > 16 * 1024):
        raise ControlFailure(failure)
    lines = [line for line in result.stdout.splitlines() if line]
    if len(lines) != 1:
        raise ControlFailure(failure)
    blob, fingerprint = _public_key(
        lines[0] + b"\n", failure, allow_comment=True,
    )
    if blob != expected_blob or fingerprint != expected_fingerprint:
        raise ControlFailure(failure)


def validate_client_ssh_trust(
    ssh_config: str | Path, *,
    expected_ssh_config: Path = HOST_SSH_CONFIG,
    trust_root: Path = HOST_SSH_TRUST_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
    effective_uid: int | None = None,
    machine_identity_reader: Callable[[], str] = current_host_machine_identity,
    agent_runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    provisioning_agent_socket: Path = PROVISIONING_AGENT_SOCKET,
    control_agent_socket: Path = CONTROL_AGENT_SOCKET,
    socket_stat_reader: Callable[[Path], os.stat_result] = _path_lstat,
) -> dict[str, object]:
    """Verify the complete machine trust projection before spawning OpenSSH."""
    supplied_config = Path(ssh_config)
    if supplied_config != expected_ssh_config:
        raise ControlFailure("host_ssh_config_path_invalid")
    config_raw, _config_info = _trusted_regular_bytes(
        supplied_config, trusted_uid, trusted_gid, 0o444,
        "host_ssh_config_untrusted", maximum=1024 * 1024,
    )
    try:
        config_text = config_raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ControlFailure("host_ssh_config_untrusted") from error
    identity_files = [
        line.split(None, 1)[1]
        for line in config_text.splitlines()
        if line.strip().startswith("IdentityFile ")
    ]
    known_host_files = [
        line.split(None, 1)[1]
        for line in config_text.splitlines()
        if line.strip().startswith("UserKnownHostsFile ")
    ]
    proxy_commands = [
        line.strip().split(None, 1)[1]
        for line in config_text.splitlines()
        if line.strip().startswith("ProxyCommand ")
    ]
    if ("%d/" in config_text
            or identity_files.count(HOST_SSH_TRUST_CONFIG_PATHS[0]) != 4
            or identity_files.count(HOST_SSH_TRUST_CONFIG_PATHS[1]) != 3
            or len(identity_files) != 7
            or known_host_files != [HOST_SSH_TRUST_CONFIG_PATHS[2]] * 7
            or proxy_commands != [HOST_GATEWAY_PROXY_COMMAND] * 2):
        raise ControlFailure("host_ssh_config_contract_invalid")

    trust_parent = trust_root.parent
    try:
        trust_parent_named = trust_parent.lstat()
    except OSError as error:
        raise ControlFailure("host_ssh_trust_parent_untrusted") from error
    trust_parent_mode = stat.S_IMODE(trust_parent_named.st_mode)
    if trust_parent_mode not in {0o700, 0o755}:
        raise ControlFailure("host_ssh_trust_parent_untrusted")
    parent_before = _trusted_directory(
        trust_parent, trusted_uid, trusted_gid, trust_parent_mode,
        "host_ssh_trust_parent_untrusted",
    )
    root_before = _trusted_directory(
        trust_root, trusted_uid, trusted_gid, 0o755,
        "host_ssh_trust_root_untrusted",
    )
    generations = trust_root / "generations"
    _trusted_directory(
        generations, trusted_uid, trusted_gid, 0o755,
        "host_ssh_trust_generations_untrusted",
    )
    selector = trust_root / "current"
    try:
        selector_before = selector.lstat()
        selector_target = os.readlink(selector)
    except OSError as error:
        raise ControlFailure("host_ssh_trust_selector_untrusted") from error
    if (not stat.S_ISLNK(selector_before.st_mode)
            or selector_before.st_uid != trusted_uid
            or selector_before.st_gid != trusted_gid
            or selector_before.st_nlink != 1
            or re.fullmatch(r"generations/[0-9a-f]{64}", selector_target) is None):
        raise ControlFailure("host_ssh_trust_selector_untrusted")
    trust_id = selector_target.rsplit("/", 1)[1]
    generation = trust_root / selector_target
    generation_before = _trusted_directory(
        generation, trusted_uid, trusted_gid, 0o555,
        "host_ssh_trust_generation_untrusted",
    )
    try:
        with os.scandir(generation) as entries:
            generation_names = {entry.name for entry in entries}
    except OSError as error:
        raise ControlFailure("host_ssh_trust_generation_untrusted") from error
    if generation_names != set(HOST_SSH_TRUST_FILENAMES.values()):
        raise ControlFailure("host_ssh_trust_generation_untrusted")
    manifest_raw, _ = _trusted_regular_bytes(
        generation / HOST_SSH_TRUST_FILENAMES["manifest"],
        trusted_uid, trusted_gid, 0o444, "host_ssh_trust_manifest_untrusted",
    )
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlFailure("host_ssh_trust_manifest_invalid") from error
    expected_manifest_fields = {
        "schema", "trust_id", "operator_uid", "machine_identity_sha256",
        "enrolled_release_id", "ssh_config_sha256",
        "provisioning_public_key_sha256",
        "provisioning_public_key_fingerprint", "control_public_key_sha256",
        "control_public_key_fingerprint", "known_hosts_sha256",
        "known_host_fingerprints", "plan_sha256", "enrolled_at",
        "manifest_sha256",
    }
    if (not isinstance(manifest, dict) or set(manifest) != expected_manifest_fields
            or manifest.get("schema") != HOST_SSH_TRUST_SCHEMA
            or manifest.get("trust_id") != trust_id
            or not isinstance(manifest.get("operator_uid"), int)
            or isinstance(manifest.get("operator_uid"), bool)
            or not 1 <= manifest["operator_uid"] < 2 ** 31
            or any(not isinstance(manifest.get(name), str)
                   or SHA256.fullmatch(manifest[name]) is None
                   for name in (
                       "machine_identity_sha256", "enrolled_release_id",
                       "ssh_config_sha256", "provisioning_public_key_sha256",
                       "control_public_key_sha256", "known_hosts_sha256",
                       "plan_sha256", "manifest_sha256",
                   ))
            or any(not isinstance(manifest.get(name), str)
                   or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", manifest[name])
                      is None
                   for name in (
                       "provisioning_public_key_fingerprint",
                       "control_public_key_fingerprint",
                   ))
            or not isinstance(manifest.get("enrolled_at"), int)
            or isinstance(manifest.get("enrolled_at"), bool)
            or manifest["enrolled_at"] <= 0
            or not isinstance(manifest.get("known_host_fingerprints"), dict)
            or tuple(manifest["known_host_fingerprints"]) != HOST_KEY_ALIASES
            or any(not isinstance(value, str)
                   or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value) is None
                   for value in manifest["known_host_fingerprints"].values())):
        raise ControlFailure("host_ssh_trust_manifest_invalid")
    unsigned = {name: item for name, item in manifest.items()
                if name != "manifest_sha256"}
    if (manifest_raw != canonical_json(manifest) + b"\n"
            or manifest["manifest_sha256"]
               != host_ssh_trust_digest(unsigned)):
        raise ControlFailure("host_ssh_trust_manifest_invalid")
    material = {
        "schema": HOST_SSH_TRUST_MATERIAL_SCHEMA,
        "operator_uid": manifest["operator_uid"],
        "machine_identity_sha256": manifest["machine_identity_sha256"],
        "ssh_config_sha256": manifest["ssh_config_sha256"],
        "provisioning_public_key_sha256":
            manifest["provisioning_public_key_sha256"],
        "provisioning_public_key_fingerprint":
            manifest["provisioning_public_key_fingerprint"],
        "control_public_key_sha256": manifest["control_public_key_sha256"],
        "control_public_key_fingerprint":
            manifest["control_public_key_fingerprint"],
        "known_hosts_sha256": manifest["known_hosts_sha256"],
        "known_host_fingerprints": manifest["known_host_fingerprints"],
    }
    if trust_id != host_ssh_trust_digest(material):
        raise ControlFailure("host_ssh_trust_id_invalid")
    if manifest["ssh_config_sha256"] != hashlib.sha256(config_raw).hexdigest():
        raise ControlFailure("host_ssh_trust_config_changed")
    machine_identity = machine_identity_reader()
    if (not isinstance(machine_identity, str)
            or SHA256.fullmatch(machine_identity) is None
            or machine_identity != manifest["machine_identity_sha256"]):
        raise ControlFailure("host_ssh_trust_machine_changed")
    observed_uid = os.geteuid() if effective_uid is None else effective_uid
    operator_uid = manifest["operator_uid"]
    if observed_uid not in {0, operator_uid}:
        raise ControlFailure("host_ssh_trust_operator_mismatch")

    provisioning_raw, _ = _trusted_regular_bytes(
        generation / HOST_SSH_TRUST_FILENAMES["provisioning"],
        trusted_uid, trusted_gid, 0o444,
        "host_ssh_trust_provisioning_key_untrusted",
    )
    control_raw, _ = _trusted_regular_bytes(
        generation / HOST_SSH_TRUST_FILENAMES["control"],
        trusted_uid, trusted_gid, 0o444,
        "host_ssh_trust_control_key_untrusted",
    )
    known_hosts_raw, _ = _trusted_regular_bytes(
        generation / HOST_SSH_TRUST_FILENAMES["known_hosts"],
        trusted_uid, trusted_gid, 0o444,
        "host_ssh_trust_known_hosts_untrusted",
    )
    provisioning_blob, provisioning_fingerprint = _public_key(
        provisioning_raw, "host_ssh_trust_provisioning_key_invalid",
        allow_comment=False,
    )
    control_blob, control_fingerprint = _public_key(
        control_raw, "host_ssh_trust_control_key_invalid", allow_comment=False,
    )
    if provisioning_blob == control_blob:
        raise ControlFailure("host_ssh_trust_key_separation_invalid")
    _canonical_hosts, host_fingerprints = _known_hosts(known_hosts_raw)
    if (hashlib.sha256(provisioning_raw).hexdigest()
            != manifest["provisioning_public_key_sha256"]
            or provisioning_fingerprint
            != manifest["provisioning_public_key_fingerprint"]
            or hashlib.sha256(control_raw).hexdigest()
            != manifest["control_public_key_sha256"]
            or control_fingerprint != manifest["control_public_key_fingerprint"]
            or hashlib.sha256(known_hosts_raw).hexdigest()
            != manifest["known_hosts_sha256"]
            or host_fingerprints != manifest["known_host_fingerprints"]):
        raise ControlFailure("host_ssh_trust_content_changed")

    _agent_identity(
        provisioning_agent_socket, operator_uid, provisioning_blob,
        provisioning_fingerprint, agent_runner, socket_stat_reader,
    )
    _agent_identity(
        control_agent_socket, operator_uid, control_blob,
        control_fingerprint, agent_runner, socket_stat_reader,
    )
    try:
        selector_after = selector.lstat()
        selector_target_after = os.readlink(selector)
        generation_after = generation.lstat()
        root_after = trust_root.lstat()
        parent_after = trust_parent.lstat()
    except OSError as error:
        raise ControlFailure("host_ssh_trust_changed") from error
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (identity(parent_before) != identity(parent_after)
            or identity(root_before) != identity(root_after)
            or identity(selector_before) != identity(selector_after)
            or selector_target_after != selector_target
            or identity(generation_before) != identity(generation_after)):
        raise ControlFailure("host_ssh_trust_changed")
    return manifest


def _operator_owned_directory(
    path: Path, operator_uid: int, operator_gid: int, failure: str, *,
    allow_deny_only_acl: bool = False,
) -> os.stat_result:
    """Validate one canonical operator-owned directory without following it."""
    descriptor = -1
    try:
        if not path.is_absolute() or path != path.resolve(strict=True):
            raise ControlFailure(failure)
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if allow_deny_only_acl:
            _reject_allowing_acl(descriptor, failure)
        else:
            _reject_extended_acl(descriptor, failure)
        after = path.lstat()
    except ControlFailure:
        raise
    except OSError as error:
        raise ControlFailure(failure) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(after.st_mode)
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or opened.st_uid != operator_uid
            or opened.st_gid != operator_gid
            or stat.S_IMODE(opened.st_mode) & 0o022):
        raise ControlFailure(failure)
    return opened


def client_ssh_process_options(
    manifest: dict[str, object], *, effective_uid: int | None = None,
    account_reader: Callable[[int], object] | None = None,
    repository_name: str = HOST_OPERATOR_REPOSITORY_NAME,
    gateway_bundle_relative: Path = HOST_GATEWAY_BUNDLE_RELATIVE,
) -> dict[str, object]:
    """Return the fail-closed identity drop required for a root client.

    OpenSSH's Gateway ProxyCommand deliberately refuses root.  A client
    admitted through the root-owned trust projection must therefore execute
    OpenSSH as the enrolled local operator, with no supplementary groups.
    """
    operator_uid = manifest.get("operator_uid")
    if (not isinstance(operator_uid, int) or isinstance(operator_uid, bool)
            or not 1 <= operator_uid < 2 ** 31):
        raise ControlFailure("host_ssh_operator_account_invalid")
    observed_uid = os.geteuid() if effective_uid is None else effective_uid
    if observed_uid not in {0, operator_uid}:
        raise ControlFailure("host_ssh_operator_account_invalid")
    reader = pwd.getpwuid if account_reader is None else account_reader
    try:
        account = reader(operator_uid)
        account_uid = account.pw_uid
        account_gid = account.pw_gid
        account_name = account.pw_name
        home_value = account.pw_dir
    except (KeyError, AttributeError, TypeError, ValueError) as error:
        raise ControlFailure("host_ssh_operator_account_invalid") from error
    if (account_uid != operator_uid
            or not isinstance(account_gid, int)
            or isinstance(account_gid, bool)
            or not 1 <= account_gid < 2 ** 31
            or not isinstance(account_name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,127}", account_name)
               is None
            or not isinstance(home_value, str) or not home_value):
        raise ControlFailure("host_ssh_operator_account_invalid")
    home = Path(home_value)
    _operator_owned_directory(
        home, operator_uid, account_gid, "host_ssh_operator_home_untrusted",
        allow_deny_only_acl=True,
    )
    if (not isinstance(repository_name, str)
            or repository_name != HOST_OPERATOR_REPOSITORY_NAME
            or gateway_bundle_relative != HOST_GATEWAY_BUNDLE_RELATIVE):
        raise ControlFailure("host_ssh_operator_repository_untrusted")
    repository = home / repository_name
    _operator_owned_directory(
        repository, operator_uid, account_gid,
        "host_ssh_operator_repository_untrusted",
    )
    _operator_owned_directory(
        repository / gateway_bundle_relative.parent,
        operator_uid, account_gid,
        "host_ssh_operator_repository_untrusted",
    )
    _operator_owned_directory(
        repository / gateway_bundle_relative, operator_uid, account_gid,
        "host_ssh_operator_gateway_bundle_untrusted",
    )
    if observed_uid == operator_uid:
        return {}
    return {
        "user": operator_uid,
        "group": account_gid,
        "extra_groups": [],
        "cwd": str(home),
        "env": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(home),
            "USER": account_name,
            "LOGNAME": account_name,
            "LANG": "C",
            "LC_ALL": "C",
        },
    }


def proxy_gateway_main(
    arguments: argparse.Namespace, *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
) -> int:
    """Run the fixed Gateway transport resolver as the enrolled operator.

    Immutable acceptance drivers legitimately invoke OpenSSH while running as
    root.  The Parallels resolver must nevertheless remain unprivileged, so
    this signed ProxyCommand validates the complete machine trust projection
    and drops only its fixed resolver child to the enrolled operator.
    """
    port = arguments.port
    if (not isinstance(port, str) or re.fullmatch(r"[0-9]{1,5}", port) is None
            or port != "22"):
        raise ControlFailure("gateway_proxy_port_invalid")
    trust_manifest = validate_client_ssh_trust(HOST_SSH_CONFIG)
    process_options = client_ssh_process_options(trust_manifest)
    command = [
        "/usr/bin/python3", "-I", str(HOST_VM_MAINTENANCE),
        "proxy-gateway", "--port", port,
    ]
    process_runner = subprocess.run if runner is None else runner
    try:
        result = process_runner(command, check=False, **process_options)
    except OSError as error:
        raise ControlFailure("gateway_proxy_launch_failed") from error
    if (not isinstance(result.returncode, int)
            or isinstance(result.returncode, bool)):
        raise ControlFailure("gateway_proxy_status_invalid")
    return result.returncode


def read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(min(remaining, 1024 * 1024))
        if not chunk:
            raise ControlFailure("request_truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_exact_fd(
    descriptor: int, length: int, *, deadline: float | None = None,
    timeout_seconds: float | None = None,
) -> bytes:
    """Read exact bytes without read-ahead and within one caller deadline."""
    chunks: list[bytes] = []
    remaining = length
    selector = selectors.DefaultSelector()
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        while remaining:
            if deadline is None:
                events = selector.select()
            else:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    raise subprocess.TimeoutExpired(
                        ["stream-handshake"], timeout_seconds
                    )
                events = selector.select(wait)
                if not events:
                    raise subprocess.TimeoutExpired(
                        ["stream-handshake"], timeout_seconds
                    )
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise ControlFailure("request_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        selector.close()
    return b"".join(chunks)


@contextlib.contextmanager
def client_interrupt_cleanup() -> object:
    """Convert CLI termination signals into exceptions so child cleanup runs."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }

    def interrupted(signum: int, _frame: object) -> None:
        # One-shot: a second TERM/INT during synchronous child termination must
        # not interrupt the reap path and recreate the orphan we are preventing.
        for pending in previous:
            signal.signal(pending, signal.SIG_IGN)
        raise ControlFailure(f"client_interrupted_{signum}")

    try:
        for signum in previous:
            signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def inherited_owned_process_group() -> int | None:
    marker = os.environ.get("SECURE_SANDBOX_OWNED_PROCESS_GROUP", "")
    group = os.getpgrp()
    if marker == "bootstrap":
        return group if os.getpid() == group == os.getsid(0) else None
    if (marker.isascii() and marker.isdecimal()
            and int(marker) == group == os.getsid(0)):
        return group
    return None


def process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate_client_process(
    process: subprocess.Popen[bytes], *, owns_group: bool,
) -> None:
    """Terminate/reap a client child without signalling an invoking shell."""
    if owns_group:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
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
            except (ProcessLookupError, PermissionError):
                pass
    elif process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise ControlFailure("client_process_unreaped") from error
    if owns_group:
        deadline = time.monotonic() + 2
        while process_group_exists(process.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        if process_group_exists(process.pid):
            raise ControlFailure("client_process_group_unreaped")


def read_request(stream: BinaryIO) -> tuple[dict[str, object], bytes]:
    raw_length = read_exact(stream, 4)
    header_length = struct.unpack(">I", raw_length)[0]
    if not 2 <= header_length <= MAX_HEADER:
        raise ControlFailure("header_size_invalid")
    try:
        request = json.loads(read_exact(stream, header_length))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlFailure("header_invalid") from error
    if not isinstance(request, dict) or request.get("schema") != SCHEMA:
        raise ControlFailure("schema_invalid")
    payload_length = request.get("payload_length", 0)
    if not isinstance(payload_length, int) or isinstance(payload_length, bool) or not 0 <= payload_length <= MAX_PAYLOAD:
        raise ControlFailure("payload_size_invalid")
    payload = read_exact(stream, payload_length)
    if stream.read(1):
        raise ControlFailure("trailing_input")
    return request, payload


def write_request(stream: BinaryIO, request: dict[str, object], payload: bytes = b"") -> None:
    request = dict(request)
    request["schema"] = SCHEMA
    request["payload_length"] = len(payload)
    header = canonical_json(request)
    if len(header) > MAX_HEADER or len(payload) > MAX_PAYLOAD:
        raise ControlFailure("request_too_large")
    stream.write(struct.pack(">I", len(header)))
    stream.write(header)
    stream.write(payload)


def _read_source(path: Path) -> tuple[bytes, int]:
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ControlFailure(f"source_not_regular:{path}")
        if opened.st_size > MAX_FILE:
            raise ControlFailure(f"source_too_large:{path.name}")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = read_exact(handle, opened.st_size)
        after = os.fstat(fd)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ControlFailure(f"source_changed:{path.name}")
        return data, stat.S_IMODE(opened.st_mode) & 0o755
    finally:
        os.close(fd)


def build_bundle(specs: list[str], virtual: tuple[str, bytes] | None = None) -> tuple[bytes, list[dict[str, object]]]:
    if not 1 <= len(specs) + (1 if virtual else 0) <= MAX_FILES:
        raise ControlFailure("file_count_invalid")
    seen: set[str] = set()
    values: list[tuple[str, bytes, int]] = []
    manifest: list[dict[str, object]] = []
    for spec in specs:
        source_text, separator, destination = spec.partition(":")
        source = Path(source_text)
        name = destination if separator else source.name
        if not SAFE_NAME.fullmatch(name) or name in seen:
            raise ControlFailure(f"destination_invalid:{name}")
        seen.add(name)
        data, mode = _read_source(source)
        values.append((name, data, mode))
        manifest.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": mode})
    if virtual is not None:
        name, data = virtual
        if not SAFE_NAME.fullmatch(name) or name in seen or len(data) > MAX_FILE:
            raise ControlFailure("stdin_file_invalid")
        values.append((name, data, 0o600))
        manifest.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": 0o600})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, mode in values:
            info = tarfile.TarInfo(f"files/{name}")
            info.size = len(data)
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    payload = output.getvalue()
    if len(payload) > MAX_PAYLOAD:
        raise ControlFailure("bundle_too_large")
    return payload, manifest


def extract_bundle(payload: bytes, manifest: object, stage: Path) -> None:
    if not isinstance(manifest, list) or not 1 <= len(manifest) <= MAX_FILES:
        raise ControlFailure("manifest_invalid")
    expected: dict[str, dict[str, object]] = {}
    for item in manifest:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256", "mode"}:
            raise ControlFailure("manifest_invalid")
        name, size, digest, mode = item["path"], item["size"], item["sha256"], item["mode"]
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name) or name in expected:
            raise ControlFailure("manifest_path_invalid")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE:
            raise ControlFailure("manifest_size_invalid")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ControlFailure("manifest_digest_invalid")
        if not isinstance(mode, int) or isinstance(mode, bool) or mode & ~0o755:
            raise ControlFailure("manifest_mode_invalid")
        expected[name] = item
    seen: set[str] = set()
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
    except tarfile.TarError as error:
        raise ControlFailure("bundle_invalid") from error
    with archive:
        members = archive.getmembers()
        if len(members) != len(expected):
            raise ControlFailure("bundle_inventory_mismatch")
        for member in members:
            if not member.isfile() or not member.name.startswith("files/"):
                raise ControlFailure("bundle_member_invalid")
            name = member.name[6:]
            if not SAFE_NAME.fullmatch(name) or name in seen or name not in expected:
                raise ControlFailure("bundle_member_invalid")
            seen.add(name)
            item = expected[name]
            if member.size != item["size"]:
                raise ControlFailure("bundle_size_mismatch")
            source = archive.extractfile(member)
            if source is None:
                raise ControlFailure("bundle_member_invalid")
            data = read_exact(source, member.size)
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ControlFailure("bundle_digest_mismatch")
            destination = stage / name
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), int(item["mode"]))
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise ControlFailure("bundle_write_failed")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
    if seen != set(expected):
        raise ControlFailure("bundle_inventory_mismatch")


def _private_tmp_exec(stage: Path, installer: str, args: list[str]) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    clone_newns = 0x00020000
    ms_bind = 4096
    ms_rec = 16384
    ms_private = 1 << 18
    if libc.unshare(clone_newns) != 0:
        raise OSError(ctypes.get_errno(), "unshare")
    if libc.mount(None, b"/", None, ms_rec | ms_private, None) != 0:
        raise OSError(ctypes.get_errno(), "mount private")
    if libc.mount(os.fsencode(stage), b"/tmp", None, ms_bind | ms_rec, None) != 0:
        raise OSError(ctypes.get_errno(), "mount stage")
    argv = ["/bin/bash", f"/tmp/{installer}", *args]
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"}
    os.execve(argv[0], argv, environment)


def prepare_private_tmp(stage: Path) -> None:
    """Give the deployment namespace normal /tmp semantics without exposing it.

    The staging parent remains root-only.  Once the directory is bind-mounted
    over /tmp in the forked private mount namespace, 01777 lets deliberately
    deprivileged installer children (notably APT's _apt verifier) use /tmp.
    Bundle members retain their independently validated modes, including 0600
    for virtual secret inputs.
    """
    before = stage.lstat()
    if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o700):
        raise ControlFailure("deployment_stage_untrusted")
    os.chmod(stage, 0o1777)
    after = stage.lstat()
    if (not stat.S_ISDIR(after.st_mode) or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o1777):
        raise ControlFailure("deployment_stage_untrusted")


def run_deployment(role: str, request: dict[str, object], payload: bytes, state_root: Path) -> int:
    installer = request.get("installer")
    args = request.get("args", [])
    if not isinstance(installer, str) or not SAFE_NAME.fullmatch(installer) or not installer.startswith(("install-", "activate-")) or not installer.endswith(".sh"):
        raise ControlFailure("installer_invalid")
    if not isinstance(args, list) or not all(isinstance(value, str) for value in args) or not _safe_args(args):
        raise ControlFailure("arguments_invalid")
    ensure_state_root(state_root)
    stage_parent = state_root / "staging"
    stage_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(stage_parent, 0o700)
    stage = Path(tempfile.mkdtemp(prefix=f"{role}-", dir=stage_parent))
    os.chmod(stage, 0o700)
    try:
        extract_bundle(payload, request.get("files"), stage)
        candidate = stage / installer
        if not candidate.is_file() or candidate.is_symlink() or candidate.stat().st_nlink != 1:
            raise ControlFailure("installer_missing")
        prepare_private_tmp(stage)
        pid = os.fork()
        if pid == 0:
            try:
                _private_tmp_exec(stage, installer, args)
            except BaseException as error:
                print(f"control_deploy_exec_failed:{error}", file=sys.stderr)
                os._exit(126)
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        return 128 + os.WTERMSIG(status)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def receipt_ledger_lock(state_root: Path):
    """Serialize replay checks, reservations, completions, and archival."""
    ensure_state_root(state_root)
    path = state_root / "receipt-ledger.lock"
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ControlFailure("request_receipt_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def reserve_request(state_root: Path, request: dict[str, object]) -> Path:
    with receipt_ledger_lock(state_root):
        return _reserve_request_locked(state_root, request)


def _reserve_request_locked(state_root: Path, request: dict[str, object]) -> Path:
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or UUID.fullmatch(request_id) is None:
        raise ControlFailure("request_id_invalid")
    receipts = state_root / "receipts"
    archive = state_root / "receipt-archive"
    try:
        receipts.mkdir(mode=0o700)
    except FileExistsError:
        metadata = receipts.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ControlFailure("request_receipts_untrusted")
    os.chmod(receipts, 0o700)
    if archive.exists():
        archive_info = archive.lstat()
        if (not stat.S_ISDIR(archive_info.st_mode) or archive_info.st_uid != os.geteuid()
                or stat.S_IMODE(archive_info.st_mode) != 0o700):
            raise ControlFailure("request_receipt_archive_untrusted")
        if archived_receipt_exists(archive, str(request_id)):
            raise ControlFailure("request_replayed")
    entry_count = 0
    with os.scandir(receipts) as entries:
        for entry in entries:
            entry_count += 1
            if entry_count >= MAX_RECEIPTS:
                raise ControlFailure("request_receipt_limit_exceeded")
            metadata = entry.stat(follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
                raise ControlFailure("request_receipts_untrusted")
    path = receipts / f"{request_id}.json"
    record = {
        "schema": "secure-sandbox-privileged-control-receipt-v1",
        "request_id": request_id,
        "request_sha256": hashlib.sha256(canonical_json(request)).hexdigest(),
        "state": "started",
    }
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as error:
        raise ControlFailure("request_replayed") from error
    try:
        data = canonical_json(record) + b"\n"
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ControlFailure("request_receipt_write_failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if archive.exists() and archived_receipt_exists(archive, str(request_id)):
        path.unlink()
        _fsync_directory(receipts)
        raise ControlFailure("request_replayed")
    _fsync_directory(receipts)
    return path


def archived_receipt_exists(archive: Path, request_id: str) -> bool:
    path = archive / f"{request_id}.json"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_HEADER):
        raise ControlFailure("request_receipt_archive_untrusted")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ControlFailure("request_receipt_archive_untrusted") from error
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-privileged-control-receipt-v1"
            or value.get("request_id") != request_id
            or value.get("state") != "completed"):
        raise ControlFailure("request_receipt_archive_untrusted")
    return True


def recover_staged_completions(receipts: Path) -> tuple[int, int]:
    """Finish only the fsynced half of an interrupted atomic completion."""
    recovered = 0
    quarantined_empty = 0
    for staged in sorted(receipts.iterdir()):
        match = COMPLETION_STAGE.fullmatch(staged.name)
        if match is None:
            continue
        canonical = receipts / match.group(1)
        try:
            staged_info = staged.lstat()
            canonical_info = canonical.lstat()
            canonical_value = json.loads(canonical.read_bytes())
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as error:
            raise ControlFailure("request_receipt_completion_recovery_invalid") from error
        if (not stat.S_ISREG(staged_info.st_mode) or stat.S_ISLNK(staged_info.st_mode)
                or staged_info.st_uid != os.geteuid() or staged_info.st_nlink != 1
                or stat.S_IMODE(staged_info.st_mode) != 0o600
                or staged_info.st_size > MAX_HEADER
                or not stat.S_ISREG(canonical_info.st_mode)
                or stat.S_ISLNK(canonical_info.st_mode)
                or canonical_info.st_uid != os.geteuid() or canonical_info.st_nlink != 1
                or stat.S_IMODE(canonical_info.st_mode) != 0o600
                or canonical_info.st_size > MAX_HEADER
                or not isinstance(canonical_value, dict)
                or set(canonical_value)
                != {"schema", "request_id", "request_sha256", "state"}
                or canonical_value.get("schema")
                != "secure-sandbox-privileged-control-receipt-v1"
                or canonical_value.get("request_id") != canonical.stem
                or canonical_value.get("state") != "started"
                or not isinstance(canonical_value.get("request_sha256"), str)
                or SHA256.fullmatch(canonical_value["request_sha256"]) is None):
            raise ControlFailure("request_receipt_completion_recovery_invalid")
        if staged_info.st_size == 0:
            recovery = receipts.parent / "receipt-recovery"
            try:
                recovery.mkdir(mode=0o700)
                _fsync_directory(receipts.parent)
            except FileExistsError:
                pass
            recovery_info = recovery.lstat()
            if (not stat.S_ISDIR(recovery_info.st_mode)
                    or recovery_info.st_uid != os.geteuid()
                    or stat.S_IMODE(recovery_info.st_mode) != 0o700):
                raise ControlFailure("request_receipt_recovery_archive_untrusted")
            destination = recovery / f"{canonical.stem}.empty-completion-stage"
            try:
                destination.lstat()
            except FileNotFoundError:
                pass
            else:
                raise ControlFailure("request_receipt_recovery_archive_collision")
            try:
                os.link(staged, destination, follow_symlinks=False)
            except FileExistsError as error:
                raise ControlFailure(
                    "request_receipt_recovery_archive_collision"
                ) from error
            _fsync_directory(recovery)
            staged.unlink()
            _fsync_directory(receipts)
            quarantined_empty += 1
            continue
        try:
            staged_value = json.loads(staged.read_bytes())
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise ControlFailure("request_receipt_completion_recovery_invalid") from error
        if (not isinstance(staged_value, dict)
                or set(staged_value) != {
                    "schema", "request_id", "request_sha256", "state", "status"
                }
                or staged_value.get("schema")
                != "secure-sandbox-privileged-control-receipt-v1"
                or staged_value.get("request_id") != canonical.stem
                or staged_value.get("state") != "completed"
                or not isinstance(staged_value.get("status"), int)
                or isinstance(staged_value.get("status"), bool)
                or not isinstance(staged_value.get("request_sha256"), str)
                or SHA256.fullmatch(staged_value["request_sha256"]) is None
                or canonical_value.get("request_sha256")
                != staged_value["request_sha256"]):
            raise ControlFailure("request_receipt_completion_recovery_invalid")
        os.replace(staged, canonical)
        _fsync_directory(receipts)
        recovered += 1
    return recovered, quarantined_empty


def archive_control_receipts(state_root: Path, keep: int = RECEIPTS_TO_KEEP) -> dict[str, object]:
    with receipt_ledger_lock(state_root):
        return _archive_control_receipts_locked(state_root, keep)


def _archive_control_receipts_locked(
    state_root: Path, keep: int = RECEIPTS_TO_KEEP
) -> dict[str, object]:
    if not isinstance(keep, int) or isinstance(keep, bool) or not 1 <= keep < MAX_RECEIPTS:
        raise ControlFailure("request_receipt_archive_limit_invalid")
    receipts = state_root / "receipts"
    archive = state_root / "receipt-archive"
    try:
        archive.mkdir(mode=0o700)
        _fsync_directory(state_root)
    except FileExistsError:
        pass
    archive_info = archive.lstat()
    if (not stat.S_ISDIR(archive_info.st_mode) or archive_info.st_uid != os.geteuid()
            or stat.S_IMODE(archive_info.st_mode) != 0o700):
        raise ControlFailure("request_receipt_archive_untrusted")
    recovered, quarantined_empty = recover_staged_completions(receipts)
    completed: list[tuple[int, str, Path]] = []
    for path in receipts.iterdir():
        info = path.lstat()
        if (not path.name.endswith(".json") or UUID.fullmatch(path.stem) is None
                or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_HEADER):
            raise ControlFailure("request_receipts_untrusted")
        try:
            value = json.loads(path.read_bytes())
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise ControlFailure("request_receipts_untrusted") from error
        if (not isinstance(value, dict)
                or value.get("schema") != "secure-sandbox-privileged-control-receipt-v1"
                or value.get("request_id") != path.stem
                or not isinstance(value.get("request_sha256"), str)
                or SHA256.fullmatch(value["request_sha256"]) is None):
            raise ControlFailure("request_receipts_untrusted")
        if value.get("state") == "completed":
            if (set(value) != {"schema", "request_id", "request_sha256", "state", "status"}
                    or not isinstance(value["status"], int) or isinstance(value["status"], bool)):
                raise ControlFailure("request_receipts_untrusted")
            completed.append((info.st_mtime_ns, path.name, path))
        elif (value.get("state") != "started"
              or set(value) != {"schema", "request_id", "request_sha256", "state"}):
            raise ControlFailure("request_receipts_untrusted")
    completed.sort(reverse=True)
    moved = 0
    for _mtime, name, source in completed[keep:]:
        destination = archive / name
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ControlFailure("request_receipt_archive_collision")
        try:
            os.link(source, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise ControlFailure("request_receipt_archive_collision") from error
        _fsync_directory(archive)
        source.unlink()
        _fsync_directory(receipts)
        moved += 1
    return {
        "archived": moved,
        "recovered_completions": recovered,
        "quarantined_empty_completion_stages": quarantined_empty,
        "retained_completed": min(len(completed), keep),
        "schema": "secure-sandbox-control-receipt-archive-v1",
        "status": "archived",
    }


def complete_request(path: Path, request: dict[str, object], result: int) -> None:
    with receipt_ledger_lock(path.parent.parent):
        _complete_request_locked(path, request, result)


def _complete_request_locked(path: Path, request: dict[str, object], result: int) -> None:
    temporary = path.with_name(f".{path.name}.complete")
    record = {
        "schema": "secure-sandbox-privileged-control-receipt-v1",
        "request_id": request["request_id"],
        "request_sha256": hashlib.sha256(canonical_json(request)).hexdigest(),
        "state": "completed",
        "status": result,
    }
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = canonical_json(record) + b"\n"
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ControlFailure("request_receipt_write_failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _self_check_file(
    path: Path, expected_mode: int, expected_uid: int = 0, expected_gid: int = 0
) -> dict[str, object]:
    descriptor, opened = _open_self_check_file(path)
    try:
        if (opened.st_uid != expected_uid or opened.st_gid != expected_gid or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != expected_mode):
            raise ControlFailure(f"control_file_untrusted:{path.name}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > 1024 * 1024:
                raise ControlFailure(f"control_file_too_large:{path.name}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ControlFailure(f"control_file_changed:{path.name}")
        return {
            "gid": opened.st_gid,
            "mode": stat.S_IMODE(opened.st_mode),
            "nlink": opened.st_nlink,
            "sha256": digest.hexdigest(),
            "size": size,
            "uid": opened.st_uid,
        }
    finally:
        os.close(descriptor)


def _open_self_check_file(path: Path) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ControlFailure(f"control_file_untrusted:{path.name}") from error
    opened = os.fstat(descriptor)
    if (not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
        os.close(descriptor)
        raise ControlFailure(f"control_file_untrusted:{path.name}")
    return descriptor, opened


def _labadmin_passwordless_sudo_present() -> bool:
    """Ask sudo itself after invalidating every noninteractive credential."""
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    invalidate = subprocess.run(
        ["/usr/sbin/runuser", "-u", "labadmin", "--", "/usr/bin/sudo", "-k"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False, timeout=10, env=environment,
    )
    if invalidate.returncode != 0:
        raise ControlFailure("labadmin_sudo_policy_unavailable")
    listing = subprocess.run(
        ["/usr/sbin/runuser", "-u", "labadmin", "--", "/usr/bin/sudo", "-n", "-l"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False, timeout=10, env=environment,
    )
    if listing.returncode not in {0, 1}:
        raise ControlFailure("labadmin_sudo_policy_unavailable")
    return listing.returncode == 0


def lifecycle_idle(blocked: tuple[Path, ...] | None = None) -> bool:
    if blocked is None:
        blocked = (
            Path("/run/secure-sandbox/run-id"),
            Path("/run/secure-sandbox/evidence-run-id"),
            Path("/var/lib/secure-sandbox/run-lifecycle/active.json"),
            Path("/var/lib/secure-sandbox/run-lifecycle/failure-latched.json"),
        )
    if any(path.exists() for path in blocked):
        return False
    result = subprocess.run(
        ["/usr/bin/pgrep", "-x", "claude"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False, timeout=10,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    # pgrep: 0 found, 1 not found, >1 operational error.  Only the exact
    # no-match result proves that deployment is safe to begin.
    return result.returncode == 1


def control_self_check(role: str) -> dict[str, object]:
    files = {
        "dispatcher": (Path("/usr/local/libexec/secure-sandbox/privileged_control.py"), 0o755),
        "entrypoint": (Path("/usr/local/libexec/secure-sandbox/privileged_control_entry.py"), 0o755),
        "sudoers": (Path("/etc/sudoers.d/secure-sandbox-control"), 0o444),
        "sshd_policy": (Path("/etc/ssh/sshd_config.d/15-secure-sandbox-control.conf"), 0o644),
        "authorized_key": (Path("/etc/ssh/authorized_keys/securectl"), 0o644),
        "role": (Path("/etc/secure-sandbox/control-role"), 0o644),
    }
    evidence = {name: _self_check_file(path, mode) for name, (path, mode) in files.items()}
    role_value = files["role"][0].read_text(encoding="ascii").strip()
    if role_value != role:
        raise ControlFailure("control_role_mismatch")
    account = pwd.getpwnam("securectl")
    if (account.pw_uid == 0 or account.pw_dir != "/var/empty/securectl"
            or account.pw_shell != "/bin/sh"):
        raise ControlFailure("control_account_untrusted")
    state = Path("/var/lib/secure-sandbox/control").lstat()
    if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0 or state.st_gid != 0
            or stat.S_IMODE(state.st_mode) != 0o700):
        raise ControlFailure("control_state_untrusted")
    for command in (
        ["/usr/sbin/visudo", "-cf", "/etc/sudoers.d/secure-sandbox-control"],
        ["/usr/sbin/sshd", "-t"],
    ):
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False, timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode:
            raise ControlFailure("control_policy_validation_failed")
    effective = subprocess.run(
        ["/usr/sbin/sshd", "-T", "-C", "user=securectl,host=localhost,addr=127.0.0.1"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=10, text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if effective.returncode:
        raise ControlFailure("control_effective_sshd_unavailable")
    settings = {
        fields[0]: " ".join(fields[1:])
        for line in effective.stdout.splitlines()
        if (fields := line.split())
    }
    required = {
        "authenticationmethods": "publickey",
        "authorizedkeysfile": "/etc/ssh/authorized_keys/%u",
        "disableforwarding": "yes",
        "forcecommand": "/usr/local/libexec/secure-sandbox/privileged_control_entry.py",
        "kbdinteractiveauthentication": "no",
        "passwordauthentication": "no",
        "permittty": "no",
        "permituserrc": "no",
        "pubkeyauthentication": "yes",
        "x11forwarding": "no",
    }
    if any(settings.get(name) != value for name, value in required.items()):
        raise ControlFailure("control_effective_sshd_invalid")
    if _labadmin_passwordless_sudo_present():
        raise ControlFailure("labadmin_passwordless_sudo_present")
    return {
        "schema": "secure-sandbox-privileged-control-self-check-v1",
        "files": evidence,
        "labadmin_passwordless_sudo": False,
        "role": role,
        "securectl_uid": account.pw_uid,
        "sshd": required,
        "status": "verified",
    }


def dispatch(role: str, stream: BinaryIO, state_root: Path) -> int:
    if role not in {"gateway", "research", "target"}:
        raise ControlFailure("role_invalid")
    ensure_state_root(state_root)
    request: dict[str, object] | None = None
    try:
        request, payload = read_request(stream)
        kind = request.get("kind")
        if kind in {"run", "pipe", "stream"}:
            if kind == "run" and payload:
                raise ControlFailure("unexpected_payload")
            if kind == "stream" and payload:
                raise ControlFailure("unexpected_payload")
            if kind == "pipe":
                digest = request.get("payload_sha256")
                if not payload or not isinstance(digest, str) or not SHA256.fullmatch(digest):
                    raise ControlFailure("payload_invalid")
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise ControlFailure("payload_digest_mismatch")
            operation = request.get("operation")
            args = request.get("args", [])
            operations = (
                OPERATIONS if kind == "run"
                else STREAM_OPERATIONS if kind == "stream"
                else PIPE_OPERATIONS
            )
            if not isinstance(operation, str) or operation not in operations or not isinstance(args, list) or not all(isinstance(value, str) for value in args):
                raise ControlFailure("operation_invalid")
            prefix, validator, roles = operations[operation]
            if role not in roles:
                raise ControlFailure("operation_not_allowed_for_role")
            if not _safe_args(args) or not validator(args):
                raise ControlFailure("arguments_invalid")
            if operation == "policy-hash" and args != [role]:
                raise ControlFailure("arguments_invalid")
        elif kind == "deploy":
            pass
        else:
            raise ControlFailure("request_kind_invalid")
        receipt = reserve_request(state_root, request)
        audit_event(state_root, role, "started", request)
        if kind in {"run", "pipe", "stream"}:
            if kind == "stream":
                sys.stdout.buffer.write(STREAM_READY)
                sys.stdout.buffer.flush()
                result = subprocess.run(
                    [*prefix, *args], stdin=stream, check=False,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                         "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                         "HOME": "/root"},
                ).returncode
            else:
                result = subprocess.run(
                    [*prefix, *args], input=payload if kind == "pipe" else None,
                    check=False,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"},
                ).returncode
            if operation == "control-status" and result == 0:
                print(json.dumps({"schema": "secure-sandbox-privileged-control-status-v1", "role": role}, sort_keys=True))
        else:
            result = run_deployment(role, request, payload, state_root)
        complete_request(receipt, request, result)
        audit_event(state_root, role, "accepted" if result == 0 else "command_failed", request, "" if result == 0 else f"status_{result}")
        return result
    except (ControlFailure, OSError) as error:
        audit_event(state_root, role, "rejected", request, str(error))
        raise


def stream_client_main(
    arguments: argparse.Namespace, request_id: str, *,
    ssh_process_options: dict[str, object] | None = None,
) -> int:
    request: dict[str, object] = {
        "kind": "stream", "args": arguments.arguments,
        "request_id": request_id, "operation": arguments.name,
    }
    starts_owned_group = inherited_owned_process_group() is None
    deadline = time.monotonic() + arguments.timeout_seconds
    process: subprocess.Popen[bytes] | None = None
    process_options = {} if ssh_process_options is None else dict(
        ssh_process_options,
    )
    with client_interrupt_cleanup():
        try:
            command = [
                "/usr/bin/ssh", "-F", arguments.ssh_config,
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                arguments.host, "request",
            ]
            if threading.current_thread() is threading.main_thread():
                deferred_signals: list[int] = []
                previous_handlers = {
                    signum: signal.getsignal(signum)
                    for signum in (signal.SIGINT, signal.SIGTERM)
                }

                def defer_spawn_signal(signum: int, _frame: object) -> None:
                    if not deferred_signals:
                        deferred_signals.append(signum)

                for signum in previous_handlers:
                    signal.signal(signum, defer_spawn_signal)
                try:
                    spawned = subprocess.Popen(
                        command, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        start_new_session=starts_owned_group, bufsize=0,
                        **process_options,
                    )
                    # Keep deferral active through the ownership assignment.
                    # A handler raised before this store would otherwise leave
                    # the newly created SSH process unreachable by cleanup.
                    process = spawned
                finally:
                    for signum, handler in previous_handlers.items():
                        signal.signal(signum, handler)
                if deferred_signals:
                    signum = deferred_signals[0]
                    handler = previous_handlers[signum]
                    if callable(handler):
                        handler(signum, None)
                    raise ControlFailure(f"client_interrupted_{signum}")
            else:
                process = subprocess.Popen(
                    command, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    start_new_session=starts_owned_group, bufsize=0,
                    **process_options,
                )
            if process.stdin is None or process.stdout is None:
                raise ControlFailure("client_stream_unavailable")
            write_request(process.stdin, request)
            process.stdin.flush()
            ready = read_exact_fd(
                process.stdout.fileno(), len(STREAM_READY), deadline=deadline,
                timeout_seconds=arguments.timeout_seconds,
            )
            if ready != STREAM_READY:
                raise ControlFailure("client_stream_handshake_invalid")

            def relay_operator() -> None:
                try:
                    while True:
                        block = os.read(sys.stdin.fileno(), 16 * 1024)
                        if not block:
                            break
                        view = memoryview(block)
                        while view:
                            count = os.write(process.stdin.fileno(), view)
                            if count <= 0:
                                return
                            view = view[count:]
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass

            writer = threading.Thread(target=relay_operator, daemon=True)
            writer.start()
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(
                            process.args, arguments.timeout_seconds
                        )
                    events = selector.select(min(remaining, 0.1))
                    if not events:
                        if process.poll() is not None:
                            block = os.read(process.stdout.fileno(), 16 * 1024)
                            if block:
                                os.write(sys.stdout.fileno(), block)
                                continue
                            break
                        continue
                    block = os.read(process.stdout.fileno(), 16 * 1024)
                    if not block:
                        break
                    view = memoryview(block)
                    while view:
                        count = os.write(sys.stdout.fileno(), view)
                        if count <= 0:
                            raise ControlFailure("client_stream_output_failed")
                        view = view[count:]
            finally:
                selector.close()
            status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if starts_owned_group and process_group_exists(process.pid):
                terminate_client_process(process, owns_group=True)
                raise ControlFailure("client_stream_process_group_unreaped")
            return status
        except subprocess.TimeoutExpired:
            if process is not None:
                terminate_client_process(process, owns_group=starts_owned_group)
            return 124
        except BaseException:
            if process is not None:
                terminate_client_process(process, owns_group=starts_owned_group)
            raise
        finally:
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                if process.stdout is not None and not process.stdout.closed:
                    process.stdout.close()


def client_main(arguments: argparse.Namespace) -> int:
    with client_interrupt_cleanup():
        return _client_main(arguments)


def _client_main(arguments: argparse.Namespace) -> int:
    if not 1 <= arguments.timeout_seconds <= 3600:
        raise ControlFailure("client_timeout_invalid")
    trust_manifest = validate_client_ssh_trust(arguments.ssh_config)
    ssh_process_options = client_ssh_process_options(trust_manifest)
    request_id = arguments.request_id or str(uuid.uuid4())
    if UUID.fullmatch(request_id) is None:
        raise ControlFailure("request_id_invalid")
    if arguments.command == "stream":
        return stream_client_main(
            arguments, request_id,
            ssh_process_options=ssh_process_options,
        )
    request: dict[str, object] = {"kind": arguments.command, "args": arguments.arguments, "request_id": request_id}
    payload = b""
    if arguments.command == "run":
        request["operation"] = arguments.name
    elif arguments.command == "pipe":
        payload = sys.stdin.buffer.read(MAX_PAYLOAD + 1)
        if not payload or len(payload) > MAX_PAYLOAD:
            raise ControlFailure("stdin_payload_size_invalid")
        request["operation"] = arguments.name
        request["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    else:
        virtual = None
        if arguments.stdin_file:
            data = sys.stdin.buffer.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise ControlFailure("stdin_file_too_large")
            virtual = (arguments.stdin_file, data)
        payload, manifest = build_bundle(arguments.files, virtual)
        request["installer"] = arguments.name
        request["files"] = manifest
    starts_owned_group = inherited_owned_process_group() is None
    process: subprocess.Popen[bytes] | None = None
    writer: threading.Thread | None = None
    writer_errors: list[OSError] = []

    def write_to_ssh() -> None:
        assert process is not None
        assert process.stdin is not None
        try:
            write_request(process.stdin, request, payload)
        except BrokenPipeError:
            pass
        except OSError as error:
            writer_errors.append(error)
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    def clean_up_child() -> None:
        if process is None:
            return
        cleanup_error: BaseException | None = None
        try:
            terminate_client_process(process, owns_group=starts_owned_group)
        except BaseException as error:
            cleanup_error = error
        try:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
        except (OSError, ValueError):
            pass
        # Thread.start can itself fail.  An ident proves that the writer did
        # start (including when an interrupt landed after the real start but
        # before Thread.start returned), so only then is join both required and
        # legal.
        if writer is not None and writer.ident is not None:
            writer.join(timeout=2)
            if writer.is_alive() and cleanup_error is None:
                cleanup_error = ControlFailure("client_writer_stuck")
        if cleanup_error is not None:
            raise cleanup_error

    try:
        command = [
            "/usr/bin/ssh", "-F", arguments.ssh_config,
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            arguments.host, "request",
        ]
        if threading.current_thread() is threading.main_thread():
            deferred_signals: list[int] = []
            previous_handlers = {
                signum: signal.getsignal(signum)
                for signum in (signal.SIGINT, signal.SIGTERM)
            }

            def defer_spawn_signal(signum: int, _frame: object) -> None:
                if not deferred_signals:
                    deferred_signals.append(signum)

            for signum in previous_handlers:
                signal.signal(signum, defer_spawn_signal)
            try:
                spawned = subprocess.Popen(
                    command, stdin=subprocess.PIPE,
                    start_new_session=starts_owned_group,
                    **ssh_process_options,
                )
                # Keep deferral active through the ownership assignment.
                process = spawned
            finally:
                for signum, handler in previous_handlers.items():
                    signal.signal(signum, handler)
            if deferred_signals:
                signum = deferred_signals[0]
                handler = previous_handlers[signum]
                if callable(handler):
                    handler(signum, None)
                raise ControlFailure(f"client_interrupted_{signum}")
        else:
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE,
                start_new_session=starts_owned_group,
                **ssh_process_options,
            )
        writer = threading.Thread(target=write_to_ssh, daemon=True)
        writer.start()
        status = process.wait(timeout=arguments.timeout_seconds)
        writer.join(timeout=2)
        if starts_owned_group and process_group_exists(process.pid):
            raise ControlFailure("client_process_group_unreaped")
        if writer.is_alive():
            raise ControlFailure("client_writer_stuck")
        if writer_errors:
            raise ControlFailure("client_write_failed") from writer_errors[0]
        if status:
            print(json.dumps({
                "schema": "secure-sandbox-control-client-failure-v1",
                "request_id": request_id, "status": status,
            }, sort_keys=True), file=sys.stderr)
        return status
    except subprocess.TimeoutExpired:
        clean_up_child()
        status = 124
        print(json.dumps({
            "schema": "secure-sandbox-control-client-failure-v1",
            "request_id": request_id,
            "status": status,
            "error": "client_deadline_exceeded",
        }, sort_keys=True), file=sys.stderr)
        return status
    except BaseException as original:
        try:
            clean_up_child()
        except BaseException as cleanup_error:
            raise cleanup_error from original
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    proxy_gateway = subparsers.add_parser("proxy-gateway")
    proxy_gateway.add_argument("--port", required=True)
    client = subparsers.add_parser("client")
    client.add_argument("--ssh-config", required=True)
    client.add_argument("--timeout-seconds", type=int, default=600)
    client.add_argument("--request-id", help="reuse the printed UUID only to diagnose/reject an ambiguous prior request")
    client.add_argument("host")
    client_sub = client.add_subparsers(dest="command", required=True)
    run = client_sub.add_parser("run")
    run.add_argument("name")
    run.add_argument("arguments", nargs="*")
    pipe = client_sub.add_parser("pipe")
    pipe.add_argument("name")
    pipe.add_argument("arguments", nargs="*")
    stream = client_sub.add_parser("stream")
    stream.add_argument("name")
    stream.add_argument("arguments", nargs="*")
    deploy = client_sub.add_parser("deploy")
    deploy.add_argument("name")
    deploy.add_argument("arguments", nargs="*")
    deploy.add_argument("--file", dest="files", action="append", default=[], required=True)
    deploy.add_argument("--stdin-file")
    dispatcher = subparsers.add_parser("dispatch")
    dispatcher.add_argument("--role-file", default="/etc/secure-sandbox/control-role")
    dispatcher.add_argument("--state-root", default="/var/lib/secure-sandbox/control")
    internal = subparsers.add_parser("internal")
    internal.add_argument("operation", choices=["capture-ready", "telemetry-tail", "session-refresh-list", "lifecycle-idle", "control-receipts-archive", "memory-list", "source-integrity-latest", "rollback-approved-claude-policy", "control-self-check"])
    internal.add_argument("arguments", nargs="*")
    arguments = parser.parse_args()
    try:
        if arguments.mode == "proxy-gateway":
            return proxy_gateway_main(arguments)
        if arguments.mode == "client":
            return client_main(arguments)
        if arguments.mode == "internal":
            if os.geteuid() != 0:
                raise ControlFailure("internal_requires_root")
            if arguments.operation == "control-self-check":
                role_path = Path("/etc/secure-sandbox/control-role")
                role_stat = role_path.stat()
                if role_stat.st_uid != 0 or stat.S_IMODE(role_stat.st_mode) & 0o022:
                    raise ControlFailure("role_file_untrusted")
                role = role_path.read_text(encoding="ascii").strip()
                if role not in {"gateway", "research", "target"}:
                    raise ControlFailure("role_invalid")
                print(json.dumps(control_self_check(role), sort_keys=True))
                return 0
            if arguments.operation == "session-refresh-list":
                return subprocess.run(
                    ["/usr/local/libexec/secure-sandbox/session_registry.py", "refresh-list"],
                    check=False,
                ).returncode
            if arguments.operation == "lifecycle-idle":
                return 0 if lifecycle_idle() else 1
            if arguments.operation == "control-receipts-archive":
                print(json.dumps(archive_control_receipts(
                    Path("/var/lib/secure-sandbox/control")), sort_keys=True))
                return 0
            if arguments.operation == "memory-list":
                directory = Path("/var/lib/secure-sandbox/memory-proposals")
                paths = sorted(directory.glob("*.json"))
                if len(paths) > 1024:
                    raise ControlFailure("memory_proposal_limit_exceeded")
                for path in paths:
                    print(json.dumps(memory_proposal_metadata(path), sort_keys=True))
                return 0
            if arguments.operation == "source-integrity-latest":
                value = Path("/var/lib/secure-sandbox/policy-backups/source-integrity-latest").read_text(encoding="ascii").strip()
                if not BACKUP_ID.fullmatch(value) or not value.startswith("source-integrity-"):
                    raise ControlFailure("latest_backup_invalid")
                print(value)
                return 0
            if arguments.operation == "rollback-approved-claude-policy":
                if len(arguments.arguments) != 2 or not all(SHA256.fullmatch(value) for value in arguments.arguments):
                    raise ControlFailure("arguments_invalid")
                paths = [Path("/etc/claude-code/managed-settings.json"), Path("/usr/local/bin/research-claude")]
                for path, expected in zip(paths, arguments.arguments):
                    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                        raise ControlFailure("approved_policy_hash_mismatch")
                for path in paths:
                    path.unlink()
                return 0
            markers = [
                Path("/run/secure-sandbox/conversation-capture-ready"),
                Path("/run/secure-sandbox/artifact-capture-ready"),
            ]
            failures = [
                Path("/run/secure-sandbox/conversation-capture-fatal"),
                Path("/run/secure-sandbox/artifact-capture-fatal"),
            ]
            if not all(path.is_file() for path in markers) or any(path.exists() for path in failures):
                return 1
            return subprocess.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", "conversation-capture.service", "conversation-shipper.service", "artifact-collector.service"],
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            ).returncode
        if os.geteuid() != 0:
            raise ControlFailure("dispatcher_requires_root")
        role_path = Path(arguments.role_file)
        role_stat = role_path.stat()
        if role_stat.st_uid != 0 or stat.S_IMODE(role_stat.st_mode) & 0o022:
            raise ControlFailure("role_file_untrusted")
        role = role_path.read_text(encoding="ascii").strip()
        return dispatch(role, sys.stdin.buffer, Path(arguments.state_root))
    except (ControlFailure, OSError) as error:
        print(json.dumps({"schema": "secure-sandbox-control-error-v1", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
