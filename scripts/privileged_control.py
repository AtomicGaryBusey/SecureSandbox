#!/usr/bin/env python3
"""Host client and guest dispatcher for the SecureSandbox control plane.

The host side sends one length-prefixed JSON request followed by an optional,
bounded tar stream.  The guest side is reached only through a forced SSH
command and executes this module as root through one exact sudoers rule.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import io
import json
import os
import pwd
import re
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
    "lease-issue": (["/usr/local/libexec/secure-sandbox/run_lease.py", "issue"], _exact(2, RUN_ID, PROFILE), {"gateway"}),
    "lease-status": (["/usr/local/libexec/secure-sandbox/run_lease.py", "status"], _exact(1, RUN_ID), {"gateway"}),
    "lease-renew": (["/usr/local/libexec/secure-sandbox/run_lease.py", "renew"], _exact(2, RUN_ID, INTEGER), {"gateway"}),
    "lease-finalize": (["/usr/local/libexec/secure-sandbox/run_lease.py", "finalize"], _exact(2, RUN_ID, SAFE_NAME), {"gateway"}),
    "watchdog-arm": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "arm"], _exact(4, RUN_ID, UUID, EPOCH, UUID), {"research"}),
    "watchdog-close": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "close"], _exact(1, RUN_ID), {"research"}),
    "watchdog-commit": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "commit"], _exact(2, RUN_ID, SHA256), {"research"}),
    "watchdog-renew": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "renew"], _exact(3, RUN_ID, UUID, EPOCH), {"research"}),
    "watchdog-status": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "status"], _exact(1, RUN_ID), {"research"}),
    "watchdog-completed": (["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", "completed"], _exact(1, RUN_ID), {"research"}),
    "execution-approval-next": (["/usr/local/libexec/secure-sandbox/execution_broker.py", "approval-next"], _exact(2, RUN_ID, UUID), {"research"}),
    "session-refresh": (["/usr/local/libexec/secure-sandbox/session_registry.py", "refresh"], _none, {"research"}),
    "session-refresh-contains": (["/usr/local/libexec/secure-sandbox/session_registry.py", "refresh-contains"], _exact(1, UUID), {"research"}),
    "session-contains": (["/usr/local/libexec/secure-sandbox/session_registry.py", "contains"], _exact(1, UUID), {"research"}),
    "session-list": (["/usr/local/libexec/secure-sandbox/session_registry.py", "list"], _none, {"research"}),
    "finding-list": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "list"], _none, {"research"}),
    "finding-show": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "show"], _exact(1, UUID), {"research"}),
    "finding-disposition-status": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "disposition-status"], _exact(1, UUID), {"research"}),
    "finding-apply": (["/usr/local/libexec/secure-sandbox/finding_admin.py", "apply"], _exact(1, SAFE_NAME), {"research"}),
    "corpus-index": (["/usr/local/libexec/secure-sandbox/corpus_intelligence.py", "index"], _exact(1, UUID), {"research"}),
    "codegraph-index": (["/usr/local/libexec/secure-sandbox/codegraph_indexer.py", "index"], _exact(1, UUID), {"research"}),
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
    "source-import-stage": (["/usr/local/sbin/secure-sandbox-source-import", "stage"], _none, {"research"}),
    "execution-approval-deliver": (["/usr/local/libexec/secure-sandbox/execution_broker.py", "approval-deliver"], _none, {"research"}),
}


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


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
        if kind in {"run", "pipe"}:
            if kind == "run" and payload:
                raise ControlFailure("unexpected_payload")
            if kind == "pipe":
                digest = request.get("payload_sha256")
                if not payload or not isinstance(digest, str) or not SHA256.fullmatch(digest):
                    raise ControlFailure("payload_invalid")
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise ControlFailure("payload_digest_mismatch")
            operation = request.get("operation")
            args = request.get("args", [])
            operations = OPERATIONS if kind == "run" else PIPE_OPERATIONS
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
        if kind in {"run", "pipe"}:
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


def client_main(arguments: argparse.Namespace) -> int:
    if not 1 <= arguments.timeout_seconds <= 3600:
        raise ControlFailure("client_timeout_invalid")
    request_id = arguments.request_id or str(uuid.uuid4())
    if UUID.fullmatch(request_id) is None:
        raise ControlFailure("request_id_invalid")
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
    process = subprocess.Popen(
        ["/usr/bin/ssh", "-F", arguments.ssh_config, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", arguments.host, "request"],
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    writer_errors: list[OSError] = []

    def write_to_ssh() -> None:
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

    writer = threading.Thread(target=write_to_ssh, daemon=True)
    writer.start()
    try:
        status = process.wait(timeout=arguments.timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        time.sleep(2)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        if process.poll() is None:
            process.wait()
        writer.join(timeout=2)
        status = 124
        print(json.dumps({
            "schema": "secure-sandbox-control-client-failure-v1",
            "request_id": request_id,
            "status": status,
            "error": "client_deadline_exceeded",
        }, sort_keys=True), file=sys.stderr)
        return status
    writer.join(timeout=2)
    if writer.is_alive():
        raise ControlFailure("client_writer_stuck")
    if writer_errors:
        raise ControlFailure("client_write_failed") from writer_errors[0]
    if status:
        print(json.dumps({"schema": "secure-sandbox-control-client-failure-v1", "request_id": request_id, "status": status}, sort_keys=True), file=sys.stderr)
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
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
