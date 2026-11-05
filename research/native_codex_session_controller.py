#!/usr/bin/env python3
"""Root-only native Codex launch supervisor contract.

The Host credential bridge owns the token stream. This process never reads it:
the stream is duplicated directly onto C-launcher fd 5, consumed as one exact
binary projection frame, and closed before the admitted Codex exec. The only
credential-derived value accepted here is a SHA-256 digest used to mint one
root-owned, unlinked, read-only fd-3 permit.

Every launched process is owned by an exact transient systemd scope selected by
``native_guest_control`` during stop-bound-runs. The scope is lifetime-bound to
both ``native-harness-supervisor.service`` and an exact controller-owner watcher
scope, then independently read back through its cgroup before launch is
accepted.
"""

from __future__ import annotations

import fcntl
import hashlib
import ctypes
import json
import math
import os
import pwd
import re
import select
import signal
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from research import native_codex_policy as policy
from research import native_codex_isolation_qualification as isolation
from research import native_codex_run_journal as run_journal
from research import native_codex_runtime_driver as runtime_driver
from research import native_lifecycle_fence
from research import native_projection_isolation
from shared import (
    native_codex_projection,
    native_guest_control,
    native_stack_session,
)


STATE_ROOT = Path("/run/secure-sandbox/native-codex/session-state")
CONTROL_ROOT = Path("/run/secure-sandbox/native-codex")
AUTHORITY_PATH = CONTROL_ROOT / "launch.authority"
LOCK_PATH = CONTROL_ROOT / "launch.lock"
PERMIT_ROOT = CONTROL_ROOT / "permits"
PREPARATION_ROOT = CONTROL_ROOT / "preparations"
UI_ROOT = CONTROL_ROOT / "ui"
POLICY_ROOT = Path("/etc/secure-sandbox/native-codex-policy")
BASELINE_CONFIG = POLICY_ROOT / "config.toml"
LAUNCHER = Path("/usr/local/libexec/secure-sandbox/native-codex-launcher")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
BUSCTL = Path("/usr/bin/busctl")
CGROUP_ROOT = Path("/sys/fs/cgroup")
IDENTITY = "native-codex"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
PREPARE_REQUEST_SCHEMA = "secure-sandbox-native-codex-session-prepare-request-v1"
PREPARE_REPLY_SCHEMA = "secure-sandbox-native-codex-session-prepare-reply-v1"
PREPARE_STATE_SCHEMA = "secure-sandbox-native-codex-session-prepare-state-v1"
STOP_REQUEST_SCHEMA = "secure-sandbox-native-codex-session-stop-request-v1"
STOP_REPLY_SCHEMA = "secure-sandbox-native-codex-session-stop-reply-v1"
STATUS_REQUEST_SCHEMA = "secure-sandbox-native-codex-session-status-request-v1"
STATUS_REPLY_SCHEMA = "secure-sandbox-native-codex-session-status-reply-v1"
MAX_PREPARE_BYTES = 64 * 1024
MAX_PREPARATIONS = 4096
MAX_NATIVE_SESSION_SECONDS = 4 * 60 * 60
NATIVE_SCOPE_TASKS_MAX = 256
NATIVE_SCOPE_MEMORY_MAX_BYTES = 4 * 1024 * 1024 * 1024
NATIVE_SCOPE_MEMORY_SWAP_MAX_BYTES = 0
NATIVE_SCOPE_CPU_QUOTA_PER_SEC_USEC = 3 * 1_000_000
NATIVE_SCOPE_CPU_QUOTA_PERIOD_USEC = 100_000
OWNER_SCOPE_TASKS_MAX = 1
OWNER_SCOPE_MEMORY_MAX_BYTES = 64 * 1024 * 1024
SCOPE_TIMEOUT_STOP_USEC = 2 * 1_000_000
UI_ATTACH_SCHEMA = "secure-sandbox-native-codex-ui-attach-v1"
MAX_UI_ATTACH_BYTES = 2048
UI_ATTACH_TIMEOUT_SECONDS = 15.0


class NativeCodexSessionError(RuntimeError):
    """Stable fail-closed native Codex supervisor error."""


def _canonical(value: object) -> bytes:
    try:
        raw = policy.canonical_bytes(value)
    except policy.NativeCodexPolicyError as error:
        raise NativeCodexSessionError("native_codex_prepare_value_invalid") from error
    if len(raw) > MAX_PREPARE_BYTES:
        raise NativeCodexSessionError("native_codex_prepare_value_oversized")
    return raw


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def validate_prepare_request(value: object, *, now: int | None = None
                             ) -> dict[str, Any]:
    fields = {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "session_id", "runtime_authority", "projection_id",
        "access_token_sha256", "expires_at", "session_lease",
        "stack_sha256", "operator_request_sha256",
        "projection_ticket_issued_at", "projection_ticket_expires_at",
        "projection_ticket_sha256", "projection_authority",
        "request_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexSessionError("native_codex_prepare_fields_invalid")
    if value["schema"] != PREPARE_REQUEST_SCHEMA:
        raise NativeCodexSessionError("native_codex_prepare_schema_invalid")
    for field in ("operation_id", "session_id", "projection_id"):
        if not isinstance(value[field], str) or UUID4.fullmatch(value[field]) is None:
            raise NativeCodexSessionError(f"native_codex_prepare_{field}_invalid")
    for field in (
        "plan_sha256", "authorization_sha256", "access_token_sha256",
        "stack_sha256", "operator_request_sha256",
        "projection_ticket_sha256", "request_sha256",
    ):
        if not isinstance(value[field], str) or SHA256.fullmatch(value[field]) is None:
            raise NativeCodexSessionError(f"native_codex_prepare_{field}_invalid")
    authority = policy.require_codex_authority(value["runtime_authority"])
    if authority["session_context_binding"]["session_id"] != value["session_id"]:
        raise NativeCodexSessionError("native_codex_prepare_session_mismatch")
    observed_at = int(time.time()) if now is None else now
    try:
        session_lease = native_stack_session.validate_session_lease(
            value["session_lease"], now=observed_at, require_fresh=True)
    except native_stack_session.NativeStackSessionError as error:
        raise NativeCodexSessionError(
            "native_codex_prepare_session_lease_invalid") from error
    if (session_lease["session_id"] != value["session_id"]
            or session_lease["runtime_authority_sha256"]
               != authority["binding_sha256"]):
        raise NativeCodexSessionError(
            "native_codex_prepare_session_lease_mismatch")
    if (not isinstance(value["expires_at"], int)
            or isinstance(value["expires_at"], bool)
            or not observed_at < value["expires_at"] <= observed_at + 120
            or value["expires_at"] > session_lease["expires_at"]):
        raise NativeCodexSessionError("native_codex_prepare_expiry_invalid")
    ticket_issued = value["projection_ticket_issued_at"]
    ticket_expires = value["projection_ticket_expires_at"]
    if (not isinstance(ticket_issued, int) or isinstance(ticket_issued, bool)
            or not isinstance(ticket_expires, int)
            or isinstance(ticket_expires, bool)
            or ticket_issued < 1
            or not observed_at < ticket_expires
            or not ticket_issued < ticket_expires <= ticket_issued + 180
            or value["expires_at"] > ticket_expires):
        raise NativeCodexSessionError(
            "native_codex_prepare_projection_ticket_invalid"
        )
    try:
        projection_authority = (
            native_codex_projection.validate_projection_authority(
                value["projection_authority"],
                operation_id=value["operation_id"],
                request_sha256=value["operator_request_sha256"],
                stack_sha256=value["stack_sha256"],
                session_authority_sha256=authority["binding_sha256"],
                ticket_issued_at=ticket_issued,
                ticket_expires_at=ticket_expires, now=observed_at,
            )
        )
    except native_codex_projection.NativeCodexProjectionError as error:
        raise NativeCodexSessionError(
            "native_codex_prepare_projection_authority_invalid"
        ) from error
    expected_descriptor = policy.make_launch_descriptor(authority)
    if (projection_authority["session_id"] != value["session_id"]
            or projection_authority["launch_descriptor_sha256"]
                != expected_descriptor["descriptor_sha256"]):
        raise NativeCodexSessionError(
            "native_codex_prepare_projection_authority_mismatch"
        )
    body = {key: value[key] for key in value
            if key not in {"schema", "request_sha256"}}
    if value["request_sha256"] != _digest(body):
        raise NativeCodexSessionError("native_codex_prepare_digest_mismatch")
    return {key: value[key] for key in fields}


def validate_session_control_request(value: object, *, status: bool
                                    ) -> dict[str, Any]:
    fields = ({"schema", "operation_id", "session_id",
               "runtime_authority_sha256", "request_sha256"} if status else {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "session_id", "runtime_authority_sha256", "request_sha256",
    })
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexSessionError("native_codex_session_control_fields_invalid")
    expected = STATUS_REQUEST_SCHEMA if status else STOP_REQUEST_SCHEMA
    if value["schema"] != expected:
        raise NativeCodexSessionError("native_codex_session_control_schema_invalid")
    for field in ("operation_id", "session_id"):
        if not isinstance(value[field], str) or UUID4.fullmatch(value[field]) is None:
            raise NativeCodexSessionError(
                f"native_codex_session_control_{field}_invalid")
    for field in ({"runtime_authority_sha256", "request_sha256"} if status else {
        "plan_sha256", "authorization_sha256", "runtime_authority_sha256",
        "request_sha256",
    }):
        if not isinstance(value[field], str) or SHA256.fullmatch(value[field]) is None:
            raise NativeCodexSessionError(
                f"native_codex_session_control_{field}_invalid")
    body = {key: value[key] for key in value
            if key not in {"schema", "request_sha256"}}
    if value["request_sha256"] != _digest(body):
        raise NativeCodexSessionError(
            "native_codex_session_control_digest_mismatch")
    return value


def validate_admitted_authority(
    value: object, *, catalog_path: Path | None = None,
    runtime_loader: Callable[[str], dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Rebuild the authority from the protected catalog and harness release."""
    from research import native_provider_controller as provider

    authority = policy.require_codex_authority(value)
    native = authority["model_stack_binding"]["authority"]
    options: dict[str, object] = {}
    if catalog_path is not None:
        options["catalog_path"] = catalog_path
    stack, _catalog_sha256 = provider.load_stack(
        native["stack_sha256"], **options)
    generation = stack["harness"]["generation_id"]
    if generation is None:
        raise NativeCodexSessionError("native_codex_prepare_harness_missing")
    harness = (provider.generation_runtime(generation) if runtime_loader is None
               else runtime_loader(generation))
    context = authority["session_context_binding"]
    expected = provider.make_authority(
        stack, harness, session_id=context["session_id"],
        source_id=context["source_id"],
        source_manifest_sha256=context["source_manifest_sha256"],
        persona_sha256=context["persona_sha256"],
        tool_catalog_sha256=context["tool_catalog_sha256"],
        extension_set_sha256=context["extension_set_sha256"])
    if expected != authority:
        raise NativeCodexSessionError("native_codex_prepare_authority_mismatch")
    return authority


def _projection_observation_reply(
    operation_id: str, observation: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": native_codex_projection.PROJECTION_STATUS_REPLY_SCHEMA,
        "operation_id": operation_id,
        **observation,
    }
    return {**body, "evidence_sha256": native_codex_projection.sha256(body)}


def _preparation_root_descriptor(root: Path, *, trusted_uid: int,
                                 trusted_gid: int) -> int:
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        current = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(current.st_mode)
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeCodexSessionError("native_codex_prepare_root_untrusted")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise NativeCodexSessionError("native_codex_prepare_write_failed")
        view = view[count:]


def _read_preparation(root_descriptor: int, name: str, *, trusted_uid: int,
                      trusted_gid: int) -> dict[str, Any]:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=root_descriptor)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != trusted_uid or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= MAX_PREPARE_BYTES):
            raise NativeCodexSessionError("native_codex_prepare_record_untrusted")
        raw = os.read(descriptor, info.st_size + 1)
        if len(raw) != info.st_size or os.read(descriptor, 1):
            raise NativeCodexSessionError("native_codex_prepare_record_changed")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeCodexSessionError("native_codex_prepare_record_invalid") from error
    if not isinstance(value, dict) or raw != _canonical(value):
        raise NativeCodexSessionError("native_codex_prepare_record_invalid")
    fields = {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "session_id", "runtime_authority", "projection_id",
        "access_token_sha256", "expires_at", "session_lease",
        "stack_sha256", "operator_request_sha256",
        "projection_ticket_issued_at", "projection_ticket_expires_at",
        "projection_ticket_sha256", "projection_authority",
        "request_sha256",
        "prepare_sha256",
    }
    body = {key: value.get(key) for key in fields - {"schema", "prepare_sha256"}}
    if (set(value) != fields or value.get("schema") != PREPARE_STATE_SCHEMA
            or value.get("prepare_sha256") != _digest(body)):
        raise NativeCodexSessionError("native_codex_prepare_record_invalid")
    return value


def prepare_session(
    value: object, *, preparation_root: Path = PREPARATION_ROOT,
    lifecycle_root: Path = native_lifecycle_fence.ROOT,
    catalog_path: Path | None = None,
    runtime_loader: Callable[[str], dict[str, str]] | None = None,
    projection_observer: Callable[[object, object], dict[str, Any]] = (
        native_projection_isolation.status_observation
    ),
    trusted_uid: int = 0, trusted_gid: int = 0,
    now: int | None = None,
) -> dict[str, Any]:
    if os.geteuid() != trusted_uid:
        raise NativeCodexSessionError("native_codex_prepare_root_required")
    observed_at = int(time.time()) if now is None else now
    request = validate_prepare_request(value, now=observed_at)
    validate_admitted_authority(
        request["runtime_authority"], catalog_path=catalog_path,
        runtime_loader=runtime_loader)
    try:
        with native_lifecycle_fence.admission_open(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ):
            descriptor = policy.make_launch_descriptor(
                request["runtime_authority"]
            )
            observation = projection_observer(
                request["runtime_authority"], descriptor
            )
            try:
                matches = (
                    native_codex_projection
                    .projection_authority_matches_observation(
                        request["projection_authority"],
                        operation_id=request["operation_id"],
                        request_sha256=request["operator_request_sha256"],
                        stack_sha256=request["stack_sha256"],
                        observation=_projection_observation_reply(
                            request["operation_id"], observation
                        ),
                        authority=request["runtime_authority"],
                        now=observed_at,
                    )
                )
            except native_codex_projection.NativeCodexProjectionError as error:
                raise NativeCodexSessionError(
                    "native_codex_prepare_projection_observation_invalid"
                ) from error
            if not matches:
                raise NativeCodexSessionError(
                    "native_codex_prepare_projection_observation_changed"
                )
            root_descriptor = _preparation_root_descriptor(
                preparation_root, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            try:
                names = os.listdir(root_descriptor)
                permitted = re.compile(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\.(?:json|consumed\.json)")
                if (len(names) >= MAX_PREPARATIONS
                        or any(permitted.fullmatch(name) is None for name in names)):
                    raise NativeCodexSessionError(
                        "native_codex_prepare_retention_limit")
                state_body = {key: request[key] for key in request
                              if key != "schema"}
                state = {"schema": PREPARE_STATE_SCHEMA, **state_body,
                         "prepare_sha256": _digest(state_body)}
                raw = _canonical(state)
                name = f"{request['operation_id']}.json"
                try:
                    descriptor = os.open(
                        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                        dir_fd=root_descriptor)
                except FileExistsError:
                    observed = _read_preparation(
                        root_descriptor, name, trusted_uid=trusted_uid,
                        trusted_gid=trusted_gid)
                    if observed != state:
                        raise NativeCodexSessionError(
                            "native_codex_prepare_replay_conflict")
                else:
                    try:
                        os.fchown(descriptor, trusted_uid, trusted_gid)
                        os.fchmod(descriptor, 0o600)
                        _write_all(descriptor, raw)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    os.fsync(root_descriptor)
                    if _read_preparation(
                        root_descriptor, name, trusted_uid=trusted_uid,
                        trusted_gid=trusted_gid) != state:
                        raise NativeCodexSessionError(
                            "native_codex_prepare_readback_failed")
            finally:
                os.close(root_descriptor)
    except native_lifecycle_fence.NativeLifecycleFenceError as error:
        raise NativeCodexSessionError(str(error)) from error
    evidence = _digest({
        "operation_id": request["operation_id"],
        "prepare_sha256": state["prepare_sha256"],
        "expires_at": request["expires_at"],
        "runtime_authority_sha256": request["runtime_authority"]["binding_sha256"],
        "session_lease_sha256": request["session_lease"]["lease_sha256"],
        "session_expires_at": request["session_lease"]["expires_at"],
    })
    return {
        "schema": PREPARE_REPLY_SCHEMA,
        "operation_id": request["operation_id"],
        "prepare_sha256": state["prepare_sha256"],
        "expires_at": request["expires_at"],
        "session_lease_sha256": request["session_lease"]["lease_sha256"],
        "session_expires_at": request["session_lease"]["expires_at"],
        "evidence_sha256": evidence,
    }


def _require_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    information = path.lstat()
    if (
        not stat.S_ISDIR(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_uid != uid
        or information.st_gid != gid
        or stat.S_IMODE(information.st_mode) != mode
    ):
        raise NativeCodexSessionError("native_codex_session_directory_untrusted")


def _make_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    _require_directory(path, uid=uid, gid=gid, mode=mode)


def _copy_exact_config(
    source: Path,
    destination: Path,
    *,
    trusted_uid: int,
    source_gid: int,
    destination_gid: int,
) -> None:
    information = source.lstat()
    if (
        not stat.S_ISREG(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_nlink != 1
        or information.st_uid != trusted_uid
        or information.st_gid != source_gid
        or stat.S_IMODE(information.st_mode) != 0o444
        or not 1 <= information.st_size <= 262_144
    ):
        raise NativeCodexSessionError("native_codex_session_policy_untrusted")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    destination_fd = -1
    try:
        opened = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino) != (information.st_dev, information.st_ino):
            raise NativeCodexSessionError("native_codex_session_policy_changed")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o640,
        )
        os.fchown(destination_fd, trusted_uid, destination_gid)
        remaining = information.st_size
        digest = hashlib.sha256()
        copied = hashlib.sha256()
        while remaining:
            block = os.read(source_fd, min(65_536, remaining))
            if not block:
                raise NativeCodexSessionError("native_codex_session_policy_truncated")
            digest.update(block)
            view = memoryview(block)
            while view:
                count = os.write(destination_fd, view)
                if count <= 0:
                    raise NativeCodexSessionError("native_codex_session_policy_write_failed")
                copied.update(view[:count])
                view = view[count:]
            remaining -= len(block)
        if os.read(source_fd, 1) or digest.digest() != copied.digest():
            raise NativeCodexSessionError("native_codex_session_policy_changed")
        os.fchmod(destination_fd, 0o640)
        os.fsync(destination_fd)
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def create_session_layout(
    descriptor_value: object,
    *,
    state_root: Path = STATE_ROOT,
    baseline_config: Path = BASELINE_CONFIG,
    baseline_gid: int = 0,
    trusted_uid: int = 0,
    launcher_uid: int,
    launcher_gid: int,
    installation_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
) -> Path:
    """Create the exact fresh CODEX_HOME projection accepted by the launcher."""
    descriptor = policy.validate_launch_descriptor(descriptor_value)
    session_id = descriptor["session_id"]
    if UUID4.fullmatch(session_id) is None or launcher_uid == 0 or launcher_gid == 0:
        raise NativeCodexSessionError("native_codex_session_identity_invalid")
    _require_directory(
        state_root, uid=trusted_uid, gid=launcher_gid, mode=0o750
    )
    session = state_root / session_id
    try:
        _make_directory(
            session, uid=trusted_uid, gid=launcher_gid, mode=0o710
        )
        for name in ("home", "cache", "tmp"):
            _make_directory(
                session / name, uid=launcher_uid, gid=launcher_gid, mode=0o700
            )
        codex_home = session / "codex-home"
        _make_directory(
            codex_home, uid=trusted_uid, gid=launcher_gid, mode=0o710
        )
        _copy_exact_config(
            baseline_config,
            codex_home / "config.toml",
            trusted_uid=trusted_uid,
            source_gid=baseline_gid,
            destination_gid=launcher_gid,
        )
        _make_directory(
            codex_home / "skills", uid=trusted_uid, gid=launcher_gid, mode=0o750
        )
        for name in ("state", "logs", "tmp", ".tmp"):
            _make_directory(
                codex_home / name,
                uid=launcher_uid,
                gid=launcher_gid,
                mode=0o700,
            )
        installation_id = installation_id_factory()
        if UUID4.fullmatch(installation_id) is None:
            raise NativeCodexSessionError("native_codex_installation_id_invalid")
        installation_fd = os.open(
            codex_home / "installation_id",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.fchown(installation_fd, launcher_uid, launcher_gid)
            os.fchmod(installation_fd, 0o600)
            if os.write(installation_fd, installation_id.encode("ascii")) != 36:
                raise NativeCodexSessionError("native_codex_installation_id_write_failed")
            os.fsync(installation_fd)
        finally:
            os.close(installation_fd)
        directory = os.open(codex_home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return session
    except Exception:
        if session.exists() and not session.is_symlink():
            shutil.rmtree(session)
        raise


def claim_projection_permit(
    descriptor_value: object,
    *,
    projection_id: str,
    access_token_sha256: str,
    issued_at_unix: int,
    expires_at_unix: int,
    launcher_uid: int,
    launcher_gid: int,
    permit_root: Path = PERMIT_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> int:
    """Return the sole pathless, rewound, root-owned 0400 permit description."""
    if SHA256.fullmatch(access_token_sha256) is None:
        raise NativeCodexSessionError("native_codex_token_digest_invalid")
    _require_directory(permit_root, uid=trusted_uid, gid=trusted_gid, mode=0o700)
    permit = policy.make_projection_permit(
        descriptor_value,
        projection_id=projection_id,
        access_token_sha256=access_token_sha256,
        issued_at_unix=issued_at_unix,
        expires_at_unix=expires_at_unix,
        launcher_uid=launcher_uid,
        launcher_gid=launcher_gid,
    )
    payload = policy.projection_permit_bytes(permit)
    path = permit_root / f".{projection_id}.permit"
    writer = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
    )
    reader = -1
    try:
        os.fchown(writer, trusted_uid, trusted_gid)
        os.fchmod(writer, 0o400)
        view = memoryview(payload)
        while view:
            count = os.write(writer, view)
            if count <= 0:
                raise NativeCodexSessionError("native_codex_permit_write_failed")
            view = view[count:]
        os.fsync(writer)
        os.close(writer)
        writer = -1
        reader = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        information = os.fstat(reader)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or information.st_uid != trusted_uid
            or information.st_gid != trusted_gid
            or stat.S_IMODE(information.st_mode) != 0o400
            or information.st_size != len(payload)
        ):
            raise NativeCodexSessionError("native_codex_permit_untrusted")
        path.unlink()
        directory = os.open(permit_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        information = os.fstat(reader)
        if information.st_nlink != 0 or os.lseek(reader, 0, os.SEEK_CUR) != 0:
            raise NativeCodexSessionError("native_codex_permit_not_pathless")
        result, reader = reader, -1
        return result
    finally:
        if reader >= 0:
            os.close(reader)
        if writer >= 0:
            os.close(writer)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, 15)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, 9)
    except ProcessLookupError:
        return
    process.wait(timeout=2)


def _release_launcher_gate_before_lease_expiry(
    descriptor: int,
    receipt: runtime_driver.ProjectionTokenReceipt,
    *,
    lease_deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Release one exact launcher only while its session lease is live."""
    if (not isinstance(lease_deadline, (int, float))
            or isinstance(lease_deadline, bool)
            or not math.isfinite(lease_deadline)
            or monotonic() >= lease_deadline):
        raise NativeCodexSessionError("native_codex_run_lease_expired")
    runtime_driver.release_launcher_gate(descriptor, receipt)


def _projection_permit_expiry(
    *, issued_at: int, requested_expires_at: int | None,
    lease_expires_at: int,
) -> int:
    """Bound the C launch permit to the shorter projection/session authority."""
    if (not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or issued_at < 1
            or not isinstance(lease_expires_at, int)
            or isinstance(lease_expires_at, bool)
            or lease_expires_at <= issued_at
            or (requested_expires_at is not None and (
                not isinstance(requested_expires_at, int)
                or isinstance(requested_expires_at, bool)
                or requested_expires_at <= issued_at))):
        raise NativeCodexSessionError("native_codex_run_lease_expired")
    requested = (
        issued_at + 60
        if requested_expires_at is None else requested_expires_at)
    expires = min(requested, lease_expires_at)
    if expires <= issued_at:
        raise NativeCodexSessionError("native_codex_run_lease_expired")
    return expires


def _open_scope_cgroup(
    cgroup_root: Path,
    scope_cgroup: str,
    *,
    scope_unit: str,
    trusted_uid: int,
) -> int:
    components = Path(scope_cgroup).parts if isinstance(
        scope_cgroup, str) else ()
    canonical = ("/" + "/".join(components[1:])
                 if components and components[0] == "/" else "")
    if (not isinstance(scope_cgroup, str) or not scope_cgroup.startswith("/")
            or scope_cgroup != canonical or ".." in components
            or Path(scope_cgroup).name != scope_unit
            or re.fullmatch(
                r"secure-sandbox-native-run-[0-9a-f]{32}\.scope",
                scope_unit) is None):
        raise NativeCodexSessionError(
            "native_codex_ready_cgroup_invalid")
    root = os.open(
        cgroup_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    current = root
    try:
        root_info = os.fstat(root)
        root_path = cgroup_root.lstat()
        if ((root_info.st_dev, root_info.st_ino)
                != (root_path.st_dev, root_path.st_ino)
                or root_info.st_uid != trusted_uid):
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_invalid")
        for component in Path(scope_cgroup).parts[1:]:
            following = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current)
            following_info = os.fstat(following)
            if (not stat.S_ISDIR(following_info.st_mode)
                    or following_info.st_uid != trusted_uid):
                os.close(following)
                raise NativeCodexSessionError(
                    "native_codex_ready_cgroup_invalid")
            if current != root:
                os.close(current)
            current = following
        info = os.fstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != trusted_uid:
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_invalid")
        result, current = current, -1
        return result
    except Exception:
        raise
    finally:
        if current >= 0 and current != root:
            os.close(current)
        os.close(root)


def _read_cgroup_control(
    scope: int, name: str, *, maximum: int = 16 * 1024,
) -> str:
    if name not in {
            "cgroup.events", "cgroup.freeze", "cgroup.procs", "cpu.max",
            "memory.max", "memory.swap.max", "pids.max"}:
        raise NativeCodexSessionError(
            "native_codex_ready_cgroup_control_invalid")
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=scope)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_control_invalid")
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if not raw or len(raw) > maximum or not raw.endswith(b"\n"):
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_readback_invalid")
        return bytes(raw).decode("ascii")
    except UnicodeError as error:
        raise NativeCodexSessionError(
            "native_codex_ready_cgroup_readback_invalid") from error
    finally:
        os.close(descriptor)


def _write_cgroup_freeze(scope: int, frozen: bool) -> None:
    descriptor = os.open(
        "cgroup.freeze", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=scope)
    try:
        info = os.fstat(descriptor)
        raw = b"1\n" if frozen else b"0\n"
        if (not stat.S_ISREG(info.st_mode)
                or os.write(descriptor, raw) != len(raw)):
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_freeze_failed")
    finally:
        os.close(descriptor)


def _cgroup_events(scope: int) -> dict[str, int]:
    raw = _read_cgroup_control(scope, "cgroup.events")
    match = re.fullmatch(r"populated ([01])\nfrozen ([01])\n", raw)
    if match is None:
        raise NativeCodexSessionError(
            "native_codex_ready_cgroup_events_invalid")
    return {"populated": int(match.group(1)), "frozen": int(match.group(2))}


def _cgroup_freeze_state(scope: int) -> int:
    raw = _read_cgroup_control(scope, "cgroup.freeze")
    if raw not in {"0\n", "1\n"}:
        raise NativeCodexSessionError(
            "native_codex_ready_cgroup_freeze_invalid")
    return int(raw[0])


def _scope_member_snapshot(
    scope: int,
    *,
    launcher_uid: int,
    proc_root: Path,
) -> tuple[tuple[int, int], ...]:
    lines = _read_cgroup_control(scope, "cgroup.procs").splitlines()
    try:
        members = [int(line) for line in lines]
    except ValueError as error:
        raise NativeCodexSessionError(
            "native_codex_ready_cgroup_members_invalid") from error
    if (not members or len(members) > 64 or len(set(members)) != len(members)
            or any(pid <= 1 or str(pid) != line for pid, line in zip(
                members, lines, strict=True))):
        raise NativeCodexSessionError(
            "native_codex_ready_cgroup_members_invalid")
    snapshot: list[tuple[int, int]] = []
    for pid in sorted(members):
        try:
            status = (proc_root / str(pid) / "status").read_text(
                encoding="ascii")
            matches = [line for line in status.splitlines()
                       if line.startswith("Uid:")]
            values = matches[0].split()[1:] if len(matches) == 1 else []
            if (len(values) != 4
                    or any(int(value) != launcher_uid for value in values)):
                raise NativeCodexSessionError(
                    "native_codex_ready_cgroup_member_uid_invalid")
            start = run_journal.process_start_time(pid, proc_root=proc_root)
        except NativeCodexSessionError:
            raise
        except (OSError, ValueError, UnicodeError,
                run_journal.NativeCodexRunJournalError) as error:
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_members_invalid") from error
        snapshot.append((pid, start))
    return tuple(snapshot)


def _quiesce_scope_for_ready(
    process_id: int,
    process_start_time_ticks: int,
    *,
    scope_cgroup: str,
    scope_unit: str,
    launcher_uid: int,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    trusted_uid: int = 0,
    timeout_seconds: float = 1.0,
    freeze_writer: Callable[[int, bool], None] = _write_cgroup_freeze,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> runtime_driver.QualificationQuiescence:
    """Freeze and stably read back every member of the exact transient scope."""
    if (not isinstance(process_id, int) or isinstance(process_id, bool)
            or process_id <= 1
            or not isinstance(process_start_time_ticks, int)
            or isinstance(process_start_time_ticks, bool)
            or process_start_time_ticks <= 0
            or not isinstance(launcher_uid, int) or launcher_uid <= 0
            or not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 5):
        raise NativeCodexSessionError(
            "native_codex_ready_quiescence_invalid")
    scope = _open_scope_cgroup(
        cgroup_root, scope_cgroup, scope_unit=scope_unit,
        trusted_uid=trusted_uid)
    try:
        before = _scope_member_snapshot(
            scope, launcher_uid=launcher_uid, proc_root=proc_root)
        if (process_id, process_start_time_ticks) not in before:
            raise NativeCodexSessionError(
                "native_codex_ready_process_changed")
        freeze_writer(scope, True)
        deadline = monotonic() + timeout_seconds
        while True:
            freeze_state = _cgroup_freeze_state(scope)
            events = _cgroup_events(scope)
            if (freeze_state == 1 and events == {
                    "populated": 1, "frozen": 1}):
                break
            if monotonic() >= deadline:
                raise NativeCodexSessionError(
                    "native_codex_ready_cgroup_freeze_incomplete")
            sleeper(0.01)
        first = _scope_member_snapshot(
            scope, launcher_uid=launcher_uid, proc_root=proc_root)
        if (_cgroup_freeze_state(scope) != 1
                or _cgroup_events(scope) != {
                    "populated": 1, "frozen": 1}
                or (process_id, process_start_time_ticks) not in first):
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_freeze_incomplete")
        second = _scope_member_snapshot(
            scope, launcher_uid=launcher_uid, proc_root=proc_root)
        if (first != second
                or (process_id, process_start_time_ticks) not in second):
            raise NativeCodexSessionError(
                "native_codex_ready_cgroup_members_changed")
        held_scope = scope
        closed = False

        def close_scope() -> None:
            nonlocal closed
            if closed:
                raise NativeCodexSessionError(
                    "native_codex_ready_quiescence_reused")
            closed = True
            os.close(held_scope)

        def abandon() -> None:
            close_scope()

        def resume(admission_deadline: float) -> None:
            if closed:
                raise NativeCodexSessionError(
                    "native_codex_ready_quiescence_reused")
            thaw_attempted = False
            try:
                if (not isinstance(admission_deadline, (int, float))
                        or isinstance(admission_deadline, bool)
                        or not math.isfinite(admission_deadline)
                        or monotonic() >= admission_deadline):
                    raise NativeCodexSessionError(
                        "native_codex_ready_admission_expired")
                if (_cgroup_freeze_state(held_scope) != 1
                        or _cgroup_events(held_scope) != {
                            "populated": 1, "frozen": 1}
                        or _scope_member_snapshot(
                            held_scope, launcher_uid=launcher_uid,
                            proc_root=proc_root) != second):
                    raise NativeCodexSessionError(
                        "native_codex_ready_cgroup_thaw_ambiguous")
                if monotonic() >= admission_deadline:
                    raise NativeCodexSessionError(
                        "native_codex_ready_admission_expired")
                thaw_attempted = True
                freeze_writer(held_scope, False)
                thaw_deadline = min(
                    monotonic() + timeout_seconds, admission_deadline)
                while True:
                    freeze_state = _cgroup_freeze_state(held_scope)
                    events = _cgroup_events(held_scope)
                    if (freeze_state == 0 and events == {
                            "populated": 1, "frozen": 0}):
                        if monotonic() >= admission_deadline:
                            raise NativeCodexSessionError(
                                "native_codex_ready_admission_expired")
                        return
                    if monotonic() >= thaw_deadline:
                        if monotonic() >= admission_deadline:
                            raise NativeCodexSessionError(
                                "native_codex_ready_admission_expired")
                        raise NativeCodexSessionError(
                            "native_codex_ready_cgroup_thaw_ambiguous")
                    sleeper(0.01)
            except Exception as error:
                if thaw_attempted:
                    try:
                        freeze_writer(held_scope, True)
                        refreeze_deadline = monotonic() + timeout_seconds
                        while True:
                            if (_cgroup_freeze_state(held_scope) == 1
                                    and _cgroup_events(
                                        held_scope).get("frozen") == 1):
                                break
                            if monotonic() >= refreeze_deadline:
                                raise NativeCodexSessionError(
                                    "native_codex_ready_cgroup_refreeze_failed")
                            sleeper(0.01)
                    except Exception as refreeze_error:
                        raise NativeCodexSessionError(
                            "native_codex_ready_cgroup_refreeze_failed"
                        ) from refreeze_error
                raise error
            finally:
                close_scope()

        result = runtime_driver.QualificationQuiescence(
            resume=resume, abandon=abandon)
        scope = -1
        return result
    except Exception:
        # Once requested, freezing is never reversed on an admission failure.
        # The outer controller tears the exact scope down while it remains
        # fail-closed.
        raise
    finally:
        if scope >= 0:
            os.close(scope)


def _systemd_duration_usec(value: str) -> int:
    """Parse the bounded duration rendering emitted by ``systemctl show``."""
    if value.isdigit():
        return int(value)
    units = {
        "us": 1,
        "ms": 1_000,
        "s": 1_000_000,
        "min": 60 * 1_000_000,
        "h": 60 * 60 * 1_000_000,
        "d": 24 * 60 * 60 * 1_000_000,
    }
    total = 0
    tokens = value.split()
    if not tokens:
        raise ValueError
    for token in tokens:
        match = re.fullmatch(
            r"([0-9]+)(?:\.([0-9]{1,6}))?(us|ms|s|min|h|d)", token)
        if match is None:
            raise ValueError
        multiplier = units[match.group(3)]
        total += int(match.group(1)) * multiplier
        if match.group(2) is not None:
            denominator = 10 ** len(match.group(2))
            numerator = int(match.group(2)) * multiplier
            if numerator % denominator:
                raise ValueError
            total += numerator // denominator
    if total <= 0:
        raise ValueError
    return total


def _scope_show_fields(
    unit: str,
    *,
    properties: set[str],
    systemctl: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, str] | None:
    try:
        result = runner(
            [str(systemctl), "show", unit, "--all",
             "--property=" + ",".join(sorted(properties))],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=2,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or len(result.stdout) > 16 * 1024:
        return None
    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            return None
        name, content = line.split("=", 1)
        if name in fields:
            return None
        fields[name] = content
    return fields if set(fields) == properties else None


def _canonical_scope_cgroup(unit: str, value: str) -> str | None:
    parts = Path(value).parts
    canonical = ("/" + "/".join(parts[1:])
                 if parts and parts[0] == "/" else "")
    if (not value.startswith("/") or value != canonical or ".." in parts
            or not value.endswith("/" + unit)):
        return None
    return value


def controller_owner_scope_unit(run_unit: str) -> str:
    match = re.fullmatch(
        r"secure-sandbox-native-run-([0-9a-f]{32})\.scope", run_unit)
    if match is None:
        raise NativeCodexSessionError("native_codex_scope_name_invalid")
    return f"secure-sandbox-native-owner-{match.group(1)}.scope"


def _scope_member_ids(
    pid: int, *, proc_root: Path,
) -> tuple[int, int] | None:
    try:
        status = (proc_root / str(pid) / "status").read_text(encoding="ascii")
        values: dict[str, list[str]] = {}
        for label in ("Uid:", "Gid:"):
            matches = [line for line in status.splitlines()
                       if line.startswith(label)]
            values[label] = (
                matches[0].split()[1:] if len(matches) == 1 else [])
        if (any(len(items) != 4 or len(set(items)) != 1
                for items in values.values())):
            return None
        return int(values["Uid:"][0]), int(values["Gid:"][0])
    except (OSError, ValueError, UnicodeError):
        return None


def verify_controller_owner_scope(
    unit: str,
    *,
    watcher_pid: int,
    watcher_start_time_ticks: int,
    trusted_uid: int,
    trusted_gid: int,
    expected_runtime_max_usec: int,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    deadline_seconds: float = 5.0,
) -> dict[str, object]:
    """Prove one exact root controller owns a fresh transient scope."""
    if (re.fullmatch(
            r"secure-sandbox-native-owner-[0-9a-f]{32}\.scope", unit) is None
            or not isinstance(watcher_pid, int) or watcher_pid <= 1
            or not isinstance(watcher_start_time_ticks, int)
            or watcher_start_time_ticks <= 0
            or not isinstance(trusted_uid, int) or trusted_uid < 0
            or not isinstance(trusted_gid, int) or trusted_gid < 0
            or not isinstance(expected_runtime_max_usec, int)
            or isinstance(expected_runtime_max_usec, bool)
            or not 1 <= expected_runtime_max_usec
               <= MAX_NATIVE_SESSION_SECONDS * 1_000_000):
        raise NativeCodexSessionError("native_codex_owner_scope_request_invalid")
    properties = {
        "LoadState", "ActiveState", "SubState", "BindsTo", "After",
        "PartOf", "ControlGroup", "RuntimeMaxUSec", "KillMode",
        "SendSIGKILL", "Delegate", "CollectMode", "Transient",
        "FragmentPath", "TasksMax", "MemoryMax", "TimeoutStopUSec",
    }
    dependency = "native-harness-supervisor.service"
    deadline = time.monotonic() + deadline_seconds
    last_error = "native_codex_owner_scope_unavailable"
    while time.monotonic() < deadline:
        fields = _scope_show_fields(
            unit, properties=properties, systemctl=systemctl, runner=runner)
        if fields is None:
            time.sleep(0.05)
            continue
        if (fields["LoadState"] != "loaded"
                or fields["ActiveState"] != "active"
                or fields["SubState"] != "running"
                or set(fields["BindsTo"].split()) != {dependency}
                or dependency not in fields["After"].split()
                or set(fields["PartOf"].split()) != {dependency}
                or fields["KillMode"] != "control-group"
                or fields["SendSIGKILL"] != "yes"
                or fields["Delegate"] != "no"
                or fields["CollectMode"] != "inactive-or-failed"
                or fields["Transient"] != "yes"
                or fields["FragmentPath"]
                   != f"/run/systemd/transient/{unit}"
                or fields["TasksMax"] != str(OWNER_SCOPE_TASKS_MAX)
                or fields["MemoryMax"] != str(
                    OWNER_SCOPE_MEMORY_MAX_BYTES)):
            last_error = "native_codex_owner_scope_identity_invalid"
            time.sleep(0.05)
            continue
        try:
            runtime_max_usec = _systemd_duration_usec(
                fields["RuntimeMaxUSec"])
            timeout_stop_usec = _systemd_duration_usec(
                fields["TimeoutStopUSec"])
        except ValueError:
            runtime_max_usec = timeout_stop_usec = -1
        if (runtime_max_usec != expected_runtime_max_usec
                or timeout_stop_usec != SCOPE_TIMEOUT_STOP_USEC):
            last_error = "native_codex_owner_scope_runtime_invalid"
            time.sleep(0.05)
            continue
        cgroup = _canonical_scope_cgroup(unit, fields["ControlGroup"])
        if cgroup is None:
            last_error = "native_codex_owner_scope_cgroup_invalid"
            time.sleep(0.05)
            continue
        snapshots: list[tuple[list[int], int, tuple[int, int] | None]] = []
        for _attempt in range(2):
            try:
                members = (
                    cgroup_root / cgroup.lstrip("/") / "cgroup.procs"
                ).read_text(encoding="ascii").splitlines()
                pids = [int(value) for value in members]
                observed_start = run_journal.process_start_time(
                    watcher_pid, proc_root=proc_root)
                ids = _scope_member_ids(watcher_pid, proc_root=proc_root)
            except (OSError, ValueError, UnicodeError,
                    run_journal.NativeCodexRunJournalError):
                pids, observed_start, ids = [], -1, None
            snapshots.append((pids, observed_start, ids))
            time.sleep(0.01)
        expected = ([watcher_pid], watcher_start_time_ticks,
                    (trusted_uid, trusted_gid))
        if snapshots != [expected, expected]:
            last_error = "native_codex_owner_scope_process_invalid"
            time.sleep(0.05)
            continue
        return {"unit": unit, "cgroup": cgroup,
                "watcher_pid": watcher_pid,
                "watcher_start_time_ticks": watcher_start_time_ticks}
    raise NativeCodexSessionError(last_error)


def verify_transient_scope(
    unit: str,
    *,
    owner_unit: str,
    launcher_uid: int,
    launcher_gid: int,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    deadline_seconds: float = 5.0,
    expected_runtime_max_usec: int | None = None,
    expected_tasks_max: int = NATIVE_SCOPE_TASKS_MAX,
    expected_memory_max_bytes: int = NATIVE_SCOPE_MEMORY_MAX_BYTES,
    expected_memory_swap_max_bytes: int = (
        NATIVE_SCOPE_MEMORY_SWAP_MAX_BYTES),
    expected_cpu_quota_per_sec_usec: int = (
        NATIVE_SCOPE_CPU_QUOTA_PER_SEC_USEC),
    expected_cpu_quota_period_usec: int = (
        NATIVE_SCOPE_CPU_QUOTA_PERIOD_USEC),
) -> dict[str, object]:
    """Require exact dependencies and launcher UID for every cgroup member."""
    if (re.fullmatch(r"secure-sandbox-native-run-[0-9a-f]{32}\.scope", unit) is None
            or re.fullmatch(
                r"secure-sandbox-native-owner-[0-9a-f]{32}\.scope",
                owner_unit) is None):
        raise NativeCodexSessionError("native_codex_scope_name_invalid")
    if (expected_runtime_max_usec is not None
            and (not isinstance(expected_runtime_max_usec, int)
                 or isinstance(expected_runtime_max_usec, bool)
                 or not 1 <= expected_runtime_max_usec
                    <= MAX_NATIVE_SESSION_SECONDS * 1_000_000)):
        raise NativeCodexSessionError("native_codex_scope_runtime_invalid")
    if (not isinstance(expected_tasks_max, int)
            or isinstance(expected_tasks_max, bool)
            or expected_tasks_max < 1
            or not isinstance(expected_memory_max_bytes, int)
            or isinstance(expected_memory_max_bytes, bool)
            or expected_memory_max_bytes < 1
            or not isinstance(expected_memory_swap_max_bytes, int)
            or isinstance(expected_memory_swap_max_bytes, bool)
            or expected_memory_swap_max_bytes < 0
            or not isinstance(expected_cpu_quota_per_sec_usec, int)
            or isinstance(expected_cpu_quota_per_sec_usec, bool)
            or expected_cpu_quota_per_sec_usec < 1
            or not isinstance(expected_cpu_quota_period_usec, int)
            or isinstance(expected_cpu_quota_period_usec, bool)
            or not 1_000 <= expected_cpu_quota_period_usec <= 1_000_000
            or (expected_cpu_quota_per_sec_usec
                * expected_cpu_quota_period_usec) % 1_000_000 != 0):
        raise NativeCodexSessionError("native_codex_scope_resource_invalid")
    properties = {
        "LoadState", "ActiveState", "SubState", "BindsTo", "After",
        "PartOf", "ControlGroup", "RuntimeMaxUSec", "KillMode",
        "KillSignal", "SendSIGKILL", "Delegate", "CollectMode", "Transient",
        "FragmentPath", "TasksMax", "MemoryMax", "CPUQuotaPerSecUSec",
        "CPUQuotaPeriodUSec", "MemorySwapMax", "TimeoutStopUSec",
    }
    deadline = time.monotonic() + deadline_seconds
    last_error = "native_codex_scope_unavailable"
    while time.monotonic() < deadline:
        fields = _scope_show_fields(
            unit, properties=properties, systemctl=systemctl, runner=runner)
        if fields is None:
            time.sleep(0.05)
            continue
        dependencies = {"native-harness-supervisor.service", owner_unit}
        if (fields["LoadState"] != "loaded"
                or fields["ActiveState"] != "active"
                or fields["SubState"] != "running"
                or set(fields["BindsTo"].split()) != dependencies
                or not dependencies.issubset(fields["After"].split())
                or set(fields["PartOf"].split()) != dependencies
                or fields["KillMode"] != "control-group"
                or fields["KillSignal"] != str(signal.SIGKILL)
                or fields["SendSIGKILL"] != "yes"
                or fields["Delegate"] != "no"
                or fields["CollectMode"] != "inactive-or-failed"
                or fields["Transient"] != "yes"
                or fields["FragmentPath"]
                   != f"/run/systemd/transient/{unit}"):
            last_error = "native_codex_scope_dependency_invalid"
            time.sleep(0.05)
            continue
        if expected_runtime_max_usec is not None:
            try:
                observed_runtime_max_usec = _systemd_duration_usec(
                    fields["RuntimeMaxUSec"])
                observed_timeout_stop_usec = _systemd_duration_usec(
                    fields["TimeoutStopUSec"])
            except ValueError:
                observed_runtime_max_usec = observed_timeout_stop_usec = -1
            if (observed_runtime_max_usec != expected_runtime_max_usec
                    or observed_timeout_stop_usec
                       != SCOPE_TIMEOUT_STOP_USEC):
                last_error = "native_codex_scope_runtime_invalid"
                time.sleep(0.05)
                continue
        try:
            tasks_max = int(fields["TasksMax"])
            memory_max = int(fields["MemoryMax"])
            memory_swap_max = int(fields["MemorySwapMax"])
            cpu_quota = _systemd_duration_usec(fields["CPUQuotaPerSecUSec"])
            cpu_period = _systemd_duration_usec(fields["CPUQuotaPeriodUSec"])
        except ValueError:
            tasks_max = memory_max = memory_swap_max = -1
            cpu_quota = cpu_period = -1
        if (tasks_max != expected_tasks_max
                or memory_max != expected_memory_max_bytes
                or memory_swap_max != expected_memory_swap_max_bytes
                or cpu_quota != expected_cpu_quota_per_sec_usec
                or cpu_period != expected_cpu_quota_period_usec):
            last_error = "native_codex_scope_resource_invalid"
            time.sleep(0.05)
            continue
        cgroup = _canonical_scope_cgroup(unit, fields["ControlGroup"])
        if cgroup is None:
            last_error = "native_codex_scope_cgroup_invalid"
            time.sleep(0.05)
            continue
        scope_descriptor = -1
        try:
            scope_descriptor = _open_scope_cgroup(
                cgroup_root, cgroup, scope_unit=unit,
                trusted_uid=os.geteuid())
            quota = (
                expected_cpu_quota_per_sec_usec
                * expected_cpu_quota_period_usec // 1_000_000)
            kernel_limits = {
                "memory.max": f"{expected_memory_max_bytes}\n",
                "memory.swap.max": f"{expected_memory_swap_max_bytes}\n",
                "pids.max": f"{expected_tasks_max}\n",
                "cpu.max": f"{quota} {expected_cpu_quota_period_usec}\n",
            }
            for name, expected in kernel_limits.items():
                if _read_cgroup_control(scope_descriptor, name) != expected:
                    raise NativeCodexSessionError(
                        "native_codex_scope_kernel_resource_invalid")
        except (OSError, NativeCodexSessionError):
            last_error = "native_codex_scope_kernel_resource_invalid"
            time.sleep(0.05)
            continue
        finally:
            if scope_descriptor >= 0:
                os.close(scope_descriptor)
        try:
            pids = [int(item) for item in (
                cgroup_root / cgroup.lstrip("/") / "cgroup.procs"
            ).read_text(encoding="ascii").splitlines()]
        except (OSError, ValueError, UnicodeError):
            last_error = "native_codex_scope_process_readback_failed"
            time.sleep(0.05)
            continue
        if not pids or len(pids) > 64:
            last_error = "native_codex_scope_process_count_invalid"
            time.sleep(0.05)
            continue
        accepted = True
        for pid in pids:
            try:
                ids = _scope_member_ids(pid, proc_root=proc_root)
                if ids != (launcher_uid, launcher_gid):
                    accepted = False
                    break
            except (OSError, ValueError, UnicodeError):
                accepted = False
                break
        if accepted:
            return {"unit": unit, "cgroup": cgroup,
                    "process_count": len(pids)}
        last_error = "native_codex_scope_uid_invalid"
        time.sleep(0.05)
    raise NativeCodexSessionError(last_error)


def start_controller_owner_scope(
    unit: str,
    pid: int,
    *,
    runtime_max_usec: int,
    busctl: Path = BUSCTL,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    """Move one stopped root owner watcher into its lifetime scope."""
    if (re.fullmatch(
            r"secure-sandbox-native-owner-[0-9a-f]{32}\.scope", unit) is None
            or not isinstance(pid, int) or pid <= 1
            or not isinstance(runtime_max_usec, int)
            or isinstance(runtime_max_usec, bool)
            or not 1 <= runtime_max_usec
               <= MAX_NATIVE_SESSION_SECONDS * 1_000_000):
        raise NativeCodexSessionError("native_codex_owner_scope_request_invalid")
    dependency = "native-harness-supervisor.service"
    command = [
        str(busctl), "--system", "--quiet", "--timeout=5s", "call",
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartTransientUnit",
        "ssa(sv)a(sa(sv))", unit, "fail", "13",
        "PIDs", "au", "1", str(pid),
        "Description", "s", "SecureSandbox native controller owner watcher",
        "BindsTo", "as", "1", dependency,
        "After", "as", "1", dependency,
        "PartOf", "as", "1", dependency,
        "KillMode", "s", "control-group",
        "SendSIGKILL", "b", "true",
        "Delegate", "b", "false",
        "CollectMode", "s", "inactive-or-failed",
        "RuntimeMaxUSec", "t", str(runtime_max_usec),
        "TimeoutStopUSec", "t", str(SCOPE_TIMEOUT_STOP_USEC),
        "TasksMax", "t", str(OWNER_SCOPE_TASKS_MAX),
        "MemoryMax", "t", str(OWNER_SCOPE_MEMORY_MAX_BYTES),
        "0",
    ]
    try:
        result = runner(
            command, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeCodexSessionError(
            "native_codex_owner_scope_create_failed") from error
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise NativeCodexSessionError("native_codex_owner_scope_create_failed")


def start_transient_scope(
    unit: str,
    pid: int,
    *,
    owner_unit: str,
    runtime_max_usec: int,
    busctl: Path = BUSCTL,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    """Atomically attach one already-stopped process to a transient scope."""
    if (re.fullmatch(r"secure-sandbox-native-run-[0-9a-f]{32}\.scope", unit) is None
            or re.fullmatch(
                r"secure-sandbox-native-owner-[0-9a-f]{32}\.scope",
                owner_unit) is None
            or not isinstance(pid, int) or pid <= 1
            or not isinstance(runtime_max_usec, int)
            or isinstance(runtime_max_usec, bool)
            or not 1 <= runtime_max_usec <= MAX_NATIVE_SESSION_SECONDS * 1_000_000):
        raise NativeCodexSessionError("native_codex_scope_request_invalid")
    dependencies = ["native-harness-supervisor.service", owner_unit]
    command = [
        str(busctl), "--system", "--quiet", "--timeout=5s", "call",
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartTransientUnit",
        "ssa(sv)a(sa(sv))", unit, "fail", "17",
        "PIDs", "au", "1", str(pid),
        "Description", "s", "SecureSandbox native vendor run",
        "BindsTo", "as", "2", *dependencies,
        "After", "as", "2", *dependencies,
        "PartOf", "as", "2", *dependencies,
        "KillMode", "s", "control-group",
        "KillSignal", "i", str(signal.SIGKILL),
        "SendSIGKILL", "b", "true",
        "Delegate", "b", "false",
        "CollectMode", "s", "inactive-or-failed",
        "RuntimeMaxUSec", "t", str(runtime_max_usec),
        "TimeoutStopUSec", "t", str(SCOPE_TIMEOUT_STOP_USEC),
        "TasksMax", "t", str(NATIVE_SCOPE_TASKS_MAX),
        "MemoryMax", "t", str(NATIVE_SCOPE_MEMORY_MAX_BYTES),
        "MemorySwapMax", "t", str(NATIVE_SCOPE_MEMORY_SWAP_MAX_BYTES),
        "CPUQuotaPerSecUSec", "t", str(
            NATIVE_SCOPE_CPU_QUOTA_PER_SEC_USEC),
        "CPUQuotaPeriodUSec", "t", str(
            NATIVE_SCOPE_CPU_QUOTA_PERIOD_USEC),
        "0",
    ]
    try:
        result = runner(
            command, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeCodexSessionError(
            "native_codex_scope_create_failed") from error
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise NativeCodexSessionError("native_codex_scope_create_failed")


def _child_hardening() -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, 9, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG, SIGKILL
            raise OSError(ctypes.get_errno(), "prctl")


def _arm_vendor_parent_death_signal(
    expected_parent_pid: int,
    *,
    hardener: Callable[[], None] = _child_hardening,
    parent_reader: Callable[[], int] = os.getppid,
) -> None:
    """Arm SIGKILL and close the pre-prctl parent-death race."""
    if expected_parent_pid <= 1:
        raise NativeCodexSessionError(
            "native_codex_vendor_parent_invalid")
    hardener()
    if parent_reader() != expected_parent_pid:
        raise NativeCodexSessionError(
            "native_codex_vendor_parent_changed")


class ControllerOwnerCustody:
    """Private custody for the exact watcher backing one owner scope."""

    __slots__ = (
        "unit", "watcher_pid", "watcher_start_time_ticks",
        "runtime_max_usec", "cgroup",
    )

    def __init__(
        self, *, unit: str, watcher_pid: int,
        watcher_start_time_ticks: int, runtime_max_usec: int, cgroup: str,
    ) -> None:
        self.unit = unit
        self.watcher_pid = watcher_pid
        self.watcher_start_time_ticks = watcher_start_time_ticks
        self.runtime_max_usec = runtime_max_usec
        self.cgroup = cgroup


def _owner_watcher_main(
    parent_pidfd: int,
    expected_parent_pid: int,
    *,
    hardener: Callable[[], None] = _child_hardening,
    parent_reader: Callable[[], int] = os.getppid,
    fd_duplicator: Callable[[int, int], int] = fcntl.fcntl,
    descriptor_duplicator: Callable[[int, int], int] = os.dup2,
    inheritable_setter: Callable[[int, bool], None] = os.set_inheritable,
    range_closer: Callable[[int, int], None] = os.closerange,
    signaler: Callable[[int, int], None] = os.kill,
    poll_factory: Callable[[], Any] = select.poll,
    exit_process: Callable[[int], Any] = os._exit,
) -> None:
    """Become a descriptor-minimal watcher, or exit before admission."""
    status = 126
    try:
        hardener()
        # PR_SET_PDEATHSIG does not report a parent death that happened before
        # prctl. This read closes that race without trusting a numeric PID later.
        if parent_reader() != expected_parent_pid:
            raise NativeCodexSessionError(
                "native_codex_owner_watcher_parent_changed")
        held = fd_duplicator(
            parent_pidfd, fcntl.F_DUPFD_CLOEXEC, 0)
        descriptor_duplicator(held, 0)
        inheritable_setter(0, False)
        maximum = os.sysconf("SC_OPEN_MAX")
        range_closer(1, maximum if maximum > 1 else 1024)
        signaler(os.getpid(), signal.SIGSTOP)
        poller = poll_factory()
        poller.register(0, select.POLLIN | select.POLLHUP | select.POLLERR)
        if not poller.poll():
            raise NativeCodexSessionError(
                "native_codex_owner_watcher_poll_failed")
        status = 0
    except BaseException:
        pass
    exit_process(status)


def _terminate_owner_watcher(
    watcher_pid: int,
    *,
    waitpid: Callable[[int, int], tuple[int, int]] = os.waitpid,
    kill: Callable[[int, int], None] = os.kill,
) -> None:
    if watcher_pid <= 1:
        return
    try:
        waited, _status = waitpid(watcher_pid, os.WNOHANG)
    except ChildProcessError:
        return
    if waited == watcher_pid:
        return
    if waited != 0:
        raise NativeCodexSessionError(
            "native_codex_owner_watcher_reap_ambiguous")
    try:
        kill(watcher_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        waited, _status = waitpid(watcher_pid, 0)
    except ChildProcessError:
        return
    if waited != watcher_pid:
        raise NativeCodexSessionError(
            "native_codex_owner_watcher_reap_ambiguous")


def spawn_controller_owner_watcher(
    *,
    proc_root: Path = Path("/proc"),
    pidfd_opener: Callable[[int, int], int] | None = None,
    fork: Callable[[], int] = os.fork,
    waitpid: Callable[[int, int], tuple[int, int]] = os.waitpid,
) -> tuple[int, int]:
    """Fork one stopped root watcher polling a private parent pidfd."""
    parent_pid = os.getpid()
    if pidfd_opener is None:
        pidfd_opener = getattr(os, "pidfd_open", None)
    if pidfd_opener is None:
        raise NativeCodexSessionError(
            "native_codex_owner_watcher_pidfd_unavailable")
    parent_pidfd = pidfd_opener(parent_pid, 0)
    if parent_pidfd < 0:
        raise NativeCodexSessionError(
            "native_codex_owner_watcher_pidfd_failed")
    watcher_pid = -1
    try:
        watcher_pid = fork()
        if watcher_pid == 0:  # pragma: no cover - exec-free Linux child
            try:
                _owner_watcher_main(parent_pidfd, parent_pid)
            finally:
                os._exit(126)
        os.close(parent_pidfd)
        parent_pidfd = -1
        waited, status = waitpid(watcher_pid, os.WUNTRACED)
        if (waited != watcher_pid or not os.WIFSTOPPED(status)
                or os.WSTOPSIG(status) != signal.SIGSTOP):
            raise NativeCodexSessionError(
                "native_codex_owner_watcher_gate_failed")
        start_time = run_journal.process_start_time(
            watcher_pid, proc_root=proc_root)
        return watcher_pid, start_time
    except BaseException:
        _terminate_owner_watcher(watcher_pid, waitpid=waitpid)
        raise
    finally:
        if parent_pidfd >= 0:
            os.close(parent_pidfd)


def prove_controller_owner_scope_absent(
    unit: str,
    *,
    watcher_pid: int,
    watcher_start_time_ticks: int,
    expected_cgroup: str | None,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    deadline_seconds: float = 5.0,
) -> None:
    """Require two stable unit/cgroup/process-generation absence reads."""
    if (re.fullmatch(
            r"secure-sandbox-native-owner-[0-9a-f]{32}\.scope", unit) is None
            or watcher_pid <= 1 or watcher_start_time_ticks <= 0
            or (expected_cgroup is not None
                and _canonical_scope_cgroup(unit, expected_cgroup) is None)):
        raise NativeCodexSessionError(
            "native_codex_owner_scope_absence_request_invalid")
    properties = {"LoadState", "ActiveState", "SubState", "ControlGroup"}
    deadline = time.monotonic() + deadline_seconds
    consecutive = 0
    while time.monotonic() < deadline:
        result = runner(
            [str(systemctl), "show", unit, "--all",
             "--property=" + ",".join(sorted(properties))],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=2,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "LC_ALL": "C.UTF-8"})
        raw = result.stdout
        if isinstance(raw, str):
            raw_bytes = raw.encode("ascii", "strict")
        else:
            raw_bytes = raw
        observed_cgroup = expected_cgroup
        unit_absent = False
        if result.returncode == 4 and not raw_bytes:
            unit_absent = True
        elif result.returncode == 0 and len(raw_bytes) <= 4096:
            try:
                fields: dict[str, str] = {}
                for line in raw_bytes.decode("ascii").splitlines():
                    name, value = line.split("=", 1)
                    if name in fields:
                        raise ValueError
                    fields[name] = value
                if set(fields) != properties:
                    raise ValueError
                candidate = fields["ControlGroup"]
                if candidate:
                    if _canonical_scope_cgroup(unit, candidate) is None:
                        raise ValueError
                    if (expected_cgroup is not None
                            and candidate != expected_cgroup):
                        raise ValueError
                    observed_cgroup = candidate
                unit_absent = (
                    fields["LoadState"] in {"loaded", "not-found"}
                    and fields["ActiveState"] in {"inactive", "failed"}
                    and fields["SubState"] in {"dead", "failed"})
            except (UnicodeDecodeError, ValueError):
                unit_absent = False
        cgroup_empty = True
        if observed_cgroup is not None:
            try:
                cgroup_members = (
                    cgroup_root / observed_cgroup.lstrip("/") / "cgroup.procs"
                ).read_text(encoding="ascii").splitlines()
                cgroup_empty = cgroup_members == []
            except FileNotFoundError:
                cgroup_empty = True
            except (OSError, UnicodeError):
                cgroup_empty = False
        process_readback_valid = True
        try:
            exact_process_alive = (
                run_journal.process_start_time(
                    watcher_pid, proc_root=proc_root)
                == watcher_start_time_ticks)
        except FileNotFoundError:
            exact_process_alive = False
        except (OSError, ValueError,
                run_journal.NativeCodexRunJournalError):
            process_readback_valid = False
            exact_process_alive = True
        if (unit_absent and cgroup_empty and process_readback_valid
                and not exact_process_alive):
            consecutive += 1
            if consecutive == 2:
                return
        else:
            consecutive = 0
        time.sleep(0.02)
    raise NativeCodexSessionError(
        "native_codex_owner_scope_teardown_ambiguous")


def create_controller_owner_scope(
    unit: str,
    *,
    runtime_max_usec: int,
    trusted_uid: int,
    trusted_gid: int,
    busctl: Path = BUSCTL,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    watcher_spawner: Callable[..., tuple[int, int]] = (
        spawn_controller_owner_watcher),
    owner_starter: Callable[..., None] = start_controller_owner_scope,
    owner_verifier: Callable[..., dict[str, object]] = (
        verify_controller_owner_scope),
    signaler: Callable[[int, int], None] = os.kill,
    systemctl_runner: Callable[..., subprocess.CompletedProcess[bytes]] = (
        subprocess.run),
    watcher_terminator: Callable[..., None] = _terminate_owner_watcher,
    absence_prover: Callable[..., None] = (
        prove_controller_owner_scope_absent),
) -> ControllerOwnerCustody:
    """Create, verify, and release one exact watcher from its stop gate."""
    if os.geteuid() != trusted_uid:
        raise NativeCodexSessionError(
            "native_codex_owner_scope_supervisor_invalid")
    watcher_pid = -1
    watcher_start = -1
    cgroup: str | None = None
    try:
        watcher_pid, watcher_start = watcher_spawner(
            proc_root=proc_root)
        owner_starter(
            unit, watcher_pid, runtime_max_usec=runtime_max_usec,
            busctl=busctl)
        readback = owner_verifier(
            unit, watcher_pid=watcher_pid,
            watcher_start_time_ticks=watcher_start,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            expected_runtime_max_usec=runtime_max_usec,
            systemctl=systemctl, cgroup_root=cgroup_root,
            proc_root=proc_root)
        cgroup = readback.get("cgroup")
        if not isinstance(cgroup, str):
            cgroup = None
            raise NativeCodexSessionError(
                "native_codex_owner_scope_cgroup_invalid")
        signaler(watcher_pid, signal.SIGCONT)
        return ControllerOwnerCustody(
            unit=unit, watcher_pid=watcher_pid,
            watcher_start_time_ticks=watcher_start,
            runtime_max_usec=runtime_max_usec,
            cgroup=cgroup)
    except BaseException as error:
        cleanup_errors: list[BaseException] = []
        try:
            watcher_terminator(watcher_pid)
        except BaseException as cleanup:
            cleanup_errors.append(cleanup)
        try:
            stopped = systemctl_runner(
                [str(systemctl), "stop", unit], check=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if stopped.returncode not in {0, 3, 4, 5}:
                raise NativeCodexSessionError(
                    "native_codex_owner_scope_stop_failed")
        except BaseException as cleanup:
            cleanup_errors.append(cleanup)
        try:
            if watcher_pid > 1 and watcher_start > 0:
                absence_prover(
                    unit, watcher_pid=watcher_pid,
                    watcher_start_time_ticks=watcher_start,
                    expected_cgroup=cgroup, systemctl=systemctl,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    runner=systemctl_runner)
        except BaseException as cleanup:
            cleanup_errors.append(cleanup)
        if cleanup_errors:
            raise NativeCodexSessionError(
                "native_codex_owner_scope_setup_cleanup_failed"
            ) from cleanup_errors[-1]
        raise error


def release_controller_owner_scope(
    custody: ControllerOwnerCustody,
    *,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    waitpid: Callable[[int, int], tuple[int, int]] = os.waitpid,
    kill: Callable[[int, int], None] = os.kill,
    deadline_seconds: float = 5.0,
) -> None:
    """Release, reap, and independently prove the owner scope inactive."""
    if (not isinstance(custody, ControllerOwnerCustody)
            or custody.watcher_pid <= 1):
        raise NativeCodexSessionError(
            "native_codex_owner_scope_custody_invalid")
    watcher_pid = custody.watcher_pid
    watcher_start = custody.watcher_start_time_ticks
    stop_error: BaseException | None = None
    try:
        stopped = runner(
            [str(systemctl), "stop", custody.unit], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=min(5.0, deadline_seconds),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        if stopped.returncode not in {0, 3, 4, 5}:
            stop_error = NativeCodexSessionError(
                "native_codex_owner_scope_stop_failed")
    except (OSError, subprocess.SubprocessError) as error:
        stop_error = error
    reap_error: BaseException | None = None
    try:
        _terminate_owner_watcher(
            watcher_pid, waitpid=waitpid, kill=kill)
    except BaseException as error:
        reap_error = error
    try:
        prove_controller_owner_scope_absent(
            custody.unit, watcher_pid=watcher_pid,
            watcher_start_time_ticks=watcher_start,
            expected_cgroup=custody.cgroup, systemctl=systemctl,
            cgroup_root=cgroup_root, proc_root=proc_root,
            runner=runner, deadline_seconds=deadline_seconds)
    except BaseException as error:
        raise NativeCodexSessionError(
            "native_codex_owner_scope_teardown_ambiguous") from error
    custody.watcher_pid = -1
    if reap_error is not None:
        raise NativeCodexSessionError(
            "native_codex_owner_watcher_reap_ambiguous") from reap_error
    if stop_error is not None:
        raise NativeCodexSessionError(
            "native_codex_owner_scope_stop_failed") from stop_error


def _release_controller_owner_with_retry(
    custody: ControllerOwnerCustody,
    *,
    releaser: Callable[..., None] = release_controller_owner_scope,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
) -> Exception | None:
    """Retry live custody and return any anomaly for post-cleanup reporting."""
    failures: list[Exception] = []
    for _attempt in range(2):
        try:
            releaser(
                custody, systemctl=systemctl,
                cgroup_root=cgroup_root, proc_root=proc_root)
            return failures[-1] if failures else None
        except Exception as error:
            failures.append(error)
            # The releaser marks watcher_pid invalid only after independent
            # absence proof. Never retry a custody object already terminal.
            if custody.watcher_pid <= 1:
                break
    return failures[-1]


def make_ui_attach_claim(
    *, session_id: str, runtime_authority_sha256: str,
    harness_generation_id: str, harness_executable_sha256: str,
    session_lease_sha256: str, session_expires_at: int,
) -> dict[str, Any]:
    body = {
        "session_id": session_id,
        "runtime_authority_sha256": runtime_authority_sha256,
        "harness_generation_id": harness_generation_id,
        "harness_executable_sha256": harness_executable_sha256,
        "session_lease_sha256": session_lease_sha256,
        "session_expires_at": session_expires_at,
    }
    if (not isinstance(session_id, str)
            or UUID4.fullmatch(session_id) is None
            or any(not isinstance(value, str)
                   or SHA256.fullmatch(value) is None for value in (
                runtime_authority_sha256, harness_generation_id,
                harness_executable_sha256, session_lease_sha256))
            or not isinstance(session_expires_at, int)
            or isinstance(session_expires_at, bool)
            or session_expires_at < 1):
        raise NativeCodexSessionError("native_codex_ui_attach_identity_invalid")
    return {
        "schema": UI_ATTACH_SCHEMA, **body,
        "claim_sha256": _digest(body),
    }


def validate_ui_attach_claim(
    value: object, *, descriptor: Mapping[str, str],
    session_lease: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "session_id", "runtime_authority_sha256",
        "harness_generation_id", "harness_executable_sha256",
        "session_lease_sha256", "session_expires_at", "claim_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexSessionError("native_codex_ui_attach_fields_invalid")
    expected = make_ui_attach_claim(
        session_id=descriptor["session_id"],
        runtime_authority_sha256=descriptor["runtime_authority_sha256"],
        harness_generation_id=descriptor["harness_generation_id"],
        harness_executable_sha256=descriptor["harness_executable_sha256"],
        session_lease_sha256=session_lease["lease_sha256"],
        session_expires_at=session_lease["expires_at"])
    if value != expected:
        raise NativeCodexSessionError("native_codex_ui_attach_identity_mismatch")
    return expected


def _create_ui_listener(root: Path, *, session_id: str, trusted_uid: int,
                        trusted_gid: int) -> socket.socket:
    if UUID4.fullmatch(session_id) is None:
        raise NativeCodexSessionError("native_codex_ui_attach_identity_invalid")
    _require_directory(root, uid=trusted_uid, gid=trusted_gid, mode=0o700)
    path = root / f"{session_id}.sock"
    try:
        stale = path.lstat()
    except FileNotFoundError:
        pass
    else:
        # The caller holds the global native-Codex launch lock. Therefore an
        # exact socket left at this one-session pathname cannot be live; it is
        # crash residue. Refuse every other node type/owner/mode and recover
        # only that exact root-controlled stale socket.
        if (not stat.S_ISSOCK(stale.st_mode) or path.is_symlink()
                or stale.st_uid != trusted_uid or stale.st_gid != trusted_gid
                or stat.S_IMODE(stale.st_mode) != 0o600):
            raise NativeCodexSessionError("native_codex_ui_socket_untrusted")
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (stale.st_dev, stale.st_ino):
            raise NativeCodexSessionError("native_codex_ui_socket_changed")
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.set_inheritable(False)
        listener.bind(str(path))
        os.chown(path, trusted_uid, trusted_gid)
        os.chmod(path, 0o600)
        information = path.lstat()
        if (not stat.S_ISSOCK(information.st_mode) or path.is_symlink()
                or information.st_uid != trusted_uid
                or information.st_gid != trusted_gid
                or stat.S_IMODE(information.st_mode) != 0o600):
            raise NativeCodexSessionError("native_codex_ui_socket_untrusted")
        listener.listen(1)
        listener.settimeout(UI_ATTACH_TIMEOUT_SECONDS)
        return listener
    except Exception:
        listener.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _accept_ui(
    listener: socket.socket, *, descriptor: Mapping[str, str],
    session_lease: Mapping[str, Any],
    trusted_uid: int, trusted_gid: int,
    timeout_seconds: float = UI_ATTACH_TIMEOUT_SECONDS,
) -> socket.socket:
    if (not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= UI_ATTACH_TIMEOUT_SECONDS):
        raise NativeCodexSessionError("native_codex_ui_attach_timeout_invalid")
    listener.settimeout(timeout_seconds)
    try:
        connection, _address = listener.accept()
    except (TimeoutError, socket.timeout) as error:
        raise NativeCodexSessionError("native_codex_ui_attach_timeout") from error
    try:
        if not hasattr(socket, "SO_PEERCRED"):
            raise NativeCodexSessionError("native_codex_ui_peer_unsupported")
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
        if (peer_pid <= 1 or peer_uid != trusted_uid or peer_gid != trusted_gid):
            raise NativeCodexSessionError("native_codex_ui_peer_untrusted")
        connection.settimeout(timeout_seconds)
        raw = bytearray()
        while len(raw) <= MAX_UI_ATTACH_BYTES:
            block = connection.recv(1)
            if not block:
                raise NativeCodexSessionError("native_codex_ui_attach_truncated")
            raw.extend(block)
            if block == b"\n":
                break
        if not raw.endswith(b"\n") or len(raw) > MAX_UI_ATTACH_BYTES:
            raise NativeCodexSessionError("native_codex_ui_attach_oversized")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeCodexSessionError("native_codex_ui_attach_invalid") from error
        if raw != _canonical(value):
            raise NativeCodexSessionError("native_codex_ui_attach_not_canonical")
        validate_ui_attach_claim(
            value, descriptor=descriptor, session_lease=session_lease)
        connection.setblocking(False)
        try:
            premature = connection.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            premature = b""
        if premature:
            raise NativeCodexSessionError("native_codex_ui_input_before_ready")
        path = Path(listener.getsockname())
        information = path.lstat()
        if (not stat.S_ISSOCK(information.st_mode) or path.is_symlink()
                or information.st_uid != trusted_uid
                or information.st_gid != trusted_gid
                or stat.S_IMODE(information.st_mode) != 0o600):
            raise NativeCodexSessionError("native_codex_ui_socket_untrusted")
        # One authenticated peer now owns the sole accepted description. The
        # pathname is removed before READY so a second attach/replay has no
        # rendezvous point even while the listener fd is still open.
        path.unlink()
        return connection
    except Exception:
        connection.close()
        raise


def _connect_ui_socket(
    descriptor: Mapping[str, str], *, session_lease: Mapping[str, Any],
    ui_root: Path = UI_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> socket.socket:
    _require_directory(ui_root, uid=trusted_uid, gid=trusted_gid, mode=0o700)
    path = ui_root / f"{descriptor['session_id']}.sock"
    deadline = time.monotonic() + UI_ATTACH_TIMEOUT_SECONDS
    while True:
        try:
            information = path.lstat()
            if (not stat.S_ISSOCK(information.st_mode) or path.is_symlink()
                    or information.st_uid != trusted_uid
                    or information.st_gid != trusted_gid
                    or stat.S_IMODE(information.st_mode) != 0o600):
                raise NativeCodexSessionError("native_codex_ui_socket_untrusted")
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.connect(str(path))
                connection.sendall(_canonical(make_ui_attach_claim(
                    session_id=descriptor["session_id"],
                    runtime_authority_sha256=descriptor[
                        "runtime_authority_sha256"],
                    harness_generation_id=descriptor[
                        "harness_generation_id"],
                    harness_executable_sha256=descriptor[
                        "harness_executable_sha256"],
                    session_lease_sha256=session_lease["lease_sha256"],
                    session_expires_at=session_lease["expires_at"])))
                return connection
            except Exception:
                connection.close()
                raise
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                raise NativeCodexSessionError(
                    "native_codex_ui_socket_unavailable") from None
            time.sleep(0.02)


def relay_ui(
    *, session_id: str, runtime_authority_sha256: str,
    harness_generation_id: str, harness_executable_sha256: str,
    session_lease_sha256: str, session_expires_at: int,
    input_fd: int = 0, output_fd: int = 1,
    ui_root: Path = UI_ROOT, trusted_uid: int = 0, trusted_gid: int = 0,
) -> int:
    """Attach one Host UI stream; never parse or reflect vendor protocol bytes."""
    claim = make_ui_attach_claim(
        session_id=session_id,
        runtime_authority_sha256=runtime_authority_sha256,
        harness_generation_id=harness_generation_id,
        harness_executable_sha256=harness_executable_sha256,
        session_lease_sha256=session_lease_sha256,
        session_expires_at=session_expires_at)
    connection = _connect_ui_socket(
        claim, session_lease={
            "lease_sha256": session_lease_sha256,
            "expires_at": session_expires_at,
        }, ui_root=ui_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid)

    def upload() -> None:
        try:
            while True:
                block = os.read(input_fd, 16 * 1024)
                if not block:
                    break
                connection.sendall(block)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    writer = threading.Thread(target=upload, daemon=True)
    writer.start()
    try:
        while True:
            block = connection.recv(16 * 1024)
            if not block:
                return 0
            _write_all(output_fd, block)
    except OSError as error:
        raise NativeCodexSessionError("native_codex_ui_relay_failed") from error
    finally:
        connection.close()


def _launch_and_wait_admitted(
    authority_value: object,
    *,
    session_lease: Mapping[str, Any],
    projection_id: str,
    access_token_sha256: str,
    input_fd: int = 0,
    now: int | None = None,
    expires_at_unix: int | None = None,
    launcher_path: Path = LAUNCHER,
    state_root: Path = STATE_ROOT,
    control_root: Path = CONTROL_ROOT,
    policy_root: Path = POLICY_ROOT,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
    identity_name: str = IDENTITY,
    busctl_path: Path = BUSCTL,
    systemctl_path: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    qualification_journal_root: Path = isolation.JOURNAL_ROOT,
    qualification_scratch_root: Path = isolation.QUALIFICATION_SCRATCH_ROOT,
    qualification_boot_id_path: Path = isolation.BOOT_ID,
    qualification_core_pattern_path: Path = isolation.CORE_PATTERN,
    scope_verifier: Callable[..., dict[str, object]] = verify_transient_scope,
    scope_starter: Callable[..., None] = start_transient_scope,
    owner_scope_factory: Callable[..., ControllerOwnerCustody] = (
        create_controller_owner_scope),
    owner_scope_verifier: Callable[..., dict[str, object]] = (
        verify_controller_owner_scope),
    owner_scope_releaser: Callable[..., None] = (
        release_controller_owner_scope),
    scope_observer: Callable[[int, str, dict[str, object]], None] | None = None,
    pre_release_qualification_gate: Callable[[object, object], str] | None = None,
    expected_qualification_evidence_sha256: str | None = None,
    qualification_gate: Callable[..., str] | None = None,
    driver_factory: Callable[..., runtime_driver.NativeCodexRuntimeDriver] = (
        runtime_driver.NativeCodexRuntimeDriver),
    token_receipt_reader: Callable[..., bytes] = runtime_driver.read_token_receipt,
    ui_listener_factory: Callable[..., socket.socket] = _create_ui_listener,
    ui_acceptor: Callable[..., socket.socket] = _accept_ui,
) -> int:
    """Launch one session after the lifecycle admission lock is held.

    The caller's ``input_fd`` is projected unchanged to launcher fd 5. Python
    never reads or buffers it. Fresh pipes exclusively bind app-server stdio to
    the first-party driver; a separate private fd-6 receipt carries only
    content-free token, process-generation, environment, and permit/session
    bindings. A private fd-7 gate releases that exact generation only while
    both its session lease and projection permit remain current.
    """
    if os.geteuid() != trusted_uid:
        raise NativeCodexSessionError("native_codex_supervisor_not_root")
    identity = pwd.getpwnam(identity_name)
    if identity.pw_uid == 0 or identity.pw_gid == 0:
        raise NativeCodexSessionError("native_codex_session_identity_invalid")
    descriptor = policy.make_launch_descriptor(authority_value)
    observed_unix = int(time.time()) if now is None else now
    try:
        validated_lease = native_stack_session.validate_session_lease(
            session_lease, now=observed_unix, require_fresh=True)
    except native_stack_session.NativeStackSessionError as error:
        raise NativeCodexSessionError("native_codex_run_lease_invalid") from error
    if (validated_lease["session_id"] != descriptor["session_id"]
            or validated_lease["runtime_authority_sha256"]
               != descriptor["runtime_authority_sha256"]):
        raise NativeCodexSessionError("native_codex_run_lease_mismatch")
    lease_remaining = validated_lease["expires_at"] - observed_unix
    if not 1 <= lease_remaining <= MAX_NATIVE_SESSION_SECONDS:
        raise NativeCodexSessionError("native_codex_run_lease_invalid")
    lease_deadline = time.monotonic() + lease_remaining
    _require_directory(control_root, uid=trusted_uid, gid=trusted_gid, mode=0o700)
    _require_directory(policy_root, uid=trusted_uid, gid=trusted_gid, mode=0o755)
    lock = os.open(
        control_root / LOCK_PATH.name,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.fchmod(lock, 0o600)
        os.fchown(lock, trusted_uid, trusted_gid)
        fcntl.flock(lock, fcntl.LOCK_EX)
        session = create_session_layout(
            descriptor,
            state_root=state_root,
            baseline_config=policy_root / "config.toml",
            baseline_gid=trusted_gid,
            trusted_uid=trusted_uid,
            launcher_uid=identity.pw_uid,
            launcher_gid=identity.pw_gid,
        )
        permit_fd = -1
        try:
            policy.write_launch_descriptor(
                control_root / AUTHORITY_PATH.name,
                descriptor,
                uid=trusted_uid,
                gid=identity.pw_gid,
            )
            issued = observed_unix
            expires = _projection_permit_expiry(
                issued_at=issued,
                requested_expires_at=expires_at_unix,
                lease_expires_at=validated_lease["expires_at"])
            permit_value = policy.make_projection_permit(
                descriptor,
                projection_id=projection_id,
                access_token_sha256=access_token_sha256,
                issued_at_unix=issued,
                expires_at_unix=expires,
                launcher_uid=identity.pw_uid,
                launcher_gid=identity.pw_gid,
            )
            permit_fd = claim_projection_permit(
                descriptor,
                projection_id=projection_id,
                access_token_sha256=access_token_sha256,
                issued_at_unix=issued,
                expires_at_unix=expires,
                launcher_uid=identity.pw_uid,
                launcher_gid=identity.pw_gid,
                permit_root=control_root / PERMIT_ROOT.name,
                trusted_uid=trusted_uid,
                trusted_gid=trusted_gid,
            )
        except Exception:
            if permit_fd >= 0:
                os.close(permit_fd)
            if session.exists() and not session.is_symlink():
                shutil.rmtree(session)
            try:
                (control_root / AUTHORITY_PATH.name).unlink()
            except FileNotFoundError:
                pass
            raise
        unit = (
            "secure-sandbox-native-run-"
            + descriptor["session_id"].replace("-", "")
            + ".scope"
        )
        if pre_release_qualification_gate is None:
            def pre_release_qualification_gate(
                *_args: object, **_kwargs: object
            ) -> str:
                raise NativeCodexSessionError(
                    "native_codex_pre_release_qualification_unavailable"
                )
        listener: socket.socket | None = None
        ui_connection: socket.socket | None = None
        app_input_read = app_input_write = -1
        app_output_read = app_output_write = -1
        app_stderr_read = app_stderr_write = -1
        receipt_read = receipt_write = -1
        gate_read = gate_write = -1
        child = -1
        current_process_start = -1
        owner_custody: ControllerOwnerCustody | None = None
        try:
            isolation.reconcile_interrupted(
                journal_root=qualification_journal_root,
                qualification_root=qualification_scratch_root,
                current_boot_id_sha256=isolation.boot_id_sha256(
                    path=qualification_boot_id_path),
                proc_root=proc_root, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            owner_runtime_max_usec = int(
                max(1.0, (lease_deadline - time.monotonic()) * 1_000_000))
            owner_custody = owner_scope_factory(
                controller_owner_scope_unit(unit),
                runtime_max_usec=owner_runtime_max_usec,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                busctl=busctl_path, systemctl=systemctl_path,
                cgroup_root=cgroup_root, proc_root=proc_root)
            listener = ui_listener_factory(
                control_root / UI_ROOT.name,
                session_id=descriptor["session_id"],
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
            app_input_read, app_input_write = os.pipe2(os.O_CLOEXEC)
            app_output_read, app_output_write = os.pipe2(os.O_CLOEXEC)
            app_stderr_read, app_stderr_write = os.pipe2(os.O_CLOEXEC)
            receipt_read, receipt_write = os.pipe2(os.O_CLOEXEC)
            gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
            expected_vendor_parent_pid = os.getpid()
            child = os.fork()
            if child == 0:  # pragma: no cover - stopped exec-only child
                try:
                    _arm_vendor_parent_death_signal(
                        expected_vendor_parent_pid)
                    os.setsid()
                    os.setgroups([])
                    os.setgid(identity.pw_gid)
                    os.setuid(identity.pw_uid)
                    # Linux clears PR_SET_PDEATHSIG when effective or
                    # filesystem credentials change. Re-arm only after the
                    # complete root-to-vendor credential transition, then
                    # close the parent-death-before-prctl race again.
                    _arm_vendor_parent_death_signal(
                        expected_vendor_parent_pid)
                    bindings = (
                        (app_input_read, 0),
                        (app_output_write, 1),
                        (app_stderr_write, 2),
                        (permit_fd, policy.PROJECTION_PERMIT_FD),
                        (input_fd, policy.PROJECTION_FRAME_FD),
                        (receipt_write, policy.TOKEN_RECEIPT_FD),
                        (gate_read, policy.LAUNCH_GATE_FD),
                    )
                    copied = [
                        (fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 10), target)
                        for source, target in bindings
                    ]
                    for source, target in copied:
                        os.dup2(source, target)
                        os.set_inheritable(target, True)
                    try:
                        os.close(4)
                    except OSError:
                        pass
                    maximum = os.sysconf("SC_OPEN_MAX")
                    os.closerange(8, maximum if maximum > 8 else 1024)
                    os.kill(os.getpid(), 19)  # SIGSTOP before any vendor exec
                    os.execve(launcher_path, [str(launcher_path)], {})
                except BaseException:
                    os._exit(126)
            os.close(permit_fd)
            permit_fd = -1
            for descriptor_to_close in (
                    app_input_read, app_output_write, app_stderr_write,
                    receipt_write, gate_read, input_fd):
                os.close(descriptor_to_close)
            app_input_read = app_output_write = app_stderr_write = -1
            receipt_write = -1
            gate_read = -1
            input_fd = -1
            waited, status = os.waitpid(child, os.WUNTRACED)
            if (waited != child or not os.WIFSTOPPED(status)
                    or os.WSTOPSIG(status) != 19):
                raise NativeCodexSessionError("native_codex_child_gate_failed")
            runtime_max_usec = int(
                max(1.0, (lease_deadline - time.monotonic()) * 1_000_000))
            scope_starter(
                unit, child, owner_unit=owner_custody.unit,
                runtime_max_usec=runtime_max_usec,
                busctl=busctl_path)
            scope_readback = scope_verifier(
                unit, owner_unit=owner_custody.unit,
                launcher_uid=identity.pw_uid,
                launcher_gid=identity.pw_gid,
                systemctl=systemctl_path, cgroup_root=cgroup_root,
                proc_root=proc_root,
                expected_runtime_max_usec=runtime_max_usec)
            scope_cgroup = scope_readback.get("cgroup")
            scope_cgroup_parts = (Path(scope_cgroup).parts
                                  if isinstance(scope_cgroup, str) else ())
            canonical_scope_cgroup = (
                "/" + "/".join(scope_cgroup_parts[1:])
                if scope_cgroup_parts and scope_cgroup_parts[0] == "/"
                else "")
            if (not isinstance(scope_cgroup, str)
                    or not scope_cgroup.startswith("/")
                    or scope_cgroup != canonical_scope_cgroup
                    or ".." in scope_cgroup_parts
                    or Path(scope_cgroup).name != unit):
                raise NativeCodexSessionError(
                    "native_codex_scope_cgroup_invalid")
            if scope_observer is not None:
                scope_observer(child, unit, scope_readback)
            current_process_start = run_journal.process_start_time(
                child, proc_root=proc_root)
            if time.monotonic() >= lease_deadline:
                raise NativeCodexSessionError("native_codex_run_lease_expired")
            qualification_evidence = pre_release_qualification_gate(
                authority_value, descriptor
            )
            if (expected_qualification_evidence_sha256 is None
                    or SHA256.fullmatch(
                        expected_qualification_evidence_sha256
                    ) is None
                    or qualification_evidence
                        != expected_qualification_evidence_sha256):
                raise NativeCodexSessionError(
                    "native_codex_pre_release_qualification_mismatch"
                )
            if time.monotonic() >= lease_deadline:
                raise NativeCodexSessionError("native_codex_run_lease_expired")
            owner_readback = owner_scope_verifier(
                owner_custody.unit,
                watcher_pid=owner_custody.watcher_pid,
                watcher_start_time_ticks=(
                    owner_custody.watcher_start_time_ticks),
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                expected_runtime_max_usec=(
                    owner_custody.runtime_max_usec),
                systemctl=systemctl_path, cgroup_root=cgroup_root,
                proc_root=proc_root)
            if owner_readback.get("cgroup") != owner_custody.cgroup:
                raise NativeCodexSessionError(
                    "native_codex_owner_scope_cgroup_changed")
            if time.monotonic() >= lease_deadline:
                raise NativeCodexSessionError(
                    "native_codex_run_lease_expired")
            os.kill(child, 18)  # SIGCONT only after exact scope/UID readback
            remaining = lease_deadline - time.monotonic()
            if remaining <= 0:
                raise NativeCodexSessionError("native_codex_run_lease_expired")
            receipt = token_receipt_reader(
                receipt_read,
                timeout_seconds=min(UI_ATTACH_TIMEOUT_SECONDS, remaining))
            os.close(receipt_read)
            receipt_read = -1
            validated_receipt = runtime_driver.validate_token_receipt(
                receipt, launch_descriptor=descriptor,
                expected_projection_id=projection_id,
                expected_permit_sha256=permit_value["permit_sha256"],
                expected_access_token_sha256=access_token_sha256,
                expected_process_id=child,
                expected_process_start_time_ticks=current_process_start)
            _release_launcher_gate_before_lease_expiry(
                gate_write, validated_receipt,
                lease_deadline=lease_deadline)
            os.close(gate_write)
            gate_write = -1
            if qualification_gate is None:
                receipt_observation = (
                    runtime_driver.launcher_receipt_observation(
                        validated_receipt))
                scope_cgroup_sha256 = hashlib.sha256(
                    (scope_cgroup + "\n").encode("ascii")).hexdigest()
                supervisor_cgroup_sha256 = hashlib.sha256(
                    (isolation.SUPERVISOR_CGROUP + "\n").encode(
                        "ascii")).hexdigest()
                policy_manifest_sha256 = isolation.compute_policy_manifest(
                    trusted_uid=trusted_uid)
                probe_executable_sha256 = (
                    isolation.probe_executable_sha256(
                        trusted_uid=trusted_uid))
                expected_executable = (
                    Path("/usr/local/libexec/secure-sandbox-harnesses/releases")
                    / descriptor["harness_generation_id"] / "harness")

                def qualification_gate(
                    firewall: object, live_descriptor: object,
                    exchange: Callable[..., tuple[dict[str, Any], dict[str, Any]]],
                    supplied_receipt: Mapping[str, Any],
                ) -> Mapping[str, Any]:
                    if dict(supplied_receipt) != receipt_observation:
                        raise NativeCodexSessionError(
                            "native_codex_live_receipt_changed")
                    challenge = isolation.make_challenge(
                        firewall, live_descriptor,
                        appserver_pid=child,
                        service_uid=identity.pw_uid,
                        token_sha256=access_token_sha256,
                        policy_manifest_sha256=policy_manifest_sha256,
                        probe_executable_sha256=probe_executable_sha256,
                        scope_cgroup_sha256=scope_cgroup_sha256,
                        allowed_service_cgroup_sha256s=[
                            scope_cgroup_sha256,
                            supervisor_cgroup_sha256,
                        ],
                        launcher_receipt_sha256=(
                            validated_receipt.receipt_sha256),
                        environment_proof_sha256=(
                            validated_receipt.environment_proof_sha256),
                        codex_home_sha256=(
                            validated_receipt.codex_home_sha256),
                        proc_root=proc_root,
                        boot_id_path=qualification_boot_id_path,
                        qualification_root=qualification_scratch_root,
                    )
                    if (challenge["appserver_pid"] != child
                            or challenge["process_start_time_ticks"]
                               != current_process_start):
                        raise NativeCodexSessionError(
                            "native_codex_live_process_changed")
                    isolation.record_reserved(
                        challenge, service_gid=identity.pw_gid,
                        journal_root=qualification_journal_root,
                        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
                    scratch_identity: Mapping[str, Any] | None = None
                    scratch_cleaned = False
                    try:
                        scratch_identity = (
                            isolation.prepare_qualification_scratch(
                                challenge, service_uid=identity.pw_uid,
                                service_gid=identity.pw_gid,
                                qualification_root=qualification_scratch_root,
                                trusted_uid=trusted_uid))
                        isolation.record_prepared(
                            challenge, scratch_identity,
                            journal_root=qualification_journal_root,
                            trusted_uid=trusted_uid, trusted_gid=trusted_gid)
                        isolation.activate_qualification_scratch(
                            challenge, scratch_identity,
                            qualification_root=qualification_scratch_root,
                            journal_root=qualification_journal_root,
                            trusted_uid=trusted_uid,
                            trusted_gid=trusted_gid)

                        def observe_root() -> Mapping[str, Any]:
                            return isolation.collect_root_observation(
                                challenge, live_descriptor,
                                expected_executable=expected_executable,
                                launcher_receipt=receipt_observation,
                                proc_root=proc_root,
                                core_pattern_path=(
                                    qualification_core_pattern_path),
                                trusted_uid=trusted_uid)

                        root_observation, tool_observation = exchange(
                            challenge, observe_root)
                        evidence = isolation.evaluate_qualification(
                            firewall, live_descriptor, challenge=challenge,
                            root_observation=root_observation,
                            tool_observation=tool_observation,
                            policy_manifest_sha256=policy_manifest_sha256,
                            probe_executable_sha256=(
                                probe_executable_sha256))
                        # A pass is not durable and cannot reach READY until
                        # the exact empty scratch inode has been removed.
                        isolation.cleanup_qualification_scratch(
                            challenge, scratch_identity,
                            qualification_root=qualification_scratch_root,
                            trusted_uid=trusted_uid)
                        scratch_cleaned = True
                        isolation.record_terminal(
                            challenge, evidence,
                            journal_root=qualification_journal_root,
                            qualification_root=qualification_scratch_root,
                            trusted_uid=trusted_uid,
                            trusted_gid=trusted_gid)
                        return evidence
                    finally:
                        if scratch_identity is not None and not scratch_cleaned:
                            isolation.cleanup_qualification_scratch(
                                challenge, scratch_identity,
                                qualification_root=qualification_scratch_root,
                                trusted_uid=trusted_uid)
            remaining = lease_deadline - time.monotonic()
            if remaining <= 0:
                raise NativeCodexSessionError("native_codex_run_lease_expired")
            ui_connection = ui_acceptor(
                listener, descriptor=descriptor,
                session_lease=validated_lease,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                timeout_seconds=min(
                    UI_ATTACH_TIMEOUT_SECONDS, remaining))
            listener.close()
            driver = driver_factory(
                launch_descriptor=descriptor,
                host_input_fd=ui_connection.fileno(),
                host_output_fd=ui_connection.fileno(),
                appserver_input_fd=app_input_write,
                appserver_output_fd=app_output_read,
                appserver_stderr_fd=app_stderr_read,
                token_receipt=receipt,
                expected_projection_id=projection_id,
                expected_permit_sha256=permit_value["permit_sha256"],
                expected_access_token_sha256=access_token_sha256,
                expected_process_id=child,
                expected_process_start_time_ticks=current_process_start,
                session_lease_sha256=validated_lease["lease_sha256"],
                session_expires_at=validated_lease["expires_at"],
                qualification_gate=qualification_gate,
                qualification_quiescer=lambda: _quiesce_scope_for_ready(
                    child, current_process_start,
                    scope_cgroup=scope_cgroup, scope_unit=unit,
                    launcher_uid=identity.pw_uid,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    trusted_uid=trusted_uid),
                lease_deadline_monotonic=lease_deadline,
            )
            driver.run()
            stopped = subprocess.run(
                [str(systemctl_path), "stop", unit], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if stopped.returncode not in {0, 3, 4, 5}:
                raise NativeCodexSessionError("native_codex_scope_stop_failed")
            reap_deadline = time.monotonic() + 5
            while True:
                waited, status = os.waitpid(child, os.WNOHANG)
                if waited == child:
                    child = -1
                    break
                if time.monotonic() >= reap_deadline:
                    raise NativeCodexSessionError("native_codex_scope_reap_timeout")
                time.sleep(0.02)
            for _attempt in range(2):
                readback = subprocess.run(
                    [str(systemctl_path), "is-active", unit], check=False,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=5,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                if (readback.returncode not in {3, 4}
                        or readback.stdout.strip() == b"active"):
                    raise NativeCodexSessionError(
                        "native_codex_scope_teardown_ambiguous")
                time.sleep(0.01)
            return 0
        except Exception:
            try:
                subprocess.run(
                    [str(systemctl_path), "stop", unit], check=False,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=10,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            except (OSError, subprocess.SubprocessError):
                pass
            if child > 0:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
            raise
        finally:
            owner_release_error: Exception | None = None
            if owner_custody is not None:
                owner_release_error = _release_controller_owner_with_retry(
                    owner_custody, releaser=owner_scope_releaser,
                    systemctl=systemctl_path,
                    cgroup_root=cgroup_root, proc_root=proc_root)
                owner_custody = None
            if listener is not None:
                listener.close()
                try:
                    (control_root / UI_ROOT.name /
                     f"{descriptor['session_id']}.sock").unlink()
                except FileNotFoundError:
                    pass
            if ui_connection is not None:
                ui_connection.close()
            for descriptor_to_close in (
                    app_input_read, app_input_write,
                    app_output_read, app_output_write,
                    app_stderr_read, app_stderr_write,
                    receipt_read, receipt_write, gate_read, gate_write):
                if descriptor_to_close >= 0:
                    try:
                        os.close(descriptor_to_close)
                    except OSError:
                        pass
            if input_fd >= 0:
                try:
                    os.close(input_fd)
                except OSError:
                    pass
            if permit_fd >= 0:
                os.close(permit_fd)
            if session.exists() and not session.is_symlink():
                shutil.rmtree(session)
            try:
                (control_root / AUTHORITY_PATH.name).unlink()
            except FileNotFoundError:
                pass
            if owner_release_error is not None:
                raise owner_release_error
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def launch_and_wait(
    authority_value: object, *, projection_id: str,
    access_token_sha256: str,
    lifecycle_root: Path = native_lifecycle_fence.ROOT,
    **options: object,
) -> int:
    """Launch exactly one session under the durable publication exclusion.

    The caller's token-bearing input descriptor is passed unchanged to the C
    launcher.  This controller handles only its digest and never reads or
    buffers the stream.
    """
    trusted_uid = options.get("trusted_uid", 0)
    trusted_gid = options.get("trusted_gid", 0)
    if not isinstance(trusted_uid, int) or not isinstance(trusted_gid, int):
        raise NativeCodexSessionError("native_codex_trusted_identity_invalid")
    try:
        with native_lifecycle_fence.admission_open(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ):
            return _launch_and_wait_admitted(
                authority_value, projection_id=projection_id,
                access_token_sha256=access_token_sha256, **options)
    except native_lifecycle_fence.NativeLifecycleFenceError as error:
        raise NativeCodexSessionError(str(error)) from error


def _claim_preparation(
    operation_id: str, prepare_sha256: str, *, preparation_root: Path,
    trusted_uid: int, trusted_gid: int, now: int,
) -> dict[str, Any]:
    if (UUID4.fullmatch(operation_id) is None
            or SHA256.fullmatch(prepare_sha256) is None):
        raise NativeCodexSessionError("native_codex_launch_identity_invalid")
    root_descriptor = _preparation_root_descriptor(
        preparation_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        source = f"{operation_id}.json"
        consumed = f"{operation_id}.consumed.json"
        try:
            os.stat(consumed, dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise NativeCodexSessionError("native_codex_launch_replay_denied")
        value = _read_preparation(
            root_descriptor, source, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        if (value["prepare_sha256"] != prepare_sha256
                or value["expires_at"] <= now):
            raise NativeCodexSessionError("native_codex_launch_preparation_invalid")
        try:
            lease = native_stack_session.validate_session_lease(
                value["session_lease"], now=now, require_fresh=True)
        except native_stack_session.NativeStackSessionError as error:
            raise NativeCodexSessionError(
                "native_codex_launch_session_lease_invalid") from error
        authority = policy.require_codex_authority(value["runtime_authority"])
        try:
            native_codex_projection.validate_projection_authority(
                value["projection_authority"],
                operation_id=value["operation_id"],
                request_sha256=value["operator_request_sha256"],
                stack_sha256=value["stack_sha256"],
                session_authority_sha256=authority["binding_sha256"],
                ticket_issued_at=value["projection_ticket_issued_at"],
                ticket_expires_at=value["projection_ticket_expires_at"],
                now=now,
            )
        except native_codex_projection.NativeCodexProjectionError as error:
            raise NativeCodexSessionError(
                "native_codex_launch_projection_authority_invalid"
            ) from error
        if (lease["session_id"] != value["session_id"]
                or lease["runtime_authority_sha256"]
                   != authority["binding_sha256"]):
            raise NativeCodexSessionError(
                "native_codex_launch_session_lease_mismatch")
        before = os.stat(source, dir_fd=root_descriptor, follow_symlinks=False)
        os.replace(source, consumed, src_dir_fd=root_descriptor,
                   dst_dir_fd=root_descriptor)
        os.fsync(root_descriptor)
        after = os.stat(consumed, dir_fd=root_descriptor, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise NativeCodexSessionError("native_codex_launch_claim_ambiguous")
        observed = _read_preparation(
            root_descriptor, consumed, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        if observed != value:
            raise NativeCodexSessionError("native_codex_launch_claim_ambiguous")
        return value
    finally:
        os.close(root_descriptor)


def close_native_egress() -> str:
    """Close Research egress, purge marked conntrack, and reduce the evidence."""
    denied = native_guest_control._deny_only("research")
    conntrack = native_guest_control._delete_conntrack("research")
    return _digest({"deny": denied, "conntrack": conntrack, "state": "closed"})


def observe_closed_native_egress() -> str:
    """Read back a closed policy, absent grant, and empty marked conntrack."""
    if native_guest_control._active_grant("research") is not None:
        raise NativeCodexSessionError("native_codex_session_egress_still_open")
    policy_sha256 = native_guest_control._verify_live_policy("research")
    retired = native_guest_control._retired_grant()
    mark: str | None = None
    if retired is not None:
        mark = native_guest_control.native_egress.conntrack_mark(
            retired, str(native_guest_control.ROLE["research"]["mark_domain"]))
        result = native_guest_control._run(
            ["/usr/sbin/conntrack", "-L", "-m", "mark", "--mark", mark],
            accepted={0})
        if result.stdout.strip():
            raise NativeCodexSessionError(
                "native_codex_session_conntrack_still_live")
    return _digest({"state": "closed", "policy_sha256": policy_sha256,
                    "retired_mark": mark, "conntrack": "absent"})


def _session_absence(
    latest: Mapping[str, Any], *, egress_evidence_sha256: str,
    proc_root: Path = Path("/proc"),
    absence_prover: Callable[..., str] = run_journal.prove_absence,
) -> str:
    process_id = latest["process_id"]
    process_start = latest["process_start_time_ticks"]
    try:
        current_boot = run_journal.boot_id_sha256()
    except (OSError, run_journal.NativeCodexRunJournalError):
        current_boot = None
    if current_boot != latest["boot_id_sha256"]:
        process_id = None
        process_start = None
    deadline = time.monotonic() + 5
    while True:
        try:
            return absence_prover(
                session_id=latest["session_id"],
                scope_unit=latest["scope_unit"], process_id=process_id,
                process_start_time_ticks=process_start,
                egress_evidence_sha256=egress_evidence_sha256,
                proc_root=proc_root)
        except run_journal.NativeCodexRunJournalError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def session_control(
    value: object, *, status: bool, journal_root: Path = run_journal.ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
    proc_root: Path = Path("/proc"), systemctl: Path = SYSTEMCTL,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    egress_closer: Callable[[], str] = close_native_egress,
    egress_observer: Callable[[], str] = observe_closed_native_egress,
    absence_prover: Callable[..., str] = run_journal.prove_absence,
) -> dict[str, Any]:
    request = validate_session_control_request(value, status=status)
    latest = run_journal.latest(
        request["session_id"], root=journal_root,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if latest["runtime_authority_sha256"] != request["runtime_authority_sha256"]:
        raise NativeCodexSessionError(
            "native_codex_session_control_authority_mismatch")
    if status:
        if latest["phase"] != "terminal":
            raise NativeCodexSessionError("native_codex_session_not_absent")
        egress = egress_observer()
        absence = _session_absence(
            latest, egress_evidence_sha256=egress, proc_root=proc_root,
            absence_prover=absence_prover)
    else:
        result = runner(
            [str(systemctl), "stop", latest["scope_unit"]], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        if result.returncode not in {0, 3, 4, 5}:
            raise NativeCodexSessionError(
                "native_codex_session_stop_failed")
        egress = egress_closer()
        absence = _session_absence(
            latest, egress_evidence_sha256=egress, proc_root=proc_root,
            absence_prover=absence_prover)
        if latest["phase"] != "terminal":
            latest = run_journal.append_event(
                phase="terminal",
                transition_operation_id=request["operation_id"],
                authority=latest["runtime_authority"],
                scope_unit=latest["scope_unit"],
                process_id=latest["process_id"],
                process_start_time_ticks=latest["process_start_time_ticks"],
                boot_id_sha256=latest["boot_id_sha256"],
                executable_sha256=latest["executable_sha256"],
                session_lease=latest["session_lease"],
                lease_started_at=latest["lease_started_at"],
                lease_expires_at=latest["lease_expires_at"],
                observed_at=max(latest["observed_at"], int(time.time())),
                exit_code=143, absence_evidence_sha256=absence,
                root=journal_root, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
        else:
            latest = run_journal.latest(
                request["session_id"], root=journal_root,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    evidence = _digest({
        "operation_id": request["operation_id"],
        "session_id": request["session_id"], "state": "absent",
        "runtime_authority_sha256": request["runtime_authority_sha256"],
        "final_summary_sha256": latest["event_sha256"],
        "absence_evidence_sha256": absence,
    })
    return {
        "schema": STATUS_REPLY_SCHEMA if status else STOP_REPLY_SCHEMA,
        "operation_id": request["operation_id"],
        "session_id": request["session_id"], "state": "absent",
        "final_summary_sha256": latest["event_sha256"],
        "evidence_sha256": evidence,
    }


def launch_prepared(
    operation_id: str, prepare_sha256: str, *, input_fd: int = 0,
    preparation_root: Path = PREPARATION_ROOT,
    lifecycle_root: Path = native_lifecycle_fence.ROOT,
    catalog_path: Path | None = None,
    runtime_loader: Callable[[str], dict[str, str]] | None = None,
    trusted_uid: int = 0, trusted_gid: int = 0,
    now: int | None = None, journal_root: Path = run_journal.ROOT,
    boot_id_path: Path = run_journal.BOOT_ID,
    proc_root: Path = Path("/proc"),
    egress_closer: Callable[[], str] = close_native_egress,
    absence_prover: Callable[..., str] = run_journal.prove_absence,
    **options: object,
) -> int:
    """Consume one preparation and pass the token pipe without reading it."""
    if os.geteuid() != trusted_uid:
        raise NativeCodexSessionError("native_codex_launch_root_required")
    timestamp = int(time.time()) if now is None else now
    try:
        with native_lifecycle_fence.admission_open(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ):
            prepared = _claim_preparation(
                operation_id, prepare_sha256,
                preparation_root=preparation_root, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid, now=timestamp)
            authority = validate_admitted_authority(
                prepared["runtime_authority"], catalog_path=catalog_path,
                runtime_loader=runtime_loader)
            session_id = authority["session_context_binding"]["session_id"]
            unit = "secure-sandbox-native-run-" + session_id.replace("-", "") + ".scope"
            boot_sha256 = run_journal.boot_id_sha256(boot_id_path)
            executable_sha256 = authority["harness_binding"]["harness_executable_sha256"]
            session_lease = native_stack_session.validate_session_lease(
                prepared["session_lease"], now=timestamp, require_fresh=True)
            projection_authority = prepared["projection_authority"]

            def exact_projection_gate(
                gate_authority: object, gate_descriptor: object,
            ) -> str:
                expected_descriptor = policy.make_launch_descriptor(
                    gate_authority
                )
                if policy.validate_launch_descriptor(
                        gate_descriptor) != expected_descriptor:
                    raise NativeCodexSessionError(
                        "native_codex_projection_descriptor_changed"
                    )
                observation = native_projection_isolation.status_observation(
                    gate_authority, expected_descriptor
                )
                try:
                    matches = (
                        native_codex_projection
                        .projection_authority_matches_observation(
                            projection_authority,
                            operation_id=prepared["operation_id"],
                            request_sha256=prepared[
                                "operator_request_sha256"
                            ],
                            stack_sha256=prepared["stack_sha256"],
                            observation=_projection_observation_reply(
                                prepared["operation_id"], observation
                            ),
                            authority=gate_authority,
                            now=int(time.time()),
                        )
                    )
                except native_codex_projection.NativeCodexProjectionError as error:
                    raise NativeCodexSessionError(
                        "native_codex_projection_observation_invalid"
                    ) from error
                evidence = isolation.require_live_qualification(
                    gate_authority
                )
                if (not matches or evidence != projection_authority[
                        "qualification_evidence_sha256"]):
                    raise NativeCodexSessionError(
                        "native_codex_projection_qualification_changed"
                    )
                return evidence

            lease_started_at = session_lease["issued_at"]
            lease_expires_at = session_lease["expires_at"]
            run_journal.append_event(
                phase="prepared", transition_operation_id=operation_id,
                authority=authority, scope_unit=unit, process_id=None,
                process_start_time_ticks=None, boot_id_sha256=boot_sha256,
                executable_sha256=executable_sha256,
                session_lease=session_lease,
                lease_started_at=lease_started_at,
                lease_expires_at=lease_expires_at,
                observed_at=timestamp, exit_code=None,
                absence_evidence_sha256=None, root=journal_root,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
            process_id: int | None = None
            process_start: int | None = None

            def scoped(pid: int, observed_unit: str,
                       _readback: dict[str, object]) -> None:
                nonlocal process_id, process_start
                if observed_unit != unit:
                    raise NativeCodexSessionError(
                        "native_codex_journal_scope_mismatch")
                process_id = pid
                process_start = run_journal.process_start_time(
                    pid, proc_root=proc_root)
                run_journal.append_event(
                    phase="active", transition_operation_id=operation_id,
                    authority=authority, scope_unit=unit, process_id=pid,
                    process_start_time_ticks=process_start,
                    boot_id_sha256=boot_sha256,
                    executable_sha256=executable_sha256,
                    session_lease=session_lease,
                    lease_started_at=lease_started_at,
                    lease_expires_at=lease_expires_at,
                    observed_at=max(timestamp, int(time.time())), exit_code=None,
                    absence_evidence_sha256=None, root=journal_root,
                    trusted_uid=trusted_uid, trusted_gid=trusted_gid)

            try:
                pre_release_gate = options.pop(
                    "pre_release_qualification_gate",
                    exact_projection_gate,
                )
                result = _launch_and_wait_admitted(
                    authority, projection_id=prepared["projection_id"],
                    session_lease=session_lease,
                    access_token_sha256=prepared["access_token_sha256"],
                    input_fd=input_fd, now=timestamp, proc_root=proc_root,
                    expires_at_unix=prepared["expires_at"],
                    trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                    scope_observer=scoped,
                    pre_release_qualification_gate=pre_release_gate,
                    expected_qualification_evidence_sha256=(
                        projection_authority[
                            "qualification_evidence_sha256"
                        ]
                    ),
                    **options)
            except Exception:
                try:
                    egress = egress_closer()
                    absence = absence_prover(
                        session_id=session_id, scope_unit=unit,
                        process_id=process_id,
                        process_start_time_ticks=process_start,
                        egress_evidence_sha256=egress, proc_root=proc_root)
                    run_journal.append_event(
                        phase="terminal", transition_operation_id=operation_id,
                        authority=authority, scope_unit=unit,
                        process_id=process_id,
                        process_start_time_ticks=process_start,
                        boot_id_sha256=boot_sha256,
                        executable_sha256=executable_sha256,
                        session_lease=session_lease,
                        lease_started_at=lease_started_at,
                        lease_expires_at=lease_expires_at,
                        observed_at=max(timestamp, int(time.time())), exit_code=1,
                        absence_evidence_sha256=absence, root=journal_root,
                        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
                except Exception:
                    try:
                        run_journal.append_event(
                            phase="ambiguous",
                            transition_operation_id=operation_id,
                            authority=authority, scope_unit=unit,
                            process_id=process_id,
                            process_start_time_ticks=process_start,
                            boot_id_sha256=boot_sha256,
                            executable_sha256=executable_sha256,
                            session_lease=session_lease,
                            lease_started_at=lease_started_at,
                            lease_expires_at=lease_expires_at,
                            observed_at=max(timestamp, int(time.time())), exit_code=None,
                            absence_evidence_sha256=None, root=journal_root,
                            trusted_uid=trusted_uid, trusted_gid=trusted_gid)
                    except Exception:
                        pass
                raise
            try:
                egress = egress_closer()
                absence = absence_prover(
                    session_id=session_id, scope_unit=unit,
                    process_id=process_id,
                    process_start_time_ticks=process_start,
                    egress_evidence_sha256=egress, proc_root=proc_root)
                run_journal.append_event(
                    phase="terminal", transition_operation_id=operation_id,
                    authority=authority, scope_unit=unit, process_id=process_id,
                    process_start_time_ticks=process_start,
                    boot_id_sha256=boot_sha256,
                    executable_sha256=executable_sha256,
                    session_lease=session_lease,
                    lease_started_at=lease_started_at,
                    lease_expires_at=lease_expires_at,
                    observed_at=max(timestamp, int(time.time())), exit_code=result,
                    absence_evidence_sha256=absence, root=journal_root,
                    trusted_uid=trusted_uid, trusted_gid=trusted_gid)
            except Exception:
                try:
                    latest = run_journal.latest(
                        session_id, root=journal_root,
                        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
                    if latest["phase"] != "terminal":
                        run_journal.append_event(
                            phase="ambiguous",
                            transition_operation_id=operation_id,
                            authority=authority, scope_unit=unit,
                            process_id=process_id,
                            process_start_time_ticks=process_start,
                            boot_id_sha256=boot_sha256,
                            executable_sha256=executable_sha256,
                            session_lease=session_lease,
                            lease_started_at=lease_started_at,
                            lease_expires_at=lease_expires_at,
                            observed_at=max(timestamp, int(time.time())),
                            exit_code=None, absence_evidence_sha256=None,
                            root=journal_root, trusted_uid=trusted_uid,
                            trusted_gid=trusted_gid)
                except Exception:
                    pass
                raise
            return result
    except native_lifecycle_fence.NativeLifecycleFenceError as error:
        raise NativeCodexSessionError(str(error)) from error


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    try:
        if values in (["prepare"], ["stop"], ["status"]):
            raw = sys.stdin.buffer.read(MAX_PREPARE_BYTES + 1)
            if not 1 <= len(raw) <= MAX_PREPARE_BYTES:
                raise NativeCodexSessionError("native_codex_prepare_request_size_invalid")
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise NativeCodexSessionError(
                    "native_codex_prepare_request_invalid") from error
            if raw != _canonical(value):
                raise NativeCodexSessionError(
                    "native_codex_prepare_request_not_canonical")
            if values == ["prepare"]:
                reply = prepare_session(value)
            else:
                reply = session_control(value, status=values == ["status"])
            sys.stdout.buffer.write(_canonical(reply))
            sys.stdout.buffer.flush()
            return 0
        if (len(values) == 3 and values[0] == "launch"
                and UUID4.fullmatch(values[1]) is not None
                and SHA256.fullmatch(values[2]) is not None):
            return launch_prepared(values[1], values[2], input_fd=0)
        if (len(values) == 7 and values[0] == "ui"
                and UUID4.fullmatch(values[1]) is not None
                and all(SHA256.fullmatch(value) is not None
                        for value in values[2:6])
                and re.fullmatch(r"[1-9][0-9]{0,11}", values[6]) is not None):
            return relay_ui(
                session_id=values[1],
                runtime_authority_sha256=values[2],
                harness_generation_id=values[3],
                harness_executable_sha256=values[4],
                session_lease_sha256=values[5],
                session_expires_at=int(values[6]),
                input_fd=0, output_fd=1)
        return 64
    except (NativeCodexSessionError, policy.NativeCodexPolicyError,
            run_journal.NativeCodexRunJournalError,
            native_guest_control.NativeGuestControlError,
            OSError, subprocess.SubprocessError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
