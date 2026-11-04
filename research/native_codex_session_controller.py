#!/usr/bin/env python3
"""Root-only native Codex launch supervisor contract.

The Host credential bridge owns the token stream. This process never reads it:
the stream is duplicated directly onto C-launcher fd 5, consumed as one exact
binary projection frame, and closed before the admitted Codex exec. The only
credential-derived value accepted here is a SHA-256 digest used to mint one
root-owned, unlinked, read-only fd-3 permit.

Every launched process is owned by an exact transient systemd scope selected by
``native_guest_control`` during stop-bound-runs. The scope is lifetime-bound to
``native-harness-supervisor.service`` and independently read back through its
cgroup before the launch is accepted.
"""

from __future__ import annotations

import fcntl
import hashlib
import ctypes
import json
import os
import pwd
import re
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
            or not observed_at < value["expires_at"] <= observed_at + 120):
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


def verify_transient_scope(
    unit: str,
    *,
    launcher_uid: int,
    systemctl: Path = SYSTEMCTL,
    cgroup_root: Path = CGROUP_ROOT,
    proc_root: Path = Path("/proc"),
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    deadline_seconds: float = 5.0,
    expected_runtime_max_usec: int | None = None,
) -> dict[str, object]:
    """Require exact dependencies and launcher UID for every cgroup member."""
    if re.fullmatch(r"secure-sandbox-native-run-[0-9a-f]{32}\.scope", unit) is None:
        raise NativeCodexSessionError("native_codex_scope_name_invalid")
    if (expected_runtime_max_usec is not None
            and (not isinstance(expected_runtime_max_usec, int)
                 or isinstance(expected_runtime_max_usec, bool)
                 or not 1 <= expected_runtime_max_usec
                    <= MAX_NATIVE_SESSION_SECONDS * 1_000_000)):
        raise NativeCodexSessionError("native_codex_scope_runtime_invalid")
    deadline = time.monotonic() + deadline_seconds
    last_error = "native_codex_scope_unavailable"
    while time.monotonic() < deadline:
        result = runner(
            [str(systemctl), "show", unit,
             "--property=ActiveState,BindsTo,After,PartOf,ControlGroup,RuntimeMaxUSec"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=2,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        if result.returncode != 0 or len(result.stdout) > 16 * 1024:
            time.sleep(0.05)
            continue
        fields: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                name, content = line.split("=", 1)
                fields[name] = content
        dependency = "native-harness-supervisor.service"
        if (fields.get("ActiveState") != "active"
                or dependency not in fields.get("BindsTo", "").split()
                or dependency not in fields.get("After", "").split()
                or dependency not in fields.get("PartOf", "").split()):
            last_error = "native_codex_scope_dependency_invalid"
            time.sleep(0.05)
            continue
        if expected_runtime_max_usec is not None:
            try:
                observed_runtime_max_usec = int(fields.get(
                    "RuntimeMaxUSec", ""
                ))
            except ValueError:
                observed_runtime_max_usec = -1
            if observed_runtime_max_usec != expected_runtime_max_usec:
                last_error = "native_codex_scope_runtime_invalid"
                time.sleep(0.05)
                continue
        cgroup = fields.get("ControlGroup", "")
        if (not cgroup.startswith("/") or ".." in Path(cgroup).parts
                or not cgroup.endswith("/" + unit)):
            last_error = "native_codex_scope_cgroup_invalid"
            time.sleep(0.05)
            continue
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
                status = (proc_root / str(pid) / "status").read_text(
                    encoding="ascii")
                matches = [line for line in status.splitlines()
                           if line.startswith("Uid:")]
                values = matches[0].split()[1:] if len(matches) == 1 else []
                if len(values) != 4 or any(
                    int(value) != launcher_uid for value in values
                ):
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


def start_transient_scope(
    unit: str,
    pid: int,
    *,
    runtime_max_usec: int,
    busctl: Path = BUSCTL,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    """Atomically attach one already-stopped process to a transient scope."""
    if (re.fullmatch(r"secure-sandbox-native-run-[0-9a-f]{32}\.scope", unit) is None
            or not isinstance(pid, int) or pid <= 1
            or not isinstance(runtime_max_usec, int)
            or isinstance(runtime_max_usec, bool)
            or not 1 <= runtime_max_usec <= MAX_NATIVE_SESSION_SECONDS * 1_000_000):
        raise NativeCodexSessionError("native_codex_scope_request_invalid")
    dependency = "native-harness-supervisor.service"
    command = [
        str(busctl), "--system", "--quiet", "--timeout=5s", "call",
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartTransientUnit",
        "ssa(sv)a(sa(sv))", unit, "fail", "8",
        "PIDs", "au", "1", str(pid),
        "Description", "s", "SecureSandbox native vendor run",
        "BindsTo", "as", "1", dependency,
        "After", "as", "1", dependency,
        "PartOf", "as", "1", dependency,
        "KillMode", "s", "control-group",
        "CollectMode", "s", "inactive-or-failed",
        "RuntimeMaxUSec", "t", str(runtime_max_usec),
        "0",
    ]
    result = runner(
        command, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise NativeCodexSessionError("native_codex_scope_create_failed")


def _child_hardening() -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, 9, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG, SIGKILL
            raise OSError(ctypes.get_errno(), "prctl")


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
    scope_verifier: Callable[..., dict[str, object]] = verify_transient_scope,
    scope_starter: Callable[..., None] = start_transient_scope,
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
    the first-party driver; a separate private fd-6 receipt carries only the
    token digest, length, rolling fingerprint, and permit/session bindings.
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
            expires = issued + 60 if expires_at_unix is None else expires_at_unix
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
        if qualification_gate is None:
            def qualification_gate(
                _firewall_authority: object, live_descriptor: object,
            ) -> str:
                return pre_release_qualification_gate(
                    authority_value, live_descriptor
                )

        listener: socket.socket | None = None
        ui_connection: socket.socket | None = None
        app_input_read = app_input_write = -1
        app_output_read = app_output_write = -1
        app_stderr_read = app_stderr_write = -1
        receipt_read = receipt_write = -1
        child = -1
        try:
            listener = ui_listener_factory(
                control_root / UI_ROOT.name,
                session_id=descriptor["session_id"],
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
            app_input_read, app_input_write = os.pipe2(os.O_CLOEXEC)
            app_output_read, app_output_write = os.pipe2(os.O_CLOEXEC)
            app_stderr_read, app_stderr_write = os.pipe2(os.O_CLOEXEC)
            receipt_read, receipt_write = os.pipe2(os.O_CLOEXEC)
            child = os.fork()
            if child == 0:  # pragma: no cover - stopped exec-only child
                try:
                    _child_hardening()
                    os.setsid()
                    os.setgroups([])
                    os.setgid(identity.pw_gid)
                    os.setuid(identity.pw_uid)
                    bindings = (
                        (app_input_read, 0),
                        (app_output_write, 1),
                        (app_stderr_write, 2),
                        (permit_fd, policy.PROJECTION_PERMIT_FD),
                        (input_fd, policy.PROJECTION_FRAME_FD),
                        (receipt_write, policy.TOKEN_RECEIPT_FD),
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
                    os.closerange(7, maximum if maximum > 7 else 1024)
                    os.kill(os.getpid(), 19)  # SIGSTOP before any vendor exec
                    os.execve(launcher_path, [str(launcher_path)], {})
                except BaseException:
                    os._exit(126)
            os.close(permit_fd)
            permit_fd = -1
            for descriptor_to_close in (
                    app_input_read, app_output_write, app_stderr_write,
                    receipt_write, input_fd):
                os.close(descriptor_to_close)
            app_input_read = app_output_write = app_stderr_write = -1
            receipt_write = -1
            input_fd = -1
            waited, status = os.waitpid(child, os.WUNTRACED)
            if (waited != child or not os.WIFSTOPPED(status)
                    or os.WSTOPSIG(status) != 19):
                raise NativeCodexSessionError("native_codex_child_gate_failed")
            runtime_max_usec = int(
                max(1.0, (lease_deadline - time.monotonic()) * 1_000_000))
            scope_starter(
                unit, child, runtime_max_usec=runtime_max_usec,
                busctl=busctl_path)
            scope_readback = scope_verifier(
                unit, launcher_uid=identity.pw_uid,
                systemctl=systemctl_path, cgroup_root=cgroup_root,
                expected_runtime_max_usec=runtime_max_usec)
            if scope_observer is not None:
                scope_observer(child, unit, scope_readback)
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
            os.kill(child, 18)  # SIGCONT only after exact scope/UID readback
            remaining = lease_deadline - time.monotonic()
            if remaining <= 0:
                raise NativeCodexSessionError("native_codex_run_lease_expired")
            receipt = token_receipt_reader(
                receipt_read,
                timeout_seconds=min(UI_ATTACH_TIMEOUT_SECONDS, remaining))
            os.close(receipt_read)
            receipt_read = -1
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
                session_lease_sha256=validated_lease["lease_sha256"],
                session_expires_at=validated_lease["expires_at"],
                qualification_gate=qualification_gate,
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
            readback = subprocess.run(
                [str(systemctl_path), "is-active", unit], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if readback.returncode not in {3, 4} or readback.stdout.strip() == b"active":
                raise NativeCodexSessionError("native_codex_scope_teardown_ambiguous")
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
                    receipt_read, receipt_write):
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
                    input_fd=input_fd, now=timestamp,
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
            OSError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
