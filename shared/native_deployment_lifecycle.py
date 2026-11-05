#!/usr/bin/env python3
"""Shared durable lifecycle transaction for protected native deployment.

The installed Research controller and the one-time legacy bootstrap consumer
must publish byte-identical fence and release evidence.  This module owns that
small transaction.  Callers retain responsibility for holding the Research
install and egress barriers while invoking the locked entry points.
"""

from __future__ import annotations

import json
import os
import stat
import uuid
from typing import Any, Callable, Mapping


RELEASE_SCHEMA = "secure-sandbox-native-deployment-fence-release-v1"
MAX_RECORD_BYTES = 1024 * 1024


class NativeDeploymentLifecycleError(RuntimeError):
    """Stable fail-closed deployment-lifecycle error."""


def _terminal_name(deployment_id: str) -> str:
    if not isinstance(deployment_id, str):
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_deployment_id_invalid")
    try:
        parsed = uuid.UUID(deployment_id)
    except ValueError as error:
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_deployment_id_invalid") from error
    if parsed.version != 4 or str(parsed) != deployment_id:
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_deployment_id_invalid")
    return f"deployment-fence.{deployment_id}.released.json"


def _terminal(
    request: Mapping[str, Any], fence_sha256: str, evidence_sha256: str,
    *, deployment: Any,
) -> dict[str, Any]:
    plan = request["plan"]
    for value in (fence_sha256, evidence_sha256):
        if not isinstance(value, str) or deployment.SHA256.fullmatch(value) is None:
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_digest_invalid")
    body = {
        "deployment_id": plan["deployment_id"],
        "plan_sha256": plan["plan_sha256"],
        "fence_sha256": fence_sha256,
        "release_request_sha256": request["request_sha256"],
        "release_evidence_sha256": evidence_sha256,
    }
    return {
        "schema": RELEASE_SCHEMA,
        **body,
        "terminal_sha256": deployment.digest(body),
    }


def _validate_terminal(
    value: object, request: Mapping[str, Any], fence_sha256: str,
    *, deployment: Any,
) -> dict[str, Any]:
    fields = {
        "schema", "deployment_id", "plan_sha256", "fence_sha256",
        "release_request_sha256", "release_evidence_sha256",
        "terminal_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_terminal_invalid")
    expected = _terminal(
        request, fence_sha256, value.get("release_evidence_sha256", ""),
        deployment=deployment)
    if value != expected:
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_terminal_invalid")
    return value


def _read_terminal(
    root_fd: int, name: str, *, deployment: Any,
    trusted_uid: int, trusted_gid: int,
) -> dict[str, Any] | None:
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if before.st_nlink == 2:
            pending_name = f".{name}.pending"
            try:
                pending_fd = os.open(
                    pending_name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_fd)
            except OSError as error:
                raise NativeDeploymentLifecycleError(
                    "native_deployment_lifecycle_terminal_untrusted") from error
            try:
                pending_info = os.fstat(pending_fd)
            finally:
                os.close(pending_fd)
            if (
                not stat.S_ISREG(pending_info.st_mode)
                or pending_info.st_uid != trusted_uid
                or pending_info.st_gid != trusted_gid
                or stat.S_IMODE(pending_info.st_mode) != 0o600
                or (pending_info.st_dev, pending_info.st_ino)
                   != (before.st_dev, before.st_ino)
            ):
                raise NativeDeploymentLifecycleError(
                    "native_deployment_lifecycle_terminal_untrusted")
            os.unlink(pending_name, dir_fd=root_fd)
            os.fsync(root_fd)
            before = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_RECORD_BYTES:
            block = os.read(
                descriptor, min(65536, MAX_RECORD_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != trusted_uid
        or before.st_gid != trusted_gid
        or stat.S_IMODE(before.st_mode) != 0o600
        or len(raw) != before.st_size
        or len(raw) > MAX_RECORD_BYTES
        or identity(before) != identity(after)
    ):
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_terminal_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_terminal_invalid") from error
    if not isinstance(value, dict) or bytes(raw) != deployment.canonical(value):
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_terminal_invalid")
    return value


def _publish_terminal(
    root_fd: int, name: str, value: Mapping[str, Any], *, deployment: Any,
    trusted_uid: int, trusted_gid: int,
    crash_hook: Callable[[str], None],
) -> None:
    payload = deployment.canonical(value)
    existing = _read_terminal(
        root_fd, name, deployment=deployment,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if existing is not None:
        if existing != dict(value):
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_terminal_collision")
        return
    temporary = f".{name}.pending"
    descriptor = -1
    linked = False
    try:
        try:
            stale = os.open(
                temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd)
        except FileNotFoundError:
            stale = -1
        if stale >= 0:
            try:
                info = os.fstat(stale)
                raw = os.read(stale, MAX_RECORD_BYTES + 1)
            finally:
                os.close(stale)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != trusted_uid
                or info.st_gid != trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or raw != payload
                or len(raw) != info.st_size
            ):
                raise NativeDeploymentLifecycleError(
                    "native_deployment_lifecycle_terminal_pending_ambiguous")
            os.unlink(temporary, dir_fd=root_fd)
            os.fsync(root_fd)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600, dir_fd=root_fd)
        os.fchown(descriptor, trusted_uid, trusted_gid)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise NativeDeploymentLifecycleError(
                    "native_deployment_lifecycle_terminal_write_failed")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(
            temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd,
            follow_symlinks=False)
        linked = True
        os.fsync(root_fd)
        crash_hook("terminal-linked")
        os.unlink(temporary, dir_fd=root_fd)
        linked = False
        os.fsync(root_fd)
        crash_hook("terminal-pending-removed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not linked:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass


def _preconditions(
    request: Mapping[str, Any], *, catalog_sha256: str,
    live_run_count: int, deployment: Any,
) -> None:
    if (
        not isinstance(catalog_sha256, str)
        or deployment.SHA256.fullmatch(catalog_sha256) is None
        or catalog_sha256 != request["plan"]["catalog_sha256"]
    ):
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_catalog_mismatch")
    if (
        not isinstance(live_run_count, int)
        or isinstance(live_run_count, bool)
        or live_run_count != 0
    ):
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_busy")


def acquire_locked(
    value: object, lifecycle_fd: int, *, catalog_sha256: str,
    live_run_count: int, deployment: Any, fence: Any,
    trusted_uid: int = 0, trusted_gid: int = 0,
    now: int | None = None,
) -> dict[str, Any]:
    """Acquire or replay one exact deployment fence under its lock."""
    try:
        if not isinstance(value, Mapping) or set(value) != {
            "schema", "plan", "request_sha256"
        }:
            raise ValueError("request-fields")
        plan = deployment.validate_plan(
            value.get("plan"), now=now, require_fresh=False)
        request = deployment.make_fence_request(plan)
        if dict(value) != request:
            raise ValueError("request-digest")
        identity = deployment.fence_identity(request["plan"])
    except Exception as error:
        if isinstance(error, NativeDeploymentLifecycleError):
            raise
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_request_invalid") from error
    _preconditions(
        request, catalog_sha256=catalog_sha256,
        live_run_count=live_run_count, deployment=deployment)
    try:
        terminal = _read_terminal(
            lifecycle_fd, _terminal_name(request["plan"]["deployment_id"]),
            deployment=deployment, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        if terminal is not None:
            release_request = deployment.make_release_request(request["plan"])
            _validate_terminal(
                terminal, release_request, terminal.get("fence_sha256", ""),
                deployment=deployment)
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_already_released")
        existing = fence.read_locked(
            lifecycle_fd, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        if existing is None:
            # Freshness is authority to create state.  Once the exact fence is
            # durable, an identical retry remains valid after plan expiry so a
            # lost transport response cannot strand the deployment forever.
            deployment.validate_fence_request(value, now=now)
        fence_sha256 = fence.acquire_locked(
            lifecycle_fd, **identity, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
    except Exception as error:
        if isinstance(error, NativeDeploymentLifecycleError):
            raise
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_fence_rejected") from error
    evidence = deployment.digest({
        "deployment_id": request["plan"]["deployment_id"],
        "plan_sha256": request["plan"]["plan_sha256"],
        "fence_sha256": fence_sha256,
        "catalog_sha256": catalog_sha256,
        "live_run_count": 0,
        "state": "fenced",
    })
    return {
        "schema": deployment.FENCE_REPLY_SCHEMA,
        "deployment_id": request["plan"]["deployment_id"],
        "plan_sha256": request["plan"]["plan_sha256"],
        "fence_sha256": fence_sha256,
        "catalog_sha256": catalog_sha256,
        "state": "fenced",
        "evidence_sha256": evidence,
    }


def recovery_acquire_locked(
    value: object, lifecycle_fd: int, *, catalog_sha256: str,
    live_run_count: int, deployment: Any, fence: Any,
    trusted_uid: int = 0, trusted_gid: int = 0,
    now: int | None = None,
) -> dict[str, Any]:
    """Acquire/replay only under exact fresh Touch-ID recovery authority."""
    try:
        request = deployment.validate_recovery_fence_request(
            value, now=now, require_fresh=False)
        plan = request["plan"]
        identity = deployment.fence_identity(plan)
    except Exception as error:
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_recovery_request_invalid") from error
    _preconditions(
        request, catalog_sha256=catalog_sha256,
        live_run_count=live_run_count, deployment=deployment)
    try:
        terminal = _read_terminal(
            lifecycle_fd, _terminal_name(plan["deployment_id"]),
            deployment=deployment, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        if terminal is not None:
            release_request = deployment.make_release_request(plan)
            _validate_terminal(
                terminal, release_request, terminal.get("fence_sha256", ""),
                deployment=deployment)
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_already_released")
        existing = fence.read_locked(
            lifecycle_fd, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        if existing is None:
            deployment.validate_recovery_fence_request(
                value, now=now, require_fresh=True)
        fence_sha256 = fence.acquire_locked(
            lifecycle_fd, **identity, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
    except Exception as error:
        if isinstance(error, NativeDeploymentLifecycleError):
            raise
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_recovery_fence_rejected") from error
    evidence = deployment.digest({
        "deployment_id": plan["deployment_id"],
        "plan_sha256": plan["plan_sha256"],
        "fence_sha256": fence_sha256,
        "catalog_sha256": catalog_sha256,
        "live_run_count": 0,
        "state": "fenced",
    })
    return {
        "schema": deployment.FENCE_REPLY_SCHEMA,
        "deployment_id": plan["deployment_id"],
        "plan_sha256": plan["plan_sha256"],
        "fence_sha256": fence_sha256,
        "catalog_sha256": catalog_sha256,
        "state": "fenced",
        "evidence_sha256": evidence,
    }


def release_locked(
    value: object, lifecycle_fd: int, *, catalog_sha256: str,
    live_run_count: int, deployment: Any, fence: Any,
    trusted_uid: int = 0, trusted_gid: int = 0,
    now: int | None = None,
    crash_hook: Callable[[str], None] = lambda _phase: None,
) -> dict[str, Any]:
    """Publish an immutable terminal before retiring one exact fence."""
    try:
        request = deployment.validate_release_request(value, now=now)
        identity = deployment.fence_identity(request["plan"])
    except Exception as error:
        if isinstance(error, NativeDeploymentLifecycleError):
            raise
        raise NativeDeploymentLifecycleError(
            "native_deployment_lifecycle_release_request_invalid") from error
    _preconditions(
        request, catalog_sha256=catalog_sha256,
        live_run_count=live_run_count, deployment=deployment)
    name = _terminal_name(request["plan"]["deployment_id"])
    existing_fence = fence.read_locked(
        lifecycle_fd, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    terminal = _read_terminal(
        lifecycle_fd, name, deployment=deployment,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if existing_fence is None:
        if terminal is None:
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_release_evidence_missing")
        terminal = _validate_terminal(
            terminal, request, terminal.get("fence_sha256", ""),
            deployment=deployment)
        evidence = terminal["release_evidence_sha256"]
    else:
        try:
            fence_sha256 = fence.acquire_locked(
                lifecycle_fd, **identity, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            expected_evidence = fence.release_evidence(existing_fence)
        except Exception as error:
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_release_fence_rejected") from error
        expected = _terminal(
            request, fence_sha256, expected_evidence,
            deployment=deployment)
        if terminal is None:
            _publish_terminal(
                lifecycle_fd, name, expected, deployment=deployment,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                crash_hook=crash_hook)
            terminal = expected
            crash_hook("terminal-published")
        else:
            terminal = _validate_terminal(
                terminal, request, fence_sha256, deployment=deployment)
            if terminal != expected:
                raise NativeDeploymentLifecycleError(
                    "native_deployment_lifecycle_terminal_mismatch")
        try:
            evidence = fence.release_locked(
                lifecycle_fd, **identity, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
        except Exception as error:
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_release_failed") from error
        if evidence != expected_evidence:
            raise NativeDeploymentLifecycleError(
                "native_deployment_lifecycle_release_evidence_mismatch")
        crash_hook("fence-released")
    return {
        "schema": deployment.RELEASE_REPLY_SCHEMA,
        "deployment_id": request["plan"]["deployment_id"],
        "plan_sha256": request["plan"]["plan_sha256"],
        "state": "released",
        "evidence_sha256": evidence,
        "terminal_sha256": terminal["terminal_sha256"],
    }
