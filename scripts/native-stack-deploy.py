#!/usr/bin/env python3
"""Touch-ID-authorized, crash-recoverable native guest deployment driver.

The installed immutable Host release is the only source of executable code,
SSH policy, and guest payloads.  Every mutation is preceded by a durable
hash-chained journal record; transport completion is never outcome evidence.
Only a subsequent authenticated, exact guest probe may advance the workflow.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from types import ModuleType
from pathlib import Path
from typing import Any, Callable, Mapping


HERE = Path(__file__).resolve().parent
SUPPORT = HERE / "native_stack_support"
native_deployment: Any | None = None
native_vendor_stack: Any | None = None
native_deployment_payload: Any | None = None
_active_support_identity: tuple[str, str] | None = None
SAFE_PAYLOAD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
STATE_ROOT = Path("/usr/local/var/lib/secure-sandbox/native-deployment")
CATALOG = Path(
    "/usr/local/var/lib/secure-sandbox/native-stack-catalog/catalog.json")
INSTALL_TRANSITION_PENDING_NAME = ".install-transition.json"
COORDINATION_CONTRACT_NAME = "native_stack_coordination_contract"
COORDINATION_CONTRACT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-contract-v1"
)
COORDINATION_FLOOR_NAME = "native-stack-coordination-minimum.json"
COORDINATION_FLOOR_SCHEMA = (
    "secure-sandbox-native-stack-coordination-minimum-v1"
)
COORDINATION_ENFORCEMENT_NAME = "native-stack-coordination-enforcement.json"
COORDINATION_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-enforcement-v1"
)
COORDINATION_REQUIRED_FEATURES = {
    "catalog-promotion-gate-v1",
    "deployment-promotion-admission-v1",
    "host-install-transition-fence-v1",
    "host-selector-two-way-gate-v1",
}
RECEIPTS = Path("/usr/local/var/log/secure-sandbox/authorization-receipts")
JOURNAL_SCHEMA = "secure-sandbox-native-deployment-journal-record-v1"
ACTIVE_SCHEMA = "secure-sandbox-native-deployment-active-v1"
PLAN_RESPONSE_SCHEMA = "secure-sandbox-native-deployment-plan-response-v1"
PUBLIC_STATUS_SCHEMA = "secure-sandbox-native-deployment-public-status-v1"
RECOVERY_PLAN_SCHEMA = "secure-sandbox-native-deployment-recovery-plan-v1"
GATE_STATE_SCHEMA = "secure-sandbox-native-deployment-gate-state-v1"
TERMINAL_PHASES = {"committed", "rolled-back"}
PHASES = {
    "authorized", "fence-requested", "fenced", "gateway-requested",
    "gateway-observed", "research-requested", "research-observed",
    "recovery-observed",
    "compensation-requested", "compensation-observed", "release-requested",
    "release-observed", "committed", "rolled-back",
    "recovery-required",
}
TRANSITIONS = {
    None: {"authorized"},
    "authorized": {"fence-requested", "recovery-required"},
    "fence-requested": {"fenced", "recovery-required"},
    "fenced": {
        "gateway-requested", "release-requested", "recovery-observed",
        "recovery-required"},
    "recovery-observed": {
        "gateway-requested", "research-requested", "compensation-requested",
        "release-requested", "recovery-required"},
    "gateway-requested": {"gateway-observed", "recovery-required"},
    "gateway-observed": {
        "research-requested", "release-requested", "recovery-required"},
    "research-requested": {
        "research-observed", "compensation-requested", "recovery-required"},
    "research-observed": {"release-requested", "compensation-requested",
                            "recovery-required"},
    "compensation-requested": {"compensation-observed", "recovery-required"},
    "compensation-observed": {"release-requested", "recovery-required"},
    "release-requested": {"release-observed", "recovery-required"},
    "release-observed": {"committed", "rolled-back", "recovery-required"},
    "recovery-required": {
        "fence-requested", "gateway-requested", "research-requested",
        "compensation-requested", "release-requested", "recovery-required"},
    "committed": set(), "rolled-back": set(),
}
EVIDENCE_FIELDS = {
    "gateway_status", "research_status",
    "gateway_status_sha256", "research_status_sha256",
    "fence_evidence_sha256", "result_sha256", "terminal_sha256", "outcome",
}
OUTCOMES = {
    "authorized", "requested", "fenced", "prior-prior", "candidate-prior",
    "candidate-candidate", "released", "committed", "rolled-back",
    "transport-ambiguous", "recovery-required",
}
PHASE_OUTCOMES = {
    "authorized": {"authorized"},
    "fence-requested": {"requested"},
    "fenced": {"fenced"},
    "gateway-requested": {"requested"},
    "gateway-observed": {
        "prior-prior", "candidate-prior", "candidate-candidate"},
    "research-requested": {"requested"},
    "research-observed": {
        "prior-prior", "candidate-prior", "candidate-candidate"},
    "recovery-observed": {
        "prior-prior", "candidate-prior", "candidate-candidate"},
    "compensation-requested": {"requested"},
    "compensation-observed": {"prior-prior"},
    "release-requested": {"requested"},
    "release-observed": {"prior-prior", "candidate-candidate"},
    "committed": {"committed"},
    "rolled-back": {"rolled-back"},
    "recovery-required": {"transport-ambiguous", "recovery-required"},
}
REQUEST_PHASES = {
    "fence-requested", "gateway-requested", "research-requested",
    "compensation-requested", "release-requested",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_JSON = 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
PROCESS_GROUP_ENV = "SECURE_SANDBOX_OWNED_PROCESS_GROUP"


class NativeStackDeployError(RuntimeError):
    """Stable fail-closed Host deployment error."""


def _activate_support(
    path: Path, expected_sha256: str, *, expected_uid: int = 0,
) -> None:
    global native_deployment, native_vendor_stack, native_deployment_payload
    global _active_support_identity
    identity = (str(path.resolve()), expected_sha256)
    if native_deployment is not None:
        if _active_support_identity != identity:
            raise NativeStackDeployError(
                "native_deployment_support_generation_changed")
        return
    raw = _release_file(
        path, expected_uid=expected_uid, expected_mode=0o444)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise NativeStackDeployError(
            "native_deployment_support_identity_mismatch")
    sys.path.insert(0, str(path))
    try:
        for name in (
            "native_deployment_payload", "shared.native_deployment",
            "shared.native_vendor_stack", "shared",
        ):
            sys.modules.pop(name, None)
        native_deployment = importlib.import_module("shared.native_deployment")
        native_vendor_stack = importlib.import_module(
            "shared.native_vendor_stack")
        native_deployment_payload = importlib.import_module(
            "native_deployment_payload")
        for module in (
            native_deployment, native_vendor_stack,
            native_deployment_payload,
        ):
            origin = str(getattr(module, "__file__", ""))
            if not origin.startswith(str(path) + "/"):
                raise NativeStackDeployError(
                    "native_deployment_support_origin_invalid")
        _active_support_identity = identity
    except Exception as error:
        native_deployment = None
        native_vendor_stack = None
        native_deployment_payload = None
        _active_support_identity = None
        try:
            sys.path.remove(str(path))
        except ValueError:
            pass
        raise NativeStackDeployError(
            "native_deployment_support_unavailable") from error


def canonical(value: object) -> bytes:
    try:
        return (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeStackDeployError(
            "native_deployment_value_invalid") from error


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_canonical(raw: bytes, label: str) -> dict[str, Any]:
    if not 2 <= len(raw) <= MAX_JSON:
        raise NativeStackDeployError(f"native_deployment_{label}_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackDeployError(
            f"native_deployment_{label}_invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise NativeStackDeployError(f"native_deployment_{label}_invalid")
    return value


def _coordination_contract(raw: bytes) -> dict[str, Any]:
    value = read_canonical(raw, "coordination_contract")
    features = value.get("features")
    epoch = value.get("epoch")
    if (
        set(value) != {"schema", "epoch", "features"}
        or value.get("schema") != COORDINATION_CONTRACT_SCHEMA
        or not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1
        or not isinstance(features, list)
        or any(
            not isinstance(feature, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", feature) is None
            for feature in features
        )
        or features != sorted(set(features))
        or not COORDINATION_REQUIRED_FEATURES <= set(features)
    ):
        raise NativeStackDeployError(
            "native_deployment_coordination_contract_invalid")
    return value


def _coordination_floor(raw: bytes) -> dict[str, Any]:
    value = read_canonical(raw, "coordination_floor")
    if (
        set(value) != {
            "schema", "minimum_epoch", "established_from_release_id",
            "established_from_contract_sha256",
        }
        or value.get("schema") != COORDINATION_FLOOR_SCHEMA
        or not isinstance(value.get("minimum_epoch"), int)
        or isinstance(value.get("minimum_epoch"), bool)
        or value["minimum_epoch"] < 1
        or SHA256.fullmatch(str(value.get(
            "established_from_release_id"))) is None
        or SHA256.fullmatch(str(value.get(
            "established_from_contract_sha256"))) is None
    ):
        raise NativeStackDeployError(
            "native_deployment_coordination_floor_invalid")
    return value


def _coordination_enforcement(raw: bytes) -> dict[str, Any]:
    value = read_canonical(raw, "coordination_enforcement")
    features = value.get("minimum_features")
    if (
        set(value) != {
            "schema", "minimum_epoch", "minimum_features",
            "authoritative_floor_sha256",
        }
        or value.get("schema") != COORDINATION_ENFORCEMENT_SCHEMA
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
        or not COORDINATION_REQUIRED_FEATURES <= set(features)
        or SHA256.fullmatch(str(value.get(
            "authoritative_floor_sha256"))) is None
    ):
        raise NativeStackDeployError(
            "native_deployment_coordination_enforcement_invalid")
    return value


def _trusted_directory(
    path: Path, *, create: bool = False,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != trusted_uid
            or parent.st_mode & 0o022
        ):
            raise NativeStackDeployError(
                "native_deployment_state_parent_untrusted")
        os.mkdir(path, 0o700)
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != trusted_uid
        or info.st_gid != trusted_gid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise NativeStackDeployError("native_deployment_state_root_untrusted")


def _atomic_file(
    path: Path, raw: bytes, *,
    crash_hook: Callable[[str], None] = lambda _phase: None,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    _trusted_directory(
        path.parent, create=True, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid)
    parent_fd = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | os.O_CLOEXEC)
    parent_info = os.fstat(parent_fd)
    current_parent = path.parent.lstat()
    if (
        (parent_info.st_dev, parent_info.st_ino)
        != (current_parent.st_dev, current_parent.st_ino)
    ):
        os.close(parent_fd)
        raise NativeStackDeployError(
            "native_deployment_atomic_parent_changed")
    temporary_name = f".{path.name}.pending"
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                temporary_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            descriptor = os.open(
                temporary_name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd)
            existing = os.read(descriptor, MAX_JSON + 1)
            if existing != raw or read_canonical(
                existing, "atomic_pending"
            ) is None:
                raise NativeStackDeployError(
                    "native_deployment_atomic_pending_mismatch")
        else:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o600)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise NativeStackDeployError(
                        "native_deployment_atomic_write_failed")
                view = view[count:]
            os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
            or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise NativeStackDeployError(
                "native_deployment_atomic_pending_untrusted")
        crash_hook("atomic-temp-fsynced")
        named = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise NativeStackDeployError(
                "native_deployment_atomic_pending_changed")
        os.replace(
            temporary_name, path.name,
            src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        published = os.stat(
            path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (
            published.st_dev, published.st_ino
        ):
            raise NativeStackDeployError(
                "native_deployment_atomic_publication_changed")
        crash_hook("atomic-replaced")
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _exclusive_file(
    path: Path, raw: bytes, *, idempotent: bool = False,
    crash_hook: Callable[[str], None] = lambda _phase: None,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    _trusted_directory(
        path.parent, create=True, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid)
    parent_fd = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | os.O_CLOEXEC)
    parent_info = os.fstat(parent_fd)
    current_parent = path.parent.lstat()
    if (
        (parent_info.st_dev, parent_info.st_ino)
        != (current_parent.st_dev, current_parent.st_ino)
    ):
        os.close(parent_fd)
        raise NativeStackDeployError(
            "native_deployment_exclusive_parent_changed")
    temporary_name = f".{path.name}.pending"
    descriptor = -1
    published = False
    try:
        try:
            descriptor = os.open(
                temporary_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            descriptor = os.open(
                temporary_name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd)
            existing = os.read(descriptor, MAX_JSON + 1)
            if existing != raw:
                raise NativeStackDeployError(
                    "native_deployment_exclusive_pending_mismatch")
            read_canonical(existing, "exclusive_pending")
        else:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o600)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise NativeStackDeployError(
                        "native_deployment_journal_write_failed")
                view = view[count:]
            os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
            or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise NativeStackDeployError(
                "native_deployment_exclusive_pending_untrusted")
        crash_hook("exclusive-temp-fsynced")
        named = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise NativeStackDeployError(
                "native_deployment_exclusive_pending_changed")
        try:
            os.link(
                temporary_name, path.name,
                src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                follow_symlinks=False)
            published = True
        except FileExistsError:
            if not idempotent:
                raise
            existing = _trusted_json(
                path, "exclusive_replay", trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            if canonical(existing) != raw:
                raise NativeStackDeployError(
                    "native_deployment_exclusive_replay_mismatch")
        crash_hook("exclusive-linked")
        if published:
            final_info = os.stat(
                path.name, dir_fd=parent_fd, follow_symlinks=False)
            pending_info = os.stat(
                temporary_name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                (opened.st_dev, opened.st_ino)
                != (final_info.st_dev, final_info.st_ino)
                or (opened.st_dev, opened.st_ino)
                != (pending_info.st_dev, pending_info.st_ino)
                or final_info.st_nlink != 2 or pending_info.st_nlink != 2
            ):
                raise NativeStackDeployError(
                    "native_deployment_exclusive_publication_changed")
        os.fsync(parent_fd)
        pending_info = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (
            pending_info.st_dev, pending_info.st_ino
        ):
            raise NativeStackDeployError(
                "native_deployment_exclusive_pending_changed")
        os.unlink(temporary_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        crash_hook("exclusive-temp-unlinked")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _trusted_json(
    path: Path, label: str, *, trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeStackDeployError(
            f"native_deployment_{label}_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, MAX_JSON + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != trusted_uid
        or opened.st_gid != trusted_gid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or len(raw) != opened.st_size
    ):
        raise NativeStackDeployError(f"native_deployment_{label}_untrusted")
    return read_canonical(raw, label)


class Journal:
    """Immutable hash chain plus one atomically replaced active pointer."""

    def __init__(
        self, root: Path = STATE_ROOT, *,
        crash_hook: Callable[[str], None] = lambda _phase: None,
        trusted_uid: int = 0, trusted_gid: int = 0,
        host_install_fd: int = -1,
        host_install_root: Path = INSTALL_ROOT,
    ):
        self.root = root
        self.active = root / "active.json"
        self.lock_path = root / "state.lock"
        self.crash_hook = crash_hook
        self.trusted_uid = trusted_uid
        self.trusted_gid = trusted_gid
        self.host_install_fd = host_install_fd
        self.host_install_root = host_install_root
        self.state_lock_fd = -1
        self.read_only_absent = False

    def _require_host_locked(self) -> None:
        if self.host_install_fd < 0:
            raise NativeStackDeployError("native_deployment_lock_order_invalid")
        host = os.fstat(self.host_install_fd)
        host_current = self.host_install_root.lstat()
        if (
            not stat.S_ISDIR(host.st_mode)
            or stat.S_ISLNK(host_current.st_mode)
            or (host.st_dev, host.st_ino)
            != (host_current.st_dev, host_current.st_ino)
        ):
            raise NativeStackDeployError("native_deployment_lock_identity_changed")

    def _require_locked(self) -> None:
        self._require_host_locked()
        if self.state_lock_fd < 0:
            raise NativeStackDeployError("native_deployment_lock_order_invalid")
        opened = os.fstat(self.state_lock_fd)
        current = self.lock_path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != self.trusted_uid
            or opened.st_gid != self.trusted_gid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_ISLNK(current.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (current.st_dev, current.st_ino)
        ):
            raise NativeStackDeployError("native_deployment_lock_identity_changed")

    def lock(self, *, create: bool = True) -> int:
        self._require_host_locked()
        if not create and not self.root.exists() and not self.root.is_symlink():
            self.read_only_absent = True
            return -1
        self.read_only_absent = False
        _trusted_directory(
            self.root, create=create, trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        try:
            if create:
                descriptor = os.open(
                    self.lock_path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600,
                )
                os.fchown(descriptor, self.trusted_uid, self.trusted_gid)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                directory = os.open(
                    self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            else:
                descriptor = os.open(
                    self.lock_path,
                    os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileExistsError:
            descriptor = os.open(
                self.lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise NativeStackDeployError(
                "native_deployment_state_lock_unavailable") from error
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != self.trusted_uid
            or info.st_gid != self.trusted_gid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise NativeStackDeployError("native_deployment_state_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self.state_lock_fd = descriptor
        return descriptor

    def promote(self) -> None:
        """Create the journal authority only after apply admission succeeds."""
        self._require_host_locked()
        if self.state_lock_fd >= 0:
            self._require_locked()
            return
        if not self.read_only_absent:
            raise NativeStackDeployError(
                "native_deployment_journal_promotion_invalid")
        if self.root.exists() or self.root.is_symlink():
            raise NativeStackDeployError(
                "native_deployment_journal_promotion_changed")
        self.lock(create=True)

    def unlock(self) -> None:
        if self.state_lock_fd >= 0:
            fcntl.flock(self.state_lock_fd, fcntl.LOCK_UN)
            os.close(self.state_lock_fd)
            self.state_lock_fd = -1
        self.read_only_absent = False

    def transaction_root(self, deployment_id: str, *, create: bool = True) -> Path:
        if create:
            self._require_locked()
        native_deployment._uuid4(deployment_id, "deployment_id")
        root = self.root / "transactions"
        _trusted_directory(
            root, create=create, trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        path = root / deployment_id
        existed = path.exists() or path.is_symlink()
        _trusted_directory(
            path, create=create, trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        if create and not existed:
            self.crash_hook("transaction-root-created")
        return path

    def _state_inventory(self) -> list[Path]:
        _trusted_directory(
            self.root, create=True, trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        entries = sorted(self.root.iterdir())
        if len(entries) > 4 or any(
            item.name not in {
                "state.lock", "active.json", ".active.json.pending",
                "transactions",
            }
            for item in entries
        ):
            raise NativeStackDeployError("native_deployment_state_inventory_invalid")
        transactions = self.root / "transactions"
        if not transactions.exists():
            if transactions.is_symlink():
                raise NativeStackDeployError(
                    "native_deployment_transaction_root_untrusted")
            return []
        _trusted_directory(
            transactions, trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        roots = sorted(transactions.iterdir())
        # This bounded immutable history accommodates decades of ordinary use
        # without silently deleting attestable transaction evidence.
        if len(roots) > 4096:
            raise NativeStackDeployError("native_deployment_transaction_limit")
        for root in roots:
            native_deployment._uuid4(root.name, "deployment_id")
            _trusted_directory(
                root, trusted_uid=self.trusted_uid,
                trusted_gid=self.trusted_gid)
            if len(list(root.iterdir())) > 256:
                raise NativeStackDeployError("native_deployment_record_limit")
        return roots

    def _pointer(self, path: Path) -> dict[str, Any]:
        pointer = _trusted_json(
            path, "active", trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        if set(pointer) != {
            "schema", "deployment_id", "sequence", "record_sha256",
            "host_release_id", "active_sha256"
        }:
            raise NativeStackDeployError("native_deployment_active_invalid")
        body = {key: item for key, item in pointer.items()
                if key not in {"schema", "active_sha256"}}
        if (
            pointer["schema"] != ACTIVE_SCHEMA
            or pointer["active_sha256"] != digest(body)
            or not isinstance(pointer["sequence"], int)
            or isinstance(pointer["sequence"], bool)
            or pointer["sequence"] < 0
            or SHA256.fullmatch(str(pointer["record_sha256"])) is None
            or SHA256.fullmatch(str(pointer["host_release_id"])) is None
        ):
            raise NativeStackDeployError("native_deployment_active_invalid")
        native_deployment._uuid4(pointer["deployment_id"], "deployment_id")
        return pointer

    def _publish_pointer_for_record(self, record: Mapping[str, Any]) -> None:
        self._require_locked()
        body = {
            "deployment_id": record["deployment_id"],
            "sequence": record["sequence"],
            "record_sha256": record["record_sha256"],
            "host_release_id": record["host_release_id"],
        }
        pointer = {"schema": ACTIVE_SCHEMA, **body, "active_sha256": digest(body)}
        _atomic_file(
            self.active, canonical(pointer), crash_hook=self.crash_hook,
            trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid)

    def _reconcile_pending_link(self, pending: Path, final: Path) -> None:
        self._require_locked()
        parent_fd = os.open(
            pending.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | os.O_CLOEXEC)
        pending_fd = -1
        try:
            pending_fd = os.open(
                pending.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd)
            pending_info = os.fstat(pending_fd)
            try:
                final_info = os.stat(
                    final.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                final_info = None
            if final_info is not None:
                if (
                    not stat.S_ISREG(pending_info.st_mode)
                    or not stat.S_ISREG(final_info.st_mode)
                    or pending_info.st_uid != self.trusted_uid
                    or pending_info.st_gid != self.trusted_gid
                    or stat.S_IMODE(pending_info.st_mode) != 0o600
                    or pending_info.st_nlink != 2
                    or final_info.st_nlink != 2
                    or (pending_info.st_dev, pending_info.st_ino)
                    != (final_info.st_dev, final_info.st_ino)
                ):
                    raise NativeStackDeployError(
                        "native_deployment_pending_record_mismatch")
            else:
                if (
                    not stat.S_ISREG(pending_info.st_mode)
                    or pending_info.st_uid != self.trusted_uid
                    or pending_info.st_gid != self.trusted_gid
                    or pending_info.st_nlink != 1
                    or stat.S_IMODE(pending_info.st_mode) != 0o600
                ):
                    raise NativeStackDeployError(
                        "native_deployment_pending_record_mismatch")
            raw = os.read(pending_fd, MAX_JSON + 1)
            after = os.fstat(pending_fd)
            if (
                (pending_info.st_dev, pending_info.st_ino,
                 pending_info.st_size, pending_info.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns)
                or len(raw) != after.st_size
            ):
                raise NativeStackDeployError(
                    "native_deployment_pending_record_mismatch")
            read_canonical(raw, "pending_record")
            if final_info is None:
                current = os.stat(
                    pending.name, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (
                    pending_info.st_dev, pending_info.st_ino
                ):
                    raise NativeStackDeployError(
                        "native_deployment_pending_record_changed")
                os.link(
                    pending.name, final.name,
                    src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    follow_symlinks=False)
                os.fsync(parent_fd)
            current = os.stat(
                pending.name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (
                pending_info.st_dev, pending_info.st_ino
            ):
                raise NativeStackDeployError(
                    "native_deployment_pending_record_changed")
            os.unlink(pending.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if pending_fd >= 0:
                os.close(pending_fd)
            os.close(parent_fd)

    def _validate_record(
        self, value: object, *, prior_sha256: str | None, sequence: int,
    ) -> dict[str, Any]:
        fields = {
            "schema", "deployment_id", "sequence", "phase", "plan",
            "apply_authorization_sha256", "authorization_sha256",
            "host_release_id",
            "payload_container_sha256", "prior_gateway", "prior_research",
            "event", "evidence", "transport", "prior_record_sha256",
            "updated_at", "record_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise NativeStackDeployError("native_deployment_journal_invalid")
        body = {key: item for key, item in value.items()
                if key not in {"schema", "record_sha256"}}
        plan = native_deployment.validate_plan(
            value["plan"], require_fresh=False)
        gateway, research = native_deployment.validate_plan_predecessor_statuses(
            plan, gateway_status=value["prior_gateway"],
            research_status=value["prior_research"])
        transport = value["transport"]
        evidence = value["evidence"]
        if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS:
            raise NativeStackDeployError("native_deployment_journal_invalid")
        for name in EVIDENCE_FIELDS - {
            "outcome", "gateway_status", "research_status"
        }:
            item = evidence[name]
            if item is not None and (
                not isinstance(item, str) or SHA256.fullmatch(item) is None
            ):
                raise NativeStackDeployError("native_deployment_journal_invalid")
        gateway_projection = evidence["gateway_status"]
        research_projection = evidence["research_status"]
        if (gateway_projection is None) != (research_projection is None):
            raise NativeStackDeployError("native_deployment_journal_invalid")
        if gateway_projection is not None:
            try:
                gateway_projection = native_deployment.validate_status_projection(
                    gateway_projection)
                research_projection = native_deployment.validate_status_projection(
                    research_projection)
            except native_deployment.NativeDeploymentError as error:
                raise NativeStackDeployError(
                    "native_deployment_journal_invalid") from error
            if (
                gateway_projection["role"] != "gateway"
                or research_projection["role"] != "research"
                or native_deployment.status_projection_sha256(gateway_projection)
                != evidence["gateway_status_sha256"]
                or native_deployment.status_projection_sha256(research_projection)
                != evidence["research_status_sha256"]
            ):
                raise NativeStackDeployError("native_deployment_journal_invalid")
            if evidence["outcome"] == "prior-prior":
                if (
                    evidence["gateway_status_sha256"]
                    != plan["previous_gateway_status_sha256"]
                    or evidence["research_status_sha256"]
                    != plan["previous_research_status_sha256"]
                ):
                    raise NativeStackDeployError(
                        "native_deployment_journal_outcome_mismatch")
            elif evidence["outcome"] in {
                "candidate-prior", "candidate-candidate"
            }:
                gateway_status = native_deployment.make_status(
                    **gateway_projection, observed_at=1)
                research_status = native_deployment.make_status(
                    **research_projection, observed_at=1)
                if classify_pair(
                    plan, gateway, research,
                    gateway_status, research_status
                ) != evidence["outcome"]:
                    raise NativeStackDeployError(
                        "native_deployment_journal_outcome_mismatch")
        if evidence["outcome"] not in OUTCOMES:
            raise NativeStackDeployError("native_deployment_journal_invalid")
        present = {
            name for name in EVIDENCE_FIELDS - {"outcome"}
            if evidence[name] is not None
        }
        required_evidence = {
            "authorized": set(),
            "fence-requested": set(),
            "fenced": {"fence_evidence_sha256"},
            "gateway-requested": set(),
            "gateway-observed": {
                "gateway_status", "research_status",
                "gateway_status_sha256", "research_status_sha256"},
            "research-requested": set(),
            "research-observed": {
                "gateway_status", "research_status",
                "gateway_status_sha256", "research_status_sha256"},
            "recovery-observed": {
                "gateway_status", "research_status",
                "gateway_status_sha256", "research_status_sha256"},
            "compensation-requested": set(),
            "compensation-observed": {
                "gateway_status", "research_status",
                "gateway_status_sha256", "research_status_sha256"},
            "release-requested": set(),
            "release-observed": {
                "gateway_status", "research_status",
                "gateway_status_sha256", "research_status_sha256",
                "fence_evidence_sha256", "terminal_sha256"},
            "committed": {
                "gateway_status", "research_status",
                "gateway_status_sha256", "research_status_sha256",
                "terminal_sha256"},
            "rolled-back": {
                "gateway_status", "research_status",
                "gateway_status_sha256", "research_status_sha256",
                "terminal_sha256"},
        }
        if value["phase"] in required_evidence:
            allowed = set(required_evidence[value["phase"]])
            if value["phase"] in {
                "gateway-observed", "research-observed",
                "compensation-observed", "release-observed",
            }:
                allowed.add("result_sha256")
            if not required_evidence[value["phase"]] <= present <= allowed:
                raise NativeStackDeployError("native_deployment_journal_invalid")
        elif value["phase"] == "recovery-required" and "terminal_sha256" in present:
            raise NativeStackDeployError("native_deployment_journal_invalid")
        if transport is not None and (
            not isinstance(transport, dict)
            or set(transport) != {
                "kind", "request_id", "semantic_sha256", "payload_sha256"
            }
            or not all(isinstance(transport[name], str) for name in transport)
            or SHA256.fullmatch(transport["semantic_sha256"]) is None
            or SHA256.fullmatch(transport["payload_sha256"]) is None
        ):
            raise NativeStackDeployError("native_deployment_journal_invalid")
        if transport is not None:
            native_deployment._uuid4(transport["request_id"], "transport_request_id")
        if (
            value["schema"] != JOURNAL_SCHEMA
            or value["deployment_id"] != plan["deployment_id"]
            or value["sequence"] != sequence
            or value["phase"] not in PHASES
            or evidence["outcome"] not in PHASE_OUTCOMES.get(value["phase"], set())
            or ((transport is not None) != (value["phase"] in REQUEST_PHASES))
            or value["prior_record_sha256"] != prior_sha256
            or value["host_release_id"] != plan["host_release_id"]
            or any(
                not isinstance(value[name], str)
                or SHA256.fullmatch(value[name]) is None
                for name in (
                    "apply_authorization_sha256", "authorization_sha256",
                    "payload_container_sha256")
            )
            or value["event"] != value["phase"]
            or not isinstance(value["updated_at"], int)
            or isinstance(value["updated_at"], bool)
            or value["updated_at"] < 1
            or value["record_sha256"] != digest(body)
        ):
            raise NativeStackDeployError("native_deployment_journal_invalid")
        return {**value, "prior_gateway": gateway, "prior_research": research}

    def _scan_transaction(
        self, root: Path,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        for pending in sorted(root.iterdir()):
            match = re.fullmatch(r"\.([0-9]{6}\.json)\.pending", pending.name)
            terminal_match = re.fullmatch(
                r"\.(terminal\.(?:committed|rolled-back)\.json)\.pending",
                pending.name)
            if match is not None:
                self._reconcile_pending_link(pending, root / match.group(1))
            elif terminal_match is not None:
                self._reconcile_pending_link(
                    pending, root / terminal_match.group(1))
        names = sorted(root.iterdir())
        records_paths = [item for item in names if re.fullmatch(
            r"[0-9]{6}\.json", item.name)]
        terminal_paths = [item for item in names if item.name in {
            "terminal.committed.json", "terminal.rolled-back.json"}]
        if (
            not records_paths
            or len(terminal_paths) > 1
            or any(item not in records_paths + terminal_paths for item in names)
            or records_paths != [
                root / f"{index:06d}.json" for index in range(len(records_paths))
            ]
        ):
            raise NativeStackDeployError(
                "native_deployment_journal_inventory_invalid")
        records: list[dict[str, Any]] = []
        prior = None
        prior_phase: str | None = None
        prior_time = 0
        last_gateway_status_sha256: str | None = None
        last_research_status_sha256: str | None = None
        for index, path in enumerate(records_paths):
            value = self._validate_record(
                _trusted_json(
                    path, "journal", trusted_uid=self.trusted_uid,
                    trusted_gid=self.trusted_gid), prior_sha256=prior,
                sequence=index)
            if value["phase"] not in TRANSITIONS.get(prior_phase, set()):
                raise NativeStackDeployError(
                    "native_deployment_journal_transition_invalid")
            if records:
                previous = records[-1]
                if value["phase"] in {
                    "release-observed", "committed", "rolled-back"
                } and (
                    value["evidence"]["gateway_status_sha256"]
                    != last_gateway_status_sha256
                    or value["evidence"]["research_status_sha256"]
                    != last_research_status_sha256
                ):
                    raise NativeStackDeployError(
                        "native_deployment_journal_status_binding_invalid")
            if value["updated_at"] < prior_time:
                raise NativeStackDeployError(
                    "native_deployment_journal_time_invalid")
            if records and any(value[name] != records[0][name] for name in (
                "deployment_id", "plan", "apply_authorization_sha256",
                "host_release_id", "payload_container_sha256",
                "prior_gateway", "prior_research",
            )):
                raise NativeStackDeployError(
                    "native_deployment_journal_authority_changed")
            if records and (
                value["authorization_sha256"]
                != records[-1]["authorization_sha256"]
                and records[-1]["phase"] != "recovery-required"
            ):
                raise NativeStackDeployError(
                    "native_deployment_journal_authority_changed")
            records.append(value)
            if value["evidence"]["gateway_status_sha256"] is not None:
                last_gateway_status_sha256 = value[
                    "evidence"]["gateway_status_sha256"]
                last_research_status_sha256 = value[
                    "evidence"]["research_status_sha256"]
            prior = value["record_sha256"]
            prior_phase = value["phase"]
            prior_time = value["updated_at"]
        terminal = None
        if terminal_paths:
            terminal = _trusted_json(
                terminal_paths[0], "terminal", trusted_uid=self.trusted_uid,
                trusted_gid=self.trusted_gid)
            if (
                terminal != records[-1]
                or terminal["phase"] not in TERMINAL_PHASES
                or terminal_paths[0].name
                != f"terminal.{terminal['phase']}.json"
            ):
                raise NativeStackDeployError(
                    "native_deployment_terminal_invalid")
        self._validate_chain(records)
        return records, terminal

    def _validate_chain(self, records: list[dict[str, Any]]) -> None:
        if not records:
            raise NativeStackDeployError("native_deployment_journal_invalid")
        first = records[0]
        prior_phase: str | None = None
        prior_time = 0
        prior_authorization = first["authorization_sha256"]
        last_gateway: str | None = None
        last_research: str | None = None
        for value in records:
            if (
                value["phase"] not in TRANSITIONS.get(prior_phase, set())
                or value["updated_at"] < prior_time
                or any(value[name] != first[name] for name in (
                    "deployment_id", "plan", "apply_authorization_sha256",
                    "host_release_id", "payload_container_sha256",
                    "prior_gateway", "prior_research"))
                or (
                    value["authorization_sha256"] != prior_authorization
                    and prior_phase != "recovery-required"
                )
            ):
                raise NativeStackDeployError(
                    "native_deployment_journal_chain_invalid")
            outcome = value["evidence"]["outcome"]
            previous = records[value["sequence"] - 1] if value["sequence"] else None
            previous_outcome = (
                None if previous is None else previous["evidence"]["outcome"])
            replay_candidate_prior = False
            if (
                previous is not None
                and previous["phase"] == "recovery-required"
                and value["phase"] in {
                    "research-requested", "compensation-requested"}
            ):
                history = records[:value["sequence"]]
                latest_request = next((
                    item for item in reversed(history)
                    if item["phase"] in REQUEST_PHASES
                ), None)
                latest_observation = next((
                    item for item in reversed(history)
                    if item["phase"] in {
                        "gateway-observed", "research-observed",
                        "recovery-observed", "compensation-observed"}
                ), None)
                replay_candidate_prior = (
                    latest_request is not None
                    and latest_request["phase"] == value["phase"]
                    and latest_observation is not None
                    and latest_observation["evidence"]["outcome"]
                    == "candidate-prior"
                )
            if (
                value["phase"] in {"research-requested", "compensation-requested"}
                and previous_outcome != "candidate-prior"
                and not replay_candidate_prior
            ) or (
                value["phase"] == "release-requested"
                and previous is not None
                and previous["phase"] in {
                    "gateway-observed", "research-observed",
                    "recovery-observed", "compensation-observed"}
                and previous_outcome not in {
                    "prior-prior", "candidate-candidate"}
            ) or (
                value["phase"] == "committed"
                and previous_outcome != "candidate-candidate"
            ) or (
                value["phase"] == "rolled-back"
                and previous_outcome != "prior-prior"
            ):
                raise NativeStackDeployError(
                    "native_deployment_journal_outcome_transition_invalid")
            if value["phase"] in {
                "release-observed", "committed", "rolled-back"
            } and (
                value["evidence"]["gateway_status_sha256"] != last_gateway
                or value["evidence"]["research_status_sha256"] != last_research
            ):
                raise NativeStackDeployError(
                    "native_deployment_journal_status_binding_invalid")
            if value["evidence"]["gateway_status_sha256"] is not None:
                last_gateway = value["evidence"]["gateway_status_sha256"]
                last_research = value["evidence"]["research_status_sha256"]
            prior_phase = value["phase"]
            prior_time = value["updated_at"]
            prior_authorization = value["authorization_sha256"]

    def load(self) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        if self.read_only_absent:
            self._require_host_locked()
            if self.root.exists() or self.root.is_symlink():
                raise NativeStackDeployError(
                    "native_deployment_state_root_changed")
            return None
        self._require_locked()
        roots = self._state_inventory()
        retained_roots: list[Path] = []
        for root in roots:
            if any(root.iterdir()):
                retained_roots.append(root)
            # A crash may leave an exact empty UUID root before the first
            # immutable record.  It carries no authority.  Retain it rather
            # than re-resolving and deleting a possibly substituted directory.
        roots = retained_roots
        pending_pointer = self.root / ".active.json.pending"
        if pending_pointer.exists() or pending_pointer.is_symlink():
            pending = self._pointer(pending_pointer)
            pending_root = self.transaction_root(
                pending["deployment_id"], create=False)
            records, _terminal = self._scan_transaction(pending_root)
            if (
                pending["sequence"] >= len(records)
                or records[pending["sequence"]]["record_sha256"]
                != pending["record_sha256"]
            ):
                raise NativeStackDeployError(
                    "native_deployment_pending_pointer_mismatch")
            if self.active.exists() or self.active.is_symlink():
                active = self._pointer(self.active)
                if (
                    active["deployment_id"] != pending["deployment_id"]
                    or pending["sequence"] < active["sequence"]
                    or pending["sequence"] > active["sequence"] + 1
                ):
                    raise NativeStackDeployError(
                        "native_deployment_pending_pointer_mismatch")
            os.replace(pending_pointer, self.active)
            directory = os.open(
                self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        if not self.active.exists():
            if self.active.is_symlink():
                raise NativeStackDeployError("native_deployment_active_untrusted")
            unterminated: list[tuple[Path, list[dict[str, Any]]]] = []
            for root in roots:
                records, terminal = self._scan_transaction(root)
                if terminal is None:
                    unterminated.append((root, records))
            if len(unterminated) > 1:
                raise NativeStackDeployError(
                    "native_deployment_multiple_orphaned_transactions")
            if unterminated:
                self._publish_pointer_for_record(unterminated[0][1][-1])
                return self.load()
            return None
        pointer = self._pointer(self.active)
        root = self.transaction_root(pointer["deployment_id"], create=False)
        if root not in roots:
            raise NativeStackDeployError("native_deployment_active_mismatch")
        for other in roots:
            if other == root:
                continue
            _other_records, other_terminal = self._scan_transaction(other)
            if other_terminal is None:
                raise NativeStackDeployError(
                    "native_deployment_multiple_active_transactions")
        records, terminal = self._scan_transaction(root)
        if len(records) == pointer["sequence"] + 2:
            # A fully linked, hash-valid next record is authoritative evidence
            # that the process crashed before replacing the pointer.
            self._publish_pointer_for_record(records[-1])
            return self.load()
        if len(records) > pointer["sequence"] + 2:
            raise NativeStackDeployError(
                "native_deployment_active_pointer_too_stale")
        prior = records[-1]["record_sha256"]
        if (
            not records
            or len(records) != pointer["sequence"] + 1
            or prior != pointer["record_sha256"]
            or records[-1]["host_release_id"] != pointer["host_release_id"]
            or records[-1]["deployment_id"] != pointer["deployment_id"]
        ):
            raise NativeStackDeployError("native_deployment_active_mismatch")
        if terminal is not None:
            os.unlink(self.active)
            self.crash_hook("terminal-active-unlinked")
            directory = os.open(
                self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self.crash_hook("terminal-active-reconciled")
            return None
        return pointer, records

    def append(
        self, *, plan: Mapping[str, Any], apply_authorization_sha256: str,
        authorization_sha256: str,
        payload_container_sha256: str, prior_gateway: Mapping[str, Any],
        prior_research: Mapping[str, Any], phase: str, event: str,
        evidence: Mapping[str, Any], transport: Mapping[str, str] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        self._require_locked()
        admitted = native_deployment.validate_plan(plan, require_fresh=False)
        loaded = self.load()
        sequence = 0 if loaded is None else loaded[0]["sequence"] + 1
        prior_record = None if loaded is None else loaded[0]["record_sha256"]
        if loaded is not None and loaded[0]["deployment_id"] != admitted["deployment_id"]:
            raise NativeStackDeployError("native_deployment_already_active")
        prior_phase = None if loaded is None else loaded[1][-1]["phase"]
        if loaded is not None:
            first = loaded[1][0]
            if (
                admitted != first["plan"]
                or apply_authorization_sha256
                != first["apply_authorization_sha256"]
                or payload_container_sha256
                != first["payload_container_sha256"]
                or dict(prior_gateway) != first["prior_gateway"]
                or dict(prior_research) != first["prior_research"]
                or (
                    authorization_sha256
                    != loaded[1][-1]["authorization_sha256"]
                    and prior_phase != "recovery-required"
                )
            ):
                raise NativeStackDeployError(
                    "native_deployment_journal_authority_changed")
        if phase not in TRANSITIONS.get(prior_phase, set()):
            raise NativeStackDeployError("native_deployment_phase_transition_invalid")
        normalized_evidence = {
            name: evidence.get(name) for name in EVIDENCE_FIELDS
        }
        if set(evidence) != EVIDENCE_FIELDS:
            raise NativeStackDeployError("native_deployment_evidence_invalid")
        body = {
            "deployment_id": admitted["deployment_id"],
            "sequence": sequence,
            "phase": phase,
            "plan": admitted,
            "apply_authorization_sha256": apply_authorization_sha256,
            "authorization_sha256": authorization_sha256,
            "host_release_id": admitted["host_release_id"],
            "payload_container_sha256": payload_container_sha256,
            "prior_gateway": dict(prior_gateway),
            "prior_research": dict(prior_research),
            "event": event,
            "evidence": normalized_evidence,
            "transport": None if transport is None else dict(transport),
            "prior_record_sha256": prior_record,
            "updated_at": int(time.time()) if now is None else now,
        }
        record = {
            "schema": JOURNAL_SCHEMA, **body, "record_sha256": digest(body),
        }
        self._validate_record(record, prior_sha256=prior_record, sequence=sequence)
        self._validate_chain(
            [record] if loaded is None else [*loaded[1], record])
        root = self.transaction_root(admitted["deployment_id"])
        _exclusive_file(
            root / f"{sequence:06d}.json", canonical(record),
            crash_hook=self.crash_hook, trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        pointer_body = {
            "deployment_id": admitted["deployment_id"], "sequence": sequence,
            "record_sha256": record["record_sha256"],
            "host_release_id": admitted["host_release_id"],
        }
        pointer = {
            "schema": ACTIVE_SCHEMA, **pointer_body,
            "active_sha256": digest(pointer_body),
        }
        _atomic_file(
            self.active, canonical(pointer), crash_hook=self.crash_hook,
            trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid)
        return record

    def complete(self, record: Mapping[str, Any]) -> None:
        self._require_locked()
        if record.get("phase") not in TERMINAL_PHASES:
            raise NativeStackDeployError("native_deployment_terminal_invalid")
        terminal = self.transaction_root(record["deployment_id"]) / (
            f"terminal.{record['phase']}.json")
        current = self.load()
        if current is None:
            if terminal.exists() and _trusted_json(
                terminal, "terminal_replay", trusted_uid=self.trusted_uid,
                trusted_gid=self.trusted_gid) == dict(record):
                return
            raise NativeStackDeployError("native_deployment_terminal_changed")
        if current[0]["record_sha256"] != record["record_sha256"]:
            raise NativeStackDeployError("native_deployment_terminal_changed")
        _exclusive_file(
            terminal, canonical(dict(record)), idempotent=True,
            crash_hook=self.crash_hook, trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid)
        self.crash_hook("terminal-published")
        current = self.load()
        if current is not None:
            if current[0]["record_sha256"] != record["record_sha256"]:
                raise NativeStackDeployError("native_deployment_terminal_changed")
            os.unlink(self.active)
            self.crash_hook("active-unlinked")
            directory = os.open(
                self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


def _module_from_bytes(raw: bytes, name: str, filename: str) -> ModuleType:
    """Execute verified source bytes without consulting or creating bytecode."""
    try:
        code = compile(raw, filename, "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as error:
        raise NativeStackDeployError(
            "native_deployment_release_authority_unavailable") from error
    module = ModuleType(name)
    module.__file__ = filename
    module.__package__ = ""
    exec(code, module.__dict__)
    return module


def _release_identity(payloads: Mapping[str, str]) -> str:
    identity = bytearray()
    for name in sorted(payloads):
        identity.extend(f"{name}\0{payloads[name]}\n".encode("ascii"))
    return hashlib.sha256(identity).hexdigest()


def _release_file(
    path: Path, *, expected_uid: int, expected_mode: int | None = None,
) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeStackDeployError(
            "native_deployment_release_payload_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while total <= 64 * 1024 * 1024:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
            total += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or opened.st_nlink != 1
        or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (expected_mode is not None
            and stat.S_IMODE(opened.st_mode) != expected_mode)
        or total != opened.st_size
        or total > 64 * 1024 * 1024
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
    ):
        raise NativeStackDeployError(
            "native_deployment_release_payload_untrusted")
    return b"".join(chunks)


class ReleaseAuthority:
    """Hold Host release selection stable and verify every sibling payload."""

    def __init__(
        self, release: Path = HERE, install_root: Path = INSTALL_ROOT, *,
        host_install_fd: int = -1, expected_uid: int = 0,
        allow_install_transition: bool = False,
        transition_release_id: str | None = None,
    ):
        self.release = release.resolve()
        self.install_root = install_root
        self.supplied_install_fd = host_install_fd
        self.expected_uid = expected_uid
        self.allow_install_transition = allow_install_transition
        self.transition_release_id = transition_release_id
        self.manager: Any | None = None
        self.install_fd = -1
        self.manifest: dict[str, Any] | None = None

    def __enter__(self) -> "ReleaseAuthority":
        if self.supplied_install_fd < 0:
            raise NativeStackDeployError(
                "native_deployment_host_lock_required")
        self.install_fd = os.dup(self.supplied_install_fd)
        try:
            try:
                # On an inherited locked open-file-description this is a
                # no-op.  An unlocked exact-root descriptor is safely locked;
                # a competing description fails without waiting.
                fcntl.flock(
                    self.install_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise NativeStackDeployError(
                    "native_deployment_host_lock_not_held") from error
            opened_root = os.fstat(self.install_fd)
            current_root = self.install_root.lstat()
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or stat.S_ISLNK(current_root.st_mode)
                or opened_root.st_uid != self.expected_uid
                or stat.S_IMODE(opened_root.st_mode) != 0o755
                or (opened_root.st_dev, opened_root.st_ino)
                != (current_root.st_dev, current_root.st_ino)
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_lock_invalid")
            releases = (self.install_root / "releases").resolve(strict=True)
            current = self.install_root / "current"
            if self.transition_release_id is None:
                selected = current.resolve(strict=True)
            else:
                if (
                    not self.allow_install_transition
                    or SHA256.fullmatch(self.transition_release_id) is None
                    or os.path.lexists(current)
                ):
                    raise NativeStackDeployError(
                        "native_deployment_transition_release_invalid")
                selected = (
                    releases / self.transition_release_id).resolve(strict=True)
            relative = selected.relative_to(releases)
            if (
                len(relative.parts) != 1
                or SHA256.fullmatch(relative.name) is None
                or selected != self.release
                or self.transition_release_id is not None
                and relative.name != self.transition_release_id
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_release_changed")
            if (
                not self.allow_install_transition
                and os.path.lexists(
                    self.install_root / INSTALL_TRANSITION_PENDING_NAME)
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_install_transition_active")
            release_info = self.release.lstat()
            if (
                not stat.S_ISDIR(release_info.st_mode)
                or stat.S_ISLNK(release_info.st_mode)
                or release_info.st_uid != self.expected_uid
                or stat.S_IMODE(release_info.st_mode) != 0o555
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_release_invalid")
            if any(
                item.name == "__pycache__" or item.suffix in {".pyc", ".pyo"}
                for item in self.release.rglob("*")
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_release_cache_forbidden")
            manifest_raw = _release_file(
                self.release / "manifest.json",
                expected_uid=self.expected_uid, expected_mode=0o444)
            try:
                bootstrap_manifest = json.loads(manifest_raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise NativeStackDeployError(
                    "native_deployment_host_manifest_invalid") from error
            if (
                not isinstance(bootstrap_manifest, dict)
                or set(bootstrap_manifest) != {"schema", "release_id", "payloads"}
                or bootstrap_manifest["schema"]
                != "secure-sandbox-host-controller-release-v1"
                or bootstrap_manifest["release_id"] != relative.name
                or not isinstance(bootstrap_manifest["payloads"], dict)
                or _release_identity(bootstrap_manifest["payloads"])
                != relative.name
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_manifest_invalid")
            payloads = bootstrap_manifest["payloads"]
            if any(
                not isinstance(name, str)
                or SAFE_PAYLOAD_NAME.fullmatch(name) is None
                or not isinstance(expected, str)
                or SHA256.fullmatch(expected) is None
                for name, expected in payloads.items()
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_manifest_invalid")
            payload_raw: dict[str, bytes] = {}
            for name, expected in payloads.items():
                raw = _release_file(
                    self.release / name, expected_uid=self.expected_uid)
                if hashlib.sha256(raw).hexdigest() != expected:
                    raise NativeStackDeployError(
                        "native_deployment_release_payload_changed")
                payload_raw[name] = raw
            if (
                "release_manager" not in payload_raw
                or COORDINATION_CONTRACT_NAME not in payload_raw
            ):
                raise NativeStackDeployError(
                    "native_deployment_host_release_incomplete")
            contract = _coordination_contract(
                payload_raw[COORDINATION_CONTRACT_NAME])
            floor_raw = _release_file(
                self.install_root / COORDINATION_FLOOR_NAME,
                expected_uid=self.expected_uid, expected_mode=0o600)
            floor = _coordination_floor(floor_raw)
            enforcement = _coordination_enforcement(_release_file(
                self.install_root / COORDINATION_ENFORCEMENT_NAME,
                expected_uid=self.expected_uid, expected_mode=0o444))
            if (
                enforcement["authoritative_floor_sha256"]
                    != hashlib.sha256(floor_raw).hexdigest()
                or enforcement["minimum_epoch"] != floor["minimum_epoch"]
                or contract["epoch"] < enforcement["minimum_epoch"]
                or not set(enforcement["minimum_features"])
                    <= set(contract["features"])
            ):
                raise NativeStackDeployError(
                    "native_deployment_coordination_contract_below_floor")
            self.manager = _module_from_bytes(
                payload_raw["release_manager"],
                "_native_deployment_release_manager",
                str(self.release / "release_manager"))
            if self.transition_release_id is None:
                selected, manifest = self.manager.verified_release(
                    self.install_root, current, self.expected_uid)
            else:
                selected, manifest = self.manager.verified_release(
                    self.install_root, self.release, self.expected_uid,
                    allow_legacy=True,
                    _direct_release_id=self.transition_release_id,
                )
            if selected.resolve() != self.release:
                raise NativeStackDeployError(
                    "native_deployment_host_release_changed")
            required = {
                "native_stack_deployer", "native_deployment_payloads",
                "native_stack_support", "control_client", "ssh_config",
                "release_manager", "authorization_broker",
                COORDINATION_CONTRACT_NAME,
            }
            if not required <= set(manifest.get("payloads", {})):
                raise NativeStackDeployError(
                    "native_deployment_host_release_incomplete")
            if manifest.get("release_id") != self.release.name:
                raise NativeStackDeployError(
                    "native_deployment_host_release_invalid")
            self.manifest = manifest
            _activate_support(
                self.release / "native_stack_support",
                manifest["payloads"]["native_stack_support"],
                expected_uid=self.expected_uid)
            return self
        except BaseException:
            os.close(self.install_fd)
            self.install_fd = -1
            raise

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self.install_fd >= 0:
            os.close(self.install_fd)
            self.install_fd = -1

    @property
    def release_id(self) -> str:
        if self.manifest is None:
            raise NativeStackDeployError("native_deployment_host_release_unverified")
        return self.manifest["release_id"]

    def payload(self, name: str) -> bytes:
        if self.manifest is None or name not in self.manifest["payloads"]:
            raise NativeStackDeployError("native_deployment_release_payload_missing")
        path = self.release / name
        raw = _release_file(
            path, expected_uid=self.expected_uid,
            expected_mode=self.manager.EXPECTED_MODES[name])
        if hashlib.sha256(raw).hexdigest() != self.manifest["payloads"][name]:
            raise NativeStackDeployError("native_deployment_release_payload_changed")
        return raw


class NativeRuntimeAuthority:
    """Serialize deployment with catalog/profile and session lifecycles."""

    def __init__(
        self, release: ReleaseAuthority, *, manager_module: Any | None = None,
        session_module: Any | None = None,
        promotion_module: Any | None = None,
    ):
        self.release = release
        # Reading through ReleaseAuthority binds both modules to the verified
        # immutable Host release before any of their code is imported.
        release.payload("native_stack_manager")
        release.payload("native_stack_session_manager")
        self.manager_module = (
            _module_from_bytes(
                release.payload("native_stack_manager"),
                "_native_deployment_stack_manager",
                str(release.release / "native_stack_manager"))
            if manager_module is None else manager_module)
        self.session_module = (
            _module_from_bytes(
                release.payload("native_stack_session_manager"),
                "_native_deployment_session_manager",
                str(release.release / "native_stack_session_manager"))
            if session_module is None else session_module)
        self.promotion_module = (
            _module_from_bytes(
                release.payload("native_stack_catalog_promoter"),
                "_native_deployment_catalog_promoter",
                str(release.release / "native_stack_catalog_promoter"))
            if promotion_module is None else promotion_module)
        self.manager = self.manager_module.NativeStackManager(
            None, trusted_uid=0, host_release_id=release.release_id)
        self.sessions = self.session_module.NativeStackSessionManager(
            None, trusted_uid=0, trusted_gid=0,
            host_release_id=release.release_id)
        self.promotion_context: Any | None = None
        self.session_lock: Any | None = None

    def __enter__(self) -> "NativeRuntimeAuthority":
        self.promotion_context = self.promotion_module.promotion_admission(
            self.release.install_fd,
            expected_host_release_id=self.release.release_id,
        )
        try:
            self.promotion_context.__enter__()
        except BaseException as error:
            self.promotion_context = None
            raise NativeStackDeployError(
                "native_deployment_catalog_promotion_gate_rejected") from error
        try:
            self.session_lock = self.sessions.locked()
            self.session_lock.__enter__()
            if self.manager._pending_records():
                raise NativeStackDeployError(
                    "native_deployment_native_stack_transaction_active")
            if any(
                value["phase"] not in self.session_module.TERMINAL_PHASES
                for _path, value in self.sessions._records()
            ):
                raise NativeStackDeployError(
                    "native_deployment_native_session_active")
            return self
        except BaseException:
            if self.session_lock is not None:
                self.session_lock.__exit__(*sys.exc_info())
                self.session_lock = None
            if self.promotion_context is not None:
                self.promotion_context.__exit__(*sys.exc_info())
                self.promotion_context = None
            raise

    def __exit__(self, kind: object, value: object, traceback: object) -> None:
        if self.session_lock is not None:
            self.session_lock.__exit__(kind, value, traceback)
            self.session_lock = None
        if self.promotion_context is not None:
            self.promotion_context.__exit__(kind, value, traceback)
            self.promotion_context = None


def _read_catalog(path: Path = CATALOG) -> tuple[dict[str, Any], bytes, str]:
    try:
        value = native_vendor_stack.load_catalog(path, private=True)
    except Exception as error:
        raise NativeStackDeployError("native_deployment_catalog_untrusted") from error
    raw = native_vendor_stack.canonical_bytes(value)
    return value, raw, hashlib.sha256(raw).hexdigest()


def _materialize(
    files: Mapping[str, tuple[bytes, int]], root: Path,
    *, extras: Mapping[str, tuple[bytes, int]] | None = None,
) -> dict[str, Path]:
    values = dict(files)
    if extras:
        if set(values) & set(extras):
            raise NativeStackDeployError("native_deployment_payload_collision")
        values.update(extras)
    result: dict[str, Path] = {}
    for name, (raw, mode) in sorted(values.items()):
        if native_deployment.SAFE_NAME.fullmatch(name) is None or mode not in {
            0o600, 0o700,
        }:
            raise NativeStackDeployError("native_deployment_payload_invalid")
        path = root / name
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode)
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise NativeStackDeployError(
                        "native_deployment_payload_write_failed")
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        result[name] = path
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return result


def _transport_environment() -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    marker = os.environ.get(PROCESS_GROUP_ENV)
    if marker is None:
        return environment
    try:
        group = os.getpgrp()
        session = os.getsid(0)
        process = os.getpid()
    except OSError as error:
        raise NativeStackDeployError(
            "native_deployment_process_group_untrusted"
        ) from error
    valid = (
        marker == "bootstrap" and process == group == session
    ) or (
        marker.isascii() and marker.isdecimal()
        and int(marker) == group == session
    )
    if not valid:
        raise NativeStackDeployError(
            "native_deployment_process_group_untrusted"
        )
    # A bootstrap marker proves that this process created the session.  Its
    # child is not the session leader, so pass the exact numeric group identity
    # that the child can independently validate rather than ambient text.
    environment[PROCESS_GROUP_ENV] = str(group)
    return environment


class Transport:
    """Release-pinned privileged control transport with bounded output."""

    HOSTS = {
        "gateway": "sandbox-gateway-control",
        "research": "sandbox-research-control",
    }

    def __init__(self, release: ReleaseAuthority):
        self.release = release
        self.client = release.release / "control_client"
        self.config = release.release / "ssh_config"

    def _run(
        self, command: list[str], *, request_id: str,
        stdin: bytes | None = None, timeout: int = 900,
    ) -> tuple[int, bytes]:
        native_deployment._uuid4(request_id, "transport_request_id")
        try:
            result = subprocess.run(
                [str(self.client), "client", "--ssh-config", str(self.config),
                 "--timeout-seconds", str(timeout), "--request-id", request_id,
                 *command],
                input=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                check=False, timeout=timeout + 30,
                env=_transport_environment(),
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise NativeStackDeployError(
                "native_deployment_transport_unavailable") from error
        if len(result.stdout) > MAX_OUTPUT:
            raise NativeStackDeployError("native_deployment_transport_output_oversized")
        return result.returncode, result.stdout

    def deploy(
        self, role: str, installer: str, files: Mapping[str, Path], *,
        arguments: tuple[str, ...] = (), request_id: str,
        timeout: int = 900,
    ) -> tuple[int, bytes]:
        if role not in self.HOSTS or installer not in files:
            raise NativeStackDeployError("native_deployment_transport_request_invalid")
        command = [self.HOSTS[role], "deploy", installer, *arguments]
        for name, path in sorted(files.items()):
            command.extend(["--file", f"{path}:{name}"])
        return self._run(command, request_id=request_id, timeout=timeout)

    def pipe(
        self, operation: str, request: Mapping[str, Any], *, request_id: str,
    ) -> tuple[int, bytes]:
        return self._run(
            [self.HOSTS["research"], "pipe", operation],
            request_id=request_id, stdin=canonical(request), timeout=180)


def _transport_identity(
    kind: str, request_id: str, semantic: object, payload_sha256: str,
) -> dict[str, str]:
    native_deployment._uuid4(request_id, "transport_request_id")
    if SHA256.fullmatch(payload_sha256) is None:
        raise NativeStackDeployError("native_deployment_transport_payload_invalid")
    return {
        "kind": kind, "request_id": request_id,
        "semantic_sha256": digest(semantic),
        "payload_sha256": payload_sha256,
    }


def _reply(raw: bytes, label: str) -> dict[str, Any]:
    return read_canonical(raw, label)


def _validate_fence_reply(
    value: object, plan: Mapping[str, Any], *, released: bool = False,
) -> dict[str, Any]:
    fields = (
        {"schema", "deployment_id", "plan_sha256", "state",
         "evidence_sha256", "terminal_sha256"}
        if released else
        {"schema", "deployment_id", "plan_sha256", "fence_sha256",
         "catalog_sha256", "state", "evidence_sha256"}
    )
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackDeployError("native_deployment_lifecycle_reply_invalid")
    if (
        value["schema"] != (
            native_deployment.RELEASE_REPLY_SCHEMA if released
            else native_deployment.FENCE_REPLY_SCHEMA)
        or value["deployment_id"] != plan["deployment_id"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or value["state"] != ("released" if released else "fenced")
        or any(SHA256.fullmatch(str(value.get(name, ""))) is None for name in (
            ("evidence_sha256", "terminal_sha256") if released
            else ("fence_sha256", "catalog_sha256", "evidence_sha256")))
        or (not released and value["catalog_sha256"] != plan["catalog_sha256"])
    ):
        raise NativeStackDeployError("native_deployment_lifecycle_reply_invalid")
    return value


def evidence(
    *, outcome: str, gateway_status_sha256: str | None = None,
    research_status_sha256: str | None = None,
    gateway_status: Mapping[str, Any] | None = None,
    research_status: Mapping[str, Any] | None = None,
    fence_evidence_sha256: str | None = None,
    result_sha256: str | None = None,
    terminal_sha256: str | None = None,
) -> dict[str, Any]:
    gateway_projection = (
        None if gateway_status is None
        else native_deployment.stable_status_projection(gateway_status))
    research_projection = (
        None if research_status is None
        else native_deployment.stable_status_projection(research_status))
    if gateway_projection is not None:
        projected = native_deployment.status_projection_sha256(
            gateway_projection)
        if gateway_status_sha256 is not None and gateway_status_sha256 != projected:
            raise NativeStackDeployError(
                "native_deployment_gateway_evidence_mismatch")
        gateway_status_sha256 = projected
    if research_projection is not None:
        projected = native_deployment.status_projection_sha256(
            research_projection)
        if research_status_sha256 is not None and research_status_sha256 != projected:
            raise NativeStackDeployError(
                "native_deployment_research_evidence_mismatch")
        research_status_sha256 = projected
    return {
        "gateway_status": gateway_projection,
        "research_status": research_projection,
        "gateway_status_sha256": gateway_status_sha256,
        "research_status_sha256": research_status_sha256,
        "fence_evidence_sha256": fence_evidence_sha256,
        "result_sha256": result_sha256,
        "terminal_sha256": terminal_sha256,
        "outcome": outcome,
    }


def _status_sha256(value: Mapping[str, Any]) -> str:
    return native_deployment.stable_status_sha256(value)


def _candidate_status(
    status: Mapping[str, Any], plan: Mapping[str, Any], role: str,
) -> bool:
    return (
        status["role"] == role
        and status["state"] == "verified"
        and status["generation_kind"] == "protected"
        and status["package_sha256"] == plan[f"{role}_package_sha256"]
        and (
            status["catalog_sha256"] == plan["catalog_sha256"]
            if role == "research" else status["catalog_sha256"] is None
        )
    )


def classify_pair(
    plan: Mapping[str, Any], prior_gateway: Mapping[str, Any],
    prior_research: Mapping[str, Any], gateway: Mapping[str, Any],
    research: Mapping[str, Any],
) -> str:
    native_deployment.validate_plan_predecessor_statuses(
        plan, gateway_status=prior_gateway, research_status=prior_research)
    gateway = native_deployment.validate_status(gateway)
    research = native_deployment.validate_status(research)
    gateway_prior = _status_sha256(gateway) == _status_sha256(prior_gateway)
    research_prior = _status_sha256(research) == _status_sha256(prior_research)
    gateway_candidate = _candidate_status(gateway, plan, "gateway")
    research_candidate = _candidate_status(research, plan, "research")
    gateway_forward = gateway_candidate or (
        gateway_prior
        and plan["gateway_package_sha256"]
        == plan["previous_gateway_package_sha256"])
    research_forward = research_candidate or (
        research_prior
        and plan["research_package_sha256"]
        == plan["previous_research_package_sha256"]
        and research["catalog_sha256"] == plan["catalog_sha256"])
    if gateway_forward and research_forward:
        return "candidate-candidate"
    if gateway_forward and research_prior:
        return "candidate-prior"
    if gateway_prior and research_prior:
        return "prior-prior"
    raise NativeStackDeployError("native_deployment_cross_plane_state_unknown")


class Coordinator:
    def __init__(
        self, release: ReleaseAuthority, journal: Journal,
        *, transport: Transport | None = None,
        catalog_path: Path = CATALOG,
    ):
        self.release = release
        self.journal = journal
        self.transport = Transport(release) if transport is None else transport
        self.catalog_path = catalog_path
        self.catalog, self.catalog_raw, self.catalog_sha256 = _read_catalog(
            catalog_path)
        self.container_raw = release.payload("native_deployment_payloads")
        self.container_sha256 = hashlib.sha256(self.container_raw).hexdigest()
        self.bases = native_deployment_payload.read_payload_container(
            self.container_raw)
        self.gateway_files, self.gateway_package = (
            native_deployment_payload.complete_package(
                self.bases["gateway.zip"], "gateway", dynamic={}))
        self.research_files, self.research_package = (
            native_deployment_payload.complete_package(
                self.bases["research.zip"], "research",
                dynamic={"native-vendor-stacks.json": self.catalog_raw}))

    def _probe(self, role: str) -> dict[str, Any]:
        files = self.gateway_files if role == "gateway" else self.research_files
        release_name = f"native_{role}_release.py"
        selected_names = [
                "install-native-deployment-probe.sh",
                "native_deployment_probe.py", "native_deployment.py",
                "native_vendor_stack.py", release_name,
        ]
        if role == "research":
            selected_names.append("native-vendor-stacks.json")
        selected = {name: files[name] for name in selected_names}
        with tempfile.TemporaryDirectory(
            prefix="secure-sandbox-native-probe.", dir="/private/tmp") as directory:
            os.chmod(directory, 0o700)
            materialized = _materialize(selected, Path(directory))
            status, raw = self.transport.deploy(
                role, "install-native-deployment-probe.sh", materialized,
                arguments=(role,), request_id=str(uuid.uuid4()), timeout=180)
        if status != 0:
            raise NativeStackDeployError("native_deployment_probe_failed")
        return native_deployment.validate_status(_reply(raw, "probe_reply"))

    def probe_pair(self) -> tuple[dict[str, Any], dict[str, Any]]:
        gateway = self._probe("gateway")
        research = self._probe("research")
        return gateway, research

    def plan(self, *, now: int | None = None) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        if self.journal.load() is not None:
            raise NativeStackDeployError("native_deployment_recovery_required")
        gateway, research = self.probe_pair()
        if (
            research["state"] == "verified"
            and research["catalog_sha256"] != self.catalog_sha256
        ):
            raise NativeStackDeployError(
                "native_deployment_research_catalog_mismatch")
        plan = native_deployment.make_plan(
            deployment_id=str(uuid.uuid4()),
            host_release_id=self.release.release_id,
            catalog_sha256=self.catalog_sha256,
            gateway_package_sha256=self.gateway_package["package_sha256"],
            research_package_sha256=self.research_package["package_sha256"],
            previous_gateway_package_sha256=gateway["package_sha256"],
            previous_research_package_sha256=research["package_sha256"],
            previous_gateway_status_sha256=_status_sha256(gateway),
            previous_research_status_sha256=_status_sha256(research),
            created_at=timestamp, expires_at=timestamp + 3600,
        )
        body = {
            "plan": plan, "prior_gateway": gateway,
            "prior_research": research,
            "payload_container_sha256": self.container_sha256,
        }
        return {
            "schema": PLAN_RESPONSE_SCHEMA, **body,
            "response_sha256": digest(body),
        }

    def validate_plan_response(
        self, value: object, *, now: int, require_fresh: bool,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        if not isinstance(value, dict) or set(value) != {
            "schema", "plan", "prior_gateway", "prior_research",
            "payload_container_sha256", "response_sha256"
        }:
            raise NativeStackDeployError("native_deployment_plan_response_invalid")
        plan = native_deployment.validate_plan(
            value["plan"], now=now, require_fresh=require_fresh)
        gateway, research = native_deployment.validate_plan_predecessor_statuses(
            plan, gateway_status=value["prior_gateway"],
            research_status=value["prior_research"])
        body = {key: item for key, item in value.items()
                if key not in {"schema", "response_sha256"}}
        if (
            value["schema"] != PLAN_RESPONSE_SCHEMA
            or value["payload_container_sha256"] != self.container_sha256
            or value["response_sha256"] != digest(body)
            or plan["host_release_id"] != self.release.release_id
            or plan["catalog_sha256"] != self.catalog_sha256
            or plan["gateway_package_sha256"]
            != self.gateway_package["package_sha256"]
            or plan["research_package_sha256"]
            != self.research_package["package_sha256"]
        ):
            raise NativeStackDeployError("native_deployment_plan_response_invalid")
        return plan, gateway, research

    def _append(
        self, context: Mapping[str, Any], phase: str,
        entry_evidence: Mapping[str, Any],
        transport: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.journal.append(
            plan=context["plan"],
            apply_authorization_sha256=context.get(
                "apply_authorization_sha256",
                context["authorization"]["authorization_sha256"]),
            authorization_sha256=context["authorization"]["authorization_sha256"],
            payload_container_sha256=self.container_sha256,
            prior_gateway=context["prior_gateway"],
            prior_research=context["prior_research"], phase=phase, event=phase,
            evidence=entry_evidence, transport=transport)

    def _deploy_files(
        self, role: str, files: Mapping[str, tuple[bytes, int]],
        installer: str, plan: Mapping[str, Any], *, request_id: str,
    ) -> tuple[int, bytes, str]:
        extras = {
            "native-deployment-plan.json": (canonical(plan), 0o600),
        }
        semantic = {
            "role": role, "installer": installer,
            "plan_sha256": plan["plan_sha256"],
            "package_sha256": plan[f"{role}_package_sha256"],
        }
        with tempfile.TemporaryDirectory(
            prefix=f"secure-sandbox-native-{role}.",
            dir="/private/tmp") as directory:
            os.chmod(directory, 0o700)
            materialized = _materialize(files, Path(directory), extras=extras)
            payload_sha256 = digest({
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in sorted(materialized.items())
            })
            status, raw = self.transport.deploy(
                role, installer, materialized, request_id=request_id)
        return status, raw, payload_sha256

    def _journaled_deploy(
        self, context: Mapping[str, Any], *, phase: str, role: str,
        installer: str, files: Mapping[str, tuple[bytes, int]],
        extras: Mapping[str, tuple[bytes, int]], semantic: Mapping[str, Any],
        arguments: tuple[str, ...] = (), timeout: int = 900,
    ) -> tuple[int, bytes]:
        request_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory(
            prefix=f"secure-sandbox-native-request-{role}.",
            dir="/private/tmp") as directory:
            os.chmod(directory, 0o700)
            materialized = _materialize(files, Path(directory), extras=extras)
            payload_sha256 = digest({
                name: {
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "mode": stat.S_IMODE(path.stat().st_mode),
                }
                for name, path in sorted(materialized.items())
            })
            transport = _transport_identity(
                f"deploy:{role}:{installer}", request_id, semantic,
                payload_sha256)
            self._append(
                context, phase, evidence(outcome="requested"), transport)
            return self.transport.deploy(
                role, installer, materialized, arguments=arguments,
                request_id=request_id, timeout=timeout)

    def _journaled_pipe(
        self, context: Mapping[str, Any], *, phase: str, operation: str,
        request: Mapping[str, Any],
    ) -> tuple[int, bytes]:
        request_id = str(uuid.uuid4())
        raw = canonical(request)
        transport = _transport_identity(
            f"pipe:research:{operation}", request_id,
            {"operation": operation,
             "request_sha256": hashlib.sha256(raw).hexdigest()},
            hashlib.sha256(raw).hexdigest())
        self._append(context, phase, evidence(outcome="requested"), transport)
        return self.transport.pipe(operation, request, request_id=request_id)

    def acquire_fence(
        self, context: Mapping[str, Any], *,
        observed_research: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        plan = context["plan"]
        recovery = (
            context["authorization"]["operation"]
            == native_deployment.RECOVER_OPERATION)
        request = (
            native_deployment.make_recovery_fence_request(
                plan, context["authorization"])
            if recovery else native_deployment.make_fence_request(plan))
        observed = (
            context["prior_research"]
            if observed_research is None else
            native_deployment.validate_status(observed_research))
        if observed["role"] != "research":
            raise NativeStackDeployError(
                "native_deployment_research_observation_invalid")
        if (
            observed["generation_kind"] == "protected"
            and observed["package_sha256"] == plan["research_package_sha256"]
        ):
            status, raw = self._journaled_pipe(
                context, phase="fence-requested",
                operation=(
                    "native-deployment-lifecycle-recovery-acquire"
                    if recovery else
                    "native-deployment-lifecycle-acquire"),
                request=request)
        else:
            fence_operation = "recovery-acquire" if recovery else "acquire"
            request_name = (
                "native-deployment-recovery-fence-request.json"
                if recovery else "native-deployment-fence-request.json")
            files, package = native_deployment_payload.complete_fence_payload(
                self.bases[f"research-fence-{fence_operation}.zip"],
                fence_operation,
                dynamic={
                    request_name: canonical(request),
                    "native-vendor-stacks.json": self.catalog_raw,
                })
            status, raw = self._journaled_deploy(
                context, phase="fence-requested", role="research",
                installer=(
                    "install-native-deployment-fence-recovery-bootstrap.sh"
                    if recovery else
                    "install-native-deployment-fence-bootstrap.sh"),
                files=files, extras={}, semantic={
                    "operation": (
                        "recovery-fence-acquire" if recovery
                        else "legacy-fence-acquire"),
                    "request_sha256": request["request_sha256"],
                    "package_sha256": package["package_sha256"],
                }, timeout=300)
        if status != 0:
            self._append(
                context, "recovery-required",
                evidence(outcome="transport-ambiguous"))
            raise NativeStackDeployError("native_deployment_fence_unresolved")
        try:
            reply = _validate_fence_reply(_reply(raw, "fence_reply"), plan)
        except Exception:
            self._append(
                context, "recovery-required",
                evidence(outcome="transport-ambiguous"))
            raise
        self._append(
            context, "fenced", evidence(
                outcome="fenced",
                fence_evidence_sha256=reply["evidence_sha256"]))
        return reply

    def _validate_install_result(
        self, raw: bytes, plan: Mapping[str, Any], role: str,
    ) -> str | None:
        try:
            value = _reply(raw, f"{role}_install_reply")
        except NativeStackDeployError:
            return None
        if role == "gateway":
            fields = {
                "schema", "status", "deployment_id", "plan_sha256",
                "package_sha256", "release_id", "backup_id",
                "closed_firewall_sha256",
            }
            valid = (
                set(value) == fields
                and value["schema"]
                == "secure-sandbox-native-gateway-install-result-v1"
                and value["status"] == "installed-default-closed"
                and value["deployment_id"] == plan["deployment_id"]
                and value["plan_sha256"] == plan["plan_sha256"]
                and value["package_sha256"] == plan["gateway_package_sha256"]
                and SHA256.fullmatch(str(value["release_id"])) is not None
                and SHA256.fullmatch(
                    str(value["closed_firewall_sha256"])) is not None
                and isinstance(value["backup_id"], str)
            )
        else:
            fields = {
                "schema", "status", "research_release_id", "package_sha256",
                "deployment_id", "projection", "live_policy_sha256",
                "persistent_policy_sha256",
            }
            valid = (
                set(value) == fields
                and value["schema"]
                == "secure-sandbox-native-research-install-result-v1"
                and value["status"] == "installed-default-closed"
                and value["deployment_id"] == plan["deployment_id"]
                and value["package_sha256"] == plan["research_package_sha256"]
                and value["projection"]
                == "closed-pending-live-qualification-and-driver"
                and all(
                    SHA256.fullmatch(str(value[name])) is not None
                    for name in (
                        "research_release_id", "live_policy_sha256",
                        "persistent_policy_sha256"))
            )
        return hashlib.sha256(raw).hexdigest() if valid else None

    def install_gateway(
        self, context: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any], dict[str, Any]]:
        plan = context["plan"]
        _status, raw = self._journaled_deploy(
            context, phase="gateway-requested", role="gateway",
            installer="install-native-egress-gateway.sh",
            files=self.gateway_files,
            extras={"native-deployment-plan.json": (canonical(plan), 0o600)},
            semantic={
                "operation": "install-gateway",
                "deployment_id": plan["deployment_id"],
                "plan_sha256": plan["plan_sha256"],
                "package_sha256": plan["gateway_package_sha256"],
            })
        result_sha = self._validate_install_result(raw, plan, "gateway")
        gateway, research = self.probe_pair()
        pair = classify_pair(
            plan, context["prior_gateway"], context["prior_research"],
            gateway, research)
        self._append(
            context, "gateway-observed", evidence(
                outcome=pair,
                gateway_status=gateway, research_status=research,
                result_sha256=result_sha))
        return pair, gateway, research

    def install_research(
        self, context: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any], dict[str, Any]]:
        plan = context["plan"]
        _status, raw = self._journaled_deploy(
            context, phase="research-requested", role="research",
            installer="install-native-research-runtime.sh",
            files=self.research_files,
            extras={"native-deployment-plan.json": (canonical(plan), 0o600)},
            semantic={
                "operation": "install-research",
                "deployment_id": plan["deployment_id"],
                "plan_sha256": plan["plan_sha256"],
                "package_sha256": plan["research_package_sha256"],
            }, timeout=1800)
        result_sha = self._validate_install_result(raw, plan, "research")
        gateway, research = self.probe_pair()
        pair = classify_pair(
            plan, context["prior_gateway"], context["prior_research"],
            gateway, research)
        self._append(
            context, "research-observed", evidence(
                outcome=pair,
                gateway_status=gateway, research_status=research,
                result_sha256=result_sha))
        return pair, gateway, research

    def compensate_gateway(
        self, context: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        plan = context["plan"]
        selected_names = {
            "install-native-gateway-compensation.sh",
            "native_gateway_compensation.py", "native_install_transaction.py",
            "native_deployment.py", "install-native-egress-gateway.sh",
        }
        files = {name: self.gateway_files[name] for name in selected_names}
        status, raw = self._journaled_deploy(
            context, phase="compensation-requested", role="gateway",
            installer="install-native-gateway-compensation.sh",
            files=files,
            extras={"native-deployment-plan.json": (canonical(plan), 0o600)},
            semantic={
                "operation": "compensate-gateway",
                "deployment_id": plan["deployment_id"],
                "plan_sha256": plan["plan_sha256"],
                "candidate_package_sha256": plan["gateway_package_sha256"],
                "previous_package_sha256": plan[
                    "previous_gateway_package_sha256"],
            })
        result_sha = None
        try:
            result = _reply(raw, "gateway_compensation_reply")
            if result == {
                "schema": "secure-sandbox-native-gateway-compensation-result-v1",
                "status": "prior-restored",
            }:
                result_sha = hashlib.sha256(raw).hexdigest()
        except NativeStackDeployError:
            pass
        gateway, research = self.probe_pair()
        pair = classify_pair(
            plan, context["prior_gateway"], context["prior_research"],
            gateway, research)
        if status != 0 or pair != "prior-prior":
            self._append(
                context, "recovery-required", evidence(
                    outcome="recovery-required",
                    gateway_status=gateway, research_status=research,
                    result_sha256=result_sha))
            raise NativeStackDeployError(
                "native_deployment_gateway_compensation_unproved")
        self._append(
            context, "compensation-observed", evidence(
                outcome="prior-prior",
                gateway_status=gateway, research_status=research,
                result_sha256=result_sha))
        return gateway, research

    def release_fence(
        self, context: Mapping[str, Any], *, pair: str,
        expected_gateway_sha256: str, expected_research_sha256: str,
    ) -> dict[str, Any]:
        if pair not in {"prior-prior", "candidate-candidate"}:
            raise NativeStackDeployError("native_deployment_release_state_invalid")
        plan = context["plan"]
        request = native_deployment.make_release_request(plan)
        if pair == "candidate-candidate":
            status, raw = self._journaled_pipe(
                context, phase="release-requested",
                operation="native-deployment-lifecycle-release",
                request=request)
        else:
            files, package = native_deployment_payload.complete_fence_payload(
                self.bases["research-fence-release.zip"], "release",
                dynamic={
                    "native-deployment-release-request.json": canonical(request),
                    "native-vendor-stacks.json": self.catalog_raw,
                })
            status, raw = self._journaled_deploy(
                context, phase="release-requested", role="research",
                installer="install-native-deployment-fence-bootstrap-release.sh",
                files=files, extras={}, semantic={
                    "operation": "legacy-fence-release",
                    "request_sha256": request["request_sha256"],
                    "package_sha256": package["package_sha256"],
                }, timeout=300)
        if status != 0:
            self._append(
                context, "recovery-required",
                evidence(outcome="transport-ambiguous"))
            raise NativeStackDeployError("native_deployment_release_unresolved")
        try:
            reply = _validate_fence_reply(
                _reply(raw, "release_reply"), plan, released=True)
        except Exception:
            self._append(
                context, "recovery-required",
                evidence(outcome="transport-ambiguous"))
            raise
        gateway, research = self.probe_pair()
        if pair == "prior-prior":
            observed_pair = (
                "prior-prior"
                if _status_sha256(gateway)
                == _status_sha256(context["prior_gateway"])
                and _status_sha256(research)
                == _status_sha256(context["prior_research"])
                else "unknown")
        else:
            observed_pair = classify_pair(
                plan, context["prior_gateway"], context["prior_research"],
                gateway, research)
        if (
            observed_pair != pair
            or _status_sha256(gateway) != expected_gateway_sha256
            or _status_sha256(research) != expected_research_sha256
        ):
            self._append(
                context, "recovery-required", evidence(
                    outcome="recovery-required",
                    gateway_status=gateway, research_status=research))
            raise NativeStackDeployError(
                "native_deployment_post_release_state_changed")
        self._append(
            context, "release-observed", evidence(
                outcome=pair,
                gateway_status=gateway, research_status=research,
                fence_evidence_sha256=reply["evidence_sha256"],
                terminal_sha256=reply["terminal_sha256"],
                result_sha256=hashlib.sha256(raw).hexdigest()))
        terminal_phase = (
            "committed" if pair == "candidate-candidate" else "rolled-back")
        terminal = self._append(
            context, terminal_phase, evidence(
                outcome=terminal_phase,
                gateway_status=gateway, research_status=research,
                terminal_sha256=reply["terminal_sha256"]))
        self.journal.complete(terminal)
        return terminal

    def _context(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        prior_gateway: Mapping[str, Any], prior_research: Mapping[str, Any],
        *, apply_authorization_sha256: str | None = None,
    ) -> dict[str, Any]:
        return {
            "plan": dict(plan), "authorization": dict(authorization),
            "prior_gateway": dict(prior_gateway),
            "prior_research": dict(prior_research),
            "apply_authorization_sha256": (
                authorization["authorization_sha256"]
                if apply_authorization_sha256 is None
                else apply_authorization_sha256),
        }

    def _mark_recovery_required(
        self, context: Mapping[str, Any], *, outcome: str = "recovery-required",
        gateway: Mapping[str, Any] | None = None,
        research: Mapping[str, Any] | None = None,
    ) -> None:
        loaded = self.journal.load()
        if loaded is None:
            return
        last = loaded[1][-1]
        if last["phase"] in TERMINAL_PHASES or last["phase"] == "recovery-required":
            return
        # The boundary record closes the original authority.  A subsequent
        # recovery authorization may change only after this exact phase.
        original = dict(context)
        original["authorization"] = {
            "authorization_sha256": last["authorization_sha256"]}
        original["apply_authorization_sha256"] = last[
            "apply_authorization_sha256"]
        self._append(
            original, "recovery-required", evidence(
                outcome=outcome,
                gateway_status=gateway, research_status=research))

    def _run_forward(
        self, context: Mapping[str, Any], *, starting_pair: str,
        gateway: Mapping[str, Any], research: Mapping[str, Any],
    ) -> dict[str, Any]:
        pair = starting_pair
        if pair == "prior-prior":
            pair, gateway, research = self.install_gateway(context)
        if pair == "prior-prior":
            return self.release_fence(
                context, pair=pair,
                expected_gateway_sha256=_status_sha256(gateway),
                expected_research_sha256=_status_sha256(research))
        if pair == "candidate-prior":
            pair, gateway, research = self.install_research(context)
        if pair == "candidate-candidate":
            return self.release_fence(
                context, pair=pair,
                expected_gateway_sha256=_status_sha256(gateway),
                expected_research_sha256=_status_sha256(research))
        if pair == "candidate-prior":
            if _status_sha256(gateway) != _status_sha256(
                context["prior_gateway"]
            ):
                gateway, research = self.compensate_gateway(context)
            return self.release_fence(
                context, pair="prior-prior",
                expected_gateway_sha256=_status_sha256(gateway),
                expected_research_sha256=_status_sha256(research))
        if pair == "prior-prior":
            return self.release_fence(
                context, pair=pair,
                expected_gateway_sha256=_status_sha256(gateway),
                expected_research_sha256=_status_sha256(research))
        self._mark_recovery_required(
            context, gateway=gateway, research=research)
        raise NativeStackDeployError("native_deployment_state_recovery_required")

    def apply(
        self, plan_response: object, authorization_value: object, *, now: int,
        receipt_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], None],
    ) -> dict[str, Any]:
        plan, prior_gateway, prior_research = self.validate_plan_response(
            plan_response, now=now, require_fresh=True)
        authorization = native_deployment.validate_authorization(
            authorization_value, plan, now=now,
            expected_host_release_id=self.release.release_id)
        if authorization["operation"] != native_deployment.APPLY_OPERATION:
            raise NativeStackDeployError(
                "native_deployment_apply_authorization_invalid")
        receipt_verifier(authorization, plan)
        if self.journal.load() is not None:
            raise NativeStackDeployError("native_deployment_recovery_required")
        current_gateway, current_research = self.probe_pair()
        native_deployment.validate_plan_predecessor_statuses(
            plan, gateway_status=current_gateway,
            research_status=current_research)
        # Invalid/stale/cancelled consume requests must leave no deployment
        # state behind.  Promote the side-effect-free read lock only after the
        # exact authorization receipt and predecessor have both been proven.
        self.journal.promote()
        context = self._context(
            plan, authorization, prior_gateway, prior_research)
        self._append(context, "authorized", evidence(outcome="authorized"))
        try:
            self.acquire_fence(
                context, observed_research=current_research)
            starting_pair = classify_pair(
                plan, prior_gateway, prior_research,
                current_gateway, current_research)
            return self._run_forward(
                context, starting_pair=starting_pair,
                gateway=current_gateway, research=current_research)
        except NativeStackDeployError:
            self._mark_recovery_required(context)
            raise


def verify_pending_authorization_receipt(
    authorization: Mapping[str, Any], plan: Mapping[str, Any], *,
    receipt_root: Path = RECEIPTS,
) -> None:
    value = _trusted_json(
        receipt_root / f"{authorization['authorization_id']}.json",
        "authorization_receipt")
    fields = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "native_deployment_id", "native_deployment_plan_sha256",
        "native_deployment_operation", "native_deployment_recovery_action",
        "native_deployment_active_journal_sha256", "host_release_id",
    }
    if (
        set(value) != fields
        or value["schema"]
        != "secure-sandbox-operator-authorization-receipt-v1"
        or value["request_id"] != authorization["authorization_id"]
        or value["request_sha256"] != authorization["request_sha256"]
        or value["status"] != "executing"
        or value["started_at"] != authorization["authorized_at"]
        or value["completed_at"] is not None
        or value["operation"] != authorization["operation"]
        or value["native_deployment_operation"] != authorization["operation"]
        or value["native_deployment_id"] != plan["deployment_id"]
        or value["native_deployment_plan_sha256"] != plan["plan_sha256"]
        or value["native_deployment_recovery_action"]
        != authorization["recovery_action"]
        or value["native_deployment_active_journal_sha256"]
        != authorization["active_journal_sha256"]
        or value["host_release_id"] != authorization["host_release_id"]
        or value["identity_evidence"] != "operator-declared"
        or value["authorization_method"] != "touch-id"
        or value["ceremony"] != "approve"
        or value["resource"] != native_deployment.RESOURCE
        or value["exit_status"] is not None
        or value["stdout_sha256"] is not None
        or value["stderr_sha256"] is not None
        or hashlib.sha256(
            str(value["declared_agent"]).encode("utf-8")).hexdigest()
        != authorization["requesting_agent_sha256"]
        or hashlib.sha256(
            str(value["declared_session"]).encode("utf-8")).hexdigest()
        != authorization["requesting_session_sha256"]
        or hashlib.sha256(canonical(value)).hexdigest()
        != authorization["pending_receipt_sha256"]
    ):
        raise NativeStackDeployError(
            "native_deployment_authorization_receipt_invalid")


def _json_argument(value: str, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise NativeStackDeployError(
            f"native_deployment_{label}_invalid") from error
    if not isinstance(parsed, dict):
        raise NativeStackDeployError(f"native_deployment_{label}_invalid")
    canonical(parsed)
    return parsed


def _public_status(journal: Journal) -> dict[str, Any]:
    try:
        loaded = journal.load()
    except NativeStackDeployError as error:
        body = {
            "state": "recovery-required", "phase": "state-invalid",
            "deployment_id": None, "host_release_id": None,
            "active_journal_sha256": None,
            "error_sha256": hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
        }
    else:
        if loaded is None:
            body = {
                "state": "ready", "phase": None, "deployment_id": None,
                "host_release_id": None, "active_journal_sha256": None,
                "error_sha256": None,
            }
        else:
            pointer, records = loaded
            body = {
                "state": "recovery-required",
                "phase": records[-1]["phase"],
                "deployment_id": pointer["deployment_id"],
                "host_release_id": pointer["host_release_id"],
                "active_journal_sha256": pointer["record_sha256"],
                "error_sha256": None,
            }
    return {
        "schema": PUBLIC_STATUS_SCHEMA, **body,
        "status_sha256": digest(body),
    }


def deployment_gate_state(
    host_install_fd: int, *, state_root: Path = STATE_ROOT,
    host_install_root: Path = INSTALL_ROOT, trusted_uid: int = 0,
    trusted_gid: int = 0, transition_release_id: str | None = None,
) -> dict[str, Any]:
    """Return the content-free Host-update/native-operation admission gate."""
    try:
        with ReleaseAuthority(
            release=(
                HERE if transition_release_id is None
                else host_install_root / "releases" / transition_release_id
            ), install_root=host_install_root,
            host_install_fd=host_install_fd, expected_uid=trusted_uid,
            allow_install_transition=True,
            transition_release_id=transition_release_id,
        ) as authority:
            journal = Journal(
                state_root, host_install_fd=authority.install_fd,
                host_install_root=host_install_root,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
            journal.lock(create=False)
            try:
                loaded = journal.load()
                body = {
                    "state": "ready" if loaded is None else "active",
                    "active_journal_sha256": (
                        None if loaded is None
                        else loaded[0]["record_sha256"]),
                }
            finally:
                journal.unlock()
    except Exception:
        body = {"state": "invalid", "active_journal_sha256": None}
    return {
        "schema": GATE_STATE_SCHEMA, **body, "gate_sha256": digest(body),
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-install-fd", required=True, type=int)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan")
    subparsers.add_parser("recovery-plan")
    subparsers.add_parser("status")
    consume = subparsers.add_parser("consume")
    consume.add_argument("--plan-json", required=True)
    consume.add_argument("--authorization-json", required=True)
    recover = subparsers.add_parser("recover")
    recover.add_argument("--recovery-json", required=True)
    recover.add_argument("--authorization-json", required=True)
    args = parser.parse_args(arguments)
    try:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise NativeStackDeployError("native_deployment_root_required")
        with ReleaseAuthority(host_install_fd=args.host_install_fd) as release:
            journal = Journal(host_install_fd=release.install_fd)
            if args.command == "status":
                journal.lock(create=False)
                try:
                    result = _public_status(journal)
                finally:
                    journal.unlock()
            else:
                # Lock order is Host install root -> native stack manager ->
                # native session manager -> deployment journal.  Keep both
                # native locks through the immutable terminal publication.
                with NativeRuntimeAuthority(release):
                    journal.lock(create=False)
                    try:
                        coordinator = Coordinator(release, journal)
                        if args.command == "plan":
                            result = coordinator.plan()
                        elif args.command == "recovery-plan":
                            result = coordinator.recovery_plan()
                        elif args.command == "consume":
                            plan_response = _json_argument(
                                args.plan_json, "plan_argument")
                            authorization = _json_argument(
                                args.authorization_json,
                                "authorization_argument")
                            result = coordinator.apply(
                                plan_response, authorization,
                                now=int(time.time()),
                                receipt_verifier=(
                                    verify_pending_authorization_receipt))
                        else:
                            recovery = _json_argument(
                                args.recovery_json, "recovery_argument")
                            authorization = _json_argument(
                                args.authorization_json,
                                "authorization_argument")
                            result = coordinator.recover(
                                recovery, authorization,
                                now=int(time.time()),
                                receipt_verifier=(
                                    verify_pending_authorization_receipt))
                    finally:
                        journal.unlock()
            sys.stdout.buffer.write(canonical(result))
            return 0
    except Exception as error:
        code = str(error)
        if not code.startswith("native_deployment_"):
            code = "native_deployment_rejected"
        print(code, file=sys.stderr)
        return 1


class _CoordinatorRecoveryMixin:
    def recovery_plan(self) -> dict[str, Any]:
        loaded = self.journal.load()
        if loaded is None:
            raise NativeStackDeployError("native_deployment_no_active_journal")
        pointer, records = loaded
        first, last = records[0], records[-1]
        gateway: dict[str, Any] | None = None
        research: dict[str, Any] | None = None
        try:
            gateway, research = self.probe_pair()
        except NativeStackDeployError:
            # A protected guest installer deliberately makes the ordinary
            # status probe fail while its durable PENDING marker exists.  The
            # immutable request record remains enough to authorize one exact
            # replay; do not mislabel this as an observed state pair.
            pair = "unavailable"
        else:
            # A valid observation which is neither exact prior nor candidate
            # is not transport unavailability.  Preserve the fail-closed
            # classification error and authorize no replay over mixed state.
            pair = classify_pair(
                first["plan"], first["prior_gateway"], first["prior_research"],
                gateway, research)
        actions: list[str] = []
        if pair == "unavailable":
            request_phase = next((
                item["phase"] for item in reversed(records)
                if item["phase"] in REQUEST_PHASES
            ), None)
            release_intent = next((
                item["evidence"]["outcome"] for item in reversed(records)
                if item["phase"] in {
                    "gateway-observed", "research-observed",
                    "recovery-observed", "compensation-observed"}
                and item["evidence"]["outcome"] in {
                    "prior-prior", "candidate-candidate"}
            ), None)
            if request_phase in {
                "fence-requested", "gateway-requested", "research-requested"
            }:
                actions.append("resume")
            elif request_phase == "compensation-requested":
                actions.append("rollback")
            elif request_phase == "release-requested":
                if release_intent == "candidate-candidate":
                    actions.append("resume")
                elif release_intent == "prior-prior":
                    actions.append("rollback")
        else:
            if pair in {"prior-prior", "candidate-prior"}:
                actions.append("rollback")
            if pair in {
                "prior-prior", "candidate-prior", "candidate-candidate"
            }:
                actions.append("resume")
        body = {
            "active_journal_sha256": pointer["record_sha256"],
            "deployment_id": pointer["deployment_id"],
            "host_release_id": pointer["host_release_id"],
            "phase": last["phase"], "observed_pair": pair,
            "allowed_actions": actions,
            "plan_response": {
                "schema": PLAN_RESPONSE_SCHEMA,
                "plan": first["plan"],
                "prior_gateway": first["prior_gateway"],
                "prior_research": first["prior_research"],
                "payload_container_sha256": first[
                    "payload_container_sha256"],
                "response_sha256": digest({
                    "plan": first["plan"],
                    "prior_gateway": first["prior_gateway"],
                    "prior_research": first["prior_research"],
                    "payload_container_sha256": first[
                        "payload_container_sha256"],
                }),
            },
            "gateway_status_sha256": (
                None if gateway is None else _status_sha256(gateway)),
            "research_status_sha256": (
                None if research is None else _status_sha256(research)),
        }
        return {
            "schema": RECOVERY_PLAN_SCHEMA, **body,
            "recovery_plan_sha256": digest(body),
        }

    def recover(
        self, recovery_value: object, authorization_value: object, *, now: int,
        receipt_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], None],
    ) -> dict[str, Any]:
        current = self.recovery_plan()
        if not isinstance(recovery_value, dict) or recovery_value != current:
            raise NativeStackDeployError(
                "native_deployment_recovery_plan_changed")
        plan, prior_gateway, prior_research = self.validate_plan_response(
            current["plan_response"], now=now, require_fresh=False)
        authorization = native_deployment.validate_authorization(
            authorization_value, plan, now=now,
            expected_host_release_id=self.release.release_id)
        if (
            authorization["operation"] != native_deployment.RECOVER_OPERATION
            or authorization["active_journal_sha256"]
            != current["active_journal_sha256"]
            or authorization["recovery_action"] not in current["allowed_actions"]
        ):
            raise NativeStackDeployError(
                "native_deployment_recovery_authorization_invalid")
        receipt_verifier(authorization, plan)
        loaded = self.journal.load()
        if loaded is None or loaded[0]["record_sha256"] != current[
            "active_journal_sha256"
        ]:
            raise NativeStackDeployError("native_deployment_active_changed")
        if loaded[1][-1]["phase"] in TERMINAL_PHASES:
            self.journal.complete(loaded[1][-1])
            return loaded[1][-1]
        context = self._context(
            plan, authorization, prior_gateway, prior_research,
            apply_authorization_sha256=loaded[1][0][
                "apply_authorization_sha256"])
        last_request_phase = next((
            item["phase"] for item in reversed(loaded[1])
            if item["phase"] in REQUEST_PHASES
        ), None)
        release_observation = next((
            item for item in reversed(loaded[1])
            if item["phase"] in {
                "gateway-observed", "research-observed",
                "recovery-observed", "compensation-observed"}
            and item["evidence"]["outcome"] in {
                "prior-prior", "candidate-candidate"}
        ), None)
        release_intent = (
            None if release_observation is None
            else release_observation["evidence"]["outcome"])
        self._mark_recovery_required(context)
        try:
            if last_request_phase == "release-requested":
                if (
                    release_intent not in {"prior-prior", "candidate-candidate"}
                    or (
                        release_intent == "candidate-candidate"
                        and authorization["recovery_action"] != "resume"
                    )
                    or (
                        release_intent == "prior-prior"
                        and authorization["recovery_action"] != "rollback"
                    )
                ):
                    raise NativeStackDeployError(
                        "native_deployment_release_recovery_state_invalid")
                assert release_observation is not None
                return self.release_fence(
                    context, pair=release_intent,
                    expected_gateway_sha256=release_observation[
                        "evidence"]["gateway_status_sha256"],
                    expected_research_sha256=release_observation[
                        "evidence"]["research_status_sha256"])

            # A guest PENDING marker intentionally makes the ordinary probe
            # fail.  Resolve the exact latest immutable request intent first;
            # every installer is plan-bound and idempotently recovers its own
            # pending transaction before performing new work.
            if current["observed_pair"] == "unavailable":
                action = authorization["recovery_action"]
                if last_request_phase == "fence-requested" and action == "resume":
                    self.acquire_fence(
                        context, observed_research=prior_research)
                    gateway, research = self.probe_pair()
                    pair = classify_pair(
                        plan, prior_gateway, prior_research,
                        gateway, research)
                    self._append(
                        context, "recovery-observed", evidence(
                            outcome=pair, gateway_status=gateway,
                            research_status=research))
                elif last_request_phase == "gateway-requested" and action == "resume":
                    pair, gateway, research = self.install_gateway(context)
                elif last_request_phase == "research-requested" and action == "resume":
                    pair, gateway, research = self.install_research(context)
                elif (
                    last_request_phase == "compensation-requested"
                    and action == "rollback"
                ):
                    gateway, research = self.compensate_gateway(context)
                    pair = "prior-prior"
                else:
                    raise NativeStackDeployError(
                        "native_deployment_pending_recovery_invalid")
            else:
                gateway, research = self.probe_pair()
                pair = classify_pair(
                    plan, prior_gateway, prior_research, gateway, research)
                self.acquire_fence(context, observed_research=research)
                self._append(
                    context, "recovery-observed", evidence(
                        outcome=pair,
                        gateway_status=gateway, research_status=research))
            if authorization["recovery_action"] == "rollback":
                if pair == "candidate-prior":
                    if _status_sha256(gateway) != _status_sha256(
                        prior_gateway
                    ):
                        gateway, research = self.compensate_gateway(context)
                    pair = "prior-prior"
                if pair != "prior-prior":
                    raise NativeStackDeployError(
                        "native_deployment_rollback_state_invalid")
                return self.release_fence(
                    context, pair=pair,
                    expected_gateway_sha256=_status_sha256(gateway),
                    expected_research_sha256=_status_sha256(research))
            return self._run_forward(
                context, starting_pair=pair,
                gateway=gateway, research=research)
        except NativeStackDeployError:
            self._mark_recovery_required(context)
            raise


Coordinator.recovery_plan = _CoordinatorRecoveryMixin.recovery_plan
Coordinator.recover = _CoordinatorRecoveryMixin.recover


if __name__ == "__main__":
    raise SystemExit(main())
