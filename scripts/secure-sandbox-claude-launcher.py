#!/usr/bin/python3 -I
"""Root-owned stable launcher for one verified host-controller release."""

from __future__ import annotations

import hashlib
import ctypes
import errno
import fcntl
import json
import os
import pwd
import re
import shutil
import stat
import sys
import time
import uuid
from pathlib import Path

INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
ACCOUNT_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
STATE_ROOT = ACCOUNT_HOME / "Library/Application Support/SecureSandbox/controller-state"
SCHEMA = "secure-sandbox-host-controller-release-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
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
LEGACY_RELEASE_ID = "cd29ebd476794c46437ddea59ca161551d2767a0f668a6eede5a1f18f9b660dd"
LOCK_INCOMPLETE_GRACE_SECONDS = 30.0
MAX_CONTROLLER_STATE_ENTRIES = 128
COORDINATION_CONTRACT_NAME = "native_stack_coordination_contract"
COORDINATION_CONTRACT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-contract-v1"
)
COORDINATION_ENFORCEMENT_NAME = "native-stack-coordination-enforcement.json"
COORDINATION_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-native-stack-coordination-enforcement-v1"
)
NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE = (
    "native-host-candidate-admission-v1"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME = (
    "native-host-candidate-enforcement.json"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME = (
    ".native-host-candidate-enforcement.pending"
)
NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA = (
    "secure-sandbox-native-host-candidate-enforcement-v1"
)
NATIVE_HOST_CANDIDATE_INVENTORY_SCHEMA = (
    "secure-sandbox-native-host-candidate-inventory-v1"
)
COORDINATION_REQUIRED_FEATURES = {
    "catalog-promotion-gate-v1",
    "deployment-promotion-admission-v1",
    "host-install-transition-fence-v1",
    "host-selector-two-way-gate-v1",
}
CURRENT_PAYLOAD_NAMES = frozenset({
    "authorization_broker", "authorization_service",
    "authorization_ui_bundle", "authorization_ui_sources",
    "control_client", "controller", "gpgv", "harness_lifecycle_manager",
    "installer_verifier", "model_profile_manager",
    "native_credential_helper_bundle", "native_credential_helper_service",
    "native_host_products_container", "native_host_products_manifest",
    "native_host_products_notarization",
    "native_host_products_notarization_signature",
    "native_projection_consumer",
    "native_stack_backend", "native_stack_catalog_promoter",
    "native_stack_coordination_contract",
    "native_stack_credential_client", "native_stack_deployer",
    "native_stack_manager",
    "native_stack_session_manager", "native_stack_support",
    "native_stack_terminal_bridge", "native_deployment_payloads",
    "pki_anchor", "release_manager",
    "seed_gateway", "seed_research", "seed_target", "seed_verifier",
    "ssh_config", "vm_maintenance",
})
PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES = CURRENT_PAYLOAD_NAMES - {
    "native_host_products_notarization_signature",
}
PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES = (
    PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES - {
        "native_stack_coordination_contract",
    }
)
PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES = PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES - {
    "native_stack_deployer", "native_deployment_payloads",
}
PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES = PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES - {
    "native_stack_session_manager"
}
PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES = (
    PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES - {
        "native_stack_terminal_bridge"
    }
)
NATIVE_CREDENTIAL_PAYLOAD_NAMES = frozenset({
    "native_credential_helper_bundle", "native_credential_helper_service",
    "native_host_products_container", "native_host_products_manifest",
    "native_host_products_notarization",
    "native_host_products_notarization_signature",
    "native_projection_consumer",
    "native_stack_credential_client",
})
PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES = (
    PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES
    - NATIVE_CREDENTIAL_PAYLOAD_NAMES
)
PRE_NATIVE_STACK_PAYLOAD_NAMES = PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES - {
    "native_stack_manager", "native_stack_backend",
    "native_stack_catalog_promoter", "native_stack_support",
}
PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES = PRE_NATIVE_STACK_PAYLOAD_NAMES - {
    "harness_lifecycle_manager"
}
PRE_MODEL_PROFILE_PAYLOAD_NAMES = PRE_NATIVE_STACK_PAYLOAD_NAMES - {
    "model_profile_manager"
}
PRE_HARNESS_LIFECYCLE_PRE_MODEL_PROFILE_PAYLOAD_NAMES = (
    PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES - {"model_profile_manager"}
)


class LaunchFailure(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise LaunchFailure("controller_coordination_record_invalid") from error


def _reject_extended_acl(descriptor: int) -> None:
    if (_ACL_GET_FD_NP is None or _ACL_GET_ENTRY is None
            or _ACL_FREE is None):
        if sys.platform != "darwin":
            return
        raise LaunchFailure("controller_coordination_record_untrusted")
    ctypes.set_errno(0)
    acl = _ACL_GET_FD_NP(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise LaunchFailure("controller_coordination_record_untrusted")
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = _ACL_GET_ENTRY(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0 or ctypes.get_errno() not in {errno.ENOENT, errno.EINVAL}:
            raise LaunchFailure("controller_coordination_record_untrusted")
    finally:
        if _ACL_FREE(acl) != 0:
            raise LaunchFailure("controller_coordination_record_untrusted")


def _stable_root_file(
    path: Path, expected_uid: int, expected_mode: int, *,
    allowed_link_counts: frozenset[int] = frozenset({1}),
    maximum: int = 1024 * 1024 * 1024,
) -> tuple[bytes, tuple[int, int]]:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise LaunchFailure("controller_coordination_record_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        _reject_extended_acl(descriptor)
        blocks = []
        size = 0
        while True:
            block = os.read(
                descriptor, min(1024 * 1024, maximum + 1 - size),
            )
            if not block:
                break
            blocks.append(block)
            size += len(block)
            if size > maximum:
                raise LaunchFailure("controller_coordination_record_untrusted")
        raw = b"".join(blocks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda info: (
        info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
        info.st_gid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns,
    )
    current = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or opened.st_nlink not in allowed_link_counts
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or not 0 <= opened.st_size <= maximum or len(raw) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or identity(after) != identity(current)
    ):
        raise LaunchFailure("controller_coordination_record_untrusted")
    return raw, (opened.st_dev, opened.st_ino)


def _stable_root_directory(
    path: Path, expected_uid: int, expected_mode: int,
) -> None:
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise LaunchFailure(
            "controller_release_directory_untrusted") from error
    try:
        opened = os.fstat(descriptor)
        _reject_extended_acl(descriptor)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = path.lstat()
    identity = lambda info: (
        info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
        info.st_gid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns,
    )
    if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or identity(after) != identity(named)):
        raise LaunchFailure("controller_release_directory_untrusted")


def _coordination_floor(
    install_root: Path, expected_uid: int,
) -> dict[str, object] | None:
    # This root-owned 0444 projection is the user-space execution fence.  The
    # authoritative 0600 floor remains private to the release manager; its
    # digest is bound here so the two records can be reconciled by root.
    path = install_root / COORDINATION_ENFORCEMENT_NAME
    if not os.path.lexists(path):
        return None
    raw, _identity = _stable_root_file(path, expected_uid, 0o444)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaunchFailure("controller_coordination_floor_invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "minimum_epoch", "minimum_features",
            "authoritative_floor_sha256",
        }
        or value.get("schema") != COORDINATION_ENFORCEMENT_SCHEMA
        or not isinstance(value.get("minimum_epoch"), int)
        or isinstance(value.get("minimum_epoch"), bool)
        or value["minimum_epoch"] < 1
        or not isinstance(value.get("minimum_features"), list)
        or any(
            not isinstance(feature, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", feature) is None
            for feature in value["minimum_features"]
        )
        or value["minimum_features"]
            != sorted(set(value["minimum_features"]))
        or not COORDINATION_REQUIRED_FEATURES
            <= set(value["minimum_features"])
        or SHA256.fullmatch(str(value.get(
            "authoritative_floor_sha256"))) is None
        or _canonical_json(value) != raw
    ):
        raise LaunchFailure("controller_coordination_floor_invalid")
    return value


def _candidate_payload_inventory_sha256() -> str:
    return digest(_canonical_json({
        "payload_names": sorted(CURRENT_PAYLOAD_NAMES),
        "schema": NATIVE_HOST_CANDIDATE_INVENTORY_SCHEMA,
    }))


def _native_host_candidate_enforcement(
    install_root: Path, expected_uid: int,
) -> dict[str, str] | None:
    # This public projection makes the irreversible admission minimum visible
    # to the stable launcher.  Root separately retains the authoritative 0600
    # record whose digest is bound here.
    final_path = install_root / NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME
    pending_path = (
        install_root / NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME
    )
    final = (
        _stable_root_file(
            final_path, expected_uid, 0o444,
            allowed_link_counts=frozenset({1, 2}),
        )
        if os.path.lexists(final_path) else None
    )
    pending = (
        _stable_root_file(
            pending_path, expected_uid, 0o444,
            allowed_link_counts=frozenset({1, 2}),
        )
        if os.path.lexists(pending_path) else None
    )
    if final is not None and pending is not None:
        if final[0] != pending[0] or final[1] != pending[1]:
            raise LaunchFailure(
                "controller_native_host_candidate_enforcement_conflict"
            )
    observed = final if final is not None else pending
    if observed is None:
        return None
    raw = observed[0]
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaunchFailure(
            "controller_native_host_candidate_enforcement_invalid"
        ) from error
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
            != _candidate_payload_inventory_sha256()
        or SHA256.fullmatch(str(value.get(
            "authoritative_floor_sha256", ""))) is None
        or _canonical_json(value) != raw
    ):
        raise LaunchFailure(
            "controller_native_host_candidate_enforcement_invalid"
        )
    return value


def _remove_claimed_lock(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


def _claim_stale_lock(lock: Path, state_root: Path) -> bool:
    claimed = state_root / f".coordination.lock.reclaim-{os.getpid()}-{uuid.uuid4()}"
    try:
        os.rename(lock, claimed)
    except FileNotFoundError:
        return False
    _remove_claimed_lock(claimed)
    return True


def _cleanup_lock_tombstones(state_root: Path) -> None:
    entries = list(state_root.iterdir())
    if len(entries) > MAX_CONTROLLER_STATE_ENTRIES:
        raise LaunchFailure("controller_state_entry_limit_exceeded")
    prefixes = (".coordination.lock.reclaim-", ".coordination.lock.release-")
    for entry in entries:
        if not entry.name.startswith(prefixes):
            continue
        info = entry.lstat()
        if entry.is_symlink() or not entry.is_dir() or info.st_uid != os.geteuid():
            raise LaunchFailure("controller_lock_tombstone_invalid")
        if time.time() - info.st_mtime >= LOCK_INCOMPLETE_GRACE_SECONDS:
            _remove_claimed_lock(entry)


def acquire_lock(state_root: Path, timeout: float = 10.0) -> Path:
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_root.is_symlink() or not state_root.is_dir() or state_root.stat().st_uid != os.geteuid():
        raise LaunchFailure("controller_state_directory_invalid")
    os.chmod(state_root, 0o700)
    _cleanup_lock_tombstones(state_root)
    lock = state_root / "coordination.lock"
    deadline = time.monotonic() + timeout
    while True:
        try:
            lock.mkdir(mode=0o700)
            pid_temporary = lock / ".pid.new"
            descriptor = os.open(pid_temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(pid_temporary, lock / "pid")
            return lock
        except FileExistsError:
            stale = False
            try:
                pid = int((lock / "pid").read_text(encoding="ascii").strip())
                os.kill(pid, 0)
            except ProcessLookupError:
                stale = True
            except PermissionError:
                stale = False
            except (FileNotFoundError, ValueError):
                try:
                    stale = time.time() - lock.stat().st_mtime >= LOCK_INCOMPLETE_GRACE_SECONDS
                except FileNotFoundError:
                    continue
            except OSError:
                stale = False
            if stale and _claim_stale_lock(lock, state_root):
                continue
            if time.monotonic() >= deadline:
                raise LaunchFailure("controller_coordination_lock_timeout")
            time.sleep(0.05)


def release_lock(lock: Path) -> None:
    tombstone = lock.parent / f".coordination.lock.release-{os.getpid()}-{uuid.uuid4()}"
    try:
        os.rename(lock, tombstone)
    except FileNotFoundError:
        return
    _remove_claimed_lock(tombstone)


def load_release_snapshot(
    install_root: Path, expected_uid: int = 0, *,
    require_controller: bool = True,
) -> tuple[Path, str, bytes | None]:
    releases = install_root / "releases"
    current = install_root / "current"
    if not current.is_symlink():
        raise LaunchFailure("controller_current_missing")
    release = current.resolve(strict=True)
    try:
        relative = release.relative_to(releases.resolve(strict=True))
    except ValueError as error:
        raise LaunchFailure("controller_current_escapes_release_root") from error
    if len(relative.parts) != 1 or not SHA256.fullmatch(relative.name):
        raise LaunchFailure("controller_release_id_invalid")
    _stable_root_directory(install_root, expected_uid, 0o755)
    _stable_root_directory(releases, expected_uid, 0o755)
    _stable_root_directory(release, expected_uid, 0o555)
    manifest_path = release / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise LaunchFailure("controller_manifest_invalid")
    try:
        manifest_raw, _manifest_identity = _stable_root_file(
            manifest_path, expected_uid, 0o444, maximum=1024 * 1024,
        )
        manifest = json.loads(manifest_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaunchFailure("controller_manifest_invalid") from error
    if manifest.get("schema") != SCHEMA or manifest.get("release_id") != relative.name:
        raise LaunchFailure("controller_manifest_identity_mismatch")
    payloads = manifest.get("payloads")
    payload_names = set(payloads) if isinstance(payloads, dict) else set()
    coordination_floor = _coordination_floor(install_root, expected_uid)
    candidate_enforcement = _native_host_candidate_enforcement(
        install_root, expected_uid,
    )
    if (
        coordination_floor is not None
        and COORDINATION_CONTRACT_NAME not in payload_names
    ):
        raise LaunchFailure("controller_release_below_coordination_floor")
    if (
        coordination_floor is None
        and COORDINATION_CONTRACT_NAME in payload_names
    ):
        raise LaunchFailure("controller_coordination_floor_missing")
    if (candidate_enforcement is not None
            and payload_names != CURRENT_PAYLOAD_NAMES):
        raise LaunchFailure(
            "controller_release_below_native_host_candidate_floor"
        )
    pre_profiled_touchid_names = {"authorization_broker", "authorization_service", "authorization_ui", "authorization_ui_sources", "control_client", "controller", "gpgv", "installer_verifier", "pki_anchor", "release_manager", "seed_gateway", "seed_research", "seed_target", "seed_verifier", "ssh_config", "vm_maintenance"}
    pre_touchid_names = {"authorization_broker", "control_client", "controller", "gpgv", "installer_verifier", "pki_anchor", "release_manager", "seed_gateway", "seed_research", "seed_target", "seed_verifier", "ssh_config", "vm_maintenance"}
    pre_maintenance_names = {"authorization_broker", "control_client", "controller", "gpgv", "installer_verifier", "pki_anchor", "release_manager", "ssh_config"}
    pre_authorization_names = {"control_client", "controller", "gpgv", "installer_verifier", "pki_anchor", "ssh_config"}
    pre_control_names = {"controller", "gpgv", "installer_verifier", "op_agents", "pki_anchor", "ssh_config"}
    pre_installer_names = {"controller", "op_agents", "pki_anchor", "ssh_config"}
    legacy_names = {"controller", "op_agents", "ssh_config"}
    if (payload_names != CURRENT_PAYLOAD_NAMES
            and payload_names != PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES
            and payload_names != PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
            and payload_names != PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES
            and payload_names != PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES
            and payload_names != PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES
            and payload_names != PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES
            and payload_names != PRE_NATIVE_STACK_PAYLOAD_NAMES
            and payload_names != PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES
            and payload_names != PRE_MODEL_PROFILE_PAYLOAD_NAMES
            and payload_names
                != PRE_HARNESS_LIFECYCLE_PRE_MODEL_PROFILE_PAYLOAD_NAMES
            and payload_names != pre_profiled_touchid_names
            and payload_names != pre_touchid_names
            and payload_names != pre_maintenance_names
            and payload_names != pre_authorization_names
            and payload_names != pre_control_names
            and payload_names != pre_installer_names
            and not (relative.name == LEGACY_RELEASE_ID and payload_names == legacy_names)):
        raise LaunchFailure("controller_manifest_payloads_invalid")
    identity = bytearray()
    controller_snapshot: bytes | None = None
    for name in sorted(payloads):
        expected = payloads[name]
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise LaunchFailure("controller_manifest_hash_invalid")
        path = release / name
        if path.is_symlink() or not path.is_file():
            raise LaunchFailure(f"controller_payload_invalid:{name}")
        info = path.stat()
        if info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise LaunchFailure(f"controller_permissions_invalid:{name}")
        raw, _payload_identity = _stable_root_file(
            path, expected_uid, stat.S_IMODE(info.st_mode),
        )
        actual = digest(raw)
        if actual != expected:
            raise LaunchFailure(f"controller_payload_hash_mismatch:{name}")
        identity.extend(f"{name}\0{actual}\n".encode("ascii"))
        if name == "controller":
            controller_snapshot = raw
    if digest(bytes(identity)) != relative.name:
        raise LaunchFailure("controller_release_digest_mismatch")
    if coordination_floor is not None:
        contract_path = release / COORDINATION_CONTRACT_NAME
        contract_raw, _contract_identity = _stable_root_file(
            contract_path, expected_uid, 0o444)
        try:
            contract = json.loads(contract_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LaunchFailure(
                "controller_coordination_contract_invalid") from error
        features = contract.get("features") if isinstance(
            contract, dict) else None
        epoch = contract.get("epoch") if isinstance(
            contract, dict) else None
        if (
            not isinstance(contract, dict)
            or set(contract) != {"schema", "epoch", "features"}
            or contract.get("schema") != COORDINATION_CONTRACT_SCHEMA
            or not isinstance(epoch, int) or isinstance(epoch, bool)
            or epoch < coordination_floor["minimum_epoch"]
            or not isinstance(features, list)
            or any(
                not isinstance(feature, str)
                or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", feature) is None
                for feature in features
            )
            or features != sorted(set(features))
            or not COORDINATION_REQUIRED_FEATURES <= set(features)
            or not set(coordination_floor["minimum_features"])
                <= set(features)
            or _canonical_json(contract) != contract_raw
        ):
            raise LaunchFailure(
                "controller_coordination_contract_invalid")
        has_candidate_feature = (
            NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE in features
        )
        if candidate_enforcement is None and has_candidate_feature:
            raise LaunchFailure(
                "controller_native_host_candidate_enforcement_missing"
            )
        if candidate_enforcement is not None and not has_candidate_feature:
            raise LaunchFailure(
                "controller_release_below_native_host_candidate_floor"
            )
    if require_controller and controller_snapshot is None:
        raise LaunchFailure("controller_payload_missing")
    return release, relative.name, controller_snapshot


def load_release(install_root: Path, expected_uid: int = 0) -> tuple[Path, str]:
    release, release_id, _controller = load_release_snapshot(
        install_root, expected_uid, require_controller=False,
    )
    return release, release_id


def verified_controller_command(controller: bytes) -> str:
    """Return the exact verified controller as an in-memory Bash program."""
    if (len(controller) > 256 * 1024
            or not controller.startswith(b"#!/bin/bash\n")
            or b"\0" in controller):
        raise LaunchFailure("controller_payload_invalid")
    try:
        command = controller.decode("ascii")
    except UnicodeDecodeError as error:
        raise LaunchFailure("controller_payload_invalid") from error
    if command.encode("ascii") != controller:
        raise LaunchFailure("controller_payload_invalid")
    return command


def controller_environment(
    marker: Path, release_id: str, *, release_dir: Path | None = None,
) -> dict[str, str]:
    environment = {
        "HOME": str(ACCOUNT_HOME),
        "LOGNAME": pwd.getpwuid(os.getuid()).pw_name,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECURE_SANDBOX_ACTIVE_MARKER": str(marker),
        "SECURE_SANDBOX_RELEASE_ID": release_id,
        "SECURE_SANDBOX_STATE_ROOT": str(STATE_ROOT),
        "USER": pwd.getpwuid(os.getuid()).pw_name,
    }
    if release_dir is not None:
        environment["SECURE_SANDBOX_RELEASE_DIR"] = str(release_dir)
    term = os.environ.get("TERM", "")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,63}", term):
        environment["TERM"] = term
    acceptance_run = os.environ.get("SECURE_SANDBOX_ACCEPTANCE_RUN_ID", "")
    acceptance_session = os.environ.get("SECURE_SANDBOX_ACCEPTANCE_SESSION_ID", "")
    uuid4 = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    if acceptance_run or acceptance_session:
        if not uuid4.fullmatch(acceptance_run) or not uuid4.fullmatch(acceptance_session):
            raise LaunchFailure("acceptance_context_invalid")
        environment["SECURE_SANDBOX_ACCEPTANCE_RUN_ID"] = acceptance_run
        environment["SECURE_SANDBOX_ACCEPTANCE_SESSION_ID"] = acceptance_session
    return environment


def main() -> int:
    marker: Path | None = None
    lock: Path | None = None
    host_lock = -1
    try:
        host_lock = os.open(
            INSTALL_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        fcntl.flock(host_lock, fcntl.LOCK_SH)
        lock = acquire_lock(STATE_ROOT)
        release, release_id, controller = load_release_snapshot(INSTALL_ROOT)
        if controller is None:
            raise LaunchFailure("controller_payload_missing")
        controller_command = verified_controller_command(controller)
        runs = STATE_ROOT / "active"
        runs.mkdir(mode=0o700, exist_ok=True)
        if runs.is_symlink() or not runs.is_dir() or runs.stat().st_uid != os.geteuid():
            raise LaunchFailure("controller_active_directory_invalid")
        os.chmod(runs, 0o700)
        marker = runs / f"{os.getpid()}-{uuid.uuid4()}.json"
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(
                descriptor,
                (json.dumps({"pid": os.getpid(), "release_id": release_id}, sort_keys=True) + "\n").encode("ascii"),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        release_lock(lock)
        lock = None
        fcntl.flock(host_lock, fcntl.LOCK_UN)
        os.close(host_lock)
        host_lock = -1
        environment = controller_environment(
            marker, release_id, release_dir=release,
        )
        os.execve(
            "/bin/bash",
            [
                "/bin/bash", "-c", controller_command,
                str(release / "controller"), *sys.argv[1:],
            ],
            environment,
        )
    except (LaunchFailure, OSError) as error:
        print(f"secure-sandbox-claude: {error}", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            release_lock(lock)
        if host_lock >= 0:
            fcntl.flock(host_lock, fcntl.LOCK_UN)
            os.close(host_lock)
        if marker is not None:
            try:
                marker.unlink()
            except FileNotFoundError:
                pass
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

