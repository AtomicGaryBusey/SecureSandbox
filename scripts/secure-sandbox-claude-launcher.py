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
LAUNCHER_PATH = Path("/usr/local/bin/secure-sandbox-claude")
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
NATIVE_HOST_CANDIDATE_AUTHORITY_DIRECTORY = (
    "native-host-candidate-authorities"
)
NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA = (
    "secure-sandbox-native-host-candidate-authority-v2"
)
HOST_RELEASE_LAUNCHER_PAIR_FEATURE = (
    "host-release-launcher-pair-fence-v1"
)
HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME = (
    "host-release-launcher-pair.json"
)
HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA = (
    "secure-sandbox-host-release-launcher-pair-v1"
)
HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA = (
    "secure-sandbox-host-release-launcher-pair-transition-v1"
)
HOST_PAIR_TERMINAL_SCHEMA = "secure-sandbox-host-pair-terminal-v1"
INSTALL_TRANSITION_DIRECTORY_NAME = "install-transitions"
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
) -> tuple[bytes, dict[str, int | str]]:
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
    return raw, {
        "ctime_ns": opened.st_ctime_ns,
        "dev": opened.st_dev,
        "gid": opened.st_gid,
        "ino": opened.st_ino,
        "kind": "file",
        "mode": stat.S_IMODE(opened.st_mode),
        "mtime_ns": opened.st_mtime_ns,
        "nlink": opened.st_nlink,
        "sha256": digest(raw),
        "size": opened.st_size,
        "uid": opened.st_uid,
    }


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


def _validate_identity_record(
    value: object, *, kind: str,
) -> dict[str, int | str]:
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
        raise LaunchFailure("controller_pair_identity_invalid")
    return {name: value[name] for name in sorted(fields)}


def _validate_release_tree_identity(
    value: object,
) -> dict[str, dict[str, int | str]]:
    if (not isinstance(value, dict) or "." not in value
            or not 1 <= len(value) <= 8192):
        raise LaunchFailure("controller_pair_tree_identity_invalid")
    result: dict[str, dict[str, int | str]] = {}
    for relative, record in value.items():
        if (not isinstance(relative, str)
                or (relative != "." and (
                    not relative or relative.startswith("/")
                    or relative.endswith("/") or "//" in relative
                    or "\0" in relative
                    or any(part in {"", ".", ".."}
                           for part in relative.split("/"))
                ))):
            raise LaunchFailure("controller_pair_tree_identity_invalid")
        kind = record.get("kind") if isinstance(record, dict) else None
        if kind not in {"directory", "file"}:
            raise LaunchFailure("controller_pair_tree_identity_invalid")
        result[relative] = _validate_identity_record(record, kind=kind)
    if result["."]["kind"] != "directory":
        raise LaunchFailure("controller_pair_tree_identity_invalid")
    return {name: result[name] for name in sorted(result)}


_RUNTIME_APP_DIRECTORY_CTIME_PATHS = frozenset({
    "SecureSandboxAuthorizationUI.app",
    "SecureSandboxNativeCredentialHelper.app",
})


def _comparable_release_tree_identity(
    value: object,
) -> dict[str, dict[str, int | str]]:
    """Ignore only LaunchServices-owned ctime on exact app containers."""
    result = _validate_release_tree_identity(value)
    for relative in _RUNTIME_APP_DIRECTORY_CTIME_PATHS:
        record = result.get(relative)
        if record is None or record["kind"] != "directory":
            raise LaunchFailure("controller_pair_tree_inventory_invalid")
        record = dict(record)
        record["ctime_ns"] = 0
        result[relative] = record
    return result


def _snapshot_release_tree(
    release: Path, expected_uid: int,
) -> dict[str, dict[str, int | str]]:
    expected_root = (
        set(CURRENT_PAYLOAD_NAMES)
        | {"manifest.json", "SecureSandboxAuthorizationUI.app",
           "SecureSandboxNativeCredentialHelper.app"}
    )
    count = 0

    def directory(path: Path, relative: str, device: int | None):
        nonlocal count
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            opened = os.fstat(descriptor)
            _reject_extended_acl(descriptor)
            expected_device = opened.st_dev if device is None else device
            if (not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or opened.st_uid != expected_uid
                    or opened.st_dev != expected_device
                    or stat.S_IMODE(opened.st_mode) != 0o555):
                raise LaunchFailure("controller_pair_tree_identity_untrusted")
            names = sorted(os.listdir(descriptor))
            if relative == "." and set(names) != expected_root:
                raise LaunchFailure("controller_pair_tree_inventory_invalid")
            records: dict[str, dict[str, int | str]] = {}
            for name in names:
                if (not name or name in {".", ".."} or "/" in name
                        or "\0" in name):
                    raise LaunchFailure("controller_pair_tree_inventory_invalid")
                count += 1
                if count > 8191:
                    raise LaunchFailure("controller_pair_tree_inventory_invalid")
                child_relative = (
                    name if relative == "." else relative + "/" + name
                )
                named = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False,
                )
                child_path = path / name
                if stat.S_ISDIR(named.st_mode):
                    records.update(directory(
                        child_path, child_relative, expected_device,
                    ))
                elif stat.S_ISREG(named.st_mode):
                    raw, identity = _stable_root_file(
                        child_path, expected_uid,
                        stat.S_IMODE(named.st_mode),
                    )
                    del raw
                    if identity["dev"] != expected_device:
                        raise LaunchFailure(
                            "controller_pair_tree_identity_untrusted"
                        )
                    records[child_relative] = identity
                else:
                    raise LaunchFailure("controller_pair_tree_inventory_invalid")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named_after = path.lstat()
        identity_tuple = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if (identity_tuple(before) != identity_tuple(opened)
                or identity_tuple(opened) != identity_tuple(after)
                or identity_tuple(after) != identity_tuple(named_after)):
            raise LaunchFailure("controller_pair_tree_identity_changed")
        records[relative] = {
            "ctime_ns": after.st_ctime_ns,
            "dev": after.st_dev,
            "gid": after.st_gid,
            "ino": after.st_ino,
            "kind": "directory",
            "mode": stat.S_IMODE(after.st_mode),
            "mtime_ns": after.st_mtime_ns,
            "nlink": after.st_nlink,
            "size": after.st_size,
            "uid": after.st_uid,
        }
        return records

    return _validate_release_tree_identity(directory(release, ".", None))


def _host_pair_public(
    install_root: Path, expected_uid: int,
) -> tuple[dict[str, object], bytes] | None:
    path = install_root / HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
    if not os.path.lexists(path):
        return None
    raw, _identity = _stable_root_file(
        path, expected_uid, 0o444, maximum=8 * 1024 * 1024,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaunchFailure("controller_pair_record_invalid") from error
    if not isinstance(value, dict) or _canonical_json(value) != raw:
        raise LaunchFailure("controller_pair_record_invalid")
    if value.get("schema") == HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA:
        # A valid pending record is an execution fence. A malformed one is a
        # conflict, not an excuse to reinterpret the physical state.
        if (set(value) != {
                "operation", "prior_stable_sha256", "required_feature",
                "schema", "source_pair", "target_pair", "transition_id",
                "transition_sha256",
        } or value.get("required_feature")
                != HOST_RELEASE_LAUNCHER_PAIR_FEATURE):
            raise LaunchFailure("controller_pair_record_invalid")
        operation = value.get("operation")
        transition_id = value.get("transition_id")
        transition_sha256 = value.get("transition_sha256")
        prior_sha256 = value.get("prior_stable_sha256")
        target = value.get("target_pair")
        source = value.get("source_pair")
        generation_fields = {
            "candidate_authority_sha256", "launcher_sha256", "release_id",
            "release_tree_identity_sha256",
        }
        if (operation not in {"install", "rollback"}
                or not isinstance(transition_id, str)
                or re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}", transition_id,
                ) is None
                or SHA256.fullmatch(str(transition_sha256)) is None
                or not isinstance(target, dict)
                or set(target) != generation_fields
                or any(SHA256.fullmatch(str(target.get(name))) is None
                       for name in generation_fields)):
            raise LaunchFailure("controller_pair_record_invalid")
        if source is None:
            if operation != "install" or prior_sha256 is not None:
                raise LaunchFailure("controller_pair_record_invalid")
        else:
            if (SHA256.fullmatch(str(prior_sha256)) is None
                    or not isinstance(source, dict)
                    or set(source) != generation_fields | {
                        "launcher_identity"
                    }
                    or any(SHA256.fullmatch(str(source.get(name))) is None
                           for name in generation_fields)):
                raise LaunchFailure("controller_pair_record_invalid")
            source_launcher = _validate_identity_record(
                source.get("launcher_identity"), kind="file",
            )
            if source_launcher["sha256"] != source["launcher_sha256"]:
                raise LaunchFailure("controller_pair_record_invalid")
        return value, raw
    if (value.get("schema") != HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA
            or set(value) != {
                "committed_terminal_sha256", "committed_transition_id",
                "committed_transition_sha256", "pair", "required_feature",
                "schema",
            }
            or value.get("required_feature")
                != HOST_RELEASE_LAUNCHER_PAIR_FEATURE):
        raise LaunchFailure("controller_pair_record_invalid")
    pair = value.get("pair")
    if (not isinstance(pair, dict) or set(pair) != {
            "candidate_authority_sha256", "launcher_identity",
            "launcher_sha256", "release_id",
            "release_tree_identity_sha256",
    } or any(SHA256.fullmatch(str(pair.get(name))) is None for name in (
        "candidate_authority_sha256", "launcher_sha256", "release_id",
        "release_tree_identity_sha256",
    ))):
        raise LaunchFailure("controller_pair_record_invalid")
    launcher_identity = _validate_identity_record(
        pair.get("launcher_identity"), kind="file",
    )
    if launcher_identity["sha256"] != pair["launcher_sha256"]:
        raise LaunchFailure("controller_pair_record_invalid")
    committed = (
        value.get("committed_transition_id"),
        value.get("committed_transition_sha256"),
        value.get("committed_terminal_sha256"),
    )
    if any(item is None for item in committed) != all(
        item is None for item in committed
    ):
        raise LaunchFailure("controller_pair_record_invalid")
    if committed[0] is not None and (
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}", str(committed[0]),
        ) is None
        or SHA256.fullmatch(str(committed[1])) is None
        or SHA256.fullmatch(str(committed[2])) is None
    ):
        raise LaunchFailure("controller_pair_record_invalid")
    value["pair"] = {**pair, "launcher_identity": launcher_identity}
    if value.get("committed_transition_id") is not None:
        directory = install_root / INSTALL_TRANSITION_DIRECTORY_NAME
        _stable_root_directory(directory, expected_uid, 0o755)
        terminal_raw, _terminal_identity = _stable_root_file(
            directory / f"{value['committed_transition_id']}.json",
            expected_uid, 0o444, maximum=64 * 1024,
        )
        try:
            terminal = json.loads(terminal_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LaunchFailure("controller_pair_terminal_invalid") from error
        fields = {
            "schema", "status", "operation", "transition_id",
            "transition_sha256", "committed_pair",
            "authorization_request_id", "authorization_request_sha256",
            "authorized_target_plan_sha256", "completed_at",
            "service_evidence", "service_evidence_sha256", "error",
            "authorization_receipt_sha256", "finalization_sha256",
            "terminal_sha256",
        }
        terminal_body = (
            {name: item for name, item in terminal.items()
             if name != "terminal_sha256"}
            if isinstance(terminal, dict) else {}
        )
        service_evidence = (
            terminal.get("service_evidence")
            if isinstance(terminal, dict) else None
        )
        evidence_fields = {
            "committed_pair_sha256", "current_target", "operation",
            "previous_target", "schema", "services", "transition_sha256",
        }
        evidence_valid = (
            isinstance(service_evidence, dict)
            and set(service_evidence) == evidence_fields
            and service_evidence.get("schema")
                == "secure-sandbox-host-pair-service-evidence-v1"
            and service_evidence.get("operation")
                == terminal.get("operation")
            and service_evidence.get("transition_sha256")
                == terminal.get("transition_sha256")
            and service_evidence.get("committed_pair_sha256")
                == digest(_canonical_json(value["pair"]))
            and service_evidence.get("current_target")
                == f"releases/{value['pair']['release_id']}"
            and (service_evidence.get("previous_target") is None
                 or re.fullmatch(
                     r"releases/[0-9a-f]{64}",
                     str(service_evidence.get("previous_target")),
                 ) is not None)
            and isinstance(service_evidence.get("services"), dict)
            and digest(_canonical_json(service_evidence))
                == terminal.get("service_evidence_sha256")
        )
        if (not isinstance(terminal, dict) or set(terminal) != fields
                or _canonical_json(terminal) != terminal_raw
                or terminal.get("schema") != HOST_PAIR_TERMINAL_SCHEMA
                or terminal.get("status") not in {
                    "target_committed", "source_restored",
                }
                or terminal.get("operation") not in {"install", "rollback"}
                or terminal.get("transition_id")
                    != value["committed_transition_id"]
                or terminal.get("transition_sha256")
                    != value["committed_transition_sha256"]
                or terminal.get("committed_pair") != value["pair"]
                or not evidence_valid
                or digest(terminal_raw)
                    != value["committed_terminal_sha256"]
                or digest(_canonical_json(terminal_body))
                    != terminal.get("terminal_sha256")):
            raise LaunchFailure("controller_pair_terminal_invalid")
    return value, raw


def _host_candidate_authority(
    install_root: Path, release_id: str, expected_uid: int,
) -> tuple[dict[str, object], bytes]:
    directory = (
        install_root / NATIVE_HOST_CANDIDATE_AUTHORITY_DIRECTORY
    )
    _stable_root_directory(directory, expected_uid, 0o755)
    raw, _identity = _stable_root_file(
        directory / f"{release_id}.json", expected_uid, 0o444,
        maximum=8 * 1024 * 1024,
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaunchFailure("controller_pair_authority_invalid") from error
    if (not isinstance(value, dict) or set(value) != {
            "candidate_record", "launcher_sha256", "payloads", "release_id",
            "release_tree_identity", "release_tree_identity_sha256", "schema",
        } or value.get("schema") != NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA
            or value.get("release_id") != release_id
            or not isinstance(value.get("candidate_record"), dict)
            or not isinstance(value.get("payloads"), dict)
            or set(value["payloads"]) != CURRENT_PAYLOAD_NAMES
            or any(SHA256.fullmatch(str(item)) is None
                   for item in value["payloads"].values())
            or SHA256.fullmatch(str(value.get("launcher_sha256"))) is None):
        raise LaunchFailure("controller_pair_authority_invalid")
    tree = _validate_release_tree_identity(value.get("release_tree_identity"))
    tree_sha256 = digest(_canonical_json(tree))
    if (value.get("release_tree_identity_sha256") != tree_sha256
            or _canonical_json(value) != raw):
        raise LaunchFailure("controller_pair_authority_invalid")
    value["release_tree_identity"] = tree
    return value, raw


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
    launcher_path: Path = LAUNCHER_PATH,
) -> tuple[Path, str, bytes | None]:
    releases = install_root / "releases"
    current = install_root / "current"
    pair_public = _host_pair_public(install_root, expected_uid)
    if (pair_public is not None
            and pair_public[0].get("schema")
                == HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA):
        raise LaunchFailure("controller_pair_transition_active")
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
        has_pair_feature = HOST_RELEASE_LAUNCHER_PAIR_FEATURE in features
        if candidate_enforcement is None and has_candidate_feature:
            raise LaunchFailure(
                "controller_native_host_candidate_enforcement_missing"
            )
        if candidate_enforcement is not None and not has_candidate_feature:
            raise LaunchFailure(
                "controller_release_below_native_host_candidate_floor"
            )
        if pair_public is None and has_pair_feature:
            raise LaunchFailure("controller_pair_record_missing")
        if pair_public is not None and not has_pair_feature:
            raise LaunchFailure("controller_release_below_pair_floor")
    if pair_public is not None:
        stable, stable_raw = pair_public
        if stable.get("schema") != HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA:
            raise LaunchFailure("controller_pair_transition_active")
        pair = stable["pair"]
        if pair["release_id"] != relative.name:
            raise LaunchFailure("controller_pair_selector_mismatch")
        authority, authority_raw = _host_candidate_authority(
            install_root, relative.name, expected_uid,
        )
        if (digest(authority_raw) != pair["candidate_authority_sha256"]
                or authority["launcher_sha256"]
                    != pair["launcher_sha256"]
                or authority["release_tree_identity_sha256"]
                    != pair["release_tree_identity_sha256"]
                or authority["payloads"] != payloads):
            raise LaunchFailure("controller_pair_authority_mismatch")
        actual_tree = _snapshot_release_tree(release, expected_uid)
        if (_comparable_release_tree_identity(actual_tree)
                != _comparable_release_tree_identity(
                    authority["release_tree_identity"]
                )):
            raise LaunchFailure("controller_pair_tree_identity_mismatch")
        launcher_raw, launcher_identity = _stable_root_file(
            launcher_path, expected_uid, 0o755, maximum=16 * 1024 * 1024,
        )
        if (digest(launcher_raw) != pair["launcher_sha256"]
                or launcher_identity != pair["launcher_identity"]):
            raise LaunchFailure("controller_pair_launcher_mismatch")
        # A second public-record read brackets all physical validation. An
        # atomic STABLE->PENDING replacement during this interval must deny.
        pair_after = _host_pair_public(install_root, expected_uid)
        if (pair_after is None or pair_after[1] != stable_raw
                or pair_after[0] != stable):
            raise LaunchFailure("controller_pair_record_changed")
    if require_controller and controller_snapshot is None:
        raise LaunchFailure("controller_payload_missing")
    return release, relative.name, controller_snapshot


def load_release(
    install_root: Path, expected_uid: int = 0, *,
    launcher_path: Path = LAUNCHER_PATH,
) -> tuple[Path, str]:
    release, release_id, _controller = load_release_snapshot(
        install_root, expected_uid, require_controller=False,
        launcher_path=launcher_path,
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
        try:
            fcntl.flock(host_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise LaunchFailure("controller_host_transition_active") from error
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

