#!/usr/bin/env python3
"""Operator-attributed coordination wrapper for host-controller mutations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Mapping, NamedTuple
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("secure-sandbox-claude-launcher.py")
SPEC = importlib.util.spec_from_file_location("secure_sandbox_launcher", MODULE_PATH)
LAUNCHER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(LAUNCHER)
MANAGER_PATH = Path(__file__).with_name("host-controller-release.py")
MANAGER_SPEC = importlib.util.spec_from_file_location("host_controller_release", MANAGER_PATH)
MANAGER = importlib.util.module_from_spec(MANAGER_SPEC)
assert MANAGER_SPEC.loader is not None
MANAGER_SPEC.loader.exec_module(MANAGER)
BROKER_PATH = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
TOUCHID_BUILD = Path(__file__).with_name("build-touchid-authorization-ui.sh")
NATIVE_COMPONENT_BUILD = Path(__file__).with_name(
    "build-native-credential-components.sh"
)
NATIVE_HOST_PRODUCTS_BUILD = Path(__file__).with_name(
    "build-native-host-products.sh"
)
INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
STABLE_LAUNCHER = Path("/usr/local/bin/secure-sandbox-claude")
INSTALL_TRANSITION_DIRECTORY = INSTALL_ROOT / "install-transitions"
SAFE_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:/+-]{0,79}$")
SAFE_SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")
BOOTSTRAP_NOTICE_SCRIPT = r'''
on run argv
  tell application "System Events"
    activate
    set answer to display dialog (item 1 of argv) with title "SecureSandbox Bootstrap Authorization" buttons {"Cancel", "Continue"} default button "Cancel" cancel button "Cancel" with icon caution giving up after 90
    if gave up of answer then error number -128
    return button returned of answer
  end tell
end run
'''
BOOTSTRAP_LOADER = r'''
import hashlib, os, stat, sys
path, expected = sys.argv[1], sys.argv[2]
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(descriptor)
    sudo_uid = int(os.environ.get("SUDO_UID", "-1"))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != sudo_uid:
        raise SystemExit("bootstrap_manager_untrusted")
    data = os.read(descriptor, 2 * 1024 * 1024 + 1)
finally:
    os.close(descriptor)
if len(data) > 2 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit("bootstrap_manager_digest_mismatch")
sys.argv = [path] + sys.argv[3:]
namespace = {"__name__": "__main__", "__file__": path, "__package__": None}
exec(compile(data, path, "exec"), namespace, namespace)
'''


class BootstrapBinding(NamedTuple):
    release_id: str
    manager_sha256: str
    broker_sha256: str
    installed_launcher_sha256: str
    replacement_launcher_sha256: str
    touchid_ui_previous_sha256: str = ""
    touchid_ui_replacement_sha256: str = ""
    touchid_sources_previous_sha256: str = ""
    touchid_sources_replacement_sha256: str = ""
    archive_current_release_id: str = ""
    archive_previous_release_id: str = ""
    archive_plan_sha256: str = ""
    archive_release_ids: tuple[str, ...] = ()
    schema_current_release_id: str = ""
    developer_id_team_id: str = ""
    current_authorization_manifest_sha256: str = ""
    candidate_authorization_manifest_sha256: str = ""
    native_host_candidate: NativeHostCandidate | None = None
    host_pair_pending_sha256: str = ""
    host_pair_transition_id: str = ""
    host_pair_transition_sha256: str = ""
    host_pair_operation: str = ""
    host_pair_target_candidate_authority_sha256: str = ""
    host_pair_target_release_tree_identity_sha256: str = ""
    authorization_predecessor_release_id: str = ""
    authorization_clean_machine_bootstrap: bool = False


class NativeHostCandidate(NamedTuple):
    schema: str
    generation_path: str
    generation_device: int
    generation_inode: int
    generation_tree_sha256: str
    release_commit: str
    source_archive_sha256: str
    source_tree_sha256: str
    signing_config_sha256: str
    host_release_preimage_path: str
    host_release_preimage_device: int
    host_release_preimage_inode: int
    host_release_preimage_size: int
    host_release_preimage_sha256: str
    host_release_preimage_schema: str
    developer_id_certificate_sha1: str
    notary_submission_id: str
    build_custody: str

    def record(self) -> dict[str, object]:
        return dict(self._asdict())


class SourceReleaseBinding(NamedTuple):
    release_id: str
    native_host_candidate: NativeHostCandidate
    authorized_target_plan: dict[str, object]
    authorized_target_plan_sha256: str


class RollbackReleaseBinding(NamedTuple):
    release_id: str
    authorized_target_plan: dict[str, object]
    authorized_target_plan_sha256: str


def prepare_touchid_ui(*, require_developer_id: bool = False) -> None:
    if require_developer_id and not os.environ.get(
        "SECURE_SANDBOX_DEVELOPER_ID"
    ):
        raise RuntimeError("SECURE_SANDBOX_DEVELOPER_ID_is_required")
    result = subprocess.run(
        [str(TOUCHID_BUILD)], check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600,
        env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError("touchid_ui_build_failed:" + detail[-1000:])


def prepare_native_credential_components() -> None:
    if not os.environ.get("SECURE_SANDBOX_DEVELOPER_ID"):
        raise RuntimeError("SECURE_SANDBOX_DEVELOPER_ID_is_required")
    result = subprocess.run(
        [str(NATIVE_COMPONENT_BUILD)], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=900,
        env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError("native_component_build_failed:" + detail[-1000:])


def prepare_native_host_products() -> NativeHostCandidate:
    requested_identity = os.environ.get("SECURE_SANDBOX_DEVELOPER_ID", "")
    requested_keychain = os.environ.get(
        "SECURE_SANDBOX_NOTARY_KEYCHAIN", "",
    )
    if (not re.fullmatch(r"[0-9A-Fa-f]{40}", requested_identity)
            or not os.environ.get(
                "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE"
            )
            or not requested_keychain.startswith("/")
            or "\n" in requested_keychain
            or "\r" in requested_keychain):
        raise RuntimeError(
            "Developer_ID_notary_profile_and_keychain_are_required"
        )
    result = subprocess.run(
        [str(NATIVE_HOST_PRODUCTS_BUILD)], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=1800,
        env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError("native_host_products_build_failed:" + detail[-2000:])
    try:
        value = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("native_host_products_build_result_invalid") from error
    required = {
        "build_custody", "candidate_evidence",
        "developer_id_certificate_sha1", "release_commit", "schema",
        "host_release_preimage_sha256",
        "signing_config_sha256", "source_archive_sha256",
        "source_tree_sha256", "status", "target",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RuntimeError("native_host_products_build_result_invalid")
    certificate = value.get("developer_id_certificate_sha1")
    if (value.get("schema")
                != "secure-sandbox-native-host-products-build-v3"
            or value.get("status") != "verified"
            or value.get("build_custody")
                != "trusted-login-principal-v1"
            or not isinstance(certificate, str)
            or re.fullmatch(r"[0-9a-f]{40}", certificate) is None
            or certificate != requested_identity.lower()
            or re.fullmatch(
                r"[0-9a-f]{40}", str(value.get("release_commit", "")),
            ) is None
            or any(
                re.fullmatch(r"[0-9a-f]{64}", str(value.get(name, "")))
                    is None
                for name in (
                    "host_release_preimage_sha256",
                    "signing_config_sha256", "source_archive_sha256",
                    "source_tree_sha256",
                )
            )
            or not all(
                isinstance(value.get(name), str)
                and Path(value[name]).is_absolute()
                for name in ("candidate_evidence", "target")
            )):
        raise RuntimeError("native_host_products_build_result_invalid")
    repo = MANAGER_PATH.parent.parent.resolve(strict=True)
    target = Path(value["target"])
    candidate = Path(value["candidate_evidence"])
    candidate_parent = repo / ".private/native-host-product-candidates"
    expected_target = repo / "artifacts/host"

    def exact_directory(path: Path, expected: Path) -> os.stat_result:
        descriptor = -1
        try:
            before = path.lstat()
            descriptor = os.open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | os.O_CLOEXEC,
            )
            opened = os.fstat(descriptor)
            named = path.lstat()
        except OSError as error:
            raise RuntimeError(
                "native_host_products_build_result_invalid"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        identity = lambda info: (
            info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns,
        )
        if (path != expected or path.resolve(strict=True) != expected
                or not stat.S_ISDIR(opened.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or identity(before) != identity(opened)
                or identity(opened) != identity(named)
                or opened.st_uid != os.geteuid()
                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise RuntimeError("native_host_products_build_result_invalid")
        return opened

    # The public projection is a convenience output, never the admitted
    # candidate.  Its declared location remains part of the build contract,
    # but all release construction below is rooted in the retained generation.
    if target != expected_target:
        raise RuntimeError("native_host_products_build_result_invalid")
    parent_info = exact_directory(candidate_parent, candidate_parent)
    if (candidate.parent != candidate_parent
            or re.fullmatch(
                re.escape(value["release_commit"])
                + r"-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}",
                candidate.name,
            ) is None):
        raise RuntimeError("native_host_products_build_result_invalid")
    candidate_info = exact_directory(candidate, candidate)
    if candidate_info.st_dev != parent_info.st_dev:
        raise RuntimeError("native_host_products_build_result_invalid")
    generation = candidate / "generation"
    try:
        record = MANAGER.native_host_candidate_record(
            repo, generation,
            expected_certificate_sha1=certificate,
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise RuntimeError(
            "native_host_products_build_result_invalid"
        ) from error
    if (not isinstance(record, dict)
            or set(record) != set(NativeHostCandidate._fields)
            or any(
                record.get(name) != value.get(name)
                for name in (
                    "build_custody", "developer_id_certificate_sha1",
                    "host_release_preimage_sha256", "release_commit",
                    "signing_config_sha256",
                    "source_archive_sha256", "source_tree_sha256",
                )
            )):
        raise RuntimeError("native_host_products_build_result_invalid")
    try:
        return NativeHostCandidate(**record)
    except TypeError as error:
        raise RuntimeError(
            "native_host_products_build_result_invalid"
        ) from error


def retained_native_host_candidate_product(
    enforcement: tuple[dict[str, object], str], *,
    establishment_mode: str, predecessor_release_id: str,
) -> NativeHostCandidate:
    """Resolve exactly one retained candidate as a public floor preimage."""
    repo = MANAGER_PATH.parent.parent.resolve(strict=True)
    retained_root = repo / ".private/native-host-product-candidates"
    try:
        root_info = retained_root.lstat()
        entries = sorted(retained_root.iterdir(), key=lambda item: item.name)
    except OSError as error:
        raise RuntimeError(
            "native_host_candidate_replay_inventory_invalid"
        ) from error
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("native_host_candidate_replay_inventory_invalid")
    matches: list[NativeHostCandidate] = []
    expected_public = enforcement[0]
    for retained in entries:
        try:
            retained_info = retained.lstat()
        except OSError as error:
            raise RuntimeError(
                "native_host_candidate_replay_inventory_invalid"
            ) from error
        if re.fullmatch(r"\.candidate\.[A-Za-z0-9]{6}", retained.name):
            # Power loss can strand mktemp build custody before the driver's
            # trap runs.  The exact trusted temp-directory class is inert
            # retained evidence: it is never parsed as candidate authority and
            # is never deleted by replay.  Anything outside this narrow class
            # remains a closed-inventory failure.
            if (not stat.S_ISDIR(retained_info.st_mode)
                    or stat.S_ISLNK(retained_info.st_mode)
                    or retained_info.st_uid != os.geteuid()
                    or stat.S_IMODE(retained_info.st_mode) != 0o700
                    or retained_info.st_dev != root_info.st_dev):
                raise RuntimeError(
                    "native_host_candidate_replay_inventory_invalid"
                )
            continue
        if re.fullmatch(
            r"[0-9a-f]{40}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            retained.name,
        ) is None:
            raise RuntimeError(
                "native_host_candidate_replay_inventory_invalid"
            )
        generation = retained / "generation"
        try:
            classification = (
                MANAGER.classify_native_host_retained_candidate(
                    repo, generation,
                )
            )
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise RuntimeError(
                "native_host_candidate_replay_inventory_invalid"
            ) from error
        classification_fields = {
            "candidate_record", "eligibility", "generation_device",
            "generation_inode", "generation_path", "generation_tree_sha256",
            "receipt_schema", "schema",
        }
        if (not isinstance(classification, dict)
                or set(classification) != classification_fields
                or classification.get("schema") != (
                    MANAGER
                    .NATIVE_HOST_RETAINED_CANDIDATE_CLASSIFICATION_SCHEMA
                )
                or classification.get("generation_path") != str(generation)
                or any(
                    not isinstance(classification.get(name), int)
                    or isinstance(classification.get(name), bool)
                    or classification[name] <= 0
                    for name in ("generation_device", "generation_inode")
                )
                or re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(classification.get("generation_tree_sha256", "")),
                ) is None):
            raise RuntimeError(
                "native_host_candidate_replay_inventory_invalid"
            )
        if classification["eligibility"] == (
            "historical-receipt-v2-ineligible"
        ):
            if (classification["receipt_schema"]
                        != MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA
                    or classification["candidate_record"] is not None):
                raise RuntimeError(
                    "native_host_candidate_replay_inventory_invalid"
                )
            continue
        record = classification["candidate_record"]
        if (classification["eligibility"] != "candidate-admission-eligible"
                or classification["receipt_schema"]
                    != MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA
                or not isinstance(record, dict)
                or set(record) != set(NativeHostCandidate._fields)):
            raise RuntimeError(
                "native_host_candidate_replay_inventory_invalid"
            )
        try:
            candidate = NativeHostCandidate(**record)
        except TypeError as error:
            raise RuntimeError(
                "native_host_candidate_replay_inventory_invalid"
            ) from error
        if (candidate.generation_path != classification["generation_path"]
                or candidate.generation_device
                    != classification["generation_device"]
                or candidate.generation_inode
                    != classification["generation_inode"]
                or candidate.generation_tree_sha256
                    != classification["generation_tree_sha256"]):
            raise RuntimeError(
                "native_host_candidate_replay_inventory_invalid"
            )
        try:
            values, _hashes, release_id = MANAGER.source_payload(
                repo,
                expected_native_host_certificate_sha1=(
                    candidate.developer_id_certificate_sha1
                ),
                native_host_generation=generation,
                expected_native_host_candidate=record,
            )
            if set(values) != MANAGER.PAYLOAD_NAMES:
                raise RuntimeError(
                    "native_host_candidate_replay_inventory_invalid"
                )
            _floor, _floor_raw, projected, _projected_raw = (
                MANAGER.native_host_candidate_floor_records(
                    release_id=release_id,
                    candidate_record=record,
                    establishment_mode=establishment_mode,
                    predecessor_release_id=predecessor_release_id,
                )
            )
        except MANAGER.ReleaseFailure:
            # Retention is append-only across releases. A valid signed older
            # generation can lack today's payload inventory and therefore
            # cannot be the public projection's preimage.
            continue
        if projected == expected_public:
            matches.append(candidate)
    if len(matches) != 1:
        raise RuntimeError(
            "native_host_candidate_replay_missing"
            if not matches
            else "native_host_candidate_replay_ambiguous"
        )
    return matches[0]


def unbound_native_host_candidate_product() -> NativeHostCandidate | None:
    """Resolve one verified transferable candidate before first install.

    A clean destination Mac must not need the release operator's Developer ID
    private key or notarization credential.  A candidate built by the trusted
    release principal may therefore be copied into the ordinary retained-
    candidate directory before the first authorization bootstrap.  There is
    no installed public candidate floor at that point, so admission is limited
    to exactly one v3 candidate whose detached Developer ID receipt, notarized
    carrier, source archive, release preimage, complete local tree identity,
    and current source-payload closure all verify.

    The subsequent bootstrap still binds the imported candidate's destination
    device, inode, and tree digest into the displayed and privileged plan.
    Multiple admissible candidates fail closed rather than letting pathname or
    directory order choose first-install authority.
    """
    repo = MANAGER_PATH.parent.parent.resolve(strict=True)
    retained_root = repo / ".private/native-host-product-candidates"
    try:
        root_info = retained_root.lstat()
        entries = sorted(retained_root.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError(
            "native_host_candidate_import_inventory_invalid"
        ) from error
    if (not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700):
        raise RuntimeError("native_host_candidate_import_inventory_invalid")
    try:
        source_provenance = MANAGER.current_native_host_source_provenance(repo)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise RuntimeError(
            "native_host_candidate_source_provenance_invalid"
        ) from error
    provenance_fields = {
        "release_commit", "signing_config_sha256",
        "source_archive_sha256", "source_tree_sha256",
    }
    if (not isinstance(source_provenance, dict)
            or set(source_provenance) != provenance_fields):
        raise RuntimeError("native_host_candidate_source_provenance_invalid")
    matches: list[NativeHostCandidate] = []
    for retained in entries:
        try:
            retained_info = retained.lstat()
        except OSError as error:
            raise RuntimeError(
                "native_host_candidate_import_inventory_invalid"
            ) from error
        if re.fullmatch(r"\.candidate\.[A-Za-z0-9]{6}", retained.name):
            if (not stat.S_ISDIR(retained_info.st_mode)
                    or stat.S_ISLNK(retained_info.st_mode)
                    or retained_info.st_uid != os.geteuid()
                    or stat.S_IMODE(retained_info.st_mode) != 0o700
                    or retained_info.st_dev != root_info.st_dev):
                raise RuntimeError(
                    "native_host_candidate_import_inventory_invalid"
                )
            continue
        if re.fullmatch(
            r"[0-9a-f]{40}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            retained.name,
        ) is None:
            raise RuntimeError(
                "native_host_candidate_import_inventory_invalid"
            )
        generation = retained / "generation"
        try:
            classification = (
                MANAGER.classify_native_host_retained_candidate(
                    repo, generation,
                )
            )
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise RuntimeError(
                "native_host_candidate_import_inventory_invalid"
            ) from error
        if classification.get("eligibility") == (
            "historical-receipt-v2-ineligible"
        ):
            continue
        record = classification.get("candidate_record")
        if (classification.get("eligibility")
                    != "candidate-admission-eligible"
                or classification.get("receipt_schema")
                    != MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA
                or not isinstance(record, dict)
                or set(record) != set(NativeHostCandidate._fields)):
            raise RuntimeError(
                "native_host_candidate_import_inventory_invalid"
            )
        try:
            candidate = NativeHostCandidate(**record)
            if any(
                getattr(candidate, name) != source_provenance[name]
                for name in provenance_fields
            ):
                # Retention is append-only across releases. An older candidate
                # can carry byte-identical native products while still naming
                # a different reviewed source commit; it is historical
                # evidence, never authority for this checkout.
                continue
            values, _hashes, _release_id = MANAGER.source_payload(
                repo,
                expected_native_host_certificate_sha1=(
                    candidate.developer_id_certificate_sha1
                ),
                native_host_generation=generation,
                expected_native_host_candidate=record,
            )
        except (TypeError, MANAGER.ReleaseFailure):
            # Retained candidates are append-only.  A correctly signed older
            # candidate can be irrelevant to the current payload inventory.
            continue
        if set(values) != MANAGER.PAYLOAD_NAMES:
            raise RuntimeError(
                "native_host_candidate_import_inventory_invalid"
            )
        matches.append(candidate)
    if len(matches) > 1:
        raise RuntimeError("native_host_candidate_import_ambiguous")
    return matches[0] if matches else None


def source_release_candidate_product() -> NativeHostCandidate:
    """Resolve transferred release bytes before considering a local build.

    Ordinary deployment and first-install bootstrap share the same destination
    boundary: a clean or disposable Mac may receive a verified public product
    candidate, but never the release principal's signing or notarization
    credentials. The retained-candidate verifier admits exactly one candidate
    compatible with the current source closure. Only a trusted release Mac
    with no such candidate falls back to building locally, where the existing
    credential checks remain authoritative.
    """
    imported = unbound_native_host_candidate_product()
    return imported if imported is not None else prepare_native_host_products()


def stage_native_host_candidate_transfer(source: Path) -> NativeHostCandidate:
    """Copy one signed release candidate into destination-local custody.

    Transfer media is never executed.  Every entry must be an owned regular
    file or directory, the bounded tree is copied without following links or
    preserving extended metadata, and the completed destination is admitted
    only by the existing detached-signature, notarization, source-archive,
    release-preimage, bundle, and whole-tree verifier.
    """
    repo = MANAGER_PATH.parent.parent.resolve(strict=True)
    source = Path(source)
    try:
        source_info = source.lstat()
        resolved_source = source.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("native_host_candidate_transfer_untrusted") from error
    if (not source.is_absolute() or source != resolved_source
            or not stat.S_ISDIR(source_info.st_mode)
            or stat.S_ISLNK(source_info.st_mode)
            or source_info.st_uid != os.geteuid()
            or source_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or re.fullmatch(
                r"[0-9a-f]{40}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}", source.name,
            ) is None):
        raise RuntimeError("native_host_candidate_transfer_untrusted")

    private_root = repo / ".private"
    retained_root = private_root / "native-host-product-candidates"
    for path in (private_root, retained_root):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise RuntimeError(
                "native_host_candidate_import_inventory_invalid"
            )
    retained_root_info = retained_root.lstat()
    destination = retained_root / source.name
    if os.path.lexists(destination):
        raise RuntimeError("native_host_candidate_transfer_exists")

    directory_modes: dict[Path, int] = {Path("."): stat.S_IMODE(source_info.st_mode)}
    files: list[tuple[Path, int, int]] = []
    total_size = 0
    entry_count = 1
    for current, directory_names, file_names in os.walk(
        source, topdown=True, followlinks=False,
    ):
        current_path = Path(current)
        relative_root = current_path.relative_to(source)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            item = current_path / name
            info = item.lstat()
            relative = relative_root / name
            entry_count += 1
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) not in {0o555, 0o700, 0o755}
                    or len(relative.parts) > 16):
                raise RuntimeError(
                    "native_host_candidate_transfer_untrusted"
                )
            directory_modes[relative] = stat.S_IMODE(info.st_mode)
        for name in file_names:
            item = current_path / name
            info = item.lstat()
            relative = relative_root / name
            entry_count += 1
            total_size += info.st_size
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode)
                        not in {0o400, 0o444, 0o555, 0o600}
                    or not 0 <= info.st_size <= 512 * 1024 * 1024
                    or total_size > 1024 * 1024 * 1024
                    or len(relative.parts) > 16):
                raise RuntimeError(
                    "native_host_candidate_transfer_untrusted"
                )
            files.append((relative, stat.S_IMODE(info.st_mode), info.st_size))
        if entry_count > 1024:
            raise RuntimeError("native_host_candidate_transfer_untrusted")
    if sorted(path.name for path in source.iterdir()) != ["evidence", "generation"]:
        raise RuntimeError("native_host_candidate_transfer_untrusted")

    retained_descriptor = os.open(
        retained_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    opened_retained = os.fstat(retained_descriptor)
    named_retained = retained_root.lstat()
    if ((opened_retained.st_dev, opened_retained.st_ino)
            != (retained_root_info.st_dev, retained_root_info.st_ino)
            or (named_retained.st_dev, named_retained.st_ino)
            != (retained_root_info.st_dev, retained_root_info.st_ino)):
        os.close(retained_descriptor)
        raise RuntimeError("native_host_candidate_import_inventory_changed")
    temporary_name = ""
    for _attempt in range(32):
        candidate_name = ".candidate." + secrets.token_hex(3)
        try:
            os.mkdir(candidate_name, mode=0o700, dir_fd=retained_descriptor)
        except FileExistsError:
            continue
        temporary_name = candidate_name
        break
    if not temporary_name:
        os.close(retained_descriptor)
        raise RuntimeError("native_host_candidate_transfer_reservation_failed")
    temporary = retained_root / temporary_name
    try:
        temporary_descriptor = os.open(
            temporary_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=retained_descriptor,
        )
    except OSError:
        os.close(retained_descriptor)
        raise
    temporary_identity = os.fstat(temporary_descriptor)
    try:
        for relative in sorted(
            (item for item in directory_modes if item != Path(".")),
            key=lambda item: (len(item.parts), item.as_posix()),
        ):
            (temporary / relative).mkdir(mode=0o700)
        for relative, mode, expected_size in files:
            source_path = source / relative
            destination_path = temporary / relative
            source_descriptor = os.open(
                source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                before = os.fstat(source_descriptor)
                MANAGER.reject_extended_acl(
                    source_descriptor,
                    "native_host_candidate_transfer_extended_acl",
                )
                destination_descriptor = os.open(
                    destination_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    copied = 0
                    while True:
                        chunk = os.read(source_descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        MANAGER.write_all(
                            destination_descriptor, chunk,
                            "native_host_candidate_transfer",
                        )
                        copied += len(chunk)
                    os.fchmod(destination_descriptor, mode)
                    os.fsync(destination_descriptor)
                finally:
                    os.close(destination_descriptor)
                after = os.fstat(source_descriptor)
            finally:
                os.close(source_descriptor)
            named = source_path.lstat()
            identity = lambda item: (
                item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                item.st_gid, item.st_nlink, item.st_size,
                item.st_mtime_ns, item.st_ctime_ns,
            )
            if (copied != expected_size or identity(before) != identity(after)
                    or identity(after) != identity(named)):
                raise RuntimeError(
                    "native_host_candidate_transfer_changed"
                )
        for relative, mode in sorted(
            directory_modes.items(),
            key=lambda item: (len(item[0].parts), item[0].as_posix()),
            reverse=True,
        ):
            path = temporary if relative == Path(".") else temporary / relative
            os.chmod(path, mode)
            MANAGER.fsync_directory(path)
        receipt_path = (
            temporary / "generation"
            / MANAGER.PAYLOAD_SOURCES[
                "native_host_products_notarization"
            ].name
        )
        receipt = MANAGER.native_host_products_notarization(
            MANAGER.read_regular(receipt_path)
        )
        expected_name = (
            str(receipt.get("release_commit", "")) + "-"
            + str(receipt.get("notary_submission_id", ""))
        )
        try:
            os.stat(
                destination.name, dir_fd=retained_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            destination_absent = True
        else:
            destination_absent = False
        named_temporary = os.stat(
            temporary_name, dir_fd=retained_descriptor,
            follow_symlinks=False,
        )
        if (expected_name != source.name or not destination_absent
                or (named_temporary.st_dev, named_temporary.st_ino)
                    != (temporary_identity.st_dev, temporary_identity.st_ino)):
            raise RuntimeError("native_host_candidate_transfer_identity_invalid")
        os.rename(
            temporary_name, destination.name,
            src_dir_fd=retained_descriptor,
            dst_dir_fd=retained_descriptor,
        )
        os.fsync(retained_descriptor)
        published = os.stat(
            destination.name, dir_fd=retained_descriptor,
            follow_symlinks=False,
        )
        if ((published.st_dev, published.st_ino)
                != (temporary_identity.st_dev, temporary_identity.st_ino)):
            raise RuntimeError("native_host_candidate_transfer_identity_changed")
        try:
            named_parent_before = retained_root.lstat()
            named_destination_before = destination.lstat()
            if ((named_parent_before.st_dev, named_parent_before.st_ino)
                        != (opened_retained.st_dev, opened_retained.st_ino)
                    or (named_destination_before.st_dev,
                        named_destination_before.st_ino)
                        != (temporary_identity.st_dev,
                            temporary_identity.st_ino)):
                raise RuntimeError(
                    "native_host_candidate_transfer_identity_changed"
                )
            record = MANAGER.native_host_candidate_record(
                repo, destination / "generation",
            )
            named_parent_after = retained_root.lstat()
            named_destination_after = destination.lstat()
            if ((named_parent_after.st_dev, named_parent_after.st_ino)
                        != (opened_retained.st_dev, opened_retained.st_ino)
                    or (named_destination_after.st_dev,
                        named_destination_after.st_ino)
                        != (temporary_identity.st_dev,
                            temporary_identity.st_ino)):
                raise RuntimeError(
                    "native_host_candidate_transfer_identity_changed"
                )
        except (OSError, RuntimeError, ValueError):
            rejected = os.stat(
                destination.name, dir_fd=retained_descriptor,
                follow_symlinks=False,
            )
            if ((rejected.st_dev, rejected.st_ino)
                    == (temporary_identity.st_dev, temporary_identity.st_ino)):
                os.rename(
                    destination.name, temporary_name,
                    src_dir_fd=retained_descriptor,
                    dst_dir_fd=retained_descriptor,
                )
                os.fsync(retained_descriptor)
            raise
        return NativeHostCandidate(**record)
    finally:
        os.close(temporary_descriptor)
        os.close(retained_descriptor)


def native_host_candidate_schema_product() -> NativeHostCandidate:
    """Build once, or resume the schema ceremony's exact public binding."""
    enforcement = MANAGER.native_host_candidate_replay_enforcement(
        INSTALL_ROOT, 0, allow_absent=True,
    )
    if enforcement is None:
        return prepare_native_host_products()
    return retained_native_host_candidate_product(
        enforcement,
        establishment_mode=(
            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
        ),
        predecessor_release_id=(
            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        ),
    )


def authorization_bootstrap_predecessor_release_id() -> str:
    predecessor = (
        INSTALL_ROOT / MANAGER.AUTHORIZATION_COORDINATION_PREDECESSOR_NAME
    )
    current = INSTALL_ROOT / "current"
    selected = predecessor if predecessor.is_symlink() else current
    try:
        path, manifest = MANAGER.verified_release(
            INSTALL_ROOT, selected, 0, allow_legacy=True,
            _bootstrap_without_developer_id_floor=True,
            _bootstrap_without_native_coordination_floor=True,
            _bootstrap_without_candidate_admission_floor=True,
        )
    except (OSError, MANAGER.ReleaseFailure) as error:
        raise RuntimeError(
            "authorization_bootstrap_predecessor_invalid"
        ) from error
    if set(manifest.get("payloads", {})) != MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES:
        raise RuntimeError("authorization_bootstrap_predecessor_invalid")
    return path.name


def clean_authorization_bootstrap_predecessor_release_id(
    values: Mapping[str, bytes],
) -> str:
    """Derive the real pre-authorization release used on a clean machine."""
    predecessor_hashes = {
        name: hashlib.sha256(values[name]).hexdigest()
        for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
    }
    return MANAGER.release_identity(predecessor_hashes)


def clean_authorization_bootstrap_state(
    values: Mapping[str, bytes], candidate_launcher: bytes,
) -> tuple[str, bytes, bool]:
    """Bind a wholly absent or exact interrupted clean-machine scaffold."""
    predecessor_id = clean_authorization_bootstrap_predecessor_release_id(
        values,
    )
    root_present = os.path.lexists(INSTALL_ROOT)
    launcher_present = os.path.lexists(STABLE_LAUNCHER)
    if not root_present:
        if launcher_present:
            raise RuntimeError(
                "authorization_bootstrap_clean_state_ambiguous"
            )
        return predecessor_id, candidate_launcher, True
    root_info = INSTALL_ROOT.lstat()
    if (not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != 0
            or stat.S_IMODE(root_info.st_mode) != 0o755):
        raise RuntimeError("authorization_bootstrap_clean_state_ambiguous")
    current = INSTALL_ROOT / "current"
    predecessor = (
        INSTALL_ROOT / MANAGER.AUTHORIZATION_COORDINATION_PREDECESSOR_NAME
    )
    if current.is_symlink() or predecessor.is_symlink():
        selected_id = authorization_bootstrap_predecessor_release_id()
        if not launcher_present:
            if current.is_symlink() or selected_id != predecessor_id:
                raise RuntimeError(
                    "authorization_bootstrap_clean_state_ambiguous"
                )
            return selected_id, candidate_launcher, True
        installed = MANAGER.read_trusted_stable_launcher(
            STABLE_LAUNCHER, 0,
        )
        return (
            selected_id,
            installed,
            not current.is_symlink() and selected_id == predecessor_id,
        )
    if os.path.lexists(current) or os.path.lexists(predecessor):
        raise RuntimeError("authorization_bootstrap_clean_state_ambiguous")
    allowed = {"releases"}
    entries = {entry.name for entry in INSTALL_ROOT.iterdir()}
    if not entries <= allowed:
        raise RuntimeError("authorization_bootstrap_clean_state_ambiguous")
    releases = INSTALL_ROOT / "releases"
    if releases.exists():
        release_info = releases.lstat()
        if (not stat.S_ISDIR(release_info.st_mode)
                or stat.S_ISLNK(release_info.st_mode)
                or release_info.st_uid != 0
                or stat.S_IMODE(release_info.st_mode) != 0o755):
            raise RuntimeError(
                "authorization_bootstrap_clean_state_ambiguous"
            )
        release_entries = list(releases.iterdir())
        if any(
            entry.name != predecessor_id
            and not entry.name.startswith(".staging-")
            for entry in release_entries
        ):
            raise RuntimeError(
                "authorization_bootstrap_clean_state_ambiguous"
            )
        final_entries = [
            entry for entry in release_entries
            if entry.name == predecessor_id
        ]
        for entry in release_entries:
            if entry.name.startswith(".staging-"):
                info = entry.lstat()
                if (not stat.S_ISDIR(info.st_mode)
                        or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != 0
                        or stat.S_IMODE(info.st_mode) != 0o755):
                    raise RuntimeError(
                        "authorization_bootstrap_clean_state_ambiguous"
                    )
        if final_entries:
            try:
                MANAGER.verified_release(
                    INSTALL_ROOT, releases / predecessor_id, 0,
                    allow_legacy=True,
                    _bootstrap_without_developer_id_floor=True,
                    _bootstrap_without_native_coordination_floor=True,
                    _bootstrap_without_candidate_admission_floor=True,
                    _direct_release_id=predecessor_id,
                )
            except (OSError, MANAGER.ReleaseFailure) as error:
                raise RuntimeError(
                    "authorization_bootstrap_clean_state_ambiguous"
                ) from error
    if launcher_present:
        installed = MANAGER.read_trusted_stable_launcher(
            STABLE_LAUNCHER, 0,
        )
        if installed != candidate_launcher:
            raise RuntimeError(
                "authorization_bootstrap_clean_state_ambiguous"
            )
    else:
        installed = candidate_launcher
    return predecessor_id, installed, True


def native_host_authorization_bootstrap_product() -> NativeHostCandidate:
    """Build once, or resume fresh bootstrap from its public binding."""
    enforcement = MANAGER.native_host_candidate_replay_enforcement(
        INSTALL_ROOT, 0, allow_absent=True,
    )
    if enforcement is None:
        return source_release_candidate_product()
    return retained_native_host_candidate_product(
        enforcement,
        establishment_mode=(
            MANAGER.NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE
        ),
        predecessor_release_id=(
            authorization_bootstrap_predecessor_release_id()
        ),
    )


def protected_broker_available(broker_path: Path | None = None) -> bool:
    broker_path = BROKER_PATH if broker_path is None else broker_path
    try:
        return (
            broker_path.is_file() and not broker_path.is_symlink()
            and os.access(broker_path, os.X_OK)
        )
    except OSError:
        return False


def wait_for_host_pair_terminal(
    pending: dict[str, object], *, timeout: float = 605.0,
) -> dict[str, object]:
    fields = {
        "schema", "status", "operation", "transition_id",
        "transition_sha256", "authorization_request_id",
        "authorized_target_plan_sha256", "target_release_id", "expires_at",
        "recovered_after_child_failure",
    }
    transition_id = pending.get("transition_id")
    transition_sha256 = pending.get("transition_sha256")
    operation = pending.get("operation")
    request_id = pending.get("authorization_request_id")
    target_plan_sha256 = pending.get("authorized_target_plan_sha256")
    target_release_id = pending.get("target_release_id")
    expires_at = pending.get("expires_at")
    if (set(pending) != fields
            or pending.get("schema") != MANAGER.SCHEMA
            or pending.get("status") != "host_pair_transition_pending"
            or operation not in {"install", "rollback"}
            or pending.get("recovered_after_child_failure") is not True
            or not isinstance(transition_id, str)
            or not isinstance(transition_sha256, str)
            or MANAGER.SHA256.fullmatch(transition_sha256) is None
            or not isinstance(request_id, str)
            or not isinstance(target_plan_sha256, str)
            or MANAGER.SHA256.fullmatch(target_plan_sha256) is None
            or not isinstance(target_release_id, str)
            or MANAGER.SHA256.fullmatch(target_release_id) is None
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)):
        raise RuntimeError("host_pair_transition_pending_invalid")
    MANAGER._validated_uuid4(transition_id, "host_pair_transition_id")
    MANAGER._validated_uuid4(request_id, "authorization_request_id")
    deadline = time.monotonic() + min(
        timeout, max(1.0, float(expires_at - int(time.time()) + 5)),
    )
    filename = f"{transition_id}.json"
    while time.monotonic() < deadline:
        descriptor = -1
        try:
            descriptor = MANAGER.open_trusted_absolute_directory(
                INSTALL_TRANSITION_DIRECTORY, 0, final_mode=0o755,
            )
            try:
                publication = os.stat(
                    filename, dir_fd=descriptor, follow_symlinks=False,
                )
            except FileNotFoundError:
                terminal = None
                time.sleep(0.05)
                continue
            if publication.st_nlink == 2:
                # The publisher first hard-links the canonical pending inode to
                # its final name, fsyncs, then unlinks pending.  nlink=2 is the
                # intentional crash-recoverable publication window, not an
                # untrusted terminal record.
                terminal = None
                time.sleep(0.05)
                continue
            value, _raw, _ = MANAGER.read_state_record_at(
                descriptor, filename, 0, 0o444,
            )
            terminal = MANAGER.validate_public_host_pair_terminal(value)
        except FileNotFoundError:
            terminal = None
        except MANAGER.ReleaseFailure as error:
            if "install_transition_parent_untrusted" in str(error):
                terminal = None
            else:
                raise RuntimeError("host_pair_terminal_untrusted") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if terminal is not None:
            if (terminal["transition_id"] != transition_id
                    or terminal["transition_sha256"] != transition_sha256
                    or terminal["operation"] != operation
                    or terminal["authorization_request_id"] != request_id
                    or terminal["authorized_target_plan_sha256"]
                        != target_plan_sha256):
                raise RuntimeError("host_pair_terminal_mismatch")
            committed = terminal["committed_pair"]
            if (terminal["status"] == "target_committed"
                    and committed["release_id"] != target_release_id):
                raise RuntimeError("host_pair_terminal_mismatch")
            try:
                public = MANAGER.host_release_launcher_pair_public(
                    INSTALL_ROOT, 0,
                )
                assert public is not None
                stable, _stable_sha256 = public
                if stable["schema"] != (
                    MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA
                ):
                    time.sleep(0.05)
                    continue
                verified = MANAGER.verified_public_host_pair_terminal(
                    INSTALL_ROOT, 0, stable,
                )
            except MANAGER.ReleaseFailure as error:
                raise RuntimeError("host_pair_terminal_untrusted") from error
            if (stable.get("committed_transition_id") != transition_id
                    or stable.get("committed_transition_sha256")
                        != transition_sha256
                    or stable.get("pair") != committed
                    or verified is None or verified[0] != terminal):
                raise RuntimeError("host_pair_terminal_mismatch")
            return terminal
        time.sleep(0.05)
    raise RuntimeError("host_pair_transition_timeout")


wait_for_install_terminal = wait_for_host_pair_terminal


def validate_host_pair_operation_result(
    value: object, *, operation: str, target_plan: dict[str, object],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("host_pair_transition_result_invalid")
    common = {
        "schema", "status", "release_id", "transition_id",
        "transition_sha256", "host_release_launcher_pair_sha256",
        "candidate_authority_sha256", "release_tree_identity_sha256",
        "developer_id_team_id", "developer_id_team_floor_sha256",
        "developer_id_team_floor_release_id",
    }
    if operation == "install":
        fields = common | {"launcher_sha256", "payloads"}
        if value.get("runtime_metadata_recovery") is True:
            fields.add("runtime_metadata_recovery")
        valid = (
            set(value) == fields
            and value.get("status") == "deployed"
            and value.get("release_id") == target_plan.get("release_id")
            and value.get("launcher_sha256")
                == target_plan.get("target_launcher_sha256")
            and value.get("payloads") == target_plan.get("payloads")
        )
    elif operation == "rollback":
        fields = common | {"repo_match", "warning"}
        valid = (
            set(value) == fields
            and value.get("status") == "rolled_back"
            and value.get("release_id")
                == target_plan.get("target_release_id")
            and value.get("candidate_authority_sha256")
                == target_plan.get("target_candidate_authority_sha256")
            and value.get("release_tree_identity_sha256")
                == target_plan.get("target_release_tree_identity_sha256")
            and value.get("repo_match") is True
            and value.get("warning") is None
        )
    else:
        valid = False
    if (not valid or value.get("schema") != MANAGER.SCHEMA
            or not isinstance(value.get("transition_id"), str)
            or any(
                not isinstance(value.get(name), str)
                or MANAGER.SHA256.fullmatch(value[name]) is None
                for name in (
                    "transition_sha256",
                    "host_release_launcher_pair_sha256",
                    "candidate_authority_sha256",
                    "release_tree_identity_sha256",
                    "developer_id_team_floor_sha256",
                    "developer_id_team_floor_release_id",
                )
            )
            or not isinstance(value.get("developer_id_team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", value["developer_id_team_id"])
                is None):
        raise RuntimeError("host_pair_transition_result_invalid")
    MANAGER._validated_uuid4(
        value["transition_id"], "host_pair_transition_id",
    )
    return value


def runtime_metadata_recovery_binding_from_failure(
    completed: subprocess.CompletedProcess[str], operation: str,
) -> tuple[str, str] | None:
    """Recognize only the broker's terminally ambiguous Host-install result.

    The privileged manager performs the authoritative receipt/error check.  A
    match here merely selects that fail-closed recovery verifier; it never
    treats the ambiguous result itself as success or reusable authority.
    """
    if operation != "host-controller-install":
        return None
    if completed.stdout:
        return None
    stderr_lines = (completed.stderr or "").splitlines()
    if not stderr_lines:
        return None
    try:
        diagnostic = json.loads(stderr_lines[-1])
    except (TypeError, json.JSONDecodeError):
        return None
    expected = {
        "action": "inspect_authorization_receipt_before_retry",
        "code": "privileged_operation_outcome_ambiguous",
        "operation": operation,
        "outcome": "ambiguous",
        "phase": "result",
        "retry": "forbidden",
        "schema": "secure-sandbox-operator-diagnostic-v1",
    }
    if (not isinstance(diagnostic, dict)
            or set(diagnostic) != set(expected) | {"request_id"}
            or any(diagnostic.get(name) != value
                   for name, value in expected.items())):
        return None
    request_id = diagnostic.get("request_id")
    try:
        MANAGER._validated_uuid4(request_id, "authorization_request_id")
    except MANAGER.ReleaseFailure:
        return None
    digests = re.findall(
        r"(?m)^Request digest: ([0-9a-f]{64})$",
        completed.stderr or "",
    )
    if len(digests) != 1:
        return None
    return request_id, digests[0]


def selector_recovery_required(
    install_root: Path = INSTALL_ROOT, expected_uid: int = 0
) -> bool:
    selector = install_root / "current"
    try:
        root_info = install_root.lstat()
        releases_info = (install_root / "releases").lstat()
        selector_info = selector.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode)
        and root_info.st_uid == expected_uid and stat.S_IMODE(root_info.st_mode) == 0o755
        and stat.S_ISDIR(releases_info.st_mode) and not stat.S_ISLNK(releases_info.st_mode)
        and releases_info.st_uid == expected_uid and stat.S_IMODE(releases_info.st_mode) == 0o755
        and stat.S_ISLNK(selector_info.st_mode) and selector_info.st_uid == expected_uid
        and stat.S_IMODE(selector_info.st_mode) != 0o755
    )


def postactivation_current_release(
    allow_legacy: bool = False, expected_uid: int = 0,
    allow_migration_predecessor_anchor: bool = False,
    allow_completed_migration_preflight: bool = False,
    allow_candidate_schema_bootstrap: bool = False,
) -> Path:
    """Verify the current selector without reading the root-only v2 floor."""
    enforce_floor = MANAGER.enforce_execution_approval_floor
    developer_floor = MANAGER.developer_id_team_floor
    floor_path = INSTALL_ROOT / MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
    floor_present = False
    selected_link = INSTALL_ROOT / "current"
    using_migration_predecessor = False
    migration_predecessor = (
        INSTALL_ROOT / MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
    )
    if (allow_migration_predecessor_anchor
            and allow_completed_migration_preflight):
        raise RuntimeError("developer_id_migration_preflight_ambiguous")
    if (allow_migration_predecessor_anchor
            and migration_predecessor.is_symlink()):
        if (os.path.lexists(selected_link)
                and not selected_link.is_symlink()):
            raise RuntimeError("developer_id_migration_current_untrusted")
        selected_link = migration_predecessor
        using_migration_predecessor = True
    elif (allow_migration_predecessor_anchor
            and os.path.lexists(migration_predecessor)):
        raise RuntimeError("developer_id_migration_predecessor_untrusted")
    using_completed_migration = allow_completed_migration_preflight
    if using_completed_migration:
        if (os.path.lexists(migration_predecessor)
                or not selected_link.is_symlink()):
            raise RuntimeError(
                "developer_id_migration_completed_selector_untrusted")
    try:
        floor_info = floor_path.lstat()
        if (not stat.S_ISREG(floor_info.st_mode)
                or stat.S_ISLNK(floor_info.st_mode)
                or floor_info.st_uid != expected_uid
                or stat.S_IMODE(floor_info.st_mode) != 0o600):
            raise RuntimeError("developer_id_team_floor_untrusted")
        if floor_info.st_nlink == 2 and using_migration_predecessor:
            pending_path = (
                INSTALL_ROOT
                / MANAGER.DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME
            )
            try:
                pending_info = pending_path.lstat()
            except OSError as error:
                raise RuntimeError(
                    "developer_id_team_floor_untrusted") from error
            if (not stat.S_ISREG(pending_info.st_mode)
                    or stat.S_ISLNK(pending_info.st_mode)
                    or pending_info.st_uid != expected_uid
                    or pending_info.st_gid != floor_info.st_gid
                    or pending_info.st_nlink != 2
                    or stat.S_IMODE(pending_info.st_mode) != 0o600
                    or not 2 <= floor_info.st_size <= 2048
                    or pending_info.st_size != floor_info.st_size
                    or (pending_info.st_dev, pending_info.st_ino)
                        != (floor_info.st_dev, floor_info.st_ino)):
                raise RuntimeError("developer_id_team_floor_untrusted")
        elif floor_info.st_nlink != 1:
            raise RuntimeError("developer_id_team_floor_untrusted")
        floor_present = True
    except FileNotFoundError:
        pass
    if using_completed_migration and not floor_present:
        raise RuntimeError("developer_id_migration_floor_missing")
    replay_candidate_enforcement = (
        MANAGER.native_host_candidate_replay_enforcement(
            INSTALL_ROOT, expected_uid, allow_absent=True,
        )
    )
    if allow_candidate_schema_bootstrap:
        public_candidate_enforcement = replay_candidate_enforcement
    elif replay_candidate_enforcement is None:
        public_candidate_enforcement = None
    else:
        # A public pending projection is already a durable fail-closed fence.
        # Ordinary operations require the one-link final projection; only the
        # named schema replay may consume the transitional hard-link state.
        public_candidate_enforcement = (
            MANAGER.native_host_candidate_enforcement(
                INSTALL_ROOT, expected_uid, allow_absent=False,
            )
        )
    public_coordination = None
    public_coordination_required = (
        using_completed_migration or allow_candidate_schema_bootstrap
    )
    if public_coordination_required:
        public_coordination = MANAGER.native_stack_coordination_enforcement(
            INSTALL_ROOT, expected_uid,
        )
        if public_coordination is None:
            raise RuntimeError(
                "native_stack_coordination_enforcement_missing")
    try:
        MANAGER.enforce_execution_approval_floor = lambda _broker, _uid=0: None
        MANAGER.developer_id_team_floor = lambda *_args, **_kwargs: None
        current_path, current_manifest = MANAGER.verified_release(
            INSTALL_ROOT, selected_link, expected_uid,
            allow_legacy=allow_legacy,
            _bootstrap_without_developer_id_floor=(
                using_migration_predecessor
            ),
            _bootstrap_without_native_coordination_floor=(
                using_migration_predecessor
                or public_coordination_required
            ),
            # This preflight runs as the login user and cannot read the 0600
            # authoritative floor. Validate its 0444 projection here; the root
            # manager revalidates both halves before any mutation.
            _bootstrap_without_candidate_admission_floor=True,
        )
    finally:
        MANAGER.enforce_execution_approval_floor = enforce_floor
        MANAGER.developer_id_team_floor = developer_floor
    if (public_candidate_enforcement is not None
            and not allow_candidate_schema_bootstrap):
        payloads = current_manifest.get("payloads")
        if (not isinstance(payloads, dict)
                or set(payloads) != MANAGER.PAYLOAD_NAMES
                or "native_stack_coordination_contract" not in payloads):
            raise RuntimeError(
                "release_below_native_host_candidate_floor"
            )
        contract = MANAGER.validate_native_stack_coordination_contract(
            MANAGER.read_regular(
                current_path / "native_stack_coordination_contract"
            )
        )
        enforcement_record = public_candidate_enforcement[0]
        if (MANAGER.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
                    not in contract["features"]
                or enforcement_record[
                    "required_payload_inventory_sha256"
                ] != MANAGER.native_host_candidate_inventory_sha256()):
            raise RuntimeError(
                "release_below_native_host_candidate_floor"
            )
    if public_coordination_required:
        contract = MANAGER.validate_native_stack_coordination_contract(
            MANAGER.read_regular(
                current_path / "native_stack_coordination_contract"
            )
        )
        enforcement = public_coordination[0]
        if (contract["epoch"] < enforcement["minimum_epoch"]
                or not set(enforcement["minimum_features"]).issubset(
                    contract["features"]
                )):
            raise RuntimeError(
                "release_below_native_stack_coordination_floor")
    if floor_present or using_migration_predecessor:
        authorization_manifest = MANAGER.read_regular(
            current_path / "authorization_ui_bundle"
        )
        if using_migration_predecessor:
            # This is only a non-authoritative preflight for the one-time,
            # terminal-bound Development -> Developer ID migration.  The root
            # manager re-reads and binds the protected floor, exact immutable
            # predecessor release, signer team, and both manifests before it
            # mutates anything.  Permitting the exact pre-migration anchor here
            # keeps a floor-created/install-failed ceremony retryable without
            # weakening ordinary post-activation verification.
            MANAGER.verified_existing_authorization_ui_anchor_policy(
                current_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                authorization_manifest,
                expected_uid,
            )
        else:
            MANAGER.verified_authorization_ui_signing_policy(
                current_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                authorization_manifest,
                expected_uid,
            )
    broker = MANAGER.read_regular(current_path / "authorization_broker")
    if MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY not in broker:
        raise RuntimeError("current_selector_below_execution_approval_floor")
    completed = subprocess.run(
        [str(current_path / "authorization_broker"),
         "execution-approval-public-key"],
        check=True, capture_output=True, text=True,
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=10,
    )
    identity = json.loads(completed.stdout)
    if (not isinstance(identity, dict)
            or identity.get("schema") != "secure-sandbox-execution-approval-key-v2"
            or identity.get("status") != "active"
            or identity.get("algorithm") != "ecdsa-p256-sha256-x962-low-s"
            or MANAGER.SHA256.fullmatch(identity.get("public_key_sha256", "")) is None
            or not isinstance(identity.get("generation_epoch"), int)
            or isinstance(identity.get("generation_epoch"), bool)
            or identity["generation_epoch"] < 1):
        raise RuntimeError("active_execution_approval_identity_invalid")
    return current_path


def validated_developer_id_migration_predecessor(
    expected_uid: int = 0,
) -> Path | None:
    """Return only the exact, fully verified one-time migration anchor."""
    current = INSTALL_ROOT / "current"
    predecessor = (
        INSTALL_ROOT / MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
    )
    try:
        predecessor_info = predecessor.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError(
            "developer_id_migration_predecessor_untrusted") from error
    if (not stat.S_ISLNK(predecessor_info.st_mode)
            or predecessor_info.st_uid != expected_uid
            or (os.path.lexists(current) and not current.is_symlink())):
        raise RuntimeError("developer_id_migration_predecessor_untrusted")
    try:
        target = os.readlink(predecessor)
    except OSError as error:
        raise RuntimeError(
            "developer_id_migration_predecessor_untrusted") from error
    matched = re.fullmatch(r"releases/([0-9a-f]{64})", target)
    if matched is None:
        raise RuntimeError("developer_id_migration_predecessor_untrusted")
    try:
        selected = postactivation_current_release(
            allow_legacy=True, expected_uid=expected_uid,
            allow_migration_predecessor_anchor=True,
        )
    except Exception as error:
        raise RuntimeError(
            "developer_id_migration_predecessor_untrusted") from error
    if selected.name != matched.group(1):
        raise RuntimeError("developer_id_migration_predecessor_untrusted")
    return selected


def developer_id_migration_recovery_required(
    expected_uid: int = 0,
) -> bool:
    """Identify only the fenced current-absent retry prefix."""
    if os.path.lexists(INSTALL_ROOT / "current"):
        return False
    return validated_developer_id_migration_predecessor(expected_uid) is not None


def validated_developer_id_migration_completed_release(
    expected_uid: int = 0,
) -> Path | None:
    """Recognize the post-predecessor-unlink completed retry prefix."""
    predecessor = (
        INSTALL_ROOT / MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
    )
    if os.path.lexists(predecessor):
        return None
    current = INSTALL_ROOT / "current"
    if not current.is_symlink():
        if os.path.lexists(current):
            raise RuntimeError("developer_id_migration_current_untrusted")
        return None
    floor = INSTALL_ROOT / MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
    try:
        floor_info = floor.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError("developer_id_team_floor_untrusted") from error
    if (not stat.S_ISREG(floor_info.st_mode)
            or stat.S_ISLNK(floor_info.st_mode)
            or floor_info.st_uid != expected_uid
            or floor_info.st_nlink != 1
            or stat.S_IMODE(floor_info.st_mode) != 0o600
            or not 2 <= floor_info.st_size <= 2048):
        raise RuntimeError("developer_id_team_floor_untrusted")
    try:
        return postactivation_current_release(
            allow_legacy=False, expected_uid=expected_uid,
            allow_completed_migration_preflight=True,
        )
    except Exception as error:
        raise RuntimeError(
            "developer_id_migration_completed_release_untrusted") from error


def postactivation_release_archive_plan(current_path: Path) -> dict[str, object]:
    """Build the public recovery plan without reading the root-only floor."""
    enforce_floor = MANAGER.enforce_execution_approval_floor
    try:
        MANAGER.enforce_execution_approval_floor = lambda _broker, _uid=0: None
        plan = MANAGER.release_archive_plan(INSTALL_ROOT, 0)
    finally:
        MANAGER.enforce_execution_approval_floor = enforce_floor
    if plan.get("current_release_id") != current_path.name:
        raise RuntimeError("release_archive_plan_current_changed")
    retained = [plan.get("current_release_id"), plan.get("previous_release_id")]
    for release_id in retained:
        if release_id is None:
            continue
        if not isinstance(release_id, str) or MANAGER.SHA256.fullmatch(release_id) is None:
            raise RuntimeError("release_archive_plan_retained_release_invalid")
        broker = MANAGER.read_regular(
            INSTALL_ROOT / "releases" / release_id / "authorization_broker"
        )
        if MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY not in broker:
            raise RuntimeError("retained_release_below_execution_approval_floor")
    return plan


def identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--requesting-agent", default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"))
    parser.add_argument("--requesting-session", default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"))
    parser.add_argument("--purpose")


def require_identity(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.requesting_agent or not args.requesting_session:
        parser.error(
            "--requesting-agent and --requesting-session are required so the authorization prompt "
            "can be attributed to the correct agent conversation"
        )
    if not SAFE_AGENT.fullmatch(args.requesting_agent):
        parser.error("--requesting-agent must be 1-80 printable allowlisted ASCII characters")
    if not SAFE_SESSION.fullmatch(args.requesting_session):
        parser.error("--requesting-session must be 1-128 printable allowlisted ASCII characters")


def bootstrap_binding(touchid_recovery: bool = False,
                      capacity_recovery: bool = False,
                      authorization_bootstrap: bool = False,
                      secure_enclave_schema: bool = False,
                      profiled_touchid_schema: bool = False,
                      touchid_bundle_v2_schema: bool = False,
                      model_profile_schema: bool = False,
                      native_stack_schema: bool = False,
                      native_deployment_schema: bool = False,
                      native_vendor_developer_id_schema: bool = False,
                      native_host_candidate_schema: bool = False,
                      authorization_icon_schema: bool = False,
                      operator_ceremony_broker_recovery: bool = False) -> BootstrapBinding:
    migration_predecessor: Path | None = None
    completed_migration_release: Path | None = None
    native_host_candidate: NativeHostCandidate | None = None
    candidate_launcher: bytes | None = None
    authorization_predecessor_release_id = ""
    authorization_clean_machine_bootstrap = False
    if capacity_recovery:
        # The monotonic execution-approval floor is intentionally root-only.
        # Capacity recovery begins as the operator, so validate the selected
        # release through the same public v2-capability and active-identity
        # checks used by post-activation schema recovery instead of trying to
        # read that protected floor directly.
        current_path = postactivation_current_release()
        release_id = current_path.name
        manager_sha256 = hashlib.sha256(MANAGER.read_regular(MANAGER_PATH)).hexdigest()
        broker_sha256 = hashlib.sha256(
            MANAGER.read_regular(current_path / "authorization_broker")
        ).hexdigest()
        hashes: dict[str, str] = {}
        previous_ui = previous_sources = ""
    elif touchid_recovery:
        values, hashes, release_id = MANAGER.touchid_ui_recovery_payload(
            MANAGER_PATH.parent.parent, INSTALL_ROOT, 0,
        )
        current_path, current_manifest = MANAGER.verified_release(
            INSTALL_ROOT, INSTALL_ROOT / "current", 0,
        )
        manager_sha256 = hashlib.sha256(MANAGER.read_regular(MANAGER_PATH)).hexdigest()
        broker_sha256 = hashlib.sha256(values["authorization_broker"]).hexdigest()
        previous_ui = current_manifest["payloads"]["authorization_ui"]
        previous_sources = current_manifest["payloads"]["authorization_ui_sources"]
    else:
        expected_native_host_certificate_sha1: str | None = None
        prepared_candidate: NativeHostCandidate | None = None
        if native_vendor_developer_id_schema:
            migration_predecessor = (
                validated_developer_id_migration_predecessor()
            )
            if migration_predecessor is None:
                completed_migration_release = (
                    validated_developer_id_migration_completed_release()
                )
        if (authorization_bootstrap or native_host_candidate_schema
                or native_vendor_developer_id_schema
                or native_deployment_schema):
            if not (native_vendor_developer_id_schema
                    and (migration_predecessor is not None
                         or completed_migration_release is not None)):
                if native_host_candidate_schema:
                    prepared_candidate = (
                        native_host_candidate_schema_product()
                    )
                elif authorization_bootstrap:
                    prepared_candidate = (
                        native_host_authorization_bootstrap_product()
                    )
                else:
                    prepared_candidate = prepare_native_host_products()
                expected_native_host_certificate_sha1 = (
                    prepared_candidate.developer_id_certificate_sha1
                )
                if authorization_bootstrap or native_host_candidate_schema:
                    native_host_candidate = prepared_candidate
        else:
            prepare_touchid_ui()
        source_options: dict[str, object] = {}
        if prepared_candidate is not None:
            source_options.update({
                "expected_native_host_certificate_sha1": (
                    expected_native_host_certificate_sha1
                ),
                "native_host_generation": Path(
                    prepared_candidate.generation_path
                ),
                "expected_native_host_candidate": (
                    prepared_candidate.record()
                ),
            })
        values, hashes, release_id = MANAGER.source_payload(
            MANAGER_PATH.parent.parent, **source_options,
        )
        if prepared_candidate is not None:
            candidate_launcher = MANAGER.native_host_candidate_tracked_source(
                MANAGER_PATH.parent.parent,
                Path(prepared_candidate.generation_path),
                prepared_candidate.record(),
                MANAGER.LAUNCHER_SOURCE,
            )
        if (completed_migration_release is not None
                and completed_migration_release.name != release_id):
            raise RuntimeError(
                "developer_id_migration_completed_source_changed")
        # The privileged loader executes this reviewed wrapper's manager, not
        # the candidate release's embedded manager.  Those bytes are normally
        # identical, but a transferable signed candidate can legitimately
        # predate a clean-machine bootstrap repair.  Keep the executable
        # identity distinct from the independently rederived target release.
        manager_sha256 = hashlib.sha256(
            MANAGER.read_regular(MANAGER_PATH)
        ).hexdigest()
        broker_sha256 = hashlib.sha256(values["authorization_broker"]).hexdigest()
        previous_ui = previous_sources = ""
    schema_current_release_id = ""
    if (secure_enclave_schema or profiled_touchid_schema or touchid_bundle_v2_schema
            or model_profile_schema or native_stack_schema
            or native_deployment_schema
            or native_vendor_developer_id_schema
            or native_host_candidate_schema or authorization_icon_schema
            or operator_ceremony_broker_recovery):
        candidate_selector_absent = (
            native_host_candidate_schema
            and not os.path.lexists(INSTALL_ROOT / "current")
        )
        if candidate_selector_absent:
            if MANAGER.native_host_candidate_replay_enforcement(
                INSTALL_ROOT, 0, allow_absent=True,
            ) is None:
                raise RuntimeError(
                    "native_host_candidate_absent_selector_without_replay"
                )
            schema_current_release_id = "absent"
        else:
            if (touchid_bundle_v2_schema or model_profile_schema
                    or native_stack_schema or native_deployment_schema
                    or native_vendor_developer_id_schema
                    or native_host_candidate_schema
                    or authorization_icon_schema
                    or operator_ceremony_broker_recovery):
                if native_vendor_developer_id_schema:
                    current_path = (
                        migration_predecessor
                        if migration_predecessor is not None
                        else completed_migration_release
                        if completed_migration_release is not None
                        else postactivation_current_release(
                            allow_legacy=True,
                            allow_migration_predecessor_anchor=True,
                        )
                    )
                else:
                    preflight_options = {
                        "allow_legacy": (
                            model_profile_schema or native_stack_schema
                            or native_deployment_schema
                            or native_host_candidate_schema
                        ),
                    }
                    if native_host_candidate_schema:
                        preflight_options[
                            "allow_candidate_schema_bootstrap"
                        ] = True
                    current_path = postactivation_current_release(
                        **preflight_options,
                    )
            else:
                current_path, _current_manifest = MANAGER.verified_release(
                    INSTALL_ROOT, INSTALL_ROOT / "current", 0,
                    allow_legacy=(
                        profiled_touchid_schema or model_profile_schema
                    ),
                )
            schema_current_release_id = current_path.name
    developer_id_team_id = ""
    current_authorization_manifest_sha256 = ""
    candidate_authorization_manifest_sha256 = ""
    if authorization_bootstrap:
        if native_host_candidate is None:
            raise RuntimeError("native_host_candidate_binding_missing")
        candidate_manifest_data = values.get("authorization_ui_bundle")
        if not isinstance(candidate_manifest_data, bytes):
            raise RuntimeError(
                "authorization_bootstrap_developer_id_binding_invalid"
            )
        try:
            candidate_policy = (
                MANAGER.verified_authorization_ui_signing_policy(
                    Path(native_host_candidate.generation_path)
                        / MANAGER.AUTHORIZATION_UI_APP_NAME,
                    candidate_manifest_data,
                    os.geteuid(),
                    developer_id_certificate_sha1=(
                        native_host_candidate.developer_id_certificate_sha1
                    ),
                )
            )
        except (OSError, MANAGER.ReleaseFailure) as error:
            raise RuntimeError(
                "authorization_bootstrap_developer_id_binding_invalid"
            ) from error
        if (not isinstance(candidate_policy, dict)
                or candidate_policy.get("team_id")
                    != MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
                or set(candidate_policy) != {
                    "access_group", "application_identifier", "bundle_id",
                    "team_id",
                }):
            raise RuntimeError(
                "authorization_bootstrap_developer_id_binding_invalid"
            )
        developer_id_team_id = candidate_policy["team_id"]
        candidate_authorization_manifest_sha256 = hashlib.sha256(
            candidate_manifest_data
        ).hexdigest()
    elif native_vendor_developer_id_schema:
        current_manifest_data = MANAGER.read_regular(
            current_path / "authorization_ui_bundle"
        )
        candidate_manifest_data = values["authorization_ui_bundle"]
        if completed_migration_release is not None:
            current_policy = MANAGER.verified_authorization_ui_signing_policy(
                current_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                current_manifest_data,
            )
        else:
            current_policy = (
                MANAGER.verified_existing_authorization_ui_anchor_policy(
                    current_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                    current_manifest_data,
                    0,
                )
            )
        candidate_policy = MANAGER.verified_authorization_ui_signing_policy(
            MANAGER_PATH.parent.parent / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
            candidate_manifest_data,
        )
        if current_policy["team_id"] != candidate_policy["team_id"]:
            raise RuntimeError("developer_id_team_mismatch")
        developer_id_team_id = candidate_policy["team_id"]
        current_authorization_manifest_sha256 = hashlib.sha256(
            current_manifest_data
        ).hexdigest()
        candidate_authorization_manifest_sha256 = hashlib.sha256(
            candidate_manifest_data
        ).hexdigest()
    replacement_launcher = (
        candidate_launcher
        if candidate_launcher is not None
        else MANAGER.read_regular(MODULE_PATH)
    )
    if authorization_bootstrap:
        if candidate_launcher is None:
            raise RuntimeError("native_host_candidate_launcher_missing")
        (
            authorization_predecessor_release_id,
            installed_launcher,
            authorization_clean_machine_bootstrap,
        ) = clean_authorization_bootstrap_state(
            values, candidate_launcher,
        )
    else:
        installed_launcher = MANAGER.read_regular(STABLE_LAUNCHER)
    archive_plan = (
        postactivation_release_archive_plan(current_path) if capacity_recovery else None
    )
    return BootstrapBinding(
        release_id=release_id,
        manager_sha256=manager_sha256,
        broker_sha256=broker_sha256,
        installed_launcher_sha256=hashlib.sha256(installed_launcher).hexdigest(),
        replacement_launcher_sha256=hashlib.sha256(replacement_launcher).hexdigest(),
        touchid_ui_previous_sha256=previous_ui,
        touchid_ui_replacement_sha256=hashes["authorization_ui"] if touchid_recovery else "",
        touchid_sources_previous_sha256=previous_sources,
        touchid_sources_replacement_sha256=(
            hashes["authorization_ui_sources"] if touchid_recovery else ""
        ),
        archive_current_release_id=(
            archive_plan["current_release_id"] if archive_plan else ""
        ),
        archive_previous_release_id=(
            (archive_plan["previous_release_id"] or "none") if archive_plan else ""
        ),
        archive_plan_sha256=archive_plan["plan_sha256"] if archive_plan else "",
        archive_release_ids=tuple(archive_plan["archive_release_ids"]) if archive_plan else (),
        schema_current_release_id=schema_current_release_id,
        developer_id_team_id=developer_id_team_id,
        current_authorization_manifest_sha256=(
            current_authorization_manifest_sha256
        ),
        candidate_authorization_manifest_sha256=(
            candidate_authorization_manifest_sha256
        ),
        native_host_candidate=native_host_candidate,
        authorization_predecessor_release_id=(
            authorization_predecessor_release_id
        ),
        authorization_clean_machine_bootstrap=(
            authorization_clean_machine_bootstrap
        ),
    )


def native_host_candidate_details(
    candidate: NativeHostCandidate,
) -> list[str]:
    return [
        f"Retained candidate: {candidate.generation_path}",
        "Candidate identity: "
            f"{candidate.generation_device}:{candidate.generation_inode}",
        f"Candidate tree SHA-256: {candidate.generation_tree_sha256}",
        "Build custody: Trusted login principal — operator-local only",
        "Build limitation: not hostile same-UID resistant",
        f"Release commit: {candidate.release_commit}",
        f"Source archive SHA-256: {candidate.source_archive_sha256}",
        f"Source tree SHA-256: {candidate.source_tree_sha256}",
        "Signing configuration SHA-256: "
            f"{candidate.signing_config_sha256}",
        f"Private HostReleasePreimage: {candidate.host_release_preimage_path}",
        "Preimage identity: "
            f"{candidate.host_release_preimage_device}:"
            f"{candidate.host_release_preimage_inode}",
        f"Preimage bytes: {candidate.host_release_preimage_size}",
        f"Preimage SHA-256: {candidate.host_release_preimage_sha256}",
        f"Preimage schema: {candidate.host_release_preimage_schema}",
        "Developer ID certificate SHA-1: "
            f"{candidate.developer_id_certificate_sha1}",
        f"Apple notarization submission: {candidate.notary_submission_id}",
    ]


def native_host_candidate_json(
    candidate: NativeHostCandidate | None,
) -> str:
    if candidate is None:
        raise RuntimeError("native_host_candidate_binding_missing")
    return json.dumps(
        candidate.record(), separators=(",", ":"), sort_keys=True,
    )


def validate_authorization_bootstrap_developer_id_binding(
    binding: BootstrapBinding,
) -> None:
    candidate = binding.native_host_candidate
    if (candidate is None
            or candidate.schema != MANAGER.NATIVE_HOST_CANDIDATE_RECORD_SCHEMA
            or candidate.developer_id_certificate_sha1.lower()
                != candidate.developer_id_certificate_sha1
            or re.fullmatch(
                r"[0-9a-f]{40}", candidate.developer_id_certificate_sha1,
            ) is None
            or binding.developer_id_team_id
                != MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
            or re.fullmatch(
                r"[A-Z0-9]{10}", binding.developer_id_team_id,
            ) is None
            or re.fullmatch(
                r"[0-9a-f]{64}",
                binding.candidate_authorization_manifest_sha256,
            ) is None
            or re.fullmatch(
                r"[0-9a-f]{64}",
                binding.authorization_predecessor_release_id,
            ) is None
            or binding.current_authorization_manifest_sha256):
        raise RuntimeError(
            "authorization_bootstrap_developer_id_binding_invalid"
        )


def bootstrap_notice(agent: str, session: str, binding: BootstrapBinding,
                     operation: str = "bootstrap-authorization") -> bool:
    authorization_bootstrap = operation == "bootstrap-authorization"
    maintenance = operation == "bootstrap-maintenance-schema"
    touchid = operation == "bootstrap-touchid-schema"
    secure_enclave = operation == "bootstrap-secure-enclave-schema"
    profiled_touchid = operation == "bootstrap-profiled-touchid-schema"
    touchid_bundle_v2 = operation == "bootstrap-touchid-bundle-v2-schema"
    model_profile = operation == "bootstrap-model-profile-schema"
    native_stack = operation == "bootstrap-native-stack-schema"
    native_deployment = operation == "bootstrap-native-deployment-schema"
    native_vendor_developer_id = (
        operation == "bootstrap-native-vendor-developer-id-schema"
    )
    native_host_candidate_schema = (
        operation == "bootstrap-native-host-candidate-schema"
    )
    authorization_icon = operation == "bootstrap-authorization-icon-schema"
    operator_ceremony_recovery = operation == "recover-operator-ceremony-broker"
    selector_recovery = operation == "recover-release-selector"
    touchid_recovery = operation == "recover-touchid-ui"
    capacity_recovery = operation == "recover-release-capacity"
    host_pair_recovery = operation == "recover-host-pair-transition"
    if (operation in {
            "bootstrap-authorization",
            "bootstrap-native-host-candidate-schema",
            }
            and binding.native_host_candidate is None):
        raise RuntimeError("native_host_candidate_binding_missing")
    if authorization_bootstrap:
        validate_authorization_bootstrap_developer_id_binding(binding)
    purpose = (
        "finish only the exact already-journaled Host release/launcher pair transition"
        if host_pair_recovery else
        "archive inactive immutable releases while retaining active and rollback releases"
        if capacity_recovery else
        "replace the known no-window signed Touch ID UI with the reviewed corrected release"
        if touchid_recovery else
        "repair the protected release selector and install the reviewed release"
        if selector_recovery else
        "migrate the protected release to the provisioned Touch ID app-bundle schema"
        if profiled_touchid else
        "migrate the protected Touch ID bundle manifest to the signing-policy-bound v2 schema"
        if touchid_bundle_v2 else
        "migrate the protected authorization UI to the attested icon source schema"
        if authorization_icon else
        "migrate the protected release to the model-profile manager schema"
        if model_profile else
        "migrate the protected release to the native-stack manager schema"
        if native_stack else
        "migrate the protected release to the protected native-deployment schema"
        if native_deployment else
        "bind protected host admission to one exact retained signed and notarized candidate"
        if native_host_candidate_schema else
        "enroll the existing Apple team as the permanent Developer ID floor and migrate to the complete native-vendor release"
        if native_vendor_developer_id else
        "replace the exact immutable pre-execution ceremony-broker defect"
        if operator_ceremony_recovery else
        "migrate the protected release to the Secure Enclave authorization schema"
        if secure_enclave else
        "migrate the protected release to the signed Touch ID authorization schema"
        if touchid else
        "migrate the protected release to the maintenance-coordinator schema"
        if maintenance else "install the first protected authorization broker"
    )
    message = "\n".join([
        "SecureSandbox exact Host pair transition recovery"
        if host_pair_recovery else
        "SecureSandbox one-time release-capacity recovery" if capacity_recovery else
        "SecureSandbox one-time Touch ID UI recovery" if touchid_recovery else
        "SecureSandbox one-time release-selector recovery" if selector_recovery else
        "SecureSandbox one-time release-schema bootstrap"
        if (maintenance or touchid or secure_enclave or profiled_touchid
            or touchid_bundle_v2 or model_profile or native_stack
            or native_deployment
            or native_vendor_developer_id or native_host_candidate_schema
            or authorization_icon)
        else "SecureSandbox one-time operator-ceremony broker recovery"
        if operator_ceremony_recovery
        else "SecureSandbox one-time authorization bootstrap",
        "",
        f"Declared agent: {agent}",
        f"Declared session: {session}",
        f"Purpose: {purpose}",
        f"Operation: {operation}",
        "Resource: /usr/local/libexec/secure-sandbox-host",
        f"Expected release: {binding.release_id}",
        f"Bootstrap manager SHA-256: {binding.manager_sha256}",
        f"Authorization broker SHA-256: {binding.broker_sha256}",
        *([] if host_pair_recovery else [
            f"Installed launcher SHA-256: {binding.installed_launcher_sha256}",
            f"Replacement launcher SHA-256: {binding.replacement_launcher_sha256}",
        ]),
        *([f"Exact current release: {binding.schema_current_release_id}"]
          if (secure_enclave or profiled_touchid or touchid_bundle_v2 or model_profile
              or native_stack or native_vendor_developer_id
              or native_deployment or native_host_candidate_schema
              or authorization_icon
              or operator_ceremony_recovery) else []),
        *(native_host_candidate_details(binding.native_host_candidate)
          if binding.native_host_candidate is not None else []),
        *([
            "This establishes an irreversible native-host feature and inventory admission floor.",
            "Pre-candidate releases may remain as evidence but cannot regain update authority.",
            "Rollback and selector recovery fail closed below this floor.",
        ] if (native_host_candidate_schema
              or operation == "bootstrap-authorization") else []),
        *([
            f"Initial Developer ID Team floor: {binding.developer_id_team_id}",
            "Bootstrap predecessor mode: " + (
                "candidate-derived clean-machine scaffold"
                if binding.authorization_clean_machine_bootstrap
                else "existing verified pre-authorization release"
            ),
            "Exact bootstrap predecessor: "
                f"{binding.authorization_predecessor_release_id}",
            "Candidate Developer ID certificate SHA-1: "
                f"{binding.native_host_candidate.developer_id_certificate_sha1}",
            "Candidate authorization manifest SHA-256: "
                f"{binding.candidate_authorization_manifest_sha256}",
            "Initial Apple signing anchor: the exact retained v3 candidate release shown above.",
            "This is a first-install candidate anchor, not the prior-release Developer ID migration.",
            "No installed predecessor Apple signing identity grants this authority.",
        ] if authorization_bootstrap else []),
        *([
            "Permitted payload changes: authorization_ui, authorization_ui_sources",
            f"Authorization UI: {binding.touchid_ui_previous_sha256} -> {binding.touchid_ui_replacement_sha256}",
            f"Authorization UI sources: {binding.touchid_sources_previous_sha256} -> {binding.touchid_sources_replacement_sha256}",
            "All other protected payload hashes remain identical to the installed release.",
        ] if touchid_recovery else []),
        *([
            f"Expected Apple Developer Team: {binding.developer_id_team_id}",
            f"Current authorization manifest SHA-256: {binding.current_authorization_manifest_sha256}",
            f"Candidate authorization manifest SHA-256: {binding.candidate_authorization_manifest_sha256}",
            "The current immutable Apple Development-signed release is the only bootstrap anchor.",
            "The candidate must carry a valid Developer ID Application signature for the same team.",
            "This one-time operation creates a non-replaceable team floor before the candidate becomes ordinary update authority.",
        ] if native_vendor_developer_id else []),
        *([
            f"Current release retained: {binding.archive_current_release_id}",
            f"Rollback release retained: {binding.archive_previous_release_id}",
            f"Inactive releases archived: {len(binding.archive_release_ids)}",
            f"Archive plan SHA-256: {binding.archive_plan_sha256}",
            "Archive targets: " + ", ".join(binding.archive_release_ids),
            "No release is deleted; inactive releases move to the protected release archive.",
        ] if capacity_recovery else []),
        *([
            f"Public PENDING record SHA-256: {binding.host_pair_pending_sha256}",
            f"Transition ID: {binding.host_pair_transition_id}",
            f"Transition SHA-256: {binding.host_pair_transition_sha256}",
            f"Journaled operation: {binding.host_pair_operation}",
            "Journaled source pair: absent (receipt-free bootstrap)",
            f"Exact target release: {binding.release_id}",
            "Exact target candidate authority SHA-256: "
                f"{binding.host_pair_target_candidate_authority_sha256}",
            "Exact target release-tree identity SHA-256: "
                f"{binding.host_pair_target_release_tree_identity_sha256}",
            f"Exact target launcher SHA-256: {binding.installed_launcher_sha256}",
            "No new target, release, launcher, candidate, or authorization is admitted.",
            "The root manager revalidates the private transition, candidate floor, "
                "target authority, physical pair, and service identities before publication.",
            "Recovery can publish only this exact journal's terminal and STABLE records.",
        ] if host_pair_recovery else []),
        "",
        "Continue only if this matches the agent conversation you intend to authorize.",
    ])
    print(message, file=sys.stderr, flush=True)
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", BOOTSTRAP_NOTICE_SCRIPT, "--", message],
            check=False, stdin=subprocess.DEVNULL, timeout=90,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def expected_source_release_binding() -> SourceReleaseBinding:
    candidate = source_release_candidate_product()
    values, hashes, release_id = MANAGER.source_payload(
        MANAGER_PATH.parent.parent,
        expected_native_host_certificate_sha1=(
            candidate.developer_id_certificate_sha1
        ),
        native_host_generation=Path(candidate.generation_path),
        expected_native_host_candidate=candidate.record(),
    )
    required = {
        "native_stack_deployer", "native_deployment_payloads",
        "native_stack_coordination_contract",
    }
    if (not required <= set(values) or not required <= set(hashes)
            or any(
                not isinstance(values[name], bytes)
                or hashes[name] != hashlib.sha256(values[name]).hexdigest()
                for name in required
            )
            or MANAGER.EXPECTED_MODES.get("native_stack_deployer") != 0o755
            or MANAGER.EXPECTED_MODES.get("native_deployment_payloads") != 0o444
            or MANAGER.EXPECTED_MODES.get(
                "native_stack_coordination_contract") != 0o444):
        raise RuntimeError("native_deployment_release_payloads_invalid")
    try:
        _stable, source_stable_sha256, *_ = (
            MANAGER.verified_host_release_launcher_pair(
                INSTALL_ROOT, STABLE_LAUNCHER, 0, public_only=True,
            )
        )
        target_launcher = MANAGER.native_host_candidate_tracked_source(
            MANAGER_PATH.parent.parent,
            Path(candidate.generation_path),
            candidate.record(),
            MANAGER.LAUNCHER_SOURCE,
        )
        target_plan, target_plan_sha256 = (
            MANAGER.authorized_host_release_target_plan(
                release_id=release_id,
                payloads=hashes,
                candidate_record=candidate.record(),
                target_launcher_sha256=hashlib.sha256(
                    target_launcher
                ).hexdigest(),
                source_stable_sha256=source_stable_sha256,
            )
        )
    except (OSError, MANAGER.ReleaseFailure) as error:
        raise RuntimeError("host_release_target_plan_invalid") from error
    return SourceReleaseBinding(
        release_id, candidate, target_plan, target_plan_sha256,
    )


def expected_source_release_id() -> str:
    """Compatibility wrapper for callers that need only the release digest."""
    return expected_source_release_binding().release_id


def previous_release_id() -> str:
    path, _manifest = MANAGER.verified_release(INSTALL_ROOT, INSTALL_ROOT / "previous", 0)
    return path.name


def rollback_release_binding(
    release_id: str | None = None,
) -> RollbackReleaseBinding:
    try:
        _stable, source_stable_sha256, *_ = (
            MANAGER.verified_host_release_launcher_pair(
                INSTALL_ROOT, STABLE_LAUNCHER, 0, public_only=True,
            )
        )
        target_release_id = release_id or previous_release_id()
        _repo, _generation, _candidate, authority = (
            MANAGER.installed_native_host_candidate_binding(
                INSTALL_ROOT, target_release_id, 0, public_only=True,
            )
        )
        target_plan, target_plan_sha256 = (
            MANAGER.authorized_host_release_rollback_plan(
                source_stable_sha256=source_stable_sha256,
                target_authority=authority,
            )
        )
    except (OSError, MANAGER.ReleaseFailure) as error:
        raise RuntimeError("host_release_rollback_plan_invalid") from error
    if target_plan.get("target_release_id") != target_release_id:
        raise RuntimeError("host_release_rollback_plan_invalid")
    return RollbackReleaseBinding(
        target_release_id, target_plan, target_plan_sha256,
    )


def host_pair_transition_recovery_binding(
    *, install_root: Path = INSTALL_ROOT,
    launcher_path: Path = STABLE_LAUNCHER,
    manager_path: Path = MANAGER_PATH,
    expected_uid: int = 0,
) -> BootstrapBinding:
    """Bind an operator prompt to one receipt-free public PENDING record.

    The private journal remains unreadable to the login user.  This preflight
    therefore accepts only the narrowly identifiable bootstrap state exposed by
    the canonical public projection.  The root manager later reopens and
    validates the private journal and requires it to match that projection.
    """
    try:
        observed = MANAGER.host_release_launcher_pair_public(
            install_root, expected_uid, allow_absent=False,
        )
        if observed is None:
            raise RuntimeError(
                "host_pair_transition_recovery_public_pending_invalid"
            )
        pending, pending_sha256 = observed
        if (pending.get("schema")
                != MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA
                or pending.get("operation") != "install"
                or pending.get("prior_stable_sha256") is not None
                or pending.get("source_pair") is not None):
            raise RuntimeError(
                "host_pair_transition_recovery_public_pending_invalid"
            )
        target = MANAGER.validate_host_release_launcher_pair_generation(
            pending.get("target_pair")
        )
    except RuntimeError:
        raise
    except (OSError, MANAGER.ReleaseFailure) as error:
        raise RuntimeError(
            "host_pair_transition_recovery_public_pending_invalid"
        ) from error

    try:
        release, manifest = MANAGER.verified_release(
            install_root, install_root / "current", expected_uid,
            _public_enforcement_only=True,
            _skip_pair_validation=True,
        )
        if release.name != target["release_id"]:
            raise RuntimeError(
                "host_pair_transition_recovery_target_invalid"
            )
        contract = MANAGER.validate_native_stack_coordination_contract(
            MANAGER.read_regular(
                release / "native_stack_coordination_contract"
            )
        )
        if (MANAGER.HOST_RELEASE_LAUNCHER_PAIR_FEATURE
                not in contract["features"]):
            raise RuntimeError(
                "host_pair_transition_recovery_target_invalid"
            )
        authority = MANAGER.native_host_candidate_authority(
            install_root, release.name, expected_uid, public_only=True,
        )
        if (authority.get("schema")
                != MANAGER.NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA
                or authority.get("payloads") != manifest.get("payloads")
                or MANAGER.host_release_launcher_pair_generation(authority)
                    != target):
            raise RuntimeError(
                "host_pair_transition_recovery_target_invalid"
            )
        tree, tree_sha256 = (
            MANAGER.installed_native_host_release_tree_identity(
                release, expected_uid,
            )
        )
        if (tree != authority.get("release_tree_identity")
                or tree_sha256
                    != authority.get("release_tree_identity_sha256")):
            raise RuntimeError(
                "host_pair_transition_recovery_target_invalid"
            )
        launcher = MANAGER.read_trusted_stable_launcher(
            launcher_path, expected_uid,
        )
        launcher_sha256 = hashlib.sha256(launcher).hexdigest()
        if launcher_sha256 != target["launcher_sha256"]:
            raise RuntimeError(
                "host_pair_transition_recovery_target_invalid"
            )
        broker = MANAGER.read_regular(release / "authorization_broker")
        broker_sha256 = hashlib.sha256(broker).hexdigest()
        if (MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY not in broker
                or broker_sha256
                    != manifest.get("payloads", {}).get(
                        "authorization_broker")):
            raise RuntimeError(
                "host_pair_transition_recovery_target_invalid"
            )
        manager_sha256 = hashlib.sha256(
            MANAGER.read_regular(manager_path)
        ).hexdigest()
    except RuntimeError:
        raise
    except (OSError, KeyError, TypeError, MANAGER.ReleaseFailure) as error:
        raise RuntimeError(
            "host_pair_transition_recovery_target_invalid"
        ) from error

    private_pending = install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
    try:
        root_info = install_root.lstat()
        pending_info = private_pending.lstat()
    except OSError as error:
        raise RuntimeError(
            "host_pair_transition_recovery_private_pending_invalid"
        ) from error
    if (not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != expected_uid
            or stat.S_IMODE(root_info.st_mode) != 0o755
            or not stat.S_ISREG(pending_info.st_mode)
            or stat.S_ISLNK(pending_info.st_mode)
            or pending_info.st_uid != expected_uid
            or pending_info.st_gid != root_info.st_gid
            or pending_info.st_nlink != 1
            or stat.S_IMODE(pending_info.st_mode) != 0o600
            or not 2 <= pending_info.st_size
                <= MANAGER.INSTALL_TRANSITION_RECORD_LIMIT):
        raise RuntimeError(
            "host_pair_transition_recovery_private_pending_invalid"
        )

    return BootstrapBinding(
        release_id=target["release_id"],
        manager_sha256=manager_sha256,
        broker_sha256=broker_sha256,
        installed_launcher_sha256=launcher_sha256,
        replacement_launcher_sha256=launcher_sha256,
        schema_current_release_id=release.name,
        host_pair_pending_sha256=pending_sha256,
        host_pair_transition_id=pending["transition_id"],
        host_pair_transition_sha256=pending["transition_sha256"],
        host_pair_operation=pending["operation"],
        host_pair_target_candidate_authority_sha256=target[
            "candidate_authority_sha256"
        ],
        host_pair_target_release_tree_identity_sha256=target[
            "release_tree_identity_sha256"
        ],
    )


def validate_host_pair_transition_recovery_result(
    value: object, binding: BootstrapBinding,
) -> dict[str, object]:
    fields = {
        "candidate_authority_sha256", "host_release_launcher_pair_sha256",
        "operation", "release_id", "release_tree_identity_sha256", "schema",
        "status", "transition_id", "transition_sha256",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != MANAGER.SCHEMA
            or value.get("status") != "host_pair_transition_recovered"
            or value.get("operation") != binding.host_pair_operation
            or value.get("release_id") != binding.release_id
            or value.get("transition_id")
                != binding.host_pair_transition_id
            or value.get("transition_sha256")
                != binding.host_pair_transition_sha256
            or value.get("candidate_authority_sha256")
                != binding.host_pair_target_candidate_authority_sha256
            or value.get("release_tree_identity_sha256")
                != binding.host_pair_target_release_tree_identity_sha256
            or MANAGER.SHA256.fullmatch(str(value.get(
                "host_release_launcher_pair_sha256", ""
            ))) is None):
        raise RuntimeError("host_pair_transition_recovery_result_invalid")
    try:
        MANAGER._validated_uuid4(
            value["transition_id"], "host_pair_transition_id",
        )
    except MANAGER.ReleaseFailure as error:
        raise RuntimeError(
            "host_pair_transition_recovery_result_invalid"
        ) from error
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=("deploy", "rollback", "bootstrap-authorization",
                            "stage-native-host-candidate",
                            "bootstrap-maintenance-schema", "bootstrap-touchid-schema",
                            "bootstrap-secure-enclave-schema", "bootstrap-profiled-touchid-schema",
                            "bootstrap-touchid-bundle-v2-schema",
                            "bootstrap-model-profile-schema",
                            "bootstrap-native-stack-schema",
                            "bootstrap-native-deployment-schema",
                            "bootstrap-native-vendor-developer-id-schema",
                            "bootstrap-native-host-candidate-schema",
                            "bootstrap-authorization-icon-schema",
                            "recover-operator-ceremony-broker",
                            "recover-touchid-ui", "recover-release-capacity",
                            "recover-host-pair-transition")
    )
    parser.add_argument("identity", nargs="?")
    identity_arguments(parser)
    args = parser.parse_args()
    if args.command == "stage-native-host-candidate":
        if args.identity is None:
            parser.error("stage-native-host-candidate requires an absolute transfer directory")
        if (args.requesting_agent is not None or args.requesting_session is not None
                or args.purpose is not None):
            parser.error("stage-native-host-candidate does not use authorization identity")
        try:
            candidate = stage_native_host_candidate_transfer(
                Path(args.identity),
            )
        except (OSError, RuntimeError, MANAGER.ReleaseFailure) as error:
            print(str(error), file=sys.stderr)
            return 1
        print(json.dumps({
            "candidate": candidate.record(),
            "schema": "secure-sandbox-native-host-candidate-transfer-v1",
            "status": "verified",
        }, sort_keys=True))
        return 0
    if args.command in {"deploy", "bootstrap-authorization", "bootstrap-maintenance-schema",
                        "bootstrap-touchid-schema", "bootstrap-secure-enclave-schema",
                        "bootstrap-profiled-touchid-schema",
                        "bootstrap-touchid-bundle-v2-schema",
                        "bootstrap-model-profile-schema",
                        "bootstrap-native-stack-schema",
                        "bootstrap-native-deployment-schema",
                        "bootstrap-native-vendor-developer-id-schema",
                        "bootstrap-native-host-candidate-schema",
                        "bootstrap-authorization-icon-schema",
                        "recover-operator-ceremony-broker",
                        "recover-touchid-ui",
                        "recover-release-capacity",
                        "recover-host-pair-transition"} and args.identity:
        parser.error("deploy does not accept a release ID")
    require_identity(parser, args)
    state_root = LAUNCHER.STATE_ROOT
    lock: Path | None = LAUNCHER.acquire_lock(state_root, timeout=10.0)
    try:
        live = MANAGER.active_markers(state_root)
        if live:
            print("active_controller_invocations:" + ",".join(live), file=sys.stderr)
            return 1
        if args.command == "recover-host-pair-transition":
            try:
                binding = host_pair_transition_recovery_binding()
            except RuntimeError as error:
                print(str(error), file=sys.stderr)
                return 1
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-host-pair-transition",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is bound to recovery of the exact "
                "journaled Host pair transition shown above.",
                file=sys.stderr,
            )
            # Recovery takes the protected Host mutation and controller fences.
            # Relinquish this user-side coordination lock first so the exact
            # root replay cannot deadlock against its own attributed wrapper.
            assert lock is not None
            owned_lock = lock
            lock = None
            LAUNCHER.release_lock(owned_lock)
            completed = subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "recover-host-pair-transition",
                "--state-root", str(state_root),
                "--expected-public-pending-sha256",
                binding.host_pair_pending_sha256,
                "--expected-transition-id",
                binding.host_pair_transition_id,
                "--expected-transition-sha256",
                binding.host_pair_transition_sha256,
                "--expected-operation", binding.host_pair_operation,
                "--expected-target-release-id", binding.release_id,
                "--expected-target-candidate-authority-sha256",
                binding.host_pair_target_candidate_authority_sha256,
                "--expected-target-release-tree-identity-sha256",
                binding.host_pair_target_release_tree_identity_sha256,
                "--expected-target-launcher-sha256",
                binding.installed_launcher_sha256,
                "--json",
            ], check=False, capture_output=True, text=True)
            if completed.returncode != 0:
                if completed.stdout:
                    sys.stdout.write(completed.stdout)
                if completed.stderr:
                    sys.stderr.write(completed.stderr)
                print(
                    "host_pair_transition_recovery_failed:"
                    f"{completed.returncode}",
                    file=sys.stderr,
                )
                return completed.returncode
            try:
                result = json.loads(completed.stdout)
                validate_host_pair_transition_recovery_result(result, binding)
            except (json.JSONDecodeError, RuntimeError) as error:
                if completed.stderr:
                    sys.stderr.write(completed.stderr)
                print(
                    "host_pair_transition_recovery_result_invalid",
                    file=sys.stderr,
                )
                return 1
            if completed.stdout:
                sys.stdout.write(completed.stdout)
            if completed.stderr:
                sys.stderr.write(completed.stderr)
            return 0
        if args.command == "bootstrap-authorization":
            binding = bootstrap_binding(authorization_bootstrap=True)
            validate_authorization_bootstrap_developer_id_binding(binding)
            if BROKER_PATH.is_file() and not BROKER_PATH.is_symlink():
                try:
                    selected = postactivation_current_release()
                except (OSError, RuntimeError):
                    print(
                        "authorization_broker_already_deployed",
                        file=sys.stderr,
                    )
                    return 1
                if selected.name != binding.release_id:
                    print(
                        "authorization_broker_already_deployed",
                        file=sys.stderr,
                    )
                    return 1
            if not bootstrap_notice(args.requesting_agent, args.requesting_session, binding):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time bootstrap.", file=sys.stderr)
            assert lock is not None
            owned_lock = lock
            lock = None
            LAUNCHER.release_lock(owned_lock)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "bootstrap-authorization",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256,
                "--native-host-candidate-json",
                native_host_candidate_json(binding.native_host_candidate),
                "--expected-developer-id-team-id",
                binding.developer_id_team_id,
                "--expected-candidate-authorization-manifest-sha256",
                binding.candidate_authorization_manifest_sha256,
                "--expected-bootstrap-predecessor-release-id",
                binding.authorization_predecessor_release_id,
                *(["--clean-machine-bootstrap"]
                  if binding.authorization_clean_machine_bootstrap else []),
                "--json",
            ], check=False).returncode
        if args.command == "bootstrap-maintenance-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding()
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-maintenance-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time schema migration.", file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "bootstrap-maintenance-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-touchid-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding()
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-touchid-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time Touch ID schema migration.",
                  file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "bootstrap-touchid-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-secure-enclave-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(secure_enclave_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-secure-enclave-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time Secure Enclave schema migration.",
                  file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-secure-enclave-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-profiled-touchid-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(profiled_touchid_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-profiled-touchid-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time provisioned UI schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-profiled-touchid-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-touchid-bundle-v2-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(touchid_bundle_v2_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-touchid-bundle-v2-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time Touch ID bundle v2 schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-touchid-bundle-v2-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-model-profile-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(model_profile_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-model-profile-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time model-profile schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-model-profile-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-native-stack-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(native_stack_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-native-stack-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time native-stack schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-native-stack-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-native-deployment-schema":
            if not BROKER_PATH.is_file():
                print(
                    "protected_authorization_broker_unavailable",
                    file=sys.stderr,
                )
                return 1
            binding = bootstrap_binding(native_deployment_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-native-deployment-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time "
                "native-deployment schema migration.",
                file=sys.stderr,
            )
            assert lock is not None
            owned_lock = lock
            lock = None
            LAUNCHER.release_lock(owned_lock)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-native-deployment-schema",
                "--state-root", str(state_root),
                "--expected-source-release-id", binding.release_id,
                "--expected-current-release-id",
                binding.schema_current_release_id,
                "--expected-launcher-sha256",
                binding.installed_launcher_sha256,
                "--expected-replacement-sha256",
                binding.replacement_launcher_sha256,
                "--json",
            ], check=False).returncode
        if args.command == "bootstrap-native-vendor-developer-id-schema":
            if not BROKER_PATH.is_file():
                try:
                    migration_recovery = (
                        developer_id_migration_recovery_required())
                except RuntimeError as error:
                    print(str(error), file=sys.stderr)
                    return 1
                if not migration_recovery:
                    print(
                        "protected_authorization_broker_unavailable",
                        file=sys.stderr,
                    )
                    return 1
            binding = bootstrap_binding(
                native_vendor_developer_id_schema=True
            )
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-native-vendor-developer-id-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time Developer ID team-floor and native-vendor schema migration.",
                file=sys.stderr,
            )
            assert lock is not None
            owned_lock = lock
            lock = None
            LAUNCHER.release_lock(owned_lock)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-native-vendor-developer-id-schema",
                "--state-root", str(state_root),
                "--expected-source-release-id", binding.release_id,
                "--expected-current-release-id",
                binding.schema_current_release_id,
                "--expected-launcher-sha256",
                binding.installed_launcher_sha256,
                "--expected-replacement-sha256",
                binding.replacement_launcher_sha256,
                "--expected-developer-id-team-id",
                binding.developer_id_team_id,
                "--expected-current-authorization-manifest-sha256",
                binding.current_authorization_manifest_sha256,
                "--expected-candidate-authorization-manifest-sha256",
                binding.candidate_authorization_manifest_sha256,
                "--json",
            ], check=False).returncode
        if args.command == "bootstrap-native-host-candidate-schema":
            binding = bootstrap_binding(native_host_candidate_schema=True)
            if binding.schema_current_release_id not in {
                MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID,
                binding.release_id,
                "absent",
            }:
                print(
                    "native_host_candidate_schema_current_release_invalid",
                    file=sys.stderr,
                )
                return 1
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-native-host-candidate-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            candidate_json = native_host_candidate_json(
                binding.native_host_candidate
            )
            print(
                "The next password request is the terminal-bound one-time "
                "native-host candidate-admission schema migration.",
                file=sys.stderr,
            )
            assert lock is not None
            owned_lock = lock
            lock = None
            LAUNCHER.release_lock(owned_lock)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-native-host-candidate-schema",
                "--state-root", str(state_root),
                "--expected-source-release-id", binding.release_id,
                "--expected-current-release-id",
                binding.schema_current_release_id,
                "--expected-launcher-sha256",
                binding.installed_launcher_sha256,
                "--expected-replacement-sha256",
                binding.replacement_launcher_sha256,
                "--native-host-candidate-json", candidate_json,
                "--json",
            ], check=False).returncode
        if args.command == "bootstrap-authorization-icon-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(authorization_icon_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-authorization-icon-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time authorization icon schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-authorization-icon-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "recover-operator-ceremony-broker":
            binding = bootstrap_binding(operator_ceremony_broker_recovery=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-operator-ceremony-broker",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time operator-ceremony broker recovery.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "recover-operator-ceremony-broker",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "recover-touchid-ui":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(touchid_recovery=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-touchid-ui",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time Touch ID UI recovery.",
                  file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "recover-touchid-ui",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "recover-release-capacity":
            binding = bootstrap_binding(capacity_recovery=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-release-capacity",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time release-capacity recovery.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "archive-inactive-releases",
                "--state-root", str(state_root),
                "--expected-current-release-id", binding.archive_current_release_id,
                "--expected-previous-release-id", binding.archive_previous_release_id,
                "--expected-plan-sha256", binding.archive_plan_sha256,
                "--json",
            ], check=False).returncode
        # A selector defect is not authority to install a new release.  In
        # particular, generic root install here would bypass the exact
        # predecessor gate and irreversible candidate-admission floor.
        if args.command == "deploy" and selector_recovery_required():
            print(
                "release_selector_recovery_requires_a_dedicated_"
                "exact_predecessor_migration",
                file=sys.stderr,
            )
            return 1
        if not protected_broker_available():
            print(
                "protected_authorization_broker_unavailable; run bootstrap-authorization once",
                file=sys.stderr,
            )
            return 1
        operation = {
            "deploy": "host-controller-install",
            "rollback": "host-controller-rollback",
        }[args.command]
        parameters = {"repo": str(MANAGER_PATH.parent.parent), "state_root": str(state_root)}
        if args.command == "deploy":
            source = expected_source_release_binding()
            parameters.update({
                "authorized_target_plan": source.authorized_target_plan,
                "authorized_target_plan_sha256": (
                    source.authorized_target_plan_sha256
                ),
                "native_host_candidate": source.native_host_candidate.record(),
            })
        if args.command == "rollback":
            rollback_binding = rollback_release_binding(args.identity)
            parameters.update({
                "authorized_target_plan": (
                    rollback_binding.authorized_target_plan
                ),
                "authorized_target_plan_sha256": (
                    rollback_binding.authorized_target_plan_sha256
                ),
            })
        purpose = args.purpose or {
            "deploy": "Publish the reviewed host-controller release",
            "rollback": "Roll back the host-controller release",
        }[args.command]
        command = [
            str(BROKER_PATH), "request", "--agent", args.requesting_agent,
            "--session", args.requesting_session, "--purpose", purpose,
            "--resource", {
                "deploy": "/usr/local/libexec/secure-sandbox-host",
                "rollback": "/usr/local/libexec/secure-sandbox-host",
            }[args.command],
            "--operation", operation, "--parameters-json",
            json.dumps(parameters, separators=(",", ":"), sort_keys=True),
        ]
        # The broker's manager child takes the protected controller fence.
        # Retaining this wrapper's coordination lock across that subprocess
        # would make the authorized install/rollback deadlock against its own
        # parent.  Everything displayed and authorized above is content-bound;
        # the manager reacquires both fences and revalidates live markers and
        # the exact source STABLE record before its first mutation.
        assert lock is not None
        owned_lock = lock
        lock = None
        LAUNCHER.release_lock(owned_lock)
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True,
        )
        if completed.returncode != 0:
            recovery_binding = runtime_metadata_recovery_binding_from_failure(
                completed, operation,
            )
            if completed.stdout:
                sys.stdout.write(completed.stdout)
            if completed.stderr:
                sys.stderr.write(completed.stderr)
            if recovery_binding is not None and args.command == "deploy":
                request_id, request_sha256 = recovery_binding
                manager_sha256 = hashlib.sha256(
                    MANAGER.read_regular(MANAGER_PATH)
                ).hexdigest()
                print(
                    "The protected operation is ambiguous. The next "
                    "administrator-password prompt runs the exact "
                    "receipt-bound runtime-metadata recovery verifier.",
                    file=sys.stderr,
                )
                completed = subprocess.run([
                    "sudo", "/usr/bin/python3", "-I", "-c",
                    BOOTSTRAP_LOADER, str(MANAGER_PATH), manager_sha256,
                    "recover-runtime-metadata-install",
                    "--state-root", str(state_root),
                    "--expected-source-release-id", source.release_id,
                    "--authorization-request-id", request_id,
                    "--authorization-request-sha256", request_sha256,
                    "--authorized-target-plan-sha256",
                    source.authorized_target_plan_sha256,
                    "--native-host-candidate-json",
                    native_host_candidate_json(
                        source.native_host_candidate
                    ),
                    "--json",
                ], check=False, capture_output=True, text=True)
                if completed.returncode == 0:
                    pass
                else:
                    if completed.stdout:
                        sys.stdout.write(completed.stdout)
                    if completed.stderr:
                        sys.stderr.write(completed.stderr)
                    print(
                        "runtime_metadata_recovery_failed:"
                        f"{completed.returncode}",
                        file=sys.stderr,
                    )
                    return completed.returncode
            else:
                print(
                    f"protected_authorization_failed:{completed.returncode}",
                    file=sys.stderr,
                )
                return completed.returncode
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            print("host_pair_transition_result_invalid", file=sys.stderr)
            return 1
        target_plan = parameters["authorized_target_plan"]
        if (isinstance(result, dict)
                and result.get("status") == "host_pair_transition_pending"):
            if (result.get("operation") != (
                    "install" if args.command == "deploy" else "rollback"
                )
                    or result.get("authorized_target_plan_sha256")
                        != parameters["authorized_target_plan_sha256"]
                    or result.get("target_release_id") != target_plan.get(
                        "release_id" if args.command == "deploy"
                        else "target_release_id"
                    )):
                print("host_pair_transition_pending_invalid", file=sys.stderr)
                return 1
            try:
                terminal = wait_for_host_pair_terminal(result)
            except RuntimeError as error:
                print(str(error), file=sys.stderr)
                return 1
            if terminal["status"] != "target_committed":
                print(
                    "host_pair_transition_failed:"
                    + str(terminal["status"]),
                    file=sys.stderr,
                )
                return 1
            print(json.dumps(
                terminal, separators=(",", ":"), sort_keys=True,
            ))
        else:
            try:
                validate_host_pair_operation_result(
                    result,
                    operation=(
                        "install" if args.command == "deploy" else "rollback"
                    ),
                    target_plan=target_plan,
                )
            except RuntimeError as error:
                print(str(error), file=sys.stderr)
                return 1
            if completed.stdout:
                sys.stdout.write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        return 0
    finally:
        if lock is not None:
            LAUNCHER.release_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())
