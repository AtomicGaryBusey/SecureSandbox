#!/usr/bin/env python3
"""Promote an inert operator native-stack catalog into protected Host state.

Promotion never authenticates, opens egress, activates a model, or starts a
harness. It publishes one reviewed canonical catalog Research-first and then
to the root-owned Host manager under one durable lifecycle fence. An immutable
authorization receipt and cross-plane journal precede every replacement, so a
crash cannot expose an unreceipted or silently mixed catalog generation.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path
from typing import Any, Callable, Mapping


HERE = Path(__file__).resolve().parent
SUPPORT = HERE / "native_stack_support"
if SUPPORT.is_file():
    sys.path.insert(0, str(SUPPORT))
elif (HERE.parent / "shared/native_vendor_stack.py").is_file():
    sys.path.insert(0, str(HERE.parent))

from shared import native_stack_catalog_promotion as promotion_authority
from shared import native_vendor_stack


CATALOG = Path("/usr/local/var/lib/secure-sandbox/native-stack-catalog/catalog.json")
PUBLIC_STATUS = Path(
    "/usr/local/var/lib/secure-sandbox/native-stack-public/status.json"
)
TRANSACTIONS = Path("/usr/local/var/lib/secure-sandbox/native-stack-transactions")
AUTHORIZATION_RECEIPTS = Path(
    "/usr/local/var/log/secure-sandbox/authorization-receipts"
)
HOST_INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
DEPLOYMENT_STATE_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-deployment"
)
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
MAX_TRANSACTION_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
TERMINAL_PHASES = {"committed", "rejected", "recovered-fenced"}
LEGACY_PROMOTION_JOURNAL_SCHEMA = (
    "secure-sandbox-native-stack-catalog-cross-plane-journal-v1"
)
PROMOTION_JOURNAL_SCHEMA = (
    "secure-sandbox-native-stack-catalog-cross-plane-journal-v2"
)
PROMOTION_GATE_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-gate-state-v1"
)
REPLAY_AUTHORITY_SCHEMA = (
    "secure-sandbox-native-stack-catalog-replay-authority-v1"
)
RECOVERY_TERMINAL_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-terminal-v1"
)
RECOVERY_INTENT_SCHEMA = (
    "secure-sandbox-native-stack-catalog-recovery-intent-v1"
)
DEPLOYMENT_GATE_SCHEMA = "secure-sandbox-native-deployment-gate-state-v1"
PROMOTION_PHASES = (
    "authorized", "research-fenced", "research-published",
    "host-published", "cross-plane-verified", "committed", "finalized",
)
PROMOTION_STATE_NAMES = (
    ".promotion.lock", "promotion-replay-authorities",
    "promotion-receipts", "promotion-staging", "promotion-journals",
    "promotion-recovery-intents", "promotion-recovery-terminals",
)
EMPTY_CATALOG = {
    "schema": native_vendor_stack.CATALOG_SCHEMA,
    "stacks": [],
}
EMPTY_CATALOG_SHA256 = hashlib.sha256(
    native_vendor_stack.canonical_bytes(EMPTY_CATALOG)
).hexdigest()


class CatalogPromotionError(RuntimeError):
    """Stable fail-closed promotion error."""


def canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CatalogPromotionError("native_catalog_value_invalid") from error


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _release_identity(payloads: Mapping[str, str]) -> str:
    identity = bytearray()
    for name in sorted(payloads):
        identity.extend(f"{name}\0{payloads[name]}\n".encode("ascii"))
    return hashlib.sha256(identity).hexdigest()


def _trusted_release_file(
    path: Path, *, expected_uid: int, expected_mode: int,
    maximum: int = 64 * 1024 * 1024,
) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise CatalogPromotionError(
            "native_catalog_host_release_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(
                descriptor, min(1024 * 1024, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size, value.st_mode,
        value.st_uid, value.st_gid, value.st_nlink,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    try:
        current = path.lstat()
    except OSError as error:
        raise CatalogPromotionError(
            "native_catalog_host_release_unavailable") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or not 1 <= opened.st_size <= maximum
        or len(raw) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or identity(after) != identity(current)
    ):
        raise CatalogPromotionError("native_catalog_host_release_untrusted")
    return bytes(raw)


def _validate_coordination_contract(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError(
            "native_catalog_coordination_contract_invalid") from error
    features = value.get("features") if isinstance(value, dict) else None
    epoch = value.get("epoch") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "epoch", "features"}
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
        or canonical(value) != raw
    ):
        raise CatalogPromotionError(
            "native_catalog_coordination_contract_invalid")
    return value


def _validate_coordination_floor(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError(
            "native_catalog_coordination_floor_invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {
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
        or canonical(value) != raw
    ):
        raise CatalogPromotionError(
            "native_catalog_coordination_floor_invalid")
    return value


def _validate_coordination_enforcement(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError(
            "native_catalog_coordination_enforcement_invalid") from error
    features = value.get("minimum_features") if isinstance(value, dict) else None
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
        or canonical(value) != raw
    ):
        raise CatalogPromotionError(
            "native_catalog_coordination_enforcement_invalid")
    return value


@contextlib.contextmanager
def inherited_host_authority(
    host_install_fd: int, *, host_install_root: Path = HOST_INSTALL_ROOT,
    trusted_uid: int = 0, expected_host_release_id: str | None = None,
    allow_install_transition: bool = False,
    allow_missing_current: bool = False,
):
    """Hold the inherited Host OFD lock and bind the selected release."""
    if host_install_fd < 0:
        raise CatalogPromotionError("native_catalog_host_lock_required")
    descriptor = os.dup(host_install_fd)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CatalogPromotionError(
                "native_catalog_host_lock_not_held") from error
        opened = os.fstat(descriptor)
        current_root = host_install_root.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(current_root.st_mode)
            or opened.st_uid != trusted_uid
            or stat.S_IMODE(opened.st_mode) != 0o755
            or (opened.st_dev, opened.st_ino)
            != (current_root.st_dev, current_root.st_ino)
        ):
            raise CatalogPromotionError("native_catalog_host_lock_invalid")
        releases = (host_install_root / "releases").resolve(strict=True)
        current = host_install_root / "current"
        if allow_missing_current:
            if (
                expected_host_release_id is None
                or SHA256.fullmatch(expected_host_release_id) is None
                or os.path.lexists(current)
            ):
                raise CatalogPromotionError(
                    "native_catalog_transition_release_invalid")
            selected = (
                releases / expected_host_release_id).resolve(strict=True)
        else:
            selected = current.resolve(strict=True)
        relative = selected.relative_to(releases)
        expected = (
            HERE.name if expected_host_release_id is None
            else expected_host_release_id
        )
        if (
            len(relative.parts) != 1
            or SHA256.fullmatch(relative.name) is None
            or relative.name != expected
            or expected_host_release_id is None and selected != HERE
        ):
            raise CatalogPromotionError(
                "native_catalog_host_release_changed")
        selected_info = selected.lstat()
        if (
            not stat.S_ISDIR(selected_info.st_mode)
            or stat.S_ISLNK(selected_info.st_mode)
            or selected_info.st_uid != trusted_uid
            or stat.S_IMODE(selected_info.st_mode) != 0o555
        ):
            raise CatalogPromotionError(
                "native_catalog_host_release_untrusted")
        try:
            manifest_raw = _trusted_release_file(
                selected / "manifest.json", expected_uid=trusted_uid,
                expected_mode=0o444, maximum=1024 * 1024)
            manifest = json.loads(manifest_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CatalogPromotionError(
                "native_catalog_host_manifest_invalid") from error
        payloads = manifest.get("payloads") if isinstance(
            manifest, dict) else None
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"schema", "release_id", "payloads"}
            or manifest.get("schema")
                != "secure-sandbox-host-controller-release-v1"
            or manifest.get("release_id") != selected.name
            or not isinstance(payloads, dict)
            or any(
                not isinstance(name, str)
                or not isinstance(expected, str)
                or SHA256.fullmatch(expected) is None
                for name, expected in payloads.items()
            )
            or _release_identity(payloads) != selected.name
            or COORDINATION_CONTRACT_NAME not in payloads
            or SHA256.fullmatch(str(payloads.get(
                COORDINATION_CONTRACT_NAME))) is None
        ):
            raise CatalogPromotionError(
                "native_catalog_host_manifest_invalid")
        contract_raw = _trusted_release_file(
            selected / COORDINATION_CONTRACT_NAME,
            expected_uid=trusted_uid, expected_mode=0o444,
            maximum=64 * 1024)
        if hashlib.sha256(contract_raw).hexdigest() != payloads[
            COORDINATION_CONTRACT_NAME
        ]:
            raise CatalogPromotionError(
                "native_catalog_coordination_contract_changed")
        contract = _validate_coordination_contract(contract_raw)
        floor_raw = _trusted_release_file(
            host_install_root / COORDINATION_FLOOR_NAME,
            expected_uid=trusted_uid, expected_mode=0o600,
            maximum=2048)
        floor = _validate_coordination_floor(floor_raw)
        enforcement = _validate_coordination_enforcement(
            _trusted_release_file(
                host_install_root / COORDINATION_ENFORCEMENT_NAME,
                expected_uid=trusted_uid, expected_mode=0o444,
                maximum=2048,
            )
        )
        if (
            enforcement["authoritative_floor_sha256"]
                != hashlib.sha256(floor_raw).hexdigest()
            or enforcement["minimum_epoch"] != floor["minimum_epoch"]
            or contract["epoch"] < enforcement["minimum_epoch"]
            or not set(enforcement["minimum_features"])
                <= set(contract["features"])
        ):
            raise CatalogPromotionError(
                "native_catalog_coordination_contract_below_floor")
        pending = host_install_root / INSTALL_TRANSITION_PENDING_NAME
        if not allow_install_transition and os.path.lexists(pending):
            raise CatalogPromotionError(
                "native_catalog_host_install_transition_active")
        yield selected, descriptor
    except (OSError, ValueError) as error:
        if isinstance(error, CatalogPromotionError):
            raise
        raise CatalogPromotionError("native_catalog_host_lock_invalid") from error
    finally:
        # Never issue LOCK_UN on a duplicate of the caller's OFD. Closing the
        # borrowed descriptor cannot release the inherited lock while the
        # caller still owns its descriptor.
        os.close(descriptor)


def _trusted_json(
    path: Path, *, expected_uid: int = 0, expected_mode: int = 0o600
) -> dict[str, Any]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise CatalogPromotionError("native_catalog_receipt_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_TRANSACTION_BYTES:
            block = os.read(
                descriptor, min(65536, MAX_TRANSACTION_BYTES + 1 - len(raw))
            )
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != expected_uid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or not 2 <= opened.st_size <= MAX_TRANSACTION_BYTES
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or (opened.st_size, opened.st_mtime_ns)
        != (after.st_size, after.st_mtime_ns)
        or len(raw) != opened.st_size
    ):
        raise CatalogPromotionError("native_catalog_receipt_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError("native_catalog_receipt_invalid") from error
    if not isinstance(value, dict) or bytes(raw) != canonical(value):
        raise CatalogPromotionError("native_catalog_receipt_not_canonical")
    return value


def _trusted_root_directory(
    path: Path,
    *,
    create: bool = False,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
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
            raise CatalogPromotionError("native_catalog_protected_parent_untrusted")
        try:
            os.mkdir(path, 0o700)
        except OSError as error:
            raise CatalogPromotionError("native_catalog_protected_root_unavailable") from error
        info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != trusted_uid
        or info.st_gid != trusted_gid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise CatalogPromotionError("native_catalog_protected_root_untrusted")


def read_operator_catalog(
    path: Path, *, expected_uid: int, expected_sha256: str | None
) -> tuple[dict[str, Any], bytes]:
    if (
        expected_uid <= 0
        or (
            expected_sha256 is not None
            and SHA256.fullmatch(expected_sha256) is None
        )
    ):
        raise CatalogPromotionError("native_catalog_promotion_authority_invalid")
    try:
        parent = path.parent.lstat()
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise CatalogPromotionError("native_catalog_source_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, native_vendor_stack.MAX_CATALOG_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != expected_uid
        or parent.st_mode & 0o022
        or not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_gid != parent.st_gid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 2 <= before.st_size <= native_vendor_stack.MAX_CATALOG_BYTES
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or len(raw) != opened.st_size
        or (
            expected_sha256 is not None
            and hashlib.sha256(raw).hexdigest() != expected_sha256
        )
    ):
        raise CatalogPromotionError("native_catalog_source_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError("native_catalog_source_invalid") from error
    try:
        validated = native_vendor_stack.validate_catalog(value)
    except native_vendor_stack.NativeVendorStackError as error:
        raise CatalogPromotionError("native_catalog_source_invalid") from error
    if raw != native_vendor_stack.canonical_bytes(validated):
        raise CatalogPromotionError("native_catalog_source_not_canonical")
    return validated, raw


def require_idle_transactions(
    path: Path = TRANSACTIONS, *, trusted_uid: int = 0
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise CatalogPromotionError("native_catalog_transaction_state_unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != trusted_uid
        or info.st_mode & 0o022
    ):
        raise CatalogPromotionError("native_catalog_transaction_state_untrusted")
    for record in sorted(path.glob("*.json")):
        before = record.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid != trusted_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 2 <= before.st_size <= MAX_TRANSACTION_BYTES
        ):
            raise CatalogPromotionError("native_catalog_transaction_state_untrusted")
        descriptor = os.open(record, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            raw = os.read(descriptor, MAX_TRANSACTION_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(raw) != opened.st_size
        ):
            raise CatalogPromotionError("native_catalog_transaction_state_changed")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CatalogPromotionError("native_catalog_transaction_state_invalid") from error
        if not isinstance(value, dict) or raw != canonical(value):
            raise CatalogPromotionError("native_catalog_transaction_state_invalid")
        if value.get("phase") not in TERMINAL_PHASES:
            raise CatalogPromotionError("native_catalog_transaction_active")


def _atomic_root_file(
    path: Path,
    raw: bytes,
    mode: int = 0o600,
    *,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> None:
    _trusted_root_directory(
        path.parent, create=True, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), trusted_uid, trusted_gid)
            os.fchmod(handle.fileno(), mode)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _trusted_public_directory(
    path: Path, *, trusted_uid: int = 0, trusted_gid: int = 0
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != trusted_uid
            or parent.st_mode & 0o022
        ):
            raise CatalogPromotionError("native_catalog_public_parent_untrusted")
        os.mkdir(path, 0o755)
        info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != trusted_uid
        or info.st_gid != trusted_gid
        or stat.S_IMODE(info.st_mode) != 0o755
    ):
        raise CatalogPromotionError("native_catalog_public_root_untrusted")


def publish_public_status(
    *,
    catalog: Mapping[str, Any],
    catalog_sha256: str,
    host_release_id: str,
    receipt: Mapping[str, Any],
    published_at: int,
    path: Path = PUBLIC_STATUS,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    stacks = [
        {
            "stack_id": stack["stack_id"],
            "stack_sha256": native_vendor_stack.stack_revision(stack),
        }
        for stack in catalog["stacks"]
    ]
    body = {
        "catalog_sha256": catalog_sha256,
        "host_release_id": host_release_id,
        "promotion_id": receipt["promotion_id"],
        "promotion_receipt_sha256": receipt["receipt_sha256"],
        "published_at": published_at,
        "stacks": stacks,
    }
    value = {
        "schema": "secure-sandbox-native-stack-catalog-public-status-v1",
        **body,
        "status_sha256": digest(body),
    }
    _trusted_public_directory(
        path.parent, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), trusted_uid, trusted_gid)
            os.fchmod(handle.fileno(), 0o644)
            handle.write(canonical(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return value


def current_catalog_digest(path: Path = CATALOG) -> str | None:
    try:
        value = native_vendor_stack.load_catalog(path, private=True)
    except FileNotFoundError:
        return None
    except native_vendor_stack.NativeVendorStackError as error:
        raise CatalogPromotionError("native_catalog_current_untrusted") from error
    return hashlib.sha256(native_vendor_stack.canonical_bytes(value)).hexdigest()


def verify_pending_authorization_receipt(
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    receipt_root: Path = AUTHORIZATION_RECEIPTS,
    trusted_uid: int = 0,
) -> None:
    value = _trusted_json(
        receipt_root / f"{authorization['authorization_id']}.json",
        expected_uid=trusted_uid,
    )
    required = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "native_catalog_promotion_id", "native_catalog_plan_sha256",
        "host_release_id",
    }
    if (
        set(value) != required
        or value["schema"] != "secure-sandbox-operator-authorization-receipt-v1"
        or value["request_id"] != authorization["authorization_id"]
        or value["request_sha256"] != authorization["request_sha256"]
        or value["status"] != "executing"
        or value["started_at"] != authorization["authorized_at"]
        or value["completed_at"] is not None
        or value["operation"] != promotion_authority.OPERATION
        or value["identity_evidence"] != "operator-declared"
        or value["authorization_method"] != "touch-id"
        or value["ceremony"] != "approve"
        or value["resource"] != promotion_authority.RESOURCE
        or value["exit_status"] is not None
        or value["stdout_sha256"] is not None
        or value["stderr_sha256"] is not None
        or value["native_catalog_promotion_id"] != plan["promotion_id"]
        or value["native_catalog_plan_sha256"] != plan["plan_sha256"]
        or value["host_release_id"] != authorization["host_release_id"]
        or hashlib.sha256(canonical(value)).hexdigest()
        != authorization["pending_receipt_sha256"]
    ):
        raise CatalogPromotionError("native_catalog_authorization_receipt_invalid")


def _create_root_file_exclusive(
    path: Path,
    raw: bytes,
    *,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> None:
    _trusted_root_directory(
        path.parent, create=True, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), trusted_uid, trusted_gid)
            os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            raise
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _promotion_receipt(
    plan: Mapping[str, Any], authorization: Mapping[str, Any], *, promoted_at: int
) -> dict[str, Any]:
    body = {
        "promotion_id": plan["promotion_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "authorization_receipt_sha256": authorization["pending_receipt_sha256"],
        "source_sha256": plan["source_sha256"],
        "previous_catalog_sha256": plan["previous_catalog_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
        "host_release_id": plan["host_release_id"],
        "promoted_at": promoted_at,
        "status": "authorized-for-publication",
    }
    return {
        "schema": promotion_authority.RECEIPT_SCHEMA,
        **body,
        "receipt_sha256": digest(body),
    }


def _validate_promotion_receipt_record(value: object) -> dict[str, Any]:
    expected = {
        "schema", "promotion_id", "plan_sha256", "authorization_sha256",
        "authorization_receipt_sha256", "source_sha256",
        "previous_catalog_sha256", "catalog_sha256", "host_release_id",
        "promoted_at", "status", "receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise CatalogPromotionError("native_catalog_promotion_receipt_invalid")
    body = {key: item for key, item in value.items() if key not in {"schema", "receipt_sha256"}}
    if (
        value["schema"] != promotion_authority.RECEIPT_SCHEMA
        or promotion_authority.UUID4.fullmatch(
            str(value["promotion_id"])) is None
        or any(
            SHA256.fullmatch(str(value[name])) is None for name in (
                "plan_sha256", "authorization_sha256",
                "authorization_receipt_sha256", "source_sha256",
                "catalog_sha256", "host_release_id", "receipt_sha256",
            )
        )
        or value["previous_catalog_sha256"] is not None
        and SHA256.fullmatch(str(value["previous_catalog_sha256"])) is None
        or value["source_sha256"] != value["catalog_sha256"]
        or not isinstance(value["promoted_at"], int)
        or isinstance(value["promoted_at"], bool)
        or value["promoted_at"] <= 0
        or value["status"] != "authorized-for-publication"
        or value["receipt_sha256"] != digest(body)
    ):
        raise CatalogPromotionError("native_catalog_promotion_receipt_invalid")
    return value


def _validate_promotion_receipt(
    value: object,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    value = _validate_promotion_receipt_record(value)
    if (
        value["promotion_id"] != plan["promotion_id"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or value["authorization_sha256"]
        != authorization["authorization_sha256"]
        or value["authorization_receipt_sha256"]
        != authorization["pending_receipt_sha256"]
        or value["source_sha256"] != plan["source_sha256"]
        or value["previous_catalog_sha256"]
        != plan["previous_catalog_sha256"]
        or value["catalog_sha256"] != plan["catalog_sha256"]
        or value["host_release_id"] != plan["host_release_id"]
    ):
        raise CatalogPromotionError("native_catalog_promotion_receipt_invalid")
    return value


def _replay_authority(
    request: Mapping[str, Any], catalog: Mapping[str, Any], *, created_at: int,
) -> dict[str, Any]:
    plan = request["plan"]
    authorization = request["authorization"]
    body = {
        "promotion_id": plan["promotion_id"],
        "request": dict(request),
        "catalog": dict(catalog),
        "request_sha256": digest(request),
        "catalog_sha256": plan["catalog_sha256"],
        "host_release_id": plan["host_release_id"],
        "authorization_receipt_sha256": authorization[
            "pending_receipt_sha256"
        ],
        "created_at": created_at,
    }
    return {
        "schema": REPLAY_AUTHORITY_SCHEMA, **body,
        "authority_sha256": digest(body),
    }


def _validate_replay_authority(
    value: object, *, expected_host_release_id: str | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    fields = {
        "schema", "promotion_id", "request", "catalog",
        "request_sha256", "catalog_sha256", "host_release_id",
        "authorization_receipt_sha256", "created_at", "authority_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CatalogPromotionError("native_catalog_replay_authority_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "authority_sha256"}
    }
    request = value.get("request")
    request_authorization = (
        request.get("authorization") if isinstance(request, dict) else None
    )
    validation_time = (
        request_authorization.get("authorized_at")
        if isinstance(request_authorization, dict) else 0
    )
    if not isinstance(validation_time, int) or isinstance(
        validation_time, bool
    ):
        raise CatalogPromotionError("native_catalog_replay_authority_invalid")
    try:
        plan, authorization = promotion_authority.validate_request(
            value["request"], now=validation_time, require_fresh=False,
            expected_host_release_id=expected_host_release_id,
        )
        catalog = native_vendor_stack.validate_catalog(value["catalog"])
        catalog_raw = native_vendor_stack.canonical_bytes(catalog)
    except (
        promotion_authority.NativeStackCatalogPromotionError,
        native_vendor_stack.NativeVendorStackError,
    ) as error:
        raise CatalogPromotionError(
            "native_catalog_replay_authority_invalid") from error
    if (
        value["schema"] != REPLAY_AUTHORITY_SCHEMA
        or value["promotion_id"] != plan["promotion_id"]
        or value["request_sha256"] != digest(value["request"])
        or value["catalog_sha256"]
        != hashlib.sha256(catalog_raw).hexdigest()
        or value["catalog_sha256"] != plan["catalog_sha256"]
        or value["catalog_sha256"] != plan["source_sha256"]
        or value["host_release_id"] != plan["host_release_id"]
        or expected_host_release_id is not None
        and value["host_release_id"] != expected_host_release_id
        or value["authorization_receipt_sha256"]
        != authorization["pending_receipt_sha256"]
        or not isinstance(value["created_at"], int)
        or isinstance(value["created_at"], bool)
        or not authorization["authorized_at"] <= value["created_at"] < min(
            authorization["expires_at"], plan["expires_at"])
        or SHA256.fullmatch(str(value["authority_sha256"])) is None
        or value["authority_sha256"] != digest(body)
    ):
        raise CatalogPromotionError("native_catalog_replay_authority_invalid")
    return plan, authorization, catalog


def _promotion_journal_static(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    receipt: Mapping[str, Any], replay_authority_sha256: str,
) -> dict[str, Any]:
    return {
        "promotion_id": plan["promotion_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "authorization_receipt_sha256": authorization[
            "pending_receipt_sha256"
        ],
        "source_sha256": plan["source_sha256"],
        "previous_catalog_sha256": plan["previous_catalog_sha256"],
        "research_previous_catalog_sha256": (
            research_previous_catalog_sha256(plan)
        ),
        "catalog_sha256": plan["catalog_sha256"],
        "host_release_id": plan["host_release_id"],
        "promotion_receipt_sha256": receipt["receipt_sha256"],
        "replay_authority_sha256": replay_authority_sha256,
    }


def _new_promotion_journal(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    receipt: Mapping[str, Any], replay_authority_sha256: str, *,
    updated_at: int,
) -> dict[str, Any]:
    body = {
        **_promotion_journal_static(
            plan, authorization, receipt, replay_authority_sha256),
        "phase": "authorized",
        "research_observed_catalog_sha256": None,
        "research_fence_sha256": None,
        "research_idle_evidence_sha256": None,
        "research_publication_evidence_sha256": None,
        "host_observed_catalog_sha256": None,
        "research_readback_evidence_sha256": None,
        "research_release_evidence_sha256": None,
        "research_terminal_evidence_sha256": None,
        "public_status_sha256": None,
        "updated_at": updated_at,
    }
    return {
        "schema": PROMOTION_JOURNAL_SCHEMA,
        **body,
        "journal_sha256": digest(body),
    }


def _validate_promotion_journal_record(value: object) -> dict[str, Any]:
    current_fields = {
        "schema", "promotion_id", "plan_sha256", "authorization_sha256",
        "authorization_receipt_sha256", "source_sha256",
        "previous_catalog_sha256", "research_previous_catalog_sha256",
        "catalog_sha256", "host_release_id", "promotion_receipt_sha256",
        "replay_authority_sha256",
        "phase", "research_observed_catalog_sha256",
        "research_fence_sha256", "research_idle_evidence_sha256",
        "research_publication_evidence_sha256",
        "host_observed_catalog_sha256",
        "research_readback_evidence_sha256",
        "research_release_evidence_sha256",
        "research_terminal_evidence_sha256", "public_status_sha256",
        "updated_at", "journal_sha256",
    }
    legacy_fields = current_fields - {
        "public_status_sha256", "replay_authority_sha256",
    }
    if not isinstance(value, dict):
        raise CatalogPromotionError("native_catalog_promotion_journal_invalid")
    is_legacy = (
        set(value) == legacy_fields
        and value.get("schema") == LEGACY_PROMOTION_JOURNAL_SCHEMA
        and value.get("phase") in PROMOTION_PHASES[:-1]
    )
    is_current = (
        set(value) == current_fields
        and value.get("schema") == PROMOTION_JOURNAL_SCHEMA
    )
    if not is_legacy and not is_current:
        raise CatalogPromotionError("native_catalog_promotion_journal_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "journal_sha256"}
    }
    if (
        value["phase"] not in PROMOTION_PHASES
        or promotion_authority.UUID4.fullmatch(
            str(value["promotion_id"])) is None
        or not isinstance(value["updated_at"], int)
        or isinstance(value["updated_at"], bool)
        or value["updated_at"] <= 0
        or any(
            SHA256.fullmatch(str(value[name])) is None for name in (
                "plan_sha256", "authorization_sha256",
                "authorization_receipt_sha256", "source_sha256",
                "research_previous_catalog_sha256", "catalog_sha256",
                "host_release_id", "promotion_receipt_sha256",
                "journal_sha256",
            )
        )
        or not is_legacy and SHA256.fullmatch(
            str(value["replay_authority_sha256"])) is None
        or value["previous_catalog_sha256"] is not None
        and SHA256.fullmatch(str(value["previous_catalog_sha256"])) is None
        or SHA256.fullmatch(str(value["journal_sha256"])) is None
        or value["journal_sha256"] != digest(body)
    ):
        raise CatalogPromotionError("native_catalog_promotion_journal_invalid")

    # Preserve the exact v1 field set and digest during admission.  Normalize
    # only after its original bytes have been proven, so an exact same-ID
    # replay can durably migrate it to v2 without silently redefining v1.
    if is_legacy:
        normalized = dict(value)
        normalized["schema"] = LEGACY_PROMOTION_JOURNAL_SCHEMA
        normalized["public_status_sha256"] = None
        normalized["replay_authority_sha256"] = None
        normalized_body = {
            key: item for key, item in normalized.items()
            if key not in {"schema", "journal_sha256"}
        }
        normalized["journal_sha256"] = digest(normalized_body)
        value = normalized

    required_by_phase = {
        "research-fenced": (
            "research_observed_catalog_sha256", "research_fence_sha256",
            "research_idle_evidence_sha256",
        ),
        "research-published": (
            "research_publication_evidence_sha256",
        ),
        "host-published": ("host_observed_catalog_sha256",),
        "cross-plane-verified": (
            "research_readback_evidence_sha256",
        ),
        "committed": (
            "research_release_evidence_sha256",
            "research_terminal_evidence_sha256",
        ),
        "finalized": ("public_status_sha256",),
    }
    phase_index = PROMOTION_PHASES.index(value["phase"])
    evidence_fields = [
        "research_observed_catalog_sha256", "research_fence_sha256",
        "research_idle_evidence_sha256",
        "research_publication_evidence_sha256",
        "host_observed_catalog_sha256",
        "research_readback_evidence_sha256",
        "research_release_evidence_sha256",
        "research_terminal_evidence_sha256",
        "public_status_sha256",
    ]
    required: set[str] = set()
    for phase, names in required_by_phase.items():
        if phase_index >= PROMOTION_PHASES.index(phase):
            required.update(names)
    for name in evidence_fields:
        item = value[name]
        if name in required:
            if not isinstance(item, str) or SHA256.fullmatch(item) is None:
                raise CatalogPromotionError(
                    "native_catalog_promotion_journal_invalid")
        elif item is not None:
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_invalid")
    if (
        value["research_observed_catalog_sha256"] is not None
        and value["research_observed_catalog_sha256"] not in {
            value["research_previous_catalog_sha256"], value["catalog_sha256"]
        }
    ):
        raise CatalogPromotionError("native_catalog_promotion_journal_invalid")
    if (
        value["host_observed_catalog_sha256"] is not None
        and value["host_observed_catalog_sha256"] != value["catalog_sha256"]
    ):
        raise CatalogPromotionError("native_catalog_promotion_journal_invalid")
    return value


def _validate_promotion_journal(
    value: object, plan: Mapping[str, Any], authorization: Mapping[str, Any],
    receipt: Mapping[str, Any], replay_authority_sha256: str,
) -> dict[str, Any]:
    value = _validate_promotion_journal_record(value)
    expected = _promotion_journal_static(
        plan, authorization, receipt, replay_authority_sha256)
    legacy = value["schema"] == LEGACY_PROMOTION_JOURNAL_SCHEMA
    if any(
        value[key] != item for key, item in expected.items()
        if key != "replay_authority_sha256" or not legacy
    ):
        raise CatalogPromotionError("native_catalog_promotion_journal_invalid")
    if legacy:
        value = dict(value)
        value["replay_authority_sha256"] = replay_authority_sha256
    return value


def _advance_promotion_journal(
    value: Mapping[str, Any], *, phase: str, updated_at: int,
    evidence: Mapping[str, str], path: Path, trusted_uid: int,
    trusted_gid: int,
) -> dict[str, Any]:
    if phase not in PROMOTION_PHASES:
        raise CatalogPromotionError("native_catalog_promotion_phase_invalid")
    current_index = PROMOTION_PHASES.index(value["phase"])
    next_index = PROMOTION_PHASES.index(phase)
    if next_index <= current_index:
        return dict(value)
    if next_index != current_index + 1:
        raise CatalogPromotionError("native_catalog_promotion_phase_gap")
    updated = dict(value)
    updated["schema"] = PROMOTION_JOURNAL_SCHEMA
    updated.update(evidence)
    updated["phase"] = phase
    updated["updated_at"] = updated_at
    body = {
        key: item for key, item in updated.items()
        if key not in {"schema", "journal_sha256"}
    }
    updated["journal_sha256"] = digest(body)
    _atomic_root_file(
        path, canonical(updated), trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    return updated


def research_previous_catalog_sha256(plan: Mapping[str, Any]) -> str:
    previous = plan["previous_catalog_sha256"]
    return EMPTY_CATALOG_SHA256 if previous is None else previous


def require_cross_plane_generation(
    plan: Mapping[str, Any], *, host_observed: str | None,
    research_observed: str,
) -> None:
    allowed = {
        (
            plan["previous_catalog_sha256"],
            research_previous_catalog_sha256(plan),
        ),
        (plan["previous_catalog_sha256"], plan["catalog_sha256"]),
        (plan["catalog_sha256"], plan["catalog_sha256"]),
    }
    if (host_observed, research_observed) not in allowed:
        raise CatalogPromotionError(
            "native_catalog_cross_plane_generation_mismatch")


def _guest_request(
    plan: Mapping[str, Any], *, schema: str,
    catalog: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "promotion_id": plan["promotion_id"],
        "plan_sha256": plan["plan_sha256"],
        "host_previous_catalog_sha256": plan["previous_catalog_sha256"],
        "previous_catalog_sha256": research_previous_catalog_sha256(plan),
        "catalog_sha256": plan["catalog_sha256"],
    }
    if catalog is not None:
        admitted = native_vendor_stack.validate_catalog(catalog)
        if (
            hashlib.sha256(
                native_vendor_stack.canonical_bytes(admitted)
            ).hexdigest()
            != plan["catalog_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_guest_request_catalog_mismatch")
        body["catalog"] = admitted
    return {"schema": schema, **body, "request_sha256": digest(body)}


def _call_research(
    operation: str, request: Mapping[str, Any], *,
    control_client: Path | None = None,
    ssh_config: Path | None = None,
) -> dict[str, Any]:
    release = Path(__file__).resolve().parent
    client = release / "control_client" if control_client is None else control_client
    config = release / "ssh_config" if ssh_config is None else ssh_config
    try:
        result = subprocess.run(
            [
                str(client), "client", "--ssh-config", str(config),
                "--timeout-seconds", "120", "sandbox-research-control", "pipe",
                operation,
            ],
            input=canonical(request),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=150,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CatalogPromotionError(
            "native_catalog_guest_operation_unavailable") from error
    try:
        reply = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError(
            "native_catalog_guest_operation_invalid") from error
    if (
        result.returncode != 0
        or not isinstance(reply, dict)
        or result.stdout != canonical(reply)
    ):
        raise CatalogPromotionError("native_catalog_guest_operation_invalid")
    return reply


def require_guest_idle(
    plan: Mapping[str, Any],
    *,
    control_client: Path | None = None,
    ssh_config: Path | None = None,
) -> dict[str, Any]:
    request = _guest_request(
        plan, schema="secure-sandbox-native-stack-lifecycle-idle-request-v1")
    reply = _call_research(
        "native-stack-lifecycle-idle", request,
        control_client=control_client, ssh_config=ssh_config)
    if (
        set(reply) != {
            "schema", "state", "live_run_count",
            "observed_catalog_sha256", "fence_sha256", "evidence_sha256",
        }
        or reply["schema"]
        != "secure-sandbox-native-stack-lifecycle-idle-reply-v1"
        or reply["state"] != "idle" or reply["live_run_count"] != 0
        or reply["observed_catalog_sha256"] not in {
            research_previous_catalog_sha256(plan), plan["catalog_sha256"]
        }
        or any(SHA256.fullmatch(str(reply[field])) is None for field in (
            "observed_catalog_sha256", "fence_sha256", "evidence_sha256"))
    ):
        raise CatalogPromotionError("native_catalog_guest_idle_invalid")
    return reply


def publish_guest_catalog(
    plan: Mapping[str, Any], catalog: Mapping[str, Any], *,
    control_client: Path | None = None, ssh_config: Path | None = None,
) -> dict[str, Any]:
    request = _guest_request(
        plan, schema="secure-sandbox-native-stack-catalog-publish-request-v1",
        catalog=catalog)
    reply = _call_research(
        "native-stack-catalog-publish", request,
        control_client=control_client, ssh_config=ssh_config)
    if (
        set(reply) != {
            "schema", "state", "catalog_sha256", "fence_sha256",
            "publication_phase", "publication_evidence_sha256",
        }
        or reply["schema"]
        != "secure-sandbox-native-stack-catalog-publish-reply-v1"
        or reply["state"] != "published"
        or reply["publication_phase"] not in {"published", "released"}
        or reply["catalog_sha256"] != plan["catalog_sha256"]
        or any(SHA256.fullmatch(str(reply[field])) is None for field in (
            "fence_sha256", "publication_evidence_sha256"))
    ):
        raise CatalogPromotionError("native_catalog_guest_publication_invalid")
    return reply


def readback_guest_catalog(
    plan: Mapping[str, Any], *, control_client: Path | None = None,
    ssh_config: Path | None = None,
) -> dict[str, Any]:
    request = _guest_request(
        plan, schema="secure-sandbox-native-stack-catalog-readback-request-v1")
    reply = _call_research(
        "native-stack-catalog-readback", request,
        control_client=control_client, ssh_config=ssh_config)
    if (
        set(reply) != {
            "schema", "state", "catalog_sha256", "fence_sha256",
            "publication_phase", "publication_evidence_sha256",
            "evidence_sha256",
        }
        or reply["schema"]
        != "secure-sandbox-native-stack-catalog-readback-reply-v1"
        or reply["state"] != "verified"
        or reply["publication_phase"] not in {"published", "released"}
        or reply["catalog_sha256"] != plan["catalog_sha256"]
        or any(SHA256.fullmatch(str(reply[field])) is None for field in (
            "fence_sha256", "publication_evidence_sha256", "evidence_sha256"))
    ):
        raise CatalogPromotionError("native_catalog_guest_readback_invalid")
    return reply


def release_guest_lifecycle(
    plan: Mapping[str, Any], *, control_client: Path | None = None,
    ssh_config: Path | None = None,
) -> dict[str, Any]:
    """Release only after Research independently proves the candidate catalog."""
    request = _guest_request(
        plan, schema="secure-sandbox-native-stack-lifecycle-release-request-v1")
    reply = _call_research(
        "native-stack-lifecycle-release", request,
        control_client=control_client, ssh_config=ssh_config)
    if (
        set(reply) != {
            "schema", "state", "catalog_sha256", "evidence_sha256",
            "publication_evidence_sha256",
        }
        or reply["schema"]
        != "secure-sandbox-native-stack-lifecycle-release-reply-v1"
        or reply["state"] != "released"
        or reply["catalog_sha256"] != plan["catalog_sha256"]
        or any(SHA256.fullmatch(str(reply[field])) is None for field in (
            "evidence_sha256", "publication_evidence_sha256"))
    ):
        raise CatalogPromotionError("native_catalog_guest_release_invalid")
    return reply


def _open_trusted_lock(
    path: Path, *, trusted_uid: int = 0, trusted_gid: int = 0,
    create: bool = True,
) -> int:
    _trusted_root_directory(
        path.parent, create=create, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid
    )
    if create:
        try:
            descriptor = os.open(
                path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
            )
            os.fchmod(descriptor, 0o600)
        except FileExistsError:
            descriptor = os.open(
                path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    else:
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != trusted_uid
        or info.st_gid != trusted_gid
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise CatalogPromotionError("native_catalog_promotion_lock_untrusted")
    return descriptor


def _trusted_artifact_inventory(
    directory: Path, *, trusted_uid: int, trusted_gid: int,
) -> dict[str, dict[str, Any]]:
    _trusted_root_directory(
        directory, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    result: dict[str, dict[str, Any]] = {}
    for candidate in sorted(directory.iterdir()):
        match = re.fullmatch(
            r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json",
            candidate.name,
        )
        if match is None:
            raise CatalogPromotionError(
                "native_catalog_promotion_artifact_inventory_invalid")
        promotion_id = match.group(1)
        if promotion_authority.UUID4.fullmatch(promotion_id) is None:
            raise CatalogPromotionError(
                "native_catalog_promotion_artifact_inventory_invalid")
        result[promotion_id] = _trusted_json(
            candidate, expected_uid=trusted_uid)
    return result


def _reconcile_exclusive_residues(
    directory: Path, *, trusted_uid: int, trusted_gid: int,
) -> None:
    """Remove only provable pre/post-link residues under the held gate lock."""
    _trusted_root_directory(
        directory, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    changed = False
    pattern = re.compile(
        r"\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json)\..+"
    )
    for temporary in sorted(directory.iterdir()):
        match = pattern.fullmatch(temporary.name)
        if match is None:
            continue
        info = temporary.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != trusted_uid
            or info.st_gid != trusted_gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink not in {1, 2}
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_residue_invalid")
        final = directory / match.group(1)
        if info.st_nlink == 2:
            final_info = final.lstat()
            if (
                (final_info.st_dev, final_info.st_ino)
                != (info.st_dev, info.st_ino)
            ):
                raise CatalogPromotionError(
                    "native_catalog_promotion_residue_invalid")
        temporary.unlink()
        changed = True
    if changed:
        descriptor = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _validate_public_status_record(value: object) -> dict[str, Any]:
    fields = {
        "schema", "catalog_sha256", "host_release_id", "promotion_id",
        "promotion_receipt_sha256", "published_at", "stacks",
        "status_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CatalogPromotionError("native_catalog_public_status_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "status_sha256"}
    }
    stacks = value["stacks"]
    if (
        value["schema"]
        != "secure-sandbox-native-stack-catalog-public-status-v1"
        or promotion_authority.UUID4.fullmatch(
            str(value["promotion_id"])) is None
        or any(
            SHA256.fullmatch(str(value[name])) is None for name in (
                "catalog_sha256", "host_release_id",
                "promotion_receipt_sha256", "status_sha256",
            )
        )
        or not isinstance(value["published_at"], int)
        or isinstance(value["published_at"], bool)
        or value["published_at"] <= 0
        or not isinstance(stacks, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"stack_id", "stack_sha256"}
            or not isinstance(item["stack_id"], str)
            or SHA256.fullmatch(str(item["stack_sha256"])) is None
            for item in stacks
        )
        or value["status_sha256"] != digest(body)
    ):
        raise CatalogPromotionError("native_catalog_public_status_invalid")
    return value


def _finalized_chain_head(
    finalized: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    if not finalized:
        return None
    by_catalog: dict[str, Mapping[str, Any]] = {}
    for record in finalized.values():
        candidate = record["catalog_sha256"]
        if candidate in by_catalog or candidate == record["previous_catalog_sha256"]:
            raise CatalogPromotionError(
                "native_catalog_promotion_history_invalid")
        by_catalog[candidate] = record
    successors: dict[str, str] = {}
    for record in finalized.values():
        previous = record["previous_catalog_sha256"]
        if previous in by_catalog:
            if previous in successors:
                raise CatalogPromotionError(
                    "native_catalog_promotion_history_forked")
            successors[previous] = record["catalog_sha256"]
    for start in by_catalog:
        visited: set[str] = set()
        cursor = start
        while cursor in successors:
            if cursor in visited:
                raise CatalogPromotionError(
                    "native_catalog_promotion_history_cycle")
            visited.add(cursor)
            cursor = successors[cursor]
        if cursor in visited:
            raise CatalogPromotionError(
                "native_catalog_promotion_history_cycle")
    roots = [
        record for record in finalized.values()
        if record["previous_catalog_sha256"] not in by_catalog
    ]
    heads = [
        record for candidate, record in by_catalog.items()
        if candidate not in successors
    ]
    if len(roots) != 1 or len(heads) != 1:
        raise CatalogPromotionError(
            "native_catalog_promotion_history_invalid")
    visited: set[str] = set()
    cursor = roots[0]["catalog_sha256"]
    while True:
        visited.add(cursor)
        if cursor not in successors:
            break
        cursor = successors[cursor]
    if visited != set(by_catalog):
        raise CatalogPromotionError(
            "native_catalog_promotion_history_invalid")
    return heads[0]


def _require_active_extends_finalized_head(
    active_previous: str | None,
    finalized_head: Mapping[str, Any] | None,
) -> None:
    if (
        finalized_head is not None
        and active_previous != finalized_head["catalog_sha256"]
    ):
        raise CatalogPromotionError(
            "native_catalog_promotion_history_disconnected")


def _authority_active_gate_identity(
    authority: Mapping[str, Any],
) -> tuple[str, str]:
    plan = authority["request"]["plan"]
    state_body = {
        "promotion_id": authority["promotion_id"],
        "replay_authority_sha256": authority["authority_sha256"],
        "previous_catalog_sha256": plan["previous_catalog_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
        "host_release_id": plan["host_release_id"],
    }
    active_state_sha256 = digest(state_body)
    gate_body = {
        "state": "active",
        "active_promotion_id": authority["promotion_id"],
        "active_state_sha256": active_state_sha256,
    }
    return active_state_sha256, digest(gate_body)


def _promotion_gate_body_under_lock(
    *, catalog_root: Path, public_status: Path, trusted_uid: int,
    trusted_gid: int, expected_host_release_id: str,
) -> dict[str, Any]:
    receipts_root = catalog_root / "promotion-receipts"
    authorities_root = catalog_root / "promotion-replay-authorities"
    intents_root = catalog_root / "promotion-recovery-intents"
    terminals_root = catalog_root / "promotion-recovery-terminals"
    staging_root = catalog_root / "promotion-staging"
    journals_root = catalog_root / "promotion-journals"
    for directory in (catalog_root, receipts_root, staging_root, journals_root):
        _trusted_root_directory(
            directory, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    authorities_exist = os.path.lexists(authorities_root)
    if authorities_exist:
        _trusted_root_directory(
            authorities_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
    for optional in (intents_root, terminals_root):
        if os.path.lexists(optional):
            _trusted_root_directory(
                optional, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            _reconcile_exclusive_residues(
                optional, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
    for directory in (receipts_root, staging_root, journals_root):
        _reconcile_exclusive_residues(
            directory, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if authorities_exist:
        _reconcile_exclusive_residues(
            authorities_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
    authorities_raw = (
        _trusted_artifact_inventory(
            authorities_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        if authorities_exist else {}
    )
    intents_raw = (
        _trusted_artifact_inventory(
            intents_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        if os.path.lexists(intents_root) else {}
    )
    terminals_raw = (
        _trusted_artifact_inventory(
            terminals_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        if os.path.lexists(terminals_root) else {}
    )
    receipts_raw = _trusted_artifact_inventory(
        receipts_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    stages_raw = _trusted_artifact_inventory(
        staging_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    journals_raw = _trusted_artifact_inventory(
        journals_root, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    receipts = {
        promotion_id: _validate_promotion_receipt_record(value)
        for promotion_id, value in receipts_raw.items()
    }
    authorities: dict[str, dict[str, Any]] = {}
    authority_bindings: dict[
        str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
    ] = {}
    for promotion_id, value in authorities_raw.items():
        plan, authorization, catalog = _validate_replay_authority(
            value, expected_host_release_id=None)
        if plan["promotion_id"] != promotion_id:
            raise CatalogPromotionError(
                "native_catalog_replay_authority_identity_invalid")
        authorities[promotion_id] = value
        authority_bindings[promotion_id] = (plan, authorization, catalog)
    intents: dict[str, dict[str, Any]] = {}
    for promotion_id, value in intents_raw.items():
        authority = authorities.get(promotion_id)
        if authority is None:
            raise CatalogPromotionError(
                "native_catalog_recovery_intent_orphaned")
        intent = _validate_recovery_intent(value, authority)
        if intent["promotion_id"] != promotion_id:
            raise CatalogPromotionError(
                "native_catalog_recovery_intent_orphaned")
        intents[promotion_id] = intent
    stages: dict[str, tuple[dict[str, Any], str]] = {}
    for promotion_id, value in stages_raw.items():
        try:
            admitted = native_vendor_stack.validate_catalog(value)
            raw = native_vendor_stack.canonical_bytes(admitted)
        except native_vendor_stack.NativeVendorStackError as error:
            raise CatalogPromotionError(
                "native_catalog_promotion_staging_invalid") from error
        if raw != canonical(value):
            raise CatalogPromotionError(
                "native_catalog_promotion_staging_invalid")
        stages[promotion_id] = (
            admitted, hashlib.sha256(raw).hexdigest())
    legacy_journals = {
        promotion_id for promotion_id, value in journals_raw.items()
        if value.get("schema") == LEGACY_PROMOTION_JOURNAL_SCHEMA
    }
    journals = {
        promotion_id: _validate_promotion_journal_record(value)
        for promotion_id, value in journals_raw.items()
    }
    if any(
        value["promotion_id"] != promotion_id
        for mapping in (receipts, journals)
        for promotion_id, value in mapping.items()
    ):
        raise CatalogPromotionError(
            "native_catalog_promotion_artifact_identity_invalid")

    active: dict[str, dict[str, Any]] = {}
    finalized: dict[str, dict[str, Any]] = {}
    for promotion_id in sorted(
        set(authorities) | set(receipts) | set(stages) | set(journals)
    ):
        authority = authorities.get(promotion_id)
        receipt = receipts.get(promotion_id)
        stage = stages.get(promotion_id)
        journal = journals.get(promotion_id)
        if authority is not None and receipt is not None:
            authority_plan, authority_authorization, _authority_catalog = (
                authority_bindings[promotion_id]
            )
            receipt = _validate_promotion_receipt(
                receipt, authority_plan, authority_authorization)
            receipts[promotion_id] = receipt
        if journal is None:
            if authority is None:
                raise CatalogPromotionError(
                    "native_catalog_promotion_authority_missing")
            if stage is None and receipt is not None:
                raise CatalogPromotionError(
                    "native_catalog_promotion_orphan_receipt")
            if stage is not None and stage[1] != authority["catalog_sha256"]:
                raise CatalogPromotionError(
                    "native_catalog_promotion_artifact_mismatch")
            if receipt is not None and (
                stage is None or receipt["catalog_sha256"] != stage[1]
            ):
                raise CatalogPromotionError(
                    "native_catalog_promotion_artifact_mismatch")
            active[promotion_id] = {
                "receipt_sha256": (
                    None if receipt is None else receipt["receipt_sha256"]),
                "stage_sha256": None if stage is None else stage[1],
                "journal_sha256": None,
                "replay_authority_sha256": authority["authority_sha256"],
                "previous_catalog_sha256": authority["request"]["plan"][
                    "previous_catalog_sha256"
                ],
                "candidate_catalog_sha256": authority["catalog_sha256"],
                "recovery_intent_sha256": (
                    None if promotion_id not in intents
                    else intents[promotion_id]["intent_sha256"]
                ),
            }
            continue
        if receipt is None:
            raise CatalogPromotionError(
                "native_catalog_promotion_orphan_journal")
        if (
            authority is not None
            and journal["schema"] != LEGACY_PROMOTION_JOURNAL_SCHEMA
        ):
            authority_plan, authority_authorization, _authority_catalog = (
                authority_bindings[promotion_id]
            )
            journal = _validate_promotion_journal(
                journal, authority_plan, authority_authorization, receipt,
                authority["authority_sha256"],
            )
            journals[promotion_id] = journal
        if (
            journal["schema"] != LEGACY_PROMOTION_JOURNAL_SCHEMA
            and (
                authority is None
                or journal["replay_authority_sha256"]
                != authority["authority_sha256"]
            )
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_authority_mismatch")
        if (
            journal["promotion_receipt_sha256"] != receipt["receipt_sha256"]
            or journal["plan_sha256"] != receipt["plan_sha256"]
            or journal["authorization_sha256"]
            != receipt["authorization_sha256"]
            or journal["authorization_receipt_sha256"]
            != receipt["authorization_receipt_sha256"]
            or journal["source_sha256"] != receipt["source_sha256"]
            or journal["previous_catalog_sha256"]
            != receipt["previous_catalog_sha256"]
            or journal["catalog_sha256"] != receipt["catalog_sha256"]
            or journal["host_release_id"] != receipt["host_release_id"]
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_artifact_mismatch")
        if journal["phase"] == "finalized":
            if stage is not None:
                raise CatalogPromotionError(
                    "native_catalog_promotion_finalized_staging_present")
            finalized[promotion_id] = journal
        else:
            # A committed journal can legitimately outlive staging: cleanup
            # precedes the v2 finalized write, and legacy v1 did not have a
            # finalized phase.  Every earlier phase must retain exact staging.
            stage_optional = journal["phase"] == "committed"
            if (
                stage is None and not stage_optional
                or stage is not None
                and stage[1] != journal["catalog_sha256"]
            ):
                raise CatalogPromotionError(
                    "native_catalog_promotion_active_staging_invalid")
            active[promotion_id] = {
                "receipt_sha256": receipt["receipt_sha256"],
                "stage_sha256": None if stage is None else stage[1],
                "journal_sha256": journal["journal_sha256"],
                "replay_authority_sha256": (
                    None if authority is None
                    else authority["authority_sha256"]
                ),
                "recovery_intent_sha256": (
                    None if promotion_id not in intents
                    else intents[promotion_id]["intent_sha256"]
                ),
                "journal": journal,
            }
    status = None
    if os.path.lexists(public_status):
        status = _validate_public_status_record(_trusted_json(
            public_status, expected_uid=trusted_uid, expected_mode=0o644))

    current_path = catalog_root / "catalog.json"
    current_digest = current_catalog_digest(current_path)
    current_catalog = None
    if current_digest is not None:
        try:
            current_catalog = native_vendor_stack.load_catalog(
                current_path, private=True)
        except native_vendor_stack.NativeVendorStackError as error:
            raise CatalogPromotionError(
                "native_catalog_current_untrusted") from error

    def status_matches(
        record: Mapping[str, Any], *, require_record_digest: bool,
    ) -> bool:
        if status is None:
            return False
        receipt = receipts[record["promotion_id"]]
        if (
            status["promotion_id"] != record["promotion_id"]
            or status["catalog_sha256"] != record["catalog_sha256"]
            or status["host_release_id"] != record["host_release_id"]
            or status["promotion_receipt_sha256"]
            != receipt["receipt_sha256"]
        ):
            return False
        if require_record_digest and (
            hashlib.sha256(canonical(status)).hexdigest()
            != record["public_status_sha256"]
        ):
            return False
        if status["catalog_sha256"] == current_digest:
            assert current_catalog is not None
            projected = [
                {
                    "stack_id": stack["stack_id"],
                    "stack_sha256": native_vendor_stack.stack_revision(stack),
                }
                for stack in current_catalog["stacks"]
            ]
            if status["stacks"] != projected:
                return False
        return True

    # Legacy v1 removed staging only after publishing public status.  Treat
    # that exact committed/no-stage prefix as history, then require the one
    # structurally derived chain head (legacy or v2) to match current status.
    for promotion_id in tuple(active):
        item = active[promotion_id]
        journal = item.get("journal")
        if (
            promotion_id in legacy_journals
            and journal is not None
            and journal["phase"] == "committed"
            and item["stage_sha256"] is None
        ):
            finalized[promotion_id] = journal
            del active[promotion_id]

    for promotion_id in intents:
        if promotion_id not in active and promotion_id not in finalized:
            raise CatalogPromotionError(
                "native_catalog_recovery_intent_orphaned")
        active_sha256, gate_sha256 = _authority_active_gate_identity(
            authorities[promotion_id])
        if (
            intents[promotion_id]["active_state_sha256"] != active_sha256
            or intents[promotion_id]["expected_gate_sha256"] != gate_sha256
        ):
            raise CatalogPromotionError(
                "native_catalog_recovery_intent_invalid")
    for promotion_id, value in terminals_raw.items():
        authority = authorities.get(promotion_id)
        receipt = receipts.get(promotion_id)
        if (
            authority is None or receipt is None
            or promotion_id not in intents
            or promotion_id not in finalized
        ):
            raise CatalogPromotionError(
                "native_catalog_recovery_terminal_orphaned")
        _validate_recovery_terminal(
            value, authority, receipt, intents[promotion_id])

    if len(active) > 1:
        raise CatalogPromotionError(
            "native_catalog_multiple_promotions_active")

    active_id = next(iter(active), None)
    active_journal = (
        None if active_id is None else active[active_id].get("journal")
    )
    if active_id is not None and active_id in authorities and (
        authorities[active_id]["host_release_id"]
        != expected_host_release_id
    ):
        raise CatalogPromotionError(
            "native_catalog_active_host_release_mismatch")
    if active_journal is not None and (
        active_journal["host_release_id"] != expected_host_release_id
    ):
        raise CatalogPromotionError(
            "native_catalog_active_host_release_mismatch")
    finalized_head = _finalized_chain_head(finalized)

    active_previous = None
    if active_journal is not None:
        active_previous = active_journal["previous_catalog_sha256"]
    elif active_id is not None and active_id in authorities:
        active_previous = authorities[active_id]["request"]["plan"][
            "previous_catalog_sha256"]
    if active_id is not None:
        _require_active_extends_finalized_head(
            active_previous, finalized_head)

    if (
        status is None and active_journal is not None
        and active_journal["phase"] == "committed"
        and active[active_id]["stage_sha256"] is None
    ):
        raise CatalogPromotionError(
            "native_catalog_promotion_cleanup_state_invalid")
    if status is None:
        if finalized:
            raise CatalogPromotionError("native_catalog_public_status_missing")
    else:
        status_is_finalized = any(
            status_matches(record, require_record_digest=(
                record["phase"] == "finalized"))
            for record in finalized.values()
        )
        status_is_active = (
            active_journal is not None
            and active_journal["phase"] == "committed"
            and status_matches(
                active_journal, require_record_digest=False)
        )
        if (
            active_journal is not None
            and active_journal["phase"] == "committed"
            and active[active_id]["stage_sha256"] is None
            and not status_is_active
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_cleanup_state_invalid")
        if not status_is_finalized and not status_is_active:
            raise CatalogPromotionError(
                "native_catalog_public_status_orphaned")
        if active_id is not None and not status_is_active and (
            finalized_head is None
            or status["promotion_id"] != finalized_head["promotion_id"]
        ):
            raise CatalogPromotionError(
                "native_catalog_public_status_mismatch")
        if active_id is None and (
            finalized_head is None
            or status["promotion_id"] != finalized_head["promotion_id"]
            or current_digest != status["catalog_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_public_status_mismatch")

    if active_journal is not None:
        phase = active_journal["phase"]
        if phase == "research-published":
            expected_current = {
                active_journal["previous_catalog_sha256"],
                active_journal["catalog_sha256"],
            }
        elif (
            PROMOTION_PHASES.index(phase)
            >= PROMOTION_PHASES.index("host-published")
        ):
            expected_current = {active_journal["catalog_sha256"]}
        else:
            expected_current = {active_journal["previous_catalog_sha256"]}
        if current_digest not in expected_current:
            raise CatalogPromotionError(
                "native_catalog_promotion_catalog_mismatch")
    elif active_id is not None and (
        active_id in receipts or active_id in authorities
    ):
        previous = (
            receipts[active_id]["previous_catalog_sha256"]
            if active_id in receipts else authorities[active_id]["request"][
                "plan"]["previous_catalog_sha256"]
        )
        if current_digest != previous:
            raise CatalogPromotionError(
                "native_catalog_promotion_catalog_mismatch")

    if not active:
        return {
            "state": "ready", "active_promotion_id": None,
            "active_state_sha256": None,
        }
    promotion_id = next(iter(active))
    authority = authorities.get(promotion_id)
    if authority is not None:
        active_state_sha256, _expected_gate = (
            _authority_active_gate_identity(authority))
    else:
        journal = active[promotion_id].get("journal")
        if journal is None:
            raise CatalogPromotionError(
                "native_catalog_active_identity_invalid")
        state_body = {
            "promotion_id": promotion_id,
            "replay_authority_sha256": None,
            "plan_sha256": journal["plan_sha256"],
            "previous_catalog_sha256": journal["previous_catalog_sha256"],
            "catalog_sha256": journal["catalog_sha256"],
            "host_release_id": journal["host_release_id"],
        }
        active_state_sha256 = digest(state_body)
    return {
        "state": "active", "active_promotion_id": promotion_id,
        "active_state_sha256": active_state_sha256,
    }


def _gate_value(body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": PROMOTION_GATE_SCHEMA, **body,
        "gate_sha256": digest(body),
    }


def _recovery_intent(
    gate: Mapping[str, Any], authority: Mapping[str, Any], *, created_at: int,
) -> dict[str, Any]:
    body = {
        "promotion_id": authority["promotion_id"],
        "active_state_sha256": gate["active_state_sha256"],
        "expected_gate_sha256": gate["gate_sha256"],
        "replay_authority_sha256": authority["authority_sha256"],
        "host_release_id": authority["host_release_id"],
        "created_at": created_at,
    }
    return {
        "schema": RECOVERY_INTENT_SCHEMA, **body,
        "intent_sha256": digest(body),
    }


def _validate_recovery_intent(
    value: object, authority: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "promotion_id", "active_state_sha256",
        "expected_gate_sha256",
        "replay_authority_sha256", "host_release_id", "created_at",
        "intent_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CatalogPromotionError("native_catalog_recovery_intent_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "intent_sha256"}
    }
    if (
        value["schema"] != RECOVERY_INTENT_SCHEMA
        or value["promotion_id"] != authority["promotion_id"]
        or value["replay_authority_sha256"]
        != authority["authority_sha256"]
        or value["host_release_id"] != authority["host_release_id"]
        or SHA256.fullmatch(str(value["active_state_sha256"])) is None
        or SHA256.fullmatch(str(value["expected_gate_sha256"])) is None
        or not isinstance(value["created_at"], int)
        or isinstance(value["created_at"], bool)
        or value["created_at"] <= 0
        or value["intent_sha256"] != digest(body)
    ):
        raise CatalogPromotionError("native_catalog_recovery_intent_invalid")
    return value


def _recovery_terminal(
    authority: Mapping[str, Any], receipt: Mapping[str, Any],
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "state": "finalized",
        "promotion_id": authority["promotion_id"],
        "catalog_sha256": authority["catalog_sha256"],
        "host_release_id": authority["host_release_id"],
        "promotion_receipt_sha256": receipt["receipt_sha256"],
        "replay_authority_sha256": authority["authority_sha256"],
        "expected_gate_sha256": intent["expected_gate_sha256"],
        "recovery_intent_sha256": intent["intent_sha256"],
    }
    return {
        "schema": RECOVERY_TERMINAL_SCHEMA, **body,
        "terminal_sha256": digest(body),
    }


def _validate_recovery_terminal(
    value: object, authority: Mapping[str, Any], receipt: Mapping[str, Any],
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    expected = _recovery_terminal(authority, receipt, intent)
    if value != expected:
        raise CatalogPromotionError("native_catalog_recovery_terminal_invalid")
    return expected


def _promotion_state_exists(
    catalog_root: Path, public_status: Path,
) -> bool:
    return os.path.lexists(public_status) or any(
        os.path.lexists(catalog_root / name)
        for name in PROMOTION_STATE_NAMES
    )


def promotion_gate_state(
    host_install_fd: int, *, catalog_root: Path = CATALOG.parent,
    transactions: Path = TRANSACTIONS, public_status: Path = PUBLIC_STATUS,
    host_install_root: Path = HOST_INSTALL_ROOT, trusted_uid: int = 0,
    trusted_gid: int = 0, expected_host_release_id: str | None = None,
    transition_release_id: str | None = None,
) -> dict[str, Any]:
    """Return a content-free, fail-closed catalog-promotion gate."""
    try:
        with inherited_host_authority(
            host_install_fd, host_install_root=host_install_root,
            trusted_uid=trusted_uid, allow_install_transition=True,
            expected_host_release_id=(
                transition_release_id
                if transition_release_id is not None
                else expected_host_release_id),
            allow_missing_current=transition_release_id is not None,
        ) as authority:
            if not _promotion_state_exists(catalog_root, public_status):
                return _gate_value({
                    "state": "ready", "active_promotion_id": None,
                    "active_state_sha256": None,
                })
            manager_lock = _open_trusted_lock(
                transactions / ".lock", trusted_uid=trusted_uid,
                trusted_gid=trusted_gid, create=False)
            promotion_lock = _open_trusted_lock(
                catalog_root / ".promotion.lock", trusted_uid=trusted_uid,
                trusted_gid=trusted_gid, create=False)
            try:
                fcntl.flock(manager_lock, fcntl.LOCK_EX)
                fcntl.flock(promotion_lock, fcntl.LOCK_EX)
                body = _promotion_gate_body_under_lock(
                    catalog_root=catalog_root, public_status=public_status,
                    trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                    expected_host_release_id=authority[0].name)
            finally:
                fcntl.flock(promotion_lock, fcntl.LOCK_UN)
                fcntl.flock(manager_lock, fcntl.LOCK_UN)
                os.close(promotion_lock)
                os.close(manager_lock)
            return _gate_value(body)
    except Exception:
        return _gate_value({
            "state": "invalid", "active_promotion_id": None,
            "active_state_sha256": None,
        })


@contextlib.contextmanager
def promotion_admission(
    host_install_fd: int, *, allow_promotion_id: str | None = None,
    catalog_root: Path = CATALOG.parent, transactions: Path = TRANSACTIONS,
    public_status: Path = PUBLIC_STATUS,
    host_install_root: Path = HOST_INSTALL_ROOT, trusted_uid: int = 0,
    trusted_gid: int = 0,
    expected_host_release_id: str | None = None,
):
    """Hold Host, manager, and promotion locks through one admitted action."""
    if (
        allow_promotion_id is not None
        and promotion_authority.UUID4.fullmatch(allow_promotion_id) is None
    ):
        raise CatalogPromotionError("native_catalog_promotion_id_invalid")
    with inherited_host_authority(
        host_install_fd, host_install_root=host_install_root,
        trusted_uid=trusted_uid,
        expected_host_release_id=expected_host_release_id,
        allow_install_transition=False,
    ) as authority:
        if (
            allow_promotion_id is None
            and not _promotion_state_exists(catalog_root, public_status)
        ):
            ready = {
                "state": "ready", "active_promotion_id": None,
                "active_state_sha256": None,
            }
            manager_lock: int | None = None
            try:
                if os.path.lexists(transactions):
                    manager_lock = _open_trusted_lock(
                        transactions / ".lock", trusted_uid=trusted_uid,
                        trusted_gid=trusted_gid, create=False)
                    fcntl.flock(manager_lock, fcntl.LOCK_EX)
                yield authority, ready
            finally:
                if manager_lock is not None:
                    fcntl.flock(manager_lock, fcntl.LOCK_UN)
                    os.close(manager_lock)
            return
        manager_lock = _open_trusted_lock(
            transactions / ".lock", trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        promotion_lock = _open_trusted_lock(
            catalog_root / ".promotion.lock", trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        try:
            fcntl.flock(manager_lock, fcntl.LOCK_EX)
            fcntl.flock(promotion_lock, fcntl.LOCK_EX)
            for directory in (
                catalog_root / "promotion-replay-authorities",
                catalog_root / "promotion-receipts",
                catalog_root / "promotion-staging",
                catalog_root / "promotion-journals",
            ):
                _trusted_root_directory(
                    directory, create=True, trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid)
            body = _promotion_gate_body_under_lock(
                catalog_root=catalog_root, public_status=public_status,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                expected_host_release_id=authority[0].name)
            if body["state"] == "active" and (
                allow_promotion_id is None
                or body["active_promotion_id"] != allow_promotion_id
            ):
                raise CatalogPromotionError(
                    "native_catalog_promotion_active")
            yield authority, body
        finally:
            fcntl.flock(promotion_lock, fcntl.LOCK_UN)
            fcntl.flock(manager_lock, fcntl.LOCK_UN)
            os.close(promotion_lock)
            os.close(manager_lock)


def require_deployment_gate_ready(
    selected_release: Path, host_install_fd: int, *,
    state_root: Path = DEPLOYMENT_STATE_ROOT,
    host_install_root: Path = HOST_INSTALL_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    manifest_raw = _trusted_release_file(
        selected_release / "manifest.json", expected_uid=trusted_uid,
        expected_mode=0o444, maximum=2 * 1024 * 1024)
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError(
            "native_catalog_host_manifest_invalid") from error
    payloads = manifest.get("payloads") if isinstance(manifest, dict) else None
    if (
        not isinstance(payloads, dict)
        or manifest.get("schema")
        != "secure-sandbox-host-controller-release-v1"
        or manifest.get("release_id") != selected_release.name
        or _release_identity(payloads) != selected_release.name
        or "native_stack_deployer" not in payloads
        or SHA256.fullmatch(str(payloads["native_stack_deployer"])) is None
    ):
        raise CatalogPromotionError("native_catalog_host_manifest_invalid")
    source = _trusted_release_file(
        selected_release / "native_stack_deployer",
        expected_uid=trusted_uid, expected_mode=0o755)
    if hashlib.sha256(source).hexdigest() != payloads["native_stack_deployer"]:
        raise CatalogPromotionError(
            "native_catalog_deployment_gate_identity_invalid")
    try:
        code = compile(
            source, str(selected_release / "native_stack_deployer"),
            "exec", dont_inherit=True, optimize=0)
        module = types.ModuleType("_native_catalog_deployment_gate")
        module.__file__ = str(selected_release / "native_stack_deployer")
        module.__package__ = None
        exec(code, module.__dict__)
        value = module.deployment_gate_state(
            host_install_fd, state_root=state_root,
            host_install_root=host_install_root,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    except Exception as error:
        raise CatalogPromotionError(
            "native_catalog_deployment_gate_invalid") from error
    fields = {
        "schema", "state", "active_journal_sha256", "gate_sha256",
    }
    state = value.get("state") if isinstance(value, dict) else None
    active = (
        value.get("active_journal_sha256")
        if isinstance(value, dict) else None
    )
    body = {"state": state, "active_journal_sha256": active}
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema") != DEPLOYMENT_GATE_SCHEMA
        or state not in {"ready", "active", "invalid"}
        or (state == "active")
        != (isinstance(active, str) and SHA256.fullmatch(active) is not None)
        or state != "active" and active is not None
        or value.get("gate_sha256") != digest(body)
    ):
        raise CatalogPromotionError(
            "native_catalog_deployment_gate_invalid")
    if state == "active":
        raise CatalogPromotionError("native_catalog_deployment_active")
    if state != "ready":
        raise CatalogPromotionError("native_catalog_deployment_gate_invalid")
    return value


def promote(
    source: Path | None,
    *,
    request: Mapping[str, Any],
    host_install_fd: int,
    target: Path = CATALOG,
    transactions: Path = TRANSACTIONS,
    authorization_receipts: Path = AUTHORIZATION_RECEIPTS,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
    expected_euid: int = 0,
    expected_host_release_id: str | None = None,
    host_install_root: Path = HOST_INSTALL_ROOT,
    deployment_state_root: Path = DEPLOYMENT_STATE_ROOT,
    public_status: Path = PUBLIC_STATUS,
    now: int | None = None,
    idle_verifier: Callable[[Mapping[str, Any]], dict[str, Any]] = (
        require_guest_idle
    ),
    guest_publisher: Callable[
        [Mapping[str, Any], Mapping[str, Any]], dict[str, Any]
    ] = publish_guest_catalog,
    guest_readback: Callable[[Mapping[str, Any]], dict[str, Any]] = (
        readback_guest_catalog
    ),
    lifecycle_releaser: Callable[[Mapping[str, Any]], dict[str, Any]] = (
        release_guest_lifecycle
    ),
    deployment_gate_verifier: Callable[..., dict[str, Any]] = (
        require_deployment_gate_ready
    ),
    replay_only: bool = False,
    crash_hook: Callable[[str], None] = lambda _phase: None,
) -> dict[str, Any]:
    if os.geteuid() != expected_euid:
        raise CatalogPromotionError("native_catalog_root_required")
    observed_now = int(time.time()) if now is None else now
    try:
        untrusted_plan = request.get("plan") if isinstance(request, Mapping) else None
        promotion_id = untrusted_plan.get("promotion_id") if isinstance(untrusted_plan, Mapping) else None
        if not isinstance(promotion_id, str) or promotion_authority.UUID4.fullmatch(promotion_id) is None:
            raise CatalogPromotionError("native_catalog_promotion_request_invalid")
        expected_release = (
            Path(__file__).resolve().parent.name
            if expected_host_release_id is None
            else expected_host_release_id
        )
        if SHA256.fullmatch(expected_release) is None:
            raise CatalogPromotionError("native_catalog_host_release_invalid")
        plan, authorization = promotion_authority.validate_request(
            request,
            now=observed_now,
            require_fresh=False,
            expected_host_release_id=expected_release,
        )
        if plan["catalog_sha256"] == plan["previous_catalog_sha256"]:
            raise CatalogPromotionError("native_catalog_noop_forbidden")
    except promotion_authority.NativeStackCatalogPromotionError as error:
        raise CatalogPromotionError("native_catalog_promotion_request_invalid") from error
    root = target.parent
    authorities = root / "promotion-replay-authorities"
    receipts = root / "promotion-receipts"
    staging = root / "promotion-staging"
    journals = root / "promotion-journals"
    authority_path = authorities / f"{plan['promotion_id']}.json"
    receipt_path = receipts / f"{plan['promotion_id']}.json"
    stage_path = staging / f"{plan['promotion_id']}.json"
    journal_path = journals / f"{plan['promotion_id']}.json"
    admission = promotion_admission(
        host_install_fd,
        allow_promotion_id=plan["promotion_id"],
        catalog_root=root, transactions=transactions,
        public_status=public_status, host_install_root=host_install_root,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        expected_host_release_id=expected_release,
    )
    host_authority, _promotion_gate = admission.__enter__()
    try:
        selected_release, inherited_host_fd = host_authority
        try:
            preexisting_journal = _validate_promotion_journal_record(
                _trusted_json(journal_path, expected_uid=trusted_uid))
        except CatalogPromotionError as error:
            if "unavailable" not in str(error):
                raise
            preexisting_journal = None
        if preexisting_journal is not None and (
            preexisting_journal["phase"] == "finalized"
            or preexisting_journal["schema"]
                == LEGACY_PROMOTION_JOURNAL_SCHEMA
            and preexisting_journal["phase"] == "committed"
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_already_finalized")
        deployment_gate_verifier(
            selected_release, inherited_host_fd,
            state_root=deployment_state_root,
            host_install_root=host_install_root,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        )
        require_idle_transactions(transactions, trusted_uid=trusted_uid)

        replay_authority = None
        try:
            replay_authority = _trusted_json(
                authority_path, expected_uid=trusted_uid)
        except CatalogPromotionError as error:
            if "unavailable" not in str(error):
                raise
        if replay_authority is not None and not replay_only:
            raise CatalogPromotionError(
                "native_catalog_recovery_required")
        if replay_authority is None:
            if replay_only or source is None:
                raise CatalogPromotionError(
                    "native_catalog_replay_authority_missing")
            try:
                promotion_authority.validate_request(
                    request, now=observed_now, require_fresh=True,
                    expected_host_release_id=expected_release,
                )
            except promotion_authority.NativeStackCatalogPromotionError as error:
                raise CatalogPromotionError(
                    "native_catalog_authorization_expired") from error
            verify_pending_authorization_receipt(
                authorization, plan, receipt_root=authorization_receipts,
                trusted_uid=trusted_uid)
            catalog, raw = read_operator_catalog(
                source, expected_uid=plan["source_uid"],
                expected_sha256=plan["source_sha256"])
            if plan["catalog_sha256"] == plan["previous_catalog_sha256"]:
                raise CatalogPromotionError("native_catalog_noop_forbidden")
            replay_authority = _replay_authority(
                request, catalog, created_at=observed_now)
            crash_hook("before-replay-authority-publication")
            _create_root_file_exclusive(
                authority_path, canonical(replay_authority),
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
            crash_hook("replay-authority-published")
        authority_plan, authority_authorization, catalog = (
            _validate_replay_authority(
                replay_authority,
                expected_host_release_id=expected_release)
        )
        if (
            digest(request) != replay_authority["request_sha256"]
            or authority_plan != plan
            or authority_authorization != authorization
        ):
            raise CatalogPromotionError(
                "native_catalog_replay_authority_mismatch")
        plan, authorization = authority_plan, authority_authorization
        raw = native_vendor_stack.canonical_bytes(catalog)
        prior = current_catalog_digest(target)
        existing_receipt = None
        try:
            existing_receipt = _validate_promotion_receipt(
                _trusted_json(receipt_path, expected_uid=trusted_uid),
                plan,
                authorization,
            )
        except FileNotFoundError:
            existing_receipt = None
        except CatalogPromotionError as error:
            if "unavailable" not in str(error):
                raise
            existing_receipt = None

        already_published = (
            existing_receipt is not None and prior == plan["catalog_sha256"]
        )
        if not already_published and prior != plan["previous_catalog_sha256"]:
            raise CatalogPromotionError("native_catalog_previous_digest_mismatch")

        if existing_receipt is None:
            try:
                _create_root_file_exclusive(
                    stage_path,
                    raw,
                    trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid,
                )
            except FileExistsError:
                staged = _trusted_json(stage_path, expected_uid=trusted_uid)
                if canonical(staged) != raw:
                    raise CatalogPromotionError("native_catalog_staging_collision")
            crash_hook("staged")
        elif not already_published:
            staged = _trusted_json(stage_path, expected_uid=trusted_uid)
            if canonical(staged) != raw:
                raise CatalogPromotionError(
                    "native_catalog_replay_staging_invalid")

        receipt = existing_receipt or _promotion_receipt(
            plan, authorization, promoted_at=observed_now
        )
        if existing_receipt is None:
            try:
                _create_root_file_exclusive(
                    receipt_path,
                    canonical(receipt),
                    trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid,
                )
            except FileExistsError as error:
                raise CatalogPromotionError("native_catalog_promotion_replay_collision") from error
        crash_hook("receipted")

        journal: dict[str, Any]
        try:
            journal = _validate_promotion_journal(
                _trusted_json(journal_path, expected_uid=trusted_uid),
                plan,
                authorization,
                receipt,
                replay_authority["authority_sha256"],
            )
        except CatalogPromotionError as error:
            if "unavailable" not in str(error):
                raise
            journal = _new_promotion_journal(
                plan, authorization, receipt,
                replay_authority["authority_sha256"],
                updated_at=observed_now)
            try:
                _create_root_file_exclusive(
                    journal_path,
                    canonical(journal),
                    trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid,
                )
            except FileExistsError:
                journal = _validate_promotion_journal(
                    _trusted_json(journal_path, expected_uid=trusted_uid),
                    plan,
                    authorization,
                    receipt,
                    replay_authority["authority_sha256"],
                )
        crash_hook("journal-authorized")
        if journal["phase"] == "finalized":
            return receipt

        # Research creates a durable fence under the same lock checked by all
        # native login/run admission. Any ambiguity intentionally leaves that
        # fence closed; exact replay may finish the same promotion later.
        crash_hook("before-fence-acquire")
        idle = idle_verifier(plan)
        if not isinstance(idle, dict):
            raise CatalogPromotionError("native_catalog_guest_idle_invalid")
        crash_hook("after-fence-acquire")
        require_idle_transactions(transactions, trusted_uid=trusted_uid)
        host_observed = current_catalog_digest(target)
        research_observed = idle["observed_catalog_sha256"]
        require_cross_plane_generation(
            plan, host_observed=host_observed,
            research_observed=research_observed)
        phase_index = PROMOTION_PHASES.index(journal["phase"])
        if (
            phase_index >= PROMOTION_PHASES.index("research-published")
            and research_observed != plan["catalog_sha256"]
        ) or (
            phase_index >= PROMOTION_PHASES.index("host-published")
            and host_observed != plan["catalog_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_state_mismatch")
        if (
            phase_index >= PROMOTION_PHASES.index("research-fenced")
            and idle["fence_sha256"] != journal["research_fence_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_evidence_mismatch")
        journal = _advance_promotion_journal(
            journal,
            phase="research-fenced",
            updated_at=observed_now,
            evidence={
                "research_observed_catalog_sha256": research_observed,
                "research_fence_sha256": idle["fence_sha256"],
                "research_idle_evidence_sha256": idle["evidence_sha256"],
            },
            path=journal_path,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        crash_hook("journal-research-fenced")

        crash_hook("before-research-catalog-publication")
        research_publication = guest_publisher(plan, catalog)
        if (
            not isinstance(research_publication, dict)
            or research_publication["fence_sha256"]
            != idle["fence_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_guest_publication_invalid")
        journal_phase = journal["phase"]
        if research_publication["publication_phase"] == "released" and (
            journal_phase not in {"cross-plane-verified", "committed"}
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_evidence_mismatch")
        if research_publication["publication_phase"] == "published" and (
            journal_phase == "committed"
            or (
                PROMOTION_PHASES.index(journal_phase)
                >= PROMOTION_PHASES.index("research-published")
                and research_publication["publication_evidence_sha256"]
                != journal["research_publication_evidence_sha256"]
            )
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_evidence_mismatch")
        if journal_phase == "committed" and (
            research_publication["publication_evidence_sha256"]
            != journal["research_terminal_evidence_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_evidence_mismatch")
        crash_hook("after-research-catalog-publication")
        journal = _advance_promotion_journal(
            journal,
            phase="research-published",
            updated_at=observed_now,
            evidence={
                "research_publication_evidence_sha256": (
                    research_publication["publication_evidence_sha256"]
                ),
            },
            path=journal_path,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        crash_hook("journal-research-published")

        if host_observed == plan["previous_catalog_sha256"]:
            crash_hook("before-host-catalog-publication")
            _atomic_root_file(
                target,
                raw,
                trusted_uid=trusted_uid,
                trusted_gid=trusted_gid,
            )
            crash_hook("after-host-catalog-publication")
        crash_hook("before-host-catalog-readback")
        host_observed = current_catalog_digest(target)
        if host_observed != plan["catalog_sha256"]:
            raise CatalogPromotionError("native_catalog_publication_readback_failed")
        crash_hook("after-host-catalog-readback")
        journal = _advance_promotion_journal(
            journal,
            phase="host-published",
            updated_at=observed_now,
            evidence={"host_observed_catalog_sha256": host_observed},
            path=journal_path,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        crash_hook("journal-host-published")

        crash_hook("before-research-catalog-readback")
        research_readback = guest_readback(plan)
        if (
            not isinstance(research_readback, dict)
            or research_readback["fence_sha256"] != idle["fence_sha256"]
            or research_readback["publication_evidence_sha256"]
            != research_publication["publication_evidence_sha256"]
            or research_readback["publication_phase"]
            != research_publication["publication_phase"]
        ):
            raise CatalogPromotionError("native_catalog_guest_readback_invalid")
        if (
            journal["phase"] == "committed"
            and research_readback["publication_evidence_sha256"]
            != journal["research_terminal_evidence_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_evidence_mismatch")
        crash_hook("after-research-catalog-readback")
        journal = _advance_promotion_journal(
            journal,
            phase="cross-plane-verified",
            updated_at=observed_now,
            evidence={
                "research_readback_evidence_sha256": research_readback[
                    "evidence_sha256"
                ],
            },
            path=journal_path,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        crash_hook("journal-cross-plane-verified")

        crash_hook("before-fence-release")
        released = lifecycle_releaser(plan)
        if not isinstance(released, dict):
            raise CatalogPromotionError("native_catalog_guest_release_invalid")
        if journal["phase"] == "committed" and (
            released["evidence_sha256"]
            != journal["research_release_evidence_sha256"]
            or released["publication_evidence_sha256"]
            != journal["research_terminal_evidence_sha256"]
        ):
            raise CatalogPromotionError(
                "native_catalog_promotion_journal_evidence_mismatch")
        crash_hook("after-fence-release")
        journal = _advance_promotion_journal(
            journal,
            phase="committed",
            updated_at=observed_now,
            evidence={
                "research_release_evidence_sha256": released[
                    "evidence_sha256"
                ],
                "research_terminal_evidence_sha256": released[
                    "publication_evidence_sha256"
                ],
            },
            path=journal_path,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        crash_hook("journal-committed")
        status = publish_public_status(
            catalog=catalog,
            catalog_sha256=plan["catalog_sha256"],
            host_release_id=plan["host_release_id"],
            receipt=receipt,
            published_at=observed_now,
            path=public_status,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        crash_hook("public-status-published")
        readback_status = _validate_public_status_record(_trusted_json(
            public_status, expected_uid=trusted_uid, expected_mode=0o644))
        if readback_status != status:
            raise CatalogPromotionError(
                "native_catalog_public_status_readback_failed")
        crash_hook("public-status-readback")
        try:
            stage_path.unlink()
            directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except FileNotFoundError:
            pass
        crash_hook("staging-cleaned")
        journal = _advance_promotion_journal(
            journal,
            phase="finalized",
            updated_at=observed_now,
            evidence={
                "public_status_sha256": hashlib.sha256(
                    canonical(readback_status)).hexdigest(),
            },
            path=journal_path,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        )
        crash_hook("journal-finalized")
        return receipt
    finally:
        admission.__exit__(*sys.exc_info())


def recover_active(
    host_install_fd: int, *, target: Path = CATALOG,
    transactions: Path = TRANSACTIONS,
    authorization_receipts: Path = AUTHORIZATION_RECEIPTS,
    host_install_root: Path = HOST_INSTALL_ROOT,
    deployment_state_root: Path = DEPLOYMENT_STATE_ROOT,
    public_status: Path = PUBLIC_STATUS, trusted_uid: int = 0,
    trusted_gid: int = 0, expected_euid: int = 0,
    expected_host_release_id: str | None = None,
    **promote_overrides: Any,
) -> dict[str, Any]:
    """Manually finish the sole durable promotion; accept no caller data."""
    if os.geteuid() != expected_euid:
        raise CatalogPromotionError("native_catalog_root_required")
    gate = promotion_gate_state(
        host_install_fd, catalog_root=target.parent,
        transactions=transactions, public_status=public_status,
        host_install_root=host_install_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
        expected_host_release_id=expected_host_release_id)
    expected_release = (
        HERE.name if expected_host_release_id is None
        else expected_host_release_id
    )
    crash_hook = promote_overrides.get(
        "crash_hook", lambda _phase: None)
    promotion_id = gate.get("active_promotion_id")
    if gate.get("state") == "ready":
        status = _validate_public_status_record(_trusted_json(
            public_status, expected_uid=trusted_uid, expected_mode=0o644))
        promotion_id = status["promotion_id"]
    elif (
        gate.get("state") != "active"
        or not isinstance(promotion_id, str)
        or promotion_authority.UUID4.fullmatch(promotion_id) is None
    ):
        raise CatalogPromotionError(
            "native_catalog_recovery_active_unavailable")
    assert isinstance(promotion_id, str)
    authority_path = (
        target.parent / "promotion-replay-authorities"
        / f"{promotion_id}.json"
    )
    authority = _trusted_json(authority_path, expected_uid=trusted_uid)
    plan, _authorization, _catalog = _validate_replay_authority(
        authority, expected_host_release_id=(
            expected_release if gate["state"] == "active" else None))
    if plan["promotion_id"] != promotion_id:
        raise CatalogPromotionError(
            "native_catalog_replay_authority_mismatch")
    intent_path = (
        target.parent / "promotion-recovery-intents"
        / f"{promotion_id}.json"
    )
    if gate["state"] == "active":
        intent = _recovery_intent(
            gate=gate, authority=authority,
            created_at=(
                int(time.time()) if "now" not in promote_overrides
                else int(promote_overrides["now"])),
        )
        crash_hook("before-recovery-intent-publication")
        try:
            _create_root_file_exclusive(
                intent_path, canonical(intent), trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
        except FileExistsError:
            intent = _validate_recovery_intent(
                _trusted_json(intent_path, expected_uid=trusted_uid),
                authority)
        crash_hook("recovery-intent-published")
        receipt = promote(
            None, request=authority["request"],
            host_install_fd=host_install_fd, target=target,
            transactions=transactions,
            authorization_receipts=authorization_receipts,
            trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            expected_euid=expected_euid,
            expected_host_release_id=expected_release,
            host_install_root=host_install_root,
            deployment_state_root=deployment_state_root,
            public_status=public_status, replay_only=True,
            **promote_overrides,
        )
    else:
        intent = _validate_recovery_intent(
            _trusted_json(intent_path, expected_uid=trusted_uid), authority)
        receipt = _validate_promotion_receipt_record(_trusted_json(
            target.parent / "promotion-receipts" / f"{promotion_id}.json",
            expected_uid=trusted_uid))
    terminal_gate = promotion_gate_state(
        host_install_fd, catalog_root=target.parent,
        transactions=transactions, public_status=public_status,
        host_install_root=host_install_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
        expected_host_release_id=expected_release)
    if terminal_gate.get("state") != "ready":
        raise CatalogPromotionError(
            "native_catalog_recovery_terminal_unverified")
    terminal = _recovery_terminal(authority, receipt, intent)
    terminal_path = (
        target.parent / "promotion-recovery-terminals"
        / f"{promotion_id}.json"
    )
    crash_hook("before-recovery-terminal-publication")
    try:
        _create_root_file_exclusive(
            terminal_path, canonical(terminal), trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
    except FileExistsError:
        terminal = _validate_recovery_terminal(
            _trusted_json(terminal_path, expected_uid=trusted_uid),
            authority, receipt, intent)
    crash_hook("recovery-terminal-published")
    return terminal


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-install-fd", type=int, default=-1)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--source", type=Path, required=True)
    plan_parser.add_argument("--source-uid", type=int, required=True)
    plan_parser.add_argument("--previous-catalog-sha256")
    plan_parser.add_argument("--host-release-id", required=True)
    consume_parser = subparsers.add_parser("consume")
    consume_parser.add_argument("--source", type=Path, required=True)
    consume_parser.add_argument("--request-json", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("gate-status")
    subparsers.add_parser("recover-active")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            _catalog, raw = read_operator_catalog(
                args.source,
                expected_uid=args.source_uid,
                expected_sha256=None,
            )
            value = promotion_authority.make_plan(
                source_uid=args.source_uid,
                source_sha256=hashlib.sha256(raw).hexdigest(),
                previous_catalog_sha256=args.previous_catalog_sha256,
                host_release_id=args.host_release_id,
            )
            if (
                value["catalog_sha256"]
                == value["previous_catalog_sha256"]
            ):
                raise CatalogPromotionError("native_catalog_noop_forbidden")
        elif args.command == "consume":
            raw = args.request_json.encode("ascii")
            if not 2 <= len(raw) <= promotion_authority.MAX_BYTES:
                raise CatalogPromotionError("native_catalog_promotion_request_invalid")
            request = json.loads(raw)
            if raw + b"\n" != canonical(request):
                raise CatalogPromotionError("native_catalog_promotion_request_not_canonical")
            value = promote(
                args.source,
                request=request,
                host_install_fd=args.host_install_fd,
            )
        elif args.command == "gate-status":
            value = promotion_gate_state(args.host_install_fd)
        elif args.command == "recover-active":
            value = recover_active(args.host_install_fd)
        else:
            value = _trusted_json(
                PUBLIC_STATUS, expected_uid=0, expected_mode=0o644
            )
    except (
        CatalogPromotionError,
        promotion_authority.NativeStackCatalogPromotionError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        print(str(error), file=__import__("sys").stderr)
        return 1
    __import__("sys").stdout.buffer.write(canonical(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
