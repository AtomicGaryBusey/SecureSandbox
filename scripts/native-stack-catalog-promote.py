#!/usr/bin/env python3
"""Promote an inert operator native-stack catalog into protected Host state.

Promotion never authenticates, opens egress, activates a model, or starts a
harness. It copies one already reviewed canonical catalog into a root-owned
location used by the protected manager. An immutable authorization receipt is
durably published before the atomic catalog replacement, so a crash cannot
leave an unreceipted protected identity active.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parents[1]
if (ROOT / "shared/native_vendor_stack.py").is_file():
    import sys
    sys.path.insert(0, str(ROOT))

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
MAX_TRANSACTION_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
TERMINAL_PHASES = {"committed", "rejected", "recovered-fenced"}


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


def _validate_promotion_receipt(
    value: object,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
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
        or value["promotion_id"] != plan["promotion_id"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or value["authorization_sha256"] != authorization["authorization_sha256"]
        or value["authorization_receipt_sha256"]
        != authorization["pending_receipt_sha256"]
        or value["source_sha256"] != plan["source_sha256"]
        or value["previous_catalog_sha256"] != plan["previous_catalog_sha256"]
        or value["catalog_sha256"] != plan["catalog_sha256"]
        or value["host_release_id"] != plan["host_release_id"]
        or not isinstance(value["promoted_at"], int)
        or value["status"] != "authorized-for-publication"
        or value["receipt_sha256"] != digest(body)
    ):
        raise CatalogPromotionError("native_catalog_promotion_receipt_invalid")
    return value


def require_guest_idle(
    plan: Mapping[str, Any],
    *,
    control_client: Path | None = None,
    ssh_config: Path | None = None,
) -> str:
    release = Path(__file__).resolve().parent
    client = release / "control_client" if control_client is None else control_client
    config = release / "ssh_config" if ssh_config is None else ssh_config
    body = {
        "promotion_id": plan["promotion_id"],
        "plan_sha256": plan["plan_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
    }
    request = {
        "schema": "secure-sandbox-native-stack-lifecycle-idle-request-v1",
        **body,
        "request_sha256": digest(body),
    }
    try:
        result = subprocess.run(
            [
                str(client), "client", "--ssh-config", str(config),
                "--timeout-seconds", "120", "sandbox-research-control", "pipe",
                "native-stack-lifecycle-idle",
            ],
            input=canonical(request),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=150,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CatalogPromotionError("native_catalog_guest_idle_unavailable") from error
    try:
        reply = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError("native_catalog_guest_idle_invalid") from error
    if (
        result.returncode != 0
        or not isinstance(reply, dict)
        or result.stdout != canonical(reply)
        or set(reply)
        != {"schema", "state", "live_run_count", "evidence_sha256"}
        or reply["schema"] != "secure-sandbox-native-stack-lifecycle-idle-reply-v1"
        or reply["state"] != "idle"
        or reply["live_run_count"] != 0
        or not isinstance(reply["evidence_sha256"], str)
        or SHA256.fullmatch(reply["evidence_sha256"]) is None
    ):
        raise CatalogPromotionError("native_catalog_guest_not_idle")
    return reply["evidence_sha256"]


def release_guest_lifecycle(
    plan: Mapping[str, Any],
    *,
    control_client: Path | None = None,
    ssh_config: Path | None = None,
) -> str:
    """Release only the exact durable Research promotion fence."""
    release = Path(__file__).resolve().parent
    client = release / "control_client" if control_client is None else control_client
    config = release / "ssh_config" if ssh_config is None else ssh_config
    body = {
        "promotion_id": plan["promotion_id"],
        "plan_sha256": plan["plan_sha256"],
        "catalog_sha256": plan["catalog_sha256"],
    }
    request = {
        "schema": "secure-sandbox-native-stack-lifecycle-release-request-v1",
        **body,
        "request_sha256": digest(body),
    }
    try:
        result = subprocess.run(
            [
                str(client), "client", "--ssh-config", str(config),
                "--timeout-seconds", "120", "sandbox-research-control", "pipe",
                "native-stack-lifecycle-release",
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
            "native_catalog_guest_release_unavailable"
        ) from error
    try:
        reply = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogPromotionError("native_catalog_guest_release_invalid") from error
    if (
        result.returncode != 0
        or not isinstance(reply, dict)
        or result.stdout != canonical(reply)
        or set(reply)
        != {"schema", "state", "catalog_sha256", "evidence_sha256"}
        or reply["schema"]
        != "secure-sandbox-native-stack-lifecycle-release-reply-v1"
        or reply["state"] != "released"
        or reply["catalog_sha256"] != plan["catalog_sha256"]
        or not isinstance(reply["evidence_sha256"], str)
        or SHA256.fullmatch(reply["evidence_sha256"]) is None
    ):
        raise CatalogPromotionError("native_catalog_guest_release_invalid")
    return reply["evidence_sha256"]


def _open_trusted_lock(
    path: Path, *, trusted_uid: int = 0, trusted_gid: int = 0
) -> int:
    _trusted_root_directory(
        path.parent, create=True, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    try:
        descriptor = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
    except FileExistsError:
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


def promote(
    source: Path,
    *,
    request: Mapping[str, Any],
    target: Path = CATALOG,
    transactions: Path = TRANSACTIONS,
    authorization_receipts: Path = AUTHORIZATION_RECEIPTS,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
    expected_euid: int = 0,
    expected_host_release_id: str | None = None,
    public_status: Path = PUBLIC_STATUS,
    now: int | None = None,
    idle_verifier: Callable[[Mapping[str, Any]], str] = require_guest_idle,
    lifecycle_releaser: Callable[[Mapping[str, Any]], str] = (
        release_guest_lifecycle
    ),
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
    except promotion_authority.NativeStackCatalogPromotionError as error:
        raise CatalogPromotionError("native_catalog_promotion_request_invalid") from error
    root = target.parent
    _trusted_root_directory(
        root, create=True, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    receipts = root / "promotion-receipts"
    staging = root / "promotion-staging"
    _trusted_root_directory(
        receipts, create=True, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    _trusted_root_directory(
        staging, create=True, trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    receipt_path = receipts / f"{plan['promotion_id']}.json"
    stage_path = staging / f"{plan['promotion_id']}.json"
    manager_lock = _open_trusted_lock(
        transactions / ".lock", trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    lock = _open_trusted_lock(
        root / ".promotion.lock", trusted_uid=trusted_uid, trusted_gid=trusted_gid
    )
    try:
        fcntl.flock(manager_lock, fcntl.LOCK_EX)
        fcntl.flock(lock, fcntl.LOCK_EX)
        require_idle_transactions(transactions, trusted_uid=trusted_uid)
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
                promotion_authority.validate_request(
                    request,
                    now=observed_now,
                    require_fresh=True,
                    expected_host_release_id=expected_release,
                )
            except promotion_authority.NativeStackCatalogPromotionError as error:
                raise CatalogPromotionError("native_catalog_authorization_expired") from error
            verify_pending_authorization_receipt(
                authorization,
                plan,
                receipt_root=authorization_receipts,
                trusted_uid=trusted_uid,
            )
            catalog, raw = read_operator_catalog(
                source,
                expected_uid=plan["source_uid"],
                expected_sha256=plan["source_sha256"],
            )
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
            try:
                catalog = native_vendor_stack.validate_catalog(
                    _trusted_json(stage_path, expected_uid=trusted_uid)
                )
            except (CatalogPromotionError, native_vendor_stack.NativeVendorStackError) as error:
                raise CatalogPromotionError("native_catalog_replay_staging_unavailable") from error
            raw = native_vendor_stack.canonical_bytes(catalog)
            if hashlib.sha256(raw).hexdigest() != plan["catalog_sha256"]:
                raise CatalogPromotionError("native_catalog_replay_staging_invalid")
        else:
            try:
                catalog = native_vendor_stack.load_catalog(target, private=True)
            except native_vendor_stack.NativeVendorStackError as error:
                raise CatalogPromotionError(
                    "native_catalog_publication_readback_failed"
                ) from error
            raw = native_vendor_stack.canonical_bytes(catalog)

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

        # Research creates a durable fence under the same lock checked by all
        # native login/run admission. Any ambiguity intentionally leaves that
        # fence closed; exact replay may finish the same promotion later.
        crash_hook("before-fence-acquire")
        idle_evidence = idle_verifier(plan)
        if SHA256.fullmatch(str(idle_evidence)) is None:
            raise CatalogPromotionError("native_catalog_guest_idle_invalid")
        crash_hook("after-fence-acquire")
        require_idle_transactions(transactions, trusted_uid=trusted_uid)

        if not already_published:
            crash_hook("before-catalog-publication")
            _atomic_root_file(
                target,
                raw,
                trusted_uid=trusted_uid,
                trusted_gid=trusted_gid,
            )
            crash_hook("after-catalog-publication")
        crash_hook("before-catalog-readback")
        if current_catalog_digest(target) != plan["catalog_sha256"]:
            raise CatalogPromotionError("native_catalog_publication_readback_failed")
        crash_hook("after-catalog-readback")

        crash_hook("before-fence-release")
        release_evidence = lifecycle_releaser(plan)
        if SHA256.fullmatch(str(release_evidence)) is None:
            raise CatalogPromotionError("native_catalog_guest_release_invalid")
        crash_hook("after-fence-release")
        publish_public_status(
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
        try:
            stage_path.unlink()
            directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except FileNotFoundError:
            pass
        return receipt
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        fcntl.flock(manager_lock, fcntl.LOCK_UN)
        os.close(lock)
        os.close(manager_lock)


def main() -> int:
    parser = argparse.ArgumentParser()
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
            )
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
