#!/usr/bin/env python3
"""One-time restore plans and detached, journaled restore execution."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:
    import control_center_backup_operation as base
    import control_center_restore as restore
except ModuleNotFoundError:
    from scripts import control_center_backup_operation as base
    from scripts import control_center_restore as restore

backup = base.backup
SCHEMA = "secure-sandbox-control-center-restore-plan-v1"
STATUS_SCHEMA = "secure-sandbox-control-center-restore-status-v1"
RETIREMENT_STATUS_SCHEMA = "secure-sandbox-control-center-restore-retirement-status-v1"
LIFETIME = 15 * 60
MAX_RETIREMENT_ENTRIES = 100_000


class RestoreOperationError(RuntimeError):
    pass


RESTORE_PROFILE_MINIMUM_VALIDITY = datetime.timedelta(hours=52)


def default_root() -> Path:
    return Path.home() / "Library/Application Support/SecureSandbox/restore-operations"


def create_plan(root: Path, source: Path, generation_id: str, volume_uuid: str,
                manifest_hmac: str, current_identities: dict, file_count: int,
                logical_bytes: int, key: bytes, *, now: int | None = None,
                restore_id: str | None = None) -> dict:
    base.trusted_root(root)
    restore_id = restore_id or str(uuid.uuid4())
    now = int(time.time()) if now is None else now
    if (base.UUID.fullmatch(restore_id) is None or base.UUID.fullmatch(generation_id) is None
            or base.UUID.fullmatch(volume_uuid.lower()) is None or not source.is_absolute()
            or re.fullmatch(r"[0-9a-f]{64}", manifest_hmac) is None
            or set(current_identities) != set(backup.NAMES)
            or not isinstance(file_count, int) or file_count < 1
            or not isinstance(logical_bytes, int) or logical_bytes < 1
            or len(key) < 32):
        raise RestoreOperationError("restore_plan_invalid")
    body = {"schema": SCHEMA, "restore_id": restore_id, "source": str(source),
            "generation_id": generation_id, "volume_uuid": volume_uuid,
            "manifest_hmac_sha256": manifest_hmac,
            "current_identities": current_identities,
            "file_count": file_count, "logical_bytes": logical_bytes,
            "created_unix": now, "expires_unix": now + LIFETIME}
    value = {**body, "plan_hmac_sha256": hmac.new(key, backup.canonical(body), hashlib.sha256).hexdigest()}
    base.write_exclusive(root / f"{restore_id}.json", backup.canonical(value))
    return value


def load_plan(root: Path, restore_id: str, key: bytes, *, allow_expired: bool = False) -> dict:
    if base.UUID.fullmatch(restore_id) is None or len(key) < 32:
        raise RestoreOperationError("restore_plan_invalid")
    base.trusted_root(root)
    try:
        value = json.loads(base.read_exact(root / f"{restore_id}.json", base.MAX_PLAN_BYTES))
    except FileNotFoundError as error:
        raise RestoreOperationError("restore_plan_not_found") from error
    if (not isinstance(value, dict) or value.get("schema") != SCHEMA
            or value.get("restore_id") != restore_id
            or not isinstance(value.get("plan_hmac_sha256"), str)):
        raise RestoreOperationError("restore_plan_invalid")
    recorded = value.pop("plan_hmac_sha256")
    if not hmac.compare_digest(recorded,
            hmac.new(key, backup.canonical(value), hashlib.sha256).hexdigest()):
        raise RestoreOperationError("restore_plan_authentication_failed")
    if not allow_expired and int(time.time()) > value["expires_unix"]:
        raise RestoreOperationError("restore_plan_expired")
    value["plan_hmac_sha256"] = recorded
    return value


def plan_detail(root: Path, restore_id: str, key: bytes) -> dict:
    plan = load_plan(root, restore_id, key, allow_expired=True)
    return {name: plan[name] for name in
            ("restore_id", "source", "generation_id", "volume_uuid",
             "file_count", "logical_bytes", "expires_unix")}


def write_status(root: Path, restore_id: str, state: str, phase: str, key: bytes,
                 *, error: str = "") -> None:
    body = {"schema": STATUS_SCHEMA, "restore_id": restore_id,
            "state": state, "phase": phase, "error": error, "updated_unix": int(time.time())}
    value = {**body, "status_hmac_sha256": hmac.new(key, backup.canonical(body), hashlib.sha256).hexdigest()}
    temporary = root / f".{restore_id}.status.new-{uuid.uuid4()}"
    try:
        base.write_exclusive(temporary, backup.canonical(value))
        os.replace(temporary, root / f"{restore_id}.status.json")
        backup.fsync_directory(root)
    finally:
        temporary.unlink(missing_ok=True)


def read_status(root: Path, restore_id: str, key: bytes) -> dict | None:
    path = root / f"{restore_id}.status.json"
    if not path.exists():
        return None
    value = json.loads(base.read_exact(path, base.MAX_PLAN_BYTES))
    if (not isinstance(value, dict) or value.get("schema") != STATUS_SCHEMA
            or value.get("restore_id") != restore_id
            or not isinstance(value.get("status_hmac_sha256"), str)):
        raise RestoreOperationError("restore_status_invalid")
    recorded = value.pop("status_hmac_sha256")
    if not hmac.compare_digest(recorded,
            hmac.new(key, backup.canonical(value), hashlib.sha256).hexdigest()):
        raise RestoreOperationError("restore_status_authentication_failed")
    return value


def operation_status(root: Path, repo: Path, restore_id: str, key: bytes) -> dict:
    load_plan(root, restore_id, key, allow_expired=True)
    journal = repo / ".private/control-center-restores" / f"restore-{restore_id}.journal.json"
    if journal.exists():
        value = restore.read_journal(journal, key)
        if value["restore_id"] != restore_id:
            raise RestoreOperationError("restore_journal_identity_changed")
        if value["phase"] in {"accepted", "rolled_back"}:
            result = {"restore_id": restore_id,
                      "state": "verified" if value["phase"] == "accepted" else "rolled_back",
                      "phase": value["phase"], "recoverable": False}
            if value["phase"] == "rolled_back":
                failed = read_status(root, restore_id, key)
                if failed is not None and failed["state"] == "failed" and failed["error"]:
                    result["error"] = failed["error"]
            return result
    status = read_status(root, restore_id, key)
    if base.worker_active(root, restore_id):
        return {"restore_id": restore_id, "state": "running", "phase": (status or {}).get("phase", "starting"),
                "recoverable": False}
    recovery_claim = root / f"{restore_id}.recovery.claimed"
    try:
        claim_metadata = recovery_claim.lstat()
    except FileNotFoundError:
        claim_metadata = None
    if claim_metadata is not None:
        if base.read_exact(recovery_claim, 64) != b"claimed\n":
            raise RestoreOperationError("restore_recovery_claim_invalid")
        if status and status["state"] == "failed" and status["phase"] in {"recovery", "recovery_startup"}:
            return {"restore_id": restore_id, "state": "failed", "phase": status["phase"],
                    "error": status["error"], "recoverable": False}
        if time.time() - claim_metadata.st_mtime < 30:
            return {"restore_id": restore_id, "state": "running", "phase": "recovery_starting",
                    "recoverable": False}
        return {"restore_id": restore_id, "state": "incomplete", "phase": "recovery_startup",
                "recoverable": False}
    if status and status["state"] == "failed":
        return {"restore_id": restore_id, "state": "failed", "phase": status["phase"],
                "error": status["error"], "recoverable": journal.exists()}
    claim = root / f"{restore_id}.claimed"
    if claim.exists():
        if time.time() - claim.stat().st_mtime < 30:
            return {"restore_id": restore_id, "state": "running", "phase": "starting", "recoverable": False}
        return {"restore_id": restore_id, "state": "incomplete", "phase": "startup",
                "recoverable": journal.exists()}
    return {"restore_id": restore_id, "state": "planned", "phase": "review", "recoverable": False}


def retirement_paths(repo: Path, restore_id: str,
                     journal: dict) -> tuple[Path, Path, str, tuple[int, int]]:
    stage_root = repo / ".private/control-center-restores"
    live = repo / "vms"
    if (journal.get("restore_id") != restore_id
            or journal.get("live_vms") != str(live)
            or journal.get("phase") not in {"accepted", "rolled_back"}):
        raise RestoreOperationError("restore_retirement_journal_invalid")
    if journal["phase"] == "accepted":
        target = stage_root / f"restore-{restore_id}.old"
        expected_path = journal.get("old_vms")
        expected_identity = journal.get("original_directory_identity")
        kind = "previous_generation"
    else:
        target = stage_root / f"restore-{restore_id}.failed"
        expected_path = journal.get("failed_vms")
        expected_identity = journal.get("candidate_directory_identity")
        kind = "failed_candidate"
    identities = (expected_identity, journal.get("original_directory_identity"),
                  journal.get("candidate_directory_identity"))
    uuid_sets = (journal.get("original_uuids"), journal.get("restored_uuids"))
    if (expected_path != str(target)
            or any(not isinstance(identity, list) or len(identity) != 2
                   or not all(isinstance(item, int) for item in identity)
                   for identity in identities)
            or any(not isinstance(values, dict) or set(values) != set(backup.NAMES)
                   or any(not isinstance(value, str)
                          or backup.UUID_RE.fullmatch(value) is None
                          for value in values.values())
                   for values in uuid_sets)):
        raise RestoreOperationError("restore_retirement_journal_invalid")
    return live, target, kind, tuple(expected_identity)


def retirement_tree(path: Path) -> tuple[int, int]:
    root = path.lstat()
    if (path.is_symlink() or not stat.S_ISDIR(root.st_mode)
            or root.st_uid != os.getuid()):
        raise RestoreOperationError("restore_retirement_target_untrusted")
    entries = 1
    reclaimable = root.st_blocks * 512
    for current, directories, files in os.walk(path, topdown=True, followlinks=False):
        for name in [*directories, *files]:
            metadata = (Path(current) / name).lstat()
            entries += 1
            if (entries > MAX_RETIREMENT_ENTRIES or metadata.st_uid != os.getuid()
                    or metadata.st_dev != root.st_dev or stat.S_ISLNK(metadata.st_mode)
                    or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode))):
                raise RestoreOperationError("restore_retirement_target_untrusted")
            reclaimable += metadata.st_blocks * 512
    return entries, reclaimable


def write_retirement_status(root: Path, restore_id: str, state: str, key: bytes,
                            *, error: str = "") -> None:
    if state not in {"running", "verified", "failed"}:
        raise RestoreOperationError("restore_retirement_status_invalid")
    body = {"schema": RETIREMENT_STATUS_SCHEMA, "restore_id": restore_id,
            "state": state, "error": error, "updated_unix": int(time.time())}
    value = {**body, "status_hmac_sha256": hmac.new(
        key, backup.canonical(body), hashlib.sha256).hexdigest()}
    temporary = root / f".{restore_id}.retirement.status.new-{uuid.uuid4()}"
    try:
        base.write_exclusive(temporary, backup.canonical(value))
        os.replace(temporary, root / f"{restore_id}.retirement.status.json")
        backup.fsync_directory(root)
    finally:
        temporary.unlink(missing_ok=True)


def read_retirement_status(root: Path, restore_id: str, key: bytes) -> dict | None:
    path = root / f"{restore_id}.retirement.status.json"
    if not path.exists():
        return None
    value = json.loads(base.read_exact(path, base.MAX_PLAN_BYTES))
    if (not isinstance(value, dict) or value.get("schema") != RETIREMENT_STATUS_SCHEMA
            or value.get("restore_id") != restore_id
            or value.get("state") not in {"running", "verified", "failed"}
            or not isinstance(value.get("status_hmac_sha256"), str)):
        raise RestoreOperationError("restore_retirement_status_invalid")
    recorded = value.pop("status_hmac_sha256")
    expected = hmac.new(key, backup.canonical(value), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(recorded, expected):
        raise RestoreOperationError("restore_retirement_status_authentication_failed")
    return value


def retirement_worker_active(root: Path, restore_id: str) -> bool:
    path = root / f"{restore_id}.retirement.worker.lock"
    if not path.exists():
        return False
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        import fcntl
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(descriptor)


def retirement_preview(root: Path, repo: Path, restore_id: str, key: bytes) -> dict:
    load_plan(root, restore_id, key, allow_expired=True)
    journal_path = (repo / ".private/control-center-restores"
                    / f"restore-{restore_id}.journal.json")
    journal = restore.read_journal(journal_path, key)
    live, target, kind, target_identity = retirement_paths(repo, restore_id, journal)
    status = read_retirement_status(root, restore_id, key)
    expected_live_identity = tuple(
        journal["candidate_directory_identity"] if journal["phase"] == "accepted"
        else journal["original_directory_identity"])
    if restore.directory_identity(live) != expected_live_identity:
        raise RestoreOperationError("restore_retirement_identity_changed")
    identities = base.vm_identities(repo)
    expected_uuids = (journal["restored_uuids"] if journal["phase"] == "accepted"
                      else journal["original_uuids"])
    if {name: value["uuid"] for name, value in identities.items()} != expected_uuids:
        raise RestoreOperationError("restore_retirement_registration_changed")
    if not target.exists():
        claim = root / f"{restore_id}.retirement.claimed"
        claimed = claim.exists() and base.read_exact(claim, 64) == b"claimed\n"
        if status is not None and status["state"] == "verified":
            return {"restore_id": restore_id, "state": "retired", "kind": kind,
                    "entry_count": 0, "reclaimable_bytes": 0, "ready": False,
                    "error": None}
        if claimed:
            return {"restore_id": restore_id, "state": "incomplete", "kind": kind,
                    "entry_count": 0, "reclaimable_bytes": 0, "ready": True,
                    "error": status.get("error") if status is not None else None}
        raise RestoreOperationError("restore_retirement_target_missing")
    if status is not None and status["state"] == "verified":
        raise RestoreOperationError("restore_retirement_target_reappeared")
    if restore.directory_identity(target) != target_identity:
        raise RestoreOperationError("restore_retirement_identity_changed")
    entry_count, reclaimable_bytes = retirement_tree(target)
    active = retirement_worker_active(root, restore_id)
    state = ("running" if active else "incomplete"
             if status is not None and status["state"] == "running"
             else status["state"] if status is not None else "available")
    return {"restore_id": restore_id, "state": state, "kind": kind,
            "entry_count": entry_count, "reclaimable_bytes": reclaimable_bytes,
            "ready": state in {"available", "failed", "incomplete"},
            "error": status.get("error") if status is not None else None}


def retirement_status(root: Path, repo: Path, restore_id: str, key: bytes) -> dict:
    return retirement_preview(root, repo, restore_id, key)


def submit_retirement(root: Path, repo: Path, restore_id: str, key: bytes) -> dict:
    preview = retirement_preview(root, repo, restore_id, key)
    if not preview["ready"]:
        raise RestoreOperationError("restore_retirement_not_ready")
    claim = root / f"{restore_id}.retirement.claimed"
    if not claim.exists():
        base.write_exclusive(claim, b"claimed\n")
    elif base.read_exact(claim, 64) != b"claimed\n":
        raise RestoreOperationError("restore_retirement_claim_invalid")
    script = repo / "scripts/control_center_restore_operation.py"
    if not script.is_file():
        write_retirement_status(root, restore_id, "failed", key,
                                error="restore_retirement_worker_unavailable")
        raise RestoreOperationError("restore_retirement_worker_unavailable")
    try:
        subprocess.Popen([sys.executable, str(script), "retire", restore_id], cwd=repo,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    except OSError as error:
        write_retirement_status(root, restore_id, "failed", key,
                                error="restore_retirement_launch_failed")
        raise RestoreOperationError("restore_retirement_launch_failed") from error
    return {"restore_id": restore_id, "state": "submitted"}


def retire(root: Path, repo: Path, restore_id: str) -> int:
    key = backup.read_backup_key()
    load_plan(root, restore_id, key, allow_expired=True)
    claim = root / f"{restore_id}.retirement.claimed"
    if base.read_exact(claim, 64) != b"claimed\n":
        raise RestoreOperationError("restore_retirement_unclaimed")
    descriptor = os.open(root / f"{restore_id}.retirement.worker.lock",
                         os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lifecycle_fd = -1
    try:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write_retirement_status(root, restore_id, "running", key)
        lifecycle = restore.load_repo_module(
            "restore_retirement_lifecycle", repo / "scripts/parallels-lifecycle.py")
        lifecycle_fd = lifecycle.ensure_mutation_preconditions("restore-retirement")
        preview = retirement_preview(root, repo, restore_id, key)
        if preview["state"] not in {"running", "failed", "available", "incomplete"}:
            raise RestoreOperationError("restore_retirement_not_ready")
        journal_path = (repo / ".private/control-center-restores"
                        / f"restore-{restore_id}.journal.json")
        journal = restore.read_journal(journal_path, key)
        _live, target, _kind, _identity = retirement_paths(repo, restore_id, journal)
        if target.exists():
            shutil.rmtree(target)
            backup.fsync_directory(target.parent)
        elif preview["state"] != "incomplete":
            raise RestoreOperationError("restore_retirement_target_missing")
        write_retirement_status(root, restore_id, "verified", key)
        return 0
    except BaseException as error:
        code = str(error)
        if re.fullmatch(r"[a-z0-9_]{1,80}", code) is None:
            code = "restore_retirement_failed"
        write_retirement_status(root, restore_id, "failed", key, error=code)
        return 1
    finally:
        if lifecycle_fd >= 0:
            os.close(lifecycle_fd)
        os.close(descriptor)


def submit_recovery(root: Path, repo: Path, restore_id: str, key: bytes) -> dict:
    load_plan(root, restore_id, key, allow_expired=True)
    journal_path = repo / ".private/control-center-restores" / f"restore-{restore_id}.journal.json"
    if not journal_path.is_file():
        raise RestoreOperationError("restore_recovery_journal_unavailable")
    journal = restore.read_journal(journal_path, key)
    if journal["restore_id"] != restore_id or journal["phase"] in {"accepted", "rolled_back"}:
        raise RestoreOperationError("restore_recovery_not_required")
    if base.worker_active(root, restore_id):
        raise RestoreOperationError("restore_worker_active")
    try:
        base.write_exclusive(root / f"{restore_id}.recovery.claimed", b"claimed\n")
    except FileExistsError as error:
        raise RestoreOperationError("restore_recovery_already_claimed") from error
    script = repo / "scripts/control_center_restore_operation.py"
    try:
        subprocess.Popen([sys.executable, str(script), "recover", restore_id], cwd=repo,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    except OSError as error:
        write_status(root, restore_id, "failed", "recovery_startup", key,
                     error="restore_recovery_launch_failed")
        raise RestoreOperationError("restore_recovery_launch_failed") from error
    return {"restore_id": restore_id, "state": "submitted"}


def submit(root: Path, repo: Path, restore_id: str, key: bytes) -> dict:
    plan = load_plan(root, restore_id, key)
    try:
        base.write_exclusive(root / f"{restore_id}.claimed", b"claimed\n")
    except FileExistsError as error:
        raise RestoreOperationError("restore_plan_already_claimed") from error
    script = repo / "scripts/control_center_restore_operation.py"
    if not script.is_file():
        write_status(root, restore_id, "failed", "startup", key, error="restore_worker_unavailable")
        raise RestoreOperationError("restore_worker_unavailable")
    try:
        subprocess.Popen([sys.executable, str(script), "worker", restore_id], cwd=repo,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    except OSError as error:
        write_status(root, restore_id, "failed", "startup", key, error="restore_worker_launch_failed")
        raise RestoreOperationError("restore_worker_launch_failed") from error
    return {"restore_id": plan["restore_id"], "state": "submitted"}


def verify_restore_profile_headroom(
        repo: Path, *, now: datetime.datetime | None = None) -> None:
    profile = (repo / "artifacts/host/SecureSandboxAuthorizationUI.app/Contents"
               / "embedded.provisionprofile")
    try:
        result = subprocess.run(
            ["/usr/bin/security", "cms", "-D", "-i", str(profile)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=30, check=False)
        value = plistlib.loads(result.stdout)
        expiration = value["ExpirationDate"]
    except (OSError, subprocess.TimeoutExpired, plistlib.InvalidFileException,
            KeyError, TypeError) as error:
        raise RestoreOperationError("restore_authorization_profile_unverified") from error
    if result.returncode != 0 or not isinstance(expiration, datetime.datetime):
        raise RestoreOperationError("restore_authorization_profile_unverified")
    current = now or datetime.datetime.now(datetime.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=datetime.timezone.utc)
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=datetime.timezone.utc)
    if expiration <= current + RESTORE_PROFILE_MINIMUM_VALIDITY:
        raise RestoreOperationError("restore_authorization_profile_headroom_insufficient")


def verify_host_release_precondition(repo: Path) -> None:
    verify_restore_profile_headroom(repo)
    try:
        result = subprocess.run(
            [sys.executable, str(repo / "scripts/secure_enclave_ddd_support.py"),
             "verify-postactivation-host-release", "--repo", str(repo),
             "--install-root", "/usr/local/libexec/secure-sandbox-host",
             "--launcher", "/usr/local/bin/secure-sandbox-claude"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RestoreOperationError("restore_host_release_unverified") from error
    if result.returncode:
        raise RestoreOperationError("restore_host_release_unverified")


def worker(root: Path, repo: Path, restore_id: str) -> int:
    key = backup.read_backup_key()
    plan = load_plan(root, restore_id, key, allow_expired=True)
    if not (root / f"{restore_id}.claimed").is_file():
        raise RestoreOperationError("restore_plan_unclaimed")
    descriptor = os.open(root / f"{restore_id}.worker.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lifecycle_fd = -1
    try:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write_status(root, restore_id, "running", "preflight", key)
        lifecycle = restore.load_repo_module("restore_worker_lifecycle", repo / "scripts/parallels-lifecycle.py")
        lifecycle_fd = lifecycle.ensure_mutation_preconditions("restore")
        verify_host_release_precondition(repo)
        api = restore.load_repo_module("restore_worker_api", repo / "scripts/control-center-api.py")
        preview = api.restore_preview(plan["source"], plan["generation_id"])
        if (not preview["ready"] or preview["volume_uuid"] != plan["volume_uuid"]
                or preview["manifest_hmac_sha256"] != plan["manifest_hmac_sha256"]
                or preview["file_count"] != plan["file_count"]
                or preview["logical_bytes"] != plan["logical_bytes"]
                or base.vm_identities(repo) != plan["current_identities"]):
            raise RestoreOperationError("restore_preflight_changed")
        maintenance = restore.load_repo_module("restore_worker_maintenance", repo / "scripts/vm-maintenance.py")
        if maintenance.pending_transaction(repo, os.getuid()) is not None:
            raise RestoreOperationError("restore_maintenance_transaction_pending")
        generation = Path(plan["source"]) / f"secure-sandbox-backup-{plan['generation_id']}"
        stage_root = repo / ".private/control-center-restores"
        write_status(root, restore_id, "running", "staging", key)
        staged = restore.stage_candidate(generation, stage_root, repo / "vms", key, restore_id=restore_id)
        write_status(root, restore_id, "running", "installing", key)
        adapter = restore.ParallelsRestoreAdapter(repo, lifecycle_fd)
        restore.swap_candidate(Path(staged["stage"]), generation, repo / "vms", key,
                               adapter, plan["current_identities"], plan["manifest_hmac_sha256"])
        write_status(root, restore_id, "verified", "accepted", key)
        return 0
    except BaseException as error:
        code = str(error)
        if re.fullmatch(r"[a-z0-9_]{1,80}", code) is None:
            code = "restore_worker_failed"
        write_status(root, restore_id, "failed", "execution", key, error=code)
        return 1
    finally:
        if lifecycle_fd >= 0:
            os.close(lifecycle_fd)
        os.close(descriptor)


def recover(root: Path, repo: Path, restore_id: str) -> int:
    key = backup.read_backup_key()
    load_plan(root, restore_id, key, allow_expired=True)
    if not (root / f"{restore_id}.recovery.claimed").is_file():
        raise RestoreOperationError("restore_recovery_unclaimed")
    journal_path = repo / ".private/control-center-restores" / f"restore-{restore_id}.journal.json"
    descriptor = os.open(root / f"{restore_id}.worker.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lifecycle_fd = -1
    try:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write_status(root, restore_id, "running", "recovering", key)
        lifecycle = restore.load_repo_module("restore_recovery_lifecycle", repo / "scripts/parallels-lifecycle.py")
        lifecycle_fd = lifecycle.ensure_mutation_preconditions("restore-recovery")
        journal = restore.read_journal(journal_path, key)
        if journal["restore_id"] != restore_id or journal["phase"] in {"accepted", "rolled_back"}:
            raise RestoreOperationError("restore_recovery_not_required")
        adapter = restore.ParallelsRestoreAdapter(repo, lifecycle_fd)
        restore.rollback_swap(journal_path, key, adapter)
        write_status(root, restore_id, "rolled_back", "recovered", key)
        return 0
    except BaseException as error:
        code = str(error)
        if re.fullmatch(r"[a-z0-9_]{1,80}", code) is None:
            code = "restore_recovery_failed"
        write_status(root, restore_id, "failed", "recovery", key, error=code)
        return 1
    finally:
        if lifecycle_fd >= 0:
            os.close(lifecycle_fd)
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("worker", "recover", "retire"))
    parser.add_argument("restore_id")
    arguments = parser.parse_args()
    if base.UUID.fullmatch(arguments.restore_id) is None:
        raise RestoreOperationError("restore_plan_invalid")
    repo = Path(__file__).resolve().parent.parent
    if arguments.operation == "recover":
        return recover(default_root(), repo, arguments.restore_id)
    if arguments.operation == "retire":
        return retire(default_root(), repo, arguments.restore_id)
    return worker(default_root(), repo, arguments.restore_id)


if __name__ == "__main__":
    raise SystemExit(main())
