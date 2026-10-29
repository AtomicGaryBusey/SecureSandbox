#!/usr/bin/env python3
"""One-time restore plans and detached, journaled restore execution."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
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
LIFETIME = 15 * 60


class RestoreOperationError(RuntimeError):
    pass


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
            return {"restore_id": restore_id,
                    "state": "verified" if value["phase"] == "accepted" else "rolled_back",
                    "phase": value["phase"]}
    status = read_status(root, restore_id, key)
    if base.worker_active(root, restore_id):
        return {"restore_id": restore_id, "state": "running", "phase": (status or {}).get("phase", "starting")}
    if status and status["state"] == "failed":
        return {"restore_id": restore_id, "state": "failed", "phase": status["phase"], "error": status["error"]}
    claim = root / f"{restore_id}.claimed"
    if claim.exists():
        if time.time() - claim.stat().st_mtime < 30:
            return {"restore_id": restore_id, "state": "running", "phase": "starting"}
        return {"restore_id": restore_id, "state": "incomplete", "phase": "startup"}
    return {"restore_id": restore_id, "state": "planned", "phase": "review"}


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("worker",))
    parser.add_argument("restore_id")
    arguments = parser.parse_args()
    if base.UUID.fullmatch(arguments.restore_id) is None:
        raise RestoreOperationError("restore_plan_invalid")
    return worker(default_root(), Path(__file__).resolve().parent.parent, arguments.restore_id)


if __name__ == "__main__":
    raise SystemExit(main())
