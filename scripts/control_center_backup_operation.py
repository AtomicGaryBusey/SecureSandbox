#!/usr/bin/env python3
"""Durable one-time plans and operation identities for Control Center backups."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import fcntl
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:
    import control_center_backup as backup
except ModuleNotFoundError:
    from scripts import control_center_backup as backup

PLAN_SCHEMA = "secure-sandbox-control-center-backup-plan-v1"
STATUS_SCHEMA = "secure-sandbox-control-center-backup-status-v1"
MAX_PLAN_BYTES = 16 * 1024
PLAN_LIFETIME_SECONDS = 15 * 60
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class OperationError(RuntimeError):
    pass


def default_root() -> Path:
    return Path.home() / "Library/Application Support/SecureSandbox/backup-operations"


def trusted_root(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise OperationError("backup_operation_directory_untrusted")


def write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        backup.write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    backup.fsync_directory(path.parent)


def read_exact(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                or opened.st_size > maximum
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise OperationError("backup_operation_file_untrusted")
        data = bytearray()
        while chunk := os.read(descriptor, min(4096, maximum + 1 - len(data))):
            data.extend(chunk)
            if len(data) > maximum:
                raise OperationError("backup_operation_file_oversized")
        after = os.fstat(descriptor)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
            raise OperationError("backup_operation_file_changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def create_plan(root: Path, destination: Path, volume_uuid: str,
                vm_identities: dict[str, dict[str, int | str]], key: bytes,
                *, logical_bytes: int = 0, now: int | None = None, plan_id: str | None = None) -> dict:
    trusted_root(root)
    now = int(time.time()) if now is None else now
    plan_id = plan_id or str(uuid.uuid4())
    if (UUID.fullmatch(plan_id) is None or not destination.is_absolute()
            or not isinstance(volume_uuid, str) or UUID.fullmatch(volume_uuid.lower()) is None
            or set(vm_identities) != set(backup.NAMES) or len(key) < 32
            or not isinstance(logical_bytes, int) or logical_bytes < 0):
        raise OperationError("backup_plan_identity_invalid")
    body = {"schema": PLAN_SCHEMA, "plan_id": plan_id,
            "destination": str(destination), "volume_uuid": volume_uuid,
            "vm_identities": vm_identities, "logical_bytes": logical_bytes, "created_unix": now,
            "expires_unix": now + PLAN_LIFETIME_SECONDS}
    digest = hmac.new(key, backup.canonical(body), hashlib.sha256).hexdigest()
    value = {**body, "plan_hmac_sha256": digest}
    payload = backup.canonical(value)
    if len(payload) > MAX_PLAN_BYTES:
        raise OperationError("backup_plan_too_large")
    write_exclusive(root / f"{plan_id}.json", payload)
    return value


def load_plan(root: Path, plan_id: str, key: bytes, *, now: int | None = None,
              allow_expired: bool = False) -> dict:
    if UUID.fullmatch(plan_id) is None or len(key) < 32:
        raise OperationError("backup_plan_identity_invalid")
    trusted_root(root)
    try:
        value = json.loads(read_exact(root / f"{plan_id}.json", MAX_PLAN_BYTES))
    except FileNotFoundError as error:
        raise OperationError("backup_plan_not_found") from error
    if (not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA
            or value.get("plan_id") != plan_id
            or not isinstance(value.get("plan_hmac_sha256"), str)):
        raise OperationError("backup_plan_invalid")
    recorded = value.pop("plan_hmac_sha256")
    expected = hmac.new(key, backup.canonical(value), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(recorded, expected):
        raise OperationError("backup_plan_authentication_failed")
    current = int(time.time()) if now is None else now
    if not allow_expired and (not isinstance(value.get("expires_unix"), int)
                              or current > value["expires_unix"]):
        raise OperationError("backup_plan_expired")
    value["plan_hmac_sha256"] = recorded
    return value


def claim_plan(root: Path, plan_id: str, key: bytes, *, now: int | None = None) -> dict:
    value = load_plan(root, plan_id, key, now=now)
    try:
        write_exclusive(root / f"{plan_id}.claimed", b"claimed\n")
    except FileExistsError as error:
        raise OperationError("backup_plan_already_claimed") from error
    return value


def load_repo_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise OperationError("backup_repo_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def vm_identities(repo: Path) -> dict[str, dict[str, int | str]]:
    maintenance = load_repo_module("backup_vm_maintenance", repo / "scripts/vm-maintenance.py")
    result = {}
    for name in backup.NAMES:
        value = maintenance.vm_identity(name, repo / "vms" / f"{name}.pvm")
        if value.get("name") != name or value.get("state") != "stopped":
            raise OperationError("backup_vm_identity_unverified")
        result[name] = {"uuid": value["uuid"].strip("{}"),
                        "device": value["bundle_device"], "inode": value["bundle_inode"]}
    return result


def write_status(root: Path, plan_id: str, state: str, phase: str, key: bytes,
                 *, error: str = "", result: dict | None = None) -> None:
    if UUID.fullmatch(plan_id) is None or state not in {"running", "verified", "failed"}:
        raise OperationError("backup_status_identity_invalid")
    body = {"schema": STATUS_SCHEMA, "plan_id": plan_id, "state": state,
            "phase": phase, "error": error, "result": result or {},
            "updated_unix": int(time.time())}
    value = {**body, "status_hmac_sha256": hmac.new(key, backup.canonical(body), hashlib.sha256).hexdigest()}
    temporary = root / f".{plan_id}.status.new-{uuid.uuid4()}"
    try:
        write_exclusive(temporary, backup.canonical(value))
        os.replace(temporary, root / f"{plan_id}.status.json")
        backup.fsync_directory(root)
    finally:
        temporary.unlink(missing_ok=True)


def read_status(root: Path, plan_id: str, key: bytes) -> dict | None:
    path = root / f"{plan_id}.status.json"
    if not path.exists():
        return None
    value = json.loads(read_exact(path, MAX_PLAN_BYTES))
    if (not isinstance(value, dict) or value.get("schema") != STATUS_SCHEMA
            or value.get("plan_id") != plan_id or value.get("state") not in {"running", "verified", "failed"}
            or not isinstance(value.get("status_hmac_sha256"), str)):
        raise OperationError("backup_status_invalid")
    recorded = value.pop("status_hmac_sha256")
    if not hmac.compare_digest(recorded, hmac.new(key, backup.canonical(value), hashlib.sha256).hexdigest()):
        raise OperationError("backup_status_authentication_failed")
    value["status_hmac_sha256"] = recorded
    return value


def worker_active(root: Path, plan_id: str) -> bool:
    path = root / f"{plan_id}.worker.lock"
    if not path.exists():
        return False
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(descriptor)


def operation_status(root: Path, plan_id: str, key: bytes) -> dict:
    plan = load_plan(root, plan_id, key, allow_expired=True)
    destination = Path(plan["destination"])
    status = read_status(root, plan_id, key)
    active = worker_active(root, plan_id)
    published = destination / f"secure-sandbox-backup-{plan_id}"
    stage = destination / f".secure-sandbox-backup-{plan_id}.incomplete"
    if published.exists() and stage.exists():
        raise OperationError("backup_result_ambiguous")
    if active:
        return {"plan_id": plan_id, "state": "running",
                "phase": "verifying" if published.exists() else (status or {}).get("phase", "starting")}
    if published.exists():
        completed = status is not None and status["state"] == "verified"
        manifest = (backup.verify_backup_metadata(published, key) if completed
                    else backup.verify_backup(published, key))
        if manifest["volume_uuid"] != plan["volume_uuid"] or manifest["vm_uuids"] != {
                name: value["uuid"] for name, value in plan["vm_identities"].items()}:
            raise OperationError("backup_result_identity_changed")
        if completed:
            result = status.get("result")
            if (not isinstance(result, dict)
                    or result.get("generation_id") != plan_id
                    or result.get("path") != str(published)
                    or result.get("manifest_hmac_sha256") != manifest["manifest_hmac_sha256"]
                    or result.get("file_count") != manifest["file_count"]
                    or result.get("logical_bytes") != manifest["logical_bytes"]):
                raise OperationError("backup_result_identity_changed")
        return {"plan_id": plan_id, "state": "verified", "phase": "complete",
                "file_count": manifest["file_count"], "logical_bytes": manifest["logical_bytes"]}
    if stage.exists():
        return {"plan_id": plan_id, "state": "incomplete", "phase": (status or {}).get("phase", "copying")}
    if status and status["state"] == "failed":
        return {"plan_id": plan_id, "state": "failed", "phase": status["phase"], "error": status["error"]}
    claim = root / f"{plan_id}.claimed"
    if claim.exists():
        if time.time() - claim.stat().st_mtime < 30:
            return {"plan_id": plan_id, "state": "running", "phase": "starting"}
        return {"plan_id": plan_id, "state": "incomplete", "phase": "startup"}
    return {"plan_id": plan_id, "state": "planned", "phase": "review"}


def plan_detail(root: Path, plan_id: str, key: bytes) -> dict:
    plan = load_plan(root, plan_id, key, allow_expired=True)
    return {field: plan[field] for field in
            ("plan_id", "destination", "volume_uuid", "expires_unix", "logical_bytes")}


def submit_backup(root: Path, repo: Path, plan_id: str, key: bytes) -> dict[str, str]:
    plan = claim_plan(root, plan_id, key)
    script = repo / "scripts/control_center_backup_operation.py"
    if not script.is_file():
        write_status(root, plan_id, "failed", "startup", key, error="backup_worker_unavailable")
        raise OperationError("backup_worker_unavailable")
    try:
        subprocess.Popen([sys.executable, str(script), "worker", plan_id], cwd=repo,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    except OSError as error:
        write_status(root, plan_id, "failed", "startup", key, error="backup_worker_launch_failed")
        raise OperationError("backup_worker_launch_failed") from error
    return {"plan_id": plan["plan_id"], "state": "submitted"}


def worker(root: Path, repo: Path, plan_id: str) -> int:
    key = backup.read_backup_key()
    plan = load_plan(root, plan_id, key, allow_expired=True)
    if not (root / f"{plan_id}.claimed").is_file():
        raise OperationError("backup_plan_unclaimed")
    lock_path = root / f"{plan_id}.worker.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lifecycle_descriptor = -1
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise OperationError("backup_worker_already_active") from error
        write_status(root, plan_id, "running", "preflight", key)
        lifecycle = load_repo_module("backup_lifecycle", repo / "scripts/parallels-lifecycle.py")
        lifecycle_descriptor = lifecycle.ensure_mutation_preconditions("backup")
        api = load_repo_module("backup_control_api", repo / "scripts/control-center-api.py")
        fresh = api.backup_preflight(plan["destination"])
        if (not fresh["ready"] or fresh["destination"] != plan["destination"]
                or fresh["volume_uuid"] != plan["volume_uuid"]):
            raise OperationError("backup_preflight_changed")
        current_identities = vm_identities(repo)
        if current_identities != plan["vm_identities"]:
            raise OperationError("backup_vm_identity_changed")
        write_status(root, plan_id, "running", "copying", key)
        result = backup.create_backup(repo / "vms", repo / "config", Path(plan["destination"]),
                                      {name: value["uuid"] for name, value in current_identities.items()},
                                      plan["volume_uuid"], key, generation=plan_id)
        write_status(root, plan_id, "verified", "complete", key, result=result)
        return 0
    except BaseException as error:
        code = str(error)
        if re.fullmatch(r"[a-z0-9_]{1,80}", code) is None:
            code = "backup_worker_failed"
        write_status(root, plan_id, "failed", "execution", key, error=code)
        return 1
    finally:
        if lifecycle_descriptor >= 0:
            os.close(lifecycle_descriptor)
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("worker",))
    parser.add_argument("plan_id")
    arguments = parser.parse_args()
    if UUID.fullmatch(arguments.plan_id) is None:
        raise OperationError("backup_plan_identity_invalid")
    repo = Path(__file__).resolve().parent.parent
    return worker(default_root(), repo, arguments.plan_id)


if __name__ == "__main__":
    raise SystemExit(main())
