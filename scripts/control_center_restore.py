#!/usr/bin/env python3
"""Stage a verified backup candidate on the host VM filesystem for restore."""

from __future__ import annotations

import os
import hashlib
import hmac
import importlib.util
import json
import re
import shutil
import stat
import uuid
from pathlib import Path
from typing import Callable, Protocol

try:
    import control_center_backup as backup
except ModuleNotFoundError:
    from scripts import control_center_backup as backup


class RestoreError(RuntimeError):
    pass


JOURNAL_SCHEMA = "secure-sandbox-control-center-restore-journal-v1"


class VMAdapter(Protocol):
    def identity(self, name: str, home: Path) -> str | None: ...
    def unregister(self, identifier: str) -> None: ...
    def register(self, home: Path) -> None: ...
    def accept(self) -> None: ...
    def stop(self) -> None: ...


def load_repo_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RestoreError("restore_repo_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ParallelsRestoreAdapter:
    def __init__(self, repo: Path, inherited_lock: int):
        self.maintenance = load_repo_module("restore_vm_maintenance", repo / "scripts/vm-maintenance.py")
        self.lifecycle = load_repo_module("restore_lifecycle", repo / "scripts/parallels-lifecycle.py")
        self.lock = inherited_lock

    def identity(self, name: str, home: Path) -> str | None:
        if name not in self.maintenance.current_vm_names():
            return None
        value = self.maintenance.vm_identity(name, home)
        if value["name"] != name or value["state"] != "stopped":
            raise RestoreError("restore_vm_identity_unverified")
        return value["uuid"].strip("{}")

    def unregister(self, identifier: str) -> None:
        self.maintenance.run([str(self.maintenance.PRLCTL), "unregister", identifier])

    def register(self, home: Path) -> None:
        self.maintenance.run([str(self.maintenance.PRLCTL), "register", str(home), "--preserve-uuid"])

    def accept(self) -> None:
        if self.lifecycle.start(inherited_lock=self.lock) != 0:
            raise RestoreError("restore_cold_acceptance_failed")

    def stop(self) -> None:
        if self.lifecycle.stop(inherited_lock=self.lock) != 0:
            raise RestoreError("restore_candidate_stop_failed")


def trusted_stage_root(path: Path, live_vms: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    live = live_vms.parent.lstat()
    if (path.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_dev != live.st_dev):
        raise RestoreError("restore_stage_root_untrusted")


def stage_candidate(generation: Path, stage_root: Path, live_vms: Path, key: bytes,
                    *, restore_id: str | None = None,
                    bundle_copier: Callable[[Path, Path], None] = backup.copy_bundle,
                    file_copier: Callable[[Path, Path], None] = shutil.copy2) -> dict:
    restore_id = restore_id or str(uuid.uuid4())
    if backup.UUID_RE.fullmatch(restore_id) is None:
        raise RestoreError("restore_identity_invalid")
    trusted_stage_root(stage_root, live_vms)
    manifest = backup.verify_backup(generation, key)
    incomplete = stage_root / f".restore-{restore_id}.incomplete"
    ready = stage_root / f"restore-{restore_id}.ready"
    if incomplete.exists() or ready.exists():
        raise RestoreError("restore_stage_collision")
    incomplete.mkdir(mode=0o700)
    backup.fsync_directory(stage_root)
    try:
        vms = incomplete / "vms"
        config = incomplete / "host-config"
        vms.mkdir(mode=0o700)
        config.mkdir(mode=0o700)
        for name in backup.NAMES:
            bundle_copier(generation / "vms" / f"{name}.pvm", vms / f"{name}.pvm")
        for name in backup.HOST_CONFIG_FILES:
            file_copier(generation / "host-config" / name, config / name)
        if (backup.inventory(vms) != manifest["files"]
                or backup.host_config_inventory(config) != manifest["host_files"]):
            raise RestoreError("restore_candidate_content_changed")
        backup.fsync_files(vms, manifest["files"])
        for name in backup.HOST_CONFIG_FILES:
            descriptor = os.open(config / name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for record in reversed(manifest["files"]):
            if record["kind"] == "directory":
                backup.fsync_directory(vms / str(record["path"]))
        backup.fsync_directory(vms)
        backup.fsync_directory(config)
        backup.fsync_directory(incomplete)
        os.replace(incomplete, ready)
        backup.fsync_directory(stage_root)
        return {"restore_id": restore_id, "stage": str(ready),
                "generation_id": manifest["generation_id"],
                "file_count": manifest["file_count"],
                "logical_bytes": manifest["logical_bytes"]}
    except BaseException:
        # Preserve the incomplete candidate so recovery can inspect the failure.
        raise


def verify_candidate(stage: Path, generation: Path, key: bytes) -> dict:
    if not stage.name.endswith(".ready") or stage.is_symlink() or not stat.S_ISDIR(stage.lstat().st_mode):
        raise RestoreError("restore_stage_untrusted")
    manifest = backup.verify_backup(generation, key)
    if (set(item.name for item in stage.iterdir()) != {"vms", "host-config"}
            or backup.inventory(stage / "vms") != manifest["files"]
            or backup.host_config_inventory(stage / "host-config") != manifest["host_files"]
            or set(item.name for item in (stage / "host-config").iterdir()) != set(backup.HOST_CONFIG_FILES)):
        raise RestoreError("restore_candidate_content_changed")
    return manifest


def directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise RestoreError("restore_directory_untrusted")
    return info.st_dev, info.st_ino


def authenticated_journal(body: dict, key: bytes) -> bytes:
    if len(key) < 32:
        raise RestoreError("restore_key_invalid")
    return backup.canonical({**body, "journal_hmac_sha256":
                             hmac.new(key, backup.canonical(body), hashlib.sha256).hexdigest()})


def write_journal(path: Path, body: dict, key: bytes, *, initial: bool = False) -> None:
    payload = authenticated_journal(body, key)
    if len(payload) > 16 * 1024:
        raise RestoreError("restore_journal_oversized")
    target = path if initial else path.parent / f".{path.name}.new-{uuid.uuid4()}"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        backup.write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not initial:
        os.replace(target, path)
    backup.fsync_directory(path.parent)


def read_journal(path: Path, key: bytes) -> dict:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size > 16 * 1024):
        raise RestoreError("restore_journal_untrusted")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise RestoreError("restore_journal_changed")
        payload = os.read(descriptor, 16 * 1024 + 1)
    finally:
        os.close(descriptor)
    value = json.loads(payload)
    if (not isinstance(value, dict) or value.get("schema") != JOURNAL_SCHEMA
            or not isinstance(value.get("journal_hmac_sha256"), str)):
        raise RestoreError("restore_journal_invalid")
    recorded = value.pop("journal_hmac_sha256")
    expected = hmac.new(key, backup.canonical(value), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(recorded, expected):
        raise RestoreError("restore_journal_authentication_failed")
    return value


def set_phase(path: Path, journal: dict, phase: str, key: bytes) -> None:
    journal["phase"] = phase
    write_journal(path, journal, key)


def rollback_swap(path: Path, key: bytes, adapter: VMAdapter) -> dict:
    journal = read_journal(path, key)
    if journal["phase"] == "rolled_back":
        return journal
    live = Path(journal["live_vms"])
    trusted_stage_root(path.parent, live)
    old = Path(journal["old_vms"])
    failed = Path(journal["failed_vms"])
    original_identity = tuple(journal["original_directory_identity"])
    candidate_identity = tuple(journal["candidate_directory_identity"])
    failed_identity = directory_identity(failed)
    if failed_identity is not None and failed_identity != candidate_identity:
        raise RestoreError("restore_failed_path_occupied")
    adapter.stop()
    for name in backup.NAMES:
        current = adapter.identity(name, live / f"{name}.pvm")
        if current is None:
            continue
        if current not in {journal["original_uuids"][name], journal["restored_uuids"][name]}:
            raise RestoreError("restore_registration_collision")
        adapter.unregister(current)
    live_identity = directory_identity(live)
    if live_identity == candidate_identity:
        if failed_identity is not None:
            raise RestoreError("restore_failed_path_occupied")
        live.rename(failed)
        backup.fsync_directory(live.parent)
        backup.fsync_directory(failed.parent)
    elif live_identity not in {None, original_identity}:
        raise RestoreError("restore_live_directory_changed")
    if directory_identity(old) == original_identity:
        if live.exists():
            raise RestoreError("restore_original_destination_occupied")
        old.rename(live)
        backup.fsync_directory(old.parent)
        backup.fsync_directory(live.parent)
    elif directory_identity(live) != original_identity:
        raise RestoreError("restore_original_missing")
    for name in backup.NAMES:
        home = live / f"{name}.pvm"
        if directory_identity(home) != tuple(journal["original_bundle_identities"][name]):
            raise RestoreError("restore_original_bundle_changed")
        adapter.register(home)
        if adapter.identity(name, home) != journal["original_uuids"][name]:
            raise RestoreError("restore_original_registration_failed")
    set_phase(path, journal, "rolled_back", key)
    return journal


def swap_candidate(stage: Path, generation: Path, live_vms: Path, key: bytes,
                   adapter: VMAdapter, expected_current: dict,
                   expected_manifest_hmac: str) -> dict:
    trusted_stage_root(stage.parent, live_vms)
    manifest = verify_candidate(stage, generation, key)
    if (manifest["manifest_hmac_sha256"] != expected_manifest_hmac
            or set(expected_current) != set(backup.NAMES)):
        raise RestoreError("restore_plan_binding_changed")
    restore_id = stage.name.removeprefix("restore-").removesuffix(".ready")
    if backup.UUID_RE.fullmatch(restore_id) is None:
        raise RestoreError("restore_identity_invalid")
    old = stage.parent / f"restore-{restore_id}.old"
    failed = stage.parent / f"restore-{restore_id}.failed"
    journal_path = stage.parent / f"restore-{restore_id}.journal.json"
    if any(path.exists() for path in (old, failed, journal_path)):
        raise RestoreError("restore_transaction_collision")
    if directory_identity(live_vms.parent) is None or directory_identity(stage / "vms") is None:
        raise RestoreError("restore_directory_untrusted")
    if live_vms.parent.stat().st_dev != stage.stat().st_dev:
        raise RestoreError("restore_filesystem_mismatch")
    originals = {}
    bundle_identities = {}
    for name in backup.NAMES:
        home = live_vms / f"{name}.pvm"
        identifier = adapter.identity(name, home)
        identity = directory_identity(home)
        if identifier is None or identity is None:
            raise RestoreError("restore_current_identity_unverified")
        if (identifier != expected_current[name].get("uuid")
                or identity != (expected_current[name].get("device"), expected_current[name].get("inode"))):
            raise RestoreError("restore_current_identity_changed")
        originals[name] = identifier
        bundle_identities[name] = identity
    journal = {"schema": JOURNAL_SCHEMA, "restore_id": restore_id,
               "generation_id": manifest["generation_id"], "phase": "prepared",
               "live_vms": str(live_vms), "old_vms": str(old), "failed_vms": str(failed),
               "original_directory_identity": directory_identity(live_vms),
               "candidate_directory_identity": directory_identity(stage / "vms"),
               "original_bundle_identities": bundle_identities,
               "original_uuids": originals, "restored_uuids": manifest["vm_uuids"]}
    write_journal(journal_path, journal, key, initial=True)
    try:
        for name in backup.NAMES:
            adapter.unregister(originals[name])
        set_phase(journal_path, journal, "unregistered", key)
        live_vms.rename(old)
        backup.fsync_directory(live_vms.parent)
        backup.fsync_directory(old.parent)
        set_phase(journal_path, journal, "quarantined", key)
        (stage / "vms").rename(live_vms)
        backup.fsync_directory(stage)
        backup.fsync_directory(live_vms.parent)
        set_phase(journal_path, journal, "installed", key)
        for name in backup.NAMES:
            home = live_vms / f"{name}.pvm"
            adapter.register(home)
            if adapter.identity(name, home) != manifest["vm_uuids"][name]:
                raise RestoreError("restore_candidate_registration_failed")
        set_phase(journal_path, journal, "registered", key)
        adapter.accept()
        set_phase(journal_path, journal, "accepted", key)
        return journal
    except BaseException as primary:
        try:
            rollback_swap(journal_path, key, adapter)
        except BaseException as recovery:
            raise RestoreError(f"restore_failed_recovery_incomplete:{type(primary).__name__}:{type(recovery).__name__}") from primary
        reason = str(primary)
        if not isinstance(primary, RestoreError) or re.fullmatch(r"[a-z0-9_]{1,50}", reason) is None:
            reason = "acceptance_error"
        raise RestoreError(f"restore_failed_rolled_back_{reason}") from primary
