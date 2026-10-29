#!/usr/bin/env python3
"""Stage a verified backup candidate on the host VM filesystem for restore."""

from __future__ import annotations

import os
import shutil
import stat
import uuid
from pathlib import Path
from typing import Callable

try:
    import control_center_backup as backup
except ModuleNotFoundError:
    from scripts import control_center_backup as backup


class RestoreError(RuntimeError):
    pass


def trusted_stage_root(path: Path, live_vms: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    live = live_vms.lstat()
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
