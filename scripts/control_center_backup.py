#!/usr/bin/env python3
"""Authenticated, staged backup generation for the three cold VM bundles."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Callable

SCHEMA = "secure-sandbox-control-center-backup-v2"
NAMES = ("SecureSandbox-Gateway", "SecureSandbox-Research", "SecureSandbox-Target")
HOST_CONFIG_FILES = ("conversation-age-recipient.txt", "external-containment.json",
                     "netplan-gateway.yaml", "netplan-research.yaml", "netplan-target.yaml",
                     "provider-credential-reference.txt", "snapshot-retention.json", "ssh_config")
MAX_FILES = 100_000
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BACKUP_KEY_REF = "op://Agents/SecureSandbox-VM-Backup/password"
BACKUP_KEY_ATTEMPTS = 3
BACKUP_KEY_TIMEOUT_SECONDS = 5
BACKUP_KEY_RETRY_DELAYS = (0.25, 0.75)


class BackupError(RuntimeError):
    pass


def read_backup_key() -> bytes:
    executable = Path.home() / ".local/bin/op-agents"
    for attempt in range(BACKUP_KEY_ATTEMPTS):
        try:
            result = subprocess.run([str(executable), "read", BACKUP_KEY_REF],
                                    capture_output=True, check=False,
                                    timeout=BACKUP_KEY_TIMEOUT_SECONDS)
            key = result.stdout.rstrip(b"\n")
            if (result.returncode == 0 and 32 <= len(key) <= 128
                    and b"\x00" not in key and b"\r" not in key):
                return key
        except subprocess.TimeoutExpired:
            pass
        if attempt < len(BACKUP_KEY_RETRY_DELAYS):
            time.sleep(BACKUP_KEY_RETRY_DELAYS[attempt])
    raise BackupError("backup_authentication_key_unavailable")


def canonical(value: dict) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        offset += os.write(descriptor, data[offset:])


def file_hash(path: Path) -> tuple[int, str]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise BackupError("backup_file_untrusted")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise BackupError("backup_file_changed")
        return opened.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def trusted_finder_metadata(path: Path) -> bool:
    metadata = path.lstat()
    return (path.name == ".DS_Store" and stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1 and metadata.st_uid == os.getuid()
            and metadata.st_size <= 1024 * 1024 and not metadata.st_mode & 0o022)


def inventory(bundles: Path) -> list[dict[str, str | int]]:
    records: list[dict[str, str | int]] = []
    if not stat.S_ISDIR(bundles.lstat().st_mode):
        raise BackupError("backup_bundle_root_invalid")
    entries = {item.name: item for item in bundles.iterdir()}
    expected = {f"{name}.pvm" for name in NAMES}
    if set(entries) - {".DS_Store"} != expected:
        raise BackupError("backup_bundle_set_invalid")
    if ".DS_Store" in entries and not trusted_finder_metadata(entries[".DS_Store"]):
        raise BackupError("backup_bundle_set_invalid")
    for name in NAMES:
        root = bundles / f"{name}.pvm"
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise BackupError("backup_bundle_invalid")
        for directory, subdirs, files in os.walk(root, followlinks=False):
            subdirs.sort()
            files.sort()
            directory_path = Path(directory)
            directory_info = directory_path.lstat()
            records.append({"kind": "directory", "path": directory_path.relative_to(bundles).as_posix(),
                            "mode": stat.S_IMODE(directory_info.st_mode),
                            "uid": directory_info.st_uid, "gid": directory_info.st_gid})
            for entry in subdirs:
                if not stat.S_ISDIR((Path(directory) / entry).lstat().st_mode):
                    raise BackupError("backup_directory_untrusted")
            for entry in files:
                path = Path(directory) / entry
                size, digest = file_hash(path)
                info = path.lstat()
                relative = path.relative_to(bundles).as_posix()
                records.append({"kind": "file", "path": relative, "bytes": size, "sha256": digest,
                                "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid})
                if len(records) > MAX_FILES:
                    raise BackupError("backup_file_count_exceeded")
    return records


def host_config_inventory(config: Path) -> list[dict[str, str | int]]:
    if config.is_symlink() or not stat.S_ISDIR(config.lstat().st_mode):
        raise BackupError("backup_host_config_untrusted")
    records = []
    for name in HOST_CONFIG_FILES:
        path = config / name
        size, digest = file_hash(path)
        if size > 1024 * 1024:
            raise BackupError("backup_host_config_oversized")
        info = path.lstat()
        records.append({"path": name, "bytes": size, "sha256": digest,
                        "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid})
    return records


def fsync_files(bundles: Path, records: list[dict[str, str | int]]) -> None:
    for record in records:
        if record["kind"] != "file":
            continue
        descriptor = os.open(bundles / str(record["path"]), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def authenticated_manifest(generation: str, files: list[dict], host_files: list[dict], vm_uuids: dict[str, str],
                           volume_uuid: str, key: bytes) -> dict:
    if (UUID_RE.fullmatch(generation) is None or len(key) < 32
            or UUID_RE.fullmatch(volume_uuid.lower()) is None
            or set(vm_uuids) != set(NAMES)
            or any(UUID_RE.fullmatch(value) is None for value in vm_uuids.values())):
        raise BackupError("backup_manifest_identity_invalid")
    body = {"schema": SCHEMA, "generation_id": generation, "volume_uuid": volume_uuid,
            "vm_uuids": vm_uuids, "files": files, "host_files": host_files,
            "file_count": sum(item["kind"] == "file" for item in files) + len(host_files),
            "logical_bytes": (sum(int(item["bytes"]) for item in files if item["kind"] == "file")
                              + sum(int(item["bytes"]) for item in host_files))}
    digest = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    return {**body, "manifest_hmac_sha256": digest}


def read_authenticated_manifest(generation_dir: Path, key: bytes, expected_generation: str) -> dict:
    if len(key) < 32:
        raise BackupError("backup_authentication_key_invalid")
    manifest_path = generation_dir / "manifest.json"
    info = manifest_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES or info.st_nlink != 1:
        raise BackupError("backup_manifest_file_invalid")
    descriptor = os.open(manifest_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise BackupError("backup_manifest_changed")
        chunks = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != opened.st_size:
            raise BackupError("backup_manifest_changed")
    finally:
        os.close(descriptor)
    value = json.loads(payload)
    if (not isinstance(value, dict) or value.get("schema") != SCHEMA
            or value.get("generation_id") != expected_generation
            or not isinstance(value.get("manifest_hmac_sha256"), str)):
        raise BackupError("backup_manifest_invalid")
    recorded = value.pop("manifest_hmac_sha256")
    expected = hmac.new(key, canonical(value), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(recorded, expected):
        raise BackupError("backup_manifest_authentication_failed")
    value["manifest_hmac_sha256"] = recorded
    return value


def verify_manifest(generation_dir: Path, key: bytes, expected_generation: str) -> dict:
    value = read_authenticated_manifest(generation_dir, key, expected_generation)
    verify_backup_files(generation_dir, value)
    return value


def verify_backup_files(generation_dir: Path, value: dict) -> None:
    if (value.get("files") != inventory(generation_dir / "vms")
            or value.get("host_files") != host_config_inventory(generation_dir / "host-config")
            or set(item.name for item in (generation_dir / "host-config").iterdir()) != set(HOST_CONFIG_FILES)):
        raise BackupError("backup_content_changed")


def verify_backup_metadata(generation_dir: Path, key: bytes) -> dict:
    prefix = "secure-sandbox-backup-"
    if not generation_dir.name.startswith(prefix) or not stat.S_ISDIR(generation_dir.lstat().st_mode):
        raise BackupError("backup_generation_name_invalid")
    generation = generation_dir.name[len(prefix):]
    entries = {item.name: item for item in generation_dir.iterdir()}
    if (UUID_RE.fullmatch(generation) is None
            or set(entries) - {".DS_Store"} != {"vms", "host-config", "manifest.json", "COMPLETE"}
            or (".DS_Store" in entries and not trusted_finder_metadata(entries[".DS_Store"]))):
        raise BackupError("backup_generation_incomplete")
    manifest = read_authenticated_manifest(generation_dir, key, generation)
    marker_path = generation_dir / "COMPLETE"
    marker_info = marker_path.lstat()
    if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_size != 65 or marker_info.st_nlink != 1:
        raise BackupError("backup_completion_marker_invalid")
    marker_descriptor = os.open(marker_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        marker = os.read(marker_descriptor, 66).decode("ascii", "strict")
    finally:
        os.close(marker_descriptor)
    if marker != manifest["manifest_hmac_sha256"] + "\n":
        raise BackupError("backup_completion_marker_invalid")
    return manifest


def verify_backup(generation_dir: Path, key: bytes) -> dict:
    manifest = verify_backup_metadata(generation_dir, key)
    verify_backup_files(generation_dir, manifest)
    return manifest


def copy_bundle(source: Path, destination: Path) -> None:
    result = subprocess.run(["/usr/bin/ditto", str(source), str(destination)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            check=False, timeout=3600)
    if result.returncode:
        raise BackupError("backup_bundle_copy_failed")


def create_backup(source_vms: Path, source_config: Path, destination: Path,
                  vm_uuids: dict[str, str], volume_uuid: str, key: bytes,
                  copier: Callable[[Path, Path], None] = copy_bundle,
                  file_copier: Callable[[Path, Path], None] = shutil.copy2,
                  generation: str | None = None) -> dict:
    generation = generation or str(uuid.uuid4())
    if UUID_RE.fullmatch(generation) is None:
        raise BackupError("backup_generation_identity_invalid")
    stage = destination / f".secure-sandbox-backup-{generation}.incomplete"
    published = destination / f"secure-sandbox-backup-{generation}"
    if stage.exists() or published.exists():
        raise BackupError("backup_generation_collision")
    source_files = inventory(source_vms)
    source_host_files = host_config_inventory(source_config)
    stage.mkdir(mode=0o700)
    try:
        (stage / "vms").mkdir(mode=0o700)
        for name in NAMES:
            source = source_vms / f"{name}.pvm"
            if not stat.S_ISDIR(source.lstat().st_mode):
                raise BackupError("backup_source_missing")
            copier(source, stage / "vms" / source.name)
        (stage / "host-config").mkdir(mode=0o700)
        for name in HOST_CONFIG_FILES:
            file_copier(source_config / name, stage / "host-config" / name)
        files = inventory(stage / "vms")
        host_files = host_config_inventory(stage / "host-config")
        if (files != source_files or inventory(source_vms) != source_files
                or host_files != source_host_files
                or host_config_inventory(source_config) != source_host_files):
            raise BackupError("backup_source_or_copy_changed")
        fsync_files(stage / "vms", files)
        for name in HOST_CONFIG_FILES:
            descriptor = os.open(stage / "host-config" / name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        manifest = authenticated_manifest(generation, files, host_files, vm_uuids, volume_uuid, key)
        payload = canonical(manifest)
        if len(payload) > MAX_MANIFEST_BYTES:
            raise BackupError("backup_manifest_too_large")
        descriptor = os.open(stage / "manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        verify_manifest(stage, key, generation)
        marker = os.open(stage / "COMPLETE", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            write_all(marker, (manifest["manifest_hmac_sha256"] + "\n").encode("ascii"))
            os.fsync(marker)
        finally:
            os.close(marker)
        for record in reversed(files):
            if record["kind"] == "directory":
                fsync_directory(stage / "vms" / str(record["path"]))
        fsync_directory(stage / "vms")
        fsync_directory(stage / "host-config")
        fsync_directory(stage)
        os.replace(stage, published)
        fsync_directory(destination)
        verify_backup(published, key)
        return {"generation_id": generation, "path": str(published),
                "file_count": manifest["file_count"], "logical_bytes": manifest["logical_bytes"],
                "manifest_hmac_sha256": manifest["manifest_hmac_sha256"]}
    except BaseException:
        # An interrupted generation stays visibly incomplete for inspection.
        raise


def backup_status(destination: Path, generation: str, key: bytes) -> dict[str, str | int]:
    if UUID_RE.fullmatch(generation) is None:
        raise BackupError("backup_generation_identity_invalid")
    published = destination / f"secure-sandbox-backup-{generation}"
    stage = destination / f".secure-sandbox-backup-{generation}.incomplete"
    if published.exists() and stage.exists():
        raise BackupError("backup_generation_ambiguous")
    if published.exists():
        value = verify_backup(published, key)
        return {"generation_id": generation, "state": "verified", "path": str(published),
                "file_count": value["file_count"], "logical_bytes": value["logical_bytes"]}
    if stage.exists():
        return {"generation_id": generation, "state": "incomplete", "path": str(stage)}
    return {"generation_id": generation, "state": "missing"}
