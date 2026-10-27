#!/usr/bin/env python3
"""Build a content-bound, read-only plan for preserving quarantined VM data."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
VM_MAINTENANCE = ROOT / "scripts/vm-maintenance.py"
GENERATION = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
VM_UUID = re.compile(rb"<VmUuid>(\{[0-9a-fA-F-]{36}\})</VmUuid>")
ROLE_BUNDLES = {
    "gateway": "SecureSandbox-Gateway.pvm",
    "research": "SecureSandbox-Research.pvm",
    "target": "SecureSandbox-Target.pvm",
}
TOOL_PATHS = {
    "control_policy": ROOT / "scripts/privileged_control.py",
    "deployment": ROOT / "scripts/install-legacy-preservation.sh",
    "exporter": ROOT / "scripts/legacy-guest-export.py",
    "guest_preserver": ROOT / "scripts/legacy_guest_preserver.py",
    "archive_verifier": ROOT / "scripts/verify-legacy-archive.py",
    "continuity_planner": ROOT / "scripts/plan-legacy-continuity-import.py",
    "continuity_importer": ROOT / "scripts/import-legacy-continuity.py",
    "continuity_control": ROOT / "scripts/legacy_continuity_control.py",
    "session_registry": ROOT / "research/session_registry.py",
    "preservation_executor": ROOT / "scripts/legacy-vm-preservation.py",
    "preservation_planner": ROOT / "scripts/plan-legacy-vm-preservation.py",
}
MAX_DISK_ENTRIES = 4096
PROTECTED_CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
PROTECTED_SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
TRANSACTION_MAXIMUM = 64 * 1024
EXTENT_NAME = re.compile(r"^[A-Za-z0-9_.{}-]+\.hds$")


class PlanError(RuntimeError):
    pass


def load_maintenance():
    spec = importlib.util.spec_from_file_location("legacy_vm_maintenance", VM_MAINTENANCE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def sha256_regular(path: Path, maximum: int = 512 * 1024 * 1024) -> str:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size > maximum
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise PlanError(f"tool_untrusted:{path.name}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PlanError(f"tool_changed:{path.name}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def read_regular(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size > maximum
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise PlanError(f"file_untrusted:{path.name}")
        data = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data))):
            data.extend(chunk)
            if len(data) > maximum:
                raise PlanError(f"file_too_large:{path.name}")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PlanError(f"file_changed:{path.name}")
        return bytes(data)
    finally:
        os.close(descriptor)


def trusted_directory(path: Path, uid: int, label: str) -> os.stat_result:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != uid
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise PlanError(f"{label}_untrusted")
        return opened
    finally:
        os.close(descriptor)


def protected_hash(path: Path, expected_mode: int) -> str:
    resolved = path.resolve(strict=True)
    root = Path("/usr/local/libexec/secure-sandbox-host/releases")
    if not resolved.is_relative_to(root):
        raise PlanError(f"protected_path_invalid:{path.name}")
    info = resolved.lstat()
    if (not stat.S_ISREG(info.st_mode) or resolved.is_symlink() or info.st_uid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != expected_mode):
        raise PlanError(f"protected_file_untrusted:{path.name}")
    return sha256_regular(resolved)


def transport_identity(maintenance, name: str, expected_home: Path,
                       *, require_stopped: bool) -> dict[str, object]:
    values = json.loads(maintenance.run(
        [str(maintenance.PRLCTL), "list", "-a", "-i", "-j", name], capture=True
    ))
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise PlanError(f"transport_vm_invalid:{name}")
    value = values[0]
    identifier = maintenance.normalize_vm_uuid(value.get("ID"))
    home = Path(str(value.get("Home", "")).rstrip("/"))
    info = home.lstat()
    state = value.get("State")
    hardware = value.get("Hardware")
    if not isinstance(hardware, dict):
        raise PlanError(f"transport_vm_invalid:{name}")
    enabled_disks = {
        key: item for key, item in hardware.items()
        if key.startswith("hdd") and isinstance(item, dict) and item.get("enabled", True)
    }
    enabled_optical = [
        key for key, item in hardware.items()
        if key.startswith("cdrom") and isinstance(item, dict) and item.get("enabled", True)
    ]
    system_disk = enabled_disks.get("hdd0", {}).get("image")
    shared_folders = value.get("Host Shared Folders", {})
    smart_mount = value.get("SmartMount", {})
    miscellaneous = value.get("Miscellaneous Sharing", {})
    if (value.get("Name") != name or state not in {"running", "stopped", "paused", "suspended"}
            or (require_stopped and state != "stopped") or home.is_symlink()
            or not stat.S_ISDIR(info.st_mode) or home.resolve() != expected_home.resolve()
            or str(value.get("Boot order", "")).strip() != "hdd0"
            or set(enabled_disks) != {"hdd0"} or enabled_optical
            or not isinstance(system_disk, str)
            or Path(system_disk).resolve(strict=True).parent != home.resolve()
            or not isinstance(shared_folders, dict) or shared_folders.get("enabled") is not False
            or not isinstance(smart_mount, dict) or smart_mount.get("enabled") is not False
            or not isinstance(miscellaneous, dict)
            or miscellaneous.get("Shared clipboard mode") != "off"
            or miscellaneous.get("Shared cloud") != "off"):
        raise PlanError(f"transport_vm_invalid:{name}")
    return {
        "name": name, "uuid": identifier, "expected_home": str(expected_home),
        "state": state, "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
        "system_disk": str(Path(system_disk).resolve(strict=True)),
        "boot_order": "hdd0", "optical_devices": [],
        "host_shared_folders": False, "smart_mount": False,
        "shared_clipboard": "off", "shared_cloud": "off",
    }


def transaction_digest(path: Path, uid: int) -> str | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_size > TRANSACTION_MAXIMUM
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise PlanError("preservation_transaction_untrusted")
        data = bytearray()
        while chunk := os.read(descriptor, TRANSACTION_MAXIMUM + 1 - len(data)):
            data.extend(chunk)
            if len(data) > TRANSACTION_MAXIMUM:
                raise PlanError("preservation_transaction_untrusted")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PlanError("preservation_transaction_changed")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PlanError("preservation_transaction_invalid") from error
    if not isinstance(value, dict) or canonical(value) != bytes(data):
        raise PlanError("preservation_transaction_invalid")
    return hashlib.sha256(bytes(data)).hexdigest()


def disk_inventory(path: Path, uid: int) -> dict[str, object]:
    root = trusted_directory(path, uid, "legacy_disk")
    records: list[dict[str, object]] = []
    logical_bytes = 0
    allocated_bytes = 0
    stack = [path]
    while stack:
        current = stack.pop()
        info = current.lstat()
        try:
            relative = current.relative_to(path)
        except ValueError as error:
            raise PlanError("legacy_disk_escape") from error
        if current.is_symlink():
            raise PlanError("legacy_disk_symlink")
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "regular" if stat.S_ISREG(info.st_mode) else "other"
        if kind == "other" or info.st_uid != uid or (kind == "regular" and info.st_nlink != 1):
            raise PlanError("legacy_disk_entry_untrusted")
        record = {
            "kind": kind, "mode": stat.S_IMODE(info.st_mode), "mtime_ns": info.st_mtime_ns,
            "path_hex": os.fsencode(str(relative)).hex(), "size": info.st_size,
        }
        records.append(record)
        if len(records) > MAX_DISK_ENTRIES:
            raise PlanError("legacy_disk_entry_limit_exceeded")
        if kind == "regular":
            descriptor = os.open(current, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(descriptor)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                        or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)):
                    raise PlanError("legacy_disk_entry_changed")
                digest = hashlib.sha256()
                while chunk := os.read(descriptor, 4 * 1024 * 1024):
                    digest.update(chunk)
                after = os.fstat(descriptor)
                if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise PlanError("legacy_disk_entry_changed")
            finally:
                os.close(descriptor)
            record["sha256"] = digest.hexdigest()
            logical_bytes += info.st_size
            allocated_bytes += info.st_blocks * 512
        else:
            with os.scandir(current) as entries:
                children = sorted((Path(entry.path) for entry in entries), key=os.fsencode, reverse=True)
            stack.extend(children)
    identity = hashlib.sha256(canonical(records)).hexdigest()
    return {
        "allocated_bytes": allocated_bytes,
        "device": root.st_dev,
        "entries": len(records),
        "inode": root.st_ino,
        "logical_bytes": logical_bytes,
        "path": str(path),
        "tree_metadata_sha256": identity,
    }


def validate_disk_descriptor(disk: Path, descriptor: bytes, uid: int) -> list[str]:
    """Prove Parallels cannot resolve a descriptor extent outside this disk."""
    upper = descriptor.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise PlanError("legacy_disk_descriptor_unsafe")
    try:
        root = ET.fromstring(descriptor)
    except ET.ParseError as error:
        raise PlanError("legacy_disk_descriptor_invalid") from error
    references: list[str] = []
    for element in root.findall(".//Image/File"):
        value = element.text
        if (not isinstance(value, str) or not EXTENT_NAME.fullmatch(value)
                or Path(value).name != value):
            raise PlanError("legacy_disk_extent_reference_unsafe")
        references.append(value)
    if not references or len(references) != len(set(references)):
        raise PlanError("legacy_disk_extent_inventory_invalid")
    present = set()
    with os.scandir(disk) as entries:
        for entry in entries:
            if not entry.name.endswith(".hds"):
                continue
            info = entry.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                    or not EXTENT_NAME.fullmatch(entry.name)):
                raise PlanError("legacy_disk_extent_untrusted")
            present.add(entry.name)
    if set(references) != present:
        raise PlanError("legacy_disk_extent_inventory_invalid")
    return sorted(references)


def build_plan(repo_value: str, generation: str, uid: int, maintenance=None) -> dict[str, object]:
    if not GENERATION.fullmatch(generation):
        raise PlanError("generation_invalid")
    maintenance = load_maintenance() if maintenance is None else maintenance
    repo = maintenance.trusted_repo(repo_value, uid)
    quarantine = repo / ".private/vm-quarantine"
    generation_root = quarantine / generation
    trusted_directory(repo / ".private", uid, "private_directory")
    trusted_directory(quarantine, uid, "quarantine_directory")
    trusted_directory(generation_root, uid, "generation_directory")
    migration_root = repo / ".private/legacy-migration"
    migration_generation = migration_root / generation
    transaction_sha256 = None
    if migration_generation.exists():
        trusted_directory(migration_root, uid, "migration_directory")
        trusted_directory(migration_generation, uid, "migration_generation_directory")
        transaction_sha256 = transaction_digest(migration_generation / "transaction.json", uid)
    if maintenance.pending_transaction(repo, uid) is not None:
        raise PlanError("maintenance_recovery_required")
    transport_vms = {}
    for name in ("SecureSandbox-Gateway", "SecureSandbox-Research"):
        identity = transport_identity(
            maintenance, name, repo / f"vms/{name}.pvm",
            require_stopped=transaction_sha256 is None,
        )
        transport_vms[name] = identity
    sources = {}
    for role, bundle_name in ROLE_BUNDLES.items():
        bundle = generation_root / bundle_name
        bundle_info = trusted_directory(bundle, uid, f"legacy_bundle_{role}")
        disk_root = bundle / "harddisk1.hdd"
        disk = disk_inventory(disk_root, uid)
        descriptor_bytes = read_regular(disk_root / "DiskDescriptor.xml", 16 * 1024 * 1024)
        disk["extent_files"] = validate_disk_descriptor(disk_root, descriptor_bytes, uid)
        config = bundle / "config.pvs"
        config_bytes = read_regular(config, 16 * 1024 * 1024)
        match = VM_UUID.search(config_bytes)
        if (len(config_bytes) > 16 * 1024 * 1024 or match is None
                or len(VM_UUID.findall(config_bytes)) != 1):
            raise PlanError(f"legacy_config_invalid:{role}")
        sources[role] = {
            "bundle_device": bundle_info.st_dev,
            "bundle_inode": bundle_info.st_ino,
            "bundle_path": str(bundle),
            "config_sha256": sha256_regular(config, 16 * 1024 * 1024),
            "disk": disk,
            "disk_descriptor_sha256": sha256_regular(
                disk_root / "DiskDescriptor.xml", 16 * 1024 * 1024
            ),
            "legacy_vm_uuid": match.group(1).decode("ascii").lower(),
        }
    registered = json.loads(maintenance.run(
        [str(maintenance.PRLCTL), "list", "-a", "-j"], capture=True
    ))
    if not isinstance(registered, list) or any(not isinstance(item, dict) for item in registered):
        raise PlanError("registered_vm_inventory_invalid")
    registered_uuids = set()
    for item in registered:
        raw = item.get("uuid")
        try:
            registered_uuids.add(maintenance.normalize_vm_uuid(raw))
        except Exception as error:
            raise PlanError("registered_vm_inventory_invalid") from error
    if any(source["legacy_vm_uuid"] in registered_uuids for source in sources.values()):
        raise PlanError("legacy_vm_registered")
    tools = {name: sha256_regular(path) for name, path in TOOL_PATHS.items()}
    plan: dict[str, object] = {
        "free_bytes": os.statvfs(repo).f_bavail * os.statvfs(repo).f_frsize,
        "generation": generation,
        "invoking_uid": uid,
        "protected_control_client_sha256": protected_hash(PROTECTED_CLIENT, 0o755),
        "protected_ssh_config_sha256": protected_hash(PROTECTED_SSH_CONFIG, 0o444),
        "prlctl_sha256": maintenance.prlctl_hash(),
        "repo": str(repo),
        "transport_vms": transport_vms,
        "schema": "secure-sandbox-legacy-vm-preservation-plan-v1",
        "operation": "recover" if transaction_sha256 else "preserve",
        "sources": sources,
        "tools": tools,
    }
    if transaction_sha256:
        plan["recovery_transaction_sha256"] = transaction_sha256
    # Free space is a runtime safety observation, not a stable authorization
    # binding: creating the authorization request itself consumes blocks.
    # The executor independently enforces the reserve immediately before each
    # archive stream.
    bound_plan = dict(plan)
    bound_plan.pop("free_bytes")
    plan["plan_sha256"] = hashlib.sha256(canonical(bound_plan)).hexdigest()
    return plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(ROOT))
    parser.add_argument("--generation", required=True)
    parser.add_argument("--invoking-uid", type=int, default=os.geteuid())
    args = parser.parse_args()
    print(json.dumps(build_plan(args.repo, args.generation, args.invoking_uid), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PlanError, OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True), file=__import__("sys").stderr)
        raise SystemExit(1)
