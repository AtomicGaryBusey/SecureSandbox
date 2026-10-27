#!/usr/bin/env python3
"""Immutable planner/executor for the three SecureSandbox Parallels VMs."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import types
import uuid
from pathlib import Path
from typing import Any, Callable


SCHEMA = "secure-sandbox-vm-maintenance-plan-v1"
TRANSACTION_SCHEMA = "secure-sandbox-vm-reprovision-transaction-v1"
NAMES = ("SecureSandbox-Gateway", "SecureSandbox-Research", "SecureSandbox-Target")
ROLES = ("gateway", "research", "target")
INSTALLER_SHA256 = "c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804"
PRLCTL = Path("/Applications/Parallels Desktop.app/Contents/MacOS/prlctl")
MIN_FREE_BYTES = 30 * 1024 * 1024 * 1024
VM_UUID = re.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
PRL_JSON_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class MaintenanceError(RuntimeError):
    pass


def load_repo_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise MaintenanceError(f"repo_module_unavailable:{path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_bound_module(path: Path, expected_sha256: str, uid: int,
                      maximum: int = 16 * 1024 * 1024) -> bytes:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or opened.st_size > maximum or stat.S_IMODE(opened.st_mode) & 0o022
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise MaintenanceError(f"repo_module_untrusted:{path.name}")
        data = bytearray()
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            data.extend(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise MaintenanceError(f"repo_module_changed:{path.name}")
        if digest.hexdigest() != expected_sha256:
            raise MaintenanceError(f"repo_module_hash_mismatch:{path.name}")
        return bytes(data)
    finally:
        os.close(descriptor)


def execute_bound_module(name: str, path: Path, source: bytes):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def legacy_preservation_plan(repo_value: str, generation: str, uid: int) -> dict[str, Any]:
    repo = trusted_repo(repo_value, uid)
    planner = load_repo_module(
        "secure_sandbox_legacy_preservation_planner",
        repo / "scripts/plan-legacy-vm-preservation.py",
    )
    return planner.build_plan(str(repo), generation, uid, maintenance=sys.modules[__name__])


def canonical(value: Any) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def trusted_directory(path: Path, uid: int, *, create: bool = False) -> tuple[int, int]:
    if create:
        try:
            path.mkdir(mode=0o700)
            fsync_directory(path.parent)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError as error:
        raise MaintenanceError(f"maintenance_directory_untrusted:{path.name}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_nlink < 1:
            raise MaintenanceError(f"maintenance_directory_untrusted:{path.name}")
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise MaintenanceError(f"maintenance_directory_untrusted:{path.name}")
        return info.st_dev, info.st_ino
    finally:
        os.close(descriptor)


def assert_directory_identity(path: Path, identity: tuple[int, int], uid: int) -> None:
    if trusted_directory(path, uid) != identity:
        raise MaintenanceError(f"maintenance_directory_changed:{path.name}")


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = canonical(value)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def transaction_path(repo: Path) -> Path:
    return repo / ".private/vm-maintenance-transactions/reprovision.json"


def validate_transaction(repo: Path, value: Any, uid: int) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != {
            "schema", "repo", "plan_sha256", "quarantine", "originals",
            "unregistered", "displaced", "created",
        } or value.get("schema") != TRANSACTION_SCHEMA
            or value.get("repo") != str(repo) or not isinstance(value.get("plan_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["plan_sha256"])):
        raise MaintenanceError("maintenance_transaction_invalid")
    quarantine = Path(str(value.get("quarantine", "")))
    quarantine_root = repo / ".private/vm-quarantine"
    try:
        relative = quarantine.relative_to(quarantine_root)
    except ValueError as error:
        raise MaintenanceError("maintenance_transaction_invalid") from error
    originals = value.get("originals")
    created = value.get("created")
    unregistered = value.get("unregistered")
    displaced = value.get("displaced")
    if (len(relative.parts) != 1 or not isinstance(originals, list)
            or [item.get("name") for item in originals if isinstance(item, dict)] != list(NAMES)
            or not isinstance(created, list) or not isinstance(unregistered, list)
            or any(not isinstance(item, str) or not VM_UUID.fullmatch(item) for item in unregistered)
            or not isinstance(displaced, list) or any(item not in NAMES for item in displaced)):
        raise MaintenanceError("maintenance_transaction_invalid")
    for identity in [*originals, *created]:
        if (not isinstance(identity, dict) or identity.get("name") not in NAMES
                or not isinstance(identity.get("uuid"), str) or not VM_UUID.fullmatch(identity["uuid"])
                or identity.get("expected_home") != str(repo / f"vms/{identity.get('name')}.pvm")
                or not isinstance(identity.get("bundle_device"), int)
                or not isinstance(identity.get("bundle_inode"), int)):
            raise MaintenanceError("maintenance_transaction_invalid")
    if (len({item["uuid"] for item in originals}) != len(originals)
            or len({item["uuid"] for item in created}) != len(created)
            or len(set(unregistered)) != len(unregistered)
            or len(set(displaced)) != len(displaced)):
        raise MaintenanceError("maintenance_transaction_invalid")
    return value


def pending_transaction(repo: Path, uid: int) -> dict[str, Any] | None:
    path = transaction_path(repo)
    if not path.exists():
        return None
    private = repo / ".private"
    transactions = path.parent
    trusted_directory(private, uid)
    trusted_directory(transactions, uid)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 64 * 1024):
            raise MaintenanceError("maintenance_transaction_untrusted")
        data = bytearray()
        while chunk := os.read(descriptor, 64 * 1024 + 1 - len(data)):
            data.extend(chunk)
            if len(data) > 64 * 1024:
                raise MaintenanceError("maintenance_transaction_untrusted")
        after = os.fstat(descriptor)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise MaintenanceError("maintenance_transaction_changed")
    finally:
        os.close(descriptor)
    value = json.loads(bytes(data).decode("utf-8"))
    return validate_transaction(repo, value, uid)


def sha256_regular(path: Path, maximum: int = 16 * 1024 * 1024 * 1024) -> str:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size > maximum
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise MaintenanceError(f"untrusted_file:{path.name}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise MaintenanceError(f"file_changed_during_read:{path.name}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def run(command: list[str], *, capture: bool = False) -> str:
    result = subprocess.run(
        command, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None, text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"]},
    )
    if result.returncode:
        detail = (result.stderr or "").strip()
        raise MaintenanceError(f"command_failed:{Path(command[0]).name}:{detail[:400]}")
    return result.stdout if capture else ""


def trusted_repo(value: str, uid: int) -> Path:
    repo = Path(value)
    info = repo.lstat()
    home = Path(pwd.getpwuid(uid).pw_dir).resolve(strict=True)
    resolved = repo.resolve(strict=True)
    if (not repo.is_absolute() or repo.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid or not resolved.is_relative_to(home)):
        raise MaintenanceError("repository_untrusted")
    return resolved


def protected_helpers() -> tuple[Path, Path]:
    release = Path(__file__).resolve(strict=True).parent
    return release / "installer_verifier", release / "seed_verifier"


def protected_seed_paths() -> dict[str, Path]:
    release = Path(__file__).resolve(strict=True).parent
    return {role: release / f"seed_{role}" for role in ROLES}


def installer_path(repo: Path) -> Path:
    verifier, _ = protected_helpers()
    output = run([
        "/usr/bin/python3", "-I", str(verifier), "--release-directory",
        str(repo / "artifacts/ubuntu-26.04.1"), "--use-promoted-autoinstall", "--path-only",
    ], capture=True).strip()
    path = Path(output)
    expected = Path("/Library/Application Support/SecureSandbox/installers") / f"{INSTALLER_SHA256}.iso"
    if path != expected:
        raise MaintenanceError("protected_installer_path_invalid")
    return path


def seed_hashes(repo: Path) -> dict[str, str]:
    _, verifier = protected_helpers()
    values: dict[str, str] = {}
    for role, seed in protected_seed_paths().items():
        run([str(verifier), role, str(seed), "--repo", str(repo), "--protected-source"], capture=True)
        values[role] = sha256_regular(seed, 16 * 1024 * 1024)
    return values


def prlctl_hash() -> str:
    info = PRLCTL.lstat()
    if (PRLCTL.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise MaintenanceError("prlctl_untrusted")
    return sha256_regular(PRLCTL, 1024 * 1024 * 1024)


def normalize_vm_uuid(value: Any) -> str:
    """Normalize Parallels JSON's bare UUID to the braced transaction form."""
    if not isinstance(value, str):
        raise MaintenanceError("vm_uuid_invalid")
    if VM_UUID.fullmatch(value):
        return value.lower()
    if PRL_JSON_UUID.fullmatch(value):
        return "{" + value.lower() + "}"
    raise MaintenanceError("vm_uuid_invalid")


def vm_identity(selector: str, expected_home: Path) -> dict[str, Any]:
    values = json.loads(run([str(PRLCTL), "list", "-a", "-i", "-j", selector], capture=True))
    if not isinstance(values, list) or len(values) != 1:
        raise MaintenanceError(f"vm_inventory_invalid:{selector}")
    value = values[0]
    name = value.get("Name")
    try:
        identifier = normalize_vm_uuid(value.get("ID"))
    except MaintenanceError as error:
        raise MaintenanceError(f"vm_identity_untrusted:{selector}") from error
    state = value.get("State")
    home = Path(str(value.get("Home", "")).rstrip("/"))
    try:
        info = home.lstat()
    except OSError as error:
        raise MaintenanceError(f"vm_home_untrusted:{selector}") from error
    if (not isinstance(name, str)
            or state != "stopped" or home.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or home.resolve() != expected_home.resolve()):
        raise MaintenanceError(f"vm_identity_untrusted:{selector}")
    return {
        "name": name, "uuid": identifier.lower(), "expected_home": str(expected_home),
        "state": state, "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
    }


def same_vm_identity(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(actual.get(key) == expected.get(key) for key in (
        "name", "uuid", "expected_home", "state", "bundle_device", "bundle_inode",
    ))


def vm_inventory(repo: Path, operation: str) -> list[dict[str, Any]]:
    listing = run([str(PRLCTL), "list", "--all", "--no-header", "--output", "name"], capture=True)
    present = set(listing.splitlines())
    result: list[dict[str, str]] = []
    for name in NAMES:
        expected = repo / f"vms/{name}.pvm"
        if operation == "create":
            if name in present:
                raise MaintenanceError(f"vm_already_exists:{name}")
            result.append({"name": name, "expected_home": str(expected), "state": "absent"})
            continue
        if name not in present:
            raise MaintenanceError(f"vm_missing:{name}")
        identity = vm_identity(name, expected)
        if identity["name"] != name:
            raise MaintenanceError(f"vm_identity_untrusted:{name}")
        result.append(identity)
    return result


def build_plan(repo_value: str, operation: str, uid: int) -> dict[str, Any]:
    repo = trusted_repo(repo_value, uid)
    vms_directory = repo / "vms"
    if vms_directory.exists():
        info = vms_directory.lstat()
        if (vms_directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != uid):
            raise MaintenanceError("vm_directory_untrusted")
    installer = installer_path(repo)
    seeds = seed_hashes(repo)
    transaction = pending_transaction(repo, uid)
    if transaction is not None and operation != "reprovision":
        raise MaintenanceError("maintenance_recovery_required")
    if transaction is None:
        vms = vm_inventory(repo, operation)
        if operation == "reprovision" and shutil.disk_usage(repo).free < MIN_FREE_BYTES:
            raise MaintenanceError("insufficient_recoverable_storage")
    else:
        vms = transaction["originals"]
    plan = {
        "schema": SCHEMA, "operation": operation, "invoking_uid": uid,
        "repo": str(repo), "installer_path": str(installer),
        "installer_sha256": INSTALLER_SHA256, "prlctl_path": str(PRLCTL),
        "prlctl_sha256": prlctl_hash(), "seed_sha256": seeds, "vms": vms,
    }
    if transaction is not None:
        plan["recovery_transaction_sha256"] = hashlib.sha256(canonical(transaction)).hexdigest()
    plan["plan_sha256"] = hashlib.sha256(canonical(plan)).hexdigest()
    return plan


def validate_plan_bindings(plan: dict[str, Any], expected_plan_sha256: str,
                           expected_components: dict[str, Any]) -> None:
    if plan["plan_sha256"] != expected_plan_sha256:
        raise MaintenanceError("maintenance_plan_changed")
    if any(plan[name] != expected for name, expected in expected_components.items()):
        raise MaintenanceError("maintenance_component_binding_changed")


def drop_privileges(uid: int) -> None:
    if os.geteuid() != 0 or uid <= 0:
        raise MaintenanceError("root_broker_required")
    account = pwd.getpwuid(uid)
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(uid)
    os.environ.clear()
    os.environ.update({"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": account.pw_dir,
                       "USER": account.pw_name, "LOGNAME": account.pw_name})
    if os.geteuid() != uid or os.getuid() != uid:
        raise MaintenanceError("privilege_drop_failed")
    try:
        os.setuid(0)
    except OSError:
        return
    raise MaintenanceError("privilege_drop_reversible")


def set_vm(identifier: str, *arguments: str) -> None:
    run([str(PRLCTL), "set", identifier, *arguments])


def create_one(repo: Path, name: str, cpus: int, memory: int, disk: int,
               seed: Path, installer: Path, created: list[dict[str, Any]],
               on_created: Callable[[dict[str, Any]], None] | None = None) -> str:
    run([str(PRLCTL), "create", name, "--distribution", "ubuntu", "--dst", str(repo / "vms"), "--no-hdd"])
    identity = vm_identity(name, repo / f"vms/{name}.pvm")
    if identity["name"] != name:
        raise MaintenanceError(f"created_vm_identity_invalid:{name}")
    created.append(identity)
    # Persist ownership of the new VM before the first configuration mutation.
    # A crash from this point forward must leave recovery enough identity to
    # distinguish our VM from an unknown same-named registration.
    if on_created:
        on_created(identity)
    identifier = identity["uuid"]
    for args in [
        ("--description", "SecureSandbox disposable Ubuntu ARM64 lab VM"),
        ("--cpus", str(cpus)), ("--memsize", str(memory)),
        ("--device-add", "hdd", "--type", "expand", "--size", str(disk), "--iface", "sata"),
        ("--device-set", "cdrom0", "--image", str(installer), "--connect"),
        ("--device-add", "cdrom", "--image", str(seed), "--iface", "sata", "--connect"),
        ("--device-bootorder", "cdrom0 cdrom1 hdd0"),
        ("--bios-type", "efi-arm64", "--efi-secure-boot", "on", "--select-boot-device", "off"),
        ("--isolate-vm", "on"),
        ("--shf-host", "off", "--shf-host-defined", "off", "--shf-host-automount", "off"),
        ("--shf-guest", "off", "--shf-guest-automount", "off"),
        ("--shf-guest-automount-cloud-drives", "off", "--shf-guest-automount-network-drives", "off", "--shf-guest-automount-removable-drives", "off"),
        ("--shared-profile", "off"),
        ("--sh-app-host-to-guest", "off", "--sh-app-guest-to-host", "off"),
        ("--show-guest-app-folder-in-dock", "off", "--bounce-dock-icon-when-app-flashes", "off"),
        ("--smart-mount", "off", "--smart-mount-removable-drives", "off", "--smart-mount-dvd-drives", "off", "--smart-mount-network-shares", "off"),
        ("--shared-clipboard", "off", "--shared-cloud", "off"),
        ("--sync-vm-hostname", "off", "--sync-ssh-ids", "off"),
        ("--show-dev-tools", "off", "--share-host-location", "off", "--rosetta-linux", "off"),
        ("--auto-share-camera", "off", "--auto-share-smart-card", "off", "--support-usb30", "off"),
        ("--auto-share-gamepad", "off"),
        ("--sync-host-printers", "off", "--sync-default-printer", "off", "--show-host-printer-ui", "off"),
        ("--nested-virt", "off", "--pmu-virt", "off", "--battery-status", "off"),
        ("--3d-accelerate", "off", "--vertical-sync", "off"),
        ("--high-resolution", "off", "--high-resolution-in-guest", "off", "--native-scaling-in-guest", "off"),
        ("--time-sync", "off", "--disable-timezone-sync", "on"),
        ("--autostart", "off", "--autostop", "stop", "--on-window-close", "ask"),
        ("--tools-autoupdate", "no", "--usedefanswers", "off"),
        ("--device-del", "usb"), ("--device-del", "sound0"), ("--device-del", "serial0"),
    ]:
        set_vm(identifier, *args)
    return identifier


def create_all(repo: Path, installer: Path,
               on_created: Callable[[dict[str, Any]], None] | None = None) -> dict[str, dict[str, Any]]:
    (repo / "vms").mkdir(parents=True, exist_ok=True)
    seeds = protected_seed_paths()
    created: list[dict[str, Any]] = []
    try:
        gateway = create_one(repo, NAMES[0], 1, 2048, 12288, seeds["gateway"], installer, created, on_created)
        set_vm(gateway, "--device-add", "net", "--type", "host-only", "--iface", "control-net", "--adapter-type", "virtio")
        research = create_one(repo, NAMES[1], 4, 6144, 51200, seeds["research"], installer, created, on_created)
        set_vm(research, "--device-add", "net", "--type", "host-only", "--iface", "control-net", "--adapter-type", "virtio")
        set_vm(research, "--device-add", "net", "--type", "host-only", "--iface", "lab-net", "--adapter-type", "virtio")
        set_vm(research, "--device-del", "net0")
        target = create_one(repo, NAMES[2], 2, 4096, 40960, seeds["target"], installer, created, on_created)
        set_vm(target, "--device-add", "net", "--type", "host-only", "--iface", "lab-net", "--adapter-type", "virtio")
        set_vm(target, "--device-del", "net0")
        for identifier in (gateway, research, target):
            set_vm(identifier, "--auto-share-gamepad", "off")
        identities = {identity["name"]: identity for identity in created}
        verify_created(repo, installer, identities)
        return identities
    except BaseException:
        for identity in reversed(created):
            try:
                actual = vm_identity(identity["uuid"], Path(identity["expected_home"]))
            except (MaintenanceError, OSError, ValueError, json.JSONDecodeError):
                continue
            if not same_vm_identity(actual, identity):
                continue
            subprocess.run([str(PRLCTL), "stop", identity["uuid"], "--kill"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([str(PRLCTL), "delete", identity["uuid"]], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise


def verify_created(repo: Path, installer: Path, identities: dict[str, dict[str, Any]]) -> None:
    expected_networks = {
        NAMES[0]: ["host:control-net", "shared:"],
        NAMES[1]: ["host:control-net", "host:lab-net"],
        NAMES[2]: ["host:lab-net"],
    }
    for name, role in zip(NAMES, ROLES, strict=True):
        identity = identities[name]
        actual = vm_identity(identity["uuid"], Path(identity["expected_home"]))
        if not same_vm_identity(actual, identity):
            raise MaintenanceError(f"effective_identity_changed:{name}")
        values = json.loads(run([str(PRLCTL), "list", "-a", "-i", "-j", identity["uuid"]], capture=True))
        if not isinstance(values, list) or len(values) != 1:
            raise MaintenanceError(f"effective_configuration_invalid:{name}")
        value = values[0]
        hardware = value.get("Hardware", {})
        networks = sorted(
            f"{device.get('type', '')}:{device.get('iface') or ''}"
            for key, device in hardware.items()
            if key.startswith("net") and isinstance(device, dict) and device.get("enabled", True)
        )
        sharing = value.get("USB and Bluetooth", {})
        expected_seed = str(protected_seed_paths()[role])
        if (value.get("State") != "stopped" or networks != expected_networks[name]
                or hardware.get("cdrom0", {}).get("image") != str(installer)
                or hardware.get("cdrom1", {}).get("image") != expected_seed
                or any(sharing.get(label) != "off" for label in (
                    "Automatic sharing cameras", "Automatic sharing bluetooth",
                    "Automatic sharing smart cards", "Automatic sharing gamepads",
                    "Support USB 3.0",
                ))
                or any(key in hardware for key in ("usb", "sound0", "serial0"))):
            raise MaintenanceError(f"effective_configuration_invalid:{name}")


def maintenance_directories(repo: Path, uid: int) -> dict[str, tuple[Path, tuple[int, int]]]:
    paths = {
        "private": repo / ".private",
        "locks": repo / ".private/locks",
        "quarantine": repo / ".private/vm-quarantine",
        "transactions": repo / ".private/vm-maintenance-transactions",
    }
    values: dict[str, tuple[Path, tuple[int, int]]] = {}
    for path in paths.values():
        trusted_directory(path, uid, create=True)
    # Creating nested state directories intentionally changes the parent's
    # link count on some filesystems. Capture every exact identity only after
    # the complete fixed directory set exists.
    for name, path in paths.items():
        values[name] = (path, trusted_directory(path, uid))
    return values


def acquire_maintenance_lock(repo: Path, uid: int) -> tuple[int, dict[str, tuple[Path, tuple[int, int]]]]:
    directories = maintenance_directories(repo, uid)
    path = directories["locks"][0] / "reprovision.lock"
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(descriptor)
        raise MaintenanceError("maintenance_lock_untrusted")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise MaintenanceError("maintenance_in_progress") from error
    return descriptor, directories


def current_vm_names() -> set[str]:
    return set(run([str(PRLCTL), "list", "--all", "--no-header", "--output", "name"], capture=True).splitlines())


def recover_transaction(repo: Path, transaction: dict[str, Any], uid: int,
                        directories: dict[str, tuple[Path, tuple[int, int]]]) -> Path:
    path = transaction_path(repo)
    quarantine = Path(transaction["quarantine"])
    quarantine_identity = trusted_directory(quarantine, uid)
    for directory, identity in directories.values():
        assert_directory_identity(directory, identity, uid)

    for created in reversed(transaction["created"]):
        try:
            actual = vm_identity(created["uuid"], Path(created["expected_home"]))
        except MaintenanceError as error:
            if "command_failed:prlctl" in str(error) or "vm_inventory_invalid" in str(error):
                continue
            raise
        if not same_vm_identity(actual, created):
            raise MaintenanceError(f"recovery_created_identity_changed:{created['name']}")
        run([str(PRLCTL), "delete", created["uuid"]])

    for original in transaction["originals"]:
        name = original["name"]
        destination = repo / f"vms/{name}.pvm"
        source = quarantine / destination.name
        if destination.exists():
            info = destination.lstat()
            if (destination.is_symlink() or not stat.S_ISDIR(info.st_mode)
                    or (info.st_dev, info.st_ino) != (original["bundle_device"], original["bundle_inode"])):
                raise MaintenanceError(f"recovery_destination_occupied:{name}")
        elif source.exists():
            info = source.lstat()
            if (source.is_symlink() or not stat.S_ISDIR(info.st_mode)
                    or (info.st_dev, info.st_ino) != (original["bundle_device"], original["bundle_inode"])):
                raise MaintenanceError(f"recovery_quarantine_identity_changed:{name}")
            assert_directory_identity(quarantine, quarantine_identity, uid)
            source.rename(destination)
            fsync_directory(destination.parent)
            fsync_directory(quarantine)
            quarantine_identity = trusted_directory(quarantine, uid)
        else:
            raise MaintenanceError(f"recovery_original_missing:{name}")

        try:
            actual = vm_identity(original["uuid"], destination)
        except MaintenanceError:
            if name in current_vm_names():
                raise MaintenanceError(f"recovery_name_collision:{name}")
            run([str(PRLCTL), "register", str(destination), "--preserve-uuid"])
            actual = vm_identity(original["uuid"], destination)
        if not same_vm_identity(actual, original):
            raise MaintenanceError(f"recovery_original_identity_changed:{name}")

    path.unlink()
    fsync_directory(path.parent)
    return quarantine


def reprovision(repo: Path, installer: Path, expected_vms: list[dict[str, Any]],
                plan_sha256: str, uid: int) -> tuple[Path, bool]:
    lock_descriptor, directories = acquire_maintenance_lock(repo, uid)
    try:
        existing = pending_transaction(repo, uid)
        if existing is not None:
            return recover_transaction(repo, existing, uid, directories), True
        quarantine = directories["quarantine"][0] / (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + str(uuid.uuid4())
        )
        quarantine.mkdir(mode=0o700)
        fsync_directory(quarantine.parent)
        # Creating the transaction-specific child changes a directory's link
        # count on filesystems that expose subdirectory links. Rebind the exact
        # trusted identity after that intentional change.
        directories["quarantine"] = (
            directories["quarantine"][0],
            trusted_directory(directories["quarantine"][0], uid),
        )
        transaction = {
            "schema": TRANSACTION_SCHEMA, "repo": str(repo), "plan_sha256": plan_sha256,
            "quarantine": str(quarantine), "originals": expected_vms,
            "unregistered": [], "displaced": [], "created": [],
        }
        atomic_json(transaction_path(repo), transaction)

        def record_created(identity: dict[str, Any]) -> None:
            transaction["created"].append(identity)
            atomic_json(transaction_path(repo), transaction)

        try:
            for expected in expected_vms:
                name = expected["name"]
                source = repo / f"vms/{name}.pvm"
                actual = vm_identity(expected["uuid"], source)
                if not same_vm_identity(actual, expected):
                    raise MaintenanceError(f"vm_identity_changed:{name}")
                run([str(PRLCTL), "unregister", expected["uuid"]])
                transaction["unregistered"].append(expected["uuid"])
                atomic_json(transaction_path(repo), transaction)
                # Unregistration is an external state transition. Revalidate
                # the bundle immediately before moving it so a same-UID path
                # substitution cannot be quarantined under the old identity.
                post_unregister = source.lstat()
                if (source.is_symlink() or not stat.S_ISDIR(post_unregister.st_mode)
                        or (post_unregister.st_dev, post_unregister.st_ino) !=
                        (expected["bundle_device"], expected["bundle_inode"])):
                    raise MaintenanceError(f"vm_bundle_identity_changed:{name}")
                source.rename(quarantine / source.name)
                fsync_directory(source.parent)
                fsync_directory(quarantine)
                directories["quarantine"] = (
                    directories["quarantine"][0],
                    trusted_directory(directories["quarantine"][0], uid),
                )
                transaction["displaced"].append(name)
                atomic_json(transaction_path(repo), transaction)
            create_all(repo, installer, record_created)
        except BaseException as primary:
            try:
                recover_transaction(repo, transaction, uid, directories)
            except BaseException as recovery:
                raise MaintenanceError(
                    f"reprovision_failed_recovery_incomplete:{primary}:{recovery}"
                ) from primary
            raise
        transaction_path(repo).unlink()
        fsync_directory(transaction_path(repo).parent)
        return quarantine, False
    finally:
        os.close(lock_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=(
        "plan-create", "plan-reprovision", "create", "reprovision",
        "plan-preserve-legacy", "preserve-legacy",
    ))
    parser.add_argument("--repo", required=True)
    parser.add_argument("--invoking-uid", type=int, default=os.getuid())
    parser.add_argument("--generation")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--expected-prlctl-sha256")
    parser.add_argument("--expected-installer-sha256")
    parser.add_argument("--expected-seed-gateway-sha256")
    parser.add_argument("--expected-seed-research-sha256")
    parser.add_argument("--expected-seed-target-sha256")
    parser.add_argument("--expected-preservation-planner-sha256")
    parser.add_argument("--expected-preservation-executor-sha256")
    args = parser.parse_args()
    operation = args.operation.removeprefix("plan-")
    try:
        if operation == "preserve-legacy":
            if not args.generation:
                raise MaintenanceError("legacy_generation_required")
            if args.operation.startswith("plan-"):
                print(json.dumps(
                    legacy_preservation_plan(args.repo, args.generation, args.invoking_uid),
                    sort_keys=True,
                ))
                return 0
            if not args.expected_plan_sha256:
                raise MaintenanceError("expected_plan_bindings_required")
            if (not args.expected_preservation_planner_sha256
                    or not args.expected_preservation_executor_sha256):
                raise MaintenanceError("expected_preservation_tool_bindings_required")
            uid = args.invoking_uid
            repo = trusted_repo(args.repo, uid)
            planner_path = repo / "scripts/plan-legacy-vm-preservation.py"
            executor_path = repo / "scripts/legacy-vm-preservation.py"
            planner_source = read_bound_module(
                planner_path, args.expected_preservation_planner_sha256, uid
            )
            executor_source = read_bound_module(
                executor_path, args.expected_preservation_executor_sha256, uid
            )
            drop_privileges(uid)
            planner = execute_bound_module(
                "secure_sandbox_legacy_preservation_planner_execution", planner_path,
                planner_source,
            )
            plan = planner.build_plan(
                str(repo), args.generation, uid, maintenance=sys.modules[__name__]
            )
            if plan["plan_sha256"] != args.expected_plan_sha256:
                raise MaintenanceError("maintenance_plan_changed")
            if (plan["tools"]["preservation_planner"] != args.expected_preservation_planner_sha256
                    or plan["tools"]["preservation_executor"] != args.expected_preservation_executor_sha256):
                raise MaintenanceError("preservation_executor_changed")
            executor = execute_bound_module(
                "secure_sandbox_legacy_preservation_executor", executor_path,
                executor_source,
            )
            result = executor.execute(
                repo, args.generation, uid, args.expected_plan_sha256,
                planner=planner, maintenance=sys.modules[__name__],
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.operation.startswith("plan-"):
            print(json.dumps(build_plan(args.repo, operation, args.invoking_uid), sort_keys=True))
            return 0
        expected_components = {
            "prlctl_sha256": args.expected_prlctl_sha256,
            "installer_sha256": args.expected_installer_sha256,
            "seed_sha256": {
                "gateway": args.expected_seed_gateway_sha256,
                "research": args.expected_seed_research_sha256,
                "target": args.expected_seed_target_sha256,
            },
        }
        if (not args.expected_plan_sha256
                or any(value is None for value in (
                    args.expected_prlctl_sha256, args.expected_installer_sha256,
                    args.expected_seed_gateway_sha256, args.expected_seed_research_sha256,
                    args.expected_seed_target_sha256,
                ))):
            raise MaintenanceError("expected_plan_bindings_required")
        uid = args.invoking_uid
        drop_privileges(uid)
        plan = build_plan(args.repo, operation, uid)
        validate_plan_bindings(plan, args.expected_plan_sha256, expected_components)
        repo = Path(plan["repo"])
        installer = Path(plan["installer_path"])
        if operation == "create":
            create_all(repo, installer)
            result = {"status": "created", "plan_sha256": plan["plan_sha256"]}
        else:
            quarantine, recovered = reprovision(repo, installer, plan["vms"], plan["plan_sha256"], uid)
            result = {"status": "recovered" if recovered else "reprovisioned",
                      "plan_sha256": plan["plan_sha256"],
                      "quarantine": str(quarantine)}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (MaintenanceError, OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
