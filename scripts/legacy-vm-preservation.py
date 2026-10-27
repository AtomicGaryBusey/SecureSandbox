#!/usr/bin/env python3
"""Execute the reviewed legacy VM preservation plan as a recoverable user operation."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import types
import uuid


ROOT = Path(__file__).resolve().parents[1]
PLANNER_PATH = ROOT / "scripts/plan-legacy-vm-preservation.py"
CONTROL_CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
PRLCTL = Path("/Applications/Parallels Desktop.app/Contents/MacOS/prlctl")
ROLES = ("research", "gateway", "target")
MIN_RESERVE = 2 * 1024 * 1024 * 1024
ARCHIVE_FIXED_OVERHEAD = 64 * 1024 * 1024
ARCHIVE_PATH_OVERHEAD = 8192
TRANSACTION_SCHEMA = "secure-sandbox-legacy-preservation-transaction-v1"
TRANSACTION_MAXIMUM = 64 * 1024
RECEIPT_MAXIMUM = 16 * 1024 * 1024


class PreservationError(RuntimeError):
    pass


def load_module(name: str, path: Path, expected_sha256: str | None = None):
    if expected_sha256 is not None:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_size > 64 * 1024 * 1024
                    or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
                raise PreservationError(f"module_untrusted:{path.name}")
            data = bytearray()
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                data.extend(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise PreservationError(f"module_changed:{path.name}")
            if digest.hexdigest() != expected_sha256:
                raise PreservationError(f"module_hash_mismatch:{path.name}")
        finally:
            os.close(descriptor)
        module = types.ModuleType(name)
        module.__file__ = str(path)
        module.__package__ = ""
        exec(compile(bytes(data), str(path), "exec"), module.__dict__)
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def run(command: list[str], *, capture: bool = False, stdout=None,
        timeout: int = 600) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command, check=False, stdin=subprocess.DEVNULL,
            stdout=stdout if stdout is not None else (subprocess.PIPE if capture else subprocess.DEVNULL),
            stderr=subprocess.PIPE, timeout=timeout,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"],
                 "LANG": "C", "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        raise PreservationError(f"command_timeout:{Path(command[0]).name}") from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace") if isinstance(result.stderr, bytes) else result.stderr
        raise PreservationError(f"command_failed:{Path(command[0]).name}:{(detail or '')[:400]}")
    return result


def atomic_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = canonical(value)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise PreservationError("short_write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def secure_directory(path: Path, uid: int) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PreservationError(f"state_directory_untrusted:{path.name}")


def acquire_lock(base: Path, uid: int) -> int:
    lock_path = base / "preservation.lock"
    descriptor = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(descriptor)
        raise PreservationError("preservation_lock_untrusted")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise PreservationError("preservation_in_progress") from error
    return descriptor


def read_transaction(path: Path, expected_sha256: str, roots: dict[str, Path],
                     uid: int) -> dict[str, object]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_size > TRANSACTION_MAXIMUM
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise PreservationError("preservation_transaction_untrusted")
        data = bytearray()
        while chunk := os.read(descriptor, TRANSACTION_MAXIMUM + 1 - len(data)):
            data.extend(chunk)
            if len(data) > TRANSACTION_MAXIMUM:
                raise PreservationError("preservation_transaction_untrusted")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PreservationError("preservation_transaction_changed")
    finally:
        os.close(descriptor)
    if hashlib.sha256(bytes(data)).hexdigest() != expected_sha256:
        raise PreservationError("preservation_transaction_digest_mismatch")
    value = json.loads(bytes(data))
    required = {
        "schema", "plan_sha256", "role", "clone", "clone_device", "clone_inode",
        "clone_root_device", "clone_root_inode", "attached_device", "phase",
        "temporary_archive", "temporary_device", "temporary_inode",
    }
    if (not isinstance(value, dict) or canonical(value) != bytes(data) or set(value) != required
            or value.get("schema") != TRANSACTION_SCHEMA
            or not isinstance(value.get("plan_sha256"), str)
            or not __import__("re").fullmatch(r"[0-9a-f]{64}", value["plan_sha256"])
            or value.get("role") not in ROLES
            or value.get("phase") not in {
                "cloning", "cloned", "attached", "transport_started", "verified",
            }
            or not isinstance(value.get("clone_root_device"), int)
            or not isinstance(value.get("clone_root_inode"), int)
            or (value.get("phase") == "cloning" and (
                value.get("clone_device") is not None or value.get("clone_inode") is not None))
            or (value.get("phase") != "cloning" and (
                not isinstance(value.get("clone_device"), int)
                or not isinstance(value.get("clone_inode"), int)))
            or (value.get("attached_device") is not None
                and not __import__("re").fullmatch(r"hdd[0-9]+", value["attached_device"]))
            or (value.get("temporary_archive") is None and (
                value.get("temporary_device") is not None or value.get("temporary_inode") is not None))
            or (value.get("temporary_archive") is not None and (
                (value.get("temporary_device") is None) != (value.get("temporary_inode") is None)))
            or (value.get("temporary_device") is not None and (
                not isinstance(value["temporary_device"], int)
                or not isinstance(value["temporary_inode"], int)))):
        raise PreservationError("preservation_transaction_invalid")
    expected_clone = roots["clones"] / f"{value['role']}.hdd"
    root_info = roots["clones"].lstat()
    if (Path(str(value.get("clone"))) != expected_clone
            or (root_info.st_dev, root_info.st_ino) != (
                value["clone_root_device"], value["clone_root_inode"])):
        raise PreservationError("preservation_transaction_invalid")
    if value["temporary_archive"] is not None:
        temporary = Path(str(value["temporary_archive"]))
        prefix = f".{value['role']}.tar.gz.new-"
        if temporary.parent != roots["archives"] or not temporary.name.startswith(prefix):
            raise PreservationError("preservation_transaction_invalid")
    return value


def read_private_json(path: Path, uid: int) -> dict[str, object]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_size > RECEIPT_MAXIMUM
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise PreservationError(f"preservation_receipt_untrusted:{path.name}")
        data = bytearray()
        while chunk := os.read(descriptor, RECEIPT_MAXIMUM + 1 - len(data)):
            data.extend(chunk)
            if len(data) > RECEIPT_MAXIMUM:
                raise PreservationError(f"preservation_receipt_untrusted:{path.name}")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PreservationError(f"preservation_receipt_changed:{path.name}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreservationError(f"preservation_receipt_invalid:{path.name}") from error
    if not isinstance(value, dict) or canonical(value) != bytes(data):
        raise PreservationError(f"preservation_receipt_invalid:{path.name}")
    return value


def vm_value(selector: str) -> dict[str, object]:
    result = run([str(PRLCTL), "list", "-a", "-i", "-j", selector], capture=True)
    try:
        values = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreservationError("vm_inventory_invalid") from error
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise PreservationError("vm_inventory_invalid")
    return values[0]


def hdd_inventory(selector: str) -> dict[str, str]:
    hardware = vm_value(selector).get("Hardware", {})
    if not isinstance(hardware, dict):
        raise PreservationError("vm_hardware_invalid")
    result = {}
    for name, value in hardware.items():
        if name.startswith("hdd") and isinstance(value, dict) and value.get("enabled", True):
            image = value.get("image")
            if not isinstance(image, str):
                raise PreservationError("vm_hardware_invalid")
            result[name] = image
    return result


def wait_vm_state(selector: str, state: str, timeout: int = 180) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if vm_value(selector).get("State") == state:
            return
        time.sleep(1)
    raise PreservationError(f"vm_state_timeout:{selector}:{state}")


def wait_stopped(selector: str, timeout: int = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if vm_value(selector).get("State") == "stopped":
            return True
        time.sleep(1)
    return False


def client_command(operation: str, *arguments: str, capture: bool = False,
                   stdout=None, timeout: int = 600) -> subprocess.CompletedProcess:
    return run([
        str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
        "--timeout-seconds", str(timeout), "sandbox-research-control", "run",
        operation, *arguments,
    ], capture=capture, stdout=stdout, timeout=timeout + 30)


def wait_control(host: str, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            [str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
             "--timeout-seconds", "20", host, "run", "control-status"],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"]},
        )
        if result.returncode == 0:
            return
        time.sleep(2)
    raise PreservationError(f"control_unreachable:{host}")


def synchronize_guest_time(host: str) -> None:
    epoch = int(time.time())
    run([
        str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
        "--timeout-seconds", "60", host, "run", "set-time", f"@{epoch}",
    ], timeout=90)


def validate_tool_hashes(plan: dict[str, object], planner) -> None:
    actual = {name: planner.sha256_regular(path) for name, path in planner.TOOL_PATHS.items()}
    if actual != plan["tools"]:
        raise PreservationError("preservation_tools_changed")


def require_archive_capacity(role: str, inventory: dict[str, object], archive_root: Path) -> int:
    archive_upper_bound = (
        int(inventory["regular_bytes"])
        + int(inventory["paths"]) * ARCHIVE_PATH_OVERHEAD
        + ARCHIVE_FIXED_OVERHEAD
    )
    filesystem = os.statvfs(archive_root)
    free = filesystem.f_bavail * filesystem.f_frsize
    host_copies = 2 if role == "research" else 1
    if archive_upper_bound * host_copies + MIN_RESERVE > free:
        raise PreservationError("insufficient_archive_storage")
    if role == "research":
        guest_free = inventory.get("research_destination_free_bytes")
        if (not isinstance(guest_free, int) or isinstance(guest_free, bool)
                # Research retains the verified archive and may import up to
                # another archive-sized set of regular-file bytes.
                or archive_upper_bound * 2 + MIN_RESERVE > guest_free):
            raise PreservationError("insufficient_research_archive_storage")
    return archive_upper_bound


def assert_legacy_unregistered(plan: dict[str, object], maintenance) -> None:
    values = json.loads(maintenance.run(
        [str(maintenance.PRLCTL), "list", "-a", "-j"], capture=True
    ))
    if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
        raise PreservationError("registered_vm_inventory_invalid")
    try:
        registered = {maintenance.normalize_vm_uuid(value.get("uuid")) for value in values}
    except Exception as error:
        raise PreservationError("registered_vm_inventory_invalid") from error
    if any(source["legacy_vm_uuid"] in registered for source in plan["sources"].values()):
        raise PreservationError("legacy_vm_registered")


def deploy_tools(plan: dict[str, object], planner) -> None:
    validate_tool_hashes(plan, planner)
    files = [
        ROOT / "scripts/install-legacy-preservation.sh",
        ROOT / "scripts/privileged_control.py",
        ROOT / "scripts/legacy-guest-export.py",
        ROOT / "scripts/legacy_guest_preserver.py",
        ROOT / "scripts/verify-legacy-archive.py",
        ROOT / "scripts/plan-legacy-continuity-import.py",
        ROOT / "scripts/import-legacy-continuity.py",
        ROOT / "scripts/legacy_continuity_control.py",
        ROOT / "research/session_registry.py",
    ]
    expected = [
        plan["tools"]["deployment"], plan["tools"]["control_policy"],
        plan["tools"]["exporter"], plan["tools"]["guest_preserver"],
        plan["tools"]["archive_verifier"], plan["tools"]["continuity_planner"],
        plan["tools"]["continuity_importer"], plan["tools"]["continuity_control"],
        plan["tools"]["session_registry"],
    ]
    command = [
        str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
        "--timeout-seconds", "600", "sandbox-research-control", "deploy",
        "install-legacy-preservation.sh", *expected,
    ]
    for path in files:
        command.extend(["--file", str(path)])
    run(command, timeout=630)


def start_transport(plan: dict[str, object]) -> None:
    transport = plan["transport_vms"]
    gateway = transport["SecureSandbox-Gateway"]["uuid"]
    research = transport["SecureSandbox-Research"]["uuid"]
    run([str(PRLCTL), "start", gateway], timeout=180)
    wait_control("sandbox-gateway-control")
    synchronize_guest_time("sandbox-gateway-control")
    run([str(PRLCTL), "start", research], timeout=180)
    wait_control("sandbox-research-control")
    synchronize_guest_time("sandbox-research-control")


def stop_research(plan: dict[str, object]) -> None:
    research = plan["transport_vms"]["SecureSandbox-Research"]["uuid"]
    try:
        client_command("poweroff", timeout=90)
    except PreservationError:
        pass
    # Parallels can remain in its legitimate "stopping" state for longer
    # than the guest poweroff request itself.  Give the graceful transition
    # the same bounded window as a forced stop before issuing a second,
    # conflicting stop command.
    if not wait_stopped(research, timeout=180):
        run([str(PRLCTL), "stop", research], timeout=180)
    wait_vm_state(research, "stopped")


def start_research(plan: dict[str, object]) -> None:
    research = plan["transport_vms"]["SecureSandbox-Research"]["uuid"]
    run([str(PRLCTL), "start", research], timeout=180)
    wait_control("sandbox-research-control")
    synchronize_guest_time("sandbox-research-control")


def stop_gateway(plan: dict[str, object]) -> None:
    gateway = plan["transport_vms"]["SecureSandbox-Gateway"]["uuid"]
    result = subprocess.run(
        [str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
         "--timeout-seconds", "90", "sandbox-gateway-control", "run", "poweroff"],
        check=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"]},
    )
    if result.returncode and not wait_stopped(gateway, timeout=180):
        run([str(PRLCTL), "stop", gateway], timeout=180)
    wait_vm_state(gateway, "stopped")


def clone_disk(source: Path, destination: Path, planner, uid: int,
               expected_tree: str) -> tuple[int, int]:
    if destination.exists() or destination.is_symlink():
        raise PreservationError("clone_destination_exists")
    before = planner.disk_inventory(source, uid)
    if before["tree_metadata_sha256"] != expected_tree:
        raise PreservationError("source_disk_changed")
    # macOS cp -cR preserves regular-file metadata but leaves the newly
    # created destination directory with its creation-time mtime.  The disk
    # tree identity deliberately binds directory metadata too, so request
    # preservation explicitly; -c still provides the APFS copy-on-write
    # clone and -p restores the source root directory metadata after copying.
    run(["/bin/cp", "-cRp", str(source), str(destination)], timeout=1800)
    after = planner.disk_inventory(source, uid)
    if after["tree_metadata_sha256"] != expected_tree:
        raise PreservationError("source_disk_changed_during_clone")
    clone = planner.disk_inventory(destination, uid)
    info = destination.lstat()
    if (clone["entries"] != before["entries"]
            or clone["tree_metadata_sha256"] != expected_tree):
        raise PreservationError("clone_inventory_mismatch")
    return info.st_dev, info.st_ino


def attach_clone(research_uuid: str, clone: Path) -> str:
    # Parallels 27 accepts a SATA configuration update while the VM is
    # running but records PRL_ERR_VM_APPLY_CONFIG_NEEDS_REBOOT; the guest does
    # not receive the disk.  Require a cold attachment so a successful
    # prlctl return cannot be mistaken for guest-visible hot-addition.
    if vm_value(research_uuid).get("State") != "stopped":
        raise PreservationError("clone_attachment_requires_stopped_vm")
    before = hdd_inventory(research_uuid)
    try:
        run([str(PRLCTL), "set", research_uuid, "--device-add", "hdd", "--image", str(clone),
             "--iface", "sata", "--connect"], timeout=180)
    except PreservationError:
        try:
            after_failure = hdd_inventory(research_uuid)
            for name in set(after_failure) - set(before):
                if Path(after_failure[name]).resolve(strict=False) == clone.resolve(strict=True):
                    run([str(PRLCTL), "set", research_uuid, "--device-del", name], timeout=180)
        finally:
            raise
    after = hdd_inventory(research_uuid)
    added = set(after) - set(before)
    matches = [name for name in added
               if Path(after[name]).resolve(strict=False) == clone.resolve(strict=True)]
    if len(added) != 1 or len(matches) != 1:
        for name in matches:
            run([str(PRLCTL), "set", research_uuid, "--device-del", name], timeout=180)
        raise PreservationError("attached_device_ambiguous")
    device = matches[0]
    if Path(after[device]).resolve(strict=True) != clone.resolve(strict=True):
        run([str(PRLCTL), "set", research_uuid, "--device-del", device], timeout=180)
        raise PreservationError("attached_device_identity_mismatch")
    # Parallels may append a newly attached disk to the EFI boot order even
    # though the device was added only as data media.  Reassert the sole
    # trusted system disk before the VM is allowed to start.  If this update
    # fails, remove only the device whose resolved identity we just proved.
    try:
        run([
            str(PRLCTL), "set", research_uuid,
            "--device-bootorder", "hdd0",
        ], timeout=180)
        # Parallels 27 may re-enable gamepad auto-sharing while rewriting the
        # hardware configuration.  Reassert the transport boundary after the
        # disk addition and again after its removal.
        run([
            str(PRLCTL), "set", research_uuid,
            "--auto-share-gamepad", "off",
        ], timeout=180)
    except PreservationError:
        run([str(PRLCTL), "set", research_uuid, "--device-del", device], timeout=180)
        raise
    return device


def assert_cold_attachment(plan: dict[str, object], device: str, clone: Path) -> None:
    transport = plan["transport_vms"]["SecureSandbox-Research"]
    research_uuid = transport["uuid"]
    value = vm_value(research_uuid)
    disks = hdd_inventory(research_uuid)
    def same_disk(actual: str, expected: Path) -> bool:
        try:
            return Path(actual).resolve(strict=True) == expected.resolve(strict=True)
        except OSError:
            return False

    failed = []
    if value.get("State") != "stopped":
        failed.append("state")
    if str(value.get("Boot order", "")).strip() != "hdd0":
        failed.append("boot_order")
    if set(disks) != {"hdd0", device}:
        failed.append("disk_set")
    if "hdd0" not in disks or not same_disk(
            disks["hdd0"], Path(transport["system_disk"])):
        failed.append("system_disk")
    if device not in disks or not same_disk(disks[device], clone):
        failed.append("clone_disk")
    if failed:
        raise PreservationError("cold_attachment_invariant_failed:" + ",".join(failed))


def detach_clone(research_uuid: str, device: str, clone: Path) -> None:
    run([str(PRLCTL), "set", research_uuid, "--device-del", device], timeout=180)
    run([
        str(PRLCTL), "set", research_uuid,
        "--auto-share-gamepad", "off",
    ], timeout=180)
    if any(Path(image).resolve(strict=False) == clone.resolve(strict=True)
           for image in hdd_inventory(research_uuid).values()):
        raise PreservationError("clone_detach_failed")


def remove_clone(clone: Path, identity: tuple[int, int], clone_root: Path) -> None:
    info = clone.lstat()
    if (clone.parent != clone_root or clone.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino) != identity):
        raise PreservationError("clone_cleanup_identity_mismatch")
    directory = os.open(clone_root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        tombstone = f".{clone.name}.delete-{uuid.uuid4()}"
        os.rename(clone.name, tombstone, src_dir_fd=directory, dst_dir_fd=directory)
        moved = clone_root / tombstone
        moved_info = moved.lstat()
        if (moved_info.st_dev, moved_info.st_ino) != identity:
            raise PreservationError("clone_cleanup_identity_changed")
        shutil.rmtree(moved)
        os.fsync(directory)
    finally:
        os.close(directory)


def bind_receipt(role: str, verification: dict[str, object],
                 plan: dict[str, object]) -> dict[str, object]:
    source = plan["sources"][role]
    result = dict(verification)
    result["verification_schema"] = result.pop("schema")
    result.update({
        "schema": "secure-sandbox-legacy-preservation-receipt-v1",
        "generation": plan["generation"],
        "plan_sha256": plan["plan_sha256"],
        "legacy_vm_uuid": source["legacy_vm_uuid"],
        "source_config_sha256": source["config_sha256"],
        "source_disk_descriptor_sha256": source["disk_descriptor_sha256"],
        "source_tree_sha256": source["disk"]["tree_metadata_sha256"],
        "transport_research_uuid": plan["transport_vms"]["SecureSandbox-Research"]["uuid"],
    })
    return result


def verify_bound_receipt(role: str, archive: Path, receipt: dict[str, object],
                         plan: dict[str, object], verifier) -> dict[str, object]:
    expected = bind_receipt(role, verifier.verify(archive), plan)
    # The receipt records the plan that created this immutable preservation
    # artifact.  A later, independently authorized resume may legitimately use
    # newer import/verification tooling, which changes the current plan hash
    # without changing the legacy source or the verified archive.  Preserve
    # and validate the creating-plan identity while comparing every stable
    # source, transport, manifest, and archive binding against the current
    # plan.  Rewriting the old receipt to the new plan would destroy useful
    # provenance; requiring equality would make safe importer fixes impossible
    # to resume.
    creating_plan = receipt.get("plan_sha256")
    if (not isinstance(creating_plan, str) or len(creating_plan) != 64
            or any(character not in "0123456789abcdef" for character in creating_plan)):
        raise PreservationError(f"existing_preservation_conflict:{role}")
    expected["plan_sha256"] = creating_plan
    if receipt != expected:
        raise PreservationError(f"existing_preservation_conflict:{role}")
    return expected


def preservation_set_receipt(plan: dict[str, object],
                             receipts: dict[str, dict[str, object]]) -> dict[str, object]:
    if set(receipts) != set(ROLES):
        raise PreservationError("preservation_set_incomplete")
    return {
        "archive_sha256": {
            role: receipts[role]["archive_sha256"] for role in ROLES
        },
        "creating_plan_sha256": {
            role: receipts[role]["plan_sha256"] for role in ROLES
        },
        "generation": plan["generation"],
        "plan_sha256": plan["plan_sha256"],
        "schema": "secure-sandbox-legacy-preservation-set-v1",
        "source_tree_sha256": {
            role: plan["sources"][role]["disk"]["tree_metadata_sha256"]
            for role in ROLES
        },
        "status": "verified",
        "transport_research_uuid":
            plan["transport_vms"]["SecureSandbox-Research"]["uuid"],
    }


def recover_transaction(plan: dict[str, object], roots: dict[str, Path], uid: int,
                        transaction_path: Path) -> dict[str, object]:
    transaction = read_transaction(
        transaction_path, plan["recovery_transaction_sha256"], roots, uid
    )
    research_uuid = plan["transport_vms"]["SecureSandbox-Research"]["uuid"]
    gateway_uuid = plan["transport_vms"]["SecureSandbox-Gateway"]["uuid"]
    clone = Path(transaction["clone"])
    identity = (transaction["clone_device"], transaction["clone_inode"])
    if vm_value(research_uuid).get("State") != "stopped":
        stop_research(plan)
    inventory = hdd_inventory(research_uuid)
    matches = [name for name, image in inventory.items()
               if Path(image).resolve(strict=False) == clone.resolve(strict=False)]
    if len(matches) > 1:
        raise PreservationError("recovery_clone_attachment_ambiguous")
    recorded = transaction["attached_device"]
    if recorded is not None and recorded in inventory:
        if recorded not in matches:
            raise PreservationError("recovery_attached_device_changed")
        detach_clone(research_uuid, recorded, clone)
    elif matches:
        detach_clone(research_uuid, matches[0], clone)
    if clone.exists() or clone.is_symlink():
        if transaction["phase"] == "cloning":
            info = clone.lstat()
            if clone.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
                raise PreservationError("recovery_partial_clone_untrusted")
            identity = (info.st_dev, info.st_ino)
        remove_clone(clone, identity, roots["clones"])
    temporary_value = transaction["temporary_archive"]
    if temporary_value is not None:
        temporary = Path(temporary_value)
        if temporary.exists() or temporary.is_symlink():
            info = temporary.lstat()
            recorded_temporary = (transaction["temporary_device"], transaction["temporary_inode"])
            if (temporary.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or (recorded_temporary != (None, None)
                        and (info.st_dev, info.st_ino) != recorded_temporary)):
                raise PreservationError("recovery_temporary_archive_untrusted")
            temporary.unlink()
            directory = os.open(roots["archives"], os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    # A crash can occur after publishing the verified archive but before its
    # bound receipt. Never infer source provenance from an unreceipted file on
    # a later invocation. It is only a disposable derivative under our private
    # state root, so remove its exact trusted inode and regenerate from the
    # still-preserved source disk. An archive with a receipt is left intact and
    # will be re-verified against the current plan on the next normal run.
    archive = roots["archives"] / f"{transaction['role']}.tar.gz"
    receipt = roots["receipts"] / f"preservation-{transaction['role']}.json"
    archive_present = archive.exists() or archive.is_symlink()
    receipt_present = receipt.exists() or receipt.is_symlink()
    if receipt_present:
        read_private_json(receipt, uid)
    if archive_present and not receipt_present:
        info = archive.lstat()
        if (archive.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise PreservationError("recovery_unreceipted_archive_untrusted")
        archive.unlink()
        directory = os.open(
            roots["archives"], os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    transaction_path.unlink()
    directory = os.open(transaction_path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if vm_value(gateway_uuid).get("State") != "stopped":
        stop_gateway(plan)
    return {
        "generation": plan["generation"],
        "plan_sha256": plan["plan_sha256"],
        "recovered_role": transaction["role"],
        "schema": "secure-sandbox-legacy-vm-preservation-result-v1",
        "status": "recovered",
    }


def preserve_role(role: str, plan: dict[str, object], roots: dict[str, Path], planner,
                  verifier, maintenance, uid: int, transaction_path: Path) -> dict[str, object]:
    archive = roots["archives"] / f"{role}.tar.gz"
    receipt_path = roots["receipts"] / f"preservation-{role}.json"
    archive_present = archive.exists() or archive.is_symlink()
    receipt_present = receipt_path.exists() or receipt_path.is_symlink()
    if archive_present and not receipt_present:
        raise PreservationError(f"unreceipted_preservation_requires_recovery:{role}")
    elif receipt_present and not archive_present:
        raise PreservationError(f"existing_preservation_conflict:{role}")
    if archive_present and receipt_present:
        receipt = read_private_json(receipt_path, uid)
        receipt = verify_bound_receipt(role, archive, receipt, plan, verifier)
        if receipt.get("role") == role:
            if role == "research":
                imported = client_command(
                    "legacy-import", str(receipt["archive_sha256"]), capture=True, timeout=3600
                )
                import_receipt = json.loads(imported.stdout)
                if (import_receipt.get("status") != "imported"
                        or import_receipt.get("archive_sha256") != receipt["archive_sha256"]):
                    raise PreservationError("continuity_import_receipt_invalid")
                atomic_json(roots["receipts"] / "continuity-import.json", import_receipt)
            stop_research(plan)
            return receipt
        raise PreservationError(f"existing_preservation_conflict:{role}")
    source = Path(plan["sources"][role]["disk"]["path"])
    clone = roots["clones"] / f"{role}.hdd"
    assert_legacy_unregistered(plan, maintenance)
    clone_root_info = roots["clones"].lstat()
    transaction = {
        "schema": TRANSACTION_SCHEMA,
        "plan_sha256": plan["plan_sha256"], "role": role, "clone": str(clone),
        "clone_device": None, "clone_inode": None,
        "clone_root_device": clone_root_info.st_dev, "clone_root_inode": clone_root_info.st_ino,
        "attached_device": None, "phase": "cloning",
        "temporary_archive": None, "temporary_device": None, "temporary_inode": None,
    }
    atomic_json(transaction_path, transaction)
    identity = clone_disk(
        source, clone, planner, uid,
        plan["sources"][role]["disk"]["tree_metadata_sha256"],
    )
    assert_legacy_unregistered(plan, maintenance)
    transaction.update({"clone_device": identity[0], "clone_inode": identity[1], "phase": "cloned"})
    atomic_json(transaction_path, transaction)
    research_uuid = plan["transport_vms"]["SecureSandbox-Research"]["uuid"]
    # A running SATA update is configuration-only in Parallels 27.  Stop the
    # disposable transport, attach the verified clone as hdd1, and re-prove
    # that the sole boot entry remains the fresh hdd0 before starting it.
    if vm_value(research_uuid).get("State") != "stopped":
        stop_research(plan)
    device = attach_clone(research_uuid, clone)
    transaction.update({"attached_device": device, "phase": "attached"})
    atomic_json(transaction_path, transaction)
    try:
        assert_cold_attachment(plan, device, clone)
        start_research(plan)
        transaction.update({"phase": "transport_started"})
        atomic_json(transaction_path, transaction)
        inventory_result = client_command("legacy-inventory", role, capture=True, timeout=1800)
        inventory = json.loads(inventory_result.stdout)
        if (inventory.get("status") != "inventory" or inventory.get("role") != role
                or not isinstance(inventory.get("regular_bytes"), int)
                or not isinstance(inventory.get("paths"), int)
                or isinstance(inventory.get("regular_bytes"), bool)
                or isinstance(inventory.get("paths"), bool)
                or inventory["regular_bytes"] < 0 or not 0 <= inventory["paths"] <= 1_000_000):
            raise PreservationError("legacy_inventory_invalid")
        require_archive_capacity(role, inventory, roots["archives"])
        temporary = archive.with_name(f".{archive.name}.new-{uuid.uuid4()}")
        transaction.update({
            "temporary_archive": str(temporary),
            "temporary_device": None, "temporary_inode": None,
        })
        atomic_json(transaction_path, transaction)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            temporary_info = os.fstat(descriptor)
            transaction.update({
                "temporary_device": temporary_info.st_dev,
                "temporary_inode": temporary_info.st_ino,
            })
            atomic_json(transaction_path, transaction)
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                client_command("legacy-preserve", role, stdout=output, timeout=3600)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(descriptor)
        verification = verifier.verify(temporary)
        if (verification.get("role") != role
                or verification.get("regular_bytes") != inventory["regular_bytes"]):
            raise PreservationError("preservation_receipt_mismatch")
        receipt = bind_receipt(role, verification, plan)
        os.replace(temporary, archive)
        directory = os.open(
            roots["archives"], os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        atomic_json(receipt_path, receipt)
        transaction.update({
            "phase": "verified", "temporary_archive": None,
            "temporary_device": None, "temporary_inode": None,
        })
        atomic_json(transaction_path, transaction)
        if role == "research":
            imported = client_command(
                "legacy-import", str(receipt["archive_sha256"]), capture=True, timeout=3600
            )
            import_receipt = json.loads(imported.stdout)
            if (import_receipt.get("status") != "imported"
                    or import_receipt.get("archive_sha256") != receipt["archive_sha256"]):
                raise PreservationError("continuity_import_receipt_invalid")
            atomic_json(roots["receipts"] / "continuity-import.json", import_receipt)
    finally:
        stop_research(plan)
        detach_clone(research_uuid, device, clone)
        remove_clone(clone, identity, roots["clones"])
    transaction_path.unlink()
    directory = os.open(transaction_path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return receipt


def execute(repo: Path, generation: str, uid: int, expected_plan_sha256: str,
            *, planner=None, maintenance=None) -> dict[str, object]:
    planner = (load_module("legacy_preservation_planner", PLANNER_PATH)
               if planner is None else planner)
    maintenance = planner.load_maintenance() if maintenance is None else maintenance
    plan = planner.build_plan(str(repo), generation, uid, maintenance=maintenance)
    if plan["plan_sha256"] != expected_plan_sha256:
        raise PreservationError("preservation_plan_changed")
    validate_tool_hashes(plan, planner)
    verifier = load_module(
        "legacy_archive_verifier_execution", ROOT / "scripts/verify-legacy-archive.py",
        plan["tools"]["archive_verifier"],
    )
    base = repo / ".private/legacy-migration" / generation
    roots = {name: base / name for name in ("archives", "clones", "receipts")}
    secure_directory(repo / ".private/legacy-migration", uid)
    secure_directory(base, uid)
    for path in roots.values():
        secure_directory(path, uid)
    transaction_path = base / "transaction.json"
    lock_descriptor = acquire_lock(base, uid)
    try:
        if plan.get("operation") == "recover":
            if not transaction_path.exists() or transaction_path.is_symlink():
                raise PreservationError("preservation_transaction_missing")
            return recover_transaction(plan, roots, uid, transaction_path)
        if transaction_path.exists() or transaction_path.is_symlink():
            raise PreservationError("legacy_preservation_recovery_required")
        try:
            start_transport(plan)
            deploy_tools(plan, planner)
            receipts = {}
            for index, role in enumerate(ROLES):
                receipts[role] = preserve_role(
                    role, plan, roots, planner, verifier, maintenance, uid, transaction_path
                )
                if index != len(ROLES) - 1:
                    start_research(plan)
            atomic_json(
                roots["receipts"] / "preservation-set.json",
                preservation_set_receipt(plan, receipts),
            )
        finally:
            gateway_uuid = plan["transport_vms"]["SecureSandbox-Gateway"]["uuid"]
            research_uuid = plan["transport_vms"]["SecureSandbox-Research"]["uuid"]
            try:
                if vm_value(research_uuid).get("State") != "stopped":
                    stop_research(plan)
            finally:
                if vm_value(gateway_uuid).get("State") != "stopped":
                    stop_gateway(plan)
        return {
            "generation": generation, "plan_sha256": plan["plan_sha256"],
            "receipts": {role: value["archive_sha256"] for role, value in receipts.items()},
            "schema": "secure-sandbox-legacy-vm-preservation-result-v1",
            "status": "preserved_and_imported",
        }
    finally:
        os.close(lock_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--invoking-uid", type=int, required=True)
    parser.add_argument("--expected-plan-sha256", required=True)
    args = parser.parse_args()
    result = execute(Path(args.repo), args.generation, args.invoking_uid, args.expected_plan_sha256)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PreservationError, OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
