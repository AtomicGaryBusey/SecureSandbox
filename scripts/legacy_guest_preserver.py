#!/usr/bin/env python3
"""Mount exactly one attached legacy ext4 partition read-only and stream its archive."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


EXPORTER = Path("/usr/local/libexec/secure-sandbox/legacy-guest-export.py")
VERIFIER = Path("/usr/local/libexec/secure-sandbox/verify-legacy-archive.py")
MOUNTPOINT = Path("/run/secure-sandbox/legacy-source")
RESEARCH_ARCHIVE = Path("/var/lib/secure-sandbox/legacy-migration/research.tar.gz")
ROLES = {"gateway", "research", "target"}
DEVICE = re.compile(r"^/dev/[A-Za-z0-9._/+:-]+$")
LAYOUT_TOKEN = re.compile(r"^[A-Za-z0-9._+-]{1,32}$")
RESEARCH_STATE = Path("/var/lib/secure-sandbox")


class PreservationError(RuntimeError):
    pass


def run(command: list[str], *, capture: bool = True) -> str:
    result = subprocess.run(
        command, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE, text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode:
        raise PreservationError(f"command_failed:{Path(command[0]).name}:{result.stderr.strip()[:400]}")
    return result.stdout if capture else ""


def require_idle() -> None:
    blocked = (
        Path("/run/secure-sandbox/run-id"),
        Path("/run/secure-sandbox/evidence-run-id"),
        Path("/var/lib/secure-sandbox/run-lifecycle/active.json"),
        Path("/var/lib/secure-sandbox/run-lifecycle/failure-latched.json"),
    )
    if any(path.exists() for path in blocked):
        raise PreservationError("agent_lifecycle_not_idle")
    result = subprocess.run(
        ["/usr/bin/pgrep", "-x", "claude"], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode != 1:
        raise PreservationError("agent_lifecycle_not_idle")


def flatten_devices(values: list[object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    stack = list(reversed(values))
    while stack:
        value = stack.pop()
        if not isinstance(value, dict):
            raise PreservationError("block_inventory_invalid")
        result.append(value)
        children = value.get("children", [])
        if children is None:
            children = []
        if not isinstance(children, list):
            raise PreservationError("block_inventory_invalid")
        stack.extend(reversed(children))
    return result


def trusted_block_device(value: str) -> Path:
    if not DEVICE.fullmatch(value):
        raise PreservationError("legacy_partition_untrusted")
    resolved = Path(value).resolve(strict=True)
    info = resolved.stat()
    if not str(resolved).startswith("/dev/") or not stat.S_ISBLK(info.st_mode):
        raise PreservationError("legacy_partition_untrusted")
    return resolved


def sanitized_block_layout(devices: list[dict[str, object]], root_source: str) -> str:
    """Return bounded topology facts without labels, UUIDs, or device names.

    Device paths are represented only by their position in lsblk's flattened
    topology.  This is sufficient to distinguish a missing hot-added disk,
    direct filesystems, and LVM/crypt layering without disclosing operator-
    chosen volume names.
    """
    bounded = devices[:16]
    positions = {
        item.get("path"): index for index, item in enumerate(bounded)
        if isinstance(item.get("path"), str)
    }
    rows = []
    for index, item in enumerate(bounded):
        kind = item.get("type")
        filesystem = item.get("fstype")
        kind = kind if isinstance(kind, str) and LAYOUT_TOKEN.fullmatch(kind) else "other"
        filesystem = (filesystem if isinstance(filesystem, str)
                      and LAYOUT_TOKEN.fullmatch(filesystem) else "none")
        parent = positions.get(item.get("pkname"), "-")
        mounts = item.get("mountpoints")
        mounted = "m" if isinstance(mounts, list) and any(mounts) else "u"
        read_only = "ro" if item.get("ro") in (True, 1, "1") else "rw"
        is_root = "root" if item.get("path") == root_source else "-"
        rows.append(f"{index}:{kind}:{filesystem}:{parent}:{mounted}:{read_only}:{is_root}")
    if len(devices) > len(bounded):
        rows.append(f"+{len(devices) - len(bounded)}")
    return ",".join(rows)


def select_legacy_partition(*, attempts: int = 30, delay: float = 1.0) -> tuple[Path, Path]:
    if attempts < 1 or delay < 0:
        raise PreservationError("block_inventory_retry_invalid")
    # Parallels reports a successful live attachment before Linux has always
    # finished publishing the disk's partition children.  Wait for queued
    # uevents, then allow a bounded zero-candidate settling window.  Ambiguity
    # is never retried: multiple eligible filesystems still fail immediately.
    run(["/usr/bin/udevadm", "settle", "--timeout=30"])
    root_source = run([
        "/usr/bin/findmnt", "--noheadings", "--output", "SOURCE", "/",
    ]).strip()
    last_count = 0
    last_layout = ""
    for attempt in range(attempts):
        try:
            value = json.loads(run([
                "/usr/bin/lsblk", "--json", "--paths", "--output",
                "NAME,PATH,TYPE,PKNAME,FSTYPE,MOUNTPOINTS,RO",
            ]))
        except json.JSONDecodeError as error:
            raise PreservationError("block_inventory_invalid") from error
        devices = flatten_devices(value.get("blockdevices", []) if isinstance(value, dict) else [])
        last_layout = sanitized_block_layout(devices, root_source)
        root = next((item for item in devices if item.get("path") == root_source), None)
        root_parent = root.get("pkname") if root else None
        if not isinstance(root_parent, str) or not DEVICE.fullmatch(root_parent):
            raise PreservationError("root_block_inventory_invalid")
        candidates = []
        for item in devices:
            mounts = item.get("mountpoints")
            if mounts is None:
                mounts = []
            path = item.get("path")
            if (item.get("type") == "part" and item.get("fstype") == "ext4"
                    and isinstance(path, str) and DEVICE.fullmatch(path)
                    and item.get("pkname") != root_parent
                    and isinstance(mounts, list) and not any(mounts)):
                parent = item.get("pkname")
                if not isinstance(parent, str) or not DEVICE.fullmatch(parent):
                    raise PreservationError("block_inventory_invalid")
                candidates.append((path, parent))
        last_count = len(candidates)
        if last_count == 1:
            partition_value, parent_value = candidates[0]
            return trusted_block_device(partition_value), trusted_block_device(parent_value)
        if last_count > 1:
            raise PreservationError(f"legacy_partition_ambiguous:{last_count}")
        if attempt + 1 < attempts:
            time.sleep(delay)
    raise PreservationError(
        f"legacy_partition_ambiguous:{last_count}:layout={last_layout}"
    )


MOUNT_OPTIONS = ("ro", "noload", "nodev", "nosuid", "noexec")
OBSERVABLE_MOUNT_OPTIONS = frozenset({"ro", "nodev", "nosuid", "noexec"})


def verify_block_devices_read_only(device: Path, partition: Path) -> None:
    for value in (device, partition):
        read_only = run([
            "/usr/bin/lsblk", "--noheadings", "--nodeps", "--output", "RO", str(value),
        ]).strip()
        if read_only != "1":
            raise PreservationError("legacy_block_device_writable")


def make_device_read_only(device: Path, partition: Path) -> None:
    run(["/usr/sbin/blockdev", "--setro", str(device)])
    run(["/usr/sbin/blockdev", "--setro", str(partition)])
    verify_block_devices_read_only(device, partition)


def mount_legacy_partition(device: Path) -> None:
    # noload is an ext4 mount-time instruction. The kernel need not expose it
    # as a persistent active option through /proc/self/mountinfo, so prove its
    # use from this fixed argv and separately verify every observable VFS
    # restriction plus the read-only state of both backing block devices.
    run([
        "/usr/bin/mount", "-t", "ext4", "-o", ",".join(MOUNT_OPTIONS),
        str(device), str(MOUNTPOINT),
    ])


def verify_mount(device: Path, parent_device: Path) -> None:
    source = run(["/usr/bin/findmnt", "--noheadings", "--output", "SOURCE", "--target", str(MOUNTPOINT)]).strip()
    if Path(source).resolve(strict=True) != device:
        raise PreservationError("legacy_mount_source_mismatch")
    options = set(run([
        "/usr/bin/findmnt", "--noheadings", "--output", "OPTIONS", "--target", str(MOUNTPOINT),
    ]).strip().split(","))
    if not OBSERVABLE_MOUNT_OPTIONS.issubset(options):
        raise PreservationError("legacy_mount_options_invalid")
    verify_block_devices_read_only(parent_device, device)


def trusted_tool(path: Path, label: str) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o755):
        raise PreservationError(f"{label}_untrusted")


def stream_regular(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1:
            raise PreservationError("research_archive_untrusted")
        while chunk := os.read(descriptor, 1024 * 1024):
            sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PreservationError("research_archive_changed")
    finally:
        os.close(descriptor)


def preserve(operation: str, role: str, exporter: Path = EXPORTER,
             verifier: Path = VERIFIER) -> int:
    if os.geteuid() != 0:
        raise PreservationError("root_required")
    if role not in ROLES:
        raise PreservationError("role_invalid")
    if operation not in {"inventory", "export"}:
        raise PreservationError("operation_invalid")
    require_idle()
    trusted_tool(exporter, "exporter")
    if operation == "export" and role == "research":
        trusted_tool(verifier, "verifier")
    device, parent_device = select_legacy_partition()
    make_device_read_only(parent_device, device)
    MOUNTPOINT.mkdir(mode=0o700, parents=True, exist_ok=True)
    mount_info = MOUNTPOINT.lstat()
    if (not stat.S_ISDIR(mount_info.st_mode) or MOUNTPOINT.is_symlink()
            or mount_info.st_uid != 0 or stat.S_IMODE(mount_info.st_mode) != 0o700):
        raise PreservationError("legacy_mountpoint_untrusted")
    if subprocess.run(["/usr/bin/mountpoint", "-q", str(MOUNTPOINT)], check=False).returncode == 0:
        raise PreservationError("legacy_mountpoint_busy")
    mounted = False
    try:
        mount_legacy_partition(device)
        mounted = True
        verify_mount(device, parent_device)
        command = [
            "/usr/bin/python3", "-I", str(exporter), operation, "--role", role,
            "--source-prefix", str(MOUNTPOINT),
        ]
        temporary = None
        if operation == "export" and role == "research":
            RESEARCH_ARCHIVE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent = RESEARCH_ARCHIVE.parent.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                    or stat.S_IMODE(parent.st_mode) != 0o700):
                raise PreservationError("research_archive_directory_untrusted")
            # Never reuse an archive merely because it is structurally valid.
            # The currently attached, host-identity-bound clone is the source
            # of truth for this invocation; a prior archive may belong to an
            # interrupted attempt or a different legacy generation.
            temporary = RESEARCH_ARCHIVE.with_name(f".{RESEARCH_ARCHIVE.name}.new-{os.getpid()}")
            command.extend(["--output", str(temporary)])
        elif operation == "export":
            command.extend(["--output", "-"])
        result = subprocess.run(
            command, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if operation == "inventory" else None,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        export_status = result.returncode
        if export_status:
            detail = result.stderr.decode("utf-8", "replace") if result.stderr else ""
            raise PreservationError(f"legacy_export_failed:{result.returncode}:{detail[:200]}")
        if operation == "inventory":
            try:
                inventory = json.loads(result.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise PreservationError("legacy_inventory_invalid") from error
            if not isinstance(inventory, dict):
                raise PreservationError("legacy_inventory_invalid")
            if role == "research":
                space = os.statvfs(RESEARCH_STATE)
                inventory["research_destination_free_bytes"] = space.f_bavail * space.f_frsize
            print(json.dumps(inventory, separators=(",", ":"), sort_keys=True))
        if temporary is not None:
            try:
                verification = json.loads(run(["/usr/bin/python3", "-I", str(verifier), str(temporary)]))
                if verification.get("status") != "verified" or verification.get("role") != "research":
                    raise PreservationError("research_archive_verification_failed")
                os.replace(temporary, RESEARCH_ARCHIVE)
                directory = os.open(RESEARCH_ARCHIVE.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                stream_regular(RESEARCH_ARCHIVE)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
    finally:
        if mounted:
            unmount = subprocess.run(
                ["/usr/bin/umount", str(MOUNTPOINT)], check=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            if unmount.returncode:
                raise PreservationError("legacy_unmount_failed")
    return export_status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("inventory", "export"))
    parser.add_argument("role", choices=sorted(ROLES))
    args = parser.parse_args()
    return preserve(args.operation, args.role)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PreservationError, OSError, ValueError) as error:
        print(f"legacy_preservation_rejected:{type(error).__name__}:{error}", file=sys.stderr)
        raise SystemExit(1)
