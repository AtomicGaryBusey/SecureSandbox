#!/usr/bin/env python3
"""Install and verify the isolated Host-to-Gateway SSH firewall admission."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable


NFTABLES = Path("/etc/nftables.conf")
ADMIN_SOURCE = Path("/etc/secure-sandbox/gateway-admin-source-ipv4")
STATE_ROOT = Path("/var/lib/secure-sandbox/control/network-migrations")
NFT = Path("/usr/sbin/nft")
HOST_CONTROL_ADDRESS = "172.30.10.30"
MAX_FILE = 64 * 1024
SCHEMA = "secure-sandbox-gateway-host-control-transport-v1"
LEGACY_PREDECESSOR = b'''#!/usr/sbin/nft -f

flush ruleset

table inet filter {
\tchain input {
\t\ttype filter hook input priority filter;
\t}
\tchain forward {
\t\ttype filter hook forward priority filter;
\t}
\tchain output {
\t\ttype filter hook output priority filter;
\t}
}
'''


class HostControlError(RuntimeError):
    """Stable, content-free host-control transport failure."""


def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ).encode("ascii") + b"\n"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def trusted_file(
    path: Path, *, mode: int = 0o600, expected_uid: int = 0,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HostControlError("host_control_input_untrusted") from error
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode
                or before.st_size > MAX_FILE):
            raise HostControlError("host_control_input_untrusted")
        raw = bytearray()
        while chunk := os.read(descriptor, MAX_FILE + 1 - len(raw)):
            raw.extend(chunk)
            if len(raw) > MAX_FILE:
                raise HostControlError("host_control_input_untrusted")
        after = os.fstat(descriptor)
        named = path.lstat()
        if ((before.st_dev, before.st_ino, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
                or (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
                != (named.st_dev, named.st_ino, named.st_size,
                    named.st_mtime_ns, named.st_ctime_ns)):
            raise HostControlError("host_control_input_changed")
        return bytes(raw), after
    finally:
        os.close(descriptor)


def trusted_directory(path: Path, *, expected_uid: int = 0) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HostControlError("host_control_input_untrusted") from error
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise HostControlError("host_control_input_untrusted")


def trusted_nftables(
    path: Path, *, expected_uid: int = 0,
) -> tuple[bytes, os.stat_result]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HostControlError("host_control_input_untrusted") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in {0o600, 0o755}:
        raise HostControlError("host_control_input_untrusted")
    return trusted_file(path, mode=mode, expected_uid=expected_uid)


def rules(admin_source: str, *, host_control: bool) -> bytes:
    try:
        address = ipaddress.ip_address(admin_source)
    except ValueError as error:
        raise HostControlError("host_control_admin_source_invalid") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise HostControlError("host_control_admin_source_invalid")
    host_rule = (
        f'    iifname "ctl0" ip saddr {HOST_CONTROL_ADDRESS} tcp dport 22 accept\n'
        if host_control else ""
    )
    return f'''#!/usr/sbin/nft -f
flush ruleset
table inet filter {{
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "uplink0" ip saddr {address} tcp dport 22 accept
    iifname "uplink0" udp sport 67 udp dport 68 accept
{host_rule}    iifname "ctl0" ip saddr 172.30.10.2 icmp type echo-request accept
    iifname "ctl0" ip saddr 172.30.10.2 tcp dport {{ 8443, 9443 }} accept
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-in-deny " flags all counter
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-fwd-deny " flags all counter
  }}
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    oifname "uplink0" udp sport 68 udp dport 67 accept
    oifname "ctl0" ip daddr 172.30.10.2 tcp dport 22 accept
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-out-deny " flags all counter
  }}
}}
'''.encode("ascii")


def require_state_root(path: Path, *, expected_uid: int = 0) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise HostControlError("host_control_state_untrusted")


def publish_exclusive(path: Path, raw: bytes, *, expected_uid: int = 0) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        existing, _ = trusted_file(path, expected_uid=expected_uid)
        if existing != raw:
            raise HostControlError("host_control_backup_collision")
        return
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise HostControlError("host_control_write_failed")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, expected_uid, os.getegid())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_nft(arguments: list[str], *, runner: Callable[..., Any]) -> subprocess.CompletedProcess[bytes]:
    try:
        result = runner(
            [str(NFT), *arguments], cwd=Path("/"), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=15,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HostControlError("host_control_nft_failed") from error
    if (result.returncode != 0 or result.stderr or len(result.stdout) > MAX_FILE):
        raise HostControlError("host_control_nft_failed")
    return result


def install(
    *, nftables: Path = NFTABLES, admin_path: Path = ADMIN_SOURCE,
    state_root: Path = STATE_ROOT, runner: Callable[..., Any] = subprocess.run,
    expected_uid: int = 0, admin_source_override: str | None = None,
) -> dict[str, Any]:
    if os.geteuid() != expected_uid:
        raise HostControlError("host_control_root_required")
    if admin_source_override is not None:
        try:
            override = ipaddress.ip_address(admin_source_override)
        except ValueError as error:
            raise HostControlError("host_control_admin_source_invalid") from error
        if not isinstance(override, ipaddress.IPv4Address):
            raise HostControlError("host_control_admin_source_invalid")
        admin_source_override = str(override)
    try:
        admin_path.lstat()
    except FileNotFoundError:
        if admin_source_override is None:
            raise HostControlError("host_control_admin_source_required")
        admin_source = admin_source_override
        admin_present = False
    except OSError as error:
        raise HostControlError("host_control_input_untrusted") from error
    else:
        admin_raw, _ = trusted_file(admin_path, expected_uid=expected_uid)
        try:
            admin_source = admin_raw.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise HostControlError("host_control_admin_source_invalid") from error
        if (admin_source_override is not None
                and admin_source_override != admin_source):
            raise HostControlError("host_control_admin_source_mismatch")
        admin_present = True
    before_raw, before_identity = trusted_nftables(
        nftables, expected_uid=expected_uid,
    )
    predecessor = rules(admin_source, host_control=False)
    successor = rules(admin_source, host_control=True)
    before_mode = stat.S_IMODE(before_identity.st_mode)
    legacy = before_mode == 0o755
    if ((legacy and before_raw != LEGACY_PREDECESSOR)
            or (not legacy and before_raw not in {predecessor, successor})):
        raise HostControlError("host_control_predecessor_invalid")
    trusted_directory(admin_path.parent, expected_uid=expected_uid)
    require_state_root(state_root, expected_uid=expected_uid)
    changed = before_raw != successor
    backup = None
    temporary = nftables.parent / f".{nftables.name}.host-control.{uuid.uuid4()}"
    try:
        if changed:
            backup = state_root / f"pre-host-control-{digest(before_raw)}.conf"
            publish_exclusive(backup, before_raw, expected_uid=expected_uid)
            if not admin_present:
                publish_exclusive(
                    admin_path, f"{admin_source}\n".encode("ascii"),
                    expected_uid=expected_uid,
                )
            publish_exclusive(temporary, successor, expected_uid=expected_uid)
            run_nft(["-c", "-f", str(temporary)], runner=runner)
            current = nftables.lstat()
            if ((current.st_dev, current.st_ino, current.st_size,
                 current.st_mtime_ns, current.st_ctime_ns)
                    != (before_identity.st_dev, before_identity.st_ino,
                        before_identity.st_size, before_identity.st_mtime_ns,
                        before_identity.st_ctime_ns)):
                raise HostControlError("host_control_predecessor_changed")
            os.replace(temporary, nftables)
            directory = os.open(
                nftables.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        else:
            if not admin_present:
                publish_exclusive(
                    admin_path, f"{admin_source}\n".encode("ascii"),
                    expected_uid=expected_uid,
                )
            run_nft(["-c", "-f", str(nftables)], runner=runner)
        installed, _ = trusted_file(nftables, expected_uid=expected_uid)
        if installed != successor:
            raise HostControlError("host_control_install_readback_invalid")
        run_nft(["-f", str(nftables)], runner=runner)
        runtime = run_nft(
            ["list", "chain", "inet", "filter", "input"], runner=runner,
        ).stdout.decode("utf-8", "strict")
        expected = (
            f'iifname "ctl0" ip saddr {HOST_CONTROL_ADDRESS} tcp dport 22 accept'
        )
        if expected not in {line.strip() for line in runtime.splitlines()}:
            raise HostControlError("host_control_runtime_readback_invalid")
        return {
            "schema": SCHEMA, "status": "installed" if changed else "verified",
            "predecessor_sha256": (
                digest(LEGACY_PREDECESSOR) if legacy else digest(predecessor)
            ),
            "successor_sha256": digest(successor),
            "backup_sha256": digest(before_raw) if backup is not None else None,
            "admin_source": admin_source,
            "host_control_address": HOST_CONTROL_ADDRESS,
            "authority": "guest-firewall-only",
        }
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("operation", choices=("install",))
    value.add_argument("admin_source", nargs="?")
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if args.operation == "install":
        sys.stdout.buffer.write(canonical(install(
            admin_source_override=args.admin_source,
        )))
        return 0
    raise HostControlError("host_control_operation_invalid")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HostControlError, OSError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, HostControlError) else "host_control_failed"
        print(json.dumps({
            "schema": f"{SCHEMA}-error", "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
