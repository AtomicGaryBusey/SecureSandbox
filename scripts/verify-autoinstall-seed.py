#!/usr/bin/env python3
"""Verify a generated NoCloud seed before Parallels can consume it."""

from __future__ import annotations

import argparse
import base64
import os
import re
import stat
import subprocess
from pathlib import Path


MAX_ISO = 4 * 1024 * 1024
MAX_MEMBER = 2 * 1024 * 1024
ROLES = {
    "gateway": "sandbox-gateway",
    "research": "sandbox-research",
    "target": "sandbox-target",
}
PAYLOADS = {
    "privileged_control.py": Path("scripts/privileged_control.py"),
    "privileged_control_entry.py": Path("scripts/privileged_control_entry.py"),
    "install-privileged-control.sh": Path("scripts/install-privileged-control.sh"),
    "privileged-control.sudoers": Path("config/privileged-control.sudoers"),
    "sshd-control.conf": Path("config/sshd-control.conf"),
}
NETPLANS = {role: Path(f"config/netplan-{role}.yaml") for role in ROLES}
EMBEDDED = re.compile(
    r"^    - /bin/sh -c \"printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d > "
    r"/target/root/secure-sandbox-control-bootstrap/([A-Za-z0-9._-]+) && chmod ([0-7]{4}) "
    r"/target/root/secure-sandbox-control-bootstrap/\2\"$"
)


class SeedFailure(RuntimeError):
    pass


def read_member(iso: Path, name: str) -> bytes:
    process = subprocess.Popen(
        ["/usr/bin/bsdtar", "-xOf", str(iso), name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    data = process.stdout.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER:
        process.kill()
        process.wait()
        raise SeedFailure(f"seed_member_too_large:{name}")
    if process.wait() != 0:
        raise SeedFailure(f"seed_member_unreadable:{name}")
    return data


def regular_bytes(path: Path) -> bytes:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise SeedFailure(f"source_not_regular:{path}")
        if opened.st_size > MAX_MEMBER:
            raise SeedFailure(f"source_too_large:{path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise SeedFailure(f"source_truncated:{path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise SeedFailure(f"source_changed:{path}")
        return data
    finally:
        os.close(descriptor)


def verify_content(repo: Path, meta_bytes: bytes, user_bytes: bytes, role: str) -> None:
    if role not in ROLES:
        raise SeedFailure("role_invalid")
    meta = meta_bytes.decode("ascii")
    if meta != f"instance-id: secure-sandbox-{role}\nlocal-hostname: {ROLES[role]}\n":
        raise SeedFailure("seed_metadata_invalid")
    user = user_bytes.decode("ascii")
    if (not user.startswith("#cloud-config\nautoinstall:\n") or "write_files:" in user
            or re.search(r"^  packages:$", user, re.MULTILINE)):
        raise SeedFailure("seed_schema_invalid")
    if any(marker in user for marker in ("PRIVATE KEY", "BEGIN OPENSSH", "BEGIN RSA")):
        raise SeedFailure("seed_private_key_forbidden")
    if not re.search(r"^    hostname: " + re.escape(ROLES[role]) + r"$", user, re.MULTILINE):
        raise SeedFailure("seed_hostname_invalid")
    if not re.search(r"^    password: '\$6\$[^']+'$", user, re.MULTILINE):
        raise SeedFailure("seed_password_hash_invalid")
    lines = user.splitlines()
    try:
        start = lines.index("  late-commands:") + 1
        end = lines.index("  shutdown: poweroff")
    except ValueError as error:
        raise SeedFailure("seed_commands_missing") from error
    commands = lines[start:end]
    if len(commands) != 13 or commands[0] != "    - install -d -m 0700 /target/root/secure-sandbox-control-bootstrap":
        raise SeedFailure("seed_commands_invalid")
    expected_modes = {
        "privileged_control.py": "0755",
        "privileged_control_entry.py": "0755",
        "install-privileged-control.sh": "0755",
        "privileged-control.sudoers": "0600",
        "sshd-control.conf": "0600",
    }
    seen: set[str] = set()
    for command in commands[1:7]:
        match = EMBEDDED.fullmatch(command)
        if not match:
            raise SeedFailure("seed_payload_command_invalid")
        encoded, name, mode = match.groups()
        if name == "netplan.yaml":
            expected_path = NETPLANS[role]
            expected_mode = "0600"
        else:
            expected_path = PAYLOADS.get(name)
            expected_mode = expected_modes.get(name)
        if name in seen or expected_path is None or mode != expected_mode:
            raise SeedFailure("seed_payload_inventory_invalid")
        seen.add(name)
        try:
            embedded = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise SeedFailure("seed_payload_encoding_invalid") from error
        if embedded != regular_bytes(repo / expected_path):
            raise SeedFailure(f"seed_payload_mismatch:{name}")
    if seen != set(PAYLOADS) | {"netplan.yaml"}:
        raise SeedFailure("seed_payload_inventory_invalid")
    key_match = EMBEDDED.fullmatch(commands[7])
    if not key_match or key_match.group(2) != "control_key.pub" or key_match.group(3) != "0600":
        raise SeedFailure("seed_control_key_command_invalid")
    if base64.b64decode(key_match.group(1), validate=True).strip() != regular_bytes(repo / "runs/control_key.pub").strip():
        raise SeedFailure("seed_control_key_mismatch")
    expected_backup = (
        "    - /bin/sh -c \"if [ -e /target/etc/netplan/00-installer-config.yaml ]; then "
        "[ ! -e /target/etc/netplan/00-installer-config.yaml.installer-backup ] && mv -- "
        "/target/etc/netplan/00-installer-config.yaml "
        "/target/etc/netplan/00-installer-config.yaml.installer-backup; fi\""
    )
    expected_netplan_install = (
        "    - install -D -m 0600 /target/root/secure-sandbox-control-bootstrap/netplan.yaml "
        "/target/etc/netplan/10-secure-sandbox.yaml"
    )
    expected_install = (
        "    - curtin in-target -- /root/secure-sandbox-control-bootstrap/"
        f"install-privileged-control.sh {role} /root/secure-sandbox-control-bootstrap/control_key.pub"
    )
    if (commands[8] != expected_backup or commands[9] != expected_netplan_install
            or commands[10] != "    - curtin in-target -- netplan generate"
            or commands[11] != expected_install
            or commands[12] != "    - rm -rf /target/root/secure-sandbox-control-bootstrap"):
        raise SeedFailure("seed_install_sequence_invalid")


def verify(repo: Path, iso: Path, role: str, protected_source: bool = False) -> dict[str, object]:
    if role not in ROLES:
        raise SeedFailure("role_invalid")
    metadata = iso.lstat()
    expected_uid = 0 if protected_source else os.geteuid()
    expected_mode = 0o444 if protected_source else 0o600
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != expected_mode
            or not 0 < metadata.st_size <= MAX_ISO):
        raise SeedFailure("seed_file_untrusted")
    inventory = subprocess.check_output(["/usr/bin/bsdtar", "-tf", str(iso)], stderr=subprocess.DEVNULL).decode("ascii").splitlines()
    if sorted(inventory) != [".", "meta-data", "user-data"]:
        raise SeedFailure("seed_inventory_invalid")
    verify_content(repo, read_member(iso, "meta-data"), read_member(iso, "user-data"), role)
    return {"schema": "secure-sandbox-autoinstall-seed-verification-v1", "role": role, "status": "verified"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=sorted(ROLES))
    parser.add_argument("iso")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--protected-source", action="store_true")
    arguments = parser.parse_args()
    try:
        result = verify(Path(arguments.repo), Path(arguments.iso), arguments.role, arguments.protected_source)
    except (OSError, UnicodeError, subprocess.SubprocessError, SeedFailure) as error:
        print(f"seed_verification_failed:{error}", file=os.sys.stderr)
        return 1
    import json
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
