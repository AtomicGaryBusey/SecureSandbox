#!/usr/bin/env python3
"""Publish, verify, and roll back immutable host-controller releases."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "secure-sandbox-host-controller-release-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PAYLOAD_SOURCES = {
    "authorization_broker": Path("scripts/operator-authorization.py"),
    "authorization_service": Path("config/org.zebeth.securesandbox.authorization.plist"),
    "authorization_ui_bundle": Path("artifacts/host/SecureSandboxAuthorizationUI.bundle.json"),
    "authorization_ui_sources": Path("artifacts/host/SecureSandboxAuthorizationUI.sources.json"),
    "control_client": Path("scripts/privileged_control.py"),
    "controller": Path("scripts/claude-run-controller.sh"),
    "installer_verifier": Path("scripts/verify_ubuntu_installer.py"),
    "pki_anchor": Path("scripts/pki-host-anchor.py"),
    "release_manager": Path("scripts/host-controller-release.py"),
    "seed_verifier": Path("scripts/verify-autoinstall-seed.py"),
    "seed_gateway": Path("seeds/gateway-cidata.iso"),
    "seed_research": Path("seeds/research-cidata.iso"),
    "seed_target": Path("seeds/target-cidata.iso"),
    "ssh_config": Path("config/ssh_config"),
    "vm_maintenance": Path("scripts/vm-maintenance.py"),
}
PAYLOAD_NAMES = {*PAYLOAD_SOURCES, "gpgv"}
LAUNCHER_SOURCE = Path("scripts/secure-sandbox-claude-launcher.py")
DEFAULT_OP_BINARY = Path("/opt/homebrew/bin/op")
DEFAULT_GPGV_BINARY = Path("/opt/homebrew/bin/gpgv")
MAX_RELEASES = 32
MAX_RELEASE_DIRECTORY_ENTRIES = 64
MAX_ARCHIVED_RELEASES = 128
MAX_ACTIVE_MARKERS = 64
EXECUTION_APPROVAL_FLOOR = Path(
    "/usr/local/var/lib/secure-sandbox/execution-approval/minimum-floor.json"
)
EXECUTION_APPROVAL_V2_CAPABILITY = b"secure-sandbox-execution-approval-floor-enforcement-v2"
EXPECTED_MODES = {
    "authorization_broker": 0o755,
    "authorization_service": 0o444,
    "authorization_ui_bundle": 0o444,
    "authorization_ui": 0o555,
    "authorization_ui_sources": 0o444,
    "control_client": 0o755,
    "controller": 0o755,
    "gpgv": 0o555,
    "installer_verifier": 0o755,
    "pki_anchor": 0o755,
    "release_manager": 0o755,
    "seed_verifier": 0o755,
    "seed_gateway": 0o444,
    "seed_research": 0o444,
    "seed_target": 0o444,
    "ssh_config": 0o444,
    "vm_maintenance": 0o755,
    "manifest.json": 0o444,
    # Read only while validating an installed pre-v1 release during migration.
    "op_agents": 0o755,
}
AUTHORIZATION_UI_APP_SOURCE = Path("artifacts/host/SecureSandboxAuthorizationUI.app")
AUTHORIZATION_UI_APP_NAME = "SecureSandboxAuthorizationUI.app"
AUTHORIZATION_UI_EXECUTABLE = Path("Contents/MacOS/SecureSandboxAuthorizationUI")
PRE_PROFILED_TOUCHID_PAYLOAD_NAMES = {
    "authorization_broker", "authorization_service", "authorization_ui",
    "authorization_ui_sources", "control_client", "controller", "gpgv",
    "installer_verifier", "pki_anchor", "release_manager", "seed_gateway",
    "seed_research", "seed_target", "seed_verifier", "ssh_config", "vm_maintenance",
}
LEGACY_PAYLOAD_NAMES = {"controller", "op_agents", "ssh_config"}
PRE_INSTALLER_PAYLOAD_NAMES = {"controller", "op_agents", "pki_anchor", "ssh_config"}
PRE_CONTROL_PAYLOAD_NAMES = {
    "controller",
    "gpgv",
    "installer_verifier",
    "op_agents",
    "pki_anchor",
    "ssh_config",
}
PRE_AUTHORIZATION_PAYLOAD_NAMES = {
    "control_client",
    "controller",
    "gpgv",
    "installer_verifier",
    "pki_anchor",
    "ssh_config",
}
PRE_MAINTENANCE_PAYLOAD_NAMES = {
    "authorization_broker",
    "control_client",
    "controller",
    "gpgv",
    "installer_verifier",
    "pki_anchor",
    "release_manager",
    "ssh_config",
}
PRE_TOUCHID_PAYLOAD_NAMES = {
    "authorization_broker", "control_client", "controller", "gpgv",
    "installer_verifier", "pki_anchor", "release_manager", "seed_verifier",
    "seed_gateway", "seed_research", "seed_target", "ssh_config", "vm_maintenance",
}
PRE_SECURE_ENCLAVE_TOUCHID_SOURCE_NAMES = {
    "Package.swift",
    "Sources/AuthorizationCore/AuthorizationRequest.swift",
    "Sources/SecureSandboxAuthorizationUI/main.swift",
}
VULNERABLE_TOUCHID_MAIN_SOURCE_SHA256 = {
    "b519a8abaf84c1ba80a1a6b94426702e8d9c69ea11c8914b4b75c481137666a3",
}
RECOVERED_TOUCHID_MAIN_SOURCE_SHA256 = (
    "7050f9babbdb592b1ab2187fc229abc3c2215ab566255bf915cfcf7e6ce9eb8f"
)
RECOVERED_TOUCHID_UI_SHA256 = (
    "56937bb37bed4f854392c0aeaa8b6945622910ee3982a9eb81b64d7347f5bf7f"
)
RECOVERED_TOUCHID_SOURCES_SHA256 = (
    "0fe447b66cf8986337771503c4a28d5bc4d50e29ba928dd7654158f46f79fe8b"
)
DEFAULT_INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
DEFAULT_AUTHORIZATION_PLIST = Path(
    "/Library/LaunchDaemons/org.zebeth.securesandbox.authorization.plist"
)
AUTHORIZATION_LABEL = "org.zebeth.securesandbox.authorization"


class ReleaseFailure(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def release_identity(payloads: dict[str, str]) -> str:
    identity = bytearray()
    for name in sorted(payloads):
        identity.extend(f"{name}\0{payloads[name]}\n".encode("ascii"))
    return sha256_bytes(bytes(identity))


def read_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except (FileNotFoundError, OSError) as error:
        raise ReleaseFailure(f"source_not_regular:{path}") from error
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ReleaseFailure(f"source_not_regular:{path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ReleaseFailure(f"source_changed_during_read:{path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def authorization_ui_bundle_manifest(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("authorization_ui_bundle_manifest_invalid") from error
    files = value.get("files") if isinstance(value, dict) else None
    schema = value.get("schema") if isinstance(value, dict) else None
    expected_keys = ({"bundle", "files", "schema"} if schema == "secure-sandbox-touchid-ui-bundle-v1"
                     else {"bundle", "files", "schema", "signing_policy"})
    if (schema not in {"secure-sandbox-touchid-ui-bundle-v1", "secure-sandbox-touchid-ui-bundle-v2"}
            or set(value) != expected_keys
            or value.get("bundle") != AUTHORIZATION_UI_APP_NAME
            or not isinstance(files, dict) or not 4 <= len(files) <= 16
            or AUTHORIZATION_UI_EXECUTABLE.as_posix() not in files
            or "Contents/embedded.provisionprofile" not in files):
        raise ReleaseFailure("authorization_ui_bundle_manifest_invalid")
    if schema == "secure-sandbox-touchid-ui-bundle-v2":
        authorization_ui_signing_policy(value)
    for relative, record in files.items():
        path = Path(relative)
        if (not isinstance(relative, str) or path.is_absolute() or ".." in path.parts
                or len(path.parts) < 2 or not isinstance(record, dict)
                or set(record) != {"mode", "sha256", "size"}
                or record["mode"] not in {0o444, 0o555}
                or not isinstance(record["size"], int) or isinstance(record["size"], bool)
                or not 0 <= record["size"] <= 16 * 1024 * 1024
                or not isinstance(record["sha256"], str)
                or SHA256.fullmatch(record["sha256"]) is None):
            raise ReleaseFailure("authorization_ui_bundle_manifest_invalid")
    if files[AUTHORIZATION_UI_EXECUTABLE.as_posix()]["mode"] != 0o555:
        raise ReleaseFailure("authorization_ui_bundle_manifest_invalid")
    return value


def authorization_ui_signing_policy(manifest: dict[str, Any]) -> dict[str, str] | None:
    if manifest.get("schema") == "secure-sandbox-touchid-ui-bundle-v1":
        return None
    policy = manifest.get("signing_policy")
    if (not isinstance(policy, dict)
            or set(policy) != {"access_group", "application_identifier", "bundle_id", "team_id"}
            or not isinstance(policy.get("team_id"), str)
            or re.fullmatch(r"[A-Z0-9]{10}", policy["team_id"]) is None
            or policy.get("bundle_id") != "org.zebeth.SecureSandbox.AuthorizationUI"
            or policy.get("application_identifier") != policy["team_id"] + "." + policy["bundle_id"]
            or policy.get("access_group") != policy["application_identifier"]):
        raise ReleaseFailure("authorization_ui_signing_policy_invalid")
    return policy


def verify_authorization_ui_bundle(root: Path, manifest_data: bytes,
                                   expected_uid: int | None = None) -> None:
    manifest = authorization_ui_bundle_manifest(manifest_data)
    expected_files = set(manifest["files"])
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    if root.is_symlink() or not root.is_dir():
        raise ReleaseFailure("authorization_ui_bundle_invalid")
    root_info = root.lstat()
    if stat.S_IMODE(root_info.st_mode) != 0o555:
        raise ReleaseFailure("authorization_ui_bundle_mode_invalid")
    if expected_uid is not None and root_info.st_uid != expected_uid:
        raise ReleaseFailure("authorization_ui_bundle_owner_invalid")
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReleaseFailure("authorization_ui_bundle_invalid")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
            if stat.S_IMODE(info.st_mode) != 0o555:
                raise ReleaseFailure("authorization_ui_bundle_mode_invalid")
        elif stat.S_ISREG(info.st_mode):
            actual_files.add(relative)
        else:
            raise ReleaseFailure("authorization_ui_bundle_invalid")
        if expected_uid is not None and info.st_uid != expected_uid:
            raise ReleaseFailure("authorization_ui_bundle_owner_invalid")
    expected_directories = {
        Path(*Path(relative).parts[:index]).as_posix()
        for relative in expected_files for index in range(1, len(Path(relative).parts))
    }
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ReleaseFailure("authorization_ui_bundle_entries_invalid")
    for relative, record in manifest["files"].items():
        path = root / relative
        info = path.lstat()
        data = read_regular(path)
        if (stat.S_IMODE(info.st_mode) != record["mode"]
                or len(data) != record["size"]
                or sha256_bytes(data) != record["sha256"]):
            raise ReleaseFailure("authorization_ui_bundle_member_invalid:" + relative)


def copy_authorization_ui_bundle(source: Path, destination: Path,
                                 manifest_data: bytes, expected_uid: int) -> None:
    verify_authorization_ui_bundle(source, manifest_data)
    manifest = authorization_ui_bundle_manifest(manifest_data)
    destination.mkdir(mode=0o755)
    directories = sorted({
        Path(*Path(relative).parts[:index])
        for relative in manifest["files"] for index in range(1, len(Path(relative).parts))
    }, key=lambda path: (len(path.parts), path.as_posix()))
    for relative in directories:
        (destination / relative).mkdir(mode=0o755)
    for relative, record in manifest["files"].items():
        data = read_regular(source / relative)
        path = destination / relative
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, record["mode"])
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
            os.fchmod(descriptor, record["mode"])
        finally:
            os.close(descriptor)
    for relative in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        os.chmod(destination / relative, 0o555)
        fsync_directory(destination / relative)
    os.chmod(destination, 0o555)
    verify_authorization_ui_bundle(destination, manifest_data, expected_uid)


def execution_approval_floor(expected_uid: int = 0,
                             path: Path | None = None) -> tuple[int, int]:
    path = EXECUTION_APPROVAL_FLOOR if path is None else path
    try:
        info = path.lstat()
    except FileNotFoundError:
        return 1, 0
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        expected = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    except (OSError, UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("execution_approval_floor_invalid") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or raw != expected
            or not isinstance(value, dict)
            or set(value) != {"schema", "minimum_protocol", "minimum_epoch", "updated_at"}
            or value.get("schema") != "secure-sandbox-execution-approval-floor-v1"
            or value.get("minimum_protocol") not in {1, 2}
            or not isinstance(value.get("minimum_epoch"), int)
            or isinstance(value.get("minimum_epoch"), bool)
            or value["minimum_epoch"] < 0):
        raise ReleaseFailure("execution_approval_floor_invalid")
    return value["minimum_protocol"], value["minimum_epoch"]


def enforce_execution_approval_floor(broker: bytes, expected_uid: int = 0) -> None:
    minimum_protocol, _minimum_epoch = execution_approval_floor(expected_uid)
    if minimum_protocol >= 2 and EXECUTION_APPROVAL_V2_CAPABILITY not in broker:
        raise ReleaseFailure("release_below_execution_approval_floor")


def source_payload(
    repo: Path,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> tuple[dict[str, bytes], dict[str, str], str]:
    values = {name: read_regular(repo / relative) for name, relative in PAYLOAD_SOURCES.items()}
    try:
        config_path = repo / ".private/secure-enclave-ddd.json"
        config_info = config_path.lstat()
        config = json.loads(read_regular(config_path))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("secure_enclave_local_config_invalid") from error
    legacy_digest = config.get("legacy_launchservices_ui_bundle_sha256")
    if (not stat.S_ISREG(config_info.st_mode) or stat.S_ISLNK(config_info.st_mode)
            or config_info.st_uid != os.geteuid() or config_info.st_nlink != 1
            or stat.S_IMODE(config_info.st_mode) != 0o600
            or config.get("schema") != "secure-sandbox-secure-enclave-ddd-local-config-v1"
            or not isinstance(legacy_digest, str) or SHA256.fullmatch(legacy_digest) is None):
        raise ReleaseFailure("secure_enclave_local_config_invalid")
    broker = values["authorization_broker"]
    marker = b"__LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256__"
    if broker.count(marker) != 1:
        raise ReleaseFailure("authorization_broker_template_invalid")
    values["authorization_broker"] = broker.replace(marker, legacy_digest.encode("ascii"))
    resolved_gpgv = gpgv_binary.resolve(strict=True)
    gpgv_bytes = read_regular(resolved_gpgv)
    values["gpgv"] = gpgv_bytes
    verifier = values["installer_verifier"]
    if verifier.count(b"__GPGV_SHA256__") != 1:
        raise ReleaseFailure("installer_verifier_template_invalid")
    values["installer_verifier"] = verifier.replace(
        b"__GPGV_SHA256__", sha256_bytes(gpgv_bytes).encode("ascii")
    )
    validate_touchid_payload(repo, values)
    try:
        compile(values["control_client"], str(repo / PAYLOAD_SOURCES["control_client"]), "exec")
        compile(values["authorization_broker"], str(repo / PAYLOAD_SOURCES["authorization_broker"]), "exec")
        compile(values["pki_anchor"], str(repo / PAYLOAD_SOURCES["pki_anchor"]), "exec")
        compile(values["release_manager"], str(repo / PAYLOAD_SOURCES["release_manager"]), "exec")
        compile(values["installer_verifier"], str(repo / PAYLOAD_SOURCES["installer_verifier"]), "exec")
        compile(values["seed_verifier"], str(repo / PAYLOAD_SOURCES["seed_verifier"]), "exec")
        compile(values["vm_maintenance"], str(repo / PAYLOAD_SOURCES["vm_maintenance"]), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("python_payload_syntax_invalid") from error
    hashes = {name: sha256_bytes(value) for name, value in values.items()}
    return values, hashes, release_identity(hashes)


def validate_touchid_payload(repo: Path, values: dict[str, bytes]) -> None:
    try:
        source_manifest = json.loads(values["authorization_ui_sources"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("authorization_ui_source_manifest_invalid") from error
    source_names = {
        "Package.swift",
        "AuthorizationUI.entitlements",
        "Info.plist",
        "SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj",
        "Sources/AuthorizationCore/AuthorizationRequest.swift",
        "Sources/AuthorizationCore/ExecutionApprovalCrypto.swift",
        "Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift",
        "Sources/SecureSandboxAuthorizationUI/main.swift",
    }
    if (source_manifest.get("schema") != "secure-sandbox-touchid-ui-source-v1"
            or set(source_manifest.get("sources", {})) != source_names):
        raise ReleaseFailure("authorization_ui_source_manifest_invalid")
    package = repo / "macos/TouchIDAuthorization"
    for name, expected in source_manifest["sources"].items():
        if (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or sha256_bytes(read_regular(package / name)) != expected):
            raise ReleaseFailure(f"authorization_ui_source_mismatch:{name}")
    try:
        service = plistlib.loads(values["authorization_service"])
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("authorization_service_plist_invalid") from error
    expected_arguments = [
        "/usr/bin/python3", "-I",
        "/usr/local/libexec/secure-sandbox-host/current/authorization_broker",
        "serve-touchid",
    ]
    if (service.get("Label") != AUTHORIZATION_LABEL
            or service.get("ProgramArguments") != expected_arguments
            or service.get("RunAtLoad") is not True or service.get("KeepAlive") is not True):
        raise ReleaseFailure("authorization_service_plist_invalid")
    bundle = repo / AUTHORIZATION_UI_APP_SOURCE
    bundle_manifest = authorization_ui_bundle_manifest(values["authorization_ui_bundle"])
    verify_authorization_ui_bundle(bundle, values["authorization_ui_bundle"])
    binary = bundle / AUTHORIZATION_UI_EXECUTABLE
    signature = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(bundle)],
        check=False, capture_output=True, text=True,
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(bundle)],
        check=False, capture_output=True, text=True,
    )
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(bundle)],
        check=False, capture_output=True,
    )
    try:
        entitlement_value = plistlib.loads(entitlements.stdout)
    except plistlib.InvalidFileException as error:
        raise ReleaseFailure("authorization_ui_entitlements_invalid") from error
    policy = authorization_ui_signing_policy(bundle_manifest)
    if policy is None:
        team = entitlement_value.get("com.apple.developer.team-identifier")
        bundle_id = "org.zebeth.SecureSandbox.AuthorizationUI"
        application_identifier = team + "." + bundle_id if isinstance(team, str) else ""
        if not isinstance(team, str) or re.fullmatch(r"[A-Z0-9]{10}", team) is None:
            raise ReleaseFailure("authorization_ui_signature_invalid")
        policy = {"team_id":team, "bundle_id":bundle_id,
                  "application_identifier":application_identifier,
                  "access_group":application_identifier}
    expected_entitlements = {
        "com.apple.application-identifier":policy["application_identifier"],
        "com.apple.developer.team-identifier":policy["team_id"],
        "keychain-access-groups":[policy["access_group"]],
    }
    requirement = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2",
         f'-R=identifier "{policy["bundle_id"]}" and anchor apple generic and certificate leaf[subject.OU] = "{policy["team_id"]}"',
         str(bundle)],
        check=False, capture_output=True, text=True,
    )
    profile = subprocess.run(
        ["/usr/bin/security", "cms", "-D", "-i",
         str(bundle / "Contents/embedded.provisionprofile")],
        check=False, capture_output=True,
    )
    try:
        profile_value = plistlib.loads(profile.stdout)
        profile_entitlements = profile_value["Entitlements"]
        expiration = profile_value["ExpirationDate"]
    except (KeyError, TypeError, plistlib.InvalidFileException) as error:
        raise ReleaseFailure("authorization_ui_profile_invalid") from error
    profile_valid = (
        profile.returncode == 0
        and profile_value.get("Platform") == ["OSX"]
        and profile_value.get("ApplicationIdentifierPrefix") == [policy["team_id"]]
        and profile_value.get("TeamIdentifier") == [policy["team_id"]]
        and profile_entitlements.get("com.apple.application-identifier")
            == policy["application_identifier"]
        and profile_entitlements.get("com.apple.developer.team-identifier") == policy["team_id"]
        and profile_entitlements.get("keychain-access-groups") == [policy["team_id"] + ".*"]
        and isinstance(expiration, datetime.datetime)
        and expiration.replace(tzinfo=datetime.timezone.utc) >
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=48)
    )
    if (signature.returncode != 0 or details.returncode != 0
            or requirement.returncode != 0 or entitlements.returncode != 0
            or "runtime" not in details.stderr
            or f'TeamIdentifier={policy["team_id"]}' not in details.stderr
            or f'Identifier={policy["bundle_id"]}' not in details.stderr
            or entitlement_value != expected_entitlements or not profile_valid):
        raise ReleaseFailure("authorization_ui_signature_invalid")


def invoking_home() -> Path:
    name = os.environ.get("SUDO_USER")
    if name:
        return Path(pwd.getpwnam(name).pw_dir)
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def active_markers(state_root: Path) -> list[str]:
    if state_root.exists() and (state_root.is_symlink() or not state_root.is_dir()):
        raise ReleaseFailure("controller_state_directory_invalid")
    active = state_root / "active"
    if not active.exists():
        return []
    if active.is_symlink() or not active.is_dir():
        raise ReleaseFailure("active_marker_directory_invalid")
    markers = list(active.iterdir())
    if len(markers) > MAX_ACTIVE_MARKERS:
        raise ReleaseFailure("active_marker_limit_exceeded")
    live: list[str] = []
    for marker in markers:
        if marker.is_symlink() or not marker.is_file():
            raise ReleaseFailure("active_marker_invalid")
        try:
            value = json.loads(marker.read_text(encoding="ascii"))
            pid = value["pid"]
            release_id = value["release_id"]
            if not isinstance(pid, int) or pid <= 1 or not isinstance(release_id, str) or not SHA256.fullmatch(release_id):
                raise ValueError
            os.kill(pid, 0)
            live.append(marker.name)
        except ProcessLookupError:
            marker.unlink()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            raise ReleaseFailure(f"active_marker_unreadable:{marker.name}") from error
    return live


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def manages_live_touchid_service(install_root: Path, expected_uid: int) -> bool:
    return expected_uid == 0 and install_root == DEFAULT_INSTALL_ROOT


def stop_touchid_service(plist_path: Path = DEFAULT_AUTHORIZATION_PLIST) -> None:
    subprocess.run(
        ["/bin/launchctl", "bootout", f"system/{AUTHORIZATION_LABEL}"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        plist_path.unlink()
        fsync_directory(plist_path.parent)
    except FileNotFoundError:
        pass


def touchid_service_is_loaded() -> bool:
    inspected = subprocess.run(
        ["/bin/launchctl", "print", f"system/{AUTHORIZATION_LABEL}"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return inspected.returncode == 0


def restart_touchid_service() -> None:
    restarted = subprocess.run(
        ["/bin/launchctl", "kickstart", "-k", f"system/{AUTHORIZATION_LABEL}"],
        check=False, capture_output=True, text=True,
    )
    if restarted.returncode != 0:
        raise ReleaseFailure(
            "authorization_service_restart_failed:" + restarted.stderr.strip()[:240]
        )
    if not touchid_service_is_loaded():
        raise ReleaseFailure("authorization_service_restart_verification_failed")


def install_touchid_service(release: Path,
                            plist_path: Path = DEFAULT_AUTHORIZATION_PLIST) -> None:
    source = release / "authorization_service"
    data = read_regular(source)
    temporary = plist_path.parent / f".{plist_path.name}.new-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise ReleaseFailure("authorization_service_short_write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
    finally:
        os.close(descriptor)
    os.replace(temporary, plist_path)
    fsync_directory(plist_path.parent)
    # Never terminate the daemon that is authorizing this release update.  Its
    # broker notices the current-release transition after it has sent the bound
    # response, exits cleanly, and launchd then starts this newly selected
    # release.  A first installation still needs an explicit bootstrap.
    if touchid_service_is_loaded():
        return
    subprocess.run(
        ["/bin/launchctl", "bootout", f"system/{AUTHORIZATION_LABEL}"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    loaded = subprocess.run(
        ["/bin/launchctl", "bootstrap", "system", str(plist_path)],
        check=False, capture_output=True, text=True,
    )
    if loaded.returncode != 0:
        raise ReleaseFailure("authorization_service_bootstrap_failed:" + loaded.stderr.strip()[:240])


def atomic_symlink(target: str, link: Path) -> None:
    temporary = link.parent / f".{link.name}.new-{os.getpid()}"
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    temporary.symlink_to(target)
    # The authorization broker runs with a restrictive umask. On macOS that
    # umask is reflected in symlink modes and can prevent the unprivileged
    # launcher and verifiers from traversing an otherwise public selector.
    os.chmod(temporary, 0o755, follow_symlinks=False)
    os.replace(temporary, link)
    fsync_directory(link.parent)


def ensure_root(default_layout: bool) -> None:
    if default_layout and os.geteuid() != 0:
        raise ReleaseFailure("root_required")


def prepare_release_root(install_root: Path, expected_uid: int) -> Path:
    releases = install_root / "releases"
    if install_root.exists():
        info = install_root.lstat()
        if install_root.is_symlink() or not install_root.is_dir() or info.st_uid != expected_uid:
            raise ReleaseFailure("install_root_untrusted")
    if releases.exists():
        info = releases.lstat()
        if releases.is_symlink() or not releases.is_dir() or info.st_uid != expected_uid:
            raise ReleaseFailure("release_root_untrusted")
    releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(install_root, 0o755)
    os.chmod(releases, 0o755)
    entries = list(releases.iterdir())
    if len(entries) > MAX_RELEASE_DIRECTORY_ENTRIES:
        raise ReleaseFailure("release_root_entry_limit_exceeded")
    release_count = 0
    for entry in entries:
        if entry.name.startswith(".staging-"):
            info = entry.lstat()
            if entry.is_symlink() or not entry.is_dir() or info.st_uid != expected_uid:
                raise ReleaseFailure("release_root_untrusted")
            os.chmod(entry, 0o755)
            shutil.rmtree(entry)
            continue
        if not SHA256.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            raise ReleaseFailure("release_root_untrusted")
        release_count += 1
    if release_count > MAX_RELEASES:
        raise ReleaseFailure("release_count_limit_exceeded")
    return releases


def release_archive_plan(install_root: Path, expected_uid: int) -> dict[str, Any]:
    releases = install_root / "releases"
    info = releases.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o755):
        raise ReleaseFailure("release_root_untrusted")
    entries = sorted(releases.iterdir(), key=lambda path: path.name)
    if len(entries) > MAX_RELEASE_DIRECTORY_ENTRIES:
        raise ReleaseFailure("release_root_entry_limit_exceeded")
    release_ids: list[str] = []
    release_modes: dict[str, int] = {}
    for entry in entries:
        entry_info = entry.lstat()
        if (not SHA256.fullmatch(entry.name) or not stat.S_ISDIR(entry_info.st_mode)
                or stat.S_ISLNK(entry_info.st_mode) or entry_info.st_uid != expected_uid
                or stat.S_IMODE(entry_info.st_mode) not in {0o555, 0o755}):
            raise ReleaseFailure("release_root_untrusted")
        release_ids.append(entry.name)
        release_modes[entry.name] = stat.S_IMODE(entry_info.st_mode)
    if len(release_ids) < MAX_RELEASES:
        raise ReleaseFailure("release_capacity_recovery_not_required")
    current_path, _ = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    previous_id: str | None = None
    previous = install_root / "previous"
    if previous.is_symlink():
        previous_path, _ = verified_release(
            install_root, previous, expected_uid, allow_legacy=True,
        )
        previous_id = previous_path.name
    elif previous.exists():
        raise ReleaseFailure("release_link_invalid:previous")
    protected = {current_path.name}
    if previous_id is not None:
        protected.add(previous_id)
    if any(release_modes[release_id] != 0o555 for release_id in protected):
        raise ReleaseFailure("release_root_untrusted")
    archive_ids = [release_id for release_id in release_ids if release_id not in protected]
    if not archive_ids:
        raise ReleaseFailure("release_capacity_recovery_unsafe")
    plan = {
        "schema": "secure-sandbox-host-release-archive-plan-v1",
        "current_release_id": current_path.name,
        "previous_release_id": previous_id,
        "archive_release_ids": archive_ids,
    }
    plan["plan_sha256"] = sha256_bytes(
        json.dumps(plan, separators=(",", ":"), sort_keys=True).encode("ascii")
    )
    return plan


def archive_inactive_releases(
    install_root: Path, state_root: Path, expected_uid: int,
    expected_current_release_id: str, expected_previous_release_id: str,
    expected_plan_sha256: str,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    plan = release_archive_plan(install_root, expected_uid)
    expected_previous = plan["previous_release_id"] or "none"
    if (plan["current_release_id"] != expected_current_release_id
            or expected_previous != expected_previous_release_id
            or plan["plan_sha256"] != expected_plan_sha256):
        raise ReleaseFailure("release_archive_plan_changed")
    archive = install_root / "release-archive"
    try:
        archive.mkdir(mode=0o755)
        fsync_directory(install_root)
    except FileExistsError:
        pass
    archive_info = archive.lstat()
    if (not stat.S_ISDIR(archive_info.st_mode) or stat.S_ISLNK(archive_info.st_mode)
            or archive_info.st_uid != expected_uid
            or stat.S_IMODE(archive_info.st_mode) != 0o755):
        raise ReleaseFailure("release_archive_untrusted")
    existing = list(archive.iterdir())
    if len(existing) + len(plan["archive_release_ids"]) > MAX_ARCHIVED_RELEASES:
        raise ReleaseFailure("release_archive_count_limit_exceeded")
    for entry in existing:
        entry_info = entry.lstat()
        if (not SHA256.fullmatch(entry.name) or not stat.S_ISDIR(entry_info.st_mode)
                or stat.S_ISLNK(entry_info.st_mode) or entry_info.st_uid != expected_uid
                or stat.S_IMODE(entry_info.st_mode) not in {0o555, 0o755}):
            raise ReleaseFailure("release_archive_untrusted")
        if stat.S_IMODE(entry_info.st_mode) == 0o755:
            os.chmod(entry, 0o555)
    releases = install_root / "releases"
    for release_id in plan["archive_release_ids"]:
        source = releases / release_id
        destination = archive / release_id
        if destination.exists() or destination.is_symlink():
            raise ReleaseFailure("release_archive_collision")
        if stat.S_IMODE(source.lstat().st_mode) == 0o755:
            os.chmod(source, 0o555)
        verification_link = install_root / f".archive-verify-{os.getpid()}"
        verification_link.symlink_to(f"releases/{release_id}")
        try:
            verified_release(install_root, verification_link, expected_uid, allow_legacy=True)
        finally:
            verification_link.unlink(missing_ok=True)
        # macOS requires write permission on a directory being renamed even
        # when both parents are writable.  No controller is active, and the
        # directory is unreferenced; restore immutable mode on either outcome.
        os.chmod(source, 0o755)
        try:
            os.rename(source, destination)
        except BaseException:
            os.chmod(source, 0o555)
            raise
        os.chmod(destination, 0o555)
        fsync_directory(archive)
        fsync_directory(releases)
    return {
        "schema": "secure-sandbox-host-release-archive-v1",
        "status": "archived",
        "archived": len(plan["archive_release_ids"]),
        "retained_release_ids": sorted(filter(None, (
            plan["current_release_id"], plan["previous_release_id"],
        ))),
        "plan_sha256": plan["plan_sha256"],
    }


def exact_mode(path: Path, mode: int) -> None:
    os.chmod(path, mode, follow_symlinks=False)


def validate_shell_payload(value: bytes, label: str) -> None:
    with tempfile.NamedTemporaryFile(prefix=f"secure-sandbox-{label}-", suffix=".sh") as syntax_copy:
        syntax_copy.write(value)
        syntax_copy.flush()
        syntax_result = subprocess.run(
            ["/bin/bash", "-n", syntax_copy.name], check=False, capture_output=True, text=True
        )
        if syntax_result.returncode != 0:
            raise ReleaseFailure(f"{label}_syntax_invalid")


def install(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
    expected_source_release_id: str | None = None,
    payload_override: tuple[dict[str, bytes], dict[str, str], str] | None = None,
    verify_against_source: bool = True,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if payload_override is None:
        values, hashes, release_id = source_payload(repo, op_binary, gpgv_binary)
    else:
        values, hashes, release_id = payload_override
        if (set(values) != PAYLOAD_NAMES or set(hashes) != PAYLOAD_NAMES
                or hashes != {name: sha256_bytes(value) for name, value in values.items()}
                or release_id != release_identity(hashes)):
            raise ReleaseFailure("payload_override_invalid")
    if expected_source_release_id is not None:
        if not SHA256.fullmatch(expected_source_release_id) or release_id != expected_source_release_id:
            raise ReleaseFailure("source_release_id_unexpected")
    enforce_execution_approval_floor(values["authorization_broker"], expected_uid)
    launcher_bytes = read_regular(repo / LAUNCHER_SOURCE)
    try:
        compile(launcher_bytes, str(repo / LAUNCHER_SOURCE), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("stable_launcher_syntax_invalid") from error
    validate_shell_payload(values["controller"], "controller")
    releases = prepare_release_root(install_root, expected_uid)
    final = releases / release_id
    if not final.exists():
        if sum(1 for entry in releases.iterdir() if SHA256.fullmatch(entry.name)) >= MAX_RELEASES:
            raise ReleaseFailure("release_count_limit_exceeded")
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
        try:
            for name, value in values.items():
                path = staging / name
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                mode = EXPECTED_MODES[name]
                descriptor = os.open(path, flags, mode)
                try:
                    os.write(descriptor, value)
                    os.fsync(descriptor)
                    os.fchmod(descriptor, mode)
                finally:
                    os.close(descriptor)
            copy_authorization_ui_bundle(
                repo / AUTHORIZATION_UI_APP_SOURCE,
                staging / AUTHORIZATION_UI_APP_NAME,
                values["authorization_ui_bundle"], expected_uid,
            )
            manifest = {"schema": SCHEMA, "release_id": release_id, "payloads": hashes}
            manifest_path = staging / "manifest.json"
            descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
            try:
                os.write(descriptor, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
                os.fsync(descriptor)
                os.fchmod(descriptor, EXPECTED_MODES["manifest.json"])
            finally:
                os.close(descriptor)
            os.chmod(staging, 0o555)
            fsync_directory(staging)
            os.rename(staging, final)
            fsync_directory(releases)
        except BaseException:
            if staging.exists():
                os.chmod(staging, 0o755)
                shutil.rmtree(staging)
            raise
    candidate = install_root / f".candidate-{os.getpid()}"
    candidate.symlink_to(f"releases/{release_id}")
    try:
        verified_release(install_root, candidate, expected_uid)
    finally:
        candidate.unlink()
    current = install_root / "current"
    old_current: str | None = None
    if current.is_symlink():
        old_path, old_manifest = verified_release(install_root, current, expected_uid, allow_legacy=True)
        if set(old_manifest["payloads"]) in (
            PAYLOAD_NAMES, PRE_PROFILED_TOUCHID_PAYLOAD_NAMES, PRE_TOUCHID_PAYLOAD_NAMES,
        ):
            old_current = f"releases/{old_path.name}"
    elif current.exists():
        raise ReleaseFailure("release_link_invalid:current")
    launcher_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if launcher_path.exists():
        installed_launcher = read_regular(launcher_path)
        launcher_info = launcher_path.stat()
        if launcher_info.st_uid != expected_uid or launcher_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReleaseFailure("launcher_permissions_invalid")
        if installed_launcher != launcher_bytes:
            raise ReleaseFailure("stable_launcher_change_requires_migration")
    else:
        launcher_tmp = launcher_path.parent / f".{launcher_path.name}.new-{os.getpid()}"
        descriptor = os.open(launcher_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        try:
            os.write(descriptor, launcher_bytes)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o755)
        finally:
            os.close(descriptor)
        os.replace(launcher_tmp, launcher_path)
        fsync_directory(launcher_path.parent)
    if old_current and old_current != f"releases/{release_id}":
        atomic_symlink(old_current, install_root / "previous")
    elif not old_current and (install_root / "previous").is_symlink():
        (install_root / "previous").unlink()
        fsync_directory(install_root)
    atomic_symlink(f"releases/{release_id}", current)
    try:
        if verify_against_source:
            result = verify(repo, install_root, launcher_path, expected_uid, op_binary, gpgv_binary)
        else:
            verified_path, verified_manifest = verified_release(
                install_root, current, expected_uid,
            )
            if (verified_path.name != release_id
                    or verified_manifest["payloads"] != hashes
                    or sha256_bytes(read_regular(launcher_path)) != sha256_bytes(launcher_bytes)):
                raise ReleaseFailure("recovery_release_verification_failed")
            result = {
                "schema": SCHEMA,
                "status": "verified",
                "release_id": release_id,
                "launcher_sha256": sha256_bytes(launcher_bytes),
                "payloads": hashes,
            }
        if manages_live_touchid_service(install_root, expected_uid):
            install_touchid_service(final)
    except BaseException:
        if manages_live_touchid_service(install_root, expected_uid):
            stop_touchid_service()
        if old_current:
            atomic_symlink(old_current, current)
        else:
            current.unlink(missing_ok=True)
            fsync_directory(install_root)
        raise
    result["status"] = "deployed"
    return result


def verified_release(
    install_root: Path, link: Path, expected_uid: int, allow_legacy: bool = False
) -> tuple[Path, dict[str, Any]]:
    releases = install_root / "releases"
    if not link.is_symlink():
        raise ReleaseFailure(f"release_link_missing:{link.name}")
    path = link.resolve(strict=True)
    try:
        relative = path.relative_to(releases.resolve(strict=True))
    except ValueError as error:
        raise ReleaseFailure(f"release_link_escapes_root:{link.name}") from error
    if len(relative.parts) != 1 or not SHA256.fullmatch(relative.name):
        raise ReleaseFailure("release_id_invalid")
    manifest_path = path / "manifest.json"
    manifest = json.loads(read_regular(manifest_path).decode("utf-8"))
    if manifest.get("schema") != SCHEMA or manifest.get("release_id") != relative.name:
        raise ReleaseFailure("release_manifest_identity_mismatch")
    payloads = manifest.get("payloads")
    valid_names = PAYLOAD_NAMES
    if not isinstance(payloads, dict) or (
        set(payloads) != valid_names and not (
            allow_legacy and set(payloads) in (
                LEGACY_PAYLOAD_NAMES,
                PRE_INSTALLER_PAYLOAD_NAMES,
                PRE_CONTROL_PAYLOAD_NAMES,
                PRE_AUTHORIZATION_PAYLOAD_NAMES,
                PRE_MAINTENANCE_PAYLOAD_NAMES,
                PRE_TOUCHID_PAYLOAD_NAMES,
                PRE_PROFILED_TOUCHID_PAYLOAD_NAMES,
            )
        )
    ):
        raise ReleaseFailure("release_manifest_payloads_invalid")
    for item in [install_root, releases, path, manifest_path, *(path / name for name in payloads)]:
        info = item.stat()
        if info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReleaseFailure(f"release_permissions_invalid:{item.name}")
    if stat.S_IMODE(install_root.stat().st_mode) != 0o755 or stat.S_IMODE(releases.stat().st_mode) != 0o755:
        raise ReleaseFailure("release_root_mode_invalid")
    if stat.S_IMODE(path.stat().st_mode) != 0o555:
        raise ReleaseFailure("release_directory_mode_invalid")
    for name in [*payloads, "manifest.json"]:
        expected_mode = EXPECTED_MODES[name]
        if stat.S_IMODE((path / name).stat().st_mode) != expected_mode:
            raise ReleaseFailure(f"release_mode_invalid:{name}")
    for name, expected in payloads.items():
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise ReleaseFailure("release_manifest_hash_invalid")
        if sha256_bytes(read_regular(path / name)) != expected:
            raise ReleaseFailure(f"release_payload_hash_mismatch:{name}")
    if set(payloads) == PAYLOAD_NAMES:
        verify_authorization_ui_bundle(
            path / AUTHORIZATION_UI_APP_NAME,
            read_regular(path / "authorization_ui_bundle"), expected_uid,
        )
    if release_identity(payloads) != relative.name:
        raise ReleaseFailure("release_digest_mismatch")
    if "authorization_broker" in payloads:
        enforce_execution_approval_floor(
            read_regular(path / "authorization_broker"), expected_uid
        )
    return path, manifest


def verify(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    path, manifest = verified_release(install_root, install_root / "current", expected_uid)
    launcher = read_regular(launcher_path)
    source_launcher = read_regular(repo / LAUNCHER_SOURCE)
    if sha256_bytes(launcher) != sha256_bytes(source_launcher):
        raise ReleaseFailure("launcher_source_mismatch")
    info = launcher_path.stat()
    if (info.st_uid != expected_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or stat.S_IMODE(info.st_mode) != 0o755):
        raise ReleaseFailure("launcher_permissions_invalid")
    _, source_hashes, source_id = source_payload(repo, op_binary, gpgv_binary)
    if manifest["payloads"] != source_hashes or manifest["release_id"] != source_id:
        raise ReleaseFailure("active_release_source_mismatch")
    return {
        "schema": SCHEMA,
        "status": "verified",
        "release_id": path.name,
        "launcher_sha256": sha256_bytes(launcher),
        "payloads": manifest["payloads"],
    }


def rollback(
    repo: Path,
    install_root: Path,
    state_root: Path,
    target_id: str | None,
    expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    current_path, _ = verified_release(install_root, install_root / "current", expected_uid)
    if target_id is None:
        target_path, _ = verified_release(
            install_root, install_root / "previous", expected_uid, allow_legacy=True,
        )
    else:
        if not SHA256.fullmatch(target_id):
            raise ReleaseFailure("rollback_release_id_invalid")
        target_link = install_root / f".rollback-{os.getpid()}"
        target_link.symlink_to(f"releases/{target_id}")
        try:
            target_path, _ = verified_release(
                install_root, target_link, expected_uid, allow_legacy=True,
            )
        finally:
            target_link.unlink()
    if target_path == current_path:
        raise ReleaseFailure("rollback_target_already_current")
    try:
        _, _, source_id = source_payload(repo, op_binary, gpgv_binary)
        repo_match: bool | None = target_path.name == source_id
    except (ReleaseFailure, OSError):
        repo_match = None
    atomic_symlink(f"releases/{current_path.name}", install_root / "previous")
    atomic_symlink(f"releases/{target_path.name}", install_root / "current")
    if manages_live_touchid_service(install_root, expected_uid):
        if (target_path / "authorization_service").is_file():
            install_touchid_service(target_path)
        else:
            stop_touchid_service()
    return {
        "schema": SCHEMA,
        "status": "rolled_back",
        "release_id": target_path.name,
        "repo_match": repo_match,
        "warning": None if repo_match is True else "active_release_source_mismatch_until_repository_realigns",
    }


def migrate_launcher(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    expected_installed_sha256: str,
    expected_replacement_sha256: str,
) -> dict[str, Any]:
    live = active_markers(state_root)
    if live:
        raise ReleaseFailure("active_controller_invocations:" + ",".join(live))
    if not SHA256.fullmatch(expected_installed_sha256) or not SHA256.fullmatch(expected_replacement_sha256):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    verified_release(install_root, install_root / "current", expected_uid, allow_legacy=True)
    installed = read_regular(launcher_path)
    installed_hash = sha256_bytes(installed)
    if installed_hash != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    info = launcher_path.stat()
    if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o755:
        raise ReleaseFailure("launcher_permissions_invalid")
    replacement = read_regular(repo / LAUNCHER_SOURCE)
    try:
        compile(replacement, str(repo / LAUNCHER_SOURCE), "exec")
    except SyntaxError as error:
        raise ReleaseFailure("stable_launcher_syntax_invalid") from error
    replacement_hash = sha256_bytes(replacement)
    if replacement_hash != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    if replacement_hash == installed_hash:
        raise ReleaseFailure("launcher_migration_not_required")
    backup_root = install_root / "launcher-backups"
    if backup_root.exists():
        backup_info = backup_root.lstat()
        if backup_root.is_symlink() or not backup_root.is_dir() or backup_info.st_uid != expected_uid:
            raise ReleaseFailure("launcher_backup_root_untrusted")
    backup_root.mkdir(mode=0o555, exist_ok=True)
    exact_mode(backup_root, 0o555)
    backup = backup_root / installed_hash
    if not backup.exists():
        exact_mode(backup_root, 0o755)
        descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o555)
        try:
            os.write(descriptor, installed)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o555)
        finally:
            os.close(descriptor)
        exact_mode(backup_root, 0o555)
        fsync_directory(backup_root)
    else:
        backup_info = backup.stat()
        if (backup_info.st_uid != expected_uid or stat.S_IMODE(backup_info.st_mode) != 0o555
                or sha256_bytes(read_regular(backup)) != installed_hash):
            raise ReleaseFailure("launcher_backup_mismatch")
    temporary = launcher_path.parent / f".{launcher_path.name}.migration-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    try:
        os.write(descriptor, replacement)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o755)
    finally:
        os.close(descriptor)
    os.replace(temporary, launcher_path)
    fsync_directory(launcher_path.parent)
    if sha256_bytes(read_regular(launcher_path)) != replacement_hash:
        raise ReleaseFailure("launcher_migration_verification_failed")
    return {
        "schema": SCHEMA,
        "status": "launcher_migrated",
        "previous_launcher_sha256": installed_hash,
        "launcher_sha256": replacement_hash,
        "backup": str(backup),
    }


def bootstrap_authorization(
    repo: Path,
    install_root: Path,
    launcher_path: Path,
    state_root: Path,
    expected_uid: int,
    expected_source_release_id: str,
    expected_installed_sha256: str,
    expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY,
    gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """Install the first broker while preserving explicit launcher migration."""
    if not SHA256.fullmatch(expected_source_release_id):
        raise ReleaseFailure("expected_source_release_id_required")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if source_release_id != expected_source_release_id:
        raise ReleaseFailure("source_release_id_unexpected")
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    if "authorization_broker" in current_manifest["payloads"]:
        raise ReleaseFailure("authorization_broker_already_deployed")
    if not SHA256.fullmatch(expected_installed_sha256):
        raise ReleaseFailure("expected_launcher_hash_invalid")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    result.update({
        "status": "authorization_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def recover_terminal_schema_service(
    repo: Path, current_path: Path, install_root: Path, launcher_path: Path,
    expected_uid: int, expected_source_release_id: str,
    op_binary: Path, gpgv_binary: Path,
) -> dict[str, Any] | None:
    """Finish a schema bootstrap that committed `current` before daemon re-exec."""
    if current_path.name != expected_source_release_id:
        return None
    result = verify(
        repo, install_root, launcher_path, expected_uid, op_binary, gpgv_binary,
    )
    if result.get("release_id") != expected_source_release_id:
        raise ReleaseFailure("schema_bootstrap_recovery_release_mismatch")
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result["recovered_existing_release"] = True
    return result


def bootstrap_maintenance_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time, content-bound migration from the eight-payload broker release."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"maintenance_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_MAINTENANCE_PAYLOAD_NAMES:
        raise ReleaseFailure("maintenance_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({"status": "maintenance_schema_bootstrapped",
                   "launcher_migrated": launcher_migrated})
    return result


def bootstrap_touchid_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time, content-bound migration to the signed Touch ID payload schema."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"touchid_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_TOUCHID_PAYLOAD_NAMES:
        raise ReleaseFailure("touchid_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status": "touchid_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def bootstrap_secure_enclave_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration to the Secure Enclave UI source schema."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"secure_enclave_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PAYLOAD_NAMES:
        raise ReleaseFailure("secure_enclave_schema_predecessor_invalid")
    try:
        installed_sources = json.loads(
            read_regular(current_path / "authorization_ui_sources").decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFailure("secure_enclave_schema_predecessor_invalid") from error
    if (installed_sources.get("schema") != "secure-sandbox-touchid-ui-source-v1"
            or set(installed_sources.get("sources", {}))
            != PRE_SECURE_ENCLAVE_TOUCHID_SOURCE_NAMES):
        raise ReleaseFailure("secure_enclave_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status": "secure_enclave_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def bootstrap_profiled_touchid_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration from a flat UI to a provisioned app bundle."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    _values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"profiled_touchid_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PRE_PROFILED_TOUCHID_PAYLOAD_NAMES:
        raise ReleaseFailure("profiled_touchid_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    # This migration is authorized by the terminal-bound bootstrap, not by the
    # launchd broker.  No broker request remains to answer after install(), so
    # re-exec the already-loaded service now.  Otherwise it keeps the old
    # Python module in memory while resolving files through the new `current`
    # selector and rejects every provisioned UI handshake.
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status": "profiled_touchid_schema_bootstrapped",
        "launcher_migrated": launcher_migrated,
        "previous_release_id": current_path.name,
    })
    return result


def bootstrap_touchid_bundle_v2_schema(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_current_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time exact-release migration from the v1 to v2 bundle manifest."""
    current_path, current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    if (not SHA256.fullmatch(expected_current_release_id)
            or current_path.name != expected_current_release_id):
        raise ReleaseFailure("current_release_id_unexpected")
    values, _hashes, source_release_id = source_payload(repo, op_binary, gpgv_binary)
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    recovered = recover_terminal_schema_service(
        repo, current_path, install_root, launcher_path, expected_uid,
        expected_source_release_id, op_binary, gpgv_binary,
    )
    if recovered is not None:
        recovered.update({
            "status":"touchid_bundle_v2_schema_bootstrapped",
            "launcher_migrated":False,
        })
        return recovered
    if set(current_manifest["payloads"]) != PAYLOAD_NAMES:
        raise ReleaseFailure("touchid_bundle_v2_schema_predecessor_invalid")
    installed_bundle = authorization_ui_bundle_manifest(
        read_regular(current_path / "authorization_ui_bundle")
    )
    replacement_bundle = authorization_ui_bundle_manifest(
        values["authorization_ui_bundle"]
    )
    if (installed_bundle.get("schema") != "secure-sandbox-touchid-ui-bundle-v1"
            or replacement_bundle.get("schema") != "secure-sandbox-touchid-ui-bundle-v2"):
        raise ReleaseFailure("touchid_bundle_v2_schema_migration_not_required")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    launcher_migrated = False
    if installed_sha256 != replacement_sha256:
        migrate_launcher(
            repo, install_root, launcher_path, state_root, expected_uid,
            installed_sha256, replacement_sha256,
        )
        launcher_migrated = True
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
    )
    if manages_live_touchid_service(install_root, expected_uid):
        restart_touchid_service()
    result.update({
        "status":"touchid_bundle_v2_schema_bootstrapped",
        "launcher_migrated":launcher_migrated,
        "previous_release_id":current_path.name,
    })
    return result


def recover_touchid_ui(
    repo: Path, install_root: Path, launcher_path: Path, state_root: Path,
    expected_uid: int, expected_source_release_id: str,
    expected_installed_sha256: str, expected_replacement_sha256: str,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> dict[str, Any]:
    """One-time, content-bound recovery from the known no-window AppKit build."""
    current_path, _current_manifest = verified_release(
        install_root, install_root / "current", expected_uid,
    )
    values, hashes, source_release_id = touchid_ui_recovery_payload(
        repo, install_root, expected_uid, op_binary, gpgv_binary,
    )
    if (not SHA256.fullmatch(expected_source_release_id)
            or source_release_id != expected_source_release_id):
        raise ReleaseFailure("source_release_id_unexpected")
    installed_sha256 = sha256_bytes(read_regular(launcher_path))
    replacement_sha256 = sha256_bytes(read_regular(repo / LAUNCHER_SOURCE))
    if installed_sha256 != expected_installed_sha256:
        raise ReleaseFailure("installed_launcher_hash_unexpected")
    if replacement_sha256 != expected_replacement_sha256:
        raise ReleaseFailure("replacement_launcher_hash_unexpected")
    if installed_sha256 != replacement_sha256:
        raise ReleaseFailure("touchid_ui_recovery_launcher_change_forbidden")
    result = install(
        repo, install_root, launcher_path, state_root, expected_uid,
        op_binary, gpgv_binary, expected_source_release_id,
        payload_override=(values, hashes, source_release_id),
        verify_against_source=False,
    )
    result.update({
        "status": "touchid_ui_recovered",
        "launcher_migrated": False,
        "previous_release_id": current_path.name,
    })
    return result


def touchid_ui_recovery_payload(
    repo: Path, install_root: Path, expected_uid: int,
    op_binary: Path = DEFAULT_OP_BINARY, gpgv_binary: Path = DEFAULT_GPGV_BINARY,
) -> tuple[dict[str, bytes], dict[str, str], str]:
    verified_release(
        install_root, install_root / "current", expected_uid, allow_legacy=True,
    )
    raise ReleaseFailure("touchid_ui_recovery_superseded_by_profiled_schema")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "command",
        choices=("install", "verify", "rollback", "migrate-launcher", "bootstrap-authorization",
                 "bootstrap-maintenance-schema", "bootstrap-touchid-schema",
                 "bootstrap-secure-enclave-schema", "bootstrap-profiled-touchid-schema",
                 "bootstrap-touchid-bundle-v2-schema",
                 "recover-touchid-ui",
                 "archive-inactive-releases"),
    )
    result.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    result.add_argument("--install-root", type=Path, default=Path("/usr/local/libexec/secure-sandbox-host"))
    result.add_argument("--launcher", type=Path, default=Path("/usr/local/bin/secure-sandbox-claude"))
    result.add_argument("--state-root", type=Path)
    result.add_argument("--release-id")
    result.add_argument("--expected-launcher-sha256")
    result.add_argument("--expected-replacement-sha256")
    result.add_argument("--expected-source-release-id")
    result.add_argument("--expected-current-release-id")
    result.add_argument("--expected-previous-release-id")
    result.add_argument("--expected-plan-sha256")
    result.add_argument("--op-binary", type=Path, default=DEFAULT_OP_BINARY)
    result.add_argument("--gpgv-binary", type=Path, default=DEFAULT_GPGV_BINARY)
    result.add_argument("--json", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    default_layout = args.install_root == Path("/usr/local/libexec/secure-sandbox-host")
    if args.state_root is None:
        state_root = invoking_home() / "Library/Application Support/SecureSandbox/controller-state"
    else:
        state_root = args.state_root
    expected_uid = 0 if default_layout else os.geteuid()
    try:
        if args.command == "install":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if default_layout and not args.expected_source_release_id:
                raise ReleaseFailure("expected_source_release_id_required")
            result = install(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.op_binary, args.gpgv_binary,
                args.expected_source_release_id,
            )
        elif args.command == "verify":
            result = verify(
                args.repo.resolve(), args.install_root, args.launcher,
                expected_uid, args.op_binary, args.gpgv_binary,
            )
        elif args.command == "rollback":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            result = rollback(
                args.repo.resolve(), args.install_root, state_root, args.release_id,
                expected_uid, args.op_binary, args.gpgv_binary,
            )
        elif args.command == "migrate-launcher":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if not args.expected_launcher_sha256 or not args.expected_replacement_sha256:
                raise ReleaseFailure("expected_launcher_hash_required")
            result = migrate_launcher(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_launcher_sha256, args.expected_replacement_sha256,
            )
        elif args.command == "archive-inactive-releases":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if not all((args.expected_current_release_id,
                        args.expected_previous_release_id,
                        args.expected_plan_sha256)):
                raise ReleaseFailure("release_archive_binding_required")
            if (SHA256.fullmatch(args.expected_current_release_id) is None
                    or (args.expected_previous_release_id != "none"
                        and SHA256.fullmatch(args.expected_previous_release_id) is None)
                    or SHA256.fullmatch(args.expected_plan_sha256) is None):
                raise ReleaseFailure("release_archive_binding_invalid")
            result = archive_inactive_releases(
                args.install_root, state_root, expected_uid,
                args.expected_current_release_id,
                args.expected_previous_release_id,
                args.expected_plan_sha256,
            )
        elif args.command == "bootstrap-authorization":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("bootstrap_binding_required")
            result = bootstrap_authorization(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-maintenance-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("maintenance_schema_binding_required")
            result = bootstrap_maintenance_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-touchid-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("touchid_schema_binding_required")
            result = bootstrap_touchid_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-secure-enclave-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("secure_enclave_schema_binding_required")
            result = bootstrap_secure_enclave_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-profiled-touchid-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("profiled_touchid_schema_binding_required")
            result = bootstrap_profiled_touchid_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        elif args.command == "bootstrap-touchid-bundle-v2-schema":
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_current_release_id
                    or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("touchid_bundle_v2_schema_binding_required")
            result = bootstrap_touchid_bundle_v2_schema(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_current_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        else:
            ensure_root(default_layout)
            if default_layout and args.state_root is None:
                raise ReleaseFailure("state_root_required_for_privileged_mutation")
            if (not args.expected_source_release_id or not args.expected_launcher_sha256
                    or not args.expected_replacement_sha256):
                raise ReleaseFailure("touchid_ui_recovery_binding_required")
            result = recover_touchid_ui(
                args.repo.resolve(), args.install_root, args.launcher, state_root,
                expected_uid, args.expected_source_release_id,
                args.expected_launcher_sha256, args.expected_replacement_sha256,
                args.op_binary, args.gpgv_binary,
            )
        print(json.dumps(result, indent=2 if args.json else None, sort_keys=True))
        return 0
    except (ReleaseFailure, OSError, subprocess.CalledProcessError, json.JSONDecodeError, SyntaxError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
