#!/usr/bin/env python3
"""Authenticate the pinned Ubuntu installer before any privileged consumer uses it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


ARTIFACT_NAME = "ubuntu-26.04.1-live-server-arm64.iso"
CANONICAL_SHA256 = "af78753c94b924c85c4964c670692a853f7c80299a4064e317edad95462e3168"
AUTOINSTALL_ARTIFACT_NAME = "ubuntu-26.04.1-autoinstall-arm64.iso"
AUTOINSTALL_SHA256 = "c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804"
SIGNER_FINGERPRINT = "843938DF228D22F7B3742BC0D94AA3F0EFE21092"
GPGV_SHA256 = "__GPGV_SHA256__"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_KEYRING_BYTES = 1024 * 1024
MAX_INSTALLER_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_STORE = Path("/Library/Application Support/SecureSandbox/installers")


class VerificationFailure(RuntimeError):
    pass


def read_regular(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise VerificationFailure(f"untrusted_input:{path.name}") from error
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size > maximum):
            raise VerificationFailure(f"untrusted_input:{path.name}")
        value = bytearray()
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)
            if len(value) > maximum:
                raise VerificationFailure(f"input_too_large:{path.name}")
        after = os.fstat(descriptor)
        if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise VerificationFailure(f"input_changed_during_read:{path.name}")
        return bytes(value)
    finally:
        os.close(descriptor)


def open_regular(path: Path, maximum: int) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise VerificationFailure(f"untrusted_input:{path.name}") from error
    opened = os.fstat(descriptor)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size > maximum):
        os.close(descriptor)
        raise VerificationFailure(f"untrusted_input:{path.name}")
    return descriptor, opened


def digest_descriptor(descriptor: int, opened: os.stat_result, label: str, maximum: int) -> str:
    try:
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise VerificationFailure(f"input_too_large:{label}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise VerificationFailure(f"input_changed_during_read:{label}")
        return digest.hexdigest()
    except BaseException:
        os.close(descriptor)
        raise


def expected_digest(manifest: bytes) -> str:
    try:
        lines = manifest.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationFailure("manifest_not_ascii") from error
    suffixes = {f" {ARTIFACT_NAME}", f"*{ARTIFACT_NAME}"}
    matches = []
    for line in lines:
        if len(line) >= 66 and line[64:66] in {"  ", " *"} and line[66:] == ARTIFACT_NAME:
            matches.append(line[:64])
        elif any(line.endswith(suffix) for suffix in suffixes):
            raise VerificationFailure("manifest_entry_malformed")
    if len(matches) != 1 or not SHA256.fullmatch(matches[0]):
        raise VerificationFailure("manifest_entry_invalid")
    return matches[0]


def gpgv_binary() -> tuple[int | None, str]:
    if not SHA256.fullmatch(GPGV_SHA256):
        raise VerificationFailure("gpgv_binding_unconfigured")
    candidate = Path(__file__).resolve().with_name("gpgv")
    descriptor, opened = open_regular(candidate, 64 * 1024 * 1024)
    actual = digest_descriptor(descriptor, opened, "gpgv", 64 * 1024 * 1024)
    os.close(descriptor)
    if actual != GPGV_SHA256:
        raise VerificationFailure("gpgv_digest_mismatch")
    info = candidate.stat()
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise VerificationFailure("gpgv_permissions_invalid")
    return None, str(candidate)


def verify_signature(manifest: bytes, signature: bytes, keyring: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="secure-sandbox-ubuntu-verification-") as temporary:
        root = Path(temporary)
        paths = {"manifest": root / "SHA256SUMS", "signature": root / "SHA256SUMS.gpg",
                 "keyring": root / "ubuntu-archive-keyring.gpg"}
        for name, value in (("manifest", manifest), ("signature", signature), ("keyring", keyring)):
            descriptor = os.open(paths[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, value)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        gpgv_descriptor, gpgv_path = gpgv_binary()
        try:
            result = subprocess.run(
                [gpgv_path, "--status-fd", "1", "--keyring", str(paths["keyring"]),
                 str(paths["signature"]), str(paths["manifest"])],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                check=False, timeout=30, env={"PATH": "/usr/bin:/bin", "LANG": "C"}, text=True,
                pass_fds=() if gpgv_descriptor is None else (gpgv_descriptor,),
            )
        finally:
            if gpgv_descriptor is not None:
                os.close(gpgv_descriptor)
    fingerprints = {
        fields[2]
        for line in result.stdout.splitlines()
        if (fields := line.split()) and len(fields) >= 3 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]
    }
    if result.returncode != 0 or fingerprints != {SIGNER_FINGERPRINT}:
        raise VerificationFailure("manifest_signature_invalid")


def verified_metadata(release_directory: Path) -> dict[str, str]:
    manifest = read_regular(release_directory / "SHA256SUMS", MAX_MANIFEST_BYTES)
    signature = read_regular(release_directory / "SHA256SUMS.gpg", MAX_SIGNATURE_BYTES)
    keyring = read_regular(release_directory / "ubuntu-archive-keyring.gpg", MAX_KEYRING_BYTES)
    verify_signature(manifest, signature, keyring)
    digest = expected_digest(manifest)
    if digest != CANONICAL_SHA256:
        raise VerificationFailure("canonical_installer_digest_unpinned")
    return {
        "artifact": ARTIFACT_NAME,
        "sha256": digest,
        "signer": SIGNER_FINGERPRINT,
        "status": "verified",
    }


def open_verified(release_directory: Path) -> tuple[int, os.stat_result, dict[str, str]]:
    result = verified_metadata(release_directory)
    descriptor, opened = open_regular(release_directory / ARTIFACT_NAME, MAX_INSTALLER_BYTES)
    actual = digest_descriptor(descriptor, opened, ARTIFACT_NAME, MAX_INSTALLER_BYTES)
    if actual != result["sha256"]:
        os.close(descriptor)
        raise VerificationFailure("installer_digest_mismatch")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor, opened, result


def verify(release_directory: Path) -> dict[str, str]:
    descriptor, _, result = open_verified(release_directory)
    os.close(descriptor)
    return result


def open_prebound_autoinstall(
    release_directory: Path,
) -> tuple[int, os.stat_result, dict[str, str]]:
    """Open the reviewed derivative and bind it to the signed Canonical base."""
    canonical = verified_metadata(release_directory)
    descriptor, opened = open_regular(
        release_directory / AUTOINSTALL_ARTIFACT_NAME, MAX_INSTALLER_BYTES
    )
    actual = digest_descriptor(
        descriptor, opened, AUTOINSTALL_ARTIFACT_NAME, MAX_INSTALLER_BYTES
    )
    if actual != AUTOINSTALL_SHA256:
        os.close(descriptor)
        raise VerificationFailure("autoinstall_installer_digest_mismatch")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor, opened, {
        "artifact": AUTOINSTALL_ARTIFACT_NAME,
        "base_artifact": canonical["artifact"],
        "base_sha256": canonical["sha256"],
        "sha256": AUTOINSTALL_SHA256,
        "signer": canonical["signer"],
        "status": "verified",
    }


def validate_store(store: Path) -> None:
    """Validate the protected store without requiring privilege.

    Reading an already-published installer is intentionally unprivileged.  The
    ownership and mode checks below, rather than the caller's effective UID,
    establish that the bytes still belong to the root-owned trust domain.
    """
    current = store
    while current != current.parent:
        info = current.lstat()
        if (current.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise VerificationFailure(f"installer_store_untrusted:{current}")
        current = current.parent
    if store == DEFAULT_STORE:
        if (stat.S_IMODE(store.parent.stat().st_mode) != 0o711
                or stat.S_IMODE(store.stat().st_mode) != 0o711):
            raise VerificationFailure("installer_store_access_invalid")


def prepare_store(store: Path) -> None:
    if os.geteuid() != 0:
        raise VerificationFailure("root_required_for_promotion")
    store.mkdir(mode=0o711, parents=True, exist_ok=True)
    current = store
    while current != current.parent:
        info = current.lstat()
        if (current.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise VerificationFailure(f"installer_store_untrusted:{current}")
        current = current.parent
    if store == DEFAULT_STORE:
        os.chmod(store.parent, 0o711)
        os.chmod(store, 0o711)
    else:
        os.chmod(store, 0o755)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise VerificationFailure("promoted_installer_write_failed")
        view = view[written:]


def validate_promoted(path: Path, expected_digest: str, expected_uid: int = 0) -> None:
    descriptor, opened = open_regular(path, MAX_INSTALLER_BYTES)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o444:
            raise VerificationFailure("promoted_installer_permissions_invalid")
        actual = digest_descriptor(descriptor, opened, path.name, MAX_INSTALLER_BYTES)
        if actual != expected_digest:
            raise VerificationFailure("promoted_installer_digest_mismatch")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def promote(release_directory: Path, store: Path = DEFAULT_STORE) -> dict[str, str]:
    prepare_store(store)
    source, opened, result = open_verified(release_directory)
    destination = store / f"{result['sha256']}.iso"
    try:
        if destination.exists():
            validate_promoted(destination, result["sha256"])
        else:
            temporary = store / f".{result['sha256']}.new-{os.getpid()}"
            try:
                output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                try:
                    while True:
                        chunk = os.read(source, 1024 * 1024)
                        if not chunk:
                            break
                        write_all(output, chunk)
                    os.fsync(output)
                    os.fchmod(output, 0o444)
                finally:
                    os.close(output)
                after = os.fstat(source)
                if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise VerificationFailure(f"input_changed_during_read:{ARTIFACT_NAME}")
                os.rename(temporary, destination)
                fsync_directory(store)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            validate_promoted(destination, result["sha256"])
    finally:
        os.close(source)
    result["path"] = str(destination)
    result["status"] = "promoted"
    return result


def promote_autoinstall(release_directory: Path, store: Path = DEFAULT_STORE) -> dict[str, str]:
    """Promote only the pre-reviewed, content-bound autoinstall derivative."""
    prepare_store(store)
    source, opened, result = open_prebound_autoinstall(release_directory)
    destination = store / f"{AUTOINSTALL_SHA256}.iso"
    try:
        if destination.exists():
            validate_promoted(destination, AUTOINSTALL_SHA256)
        else:
            temporary = store / f".{AUTOINSTALL_SHA256}.new-{os.getpid()}"
            try:
                output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                try:
                    while True:
                        chunk = os.read(source, 1024 * 1024)
                        if not chunk:
                            break
                        write_all(output, chunk)
                    os.fsync(output)
                    os.fchmod(output, 0o444)
                finally:
                    os.close(output)
                after = os.fstat(source)
                if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise VerificationFailure(
                        f"input_changed_during_read:{AUTOINSTALL_ARTIFACT_NAME}"
                    )
                os.rename(temporary, destination)
                fsync_directory(store)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            validate_promoted(destination, AUTOINSTALL_SHA256)
    finally:
        os.close(source)
    result["path"] = str(destination)
    result["status"] = "promoted"
    return result


def use_promoted(release_directory: Path, store: Path = DEFAULT_STORE) -> dict[str, str]:
    """Authenticate and return an already-promoted installer without mutable source bytes."""
    validate_store(store)
    result = verified_metadata(release_directory)
    destination = store / f"{result['sha256']}.iso"
    validate_promoted(destination, result["sha256"])
    result["path"] = str(destination)
    result["status"] = "promoted_verified"
    return result


def use_promoted_autoinstall(
    release_directory: Path, store: Path = DEFAULT_STORE
) -> dict[str, str]:
    """Authenticate and return the protected, reviewed autoinstall derivative."""
    validate_store(store)
    canonical = verified_metadata(release_directory)
    destination = store / f"{AUTOINSTALL_SHA256}.iso"
    validate_promoted(destination, AUTOINSTALL_SHA256)
    return {
        "artifact": AUTOINSTALL_ARTIFACT_NAME,
        "base_artifact": canonical["artifact"],
        "base_sha256": canonical["sha256"],
        "sha256": AUTOINSTALL_SHA256,
        "signer": canonical["signer"],
        "path": str(destination),
        "status": "promoted_verified",
    }


def repair_store_access(release_directory: Path, store: Path = DEFAULT_STORE) -> dict[str, str]:
    """Repair traversal modes only after authenticating the protected installer."""
    if os.geteuid() != 0 or store != DEFAULT_STORE:
        raise VerificationFailure("default_store_root_required_for_access_repair")
    result = verified_metadata(release_directory)
    destination = store / f"{result['sha256']}.iso"
    for directory in (store.parent, store):
        info = directory.lstat()
        if (directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise VerificationFailure(f"installer_store_untrusted:{directory}")
    validate_promoted(destination, result["sha256"])
    os.chmod(store.parent, 0o711)
    os.chmod(store, 0o711)
    fsync_directory(store.parent.parent)
    fsync_directory(store.parent)
    validate_store(store)
    validate_promoted(destination, result["sha256"])
    result["path"] = str(destination)
    result["status"] = "store_access_repaired"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-directory", type=Path, required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--promote", action="store_true")
    action.add_argument("--use-promoted", action="store_true")
    action.add_argument("--promote-autoinstall", action="store_true")
    action.add_argument("--use-promoted-autoinstall", action="store_true")
    action.add_argument("--repair-store-access", action="store_true")
    parser.add_argument("--path-only", action="store_true")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE)
    args = parser.parse_args()
    if args.path_only and not (
        args.promote or args.use_promoted or args.promote_autoinstall
        or args.use_promoted_autoinstall or args.repair_store_access
    ):
        parser.error("--path-only requires a protected-store action")
    try:
        release_directory = args.release_directory.resolve(strict=True)
        if args.promote:
            result = promote(release_directory, args.store)
        elif args.use_promoted:
            result = use_promoted(release_directory, args.store)
        elif args.promote_autoinstall:
            result = promote_autoinstall(release_directory, args.store)
        elif args.use_promoted_autoinstall:
            result = use_promoted_autoinstall(release_directory, args.store)
        elif args.repair_store_access:
            result = repair_store_access(release_directory, args.store)
        else:
            result = verify(release_directory)
    except (OSError, VerificationFailure, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error), "status": "rejected"}, separators=(",", ":")))
        return 1
    print(result["path"] if args.path_only else json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
