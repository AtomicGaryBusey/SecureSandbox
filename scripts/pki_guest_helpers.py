#!/usr/bin/env python3
"""Small fail-closed filesystem and OpenSSL helpers for guest PKI managers."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from pki_lifecycle import LifecycleError


OPENSSL = "/usr/bin/openssl"


def run(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(arguments, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode:
        raise LifecycleError("external_operation_failed")
    return result.stdout


def require_regular(path: Path, maximum: int = 128 * 1024) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise LifecycleError("input_untrusted")


def atomic_copy(source: Path, target: Path, mode: int, uid: int | None = None, gid: int | None = None) -> None:
    require_regular(source)
    source_info = source.lstat()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary: Path | None = Path(temporary_name)
    try:
        source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(source_descriptor, "rb") as source_handle, os.fdopen(descriptor, "wb") as target_handle:
            opened = os.fstat(source_handle.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (source_info.st_dev, source_info.st_ino, source_info.st_size):
                raise LifecycleError("input_changed_during_copy")
            shutil.copyfileobj(source_handle, target_handle, 64 * 1024)
            after = os.fstat(source_handle.fileno())
            if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                raise LifecycleError("input_changed_during_copy")
            target_handle.flush()
            os.fsync(target_handle.fileno())
            os.fchmod(target_handle.fileno(), mode)
            os.fchown(target_handle.fileno(), os.geteuid() if uid is None else uid, os.getegid() if gid is None else gid)
        os.replace(temporary, target)
        temporary = None
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def key_spki(key: Path) -> bytes:
    require_regular(key)
    return run(OPENSSL, "pkey", "-in", str(key), "-pubout", "-outform", "DER")


def cert_spki(cert: Path) -> bytes:
    require_regular(cert)
    public = run(OPENSSL, "x509", "-in", str(cert), "-pubkey", "-noout")
    return run(OPENSSL, "pkey", "-pubin", "-outform", "DER", input_bytes=public)


def validate_chain(cert: Path, ca: Path) -> None:
    run(OPENSSL, "verify", "-CAfile", str(ca), str(cert))


def validate_subject(cert: Path, expected_cn: str) -> None:
    value = run(OPENSSL, "x509", "-in", str(cert), "-subject", "-noout", "-nameopt", "RFC2253").decode().strip()
    if value != f"subject=CN={expected_cn}":
        raise LifecycleError("certificate_subject_invalid")


__all__ = ["atomic_copy", "cert_spki", "key_spki", "require_regular", "run", "validate_chain", "validate_subject"]
