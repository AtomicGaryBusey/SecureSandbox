#!/usr/bin/env python3
"""Verify sealed, operator-published white-box review bundles."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata

WORKSPACE = "/home/agent/research-workspace"
REVIEW_ROOT = "/var/lib/secure-sandbox/review-bundles"
REVIEW_VIEW = f"{WORKSPACE}/review-bundles"
TRUSTED_UID = 0
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ENTRIES = 128
MAX_TREE_ENTRIES = 2048
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_PATH_BYTES = 240
MAX_COMPONENTS = 16
BUNDLE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,55}[a-z0-9])?-review$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReviewBundleError(ValueError):
    pass


def safe_bundle_id(value: object) -> str:
    if not isinstance(value, str) or not BUNDLE_RE.fullmatch(value):
        raise ReviewBundleError("invalid_bundle_id")
    return value


def safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise ReviewBundleError("invalid_manifest_path")
    encoded = value.encode("utf-8", "strict")
    parts = value.split("/")
    if (len(encoded) > MAX_PATH_BYTES or len(parts) > MAX_COMPONENTS
            or any(part in {"", ".", ".."} for part in parts)):
        raise ReviewBundleError("invalid_manifest_path")
    for character in value:
        code = ord(character)
        if code < 0x20 or 0x7F <= code <= 0x9F or unicodedata.category(character) == "Cf":
            raise ReviewBundleError("invalid_manifest_path")
    return value


def trusted_directory(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
        raise ReviewBundleError("bundle_directory_untrusted")


def open_trusted_directory(path: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReviewBundleError("bundle_unavailable") from error
    try:
        trusted_directory(os.fstat(descriptor))
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def read_trusted_file(directory_fd: int, name: str, maximum: int) -> tuple[bytes, os.stat_result]:
    try:
        initial = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except OSError as error:
        raise ReviewBundleError("bundle_file_unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != TRUSTED_UID
                or before.st_mode & 0o022 or before.st_nlink != 1
                or before.st_size > maximum
                or (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino)):
            raise ReviewBundleError("bundle_file_untrusted")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                raise ReviewBundleError("bundle_file_too_large")
        after = os.fstat(descriptor)
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)):
            raise ReviewBundleError("bundle_changed_during_verification")
        return bytes(data), before
    finally:
        os.close(descriptor)


def parse_manifest(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ReviewBundleError("invalid_bundle_manifest") from error
    if not text.endswith("\n"):
        raise ReviewBundleError("invalid_bundle_manifest")
    records: dict[str, str] = {}
    lines = text.splitlines()
    if not lines or len(lines) > MAX_ENTRIES:
        raise ReviewBundleError("invalid_bundle_manifest")
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ReviewBundleError("invalid_bundle_manifest")
        digest, path = line[:64], safe_relative(line[66:])
        if not SHA256_RE.fullmatch(digest) or path == "SHA256SUMS" or path in records:
            raise ReviewBundleError("invalid_bundle_manifest")
        records[path] = digest
    if list(records) != sorted(records, key=lambda item: item.encode("utf-8")):
        raise ReviewBundleError("invalid_bundle_manifest")
    if ".bundle-id" not in records:
        raise ReviewBundleError("invalid_bundle_manifest")
    return records


def open_child_directory(parent_fd: int, name: str) -> int:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as error:
        raise ReviewBundleError("bundle_tree_untrusted") from error
    try:
        trusted_directory(os.fstat(descriptor))
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def enumerate_tree(root_fd: int) -> tuple[dict[str, tuple[int, str]], set[str]]:
    records: dict[str, tuple[int, str]] = {}
    directories: set[str] = set()
    total_bytes = 0
    tree_entries = 0

    def visit(directory_fd: int, parent: str) -> None:
        nonlocal total_bytes, tree_entries
        try:
            names = sorted(os.listdir(directory_fd), key=lambda item: item.encode("utf-8", "surrogateescape"))
        except OSError as error:
            raise ReviewBundleError("bundle_tree_unreadable") from error
        for name in names:
            relative = safe_relative(f"{parent}/{name}" if parent else name)
            tree_entries += 1
            if tree_entries > MAX_TREE_ENTRIES:
                raise ReviewBundleError("bundle_too_many_entries")
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise ReviewBundleError("bundle_tree_unreadable") from error
            if stat.S_ISDIR(info.st_mode):
                directories.add(relative)
                child = open_child_directory(directory_fd, name)
                try:
                    visit(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                data, trusted = read_trusted_file(directory_fd, name, MAX_FILE_BYTES)
                total_bytes += len(data)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ReviewBundleError("bundle_too_large")
                records[relative] = (trusted.st_size, hashlib.sha256(data).hexdigest())
            else:
                raise ReviewBundleError("bundle_tree_untrusted")

    visit(root_fd, "")
    return records, directories


def verify_review_bundle(bundle_id: object) -> dict:
    bundle = safe_bundle_id(bundle_id)
    root_fd = open_trusted_directory(REVIEW_ROOT)
    try:
        bundle_fd = open_child_directory(root_fd, bundle)
    finally:
        os.close(root_fd)
    try:
        manifest_data, _ = read_trusted_file(bundle_fd, "SHA256SUMS", MAX_MANIFEST_BYTES)
        expected = parse_manifest(manifest_data)
        actual, actual_directories = enumerate_tree(bundle_fd)
    finally:
        os.close(bundle_fd)
    expected_paths = set(expected)
    actual_paths = set(actual) - {"SHA256SUMS"}
    if actual_paths != expected_paths:
        raise ReviewBundleError("bundle_inventory_mismatch")
    expected_directories = {
        "/".join(path.split("/")[:depth])
        for path in expected_paths
        for depth in range(1, len(path.split("/")))
    }
    if actual_directories != expected_directories:
        raise ReviewBundleError("bundle_inventory_mismatch")
    for path, digest in expected.items():
        if actual[path][1] != digest:
            raise ReviewBundleError("bundle_digest_mismatch")
    if actual[".bundle-id"][0] != len(bundle.encode("utf-8")) + 1:
        raise ReviewBundleError("bundle_identity_mismatch")
    # Read again through the still-open tree contract embodied in the verified
    # digest, so a renamed root-owned bundle cannot be relabelled by its parent.
    identity_digest = hashlib.sha256((bundle + "\n").encode("utf-8")).hexdigest()
    if expected[".bundle-id"] != identity_digest:
        raise ReviewBundleError("bundle_identity_mismatch")
    entries = [
        {"path": path, "bytes": actual[path][0], "sha256": expected[path]}
        for path in sorted(expected) if path != ".bundle-id"
    ]
    return {
        "schema": "secure-sandbox-review-bundle-verification-v1",
        "bundle_id": bundle,
        "status": "verified",
        "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
        "file_count": len(entries),
        "total_bytes": sum(item["bytes"] for item in entries),
        "files": entries,
    }
