#!/usr/bin/env python3
"""Closed, descriptor-checked source preparation for native Host releases."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Mapping, Optional, Tuple


MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20000
MAX_PATH_BYTES = 4096
SIGNING_CONFIG_RELATIVE = (
    "macos/TouchIDAuthorization/Signing.local.xcconfig"
)
EXPECTED_SIGNING_CONFIG = (
    b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
)
SHA256 = set("0123456789abcdef")
RENAME_EXCL = 0x00000004


class SourceError(RuntimeError):
    """The release source or its retained identity is not trustworthy."""


def rename_exclusive_at(
    source_parent: int, source: str, destination_parent: int, destination: str,
) -> None:
    """Move one name without ever replacing an existing destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = getattr(libc, "renameatx_np", None)
    if renameatx_np is None:
        raise SourceError("release_cleanup_atomic_rename_unavailable")
    renameatx_np.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx_np.restype = ctypes.c_int
    if renameatx_np(
        source_parent, os.fsencode(source), destination_parent,
        os.fsencode(destination), RENAME_EXCL,
    ) != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value), source)


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value, allow_nan=False, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def sha256_valid(value: str) -> bool:
    return len(value) == 64 and not (set(value) - SHA256)


def stable_identity(info: os.stat_result) -> Tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def directory_identity(info: os.stat_result) -> Tuple[int, ...]:
    # Directory link count and timestamps legitimately change as children are
    # published.  The namespace object itself must not change.
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        stat.S_IMODE(info.st_mode),
    )


def no_acl(path: Path) -> bool:
    completed = subprocess.run(
        ["/bin/ls", "-lde", str(path)], check=False,
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
    )
    lines = completed.stdout.splitlines()
    return (
        completed.returncode == 0 and len(lines) == 1
        and "+" not in lines[0].split()[0]
    )


def open_directory(
    path: Path, *, empty: bool = False, private: bool = True,
) -> Tuple[int, os.stat_result]:
    try:
        before = path.lstat()
        descriptor = os.open(
            str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        raise SourceError("release_source_directory_untrusted") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(named.st_mode)
        or stable_identity(before) != stable_identity(opened)
        or stable_identity(opened) != stable_identity(named)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & (0o077 if private else 0o022)
        or not no_acl(path)
    ):
        os.close(descriptor)
        raise SourceError("release_source_directory_untrusted")
    if empty and any(os.scandir(descriptor)):
        os.close(descriptor)
        raise SourceError("release_source_directory_not_empty")
    return descriptor, opened


def open_regular(path: Path) -> Tuple[int, os.stat_result]:
    try:
        before = path.lstat()
        descriptor = os.open(
            str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        raise SourceError("release_source_file_untrusted") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode) or stat.S_ISLNK(named.st_mode)
        or stable_identity(before) != stable_identity(opened)
        or stable_identity(opened) != stable_identity(named)
        or opened.st_uid != os.geteuid() or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) & 0o022
        or not no_acl(path)
    ):
        os.close(descriptor)
        raise SourceError("release_source_file_untrusted")
    return descriptor, opened


def read_and_hash(descriptor: int, limit: int = MAX_ARCHIVE_BYTES) -> Tuple[bytes, str]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    data = bytearray()
    digest = hashlib.sha256()
    while len(data) <= limit:
        block = os.read(descriptor, min(1024 * 1024, limit + 1 - len(data)))
        if not block:
            break
        data.extend(block)
        digest.update(block)
    if len(data) > limit:
        raise SourceError("release_source_file_too_large")
    return bytes(data), digest.hexdigest()


def safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name or name.startswith("/") or path.is_absolute()
        or "." in path.parts or ".." in path.parts
        or len(name.encode("utf-8")) > MAX_PATH_BYTES
    ):
        raise SourceError("release_source_archive_path_invalid")
    return path


def normalized_file_mode(mode: int) -> int:
    return 0o555 if mode & 0o111 else 0o444


def archive_record_from_bytes(raw: bytes) -> Tuple[Dict[str, Dict[str, object]], List[Tuple[tarfile.TarInfo, bytes]]]:
    entries: Dict[str, Dict[str, object]] = {}
    extracted: List[Tuple[tarfile.TarInfo, bytes]] = []
    total = 0
    try:
        import io
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if not 1 <= len(members) <= MAX_ARCHIVE_ENTRIES:
                raise SourceError("release_source_archive_inventory_invalid")
            for member in members:
                relative = safe_relative(member.name).as_posix()
                if relative in entries:
                    raise SourceError("release_source_archive_duplicate")
                if member.isdir():
                    entries[relative] = {"kind": "directory", "mode": 0o755}
                    extracted.append((member, b""))
                    continue
                if not member.isreg() or member.size < 0:
                    raise SourceError("release_source_archive_entry_invalid")
                total += member.size
                if total > MAX_ARCHIVE_BYTES:
                    raise SourceError("release_source_archive_too_large")
                source = archive.extractfile(member)
                if source is None:
                    raise SourceError("release_source_archive_entry_invalid")
                payload = source.read(member.size + 1)
                if len(payload) != member.size:
                    raise SourceError("release_source_archive_entry_invalid")
                mode = normalized_file_mode(member.mode)
                entries[relative] = {
                    "kind": "file", "mode": mode,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
                extracted.append((member, payload))
    except (OSError, tarfile.TarError, UnicodeError) as error:
        raise SourceError("release_source_archive_invalid") from error
    # Every file parent must either be an explicit directory or be the root.
    for relative in tuple(entries):
        parts = PurePosixPath(relative).parts
        for index in range(1, len(parts)):
            parent = PurePosixPath(*parts[:index]).as_posix()
            if entries.get(parent) != {"kind": "directory", "mode": 0o755}:
                raise SourceError("release_source_archive_parent_invalid")
    return entries, extracted


def open_child_directory(parent: int, name: str) -> int:
    return os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent,
    )


def parent_descriptor(root: int, parts: Iterable[str]) -> int:
    current = os.dup(root)
    try:
        for part in parts:
            next_descriptor = open_child_directory(current, part)
            os.close(current)
            current = next_descriptor
        return current
    except BaseException:
        os.close(current)
        raise


def extract_archive(root: int, extracted: List[Tuple[tarfile.TarInfo, bytes]]) -> None:
    directories = sorted(
        (safe_relative(member.name) for member, _ in extracted if member.isdir()),
        key=lambda item: len(item.parts),
    )
    for relative in directories:
        parent = parent_descriptor(root, relative.parts[:-1])
        try:
            os.mkdir(relative.name, 0o755, dir_fd=parent)
            child = open_child_directory(parent, relative.name)
            try:
                os.fchmod(child, 0o755)
                os.fsync(child)
            finally:
                os.close(child)
        finally:
            os.close(parent)
    for member, payload in extracted:
        if not member.isreg():
            continue
        relative = safe_relative(member.name)
        parent = parent_descriptor(root, relative.parts[:-1])
        try:
            descriptor = os.open(
                relative.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                normalized_file_mode(member.mode), dir_fd=parent,
            )
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise SourceError("release_source_extract_write_failed")
                    view = view[written:]
                os.fchmod(descriptor, normalized_file_mode(member.mode))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent)
        finally:
            os.close(parent)
    os.fsync(root)


def tree_record(root: Path, *, exclude: Optional[str] = None) -> Dict[str, Dict[str, object]]:
    root_descriptor, root_info = open_directory(root)
    entries: Dict[str, Dict[str, object]] = {}

    def visit(descriptor: int, prefix: Tuple[str, ...]) -> None:
        for entry in sorted(os.scandir(descriptor), key=lambda item: item.name):
            relative = PurePosixPath(*(prefix + (entry.name,))).as_posix()
            if relative == exclude:
                continue
            before = entry.stat(follow_symlinks=False)
            if before.st_dev != root_info.st_dev or before.st_uid != os.geteuid():
                raise SourceError("release_source_tree_entry_untrusted")
            if stat.S_ISDIR(before.st_mode):
                child = open_child_directory(descriptor, entry.name)
                try:
                    opened = os.fstat(child)
                    if stable_identity(before) != stable_identity(opened):
                        raise SourceError("release_source_tree_changed")
                    mode = stat.S_IMODE(opened.st_mode)
                    if mode & 0o022:
                        raise SourceError("release_source_tree_entry_untrusted")
                    entries[relative] = {"kind": "directory", "mode": mode}
                    visit(child, prefix + (entry.name,))
                    after = os.fstat(child)
                    if stable_identity(opened) != stable_identity(after):
                        raise SourceError("release_source_tree_changed")
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise SourceError("release_source_tree_entry_invalid")
            child = os.open(
                entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if stable_identity(before) != stable_identity(opened):
                    raise SourceError("release_source_tree_changed")
                raw, digest = read_and_hash(child)
                after = os.fstat(child)
                if stable_identity(opened) != stable_identity(after):
                    raise SourceError("release_source_tree_changed")
                mode = stat.S_IMODE(opened.st_mode)
                if mode & 0o022 or len(raw) != opened.st_size:
                    raise SourceError("release_source_tree_entry_untrusted")
                entries[relative] = {
                    "kind": "file", "mode": mode,
                    "sha256": digest, "size": len(raw),
                }
            finally:
                os.close(child)

    try:
        visit(root_descriptor, ())
        named = root.lstat()
        after = os.fstat(root_descriptor)
        if directory_identity(root_info) != directory_identity(named) or directory_identity(root_info) != directory_identity(after):
            raise SourceError("release_source_directory_changed")
    finally:
        os.close(root_descriptor)
    return entries


def record_digest(entries: Mapping[str, Mapping[str, object]]) -> str:
    return hashlib.sha256(canonical({"entries": entries, "schema": "secure-sandbox-native-host-source-tree-v1"})).hexdigest()


def git_environment() -> Dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C", "LANG": "C", "HOME": "/var/empty",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
    }


def git(repo: Path, arguments: List[str], *, check: bool = True, stdout=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo)] + arguments,
        check=check, stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE, env=git_environment(),
    )


def validate_repo(repo: Path, expected_commit: Optional[str] = None) -> Dict[str, str]:
    repo_descriptor, _ = open_directory(repo, private=False)
    os.close(repo_descriptor)
    git_path = repo / ".git"
    git_descriptor, _ = open_directory(git_path, private=False)
    os.close(git_descriptor)
    for forbidden in (git_path / "info/attributes", git_path / "info/grafts"):
        if forbidden.exists() or forbidden.is_symlink():
            raise SourceError("release_source_git_override_forbidden")
    attributes = git(repo, ["config", "--local", "--get-all", "core.attributesfile"], check=False)
    if attributes.returncode not in (1,) or attributes.stdout:
        raise SourceError("release_source_git_attributes_override_forbidden")
    replacements = git(repo, ["for-each-ref", "--format=%(refname)", "refs/replace"])
    if replacements.stdout:
        raise SourceError("release_source_git_replace_ref_forbidden")
    branch = git(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"]).stdout.decode("ascii").strip()
    commit = git(repo, ["rev-parse", "--verify", "HEAD^{commit}"]).stdout.decode("ascii").strip()
    if branch != "public-release" or len(commit) != 40 or set(commit) - set("0123456789abcdef"):
        raise SourceError("release_source_git_identity_invalid")
    if expected_commit is not None and commit != expected_commit:
        raise SourceError("release_source_git_commit_changed")
    flags = git(repo, ["ls-files", "-v", "-z"]).stdout.split(b"\0")
    if any(item and not item.startswith(b"H ") for item in flags):
        raise SourceError("release_source_git_index_flags_forbidden")
    tree = git(repo, ["ls-tree", "-r", "-z", commit]).stdout.split(b"\0")
    for item in tree:
        if not item:
            continue
        try:
            metadata, _name = item.split(b"\t", 1)
            mode, kind, _object = metadata.split(b" ", 2)
        except ValueError as error:
            raise SourceError("release_source_git_tree_invalid") from error
        if mode not in (b"100644", b"100755") or kind != b"blob":
            raise SourceError("release_source_git_tree_entry_forbidden")
    if git(repo, ["status", "--porcelain=v1", "--untracked-files=all"]).stdout:
        raise SourceError("release_source_git_worktree_not_clean")
    difference = git(
        repo, ["--no-pager", "diff", "--no-ext-diff", "--quiet", commit, "--"],
        check=False,
    )
    if difference.returncode != 0:
        raise SourceError("release_source_git_worktree_not_clean")
    return {"branch": branch, "commit": commit}


def archive_bytes(path: Path) -> Tuple[bytes, str, Tuple[int, ...]]:
    descriptor, opened = open_regular(path)
    try:
        raw, digest = read_and_hash(descriptor)
        after = os.fstat(descriptor)
        named = path.lstat()
        if stable_identity(opened) != stable_identity(after) or stable_identity(opened) != stable_identity(named):
            raise SourceError("release_source_archive_changed")
        return raw, digest, stable_identity(opened)
    finally:
        os.close(descriptor)


def prepare(repo: Path, archive: Path, source_root: Path) -> Dict[str, object]:
    identity = validate_repo(repo)
    parent_descriptor, _ = open_directory(archive.parent)
    source_descriptor, source_opened = open_directory(source_root, empty=True)
    try:
        descriptor = os.open(
            archive.name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent_descriptor,
        )
        try:
            completed = git(
                repo,
                ["-c", "core.attributesFile=/dev/null", "archive", "--format=tar", identity["commit"]],
                stdout=descriptor,
            )
            if completed.returncode != 0:
                raise SourceError("release_source_git_archive_failed")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            subprocess.run(
                ["/bin/chmod", "-N", str(archive)], check=True,
                capture_output=True,
            )
            opened = os.fstat(descriptor)
            named = archive.lstat()
            if (
                stable_identity(opened) != stable_identity(named)
                or not no_acl(archive)
            ):
                raise SourceError("release_source_archive_changed")
            raw, digest = read_and_hash(descriptor)
            entries, extracted = archive_record_from_bytes(raw)
            extract_archive(source_descriptor, extracted)
            source_after_extract = os.fstat(source_descriptor)
            source_named = source_root.lstat()
            if (
                directory_identity(source_opened)
                != directory_identity(source_after_extract)
                or directory_identity(source_opened)
                != directory_identity(source_named)
            ):
                raise SourceError("release_source_directory_changed")
            observed = tree_record(source_root)
            if observed != entries:
                raise SourceError("release_source_extract_mismatch")
            raw_after, digest_after = read_and_hash(descriptor)
            after = os.fstat(descriptor)
            named_after = archive.lstat()
            if (
                raw_after != raw or digest_after != digest
                or stable_identity(opened) != stable_identity(after)
                or stable_identity(opened) != stable_identity(named_after)
            ):
                raise SourceError("release_source_archive_changed")
            source_final = os.fstat(source_descriptor)
            source_named_final = source_root.lstat()
            if (
                directory_identity(source_opened)
                != directory_identity(source_final)
                or directory_identity(source_opened)
                != directory_identity(source_named_final)
            ):
                raise SourceError("release_source_directory_changed")
        finally:
            os.close(descriptor)
        validate_repo(repo, identity["commit"])
        return {
            "archive_sha256": digest,
            "commit": identity["commit"],
            "schema": "secure-sandbox-native-host-source-preparation-v1",
            "source_tree_sha256": record_digest(entries),
            "status": "verified",
        }
    finally:
        os.close(source_descriptor)
        os.close(parent_descriptor)


def verify_source(
    archive: Path, source_root: Path, expected_archive: str,
    signing_config_sha256: str,
) -> Dict[str, object]:
    if not sha256_valid(expected_archive) or not sha256_valid(signing_config_sha256):
        raise SourceError("release_source_expected_digest_invalid")
    if signing_config_sha256 != hashlib.sha256(EXPECTED_SIGNING_CONFIG).hexdigest():
        raise SourceError("release_source_signing_config_mismatch")
    raw, digest, _ = archive_bytes(archive)
    if digest != expected_archive:
        raise SourceError("release_source_archive_digest_mismatch")
    archive_entries, _ = archive_record_from_bytes(raw)
    source_entries = tree_record(source_root, exclude=SIGNING_CONFIG_RELATIVE)
    if source_entries != archive_entries:
        raise SourceError("release_source_tree_mismatch")
    complete_entries = tree_record(source_root)
    signing = complete_entries.get(SIGNING_CONFIG_RELATIVE)
    if signing != {
        "kind": "file", "mode": 0o444,
        "sha256": signing_config_sha256,
        "size": len(EXPECTED_SIGNING_CONFIG),
    }:
        raise SourceError("release_source_signing_config_mismatch")
    raw_after, digest_after, _ = archive_bytes(archive)
    if raw_after != raw or digest_after != digest:
        raise SourceError("release_source_archive_changed")
    return {
        "archive_sha256": digest,
        "archive_tree_sha256": record_digest(archive_entries),
        "schema": "secure-sandbox-native-host-source-verification-v1",
        "source_tree_sha256": record_digest(complete_entries),
        "status": "verified",
    }


def identity_value(path: Path) -> Dict[str, object]:
    descriptor, opened = open_directory(path)
    try:
        named = path.lstat()
        after = os.fstat(descriptor)
        value = directory_identity(opened)
        if value != directory_identity(named) or value != directory_identity(after):
            raise SourceError("release_source_directory_changed")
    finally:
        os.close(descriptor)
    return {
        "identity": list(value),
        "schema": "secure-sandbox-native-host-directory-identity-v1",
        "status": "verified",
    }


def decoded_directory_identity(encoded: str, error: str) -> Tuple[int, ...]:
    try:
        value = json.loads(encoded)
        identity = tuple(value["identity"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as cause:
        raise SourceError(error) from cause
    if (
        len(identity) != 5
        or any(not isinstance(item, int) or isinstance(item, bool) for item in identity)
    ):
        raise SourceError(error)
    return identity


def require_acl_free_descriptor(descriptor: int, error: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = getattr(libc, "acl_get_fd_np", None)
    acl_get_entry = getattr(libc, "acl_get_entry", None)
    acl_free = getattr(libc, "acl_free", None)
    if acl_get_fd_np is None or acl_get_entry is None or acl_free is None:
        raise SourceError(error)
    acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry.argtypes = (
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
    )
    acl_get_entry.restype = ctypes.c_int
    acl_free.argtypes = (ctypes.c_void_p,)
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, 0x00000100)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise SourceError(error)
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = acl_get_entry(acl, 0, ctypes.byref(entry))
        if result == 0 or ctypes.get_errno() not in {errno.ENOENT, errno.EINVAL}:
            raise SourceError(error)
    finally:
        if acl_free(acl) != 0:
            raise SourceError(error)


def validate_directory_descriptor(
    descriptor: int, expected: Tuple[int, ...], error: str,
) -> os.stat_result:
    try:
        info = os.fstat(descriptor)
    except OSError as cause:
        raise SourceError(error) from cause
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or directory_identity(info) != expected
    ):
        raise SourceError(error)
    require_acl_free_descriptor(descriptor, error)
    return info


def create_build_directory_at(
    parent_descriptor: int, prefix: str, encoded_parent_identity: str,
) -> Dict[str, object]:
    if prefix != ".build.":
        raise SourceError("release_build_directory_prefix_invalid")
    parent_identity = decoded_directory_identity(
        encoded_parent_identity, "release_build_parent_identity_invalid",
    )
    parent = validate_directory_descriptor(
        parent_descriptor, parent_identity, "release_build_parent_changed",
    )
    name = ""
    for _attempt in range(16):
        name = prefix + os.urandom(12).hex()
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
            break
        except FileExistsError:
            continue
    else:
        raise SourceError("release_build_directory_collision")
    child = -1
    try:
        child = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(child)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        identity = directory_identity(opened)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or identity != directory_identity(named)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_dev != parent.st_dev
        ):
            raise SourceError("release_build_directory_changed")
        require_acl_free_descriptor(child, "release_build_directory_acl_untrusted")
        os.fsync(child)
        os.fsync(parent_descriptor)
        validate_directory_descriptor(
            parent_descriptor, parent_identity, "release_build_parent_changed",
        )
    finally:
        if child >= 0:
            os.close(child)
    return {
        "identity": list(identity), "name": name,
        "schema": "secure-sandbox-native-host-build-directory-v1",
        "status": "verified",
    }


def verify_build_directory_at(
    parent_descriptor: int, root_descriptor: int, name: str,
    encoded_parent_identity: str, encoded_root_identity: str,
    parent_path: Optional[Path] = None, root_path: Optional[Path] = None,
) -> Dict[str, object]:
    if not name.startswith(".build.") or "/" in name or name in {".", ".."}:
        raise SourceError("release_build_directory_name_invalid")
    parent_identity = decoded_directory_identity(
        encoded_parent_identity, "release_build_parent_identity_invalid",
    )
    root_identity = decoded_directory_identity(
        encoded_root_identity, "release_build_directory_identity_invalid",
    )
    parent = validate_directory_descriptor(
        parent_descriptor, parent_identity, "release_build_parent_changed",
    )
    root = validate_directory_descriptor(
        root_descriptor, root_identity, "release_build_directory_changed",
    )
    try:
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as cause:
        raise SourceError("release_build_directory_changed") from cause
    if (
        stat.S_ISLNK(named.st_mode)
        or directory_identity(named) != root_identity
        or root.st_dev != parent.st_dev
    ):
        raise SourceError("release_build_directory_changed")
    if parent_path is not None:
        try:
            named_parent = parent_path.lstat()
        except OSError as cause:
            raise SourceError("release_build_parent_path_changed") from cause
        if (
            stat.S_ISLNK(named_parent.st_mode)
            or directory_identity(named_parent) != parent_identity
        ):
            raise SourceError("release_build_parent_path_changed")
    if root_path is not None:
        try:
            named_root = root_path.lstat()
        except OSError as cause:
            raise SourceError("release_build_directory_path_changed") from cause
        if (
            stat.S_ISLNK(named_root.st_mode)
            or directory_identity(named_root) != root_identity
        ):
            raise SourceError("release_build_directory_path_changed")
    return {
        "identity": list(root_identity), "name": name,
        "schema": "secure-sandbox-native-host-build-directory-verification-v1",
        "status": "verified",
    }


def retire_build_directory_at(
    parent_descriptor: int, root_descriptor: int, name: str,
    encoded_parent_identity: str, encoded_root_identity: str,
    parent_path: Optional[Path] = None,
) -> Dict[str, object]:
    verified = verify_build_directory_at(
        parent_descriptor, root_descriptor, name,
        encoded_parent_identity, encoded_root_identity,
    )
    root_identity = tuple(verified["identity"])
    retained = ""
    for _attempt in range(16):
        retained = (
            ".secure-sandbox-retained-" + str(os.getpid()) + "-"
            + os.urandom(12).hex()
        )
        try:
            rename_exclusive_at(
                parent_descriptor, name, parent_descriptor, retained,
            )
            break
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
    else:
        raise SourceError("release_cleanup_quarantine_collision")
    os.fsync(parent_descriptor)
    quarantined = os.stat(
        retained, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(quarantined.st_mode)
        or directory_identity(quarantined) != root_identity
        or directory_identity(os.fstat(root_descriptor)) != root_identity
    ):
        raise SourceError(
            "release_build_directory_changed:retained=" + retained
        )
    parent_identity = decoded_directory_identity(
        encoded_parent_identity, "release_build_parent_identity_invalid",
    )
    validate_directory_descriptor(
        parent_descriptor, parent_identity, "release_build_parent_changed",
    )
    if parent_path is not None:
        try:
            named_parent = parent_path.lstat()
        except OSError as cause:
            raise SourceError(
                "release_build_parent_path_changed:retained=" + retained
            ) from cause
        if (
            stat.S_ISLNK(named_parent.st_mode)
            or directory_identity(named_parent) != parent_identity
        ):
            raise SourceError(
                "release_build_parent_path_changed:retained=" + retained
            )
    return {
        "disposition": "retained", "retained_name": retained,
        "schema": "secure-sandbox-native-host-build-cleanup-v1",
        "status": "verified",
    }


def tree_value(path: Path) -> Dict[str, object]:
    entries = tree_record(path)
    return {
        "schema": "secure-sandbox-native-host-directory-tree-v1",
        "status": "verified", "tree_sha256": record_digest(entries),
    }


def remove_tree(path: Path, parent: Path, prefix: str, encoded_identity: str) -> Dict[str, object]:
    """Retire a captured tree without unlinking an attacker-controlled name.

    Darwin has no unlink-by-inode operation.  A same-UID process can replace a
    pathname after even a descriptor-backed identity check, so recursively
    unlinking would always leave a destructive final race.  Move the complete
    tree to a no-replace, content-preserving quarantine name instead.  If the
    source name was substituted, post-rename identity readback fails closed and
    the moved object remains recoverable under that quarantine name.
    """
    try:
        expected_value = json.loads(encoded_identity)
        expected = tuple(expected_value["identity"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SourceError("release_cleanup_identity_invalid") from error
    if (
        path.parent != parent or not path.name.startswith(prefix)
        or len(expected) != 5
    ):
        raise SourceError("release_cleanup_target_invalid")
    parent_descriptor, parent_info = open_directory(parent)
    retained = ""
    try:
        root = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        try:
            root_info = os.fstat(root)
            named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                directory_identity(root_info) != expected
                or directory_identity(named) != expected
                or root_info.st_dev != parent_info.st_dev
            ):
                raise SourceError("release_cleanup_target_changed")
            for _attempt in range(16):
                retained = (
                    ".secure-sandbox-retained-" + str(os.getpid()) + "-"
                    + os.urandom(12).hex()
                )
                try:
                    rename_exclusive_at(
                        parent_descriptor, path.name,
                        parent_descriptor, retained,
                    )
                    break
                except OSError as error:
                    if error.errno != errno.EEXIST:
                        raise
            else:
                raise SourceError("release_cleanup_quarantine_collision")
            os.fsync(parent_descriptor)
            quarantined = os.stat(
                retained, dir_fd=parent_descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(quarantined.st_mode)
                or directory_identity(quarantined) != expected
                or directory_identity(os.fstat(root)) != expected
            ):
                raise SourceError(
                    "release_cleanup_target_changed:retained=" + retained
                )
        finally:
            os.close(root)
    finally:
        os.close(parent_descriptor)
    return {
        "disposition": "retained",
        "retained_name": retained,
        "schema": "secure-sandbox-native-host-cleanup-v2",
        "status": "verified",
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--repo", type=Path, required=True)
    prepare_parser.add_argument("--archive", type=Path, required=True)
    prepare_parser.add_argument("--source-root", type=Path, required=True)
    verify_repo_parser = commands.add_parser("verify-repo")
    verify_repo_parser.add_argument("--repo", type=Path, required=True)
    verify_repo_parser.add_argument("--commit", required=True)
    verify_source_parser = commands.add_parser("verify-source")
    verify_source_parser.add_argument("--archive", type=Path, required=True)
    verify_source_parser.add_argument("--source-root", type=Path, required=True)
    verify_source_parser.add_argument("--archive-sha256", required=True)
    verify_source_parser.add_argument("--signing-config-sha256", required=True)
    identity_parser = commands.add_parser("identity")
    identity_parser.add_argument("--path", type=Path, required=True)
    tree_parser = commands.add_parser("tree")
    tree_parser.add_argument("--path", type=Path, required=True)
    remove_parser = commands.add_parser("remove-tree")
    remove_parser.add_argument("--path", type=Path, required=True)
    remove_parser.add_argument("--parent", type=Path, required=True)
    remove_parser.add_argument("--prefix", required=True)
    remove_parser.add_argument("--identity", required=True)
    create_build_parser = commands.add_parser("create-build-directory-at")
    create_build_parser.add_argument("--parent-fd", type=int, required=True)
    create_build_parser.add_argument("--prefix", required=True)
    create_build_parser.add_argument("--parent-identity", required=True)
    verify_build_parser = commands.add_parser("verify-build-directory-at")
    verify_build_parser.add_argument("--parent-fd", type=int, required=True)
    verify_build_parser.add_argument("--root-fd", type=int, required=True)
    verify_build_parser.add_argument("--name", required=True)
    verify_build_parser.add_argument("--parent-identity", required=True)
    verify_build_parser.add_argument("--identity", required=True)
    verify_build_parser.add_argument("--parent-path", type=Path, required=True)
    verify_build_parser.add_argument("--root-path", type=Path, required=True)
    retire_build_parser = commands.add_parser("retire-build-directory-at")
    retire_build_parser.add_argument("--parent-fd", type=int, required=True)
    retire_build_parser.add_argument("--root-fd", type=int, required=True)
    retire_build_parser.add_argument("--name", required=True)
    retire_build_parser.add_argument("--parent-identity", required=True)
    retire_build_parser.add_argument("--identity", required=True)
    retire_build_parser.add_argument("--parent-path", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "prepare":
            value = prepare(
                arguments.repo.absolute(), arguments.archive.absolute(),
                arguments.source_root.absolute(),
            )
        elif arguments.command == "verify-repo":
            observed = validate_repo(arguments.repo.absolute(), arguments.commit)
            value = {
                **observed,
                "schema": "secure-sandbox-native-host-repository-verification-v1",
                "status": "verified",
            }
        elif arguments.command == "verify-source":
            value = verify_source(
                arguments.archive.absolute(), arguments.source_root.absolute(),
                arguments.archive_sha256, arguments.signing_config_sha256,
            )
        elif arguments.command == "identity":
            value = identity_value(arguments.path.absolute())
        elif arguments.command == "tree":
            value = tree_value(arguments.path.absolute())
        elif arguments.command == "remove-tree":
            value = remove_tree(
                arguments.path.absolute(), arguments.parent.absolute(),
                arguments.prefix, arguments.identity,
            )
        elif arguments.command == "create-build-directory-at":
            value = create_build_directory_at(
                arguments.parent_fd, arguments.prefix,
                arguments.parent_identity,
            )
        elif arguments.command == "verify-build-directory-at":
            value = verify_build_directory_at(
                arguments.parent_fd, arguments.root_fd, arguments.name,
                arguments.parent_identity, arguments.identity,
                parent_path=arguments.parent_path.absolute(),
                root_path=arguments.root_path.absolute(),
            )
        else:
            value = retire_build_directory_at(
                arguments.parent_fd, arguments.root_fd, arguments.name,
                arguments.parent_identity, arguments.identity,
                parent_path=arguments.parent_path.absolute(),
            )
    except (OSError, SourceError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(canonical(value).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
