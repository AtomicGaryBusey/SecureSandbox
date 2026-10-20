#!/usr/bin/env python3
"""Read-only verification for registered SecureSandbox source snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata

WORKSPACE = "/home/agent/research-workspace"
INDEX = f"{WORKSPACE}/repos/INDEX.json"
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_PATH_BYTES = 240
MAX_COMPONENTS = 32
MAX_REPORTED_PATHS = 200
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise IntegrityError("unsafe_registered_path")
    encoded = value.encode("utf-8", "strict")
    parts = value.split("/")
    if len(encoded) > MAX_PATH_BYTES or len(parts) > MAX_COMPONENTS or any(part in {"", ".", ".."} for part in parts):
        raise IntegrityError("unsafe_registered_path")
    for character in value:
        code = ord(character)
        if code < 0x20 or 0x7F <= code <= 0x9F or unicodedata.category(character) == "Cf":
            raise IntegrityError("unsafe_registered_path")
    return value


def controlled_file(path: str, maximum: int) -> bytes:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > maximum:
        raise IntegrityError("untrusted_control_file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = bytearray()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                raise IntegrityError("control_file_too_large")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise IntegrityError("control_file_changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def load_control_json(path: str, maximum: int) -> object:
    try:
        return json.loads(controlled_file(path, maximum))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError("invalid_control_json") from error


def registered_source(source_id: str) -> dict:
    if not UUID_RE.fullmatch(source_id):
        raise IntegrityError("invalid_source_id")
    index = load_control_json(INDEX, MAX_INDEX_BYTES)
    if not isinstance(index, dict) or index.get("schema") != "secure-sandbox-source-registry-v1" or not isinstance(index.get("sources"), list):
        raise IntegrityError("invalid_source_index")
    matches = [item for item in index["sources"] if isinstance(item, dict) and item.get("source_id") == source_id]
    if len(matches) != 1:
        raise IntegrityError("source_not_registered")
    return matches[0]


def fixed_tree_path(relative: object, prefix: str) -> str:
    if not isinstance(relative, str) or not relative.startswith(prefix + "/"):
        raise IntegrityError("unsafe_registered_path")
    safe_relative(relative)
    candidate = os.path.normpath(os.path.join(WORKSPACE, relative))
    required = os.path.join(WORKSPACE, prefix) + os.sep
    if not candidate.startswith(required):
        raise IntegrityError("unsafe_registered_path")
    return candidate


def hash_regular(path: str, initial: os.stat_result) -> tuple[str, int]:
    if initial.st_size > MAX_FILE_BYTES:
        raise IntegrityError("file_too_large")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
            raise IntegrityError("filesystem_race")
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise IntegrityError("file_too_large")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
            raise IntegrityError("filesystem_changed_during_verification")
    finally:
        os.close(descriptor)
    if total != initial.st_size:
        raise IntegrityError("filesystem_changed_during_verification")
    return digest.hexdigest(), total


def scan_tree(root: str) -> dict[str, dict]:
    root_info = os.lstat(root)
    if not stat.S_ISDIR(root_info.st_mode):
        raise IntegrityError("registered_tree_missing")
    records: dict[str, dict] = {}
    total_bytes = 0

    def visit(directory: str, relative_parent: str) -> None:
        nonlocal total_bytes
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.encode("utf-8", "surrogateescape"))
        except OSError as error:
            raise IntegrityError("tree_unreadable") from error
        for entry in entries:
            raw_relative = f"{relative_parent}/{entry.name}" if relative_parent else entry.name
            try:
                relative = safe_relative(raw_relative)
            except (IntegrityError, UnicodeError):
                relative = f"unsafe-name-sha256-{hashlib.sha256(os.fsencode(raw_relative)).hexdigest()}"
                if relative in records:
                    raise IntegrityError("unsafe_path_collision")
            if len(records) >= MAX_ENTRIES:
                raise IntegrityError("too_many_entries")
            info = entry.stat(follow_symlinks=False)
            path = entry.path
            if stat.S_ISDIR(info.st_mode):
                records[relative] = {"path": relative, "type": "directory"}
                visit(path, raw_relative)
            elif stat.S_ISREG(info.st_mode):
                digest, size = hash_regular(path, info)
                total_bytes += size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise IntegrityError("tree_too_large")
                records[relative] = {"path": relative, "type": "file", "bytes": size, "sha256": digest}
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                records[relative] = {"path": relative, "type": "symlink", "target": target}
            else:
                records[relative] = {"path": relative, "type": "unsupported"}

    visit(root, "")
    return records


def expected_records(manifest: dict, omit_symlinks: bool = False) -> dict[str, dict]:
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise IntegrityError("invalid_integrity_manifest")
    result: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict) or item.get("type") not in {"directory", "file", "symlink"}:
            raise IntegrityError("invalid_integrity_manifest")
        path = safe_relative(item.get("path", ""))
        if path in result:
            raise IntegrityError("invalid_integrity_manifest")
        if omit_symlinks and item["type"] == "symlink":
            continue
        normalized = {"path": path, "type": item["type"]}
        if item["type"] == "file":
            if not isinstance(item.get("bytes"), int) or not SHA256_RE.fullmatch(str(item.get("sha256", ""))):
                raise IntegrityError("invalid_integrity_manifest")
            normalized.update(bytes=item["bytes"], sha256=item["sha256"])
        elif item["type"] == "symlink":
            if not isinstance(item.get("target"), str):
                raise IntegrityError("invalid_integrity_manifest")
            normalized["target"] = item["target"]
        result[path] = normalized
    # npm tarballs commonly omit explicit directory members. Extraction still
    # creates those parents, so derive the directory records without changing
    # the signed/import-time manifest or its tree hash.
    for path in list(result):
        parts = path.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            parent = "/".join(parts[:depth])
            existing = result.get(parent)
            if existing is not None and existing.get("type") != "directory":
                raise IntegrityError("invalid_integrity_manifest")
            result.setdefault(parent, {"path": parent, "type": "directory"})
    return result


def compare(expected: dict[str, dict], actual: dict[str, dict]) -> dict:
    missing = sorted(set(expected) - set(actual))
    added = sorted(set(actual) - set(expected))
    modified = sorted(path for path in set(expected) & set(actual) if expected[path] != actual[path])
    all_changes = [("missing", path) for path in missing] + [("added", path) for path in added] + [("modified", path) for path in modified]
    visible = [{"change": change, "path": path} for change, path in all_changes[:MAX_REPORTED_PATHS]]
    return {
        "status": "match" if not all_changes else "changed",
        "expected_entries": len(expected),
        "actual_entries": len(actual),
        "missing": len(missing),
        "added": len(added),
        "modified": len(modified),
        "changes": visible,
        "changes_truncated": len(all_changes) > len(visible),
        "actual_content_manifest_sha256": hashlib.sha256(canonical([actual[path] for path in sorted(actual)])).hexdigest(),
    }


def verify_source(source_id: str, scope: str = "both") -> dict:
    if scope not in {"baseline", "worktree", "both"}:
        raise IntegrityError("invalid_scope")
    record = registered_source(source_id)
    baseline_path = fixed_tree_path(record.get("baseline_path"), "baselines")
    worktree_path = fixed_tree_path(record.get("worktree_path"), "repos")
    output = {
        "schema": "secure-sandbox-source-verification-v1",
        "source_id": source_id,
        "repository": record.get("repository"),
        "resolved_commit": record.get("resolved_commit"),
        "registered_tree_manifest_sha256": record.get("tree_manifest_sha256"),
        "scope": scope,
    }
    manifest_relative = record.get("integrity_manifest_path")
    manifest = None
    if manifest_relative is not None:
        manifest_path = fixed_tree_path(manifest_relative, "source-manifests")
        value = load_control_json(manifest_path, MAX_MANIFEST_BYTES)
        if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-source-integrity-v1" or value.get("source_id") != source_id:
            raise IntegrityError("invalid_integrity_manifest")
        entries = value.get("entries")
        manifest_hash = hashlib.sha256(canonical(entries)).hexdigest()
        if manifest_hash != value.get("tree_manifest_sha256") or manifest_hash != record.get("tree_manifest_sha256"):
            raise IntegrityError("integrity_manifest_hash_mismatch")
        manifest = value
        output["anchor_status"] = "import_validated"
        output["manifest_tree_hash_verified"] = True
    else:
        output["anchor_status"] = "legacy_manifest_unavailable"
        output["manifest_tree_hash_verified"] = False

    baseline_actual = scan_tree(baseline_path)
    if manifest is not None:
        baseline_expected = expected_records(manifest)
        output["baseline"] = compare(baseline_expected, baseline_actual)
    else:
        output["baseline"] = {
            "status": "unanchored",
            "actual_entries": len(baseline_actual),
            "actual_content_manifest_sha256": hashlib.sha256(canonical([baseline_actual[path] for path in sorted(baseline_actual)])).hexdigest(),
        }
    if scope in {"worktree", "both"}:
        expected = expected_records(manifest, omit_symlinks=True) if manifest is not None else {
            path: item for path, item in baseline_actual.items() if item["type"] != "symlink"
        }
        output["worktree"] = compare(expected, scan_tree(worktree_path))
    if scope == "worktree":
        output.pop("baseline", None)
    comparisons_match = all(
        value.get("status") in {"match", "unanchored"}
        for key, value in output.items() if key in {"baseline", "worktree"}
    )
    if manifest is None:
        output["overall_status"] = "legacy_unanchored_match" if comparisons_match and output.get("worktree", {}).get("status") == "match" else "changed_or_unverified"
    else:
        output["overall_status"] = "match" if comparisons_match else "changed_or_unverified"
    return output
