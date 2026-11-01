#!/usr/bin/env python3
"""Bounded, non-extracting preflight for the accepted ustar subset."""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Any


BLOCK = 512
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 256
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024


class ArchivePreflightError(RuntimeError):
    """Stable, content-free archive preflight failure."""


def _text(field: bytes, label: str) -> str:
    raw, separator, remainder = field.partition(b"\0")
    if separator and any(remainder):
        raise ArchivePreflightError(f"archive_{label}_invalid")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArchivePreflightError(f"archive_{label}_encoding_invalid") from error
    if not value:
        raise ArchivePreflightError(f"archive_{label}_invalid")
    return value


def _octal(field: bytes, label: str) -> int:
    raw = field.strip(b" \0")
    if not raw or any(value not in b"01234567" for value in raw):
        raise ArchivePreflightError(f"archive_{label}_invalid")
    return int(raw, 8)


def _member_path(block: bytes, typeflag: bytes) -> tuple[str, str]:
    name = _text(block[0:100], "path")
    prefix_raw, separator, remainder = block[345:500].partition(b"\0")
    if separator and any(remainder):
        raise ArchivePreflightError("archive_path_invalid")
    if prefix_raw:
        try:
            prefix = prefix_raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ArchivePreflightError("archive_path_encoding_invalid") from error
        name = f"{prefix}/{name}"
    if name.startswith("/"):
        raise ArchivePreflightError("archive_path_absolute")
    if "\\" in name:
        raise ArchivePreflightError("archive_path_invalid")
    if typeflag == b"5" and name.endswith("/"):
        name = name[:-1]
    components = name.split("/")
    if any(component in {"", ".", ".."} for component in components):
        if ".." in components:
            raise ArchivePreflightError("archive_path_traversal")
        raise ArchivePreflightError("archive_path_invalid")
    if any(":" in component or component.startswith("._") for component in components):
        raise ArchivePreflightError("archive_path_alternate_stream")
    normalized = unicodedata.normalize("NFC", name)
    return name, normalized


def validate_ustar(raw: bytes) -> dict[str, Any]:
    """Validate an entire archive without extracting or executing any member."""
    if not isinstance(raw, bytes) or not 3 * BLOCK <= len(raw) <= MAX_ARCHIVE_BYTES:
        raise ArchivePreflightError("archive_size_invalid")
    if len(raw) % BLOCK:
        raise ArchivePreflightError("archive_trailing_data")
    entries: list[dict[str, Any]] = []
    exact_paths: set[str] = set()
    normalized_paths: dict[str, str] = {}
    folded_paths: dict[str, str] = {}
    expanded = 0
    offset = 0
    terminated = False
    while offset < len(raw):
        block = raw[offset:offset + BLOCK]
        if block == bytes(BLOCK):
            if offset + 2 * BLOCK > len(raw) or raw[offset + BLOCK:offset + 2 * BLOCK] != bytes(BLOCK):
                raise ArchivePreflightError("archive_terminator_invalid")
            if any(raw[offset + 2 * BLOCK:]):
                raise ArchivePreflightError("archive_trailing_data")
            terminated = True
            break
        if block[257:263] != b"ustar\0" or block[263:265] != b"00":
            raise ArchivePreflightError("archive_format_invalid")
        _octal(block[100:108], "mode")
        _octal(block[108:116], "uid")
        _octal(block[116:124], "gid")
        _octal(block[136:148], "mtime")
        stored_checksum = _octal(block[148:156], "checksum")
        calculated_checksum = sum(block[:148]) + 8 * ord(" ") + sum(block[156:])
        if stored_checksum != calculated_checksum:
            raise ArchivePreflightError("archive_checksum_invalid")
        typeflag = block[156:157]
        if typeflag not in {b"\0", b"0", b"5"}:
            raise ArchivePreflightError("archive_entry_type_forbidden")
        size = _octal(block[124:136], "member_size")
        if typeflag == b"5" and size != 0:
            raise ArchivePreflightError("archive_directory_size_invalid")
        if size > MAX_FILE_BYTES or expanded + size > MAX_EXPANDED_BYTES:
            raise ArchivePreflightError("archive_expansion_limit_exceeded")
        if len(entries) >= MAX_ENTRIES:
            raise ArchivePreflightError("archive_entry_limit_exceeded")
        original, normalized = _member_path(block, typeflag)
        if original in exact_paths:
            raise ArchivePreflightError("archive_path_duplicate")
        prior_normalized = normalized_paths.get(normalized)
        if prior_normalized is not None and prior_normalized != original:
            raise ArchivePreflightError("archive_path_unicode_collision")
        folded = normalized.casefold()
        prior_folded = folded_paths.get(folded)
        if prior_folded is not None and prior_folded != normalized:
            raise ArchivePreflightError("archive_path_casefold_collision")
        data_start = offset + BLOCK
        padded = ((size + BLOCK - 1) // BLOCK) * BLOCK
        data_end = data_start + padded
        if data_end > len(raw):
            raise ArchivePreflightError("archive_member_truncated")
        exact_paths.add(original)
        normalized_paths[normalized] = original
        folded_paths[folded] = normalized
        expanded += size
        entries.append({
            "path": normalized,
            "size": size,
            "type": "directory" if typeflag == b"5" else "file",
            "sha256": (None if typeflag == b"5" else
                       hashlib.sha256(raw[data_start:data_start + size]).hexdigest()),
        })
        offset = data_end
    if not terminated or not entries:
        raise ArchivePreflightError("archive_terminator_invalid")
    return {
        "schema": "secure-sandbox-harness-archive-preflight-v1",
        "status": "verified",
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "archive_size": len(raw),
        "entry_count": len(entries),
        "expanded_size": expanded,
        "entries": entries,
        "extracted": False,
        "executed": False,
        "authority": "none",
    }
