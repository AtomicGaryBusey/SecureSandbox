#!/usr/bin/env python3
"""Synthetic, non-admitting archive rejection cases for acceptance."""

from __future__ import annotations

import hashlib
from typing import Any

from harness_archive_preflight import (
    ArchivePreflightError,
    MAX_FILE_BYTES,
    validate_ustar,
)
from harness_lifecycle_acceptance import CASE_BY_ID, digest


SCHEMA = "secure-sandbox-harness-lifecycle-archive-fixture-v1"
ARCHIVE_CASES = frozenset(
    case.case_id for case in CASE_BY_ID.values() if case.category == "archive"
)
EXPECTED_ERRORS = {
    "reject-archive-absolute-path": "archive_path_absolute",
    "reject-archive-dotdot": "archive_path_traversal",
    "reject-archive-symlink": "archive_entry_type_forbidden",
    "reject-archive-hardlink": "archive_entry_type_forbidden",
    "reject-archive-special-file": "archive_entry_type_forbidden",
    "reject-archive-sparse-file": "archive_entry_type_forbidden",
    "reject-archive-duplicate-path": "archive_path_duplicate",
    "reject-archive-case-fold-collision": "archive_path_casefold_collision",
    "reject-archive-unicode-collision": "archive_path_unicode_collision",
    "reject-archive-archive-bomb": "archive_expansion_limit_exceeded",
    "reject-archive-alternate-stream": "archive_path_alternate_stream",
    "reject-archive-trailing-data": "archive_trailing_data",
}


class ArchiveFixtureError(RuntimeError):
    """Stable failure for archive acceptance fixtures."""


def _field(value: bytes, length: int) -> bytes:
    if len(value) > length:
        raise ArchiveFixtureError("archive_fixture_field_invalid")
    return value + bytes(length - len(value))


def _octal(value: int, length: int) -> bytes:
    encoded = f"{value:0{length - 1}o}".encode("ascii") + b"\0"
    if len(encoded) != length:
        raise ArchiveFixtureError("archive_fixture_number_invalid")
    return encoded


def member(name: str, *, value: bytes = b"fixture\n", typeflag: bytes = b"0",
           declared_size: int | None = None) -> bytes:
    name_bytes = name.encode("utf-8")
    header = bytearray(512)
    header[0:100] = _field(name_bytes, 100)
    header[100:108] = _octal(0o600, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    size = len(value) if declared_size is None else declared_size
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(0, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[265:297] = _field(b"root", 32)
    header[297:329] = _field(b"wheel", 32)
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    padded = value + bytes((-len(value)) % 512)
    return bytes(header) + padded


def archive(*members: bytes, trailing: bytes = b"") -> bytes:
    return b"".join(members) + bytes(1024) + trailing


def case_archive(case_id: str) -> bytes:
    if case_id == "reject-archive-absolute-path":
        return archive(member("/escape"))
    if case_id == "reject-archive-dotdot":
        return archive(member("payload/../escape"))
    if case_id == "reject-archive-symlink":
        return archive(member("link", value=b"", typeflag=b"2"))
    if case_id == "reject-archive-hardlink":
        return archive(member("hardlink", value=b"", typeflag=b"1"))
    if case_id == "reject-archive-special-file":
        return archive(member("device", value=b"", typeflag=b"3"))
    if case_id == "reject-archive-sparse-file":
        return archive(member("sparse", value=b"", typeflag=b"S"))
    if case_id == "reject-archive-duplicate-path":
        return archive(member("same"), member("same"))
    if case_id == "reject-archive-case-fold-collision":
        return archive(member("Readme"), member("README"))
    if case_id == "reject-archive-unicode-collision":
        return archive(member("caf\u00e9"), member("cafe\u0301"))
    if case_id == "reject-archive-archive-bomb":
        return archive(member("bomb", value=b"", declared_size=MAX_FILE_BYTES + 1))
    if case_id == "reject-archive-alternate-stream":
        return archive(member("payload:fork"))
    if case_id == "reject-archive-trailing-data":
        return archive(member("safe"), trailing=b"candidate-controlled-trailing-data")
    raise ArchiveFixtureError("archive_fixture_case_invalid")


def run(case_id: str) -> dict[str, Any]:
    if case_id not in ARCHIVE_CASES:
        raise ArchiveFixtureError("archive_fixture_case_invalid")
    raw = case_archive(case_id)
    state = digest([])
    try:
        validate_ustar(raw)
    except ArchivePreflightError as error:
        observed_error = str(error)
    else:
        raise ArchiveFixtureError("archive_fixture_case_did_not_reject")
    if observed_error != EXPECTED_ERRORS[case_id]:
        raise ArchiveFixtureError("archive_fixture_rejection_mismatch")
    return {
        "schema": SCHEMA,
        "status": "rejected",
        "case_id": case_id,
        "expected": "rejected",
        "observed_error": observed_error,
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "archive_size": len(raw),
        "protected_state_before_sha256": state,
        "protected_state_after_sha256": state,
        "extracted": False,
        "executed": False,
        "candidate_authority": "none",
        "production_material_used": False,
    }
