#!/usr/bin/env python3
"""Content-only session policy and source identity bound across run boundaries."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping


SCHEMA = "secure-sandbox-session-context-binding-v1"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
BODY_FIELDS = (
    "session_id",
    "source_id",
    "source_manifest_sha256",
    "persona_sha256",
    "tool_catalog_sha256",
    "extension_set_sha256",
)


class SessionContextBindingError(ValueError):
    """Stable fail-closed session-context validation failure."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise SessionContextBindingError("session_context_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise SessionContextBindingError(f"session_context_{label}_invalid")
    return value


def validate_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", *BODY_FIELDS, "binding_sha256"
    }:
        raise SessionContextBindingError("session_context_fields_invalid")
    if value.get("schema") != SCHEMA:
        raise SessionContextBindingError("session_context_schema_invalid")
    body = {field: value.get(field) for field in BODY_FIELDS}
    if not isinstance(body["session_id"], str) or UUID4.fullmatch(body["session_id"]) is None:
        raise SessionContextBindingError("session_context_session_id_invalid")
    source_id = body["source_id"]
    source_digest = body["source_manifest_sha256"]
    if (source_id is None) != (source_digest is None):
        raise SessionContextBindingError("session_context_source_partial")
    if source_id is not None:
        if not isinstance(source_id, str) or UUID4.fullmatch(source_id) is None:
            raise SessionContextBindingError("session_context_source_id_invalid")
        _digest(source_digest, "source_manifest_sha256")
    for field in ("persona_sha256", "tool_catalog_sha256", "extension_set_sha256"):
        _digest(body[field], field)
    supplied = _digest(value.get("binding_sha256"), "digest")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise SessionContextBindingError("session_context_digest_mismatch")
    return {"schema": SCHEMA, **body, "binding_sha256": supplied}


def make_binding(
    *,
    session_id: str,
    source_id: str | None,
    source_manifest_sha256: str | None,
    persona_sha256: str,
    tool_catalog_sha256: str,
    extension_set_sha256: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "session_id": session_id,
        "source_id": source_id,
        "source_manifest_sha256": source_manifest_sha256,
        "persona_sha256": persona_sha256,
        "tool_catalog_sha256": tool_catalog_sha256,
        "extension_set_sha256": extension_set_sha256,
    }
    return validate_binding(
        {"schema": SCHEMA, **body, "binding_sha256": sha256(body)}
    )


def same_binding(left: object, right: object) -> bool:
    return validate_binding(left) == validate_binding(right)
