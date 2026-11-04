#!/usr/bin/env python3
"""One indivisible model, session-policy, source, and harness authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from shared.harness_runtime_binding import (
    HarnessBindingError,
    validate_binding as validate_harness_binding,
)
from shared.model_stack_runtime_binding import (
    ModelStackBindingError,
    NATIVE_MODE,
    validate_binding as validate_model_stack_binding,
)
from shared.native_stack_runtime_binding import (
    NativeStackBindingError,
    assert_harness_match,
)
from shared.session_context_binding import (
    SessionContextBindingError,
    validate_binding as validate_session_context_binding,
)


SCHEMA = "secure-sandbox-runtime-authority-v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
BODY_FIELDS = (
    "model_stack_binding",
    "session_context_binding",
    "harness_binding",
)


class RuntimeAuthorityError(ValueError):
    """Stable fail-closed runtime-authority validation failure."""


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
        raise RuntimeAuthorityError("runtime_authority_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", *BODY_FIELDS, "binding_sha256"
    }:
        raise RuntimeAuthorityError("runtime_authority_fields_invalid")
    if value.get("schema") != SCHEMA:
        raise RuntimeAuthorityError("runtime_authority_schema_invalid")
    try:
        model_stack = validate_model_stack_binding(value.get("model_stack_binding"))
        session_context = validate_session_context_binding(
            value.get("session_context_binding")
        )
        harness = validate_harness_binding(value.get("harness_binding"))
        if model_stack["mode"] == NATIVE_MODE:
            assert_harness_match(model_stack["authority"], harness)
    except (
        ModelStackBindingError,
        SessionContextBindingError,
        HarnessBindingError,
        NativeStackBindingError,
    ) as error:
        raise RuntimeAuthorityError("runtime_authority_component_invalid") from error
    body = {
        "model_stack_binding": model_stack,
        "session_context_binding": session_context,
        "harness_binding": harness,
    }
    supplied = value.get("binding_sha256")
    if (
        not isinstance(supplied, str)
        or SHA256.fullmatch(supplied) is None
        or not hmac.compare_digest(supplied, sha256(body))
    ):
        raise RuntimeAuthorityError("runtime_authority_digest_mismatch")
    return {"schema": SCHEMA, **body, "binding_sha256": supplied}


def make_binding(
    *,
    model_stack_binding: object,
    session_context_binding: object,
    harness_binding: object,
) -> dict[str, Any]:
    try:
        model_stack = validate_model_stack_binding(model_stack_binding)
        session_context = validate_session_context_binding(session_context_binding)
        harness = validate_harness_binding(harness_binding)
    except (
        ModelStackBindingError,
        SessionContextBindingError,
        HarnessBindingError,
    ) as error:
        raise RuntimeAuthorityError("runtime_authority_component_invalid") from error
    body = {
        "model_stack_binding": model_stack,
        "session_context_binding": session_context,
        "harness_binding": harness,
    }
    return validate_binding(
        {"schema": SCHEMA, **body, "binding_sha256": sha256(body)}
    )


def same_binding(left: object, right: object) -> bool:
    return validate_binding(left) == validate_binding(right)
