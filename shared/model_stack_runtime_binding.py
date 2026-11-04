#!/usr/bin/env python3
"""Discriminated runtime authority for brokered profiles or native stacks."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from shared import native_vendor_stack
from shared.native_stack_runtime_binding import (
    NativeStackBindingError,
    validate_binding as validate_native_binding,
)


SCHEMA = "secure-sandbox-model-stack-runtime-binding-v1"
BROKERED_SCHEMA = "secure-sandbox-brokered-model-runtime-binding-v1"
BROKERED_MODE = "brokered-model-profile"
NATIVE_MODE = native_vendor_stack.MODE
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+\-\[\]]{0,191}")
BROKERED_ADAPTERS = {
    "anthropic-messages-v1",
    "openai-responses-v1",
    "google-openai-chat-v1",
}
PROVIDER_MODES = {"mock", "production"}
BROKERED_FIELDS = (
    "adapter",
    "model",
    "profile_id",
    "profile_sha256",
    "provider_mode",
    "vendor_id",
)


class ModelStackBindingError(ValueError):
    """Stable fail-closed model-stack binding validation failure."""


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
        raise ModelStackBindingError("model_stack_binding_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise ModelStackBindingError(f"model_stack_binding_{label}_invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ModelStackBindingError(f"model_stack_binding_{label}_invalid")
    return value


def validate_brokered_binding(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", *BROKERED_FIELDS, "binding_sha256"
    }:
        raise ModelStackBindingError("brokered_model_binding_fields_invalid")
    if value.get("schema") != BROKERED_SCHEMA:
        raise ModelStackBindingError("brokered_model_binding_schema_invalid")
    body = {field: value.get(field) for field in BROKERED_FIELDS}
    if body["adapter"] not in BROKERED_ADAPTERS:
        raise ModelStackBindingError("brokered_model_binding_adapter_invalid")
    if not isinstance(body["model"], str) or MODEL_ID.fullmatch(body["model"]) is None:
        raise ModelStackBindingError("brokered_model_binding_model_invalid")
    _name(body["profile_id"], "profile_id")
    _digest(body["profile_sha256"], "profile_sha256")
    if body["provider_mode"] not in PROVIDER_MODES:
        raise ModelStackBindingError("brokered_model_binding_provider_mode_invalid")
    _name(body["vendor_id"], "vendor_id")
    supplied = _digest(value.get("binding_sha256"), "brokered_digest")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise ModelStackBindingError("brokered_model_binding_digest_mismatch")
    return {"schema": BROKERED_SCHEMA, **body, "binding_sha256": supplied}  # type: ignore[dict-item]


def make_brokered_binding(
    *,
    adapter: str,
    model: str,
    profile_id: str,
    profile_sha256: str,
    provider_mode: str,
    vendor_id: str,
) -> dict[str, str]:
    body = {
        "adapter": adapter,
        "model": model,
        "profile_id": profile_id,
        "profile_sha256": profile_sha256,
        "provider_mode": provider_mode,
        "vendor_id": vendor_id,
    }
    return validate_brokered_binding(
        {"schema": BROKERED_SCHEMA, **body, "binding_sha256": sha256(body)}
    )


def validate_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "authority", "binding_sha256", "mode", "schema"
    }:
        raise ModelStackBindingError("model_stack_binding_fields_invalid")
    if value.get("schema") != SCHEMA:
        raise ModelStackBindingError("model_stack_binding_schema_invalid")
    mode = value.get("mode")
    authority = value.get("authority")
    try:
        if mode == BROKERED_MODE:
            validated_authority: dict[str, Any] = validate_brokered_binding(authority)
        elif mode == NATIVE_MODE:
            validated_authority = validate_native_binding(authority)
        else:
            raise ModelStackBindingError("model_stack_binding_mode_invalid")
    except NativeStackBindingError as error:
        raise ModelStackBindingError("model_stack_binding_native_invalid") from error
    body = {"authority": validated_authority, "mode": mode}
    supplied = _digest(value.get("binding_sha256"), "digest")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise ModelStackBindingError("model_stack_binding_digest_mismatch")
    return {"authority": validated_authority, "binding_sha256": supplied,
            "mode": mode, "schema": SCHEMA}


def make_binding(mode: str, authority: object) -> dict[str, Any]:
    if mode == BROKERED_MODE:
        validated: dict[str, Any] = validate_brokered_binding(authority)
    elif mode == NATIVE_MODE:
        try:
            validated = validate_native_binding(authority)
        except NativeStackBindingError as error:
            raise ModelStackBindingError("model_stack_binding_native_invalid") from error
    else:
        raise ModelStackBindingError("model_stack_binding_mode_invalid")
    body = {"authority": validated, "mode": mode}
    return validate_binding(
        {"schema": SCHEMA, **body, "binding_sha256": sha256(body)}
    )


def identity_projection(value: object) -> dict[str, str]:
    binding = validate_binding(value)
    authority = binding["authority"]
    if binding["mode"] == BROKERED_MODE:
        return {
            "adapter": authority["adapter"],
            "model": authority["model"],
            "vendor_id": authority["vendor_id"],
        }
    return {
        "adapter": authority["harness_adapter_id"],
        "model": authority["model_id"],
        "vendor_id": authority["vendor_id"],
    }


def same_binding(left: object, right: object) -> bool:
    return validate_binding(left) == validate_binding(right)
