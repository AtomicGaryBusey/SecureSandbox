#!/usr/bin/env python3
"""Content-only runtime identity for one native vendor harness/model stack."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from shared import native_vendor_stack
from shared.harness_runtime_binding import (
    HarnessBindingError,
    validate_binding as validate_harness_binding,
)


SCHEMA = "secure-sandbox-native-stack-runtime-binding-v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}")

BODY_FIELDS = (
    "mode",
    "stack_id",
    "stack_sha256",
    "vendor_id",
    "harness_id",
    "harness_generation_id",
    "harness_adapter_id",
    "authentication_mode",
    "credential_custody",
    "account_subject_sha256",
    "workspace_sha256",
    "program_id",
    "program_tier",
    "model_id",
    "model_settings_sha256",
    "network_policy_id",
)

CONTAINER_NAMES = {
    field: f"native_stack_{field}"
    for field in BODY_FIELDS
}
CONTAINER_NAMES["binding_sha256"] = "native_stack_binding_sha256"


class NativeStackBindingError(ValueError):
    """Stable fail-closed native runtime-binding validation failure."""


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
        raise NativeStackBindingError("native_stack_binding_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise NativeStackBindingError(f"native_stack_binding_{label}_invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeStackBindingError(f"native_stack_binding_{label}_invalid")
    return value


def validate_binding(
    value: object,
    *,
    require_schema: bool = True,
) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise NativeStackBindingError("native_stack_binding_invalid")
    expected = {*BODY_FIELDS, "binding_sha256"}
    if require_schema:
        expected.add("schema")
    if set(value) != expected or (require_schema and value.get("schema") != SCHEMA):
        raise NativeStackBindingError("native_stack_binding_fields_invalid")

    body = {field: value.get(field) for field in BODY_FIELDS}
    if body["mode"] != native_vendor_stack.MODE:
        raise NativeStackBindingError("native_stack_binding_mode_invalid")
    for field in (
        "stack_id",
        "vendor_id",
        "harness_id",
        "harness_adapter_id",
        "authentication_mode",
        "credential_custody",
        "program_id",
        "program_tier",
        "network_policy_id",
    ):
        _name(body[field], field)
    for field in (
        "stack_sha256",
        "harness_generation_id",
        "account_subject_sha256",
        "workspace_sha256",
        "model_settings_sha256",
    ):
        _digest(body[field], field)
    if not isinstance(body["model_id"], str) or MODEL_ID.fullmatch(body["model_id"]) is None:
        raise NativeStackBindingError("native_stack_binding_model_id_invalid")
    supplied = _digest(value.get("binding_sha256"), "digest")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeStackBindingError("native_stack_binding_digest_mismatch")
    return {
        **({"schema": SCHEMA} if require_schema else {}),
        **body,
        "binding_sha256": supplied,
    }  # type: ignore[dict-item]


def make_binding(stack: object) -> dict[str, str]:
    try:
        validated = native_vendor_stack.validate_stack(stack)
        readiness = native_vendor_stack.activation_readiness(validated)
    except native_vendor_stack.NativeVendorStackError as error:
        raise NativeStackBindingError("native_stack_binding_stack_invalid") from error
    if readiness["status"] != "content-ready":
        raise NativeStackBindingError("native_stack_binding_stack_not_content_ready")
    harness = validated["harness"]
    authentication = validated["authentication"]
    account = validated["account_binding"]
    model = validated["model"]
    body = {
        "mode": validated["mode"],
        "stack_id": validated["stack_id"],
        "stack_sha256": native_vendor_stack.stack_revision(validated),
        "vendor_id": validated["vendor_id"],
        "harness_id": harness["harness_id"],
        "harness_generation_id": harness["generation_id"],
        "harness_adapter_id": harness["adapter_id"],
        "authentication_mode": authentication["mode"],
        "credential_custody": authentication["credential_custody"],
        "account_subject_sha256": account["account_subject_sha256"],
        "workspace_sha256": account["workspace_sha256"],
        "program_id": account["program_id"],
        "program_tier": account["program_tier"],
        "model_id": model["model_id"],
        "model_settings_sha256": native_vendor_stack.sha256(model["settings"]),
        "network_policy_id": validated["network_policy_id"],
    }
    value = {"schema": SCHEMA, **body, "binding_sha256": sha256(body)}
    return validate_binding(value)


def container_fields(binding: object) -> dict[str, str]:
    validated = validate_binding(binding)
    return {
        CONTAINER_NAMES[field]: validated[field]
        for field in (*BODY_FIELDS, "binding_sha256")
    }


def from_container(value: Mapping[str, Any]) -> dict[str, str]:
    projected = {
        field: value.get(container_name)
        for field, container_name in CONTAINER_NAMES.items()
    }
    return validate_binding(projected, require_schema=False)


def assert_harness_match(native_binding: object, harness_binding: object) -> None:
    native = validate_binding(native_binding)
    try:
        harness = validate_harness_binding(harness_binding)
    except HarnessBindingError as error:
        raise NativeStackBindingError("native_stack_binding_harness_invalid") from error
    if any(
        native[native_name] != harness[harness_name]
        for native_name, harness_name in (
            ("harness_id", "harness_id"),
            ("harness_generation_id", "harness_generation_id"),
            ("harness_adapter_id", "harness_adapter_id"),
        )
    ):
        raise NativeStackBindingError("native_stack_binding_harness_mismatch")
