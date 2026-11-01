#!/usr/bin/env python3
"""Canonical, content-only harness identity carried across run boundaries."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


SCHEMA = "secure-sandbox-harness-runtime-binding-v1"
SESSION_SCHEMA = "secure-sandbox-session-runs-v4"
GATEWAY_LEASE_SCHEMA = "secure-sandbox-run-lease-v2"
RESEARCH_LEASE_SCHEMA = "secure-sandbox-research-run-lease-v2"
PROCESS_SCHEMA = "secure-sandbox-run-process-v2"
MIGRATION_PLAN_SCHEMA = "secure-sandbox-harness-session-migration-plan-v1"
MIGRATION_AUTHORIZATION_SCHEMA = "secure-sandbox-harness-session-migration-touchid-v1"
MIGRATION_RECEIPT_SCHEMA = "secure-sandbox-harness-session-migration-receipt-v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

BINDING_FIELDS = (
    "harness_id",
    "harness_generation_id",
    "harness_manifest_sha256",
    "harness_executable_sha256",
    "harness_inventory_sha256",
    "harness_adapter_id",
    "harness_adapter_sha256",
)


class HarnessBindingError(ValueError):
    """Stable fail-closed binding validation failure."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                           separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise HarnessBindingError("harness_binding_not_canonicalizable") from error


def sha256_value(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise HarnessBindingError(f"{label}_invalid")
    return value


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise HarnessBindingError(f"{label}_invalid")
    return value


def validate_binding(value: object, *, require_schema: bool = True) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise HarnessBindingError("harness_binding_invalid")
    expected = {*BINDING_FIELDS, "binding_sha256"}
    if require_schema:
        expected.add("schema")
    if set(value) != expected or (require_schema and value.get("schema") != SCHEMA):
        raise HarnessBindingError("harness_binding_fields_invalid")
    body = {field: value.get(field) for field in BINDING_FIELDS}
    _name(body["harness_id"], "harness_id")
    _digest(body["harness_generation_id"], "harness_generation_id")
    _digest(body["harness_manifest_sha256"], "harness_manifest_sha256")
    _digest(body["harness_executable_sha256"], "harness_executable_sha256")
    _digest(body["harness_inventory_sha256"], "harness_inventory_sha256")
    _name(body["harness_adapter_id"], "harness_adapter_id")
    _digest(body["harness_adapter_sha256"], "harness_adapter_sha256")
    supplied = _digest(value.get("binding_sha256"), "harness_binding_sha256")
    if supplied != sha256_value(body):
        raise HarnessBindingError("harness_binding_digest_mismatch")
    return {**({"schema": SCHEMA} if require_schema else {}), **body,
            "binding_sha256": supplied}  # type: ignore[dict-item]


def make_binding(*, harness_id: str, generation_id: str, manifest_sha256: str,
                 executable_sha256: str, inventory_sha256: str,
                 adapter_id: str, adapter_sha256: str) -> dict[str, str]:
    body = {
        "harness_id": harness_id,
        "harness_generation_id": generation_id,
        "harness_manifest_sha256": manifest_sha256,
        "harness_executable_sha256": executable_sha256,
        "harness_inventory_sha256": inventory_sha256,
        "harness_adapter_id": adapter_id,
        "harness_adapter_sha256": adapter_sha256,
    }
    value = {"schema": SCHEMA, **body, "binding_sha256": sha256_value(body)}
    return validate_binding(value)


def from_container(value: Mapping[str, Any]) -> dict[str, str]:
    projected = {field: value.get(field) for field in BINDING_FIELDS}
    projected["binding_sha256"] = value.get("harness_binding_sha256")
    return validate_binding(projected, require_schema=False)


def container_fields(binding: object) -> dict[str, str]:
    validated = validate_binding(binding)
    return {**{field: validated[field] for field in BINDING_FIELDS},
            "harness_binding_sha256": validated["binding_sha256"]}


def same_binding(left: object, right: object) -> bool:
    return validate_binding(left) == validate_binding(right)
