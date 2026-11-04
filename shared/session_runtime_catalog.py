#!/usr/bin/env python3
"""Canonical validation for versioned Host session/runtime bindings."""

from __future__ import annotations

import re
from typing import Any, Mapping

from shared.harness_runtime_binding import HarnessBindingError, from_container
from shared.model_stack_runtime_binding import (
    ModelStackBindingError,
    identity_projection,
    validate_binding as validate_model_stack_binding,
)


LEGACY_SCHEMA = "secure-sandbox-session-runs-v1"
RUN_LINK_SCHEMA = "secure-sandbox-session-runs-v2"
MODEL_PROFILE_SCHEMA = "secure-sandbox-session-runs-v3"
HARNESS_BOUND_SCHEMA = "secure-sandbox-session-runs-v4"
CURRENT_SCHEMA = "secure-sandbox-session-runs-v5"
SCHEMAS = {
    LEGACY_SCHEMA,
    RUN_LINK_SCHEMA,
    MODEL_PROFILE_SCHEMA,
    HARNESS_BOUND_SCHEMA,
    CURRENT_SCHEMA,
}
SESSION_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
RUN_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_SESSIONS = 10_000
MAX_RUNS = 1_000_000
MAX_LINKS = 1_000

BASE_FIELDS = {"last_started_at", "runs"}
LINK_FIELDS = BASE_FIELDS | {"run_ids"}
MODEL_FIELDS = {
    "adapter",
    "model",
    "model_profile_id",
    "model_profile_sha256",
    "vendor_id",
}
HARNESS_FIELDS = {
    "harness_id",
    "harness_generation_id",
    "harness_manifest_sha256",
    "harness_executable_sha256",
    "harness_inventory_sha256",
    "harness_adapter_id",
    "harness_adapter_sha256",
    "harness_binding_sha256",
}
CURRENT_FIELDS = LINK_FIELDS | {
    "adapter",
    "model",
    "model_stack_binding",
    "vendor_id",
} | HARNESS_FIELDS
LEGACY_FIELD_SETS = {
    frozenset(BASE_FIELDS),
    frozenset(LINK_FIELDS),
    frozenset(LINK_FIELDS | MODEL_FIELDS),
    frozenset(LINK_FIELDS | MODEL_FIELDS | HARNESS_FIELDS),
}
SCHEMA_RANK = {
    LEGACY_SCHEMA: 1,
    RUN_LINK_SCHEMA: 2,
    MODEL_PROFILE_SCHEMA: 3,
    HARNESS_BOUND_SCHEMA: 4,
    CURRENT_SCHEMA: 5,
}
LEGACY_FIELD_RANK = {
    frozenset(BASE_FIELDS): 1,
    frozenset(LINK_FIELDS): 2,
    frozenset(LINK_FIELDS | MODEL_FIELDS): 3,
    frozenset(LINK_FIELDS | MODEL_FIELDS | HARNESS_FIELDS): 4,
}


class SessionRuntimeCatalogError(ValueError):
    """Stable fail-closed session runtime catalog validation failure."""


def _integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _validate_metadata(record: Mapping[str, Any]) -> None:
    if not _integer(record.get("runs"), 1, MAX_RUNS):
        raise SessionRuntimeCatalogError("session_runtime_counter_invalid")
    if not _integer(record.get("last_started_at"), 0, 2**63 - 1):
        raise SessionRuntimeCatalogError("session_runtime_timestamp_invalid")
    run_ids = record.get("run_ids", [])
    if (
        not isinstance(run_ids, list)
        or len(run_ids) > min(int(record["runs"]), MAX_LINKS)
        or any(not isinstance(item, str) or RUN_UUID.fullmatch(item) is None for item in run_ids)
        or len(set(run_ids)) != len(run_ids)
    ):
        raise SessionRuntimeCatalogError("session_runtime_links_invalid")


def _validate_legacy_record(record: Mapping[str, Any], schema: str) -> None:
    fields = frozenset(record)
    if fields not in LEGACY_FIELD_SETS:
        raise SessionRuntimeCatalogError("session_runtime_legacy_fields_invalid")
    if LEGACY_FIELD_RANK[fields] > SCHEMA_RANK[schema]:
        raise SessionRuntimeCatalogError("session_runtime_legacy_schema_mismatch")
    if MODEL_FIELDS <= fields:
        if (
            NAME.fullmatch(str(record.get("model_profile_id"))) is None
            or NAME.fullmatch(str(record.get("vendor_id"))) is None
            or SHA256.fullmatch(str(record.get("model_profile_sha256"))) is None
            or not isinstance(record.get("adapter"), str)
            or not isinstance(record.get("model"), str)
            or not record["adapter"]
            or not record["model"]
        ):
            raise SessionRuntimeCatalogError("session_runtime_legacy_model_invalid")
    if HARNESS_FIELDS <= fields:
        if (
            NAME.fullmatch(str(record.get("harness_id"))) is None
            or NAME.fullmatch(str(record.get("harness_adapter_id"))) is None
            or any(
                SHA256.fullmatch(str(record.get(name))) is None
                for name in HARNESS_FIELDS
                if name not in {"harness_id", "harness_adapter_id"}
            )
        ):
            raise SessionRuntimeCatalogError("session_runtime_legacy_harness_invalid")


def validate_record(value: object, *, catalog_schema: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SessionRuntimeCatalogError("session_runtime_record_invalid")
    record = dict(value)
    _validate_metadata(record)
    if set(record) != CURRENT_FIELDS:
        _validate_legacy_record(record, catalog_schema)
        return record
    if catalog_schema != CURRENT_SCHEMA:
        raise SessionRuntimeCatalogError("session_runtime_current_schema_mismatch")
    try:
        model_stack = validate_model_stack_binding(record["model_stack_binding"])
        harness = from_container(record)
    except (ModelStackBindingError, HarnessBindingError) as error:
        raise SessionRuntimeCatalogError("session_runtime_binding_invalid") from error
    projected = identity_projection(model_stack)
    if any(record.get(name) != projected[name] for name in ("adapter", "model", "vendor_id")):
        raise SessionRuntimeCatalogError("session_runtime_identity_projection_mismatch")
    native_authority = (
        model_stack["authority"]
        if model_stack["mode"] == "native-vendor-harness-model-stack"
        else None
    )
    if native_authority is not None and any(
        native_authority[native_name] != harness[harness_name]
        for native_name, harness_name in (
            ("harness_id", "harness_id"),
            ("harness_generation_id", "harness_generation_id"),
            ("harness_adapter_id", "harness_adapter_id"),
        )
    ):
        raise SessionRuntimeCatalogError("session_runtime_native_harness_mismatch")
    return record


def validate_catalog(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"schema", "sessions"}:
        raise SessionRuntimeCatalogError("session_runtime_catalog_fields_invalid")
    schema = value.get("schema")
    sessions = value.get("sessions")
    if schema not in SCHEMAS or not isinstance(sessions, Mapping) or len(sessions) > MAX_SESSIONS:
        raise SessionRuntimeCatalogError("session_runtime_catalog_invalid")
    validated: dict[str, dict[str, Any]] = {}
    for session_id, record in sessions.items():
        if not isinstance(session_id, str) or SESSION_UUID.fullmatch(session_id) is None:
            raise SessionRuntimeCatalogError("session_runtime_session_id_invalid")
        validated[session_id] = validate_record(record, catalog_schema=str(schema))
    return {"schema": schema, "sessions": validated}


def is_current_record(record: object) -> bool:
    return isinstance(record, Mapping) and set(record) == CURRENT_FIELDS
