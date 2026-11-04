#!/usr/bin/env python3
"""Canonical admission contract for native vendor harness + model stacks.

This module grants no runtime, network, credential, or provider authority.  It
validates only the content identity that later activation and run boundaries
must bind.  Every admitted pairing is closed in reviewed code; a settings file
cannot compose an arbitrary harness with an arbitrary vendor credential.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping


CATALOG_SCHEMA = "secure-sandbox-native-vendor-stack-catalog-v1"
MODE = "native-vendor-harness-model-stack"
MAX_CATALOG_BYTES = 64 * 1024
MAX_STACKS = 8

IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,62}")
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}")
SHA256 = re.compile(r"[0-9a-f]{64}")


# The pairing registry is the security boundary.  Adding a row requires a new
# reviewed implementation; catalog data cannot nominate another combination.
PAIRINGS: dict[tuple[str, str, str], dict[str, Any]] = {
    (
        "anthropic",
        "claude-code",
        "anthropic-claude-subscription-oauth",
    ): {
        "adapter_id": "claude-native-oauth-v1",
        "credential_custody": "vendor-harness",
        "network_policy_id": "anthropic-claude-native-oauth-v1",
        "program_id": "anthropic-cvp",
        "program_requirements_version": "anthropic-cvp-defense-2026-10-31",
        "program_tier": "defense",
        "models": {"claude-mythos-5-1"},
        "settings": {
            "effort": {"low", "medium", "high"},
        },
    },
    (
        "openai",
        "codex",
        "openai-sign-in-with-chatgpt",
    ): {
        "adapter_id": "codex-app-server-oauth-v1",
        "credential_custody": "secure-sandbox-host",
        "network_policy_id": "openai-codex-siwc-v1",
        "program_id": "openai-daybreak",
        "program_requirements_version": "openai-daybreak-blue-2026-10-31",
        "program_tier": "blue",
        "models": {"gpt-6-sol", "gpt-6-luna", "gpt-6.1-sol"},
        "settings": {
            "cyber_access": {"daybreak_blue"},
            "reasoning_effort": {"low", "medium", "high", "xhigh"},
        },
    },
}


class NativeVendorStackError(ValueError):
    """Stable fail-closed native-stack validation failure."""


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeVendorStackError("native_stack_json_invalid") from error
    if len(encoded) > MAX_CATALOG_BYTES:
        raise NativeVendorStackError("native_stack_catalog_oversized")
    return encoded


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise NativeVendorStackError(f"{label}_fields_invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise NativeVendorStackError(f"{label}_invalid")
    return value


def _text(value: object, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise NativeVendorStackError(f"{label}_invalid")
    return value


def _digest_or_none(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeVendorStackError(f"{label}_invalid")
    return value


def _settings(value: object, specification: Mapping[str, Any]) -> dict[str, str]:
    expected = set(specification["settings"])
    settings = _exact(value, expected, "native_stack_settings")
    for name, allowed in specification["settings"].items():
        if not isinstance(settings[name], str) or settings[name] not in allowed:
            raise NativeVendorStackError(f"native_stack_setting_{name}_invalid")
    return dict(settings)


def validate_stack(value: object) -> dict[str, Any]:
    stack = _exact(
        value,
        {
            "account_binding",
            "authentication",
            "display_name",
            "harness",
            "mode",
            "model",
            "network_policy_id",
            "stack_id",
            "vendor_id",
        },
        "native_stack",
    )
    if stack["mode"] != MODE:
        raise NativeVendorStackError("native_stack_mode_invalid")
    stack_id = _identifier(stack["stack_id"], "native_stack_id")
    _text(stack["display_name"], "native_stack_display_name", 96)
    vendor_id = _identifier(stack["vendor_id"], "native_stack_vendor_id")

    harness = _exact(
        stack["harness"],
        {"adapter_id", "generation_id", "harness_id"},
        "native_stack_harness",
    )
    harness_id = _identifier(harness["harness_id"], "native_stack_harness_id")
    adapter_id = _identifier(harness["adapter_id"], "native_stack_adapter_id")
    _digest_or_none(
        harness["generation_id"],
        "native_stack_harness_generation",
    )

    authentication = _exact(
        stack["authentication"],
        {"credential_custody", "mode"},
        "native_stack_authentication",
    )
    authentication_mode = _identifier(
        authentication["mode"], "native_stack_authentication_mode"
    )
    pairing = PAIRINGS.get((vendor_id, harness_id, authentication_mode))
    if pairing is None:
        raise NativeVendorStackError("native_stack_pairing_not_admitted")
    if adapter_id != pairing["adapter_id"]:
        raise NativeVendorStackError("native_stack_adapter_pairing_mismatch")
    if authentication["credential_custody"] != pairing["credential_custody"]:
        raise NativeVendorStackError("native_stack_credential_custody_mismatch")
    if stack["network_policy_id"] != pairing["network_policy_id"]:
        raise NativeVendorStackError("native_stack_network_policy_mismatch")

    binding = _exact(
        stack["account_binding"],
        {
            "account_subject_sha256",
            "program_id",
            "program_requirements_version",
            "program_tier",
            "workspace_sha256",
        },
        "native_stack_account_binding",
    )
    if (
        binding["program_id"] != pairing["program_id"]
        or binding["program_requirements_version"]
        != pairing["program_requirements_version"]
        or binding["program_tier"] != pairing["program_tier"]
    ):
        raise NativeVendorStackError("native_stack_program_pairing_mismatch")
    _digest_or_none(
        binding["account_subject_sha256"], "native_stack_account_subject_sha256"
    )
    _digest_or_none(binding["workspace_sha256"], "native_stack_workspace_sha256")

    model = _exact(
        stack["model"],
        {"model_id", "model_name", "settings"},
        "native_stack_model",
    )
    model_id = model["model_id"]
    if not isinstance(model_id, str) or MODEL_ID.fullmatch(model_id) is None:
        raise NativeVendorStackError("native_stack_model_id_invalid")
    if model_id not in pairing["models"]:
        raise NativeVendorStackError("native_stack_model_pairing_mismatch")
    _text(model["model_name"], "native_stack_model_name", 120)
    _settings(model["settings"], pairing)

    canonical_bytes(stack)
    return stack


def validate_catalog(value: object) -> dict[str, Any]:
    catalog = _exact(value, {"schema", "stacks"}, "native_stack_catalog")
    if catalog["schema"] != CATALOG_SCHEMA:
        raise NativeVendorStackError("native_stack_catalog_schema_invalid")
    stacks = catalog["stacks"]
    # The canonical empty catalog is the only safe bootstrap state when Host
    # has not yet published a native stack. It grants no runtime authority and
    # gives Research an exact, release-bound predecessor for the first
    # cross-plane promotion.
    if not isinstance(stacks, list) or not 0 <= len(stacks) <= MAX_STACKS:
        raise NativeVendorStackError("native_stack_catalog_count_invalid")
    seen: set[str] = set()
    for stack in stacks:
        validated = validate_stack(stack)
        stack_id = validated["stack_id"]
        if stack_id in seen:
            raise NativeVendorStackError("native_stack_id_duplicate")
        seen.add(stack_id)
    if stacks != sorted(stacks, key=lambda item: item["stack_id"]):
        raise NativeVendorStackError("native_stack_catalog_order_invalid")
    canonical_bytes(catalog)
    return catalog


def load_catalog(path: Path, *, private: bool = True) -> dict[str, Any]:
    info = path.lstat()
    expected_mode = 0o600 if private else 0o644
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != expected_mode
        or info.st_size < 2
        or info.st_size > MAX_CATALOG_BYTES
    ):
        raise NativeVendorStackError("native_stack_catalog_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        raw = handle.read(MAX_CATALOG_BYTES + 1)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeVendorStackError("native_stack_catalog_json_invalid") from error
    validate_catalog(value)
    if canonical_bytes(value) != raw:
        raise NativeVendorStackError("native_stack_catalog_not_canonical")
    return value


def write_catalog(path: Path, value: object) -> dict[str, str]:
    catalog = validate_catalog(value)
    payload = canonical_bytes(catalog)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o022
    ):
        raise NativeVendorStackError("native_stack_catalog_directory_untrusted")
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return {"catalog_sha256": hashlib.sha256(payload).hexdigest(), "status": "staged"}


def stack_by_id(catalog: dict[str, Any], stack_id: str) -> dict[str, Any]:
    validate_catalog(catalog)
    matches = [item for item in catalog["stacks"] if item["stack_id"] == stack_id]
    if len(matches) != 1:
        raise NativeVendorStackError("native_stack_not_found")
    return matches[0]


def stack_revision(stack: dict[str, Any]) -> str:
    validate_stack(stack)
    return sha256(stack)


def activation_readiness(value: object) -> dict[str, Any]:
    """Return content-only readiness; this does not inspect or grant authority."""
    stack = validate_stack(value)
    binding = stack["account_binding"]
    missing = []
    if stack["harness"]["generation_id"] is None:
        missing.append("harness_generation_id")
    missing.extend(
        name
        for name in ("account_subject_sha256", "workspace_sha256")
        if binding[name] is None
    )
    if "harness_generation_id" in missing:
        status = "configuration-required"
    elif missing:
        status = "login-required"
    else:
        status = "content-ready"
    return {
        "schema": "secure-sandbox-native-vendor-stack-readiness-v1",
        "stack_id": stack["stack_id"],
        "stack_sha256": sha256(stack),
        "status": status,
        "missing": missing,
    }
