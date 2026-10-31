#!/usr/bin/env python3
"""Canonical, deny-by-default model-profile catalog validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any


CATALOG_SCHEMA = "secure-sandbox-model-profile-catalog-v1"
MAX_CATALOG_BYTES = 64 * 1024
MAX_PROFILES = 16
PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}$")
VENDOR_ID = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
LOCATION = re.compile(r"^(?:global|[a-z]+-[a-z]+[0-9])$")
OP_REFERENCE = re.compile(r"^op://Agents/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ADAPTERS = {
    "anthropic-messages-v1",
    "openai-responses-v1",
    "google-openai-chat-v1",
}
LIMIT_KEYS = {
    "max_request_bytes", "max_response_bytes", "max_output_tokens",
    "rate_limit_requests", "rate_limit_window_seconds",
    "client_timeout_seconds", "upstream_timeout_seconds",
}
LEASE_LIMIT_KEYS = {
    "duration_seconds", "maximum_total_seconds", "max_requests",
    "max_input_tokens", "max_output_tokens", "max_cost_microusd",
}
LEASE_PROFILE_NAMES = {"short", "standard", "extended"}


class ProfileError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ProfileError("model_profile_json_invalid") from error
    if len(encoded) > MAX_CATALOG_BYTES:
        raise ProfileError("model_profile_catalog_oversized")
    return encoded


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProfileError(f"{label}_invalid")
    return value


def _text(value: object, label: str, maximum: int) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or any(ord(character) < 32 or ord(character) > 126 for character in value)):
        raise ProfileError(f"{label}_invalid")
    return value


def _positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ProfileError(f"{label}_invalid")
    return value


def _origin(value: object, adapter: str) -> str:
    value = _text(value, "model_profile_origin", 256)
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or parsed.hostname is None
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment
            or parsed.hostname != parsed.hostname.lower()
            or value != f"https://{parsed.hostname}"):
        raise ProfileError("model_profile_origin_invalid")
    if adapter == "google-openai-chat-v1" and value != "https://aiplatform.googleapis.com":
        raise ProfileError("model_profile_google_origin_invalid")
    return value


def _credential(value: object, adapter: str) -> dict[str, str]:
    credential = _object(value, {"reference", "scheme"}, "model_profile_credential")
    reference = _text(credential["reference"], "model_profile_credential_reference", 240)
    if OP_REFERENCE.fullmatch(reference) is None:
        raise ProfileError("model_profile_credential_reference_invalid")
    scheme = credential["scheme"]
    allowed = {
        "anthropic-messages-v1": {"bearer", "anthropic-api-key"},
        "openai-responses-v1": {"bearer"},
        "google-openai-chat-v1": {"google-service-account-json"},
    }[adapter]
    if scheme not in allowed:
        raise ProfileError("model_profile_credential_scheme_invalid")
    return {"reference": reference, "scheme": scheme}


def _deployment(value: object, adapter: str) -> dict[str, str]:
    if adapter != "google-openai-chat-v1":
        return _object(value, set(), "model_profile_deployment")
    deployment = _object(value, {"location", "project_id"}, "model_profile_deployment")
    project = _text(deployment["project_id"], "model_profile_project_id", 30)
    location = _text(deployment["location"], "model_profile_location", 32)
    if PROJECT_ID.fullmatch(project) is None or LOCATION.fullmatch(location) is None:
        raise ProfileError("model_profile_deployment_invalid")
    return {"location": location, "project_id": project}


def _settings(value: object, adapter: str) -> dict[str, Any]:
    common = {"maximum_output_tokens", "temperature_milli"}
    extras = {
        "anthropic-messages-v1": {"anthropic_version"},
        "openai-responses-v1": {"cyber_access", "reasoning_effort"},
        "google-openai-chat-v1": {"reasoning_effort"},
    }[adapter]
    settings = _object(value, common | extras, "model_profile_settings")
    _positive_int(settings["maximum_output_tokens"], "model_profile_maximum_output_tokens", 1_048_576)
    temperature = settings["temperature_milli"]
    if (temperature is not None and (isinstance(temperature, bool)
            or not isinstance(temperature, int) or not 0 <= temperature <= 2000)):
        raise ProfileError("model_profile_temperature_invalid")
    if adapter == "anthropic-messages-v1":
        if settings["anthropic_version"] not in {"2023-06-01"}:
            raise ProfileError("model_profile_anthropic_version_invalid")
    else:
        if settings["reasoning_effort"] not in {"minimal", "low", "medium", "high"}:
            raise ProfileError("model_profile_reasoning_effort_invalid")
        if (adapter == "openai-responses-v1"
                and settings["cyber_access"] not in {"standard", "daybreak_blue", "daybreak_red"}):
            raise ProfileError("model_profile_cyber_access_invalid")
    return settings


def _limits(value: object, maximum_output_tokens: int) -> dict[str, int]:
    limits = _object(value, LIMIT_KEYS, "model_profile_limits")
    maxima = {
        "max_request_bytes": 16 * 1024 * 1024,
        "max_response_bytes": 64 * 1024 * 1024,
        "max_output_tokens": 1_048_576,
        "rate_limit_requests": 10_000,
        "rate_limit_window_seconds": 3600,
        "client_timeout_seconds": 120,
        "upstream_timeout_seconds": 1800,
    }
    for name in sorted(LIMIT_KEYS):
        _positive_int(limits[name], f"model_profile_{name}", maxima[name])
    if limits["max_output_tokens"] != maximum_output_tokens:
        raise ProfileError("model_profile_output_limit_mismatch")
    return limits


def _pricing(value: object) -> dict[str, int]:
    keys = {"input_microusd_per_million_tokens", "output_microusd_per_million_tokens"}
    pricing = _object(value, keys, "model_profile_pricing")
    for name in sorted(keys):
        _positive_int(pricing[name], f"model_profile_{name}", 1_000_000_000_000)
    return pricing


def _lease_profiles(value: object) -> dict[str, dict[str, int]]:
    profiles = _object(value, LEASE_PROFILE_NAMES, "model_profile_lease_profiles")
    for name in sorted(LEASE_PROFILE_NAMES):
        profile = _object(profiles[name], LEASE_LIMIT_KEYS, "model_profile_lease_profile")
        for key in sorted(LEASE_LIMIT_KEYS):
            _positive_int(profile[key], f"model_profile_lease_{key}", 1_000_000_000_000)
        if profile["duration_seconds"] > profile["maximum_total_seconds"]:
            raise ProfileError("model_profile_lease_duration_invalid")
    return profiles


def validate_profile(value: object) -> dict[str, Any]:
    keys = {
        "adapter", "credential", "deployment", "display_name", "lease_profiles",
        "limits", "model_id", "model_name", "pricing", "profile_id", "settings",
        "upstream_origin", "vendor_id", "vendor_name",
    }
    profile = _object(value, keys, "model_profile")
    profile_id = _text(profile["profile_id"], "model_profile_id", 48)
    vendor_id = _text(profile["vendor_id"], "model_profile_vendor_id", 48)
    model_id = _text(profile["model_id"], "model_profile_model_id", 192)
    if PROFILE_ID.fullmatch(profile_id) is None:
        raise ProfileError("model_profile_id_invalid")
    if VENDOR_ID.fullmatch(vendor_id) is None:
        raise ProfileError("model_profile_vendor_id_invalid")
    if MODEL_ID.fullmatch(model_id) is None:
        raise ProfileError("model_profile_model_id_invalid")
    _text(profile["display_name"], "model_profile_display_name", 80)
    _text(profile["vendor_name"], "model_profile_vendor_name", 80)
    _text(profile["model_name"], "model_profile_model_name", 120)
    adapter = profile["adapter"]
    if adapter not in ADAPTERS:
        raise ProfileError("model_profile_adapter_invalid")
    _origin(profile["upstream_origin"], adapter)
    _deployment(profile["deployment"], adapter)
    _credential(profile["credential"], adapter)
    settings = _settings(profile["settings"], adapter)
    _limits(profile["limits"], settings["maximum_output_tokens"])
    _pricing(profile["pricing"])
    _lease_profiles(profile["lease_profiles"])
    canonical_json(profile)
    return profile


def validate_catalog(value: object) -> dict[str, Any]:
    catalog = _object(value, {"profiles", "schema"}, "model_profile_catalog")
    if catalog["schema"] != CATALOG_SCHEMA:
        raise ProfileError("model_profile_catalog_schema_invalid")
    profiles = catalog["profiles"]
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= MAX_PROFILES:
        raise ProfileError("model_profile_catalog_count_invalid")
    seen: set[str] = set()
    for profile in profiles:
        validated = validate_profile(profile)
        profile_id = validated["profile_id"]
        if profile_id in seen:
            raise ProfileError("model_profile_id_duplicate")
        seen.add(profile_id)
    if profiles != sorted(profiles, key=lambda item: item["profile_id"]):
        raise ProfileError("model_profile_catalog_order_invalid")
    canonical_json(catalog)
    return catalog


def load_catalog(path: Path, *, private: bool = True) -> dict[str, Any]:
    info = path.lstat()
    expected_mode = 0o600 if private else 0o644
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != expected_mode
            or info.st_size < 2 or info.st_size > MAX_CATALOG_BYTES):
        raise ProfileError("model_profile_catalog_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        raw = handle.read(MAX_CATALOG_BYTES + 1)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProfileError("model_profile_catalog_json_invalid") from error
    validate_catalog(value)
    if canonical_json(value) != raw:
        raise ProfileError("model_profile_catalog_not_canonical")
    return value


def write_catalog(path: Path, value: object) -> dict[str, str]:
    catalog = validate_catalog(value)
    payload = canonical_json(catalog)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != os.geteuid() or parent.st_mode & 0o022):
        raise ProfileError("model_profile_catalog_directory_untrusted")
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


def profile_by_id(catalog: dict[str, Any], profile_id: str) -> dict[str, Any]:
    matches = [item for item in catalog["profiles"] if item["profile_id"] == profile_id]
    if len(matches) != 1:
        raise ProfileError("model_profile_not_found")
    return matches[0]


def profile_revision(profile: dict[str, Any]) -> str:
    validate_profile(profile)
    return sha256(profile)
