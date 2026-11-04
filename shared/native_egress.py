#!/usr/bin/env python3
"""Closed, content-free native-vendor egress grant contract.

This module grants no credential, process, or provider authority on its own.
It binds a short-lived CONNECT allowlist to one reviewed native stack intent,
one content-complete native stack, or one exact native runtime authority.  The
Gateway tunnel and firewall independently validate the same canonical grant.
Hostname-to-IPv4 mappings are authorization-time artifacts produced outside
the DNS-less guests; they are never instructions to resolve names at runtime.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping

from shared import native_vendor_stack
from shared.native_stack_runtime_binding import (
    NativeStackBindingError,
    validate_binding as validate_native_stack_binding,
)
from shared.runtime_authority import (
    RuntimeAuthorityError,
    validate_binding as validate_runtime_authority,
)


GRANT_SCHEMA = "secure-sandbox-native-egress-grant-v1"
BINDING_SCHEMA = "secure-sandbox-native-egress-binding-v1"
INTENT_SCHEMA = "secure-sandbox-native-stack-egress-intent-v1"
MAX_GRANT_BYTES = 128 * 1024
INSTALL_STATE_BYTES = b"secure-sandbox-native-egress-installed-v1\n"
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)

PHASE_LOGIN = "login"
PHASE_INFERENCE = "inference"
PHASE_STATUS_LOGOUT = "status-logout"
PHASES = {PHASE_LOGIN, PHASE_INFERENCE, PHASE_STATUS_LOGOUT}

# Coordinator contract for every grant replacement or revocation. Socket
# owners stop before either firewall changes; both guests reach deny-only and
# delete their native conntrack tuples before successor policy is installed.
# Services restart only after both exact successor policies are live.
ROTATION_PROTOCOL = (
    "stop-research-native-harness",
    "stop-gateway-native-tunnel",
    "apply-research-deny-only",
    "apply-gateway-deny-only",
    "delete-research-native-conntrack",
    "delete-gateway-native-conntrack",
    "apply-gateway-successor-policy",
    "apply-research-successor-policy",
    "start-gateway-native-tunnel",
    "start-research-native-harness",
)

# These are the minimum documented destinations for the deliberately reduced
# feature set.  Optional telemetry, updates, plugins, connectors, artifacts,
# browser integration, WebFetch, and marketplace traffic are disabled by the
# native harness policy and therefore are intentionally absent here.
POLICIES: dict[str, dict[str, Any]] = {
    "anthropic-claude-native-oauth-v1": {
        "vendor_id": "anthropic",
        "phases": {
            PHASE_LOGIN: {
                "hosts": (
                    "api.anthropic.com",
                    "claude.ai",
                    "claude.com",
                    "platform.claude.com",
                    "sso.claude.com",
                ),
                "maximum_duration_seconds": 900,
                "maximum_connections": 32,
                "maximum_bytes_from_client": 16 * 1024 * 1024,
                "maximum_bytes_to_client": 32 * 1024 * 1024,
                "maximum_connection_seconds": 300,
            },
            PHASE_INFERENCE: {
                "hosts": ("api.anthropic.com", "platform.claude.com"),
                "maximum_duration_seconds": 4 * 60 * 60,
                "maximum_connections": 128,
                "maximum_bytes_from_client": 512 * 1024 * 1024,
                "maximum_bytes_to_client": 1024 * 1024 * 1024,
                "maximum_connection_seconds": 1800,
            },
            PHASE_STATUS_LOGOUT: {
                "hosts": ("claude.ai", "platform.claude.com"),
                "maximum_duration_seconds": 300,
                "maximum_connections": 16,
                "maximum_bytes_from_client": 8 * 1024 * 1024,
                "maximum_bytes_to_client": 16 * 1024 * 1024,
                "maximum_connection_seconds": 120,
            },
        },
    },
    "openai-codex-siwc-v1": {
        "vendor_id": "openai",
        "phases": {
            # SIWC registration, refresh, and revocation remain Host-only.
            # Research receives inference egress and at most one short-lived
            # access token projected to the exact Codex app-server process.
            PHASE_INFERENCE: {
                "hosts": ("api.openai.com",),
                "maximum_duration_seconds": 60 * 60,
                "maximum_connections": 128,
                "maximum_bytes_from_client": 512 * 1024 * 1024,
                "maximum_bytes_to_client": 1024 * 1024 * 1024,
                "maximum_connection_seconds": 1800,
            },
        },
    },
}


class NativeEgressError(ValueError):
    """Stable fail-closed native-egress validation failure."""


def canonical_bytes(value: object) -> bytes:
    try:
        result = (
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
        raise NativeEgressError("native_egress_not_canonicalizable") from error
    if len(result) > MAX_GRANT_BYTES:
        raise NativeEgressError("native_egress_grant_oversized")
    return result


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeEgressError(f"native_egress_{label}_fields_invalid")
    return dict(value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeEgressError(f"native_egress_{label}_invalid")
    return value


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise NativeEgressError(f"native_egress_{label}_invalid")
    return value


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise NativeEgressError(f"native_egress_{label}_invalid")
    return value


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError) as error:
        raise NativeEgressError(f"native_egress_{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise NativeEgressError(f"native_egress_{label}_invalid")
    return str(parsed)


INTENT_FIELDS = (
    "mode",
    "stack_id",
    "stack_sha256",
    "vendor_id",
    "harness_id",
    "harness_generation_id",
    "harness_adapter_id",
    "authentication_mode",
    "credential_custody",
    "program_id",
    "program_requirements_version",
    "program_tier",
    "model_id",
    "model_settings_sha256",
    "network_policy_id",
)


def make_stack_intent(value: object) -> dict[str, Any]:
    """Project a staged login target without account or workspace identity."""
    try:
        stack = native_vendor_stack.validate_stack(value)
    except native_vendor_stack.NativeVendorStackError as error:
        raise NativeEgressError("native_egress_stack_intent_stack_invalid") from error
    harness = stack["harness"]
    if harness["generation_id"] is None:
        raise NativeEgressError("native_egress_stack_intent_generation_missing")
    authentication = stack["authentication"]
    account = stack["account_binding"]
    model = stack["model"]
    body = {
        "mode": stack["mode"],
        "stack_id": stack["stack_id"],
        "stack_sha256": native_vendor_stack.stack_revision(stack),
        "vendor_id": stack["vendor_id"],
        "harness_id": harness["harness_id"],
        "harness_generation_id": harness["generation_id"],
        "harness_adapter_id": harness["adapter_id"],
        "authentication_mode": authentication["mode"],
        "credential_custody": authentication["credential_custody"],
        "program_id": account["program_id"],
        "program_requirements_version": account["program_requirements_version"],
        "program_tier": account["program_tier"],
        "model_id": model["model_id"],
        "model_settings_sha256": native_vendor_stack.sha256(model["settings"]),
        "network_policy_id": stack["network_policy_id"],
    }
    return validate_stack_intent(
        {"schema": INTENT_SCHEMA, **body, "binding_sha256": sha256(body)}
    )


def validate_stack_intent(value: object) -> dict[str, Any]:
    intent = _exact(
        value, {"schema", *INTENT_FIELDS, "binding_sha256"}, "stack_intent"
    )
    if intent["schema"] != INTENT_SCHEMA or intent["mode"] != native_vendor_stack.MODE:
        raise NativeEgressError("native_egress_stack_intent_schema_invalid")
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
        _name(intent[field], f"stack_intent_{field}")
    for field in (
        "stack_sha256",
        "harness_generation_id",
        "model_settings_sha256",
    ):
        _digest(intent[field], f"stack_intent_{field}")
    if (
        not isinstance(intent["program_requirements_version"], str)
        or not 1 <= len(intent["program_requirements_version"]) <= 96
        or not isinstance(intent["model_id"], str)
        or not 1 <= len(intent["model_id"]) <= 192
    ):
        raise NativeEgressError("native_egress_stack_intent_text_invalid")
    policy = POLICIES.get(intent["network_policy_id"])
    if policy is None or policy["vendor_id"] != intent["vendor_id"]:
        raise NativeEgressError("native_egress_stack_intent_policy_mismatch")
    pairing = native_vendor_stack.PAIRINGS.get(
        (
            intent["vendor_id"],
            intent["harness_id"],
            intent["authentication_mode"],
        )
    )
    if (
        pairing is None
        or pairing["adapter_id"] != intent["harness_adapter_id"]
        or pairing["credential_custody"] != intent["credential_custody"]
        or pairing["network_policy_id"] != intent["network_policy_id"]
        or pairing["program_id"] != intent["program_id"]
        or pairing["program_requirements_version"]
        != intent["program_requirements_version"]
        or pairing["program_tier"] != intent["program_tier"]
        or intent["model_id"] not in pairing["models"]
    ):
        raise NativeEgressError("native_egress_stack_intent_pairing_mismatch")
    body = {field: intent[field] for field in INTENT_FIELDS}
    supplied = _digest(intent["binding_sha256"], "stack_intent_digest")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeEgressError("native_egress_stack_intent_digest_mismatch")
    return {"schema": INTENT_SCHEMA, **body, "binding_sha256": supplied}


def make_binding(kind: str, value: object) -> dict[str, Any]:
    if kind == "stack-intent":
        validated = validate_stack_intent(value)
    elif kind == "native-stack":
        try:
            validated = validate_native_stack_binding(value)
        except NativeStackBindingError as error:
            raise NativeEgressError("native_egress_native_stack_binding_invalid") from error
    elif kind == "runtime-authority":
        try:
            validated = validate_runtime_authority(value)
        except RuntimeAuthorityError as error:
            raise NativeEgressError("native_egress_runtime_authority_invalid") from error
        if validated["model_stack_binding"]["mode"] != native_vendor_stack.MODE:
            raise NativeEgressError("native_egress_runtime_authority_not_native")
    else:
        raise NativeEgressError("native_egress_binding_kind_invalid")
    body = {"kind": kind, "value": validated}
    return validate_binding(
        {"schema": BINDING_SCHEMA, **body, "binding_sha256": sha256(body)}
    )


def validate_binding(value: object) -> dict[str, Any]:
    binding = _exact(
        value, {"schema", "kind", "value", "binding_sha256"}, "binding"
    )
    if binding["schema"] != BINDING_SCHEMA:
        raise NativeEgressError("native_egress_binding_schema_invalid")
    kind = binding["kind"]
    if kind == "stack-intent":
        validated = validate_stack_intent(binding["value"])
    elif kind == "native-stack":
        try:
            validated = validate_native_stack_binding(binding["value"])
        except NativeStackBindingError as error:
            raise NativeEgressError("native_egress_native_stack_binding_invalid") from error
    elif kind == "runtime-authority":
        try:
            validated = validate_runtime_authority(binding["value"])
        except RuntimeAuthorityError as error:
            raise NativeEgressError("native_egress_runtime_authority_invalid") from error
        if validated["model_stack_binding"]["mode"] != native_vendor_stack.MODE:
            raise NativeEgressError("native_egress_runtime_authority_not_native")
    else:
        raise NativeEgressError("native_egress_binding_kind_invalid")
    body = {"kind": kind, "value": validated}
    supplied = _digest(binding["binding_sha256"], "binding_digest")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeEgressError("native_egress_binding_digest_mismatch")
    return {"schema": BINDING_SCHEMA, **body, "binding_sha256": supplied}


def _binding_identity(binding: Mapping[str, Any]) -> tuple[str, str]:
    value = binding["value"]
    if binding["kind"] == "stack-intent":
        return value["vendor_id"], value["network_policy_id"]
    if binding["kind"] == "native-stack":
        return value["vendor_id"], value["network_policy_id"]
    native = value["model_stack_binding"]["authority"]
    return native["vendor_id"], native["network_policy_id"]


LIMIT_FIELDS = (
    "max_connections",
    "max_bytes_from_client",
    "max_bytes_to_client",
    "max_connection_seconds",
)


def _validate_limits(value: object, specification: Mapping[str, Any]) -> dict[str, int]:
    limits = _exact(value, set(LIMIT_FIELDS), "limits")
    maximum_names = {
        "max_connections": "maximum_connections",
        "max_bytes_from_client": "maximum_bytes_from_client",
        "max_bytes_to_client": "maximum_bytes_to_client",
        "max_connection_seconds": "maximum_connection_seconds",
    }
    result: dict[str, int] = {}
    for field in LIMIT_FIELDS:
        result[field] = _integer(limits[field], field, 1)
        if result[field] > specification[maximum_names[field]]:
            raise NativeEgressError(f"native_egress_{field}_exceeds_policy")
    return result


def _validate_destinations(
    value: object, expected_hosts: tuple[str, ...]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(expected_hosts):
        raise NativeEgressError("native_egress_destinations_invalid")
    result: list[dict[str, Any]] = []
    for destination in value:
        item = _exact(destination, {"hostname", "ipv4", "port"}, "destination")
        hostname = item["hostname"]
        if not isinstance(hostname, str) or HOSTNAME.fullmatch(hostname) is None:
            raise NativeEgressError("native_egress_destination_hostname_invalid")
        if item["port"] != 443:
            raise NativeEgressError("native_egress_destination_port_invalid")
        addresses = item["ipv4"]
        if not isinstance(addresses, list) or not addresses or len(addresses) > 64:
            raise NativeEgressError("native_egress_destination_addresses_invalid")
        normalized: list[str] = []
        for address_value in addresses:
            try:
                address = ipaddress.ip_address(address_value)
            except ValueError as error:
                raise NativeEgressError(
                    "native_egress_destination_address_invalid"
                ) from error
            if address.version != 4 or not address.is_global:
                raise NativeEgressError("native_egress_destination_address_not_global")
            normalized.append(str(address))
        if normalized != sorted(set(normalized)):
            raise NativeEgressError("native_egress_destination_addresses_not_canonical")
        result.append({"hostname": hostname, "ipv4": normalized, "port": 443})
    if [item["hostname"] for item in result] != sorted(expected_hosts):
        raise NativeEgressError("native_egress_destination_set_mismatch")
    return result


def make_grant(
    *,
    binding_kind: str,
    binding_value: object,
    phase: str,
    resolved_ipv4: Mapping[str, list[str]],
    issued_at: int,
    expires_at: int,
    grant_id: str | None = None,
    limits: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Build a grant from activation-time, pre-authorized IPv4 pin artifacts."""
    binding = make_binding(binding_kind, binding_value)
    vendor_id, policy_id = _binding_identity(binding)
    policy = POLICIES.get(policy_id)
    specification = None if policy is None else policy["phases"].get(phase)
    if policy is None or policy["vendor_id"] != vendor_id or specification is None:
        raise NativeEgressError("native_egress_phase_not_admitted")
    if phase == PHASE_LOGIN and binding_kind not in {"stack-intent", "native-stack"}:
        raise NativeEgressError("native_egress_phase_binding_mismatch")
    if phase == PHASE_INFERENCE and binding_kind != "runtime-authority":
        raise NativeEgressError("native_egress_phase_binding_mismatch")
    if phase == PHASE_STATUS_LOGOUT and binding_kind != "native-stack":
        raise NativeEgressError("native_egress_phase_binding_mismatch")
    maximums = {
        "max_connections": specification["maximum_connections"],
        "max_bytes_from_client": specification["maximum_bytes_from_client"],
        "max_bytes_to_client": specification["maximum_bytes_to_client"],
        "max_connection_seconds": specification["maximum_connection_seconds"],
    }
    destinations = [
        {"hostname": host, "ipv4": resolved_ipv4.get(host), "port": 443}
        for host in sorted(specification["hosts"])
    ]
    body = {
        "binding": binding,
        "destinations": destinations,
        "expires_at": expires_at,
        "grant_id": grant_id or str(uuid.uuid4()),
        "issued_at": issued_at,
        "limits": dict(maximums if limits is None else limits),
        "network_policy_id": policy_id,
        "phase": phase,
        "vendor_id": vendor_id,
    }
    return validate_grant({"schema": GRANT_SCHEMA, **body, "grant_sha256": sha256(body)})


def validate_grant(value: object, *, now: int | None = None) -> dict[str, Any]:
    grant = _exact(
        value,
        {
            "schema",
            "binding",
            "destinations",
            "expires_at",
            "grant_id",
            "issued_at",
            "limits",
            "network_policy_id",
            "phase",
            "vendor_id",
            "grant_sha256",
        },
        "grant",
    )
    if grant["schema"] != GRANT_SCHEMA:
        raise NativeEgressError("native_egress_grant_schema_invalid")
    grant_id = _uuid4(grant["grant_id"], "grant_id")
    phase = grant["phase"]
    if phase not in PHASES:
        raise NativeEgressError("native_egress_phase_invalid")
    issued_at = _integer(grant["issued_at"], "issued_at")
    expires_at = _integer(grant["expires_at"], "expires_at", 1)
    if expires_at <= issued_at:
        raise NativeEgressError("native_egress_expiry_invalid")
    binding = validate_binding(grant["binding"])
    vendor_id, policy_id = _binding_identity(binding)
    if grant["vendor_id"] != vendor_id or grant["network_policy_id"] != policy_id:
        raise NativeEgressError("native_egress_grant_binding_mismatch")
    policy = POLICIES.get(policy_id)
    specification = None if policy is None else policy["phases"].get(phase)
    if policy is None or policy["vendor_id"] != vendor_id or specification is None:
        raise NativeEgressError("native_egress_phase_not_admitted")
    kind = binding["kind"]
    if (
        (phase == PHASE_LOGIN and kind not in {"stack-intent", "native-stack"})
        or (phase == PHASE_INFERENCE and kind != "runtime-authority")
        or (phase == PHASE_STATUS_LOGOUT and kind != "native-stack")
    ):
        raise NativeEgressError("native_egress_phase_binding_mismatch")
    if expires_at - issued_at > specification["maximum_duration_seconds"]:
        raise NativeEgressError("native_egress_duration_exceeds_policy")
    limits = _validate_limits(grant["limits"], specification)
    destinations = _validate_destinations(
        grant["destinations"], tuple(specification["hosts"])
    )
    body = {
        "binding": binding,
        "destinations": destinations,
        "expires_at": expires_at,
        "grant_id": grant_id,
        "issued_at": issued_at,
        "limits": limits,
        "network_policy_id": policy_id,
        "phase": phase,
        "vendor_id": vendor_id,
    }
    supplied = _digest(grant["grant_sha256"], "grant_digest")
    if not hmac.compare_digest(supplied, sha256(body)):
        raise NativeEgressError("native_egress_grant_digest_mismatch")
    if now is not None and not issued_at <= now < expires_at:
        raise NativeEgressError("native_egress_grant_inactive")
    canonical_bytes({"schema": GRANT_SCHEMA, **body, "grant_sha256": supplied})
    return {"schema": GRANT_SCHEMA, **body, "grant_sha256": supplied}


def load_grant(
    path: Path,
    *,
    now: int | None = None,
    expected_uid: int = 0,
    expected_gid: int | None = None,
    expected_mode: int = 0o600,
) -> dict[str, Any]:
    try:
        parent = path.parent.lstat()
        info = path.lstat()
    except OSError as error:
        raise NativeEgressError("native_egress_grant_unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != expected_uid
        or parent.st_mode & 0o022
        or not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != expected_uid
        or (expected_gid is not None and info.st_gid != expected_gid)
        or stat.S_IMODE(info.st_mode) != expected_mode
        or not 2 <= info.st_size <= MAX_GRANT_BYTES
    ):
        raise NativeEgressError("native_egress_grant_file_untrusted")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                or opened.st_uid != expected_uid
                or (expected_gid is not None and opened.st_gid != expected_gid)
                or stat.S_IMODE(opened.st_mode) != expected_mode
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or not 2 <= opened.st_size <= MAX_GRANT_BYTES
            ):
                raise NativeEgressError("native_egress_grant_identity_changed")
            raw = handle.read(MAX_GRANT_BYTES + 1)
        value = json.loads(raw)
    except NativeEgressError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeEgressError("native_egress_grant_unreadable") from error
    validated = validate_grant(value, now=now)
    if raw != canonical_bytes(validated):
        raise NativeEgressError("native_egress_grant_not_canonical")
    return validated


def load_install_state(
    path: Path,
    *,
    expected_uid: int = 0,
    expected_gid: int | None = 0,
    expected_mode: int = 0o600,
) -> bool:
    """Read the durable native-feature sentinel, or return False if absent."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise NativeEgressError("native_egress_install_state_unavailable") from error
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise NativeEgressError("native_egress_install_state_unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != expected_uid
        or parent.st_mode & 0o022
        or not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != expected_uid
        or (expected_gid is not None and info.st_gid != expected_gid)
        or stat.S_IMODE(info.st_mode) != expected_mode
        or info.st_size != len(INSTALL_STATE_BYTES)
    ):
        raise NativeEgressError("native_egress_install_state_untrusted")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != expected_uid
                or (expected_gid is not None and opened.st_gid != expected_gid)
                or stat.S_IMODE(opened.st_mode) != expected_mode
                or opened.st_size != len(INSTALL_STATE_BYTES)
            ):
                raise NativeEgressError("native_egress_install_state_identity_changed")
            raw = handle.read(len(INSTALL_STATE_BYTES) + 1)
    except NativeEgressError:
        raise
    except OSError as error:
        raise NativeEgressError("native_egress_install_state_unreadable") from error
    if raw != INSTALL_STATE_BYTES:
        raise NativeEgressError("native_egress_install_state_invalid")
    return True


def validate_rotation_protocol(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or tuple(value) != ROTATION_PROTOCOL:
        raise NativeEgressError("native_egress_rotation_protocol_invalid")
    return ROTATION_PROTOCOL


def flattened_ipv4(value: object, *, now: int | None = None) -> list[str]:
    grant = validate_grant(value, now=now)
    return sorted(
        {address for destination in grant["destinations"] for address in destination["ipv4"]}
    )


def conntrack_mark(value: object, domain: str, *, now: int | None = None) -> str:
    """Derive a domain-separated, grant-specific nonzero 32-bit nft mark."""
    grant = validate_grant(value, now=now)
    if domain not in {"provider", "research"}:
        raise NativeEgressError("native_egress_conntrack_domain_invalid")
    material = domain.encode("ascii") + b"\x00" + bytes.fromhex(grant["grant_sha256"])
    number = int.from_bytes(hashlib.sha256(material).digest()[:4], "big") or 1
    return f"0x{number:08x}"
