#!/usr/bin/env python3
"""Content-free Host handshake for the signed Codex credential consumer."""

from __future__ import annotations

import array
import hashlib
import hmac
import json
import os
import re
import select
import socket
import stat
import struct
import time
from typing import Any, Mapping

from shared import native_stack_runtime_binding, native_vendor_stack
from shared import runtime_authority

CLAIM_MAGIC = b"SSCLM01\n"
FD_MAGIC = b"SSFD001\n"
READY_MAGIC = b"SSRDY01\n"
CLAIM_SCHEMA = "secure-sandbox-native-codex-projection-claim-v1"
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = re.compile(r"[0-9a-f]{64}")
CLAIM_BYTES = 8 + 36 + 64 + 64 + 64 + 8
READY_BYTES = 8 + 36 + 64
MAXIMUM_ACCESS_LIFETIME_MS = 60 * 60 * 1000
CLIENT_REPLY_SCHEMA = "secure-sandbox-native-credential-client-reply-v1"
PROJECTION_STATUS_REQUEST_SCHEMA = (
    "secure-sandbox-native-projection-isolation-status-request-v2"
)
PROJECTION_STATUS_REPLY_SCHEMA = (
    "secure-sandbox-native-projection-isolation-status-reply-v2"
)
LAUNCH_DESCRIPTOR_SCHEMA = "secure-sandbox-native-codex-launch-v2"
PROJECTION_AUTHORITY_FIELDS = (
    "consumer_executable_path",
    "consumer_executable_sha256",
    "host_release_id",
    "session_id",
    "runtime_authority_sha256",
    "native_stack_binding_sha256",
    "harness_binding_sha256",
    "harness_generation_id",
    "harness_executable_sha256",
    "model_id",
    "reasoning_effort",
    "cyber_access_program",
    "policy_manifest_sha256",
    "probe_executable_sha256",
    "protocol_version",
    "launch_descriptor_sha256",
    "research_release_id",
    "boot_id_sha256",
    "qualification_subject_sha256",
    "qualification_evidence_sha256",
    "qualification_observed_at",
    "qualification_expires_at",
    "qualification_readback_sha256",
)
QUALIFICATION_SUBJECT_FIELDS = (
    "provider",
    "harness_generation_id",
    "harness_executable_sha256",
    "model_id",
    "reasoning_effort",
    "cyber_access_program",
    "policy_manifest_sha256",
    "probe_executable_sha256",
    "protocol_version",
    "qualification_subject_sha256",
)
LAUNCH_DESCRIPTOR_FIELDS = (
    "runtime_authority_sha256",
    "session_id",
    "native_stack_binding_sha256",
    "harness_binding_sha256",
    "harness_generation_id",
    "harness_executable_sha256",
    "model_id",
    "reasoning_effort",
    "cyber_access_program",
)
CODEX_MODELS = {"gpt-6-sol", "gpt-6-luna", "gpt-6.1-sol"}
CODEX_REASONING_EFFORTS = {"low", "medium", "high", "xhigh"}
CODEX_SETTINGS = {
    (model, effort): native_vendor_stack.sha256({
        "cyber_access": "daybreak_blue", "reasoning_effort": effort,
    })
    for model in CODEX_MODELS for effort in CODEX_REASONING_EFFORTS
}
PROTOCOL_VERSION = re.compile(r"[A-Za-z0-9._-]{1,64}")


class NativeCodexProjectionError(ValueError):
    """Stable fail-closed signed-consumer handshake error."""


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeCodexProjectionError(
            "native_codex_projection_value_invalid"
        ) from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sha(value: object, reason: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeCodexProjectionError(reason)
    return value


def _uuid(value: object, reason: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeCodexProjectionError(reason)
    return value


def make_launch_descriptor(authority_value: object) -> dict[str, Any]:
    """Reduce one exact OpenAI runtime authority to its launch descriptor."""
    try:
        authority = runtime_authority.validate_binding(authority_value)
        native = native_stack_runtime_binding.validate_binding(
            authority["model_stack_binding"]["authority"]
        )
    except (
        KeyError,
        runtime_authority.RuntimeAuthorityError,
        native_stack_runtime_binding.NativeStackBindingError,
    ) as error:
        raise NativeCodexProjectionError(
            "native_codex_projection_runtime_authority_invalid"
        ) from error
    harness = authority["harness_binding"]
    expected = {
        "vendor_id": "openai",
        "harness_id": "codex",
        "harness_adapter_id": "codex-app-server-oauth-v1",
        "authentication_mode": "openai-sign-in-with-chatgpt",
        "credential_custody": "secure-sandbox-host",
        "program_id": "openai-daybreak",
        "program_requirements_version": "openai-daybreak-blue-2026-10-31",
        "program_tier": "blue",
        "network_policy_id": "openai-codex-siwc-v1",
    }
    if (authority["model_stack_binding"]["mode"] != native_vendor_stack.MODE
            or any(native.get(name) != expected_value
                   for name, expected_value in expected.items())
            or native["model_id"] not in CODEX_MODELS
            or any(native[native_name] != harness[harness_name]
                   for native_name, harness_name in (
                       ("harness_id", "harness_id"),
                       ("harness_generation_id", "harness_generation_id"),
                       ("harness_adapter_id", "harness_adapter_id"),
                   ))):
        raise NativeCodexProjectionError(
            "native_codex_projection_runtime_authority_invalid"
        )
    efforts = [
        effort for effort in sorted(CODEX_REASONING_EFFORTS)
        if hmac.compare_digest(
            native["model_settings_sha256"],
            CODEX_SETTINGS[(native["model_id"], effort)],
        )
    ]
    if len(efforts) != 1:
        raise NativeCodexProjectionError(
            "native_codex_projection_model_settings_invalid"
        )
    body = {
        "runtime_authority_sha256": authority["binding_sha256"],
        "session_id": authority["session_context_binding"]["session_id"],
        "native_stack_binding_sha256": native["binding_sha256"],
        "harness_binding_sha256": harness["binding_sha256"],
        "harness_generation_id": harness["harness_generation_id"],
        "harness_executable_sha256": harness["harness_executable_sha256"],
        "model_id": native["model_id"],
        "reasoning_effort": efforts[0],
        "cyber_access_program": "daybreakBlue",
    }
    return {
        "schema": LAUNCH_DESCRIPTOR_SCHEMA,
        **body,
        "descriptor_sha256": sha256(body),
    }


def validate_launch_descriptor(value: object) -> dict[str, Any]:
    fields = {"schema", *LAUNCH_DESCRIPTOR_FIELDS, "descriptor_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexProjectionError(
            "native_codex_projection_launch_descriptor_fields_invalid"
        )
    body = {name: value[name] for name in LAUNCH_DESCRIPTOR_FIELDS}
    for name in (
        "runtime_authority_sha256",
        "native_stack_binding_sha256",
        "harness_binding_sha256",
        "harness_generation_id",
        "harness_executable_sha256",
    ):
        _sha(body[name], "native_codex_projection_launch_descriptor_invalid")
    _uuid(
        body["session_id"],
        "native_codex_projection_launch_descriptor_invalid",
    )
    if (value.get("schema") != LAUNCH_DESCRIPTOR_SCHEMA
            or body["model_id"] not in CODEX_MODELS
            or body["reasoning_effort"] not in CODEX_REASONING_EFFORTS
            or body["cyber_access_program"] != "daybreakBlue"
            or value.get("descriptor_sha256") != sha256(body)):
        raise NativeCodexProjectionError(
            "native_codex_projection_launch_descriptor_invalid"
        )
    return {"schema": LAUNCH_DESCRIPTOR_SCHEMA, **body,
            "descriptor_sha256": value["descriptor_sha256"]}


def make_qualification_subject(
    descriptor_value: object, *, policy_manifest_sha256: str,
    probe_executable_sha256: str, protocol_version: str,
) -> dict[str, Any]:
    descriptor = validate_launch_descriptor(descriptor_value)
    body = {
        "provider": "codex",
        "harness_generation_id": descriptor["harness_generation_id"],
        "harness_executable_sha256": descriptor[
            "harness_executable_sha256"
        ],
        "model_id": descriptor["model_id"],
        "reasoning_effort": descriptor["reasoning_effort"],
        "cyber_access_program": descriptor["cyber_access_program"],
        "policy_manifest_sha256": _sha(
            policy_manifest_sha256,
            "native_codex_projection_policy_manifest_invalid",
        ),
        "probe_executable_sha256": _sha(
            probe_executable_sha256,
            "native_codex_projection_probe_executable_invalid",
        ),
        "protocol_version": protocol_version,
    }
    if (not isinstance(protocol_version, str)
            or PROTOCOL_VERSION.fullmatch(protocol_version) is None):
        raise NativeCodexProjectionError(
            "native_codex_projection_protocol_version_invalid"
        )
    return {**body, "qualification_subject_sha256": sha256(body)}


def validate_qualification_subject(
    value: object, *, descriptor_value: object | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(
            QUALIFICATION_SUBJECT_FIELDS):
        raise NativeCodexProjectionError(
            "native_codex_projection_qualification_subject_fields_invalid"
        )
    descriptor = None if descriptor_value is None else (
        validate_launch_descriptor(descriptor_value)
    )
    body = {
        name: value[name]
        for name in QUALIFICATION_SUBJECT_FIELDS
        if name != "qualification_subject_sha256"
    }
    if (body["provider"] != "codex"
            or body["model_id"] not in CODEX_MODELS
            or body["reasoning_effort"] not in CODEX_REASONING_EFFORTS
            or body["cyber_access_program"] != "daybreakBlue"
            or any(not isinstance(body[name], str)
                   or SHA256.fullmatch(body[name]) is None for name in (
                       "harness_generation_id",
                       "harness_executable_sha256",
                       "policy_manifest_sha256",
                       "probe_executable_sha256",
                   ))
            or not isinstance(body["protocol_version"], str)
            or PROTOCOL_VERSION.fullmatch(body["protocol_version"]) is None
            or value.get("qualification_subject_sha256") != sha256(body)
            or (descriptor is not None and any(
                body[name] != descriptor[name] for name in (
                    "harness_generation_id",
                    "harness_executable_sha256",
                    "model_id",
                    "reasoning_effort",
                    "cyber_access_program",
                )
            ))):
        raise NativeCodexProjectionError(
            "native_codex_projection_qualification_subject_invalid"
        )
    return {**body, "qualification_subject_sha256": value[
        "qualification_subject_sha256"
    ]}


def make_projection_status_request(
    *, operation_id: str, authority: object,
) -> dict[str, Any]:
    descriptor = make_launch_descriptor(authority)
    body = {
        "operation_id": _uuid(
            operation_id, "native_codex_projection_operation_invalid"
        ),
        "runtime_authority": runtime_authority.validate_binding(authority),
        "launch_descriptor": descriptor,
    }
    return {"schema": PROJECTION_STATUS_REQUEST_SCHEMA, **body,
            "request_sha256": sha256(body)}


def validate_projection_status_request(value: object) -> dict[str, Any]:
    fields = {
        "schema", "operation_id", "runtime_authority",
        "launch_descriptor", "request_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexProjectionError(
            "native_codex_projection_status_request_fields_invalid"
        )
    try:
        authority = runtime_authority.validate_binding(
            value["runtime_authority"]
        )
    except runtime_authority.RuntimeAuthorityError as error:
        raise NativeCodexProjectionError(
            "native_codex_projection_status_request_authority_invalid"
        ) from error
    descriptor = validate_launch_descriptor(value["launch_descriptor"])
    expected = make_launch_descriptor(authority)
    body = {
        "operation_id": value["operation_id"],
        "runtime_authority": authority,
        "launch_descriptor": descriptor,
    }
    _uuid(
        value["operation_id"],
        "native_codex_projection_status_request_invalid",
    )
    if (descriptor != expected
            or value.get("schema") != PROJECTION_STATUS_REQUEST_SCHEMA
            or value.get("request_sha256") != sha256(body)):
        raise NativeCodexProjectionError(
            "native_codex_projection_status_request_invalid"
        )
    return {"schema": PROJECTION_STATUS_REQUEST_SCHEMA, **body,
            "request_sha256": value["request_sha256"]}


def make_projection_status_reply(
    *, operation_id: str, research_release_id: str, boot_id_sha256: str,
    runtime_authority_sha256: str, launch_descriptor_sha256: str,
    qualification_subject: object, qualification_evidence_sha256: str,
    observed_at: int, expires_at: int,
) -> dict[str, Any]:
    subject = validate_qualification_subject(qualification_subject)
    body = {
        "operation_id": _uuid(
            operation_id, "native_codex_projection_operation_invalid"
        ),
        "research_release_id": _sha(
            research_release_id,
            "native_codex_projection_research_release_invalid",
        ),
        "boot_id_sha256": _sha(
            boot_id_sha256, "native_codex_projection_boot_id_invalid"
        ),
        "runtime_authority_sha256": _sha(
            runtime_authority_sha256,
            "native_codex_projection_runtime_authority_invalid",
        ),
        "launch_descriptor_sha256": _sha(
            launch_descriptor_sha256,
            "native_codex_projection_launch_descriptor_invalid",
        ),
        "qualification_subject": subject,
        "qualification_evidence_sha256": _sha(
            qualification_evidence_sha256,
            "native_codex_projection_qualification_evidence_invalid",
        ),
        "observed_at": observed_at,
        "expires_at": expires_at,
    }
    if (not isinstance(observed_at, int) or isinstance(observed_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or observed_at < 1
            or not observed_at < expires_at <= observed_at + 120):
        raise NativeCodexProjectionError(
            "native_codex_projection_status_reply_time_invalid"
        )
    reply = {"schema": PROJECTION_STATUS_REPLY_SCHEMA, **body}
    return {**reply, "evidence_sha256": sha256(reply)}


def validate_projection_status_reply(
    value: object, *, request_value: object, now: int,
) -> dict[str, Any]:
    request = validate_projection_status_request(request_value)
    fields = {
        "schema", "operation_id", "research_release_id", "boot_id_sha256",
        "runtime_authority_sha256", "launch_descriptor_sha256",
        "qualification_subject", "qualification_evidence_sha256",
        "observed_at", "expires_at", "evidence_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexProjectionError(
            "native_codex_projection_status_reply_fields_invalid"
        )
    descriptor = request["launch_descriptor"]
    subject = validate_qualification_subject(
        value["qualification_subject"], descriptor_value=descriptor
    )
    body = {
        name: value[name] for name in fields - {"schema", "evidence_sha256"}
    }
    reply = {"schema": PROJECTION_STATUS_REPLY_SCHEMA, **body}
    if (value.get("schema") != PROJECTION_STATUS_REPLY_SCHEMA
            or value.get("operation_id") != request["operation_id"]
            or value.get("runtime_authority_sha256")
                != descriptor["runtime_authority_sha256"]
            or value.get("launch_descriptor_sha256")
                != descriptor["descriptor_sha256"]
            or any(not isinstance(value.get(name), str)
                   or SHA256.fullmatch(value[name]) is None for name in (
                       "research_release_id", "boot_id_sha256",
                       "qualification_evidence_sha256", "evidence_sha256",
                   ))
            or not isinstance(value.get("observed_at"), int)
            or isinstance(value.get("observed_at"), bool)
            or not isinstance(value.get("expires_at"), int)
            or isinstance(value.get("expires_at"), bool)
            or not value["observed_at"] <= now < value["expires_at"]
            or value["expires_at"] > value["observed_at"] + 120
            or value.get("evidence_sha256") != sha256(reply)):
        raise NativeCodexProjectionError(
            "native_codex_projection_status_reply_invalid"
        )
    return {"schema": PROJECTION_STATUS_REPLY_SCHEMA, **body,
            "qualification_subject": subject,
            "evidence_sha256": value["evidence_sha256"]}


def projection_readback_sha256(
    *, operation_id: str, request_sha256: str, stack_sha256: str,
    session_id: str, runtime_authority_sha256: str,
    launch_descriptor_sha256: str, research_release_id: str,
    boot_id_sha256: str, qualification_subject_sha256: str,
    qualification_evidence_sha256: str, qualification_observed_at: int,
    qualification_expires_at: int,
) -> str:
    return sha256({
        "operation_id": operation_id,
        "request_sha256": request_sha256,
        "stack_sha256": stack_sha256,
        "session_id": session_id,
        "runtime_authority_sha256": runtime_authority_sha256,
        "launch_descriptor_sha256": launch_descriptor_sha256,
        "research_release_id": research_release_id,
        "boot_id_sha256": boot_id_sha256,
        "qualification_subject_sha256": qualification_subject_sha256,
        "qualification_evidence_sha256": qualification_evidence_sha256,
        "qualification_observed_at": qualification_observed_at,
        "qualification_expires_at": qualification_expires_at,
    })


def make_projection_authority(
    *, consumer_executable_path: str, consumer_executable_sha256: str,
    host_release_id: str, operation_id: str, request_sha256: str,
    stack_sha256: str, authority: object, observation: object,
    now: int | None = None,
) -> dict[str, Any]:
    descriptor = make_launch_descriptor(authority)
    request = make_projection_status_request(
        operation_id=operation_id, authority=authority
    )
    timestamp = int(time.time()) if now is None else now
    observed = validate_projection_status_reply(
        observation, request_value=request, now=timestamp
    )
    subject = observed["qualification_subject"]
    result = {
        "consumer_executable_path": consumer_executable_path,
        "consumer_executable_sha256": consumer_executable_sha256,
        "host_release_id": host_release_id,
        "session_id": descriptor["session_id"],
        "runtime_authority_sha256": descriptor[
            "runtime_authority_sha256"
        ],
        "native_stack_binding_sha256": descriptor[
            "native_stack_binding_sha256"
        ],
        "harness_binding_sha256": descriptor["harness_binding_sha256"],
        "harness_generation_id": descriptor["harness_generation_id"],
        "harness_executable_sha256": descriptor[
            "harness_executable_sha256"
        ],
        "model_id": descriptor["model_id"],
        "reasoning_effort": descriptor["reasoning_effort"],
        "cyber_access_program": descriptor["cyber_access_program"],
        "policy_manifest_sha256": subject["policy_manifest_sha256"],
        "probe_executable_sha256": subject["probe_executable_sha256"],
        "protocol_version": subject["protocol_version"],
        "launch_descriptor_sha256": descriptor["descriptor_sha256"],
        "research_release_id": observed["research_release_id"],
        "boot_id_sha256": observed["boot_id_sha256"],
        "qualification_subject_sha256": subject[
            "qualification_subject_sha256"
        ],
        "qualification_evidence_sha256": observed[
            "qualification_evidence_sha256"
        ],
        "qualification_observed_at": observed["observed_at"],
        "qualification_expires_at": observed["expires_at"],
        "qualification_readback_sha256": projection_readback_sha256(
            operation_id=operation_id,
            request_sha256=request_sha256,
            stack_sha256=stack_sha256,
            session_id=descriptor["session_id"],
            runtime_authority_sha256=descriptor[
                "runtime_authority_sha256"
            ],
            launch_descriptor_sha256=descriptor["descriptor_sha256"],
            research_release_id=observed["research_release_id"],
            boot_id_sha256=observed["boot_id_sha256"],
            qualification_subject_sha256=subject[
                "qualification_subject_sha256"
            ],
            qualification_evidence_sha256=observed[
                "qualification_evidence_sha256"
            ],
            qualification_observed_at=observed["observed_at"],
            qualification_expires_at=observed["expires_at"],
        ),
    }
    return validate_projection_authority(
        result, operation_id=operation_id, request_sha256=request_sha256,
        stack_sha256=stack_sha256, session_authority_sha256=descriptor[
            "runtime_authority_sha256"
        ], ticket_issued_at=max(timestamp, observed["observed_at"]),
        ticket_expires_at=observed["expires_at"], now=timestamp,
    )


def validate_projection_authority(
    value: object, *, operation_id: str, request_sha256: str,
    stack_sha256: str, session_authority_sha256: str,
    ticket_issued_at: int, ticket_expires_at: int, now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(
            PROJECTION_AUTHORITY_FIELDS):
        raise NativeCodexProjectionError(
            "native_codex_projection_authority_fields_invalid"
        )
    result = {name: value[name] for name in PROJECTION_AUTHORITY_FIELDS}
    expected_path = (
        "/usr/local/libexec/secure-sandbox-host/releases/"
        f"{result['host_release_id']}/native_projection_consumer"
    )
    descriptor_body = {
        name: result[name] for name in LAUNCH_DESCRIPTOR_FIELDS
    }
    descriptor = validate_launch_descriptor({
        "schema": LAUNCH_DESCRIPTOR_SCHEMA,
        **descriptor_body,
        "descriptor_sha256": result["launch_descriptor_sha256"],
    })
    subject = validate_qualification_subject({
        "provider": "codex",
        "harness_generation_id": result["harness_generation_id"],
        "harness_executable_sha256": result[
            "harness_executable_sha256"
        ],
        "model_id": result["model_id"],
        "reasoning_effort": result["reasoning_effort"],
        "cyber_access_program": result["cyber_access_program"],
        "policy_manifest_sha256": result["policy_manifest_sha256"],
        "probe_executable_sha256": result["probe_executable_sha256"],
        "protocol_version": result["protocol_version"],
        "qualification_subject_sha256": result[
            "qualification_subject_sha256"
        ],
    }, descriptor_value=descriptor)
    observed_at = result["qualification_observed_at"]
    expires_at = result["qualification_expires_at"]
    _uuid(operation_id, "native_codex_projection_authority_invalid")
    _sha(request_sha256, "native_codex_projection_authority_invalid")
    _sha(stack_sha256, "native_codex_projection_authority_invalid")
    _sha(
        session_authority_sha256,
        "native_codex_projection_authority_invalid",
    )
    expected_readback = projection_readback_sha256(
        operation_id=operation_id, request_sha256=request_sha256,
        stack_sha256=stack_sha256, session_id=result["session_id"],
        runtime_authority_sha256=result["runtime_authority_sha256"],
        launch_descriptor_sha256=result["launch_descriptor_sha256"],
        research_release_id=result["research_release_id"],
        boot_id_sha256=result["boot_id_sha256"],
        qualification_subject_sha256=result[
            "qualification_subject_sha256"
        ],
        qualification_evidence_sha256=result[
            "qualification_evidence_sha256"
        ],
        qualification_observed_at=observed_at,
        qualification_expires_at=expires_at,
    )
    if (not isinstance(result["consumer_executable_path"], str)
            or result["consumer_executable_path"] != expected_path
            or any(not isinstance(result[name], str)
                   or SHA256.fullmatch(result[name]) is None for name in (
                       "consumer_executable_sha256", "host_release_id",
                       "runtime_authority_sha256",
                       "native_stack_binding_sha256",
                       "harness_binding_sha256", "harness_generation_id",
                       "harness_executable_sha256",
                       "policy_manifest_sha256", "probe_executable_sha256",
                       "launch_descriptor_sha256", "research_release_id",
                       "boot_id_sha256", "qualification_subject_sha256",
                       "qualification_evidence_sha256",
                       "qualification_readback_sha256",
                   ))
            or result["runtime_authority_sha256"]
                != session_authority_sha256
            or result["qualification_subject_sha256"]
                != subject["qualification_subject_sha256"]
            or not isinstance(observed_at, int) or isinstance(observed_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or observed_at < 1
            or not observed_at < expires_at <= observed_at + 120
            or observed_at > ticket_issued_at
            or not ticket_issued_at < ticket_expires_at <= expires_at
            or (now is not None and not observed_at <= now < expires_at)
            or result["qualification_readback_sha256"] != expected_readback):
        raise NativeCodexProjectionError(
            "native_codex_projection_authority_invalid"
        )
    return result


def projection_authority_matches_observation(
    value: object, *, operation_id: str, request_sha256: str,
    stack_sha256: str, observation: object, authority: object,
    now: int | None = None,
) -> bool:
    if not isinstance(value, Mapping):
        raise NativeCodexProjectionError(
            "native_codex_projection_authority_invalid"
        )
    descriptor = make_launch_descriptor(authority)
    request = make_projection_status_request(
        operation_id=operation_id, authority=authority
    )
    timestamp = int(time.time()) if now is None else now
    observed = validate_projection_status_reply(
        observation, request_value=request,
        now=timestamp,
    )
    candidate = make_projection_authority(
        consumer_executable_path=value["consumer_executable_path"],
        consumer_executable_sha256=value["consumer_executable_sha256"],
        host_release_id=value["host_release_id"],
        operation_id=operation_id, request_sha256=request_sha256,
        stack_sha256=stack_sha256, authority=authority,
        observation=observed, now=timestamp,
    )
    return (descriptor["runtime_authority_sha256"]
            == value["runtime_authority_sha256"] and candidate == value)


def validate_claim(value: object, *, now_ms: int | None = None) -> dict[str, Any]:
    fields = {
        "schema", "operation_id", "session_authority_sha256",
        "authorization_receipt_sha256", "access_token_sha256",
        "access_expires_at_ms", "claim_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexProjectionError(
            "native_codex_projection_claim_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "claim_sha256"}}
    observed = int(time.time() * 1000) if now_ms is None else now_ms
    expiry = body.get("access_expires_at_ms")
    if (value.get("schema") != CLAIM_SCHEMA
            or not isinstance(body.get("operation_id"), str)
            or UUID4.fullmatch(body["operation_id"]) is None
            or any(not isinstance(body.get(field), str)
                   or SHA256.fullmatch(body[field]) is None for field in (
                       "session_authority_sha256",
                       "authorization_receipt_sha256",
                       "access_token_sha256",
                   ))
            or not isinstance(expiry, int) or isinstance(expiry, bool)
            or not observed < expiry <= observed + MAXIMUM_ACCESS_LIFETIME_MS
            or not isinstance(value.get("claim_sha256"), str)
            or SHA256.fullmatch(value["claim_sha256"]) is None
            or not hmac.compare_digest(value["claim_sha256"], sha256(body))):
        raise NativeCodexProjectionError(
            "native_codex_projection_claim_invalid"
        )
    return {"schema": CLAIM_SCHEMA, **body,
            "claim_sha256": value["claim_sha256"]}


def make_claim(**values: object) -> dict[str, Any]:
    now_ms = values.pop("now_ms", None)
    return validate_claim({
        "schema": CLAIM_SCHEMA, **values, "claim_sha256": sha256(values),
    }, now_ms=now_ms if isinstance(now_ms, int) else None)


def validate_client_projection_reply(
    value: object, *, expected_operation_id: str,
    expected_session_authority_sha256: str,
    expected_executable_sha256: str, now_ms: int | None = None,
) -> dict[str, Any]:
    """Validate both signed-client and inner XPC projection reply digests."""
    fields = {
        "schema", "operation_id", "verified", "status", "projection",
        "error_code", "response_sha256", "reply_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeCodexProjectionError(
            "native_codex_projection_reply_fields_invalid"
        )
    projection = value.get("projection")
    projection_fields = {
        "process_identifier", "process_start_time_us", "executable_sha256",
        "session_authority_sha256", "started_at_ms",
    }
    observed_at = int(time.time() * 1000) if now_ms is None else now_ms
    if (value.get("schema") != CLIENT_REPLY_SCHEMA
            or value.get("operation_id") != expected_operation_id
            or value.get("verified") is not True
            or value.get("status") is not None
            or value.get("error_code") is not None
            or not isinstance(projection, Mapping)
            or set(projection) != projection_fields
            or not isinstance(projection.get("process_identifier"), int)
            or isinstance(projection.get("process_identifier"), bool)
            or projection["process_identifier"] <= 1
            or not isinstance(projection.get("process_start_time_us"), int)
            or isinstance(projection.get("process_start_time_us"), bool)
            or projection["process_start_time_us"] < 1
            or projection.get("executable_sha256")
                != expected_executable_sha256
            or projection.get("session_authority_sha256")
                != expected_session_authority_sha256
            or not isinstance(projection.get("started_at_ms"), int)
            or isinstance(projection.get("started_at_ms"), bool)
            or not observed_at - 300_000 <= projection["started_at_ms"]
                <= observed_at + 5_000
            or any(not isinstance(value.get(field), str)
                   or SHA256.fullmatch(value[field]) is None
                   for field in ("response_sha256", "reply_sha256"))):
        raise NativeCodexProjectionError(
            "native_codex_projection_reply_invalid"
        )
    inner_projection = {
        "process_identifier": projection["process_identifier"],
        "process_start_time_us": projection["process_start_time_us"],
        "executable_sha256": projection["executable_sha256"],
        "session_authority_sha256": projection["session_authority_sha256"],
        "started_at_milliseconds": projection["started_at_ms"],
    }
    inner_body = {
        "operation_id": value["operation_id"], "outcome": "verified",
        "status": None, "projection": inner_projection, "error_code": None,
    }
    outer_body = {
        key: value[key] for key in fields - {"schema", "reply_sha256"}
    }
    if (not hmac.compare_digest(value["response_sha256"], sha256(inner_body))
            or not hmac.compare_digest(
                value["reply_sha256"], sha256(outer_body)
            )):
        raise NativeCodexProjectionError(
            "native_codex_projection_reply_digest_mismatch"
        )
    return {"schema": CLIENT_REPLY_SCHEMA, **outer_body,
            "reply_sha256": value["reply_sha256"]}


def _socket(descriptor: int) -> socket.socket:
    result: socket.socket | None = None
    try:
        info = os.fstat(descriptor)
        result = socket.socket(fileno=os.dup(descriptor))
        if (descriptor < 3 or not stat.S_ISSOCK(info.st_mode)
                or os.isatty(descriptor) or result.family != socket.AF_UNIX
                or result.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                    != socket.SOCK_STREAM):
            raise OSError
        result.getsockname(); result.getpeername()
        return result
    except OSError as error:
        if result is not None:
            result.close()
        raise NativeCodexProjectionError(
            "native_codex_projection_control_invalid"
        ) from error


def _read_exact(descriptor: int, length: int, *, timeout: float) -> bytes:
    if not 0 < timeout <= 180:
        raise NativeCodexProjectionError(
            "native_codex_projection_timeout_invalid"
        )
    connection = _socket(descriptor)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while len(output) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select(
                [connection], [], [], max(0, remaining)
            )[0]:
                raise NativeCodexProjectionError(
                    "native_codex_projection_handshake_timeout"
                )
            block, ancillary, flags, _ = connection.recvmsg(
                length - len(output), socket.CMSG_SPACE(4)
            )
            if ancillary:
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        descriptors = array.array("i")
                        descriptors.frombytes(
                            data[:len(data) - (len(data) % descriptors.itemsize)]
                        )
                        for received in descriptors:
                            os.close(received)
            if (not block or ancillary
                    or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)):
                raise NativeCodexProjectionError(
                    "native_codex_projection_handshake_invalid"
                )
            output.extend(block)
        try:
            trailing = connection.recv(
                1, socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0)
            )
        except BlockingIOError:
            trailing = b""
        if trailing:
            raise NativeCodexProjectionError(
                "native_codex_projection_handshake_trailing_data"
            )
        return bytes(output)
    finally:
        connection.close()


def read_claim(descriptor: int, *, timeout: float = 120,
               now_ms: int | None = None) -> dict[str, Any]:
    raw = _read_exact(descriptor, CLAIM_BYTES, timeout=timeout)
    if raw[:8] != CLAIM_MAGIC:
        raise NativeCodexProjectionError(
            "native_codex_projection_claim_magic_invalid"
        )
    try:
        values: dict[str, object] = {
            "operation_id": raw[8:44].decode("ascii"),
            "session_authority_sha256": raw[44:108].decode("ascii"),
            "authorization_receipt_sha256": raw[108:172].decode("ascii"),
            "access_token_sha256": raw[172:236].decode("ascii"),
            "access_expires_at_ms": struct.unpack(">Q", raw[236:244])[0],
        }
    except (UnicodeDecodeError, struct.error) as error:
        raise NativeCodexProjectionError(
            "native_codex_projection_claim_encoding_invalid"
        ) from error
    if now_ms is not None:
        values["now_ms"] = now_ms
    return make_claim(**values)


def send_stream_fd(control_descriptor: int, stream_descriptor: int) -> None:
    control = _socket(control_descriptor)
    stream = _socket(stream_descriptor)
    try:
        rights = array.array("i", [stream_descriptor])
        if control.sendmsg(
            [FD_MAGIC], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
        ) != len(FD_MAGIC):
            raise NativeCodexProjectionError(
                "native_codex_projection_fd_transfer_failed"
            )
    except OSError as error:
        raise NativeCodexProjectionError(
            "native_codex_projection_fd_transfer_failed"
        ) from error
    finally:
        stream.close(); control.close()


def read_ready(descriptor: int, *, expected_operation_id: str,
               expected_access_token_sha256: str, timeout: float = 120) -> None:
    raw = _read_exact(descriptor, READY_BYTES, timeout=timeout)
    expected = (READY_MAGIC + expected_operation_id.encode("ascii")
                + expected_access_token_sha256.encode("ascii"))
    if not hmac.compare_digest(raw, expected):
        raise NativeCodexProjectionError(
            "native_codex_projection_ready_mismatch"
        )
