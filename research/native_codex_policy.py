#!/usr/bin/env python3
"""Content-only admission policy for the native Codex/Daybreak stack.

This module never accepts or handles an OpenAI access or refresh token.  It
reduces a fully validated runtime authority to the small, root-owned launch
descriptor consumed by ``native_codex_launcher`` before the separate signed
Host helper projects a short-lived access token over dedicated launcher fd 5.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping

from shared import native_vendor_stack
from shared.native_stack_runtime_binding import (
    NativeStackBindingError,
    validate_binding as validate_native_binding,
)
from shared.runtime_authority import RuntimeAuthorityError, validate_binding


LAUNCH_SCHEMA = "secure-sandbox-native-codex-launch-v2"
PROJECTION_PERMIT_SCHEMA = "secure-sandbox-native-codex-projection-permit-v1"
STATUS_SCHEMA = "secure-sandbox-native-codex-status-v1"
DESCRIPTOR_FIELDS = (
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
PROJECTION_PERMIT_FIELDS = (
    "projection_id",
    "session_id",
    "runtime_authority_sha256",
    "harness_generation_id",
    "harness_executable_sha256",
    "model_id",
    "access_token_sha256",
    "issued_at_unix",
    "expires_at_unix",
    "launcher_uid",
    "launcher_gid",
)
MAX_DESCRIPTOR_BYTES = 2048
MAX_PROJECTION_PERMIT_BYTES = 2048
PROJECTION_PERMIT_FD = 3
PROJECTION_FRAME_FD = 5
TOKEN_RECEIPT_FD = 6
PROJECTION_PERMIT_MAX_LIFETIME_SECONDS = 120
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
MODELS = {"gpt-6-sol", "gpt-6-luna", "gpt-6.1-sol"}
REASONING_EFFORTS = {"low", "medium", "high", "xhigh"}
EXPECTED_SETTINGS = {
    (model, effort): native_vendor_stack.sha256(
        {"cyber_access": "daybreak_blue", "reasoning_effort": effort}
    )
    for model in MODELS for effort in REASONING_EFFORTS
}


class NativeCodexPolicyError(ValueError):
    """Stable fail-closed native Codex policy error."""


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
        raise NativeCodexPolicyError("native_codex_not_canonicalizable") from error


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_codex_authority(value: object) -> dict[str, Any]:
    try:
        authority = validate_binding(value)
    except RuntimeAuthorityError as error:
        raise NativeCodexPolicyError("native_codex_runtime_authority_invalid") from error
    wrapper = authority["model_stack_binding"]
    if wrapper["mode"] != native_vendor_stack.MODE:
        raise NativeCodexPolicyError("native_codex_runtime_mode_invalid")
    try:
        native = validate_native_binding(wrapper["authority"])
    except NativeStackBindingError as error:
        raise NativeCodexPolicyError("native_codex_stack_binding_invalid") from error
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
    if any(native.get(name) != expected_value for name, expected_value in expected.items()):
        raise NativeCodexPolicyError("native_codex_stack_pairing_invalid")
    if native["model_id"] not in MODELS:
        raise NativeCodexPolicyError("native_codex_model_invalid")
    if not any(hmac.compare_digest(
        native["model_settings_sha256"],
        EXPECTED_SETTINGS[(native["model_id"], effort)])
        for effort in REASONING_EFFORTS
    ):
        raise NativeCodexPolicyError("native_codex_settings_invalid")
    if any(
        native[native_name] != harness[harness_name]
        for native_name, harness_name in (
            ("harness_id", "harness_id"),
            ("harness_generation_id", "harness_generation_id"),
            ("harness_adapter_id", "harness_adapter_id"),
        )
    ):
        raise NativeCodexPolicyError("native_codex_harness_binding_mismatch")
    return authority


def reasoning_effort(value: object) -> str:
    authority = require_codex_authority(value)
    native = authority["model_stack_binding"]["authority"]
    matches = [effort for effort in sorted(REASONING_EFFORTS)
               if hmac.compare_digest(
                   native["model_settings_sha256"],
                   EXPECTED_SETTINGS[(native["model_id"], effort)])]
    if len(matches) != 1:
        raise NativeCodexPolicyError("native_codex_settings_ambiguous")
    return matches[0]


def make_launch_descriptor(value: object) -> dict[str, str]:
    authority = require_codex_authority(value)
    native = authority["model_stack_binding"]["authority"]
    harness = authority["harness_binding"]
    body = {
        "runtime_authority_sha256": authority["binding_sha256"],
        "session_id": authority["session_context_binding"]["session_id"],
        "native_stack_binding_sha256": native["binding_sha256"],
        "harness_binding_sha256": harness["binding_sha256"],
        "harness_generation_id": harness["harness_generation_id"],
        "harness_executable_sha256": harness["harness_executable_sha256"],
        "model_id": native["model_id"],
        "reasoning_effort": reasoning_effort(authority),
        "cyber_access_program": "daybreakBlue",
    }
    return validate_launch_descriptor(
        {"schema": LAUNCH_SCHEMA, **body, "descriptor_sha256": sha256(body)}
    )


def validate_launch_descriptor(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", *DESCRIPTOR_FIELDS, "descriptor_sha256"
    }:
        raise NativeCodexPolicyError("native_codex_descriptor_fields_invalid")
    if value.get("schema") != LAUNCH_SCHEMA:
        raise NativeCodexPolicyError("native_codex_descriptor_schema_invalid")
    result = {name: value.get(name) for name in DESCRIPTOR_FIELDS}
    for name in (
        "runtime_authority_sha256",
        "native_stack_binding_sha256",
        "harness_binding_sha256",
        "harness_generation_id",
        "harness_executable_sha256",
    ):
        if not isinstance(result[name], str) or SHA256.fullmatch(result[name]) is None:
            raise NativeCodexPolicyError(f"native_codex_descriptor_{name}_invalid")
    if (
        not isinstance(result["session_id"], str)
        or UUID4.fullmatch(result["session_id"]) is None
    ):
        raise NativeCodexPolicyError("native_codex_descriptor_session_id_invalid")
    if result["model_id"] not in MODELS:
        raise NativeCodexPolicyError("native_codex_descriptor_model_invalid")
    if result["reasoning_effort"] not in REASONING_EFFORTS:
        raise NativeCodexPolicyError("native_codex_descriptor_effort_invalid")
    if result["cyber_access_program"] != "daybreakBlue":
        raise NativeCodexPolicyError("native_codex_descriptor_program_invalid")
    body = {name: result[name] for name in DESCRIPTOR_FIELDS}
    supplied = value.get("descriptor_sha256")
    if (
        not isinstance(supplied, str)
        or SHA256.fullmatch(supplied) is None
        or not hmac.compare_digest(supplied, sha256(body))
    ):
        raise NativeCodexPolicyError("native_codex_descriptor_digest_mismatch")
    return {"schema": LAUNCH_SCHEMA, **result, "descriptor_sha256": supplied}  # type: ignore[dict-item]


def descriptor_bytes(value: object) -> bytes:
    descriptor = validate_launch_descriptor(value)
    lines = [f"schema={LAUNCH_SCHEMA}"]
    lines.extend(f"{name}={descriptor[name]}" for name in DESCRIPTOR_FIELDS)
    lines.append(f"descriptor_sha256={descriptor['descriptor_sha256']}")
    encoded = ("\n".join(lines) + "\n").encode("ascii")
    if len(encoded) > MAX_DESCRIPTOR_BYTES:
        raise NativeCodexPolicyError("native_codex_descriptor_oversized")
    return encoded


def write_launch_descriptor(
    path: Path,
    value: object,
    *,
    uid: int = 0,
    gid: int,
) -> str:
    """Atomically publish only non-secret launch authority for the C consumer."""
    data = descriptor_bytes(value)
    parent = path.parent
    info = parent.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or info.st_mode & 0o022
    ):
        raise NativeCodexPolicyError("native_codex_descriptor_parent_untrusted")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o640)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return validate_launch_descriptor(value)["descriptor_sha256"]


def make_projection_permit(
    descriptor_value: object,
    *,
    projection_id: str,
    access_token_sha256: str,
    issued_at_unix: int,
    expires_at_unix: int,
    launcher_uid: int,
    launcher_gid: int,
) -> dict[str, Any]:
    """Create the non-secret permit a root supervisor hands off on fd 3.

    The supervisor contract is deliberately narrower than a pathname protocol:

    * root atomically claims exactly one permit, writes these canonical bytes to
      a root-owned 0400 regular file, opens it read-only, unlinks it, rewinds it,
      and passes that sole open description as ``PROJECTION_PERMIT_FD``;
    * the permit UUID is copied into the fd-5 credential-frame header and the
      access-token digest is computed before launch without persisting the token;
    * root closes every other permit descriptor immediately after spawn and
      creates a fresh root-owned 0710 session directory containing only empty
      ``home``, ``cache``, and ``tmp`` directories owned 0700 by the launcher;
    * the launcher UID/GID named here are the credentials in effect when the
      launcher validates the inherited descriptor and executes Codex.

    The permit inode is root:root.  A permit path, a linked permit file, a
    caller-created descriptor, or a permit reused for another spawn is outside
    this contract and must fail.
    """
    descriptor = validate_launch_descriptor(descriptor_value)
    body: dict[str, Any] = {
        "projection_id": projection_id,
        "session_id": descriptor["session_id"],
        "runtime_authority_sha256": descriptor["runtime_authority_sha256"],
        "harness_generation_id": descriptor["harness_generation_id"],
        "harness_executable_sha256": descriptor["harness_executable_sha256"],
        "model_id": descriptor["model_id"],
        "access_token_sha256": access_token_sha256,
        "issued_at_unix": issued_at_unix,
        "expires_at_unix": expires_at_unix,
        "launcher_uid": launcher_uid,
        "launcher_gid": launcher_gid,
    }
    return validate_projection_permit(
        {
            "schema": PROJECTION_PERMIT_SCHEMA,
            **body,
            "permit_sha256": sha256(body),
        },
        descriptor_value=descriptor,
    )


def validate_projection_permit(
    value: object,
    *,
    descriptor_value: object | None = None,
    now_unix: int | None = None,
    launcher_uid: int | None = None,
    launcher_gid: int | None = None,
    expected_projection_id: str | None = None,
    expected_access_token_sha256: str | None = None,
) -> dict[str, Any]:
    expected_fields = {"schema", *PROJECTION_PERMIT_FIELDS, "permit_sha256"}
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise NativeCodexPolicyError("native_codex_projection_permit_fields_invalid")
    if value.get("schema") != PROJECTION_PERMIT_SCHEMA:
        raise NativeCodexPolicyError("native_codex_projection_permit_schema_invalid")
    result = {name: value.get(name) for name in PROJECTION_PERMIT_FIELDS}
    for name in (
        "runtime_authority_sha256",
        "harness_generation_id",
        "harness_executable_sha256",
        "access_token_sha256",
    ):
        if not isinstance(result[name], str) or SHA256.fullmatch(result[name]) is None:
            raise NativeCodexPolicyError(
                f"native_codex_projection_permit_{name}_invalid"
            )
    for name in ("projection_id", "session_id"):
        if not isinstance(result[name], str) or UUID4.fullmatch(result[name]) is None:
            raise NativeCodexPolicyError(
                f"native_codex_projection_permit_{name}_invalid"
            )
    if result["model_id"] not in MODELS:
        raise NativeCodexPolicyError("native_codex_projection_permit_model_invalid")
    for name in ("issued_at_unix", "expires_at_unix", "launcher_uid", "launcher_gid"):
        item = result[name]
        maximum = (
            (1 << 32) - 1
            if name in {"launcher_uid", "launcher_gid"}
            else (1 << 64) - 1
        )
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 0
            or item > maximum
        ):
            raise NativeCodexPolicyError(
                f"native_codex_projection_permit_{name}_invalid"
            )
    issued_at = result["issued_at_unix"]
    expires_at = result["expires_at_unix"]
    if not (
        issued_at < expires_at
        and expires_at - issued_at <= PROJECTION_PERMIT_MAX_LIFETIME_SECONDS
    ):
        raise NativeCodexPolicyError("native_codex_projection_permit_lifetime_invalid")
    if now_unix is not None and not (issued_at - 5 <= now_unix < expires_at):
        raise NativeCodexPolicyError("native_codex_projection_permit_expired")
    if launcher_uid is not None and result["launcher_uid"] != launcher_uid:
        raise NativeCodexPolicyError("native_codex_projection_permit_uid_invalid")
    if launcher_gid is not None and result["launcher_gid"] != launcher_gid:
        raise NativeCodexPolicyError("native_codex_projection_permit_gid_invalid")
    if expected_projection_id is not None and not hmac.compare_digest(
        str(result["projection_id"]), expected_projection_id
    ):
        raise NativeCodexPolicyError(
            "native_codex_projection_permit_projection_id_mismatch"
        )
    if expected_access_token_sha256 is not None and not hmac.compare_digest(
        str(result["access_token_sha256"]), expected_access_token_sha256
    ):
        raise NativeCodexPolicyError(
            "native_codex_projection_permit_access_token_sha256_mismatch"
        )
    if descriptor_value is not None:
        descriptor = validate_launch_descriptor(descriptor_value)
        for permit_name, descriptor_name in (
            ("session_id", "session_id"),
            ("runtime_authority_sha256", "runtime_authority_sha256"),
            ("harness_generation_id", "harness_generation_id"),
            ("harness_executable_sha256", "harness_executable_sha256"),
            ("model_id", "model_id"),
        ):
            if not hmac.compare_digest(
                str(result[permit_name]), str(descriptor[descriptor_name])
            ):
                raise NativeCodexPolicyError(
                    f"native_codex_projection_permit_{permit_name}_mismatch"
                )
    body = {name: result[name] for name in PROJECTION_PERMIT_FIELDS}
    supplied = value.get("permit_sha256")
    if (
        not isinstance(supplied, str)
        or SHA256.fullmatch(supplied) is None
        or not hmac.compare_digest(supplied, sha256(body))
    ):
        raise NativeCodexPolicyError("native_codex_projection_permit_digest_mismatch")
    return {
        "schema": PROJECTION_PERMIT_SCHEMA,
        **result,
        "permit_sha256": supplied,
    }


def projection_permit_bytes(value: object) -> bytes:
    permit = validate_projection_permit(value)
    lines = [f"schema={PROJECTION_PERMIT_SCHEMA}"]
    lines.extend(f"{name}={permit[name]}" for name in PROJECTION_PERMIT_FIELDS)
    lines.append(f"permit_sha256={permit['permit_sha256']}")
    encoded = ("\n".join(lines) + "\n").encode("ascii")
    if len(encoded) > MAX_PROJECTION_PERMIT_BYTES:
        raise NativeCodexPolicyError("native_codex_projection_permit_oversized")
    return encoded


def content_free_status(value: object, *, state: str) -> dict[str, str]:
    descriptor = validate_launch_descriptor(value)
    if state not in {"ready", "started", "closed", "fenced", "ambiguous"}:
        raise NativeCodexPolicyError("native_codex_status_state_invalid")
    body = {
        "state": state,
        "runtime_authority_sha256": descriptor["runtime_authority_sha256"],
        "native_stack_binding_sha256": descriptor["native_stack_binding_sha256"],
        "harness_binding_sha256": descriptor["harness_binding_sha256"],
        "model_id": descriptor["model_id"],
        "cyber_access_program": descriptor["cyber_access_program"],
        "launch_descriptor_sha256": descriptor["descriptor_sha256"],
    }
    return {"schema": STATUS_SCHEMA, **body, "status_sha256": sha256(body)}
