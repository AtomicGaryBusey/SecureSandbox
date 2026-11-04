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
