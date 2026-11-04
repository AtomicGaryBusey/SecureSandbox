#!/usr/bin/env python3
"""First-party Codex 0.166 app-server runtime driver.

The driver is the only owner of app-server stdin, stdout, and stderr.  It
converts a closed, self-digested human command protocol into the four requests
exposed by :class:`NativeCodexProtocolFirewall`, and converts admitted server
events into a separate bounded event protocol.  Raw JSON-RPC, stderr, terminal
control bytes, and arbitrary server fields never reach Host or GUI code.

Credential projection is deliberately outside this module. The C launcher
consumes the exact token frame from fd 5, writes a content-free digest/length
receipt on private fd 6, and closes both before ``exec``. The controller
requires receipt EOF before constructing this driver. A distinct UI channel is
therefore never an alias of either projection descriptor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import selectors
import stat
import struct
import time
import unicodedata
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from research import native_codex_policy
from research.native_codex_protocol_firewall import (
    CYBER_ACCESS_PROGRAM,
    MAX_USER_TEXT_BYTES,
    MAX_WIRE_BYTES,
    CodexServerEvent,
    NativeCodexProtocolFirewall,
    ProtocolViolation,
)


COMMAND_SCHEMA = "secure-sandbox-native-codex-command-v1"
EVENT_SCHEMA = "secure-sandbox-native-codex-event-v1"
MAX_COMMAND_BYTES = MAX_USER_TEXT_BYTES + 4096
MAX_EVENT_BYTES = 48 * 1024
MAX_SERVER_STDERR_BYTES = 64 * 1024
MAX_TURN_TEXT_BYTES = 1024 * 1024
MAX_BUFFER_BYTES = MAX_WIRE_BYTES + 1
STARTUP_TIMEOUT_SECONDS = 15.0
VERIFICATION_TIMEOUT_SECONDS = 15.0
POLL_SECONDS = 0.1
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}")
SAFE_OPERATION = frozenset({"turn", "interrupt", "close"})
TOKEN_RECEIPT_MAGIC = b"SSCDXR1\n"
TOKEN_RECEIPT_BODY_BYTES = 8 + 36 + 36 + 64 + 64 + 64 + 4 + 8
TOKEN_RECEIPT_BYTES = TOKEN_RECEIPT_BODY_BYTES + 64
MIN_TOKEN_BYTES = 16
MAX_TOKEN_BYTES = 65_536
ROLLING_BASE = 257
UINT64_MASK = (1 << 64) - 1
_CREDENTIAL_MARKERS = (
    "access_token",
    "openai_api_key",
    "openai_access_token",
    "openai_refresh_token",
    "chatgpt_access_token",
    "chatgpt_refresh_token",
    "authorization: bearer",
)


class NativeCodexRuntimeError(RuntimeError):
    """Stable fail-closed runtime-driver error."""


@dataclass(frozen=True)
class RuntimeDriverResult:
    reason: str
    event_count: int
    command_count: int
    stderr_bytes: int
    stderr_sha256: str
    qualification_attestation_sha256: str
    session_lease_sha256: str
    session_expires_at: int


@dataclass(frozen=True)
class ProjectionTokenReceipt:
    projection_id: str
    session_id: str
    runtime_authority_sha256: str
    permit_sha256: str
    access_token_sha256: str
    token_length: int
    rolling_fingerprint: int


def token_rolling_fingerprint(value: bytes) -> int:
    if not isinstance(value, bytes):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_fingerprint_invalid")
    result = 0
    for byte in value:
        result = ((result * ROLLING_BASE) + byte) & UINT64_MASK
    return result


def make_token_receipt_bytes(receipt: ProjectionTokenReceipt) -> bytes:
    if (not isinstance(receipt, ProjectionTokenReceipt)
            or not isinstance(receipt.projection_id, str)
            or UUID4.fullmatch(receipt.projection_id) is None
            or not isinstance(receipt.session_id, str)
            or UUID4.fullmatch(receipt.session_id) is None
            or any(not isinstance(value, str)
                   or SHA256.fullmatch(value) is None for value in (
                receipt.runtime_authority_sha256, receipt.permit_sha256,
                receipt.access_token_sha256))
            or not MIN_TOKEN_BYTES <= receipt.token_length <= MAX_TOKEN_BYTES
            or not isinstance(receipt.rolling_fingerprint, int)
            or isinstance(receipt.rolling_fingerprint, bool)
            or not 0 <= receipt.rolling_fingerprint <= UINT64_MASK):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_invalid")
    body = b"".join((
        TOKEN_RECEIPT_MAGIC,
        receipt.projection_id.encode("ascii"),
        receipt.session_id.encode("ascii"),
        receipt.runtime_authority_sha256.encode("ascii"),
        receipt.permit_sha256.encode("ascii"),
        receipt.access_token_sha256.encode("ascii"),
        struct.pack(">I", receipt.token_length),
        struct.pack(">Q", receipt.rolling_fingerprint),
    ))
    return body + hashlib.sha256(body).hexdigest().encode("ascii")


def validate_token_receipt(
    raw: bytes,
    *,
    launch_descriptor: Mapping[str, str],
    expected_projection_id: str,
    expected_permit_sha256: str,
    expected_access_token_sha256: str,
) -> ProjectionTokenReceipt:
    if (not isinstance(expected_projection_id, str)
            or UUID4.fullmatch(expected_projection_id) is None
            or any(not isinstance(value, str)
                   or SHA256.fullmatch(value) is None for value in (
                       expected_permit_sha256,
                       expected_access_token_sha256))):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_expectation_invalid")
    if (not isinstance(raw, bytes) or len(raw) != TOKEN_RECEIPT_BYTES
            or not hmac.compare_digest(raw[:8], TOKEN_RECEIPT_MAGIC)):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_framing_invalid")
    supplied_digest = raw[TOKEN_RECEIPT_BODY_BYTES:]
    expected_digest = hashlib.sha256(
        raw[:TOKEN_RECEIPT_BODY_BYTES]).hexdigest().encode("ascii")
    if not hmac.compare_digest(supplied_digest, expected_digest):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_digest_mismatch")
    offsets = (8, 44, 80, 144, 208, 272)
    try:
        values = [raw[offsets[index]:offsets[index + 1]].decode("ascii")
                  for index in range(5)]
        token_length = struct.unpack(">I", raw[272:276])[0]
        rolling_fingerprint = struct.unpack(">Q", raw[276:284])[0]
    except (UnicodeDecodeError, struct.error) as error:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_framing_invalid") from error
    receipt = ProjectionTokenReceipt(
        projection_id=values[0], session_id=values[1],
        runtime_authority_sha256=values[2], permit_sha256=values[3],
        access_token_sha256=values[4], token_length=token_length,
        rolling_fingerprint=rolling_fingerprint)
    if make_token_receipt_bytes(receipt) != raw:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_not_canonical")
    expected = (
        expected_projection_id,
        launch_descriptor["session_id"],
        launch_descriptor["runtime_authority_sha256"],
        expected_permit_sha256,
        expected_access_token_sha256,
    )
    observed = (
        receipt.projection_id, receipt.session_id,
        receipt.runtime_authority_sha256, receipt.permit_sha256,
        receipt.access_token_sha256,
    )
    if any(not hmac.compare_digest(left, right)
           for left, right in zip(observed, expected, strict=True)):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_identity_mismatch")
    return receipt


def read_token_receipt(descriptor: int, *, timeout_seconds: float = 15.0) -> bytes:
    """Read one exact launcher receipt and require pipe EOF before returning."""
    _transport_descriptor(descriptor, readable=True)
    if (not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 60):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_token_receipt_timeout_invalid")
    deadline = time.monotonic() + timeout_seconds
    value = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_token_receipt_timeout")
            try:
                block = os.read(descriptor, TOKEN_RECEIPT_BYTES + 1 - len(value))
            except InterruptedError:
                continue
            except OSError as error:
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_token_receipt_read_failed") from error
            if not block:
                if len(value) != TOKEN_RECEIPT_BYTES:
                    raise NativeCodexRuntimeError(
                        "native_codex_runtime_token_receipt_truncated")
                return bytes(value)
            value.extend(block)
            if len(value) > TOKEN_RECEIPT_BYTES:
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_token_receipt_trailing_data")
    finally:
        selector.close()


class _TokenExfiltrationGuard:
    """Quarantine the exact-token overlap window before UI publication.

    Digest DLP blocks exact raw-token reflection. It cannot block an admitted
    malicious binary from encoding or covertly leaking a credential; exact
    binary admission and process isolation remain the primary controls.
    """

    def __init__(self, receipt: ProjectionTokenReceipt) -> None:
        self._length = receipt.token_length
        self._digest = receipt.access_token_sha256
        self._target_fingerprint = receipt.rolling_fingerprint
        self._power = pow(ROLLING_BASE, self._length - 1, 1 << 64)
        self._window: deque[int] = deque()
        self._fingerprint = 0
        self._segments: deque[tuple[str, bytes]] = deque()
        self._quarantine_bytes = 0

    def admit(self, channel: str, encoded: bytes) -> list[tuple[str, str]]:
        for byte in encoded:
            if len(self._window) == self._length:
                removed = self._window.popleft()
                self._fingerprint = (
                    self._fingerprint - removed * self._power) & UINT64_MASK
            self._window.append(byte)
            self._fingerprint = (
                self._fingerprint * ROLLING_BASE + byte) & UINT64_MASK
            if (len(self._window) == self._length
                    and self._fingerprint == self._target_fingerprint
                    and hmac.compare_digest(
                        hashlib.sha256(bytes(self._window)).hexdigest(),
                        self._digest)):
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_projected_token_reflected")

        if encoded:
            # Keep immutable deltas as individual deque entries. Repeatedly
            # concatenating same-channel deltas would make an otherwise O(n)
            # rolling scan quadratic for a long stream of tiny app-server
            # notifications.
            self._segments.append((channel, encoded))
            self._quarantine_bytes += len(encoded)
        releasable = max(
            0, self._quarantine_bytes - (self._length - 1))
        released: list[tuple[str, str]] = []
        while releasable > 0 and self._segments:
            segment_channel, segment = self._segments[0]
            count = min(releasable, len(segment))
            while count > 0:
                try:
                    text = segment[:count].decode("utf-8", errors="strict")
                    break
                except UnicodeDecodeError:
                    count -= 1
            if count == 0:
                break
            released.append((segment_channel, text))
            releasable -= count
            self._quarantine_bytes -= count
            if count == len(segment):
                self._segments.popleft()
            else:
                self._segments[0] = (segment_channel, segment[count:])
        return released

    def finish(self) -> list[tuple[str, str]]:
        """Release the non-token tail only at an explicit clean boundary.

        The rolling window deliberately spans every delta and every turn in a
        session.  Consequently, the last ``token_length - 1`` bytes cannot be
        published until the caller has committed to accepting no more vendor
        output.  ``finish`` is therefore intentionally separate from
        ``admit`` and must never be used by failure or disconnect paths.
        """
        released: list[tuple[str, str]] = []
        while self._segments:
            channel, encoded = self._segments.popleft()
            try:
                text = encoded.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                self.discard()
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_quarantine_utf8_invalid") from error
            if text:
                released.append((channel, text))
        self._quarantine_bytes = 0
        self._window.clear()
        self._fingerprint = 0
        return released

    def discard(self) -> None:
        """Forget quarantined bytes without ever making them observable."""
        self._segments.clear()
        self._quarantine_bytes = 0
        self._window.clear()
        self._fingerprint = 0


def canonical_bytes(value: object) -> bytes:
    try:
        return (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_value_invalid") from error


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def make_command(
    *,
    sequence: int,
    runtime_authority_sha256: str,
    operation: str,
    text: str | None = None,
) -> dict[str, Any]:
    if operation == "turn":
        payload: dict[str, Any] = {"text": text}
    else:
        payload = {}
    body = {
        "schema": COMMAND_SCHEMA,
        "sequence": sequence,
        "runtime_authority_sha256": runtime_authority_sha256,
        "operation": operation,
        "payload": payload,
    }
    return {**body, "command_sha256": digest(body)}


def _safe_text(value: object, *, maximum: int, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise NativeCodexRuntimeError("native_codex_runtime_text_invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_text_invalid") from error
    if (len(encoded) > maximum or (not empty and not encoded)
            or any(
                (unicodedata.category(character) in {"Cc", "Cf"}
                 and character not in {"\n", "\t"})
                for character in value)):
        raise NativeCodexRuntimeError("native_codex_runtime_text_invalid")
    lowered = value.casefold()
    if any(marker in lowered for marker in _CREDENTIAL_MARKERS):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_credential_text_forbidden")
    return value


def validate_command(
    value: object,
    *,
    expected_sequence: int,
    runtime_authority_sha256: str,
) -> dict[str, Any]:
    fields = {
        "schema", "sequence", "runtime_authority_sha256", "operation",
        "payload", "command_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_fields_invalid")
    if (value["schema"] != COMMAND_SCHEMA
            or not isinstance(value["sequence"], int)
            or isinstance(value["sequence"], bool)
            or value["sequence"] != expected_sequence
            or value["runtime_authority_sha256"]
               != runtime_authority_sha256
            or value["operation"] not in SAFE_OPERATION
            or not isinstance(value["payload"], dict)
            or not isinstance(value["command_sha256"], str)
            or SHA256.fullmatch(value["command_sha256"]) is None):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_identity_invalid")
    operation = value["operation"]
    if operation == "turn":
        if set(value["payload"]) != {"text"}:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_command_payload_invalid")
        _safe_text(value["payload"]["text"], maximum=MAX_USER_TEXT_BYTES)
    elif value["payload"] != {}:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_payload_invalid")
    body = {name: value[name] for name in fields - {"command_sha256"}}
    if value["command_sha256"] != digest(body):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_digest_mismatch")
    return value


def decode_command_line(
    raw: bytes,
    *,
    expected_sequence: int,
    runtime_authority_sha256: str,
) -> dict[str, Any]:
    if (not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_COMMAND_BYTES
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1
            or b"\x00" in raw):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_framing_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_json_invalid") from error
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_not_canonical")
    return validate_command(
        value, expected_sequence=expected_sequence,
        runtime_authority_sha256=runtime_authority_sha256)


def _transport_descriptor(descriptor: int, *, readable: bool) -> None:
    if not isinstance(descriptor, int) or descriptor < 0 or os.isatty(descriptor):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_transport_invalid")
    try:
        info = os.fstat(descriptor)
        flags = fcntl_getfl(descriptor)
    except OSError as error:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_transport_invalid") from error
    if not (stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode)):
        raise NativeCodexRuntimeError(
            "native_codex_runtime_transport_invalid")
    access = flags & os.O_ACCMODE
    if readable and access == os.O_WRONLY:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_transport_invalid")
    if not readable and access == os.O_RDONLY:
        raise NativeCodexRuntimeError(
            "native_codex_runtime_transport_invalid")


def fcntl_getfl(descriptor: int) -> int:
    import fcntl
    return fcntl.fcntl(descriptor, fcntl.F_GETFL)


class NativeCodexRuntimeDriver:
    """Own one admitted app-server transport and one human command stream."""

    def __init__(
        self,
        *,
        launch_descriptor: Mapping[str, object],
        host_input_fd: int,
        host_output_fd: int,
        appserver_input_fd: int,
        appserver_output_fd: int,
        appserver_stderr_fd: int,
        token_receipt: bytes,
        expected_projection_id: str,
        expected_permit_sha256: str,
        expected_access_token_sha256: str,
        session_lease_sha256: str,
        session_expires_at: int,
        qualification_gate: Callable[
            [NativeCodexProtocolFirewall, Mapping[str, str]], str],
        lease_deadline_monotonic: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            descriptor = native_codex_policy.validate_launch_descriptor(
                launch_descriptor)
        except native_codex_policy.NativeCodexPolicyError as error:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_descriptor_invalid") from error
        if not callable(qualification_gate):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_qualification_gate_invalid")
        if (not isinstance(session_lease_sha256, str)
                or SHA256.fullmatch(session_lease_sha256) is None
                or not isinstance(session_expires_at, int)
                or isinstance(session_expires_at, bool)
                or session_expires_at < 1):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_session_lease_invalid")
        if (lease_deadline_monotonic is not None
                and (not isinstance(lease_deadline_monotonic, (int, float))
                     or isinstance(lease_deadline_monotonic, bool)
                     or not math.isfinite(lease_deadline_monotonic)
                     or lease_deadline_monotonic <= monotonic())):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_lease_invalid")
        receipt = validate_token_receipt(
            token_receipt, launch_descriptor=descriptor,
            expected_projection_id=expected_projection_id,
            expected_permit_sha256=expected_permit_sha256,
            expected_access_token_sha256=expected_access_token_sha256)
        descriptors = {
            host_input_fd, host_output_fd, appserver_input_fd,
            appserver_output_fd, appserver_stderr_fd,
        }
        # A duplex Host socket may intentionally occupy both directions; every
        # app-server endpoint must nevertheless be a separate description.
        if (len({appserver_input_fd, appserver_output_fd,
                 appserver_stderr_fd}) != 3
                or appserver_input_fd in {host_input_fd, host_output_fd}
                or appserver_output_fd in {host_input_fd, host_output_fd}
                or appserver_stderr_fd in {host_input_fd, host_output_fd}
                or len(descriptors) < 4):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_descriptor_alias_invalid")
        try:
            identities = {
                descriptor: (
                    os.fstat(descriptor).st_dev,
                    os.fstat(descriptor).st_ino,
                ) for descriptor in descriptors
            }
        except OSError as error:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_transport_invalid") from error
        app_identities = {
            identities[appserver_input_fd], identities[appserver_output_fd],
            identities[appserver_stderr_fd],
        }
        host_identities = {
            identities[host_input_fd], identities[host_output_fd],
        }
        if len(app_identities) != 3 or app_identities & host_identities:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_descriptor_alias_invalid")
        _transport_descriptor(host_input_fd, readable=True)
        _transport_descriptor(host_output_fd, readable=False)
        _transport_descriptor(appserver_input_fd, readable=False)
        _transport_descriptor(appserver_output_fd, readable=True)
        _transport_descriptor(appserver_stderr_fd, readable=True)
        self._descriptor = descriptor
        self._host_input_fd = host_input_fd
        self._host_output_fd = host_output_fd
        self._appserver_input_fd = appserver_input_fd
        self._appserver_output_fd = appserver_output_fd
        self._appserver_stderr_fd = appserver_stderr_fd
        self._qualification_gate = qualification_gate
        self._session_lease_sha256 = session_lease_sha256
        self._session_expires_at = session_expires_at
        self._token_guard = _TokenExfiltrationGuard(receipt)
        self._monotonic = monotonic
        self._lease_deadline = lease_deadline_monotonic
        self._firewall = NativeCodexProtocolFirewall(
            launch_descriptor=descriptor)
        self._host_buffer = bytearray()
        self._server_buffer = bytearray()
        self._stderr_bytes = 0
        self._stderr_hasher = hashlib.sha256()
        self._event_sequence = 1
        self._command_sequence = 1
        self._event_count = 0
        self._command_count = 0
        self._turn_text_bytes = 0
        self._turn_started_emitted = False
        self._turn_completion_emitted = False
        self._normal_completion_observed = False
        self._verification_deadline: float | None = None
        self._qualified_terminal_boundary = True
        self._release_token_tail = False
        self._qualification_attestation_sha256: str | None = None

    @property
    def firewall(self) -> NativeCodexProtocolFirewall:
        return self._firewall

    def _bounded_deadline(self, seconds: float) -> float:
        now = self._monotonic()
        if self._lease_deadline is not None and now >= self._lease_deadline:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_lease_expired")
        deadline = now + seconds
        return (deadline if self._lease_deadline is None
                else min(deadline, self._lease_deadline))

    def _raise_timeout(self, fallback: str) -> None:
        if (self._lease_deadline is not None
                and self._monotonic() >= self._lease_deadline):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_lease_expired")
        raise NativeCodexRuntimeError(fallback)

    def _write(self, descriptor: int, raw: bytes, *, code: str) -> None:
        view = memoryview(raw)
        deadline = self._bounded_deadline(STARTUP_TIMEOUT_SECONDS)
        while view:
            if self._monotonic() >= deadline:
                self._raise_timeout(code)
            try:
                count = os.write(descriptor, view)
            except BlockingIOError:
                if self._monotonic() >= deadline:
                    self._raise_timeout(code)
                time.sleep(0.005)
                continue
            except (BrokenPipeError, OSError) as error:
                raise NativeCodexRuntimeError(code) from error
            if count <= 0:
                raise NativeCodexRuntimeError(code)
            view = view[count:]

    def _send_server(self, raw: bytes) -> None:
        if not isinstance(raw, bytes) or len(raw) > MAX_WIRE_BYTES:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_server_request_invalid")
        self._write(
            self._appserver_input_fd, raw,
            code="native_codex_runtime_server_write_failed")

    def _emit(self, event: str, payload: Mapping[str, object]) -> None:
        if (not isinstance(event, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,47}", event) is None
                or not isinstance(payload, Mapping)):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_event_invalid")
        body = {
            "schema": EVENT_SCHEMA,
            "sequence": self._event_sequence,
            "runtime_authority_sha256": self._descriptor[
                "runtime_authority_sha256"],
            "session_lease_sha256": self._session_lease_sha256,
            "event": event,
            "payload": dict(payload),
        }
        value = {**body, "event_sha256": digest(body)}
        raw = canonical_bytes(value)
        if len(raw) > MAX_EVENT_BYTES:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_event_oversized")
        self._write(
            self._host_output_fd, raw,
            code="native_codex_runtime_host_write_failed")
        self._event_sequence += 1
        self._event_count += 1

    def _drain_stderr(self) -> bool:
        try:
            block = os.read(self._appserver_stderr_fd, 16 * 1024)
        except BlockingIOError:
            return True
        except OSError as error:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_stderr_read_failed") from error
        if not block:
            return False
        self._stderr_bytes += len(block)
        if self._stderr_bytes > MAX_SERVER_STDERR_BYTES:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_stderr_limit")
        self._stderr_hasher.update(block)
        return True

    def _read_startup_server_line(self, *, deadline: float) -> bytes:
        selector = selectors.DefaultSelector()
        selector.register(self._appserver_output_fd, selectors.EVENT_READ, "out")
        selector.register(self._appserver_stderr_fd, selectors.EVENT_READ, "err")
        try:
            while self._monotonic() < deadline:
                newline = self._server_buffer.find(b"\n")
                if newline >= 0:
                    raw = bytes(self._server_buffer[:newline + 1])
                    del self._server_buffer[:newline + 1]
                    return raw
                events = selector.select(
                    min(POLL_SECONDS, max(0.0, deadline - self._monotonic())))
                for key, _mask in events:
                    if key.data == "err":
                        self._drain_stderr()
                        continue
                    try:
                        block = os.read(self._appserver_output_fd, 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not block:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_server_eof")
                    self._server_buffer.extend(block)
                    if len(self._server_buffer) > MAX_BUFFER_BYTES:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_server_frame_oversized")
            self._raise_timeout("native_codex_runtime_server_timeout")
        finally:
            selector.close()

    def _exchange_startup(self, request: bytes) -> None:
        self._send_server(request)
        deadline = self._bounded_deadline(STARTUP_TIMEOUT_SECONDS)
        while True:
            line = self._read_startup_server_line(deadline=deadline)
            event = self._firewall.ingest_server_line(line)
            if event is not None:
                # Only a disabled remote-control notification is admissible
                # before thread startup; the firewall enforces that shape.
                self._sanitize_event(event, emit=False)
                continue
            return

    def _drain_pre_ready_server(self) -> None:
        """Validate every app-server byte already observable before READY."""
        selector = selectors.DefaultSelector()
        selector.register(self._appserver_output_fd, selectors.EVENT_READ, "out")
        selector.register(self._appserver_stderr_fd, selectors.EVENT_READ, "err")
        try:
            while True:
                if (self._lease_deadline is not None
                        and self._monotonic() >= self._lease_deadline):
                    raise NativeCodexRuntimeError(
                        "native_codex_runtime_lease_expired")
                while True:
                    newline = self._server_buffer.find(b"\n")
                    if newline < 0:
                        break
                    raw = bytes(self._server_buffer[:newline + 1])
                    del self._server_buffer[:newline + 1]
                    try:
                        event = self._firewall.ingest_server_line(raw)
                    except ProtocolViolation as error:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_server_protocol_violation"
                        ) from error
                    if event is not None:
                        self._sanitize_event(event, emit=False)
                events = selector.select(0)
                if not events:
                    if self._server_buffer:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_pre_ready_server_fragment")
                    return
                for key, _mask in events:
                    if key.data == "err":
                        if not self._drain_stderr():
                            raise NativeCodexRuntimeError(
                                "native_codex_runtime_server_stderr_eof")
                        continue
                    try:
                        block = os.read(self._appserver_output_fd, 64 * 1024)
                    except BlockingIOError:
                        continue
                    except OSError as error:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_server_read_failed") from error
                    if not block:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_server_eof")
                    self._server_buffer.extend(block)
                    if len(self._server_buffer) > MAX_BUFFER_BYTES:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_server_frame_oversized")
        finally:
            selector.close()

    def _startup(self) -> None:
        self._exchange_startup(self._firewall.initialize())
        self._exchange_startup(self._firewall.start_thread())
        self._drain_pre_ready_server()
        authority = self._firewall.qualification_authority
        if authority is None:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_firewall_not_ready")
        try:
            attestation = self._qualification_gate(
                self._firewall, self._descriptor)
        except NativeCodexRuntimeError:
            raise
        except Exception as error:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_qualification_rejected") from error
        if (self._lease_deadline is not None
                and self._monotonic() >= self._lease_deadline):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_lease_expired")
        if not isinstance(attestation, str) or SHA256.fullmatch(attestation) is None:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_qualification_invalid")
        self._qualification_attestation_sha256 = attestation
        # The distinct UI stream cannot carry input until typed READY. Any
        # already waiting byte is therefore a protocol violation.
        selector = selectors.DefaultSelector()
        selector.register(self._host_input_fd, selectors.EVENT_READ)
        try:
            if selector.select(0):
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_premature_host_input")
        finally:
            selector.close()
        if (self._lease_deadline is not None
                and self._monotonic() >= self._lease_deadline):
            raise NativeCodexRuntimeError(
                "native_codex_runtime_lease_expired")
        self._emit("ready", {
            "session_id_sha256": hashlib.sha256(
                self._descriptor["session_id"].encode("ascii")).hexdigest(),
            "harness_generation_id": self._descriptor[
                "harness_generation_id"],
            "harness_executable_sha256": self._descriptor[
                "harness_executable_sha256"],
            "model_id": self._descriptor["model_id"],
            "reasoning_effort": self._descriptor["reasoning_effort"],
            "cyber_access_program": CYBER_ACCESS_PROGRAM,
            "qualification_attestation_sha256": attestation,
            "session_lease_sha256": self._session_lease_sha256,
            "session_expires_at": self._session_expires_at,
        })

    def _emit_turn_completion(self) -> None:
        if self._turn_completion_emitted:
            return
        fact = self._firewall.qualified_completion
        if fact is None:
            return
        self._emit("turn_completed", {
            "qualified": True,
            "completion_sha256": digest({
                "thread_id": fact.thread_id,
                "turn_id": fact.turn_id,
                "model": fact.model,
                "launch_descriptor_sha256": fact.launch_descriptor_sha256,
                "cyber_access_program": fact.cyber_access_program,
                "verifications": list(fact.verifications),
            }),
        })
        self._turn_completion_emitted = True
        self._normal_completion_observed = False
        self._verification_deadline = None
        self._qualified_terminal_boundary = True

    def _sanitize_delta(self, event: CodexServerEvent, *, channel: str) -> None:
        text = _safe_text(event.params.get("delta"), maximum=32 * 1024, empty=True)
        encoded = text.encode("utf-8")
        self._turn_text_bytes += len(encoded)
        if self._turn_text_bytes > MAX_TURN_TEXT_BYTES:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_turn_text_limit")
        for released_channel, released_text in self._token_guard.admit(
                channel, encoded):
            self._emit("text_delta", {
                "channel": released_channel, "text": released_text})

    def _sanitize_event(self, event: CodexServerEvent, *, emit: bool = True) -> None:
        method = event.method
        if method == "item/agentMessage/delta":
            if emit:
                self._sanitize_delta(event, channel="assistant")
            return
        if method in {
                "item/commandExecution/outputDelta",
                "item/fileChange/outputDelta",
                "item/plan/delta"}:
            if emit:
                self._sanitize_delta(event, channel="tool")
            return
        if method == "turn/started":
            if emit and not self._turn_started_emitted:
                self._emit("turn_started", {})
                self._turn_started_emitted = True
            return
        if method == "turn/completed":
            status = event.params["turn"].get("status")
            if status == "interrupted":
                if emit:
                    self._emit("turn_interrupted", {})
                self._turn_completion_emitted = True
                self._verification_deadline = None
            else:
                self._normal_completion_observed = True
                self._verification_deadline = (
                    self._monotonic() + VERIFICATION_TIMEOUT_SECONDS)
                if emit:
                    self._emit_turn_completion()
            return
        if method == "model/verification":
            if emit:
                self._emit_turn_completion()
            return
        if method == "remoteControl/status/changed":
            return
        if method in {
                "thread/started", "thread/status/changed",
                "thread/tokenUsage/updated", "turn/diff/updated",
                "turn/plan/updated", "item/started", "item/completed",
                "item/fileChange/patchUpdated",
                "item/reasoning/summaryPartAdded",
                "item/reasoning/summaryTextDelta",
                "item/reasoning/textDelta"}:
            if emit:
                self._emit("activity", {
                    "code": method.replace("/", "_")})
            return
        raise NativeCodexRuntimeError(
            "native_codex_runtime_event_unhandled")

    def _process_server_line(self, raw: bytes) -> None:
        try:
            event = self._firewall.ingest_server_line(raw)
        except ProtocolViolation as error:
            raise NativeCodexRuntimeError(
                "native_codex_runtime_server_protocol_violation") from error
        if event is not None:
            self._sanitize_event(event)
        if self._firewall.turn_id is not None and not self._turn_started_emitted:
            self._emit("turn_started", {})
            self._turn_started_emitted = True
        self._emit_turn_completion()

    def _process_server_buffer(self) -> None:
        while True:
            newline = self._server_buffer.find(b"\n")
            if newline < 0:
                return
            raw = bytes(self._server_buffer[:newline + 1])
            del self._server_buffer[:newline + 1]
            self._process_server_line(raw)

    def _handle_command(self, command: Mapping[str, Any]) -> bool:
        operation = command["operation"]
        self._command_count += 1
        self._command_sequence += 1
        if operation == "turn":
            self._turn_text_bytes = 0
            self._turn_started_emitted = False
            self._turn_completion_emitted = False
            self._normal_completion_observed = False
            self._verification_deadline = None
            self._qualified_terminal_boundary = False
            try:
                request = self._firewall.start_turn(command["payload"]["text"])
            except ProtocolViolation as error:
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_turn_state_invalid") from error
            self._send_server(request)
            return True
        if operation == "interrupt":
            try:
                request = self._firewall.interrupt_turn()
            except ProtocolViolation as error:
                raise NativeCodexRuntimeError(
                    "native_codex_runtime_interrupt_state_invalid") from error
            self._send_server(request)
            return True
        if operation == "close":
            self._release_token_tail = (
                self._firewall.turn_id is None
                and not self._server_buffer
                and self._verification_deadline is None
                and self._qualified_terminal_boundary
            )
            if self._firewall.turn_id is not None:
                try:
                    self._send_server(self._firewall.interrupt_turn())
                except ProtocolViolation:
                    pass
            return False
        raise NativeCodexRuntimeError(
            "native_codex_runtime_command_operation_invalid")

    def _process_host_buffer(self) -> bool:
        while True:
            newline = self._host_buffer.find(b"\n")
            if newline < 0:
                if len(self._host_buffer) > MAX_COMMAND_BYTES:
                    raise NativeCodexRuntimeError(
                        "native_codex_runtime_command_oversized")
                return True
            raw = bytes(self._host_buffer[:newline + 1])
            del self._host_buffer[:newline + 1]
            command = decode_command_line(
                raw, expected_sequence=self._command_sequence,
                runtime_authority_sha256=self._descriptor[
                    "runtime_authority_sha256"])
            if not self._handle_command(command):
                if self._host_buffer:
                    raise NativeCodexRuntimeError(
                        "native_codex_runtime_command_after_close")
                return False

    def _run_loop(self) -> str:
        selector = selectors.DefaultSelector()
        selector.register(self._host_input_fd, selectors.EVENT_READ, "host")
        selector.register(self._appserver_output_fd, selectors.EVENT_READ, "server")
        selector.register(self._appserver_stderr_fd, selectors.EVENT_READ, "stderr")
        try:
            while True:
                self._process_server_buffer()
                if (self._lease_deadline is not None
                        and self._monotonic() >= self._lease_deadline):
                    raise NativeCodexRuntimeError(
                        "native_codex_runtime_lease_expired")
                if (self._verification_deadline is not None
                        and self._monotonic() >= self._verification_deadline):
                    raise NativeCodexRuntimeError(
                        "native_codex_runtime_verification_timeout")
                timeout = POLL_SECONDS
                if self._lease_deadline is not None:
                    timeout = min(
                        timeout,
                        max(0.0, self._lease_deadline - self._monotonic()))
                events = selector.select(timeout)
                # If Host and app-server fail in the same poll, retain the
                # app-server failure rather than misclassifying it as a clean
                # human disconnect.
                events.sort(key=lambda item: {
                    "stderr": 0, "server": 1, "host": 2,
                }[item[0].data])
                for key, _mask in events:
                    if key.data == "stderr":
                        if not self._drain_stderr():
                            selector.unregister(self._appserver_stderr_fd)
                        continue
                    try:
                        block = os.read(key.fd, 64 * 1024)
                    except BlockingIOError:
                        continue
                    except OSError as error:
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_transport_read_failed") from error
                    if not block:
                        if key.data == "host":
                            if self._host_buffer:
                                raise NativeCodexRuntimeError(
                                    "native_codex_runtime_command_truncated")
                            if self._firewall.turn_id is not None:
                                try:
                                    self._send_server(
                                        self._firewall.interrupt_turn())
                                except ProtocolViolation:
                                    pass
                            return "host_eof"
                        raise NativeCodexRuntimeError(
                            "native_codex_runtime_server_eof")
                    if key.data == "host":
                        self._host_buffer.extend(block)
                        if not self._process_host_buffer():
                            return "operator_close"
                    else:
                        self._server_buffer.extend(block)
                        if len(self._server_buffer) > MAX_BUFFER_BYTES:
                            raise NativeCodexRuntimeError(
                                "native_codex_runtime_server_frame_oversized")
                        self._process_server_buffer()
        finally:
            selector.close()

    def run(self) -> RuntimeDriverResult:
        """Run until explicit close or Host EOF; failures never reflect input."""
        for descriptor in (
            self._host_input_fd, self._host_output_fd,
            self._appserver_input_fd, self._appserver_output_fd,
            self._appserver_stderr_fd,
        ):
            os.set_blocking(descriptor, False)
        try:
            self._startup()
            reason = self._run_loop()
            if reason == "operator_close" and self._release_token_tail:
                for channel, text in self._token_guard.finish():
                    self._emit("text_delta", {
                        "channel": channel, "text": text})
            else:
                self._token_guard.discard()
            if reason != "host_eof":
                self._emit("closed", {"reason": reason})
            assert self._qualification_attestation_sha256 is not None
            return RuntimeDriverResult(
                reason=reason,
                event_count=self._event_count,
                command_count=self._command_count,
                stderr_bytes=self._stderr_bytes,
                stderr_sha256=self._stderr_hasher.hexdigest(),
                qualification_attestation_sha256=(
                    self._qualification_attestation_sha256),
                session_lease_sha256=self._session_lease_sha256,
                session_expires_at=self._session_expires_at,
            )
        finally:
            # Failure, timeout, EOF, and unqualified-close paths must never
            # make quarantined bytes observable.
            self._token_guard.discard()


__all__ = [
    "COMMAND_SCHEMA",
    "EVENT_SCHEMA",
    "MAX_COMMAND_BYTES",
    "MAX_EVENT_BYTES",
    "MAX_TOKEN_BYTES",
    "NativeCodexRuntimeDriver",
    "NativeCodexRuntimeError",
    "ProjectionTokenReceipt",
    "RuntimeDriverResult",
    "canonical_bytes",
    "decode_command_line",
    "digest",
    "make_command",
    "make_token_receipt_bytes",
    "read_token_receipt",
    "token_rolling_fingerprint",
    "validate_token_receipt",
    "validate_command",
]
