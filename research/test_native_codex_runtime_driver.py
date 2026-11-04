#!/usr/bin/env python3
"""Hostile transport tests for the first-party Codex runtime driver."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import threading
import time
import unittest
from dataclasses import dataclass
from typing import Callable

from research import native_codex_runtime_driver as runtime
from research.test_native_codex_protocol_firewall import (
    THREAD_ID,
    TURN_ID,
    initialize_result,
    launch_descriptor,
    thread_result,
    turn,
    wire,
)


QUALIFICATION_SHA256 = "9" * 64
SESSION_LEASE_SHA256 = "7" * 64
SESSION_EXPIRES_AT = 2_000_000_000
PROJECTION_ID = "12345678-1234-4234-8234-123456789abc"
PERMIT_SHA256 = "8" * 64
PROJECTED_TOKEN = b"marker-free-project-token-0123456789-ABCDEFGHIJKLMN"
PROJECTED_TOKEN_SHA256 = hashlib.sha256(PROJECTED_TOKEN).hexdigest()
BENIGN_DELTA = "bounded response " * 6


def token_receipt(
    *,
    projection_id: str = PROJECTION_ID,
    permit_sha256: str = PERMIT_SHA256,
    access_token_sha256: str = PROJECTED_TOKEN_SHA256,
    token_length: int = len(PROJECTED_TOKEN),
    rolling_fingerprint: int | None = None,
) -> bytes:
    fingerprint = (runtime.token_rolling_fingerprint(PROJECTED_TOKEN)
                   if rolling_fingerprint is None else rolling_fingerprint)
    return runtime.make_token_receipt_bytes(runtime.ProjectionTokenReceipt(
        projection_id=projection_id,
        session_id="11111111-1111-4111-8111-111111111111",
        runtime_authority_sha256="1" * 64,
        permit_sha256=permit_sha256,
        access_token_sha256=access_token_sha256,
        token_length=token_length,
        rolling_fingerprint=fingerprint,
    ))


def recv_line(endpoint: socket.socket, timeout: float = 2.0) -> bytes:
    endpoint.settimeout(timeout)
    value = bytearray()
    while True:
        block = endpoint.recv(1)
        if not block:
            if value:
                raise AssertionError("truncated line")
            return b""
        value.extend(block)
        if block == b"\n":
            return bytes(value)


def send_line(endpoint: socket.socket, value: object) -> None:
    endpoint.sendall(runtime.canonical_bytes(value))


def event(endpoint: socket.socket) -> dict:
    raw = recv_line(endpoint)
    if not raw:
        raise AssertionError("event stream closed")
    value = json.loads(raw)
    assert isinstance(value, dict)
    assert set(value) == {
        "schema", "sequence", "runtime_authority_sha256",
        "session_lease_sha256", "event", "payload", "event_sha256",
    }
    body = {name: value[name] for name in value if name != "event_sha256"}
    assert value["event_sha256"] == runtime.digest(body)
    return value


@dataclass
class DriverFixture:
    driver: runtime.NativeCodexRuntimeDriver
    host: socket.socket
    app_input: socket.socket
    app_output: socket.socket
    app_stderr: socket.socket
    owned: list[socket.socket]

    def close(self) -> None:
        for endpoint in self.owned:
            try:
                endpoint.close()
            except OSError:
                pass


def driver_fixture(
    *,
    gate: Callable | None = None,
    lease_deadline_monotonic: float | None = None,
    model: str = "gpt-6-sol",
) -> DriverFixture:
    host_driver, host_client = socket.socketpair()
    input_driver, input_server = socket.socketpair()
    output_driver, output_server = socket.socketpair()
    stderr_driver, stderr_server = socket.socketpair()
    qualification = gate or (lambda _firewall, _descriptor: QUALIFICATION_SHA256)
    driver = runtime.NativeCodexRuntimeDriver(
        launch_descriptor=launch_descriptor(model=model),
        host_input_fd=host_driver.fileno(),
        host_output_fd=host_driver.fileno(),
        appserver_input_fd=input_driver.fileno(),
        appserver_output_fd=output_driver.fileno(),
        appserver_stderr_fd=stderr_driver.fileno(),
        token_receipt=token_receipt(),
        expected_projection_id=PROJECTION_ID,
        expected_permit_sha256=PERMIT_SHA256,
        expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
        session_lease_sha256=SESSION_LEASE_SHA256,
        session_expires_at=SESSION_EXPIRES_AT,
        qualification_gate=qualification,
        lease_deadline_monotonic=lease_deadline_monotonic,
    )
    return DriverFixture(
        driver=driver,
        host=host_client,
        app_input=input_server,
        app_output=output_server,
        app_stderr=stderr_server,
        owned=[host_driver, host_client, input_driver, input_server,
               output_driver, output_server, stderr_driver, stderr_server],
    )


def startup_server(fixture: DriverFixture) -> None:
    initialize = json.loads(recv_line(fixture.app_input))
    assert initialize["method"] == "initialize"
    send_line(fixture.app_output, {
        "id": initialize["id"], "result": initialize_result()})
    start = json.loads(recv_line(fixture.app_input))
    assert start["method"] == "thread/start"
    send_line(fixture.app_output, {
        "id": start["id"], "result": thread_result()})


def normal_turn_server(
    fixture: DriverFixture,
    *,
    delta: str = BENIGN_DELTA,
    extra: Callable[[DriverFixture], None] | None = None,
) -> None:
    startup_server(fixture)
    request = json.loads(recv_line(fixture.app_input))
    assert request["method"] == "turn/start"
    assert request["params"]["cyberAccessProgram"] == "daybreakBlue"
    send_line(fixture.app_output, {
        "id": request["id"], "result": {"turn": turn()}})
    send_line(fixture.app_output, {
        "method": "item/agentMessage/delta",
        "params": {
            "delta": delta,
            "itemId": "item-1",
            "threadId": THREAD_ID,
            "turnId": TURN_ID,
        },
    })
    if extra is not None:
        extra(fixture)
    send_line(fixture.app_output, {
        "method": "model/verification",
        "params": {
            "threadId": THREAD_ID,
            "turnId": TURN_ID,
            "verifications": ["trustedAccessForCyber"],
        },
    })
    send_line(fixture.app_output, {
        "method": "turn/completed",
        "params": {
            "threadId": THREAD_ID,
            "turn": turn(status="completed"),
        },
    })


class NativeCodexRuntimeDriverTests(unittest.TestCase):
    def run_driver(self, fixture: DriverFixture):
        result: dict[str, object] = {}

        def target() -> None:
            try:
                result["value"] = fixture.driver.run()
            except BaseException as error:
                result["error"] = error

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread, result

    def test_happy_path_is_fixed_sanitized_and_daybreak_qualified(self) -> None:
        fixture = driver_fixture()
        try:
            server = threading.Thread(
                target=normal_turn_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            ready = event(fixture.host)
            self.assertEqual(ready["event"], "ready")
            self.assertEqual(ready["payload"], {
                "cyber_access_program": "daybreakBlue",
                "harness_executable_sha256": "5" * 64,
                "harness_generation_id": "4" * 64,
                "model_id": "gpt-6-sol",
                "qualification_attestation_sha256": QUALIFICATION_SHA256,
                "reasoning_effort": "high",
                "session_lease_sha256": SESSION_LEASE_SHA256,
                "session_expires_at": SESSION_EXPIRES_AT,
                "session_id_sha256": (
                    "bd7662a5eeb41614e720d477abfcb2272e19a8a70a93b7e3b"
                    "c8560d44ad326e9"),
            })
            command = runtime.make_command(
                sequence=1,
                runtime_authority_sha256="1" * 64,
                operation="turn",
                text="inspect the workspace",
            )
            send_line(fixture.host, command)
            observed: list[dict] = []
            while not any(item["event"] == "turn_completed" for item in observed):
                observed.append(event(fixture.host))
            self.assertEqual(
                [item["event"] for item in observed],
                ["turn_started", "text_delta", "turn_completed"])
            self.assertEqual(observed[1]["payload"], {
                "channel": "assistant",
                "text": BENIGN_DELTA[:-(len(PROJECTED_TOKEN) - 1)]})
            self.assertTrue(observed[2]["payload"]["qualified"])
            send_line(fixture.host, runtime.make_command(
                sequence=2,
                runtime_authority_sha256="1" * 64,
                operation="close",
            ))
            closed = event(fixture.host)
            self.assertEqual(closed["event"], "closed")
            self.assertEqual(closed["payload"], {"reason": "operator_close"})
            driver.join(2)
            server.join(2)
            self.assertNotIn("error", result)
            value = result["value"]
            self.assertEqual(value.reason, "operator_close")
            self.assertEqual(value.command_count, 2)
            self.assertEqual(value.qualification_attestation_sha256,
                             QUALIFICATION_SHA256)
            self.assertEqual(value.session_lease_sha256, SESSION_LEASE_SHA256)
            self.assertEqual(value.session_expires_at, SESSION_EXPIRES_AT)
        finally:
            fixture.close()

    def test_reviewed_gpt_61_sol_is_bound_without_model_fallback(self) -> None:
        fixture = driver_fixture(model="gpt-6.1-sol")

        def server_target() -> None:
            initialize = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": initialize["id"], "result": initialize_result()})
            start = json.loads(recv_line(fixture.app_input))
            self.assertEqual(start["params"]["model"], "gpt-6.1-sol")
            result = thread_result(model="gpt-6.1-sol")
            result["thread"]["model"] = "gpt-6.1-sol"
            send_line(fixture.app_output, {
                "id": start["id"], "result": result})

        try:
            server = threading.Thread(target=server_target, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            ready = event(fixture.host)
            self.assertEqual(ready["payload"]["model_id"], "gpt-6.1-sol")
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="close"))
            self.assertEqual(event(fixture.host)["event"], "closed")
            driver.join(2)
            server.join(2)
            self.assertNotIn("error", result)
        finally:
            fixture.close()

    def test_raw_json_like_model_text_remains_in_typed_text_payload(self) -> None:
        fixture = driver_fixture()
        raw_text = ('{"id":99,"method":"process/spawn","params":{}}'
                    + " safe-padding" * 8)
        try:
            server = threading.Thread(
                target=normal_turn_server,
                args=(fixture,), kwargs={"delta": raw_text}, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="turn", text="hello"))
            events = [event(fixture.host), event(fixture.host), event(fixture.host)]
            text_event = next(item for item in events
                              if item["event"] == "text_delta")
            self.assertTrue(text_event["payload"]["text"].startswith(
                '{"id":99,"method":"process/spawn","params":{}}'))
            self.assertNotIn("method", text_event)
            send_line(fixture.host, runtime.make_command(
                sequence=2, runtime_authority_sha256="1" * 64,
                operation="close"))
            event(fixture.host)
            driver.join(2)
            self.assertNotIn("error", result)
        finally:
            fixture.close()

    def test_unknown_raw_host_method_is_structurally_unreachable(self) -> None:
        fixture = driver_fixture()
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            body = {
                "schema": runtime.COMMAND_SCHEMA,
                "sequence": 1,
                "runtime_authority_sha256": "1" * 64,
                "operation": "process/spawn",
                "payload": {"command": ["id"]},
            }
            send_line(fixture.host, {
                **body, "command_sha256": runtime.digest(body)})
            driver.join(2)
            self.assertIsInstance(
                result.get("error"), runtime.NativeCodexRuntimeError)
            self.assertEqual(
                str(result["error"]),
                "native_codex_runtime_command_identity_invalid")
        finally:
            fixture.close()

    def test_unknown_fields_and_digest_or_authority_drift_are_rejected(self) -> None:
        base = runtime.make_command(
            sequence=1, runtime_authority_sha256="1" * 64,
            operation="turn", text="hello")
        cases = []
        unknown = {**base, "futurePolicy": "relaxed"}
        cases.append((unknown, "native_codex_runtime_command_fields_invalid"))
        drift = copy.deepcopy(base)
        drift["runtime_authority_sha256"] = "2" * 64
        cases.append((drift, "native_codex_runtime_command_identity_invalid"))
        tampered = copy.deepcopy(base)
        tampered["payload"]["text"] = "different"
        cases.append((tampered, "native_codex_runtime_command_digest_mismatch"))
        for value, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(runtime.NativeCodexRuntimeError) as captured:
                    runtime.decode_command_line(
                        runtime.canonical_bytes(value), expected_sequence=1,
                        runtime_authority_sha256="1" * 64)
                self.assertEqual(str(captured.exception), code)

    def test_ansi_control_and_credential_markers_never_reach_host(self) -> None:
        for delta, expected in (
            ("\x1b[31mred", "native_codex_runtime_text_invalid"),
            ("ACCESS_TOKEN=not-a-real-token",
             "native_codex_runtime_credential_text_forbidden"),
        ):
            with self.subTest(delta=delta):
                fixture = driver_fixture()
                try:
                    server = threading.Thread(
                        target=normal_turn_server,
                        args=(fixture,), kwargs={"delta": delta}, daemon=True)
                    driver, result = self.run_driver(fixture)
                    server.start()
                    event(fixture.host)
                    send_line(fixture.host, runtime.make_command(
                        sequence=1, runtime_authority_sha256="1" * 64,
                        operation="turn", text="hello"))
                    # turn_started is safe; the hostile delta terminates before
                    # any reflected text event is emitted.
                    self.assertEqual(event(fixture.host)["event"], "turn_started")
                    driver.join(2)
                    self.assertIsInstance(
                        result.get("error"), runtime.NativeCodexRuntimeError)
                    self.assertEqual(str(result["error"]), expected)
                finally:
                    fixture.close()

    def test_marker_free_projected_token_echo_is_blocked(self) -> None:
        fixture = driver_fixture()
        try:
            server = threading.Thread(
                target=normal_turn_server, args=(fixture,),
                kwargs={"delta": PROJECTED_TOKEN.decode("ascii")}, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="turn", text="hello"))
            self.assertEqual(event(fixture.host)["event"], "turn_started")
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_projected_token_reflected")
        finally:
            fixture.close()

    def test_projected_token_split_across_deltas_is_blocked(self) -> None:
        fixture = driver_fixture()
        split = len(PROJECTED_TOKEN) // 2

        def split_server() -> None:
            startup_server(fixture)
            request = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": request["id"], "result": {"turn": turn()}})
            for item_id, delta in enumerate((
                    PROJECTED_TOKEN[:split], PROJECTED_TOKEN[split:]), start=1):
                send_line(fixture.app_output, {
                    "method": "item/agentMessage/delta",
                    "params": {
                        "delta": delta.decode("ascii"),
                        "itemId": f"item-{item_id}",
                        "threadId": THREAD_ID,
                        "turnId": TURN_ID,
                    },
                })

        try:
            server = threading.Thread(target=split_server, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="turn", text="hello"))
            self.assertEqual(event(fixture.host)["event"], "turn_started")
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_projected_token_reflected")
        finally:
            fixture.close()

    def test_projected_token_split_across_channels_and_turns_emits_zero_bytes(self) -> None:
        fixture = driver_fixture()
        split = len(PROJECTED_TOKEN) // 2
        second_turn = "turn-0000000000000002"

        def two_turn_server() -> None:
            startup_server(fixture)
            for index, (turn_id, method, fragment) in enumerate((
                (TURN_ID, "item/agentMessage/delta", PROJECTED_TOKEN[:split]),
                (second_turn, "item/commandExecution/outputDelta",
                 PROJECTED_TOKEN[split:]),
            ), start=1):
                request = json.loads(recv_line(fixture.app_input))
                send_line(fixture.app_output, {
                    "id": request["id"],
                    "result": {"turn": turn(turn_id=turn_id)}})
                send_line(fixture.app_output, {
                    "method": method,
                    "params": {
                        "delta": fragment.decode("ascii"),
                        "itemId": f"item-{index}",
                        "threadId": THREAD_ID,
                        "turnId": turn_id,
                    },
                })
                if index == 1:
                    send_line(fixture.app_output, {
                        "method": "model/verification",
                        "params": {
                            "threadId": THREAD_ID, "turnId": turn_id,
                            "verifications": ["trustedAccessForCyber"],
                        },
                    })
                    send_line(fixture.app_output, {
                        "method": "turn/completed",
                        "params": {
                            "threadId": THREAD_ID,
                            "turn": turn(turn_id=turn_id, status="completed"),
                        },
                    })

        try:
            server = threading.Thread(target=two_turn_server, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="turn", text="first"))
            first_events = [event(fixture.host), event(fixture.host)]
            self.assertEqual(
                [item["event"] for item in first_events],
                ["turn_started", "turn_completed"])
            self.assertNotIn(
                PROJECTED_TOKEN[:split].decode("ascii"),
                json.dumps(first_events))
            send_line(fixture.host, runtime.make_command(
                sequence=2, runtime_authority_sha256="1" * 64,
                operation="turn", text="second"))
            second_started = event(fixture.host)
            self.assertEqual(second_started["event"], "turn_started")
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_projected_token_reflected")
            self.assertNotIn(
                PROJECTED_TOKEN.decode("ascii"), json.dumps(second_started))
        finally:
            fixture.close()

    def test_token_receipt_digest_identity_length_and_eof_are_exact(self) -> None:
        descriptor = launch_descriptor()
        accepted = runtime.validate_token_receipt(
            token_receipt(), launch_descriptor=descriptor,
            expected_projection_id=PROJECTION_ID,
            expected_permit_sha256=PERMIT_SHA256,
            expected_access_token_sha256=PROJECTED_TOKEN_SHA256)
        self.assertEqual(accepted.token_length, len(PROJECTED_TOKEN))
        self.assertEqual(
            accepted.rolling_fingerprint,
            runtime.token_rolling_fingerprint(PROJECTED_TOKEN))
        for offset in (208, 275, len(token_receipt()) - 1):
            with self.subTest(offset=offset):
                changed = bytearray(token_receipt())
                changed[offset] ^= 1
                with self.assertRaises(runtime.NativeCodexRuntimeError):
                    runtime.validate_token_receipt(
                        bytes(changed), launch_descriptor=descriptor,
                        expected_projection_id=PROJECTION_ID,
                        expected_permit_sha256=PERMIT_SHA256,
                        expected_access_token_sha256=PROJECTED_TOKEN_SHA256)
        with self.assertRaisesRegex(
                runtime.NativeCodexRuntimeError, "identity_mismatch"):
            runtime.validate_token_receipt(
                token_receipt(permit_sha256="7" * 64),
                launch_descriptor=descriptor,
                expected_projection_id=PROJECTION_ID,
                expected_permit_sha256=PERMIT_SHA256,
                expected_access_token_sha256=PROJECTED_TOKEN_SHA256)

        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, token_receipt())
            with self.assertRaisesRegex(
                    runtime.NativeCodexRuntimeError, "receipt_timeout"):
                runtime.read_token_receipt(read_fd, timeout_seconds=0.01)
        finally:
            os.close(write_fd)
            os.close(read_fd)
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, token_receipt())
            os.close(write_fd)
            write_fd = -1
            self.assertEqual(
                runtime.read_token_receipt(read_fd), token_receipt())
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)

    def test_quarantine_is_global_and_rolling_collision_needs_sha_match(self) -> None:
        receipt = runtime.validate_token_receipt(
            token_receipt(), launch_descriptor=launch_descriptor(),
            expected_projection_id=PROJECTION_ID,
            expected_permit_sha256=PERMIT_SHA256,
            expected_access_token_sha256=PROJECTED_TOKEN_SHA256)
        guard = runtime._TokenExfiltrationGuard(receipt)
        split = len(PROJECTED_TOKEN) // 2
        self.assertEqual(
            guard.admit("assistant", PROJECTED_TOKEN[:split]), [])
        with self.assertRaisesRegex(
                runtime.NativeCodexRuntimeError, "projected_token_reflected"):
            # A different channel models a tool delta or a later turn. The
            # first fragment remains quarantined and no token byte was emitted.
            guard.admit("tool", PROJECTED_TOKEN[split:])

        near_match = b"z" * len(PROJECTED_TOKEN)
        collision_receipt = runtime.validate_token_receipt(
            token_receipt(rolling_fingerprint=
                          runtime.token_rolling_fingerprint(near_match)),
            launch_descriptor=launch_descriptor(),
            expected_projection_id=PROJECTION_ID,
            expected_permit_sha256=PERMIT_SHA256,
            expected_access_token_sha256=PROJECTED_TOKEN_SHA256)
        guard = runtime._TokenExfiltrationGuard(collision_receipt)
        released = guard.admit("assistant", near_match)
        self.assertEqual(sum(len(text) for _channel, text in released), 1)
        total = len(near_match)
        for _ in range(8):
            block = b"benign-output-" * 4096
            total += len(block)
            released.extend(guard.admit("assistant", block))
        self.assertEqual(
            sum(len(text.encode("utf-8")) for _channel, text in released),
            total - (len(PROJECTED_TOKEN) - 1))

    def test_unknown_server_method_and_server_requests_fail_closed(self) -> None:
        messages = (
            {"method": "unknown/futureEscape", "params": {}},
            {"id": "server-1", "method": "process/spawn", "params": {}},
        )
        for message in messages:
            with self.subTest(message=message):
                fixture = driver_fixture()

                def hostile_server() -> None:
                    startup_server(fixture)
                    recv_line(fixture.app_input)
                    send_line(fixture.app_output, message)

                try:
                    server = threading.Thread(target=hostile_server, daemon=True)
                    driver, result = self.run_driver(fixture)
                    server.start()
                    event(fixture.host)
                    send_line(fixture.host, runtime.make_command(
                        sequence=1, runtime_authority_sha256="1" * 64,
                        operation="turn", text="hello"))
                    driver.join(2)
                    self.assertIsInstance(
                        result.get("error"), runtime.NativeCodexRuntimeError)
                    self.assertEqual(
                        str(result["error"]),
                        "native_codex_runtime_server_protocol_violation")
                finally:
                    fixture.close()

    def test_stderr_is_hashed_bounded_and_never_forwarded(self) -> None:
        fixture = driver_fixture()

        def with_stderr(value: DriverFixture) -> None:
            value.app_stderr.sendall(b"private provider diagnostic\n")

        try:
            server = threading.Thread(
                target=normal_turn_server,
                args=(fixture,), kwargs={"extra": with_stderr}, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            ready = event(fixture.host)
            self.assertNotIn("stderr", json.dumps(ready))
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="turn", text="hello"))
            observed = []
            while not any(item["event"] == "turn_completed" for item in observed):
                observed.append(event(fixture.host))
            self.assertNotIn(
                "private provider diagnostic", json.dumps(observed))
            send_line(fixture.host, runtime.make_command(
                sequence=2, runtime_authority_sha256="1" * 64,
                operation="close"))
            event(fixture.host)
            driver.join(2)
            value = result["value"]
            self.assertEqual(value.stderr_bytes, 28)
            self.assertNotEqual(value.stderr_sha256, "0" * 64)
        finally:
            fixture.close()

    def test_qualification_failure_and_premature_human_bytes_prevent_ready(self) -> None:
        def rejected(_firewall, _descriptor):
            raise RuntimeError("unqualified")

        fixture = driver_fixture(gate=rejected)
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertIsInstance(
                result.get("error"), runtime.NativeCodexRuntimeError)
            self.assertEqual(
                str(result["error"]),
                "native_codex_runtime_qualification_rejected")
            fixture.host.settimeout(0.1)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

    def test_buffered_pre_ready_server_escape_is_rejected_before_ready(self) -> None:
        fixture = driver_fixture()

        def hostile_server() -> None:
            initialize = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": initialize["id"], "result": initialize_result()})
            start = json.loads(recv_line(fixture.app_input))
            combined = (
                runtime.canonical_bytes({
                    "id": start["id"], "result": thread_result()})
                + runtime.canonical_bytes({
                    "method": "process/spawn", "params": {}}))
            fixture.app_output.sendall(combined)

        try:
            server = threading.Thread(target=hostile_server, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_server_protocol_violation")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

    def test_partial_host_frame_at_eof_is_not_clean_disconnect(self) -> None:
        fixture = driver_fixture()
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            fixture.host.sendall(b'{"schema":"truncated"')
            fixture.host.shutdown(socket.SHUT_WR)
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_command_truncated")
        finally:
            fixture.close()

        def unavailable(_firewall, _descriptor):
            raise runtime.NativeCodexRuntimeError(
                "native_codex_runtime_live_qualification_unavailable")

        fixture = driver_fixture(gate=unavailable)
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_live_qualification_unavailable")
        finally:
            fixture.close()

        fixture = driver_fixture()
        try:
            # This byte is deliberately not a valid command; its mere presence
            # before the Research ready event is enough to fail the boundary.
            fixture.host.sendall(b"premature")
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_premature_host_input")
        finally:
            fixture.close()

    def test_host_eof_is_terminal_without_writing_to_closed_peer(self) -> None:
        fixture = driver_fixture()
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            fixture.host.close()
            driver.join(2)
            self.assertNotIn("error", result)
            self.assertEqual(result["value"].reason, "host_eof")
        finally:
            fixture.close()

    def test_runtime_lease_expiry_is_fail_closed(self) -> None:
        fixture = driver_fixture(
            lease_deadline_monotonic=time.monotonic() + 0.2)
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_lease_expired")
        finally:
            fixture.close()

    def test_interrupt_is_the_only_runtime_cancellation_request(self) -> None:
        fixture = driver_fixture()

        def interrupt_server() -> None:
            startup_server(fixture)
            turn_request = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": turn_request["id"], "result": {"turn": turn()}})
            interrupt = json.loads(recv_line(fixture.app_input))
            assert interrupt == {
                "id": 4,
                "method": "turn/interrupt",
                "params": {"threadId": THREAD_ID, "turnId": TURN_ID},
            }
            send_line(fixture.app_output, {
                "method": "turn/completed",
                "params": {
                    "threadId": THREAD_ID,
                    "turn": turn(status="interrupted"),
                },
            })
            send_line(fixture.app_output, {"id": 4, "result": {}})

        try:
            server = threading.Thread(target=interrupt_server, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="turn", text="hello"))
            self.assertEqual(event(fixture.host)["event"], "turn_started")
            send_line(fixture.host, runtime.make_command(
                sequence=2, runtime_authority_sha256="1" * 64,
                operation="interrupt"))
            self.assertEqual(event(fixture.host)["event"], "turn_interrupted")
            send_line(fixture.host, runtime.make_command(
                sequence=3, runtime_authority_sha256="1" * 64,
                operation="close"))
            self.assertEqual(event(fixture.host)["event"], "closed")
            driver.join(2)
            self.assertNotIn("error", result)
        finally:
            fixture.close()

    def test_stderr_limit_fails_closed_without_reflection(self) -> None:
        fixture = driver_fixture()

        def noisy_server() -> None:
            startup_server(fixture)
            fixture.app_stderr.sendall(
                b"x" * (runtime.MAX_SERVER_STDERR_BYTES + 1))

        try:
            server = threading.Thread(target=noisy_server, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertEqual(
                str(result.get("error")), "native_codex_runtime_stderr_limit")
            fixture.host.settimeout(0.05)
            observed = bytearray()
            while True:
                try:
                    observed.extend(fixture.host.recv(4096))
                except (TimeoutError, socket.timeout):
                    break
            self.assertNotIn(b"x" * 32, observed)
            self.assertNotIn(b"stderr", observed)
        finally:
            fixture.close()

    def test_appserver_eof_is_a_crash_not_clean_completion(self) -> None:
        fixture = driver_fixture()
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            event(fixture.host)
            fixture.app_output.close()
            driver.join(2)
            self.assertEqual(
                str(result.get("error")), "native_codex_runtime_server_eof")
        finally:
            fixture.close()

    def test_appserver_fds_cannot_alias_host_or_each_other(self) -> None:
        host_driver, host_client = socket.socketpair()
        app_driver, app_server = socket.socketpair()
        err_driver, err_server = socket.socketpair()
        endpoints = [host_driver, host_client, app_driver, app_server,
                     err_driver, err_server]
        try:
            with self.assertRaises(runtime.NativeCodexRuntimeError) as captured:
                runtime.NativeCodexRuntimeDriver(
                    launch_descriptor=launch_descriptor(),
                    host_input_fd=host_driver.fileno(),
                    host_output_fd=host_driver.fileno(),
                    appserver_input_fd=app_driver.fileno(),
                    appserver_output_fd=app_driver.fileno(),
                    appserver_stderr_fd=err_driver.fileno(),
                    token_receipt=token_receipt(),
                    expected_projection_id=PROJECTION_ID,
                    expected_permit_sha256=PERMIT_SHA256,
                    expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
                    session_lease_sha256=SESSION_LEASE_SHA256,
                    session_expires_at=SESSION_EXPIRES_AT,
                    qualification_gate=lambda _firewall, _descriptor: "9" * 64,
                )
            self.assertEqual(
                str(captured.exception),
                "native_codex_runtime_descriptor_alias_invalid")
        finally:
            for endpoint in endpoints:
                endpoint.close()


if __name__ == "__main__":
    unittest.main()
