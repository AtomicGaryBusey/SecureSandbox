#!/usr/bin/env python3
"""Hostile transport tests for the first-party Codex runtime driver."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import socket
import threading
import time
import unittest
from dataclasses import dataclass
from typing import Callable
from unittest import mock

from research import native_codex_runtime_driver as runtime
from research import native_codex_isolation_qualification as isolation
from research.test_native_codex_isolation_qualification import (
    POLICY_SHA,
    PROBE_SHA,
    challenge_fixture,
    root_observation,
    tool_observation,
)
from research.test_native_codex_protocol_firewall import (
    THREAD_ID,
    TURN_ID,
    initialize_result,
    launch_descriptor,
    thread_result,
    turn,
    wire,
)


SESSION_LEASE_SHA256 = "7" * 64
SESSION_EXPIRES_AT = 2_000_000_000
PROJECTION_ID = "12345678-1234-4234-8234-123456789abc"
PERMIT_SHA256 = "8" * 64
PROJECTED_TOKEN = b"marker-free-project-token-0123456789-ABCDEFGHIJKLMN"
PROJECTED_TOKEN_SHA256 = hashlib.sha256(PROJECTED_TOKEN).hexdigest()
PROCESS_ID = 4242
PROCESS_START_TIME_TICKS = 19
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
    codex_home_sha256, environment_proof_sha256 = (
        runtime.expected_environment_proof(
            launch_descriptor(), access_token_sha256))
    return runtime.make_token_receipt_bytes(runtime.ProjectionTokenReceipt(
        projection_id=projection_id,
        session_id="11111111-1111-4111-8111-111111111111",
        runtime_authority_sha256="1" * 64,
        permit_sha256=permit_sha256,
        access_token_sha256=access_token_sha256,
        token_length=token_length,
        rolling_fingerprint=fingerprint,
        process_id=PROCESS_ID,
        process_start_time_ticks=PROCESS_START_TIME_TICKS,
        codex_home_sha256=codex_home_sha256,
        environment_proof_sha256=environment_proof_sha256,
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
    quiescer: Callable | None = None,
    lease_deadline_monotonic: float | None = None,
    model: str = "gpt-6-sol",
    monotonic: Callable[[], float] = time.monotonic,
) -> DriverFixture:
    host_driver, host_client = socket.socketpair()
    input_driver, input_server = socket.socketpair()
    output_driver, output_server = socket.socketpair()
    stderr_driver, stderr_server = socket.socketpair()
    def qualified(firewall, descriptor, exchange, launcher_receipt):
        _fixture_firewall, challenge = challenge_fixture(
            launcher_receipt_sha256=launcher_receipt["receipt_sha256"],
            environment_proof_sha256=launcher_receipt[
                "environment_proof_sha256"],
            codex_home_sha256=launcher_receipt["codex_home_sha256"],
            token_sha256=launcher_receipt["access_token_sha256"],
            descriptor_value=dict(descriptor),
        )
        root, tool = exchange(
            challenge, lambda: root_observation(challenge))
        return isolation.evaluate_qualification(
            firewall, descriptor, challenge=challenge,
            root_observation=root, tool_observation=tool,
            policy_manifest_sha256=POLICY_SHA,
            probe_executable_sha256=PROBE_SHA,
            observed_at_unix=1_800_000_000, marker_absent=True)

    qualification = gate or qualified
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
        expected_process_id=PROCESS_ID,
        expected_process_start_time_ticks=PROCESS_START_TIME_TICKS,
        session_lease_sha256=SESSION_LEASE_SHA256,
        session_expires_at=SESSION_EXPIRES_AT,
        qualification_gate=qualification,
        qualification_quiescer=(quiescer or (
            lambda: runtime.QualificationQuiescence(
                resume=lambda _deadline: None, abandon=lambda: None))),
        lease_deadline_monotonic=lease_deadline_monotonic,
        monotonic=monotonic,
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

    try:
        qualification_server_exchange(fixture)
    except TimeoutError:
        # Some rejection tests intentionally fail before the private request.
        return


def qualification_server_exchange(fixture: DriverFixture) -> None:
    request = json.loads(recv_line(fixture.app_input))
    assert request["method"] == "command/exec"
    challenge = isolation.decode_probe_challenge(
        request["params"]["command"][2])
    observation = tool_observation(challenge)
    stdout = (
        challenge["raw_escape_payload"] + "\n"
        + isolation.canonical_bytes(observation).decode("ascii"))
    send_line(fixture.app_output, {
        "id": request["id"],
        "result": {"exitCode": 0, "stderr": "", "stdout": stdout},
    })


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
            attestation = ready["payload"][
                "qualification_attestation_sha256"]
            self.assertRegex(attestation, r"[0-9a-f]{64}")
            self.assertEqual(ready["payload"], {
                "cyber_access_program": "daybreakBlue",
                "harness_executable_sha256": "5" * 64,
                "harness_generation_id": "4" * 64,
                "model_id": "gpt-6-sol",
                "qualification_attestation_sha256": attestation,
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
            tail = event(fixture.host)
            self.assertEqual(tail["event"], "text_delta")
            self.assertEqual(tail["payload"], {
                "channel": "assistant",
                "text": BENIGN_DELTA[-(len(PROJECTED_TOKEN) - 1):],
            })
            self.assertEqual(
                observed[1]["payload"]["text"] + tail["payload"]["text"],
                BENIGN_DELTA)
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
                             attestation)
            self.assertEqual(value.session_lease_sha256, SESSION_LEASE_SHA256)
            self.assertEqual(value.session_expires_at, SESSION_EXPIRES_AT)
        finally:
            fixture.close()

    def test_receipt_from_process_a_is_rejected_for_process_b(self) -> None:
        with self.assertRaises(runtime.NativeCodexRuntimeError) as captured:
            runtime.validate_token_receipt(
                token_receipt(), launch_descriptor=launch_descriptor(),
                expected_projection_id=PROJECTION_ID,
                expected_permit_sha256=PERMIT_SHA256,
                expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
                expected_process_id=PROCESS_ID + 1,
                expected_process_start_time_ticks=PROCESS_START_TIME_TICKS)
        self.assertEqual(
            str(captured.exception),
            "native_codex_runtime_token_receipt_process_mismatch")

    def test_ready_is_written_only_while_exact_process_is_quiesced(self) -> None:
        state = {"frozen": False, "resumed": 0, "abandoned": 0}

        def quiesce():
            state["frozen"] = True

            def resume(deadline):
                self.assertEqual(
                    deadline, fixture.driver._qualification_deadline)
                state["resumed"] += 1
                state["frozen"] = False

            def abandon():
                state["abandoned"] += 1

            return runtime.QualificationQuiescence(
                resume=resume, abandon=abandon)

        fixture = driver_fixture(quiescer=quiesce)
        ordering: list[str] = []
        original_emit = fixture.driver._emit

        def observed_emit(name, payload, **options):
            if name == "ready":
                self.assertTrue(state["frozen"])
                ordering.append("ready")
            return original_emit(name, payload, **options)

        fixture.driver._emit = observed_emit
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            self.assertEqual(event(fixture.host)["event"], "ready")
            self.assertEqual(ordering, ["ready"])
            self.assertFalse(state["frozen"])
            self.assertEqual(state["resumed"], 1)
            self.assertEqual(state["abandoned"], 0)
            send_line(fixture.host, runtime.make_command(
                sequence=1, runtime_authority_sha256="1" * 64,
                operation="close"))
            self.assertEqual(event(fixture.host)["event"], "closed")
            driver.join(2)
            self.assertNotIn("error", result)
        finally:
            fixture.close()

    def test_deadline_jump_after_final_barrier_blocks_ready(self) -> None:
        clock = [100.0]
        state = {"resumed": 0, "abandoned": 0}

        def quiesce():
            return runtime.QualificationQuiescence(
                resume=lambda _deadline: state.__setitem__(
                    "resumed", state["resumed"] + 1),
                abandon=lambda: state.__setitem__(
                    "abandoned", state["abandoned"] + 1))

        fixture = driver_fixture(
            monotonic=lambda: clock[0], quiescer=quiesce)
        barrier_calls = 0

        def barrier(*, deadline):
            nonlocal barrier_calls
            self.assertGreater(deadline, clock[0])
            barrier_calls += 1
            if barrier_calls == 2:
                clock[0] = deadline + 1.0

        fixture.driver._qualification_quiet_barrier = barrier
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertEqual(barrier_calls, 2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_timeout")
            self.assertEqual(state, {"resumed": 0, "abandoned": 1})
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

    def test_ready_write_failure_abandons_frozen_scope_without_resume(self) -> None:
        state = {"resumed": 0, "abandoned": 0}

        def quiesce():
            return runtime.QualificationQuiescence(
                resume=lambda _deadline: state.__setitem__(
                    "resumed", state["resumed"] + 1),
                abandon=lambda: state.__setitem__(
                    "abandoned", state["abandoned"] + 1))

        fixture = driver_fixture(quiescer=quiesce)
        original_emit = fixture.driver._emit

        def failing_emit(name, payload, **options):
            if name == "ready":
                raise BrokenPipeError("host write rejected")
            return original_emit(name, payload, **options)

        fixture.driver._emit = failing_emit
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertIsInstance(result.get("error"), BrokenPipeError)
            self.assertEqual(state, {"resumed": 0, "abandoned": 1})
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

    def test_ready_crossing_deadline_is_emitted_but_scope_stays_frozen(self) -> None:
        clock = [100.0]
        state = {"resumed": 0, "abandoned": 0}

        def quiesce():
            return runtime.QualificationQuiescence(
                resume=lambda _deadline: state.__setitem__(
                    "resumed", state["resumed"] + 1),
                abandon=lambda: state.__setitem__(
                    "abandoned", state["abandoned"] + 1))

        fixture = driver_fixture(
            monotonic=lambda: clock[0], quiescer=quiesce)
        fixture.driver._qualification_quiet_barrier = lambda *, deadline: None
        original_emit = fixture.driver._emit

        def slow_emit(name, payload, **options):
            result = original_emit(name, payload, **options)
            if name == "ready":
                clock[0] = fixture.driver._qualification_deadline + 1.0
            return result

        fixture.driver._emit = slow_emit
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            self.assertEqual(event(fixture.host)["event"], "ready")
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_timeout")
            self.assertEqual(state, {"resumed": 0, "abandoned": 1})
        finally:
            fixture.close()

    def test_content_free_environment_proof_is_exact(self) -> None:
        codex_home_sha256, _environment_proof_sha256 = (
            runtime.expected_environment_proof(
                launch_descriptor(), PROJECTED_TOKEN_SHA256))
        changed = runtime.ProjectionTokenReceipt(
            projection_id=PROJECTION_ID,
            session_id="11111111-1111-4111-8111-111111111111",
            runtime_authority_sha256="1" * 64,
            permit_sha256=PERMIT_SHA256,
            access_token_sha256=PROJECTED_TOKEN_SHA256,
            token_length=len(PROJECTED_TOKEN),
            rolling_fingerprint=runtime.token_rolling_fingerprint(
                PROJECTED_TOKEN),
            process_id=PROCESS_ID,
            process_start_time_ticks=PROCESS_START_TIME_TICKS,
            codex_home_sha256=codex_home_sha256,
            environment_proof_sha256="f" * 64)
        with self.assertRaises(runtime.NativeCodexRuntimeError) as captured:
            runtime.validate_token_receipt(
                runtime.make_token_receipt_bytes(changed),
                launch_descriptor=launch_descriptor(),
                expected_projection_id=PROJECTION_ID,
                expected_permit_sha256=PERMIT_SHA256,
                expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
                expected_process_id=PROCESS_ID,
                expected_process_start_time_ticks=PROCESS_START_TIME_TICKS)
        self.assertEqual(
            str(captured.exception),
            "native_codex_runtime_token_receipt_process_mismatch")

    def test_controller_side_python_never_materializes_projected_token(self) -> None:
        from research import native_codex_session_controller as controller

        sources = (
            inspect.getsource(controller._launch_and_wait_admitted),
            inspect.getsource(runtime),
            inspect.getsource(isolation.collect_root_observation),
        )
        for source in sources:
            self.assertNotIn("/environ", source)
            self.assertNotIn("os.environ", source)
            self.assertNotIn('"ACCESS_TOKEN="', source)

    def test_missing_or_duplicate_private_exchange_never_reaches_ready(self) -> None:
        def initialized_only(fixture: DriverFixture) -> None:
            initialize = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": initialize["id"], "result": initialize_result()})
            start = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": start["id"], "result": thread_result()})

        def no_exchange(firewall, descriptor, _exchange, launcher_receipt):
            _unused, challenge = challenge_fixture(
                launcher_receipt_sha256=launcher_receipt["receipt_sha256"],
                environment_proof_sha256=launcher_receipt[
                    "environment_proof_sha256"],
                codex_home_sha256=launcher_receipt["codex_home_sha256"],
                token_sha256=launcher_receipt["access_token_sha256"],
                descriptor_value=dict(descriptor))
            return isolation.evaluate_qualification(
                firewall, descriptor, challenge=challenge,
                root_observation=root_observation(challenge),
                tool_observation=tool_observation(challenge),
                policy_manifest_sha256=POLICY_SHA,
                probe_executable_sha256=PROBE_SHA,
                observed_at_unix=1_800_000_000, marker_absent=True)

        fixture = driver_fixture(gate=no_exchange)
        try:
            server = threading.Thread(
                target=initialized_only, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_exchange_missing")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

        def duplicate(firewall, descriptor, exchange, launcher_receipt):
            _unused, challenge = challenge_fixture(
                launcher_receipt_sha256=launcher_receipt["receipt_sha256"],
                environment_proof_sha256=launcher_receipt[
                    "environment_proof_sha256"],
                codex_home_sha256=launcher_receipt["codex_home_sha256"],
                token_sha256=launcher_receipt["access_token_sha256"],
                descriptor_value=dict(descriptor))
            exchange(challenge, lambda: root_observation(challenge))
            exchange(challenge, lambda: root_observation(challenge))
            raise AssertionError("unreachable")

        fixture = driver_fixture(gate=duplicate)
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(3)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_exchange_duplicate")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

    def test_failed_and_unsupported_evidence_never_reaches_ready(self) -> None:
        def gate_for(outcome: str):
            def gate(firewall, descriptor, exchange, launcher_receipt):
                _unused, challenge = challenge_fixture(
                    launcher_receipt_sha256=launcher_receipt["receipt_sha256"],
                    environment_proof_sha256=launcher_receipt[
                        "environment_proof_sha256"],
                    codex_home_sha256=launcher_receipt["codex_home_sha256"],
                    token_sha256=launcher_receipt["access_token_sha256"],
                    descriptor_value=dict(descriptor))
                root, _tool = exchange(
                    challenge, lambda: root_observation(challenge))
                observed_tool = (
                    tool_observation(
                        challenge, outcome="unsupported",
                        unsupported=["proc_mount_unavailable"])
                    if outcome == "unsupported"
                    else tool_observation(
                        challenge, outcome="fail",
                        failures=["forced_failure"]))
                return isolation.evaluate_qualification(
                    firewall, descriptor, challenge=challenge,
                    root_observation=root, tool_observation=observed_tool,
                    policy_manifest_sha256=POLICY_SHA,
                    probe_executable_sha256=PROBE_SHA,
                    observed_at_unix=1_800_000_000, marker_absent=True)
            return gate

        for outcome in ("fail", "unsupported"):
            with self.subTest(outcome=outcome):
                fixture = driver_fixture(gate=gate_for(outcome))
                try:
                    server = threading.Thread(
                        target=startup_server, args=(fixture,), daemon=True)
                    driver, result = self.run_driver(fixture)
                    server.start()
                    driver.join(3)
                    self.assertEqual(
                        str(result.get("error")),
                        "native_codex_runtime_qualification_rejected")
                    fixture.host.settimeout(0.05)
                    with self.assertRaises((TimeoutError, socket.timeout)):
                        fixture.host.recv(1)
                finally:
                    fixture.close()

    def test_evidence_from_another_challenge_cannot_authorize_ready(self) -> None:
        def mismatched(firewall, descriptor, exchange, launcher_receipt):
            _unused, challenge = challenge_fixture(
                launcher_receipt_sha256=launcher_receipt["receipt_sha256"],
                environment_proof_sha256=launcher_receipt[
                    "environment_proof_sha256"],
                codex_home_sha256=launcher_receipt["codex_home_sha256"],
                token_sha256=launcher_receipt["access_token_sha256"],
                descriptor_value=dict(descriptor))
            root, tool = exchange(
                challenge, lambda: root_observation(challenge))
            evidence = isolation.evaluate_qualification(
                firewall, descriptor, challenge=challenge,
                root_observation=root, tool_observation=tool,
                policy_manifest_sha256=POLICY_SHA,
                probe_executable_sha256=PROBE_SHA,
                observed_at_unix=1_800_000_000, marker_absent=True)
            evidence["challenge_sha256"] = "f" * 64
            body = {name: evidence[name] for name in evidence
                    if name != "evidence_sha256"}
            evidence["evidence_sha256"] = isolation.digest(body)
            return evidence

        fixture = driver_fixture(gate=mismatched)
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(3)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_rejected")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

    def test_qualification_timeout_and_delayed_duplicate_block_ready(self) -> None:
        def slow_gate(firewall, descriptor, exchange, launcher_receipt):
            _unused, challenge = challenge_fixture(
                launcher_receipt_sha256=launcher_receipt["receipt_sha256"],
                environment_proof_sha256=launcher_receipt[
                    "environment_proof_sha256"],
                codex_home_sha256=launcher_receipt["codex_home_sha256"],
                token_sha256=launcher_receipt["access_token_sha256"],
                descriptor_value=dict(descriptor))
            exchange(
                challenge,
                lambda: (time.sleep(0.05) or root_observation(challenge)))
            raise AssertionError("unreachable")

        fixture = driver_fixture(gate=slow_gate)
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            with mock.patch.object(
                    runtime, "QUALIFICATION_TIMEOUT_SECONDS", 0.02):
                driver, result = self.run_driver(fixture)
                server.start()
                driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_timeout")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

        fixture = driver_fixture()

        def no_response_server() -> None:
            initialize = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": initialize["id"], "result": initialize_result()})
            start = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": start["id"], "result": thread_result()})
            request = json.loads(recv_line(fixture.app_input))
            self.assertEqual(request["method"], "command/exec")
            time.sleep(0.1)

        try:
            server = threading.Thread(
                target=no_response_server, daemon=True)
            with mock.patch.object(
                    runtime, "QUALIFICATION_TIMEOUT_SECONDS", 0.05), \
                    mock.patch.object(
                        runtime, "QUALIFICATION_QUIET_SECONDS", 0.005):
                driver, result = self.run_driver(fixture)
                server.start()
                driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_timeout")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

        def slow_post_exchange_gate(
            firewall, descriptor, exchange, launcher_receipt,
        ):
            _unused, challenge = challenge_fixture(
                launcher_receipt_sha256=launcher_receipt["receipt_sha256"],
                environment_proof_sha256=launcher_receipt[
                    "environment_proof_sha256"],
                codex_home_sha256=launcher_receipt["codex_home_sha256"],
                token_sha256=launcher_receipt["access_token_sha256"],
                descriptor_value=dict(descriptor))
            root, tool = exchange(
                challenge, lambda: root_observation(challenge))
            evidence = isolation.evaluate_qualification(
                firewall, descriptor, challenge=challenge,
                root_observation=root, tool_observation=tool,
                policy_manifest_sha256=POLICY_SHA,
                probe_executable_sha256=PROBE_SHA,
                observed_at_unix=1_800_000_000, marker_absent=True)
            # Models slow evaluation/cleanup/journal work after the exchange.
            time.sleep(0.08)
            return evidence

        fixture = driver_fixture(gate=slow_post_exchange_gate)
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            with mock.patch.object(
                    runtime, "QUALIFICATION_TIMEOUT_SECONDS", 0.05), \
                    mock.patch.object(
                        runtime, "QUALIFICATION_QUIET_SECONDS", 0.005):
                driver, result = self.run_driver(fixture)
                server.start()
                driver.join(2)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_timeout")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

        fixture = driver_fixture()

        def delayed_duplicate_server() -> None:
            initialize = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": initialize["id"], "result": initialize_result()})
            start = json.loads(recv_line(fixture.app_input))
            send_line(fixture.app_output, {
                "id": start["id"], "result": thread_result()})
            request = json.loads(recv_line(fixture.app_input))
            challenge = isolation.decode_probe_challenge(
                request["params"]["command"][2])
            observation = tool_observation(challenge)
            stdout = (
                challenge["raw_escape_payload"] + "\n"
                + isolation.canonical_bytes(observation).decode("ascii"))
            response = {
                "id": request["id"],
                "result": {"exitCode": 0, "stderr": "", "stdout": stdout},
            }
            send_line(fixture.app_output, response)
            time.sleep(0.05)
            send_line(fixture.app_output, response)

        try:
            server = threading.Thread(
                target=delayed_duplicate_server, daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(3)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_response_interleaved")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
        finally:
            fixture.close()

    def test_qualification_request_write_uses_fixed_overall_deadline(self) -> None:
        clock = [100.0]
        fixture = driver_fixture(monotonic=lambda: clock[0])
        original_send = fixture.driver._send_server
        bounded_writes: list[tuple[float, str]] = []

        def expire_qualification_write(raw, **options):
            deadline = options.get("deadline")
            timeout_code = options.get("timeout_code")
            if deadline is not None:
                self.assertIsInstance(deadline, float)
                self.assertEqual(
                    timeout_code,
                    "native_codex_runtime_qualification_timeout")
                bounded_writes.append((deadline, timeout_code))
                # Model a non-writable app-server request pipe consuming the
                # entire aggregate qualification budget.
                clock[0] = deadline
            return original_send(raw, **options)

        fixture.driver._send_server = expire_qualification_write
        try:
            server = threading.Thread(
                target=startup_server, args=(fixture,), daemon=True)
            driver, result = self.run_driver(fixture)
            server.start()
            driver.join(2)
            self.assertEqual(len(bounded_writes), 1)
            self.assertEqual(
                str(result.get("error")),
                "native_codex_runtime_qualification_timeout")
            fixture.host.settimeout(0.05)
            with self.assertRaises((TimeoutError, socket.timeout)):
                fixture.host.recv(1)
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
            qualification_server_exchange(fixture)

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
            expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
            expected_process_id=PROCESS_ID,
            expected_process_start_time_ticks=PROCESS_START_TIME_TICKS)
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
                        expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
                        expected_process_id=PROCESS_ID,
                        expected_process_start_time_ticks=(
                            PROCESS_START_TIME_TICKS))
        with self.assertRaisesRegex(
                runtime.NativeCodexRuntimeError, "identity_mismatch"):
            runtime.validate_token_receipt(
                token_receipt(permit_sha256="7" * 64),
                launch_descriptor=descriptor,
                expected_projection_id=PROJECTION_ID,
                expected_permit_sha256=PERMIT_SHA256,
                expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
                expected_process_id=PROCESS_ID,
                expected_process_start_time_ticks=PROCESS_START_TIME_TICKS)

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
            expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
            expected_process_id=PROCESS_ID,
            expected_process_start_time_ticks=PROCESS_START_TIME_TICKS)
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
            expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
            expected_process_id=PROCESS_ID,
            expected_process_start_time_ticks=PROCESS_START_TIME_TICKS)
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

    def test_quarantine_releases_short_benign_tail_only_on_finish(self) -> None:
        receipt = runtime.validate_token_receipt(
            token_receipt(), launch_descriptor=launch_descriptor(),
            expected_projection_id=PROJECTION_ID,
            expected_permit_sha256=PERMIT_SHA256,
            expected_access_token_sha256=PROJECTED_TOKEN_SHA256,
            expected_process_id=PROCESS_ID,
            expected_process_start_time_ticks=PROCESS_START_TIME_TICKS)
        guard = runtime._TokenExfiltrationGuard(receipt)
        short = b"short benign response"
        self.assertEqual(guard.admit("assistant", short), [])
        self.assertEqual(
            guard.finish(), [("assistant", short.decode("ascii"))])
        self.assertEqual(guard.finish(), [])

        guard = runtime._TokenExfiltrationGuard(receipt)
        self.assertEqual(guard.admit("assistant", short), [])
        guard.discard()
        self.assertEqual(guard.finish(), [])

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
        def rejected(_firewall, _descriptor, _exchange, _receipt):
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

        def unavailable(_firewall, _descriptor, _exchange, _receipt):
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

        quiescence = {"resumed": 0, "abandoned": 0}

        def quiesce():
            return runtime.QualificationQuiescence(
                resume=lambda _deadline: quiescence.__setitem__(
                    "resumed", quiescence["resumed"] + 1),
                abandon=lambda: quiescence.__setitem__(
                    "abandoned", quiescence["abandoned"] + 1))

        fixture = driver_fixture(quiescer=quiesce)
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
            self.assertEqual(quiescence, {"resumed": 0, "abandoned": 1})
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
            lease_deadline_monotonic=time.monotonic() + 0.9)
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
                    expected_process_id=PROCESS_ID,
                    expected_process_start_time_ticks=(
                        PROCESS_START_TIME_TICKS),
                    session_lease_sha256=SESSION_LEASE_SHA256,
                    session_expires_at=SESSION_EXPIRES_AT,
                    qualification_gate=lambda _firewall, _descriptor: "9" * 64,
                    qualification_quiescer=lambda: (
                        runtime.QualificationQuiescence(
                            resume=lambda _deadline: None,
                            abandon=lambda: None)),
                )
            self.assertEqual(
                str(captured.exception),
                "native_codex_runtime_descriptor_alias_invalid")
        finally:
            for endpoint in endpoints:
                endpoint.close()


if __name__ == "__main__":
    unittest.main()
