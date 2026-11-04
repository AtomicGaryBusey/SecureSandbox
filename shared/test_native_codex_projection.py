#!/usr/bin/env python3

from __future__ import annotations

import copy
import os
import socket
import struct
import unittest

from scripts.test_native_stack_manager import runtime_for
from shared import native_codex_projection as projection
from shared.test_native_vendor_stack import openai_stack


OPERATION_ID = "11111111-1111-4111-8111-111111111111"
AUTHORITY_SHA256 = "a" * 64
RECEIPT_SHA256 = "b" * 64
TOKEN_SHA256 = "c" * 64
EXECUTABLE_SHA256 = "d" * 64
NOW_MS = 2_000_000_000_000


def client_reply() -> dict:
    projected = {
        "process_identifier": 123,
        "process_start_time_us": 456,
        "executable_sha256": EXECUTABLE_SHA256,
        "session_authority_sha256": AUTHORITY_SHA256,
        "started_at_ms": NOW_MS,
    }
    inner = {
        "operation_id": OPERATION_ID, "outcome": "verified",
        "status": None,
        "projection": {
            **{key: value for key, value in projected.items()
               if key != "started_at_ms"},
            "started_at_milliseconds": projected["started_at_ms"],
        },
        "error_code": None,
    }
    body = {
        "operation_id": OPERATION_ID, "verified": True, "status": None,
        "projection": projected, "error_code": None,
        "response_sha256": projection.sha256(inner),
    }
    return {
        "schema": projection.CLIENT_REPLY_SCHEMA, **body,
        "reply_sha256": projection.sha256(body),
    }


class NativeCodexProjectionTests(unittest.TestCase):
    def test_qualification_authority_binds_exact_runtime_subject(self) -> None:
        runtime = runtime_for(openai_stack())
        request = projection.make_projection_status_request(
            operation_id=OPERATION_ID, authority=runtime
        )
        descriptor = request["launch_descriptor"]
        subject = projection.make_qualification_subject(
            descriptor, policy_manifest_sha256="1" * 64,
            probe_executable_sha256="2" * 64,
            protocol_version="0.166.0",
        )
        reply = projection.make_projection_status_reply(
            operation_id=OPERATION_ID,
            research_release_id="3" * 64,
            boot_id_sha256="4" * 64,
            runtime_authority_sha256=runtime["binding_sha256"],
            launch_descriptor_sha256=descriptor["descriptor_sha256"],
            qualification_subject=subject,
            qualification_evidence_sha256="5" * 64,
            observed_at=2_000_000_000, expires_at=2_000_000_120,
        )
        authority = projection.make_projection_authority(
            consumer_executable_path=(
                "/usr/local/libexec/secure-sandbox-host/releases/"
                + "6" * 64 + "/native_projection_consumer"
            ),
            consumer_executable_sha256="7" * 64,
            host_release_id="6" * 64,
            operation_id=OPERATION_ID, request_sha256="8" * 64,
            stack_sha256="9" * 64, authority=runtime,
            observation=reply, now=2_000_000_001,
        )
        self.assertEqual(authority["session_id"], descriptor["session_id"])
        self.assertEqual(
            projection.validate_projection_authority(
                authority, operation_id=OPERATION_ID,
                request_sha256="8" * 64, stack_sha256="9" * 64,
                session_authority_sha256=runtime["binding_sha256"],
                ticket_issued_at=2_000_000_001,
                ticket_expires_at=2_000_000_100,
                now=2_000_000_002,
            ),
            authority,
        )
        for field, replacement in (
            ("model_id", "gpt-6-luna"),
            ("research_release_id", "a" * 64),
            ("qualification_evidence_sha256", "b" * 64),
            ("qualification_readback_sha256", "c" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(
                projection.NativeCodexProjectionError
            ):
                projection.validate_projection_authority(
                    {**authority, field: replacement},
                    operation_id=OPERATION_ID,
                    request_sha256="8" * 64, stack_sha256="9" * 64,
                    session_authority_sha256=runtime["binding_sha256"],
                    ticket_issued_at=2_000_000_001,
                    ticket_expires_at=2_000_000_100,
                    now=2_000_000_002,
                )

    def test_projection_reply_is_exact_and_binds_consumer_process(self) -> None:
        value = client_reply()
        self.assertEqual(
            projection.validate_client_projection_reply(
                value, expected_operation_id=OPERATION_ID,
                expected_session_authority_sha256=AUTHORITY_SHA256,
                expected_executable_sha256=EXECUTABLE_SHA256,
                now_ms=NOW_MS,
            ),
            value,
        )
        for mutation in ("extra", "executable", "pid", "inner", "outer"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(value)
                if mutation == "extra":
                    changed["unexpected"] = None
                elif mutation == "executable":
                    changed["projection"]["executable_sha256"] = "e" * 64
                elif mutation == "pid":
                    changed["projection"]["process_identifier"] = 0
                elif mutation == "inner":
                    changed["response_sha256"] = "e" * 64
                else:
                    changed["reply_sha256"] = "e" * 64
                with self.assertRaises(projection.NativeCodexProjectionError):
                    projection.validate_client_projection_reply(
                        changed, expected_operation_id=OPERATION_ID,
                        expected_session_authority_sha256=AUTHORITY_SHA256,
                        expected_executable_sha256=EXECUTABLE_SHA256,
                        now_ms=NOW_MS,
                    )

    def test_claim_transport_rejects_ancillary_or_trailing_substitution(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        extra_read, extra_write = os.pipe()
        try:
            raw = (
                projection.CLAIM_MAGIC + OPERATION_ID.encode("ascii")
                + AUTHORITY_SHA256.encode("ascii")
                + RECEIPT_SHA256.encode("ascii")
                + TOKEN_SHA256.encode("ascii")
                + struct.pack(">Q", NOW_MS + 60_000)
            )
            import array
            right.sendmsg(
                [raw],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                  array.array("i", [extra_read]))],
            )
            with self.assertRaisesRegex(
                projection.NativeCodexProjectionError, "handshake_invalid"
            ):
                projection.read_claim(left.fileno(), timeout=1, now_ms=NOW_MS)
        finally:
            os.close(extra_read); os.close(extra_write)
            left.close(); right.close()


if __name__ == "__main__":
    unittest.main()
