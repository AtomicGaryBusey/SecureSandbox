#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import native_stack_backend as backend
from scripts.test_native_stack_manager import runtime_for, status_for
from shared import native_program_attestation
from shared import native_codex_ui_handle
from shared import native_stack_operations as operations
from shared import native_stack_session
from shared import native_terminal_handle
from shared import native_vendor_stack
from shared.test_native_vendor_stack import anthropic_stack, openai_stack


NOW = 2_000_000_000


def plan_for(action: str) -> tuple[dict, dict]:
    stack = openai_stack()
    plan = operations.make_plan(
        stack=stack,
        status=status_for(stack),
        action=action,
        created_at=NOW,
        action_id="11111111-1111-4111-8111-111111111111",
    )
    authorization = {
        "authorization_id": "22222222-2222-4222-8222-222222222222",
        "request_sha256": "1" * 64,
        "pending_receipt_sha256": "2" * 64,
        "authorization_sha256": "3" * 64,
        "authorized_at": NOW + 1,
        "expires_at": NOW + 121,
    }
    return plan, authorization


class NativeStackBackendTests(unittest.TestCase):
    @staticmethod
    def credential_reply() -> bytes:
        body = {
            "operation_id": "11111111-1111-4111-8111-111111111111",
            "verified": True,
            "status": None,
            "projection": {
                "process_identifier": 42,
                "process_start_time_us": 123456,
                "executable_sha256": "a" * 64,
                "session_authority_sha256": "b" * 64,
                "started_at_ms": NOW * 1000,
            },
            "error_code": None,
            "response_sha256": "c" * 64,
        }
        body["reply_sha256"] = backend.digest(body)
        return backend.canonical({
            "schema": "secure-sandbox-native-credential-client-reply-v1",
            **body,
        })

    def test_dns_policy_requires_two_stable_global_ipv4_observations(self) -> None:
        calls: dict[str, int] = {}

        def resolver(hostname: str) -> tuple[str, ...]:
            calls[hostname] = calls.get(hostname, 0) + 1
            return (
                ("8.8.8.8", "1.1.1.1")
                if calls[hostname] == 1
                else ("1.1.1.1", "9.9.9.9")
            )

        pins = backend.resolve_policy(
            "openai-codex-siwc-v1", "inference", resolver=resolver
        )
        self.assertTrue(pins)
        self.assertTrue(all(values == ["1.1.1.1"] for values in pins.values()))
        self.assertTrue(all(count == 2 for count in calls.values()))

    def test_activate_never_calls_credential_service_or_projects_session(self) -> None:
        plan, authorization = plan_for("activate")
        stack = openai_stack()
        observed_request: dict = {}

        def credential(_value):
            self.fail("activate must not call credential custody")

        def guest(operation: str, request: object) -> dict:
            self.assertEqual(operation, "native-provider-action")
            observed_request.update(request)
            return {
                "schema": backend.PROVIDER_RESULT_SCHEMA,
                "action_id": plan["action_id"],
                "action": plan["action"],
                "plan_sha256": plan["plan_sha256"],
                "authorization_sha256": authorization["authorization_sha256"],
                "status": "verified",
                "evidence_sha256": "4" * 64,
            }

        result = backend.provider_action(
            plan, authorization, stack, credential=credential, guest=guest
        )
        self.assertEqual(result["status"], "verified")
        self.assertIsNone(observed_request["runtime_authority"])

    def test_refresh_ticket_is_pre_session_and_never_fabricates_session_digest(self) -> None:
        plan, authorization = plan_for("entitlement-verify")
        ticket = backend.make_credential_ticket(
            operation="refresh",
            action="entitlement-verify",
            plan=plan,
            authorization=authorization,
        )
        handoff = backend.credential_handoff(
            operation="refresh",
            operation_id=plan["action_id"],
            plan=plan,
            authorization=authorization,
        )
        self.assertIsNone(ticket["session_authority_sha256"])
        self.assertIsNone(handoff["session_authority_sha256"])

    def test_credential_ticket_inventory_is_bounded_and_crash_safe(self) -> None:
        plan, authorization = plan_for("entitlement-verify")
        ticket = backend.make_credential_ticket(
            operation="refresh", action="entitlement-verify",
            plan=plan, authorization=authorization,
        )
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tickets"
            path = root / f"{ticket['ticket_id']}.json"
            backend._atomic_ticket(
                path, ticket, now=NOW + 2,
                trusted_uid=uid, trusted_gid=gid,
            )
            self.assertEqual(
                backend._validate_credential_ticket(json.loads(path.read_bytes())),
                ticket,
            )
            backend._atomic_ticket(
                path, ticket, now=NOW + 2,
                trusted_uid=uid, trusted_gid=gid,
            )

            second_authorization = dict(
                authorization,
                authorization_id="33333333-3333-4333-8333-333333333333",
            )
            second = backend.make_credential_ticket(
                operation="refresh", action="entitlement-verify",
                plan=plan, authorization=second_authorization,
            )
            with mock.patch.object(backend, "CREDENTIAL_TICKET_MAXIMUM", 1), \
                    self.assertRaisesRegex(
                        backend.NativeStackBackendError, "capacity_exceeded"
                    ):
                backend._atomic_ticket(
                    root / f"{second['ticket_id']}.json", second, now=NOW + 2,
                    trusted_uid=uid, trusted_gid=gid,
                )

    def test_credential_ticket_inventory_rejects_unknown_and_symlink_entries(self) -> None:
        plan, authorization = plan_for("entitlement-verify")
        ticket = backend.make_credential_ticket(
            operation="refresh", action="entitlement-verify",
            plan=plan, authorization=authorization,
        )
        uid, gid = os.geteuid(), os.getegid()
        for entry_kind in ("unknown", "symlink"):
            with self.subTest(entry_kind=entry_kind), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "tickets"
                root.mkdir(mode=0o755)
                if entry_kind == "unknown":
                    (root / "unrecognized").write_text("x", encoding="ascii")
                else:
                    (root / "33333333-3333-4333-8333-333333333333.json").symlink_to(
                        root / "missing"
                    )
                with self.assertRaisesRegex(
                    backend.NativeStackBackendError, "inventory_untrusted"
                ):
                    backend._atomic_ticket(
                        root / f"{ticket['ticket_id']}.json", ticket,
                        now=NOW + 2, trusted_uid=uid, trusted_gid=gid,
                    )

    def test_credential_ticket_inventory_reaps_only_provably_stale_entries(self) -> None:
        plan, authorization = plan_for("entitlement-verify")
        ticket = backend.make_credential_ticket(
            operation="refresh", action="entitlement-verify",
            plan=plan, authorization=authorization,
        )
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tickets"
            root.mkdir(mode=0o755)
            stale = root / ".ticket-33333333-3333-4333-8333-333333333333"
            stale.write_bytes(b"partial")
            stale.chmod(0o600)
            os.utime(stale, (NOW - 1000, NOW - 1000))
            backend._atomic_ticket(
                root / f"{ticket['ticket_id']}.json", ticket, now=NOW,
                trusted_uid=uid, trusted_gid=gid,
            )
            self.assertFalse(stale.exists())

    def test_projection_call_requires_exact_connected_unix_stream(self) -> None:
        handoff = {"operation": "projectForSession"}
        with mock.patch.object(backend, "_trusted_executable"), \
                mock.patch.object(backend, "_ensure_root_directory"), \
                mock.patch.object(backend, "console_uid", return_value=os.getuid()), \
                mock.patch.object(backend.os, "fchown"), \
                mock.patch.object(
                    backend, "run_bounded", return_value=self.credential_reply()
                ) as run:
            with self.assertRaisesRegex(
                backend.NativeStackBackendError, "projection_channel_invalid"
            ):
                backend.signed_credential_call(handoff, uid=os.getuid())
            read_fd, write_fd = os.pipe()
            try:
                with self.assertRaisesRegex(
                    backend.NativeStackBackendError, "projection_channel_invalid"
                ):
                    backend.signed_credential_call(
                        handoff, uid=os.getuid(), projection_fd=write_fd
                    )
            finally:
                os.close(read_fd); os.close(write_fd)
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            projection_fd = left.fileno()
            try:
                with tempfile.TemporaryDirectory() as temporary:
                    reply = backend.signed_credential_call(
                        handoff, uid=os.getuid(), projection_fd=projection_fd,
                        state_root=Path(temporary),
                    )
            finally:
                left.close(); right.close()
            self.assertTrue(reply["verified"])
            self.assertIn(projection_fd, run.call_args.kwargs["pass_fds"])

    def test_non_projection_call_rejects_projection_channel(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with mock.patch.object(backend, "_trusted_executable"), \
                    mock.patch.object(backend, "_ensure_root_directory"), \
                    self.assertRaisesRegex(
                        backend.NativeStackBackendError, "projection_channel_invalid"
                    ):
                backend.signed_credential_call(
                    {"operation": "status"}, uid=os.getuid(),
                    projection_fd=left.fileno()
                )
        finally:
            left.close(); right.close()

    def test_openai_status_maps_exact_xpc_custody_without_inferring_absence(self) -> None:
        stack = openai_stack()
        guest = status_for(stack)
        reply = {
            "reply_sha256": "5" * 64,
            "projection": None,
            "status": {
                "provider": "openAIChatGPT",
                "state": "ready",
                "client_id_sha256": "6" * 64,
                "account_subject_sha256": stack["account_binding"]["account_subject_sha256"],
                "workspace_sha256": stack["account_binding"]["workspace_sha256"],
                "scope_sha256": "7" * 64,
                "access_expires_at_ms": (NOW + 300) * 1000,
                "earliest_refresh_at_ms": (NOW + 200) * 1000,
                "refresh_expires_at_ms": (NOW + 600) * 1000,
                "custody_state": "retained",
                "custody_tombstone_sha256": None,
                "custody_projection_count": 0,
            },
        }
        merged = backend.merge_openai_status(guest, reply, stack, now=NOW)
        self.assertEqual(
            merged["credential_custody"],
            {
                "state": "retained",
                "observed_at": NOW,
                "evidence_sha256": "5" * 64,
                "tombstone_sha256": None,
                "projection_count": 0,
            },
        )
        ambiguous = copy.deepcopy(reply)
        ambiguous["status"]["state"] = "loggedOut"
        ambiguous["status"]["client_id_sha256"] = None
        ambiguous["status"]["account_subject_sha256"] = None
        ambiguous["status"]["workspace_sha256"] = None
        ambiguous["status"]["scope_sha256"] = None
        ambiguous["status"]["access_expires_at_ms"] = None
        ambiguous["status"]["earliest_refresh_at_ms"] = None
        ambiguous["status"]["refresh_expires_at_ms"] = None
        ambiguous["status"]["custody_state"] = "ambiguous"
        ambiguous["status"]["custody_projection_count"] = None
        merged = backend.merge_openai_status(guest, ambiguous, stack, now=NOW)
        self.assertEqual(merged["credential_custody"]["state"], "ambiguous")

    def test_inspect_request_is_bound_to_exact_root_catalog_revision(self) -> None:
        stack = openai_stack()
        catalog = {
            "schema": native_vendor_stack.CATALOG_SCHEMA,
            "stacks": [stack],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            raw = native_vendor_stack.canonical_bytes(catalog)
            path.write_bytes(raw)
            path.chmod(0o600)
            body = {
                "operation_id": "33333333-3333-4333-8333-333333333333",
                "stack_id": stack["stack_id"],
                "stack_sha256": native_vendor_stack.stack_revision(stack),
                "catalog_sha256": hashlib.sha256(raw).hexdigest(),
            }
            request = {
                "schema": "secure-sandbox-native-stack-inspect-request-v1",
                **body,
                "request_sha256": backend.digest(body),
            }
            validated, selected, observed = backend.validate_inspect_request(
                request, catalog_path=path
            )
            self.assertEqual(validated, request)
            self.assertEqual(selected, stack)
            self.assertEqual(observed, body["catalog_sha256"])
            changed = json.loads(json.dumps(request))
            changed["stack_sha256"] = "f" * 64
            changed_body = {
                key: changed[key]
                for key in ("operation_id", "stack_id", "stack_sha256", "catalog_sha256")
            }
            changed["request_sha256"] = backend.digest(changed_body)
            with self.assertRaisesRegex(
                backend.NativeStackBackendError, "inspect_catalog_changed"
            ):
                backend.validate_inspect_request(changed, catalog_path=path)

    def test_projection_readback_is_fresh_canonical_and_root_published(self) -> None:
        operation_id = "44444444-4444-4444-8444-444444444444"
        request_body = {"operation_id": operation_id}
        request = {
            "schema": (
                "secure-sandbox-native-projection-readback-refresh-request-v1"
            ),
            **request_body,
            "request_sha256": backend.digest(request_body),
        }
        reply_body = {
            "schema": (
                "secure-sandbox-native-projection-isolation-status-reply-v1"
            ),
            "operation_id": operation_id,
            "research_release_id": "a" * 64,
            "isolation_attestation_sha256": "b" * 64,
            "observed_at": NOW,
            "expires_at": NOW + 120,
        }
        reply = {**reply_body, "evidence_sha256": backend.digest(reply_body)}
        observed: list[tuple[str, object]] = []

        def guest(operation: str, value: object) -> dict:
            observed.append((operation, value))
            return reply

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            path = root / "native-research-projection-readback.json"
            publication = backend.refresh_projection_readback(
                request, now=NOW, guest=guest, path=path,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            )
            document = json.loads(path.read_bytes())
            self.assertEqual(path.read_bytes(), backend.canonical(document))
            self.assertEqual(path.stat().st_mode & 0o777, 0o444)
            self.assertEqual(document["research_release_id"], "a" * 64)
            self.assertEqual(
                document["research_isolation_attestation_sha256"], "b" * 64
            )
            self.assertEqual(
                publication["readback_sha256"], document["readback_sha256"]
            )
        self.assertEqual(observed[0][0], "native-projection-isolation-status")
        self.assertEqual(
            observed[0][1]["request_sha256"],
            backend.digest({"operation_id": operation_id}),
        )

        changed = dict(reply, evidence_sha256="f" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            with self.assertRaisesRegex(
                backend.NativeStackBackendError,
                "projection_readback_guest_invalid",
            ):
                backend.refresh_projection_readback(
                    request, now=NOW, guest=lambda _operation, _value: changed,
                    path=root / "readback.json", trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid(),
                )

    def test_program_attestation_is_separate_and_read_back_operator_external(self) -> None:
        stack = anthropic_stack()
        before = status_for(stack, program="unknown")
        plan = native_program_attestation.make_plan(
            stack=stack, catalog_sha256="2" * 64, status_value=before,
            attestation_id="55555555-5555-4555-8555-555555555555",
            created_at=NOW,
        )
        authorization_body = {
            "authorization_id": "66666666-6666-4666-8666-666666666666",
            "attestation_id": plan["attestation_id"],
            "plan_sha256": plan["plan_sha256"],
            "request_sha256": "3" * 64,
            "pending_receipt_sha256": "4" * 64,
            "host_release_id": "5" * 64,
            "method": "touch-id", "password_fallback": False,
            "requesting_agent_sha256": "6" * 64,
            "requesting_session_sha256": "7" * 64,
            "authorized_at": NOW + 1, "expires_at": NOW + 120,
            "status": "authorized",
        }
        authorization = {
            "schema": native_program_attestation.AUTHORIZATION_SCHEMA,
            **authorization_body,
            "authorization_sha256": native_program_attestation.sha256(
                authorization_body
            ),
        }
        evidence = "d" * 64
        after = status_for(stack, program="verified")
        operations_seen: list[str] = []

        def guest(operation: str, request: object) -> dict:
            operations_seen.append(operation)
            if operation == "native-stack-inspect-status":
                return before if operations_seen.count(operation) == 1 else after
            self.assertEqual(operation, "native-program-attestation")
            self.assertEqual(request["program_id"], "anthropic-cvp")
            self.assertEqual(request["program_tier"], "defense")
            self.assertEqual(
                request["attestation_receipt_sha256"],
                authorization["pending_receipt_sha256"],
            )
            return {
                "schema": backend.PROVIDER_RESULT_SCHEMA,
                "action_id": plan["attestation_id"],
                "action": "program-attest",
                "plan_sha256": plan["plan_sha256"],
                "authorization_sha256": authorization["authorization_sha256"],
                "status": "verified", "evidence_sha256": evidence,
            }

        result = backend.program_attest(
            plan, authorization, stack, guest=guest
        )
        self.assertEqual(result["evidence_sha256"], evidence)
        self.assertEqual(operations_seen, [
            "native-stack-inspect-status", "native-program-attestation",
            "native-stack-inspect-status",
        ])

    def test_program_status_requires_matching_host_commit_and_operator_receipt(self) -> None:
        stack = anthropic_stack()
        initial = status_for(stack, program="unknown")
        verified = status_for(stack, program="verified")
        catalog_sha256 = "2" * 64
        plan = native_program_attestation.make_plan(
            stack=stack, catalog_sha256=catalog_sha256,
            status_value=initial,
            attestation_id="77777777-7777-4777-8777-777777777777",
            created_at=NOW,
        )
        authorization_body = {
            "authorization_id": "88888888-8888-4888-8888-888888888888",
            "attestation_id": plan["attestation_id"],
            "plan_sha256": plan["plan_sha256"],
            "request_sha256": "3" * 64,
            "pending_receipt_sha256": "4" * 64,
            "host_release_id": "5" * 64,
            "method": "touch-id", "password_fallback": False,
            "requesting_agent_sha256": "6" * 64,
            "requesting_session_sha256": "7" * 64,
            "authorized_at": NOW + 1, "expires_at": NOW + 120,
            "status": "authorized",
        }
        authorization = {
            "schema": native_program_attestation.AUTHORIZATION_SCHEMA,
            **authorization_body,
            "authorization_sha256": native_program_attestation.sha256(
                authorization_body
            ),
        }
        receipt = {
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "request_id": authorization["authorization_id"],
            "request_sha256": authorization["request_sha256"],
            "status": "succeeded", "started_at": NOW + 1,
            "completed_at": NOW + 2,
            "operation": native_program_attestation.OPERATION,
            "declared_agent": "Codex", "declared_session": "program-test",
            "identity_evidence": "operator-declared",
            "authorization_method": "touch-id", "ceremony": "approve",
            "purpose": "Attest exact CVP enrollment",
            "resource": native_program_attestation.RESOURCE,
            "exit_status": 0, "stdout_sha256": "8" * 64,
            "stderr_sha256": "9" * 64,
            "native_program_attestation_id": plan["attestation_id"],
            "native_program_plan_sha256": plan["plan_sha256"],
            "native_program_provider_evidence_sha256": (
                verified["program_entitlement"]["evidence_sha256"]
            ),
            "host_release_id": authorization["host_release_id"],
        }
        commit = native_program_attestation.make_commit(
            plan_value=plan, authorization_value=authorization,
            operator_receipt_sha256=backend.digest(receipt),
            provider_evidence_sha256=(
                verified["program_entitlement"]["evidence_sha256"]
            ),
            committed_at=NOW + 2,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commits = root / "commits"
            receipts = root / "receipts"
            commits.mkdir(mode=0o700)
            receipts.mkdir(mode=0o700)
            commit_path = commits / f"{verified['stack_sha256']}.json"
            receipt_path = receipts / f"{authorization['authorization_id']}.json"
            commit_path.write_bytes(backend.canonical(commit))
            receipt_path.write_bytes(backend.canonical(receipt))
            commit_path.chmod(0o600)
            receipt_path.chmod(0o600)
            admitted = backend.enforce_program_attestation_commit(
                verified, stack, catalog_sha256, commit_root=commits,
                receipt_root=receipts, trusted_uid=os.geteuid(),
            )
            self.assertEqual(
                admitted["program_entitlement"]["assurance"],
                "operator-external",
            )
            commit_path.unlink()
            rejected = backend.enforce_program_attestation_commit(
                verified, stack, catalog_sha256, commit_root=commits,
                receipt_root=receipts, trusted_uid=os.geteuid(),
            )
            self.assertEqual(rejected["program_entitlement"], {
                "state": "unknown", "assurance": "unknown",
                "observed_at": verified["program_entitlement"]["observed_at"],
                "evidence_sha256": rejected["program_entitlement"][
                    "evidence_sha256"
                ],
            })

    def test_claude_session_prepare_revalidates_authority_and_returns_one_shot_handle(
        self,
    ) -> None:
        stack = anthropic_stack()
        authority = runtime_for(stack)
        status = status_for(stack, activation="active")
        plan = native_stack_session.make_plan(
            action="session-start",
            action_id="99999999-9999-4999-8999-999999999999",
            session_id=authority["session_context_binding"]["session_id"],
            stack_id=stack["stack_id"],
            stack_sha256=native_vendor_stack.stack_revision(stack),
            catalog_sha256="1" * 64,
            status_sha256=status["status_sha256"],
            runtime_authority_value=authority,
            source_id=None, source_manifest_sha256=None,
            resume_session_id=None, lease_profile_id="interactive",
            created_at=NOW,
        )
        authorization = {
            "authorization_sha256": "2" * 64,
            "expires_at": NOW + 120,
        }
        lease = native_stack_session.make_session_lease(
            lease_profile_id="interactive", session_id=plan["session_id"],
            runtime_authority_sha256=plan["runtime_authority_sha256"],
            grant_id="88888888-8888-4888-8888-888888888888",
            grant_sha256="5" * 64, issued_at=NOW,
            expires_at=NOW + 60 * 60,
        )
        operations_seen: list[str] = []

        def guest(operation: str, request: object) -> dict:
            operations_seen.append(operation)
            self.assertIsInstance(request, dict)
            if operation == "native-stack-inspect-status":
                return status
            if operation == "native-session-authority":
                return {
                    "schema": "secure-sandbox-native-session-authority-reply-v1",
                    "authority": authority,
                    "evidence_sha256": backend.digest({
                        "operation_id": plan["action_id"],
                        "request_sha256": request["request_sha256"],
                        "authority_sha256": authority["binding_sha256"],
                    }),
                }
            if operation == "native-claude-session-prepare":
                self.assertEqual(request["runtime_authority"], authority)
                return {
                    "schema": (
                        "secure-sandbox-native-claude-session-prepare-reply-v1"
                    ),
                    "operation_id": plan["action_id"],
                    "prepare_sha256": "3" * 64,
                    "session_lease_sha256": lease["lease_sha256"],
                    "session_expires_at": lease["expires_at"],
                    "evidence_sha256": "4" * 64,
                }
            self.fail(operation)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            backend, "enforce_program_attestation_commit",
            side_effect=lambda value, _stack, _catalog: value,
        ):
            root = Path(temporary)
            root.chmod(0o700)
            public = backend.session_operation(
                plan, authorization, stack, now=NOW + 1,
                guest=guest, terminal_root=root,
                terminal_handle_id=(
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                ),
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                session_lease=lease,
            )
            self.assertEqual(public["kind"], "claude-session")
            record = json.loads(
                (root / f"{public['handle_id']}.json").read_bytes()
            )
            self.assertEqual(record["session_id"], plan["session_id"])
            self.assertEqual(record["remote_arguments"], [
                plan["action_id"], "3" * 64,
            ])
        self.assertEqual(operations_seen, [
            "native-stack-inspect-status", "native-session-authority",
            "native-claude-session-prepare",
        ])

    def test_session_plan_uses_guest_measured_policy_not_caller_digests(
        self,
    ) -> None:
        stack = anthropic_stack()
        authority = runtime_for(stack)
        status = status_for(stack, activation="active")
        status["harness"]["binding_sha256"] = authority["harness_binding"][
            "binding_sha256"
        ]
        status_body = {
            key: value for key, value in status.items()
            if key not in {"schema", "status_sha256"}
        }
        status["status_sha256"] = operations.sha256(status_body)
        request = {
            "action": "session-start",
            "action_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "session_id": authority["session_context_binding"]["session_id"],
            "stack_id": stack["stack_id"],
            "stack_sha256": native_vendor_stack.stack_revision(stack),
            "catalog_sha256": "1" * 64,
            "source_id": None, "resume_session_id": None,
            "lease_profile_id": "interactive",
        }
        seen: list[str] = []

        def guest(operation: str, value: object) -> dict:
            seen.append(operation)
            if operation == "native-session-plan-authority":
                self.assertNotIn("persona_sha256", value)
                return {
                    "schema": (
                        "secure-sandbox-native-session-plan-authority-reply-v1"
                    ),
                    "authority": authority,
                    "evidence_sha256": backend.digest({
                        "operation_id": request["action_id"],
                        "request_sha256": value["request_sha256"],
                        "authority_sha256": authority["binding_sha256"],
                    }),
                }
            if operation == "native-stack-inspect-status":
                return status
            self.fail(operation)

        with mock.patch.object(
            backend, "enforce_program_attestation_commit",
            side_effect=lambda value, _stack, _catalog: value,
        ):
            plan = backend.session_plan(
                request, stack, now=NOW, guest=guest
            )
        self.assertEqual(plan["runtime_authority"], authority)
        self.assertEqual(plan["status_sha256"], status["status_sha256"])
        self.assertEqual(seen, [
            "native-session-plan-authority", "native-stack-inspect-status",
        ])

    def test_codex_session_start_publishes_only_typed_ui_authority(
        self,
    ) -> None:
        stack = openai_stack()
        authority = runtime_for(stack)
        status = status_for(stack, activation="active")
        plan = native_stack_session.make_plan(
            action="session-start",
            action_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            session_id=authority["session_context_binding"]["session_id"],
            stack_id=stack["stack_id"],
            stack_sha256=native_vendor_stack.stack_revision(stack),
            catalog_sha256="1" * 64,
            status_sha256=status["status_sha256"],
            runtime_authority_value=authority,
            source_id=None, source_manifest_sha256=None,
            resume_session_id=None, lease_profile_id="interactive",
            created_at=NOW,
        )
        authorization = {
            "authorization_sha256": "2" * 64,
            "expires_at": NOW + 120,
        }
        lease = native_stack_session.make_session_lease(
            lease_profile_id="interactive", session_id=plan["session_id"],
            runtime_authority_sha256=plan["runtime_authority_sha256"],
            grant_id="77777777-7777-4777-8777-777777777777",
            grant_sha256="5" * 64, issued_at=NOW,
            expires_at=NOW + 60 * 60,
        )
        def credential(_request: object) -> dict:
            return {"status": {}, "projection": None}

        def guest(operation: str, request: object) -> dict:
            if operation == "native-stack-inspect-status":
                return status
            if operation == "native-session-authority":
                return {
                    "schema": "secure-sandbox-native-session-authority-reply-v1",
                    "authority": authority,
                    "evidence_sha256": backend.digest({
                        "operation_id": plan["action_id"],
                        "request_sha256": request["request_sha256"],
                        "authority_sha256": authority["binding_sha256"],
                    }),
                }
            self.fail(operation)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "handles"
            root.mkdir(mode=0o700)
            with mock.patch.object(
                backend, "merge_openai_status", return_value=status
            ), mock.patch.object(
                backend, "enforce_program_attestation_commit",
                side_effect=lambda value, _stack, _catalog: value,
            ):
                public = backend.session_operation(
                    plan, authorization, stack, now=NOW + 1,
                    credential=credential, guest=guest,
                    codex_ui_root=root, trusted_uid=os.getuid(),
                    trusted_gid=os.getgid(), session_lease=lease,
                )
        observed = native_codex_ui_handle.validate_public(public)
        self.assertEqual(observed["kind"], "codex-typed-ui")
        self.assertEqual(observed["operation_id"], plan["action_id"])
        self.assertEqual(observed["session_lease_sha256"], lease["lease_sha256"])

    def test_interactive_resume_requires_timely_consumed_handle_and_completed_receipt(
        self,
    ) -> None:
        stack = anthropic_stack()
        initial = status_for(stack, authentication="signed-out")
        plan = operations.make_plan(
            stack=stack, status=initial, action="signin-begin",
            action_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            created_at=NOW,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipts = root / "receipts"
            catalog_root = root / "catalog"
            handles = root / "handles"
            receipts.mkdir(mode=0o700)
            catalog_root.mkdir(mode=0o700)
            handles.mkdir(mode=0o700)
            catalog_path = catalog_root / "catalog.json"
            native_vendor_stack.write_catalog(catalog_path, {
                "schema": native_vendor_stack.CATALOG_SCHEMA,
                "stacks": [stack],
            })
            catalog_sha256 = hashlib.sha256(
                catalog_path.read_bytes()
            ).hexdigest()
            pending = {
                "schema": "secure-sandbox-operator-authorization-receipt-v1",
                "request_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                "request_sha256": "1" * 64, "status": "executing",
                "started_at": NOW + 1, "completed_at": None,
                "operation": "native-stack-signin-begin",
                "declared_agent": "Codex",
                "declared_session": "native-login-test",
                "identity_evidence": "operator-declared",
                "authorization_method": "touch-id", "ceremony": "approve",
                "purpose": "Sign in to exact native stack",
                "resource": "Native vendor harness and model stack authority",
                "exit_status": None, "stdout_sha256": None,
                "stderr_sha256": None,
                "native_action_id": plan["action_id"],
                "native_plan_sha256": plan["plan_sha256"],
                "host_release_id": "2" * 64,
            }
            authorization_body = {
                "schema": backend.MANAGER.AUTHORIZATION_SCHEMA,
                "authorization_id": pending["request_id"],
                "request_sha256": pending["request_sha256"],
                "pending_receipt_sha256": backend.digest(pending),
                "action_id": plan["action_id"], "action": plan["action"],
                "plan_sha256": plan["plan_sha256"], "method": "touch-id",
                "password_fallback": False, "authorized_at": NOW + 1,
                "expires_at": NOW + 121, "host_release_id": "2" * 64,
                "requesting_agent_sha256": hashlib.sha256(
                    b"Codex"
                ).hexdigest(),
                "requesting_session_sha256": hashlib.sha256(
                    b"native-login-test"
                ).hexdigest(),
            }
            authorization = {
                **authorization_body,
                "authorization_sha256": backend.digest(authorization_body),
            }
            record = native_terminal_handle.make_record(
                handle_id=plan["action_id"], kind="claude-login",
                operation_id=plan["action_id"],
                plan_sha256=plan["plan_sha256"],
                authorization_sha256=authorization["authorization_sha256"],
                stack_sha256=plan["identity"]["stack_sha256"],
                catalog_sha256=catalog_sha256,
                session_id=plan["action_id"],
                remote_arguments=[
                    plan["action_id"], plan["plan_sha256"],
                    authorization["authorization_sha256"],
                    plan["identity"]["stack_sha256"], catalog_sha256,
                ],
                issued_at=NOW + 1, expires_at=NOW + 121,
            )
            public = native_terminal_handle.publish(
                record, root=handles, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            claim_body = {
                "kind": public["kind"],
                "handle_id": public["handle_id"],
                "handle_sha256": public["handle_sha256"],
            }
            descriptor, _ = native_terminal_handle.claim_unlinked_fd(
                {
                    "schema": native_terminal_handle.CLAIM_SCHEMA,
                    **claim_body,
                    "request_sha256": native_terminal_handle.sha256(
                        claim_body
                    ),
                },
                root=handles, now=NOW + 2,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            )
            os.close(descriptor)
            completed = {
                **pending, "status": "succeeded", "completed_at": NOW + 5,
                "exit_status": 0,
                "stdout_sha256": hashlib.sha256(
                    backend.canonical(public)
                ).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            }
            receipt_path = receipts / f"{authorization['authorization_id']}.json"
            receipt_path.write_bytes(backend.canonical(completed))
            receipt_path.chmod(0o600)
            ticket_body = {
                "schema": backend.INTERACTIVE_HOST_TICKET_SCHEMA,
                "plan": plan, "authorization": authorization,
                "handle_id": plan["action_id"],
            }
            ticket = {
                **ticket_body, "ticket_sha256": backend.digest(ticket_body),
            }
            observed = backend.validate_interactive_resume_ticket(
                ticket, now=NOW + 1_000,
                expected_host_release_id="2" * 64,
                receipt_root=receipts, catalog_path=catalog_path,
                terminal_root=handles, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            self.assertEqual(observed[0], plan)
            self.assertEqual(observed[1], authorization)


if __name__ == "__main__":
    unittest.main()
