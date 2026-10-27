#!/usr/bin/env python3

import base64
import hashlib
import importlib.util
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).with_name("operator-authorization.py")
SPEC = importlib.util.spec_from_file_location("operator_authorization", SCRIPT)
AUTH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUTH)


class OperatorAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.uid = os.geteuid()
        self.identity = SimpleNamespace(pw_dir=str(self.home))
        self.pwd = mock.patch.object(AUTH.pwd, "getpwuid", return_value=self.identity)
        self.pwd.start()
        self.touchid_ui = mock.patch.object(AUTH, "DEFAULT_TOUCHID_UI", self.root / "missing-ui")
        self.touchid_ui.start()
        self.team_id = "ABCDE" + "12345"
        self.access_group = self.team_id + ".org.zebeth.SecureSandbox.AuthorizationUI"
        self.signing_policy = mock.patch.object(
            AUTH, "touchid_signing_policy", return_value={
                "access_group": self.access_group,
                "application_identifier": self.access_group,
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
                "team_id": self.team_id,
            },
        )
        self.signing_policy.start()

    def tearDown(self):
        self.signing_policy.stop()
        self.touchid_ui.stop()
        self.pwd.stop()
        self.temporary.cleanup()

    def parameters(self):
        return {"generation_id": "12345678-1234-4123-8123-123456789abc"}

    def test_manifest_signing_policy_is_exact_and_self_consistent(self):
        policy = {
            "access_group":self.access_group,
            "application_identifier":self.access_group,
            "bundle_id":"org.zebeth.SecureSandbox.AuthorizationUI",
            "team_id":self.team_id,
        }
        self.assertEqual(AUTH.manifest_signing_policy({
            "schema":"secure-sandbox-touchid-ui-bundle-v2",
            "signing_policy":policy,
        }), policy)
        broken = dict(policy, access_group=self.team_id + ".org.example.Other")
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signing_policy_invalid"):
            AUTH.manifest_signing_policy({
                "schema":"secure-sandbox-touchid-ui-bundle-v2",
                "signing_policy":broken,
            })

    def execution_parameters(self):
        fixtures = [{"path":"fixtures/input.txt", "bytes":4, "sha256":"a" * 64}]
        return {
            "schema":"secure-sandbox-execution-approval-request-v1",
            "approval_id":"11111111-1111-4111-8111-111111111111",
            "created_at":2_000_000_000, "expires_at":2_000_000_090,
            "run_id":"22222222-2222-4222-8222-222222222222",
            "session_id":"33333333-3333-4333-8333-333333333333",
            "source_id":"44444444-4444-4444-8444-444444444444",
            "source_manifest_sha256":"b" * 64, "code_sha256":"c" * 64,
            "fixture_manifest":fixtures,
            "fixture_manifest_sha256":hashlib.sha256(json.dumps(
                fixtures, separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
            "timeout_seconds":5, "runtime_image_id":"sha256:" + "d" * 64,
        }

    def test_prompt_binds_declared_identity_purpose_operation_nonce_and_digest(self):
        calls = []

        def runner(command, timeout):
            calls.append((command, timeout))
            if len(calls) == 1:
                return SimpleNamespace(returncode=0, stdout="Continue\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = AUTH.request_authorization(
            "Codex", "thread-7", "Begin reviewed PKI rotation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
            "pki-anchor-begin", self.parameters(), now=2_000_000_000, runner=runner,
        )
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 2)
        message = calls[0][0][-1]
        self.assertIn("Declared agent: Codex", message)
        self.assertIn("Declared session: thread-7", message)
        self.assertIn("Purpose: Begin reviewed PKI rotation", message)
        self.assertIn("Operation: pki-anchor-begin", message)
        self.assertRegex(message, r"One-time nonce: [0-9a-f-]{36}")
        self.assertRegex(message, r"Request digest: [0-9a-f]{64}")
        native_prompt = calls[1][0][-1]
        self.assertIn("Codex [thread-7]", native_prompt)
        self.assertIn("Nonce:", native_prompt)
        self.assertIn("Digest:", native_prompt)
        self.assertEqual(list(AUTH.request_directory(self.home).glob("*.json")), [])

    def test_cancel_prevents_native_authorization(self):
        calls = []

        def runner(command, timeout):
            calls.append(command)
            return SimpleNamespace(returncode=1, stdout="", stderr="cancelled")

        with self.assertRaisesRegex(AUTH.AuthorizationError, "operator_cancelled"):
            AUTH.request_authorization(
                "Claude", "session-1", "Begin PKI rotation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                "pki-anchor-begin", self.parameters(), runner=runner,
            )
        self.assertEqual(len(calls), 1)

    def test_native_ui_touchid_success_replaces_both_applescript_dialogs(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        calls = []

        def runner(command, timeout):
            calls.append((command, timeout))
            return SimpleNamespace(returncode=0, stdout="operation-output\n", stderr="")

        self.assertEqual(AUTH.request_authorization(
            "Codex", "touchid-live", "Touch ID acceptance",
            AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
            self.parameters(), runner=runner, native_ui_path=ui,
        ), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][0], str(ui))
        self.assertIn("--request-sha256", calls[0][0])
        self.assertNotIn("osascript", calls[0][0])

    def test_native_ui_password_fallback_is_explicit_and_skips_duplicate_preflight(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        calls = []

        def runner(command, timeout):
            calls.append(command)
            if len(calls) == 1:
                return SimpleNamespace(returncode=AUTH.TOUCHID_PASSWORD_FALLBACK_EXIT,
                                       stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        self.assertEqual(AUTH.request_authorization(
            "Codex", "password-fallback", "Fallback acceptance",
            AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
            self.parameters(), runner=runner, native_ui_path=ui,
        ), 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], str(ui))
        self.assertEqual(calls[1][0:2], ["/usr/bin/osascript", "-e"])
        self.assertIn("administrator privileges", calls[1][2])

    def test_execution_approval_rejects_password_fallback(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=AUTH.TOUCHID_PASSWORD_FALLBACK_EXIT, stdout="", stderr=""
        ))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "touchid_required"):
            AUTH.request_authorization(
                "Codex", "execution-approval", "Approve exact execution",
                AUTH.OPERATION_RESOURCES["execution-approval-sign"],
                "execution-approval-sign", self.execution_parameters(),
                now=2_000_000_000, runner=runner, native_ui_path=ui,
            )
        runner.assert_called_once()

    def test_execution_approval_parameters_are_content_bound(self):
        parameters = self.execution_parameters()
        AUTH.validate_parameters("execution-approval-sign", parameters, self.home)
        details = "\n".join(AUTH.operation_details({
            "operation":"execution-approval-sign", "parameters":parameters,
        }))
        self.assertIn("Source manifest SHA-256: " + "b" * 64, details)
        self.assertIn("fixtures/input.txt (4 bytes", details)
        changed = {**parameters, "fixture_manifest":[{**parameters["fixture_manifest"][0], "bytes":5}]}
        with self.assertRaisesRegex(AUTH.AuthorizationError, "fixture_manifest_hash_mismatch"):
            AUTH.validate_parameters("execution-approval-sign", changed, self.home)

    def test_execution_approval_key_exposes_only_public_half(self):
        key_root = self.root / "execution-approval"
        key_root.mkdir(mode=0o700)
        key = key_root / "id_ed25519"
        with mock.patch.object(AUTH.os, "chown"):
            value = AUTH.execution_approval_key_initialize(key_root, key, self.uid)
        self.assertEqual(value["status"], "ready")
        self.assertEqual(key_root.stat().st_mode & 0o777, 0o711)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key.with_suffix(".pub").stat().st_mode & 0o777, 0o644)

    def test_v2_der_parser_enforces_canonical_low_s_and_no_trailing_bytes(self):
        canonical = AUTH.encode_p256_der(1, 1)
        self.assertEqual(AUTH.parse_p256_der(canonical), (1, 1))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signature_invalid"):
            AUTH.parse_p256_der(AUTH.encode_p256_der(1, AUTH.P256_ORDER - 1))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signature_invalid"):
            AUTH.parse_p256_der(canonical + b"\x00")
        nonminimal = bytes.fromhex("300702020001020101")
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signature_invalid"):
            AUTH.parse_p256_der(nonminimal)

    def test_v2_spki_and_base64_are_exact(self):
        point = b"\x04" + b"\x01" * 64
        der = AUTH.P256_SPKI_PREFIX + point
        self.assertEqual(AUTH.validate_p256_spki(der), hashlib.sha256(der).hexdigest())
        encoded = __import__("base64").b64encode(der).decode("ascii")
        self.assertEqual(AUTH.canonical_base64_decode(encoded, "public", 256), der)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "public_invalid"):
            AUTH.canonical_base64_decode(encoded + "\n", "public", 256)

    def test_secure_enclave_migration_advances_floor_and_retires_software_key(self):
        root = self.root / "execution-approval-v2"
        root.mkdir(mode=0o711)
        generation = "55555555-5555-4555-8555-555555555555"
        transaction = "66666666-6666-4666-8666-666666666666"
        spki = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x01" * 64
        encoded = __import__("base64").b64encode(spki).decode("ascii")
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":transaction, "generation_id":generation,
            "generation_epoch":1, "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":"a" * 64, "research_release_id":"f" * 64,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepared", "created_at":100,
            "prepared_host_boot":"boot-old",
            "prepared_at":101, "public_key_spki_der_b64":encoded,
            "public_key_sha256":hashlib.sha256(spki).hexdigest(),
            "preparation_attestation_sha256":"b" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        def proof(status, expected_prior, journal):
            return {
                "schema":"secure-sandbox-execution-approval-transition-result-v2",
                "status":status, "transaction_id":transaction,
                "generation_id":generation, "generation_epoch":1,
                "previous_generation_id":None, "previous_generation_epoch":None,
                "operator_uid":self.uid, "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
                "public_key_sha256":pending["public_key_sha256"],
                "host_release_id":"a" * 64, "research_release_id":"f" * 64,
                "expected_prior_phase":expected_prior,
                "prior_record_sha256":None if expected_prior == "none" else "9" * 64,
                "journal_sha256":journal * 64, "phase_receipt_sha256":"8" * 64,
                "acceptance_binding_sha256":None,
            }
        fence = proof("fenced", "prepared", "c")
        activated = AUTH.execution_approval_migration_activate(
            transaction, fence, root=root, expected_uid=self.uid, now=102,
        )
        self.assertEqual(activated["status"], "host_activated")
        retried = AUTH.execution_approval_migration_activate(
            transaction, fence, root=root, expected_uid=self.uid, now=999,
        )
        self.assertEqual(retried, activated)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "migration_conflict"):
            AUTH.execution_approval_migration_activate(
                transaction, {**fence, "journal_sha256":"9" * 64},
                root=root, expected_uid=self.uid, now=999,
            )
        floor = AUTH.secure_enclave_floor(root, self.uid)
        self.assertEqual((floor["minimum_protocol"], floor["minimum_epoch"]), (2, 1))
        self.assertEqual((root / AUTH.EXECUTION_APPROVAL_PUBLIC.name).stat().st_mode & 0o777, 0o644)
        pending_after_activation = json.loads(
            (root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes()
        )
        pending_after_activation.update({
            "acceptance_attempt_number":3,
            "acceptance_binding_sha256":"7" * 64,
        })
        AUTH.atomic_receipt(
            root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending_after_activation
        )
        acceptance = proof("acceptance", "acceptance", "d")
        acceptance["acceptance_binding_sha256"] = "7" * 64
        verifier = {
            "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
            "status":"verified",
            "transaction_id":transaction, "generation_id":generation,
            "generation_epoch":1, "host_release_id":"a" * 64,
            "research_release_id":"f" * 64,
            "acceptance_binding_sha256":acceptance["acceptance_binding_sha256"],
            "prepared_host_boot_sha256":hashlib.sha256(b"boot-old").hexdigest(),
            "verified_host_boot_sha256":hashlib.sha256(b"boot-new").hexdigest(),
        }
        verifier["verifier_sha256"] = hashlib.sha256(
            AUTH.canonical_v2(verifier)
        ).hexdigest()
        AUTH.atomic_receipt(root / "acceptance-verifier.json", verifier)
        legacy_completion_directory = root / AUTH.EXECUTION_APPROVAL_COMPLETIONS.name
        legacy_completion_directory.mkdir(mode=0o700)
        unexpected = legacy_completion_directory / "unexpected"
        unexpected.write_bytes(b"fail closed")
        unexpected.chmod(0o600)
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"), \
                self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "execution_approval_completion_directory_untrusted",
                ):
            AUTH.execution_approval_migration_commit(
                transaction, acceptance, "e" * 64, verifier["verifier_sha256"],
                root=root, expected_uid=self.uid, now=103,
            )
        self.assertEqual(
            json.loads(
                (root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes()
            )["phase"],
            "committed",
        )
        unexpected.unlink()
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"):
            committed = AUTH.execution_approval_migration_commit(
                transaction, acceptance, "e" * 64, verifier["verifier_sha256"], root=root,
                expected_uid=self.uid, now=103,
            )
        self.assertEqual(committed["status"], "committed")
        self.assertEqual(
            legacy_completion_directory.stat().st_mode & 0o777, 0o711
        )
        completion = AUTH.read_public_completion_receipt(
            transaction, root=root, expected_uid=self.uid
        )
        self.assertEqual(completion["status"], "committed")
        self.assertEqual(
            completion["acceptance_verifier_sha256"], verifier["verifier_sha256"]
        )
        key = root / "id_ed25519"
        key.write_bytes(b"private")
        key.chmod(0o600)
        key.with_suffix(".pub").write_bytes(b"public")
        key.with_suffix(".pub").chmod(0o644)
        retired = AUTH.execution_approval_software_retire(
            transaction, root=root, key=key, expected_uid=self.uid, now=104,
        )
        self.assertEqual(retired["status"], "software_retired")
        self.assertFalse(key.exists())
        self.assertFalse(key.with_suffix(".pub").exists())
        completion = AUTH.read_public_completion_receipt(
            transaction, root=root, expected_uid=self.uid
        )
        self.assertEqual(completion["status"], "software_retired")
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"):
            retried_commit = AUTH.execution_approval_migration_commit(
                transaction, acceptance, "e" * 64, verifier["verifier_sha256"], root=root,
                expected_uid=self.uid, now=999,
            )
        self.assertEqual(retried_commit["status"], "committed")
        self.assertEqual(json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())["phase"],
                         "software_retired")
        # Simulate a crash after the prior verifier was archived and removed,
        # but before the terminal pending record was retired from its live name.
        history = root / "history"
        history.mkdir(mode=0o700)
        AUTH.atomic_receipt(
            history / f"{transaction}.acceptance-verifier.json", verifier
        )
        (root / "acceptance-verifier.json").unlink()
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root):
            rotated = AUTH.prepare_secure_enclave_challenge(
                {"invoking_uid":self.uid,
                 "request_id":"77777777-7777-4777-8777-777777777777",
                 "parameters":{"research_release_id":"f" * 64}}, "f" * 64,
                Path("/protected") / ("a" * 64), self.uid, now=105,
            )
        self.assertEqual(rotated["generation_epoch"], 2)
        self.assertNotEqual(rotated["generation_id"], generation)
        self.assertTrue((root / "history" / f"{transaction}.json").exists())
        self.assertTrue(
            (root / "history" / f"{transaction}.acceptance-verifier.json").exists()
        )
        self.assertFalse((root / "acceptance-verifier.json").exists())
        completion = AUTH.read_public_completion_receipt(
            transaction, root=root, expected_uid=self.uid
        )
        self.assertEqual(completion["status"], "software_retired")
        forbidden = {"code", "fixtures", "stdout", "stderr", "biometric", "private_key"}
        stack = [completion]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                self.assertTrue(forbidden.isdisjoint(item))
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        receipt_path = (
            root / AUTH.EXECUTION_APPROVAL_COMPLETIONS.name / f"{transaction}.json"
        )
        substituted = dict(completion)
        substituted["public_key_sha256"] = "0" * 64
        receipt_path.write_bytes(AUTH.canonical(substituted))
        receipt_path.chmod(0o644)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "execution_approval_completion_untrusted"
        ):
            AUTH.read_public_completion_receipt(
                transaction, root=root, expected_uid=self.uid
            )

    def test_host_authorizes_append_only_cas_bound_acceptance_attempts(self):
        root = self.root / "acceptance-authority"
        root.mkdir(mode=0o711)
        transaction = "11111111-1111-4111-8111-111111111111"
        generation = "22222222-2222-4222-8222-222222222222"
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "phase":"host_activated", "transaction_id":transaction,
            "generation_id":generation, "generation_epoch":3,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "public_key_sha256":"a" * 64, "operator_uid":self.uid,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "host_release_id":"b" * 64, "research_release_id":"c" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)

        def attempt(number, previous):
            return {
                "transaction_id":transaction, "generation_id":generation,
                "generation_epoch":3, "acceptance_attempt_id":str(uuid.uuid4()),
                "acceptance_attempt_number":number,
                "previous_acceptance_binding_sha256":previous,
                "run_id":str(uuid.uuid4()), "session_id":str(uuid.uuid4()),
                "source_id":str(uuid.uuid4()), "code_sha256":"d" * 64,
                "fixture_manifest_sha256":"e" * 64, "timeout_seconds":5,
                "runtime_image_id":"sha256:" + "f" * 64,
                "expires_at":2_000_000_300,
            }

        first_attempt = attempt(1, None)
        first = AUTH.execution_approval_authorize_acceptance(
            transaction, first_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_000,
        )
        self.assertEqual(first["acceptance_attempt_number"], 1)
        self.assertEqual(first, AUTH.execution_approval_authorize_acceptance(
            transaction, first_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_100,
        ))
        # Simulate power loss after the immutable attempt artifact was fsynced
        # but before the pending pointer advanced.  Redelivery must repair the
        # pointer without minting a different authorization timestamp.
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        self.assertEqual(first, AUTH.execution_approval_authorize_acceptance(
            transaction, first_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_400,
        ))
        expired = AUTH.execution_approval_authorize_acceptance(
            transaction, attempt(2, first["acceptance_binding_sha256"]),
            root=root, expected_uid=self.uid, now=2_000_000_400,
        )
        self.assertEqual(expired["status"], "not_issued_expired")
        self.assertFalse((root / "acceptance-attempts" / f"{transaction}.2.json").exists())
        with self.assertRaisesRegex(AUTH.AuthorizationError, "acceptance_attempt_conflict"):
            AUTH.execution_approval_authorize_acceptance(
                transaction, attempt(2, "0" * 64), root=root,
                expected_uid=self.uid, now=2_000_000_100,
            )
        second_attempt = attempt(2, first["acceptance_binding_sha256"])
        second = AUTH.execution_approval_authorize_acceptance(
            transaction, second_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_100,
        )
        self.assertEqual(second["acceptance_attempt_number"], 2)
        self.assertEqual(second["previous_acceptance_binding_sha256"],
                         first["acceptance_binding_sha256"])
        self.assertTrue((root / "acceptance-attempts" / f"{transaction}.1.json").exists())
        self.assertTrue((root / "acceptance-attempts" / f"{transaction}.2.json").exists())

    def test_acceptance_authorization_dispatches_to_protected_broker(self):
        transaction = "11111111-1111-4111-8111-111111111111"
        acceptance = {
            "transaction_id":transaction,
            "generation_id":"22222222-2222-4222-8222-222222222222",
            "generation_epoch":3,
            "acceptance_attempt_id":"33333333-3333-4333-8333-333333333333",
            "acceptance_attempt_number":1,
            "previous_acceptance_binding_sha256":None,
            "run_id":"44444444-4444-4444-8444-444444444444",
            "session_id":"55555555-5555-4555-8555-555555555555",
            "source_id":"66666666-6666-4666-8666-666666666666",
            "code_sha256":"a" * 64, "fixture_manifest_sha256":"b" * 64,
            "timeout_seconds":5, "runtime_image_id":"sha256:" + "c" * 64,
            "expires_at":2_000_000_300,
        }
        release = self.root / ("d" * 64)
        value = {
            "operation":"execution-approval-migration-authorize-acceptance",
            "parameters":{"transaction_id":transaction, "acceptance":acceptance},
        }
        command = AUTH.operation_command(value, release)
        self.assertEqual(command[:2], [
            str(release / "authorization_broker"),
            "execution-approval-migration-authorize-acceptance",
        ])
        self.assertEqual(command[2:4], ["--transaction-id", transaction])
        self.assertEqual(command[4], "--acceptance-json")
        self.assertEqual(json.loads(command[5]), acceptance)
        details = AUTH.operation_details(value)
        self.assertIn("Acceptance attempt: 1", details)
        self.assertIn("Attempt ID: " + acceptance["acceptance_attempt_id"], details)

    def test_acceptance_verifier_correlates_exact_host_receipt_and_is_idempotent(self):
        root = self.root / "acceptance-verifier"
        root.mkdir(mode=0o700)
        receipt_root = self.root / "authorization-receipts"
        receipt_root.mkdir(mode=0o700)
        transaction = "11111111-1111-4111-8111-111111111111"
        generation = "22222222-2222-4222-8222-222222222222"
        approval_id = "33333333-3333-4333-8333-333333333333"
        evidence = {
            "schema":"secure-sandbox-execution-approval-acceptance-evidence-v1",
            "status":"verified", "transaction_id":transaction,
            "generation_id":generation, "generation_epoch":3,
            "host_release_id":"a" * 64, "research_release_id":"b" * 64,
            "run_id":"44444444-4444-4444-8444-444444444444",
            "session_id":"55555555-5555-4555-8555-555555555555",
            "acceptance_attempt_id":"99999999-9999-4999-8999-999999999999",
            "acceptance_attempt_number":1,
            "approval_id":approval_id, "approval_attestation_sha256":"c" * 64,
            "research_receipt_id":"66666666-6666-4666-8666-666666666666",
            "research_receipt_sha256":"d" * 64,
            "consumed_marker_sha256":"e" * 64,
            "acceptance_binding_sha256":"f" * 64, "verified_at":100,
        }
        active = {
            "generation_id":generation, "generation_epoch":3,
            "public_key_sha256":"1" * 64,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
        }
        pending = {
            "phase":"host_activated", **{name:evidence[name] for name in (
                "transaction_id", "generation_id", "generation_epoch",
                "host_release_id", "research_release_id",
            )}, "prepared_host_boot":"boot-old",
            "acceptance_attempt_id":evidence["acceptance_attempt_id"],
            "acceptance_attempt_number":evidence["acceptance_attempt_number"],
            "acceptance_binding_sha256":evidence["acceptance_binding_sha256"],
        }
        receipt = {
            "schema":AUTH.RECEIPT_SCHEMA, "status":"succeeded", "outcome":"approved",
            "operation":"execution-approval-sign",
            "approval_id":approval_id, "approval_key_generation_id":generation,
            "approval_key_generation_epoch":3,
            "approval_public_key_sha256":"1" * 64,
            "approval_signature_algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "approval_attestation_sha256":"c" * 64,
        }
        AUTH.atomic_receipt(receipt_root / "77777777-7777-4777-8777-777777777777.json", receipt)
        AUTH.atomic_receipt(receipt_root / "88888888-8888-4888-8888-888888888888.json", {
            **receipt, "operation":"execution-approval-migration-verify-acceptance",
        })
        def read_state(path, _schema, _uid):
            return json.loads(path.read_bytes()) if path.parent == receipt_root else pending
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-old"), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=active), \
                mock.patch.object(AUTH, "read_secure_enclave_state", side_effect=read_state), \
                self.assertRaisesRegex(AUTH.AuthorizationError, "actual_host_reboot_required"):
            AUTH.execution_approval_acceptance_verify(
                evidence, root=root, receipt_root=receipt_root,
                expected_uid=self.uid, now=200,
            )
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=active), \
                mock.patch.object(AUTH, "read_secure_enclave_state", side_effect=read_state):
            result = AUTH.execution_approval_acceptance_verify(
                evidence, root=root, receipt_root=receipt_root,
                expected_uid=self.uid, now=200,
            )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["approval_id"], approval_id)
        self.assertEqual(result["host_receipt_sha256"],
                         hashlib.sha256(AUTH.canonical(receipt)).hexdigest())
        self.assertEqual(result["prepared_host_boot_sha256"],
                         hashlib.sha256(b"boot-old").hexdigest())
        self.assertEqual(result["verified_host_boot_sha256"],
                         hashlib.sha256(b"boot-new").hexdigest())
        self.assertRegex(result["verifier_sha256"], r"^[0-9a-f]{64}$")
        existing = json.loads((root / "acceptance-verifier.json").read_bytes())
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=active), \
                mock.patch.object(AUTH, "read_secure_enclave_state",
                                  side_effect=lambda path, schema, uid: (
                                      existing if path.name == "acceptance-verifier.json"
                                      else json.loads(path.read_bytes())
                                      if path.parent == receipt_root else pending)):
            self.assertEqual(AUTH.execution_approval_acceptance_verify(
                evidence, root=root, receipt_root=receipt_root,
                expected_uid=self.uid, now=999,
            ), existing)

        command = AUTH.operation_command({
            "operation":"execution-approval-migration-verify-acceptance",
            "parameters":{"research_evidence":evidence},
        }, Path("/protected/release"))
        self.assertEqual(command[:2], [
            "/protected/release/authorization_broker",
            "execution-approval-acceptance-verify",
        ])
        self.assertEqual(command[2], "--research-evidence-json")

    def test_protocol_v2_floor_never_falls_back_to_software_signing(self):
        root = self.root / "execution-approval-floor"
        root.mkdir(mode=0o711)
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_FLOOR.name, {
            "schema":"secure-sandbox-execution-approval-floor-v1",
            "minimum_protocol":2, "minimum_epoch":7, "updated_at":100,
        })
        value = {"operation":"execution-approval-sign", "invoking_uid":self.uid}
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=None), \
                self.assertRaisesRegex(
                    AUTH.AuthorizationError, "execution_approval_v2_authority_unavailable"
                ):
            AUTH.touchid_v2_challenge(
                value, "a" * 64, Path("/protected/") / ("b" * 64), self.uid,
            )
        key = root / "id_ed25519"
        with self.assertRaisesRegex(AUTH.AuthorizationError, "execution_approval_v1_retired"):
            AUTH.execution_approval_key_initialize(root, key, self.uid)
        self.assertFalse(key.exists())
        with self.assertRaisesRegex(AUTH.AuthorizationError, "execution_approval_v1_retired"):
            AUTH.sign_execution_approval(
                json.dumps(self.execution_parameters()),
                "88888888-8888-4888-8888-888888888888", "b" * 64,
                root=root, key=key, expected_uid=self.uid,
            )

    def test_secure_enclave_signing_rejects_nonconfigured_invoking_uid(self):
        active = {
            "generation_id":"11111111-1111-4111-8111-111111111111",
            "generation_epoch":2, "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval."
                              "11111111-1111-4111-8111-111111111111",
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":"a" * 64, "research_release_id":"b" * 64,
            "public_key_spki_der_b64":"c3BraQ==",
            "public_key_sha256":"c" * 64,
        }
        value = {
            "operation":"execution-approval-sign",
            "invoking_uid":self.uid + 1,
        }
        with mock.patch.object(
            AUTH, "active_secure_enclave_state", return_value=active
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "execution_approval_operator_mismatch"
        ):
            AUTH.touchid_v2_challenge(
                value, "d" * 64, Path("/protected") / ("a" * 64), self.uid
            )

    def test_prepared_retry_is_lookup_only_and_cannot_substitute_key(self):
        root = self.root / "prepared-retry"
        root.mkdir(mode=0o711)
        transaction = "99999999-9999-4999-8999-999999999999"
        generation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        spki = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x01" * 64
        encoded = __import__("base64").b64encode(spki).decode("ascii")
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":transaction, "generation_id":generation,
            "generation_epoch":2, "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":"a" * 64, "research_release_id":"b" * 64,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepared", "created_at":90, "prepared_at":91,
            "public_key_spki_der_b64":encoded,
            "public_key_sha256":hashlib.sha256(spki).hexdigest(),
            "preparation_attestation_sha256":"c" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        challenge = {
            "request_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "request_sha256":"d" * 64,
            **{name:pending[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "operator_uid",
                "application_tag", "access_group", "algorithm", "host_release_id",
                "research_release_id", "public_key_spki_der_b64", "public_key_sha256",
            )},
            "allow_creation":False,
        }
        attestation = {
            "schema":"secure-sandbox-execution-approval-preparation-v2",
            "authorization_request_id":challenge["request_id"],
            "authorization_request_sha256":challenge["request_sha256"],
            **{name:pending[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "operator_uid",
                "application_tag", "access_group", "algorithm", "host_release_id",
                "research_release_id", "public_key_spki_der_b64", "public_key_sha256",
            )},
            "prepared_at":100,
        }
        envelope = {
            "schema":"secure-sandbox-execution-approval-preparation-envelope-v2",
            "attestation":attestation,
            "signature_der_b64":__import__("base64").b64encode(AUTH.encode_p256_der(1, 1)).decode("ascii"),
        }
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(AUTH, "verify_p256_signature"):
            result = AUTH.verify_secure_enclave_preparation(
                envelope, challenge, now=100, expected_uid=self.uid,
            )
            self.assertEqual(result["public_key_sha256"], pending["public_key_sha256"])
            self.assertEqual(json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes()), pending)
            changed = dict(attestation)
            alternate = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x02" * 64
            changed["public_key_spki_der_b64"] = __import__("base64").b64encode(alternate).decode("ascii")
            changed["public_key_sha256"] = hashlib.sha256(alternate).hexdigest()
            with self.assertRaisesRegex(AUTH.AuthorizationError, "key_substitution"):
                AUTH.verify_secure_enclave_preparation(
                    {**envelope, "attestation":changed}, challenge,
                    now=100, expected_uid=self.uid,
                )

    def test_failed_prepare_rebinds_through_bounded_exact_rollback_chain(self):
        root = self.root / "prepare-release-rebind"
        root.mkdir(mode=0o711)
        old_release = "a" * 64
        new_release = "b" * 64
        research_release = "c" * 64
        generation = "11111111-1111-4111-8111-111111111111"
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "generation_id":generation, "generation_epoch":1,
            "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":old_release,
            "research_release_id":research_release,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepare_requested", "created_at":90,
            "prepared_host_boot":"boot-old",
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        value = {
            "operation":"execution-approval-key-init",
            "invoking_uid":self.uid,
            "request_id":"33333333-3333-4333-8333-333333333333",
            "parameters":{"research_release_id":research_release},
        }
        release = Path("/protected/releases") / new_release
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / old_release,
                ):
            challenge = AUTH.prepare_secure_enclave_challenge(
                value, "d" * 64, release, self.uid, now=100,
            )
            repeated = AUTH.prepare_secure_enclave_challenge(
                value, "d" * 64, release, self.uid, now=101,
            )
        self.assertTrue(challenge["allow_creation"])
        self.assertEqual(challenge["host_release_id"], new_release)
        self.assertEqual(challenge["application_tag"], pending["application_tag"])
        self.assertEqual(repeated["host_release_id"], new_release)
        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(rebound["host_prepare_release_rebindings"], [{
            "from_host_release_id":old_release,
            "to_host_release_id":new_release,
            "rebound_at":100,
        }])

        releases = ["e" * 64, "f" * 64]
        prior = new_release
        for offset, successor in enumerate(releases, start=2):
            with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                    mock.patch.object(
                        AUTH, "protected_release_directory",
                        return_value=Path("/protected/releases") / prior,
                    ):
                next_challenge = AUTH.prepare_secure_enclave_challenge(
                    value, "d" * 64, Path("/protected/releases") / successor,
                    self.uid, now=100 + offset,
                )
            self.assertEqual(next_challenge["host_release_id"], successor)
            prior = successor

        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / prior,
                ), self.assertRaisesRegex(AUTH.AuthorizationError, "migration_conflict"):
            AUTH.prepare_secure_enclave_challenge(
                value, "d" * 64, Path("/protected/releases") / ("9" * 64),
                self.uid, now=104,
            )

        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(len(rebound["host_prepare_release_rebindings"]), 3)
        self.assertEqual(rebound["host_prepare_release_rebindings"][-1], {
            "from_host_release_id":"e" * 64,
            "to_host_release_id":"f" * 64,
            "rebound_at":103,
        })

    def test_failed_prepare_rebind_migrates_legacy_record_and_requires_exact_previous(self):
        root = self.root / "prepare-release-legacy-rebind"
        root.mkdir(mode=0o711)
        old_release = "a" * 64
        current_release = "b" * 64
        next_release = "c" * 64
        research_release = "d" * 64
        generation = "11111111-1111-4111-8111-111111111111"
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "generation_id":generation, "generation_epoch":1,
            "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":current_release,
            "research_release_id":research_release,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepare_requested", "created_at":90,
            "prepared_host_boot":"boot-old",
            "host_prepare_release_rebinding":{
                "from_host_release_id":old_release,
                "to_host_release_id":current_release,
                "rebound_at":95,
            },
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        value = {
            "operation":"execution-approval-key-init",
            "invoking_uid":self.uid,
            "request_id":"33333333-3333-4333-8333-333333333333",
            "parameters":{"research_release_id":research_release},
        }
        release = Path("/protected/releases") / next_release
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / old_release,
                ), self.assertRaisesRegex(AUTH.AuthorizationError, "migration_conflict"):
            AUTH.prepare_secure_enclave_challenge(
                value, "e" * 64, release, self.uid, now=100,
            )
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / current_release,
                ):
            challenge = AUTH.prepare_secure_enclave_challenge(
                value, "e" * 64, release, self.uid, now=101,
            )
        self.assertEqual(challenge["host_release_id"], next_release)
        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertNotIn("host_prepare_release_rebinding", rebound)
        self.assertEqual(rebound["host_prepare_release_rebindings"], [
            pending["host_prepare_release_rebinding"],
            {
                "from_host_release_id":current_release,
                "to_host_release_id":next_release,
                "rebound_at":101,
            },
        ])

    def test_prepared_key_is_resigned_for_bounded_research_release_repair(self):
        root = self.root / "prepared-research-release-repair"
        root.mkdir(mode=0o711)
        host_release = "a" * 64
        old_research = "b" * 64
        new_research = "c" * 64
        generation = "11111111-1111-4111-8111-111111111111"
        spki = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x01" * 64
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "generation_id":generation, "generation_epoch":1,
            "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":host_release,
            "research_release_id":old_research,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepared", "created_at":90,
            "prepared_host_boot":"boot-old", "prepared_at":95,
            "public_key_spki_der_b64":base64.b64encode(spki).decode("ascii"),
            "public_key_sha256":hashlib.sha256(spki).hexdigest(),
            "preparation_attestation_sha256":"d" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        value = {
            "operation":"execution-approval-key-init",
            "invoking_uid":self.uid,
            "request_id":"33333333-3333-4333-8333-333333333333",
            "parameters":{"research_release_id":new_research},
        }
        release = Path("/protected/releases") / host_release
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root):
            challenge = AUTH.prepare_secure_enclave_challenge(
                value, "e" * 64, release, self.uid, now=100,
            )
        self.assertFalse(challenge["allow_creation"])
        self.assertEqual(challenge["research_release_id"], new_research)
        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(rebound["research_prepare_release_rebindings"], [{
            "from_research_release_id":old_research,
            "to_research_release_id":new_research,
            "rebound_at":100,
        }])
        attestation = {
            "schema":"secure-sandbox-execution-approval-preparation-v2",
            "authorization_request_id":challenge["request_id"],
            "authorization_request_sha256":challenge["request_sha256"],
            **{name:challenge[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "operator_uid",
                "application_tag", "access_group", "algorithm", "host_release_id",
                "research_release_id", "public_key_spki_der_b64", "public_key_sha256",
            )},
            "prepared_at":101,
        }
        envelope = {
            "schema":"secure-sandbox-execution-approval-preparation-envelope-v2",
            "attestation":attestation,
            "signature_der_b64":base64.b64encode(AUTH.encode_p256_der(1, 1)).decode("ascii"),
        }
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(AUTH, "verify_p256_signature"):
            result = AUTH.verify_secure_enclave_preparation(
                envelope, challenge, now=101, expected_uid=self.uid,
            )
        self.assertEqual(result["research_release_id"], new_research)
        repaired = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(repaired["prepared_at"], 101)
        self.assertEqual(
            repaired["preparation_attestation_sha256"],
            hashlib.sha256(AUTH.canonical_v2(attestation)).hexdigest(),
        )

    def test_native_ui_cancel_never_reaches_password_broker(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=AUTH.TOUCHID_CANCELLED_EXIT, stdout="", stderr=""
        ))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operator_cancelled"):
            AUTH.request_authorization(
                "Codex", "cancel-touchid", "Cancel acceptance",
                AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
                self.parameters(), runner=runner, native_ui_path=ui,
            )
        runner.assert_called_once()

    def test_touchid_ui_registration_binds_exact_bundle_and_fails_closed(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        (bundle / "Contents/Info.plist").write_bytes(b"plist")
        runner = mock.Mock(return_value=SimpleNamespace(returncode=0))
        AUTH.register_touchid_ui(executable, runner=runner)
        self.assertEqual(
            runner.call_args.args[0],
            [str(AUTH.LSREGISTER), "-f", str(bundle.resolve())],
        )
        self.assertEqual(runner.call_args.kwargs["timeout"], 15)
        runner.return_value = SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "touchid_ui_registration_failed"
        ):
            AUTH.register_touchid_ui(executable, runner=runner)

    def test_touchid_ui_launch_uses_launchservices_and_exact_result_channel(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        request_id = "11111111-1111-4111-8111-111111111111"
        request_path = self.root / f"{request_id}.json"
        request_value = {"operation":"pki-anchor-begin"}
        request_path.write_bytes(AUTH.canonical(request_value))
        request_path.chmod(0o600)
        digest = hashlib.sha256(AUTH.canonical(request_value)).hexdigest()

        def launch(command, timeout):
            stdout_path = Path(command[command.index("-o") + 1])
            stderr_path = Path(command[command.index("--stderr") + 1])
            result_path = Path(command[command.index("--result-path") + 1])
            stdout_path.write_text("broker-output\n", encoding="utf-8")
            stderr_path.write_text("broker-diagnostic\n", encoding="utf-8")
            result_path.write_bytes(AUTH.canonical({
                "request_id": request_id,
                "request_sha256": digest,
                "schema": "secure-sandbox-touchid-ui-result-v1",
                "status": AUTH.TOUCHID_CANCELLED_EXIT,
            }))
            result_path.chmod(0o600)
            return subprocess.CompletedProcess(command, 0, "", "")

        with (mock.patch.object(AUTH, "register_touchid_ui") as register,
              mock.patch.object(AUTH, "run_process", side_effect=launch) as run):
            result = AUTH.run_touchid_app(
                executable, request_path, digest, self.root / "broker.sock", 180, self.uid,
            )
        register.assert_called_once_with(executable)
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["/usr/bin/open", "-n", "-W", "-F"])
        self.assertIn("--result-path", command)
        self.assertEqual(result.returncode, AUTH.TOUCHID_CANCELLED_EXIT)
        self.assertEqual(result.stdout, "broker-output\n")
        self.assertEqual(result.stderr, "broker-diagnostic\n")
        self.assertFalse(any(self.root.glob(f".{request_id}.*")))

    def test_exact_legacy_ui_allows_only_bounded_schema_checked_successes(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        request_id = "22222222-2222-4222-8222-222222222222"
        request_path = self.root / f"{request_id}.json"
        request_value = {
            "operation":"execution-approval-migration-authorize-acceptance",
        }
        request_path.write_bytes(AUTH.canonical(request_value))
        request_path.chmod(0o600)
        digest = hashlib.sha256(AUTH.canonical(request_value)).hexdigest()
        (self.root / "manifest.json").write_text(json.dumps({
            "payloads": {
                "authorization_ui_bundle": AUTH.LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256,
            },
        }), encoding="utf-8")

        def launch(command, timeout):
            Path(command[command.index("-o") + 1]).write_text(
                json.dumps({
                    "schema": "secure-sandbox-execution-approval-acceptance-authorization-v1",
                    "status": "authorized",
                }) + "\n", encoding="utf-8",
            )
            Path(command[command.index("--stderr") + 1]).write_text("", encoding="utf-8")
            # Successful broker execution consumes the one-time request before
            # the predecessor UI exits and before the compatibility parser runs.
            request_path.unlink()
            return subprocess.CompletedProcess(command, 0, "", "")

        with (mock.patch.object(AUTH, "register_touchid_ui"),
              mock.patch.object(AUTH, "run_process", side_effect=launch),
              mock.patch.object(AUTH, "protected_release_directory", return_value=self.root)):
            result = AUTH.run_touchid_app(
                executable, request_path, digest, self.root / "broker.sock", 180, self.uid,
            )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any(self.root.glob(f".{request_id}.*")))

        allowed = {
            "execution-approval-migration-authorize-acceptance": {
                "schema":"secure-sandbox-execution-approval-acceptance-authorization-v1",
                "status":"not_issued_expired",
            },
            "execution-approval-migration-verify-acceptance": {
                "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
                "status":"verified",
            },
            "execution-approval-sign": {
                "schema":AUTH.EXECUTION_APPROVAL_V2_ENVELOPE,
                "attestation":{}, "signature_der_b64":"MEUCIQ==",
            },
            "execution-approval-migration-commit": {
                "schema":"secure-sandbox-execution-approval-migration-result-v2",
                "status":"committed",
            },
            "host-controller-install": {
                "schema":"secure-sandbox-host-controller-release-v1",
                "status":"deployed", "release_id":"c" * 64,
            },
        }
        for operation, output in allowed.items():
            self.assertTrue(AUTH.legacy_launchservices_success(operation, output))
        self.assertFalse(AUTH.legacy_launchservices_success(
            "execution-approval-software-retire",
            {"schema":"secure-sandbox-execution-approval-migration-result-v2",
             "status":"software_retired"},
        ))
        self.assertFalse(AUTH.legacy_launchservices_success(
            "execution-approval-sign", {"schema":AUTH.EXECUTION_APPROVAL_V2_ENVELOPE},
        ))
        rejection_cases = [
            ("execution-approval-migration-authorize-acceptance", {
                "schema":"secure-sandbox-execution-approval-acceptance-authorization-v1",
                "status":"cancelled",
            }),
            ("execution-approval-migration-verify-acceptance", {
                "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
                "status":"rejected",
            }),
            ("execution-approval-migration-commit", {
                "schema":"secure-sandbox-execution-approval-migration-result-v2",
                "status":"software_retired",
            }),
            ("host-controller-install", {
                "schema":"secure-sandbox-host-controller-release-v1",
                "status":"deployed", "release_id":"not-a-digest",
            }),
            ("execution-approval-software-retire", {
                "schema":"secure-sandbox-execution-approval-migration-result-v2",
                "status":"software_retired",
            }),
        ]
        for operation, output in rejection_cases:
            with self.subTest(operation=operation, output=output):
                self.assertFalse(AUTH.legacy_launchservices_success(operation, output))

    def test_exact_legacy_ui_preserves_only_structured_broker_rejection(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        request_id = "33333333-3333-4333-8333-333333333333"
        request_path = self.root / f"{request_id}.json"
        request_value = {"operation":"execution-approval-migration-commit"}
        request_path.write_bytes(AUTH.canonical(request_value))
        request_path.chmod(0o600)
        digest = hashlib.sha256(AUTH.canonical(request_value)).hexdigest()
        (self.root / "manifest.json").write_text(json.dumps({
            "payloads": {
                "authorization_ui_bundle": AUTH.LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256,
            },
        }), encoding="utf-8")
        rejection = {
            "error":"execution_approval_acceptance_verifier_invalid",
            "schema":AUTH.SCHEMA,
            "status":"rejected",
        }

        def launch(command, timeout):
            Path(command[command.index("-o") + 1]).write_text("", encoding="utf-8")
            Path(command[command.index("--stderr") + 1]).write_text(
                json.dumps(rejection, sort_keys=True) + "\n", encoding="utf-8",
            )
            request_path.unlink()
            return subprocess.CompletedProcess(command, 0, "", "")

        with (mock.patch.object(AUTH, "register_touchid_ui"),
              mock.patch.object(AUTH, "run_process", side_effect=launch),
              mock.patch.object(AUTH, "protected_release_directory", return_value=self.root)):
            result = AUTH.run_touchid_app(
                executable, request_path, digest, self.root / "broker.sock", 180, self.uid,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr), rejection)
        self.assertFalse(any(self.root.glob(f".{request_id}.*")))
        self.assertTrue(AUTH.legacy_launchservices_rejection(rejection))
        self.assertFalse(AUTH.legacy_launchservices_rejection({
            **rejection, "status":"committed",
        }))
        self.assertFalse(AUTH.legacy_launchservices_rejection({
            **rejection, "error":"error with spaces",
        }))

    def test_concurrent_requests_fail_closed_before_second_prompt(self):
        entered = threading.Event()
        release = threading.Event()
        first_result = []

        def slow_runner(command, timeout):
            if "SecureSandbox Authorization" in command[2]:
                entered.set()
                release.wait(2)
                return SimpleNamespace(returncode=0, stdout="Continue\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        def first():
            first_result.append(AUTH.request_authorization(
                "Codex", "session-a", "First operation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                "pki-anchor-begin", self.parameters(), runner=slow_runner,
            ))

        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(entered.wait(1))
        with mock.patch.object(AUTH, "LOCK_TIMEOUT_SECONDS", 0.1):
            with self.assertRaisesRegex(AUTH.AuthorizationError, "authorization_request_in_progress"):
                AUTH.request_authorization(
                    "Claude", "session-b", "Second operation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                    "pki-anchor-begin", self.parameters(), runner=slow_runner,
                )
        release.set()
        thread.join(2)
        self.assertEqual(first_result, [0])

    def test_separate_process_request_lock_prevents_any_second_prompt(self):
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        lock_path = directory / "active.lock"
        holder = subprocess.Popen(
            [
                sys.executable, "-c",
                "import fcntl,os,sys; "
                "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600); "
                "fcntl.flock(fd,fcntl.LOCK_EX); print('locked',flush=True); sys.stdin.readline()",
                str(lock_path),
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            runner = mock.Mock()
            with mock.patch.object(AUTH, "LOCK_TIMEOUT_SECONDS", 0.1):
                with self.assertRaisesRegex(
                    AUTH.AuthorizationError, "authorization_request_in_progress"
                ):
                    AUTH.request_authorization(
                        "Claude", "separate-process", "Second operation",
                        AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                        "pki-anchor-begin", self.parameters(), runner=runner,
                    )
            runner.assert_not_called()
        finally:
            assert holder.stdin is not None
            holder.stdin.write("\n")
            holder.stdin.flush()
            holder.communicate(timeout=3)

    def test_parameter_allowlist_rejects_arbitrary_command(self):
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_not_allowed"):
            AUTH.validate_parameters("shell", {"command": "id"}, self.home)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_parameters_invalid"):
            AUTH.validate_parameters(
                "pki-anchor-begin", {**self.parameters(), "command": "id"}, self.home
            )
        parameters = {
            "repo": str(self.home / "repo"),
            "state_root": str(self.home / "Library/Application Support/SecureSandbox/controller-state"),
            "expected_source_release_id": "a" * 64,
        }
        (self.home / "repo").mkdir()
        AUTH.validate_parameters("host-controller-install", parameters, self.home)
        install_value = {
            "declared_agent": "Codex", "declared_session": "thread-7",
            "purpose": "Publish", "resource": "host controller",
            "operation": "host-controller-install", "parameters": parameters,
            "request_id": "12345678-1234-4123-8123-123456789abc", "expires_at": 123,
        }
        self.assertIn("Expected release: " + "a" * 64,
                      AUTH.preflight_message(install_value, "b" * 64))
        command = AUTH.operation_command(install_value, Path("/protected/release"))
        self.assertEqual(command[:2], ["/usr/bin/python3", "-I"])
        self.assertEqual(command[command.index("--expected-source-release-id") + 1], "a" * 64)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "expected_source_release_id_invalid"):
            AUTH.validate_parameters(
                "host-controller-install",
                {**parameters, "expected_source_release_id": "b" * 63}, self.home,
            )

    def test_authorization_probe_is_side_effect_free_and_strictly_typed(self):
        challenge = "12345678-1234-4123-8123-123456789abc"
        AUTH.validate_parameters("authorization-probe", {"challenge": challenge}, self.home)
        value = {"operation": "authorization-probe", "parameters": {"challenge": challenge}}
        self.assertEqual(
            AUTH.operation_command(value, Path("/protected/release")),
            ["/usr/bin/printf", "touchid-authorization-probe:%s\\n", challenge],
        )
        self.assertEqual(AUTH.operation_details(value), [f"Acceptance challenge: {challenge}"])
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_parameters_invalid"):
            AUTH.validate_parameters(
                "authorization-probe", {"challenge": challenge, "command": "id"}, self.home
            )

    def test_all_operation_parameters_are_rendered_for_the_operator(self):
        base = {
            "declared_agent": "Codex", "declared_session": "thread-7", "purpose": "Review",
            "request_id": "12345678-1234-4123-8123-123456789abc", "expires_at": 123,
        }
        cases = [
            ("host-controller-rollback", {
                "repo": str(self.home), "state_root": str(self.home / "state"),
                "release_id": "a" * 64,
            }, "Target release: " + "a" * 64),
            ("host-controller-migrate-launcher", {
                "repo": str(self.home), "state_root": str(self.home / "state"),
                "expected_installed_sha256": "b" * 64,
                "expected_replacement_sha256": "c" * 64,
            }, "Replacement launcher: " + "c" * 64),
            ("pki-anchor-begin", self.parameters(), "PKI generation: 12345678"),
            ("pki-anchor-commit", {
                "generation_id": "12345678-1234-4123-8123-123456789abc",
                "manifest_sha256": "d" * 64, "expected_current": None,
            }, "Manifest SHA-256: " + "d" * 64),
        ]
        for operation, parameters, expected in cases:
            value = {**base, "operation": operation, "parameters": parameters,
                     "resource": AUTH.OPERATION_RESOURCES[operation]}
            self.assertIn(expected, AUTH.preflight_message(value, "e" * 64))

    def test_vm_displayed_component_hashes_are_forwarded_to_coordinator(self):
        parameters = {
            "repo": str(self.home.resolve()), "plan_sha256": "a" * 64,
            "prlctl_sha256": "b" * 64,
            "installer_sha256": AUTH.AUTOINSTALL_INSTALLER_SHA256,
            "seed_sha256": {"gateway": "c" * 64, "research": "d" * 64, "target": "e" * 64},
        }
        AUTH.validate_parameters("vm-reprovision", parameters, self.home)
        value = {"operation": "vm-reprovision", "parameters": parameters, "invoking_uid": self.uid}
        command = AUTH.operation_command(value, Path("/protected/release"))
        expected_flags = {
            "--expected-plan-sha256": parameters["plan_sha256"],
            "--expected-prlctl-sha256": parameters["prlctl_sha256"],
            "--expected-installer-sha256": parameters["installer_sha256"],
            "--expected-seed-gateway-sha256": parameters["seed_sha256"]["gateway"],
            "--expected-seed-research-sha256": parameters["seed_sha256"]["research"],
            "--expected-seed-target-sha256": parameters["seed_sha256"]["target"],
        }
        for flag, expected in expected_flags.items():
            self.assertEqual(command[command.index(flag) + 1], expected)

    def test_legacy_preservation_request_is_strictly_typed_and_forwarded(self):
        uuid_value = "{00000000-0000-4000-8000-000000000001}"
        parameters = {
            "repo": str(self.home.resolve()), "generation": "20261021T040946Z",
            "plan_operation": "preserve", "recovery_transaction_sha256": None,
            "plan_sha256": "a" * 64, "prlctl_sha256": "b" * 64,
            "protected_control_client_sha256": "c" * 64,
            "protected_ssh_config_sha256": "d" * 64,
            "legacy_vm_uuid": {role: uuid_value for role in ("gateway", "research", "target")},
            "source_tree_sha256": {role: "e" * 64 for role in ("gateway", "research", "target")},
            "transport_vm_uuid": {
                "SecureSandbox-Gateway": uuid_value,
                "SecureSandbox-Research": uuid_value,
            },
            "tools": {name: "f" * 64 for name in AUTH.PRESERVATION_TOOL_NAMES},
        }
        AUTH.validate_parameters("vm-preserve-legacy", parameters, self.home)
        value = {"operation": "vm-preserve-legacy", "parameters": parameters,
                 "invoking_uid": self.uid}
        command = AUTH.operation_command(value, Path("/protected/release"))
        self.assertEqual(command[command.index("--generation") + 1], parameters["generation"])
        self.assertEqual(command[command.index("--expected-plan-sha256") + 1], parameters["plan_sha256"])
        details = "\n".join(AUTH.operation_details(value))
        self.assertIn(parameters["legacy_vm_uuid"]["research"], details)
        self.assertIn(
            "Protected control client SHA-256: " + parameters["protected_control_client_sha256"],
            details,
        )
        self.assertIn(
            "Protected SSH configuration SHA-256: " + parameters["protected_ssh_config_sha256"],
            details,
        )
        self.assertIn(
            "Migration planner SHA-256: " + parameters["tools"]["preservation_planner"],
            details,
        )
        self.assertIn(
            "Migration executor SHA-256: " + parameters["tools"]["preservation_executor"],
            details,
        )
        self.assertIn(
            "Migration tool-set SHA-256: "
            + hashlib.sha256(AUTH.canonical(parameters["tools"])).hexdigest(),
            details,
        )
        self.assertIn("Legacy disk-chain content trees:", details)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_parameters_invalid"):
            AUTH.validate_parameters(
                "vm-preserve-legacy", {**parameters, "command": "id"}, self.home
            )
        self.assertGreater(AUTH.authorization_execution_timeout("vm-preserve-legacy"), 8 * 60 * 60)

    def test_visual_control_characters_are_rejected(self):
        for value in ("line\nbreak", "right-to-left\u202eoverride", "delete\x7f"):
            with self.assertRaisesRegex(AUTH.AuthorizationError, "purpose_invalid"):
                AUTH.clean_text(value, "purpose", AUTH.MAX_PURPOSE)

    def test_expired_and_tampered_requests_are_rejected(self):
        request_id = "12345678-1234-4123-8123-123456789abc"
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id, "created_at": 100,
            "expires_at": 100 + AUTH.REQUEST_TTL_SECONDS, "invoking_uid": self.uid,
            "declared_agent": "Codex", "declared_session": "session-1",
            "identity_evidence": "operator-declared", "purpose": "Rotate PKI",
            "resource": AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "operation": "pki-anchor-begin",
            "parameters": self.parameters(),
        }
        with self.assertRaisesRegex(AUTH.AuthorizationError, "request_expired"):
            AUTH.verify_request(value, self.uid, request_id, 1000)
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        path = directory / f"{request_id}.json"
        AUTH.write_request(path, value)
        expected = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        path.write_bytes(path.read_bytes() + b" ")
        path.chmod(0o600)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "request_digest_mismatch"):
            AUTH.read_request(path, self.uid, expected)

    def make_release(self):
        release_root = self.root / "installed/releases"
        release_root.mkdir(parents=True)
        payloads = {}
        bundle_contents = {
            "Contents/Info.plist": b"plist\n",
            "Contents/MacOS/SecureSandboxAuthorizationUI": b"signed-ui\n",
            "Contents/PkgInfo": b"APPL????",
            "Contents/_CodeSignature/CodeResources": b"signature\n",
            "Contents/embedded.provisionprofile": b"profile\n",
        }
        bundle_manifest = {
            "bundle": AUTH.TOUCHID_UI_APP_NAME,
            "files": {
                name: {
                    "mode": 0o555 if name == AUTH.TOUCHID_UI_EXECUTABLE.as_posix() else 0o444,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
                for name, data in bundle_contents.items()
            },
            "schema": "secure-sandbox-touchid-ui-bundle-v2",
            "signing_policy": {
                "access_group": self.access_group,
                "application_identifier": self.access_group,
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
                "team_id": self.team_id,
            },
        }
        contents = {
            "authorization_broker": b"#!/usr/bin/python3\n",
            "authorization_service": b"plist\n",
            "authorization_ui_bundle": AUTH.canonical(bundle_manifest),
            "authorization_ui_sources": b"{}\n",
            "control_client": b"#!/usr/bin/python3\n# client\n",
            "controller": b"#!/bin/bash\n",
            "gpgv": b"test-gpgv\n",
            "installer_verifier": b"#!/usr/bin/python3\n# verifier\n",
            "release_manager": b"#!/usr/bin/python3\n",
            "pki_anchor": b"#!/usr/bin/python3\n",
            "seed_verifier": b"#!/usr/bin/python3\n# seed\n",
            "seed_gateway": b"gateway-seed\n",
            "seed_research": b"research-seed\n",
            "seed_target": b"target-seed\n",
            "ssh_config": b"Host test\n",
            "vm_maintenance": b"#!/usr/bin/python3\n# maintenance\n",
        }
        for name, data in contents.items():
            payloads[name] = hashlib.sha256(data).hexdigest()
        release_id = hashlib.sha256(b"".join(
            f"{name}\0{payloads[name]}\n".encode("ascii") for name in sorted(payloads)
        )).hexdigest()
        release = release_root / release_id
        release.mkdir()
        for name, data in contents.items():
            (release / name).write_bytes(data)
            (release / name).chmod(AUTH.EXPECTED_RELEASE_MODES[name])
        bundle = release / AUTH.TOUCHID_UI_APP_NAME
        for relative, data in bundle_contents.items():
            path = bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(bundle_manifest["files"][relative]["mode"])
        for directory in sorted(
            (path for path in bundle.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts), reverse=True,
        ):
            directory.chmod(0o555)
        bundle.chmod(0o555)
        manifest = {"schema": "secure-sandbox-host-controller-release-v1",
                    "release_id": release_id, "payloads": payloads}
        (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (release / "manifest.json").chmod(0o444)
        release.chmod(0o555)
        return release

    def make_request(self, now=2_000_000_000):
        request_id = "12345678-1234-4123-8123-123456789abc"
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id, "created_at": now,
            "expires_at": now + AUTH.REQUEST_TTL_SECONDS, "invoking_uid": self.uid,
            "declared_agent": "Codex", "declared_session": "thread-7",
            "identity_evidence": "operator-declared", "purpose": "Begin PKI rotation",
            "resource": AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "operation": "pki-anchor-begin",
            "parameters": self.parameters(),
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        path = directory / f"{request_id}.json"
        AUTH.write_request(path, value)
        return request_id, value, hashlib.sha256(AUTH.canonical(value)).hexdigest(), path

    def test_root_execution_is_at_most_once_and_receipt_is_content_free(self):
        release = self.make_release()
        request_id, value, request_sha256, request_path = self.make_request()
        receipt_root = self.root / "receipts"
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(AUTH, "run_privileged_operation", return_value=completed) as run:
            status = AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=2_000_000_000,
                broker_path=release / "authorization_broker", expected_root_uid=self.uid,
            )
        self.assertEqual(status, 0)
        command = run.call_args.args[0]
        self.assertEqual(command[0], str(release.resolve() / "pki_anchor"))
        self.assertNotIn("/bin/sh", command)
        receipt = json.loads((receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["authorization_method"], "administrator-password")
        self.assertEqual(receipt["request_sha256"], request_sha256)
        self.assertNotIn("parameters", receipt)
        self.assertNotIn("stdout", receipt)
        AUTH.write_request(request_path, value)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "request_already_consumed"):
            AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=2_000_000_000,
                broker_path=release / "authorization_broker", expected_root_uid=self.uid,
            )

    def test_short_writes_cannot_truncate_receipts(self):
        release = self.make_release()
        request_id, _value, request_sha256, _request_path = self.make_request()
        receipt_root = self.root / "receipts"
        completed = SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")
        real_write = os.write

        def short_write(descriptor, data):
            return real_write(descriptor, data[:7])

        with (mock.patch.object(AUTH, "run_privileged_operation", return_value=completed),
              mock.patch.object(AUTH.os, "write", side_effect=short_write)):
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=2_000_000_000,
                broker_path=release / "authorization_broker", expected_root_uid=self.uid,
            ), 0)
        receipt = json.loads((receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["stdout_sha256"], hashlib.sha256(b"ok").hexdigest())

    def test_secure_enclave_migration_receipt_is_content_free_and_cas_bound(self):
        release = self.make_release()
        request_id = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        transaction_id = "fedcbafe-dcba-4fed-8cba-fedcbafedcba"
        value = {
            "schema":AUTH.SCHEMA, "request_id":request_id,
            "created_at":2_000_000_000,
            "expires_at":2_000_000_000 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid":self.uid, "declared_agent":"Codex",
            "declared_session":"secure-enclave-ddd",
            "identity_evidence":"operator-declared",
            "purpose":"Prepare Secure Enclave authority",
            "resource":AUTH.OPERATION_RESOURCES["execution-approval-key-init"],
            "operation":"execution-approval-key-init",
            "parameters":{"research_release_id":"f" * 64},
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        migration = {
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"prepared", "transaction_id":transaction_id,
            "generation_id":"55555555-5555-4555-8555-555555555555",
            "generation_epoch":1, "public_key_sha256":"a" * 64,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "operator_uid":self.uid, "host_release_id":"b" * 64,
            "research_release_id":"f" * 64,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "preparation_attestation_sha256":"c" * 64,
        }
        completed = SimpleNamespace(
            returncode=0, stdout=AUTH.canonical_v2(migration), stderr=b""
        )
        receipt_root = self.root / "migration-receipts"
        with mock.patch.object(AUTH, "run_privileged_operation", return_value=completed):
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_000, broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
            ), 0)
        receipt = json.loads((receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["migration_phase"], "prepared")
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["research_release_id"], "f" * 64)
        self.assertEqual(receipt["preparation_attestation_sha256"], "c" * 64)
        self.assertNotIn("parameters", receipt)
        self.assertNotIn("public_key_spki_der_b64", receipt)

    def test_release_identity_tampering_is_rejected(self):
        release = self.make_release()
        manifest_path = release / "manifest.json"
        release.chmod(0o755)
        manifest_path.chmod(0o644)
        manifest = json.loads(manifest_path.read_text())
        manifest["release_id"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o444)
        release.chmod(0o555)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "authorization_release_identity_invalid"):
            AUTH.protected_release_directory(release / "authorization_broker", self.uid)

    def test_timeout_terminates_the_dialog_process_group(self):
        started = time.monotonic()
        with self.assertRaisesRegex(AUTH.AuthorizationError, "authorization_dialog_timeout"):
            AUTH.run_process(["/bin/sleep", "5"], 0.05)
        self.assertLess(time.monotonic() - started, 2)

    def test_timeout_terminates_privileged_operation_group(self):
        started = time.monotonic()
        result = AUTH.run_privileged_operation(["/bin/sleep", "5"], 0.05)
        self.assertEqual(result.returncode, 124)
        self.assertIn(b"privileged_operation_timeout", result.stderr)
        self.assertLess(time.monotonic() - started, 2)

    def test_touchid_protocol_is_canonical_bounded_and_exact(self):
        client, server = socket.socketpair()
        try:
            value = {
                "request_id": "12345678-1234-4123-8123-123456789abc",
                "request_sha256": "a" * 64,
                "schema": AUTH.TOUCHID_SCHEMA,
            }
            client.sendall(AUTH.canonical(value))
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(AUTH.read_touchid_message(server), value)
        finally:
            client.close()
            server.close()

    def test_touchid_cancellation_receipt_is_content_free_and_generation_bound(self):
        receipt_root = self.root / "receipts"
        parameters = self.execution_parameters()
        value = {
            "schema":AUTH.SCHEMA,
            "request_id":"88888888-8888-4888-8888-888888888888",
            "declared_agent":"Codex", "declared_session":"cancel-v2",
            "purpose":"Cancel exact execution",
            "resource":AUTH.OPERATION_RESOURCES["execution-approval-sign"],
            "operation":"execution-approval-sign", "parameters":parameters,
        }
        challenge = {
            "mode":"secure-enclave-sign",
            "generation_id":"99999999-9999-4999-8999-999999999999",
            "generation_epoch":4,
            "public_key_sha256":"a" * 64,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
        }
        AUTH.record_touchid_cancellation(
            value, "b" * 64, challenge, receipt_root, self.uid, now=123,
        )
        receipt = json.loads((receipt_root / f"{value['request_id']}.json").read_text())
        self.assertEqual(receipt["status"], "cancelled")
        self.assertEqual(receipt["outcome"], "cancelled")
        self.assertEqual(receipt["approval_id"], parameters["approval_id"])
        self.assertEqual(receipt["approval_key_generation_epoch"], 4)
        self.assertNotIn("parameters", receipt)
        self.assertNotIn("code_sha256", receipt)

    def test_touchid_connection_binds_kernel_peer_and_records_method(self):
        client, server = socket.socketpair()
        value = {
            "request_id": "12345678-1234-4123-8123-123456789abc",
            "request_sha256": "b" * 64,
            "schema": AUTH.TOUCHID_SCHEMA,
        }
        client.sendall(AUTH.canonical(value))
        client.shutdown(socket.SHUT_WR)

        def execute(uid, request_id, request_sha256, **kwargs):
            self.assertEqual(uid, self.uid)
            self.assertEqual(request_id, value["request_id"])
            self.assertEqual(request_sha256, value["request_sha256"])
            self.assertEqual(kwargs["authorization_method"], "touch-id")
            kwargs["result_capture"].append(SimpleNamespace(
                returncode=0, stdout=b"ok\n", stderr=b""
            ))
            return 0

        try:
            with (mock.patch.object(AUTH, "peer_audit_identity",
                                    return_value=(self.uid, b"x" * 32, Path("/signed-ui"))),
                  mock.patch.object(AUTH, "protected_release_directory", return_value=self.root),
                  mock.patch.object(AUTH, "verify_touchid_peer") as verify,
                  mock.patch.object(AUTH, "execute_request", side_effect=execute)):
                restart = AUTH.handle_touchid_connection(server, broker_path=self.root / "broker",
                                                         expected_root_uid=self.uid,
                                                         receipt_root=self.root / "receipts")
            response = client.recv(1024)
            magic, status, stdout_size, stderr_size = struct.unpack("!4sIII", response[:16])
            self.assertEqual((magic, status, stdout_size, stderr_size), (b"SSAR", 0, 3, 0))
            self.assertEqual(response[16:], b"ok\n")
            self.assertFalse(restart)
            verify.assert_called_once_with(Path("/signed-ui"), self.root, self.uid)
        finally:
            client.close()
            server.close()

    def test_touchid_connection_rejects_different_peer_before_protocol_or_execution(self):
        client, server = socket.socketpair()
        client.shutdown(socket.SHUT_WR)
        try:
            with (mock.patch.object(
                      AUTH, "peer_audit_identity",
                      return_value=(self.uid, b"x" * 32, Path("/different/helper")),
                  ), mock.patch.object(
                      AUTH, "protected_release_directory", return_value=self.root,
                  ), mock.patch.object(
                      AUTH, "verify_touchid_peer",
                      side_effect=AUTH.AuthorizationError(
                          "touchid_peer_identity_mismatch"
                      ),
                  ) as verify, mock.patch.object(
                      AUTH, "execute_request"
                  ) as execute):
                restart = AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid,
                    receipt_root=self.root / "receipts",
                )
            response = client.recv(4096)
            magic, status, stdout_size, stderr_size = struct.unpack(
                "!4sIII", response[:16]
            )
            self.assertEqual((magic, status, stdout_size), (b"SSAR", 1, 0))
            body = json.loads(response[16:16 + stderr_size])
            self.assertEqual(body, {
                "schema":AUTH.TOUCHID_SCHEMA, "status":"rejected",
                "error":"touchid_peer_identity_mismatch",
            })
            self.assertFalse(restart)
            verify.assert_called_once_with(Path("/different/helper"), self.root, self.uid)
            execute.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_touchid_connection_requests_restart_only_after_sending_release_response(self):
        client, server = socket.socketpair()
        value = {
            "request_id": "12345678-1234-4123-8123-123456789abc",
            "request_sha256": "c" * 64,
            "schema": AUTH.TOUCHID_SCHEMA,
        }
        client.sendall(AUTH.canonical(value))
        client.shutdown(socket.SHUT_WR)

        def execute(*_args, **kwargs):
            kwargs["result_capture"].append(SimpleNamespace(
                returncode=0, stdout=b"deployed\n", stderr=b""
            ))
            return 0

        try:
            with (mock.patch.object(AUTH, "peer_audit_identity",
                                    return_value=(self.uid, b"x" * 32, Path("/signed-ui"))),
                  mock.patch.object(AUTH, "protected_release_directory", return_value=self.root),
                  mock.patch.object(AUTH, "verify_touchid_peer"),
                  mock.patch.object(AUTH, "execute_request", side_effect=execute),
                  mock.patch.object(AUTH, "selected_release_changed", return_value=True)):
                restart = AUTH.handle_touchid_connection(server, broker_path=self.root / "broker",
                                                         expected_root_uid=self.uid,
                                                         receipt_root=self.root / "receipts")
            response = client.recv(1024)
            self.assertEqual(response[16:], b"deployed\n")
            self.assertTrue(restart)
        finally:
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
