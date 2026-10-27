#!/usr/bin/env python3

import importlib.util
import json
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).with_name(
    "verify-secure-enclave-execution-approval-ddd.py"
)
SPEC = importlib.util.spec_from_file_location("verify_secure_enclave_ddd", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class CompletionAuditTests(unittest.TestCase):
    GENERATION = "11111111-1111-4111-8111-111111111111"
    PREVIOUS = "22222222-2222-4222-8222-222222222222"
    TRANSACTION = "33333333-3333-4333-8333-333333333333"
    BRIDGE_TRANSACTION = "44444444-4444-4444-8444-444444444444"
    BRIDGE_UI_BUNDLE_SHA256 = "f" * 64
    HOST = "a" * 64
    RESEARCH = "b" * 64
    PUBLIC = "c" * 64

    def acceptance_evidence(self, prepared, marker):
        shared = {
            "status":"verified",
            "transaction_id":prepared["transaction_id"],
            "generation_id":prepared["generation_id"],
            "generation_epoch":prepared["generation_epoch"],
            "host_release_id":prepared["host_release_id"],
            "research_release_id":prepared["research_release_id"],
            "run_id":f"{marker}1111111-1111-4111-8111-111111111111",
            "session_id":f"{marker}2222222-2222-4222-8222-222222222222",
            "approval_id":f"{marker}3333333-3333-4333-8333-333333333333",
            "acceptance_attempt_id":f"{marker}4444444-4444-4444-8444-444444444444",
            "acceptance_attempt_number":1,
            "approval_attestation_sha256":"4" * 64,
            "research_receipt_id":f"{marker}5555555-5555-4555-8555-555555555555",
            "research_receipt_sha256":"5" * 64,
            "consumed_marker_sha256":"6" * 64,
            "acceptance_binding_sha256":"7" * 64,
        }
        research = {
            "schema":"secure-sandbox-execution-approval-acceptance-evidence-v1",
            **shared, "verified_at":100,
        }
        verifier = {
            "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
            **shared, "host_receipt_sha256":"8" * 64,
            "prepared_host_boot_sha256":"9" * 64,
            "verified_host_boot_sha256":"a" * 64,
            "verified_at":101,
        }
        verifier["verifier_sha256"] = __import__("hashlib").sha256(
            AUDIT.canonical_v2(verifier)
        ).hexdigest()
        return research, verifier

    def cold_boot(self, prepared, bridge):
        proof = None
        proof_digest = None
        research_proof = None
        research_proof_digest = None
        if bridge:
            proof = {
                "schema":"secure-sandbox-checkpoint-host-release-verification-v1",
                "status":"verified", "release_id":prepared["host_release_id"],
                "generation_id":prepared["generation_id"],
                "generation_epoch":prepared["generation_epoch"],
                "public_key_sha256":prepared["public_key_sha256"],
                "authorization_ui_bundle_sha256":self.BRIDGE_UI_BUNDLE_SHA256,
                "launcher_sha256":"c" * 64,
            }
            proof_digest = __import__("hashlib").sha256(
                AUDIT.canonical_v2(proof) + b"\n"
            ).hexdigest()
            research_proof = {
                "schema":"secure-sandbox-checkpoint-research-boundary-verification-v1",
                "status":"verified",
                "release_id":prepared["research_release_id"],
                "execution_broker_sha256":"a" * 64,
                "source_execution_broker_sha256":"b" * 64,
                "transition_sha256":"c" * 64,
                "watchdog_sha256":"d" * 64,
                "receipt_boundary_verified":True,
            }
            research_proof_digest = __import__("hashlib").sha256(
                AUDIT.canonical_v2(research_proof) + b"\n"
            ).hexdigest()
        successor_deployment = None
        successor_release = None
        successor_deployment_digest = None
        if bridge:
            successor_release = self.HOST
            successor_deployment = {
                "schema":"secure-sandbox-host-controller-release-v1",
                "status":"deployed", "release_id":successor_release,
            }
            successor_deployment_digest = __import__("hashlib").sha256(
                AUDIT.canonical_v2(successor_deployment) + b"\n"
            ).hexdigest()
        evidence = {
            "schema":"secure-sandbox-host-reboot-acceptance-v1",
            "prior_boot":"boot-before", "rebooted_boot":"boot-after",
            "boundary_sha256":"d" * 64,
            "bridge_predecessor_exception":bridge,
            "checkpoint_host_verification":proof,
            "checkpoint_host_verification_sha256":proof_digest,
            "checkpoint_research_verification":research_proof,
            "checkpoint_research_verification_sha256":research_proof_digest,
            "bridge_successor_deployment":successor_deployment,
            "bridge_successor_release_id":successor_release,
            "bridge_successor_deployment_sha256":successor_deployment_digest,
        }
        return evidence, __import__("hashlib").sha256(
            AUDIT.canonical_v2(evidence)
        ).hexdigest()

    def completion(self, prepared, verifier, cold_sha, status):
        value = {
            "schema":"secure-sandbox-execution-approval-completion-receipt-v1",
            "status":status,
            **{name:prepared.get(name) for name in (
                "transaction_id", "generation_id", "generation_epoch", "algorithm",
                "public_key_sha256", "operator_uid", "host_release_id",
                "research_release_id", "previous_generation_id",
                "previous_generation_epoch",
            )},
            "research_activation_sha256":"e" * 64,
            "cold_boot_acceptance_sha256":cold_sha,
            "acceptance_verifier_sha256":verifier["verifier_sha256"],
            "acceptance_binding_sha256":verifier["acceptance_binding_sha256"],
            "acceptance_verifier":json.loads(json.dumps(verifier)),
        }
        if status == "software_retired":
            value["software_retired_at"] = 102
        value["receipt_sha256"] = __import__("hashlib").sha256(
            AUDIT.canonical_v2(value)
        ).hexdigest()
        return value

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.state_dir = self.root / "state"
        self.history = self.root / "history"
        self.install = self.root / "installed"
        for path in (self.repo, self.state_dir, self.history, self.install):
            path.mkdir(mode=0o700)
        self.bridge = self.history / f"{self.BRIDGE_TRANSACTION}.bridge"
        self.bridge.mkdir(mode=0o700)
        bridge_prepared = {
            "transaction_id":self.BRIDGE_TRANSACTION,
            "generation_id":self.PREVIOUS, "generation_epoch":1,
            "algorithm":"ecdsa-p256-sha256-x962-low-s", "operator_uid":501,
            "public_key_sha256":"3" * 64,
            "host_release_id":"1" * 64,
            "research_release_id":"2" * 64,
            "previous_generation_id":None, "previous_generation_epoch":None,
        }
        bridge_research, bridge_verifier = self.acceptance_evidence(
            bridge_prepared, "1"
        )
        bridge_cold, bridge_cold_sha = self.cold_boot(bridge_prepared, True)
        self.bridge_completion = self.completion(
            bridge_prepared, bridge_verifier, bridge_cold_sha, "committed"
        )
        self.write(self.bridge / "state.json", {
            "schema":AUDIT.SCHEMA, "stage":"bridge_committed",
            "prepared":bridge_prepared,
            "research_evidence":bridge_research,
            "host_acceptance_verifier":bridge_verifier,
            "negative_gates":{
                "schema":"secure-sandbox-execution-approval-negative-gates-v1",
                "status":"verified", "wrong_key_rejected":True,
                "replay_rejected":True,
            },
            "cold_boot_evidence":bridge_cold,
            "cold_boot_acceptance_sha256":bridge_cold_sha,
            "post_reboot_boundary_sha256":bridge_cold["boundary_sha256"],
            "bridge_successor_deployment":bridge_cold[
                "bridge_successor_deployment"
            ],
            "bridge_successor_release_id":bridge_cold[
                "bridge_successor_release_id"
            ],
        })
        self.write(self.history / "forward-rotation-handoff.json", {
            "schema":"secure-sandbox-secure-enclave-forward-rotation-handoff-v1",
            "bridge_transaction_id":self.BRIDGE_TRANSACTION,
            "bridge_generation_id":self.PREVIOUS,
            "source_host_release_id":self.HOST,
        })
        prepared = {
            "transaction_id":self.TRANSACTION,
            "generation_id":self.GENERATION, "generation_epoch":2,
            "previous_generation_id":self.PREVIOUS,
            "previous_generation_epoch":1,
            "algorithm":"ecdsa-p256-sha256-x962-low-s", "operator_uid":501,
            "public_key_sha256":self.PUBLIC,
            "public_key_spki_der_b64":"test-spki",
            "host_release_id":self.HOST,
            "research_release_id":self.RESEARCH,
        }
        research_evidence, host_verifier = self.acceptance_evidence(prepared, "2")
        cold_boot, cold_boot_sha = self.cold_boot(prepared, False)
        self.final_completion = self.completion(
            prepared, host_verifier, cold_boot_sha, "software_retired"
        )
        self.state = {
            "schema":AUDIT.SCHEMA, "stage":"complete",
            "prepared":prepared,
            "cancellation_evidence":{
                "schema":"secure-sandbox-execution-approval-cancellation-evidence-v1",
                "status":"cancelled", "stdout_empty":True,
                "generation_id":self.GENERATION, "generation_epoch":2,
                "public_key_sha256":self.PUBLIC,
                "request_sha256":"d" * 64, "stderr_sha256":"e" * 64,
            },
            "software_retirement":{
                "schema":"secure-sandbox-execution-approval-migration-result-v2",
                "status":"software_retired", "transaction_id":self.TRANSACTION,
                "generation_id":self.GENERATION, "generation_epoch":2,
            },
            "research_evidence":research_evidence,
            "host_acceptance_verifier":host_verifier,
            "negative_gates":{
                "schema":"secure-sandbox-execution-approval-negative-gates-v1",
                "status":"verified", "wrong_key_rejected":True,
                "replay_rejected":True,
            },
            "cold_boot_evidence":cold_boot,
            "cold_boot_acceptance_sha256":cold_boot_sha,
            "post_reboot_boundary_sha256":cold_boot["boundary_sha256"],
            "final_boundary_sha256":"0" * 64,
        }
        self.write(self.state_dir / "state.json", self.state)
        self.active = {
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"active", "algorithm":"ecdsa-p256-sha256-x962-low-s",
            "generation_id":self.GENERATION, "generation_epoch":2,
            "public_key_sha256":self.PUBLIC,
        }
        self.keys = (self.root / "old-key", self.root / "old-key.pub")

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")
        path.chmod(0o600)

    def write_live_expiry(self):
        approval = {
            "schema":"secure-sandbox-execution-approval-request-v1",
            "approval_id":"66666666-6666-4666-8666-666666666666",
            "expires_at":100,
        }
        envelope = {
            "schema":"secure-sandbox-execution-approval-envelope-v2",
            "attestation":{"approval":approval},
        }
        value = {
            "schema":"secure-sandbox-live-expiry-evidence-v1",
            "status":"verified",
            "approval_id":approval["approval_id"],
            "expires_at":100, "observed_at":101,
            "generation_id":self.GENERATION, "generation_epoch":2,
            "public_key_sha256":self.PUBLIC,
            "signature_algorithm":"ecdsa-p256-sha256-x962-low-s",
            "approval":approval, "envelope":envelope,
            "approval_request_sha256":__import__("hashlib").sha256(
                AUDIT.canonical_v2(approval) + b"\n"
            ).hexdigest(),
            "approval_attestation_sha256":"d" * 64,
            "signed_envelope_sha256":__import__("hashlib").sha256(
                AUDIT.canonical_v2(envelope) + b"\n"
            ).hexdigest(),
            "verified_attestation_generation_id":self.GENERATION,
            "verified_attestation_generation_epoch":2,
            "rejection":"approval_expired", "consumed_marker_absent":True,
            "rejection_precedes_target_dispatch":True,
        }
        value["evidence_sha256"] = __import__("hashlib").sha256(
            AUDIT.canonical_v2(value) + b"\n"
        ).hexdigest()
        self.write(self.state_dir / "live-expiry-evidence.json", value)

    def run_audit(self, require_live_expiry=False):
        support = SimpleNamespace(
            source_host_release_id=lambda _repo: self.HOST,
            protected_selector_identities=lambda *_args: (_ for _ in ()).throw(
                PermissionError("root-only floor")
            ),
            verify_postactivation_host_release=lambda _repo, _root, _launcher: {
                "schema":"secure-sandbox-host-controller-release-v1",
                "status":"verified", "release_id":self.HOST,
            },
        )
        def run(command, **_kwargs):
            if "execution-approval-completion-status" in command:
                transaction = command[command.index("--transaction-id") + 1]
                value = (self.final_completion if transaction == self.TRANSACTION
                         else self.bridge_completion)
            else:
                value = self.active
            return SimpleNamespace(stdout=json.dumps(value), returncode=0)
        class Rejected(ValueError):
            pass
        def await_operator_approval(approval, _config, root, trusted_uid):
            self.assertEqual(trusted_uid, os.geteuid())
            raise Rejected("approval_expired")
        broker = SimpleNamespace(
            Rejected=Rejected,
            await_operator_approval=await_operator_approval,
            verify_v2_envelope=lambda envelope, approval, config: ({
                "key_generation_id":config["approval"]["generation_id"],
                "key_generation_epoch":config["approval"]["generation_epoch"],
            }, "d" * 64)
        )
        with (mock.patch.object(AUDIT, "load_support", return_value=support),
              mock.patch.object(AUDIT, "load_research_broker", return_value=broker),
              mock.patch.object(
                  AUDIT, "source_research_release_id", return_value=self.RESEARCH
              ),
              mock.patch.object(AUDIT.subprocess, "run", side_effect=run)):
            return AUDIT.audit(
                self.repo, self.install, self.state_dir, self.history,
                os.geteuid(), self.keys,
                bridge_ui_bundle_sha256=self.BRIDGE_UI_BUNDLE_SHA256,
                require_live_expiry=require_live_expiry,
            )

    def test_complete_rotated_generation_is_verified(self):
        result = self.run_audit()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["generation_epoch"], 2)
        self.assertTrue(result["software_key_absent"])
        self.assertFalse(result["live_expiry_verified"])
        self.assertFalse(result["live_peer_isolation_verified"])
        self.assertFalse(result["live_keychain_isolation_verified"])

    def test_current_generation_live_expiry_is_verified_when_required(self):
        self.write_live_expiry()
        result = self.run_audit(require_live_expiry=True)
        self.assertTrue(result["live_expiry_verified"])

    def test_live_expiry_generation_substitution_fails_closed(self):
        self.write_live_expiry()
        path = self.state_dir / "live-expiry-evidence.json"
        value = json.loads(path.read_text(encoding="ascii"))
        value["generation_epoch"] = 1
        value["evidence_sha256"] = __import__("hashlib").sha256(
            AUDIT.canonical_v2({
                key:item for key, item in value.items() if key != "evidence_sha256"
            }) + b"\n"
        ).hexdigest()
        self.write(path, value)
        with self.assertRaisesRegex(
            AUDIT.AuditError, "live_expiry_generation_epoch_mismatch"
        ):
            self.run_audit(require_live_expiry=True)

    def test_live_expiry_requires_post_expiry_observation(self):
        self.write_live_expiry()
        path = self.state_dir / "live-expiry-evidence.json"
        value = json.loads(path.read_text(encoding="ascii"))
        value["observed_at"] = value["expires_at"]
        value["evidence_sha256"] = __import__("hashlib").sha256(
            AUDIT.canonical_v2({
                key:item for key, item in value.items() if key != "evidence_sha256"
            }) + b"\n"
        ).hexdigest()
        self.write(path, value)
        with self.assertRaisesRegex(
            AUDIT.AuditError, "live_expiry_evidence_invalid"
        ):
            self.run_audit(require_live_expiry=True)

    def test_live_expiry_signature_is_independently_required(self):
        self.write_live_expiry()
        value = json.loads(
            (self.state_dir / "live-expiry-evidence.json").read_text(
                encoding="ascii"
            )
        )
        broker = SimpleNamespace(
            verify_v2_envelope=mock.Mock(side_effect=ValueError("bad signature"))
        )
        with self.assertRaisesRegex(
            AUDIT.AuditError, "live_expiry_signature_invalid"
        ):
            AUDIT.verify_live_expiry_evidence(
                value, self.state["prepared"], broker, os.geteuid()
            )

    def test_live_differently_signed_peer_is_rejected(self):
        body = AUDIT.canonical_v2({
            "schema":"secure-sandbox-touchid-approval-v1",
            "status":"rejected", "error":"touchid_peer_identity_mismatch",
        }) + b"\n"

        class Connection:
            def __init__(self):
                self.data = bytearray(
                    struct.pack("!4sIII", b"SSAR", 1, 0, len(body)) + body
                )
            def settimeout(self, _timeout): pass
            def connect(self, _path): pass
            def shutdown(self, how):
                self_test.assertEqual(how, socket.SHUT_WR)
            def recv(self, count):
                result = bytes(self.data[:count]); del self.data[:count]
                return result
            def close(self): pass

        self_test = self
        AUDIT.verify_live_touchid_peer_isolation(
            Path("/test/socket"), lambda *_args: Connection()
        )

    def test_live_peer_wrong_rejection_fails_closed(self):
        body = AUDIT.canonical_v2({
            "schema":"secure-sandbox-touchid-approval-v1",
            "status":"rejected", "error":"touchid_protocol_invalid",
        }) + b"\n"

        class Connection:
            def __init__(self):
                self.data = bytearray(
                    struct.pack("!4sIII", b"SSAR", 1, 0, len(body)) + body
                )
            def settimeout(self, _timeout): pass
            def connect(self, _path): pass
            def shutdown(self, _how): pass
            def recv(self, count):
                result = bytes(self.data[:count]); del self.data[:count]
                return result
            def close(self): pass

        with self.assertRaisesRegex(
            AUDIT.AuditError, "touchid_peer_rejection_invalid"
        ):
            AUDIT.verify_live_touchid_peer_isolation(
                Path("/test/socket"), lambda *_args: Connection()
            )

    def test_live_expiry_harness_uses_exact_host_ttl_and_full_audit(self):
        harness = MODULE_PATH.with_name(
            "verify-live-secure-enclave-expiry.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('expires_at="$((created_at + 90))"', harness)
        self.assertNotIn('expires_at="$((created_at + 30))"', harness)
        self.assertIn("install-audit-expired-execution-approval.sh", harness)
        self.assertIn("control_status=$?", harness)
        for flag in (
            "--require-live-expiry", "--require-live-peer-isolation",
            "--require-live-keychain-isolation",
        ):
            self.assertIn(flag, harness)

    def test_research_broker_loader_resolves_sibling_modules(self):
        repo = MODULE_PATH.parent.parent
        broker = AUDIT.load_research_broker(repo)
        self.assertTrue(callable(broker.await_operator_approval))
        first = AUDIT.source_research_release_id(repo)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, AUDIT.source_research_release_id(repo))


    def test_live_generation_substitution_fails_closed(self):
        self.active["generation_id"] = "55555555-5555-4555-8555-555555555555"
        with self.assertRaisesRegex(AUDIT.AuditError, "active_generation_id_mismatch"):
            self.run_audit()

    def test_present_software_key_fails_completion(self):
        self.keys[0].write_bytes(b"extractable")
        with self.assertRaisesRegex(AUDIT.AuditError, "software_key_still_present"):
            self.run_audit()

    def test_bridge_generation_must_be_rotation_predecessor(self):
        handoff = json.loads(
            (self.history / "forward-rotation-handoff.json").read_text(encoding="ascii")
        )
        handoff["bridge_generation_id"] = self.GENERATION
        self.write(self.history / "forward-rotation-handoff.json", handoff)
        with self.assertRaisesRegex(AUDIT.AuditError, "bridge_generation_mismatch"):
            self.run_audit()

    def test_cold_boot_evidence_digest_substitution_fails_closed(self):
        self.state["cold_boot_evidence"]["rebooted_boot"] = "substituted-boot"
        self.write(self.state_dir / "state.json", self.state)
        with self.assertRaisesRegex(AUDIT.AuditError, "cold_boot_evidence_digest_mismatch"):
            self.run_audit()

    def test_host_acceptance_verifier_substitution_fails_closed(self):
        self.state["host_acceptance_verifier"]["run_id"] = \
            "99999999-9999-4999-8999-999999999999"
        self.write(self.state_dir / "state.json", self.state)
        with self.assertRaisesRegex(AUDIT.AuditError, "verifier_run_id_mismatch"):
            self.run_audit()

    def test_bridge_checkpoint_proof_substitution_fails_closed(self):
        path = self.bridge / "state.json"
        bridge = json.loads(path.read_text(encoding="ascii"))
        bridge["cold_boot_evidence"]["checkpoint_host_verification"][
            "release_id"
        ] = "f" * 64
        bridge["cold_boot_acceptance_sha256"] = __import__("hashlib").sha256(
            AUDIT.canonical_v2(bridge["cold_boot_evidence"])
        ).hexdigest()
        self.write(path, bridge)
        with self.assertRaisesRegex(
            AUDIT.AuditError, "protected_cold_boot_evidence_mismatch"
        ):
            self.run_audit()

    def test_bridge_research_checkpoint_identity_substitution_fails_closed(self):
        path = self.bridge / "state.json"
        bridge = json.loads(path.read_text(encoding="ascii"))
        evidence = bridge["cold_boot_evidence"]
        evidence["checkpoint_research_verification"]["release_id"] = "f" * 64
        digest = __import__("hashlib").sha256(
            AUDIT.canonical_v2(evidence)
        ).hexdigest()
        bridge["cold_boot_acceptance_sha256"] = digest
        with self.assertRaisesRegex(
            AUDIT.AuditError, "checkpoint_research_release_mismatch"
        ):
            AUDIT.verify_cold_boot_evidence(
                bridge, bridge["prepared"], True, digest,
                self.BRIDGE_UI_BUNDLE_SHA256,
            )

    def test_bridge_research_source_divergence_must_be_proven(self):
        path = self.bridge / "state.json"
        bridge = json.loads(path.read_text(encoding="ascii"))
        evidence = bridge["cold_boot_evidence"]
        proof = evidence["checkpoint_research_verification"]
        proof["source_execution_broker_sha256"] = proof[
            "execution_broker_sha256"
        ]
        evidence["checkpoint_research_verification_sha256"] = \
            __import__("hashlib").sha256(
                AUDIT.canonical_v2(proof) + b"\n"
            ).hexdigest()
        digest = __import__("hashlib").sha256(
            AUDIT.canonical_v2(evidence)
        ).hexdigest()
        bridge["cold_boot_acceptance_sha256"] = digest
        with self.assertRaisesRegex(
            AUDIT.AuditError,
            "checkpoint_research_bridge_exception_not_proven",
        ):
            AUDIT.verify_cold_boot_evidence(
                bridge, bridge["prepared"], True, digest,
                self.BRIDGE_UI_BUNDLE_SHA256,
            )

    def test_bridge_successor_deployment_substitution_fails_closed(self):
        path = self.bridge / "state.json"
        bridge = json.loads(path.read_text(encoding="ascii"))
        evidence = bridge["cold_boot_evidence"]
        evidence["bridge_successor_deployment"]["release_id"] = "f" * 64
        digest = __import__("hashlib").sha256(
            AUDIT.canonical_v2(evidence)
        ).hexdigest()
        bridge["cold_boot_acceptance_sha256"] = digest
        with self.assertRaisesRegex(
            AUDIT.AuditError, "bridge_successor_deployment_release_mismatch"
        ):
            AUDIT.verify_cold_boot_evidence(
                bridge, bridge["prepared"], True, digest,
                self.BRIDGE_UI_BUNDLE_SHA256,
            )

    def test_bridge_successor_deployment_digest_substitution_fails_closed(self):
        path = self.bridge / "state.json"
        bridge = json.loads(path.read_text(encoding="ascii"))
        evidence = bridge["cold_boot_evidence"]
        evidence["bridge_successor_deployment_sha256"] = "f" * 64
        digest = __import__("hashlib").sha256(
            AUDIT.canonical_v2(evidence)
        ).hexdigest()
        bridge["cold_boot_acceptance_sha256"] = digest
        with self.assertRaisesRegex(
            AUDIT.AuditError, "bridge_successor_deployment_digest_mismatch"
        ):
            AUDIT.verify_cold_boot_evidence(
                bridge, bridge["prepared"], True, digest,
                self.BRIDGE_UI_BUNDLE_SHA256,
            )

    def test_rotation_source_release_substitution_fails_closed(self):
        path = self.history / "forward-rotation-handoff.json"
        handoff = json.loads(path.read_text(encoding="ascii"))
        handoff["source_host_release_id"] = "f" * 64
        self.write(path, handoff)
        with self.assertRaisesRegex(AUDIT.AuditError, "rotation_source_release_mismatch"):
            self.run_audit()

    def test_bridge_commit_repair_chain_is_bound_to_source_release(self):
        path = self.bridge / "state.json"
        bridge = json.loads(path.read_text(encoding="ascii"))
        repaired_release = "e" * 64
        deployment = {
            "schema":"secure-sandbox-host-controller-release-v1",
            "status":"deployed", "release_id":repaired_release,
        }
        bridge["bridge_commit_repairs"] = [{
            "schema":"secure-sandbox-execution-approval-bridge-commit-repair-v1",
            "reason":"empty_legacy_completion_directory_mode_migration",
            "from_release_id":self.HOST,
            "to_release_id":repaired_release,
            "deployment":deployment,
            "deployment_sha256":__import__("hashlib").sha256(
                AUDIT.canonical_v2(deployment) + b"\n"
            ).hexdigest(),
            "protected_cold_boot_acceptance_sha256":bridge[
                "cold_boot_acceptance_sha256"
            ],
            "recorded_at":103,
        }]
        AUDIT.verify_bridge_commit_repairs(bridge, repaired_release)
        with self.assertRaisesRegex(
            AUDIT.AuditError, "bridge_commit_repair_source_release_mismatch"
        ):
            AUDIT.verify_bridge_commit_repairs(bridge, self.HOST)


if __name__ == "__main__":
    unittest.main()
