#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("audit_expired_execution_approval.py")
SPEC = importlib.util.spec_from_file_location("audit_expired_execution_approval", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class FakeBroker:
    class Rejected(ValueError):
        pass

    def __init__(self, outcome="approval_expired"):
        self.outcome = outcome

    def load_config(self):
        return {
            "schema":"secure-sandbox-execution-broker-v3",
            "approval":{
                "mode":"active-v2", "minimum_protocol":2,
                "minimum_epoch":2, "generation_epoch":2,
                "generation_id":"11111111-1111-4111-8111-111111111111",
                "public_key_sha256":"a" * 64,
                "algorithm":"ecdsa-p256-sha256-x962-low-s",
            },
        }

    def await_operator_approval(self, approval, _config, root, trusted_uid):
        assert trusted_uid == 0
        assert not any((root / "consumed").iterdir())
        if self.outcome is None:
            return {}, ""
        raise self.Rejected(self.outcome)

    def verify_v2_envelope(self, envelope, approval, _config):
        if envelope["attestation"]["approval"] != approval:
            raise self.Rejected("approval_invalid")
        return ({
            "key_generation_id":"11111111-1111-4111-8111-111111111111",
            "key_generation_epoch":2,
        }, "b" * 64)


class ExpiryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.approval = {
            "schema":"secure-sandbox-execution-approval-request-v1",
            "approval_id":"22222222-2222-4222-8222-222222222222",
            "expires_at":100,
        }
        self.envelope = {
            "schema":"secure-sandbox-execution-approval-envelope-v2",
            "attestation":{"approval":self.approval},
        }

    def tearDown(self):
        self.temporary.cleanup()

    def run_audit(self, broker=None):
        original = tempfile.TemporaryDirectory
        with mock.patch.object(
            AUDIT.tempfile, "TemporaryDirectory",
            side_effect=lambda **kwargs: original(dir=self.temporary.name),
        ):
            return AUDIT.verify_expired_approval(
                self.approval, self.envelope, broker or FakeBroker(), 101
            )

    def test_expired_current_generation_is_rejected_without_consumption(self):
        result = self.run_audit()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["rejection"], "approval_expired")
        self.assertTrue(result["consumed_marker_absent"])
        self.assertTrue(result["rejection_precedes_target_dispatch"])
        self.assertEqual(result["approval_attestation_sha256"], "b" * 64)
        self.assertEqual(len(result["evidence_sha256"]), 64)

    def test_exact_signed_approval_binding_is_required(self):
        self.envelope["attestation"]["approval"] = dict(
            self.approval, expires_at=99
        )
        with self.assertRaisesRegex(RuntimeError, "expiry_request_invalid"):
            self.run_audit()

    def test_unexpired_request_is_rejected_by_auditor(self):
        with self.assertRaisesRegex(RuntimeError, "expiry_request_invalid"):
            original = tempfile.TemporaryDirectory
            with mock.patch.object(
                AUDIT.tempfile, "TemporaryDirectory",
                side_effect=lambda **kwargs: original(dir=self.temporary.name),
            ):
                AUDIT.verify_expired_approval(
                    self.approval, self.envelope, FakeBroker(), 100
                )

    def test_acceptance_or_wrong_rejection_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "expired_approval_accepted"):
            self.run_audit(FakeBroker(None))
        with self.assertRaisesRegex(FakeBroker.Rejected, "approval_invalid"):
            self.run_audit(FakeBroker("approval_invalid"))

    def test_inactive_configuration_is_rejected(self):
        broker = FakeBroker()
        broker.load_config = lambda: {
            "schema":"secure-sandbox-execution-broker-v3",
            "approval":{"mode":"fenced-v2"},
        }
        with self.assertRaisesRegex(
            RuntimeError, "live_approval_configuration_invalid"
        ):
            self.run_audit(broker)

    def test_invalid_signature_fails_before_expiry_check(self):
        broker = FakeBroker()
        broker.verify_v2_envelope = mock.Mock(
            side_effect=broker.Rejected("approval_invalid")
        )
        with self.assertRaisesRegex(RuntimeError, "live_signed_envelope_invalid"):
            self.run_audit(broker)

    def test_deployed_broker_loader_resolves_sibling_modules(self):
        root = Path(self.temporary.name)
        (root / "broker_dependency.py").write_text(
            "VALUE = 'sibling-loaded'\n", encoding="utf-8"
        )
        broker_path = root / "execution_broker.py"
        broker_path.write_text(
            "from broker_dependency import VALUE\n", encoding="utf-8"
        )
        broker = AUDIT.load_deployed_broker(broker_path)
        self.assertEqual(broker.VALUE, "sibling-loaded")


if __name__ == "__main__":
    unittest.main()
