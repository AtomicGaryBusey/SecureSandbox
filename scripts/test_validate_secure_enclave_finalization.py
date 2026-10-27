import hashlib, importlib.util, json, os, tempfile, unittest
from pathlib import Path

PATH = Path(__file__).with_name("validate_secure_enclave_finalization.py")
SPEC = importlib.util.spec_from_file_location("finalization_validation", PATH)
assert SPEC and SPEC.loader
V = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(V)

class FinalizationValidationTests(unittest.TestCase):
    def verifier_state(self):
        prepared = {"transaction_id":"t", "generation_id":"g", "generation_epoch":2,
                    "host_release_id":"h", "research_release_id":"r"}
        research = {name:name for name in ("run_id","session_id","approval_id",
            "acceptance_attempt_id","approval_attestation_sha256","research_receipt_id",
            "research_receipt_sha256","consumed_marker_sha256","acceptance_binding_sha256")}
        research["acceptance_attempt_number"] = 3
        verifier = {"schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
                    "status":"verified", **prepared, **research,
                    "host_receipt_sha256":"a"*64,
                    "prepared_host_boot_sha256":hashlib.sha256(b"old").hexdigest(),
                    "verified_host_boot_sha256":hashlib.sha256(b"new").hexdigest(),
                    "verified_at":1}
        verifier["verifier_sha256"] = hashlib.sha256(V.canonical_v2(verifier)).hexdigest()
        return {"host_boot":"old", "prepared":prepared, "research_evidence":research,
                "host_acceptance_verifier":verifier}

    def test_verifier_accepts_exact_cross_bound_digest(self):
        state = self.verifier_state()
        self.assertEqual(V.validate_verifier(state, "new"),
                         state["host_acceptance_verifier"]["verifier_sha256"])

    def test_verifier_rejects_each_substitution_class(self):
        for field, value in (("run_id","other"), ("host_release_id","other"),
                             ("verified_host_boot_sha256","0"*64), ("verifier_sha256","0"*64)):
            with self.subTest(field=field):
                state = self.verifier_state(); state["host_acceptance_verifier"][field] = value
                with self.assertRaises(V.ValidationError): V.validate_verifier(state, "new")

    def test_negative_requires_exact_shape_identity_and_boolean(self):
        good = {"schema":"secure-sandbox-execution-approval-negative-gates-v1",
                "status":"verified", "approval_id":"a", "wrong_key_rejected":True,
                "replay_rejected":True, "verified_at":1}
        V.validate_negative(good, "a")
        for mutation in ({**good, "wrong_key_rejected":1}, {**good, "approval_id":"b"},
                         {**good, "extra":True}):
            with self.assertRaises(V.ValidationError): V.validate_negative(mutation, "a")

    def test_cancellation_requires_exact_terminal_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stderr"
            receipts = Path(directory) / "receipts"; receipts.mkdir(mode=0o755)
            exact = {"action":"start_new_request_when_ready",
                     "code":"operator_cancelled",
                     "operation":"execution-approval-sign",
                     "outcome":"cancelled", "phase":"ceremony",
                     "request_id":"12345678-1234-4123-8123-123456789abc",
                     "retry":"new-request",
                     "schema":"secure-sandbox-operator-diagnostic-v1"}
            receipt = {
                "approval_key_generation_epoch":2,
                "approval_key_generation_id":"12345678-1234-4123-8123-123456789abc",
                "approval_public_key_sha256":"a" * 64,
                "approval_signature_algorithm":"ecdsa-p256-sha256-x962-low-s",
                "authorization_method":"touch-id",
                "authorization_receipt_sha256":"b" * 64,
                "authorization_ui_bundle_sha256":"c" * 64,
                "ceremony":"cancel-test", "completed_at":1,
                "host_release_id":"d" * 64,
                "operation":"execution-approval-sign",
                "request_id":exact["request_id"], "request_sha256":"e" * 64,
                "schema":"secure-sandbox-operator-cancellation-receipt-v1",
                "status":"cancelled",
            }
            receipt_path = receipts / f"{exact['request_id']}.json"
            receipt_path.write_bytes(V.canonical_v2(receipt) + b"\n")
            receipt_path.chmod(0o644)
            validate = lambda: V.validate_cancellation(
                path, receipts, "d" * 64, "c" * 64,
                "12345678-1234-4123-8123-123456789abc", 2, "a" * 64,
                expected_uid=os.geteuid(),
            )
            path.write_text("preflight\n" + json.dumps(exact, sort_keys=True) + "\n")
            self.assertEqual(validate(), receipt)
            for tail in ('{"code":"not_operator_cancelled"}\n', json.dumps(exact)+"\ntrailing\n"):
                path.write_text("operator_cancelled\n" + tail)
                with self.assertRaises(V.ValidationError): validate()

            path.write_text(json.dumps(exact, sort_keys=True) + "\n")
            receipt_path.write_bytes(V.canonical_v2({**receipt, "host_release_id":"f" * 64}) + b"\n")
            with self.assertRaises(V.ValidationError): validate()

if __name__ == "__main__": unittest.main()
