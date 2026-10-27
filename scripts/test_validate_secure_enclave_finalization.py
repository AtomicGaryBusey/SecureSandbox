import hashlib, importlib.util, json, tempfile, unittest
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
            exact = {"error":"operator_cancelled",
                     "schema":"secure-sandbox-operator-authorization-v1",
                     "status":"rejected"}
            path.write_text("preflight\n" + json.dumps(exact, sort_keys=True) + "\n")
            V.validate_cancellation(path)
            for tail in ('{"error":"not_operator_cancelled"}\n', json.dumps(exact)+"\ntrailing\n"):
                path.write_text("operator_cancelled\n" + tail)
                with self.assertRaises(V.ValidationError): V.validate_cancellation(path)

if __name__ == "__main__": unittest.main()
