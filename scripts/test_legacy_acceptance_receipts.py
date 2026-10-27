import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GENERATION = "20261021T040946Z"
SESSION = "00000000-0000-4000-8000-000000000001"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ACCEPTANCE = load(
    "record_legacy_continuity_acceptance",
    ROOT / "scripts/record-legacy-continuity-acceptance.py",
)
REDUNDANCY = load(
    "verify_legacy_redundancy",
    ROOT / "scripts/verify-legacy-redundancy.py",
)
APPROVAL = load(
    "record_legacy_retirement_approval",
    ROOT / "scripts/record-legacy-retirement-approval.py",
)


class LegacyAcceptanceReceiptTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name) / "repo"
        private = repo / ".private"
        migration = private / "legacy-migration"
        generation = migration / GENERATION
        archives = generation / "archives"
        receipts = generation / "receipts"
        for directory in (repo, private, migration, generation, archives, receipts):
            directory.mkdir(exist_ok=True)
            directory.chmod(0o700)
        hashes = {}
        for role in REDUNDANCY.ROLES:
            content = f"archive:{role}".encode()
            digest = hashlib.sha256(content).hexdigest()
            hashes[role] = digest
            (archives / f"{role}.tar.gz").write_bytes(content)
            (receipts / f"preservation-{role}.json").write_text(json.dumps({
                "archive_sha256": digest,
                "generation": GENERATION,
                "role": role,
                "schema": "secure-sandbox-legacy-preservation-receipt-v1",
                "status": "verified",
                "verification_schema": "secure-sandbox-legacy-preservation-verification-v1",
            }))
        scope = {
            category: {"records": 0, "regular_bytes": 0, "sha256": "a" * 64}
            for category in ACCEPTANCE.SCOPE_CATEGORIES
        }
        (receipts / "continuity-import.json").write_text(json.dumps({
            "archive_sha256": hashes["research"],
            "blocking_conflicts": 0,
            "imported_session_ids": [SESSION],
            "rejected": 0,
            "preserved_scope": scope,
            "preserved_scope_sha256": hashlib.sha256(ACCEPTANCE.canonical(scope)).hexdigest(),
            "report_evidence_count": 3,
            "report_evidence_sha256": "b" * 64,
            "schema": "secure-sandbox-legacy-continuity-receipt-v1",
            "status": "imported",
        }))
        return repo, archives, receipts, hashes

    def test_records_bound_first_person_acceptance(self):
        repo, _archives, receipts, hashes = self.fixture()
        result = ACCEPTANCE.record(repo, GENERATION, SESSION, observed_at=123)
        self.assertEqual(result["archive_sha256"], hashes["research"])
        self.assertEqual(result["session_id"], SESSION)
        self.assertTrue(result["context_verified"])
        self.assertRegex(result["preserved_scope_sha256"], r"^[0-9a-f]{64}$")
        output = receipts / "glm-continuity.json"
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text()), result)

    def test_rejects_session_not_imported(self):
        repo, _archives, _receipts, _hashes = self.fixture()
        with self.assertRaisesRegex(ACCEPTANCE.AcceptanceError, "continuity_evidence_incomplete"):
            ACCEPTANCE.record(
                repo, GENERATION, "00000000-0000-4000-8000-000000000002", observed_at=123
            )

    def test_rejects_incomplete_confirmation(self):
        repo, _archives, _receipts, _hashes = self.fixture()
        with self.assertRaisesRegex(ACCEPTANCE.AcceptanceError, "acceptance_confirmation_incomplete"):
            ACCEPTANCE.record(
                repo, GENERATION, SESSION, observed_at=123,
                confirmations=(True, False, True),
            )

    def test_verifies_second_copy_and_writes_bound_receipt(self):
        repo, archives, receipts, hashes = self.fixture()
        second = repo.parent / "second-copy"
        second.mkdir(mode=0o700)
        for role in REDUNDANCY.ROLES:
            (second / f"{role}.tar.gz").write_bytes((archives / f"{role}.tar.gz").read_bytes())
        result = REDUNDANCY.verify(
            repo, GENERATION, second,
            declared_separate_failure_domain=True,
            require_distinct_device=False,
            verified_at=456,
        )
        self.assertEqual(result["archive_sha256"], hashes)
        self.assertEqual(result["independent_copies"], 2)
        output = receipts / "redundancy.json"
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text()), result)

    def test_cli_policy_rejects_same_filesystem_as_not_independent(self):
        repo, archives, _receipts, _hashes = self.fixture()
        second = repo.parent / "second-copy"
        second.mkdir(mode=0o700)
        for role in REDUNDANCY.ROLES:
            (second / f"{role}.tar.gz").write_bytes((archives / f"{role}.tar.gz").read_bytes())
        with self.assertRaisesRegex(
            REDUNDANCY.RedundancyError, "second_copy_not_on_distinct_filesystem"
        ):
            REDUNDANCY.verify(
                repo, GENERATION, second,
                declared_separate_failure_domain=True,
                verified_at=456,
            )
        self.assertFalse((_receipts / "redundancy.json").exists())

    def test_rejects_mismatched_second_copy(self):
        repo, archives, _receipts, _hashes = self.fixture()
        second = repo.parent / "second-copy"
        second.mkdir(mode=0o700)
        for role in REDUNDANCY.ROLES:
            content = (archives / f"{role}.tar.gz").read_bytes()
            (second / f"{role}.tar.gz").write_bytes(
                b"tampered" if role == "research" else content
            )
        with self.assertRaisesRegex(REDUNDANCY.RedundancyError, "archive_copy_mismatch:research"):
            REDUNDANCY.verify(
                repo, GENERATION, second,
                declared_separate_failure_domain=True,
                require_distinct_device=False,
                verified_at=456,
            )

    def test_retirement_approval_requires_and_binds_all_prior_gates(self):
        repo, archives, receipts, hashes = self.fixture()

        class Status:
            @staticmethod
            def evaluate(_repo, _generation):
                return {"failed_gates": ["operator_retirement_approved"]}

            @staticmethod
            def sha256_regular(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()

        result = APPROVAL.record(
            repo, GENERATION, confirmations=(True, True, True),
            approved_at=789, status_module=Status,
        )
        self.assertEqual(result["archive_sha256"], hashes)
        self.assertTrue(result["retirement_understood"])
        output = receipts / "operator-retirement-approval.json"
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_retirement_approval_fails_while_any_technical_gate_is_open(self):
        repo, _archives, _receipts, _hashes = self.fixture()

        class Status:
            @staticmethod
            def evaluate(_repo, _generation):
                return {"failed_gates": [
                    "glm_continuity_accepted", "operator_retirement_approved",
                ]}

        with self.assertRaisesRegex(APPROVAL.ApprovalError, "technical_gates_incomplete"):
            APPROVAL.record(
                repo, GENERATION, confirmations=(True, True, True),
                approved_at=789, status_module=Status,
            )


if __name__ == "__main__":
    unittest.main()
