import importlib.util
import os
import tempfile
import unittest
import uuid
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("archive_execution_approval_acceptance_evidence.py")
SPEC = importlib.util.spec_from_file_location("acceptance_archiver", MODULE_PATH)
assert SPEC and SPEC.loader
archiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archiver)


class AcceptanceEvidenceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / "history").mkdir(mode=0o700)
        (self.root / "phase-receipts").mkdir(mode=0o700)
        self.uid, self.gid = os.geteuid(), os.getegid()
        self.prior_transaction = str(uuid.uuid4())
        self.current_transaction = str(uuid.uuid4())
        self.prior_generation = str(uuid.uuid4())
        self.current_generation = str(uuid.uuid4())
        self.bound = {
            "transaction_id": self.prior_transaction,
            "generation_id": self.prior_generation,
            "generation_epoch": 1,
            "host_release_id": "1" * 64,
            "research_release_id": "2" * 64,
            "run_id": str(uuid.uuid4()),
            "session_id": str(uuid.uuid4()),
            "acceptance_attempt_id": str(uuid.uuid4()),
            "acceptance_attempt_number": 3,
            "acceptance_binding_sha256": "3" * 64,
        }
        self.acceptance_journal_sha256 = "4" * 64
        self.prior_journal = {
            "schema": archiver.JOURNAL_SCHEMA, "phase": "committed",
            "prior_record_sha256": self.acceptance_journal_sha256,
            **{name:self.bound[name] for name in archiver.COMMITTED_FIELDS},
        }
        self.current_journal = {
            "schema": archiver.JOURNAL_SCHEMA, "phase": "acceptance",
            "transaction_id": self.current_transaction,
            "generation_id": self.current_generation, "generation_epoch": 2,
            "previous_generation_id": self.prior_generation,
            "previous_generation_epoch": 1,
        }
        self.evidence = {"schema": archiver.EVIDENCE_SCHEMA, "status": "verified", **self.bound}
        self.write(self.root / "history" / f"{self.prior_transaction}.json", self.prior_journal)
        self.write(
            self.root / "phase-receipts" / f"{self.prior_transaction}.acceptance-3.json",
            {"schema":archiver.PHASE_RECEIPT_SCHEMA, "outcome":"succeeded",
             "phase":"acceptance", "transaction_id":self.prior_transaction,
             "generation_id":self.prior_generation, "generation_epoch":1,
             "journal_sha256":self.acceptance_journal_sha256},
        )
        self.write(self.root / "journal.json", self.current_journal)
        self.write(self.root / "acceptance-evidence.json", self.evidence)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path, value):
        path.write_bytes(archiver.canonical(value))
        path.chmod(0o600)

    def run_archive(self, **kwargs):
        return archiver.archive_predecessor(
            self.current_transaction, state_root=self.root,
            expected_uid=self.uid, expected_gid=self.gid, **kwargs)

    def test_moves_predecessor_and_is_idempotent(self):
        result = self.run_archive()
        self.assertEqual(result["status"], "archived")
        self.assertFalse(os.path.lexists(self.root / "acceptance-evidence.json"))
        self.assertTrue((self.root / "acceptance-evidence-history" / f"{self.prior_transaction}.json").is_file())
        self.assertEqual(self.run_archive()["status"], "absent")

    def test_each_crash_point_recovers_without_losing_evidence(self):
        for point in ("after_replace", "after_archive_fsync", "after_state_fsync"):
            with self.subTest(point=point):
                if not os.path.lexists(self.root / "acceptance-evidence.json"):
                    self.write(self.root / "acceptance-evidence.json", self.evidence)
                archive = self.root / "acceptance-evidence-history" / f"{self.prior_transaction}.json"
                if archive.exists(): archive.unlink()
                def fault(observed):
                    if observed == point: raise RuntimeError("simulated_crash")
                with self.assertRaisesRegex(RuntimeError, "simulated_crash"):
                    self.run_archive(fault=fault)
                self.assertEqual(self.run_archive()["status"], "absent")

    def test_absent_without_archive_fails_closed(self):
        (self.root / "acceptance-evidence.json").unlink()
        with self.assertRaisesRegex(archiver.ArchiveError, "predecessor_missing"):
            self.run_archive()

    def test_corrupt_archive_fails_closed(self):
        archive = self.root / "acceptance-evidence-history"
        archive.mkdir(mode=0o700)
        path = archive / f"{self.prior_transaction}.json"
        path.write_text("not-json\n", encoding="utf-8"); path.chmod(0o600)
        with self.assertRaisesRegex(archiver.ArchiveError, "state_untrusted"):
            self.run_archive()

    def test_dangling_singleton_symlink_fails_closed(self):
        (self.root / "acceptance-evidence.json").unlink()
        (self.root / "acceptance-evidence.json").symlink_to(self.root / "missing")
        with self.assertRaisesRegex(archiver.ArchiveError, "state_untrusted"):
            self.run_archive()

    def test_current_singleton_requires_predecessor_archive(self):
        current_evidence = dict(self.evidence)
        current_evidence.update(transaction_id=self.current_transaction,
                                generation_id=self.current_generation,
                                generation_epoch=2)
        self.write(self.root / "acceptance-evidence.json", current_evidence)
        with self.assertRaisesRegex(archiver.ArchiveError, "predecessor_missing"):
            self.run_archive()


if __name__ == "__main__":
    unittest.main()
