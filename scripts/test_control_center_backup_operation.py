import tempfile
import unittest
from pathlib import Path

from scripts import control_center_backup as backup
from scripts import control_center_backup_operation as operation


class BackupOperationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "operations"
        self.destination = Path(self.temporary.name) / "destination"
        self.destination.mkdir()
        self.key = b"k" * 32
        self.identities = {name: {"uuid": f"{index:08x}-1111-4111-8111-111111111111",
                                  "device": 1, "inode": index}
                           for index, name in enumerate(backup.NAMES, 1)}
        self.plan_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.volume = "11111111-1111-4111-8111-111111111111"

    def tearDown(self):
        self.temporary.cleanup()

    def test_plan_authenticates_identity_expires_and_claims_once(self):
        value = operation.create_plan(self.root, self.destination, self.volume,
                                      self.identities, self.key, now=100,
                                      plan_id=self.plan_id)
        self.assertEqual(value["plan_id"], self.plan_id)
        self.assertEqual(operation.load_plan(self.root, self.plan_id, self.key, now=101)["destination"],
                         str(self.destination))
        with self.assertRaisesRegex(operation.OperationError, "authentication_failed"):
            operation.load_plan(self.root, self.plan_id, b"x" * 32, now=101)
        with self.assertRaisesRegex(operation.OperationError, "expired"):
            operation.load_plan(self.root, self.plan_id, self.key, now=1000 + operation.PLAN_LIFETIME_SECONDS)
        operation.claim_plan(self.root, self.plan_id, self.key, now=101)
        with self.assertRaisesRegex(operation.OperationError, "already_claimed"):
            operation.claim_plan(self.root, self.plan_id, self.key, now=101)

    def test_plan_file_change_is_rejected(self):
        operation.create_plan(self.root, self.destination, self.volume,
                              self.identities, self.key, now=100,
                              plan_id=self.plan_id)
        path = self.root / f"{self.plan_id}.json"
        payload = path.read_text().replace(str(self.destination), "/tmp/attacker")
        path.write_text(payload)
        with self.assertRaisesRegex(operation.OperationError, "authentication_failed"):
            operation.load_plan(self.root, self.plan_id, self.key, now=101)


if __name__ == "__main__":
    unittest.main()
