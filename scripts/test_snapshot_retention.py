import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("snapshot_retention", Path(__file__).with_name("snapshot_retention.py"))
SNAPSHOTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOTS)


class SnapshotRetentionTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"schema": "secure-sandbox-snapshot-retention-v1",
                       "maximum_snapshots_per_vm": 2,
                       "minimum_free_gib_for_apply": 1,
                       "virtual_machines": list(SNAPSHOTS.NAMES),
                       "retain_names": ["baseline", "current"]}
        self.states = {name: "stopped" for name in SNAPSHOTS.NAMES}
        self.inventories = {name: {
            "base": {"name": "baseline", "date": "2026-01-01", "current": False},
            "extra": {"name": "obsolete", "date": "2026-01-02", "current": False},
            "now": {"name": "current", "date": "2026-01-03", "current": True}}
            for name in SNAPSHOTS.NAMES}

    def test_policy_rejects_duplicate_retained_names(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(json.dumps({**self.policy, "retain_names": ["current", "current"]}))
            with patch.object(SNAPSHOTS, "POLICY", policy_path):
                with self.assertRaisesRegex(SNAPSHOTS.SnapshotError, "snapshot_policy_invalid"):
                    SNAPSHOTS.load_policy()

    def test_apply_checks_all_vm_inventories_before_deleting_any_snapshot(self):
        self.inventories[SNAPSHOTS.NAMES[1]].pop("base")
        calls = []
        def command(*arguments):
            calls.append(arguments)
            if arguments[0] == "snapshot-list":
                return json.dumps(self.inventories[arguments[1]])
            if arguments[0] == "list":
                return "\n".join(f"stopped {name}" for name in SNAPSHOTS.NAMES)
            raise AssertionError("Deletion began before preflight finished")
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "prlctl"
            executable.touch()
            with (patch.object(SNAPSHOTS, "PRLCTL", executable),
                  patch.object(SNAPSHOTS, "load_policy", return_value=self.policy),
                  patch.object(SNAPSHOTS, "lifecycle_module", return_value=SimpleNamespace(ensure_mutation_preconditions=lambda _: -1)),
                  patch.object(SNAPSHOTS, "free_bytes", return_value=2 * 1024**3),
                  patch.object(SNAPSHOTS, "prlctl", side_effect=command)):
                with self.assertRaisesRegex(SNAPSHOTS.SnapshotError, "Retention milestone"):
                    SNAPSHOTS.execute(apply=True)
        self.assertFalse(any(call[0] == "snapshot-delete" for call in calls))

    def test_apply_deletes_only_unretained_ids_and_reads_back_each_vm(self):
        calls = []
        def command(*arguments):
            calls.append(arguments)
            if arguments[0] == "list":
                return "\n".join(f"stopped {name}" for name in SNAPSHOTS.NAMES)
            if arguments[0] == "snapshot-list":
                return json.dumps(self.inventories[arguments[1]])
            if arguments[0] == "snapshot-delete":
                self.inventories[arguments[1]].pop(arguments[3])
                return ""
            raise AssertionError(arguments)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "prlctl"
            executable.touch()
            with (patch.object(SNAPSHOTS, "PRLCTL", executable),
                  patch.object(SNAPSHOTS, "load_policy", return_value=self.policy),
                  patch.object(SNAPSHOTS, "lifecycle_module", return_value=SimpleNamespace(ensure_mutation_preconditions=lambda _: -1)),
                  patch.object(SNAPSHOTS, "free_bytes", return_value=2 * 1024**3),
                  patch.object(SNAPSHOTS, "prlctl", side_effect=command)):
                rows = SNAPSHOTS.execute(apply=True)
        self.assertEqual(len(rows), 3)
        self.assertEqual([call for call in calls if call[0] == "snapshot-delete"],
                         [("snapshot-delete", name, "--id", "extra") for name in SNAPSHOTS.NAMES])
        self.assertEqual([call[1] for call in calls if call[0] == "snapshot-list"],
                         list(SNAPSHOTS.NAMES) * 2)


if __name__ == "__main__":
    unittest.main()
