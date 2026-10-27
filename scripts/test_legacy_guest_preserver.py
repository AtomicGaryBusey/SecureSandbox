import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("legacy_guest_preserver.py")
SPEC = importlib.util.spec_from_file_location("legacy_guest_preserver", SCRIPT)
PRESERVER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PRESERVER)


class LegacyGuestPreserverTests(unittest.TestCase):
    def inventory(self, candidates=1):
        children = [{
            "name": f"/dev/vdb{index + 1}", "path": f"/dev/vdb{index + 1}",
            "type": "part", "pkname": "/dev/vdb", "fstype": "ext4",
            "mountpoints": [None], "ro": False,
        } for index in range(candidates)]
        return json.dumps({"blockdevices": [
            {"name": "/dev/vda", "path": "/dev/vda", "type": "disk", "pkname": None,
             "fstype": None, "mountpoints": [None], "ro": False, "children": [
                 {"name": "/dev/vda2", "path": "/dev/vda2", "type": "part",
                  "pkname": "/dev/vda", "fstype": "ext4", "mountpoints": ["/"], "ro": False}
             ]},
            {"name": "/dev/vdb", "path": "/dev/vdb", "type": "disk", "pkname": None,
             "fstype": None, "mountpoints": [None], "ro": False, "children": children},
        ]})

    def test_selects_only_unmounted_non_root_ext4_partition(self):
        def fake_run(command, **_kwargs):
            if command[0] == "/usr/bin/lsblk":
                return self.inventory()
            return "/dev/vda2\n"
        block = mock.Mock(st_mode=0o060000)
        with mock.patch.object(PRESERVER, "run", side_effect=fake_run), \
             mock.patch.object(PRESERVER.Path, "resolve", return_value=Path("/dev/vdb1")), \
             mock.patch.object(PRESERVER.Path, "stat", return_value=block):
            self.assertEqual(
                PRESERVER.select_legacy_partition(),
                (Path("/dev/vdb1"), Path("/dev/vdb1")),
            )

    def test_rejects_ambiguous_legacy_partitions(self):
        with mock.patch.object(
                PRESERVER, "run", side_effect=["", "/dev/vda2\n", self.inventory(2)]):
            with self.assertRaisesRegex(PRESERVER.PreservationError, "legacy_partition_ambiguous:2"):
                PRESERVER.select_legacy_partition()

    def test_waits_for_hot_added_partition_to_settle(self):
        calls = iter(["", "/dev/vda2\n", self.inventory(0), self.inventory(1)])
        block = mock.Mock(st_mode=0o060000)
        with mock.patch.object(PRESERVER, "run", side_effect=lambda *_args, **_kwargs: next(calls)), \
             mock.patch.object(PRESERVER.time, "sleep") as sleep, \
             mock.patch.object(PRESERVER.Path, "resolve", return_value=Path("/dev/vdb1")), \
             mock.patch.object(PRESERVER.Path, "stat", return_value=block):
            self.assertEqual(
                PRESERVER.select_legacy_partition(attempts=2, delay=0.01),
                (Path("/dev/vdb1"), Path("/dev/vdb1")),
            )
        sleep.assert_called_once_with(0.01)

    def test_zero_candidates_remains_fail_closed_after_bound(self):
        with mock.patch.object(
                PRESERVER, "run",
                side_effect=["", "/dev/vda2\n", self.inventory(0), self.inventory(0)]), \
             mock.patch.object(PRESERVER.time, "sleep"):
            with self.assertRaisesRegex(
                    PRESERVER.PreservationError,
                    r"legacy_partition_ambiguous:0:layout=.*disk.*part.*ext4"):
                PRESERVER.select_legacy_partition(attempts=2, delay=0)

    def test_layout_diagnostic_omits_device_and_volume_names(self):
        values = PRESERVER.flatten_devices(json.loads(self.inventory())["blockdevices"])
        layout = PRESERVER.sanitized_block_layout(values, "/dev/vda2")
        self.assertIn("0:disk:none:-:u:rw:-", layout)
        self.assertIn("1:part:ext4:0:m:rw:root", layout)
        self.assertNotIn("vda", layout)
        self.assertNotIn("vdb", layout)

    def test_layout_diagnostic_reveals_lvm_shape_without_lv_name(self):
        devices = [{
            "path": "/dev/legacy-secret", "type": "part", "pkname": "/dev/vdb",
            "fstype": "LVM2_member", "mountpoints": [None], "ro": 0,
        }, {
            "path": "/dev/mapper/operator-chosen-name", "type": "lvm",
            "pkname": "/dev/legacy-secret", "fstype": "ext4",
            "mountpoints": [None], "ro": 0,
        }]
        layout = PRESERVER.sanitized_block_layout(devices, "/dev/vda2")
        self.assertEqual(
            layout,
            "0:part:LVM2_member:-:u:rw:-,1:lvm:ext4:0:u:rw:-",
        )
        self.assertNotIn("legacy-secret", layout)
        self.assertNotIn("operator-chosen-name", layout)

    def test_mount_verification_requires_every_safety_option(self):
        with mock.patch.object(PRESERVER.Path, "resolve", return_value=Path("/dev/vdb1")), \
             mock.patch.object(PRESERVER, "run", side_effect=["/dev/vdb1\n", "ro,nodev,nosuid\n"]):
            with self.assertRaisesRegex(PRESERVER.PreservationError, "legacy_mount_options_invalid"):
                PRESERVER.verify_mount(Path("/dev/vdb1"), Path("/dev/vdb"))

    def test_mount_verification_accepts_unreported_noload_and_rechecks_backing_ro(self):
        with mock.patch.object(PRESERVER.Path, "resolve", return_value=Path("/dev/vdb1")), \
             mock.patch.object(
                 PRESERVER, "run",
                 side_effect=["/dev/vdb1\n", "ro,nodev,nosuid,noexec,relatime\n", "1\n", "1\n"],
             ):
            PRESERVER.verify_mount(Path("/dev/vdb1"), Path("/dev/vdb"))

    def test_mount_command_always_requests_noload_and_all_vfs_restrictions(self):
        with mock.patch.object(PRESERVER, "run") as run:
            PRESERVER.mount_legacy_partition(Path("/dev/vdb1"))
        run.assert_called_once_with([
            "/usr/bin/mount", "-t", "ext4", "-o", "ro,noload,nodev,nosuid,noexec",
            "/dev/vdb1", str(PRESERVER.MOUNTPOINT),
        ])

    def test_block_device_must_report_read_only_after_setro(self):
        with mock.patch.object(PRESERVER, "run", side_effect=["", "", "1\n", "0\n"]):
            with self.assertRaisesRegex(PRESERVER.PreservationError, "block_device_writable"):
                PRESERVER.make_device_read_only(Path("/dev/vdb"), Path("/dev/vdb1"))

    def test_lifecycle_requires_exact_pgrep_no_match(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(PRESERVER, "Path", wraps=Path), \
             mock.patch.object(PRESERVER.subprocess, "run", return_value=mock.Mock(returncode=2)):
            with self.assertRaisesRegex(PRESERVER.PreservationError, "agent_lifecycle_not_idle"):
                PRESERVER.require_idle()


if __name__ == "__main__":
    unittest.main()
