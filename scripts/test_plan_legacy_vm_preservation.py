import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("plan-legacy-vm-preservation.py")
SPEC = importlib.util.spec_from_file_location("plan_legacy_vm_preservation", SCRIPT)
PLAN = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PLAN)


class LegacyVmPreservationPlanTests(unittest.TestCase):
    def test_disk_inventory_binds_metadata_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            disk = Path(directory) / "disk.hdd"
            disk.mkdir(mode=0o700)
            (disk / "DiskDescriptor.xml").write_text("descriptor")
            first = PLAN.disk_inventory(disk, os.geteuid())
            (disk / "DiskDescriptor.xml").write_text("changed")
            second = PLAN.disk_inventory(disk, os.geteuid())
            self.assertNotEqual(first["tree_metadata_sha256"], second["tree_metadata_sha256"])
            (disk / "escape").symlink_to("DiskDescriptor.xml")
            with self.assertRaisesRegex(PLAN.PlanError, "legacy_disk_symlink"):
                PLAN.disk_inventory(disk, os.geteuid())

    def test_plan_binds_generation_sources_vm_tools_and_prlctl(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            generation = "20261021T040946Z"
            root = repo / ".private/vm-quarantine" / generation
            root.mkdir(parents=True, mode=0o700)
            os.chmod(repo / ".private", 0o700)
            os.chmod(repo / ".private/vm-quarantine", 0o700)
            for bundle in PLAN.ROLE_BUNDLES.values():
                disk = root / bundle / "harddisk1.hdd"
                disk.mkdir(parents=True, mode=0o700)
                os.chmod(disk.parent, 0o700)
                extent = "harddisk1.hdd.0.{00000000-0000-4000-8000-000000000001}.hds"
                (disk / extent).write_bytes(b"extent")
                (disk / "DiskDescriptor.xml").write_text(
                    "<Parallels_disk_image><StorageData><Storage><Image>"
                    f"<File>{extent}</File>"
                    "</Image></Storage></StorageData></Parallels_disk_image>"
                )
                (disk.parent / "config.pvs").write_text(
                    "<ParallelsVirtualMachine><VmUuid>{00000000-0000-4000-8000-000000000001}</VmUuid></ParallelsVirtualMachine>"
                )
            maintenance = mock.Mock()
            maintenance.trusted_repo.return_value = repo
            maintenance.pending_transaction.return_value = None
            maintenance.PRLCTL = Path("/protected/prlctl")
            maintenance.normalize_vm_uuid.return_value = "{00000000-0000-4000-8000-000000000002}"
            vm_homes = {
                name: repo / f"vms/{name}.pvm"
                for name in ("SecureSandbox-Gateway", "SecureSandbox-Research")
            }
            for home in vm_homes.values():
                home.mkdir(parents=True)
                disk = home / "harddisk.hdd"
                disk.mkdir()
            def inventory(command, capture=False):
                if command[-2:] == ["-a", "-j"]:
                    return "[]"
                return __import__("json").dumps([{
                    "Name": command[-1], "ID": "00000000-0000-4000-8000-000000000002",
                    "State": "stopped", "Home": str(vm_homes[command[-1]]) + "/",
                    "Boot order": "hdd0 ",
                    "Hardware": {"hdd0": {
                        "enabled": True,
                        "image": str(vm_homes[command[-1]] / "harddisk.hdd"),
                    }},
                    "Host Shared Folders": {"enabled": False},
                    "SmartMount": {"enabled": False},
                    "Miscellaneous Sharing": {
                        "Shared clipboard mode": "off", "Shared cloud": "off",
                    },
                }])
            maintenance.run.side_effect = inventory
            maintenance.prlctl_hash.return_value = "a" * 64
            with mock.patch.object(PLAN, "load_maintenance", return_value=maintenance), \
                 mock.patch.object(PLAN, "sha256_regular", return_value="b" * 64), \
                 mock.patch.object(PLAN, "protected_hash", return_value="c" * 64):
                value = PLAN.build_plan(str(repo), generation, os.geteuid())
            self.assertEqual(value["generation"], generation)
            self.assertEqual(set(value["sources"]), set(PLAN.ROLE_BUNDLES))
            self.assertEqual(value["tools"], {name: "b" * 64 for name in PLAN.TOOL_PATHS})
            unsigned = dict(value)
            claimed = unsigned.pop("plan_sha256")
            unsigned.pop("free_bytes")
            self.assertEqual(claimed, __import__("hashlib").sha256(PLAN.canonical(unsigned)).hexdigest())

    def test_disk_descriptor_rejects_extent_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            disk = Path(directory) / "disk.hdd"
            disk.mkdir()
            descriptor = (
                "<Parallels_disk_image><StorageData><Storage><Image>"
                "<File>../outside.hds</File>"
                "</Image></Storage></StorageData></Parallels_disk_image>"
            ).encode()
            with self.assertRaisesRegex(PLAN.PlanError, "extent_reference_unsafe"):
                PLAN.validate_disk_descriptor(disk, descriptor, os.geteuid())


if __name__ == "__main__":
    unittest.main()
