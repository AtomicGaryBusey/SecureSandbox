#!/usr/bin/env python3

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shared import native_gateway_release as release


class NativeGatewayReleaseTests(unittest.TestCase):
    def test_release_binds_package_name_mode_and_content(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            first.chmod(0o444)
            second.chmod(0o555)
            manifest = root / "release.json"
            inventory = {str(first): 0o444, str(second): 0o555}
            with mock.patch.object(release, "EXPECTED_ARTIFACTS", inventory):
                value = release.observe(
                    package_sha256="a" * 64,
                    trusted_uid=uid, trusted_gid=gid,
                )
                manifest.write_bytes(release.canonical(value))
                manifest.chmod(0o444)
                self.assertEqual(
                    release.verify_installed(
                        manifest=manifest, trusted_uid=uid, trusted_gid=gid,
                    ),
                    value,
                )
                second.chmod(0o644)
                second.write_bytes(b"changed")
                second.chmod(0o555)
                with self.assertRaisesRegex(
                    release.NativeGatewayReleaseError, "readback_mismatch"
                ):
                    release.verify_installed(
                        manifest=manifest, trusted_uid=uid, trusted_gid=gid,
                    )

    def test_manifest_cannot_omit_package_or_inventory(self) -> None:
        inventory = {"/fixed/a": 0o444, "/fixed/b": 0o555}
        body = {
            "schema": release.SCHEMA,
            "package_sha256": "a" * 64,
            "artifacts": [{
                "path": "/fixed/a", "mode": 0o444, "sha256": "1" * 64,
            }],
        }
        value = {**body, "release_id": release.digest(body)}
        with mock.patch.object(release, "EXPECTED_ARTIFACTS", inventory), \
             self.assertRaisesRegex(
                 release.NativeGatewayReleaseError, "manifest_invalid"
             ):
            release.validate(value)

    def test_legacy_identity_binds_complete_inventory_and_rejects_mixed(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            first.chmod(0o444)
            second.chmod(0o555)
            manifest = root / "release.json"
            new_only = root / "new-only"
            inventory = {str(first): 0o444, str(second): 0o555}
            with mock.patch.object(release, "MANIFEST", manifest), \
                 mock.patch.object(release, "LEGACY_NEW_ONLY", {str(new_only)}), \
                 mock.patch.object(
                     release, "LEGACY_EXPECTED_ARTIFACTS", inventory):
                value = release.verify_legacy_installed(
                    trusted_uid=uid, trusted_gid=gid)
                self.assertEqual(value["schema"], release.LEGACY_SCHEMA)
                self.assertEqual(len(value["artifacts"]), 2)
                second.chmod(0o444)
                with self.assertRaises(release.NativeGatewayReleaseError):
                    release.verify_legacy_installed(
                        trusted_uid=uid, trusted_gid=gid)
                second.chmod(0o555)
                new_only.write_bytes(b"mixed")
                with self.assertRaisesRegex(
                    release.NativeGatewayReleaseError, "mixed_generation"
                ):
                    release.verify_legacy_installed(
                        trusted_uid=uid, trusted_gid=gid)


if __name__ == "__main__":
    unittest.main()
