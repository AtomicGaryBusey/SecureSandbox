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


if __name__ == "__main__":
    unittest.main()
