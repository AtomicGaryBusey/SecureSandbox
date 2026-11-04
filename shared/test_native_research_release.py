#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shared import native_research_release as release


class NativeResearchReleaseTests(unittest.TestCase):
    def test_name_mode_and_content_are_all_release_bound(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            first.chmod(0o444)
            second.chmod(0o555)
            manifest = root / "release.json"
            inventory = {str(first): 0o444, str(second): 0o555}
            with mock.patch.object(release, "EXPECTED_ARTIFACTS", inventory):
                value = release.observe(
                    package_sha256="a" * 64,
                    trusted_uid=uid, trusted_gid=gid)
                manifest.write_bytes(release.canonical(value))
                manifest.chmod(0o444)
                self.assertEqual(release.verify_installed(
                    manifest=manifest, trusted_uid=uid,
                    trusted_gid=gid), value)
                second.chmod(0o644)
                second.write_bytes(b"changed")
                second.chmod(0o555)
                with self.assertRaisesRegex(
                    release.NativeResearchReleaseError, "readback_mismatch"
                ):
                    release.verify_installed(
                        manifest=manifest, trusted_uid=uid,
                        trusted_gid=gid)

    def test_manifest_cannot_omit_or_rename_inventory(self) -> None:
        inventory = {"/fixed/a": 0o444, "/fixed/b": 0o555}
        body = {"schema": release.SCHEMA, "package_sha256": "a" * 64,
                "artifacts": [{
            "path": "/fixed/a", "mode": 0o444, "sha256": "1" * 64}]}
        value = {**body, "release_id": release.digest(body)}
        with mock.patch.object(release, "EXPECTED_ARTIFACTS", inventory), \
             self.assertRaisesRegex(
                 release.NativeResearchReleaseError, "manifest_invalid"):
            release.validate(value)


if __name__ == "__main__":
    unittest.main()
