#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from shared import native_research_release as release


class NativeResearchReleaseTests(unittest.TestCase):
    @staticmethod
    def _terminal(
        promotion_id: str, previous: str, current: str,
        *, host_previous: str | None | object = Ellipsis,
    ) -> dict:
        host = previous if host_previous is Ellipsis else host_previous
        body = {
            "promotion_id": promotion_id,
            "plan_sha256": "1" * 64,
            "host_previous_catalog_sha256": host,
            "previous_catalog_sha256": previous,
            "catalog_sha256": current,
            "fence_sha256": "2" * 64,
            "publish_request_sha256": "3" * 64,
            "phase": "released",
            "observed_catalog_sha256": current,
            "release_request_sha256": "4" * 64,
            "release_evidence_sha256": "5" * 64,
        }
        return {
            "schema": release.CATALOG_PUBLICATION_SCHEMA, **body,
            "journal_sha256": release.digest(body),
        }

    @staticmethod
    def _catalog_module() -> SimpleNamespace:
        return SimpleNamespace(
            load_catalog=lambda path, private=False: json.loads(
                path.read_bytes()),
            canonical_bytes=release.canonical,
        )

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

    def test_legacy_v1_manifest_is_exact_and_typed(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            first.chmod(0o444)
            second.chmod(0o555)
            inventory = {str(first): 0o444, str(second): 0o555}
            artifacts = [
                release._artifact(
                    Path(name), mode, trusted_uid=uid, trusted_gid=gid)
                for name, mode in sorted(inventory.items())
            ]
            body = {"schema": release.LEGACY_SCHEMA, "artifacts": artifacts}
            legacy = {**body, "release_id": release.digest(body)}
            manifest = root / "release.json"
            manifest.write_bytes(release.canonical(legacy))
            manifest.chmod(0o444)
            new_only = root / "new-only"
            with mock.patch.object(
                     release, "LEGACY_EXPECTED_ARTIFACTS", inventory), \
                 mock.patch.object(release, "LEGACY_NEW_ONLY", {str(new_only)}):
                admitted = release.verify_legacy_installed(
                    manifest=manifest, trusted_uid=uid, trusted_gid=gid)
                self.assertEqual(
                    admitted["schema"], release.LEGACY_ADMISSION_SCHEMA)
                self.assertEqual(admitted["artifacts"], artifacts)
                changed = json.loads(manifest.read_bytes())
                changed["artifacts"][0]["sha256"] = "0" * 64
                manifest.chmod(0o644)
                manifest.write_bytes(release.canonical(changed))
                manifest.chmod(0o444)
                with self.assertRaises(
                    release.NativeResearchReleaseError
                ):
                    release.verify_legacy_installed(
                        manifest=manifest, trusted_uid=uid, trusted_gid=gid)

    def test_v2_catalog_transition_is_narrow_and_v3_omits_catalog(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "runtime.py"
            artifact.write_bytes(b"runtime")
            artifact.chmod(0o444)
            catalog = root / "catalog.json"
            baseline_raw = release.canonical({"catalog": "a"})
            current_raw = release.canonical({"catalog": "b"})
            catalog.write_bytes(baseline_raw)
            catalog.chmod(0o644)
            prior_inventory = {str(artifact): 0o444, str(catalog): 0o644}
            artifacts = [
                release._artifact(
                    Path(name), mode, trusted_uid=uid, trusted_gid=gid)
                for name, mode in sorted(prior_inventory.items())
            ]
            body = {
                "schema": release.PRIOR_SCHEMA,
                "package_sha256": "a" * 64,
                "artifacts": artifacts,
            }
            manifest_value = {**body, "release_id": release.digest(body)}
            manifest = root / "release.json"
            manifest.write_bytes(release.canonical(manifest_value))
            manifest.chmod(0o444)
            catalog.write_bytes(current_raw)
            catalog.chmod(0o644)
            lifecycle = root / "lifecycle"
            lifecycle.mkdir(mode=0o700)
            promotion_id = str(uuid.uuid4())
            terminal = self._terminal(
                promotion_id,
                release.hashlib.sha256(baseline_raw).hexdigest(),
                release.hashlib.sha256(current_raw).hexdigest())
            terminal_path = lifecycle / (
                f"catalog-publication.{promotion_id}.released.json")
            terminal_path.write_bytes(release.canonical(terminal))
            terminal_path.chmod(0o600)
            lifecycle_fd = os.open(
                lifecycle, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with mock.patch.object(
                         release, "PRIOR_EXPECTED_ARTIFACTS",
                         prior_inventory), \
                     mock.patch.object(
                         release, "EXPECTED_ARTIFACTS",
                         {str(artifact): 0o444}), \
                     mock.patch.object(release, "CATALOG", catalog):
                    admitted = release.verify_transition_predecessor(
                        lifecycle_fd=lifecycle_fd,
                        catalog_module=self._catalog_module(),
                        expected_catalog_sha256=(
                            release.hashlib.sha256(current_raw).hexdigest()),
                        manifest=manifest, catalog_path=catalog,
                        lifecycle_root=lifecycle,
                        trusted_uid=uid, trusted_gid=gid)
                    self.assertEqual(admitted, manifest_value)
                    with self.assertRaisesRegex(
                        release.NativeResearchReleaseError,
                        "readback_mismatch",
                    ):
                        release.verify_installed(
                            manifest=manifest, trusted_uid=uid,
                            trusted_gid=gid)
            finally:
                os.close(lifecycle_fd)
        self.assertNotIn(str(release.CATALOG), release.EXPECTED_ARTIFACTS)
        self.assertIn(str(release.CATALOG), release.PRIOR_EXPECTED_ARTIFACTS)

    def test_catalog_transition_rejects_active_fork_cycle_and_non_sink(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        a, b, c = "a" * 64, "b" * 64, "c" * 64
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = Path(directory)

            def write(previous: str, current: str) -> Path:
                promotion_id = str(uuid.uuid4())
                path = lifecycle / (
                    f"catalog-publication.{promotion_id}.released.json")
                path.write_bytes(release.canonical(self._terminal(
                    promotion_id, previous, current)))
                path.chmod(0o600)
                return path

            descriptor = os.open(
                lifecycle, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                active = lifecycle / "catalog-publication.json"
                active.write_bytes(b"{}\n")
                active.chmod(0o600)
                with self.assertRaisesRegex(
                    release.NativeResearchReleaseError, "transition_active"
                ):
                    release._require_catalog_transition_chain(
                        descriptor, previous_catalog_sha256=a,
                        catalog_sha256=a, lifecycle_root=lifecycle,
                        trusted_uid=uid, trusted_gid=gid)
                active.unlink()
                first = write(a, b)
                write(a, c)
                with self.assertRaisesRegex(
                    release.NativeResearchReleaseError, "history_invalid"
                ):
                    release._require_catalog_transition_chain(
                        descriptor, previous_catalog_sha256=a,
                        catalog_sha256=b, lifecycle_root=lifecycle,
                        trusted_uid=uid, trusted_gid=gid)
                for path in lifecycle.iterdir():
                    path.unlink()
                write(a, b)
                write(b, c)
                with self.assertRaisesRegex(
                    release.NativeResearchReleaseError, "history_invalid"
                ):
                    release._require_catalog_transition_chain(
                        descriptor, previous_catalog_sha256=a,
                        catalog_sha256=b, lifecycle_root=lifecycle,
                        trusted_uid=uid, trusted_gid=gid)
                for path in lifecycle.iterdir():
                    path.unlink()
                write(a, b)
                write(b, a)
                with self.assertRaisesRegex(
                    release.NativeResearchReleaseError, "history_invalid"
                ):
                    release._require_catalog_transition_chain(
                        descriptor, previous_catalog_sha256=a,
                        catalog_sha256=c, lifecycle_root=lifecycle,
                        trusted_uid=uid, trusted_gid=gid)
            finally:
                os.close(descriptor)

    def test_v1_empty_catalog_transition_preserves_synthetic_identity(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "legacy.py"
            artifact.write_bytes(b"legacy")
            artifact.chmod(0o444)
            catalog = root / "catalog.json"
            catalog.write_bytes(release.canonical({"stacks": []}))
            catalog.chmod(0o644)
            inventory = {str(artifact): 0o444, str(catalog): 0o644}
            artifacts = [
                release._artifact(
                    Path(name), mode, trusted_uid=uid, trusted_gid=gid)
                for name, mode in sorted(inventory.items())
            ]
            # Bind the canonical empty digest exactly as the v1 manifest's
            # installed catalog artifact identity.
            artifacts = [
                ({**item, "sha256": release.EMPTY_CATALOG_SHA256}
                 if item["path"] == str(catalog) else item)
                for item in artifacts
            ]
            body = {"schema": release.LEGACY_SCHEMA, "artifacts": artifacts}
            legacy = {**body, "release_id": release.digest(body)}
            manifest = root / "release.json"
            manifest.write_bytes(release.canonical(legacy))
            manifest.chmod(0o444)
            current_raw = release.canonical({"stacks": ["first"]})
            catalog.write_bytes(current_raw)
            catalog.chmod(0o644)
            current_sha = release.hashlib.sha256(current_raw).hexdigest()
            lifecycle = root / "lifecycle"
            lifecycle.mkdir(mode=0o700)
            promotion_id = str(uuid.uuid4())
            terminal = self._terminal(
                promotion_id, release.EMPTY_CATALOG_SHA256, current_sha,
                host_previous=None)
            terminal_path = lifecycle / (
                f"catalog-publication.{promotion_id}.released.json")
            terminal_path.write_bytes(release.canonical(terminal))
            terminal_path.chmod(0o600)
            descriptor = os.open(
                lifecycle, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with mock.patch.object(
                         release, "LEGACY_EXPECTED_ARTIFACTS", inventory), \
                     mock.patch.object(release, "LEGACY_NEW_ONLY", set()), \
                     mock.patch.object(release, "CATALOG", catalog):
                    admitted = release.verify_transition_predecessor(
                        lifecycle_fd=descriptor,
                        catalog_module=self._catalog_module(),
                        expected_catalog_sha256=current_sha,
                        manifest=manifest, catalog_path=catalog,
                        lifecycle_root=lifecycle,
                        trusted_uid=uid, trusted_gid=gid)
                expected = release._admit_legacy(legacy, artifacts)
                self.assertEqual(admitted, expected)
            finally:
                os.close(descriptor)

    def test_catalog_baseline_and_first_empty_promotion_are_exact(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = Path(directory)
            descriptor = os.open(
                lifecycle, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                release._require_catalog_transition_chain(
                    descriptor, previous_catalog_sha256="a" * 64,
                    catalog_sha256="a" * 64, lifecycle_root=lifecycle,
                    trusted_uid=uid, trusted_gid=gid)
                promotion_id = str(uuid.uuid4())
                terminal = self._terminal(
                    promotion_id, release.EMPTY_CATALOG_SHA256, "b" * 64,
                    host_previous=None)
                path = lifecycle / (
                    f"catalog-publication.{promotion_id}.released.json")
                path.write_bytes(release.canonical(terminal))
                path.chmod(0o600)
                release._require_catalog_transition_chain(
                    descriptor,
                    previous_catalog_sha256=release.EMPTY_CATALOG_SHA256,
                    catalog_sha256="b" * 64, lifecycle_root=lifecycle,
                    trusted_uid=uid, trusted_gid=gid)
                malformed = lifecycle / "catalog-publication.untrusted"
                malformed.write_bytes(b"{}\n")
                malformed.chmod(0o600)
                with self.assertRaisesRegex(
                    release.NativeResearchReleaseError, "transition_active"
                ):
                    release._require_catalog_transition_chain(
                        descriptor,
                        previous_catalog_sha256=(
                            release.EMPTY_CATALOG_SHA256),
                        catalog_sha256="b" * 64,
                        lifecycle_root=lifecycle,
                        trusted_uid=uid, trusted_gid=gid)
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
