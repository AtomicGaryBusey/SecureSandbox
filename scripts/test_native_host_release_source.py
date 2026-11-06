#!/usr/bin/env python3
"""Focused hostile tests for native Host exact-source preparation."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parent.parent
HELPER_PATH = REPO / "scripts/native_host_release_source.py"
SPEC = importlib.util.spec_from_file_location("native_host_release_source", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)


class NativeHostReleaseSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir(mode=0o700)
        self.git("init", "-b", "public-release")
        self.git("config", "user.name", "SecureSandbox Test")
        self.git("config", "user.email", "test@example.invalid")
        package = self.repo / "macos/TouchIDAuthorization"
        package.mkdir(parents=True)
        (package / "source.txt").write_text("trusted source\n", encoding="ascii")
        script = self.repo / "scripts/build.sh"
        script.parent.mkdir()
        script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        script.chmod(0o755)
        self.git("add", ".")
        self.git("commit", "-m", "fixture")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.archive = self.workspace / "source.tar"
        self.source = self.workspace / "source"
        self.source.mkdir(mode=0o700)

    def tearDown(self) -> None:
        for directory, _children, _files in os.walk(
            self.root, topdown=True, followlinks=False,
        ):
            try:
                os.chmod(directory, 0o700)
            except FileNotFoundError:
                pass
        self.temporary.cleanup()

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), *arguments], check=True,
            capture_output=True, text=True,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(self.root), "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_NO_REPLACE_OBJECTS": "1",
            },
        )

    def prepare(self):
        return SOURCE.prepare(self.repo, self.archive, self.source)

    def inject_signing_config(self) -> str:
        path = self.source / SOURCE.SIGNING_CONFIG_RELATIVE
        path.write_bytes(SOURCE.EXPECTED_SIGNING_CONFIG)
        path.chmod(0o444)
        import hashlib
        return hashlib.sha256(SOURCE.EXPECTED_SIGNING_CONFIG).hexdigest()

    def test_prepares_and_reverifies_exact_archive_tree(self) -> None:
        prepared = self.prepare()
        self.assertEqual(prepared["commit"], self.commit)
        digest = self.inject_signing_config()
        verified = SOURCE.verify_source(
            self.archive, self.source, prepared["archive_sha256"], digest,
        )
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(
            verified["archive_tree_sha256"], prepared["source_tree_sha256"],
        )

    def test_rejects_repository_local_attribute_override(self) -> None:
        attributes = self.repo / ".git/info/attributes"
        attributes.write_text("scripts/build.sh export-ignore\n", encoding="ascii")
        with self.assertRaisesRegex(
            SOURCE.SourceError, "release_source_git_override_forbidden",
        ):
            self.prepare()

    def test_rejects_replace_refs_even_when_git_would_ignore_them(self) -> None:
        replacement = self.repo / ".git/refs/replace" / self.commit
        replacement.parent.mkdir()
        replacement.write_text(self.commit + "\n", encoding="ascii")
        with self.assertRaisesRegex(
            SOURCE.SourceError, "release_source_git_replace_ref_forbidden",
        ):
            self.prepare()

    def test_rejects_assume_unchanged_index_entries(self) -> None:
        self.git("update-index", "--assume-unchanged", "scripts/build.sh")
        with self.assertRaisesRegex(
            SOURCE.SourceError, "release_source_git_index_flags_forbidden",
        ):
            self.prepare()

    def test_rejects_tracked_symlink_before_archive(self) -> None:
        link = self.repo / "outside-link"
        link.symlink_to("scripts/build.sh")
        self.git("add", "outside-link")
        self.git("commit", "-m", "add forbidden link")
        with self.assertRaisesRegex(
            SOURCE.SourceError, "release_source_git_tree_entry_forbidden",
        ):
            self.prepare()

    def test_rejects_extracted_source_mutation(self) -> None:
        prepared = self.prepare()
        digest = self.inject_signing_config()
        source = self.source / "scripts/build.sh"
        source.chmod(0o755)
        source.write_text("#!/bin/sh\nexit 7\n", encoding="ascii")
        source.chmod(0o555)
        with self.assertRaisesRegex(
            SOURCE.SourceError, "release_source_tree_mismatch",
        ):
            SOURCE.verify_source(
                self.archive, self.source, prepared["archive_sha256"], digest,
            )

    def test_directory_identity_changes_after_path_substitution(self) -> None:
        first = SOURCE.identity_value(self.source)
        displaced = self.workspace / "source-old"
        self.source.rename(displaced)
        self.source.mkdir(mode=0o700)
        second = SOURCE.identity_value(self.source)
        self.assertNotEqual(first, second)

    def test_descriptor_anchored_build_directory_lifecycle(self) -> None:
        parent_identity = json.dumps(SOURCE.identity_value(self.workspace))
        parent_fd = os.open(
            self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        root_fd = -1
        try:
            created = SOURCE.create_build_directory_at(
                parent_fd, ".build.", parent_identity,
            )
            root = self.workspace / created["name"]
            root_fd = os.open(
                root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            (root / "evidence").write_text("retained\n", encoding="ascii")
            verified = SOURCE.verify_build_directory_at(
                parent_fd, root_fd, created["name"], parent_identity,
                json.dumps(created), parent_path=self.workspace,
                root_path=root,
            )
            self.assertEqual(verified["status"], "verified")
            retired = SOURCE.retire_build_directory_at(
                parent_fd, root_fd, created["name"], parent_identity,
                json.dumps(created), parent_path=self.workspace,
            )
            self.assertEqual(retired["disposition"], "retained")
            self.assertFalse(root.exists())
            self.assertEqual(
                (self.workspace / retired["retained_name"] / "evidence")
                .read_text(encoding="ascii"),
                "retained\n",
            )
        finally:
            if root_fd >= 0:
                os.close(root_fd)
            os.close(parent_fd)

    def test_fd_cleanup_retires_original_when_parent_path_is_displaced(self) -> None:
        parent = self.root / "build-parent"
        parent.mkdir(mode=0o700)
        parent_identity = json.dumps(SOURCE.identity_value(parent))
        parent_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        root_fd = -1
        parked = self.root / "build-parent-parked"
        try:
            created = SOURCE.create_build_directory_at(
                parent_fd, ".build.", parent_identity,
            )
            root = parent / created["name"]
            root_fd = os.open(
                root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            (root / "must-survive").write_text("evidence\n", encoding="ascii")
            parent.rename(parked)
            parent.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                SOURCE.SourceError,
                "release_build_parent_path_changed:retained=",
            ):
                SOURCE.retire_build_directory_at(
                    parent_fd, root_fd, created["name"], parent_identity,
                    json.dumps(created), parent_path=parent,
                )
            retained = list(parked.glob(".secure-sandbox-retained-*"))
            self.assertEqual(len(retained), 1)
            self.assertEqual(
                (retained[0] / "must-survive").read_text(encoding="ascii"),
                "evidence\n",
            )
            self.assertEqual(list(parent.iterdir()), [])
        finally:
            if root_fd >= 0:
                os.close(root_fd)
            os.close(parent_fd)

    def test_build_creation_rejects_wrong_parent_identity(self) -> None:
        wrong = SOURCE.identity_value(self.source)
        parent_fd = os.open(
            self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            with self.assertRaisesRegex(
                SOURCE.SourceError, "release_build_parent_changed",
            ):
                SOURCE.create_build_directory_at(
                    parent_fd, ".build.", json.dumps(wrong),
                )
        finally:
            os.close(parent_fd)

    def test_descriptor_relative_cleanup_retires_captured_tree_intact(self) -> None:
        disposable = self.workspace / ".build.good"
        disposable.mkdir(mode=0o700)
        (disposable / "item").write_text("temporary\n", encoding="ascii")
        identity = SOURCE.identity_value(disposable)
        result = SOURCE.remove_tree(
            disposable, self.workspace, ".build.", json.dumps(identity),
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["disposition"], "retained")
        self.assertFalse(disposable.exists())
        retained = self.workspace / result["retained_name"]
        self.assertEqual(
            (retained / "item").read_text(encoding="ascii"), "temporary\n",
        )

    def test_descriptor_relative_cleanup_rejects_substituted_root(self) -> None:
        disposable = self.workspace / ".build.race"
        disposable.mkdir(mode=0o700)
        identity = SOURCE.identity_value(disposable)
        parked = self.workspace / "parked"
        disposable.rename(parked)
        disposable.mkdir(mode=0o700)
        (disposable / "must-survive").write_text("evidence\n", encoding="ascii")
        with self.assertRaisesRegex(
            SOURCE.SourceError, "release_cleanup_target_changed",
        ):
            SOURCE.remove_tree(
                disposable, self.workspace, ".build.", json.dumps(identity),
            )
        self.assertTrue((disposable / "must-survive").is_file())
        self.assertTrue(parked.is_dir())

    def test_cleanup_race_never_deletes_substituted_victim(self) -> None:
        disposable = self.workspace / ".build.race-window"
        disposable.mkdir(mode=0o700)
        (disposable / "expected").write_text("expected\n", encoding="ascii")
        identity = SOURCE.identity_value(disposable)
        parked = self.workspace / "expected-parked"
        victim = self.workspace / "victim"
        victim.mkdir(mode=0o700)
        (victim / "must-survive").write_text("evidence\n", encoding="ascii")
        real_rename = SOURCE.rename_exclusive_at

        def substitute_then_rename(
            source_parent: int, source: str,
            destination_parent: int, destination: str,
        ) -> None:
            disposable.rename(parked)
            victim.rename(disposable)
            real_rename(
                source_parent, source, destination_parent, destination,
            )

        with mock.patch.object(
            SOURCE, "rename_exclusive_at", side_effect=substitute_then_rename,
        ), self.assertRaisesRegex(
            SOURCE.SourceError, "release_cleanup_target_changed:retained=",
        ):
            SOURCE.remove_tree(
                disposable, self.workspace, ".build.", json.dumps(identity),
            )

        self.assertEqual(
            (parked / "expected").read_text(encoding="ascii"), "expected\n",
        )
        retained = list(
            self.workspace.glob(".secure-sandbox-retained-*")
        )
        self.assertEqual(len(retained), 1)
        self.assertEqual(
            (retained[0] / "must-survive").read_text(encoding="ascii"),
            "evidence\n",
        )

    def test_cleanup_collision_never_overwrites_retained_evidence(self) -> None:
        disposable = self.workspace / ".build.collision"
        disposable.mkdir(mode=0o700)
        (disposable / "expected").write_text("expected\n", encoding="ascii")
        identity = SOURCE.identity_value(disposable)
        retained = self.workspace / (
            f".secure-sandbox-retained-{os.getpid()}-" + ("00" * 12)
        )
        retained.write_text("existing retained evidence\n", encoding="ascii")
        with mock.patch.object(SOURCE.os, "urandom", return_value=b"\0" * 12), \
                self.assertRaisesRegex(
                    SOURCE.SourceError, "release_cleanup_quarantine_collision",
                ):
            SOURCE.remove_tree(
                disposable, self.workspace, ".build.", json.dumps(identity),
            )
        self.assertEqual(
            retained.read_text(encoding="ascii"), "existing retained evidence\n",
        )
        self.assertEqual(
            (disposable / "expected").read_text(encoding="ascii"), "expected\n",
        )


class NativeHostCarrierSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (
            REPO / "scripts/build-native-host-products.sh"
        ).read_text(encoding="utf-8")

    def test_carrier_uses_closed_source_helper_and_detached_receipt_signature(self) -> None:
        for required in (
            "native_host_release_source.py",
            "GIT_NO_REPLACE_OBJECTS=1",
            "SECURE_SANDBOX_SOURCE_ARCHIVE_PATH",
            "SECURE_SANDBOX_SOURCE_TREE_SHA256",
            "verify_candidate_source",
            "require_child_output_identity",
            "SecureSandboxNativeHostProducts.notarization.sig",
            "org.zebeth.SecureSandbox.NativeHostProductsReceipt",
            '--detached "$container_receipt_signature"',
            'certificate leaf = H\\"$developer_id_input\\"',
        ):
            self.assertIn(required, self.script)

    def test_committed_source_helper_ls_tree_pattern_matches_git_output(self) -> None:
        line = next(
            value for value in self.script.splitlines()
            if value.startswith("match=re.fullmatch(")
            and "native_host_release_source.py" in value
        )
        literal = line.removeprefix("match=re.fullmatch(").removesuffix(",raw)")
        pattern = ast.literal_eval(literal)
        observed = subprocess.run(
            [
                "/usr/bin/git", "-C", str(REPO), "ls-tree", "HEAD", "--",
                "scripts/native_host_release_source.py",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        match = re.fullmatch(pattern, observed)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertRegex(match.group(1), r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
