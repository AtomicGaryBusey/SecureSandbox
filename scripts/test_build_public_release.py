#!/usr/bin/env python3

import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("build-public-release.py")
SPEC = importlib.util.spec_from_file_location("build_public_release", SCRIPT)
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class PublicReleaseBuilderTests(unittest.TestCase):
    def repository(self, root: Path) -> str:
        subprocess.run(["git", "init", "-q", "-b", "public-release"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Release Test"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "release-test@users.noreply.github.com"],
            cwd=root,
            check=True,
        )
        (root / "README.md").write_text("deterministic\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
        environment = {
            "GIT_AUTHOR_DATE": "1700000000 +0000",
            "GIT_COMMITTER_DATE": "1700000000 +0000",
        }
        subprocess.run(
            ["git", "commit", "-q", "-m", "release fixture"],
            cwd=root,
            env={**__import__("os").environ, **environment},
            check=True,
        )
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

    def test_two_builds_of_one_commit_are_byte_identical_and_self_describing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            commit = self.repository(root)
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            builder.build(commit, first, root)
            builder.build(commit, second, root)

            for name in builder.OUTPUT_NAMES:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

            provenance = json.loads((first / builder.PROVENANCE_NAME).read_text("utf-8"))
            self.assertEqual(provenance["commit"], commit)
            self.assertEqual(provenance["schema"], "secure-sandbox-public-release-provenance-v1")
            archive = first / builder.ARCHIVE_NAME
            self.assertEqual(provenance["archive"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            with gzip.open(archive, "rb") as compressed:
                with tarfile.open(fileobj=io.BytesIO(compressed.read()), mode="r:") as bundle:
                    self.assertIn("SecureSandbox/README.md", bundle.getnames())

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            commit = self.repository(root)
            output = Path(temporary) / "output"
            output.mkdir()
            sentinel = output / builder.ARCHIVE_NAME
            sentinel.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                builder.build(commit, output, root)
            self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_replacement_refs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            original = self.repository(root)
            (root / "README.md").write_text("replacement\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "replacement"], cwd=root, check=True)
            replacement = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True,
            ).strip()
            subprocess.run(["git", "replace", original, replacement], cwd=root, check=True)
            with self.assertRaisesRegex(ValueError, "replacement refs"):
                builder.build(original, Path(temporary) / "output", root)

    def test_custom_replacement_namespace_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            commit = self.repository(root)
            with mock.patch.dict(os.environ, {"GIT_REPLACE_REF_BASE": "refs/custom"}):
                with self.assertRaisesRegex(ValueError, "replacement-ref base"):
                    builder.build(commit, Path(temporary) / "output", root)


if __name__ == "__main__":
    unittest.main()
