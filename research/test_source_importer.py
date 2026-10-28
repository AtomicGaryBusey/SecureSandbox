import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("source_importer", os.path.join(os.path.dirname(__file__), "source_importer.py"))
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


def archive_with(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        root = tarfile.TarInfo("root/")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, kind, payload in entries:
            item = tarfile.TarInfo(name)
            if kind == "file":
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            elif kind == "dir":
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
            elif kind == "symlink":
                item.type = tarfile.SYMTYPE
                item.linkname = payload
                archive.addfile(item)
            elif kind == "hardlink":
                item.type = tarfile.LNKTYPE
                item.linkname = payload
                archive.addfile(item)
    stream.seek(0)
    return stream


class SourceImporterTests(unittest.TestCase):
    def inspect(self, entries):
        stream = archive_with(entries)
        with tarfile.open(fileobj=stream, mode="r:gz", encoding="utf-8", errors="strict") as archive:
            return module.inspect_members(archive)

    def test_archive_root_does_not_consume_relative_path_budget(self):
        root = "repository-" + "a" * 40
        relative = "docs/" + "x" * 190
        parts = module.normalized_path(f"{root}/{relative}")
        self.assertEqual("/".join(parts[1:]), relative)

    def test_accepts_regular_tree(self):
        entries, warnings = self.inspect([
            ("root/src/", "dir", b""),
            ("root/src/a.py", "file", b"print('x')\n"),
        ])
        self.assertEqual(len(entries), 2)
        self.assertEqual(warnings, [])

    def test_rejects_traversal_absolute_and_symlink_escape(self):
        for entries in (
            [("root/../escape", "file", b"x")],
            [("/absolute", "file", b"x")],
            [("root/link", "symlink", "../../escape")],
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.inspect(entries)

    def test_rejects_hardlinks_and_case_collisions(self):
        with self.assertRaises(ValueError):
            self.inspect([("root/hard", "hardlink", "root/a")])
        with self.assertRaises(ValueError):
            self.inspect([("root/A", "file", b"a"), ("root/a", "file", b"b")])

    def test_rejects_all_symlinks_including_chained_ancestors(self):
        for entries in (
            [("root/link", "symlink", "src/a.py")],
            [
                ("root/first", "symlink", "second"),
                ("root/second", "symlink", "inside"),
                ("root/first/payload", "file", b"escape attempt"),
            ],
        ):
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, "unsupported_member_type"):
                self.inspect(entries)

    def test_rejects_extended_attribute_pax_header(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            item = tarfile.TarInfo("root/file")
            item.size = 1
            item.pax_headers = {"SCHILY.xattr.user.test": "value"}
            archive.addfile(item, io.BytesIO(b"x"))
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:gz", encoding="utf-8", errors="strict") as archive:
            with self.assertRaises(ValueError):
                module.inspect_members(archive)

    def test_extract_makes_files_non_executable(self):
        stream = archive_with([
            ("root/tool", "file", b"#!/bin/sh\nexit 0\n"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            archive_path = os.path.join(directory, "source.tar.gz")
            destination = os.path.join(directory, "stage")
            os.mkdir(destination)
            with open(archive_path, "wb") as handle:
                handle.write(stream.read())
            tree_hash, count, _, warnings, records = module.extract_archive(archive_path, destination)
            self.assertRegex(tree_hash, r"^[0-9a-f]{64}$")
            self.assertEqual(count, 1)
            self.assertEqual(len(records), 1)
            self.assertEqual(os.stat(os.path.join(destination, "baseline", "tool")).st_mode & 0o777, 0o400)
            self.assertEqual(warnings, [])

    def publication_fixture(self, directory):
        root = Path(directory)
        baselines = root / "baselines"
        repos = root / "repos"
        manifests = root / "manifests"
        control = root / "control"
        staging = control / "staging"
        for path in (baselines, repos, manifests, staging):
            path.mkdir(parents=True, exist_ok=True)
        source_id = "11111111-1111-4111-8111-111111111111"
        (staging / source_id).mkdir()
        prior = {"schema": "secure-sandbox-source-registry-v1", "sources": []}
        record = {"source_id": source_id, "repository": "owner/repo",
                  "worktree_path": f"repos/owner--repo--abc--{source_id}"}
        updated = {"schema": prior["schema"], "sources": [record]}
        (control / "registry.json").write_text(json.dumps(prior), encoding="utf-8")
        (repos / "INDEX.json").write_text(json.dumps(prior), encoding="utf-8")
        (control / "registry.json").chmod(0o600)
        (repos / "INDEX.json").chmod(0o444)
        temporary = [baselines / f".source-{source_id}.new",
                     repos / f".source-{source_id}.new",
                     manifests / f".{source_id}.new"]
        final = [baselines / source_id, repos / f"owner--repo--abc--{source_id}",
                 manifests / f"{source_id}.json"]
        temporary[0].mkdir(); (temporary[0] / "source.py").write_text("pass\n", encoding="utf-8")
        temporary[1].mkdir(); (temporary[1] / "source.py").write_text("pass\n", encoding="utf-8")
        temporary[2].write_text("{}\n", encoding="utf-8")
        pending = [control / f"registry-{source_id}.pending", repos / f".INDEX-{source_id}.pending"]
        for path in pending:
            path.write_text(json.dumps(updated), encoding="utf-8")
        pending[0].chmod(0o600)
        pending[1].chmod(0o444)
        artifacts = [
            {"temporary": str(source), "final": str(destination), "uid": os.geteuid(),
             "identity": module.publication_identity(str(source))}
            for source, destination in zip(temporary, final)
        ]
        transaction = {
            "schema": module.PUBLICATION_SCHEMA, "source_id": source_id,
            "phase": "prepared", "control_uid": os.geteuid(), "record": record,
            "prior_registry": prior, "updated_registry": updated,
            "artifacts": artifacts, "pending": [str(path) for path in pending],
        }
        transaction_path = control / f"publication-{source_id}.transaction.json"
        transaction_path.write_text(json.dumps(transaction), encoding="utf-8")
        transaction_path.chmod(0o600)
        patches = mock.patch.multiple(
            module, ROOT=str(control), STAGING=str(staging), BASELINES=str(baselines),
            REPOS=str(repos), MANIFESTS=str(manifests), REGISTRY=str(control / "registry.json"),
        )
        return source_id, prior, updated, temporary, final, pending, transaction_path, patches

    def test_publication_recovers_every_durable_phase_boundary(self):
        for completed_moves in range(7):
            with self.subTest(completed_moves=completed_moves), tempfile.TemporaryDirectory() as directory:
                source_id, _, updated, temporary, final, pending, transaction_path, patches = self.publication_fixture(directory)
                moves = [(temporary[0], final[0]), (temporary[1], final[1]),
                         (temporary[2], final[2]), (pending[0], Path(directory) / "control/registry.json"),
                         (pending[1], Path(directory) / "repos/INDEX.json"),
                         (Path(directory) / "control/staging" / source_id, None)]
                for source, destination in moves[:completed_moves]:
                    if destination is None:
                        os.rmdir(source)
                    else:
                        os.replace(source, destination)
                with patches:
                    recovered = module.recover_publication(source_id)
                self.assertEqual(recovered["source_id"], source_id)
                self.assertTrue(all(path.exists() for path in final))
                self.assertFalse(transaction_path.exists())
                self.assertFalse((Path(directory) / "control/staging" / source_id).exists())
                for path in (Path(directory) / "control/registry.json", Path(directory) / "repos/INDEX.json"):
                    self.assertEqual(json.loads(path.read_text(encoding="utf-8")), updated)

    def test_publication_recovery_refuses_substituted_final(self):
        with tempfile.TemporaryDirectory() as directory:
            source_id, _, _, temporary, final, _, transaction_path, patches = self.publication_fixture(directory)
            os.replace(temporary[0], final[0])
            original = final[0].with_name("original")
            os.replace(final[0], original)
            final[0].mkdir()
            with patches, self.assertRaisesRegex(ValueError, "publication_recovery_identity_mismatch"):
                module.recover_publication(source_id)
            self.assertTrue(final[0].is_dir())
            self.assertTrue(transaction_path.exists())

    def test_preparing_transaction_cleans_only_expected_unpublished_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            source_id, _, _, temporary, final, pending, transaction_path, patches = self.publication_fixture(directory)
            transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
            transaction["phase"] = "preparing"
            for artifact in transaction["artifacts"]:
                artifact.pop("identity")
            transaction_path.write_text(json.dumps(transaction), encoding="utf-8")
            transaction_path.chmod(0o600)
            with patches:
                self.assertIsNone(module.recover_publication(source_id))
            self.assertFalse(transaction_path.exists())
            self.assertTrue(all(not path.exists() for path in temporary + pending))
            self.assertTrue(all(not path.exists() for path in final))

    def test_list_sources_requires_matching_protected_registry_and_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control"
            repos = root / "repos"
            control.mkdir()
            repos.mkdir()
            registry_path = control / "registry.json"
            index_path = repos / "INDEX.json"
            value = {
                "schema": "secure-sandbox-source-registry-v1",
                "sources": [{"source_id": "11111111-1111-4111-8111-111111111111"}],
            }
            registry_path.write_text(json.dumps(value), encoding="utf-8")
            index_path.write_text(json.dumps(value), encoding="utf-8")
            registry_path.chmod(0o600)
            index_path.chmod(0o444)
            with mock.patch.multiple(
                module, REGISTRY=str(registry_path), REPOS=str(repos),
            ):
                self.assertEqual(module.list_sources(), value)
                index_path.chmod(0o644)
                index_path.write_text(
                    json.dumps({"schema": value["schema"], "sources": []}),
                    encoding="utf-8",
                )
                index_path.chmod(0o444)
                with self.assertRaisesRegex(ValueError, "invalid_registry"):
                    module.list_sources()


if __name__ == "__main__":
    unittest.main()
