import importlib.util
import io
import os
import tarfile
import tempfile
import unittest

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

    def test_accepts_regular_tree_and_warns_on_symlink(self):
        entries, warnings = self.inspect([
            ("root/src/", "dir", b""),
            ("root/src/a.py", "file", b"print('x')\n"),
            ("root/link", "symlink", "src/a.py"),
        ])
        self.assertEqual(len(entries), 3)
        self.assertIn("working_copy_omits_symlinks", warnings)

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

    def test_extract_makes_files_non_executable_and_omits_worktree_symlinks(self):
        stream = archive_with([
            ("root/tool", "file", b"#!/bin/sh\nexit 0\n"),
            ("root/tool-link", "symlink", "tool"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            archive_path = os.path.join(directory, "source.tar.gz")
            destination = os.path.join(directory, "stage")
            os.mkdir(destination)
            with open(archive_path, "wb") as handle:
                handle.write(stream.read())
            tree_hash, count, _, warnings, records = module.extract_archive(archive_path, destination)
            self.assertRegex(tree_hash, r"^[0-9a-f]{64}$")
            self.assertEqual(count, 2)
            self.assertEqual(len(records), 2)
            self.assertEqual(os.stat(os.path.join(destination, "baseline", "tool")).st_mode & 0o777, 0o400)
            self.assertFalse(os.path.lexists(os.path.join(destination, "worktree", "tool-link")))
            self.assertIn("working_copy_omits_symlinks", warnings)


if __name__ == "__main__":
    unittest.main()
