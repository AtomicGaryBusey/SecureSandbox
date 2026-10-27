#!/usr/bin/env python3

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check-public-identifiers.py")
SPEC = importlib.util.spec_from_file_location("check_public_identifiers", SCRIPT)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class PublicIdentifierCheckerTests(unittest.TestCase):
    def test_worktree_inventory_includes_tracked_and_untracked_nonignored_files(self):
        with mock.patch.object(checker, "git", return_value=b"tracked.txt\0new.txt\0") as git:
            self.assertEqual(checker.worktree_files(), [Path("tracked.txt"), Path("new.txt")])
        git.assert_called_once_with("ls-files", "--cached", "--others", "--exclude-standard", "-z")

    def test_worktree_ancestor_symlink_is_rejected_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "file").write_text("safe\n", encoding="utf-8")
            os.symlink(outside, root / "dir")
            with (mock.patch.object(checker, "ROOT", root),
                  mock.patch.object(checker, "worktree_files", return_value=[Path("dir/file")])):
                findings = checker.inspect_worktree([])
        self.assertTrue(any("not a readable no-follow regular file" in item for item in findings))

    def test_random_uuid_is_rejected_in_python(self):
        findings = checker.inspect_text(
            "example.py",
            'session_id = "' + "0f2c1a09" + "-adce-46fd-b91b-6eb297320dba" + '"\n',
            [],
        )
        self.assertTrue(any("concrete operational UUID" in item for item in findings))

    def test_explicit_synthetic_uuid_is_allowed(self):
        findings = checker.inspect_text(
            "example.py",
            'session_id = "11111111-1111-4111-8111-111111111111"\n',
            [],
        )
        self.assertEqual(findings, [])

    def test_repeated_digit_and_reserved_zero_uuid_fixtures_are_allowed(self):
        for value in (
            "55555555-5555-4555-8555-555555555555",
            "00000000-0000-4000-8000-000000000005",
        ):
            with self.subTest(value=value):
                self.assertTrue(checker.synthetic_uuid(value))
                self.assertEqual(
                    checker.inspect_text("test_fixture.py", f'id = "{value}"\n', []),
                    [],
                )

    def test_generated_authorization_artifacts_are_rejected_by_path(self):
        for path in (
            "artifacts/host/SecureSandboxAuthorizationUI",
            "artifacts/host/SecureSandboxAuthorizationUI.bundle.json",
            "artifacts/host/SecureSandboxAuthorizationUI.sources.json",
            "artifacts/host/SecureSandboxAuthorizationUI.app/Contents/Info.plist",
            "other/Sample.app/Contents/embedded.provisionprofile",
            "macos/TouchIDAuthorization/Signing.local.xcconfig",
        ):
            with self.subTest(path=path):
                findings = checker.inspect_raw(path, b"safe text\n", [])
                self.assertTrue(any("generated signed authorization artifact" in item
                                    for item in findings))

    def test_publication_hooks_bind_exact_index_and_only_public_release(self):
        pre_commit = (checker.ROOT / ".githooks/pre-commit").read_text("utf-8")
        pre_push = (checker.ROOT / ".githooks/pre-push").read_text("utf-8")
        self.assertIn("--staged-only", pre_commit)
        self.assertIn('refs/heads/public-release', pre_push)
        self.assertIn('--history-only --ref "$local_oid"', pre_push)
        rejected = subprocess.run(
            [str(checker.ROOT / ".githooks/pre-push"), "origin", "unused"],
            cwd=checker.ROOT,
            input=("refs/heads/main " + "a" * 40 + " refs/heads/main "
                   + "0" * 40 + "\n"),
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("only refs/heads/public-release", rejected.stderr)

        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=checker.ROOT, text=True,
        ).strip()
        ancestor = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=checker.ROOT, text=True,
        ).strip()
        rewrite = subprocess.run(
            [str(checker.ROOT / ".githooks/pre-push"), "origin", "unused"],
            cwd=checker.ROOT,
            input=(f"refs/heads/public-release {ancestor} "
                   f"refs/heads/public-release {head}\n"),
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(rewrite.returncode, 0)
        self.assertIn("must be fast-forward", rewrite.stderr)

    def test_private_reports_root_is_rejected_even_when_force_added(self):
        findings = checker.inspect_text("reports/operator.json", "{}\n", [])
        self.assertTrue(any("private runtime directory" in item for item in findings))

    def test_concrete_apple_signing_identity_is_rejected(self):
        for line in (
            "DEVELOPMENT_TEAM = " + "ABCDE" + "12345;",
            '"keychain-access-groups": ["' + "ABCDE" + '12345.org.example.App"]',
            '"keychain-access-groups": ["' + "ABCDE" + '12345.com.App"]',
        ):
            with self.subTest(line=line):
                findings = checker.inspect_text("project.pbxproj", line + "\n", [])
                self.assertTrue(any("concrete Apple signing identity" in item
                                    for item in findings))

    def test_build_setting_placeholders_are_allowed(self):
        text = (
            "DEVELOPMENT_TEAM = $(SECURE_SANDBOX_DEVELOPMENT_TEAM);\n"
            "$(DEVELOPMENT_TEAM).$(PRODUCT_BUNDLE_IDENTIFIER)\n"
        )
        self.assertEqual(checker.inspect_text("template.xcconfig", text, []), [])

    def test_common_secret_formats_are_rejected(self):
        samples = (
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "ghp_" + "A" * 36,
            "sk-proj-" + "A" * 24,
            "sk-ant-" + "A" * 24,
            "AKIA" + "A" * 16,
            "xoxb-" + "A" * 24,
            "ops_" + "A" * 24,
            "AccountKey=" + "A" * 44,
        )
        for sample in samples:
            with self.subTest(sample=sample[:12]):
                findings = checker.inspect_text("config.txt", sample + "\n", [])
                self.assertTrue(any("probable" in item for item in findings))

    def test_secret_placeholders_remain_publishable(self):
        text = "OPENAI_API_KEY=REPLACE_ME\nAccountKey=REPLACE_ME\n"
        self.assertEqual(checker.inspect_text("config.example", text, []), [])

    def test_unsupported_blob_classes_fail_closed(self):
        self.assertTrue(checker.inspect_raw("binary.dat", b"a\0b", []))
        self.assertTrue(checker.inspect_raw("legacy.txt", b"\xff", []))
        self.assertTrue(checker.inspect_raw("large.txt", b"a" * (8 * 1024 * 1024 + 1), []))

    def test_index_scan_reads_exact_staged_blobs_and_rejects_forced_private_path(self):
        object_id = "a" * 40

        def fake_git(*arguments, input_bytes=None):
            if arguments == ("ls-files", "--stage", "-z"):
                return f"100644 {object_id} 0\treports/private.json\0".encode()
            if arguments == ("cat-file", "-s", object_id):
                return b"3\n"
            if arguments == ("cat-file", "blob", object_id):
                return b"{}\n"
            raise AssertionError(arguments)

        with mock.patch.object(checker, "git", side_effect=fake_git):
            findings = checker.inspect_index([])
        self.assertTrue(any("private runtime directory" in item for item in findings))

    def test_identifier_bearing_git_path_is_rejected(self):
        private_uuid = "0f2c1a09" + "-adce-46fd-b91b-6eb297320dba"
        findings = checker.inspect_identifier_value(
            "Git path evidence/" + private_uuid + ".json",
            "evidence/" + private_uuid + ".json",
            [],
        )
        self.assertTrue(any("concrete operational UUID" in item for item in findings))

    def test_invalid_json_and_key_variants_fail_closed(self):
        self.assertTrue(checker.inspect_text("broken.json", "{", []))
        findings = checker.inspect_text(
            "config.json",
            '{"tenantId":"11111111-1111-1111-1111-111111111111"}',
            [],
        )
        self.assertTrue(any("deployment-specific value" in item for item in findings))

    def test_commit_message_content_is_inspected(self):
        commit = "a" * 40

        def fake_git(*arguments, input_bytes=None):
            if arguments[:2] == ("log", "HEAD"):
                return f"{commit}\0agent@users.noreply.github.com\0agent@users.noreply.github.com\n".encode()
            if arguments == ("rev-list", "HEAD"):
                return f"{commit}\n".encode()
            if arguments == ("cat-file", "commit", commit):
                operational_uuid = b"0f2c1a09" + b"-adce-46fd-b91b-6eb297320dba"
                return (
                    b"tree " + b"b" * 40 + b"\n"
                    b"author Agent <agent@users.noreply.github.com> 0 +0000\n"
                    b"committer Agent <agent@users.noreply.github.com> 0 +0000\n\n"
                    b"mentions " + operational_uuid + b"\n"
                )
            if arguments == ("for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", "refs/tags"):
                return b""
            raise AssertionError(arguments)

        with (mock.patch.object(checker, "reachable_entries", return_value=[]),
              mock.patch.object(checker, "git", side_effect=fake_git)):
            findings = checker.inspect_history("HEAD", [])
        self.assertTrue(any("commit-object" in item and "concrete operational UUID" in item for item in findings))

    def test_commit_author_name_content_is_inspected(self):
        commit = "a" * 40
        private_uuid = b"0f2c1a09" + b"-adce-46fd-b91b-6eb297320dba"

        def fake_git(*arguments, input_bytes=None):
            if arguments[:2] == ("log", "HEAD"):
                return f"{commit}\0agent@users.noreply.github.com\0agent@users.noreply.github.com\n".encode()
            if arguments == ("rev-list", "HEAD"):
                return f"{commit}\n".encode()
            if arguments == ("cat-file", "commit", commit):
                return (b"tree " + b"b" * 40 + b"\n" + b"author " + private_uuid
                        + b" <agent@users.noreply.github.com> 0 +0000\n"
                        + b"committer Agent <agent@users.noreply.github.com> 0 +0000\n\nrelease\n")
            if arguments == ("for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", "refs/tags"):
                return b""
            raise AssertionError(arguments)

        with (mock.patch.object(checker, "reachable_entries", return_value=[]),
              mock.patch.object(checker, "git", side_effect=fake_git)):
            findings = checker.inspect_history("HEAD", [])
        self.assertTrue(any("commit-object" in item and "concrete operational UUID" in item
                            for item in findings))

    def test_annotated_tag_object_is_inspected(self):
        tag = "c" * 40

        def fake_git(*arguments, input_bytes=None):
            if arguments[:2] == ("log", "HEAD"):
                return b""
            if arguments == ("rev-list", "HEAD"):
                return b""
            if arguments == ("for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", "refs/tags"):
                return f"{tag}\0tag\0refs/tags/v1\n".encode()
            if arguments == ("cat-file", "tag", tag):
                private_email = b"person" + b"@private.invalid"
                return (b"object " + b"d" * 40 + b"\ntype commit\ntag v1\ntagger Person <"
                        + private_email + b"> 0 +0000\n\nrelease\n")
            if arguments == ("cat-file", "-t", "d" * 40):
                return b"commit\n"
            raise AssertionError(arguments)

        with (mock.patch.object(checker, "reachable_entries", return_value=[]),
              mock.patch.object(checker, "git", side_effect=fake_git)):
            findings = checker.inspect_history("HEAD", [])
        self.assertTrue(any("tag-object" in item and "non-placeholder email address" in item for item in findings))

    def test_nested_annotated_tag_object_is_inspected(self):
        outer = "e" * 40
        inner = "f" * 40

        def fake_git(*arguments, input_bytes=None):
            if arguments[:2] == ("log", "HEAD") or arguments == ("rev-list", "HEAD"):
                return b""
            if arguments == ("for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", "refs/tags"):
                return f"{outer}\0tag\0refs/tags/v2\n".encode()
            if arguments == ("cat-file", "tag", outer):
                return (f"object {inner}\ntype tag\ntag v2\ntagger Agent <agent@users.noreply.github.com> 0 +0000\n\nouter\n".encode())
            if arguments == ("cat-file", "tag", inner):
                private_email = b"person" + b"@private.invalid"
                return (b"object " + b"d" * 40 + b"\ntype commit\ntag inner\ntagger Person <"
                        + private_email + b"> 0 +0000\n\ninner\n")
            if arguments == ("cat-file", "-t", inner):
                return b"tag\n"
            if arguments == ("cat-file", "-t", "d" * 40):
                return b"commit\n"
            raise AssertionError(arguments)

        with (mock.patch.object(checker, "reachable_entries", return_value=[]),
              mock.patch.object(checker, "git", side_effect=fake_git)):
            findings = checker.inspect_history("HEAD", [])
        self.assertTrue(any(inner[:12] in item and "non-placeholder email address" in item for item in findings))

    def test_annotated_tag_type_mismatch_is_rejected_and_actual_tag_is_inspected(self):
        outer = "1" * 40
        inner = "2" * 40

        def fake_git(*arguments, input_bytes=None):
            if arguments[:2] == ("log", "HEAD") or arguments == ("rev-list", "HEAD"):
                return b""
            if arguments == ("for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", "refs/tags"):
                return f"{outer}\0tag\0refs/tags/mismatch\n".encode()
            if arguments == ("cat-file", "tag", outer):
                return (f"object {inner}\ntype commit\ntag outer\ntagger Agent <agent@users.noreply.github.com> 0 +0000\n\nouter\n".encode())
            if arguments == ("cat-file", "-t", inner):
                return b"tag\n"
            if arguments == ("cat-file", "tag", inner):
                private_email = b"person" + b"@private.invalid"
                return (b"object " + b"3" * 40 + b"\ntype commit\ntag inner\ntagger Person <"
                        + private_email + b"> 0 +0000\n\ninner\n")
            if arguments == ("cat-file", "-t", "3" * 40):
                return b"commit\n"
            raise AssertionError(arguments)

        with (mock.patch.object(checker, "reachable_entries", return_value=[]),
              mock.patch.object(checker, "git", side_effect=fake_git)):
            findings = checker.inspect_history("HEAD", [])
        self.assertTrue(any("declared/actual type mismatch" in item for item in findings))
        self.assertTrue(any(inner[:12] in item and "non-placeholder email address" in item for item in findings))


if __name__ == "__main__":
    unittest.main()
