#!/usr/bin/env python3

import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "publish_public_github_release",
    Path(__file__).with_name("publish-public-github-release.py"),
)
publish = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(publish)


class PublicGitHubPublicationTests(unittest.TestCase):
    head = "b" * 40
    parent = "a" * 40

    def git_result(self, *arguments, **_kwargs):
        if arguments == ("rev-parse", "HEAD"):
            return self.head
        if arguments == ("rev-parse", "refs/heads/public-release"):
            return self.head
        if arguments == ("rev-parse", "origin/public-release"):
            return self.parent
        if arguments[:2] == ("push", "origin"):
            return ""
        raise AssertionError(arguments)

    def test_publish_unseals_pushes_reseals_and_verifies(self):
        with mock.patch.object(publish, "git", side_effect=self.git_result), \
             mock.patch.object(publish, "verify_prepublication") as preflight, \
             mock.patch.object(publish.subprocess, "run", return_value=mock.Mock(returncode=0)) as checks, \
             mock.patch.object(publish.SEAL, "put_ruleset") as put, \
             mock.patch.object(publish, "verify_ruleset_enforcement") as disabled, \
             mock.patch.object(publish, "remote_tip", return_value=self.head), \
             mock.patch.object(publish.SEAL, "verify_ruleset") as resealed, \
             mock.patch.object(publish.SEAL, "verify_repository") as verified:
            result = publish.publish("owner/repo")
        self.assertEqual(result["commit"], self.head)
        self.assertEqual(result["status"], "published-and-resealed")
        preflight.assert_called_once_with("owner/repo", self.head, self.parent)
        checks.assert_called_once()
        self.assertEqual(put.call_count, 2)
        self.assertEqual(put.call_args_list[0].args[1]["enforcement"], "disabled")
        self.assertEqual(put.call_args_list[1].args[1]["enforcement"], "active")
        disabled.assert_called_once()
        resealed.assert_called_once()
        verified.assert_called_once_with("owner/repo")

    def test_publish_uses_named_branch_for_the_pre_push_guard(self):
        calls = []

        def recording_git(*arguments, **kwargs):
            calls.append((arguments, kwargs))
            return self.git_result(*arguments, **kwargs)

        with mock.patch.object(publish, "git", side_effect=recording_git), \
             mock.patch.object(publish, "verify_prepublication"), \
             mock.patch.object(publish.subprocess, "run", return_value=mock.Mock(returncode=0)), \
             mock.patch.object(publish.SEAL, "put_ruleset"), \
             mock.patch.object(publish, "verify_ruleset_enforcement"), \
             mock.patch.object(publish, "remote_tip", return_value=self.head), \
             mock.patch.object(publish.SEAL, "verify_ruleset"), \
             mock.patch.object(publish.SEAL, "verify_repository"):
            publish.publish("owner/repo")
        self.assertIn(
            (("push", "origin", "refs/heads/public-release:refs/heads/public-release"),
             {"capture": False}),
            calls,
        )

    def test_branch_movement_before_unseal_is_rejected(self):
        def moved_git(*arguments, **kwargs):
            if arguments == ("rev-parse", "refs/heads/public-release"):
                return "c" * 40
            return self.git_result(*arguments, **kwargs)

        with mock.patch.object(publish, "git", side_effect=moved_git), \
             mock.patch.object(publish.SEAL, "put_ruleset") as put:
            with self.assertRaisesRegex(RuntimeError, "does not name the reviewed"):
                publish.publish("owner/repo")
        put.assert_not_called()

    def test_push_failure_still_restores_and_verifies_active_ruleset(self):
        def failing_git(*arguments, **kwargs):
            if arguments[:2] == ("push", "origin"):
                raise RuntimeError("push failed")
            return self.git_result(*arguments, **kwargs)

        with mock.patch.object(publish, "git", side_effect=failing_git), \
             mock.patch.object(publish, "verify_prepublication"), \
             mock.patch.object(publish.subprocess, "run", return_value=mock.Mock(returncode=0)), \
             mock.patch.object(publish.SEAL, "put_ruleset") as put, \
             mock.patch.object(publish, "verify_ruleset_enforcement"), \
             mock.patch.object(publish.SEAL, "verify_ruleset") as resealed:
            with self.assertRaisesRegex(RuntimeError, "immutable ruleset was restored"):
                publish.publish("owner/repo")
        self.assertEqual(put.call_count, 2)
        self.assertEqual(put.call_args_list[-1].args[1]["enforcement"], "active")
        resealed.assert_called_once()

    def test_check_failure_never_unseals(self):
        with mock.patch.object(publish, "git", side_effect=self.git_result), \
             mock.patch.object(publish, "verify_prepublication"), \
             mock.patch.object(
                 publish.subprocess, "run",
                 side_effect=subprocess.CalledProcessError(1, ["checks"]),
             ), \
             mock.patch.object(publish.SEAL, "put_ruleset") as put:
            with self.assertRaises(subprocess.CalledProcessError):
                publish.publish("owner/repo")
        put.assert_not_called()


if __name__ == "__main__":
    unittest.main()
