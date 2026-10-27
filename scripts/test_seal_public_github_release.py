#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("seal-public-github-release.py")
SPEC = importlib.util.spec_from_file_location("seal_public_github_release", SCRIPT)
assert SPEC and SPEC.loader
seal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seal)


class PublicGitHubSealTests(unittest.TestCase):
    def test_branch_rules_freeze_every_ref_without_bypass(self):
        value = seal.ruleset_payload("branch", "branch")
        self.assertEqual(value["conditions"], {"ref_name": {"include": ["~ALL"], "exclude": []}})
        self.assertEqual(value["bypass_actors"], [])
        self.assertEqual(
            [rule["type"] for rule in value["rules"]],
            ["creation", "update", "deletion", "non_fast_forward"],
        )

    def test_tag_rules_freeze_every_ref_without_bypass(self):
        value = seal.ruleset_payload("tag", "tag")
        self.assertEqual(value["bypass_actors"], [])
        self.assertEqual(
            [rule["type"] for rule in value["rules"]],
            ["creation", "update", "deletion"],
        )

    def test_verify_requires_exact_public_tip_and_reporting(self):
        metadata = {
            "visibility": "public",
            "default_branch": "public-release",
        }

        def api(endpoint, **_kwargs):
            if endpoint == "repos/example/project":
                return metadata
            if endpoint.endswith("git/ref/heads/public-release"):
                return {"object": {"sha": "a" * 40}}
            if endpoint.endswith("private-vulnerability-reporting"):
                return {"enabled": True}
            raise AssertionError(endpoint)

        with mock.patch.object(seal, "gh_json", side_effect=api), \
             mock.patch.object(seal, "ref_names", side_effect=(["public-release"], [])), \
             mock.patch.object(seal, "local_head", return_value="a" * 40), \
             mock.patch.object(seal, "verify_ruleset") as verify_ruleset:
            seal.verify_repository("example/project")
        self.assertEqual(verify_ruleset.call_count, 2)

    def test_verify_rejects_any_extra_public_ref(self):
        metadata = {"visibility": "public", "default_branch": "public-release"}
        with mock.patch.object(seal, "gh_json", return_value=metadata), \
             mock.patch.object(seal, "ref_names", return_value=["main", "public-release"]):
            with self.assertRaisesRegex(RuntimeError, "unexpected branch"):
                seal.verify_repository("example/project")


if __name__ == "__main__":
    unittest.main()
