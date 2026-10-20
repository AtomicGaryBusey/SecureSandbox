import importlib.util
import os
import json
import base64
import unittest

SPEC = importlib.util.spec_from_file_location("source_fetcher", os.path.join(os.path.dirname(__file__), "source_fetcher.py"))
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class SourceFetcherTests(unittest.TestCase):
    def test_repository_accepts_conservative_slug(self):
        self.assertEqual(module.validate_repository("owner/repo-name"), "owner/repo-name")

    def test_repository_rejects_urls_git_suffix_and_controls(self):
        for value in ("https://github.com/a/b", "owner/repo.git", "owner/repo\nnext", "owner//repo", "../repo"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_repository(value)

    def test_ref_rejects_encoded_or_url_like_input(self):
        for value in ("", "main?x=1", "main#fragment", "heads%2Fmain", "a\\b", "line\nfeed"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_ref(value)

    def test_npm_requires_scoped_name_and_exact_version(self):
        self.assertEqual(module.validate_npm_package("@example/sdk"), "@example/sdk")
        self.assertEqual(module.validate_npm_version("4.13.0"), "4.13.0")
        for value in ("example/sdk", "@scope/pkg/latest", "@scope/pkg\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_npm_package(value)
        for value in ("latest", "^4.13.0", "4.13", "4.13.0 || 9.0.0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_npm_version(value)

    def test_npm_resolution_binds_registry_integrity(self):
        integrity = "sha512-" + base64.b64encode(b"x" * 64).decode()
        payload = json.dumps({
            "name": "@example/sdk", "version": "4.13.0",
            "dist": {"integrity": integrity, "shasum": "a" * 40,
                     "tarball": "https://registry.npmjs.org/@example/sdk/-/sdk-4.13.0.tgz"},
        }).encode()
        original = module.request
        try:
            module.request = lambda *_args, **_kwargs: (200, {"content-type": "application/json"}, payload)
            result = module.resolve_npm({}, "@example/sdk", "4.13.0")
        finally:
            module.request = original
        self.assertEqual(result["source_kind"], "npm_package")
        self.assertEqual(result["npm_integrity"], integrity)
        self.assertEqual(result["resolved_commit"], "a" * 40)


if __name__ == "__main__":
    unittest.main()
