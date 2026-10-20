#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from unittest import mock

import dependency_orchestrator as dependency


ROOT_SOURCE = "11111111-1111-4111-8111-111111111111"
DEP_SOURCE = "22222222-2222-4222-8222-222222222222"


class DependencyOrchestratorTests(unittest.TestCase):
    def test_exact_direct_dependencies_are_canonical(self):
        package = {"dependencies": {"@scope/zeta": "3.23.8", "@scope/pkg": "1.2.3"}}
        self.assertEqual(dependency.exact_dependencies(package), [
            {"name": "@scope/pkg", "version": "1.2.3"},
            {"name": "@scope/zeta", "version": "3.23.8"},
        ])

    def test_ranges_aliases_and_excessive_sets_are_rejected(self):
        for version in ("^1.2.3", "~1.2.3", "latest", "workspace:*", "npm:other@1.0.0"):
            with self.subTest(version=version), self.assertRaisesRegex(dependency.DependencyError, "non_exact_dependency_version"):
                dependency.exact_dependencies({"dependencies": {"@scope/pkg": version}})
        with self.assertRaisesRegex(dependency.DependencyError, "invalid_dependencies"):
            dependency.exact_dependencies({"dependencies": {f"@scope/pkg-{index}": "1.0.0" for index in range(65)}})

    def test_resolution_reports_missing_and_rejects_ambiguity(self):
        records = [{
            "source_id": DEP_SOURCE,
            "source_kind": "npm_package",
            "package_name": "@scope/zod",
            "package_version": "3.23.8",
            "registry_integrity_verified": True,
            "npm_integrity": "sha512-value",
            "tree_manifest_sha256": "a" * 64,
        }]
        with mock.patch.object(dependency, "source_records", return_value=records), \
             mock.patch.object(dependency, "package_identity", return_value=(records[0], {})):
            resolved = dependency.resolve_dependencies([
                {"name": "@scope/missing", "version": "1.0.0"},
                {"name": "@scope/zod", "version": "3.23.8"},
            ])
        self.assertIsNone(resolved[0]["source_id"])
        self.assertEqual(resolved[1]["source_id"], DEP_SOURCE)
        with mock.patch.object(dependency, "source_records", return_value=[records[0], dict(records[0])]):
            with self.assertRaisesRegex(dependency.DependencyError, "ambiguous_dependency_source"):
                dependency.resolve_dependencies([{"name": "@scope/zod", "version": "3.23.8"}])

    def test_plan_is_bound_to_root_tree_and_dependency_set(self):
        first = dependency.dependency_digest(ROOT_SOURCE, "a" * 64, [{"name": "@scope/zod", "version": "3.23.8"}])
        changed_tree = dependency.dependency_digest(ROOT_SOURCE, "b" * 64, [{"name": "@scope/zod", "version": "3.23.8"}])
        changed_version = dependency.dependency_digest(ROOT_SOURCE, "a" * 64, [{"name": "@scope/zod", "version": "3.23.9"}])
        self.assertNotEqual(first, changed_tree)
        self.assertNotEqual(first, changed_version)

    def test_apply_creates_read_only_bundle_without_executing_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = os.path.join(directory, "workspace")
            state = os.path.join(directory, "state")
            bundle_root = os.path.join(workspace, "dependency-bundles")
            baselines = os.path.join(workspace, "baselines")
            os.makedirs(os.path.join(state, "plans"))
            os.makedirs(os.path.join(state, "transactions"))
            os.makedirs(bundle_root)
            os.makedirs(os.path.join(baselines, ROOT_SOURCE))
            os.makedirs(os.path.join(baselines, DEP_SOURCE))
            index_path = os.path.join(bundle_root, "INDEX.json")
            with open(index_path, "w", encoding="utf-8") as handle:
                json.dump({"schema": "secure-sandbox-dependency-bundle-index-v1", "bundles": []}, handle)
            root_record = {
                "source_id": ROOT_SOURCE, "source_kind": "npm_package",
                "package_name": "@scope/root", "package_version": "1.0.0",
                "tree_manifest_sha256": "a" * 64,
                "baseline_path": f"baselines/{ROOT_SOURCE}",
            }
            dep_record = {
                "source_id": DEP_SOURCE, "source_kind": "npm_package",
                "package_name": "@scope/zod", "package_version": "3.23.8",
                "tree_manifest_sha256": "b" * 64,
                "baseline_path": f"baselines/{DEP_SOURCE}",
            }
            deps = [{"name": "@scope/zod", "version": "3.23.8"}]
            digest = dependency.dependency_digest(ROOT_SOURCE, "a" * 64, deps)
            plan_id = "33333333-3333-4333-8333-333333333333"
            plan = {
                "schema": "secure-sandbox-dependency-plan-v1", "plan_id": plan_id,
                "root_source_id": ROOT_SOURCE, "root_package_name": "@scope/root",
                "root_package_version": "1.0.0", "root_tree_manifest_sha256": "a" * 64,
                "dependency_set_sha256": digest, "dependencies": deps,
                "expires_unix": 4_000_000_000, "state": "planned",
            }
            plan_path = os.path.join(state, "plans", f"{plan_id}.json")
            with open(plan_path, "w", encoding="utf-8") as handle:
                json.dump(plan, handle)

            def fixed(path, prefix):
                return os.path.join(workspace, path)

            def registered(source_id):
                return root_record if source_id == ROOT_SOURCE else dep_record

            resolved = [{**deps[0], "source_id": DEP_SOURCE, "npm_integrity": "sha512-value", "tree_manifest_sha256": "b" * 64}]
            with mock.patch.multiple(dependency, BUNDLE_ROOT=bundle_root, BUNDLE_INDEX=index_path, STATE_ROOT=state, PLAN_ROOT=os.path.join(state, "plans"), TRANSACTION_ROOT=os.path.join(state, "transactions"), LOCK=os.path.join(state, "lock")), \
                 mock.patch.object(dependency, "require_root_and_idle"), \
                 mock.patch.object(dependency, "load_plan", return_value=plan), \
                 mock.patch.object(dependency, "load_control_json", return_value={"schema": "secure-sandbox-dependency-bundle-index-v1", "bundles": []}), \
                 mock.patch.object(dependency, "package_identity", return_value=(root_record, {"dependencies": {"@scope/zod": "3.23.8"}})), \
                 mock.patch.object(dependency, "resolve_dependencies", return_value=resolved), \
                 mock.patch.object(dependency, "registered_source", side_effect=registered), \
                 mock.patch.object(dependency, "fixed_tree_path", side_effect=fixed), \
                 mock.patch.object(dependency.os, "chown"), \
                 mock.patch.object(dependency, "emit"):
                result = dependency.apply(plan_id)
            destination = os.path.join(bundle_root, result["bundle_id"])
            self.assertTrue(os.path.islink(os.path.join(destination, "root-package")))
            self.assertTrue(os.path.islink(os.path.join(destination, "node_modules", "@scope", "zod")))
            self.assertEqual(result["lifecycle_execution"], "disabled")
            self.assertFalse(result["transitive_completeness"])
            self.assertEqual(os.stat(os.path.join(destination, "manifest.json")).st_mode & 0o777, 0o444)

    def test_recovery_commits_bundle_across_both_publication_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            plans = os.path.join(directory, "plans")
            transactions = os.path.join(directory, "transactions")
            bundles = os.path.join(directory, "bundles")
            os.makedirs(plans)
            os.makedirs(transactions)
            os.makedirs(bundles)
            index_path = os.path.join(bundles, "INDEX.json")
            with open(index_path, "w", encoding="utf-8") as handle:
                json.dump({"schema": "secure-sandbox-dependency-bundle-index-v1", "bundles": []}, handle)
            plan_id = "33333333-3333-4333-8333-333333333333"
            bundle_id = "44444444-4444-4444-8444-444444444444"
            plan = {
                "schema": "secure-sandbox-dependency-plan-v1", "plan_id": plan_id,
                "root_source_id": ROOT_SOURCE, "root_package_name": "@scope/root",
                "root_package_version": "1.0.0", "root_tree_manifest_sha256": "a" * 64,
                "dependency_set_sha256": "c" * 64, "state": "planned",
            }
            manifest = {
                "schema": "secure-sandbox-dependency-bundle-v1", "bundle_id": bundle_id,
                "plan_id": plan_id, "root_source_id": ROOT_SOURCE,
                "root_package_name": "@scope/root", "root_package_version": "1.0.0",
                "root_tree_manifest_sha256": "a" * 64, "dependency_set_sha256": "c" * 64,
                "dependencies": [], "scope": "direct_runtime_dependencies",
                "lifecycle_execution": "disabled", "transitive_completeness": False,
                "created_at": "2026-10-17T00:00:00Z",
            }
            plan_path = os.path.join(plans, f"{plan_id}.json")
            with open(plan_path, "w", encoding="utf-8") as handle:
                json.dump(plan, handle)
            index = {"schema": "secure-sandbox-dependency-bundle-index-v1", "bundles": []}
            with mock.patch.multiple(dependency, BUNDLE_ROOT=bundles, BUNDLE_INDEX=index_path, PLAN_ROOT=plans, TRANSACTION_ROOT=transactions), \
                 mock.patch.object(dependency, "matching_bundles", return_value=[manifest]):
                recovered, updated = dependency.recover_plan(plan, index)
            self.assertEqual(recovered["bundle_id"], bundle_id)
            self.assertEqual(updated["bundles"][0]["plan_id"], plan_id)
            with open(plan_path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["state"], "completed")
            with open(index_path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["bundles"][0]["bundle_id"], bundle_id)

            # Simulate the second crash window: the index contains the bundle,
            # but the plan record still says planned. Recovery must complete
            # the plan without appending a duplicate index entry.
            with open(plan_path, "w", encoding="utf-8") as handle:
                json.dump(plan, handle)
            with mock.patch.multiple(dependency, BUNDLE_ROOT=bundles, BUNDLE_INDEX=index_path, PLAN_ROOT=plans, TRANSACTION_ROOT=transactions), \
                 mock.patch.object(dependency, "matching_bundles", return_value=[manifest]):
                recovered, updated_again = dependency.recover_plan(plan, updated)
            self.assertEqual(recovered["bundle_id"], bundle_id)
            self.assertEqual(len(updated_again["bundles"]), 1)
            with open(plan_path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["state"], "completed")

    def test_cumulative_bundle_limit_is_explicit(self):
        value = {
            "schema": "secure-sandbox-dependency-bundle-index-v1",
            "bundles": [{"bundle_id": str(__import__("uuid").uuid4())} for _ in range(dependency.MAX_BUNDLES + 1)],
        }
        with mock.patch.object(dependency, "load_control_json", return_value=value):
            with self.assertRaisesRegex(dependency.DependencyError, "bundle_limit_exceeded"):
                dependency.bundle_index()


if __name__ == "__main__":
    unittest.main()
