#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_morning_preflight",
    ROOT / "scripts/harness-lifecycle-acceptance-morning-preflight.py",
)
assert SPEC is not None and SPEC.loader is not None
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)
NOW = 2_000_000_000
COMMIT = "a" * 40


class GitRunner:
    def __init__(self, *, dirty: bool = False, remote_commit: str = COMMIT):
        self.dirty = dirty
        self.remote_commit = remote_commit
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        arguments = command[1:]
        if arguments[0] == "rev-parse":
            output = f"{COMMIT}\n".encode("ascii")
        elif arguments[0] == "symbolic-ref":
            output = b"public-release\n"
        elif arguments[0] == "status":
            output = b"?? unexpected\n" if self.dirty else b""
        elif arguments[0] == "ls-remote":
            output = (
                f"{self.remote_commit}\trefs/heads/public-release\n".encode("ascii")
            )
        else:
            raise AssertionError(arguments)
        return subprocess.CompletedProcess(command, 0, output, b"")


class MorningPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.enrollment_path = self.root / "enrollment.json"
        self.enrollment = {
            "schema": acceptance.ENROLLMENT_SCHEMA,
            "enrollment_id": str(uuid.uuid4()),
            "machine_identity_sha256": "b" * 64,
            "observed_at": NOW - 60,
            "disposable": True,
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "collector": "secure-sandbox-disposable-supervisor-v1",
        }
        self.enrollment["enrollment_sha256"] = acceptance.digest(self.enrollment)
        self.enrollment_path.write_bytes(acceptance.canonical(self.enrollment))
        self.enrollment_path.chmod(0o600)
        self.source = {
            "driver_count": 10,
            "drivers": [{"source_complete": True} for _ in range(10)],
        }

    def tearDown(self):
        self.temporary.cleanup()

    def installed(self, count: int, error: str | None) -> dict:
        return {
            "available_driver_count": count,
            "drivers": [{"installation_error": error} for _ in range(10)],
        }

    def execute(self, installed: dict):
        with mock.patch.object(
            preflight, "source_checkout",
            return_value=(COMMIT, {"origin": COMMIT}),
        ), mock.patch.object(
            preflight.ACCEPTANCE_CLI, "trusted_json", return_value=self.enrollment,
        ), mock.patch.object(
            preflight.ENROLLER, "machine_identity", return_value="b" * 64,
        ), mock.patch.object(
            preflight, "production_material_absent",
        ), mock.patch.object(
            preflight, "trusted_bootstrap_hierarchy",
            return_value=[
                {"path": path, "device": 1, "inode": inode, "uid": 0,
                 "gid": 0, "mode": 0o755, "acl_present": False}
                for inode, path in enumerate(
                    ("/", "/private", "/private/var", "/private/var/db"), 1,
                )
            ],
        ), mock.patch.object(
            preflight.ACCEPTANCE_CLI, "driver_readiness",
            side_effect=(self.source, installed),
        ), mock.patch.object(
            preflight.SUPERVISOR, "require_gui_closed",
        ), mock.patch.object(
            preflight.SUPERVISOR, "vm_inventory",
            return_value={"gateway": "stopped", "research": "stopped", "target": "stopped"},
        ):
            return preflight.run_preflight(
                self.enrollment_path, now=NOW, home=self.root,
                environment={}, expected_install_uid=0, effective_uid=501,
            )

    def test_clean_uninstalled_machine_queues_only_exact_root_install(self):
        value = self.execute(
            self.installed(0, "protected_driver_installation_missing"),
        )
        self.assertEqual(value["status"], "ready")
        self.assertEqual(value["next_authorization"], "root-password")
        self.assertEqual(
            value["next_action"],
            "bootstrap-root-owned-exact-commit-host-installer",
        )
        self.assertEqual(value["source_driver_count"], 10)
        self.assertEqual(value["protected_driver_count"], 0)
        self.assertEqual(
            [item["path"] for item in value["bootstrap_trust_root"]],
            ["/", "/private", "/private/var", "/private/var/db"],
        )
        self.assertFalse(value["touch_id_authorization_ready"])
        self.assertEqual(value["touch_id_cases_queued"], 11)
        self.assertEqual(
            value["preflight_sha256"],
            acceptance.digest({key: item for key, item in value.items()
                               if key != "preflight_sha256"}),
        )

    def test_complete_protected_release_never_preapproves_touch_id(self):
        value = self.execute(self.installed(10, None))
        self.assertTrue(value["protected_installation_ready"])
        self.assertEqual(value["next_authorization"], "none")
        self.assertEqual(value["next_action"], "initialize-exact-commit-campaign")
        self.assertFalse(value["touch_id_authorization_ready"])

    def test_partial_or_invalid_absent_installation_fails_closed(self):
        for installed, reason in (
            (self.installed(1, None), "partial"),
            (self.installed(0, "protected_driver_manifest_invalid"), "invalid"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(
                preflight.PreflightError, f"protected_installation_{reason}",
            ):
                self.execute(installed)

    def test_changed_machine_identity_fails_before_driver_or_vm_checks(self):
        with mock.patch.object(
            preflight, "source_checkout",
            return_value=(COMMIT, {"origin": COMMIT}),
        ), mock.patch.object(
            preflight.ACCEPTANCE_CLI, "trusted_json", return_value=self.enrollment,
        ), mock.patch.object(
            preflight.ENROLLER, "machine_identity", return_value="c" * 64,
        ), mock.patch.object(
            preflight.ACCEPTANCE_CLI, "driver_readiness",
        ) as readiness, self.assertRaisesRegex(
            preflight.PreflightError, "machine_identity_mismatch",
        ):
            preflight.run_preflight(
                self.enrollment_path, now=NOW, home=self.root, environment={},
                effective_uid=501,
            )
        readiness.assert_not_called()

    def test_gate_itself_rejects_root_without_probing(self):
        with mock.patch.object(preflight, "trusted_bootstrap_hierarchy") as trust, \
                mock.patch.object(preflight, "source_checkout") as checkout, \
                self.assertRaisesRegex(preflight.PreflightError, "must_not_run_as_root"):
            preflight.run_preflight(
                self.enrollment_path, now=NOW, home=self.root,
                environment={}, effective_uid=0,
            )
        checkout.assert_not_called()
        trust.assert_not_called()

    def test_bootstrap_trust_root_requires_fixed_safe_directories_without_acls(self):
        first = self.root / "first"
        second = first / "second"
        second.mkdir(parents=True)
        first.chmod(0o755)
        second.chmod(0o755)
        records = preflight.trusted_bootstrap_hierarchy(
            hierarchy=(first, second), expected_uid=os.getuid(),
        )
        self.assertEqual([item["path"] for item in records], [str(first), str(second)])
        self.assertTrue(all(item["acl_present"] is False for item in records))
        self.assertTrue(all(
            item["device"] > 0 and item["inode"] > 0 for item in records
        ))

        second.chmod(0o775)
        with self.assertRaisesRegex(preflight.PreflightError, "trust_root_invalid"):
            preflight.trusted_bootstrap_hierarchy(
                hierarchy=(first, second), expected_uid=os.getuid(),
            )
        second.chmod(0o755)
        link = self.root / "link"
        link.symlink_to(first, target_is_directory=True)
        with self.assertRaisesRegex(preflight.PreflightError, "trust_root_invalid"):
            preflight.trusted_bootstrap_hierarchy(
                hierarchy=(link,), expected_uid=os.getuid(),
            )

        def acl_runner(command, **_kwargs):
            return subprocess.CompletedProcess(
                command, 0,
                b"drwxr-xr-x 2 owner group 64 Jan 1 00:00 path\n"
                b" 0: user:example allow write\n",
                b"",
            )

        with self.assertRaisesRegex(preflight.PreflightError, "trust_root_invalid"):
            preflight.trusted_bootstrap_hierarchy(
                hierarchy=(first,), expected_uid=os.getuid(), runner=acl_runner,
            )

    def test_bootstrap_trust_root_rejects_identity_change_across_acl_probe(self):
        directory = self.root / "directory"
        directory.mkdir()
        before = os.lstat(directory)
        values = list(before)
        values[1] += 1
        changed = os.stat_result(values)
        lstat = mock.Mock(side_effect=(before, changed))

        def runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, b"safe directory\n", b"")

        with self.assertRaisesRegex(preflight.PreflightError, "trust_root_invalid"):
            preflight.trusted_bootstrap_hierarchy(
                hierarchy=(directory,), expected_uid=os.getuid(), runner=runner,
                lstat=lstat,
            )

    def test_checkout_requires_clean_public_branch_at_both_exact_remote_tips(self):
        runner = GitRunner()
        commit, tips = preflight.source_checkout(runner=runner)
        self.assertEqual(commit, COMMIT)
        self.assertEqual(tips, {"origin": COMMIT})
        remote_calls = [call for call in runner.calls if call[0][1] == "ls-remote"]
        self.assertEqual(
            [call[0][4] for call in remote_calls],
            ["refs/heads/public-release"],
        )
        self.assertEqual(
            [call[0][3] for call in remote_calls],
            [
                "https://github.com/AtomicGaryBusey/SecureSandbox.git",
            ],
        )
        for command, kwargs in remote_calls:
            self.assertNotIn("origin", command)
            self.assertNotIn("hobby", command)
            self.assertEqual(kwargs["cwd"], Path("/"))
            self.assertEqual(kwargs["env"]["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
        for runner, reason in (
            (GitRunner(dirty=True), "checkout_invalid"),
            (GitRunner(remote_commit="c" * 40), "remote_tip_mismatch"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(
                preflight.PreflightError, reason,
            ):
                preflight.source_checkout(runner=runner)

    def test_checkout_git_commands_use_only_their_explicit_trusted_context(self):
        runner = GitRunner()
        preflight.source_checkout(runner=runner)
        for command, kwargs in runner.calls:
            self.assertEqual(command[0], "/usr/bin/git")
            self.assertEqual(
                set(kwargs["env"]),
                {
                    "PATH", "LANG", "LC_ALL", "GIT_NO_REPLACE_OBJECTS",
                    "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL",
                    "GIT_TERMINAL_PROMPT",
                },
            )
            expected_cwd = Path("/") if command[1] == "ls-remote" else preflight.ROOT
            self.assertEqual(kwargs["cwd"], expected_cwd)

    def test_repository_local_url_rewrite_cannot_substitute_authorized_tip(self):
        checkout = self.root / "checkout"
        good_bare = self.root / "good.git"
        bad_checkout = self.root / "bad-checkout"
        bad_bare = self.root / "bad.git"

        def git(*arguments: str, cwd: Path | None = None) -> bytes:
            return subprocess.run(
                ["/usr/bin/git", *arguments], cwd=cwd,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            ).stdout

        for repository, content in ((checkout, "authorized\n"),
                                    (bad_checkout, "substituted\n")):
            git("init", "-q", str(repository))
            git("config", "user.name", "Acceptance Test", cwd=repository)
            git("config", "user.email", "acceptance@example.invalid", cwd=repository)
            (repository / "payload.txt").write_text(content, encoding="utf-8")
            git("add", "payload.txt", cwd=repository)
            git("commit", "-q", "-m", "fixture", cwd=repository)
            git("branch", "-M", "public-release", cwd=repository)
        git("clone", "-q", "--bare", str(checkout), str(good_bare))
        git("clone", "-q", "--bare", str(bad_checkout), str(bad_bare))
        good_commit = git("rev-parse", "HEAD", cwd=checkout).decode("ascii").strip()
        bad_commit = git("rev-parse", "HEAD", cwd=bad_checkout).decode("ascii").strip()
        good_url = good_bare.as_uri()
        bad_url = bad_bare.as_uri()
        git("config", f"url.{bad_url}.insteadOf", good_url, cwd=checkout)

        poisoned = preflight.git_command(
            ["ls-remote", "--exit-code", good_url,
             "refs/heads/public-release"],
            cwd=checkout,
        ).decode("ascii").split()[0]
        self.assertEqual(poisoned, bad_commit)
        with mock.patch.object(preflight, "ROOT", checkout), mock.patch.object(
            preflight, "AUTHORIZED_REMOTES",
            (("origin", good_url), ("hobby", good_url)),
        ):
            commit, tips = preflight.source_checkout()
        self.assertEqual(commit, good_commit)
        self.assertEqual(tips, {"origin": good_commit, "hobby": good_commit})

    def test_production_material_probe_rejects_environment_path_and_keychain(self):
        with mock.patch.object(preflight.ENROLLER, "keychain_absent"):
            with self.assertRaisesRegex(preflight.PreflightError, "material_present"):
                preflight.production_material_absent(
                    home=self.root, environment={"OPENAI_API_KEY": "set"},
                )
            marker = self.root / ".claude"
            marker.mkdir()
            with self.assertRaisesRegex(preflight.PreflightError, "material_present"):
                preflight.production_material_absent(home=self.root, environment={})
            marker.rmdir()
        with mock.patch.object(
            preflight.ENROLLER, "keychain_absent",
            side_effect=acceptance.AcceptanceError("credential_marker_present"),
        ), self.assertRaisesRegex(preflight.PreflightError, "material_present"):
            preflight.production_material_absent(home=self.root, environment={})


if __name__ == "__main__":
    unittest.main()
