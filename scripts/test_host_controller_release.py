#!/usr/bin/env python3

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
REPO = SCRIPT_DIR.parent
MANAGER_PATH = SCRIPT_DIR / "host-controller-release.py"
SPEC = importlib.util.spec_from_file_location("host_controller_release", MANAGER_PATH)
MANAGER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MANAGER)
LAUNCHER_PATH = SCRIPT_DIR / "secure-sandbox-claude-launcher.py"
LAUNCHER_SPEC = importlib.util.spec_from_file_location("secure_sandbox_launcher_test", LAUNCHER_PATH)
LAUNCHER = importlib.util.module_from_spec(LAUNCHER_SPEC)
assert LAUNCHER_SPEC.loader is not None
LAUNCHER_SPEC.loader.exec_module(LAUNCHER)


class HostControllerReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "config").mkdir()
        for relative in [*MANAGER.PAYLOAD_SOURCES.values(), MANAGER.LAUNCHER_SOURCE]:
            shutil.copyfile(REPO / relative, self.repo / relative)
        self.install_root = self.root / "installed"
        self.launcher = self.root / "bin/secure-sandbox-claude"
        self.state = self.root / "state"
        self.uid = os.geteuid()
        self.op_binary = self.root / "op"
        self.op_binary.write_bytes(b"test-op-binary\n")
        self.op_binary.chmod(0o755)
        self.gpgv_binary = self.root / "gpgv"
        self.gpgv_binary.write_bytes(b"test-gpgv-binary\n")
        self.gpgv_binary.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def install(self):
        return MANAGER.install(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            self.op_binary, self.gpgv_binary,
        )

    def test_install_and_verify_are_content_bound(self):
        deployed = self.install()
        verified = MANAGER.verify(
            self.repo, self.install_root, self.launcher, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        loaded_path, loaded_id = LAUNCHER.load_release(self.install_root, self.uid)
        self.assertEqual(deployed["release_id"], verified["release_id"])
        self.assertEqual((loaded_path.name, loaded_id), (verified["release_id"], verified["release_id"]))
        self.assertEqual(os.readlink(self.install_root / "current"), f"releases/{verified['release_id']}")
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# changed\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_release_source_mismatch"):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )

    def test_launcher_rejects_payload_tampering(self):
        self.install()
        controller = (self.install_root / "current").resolve() / "controller"
        controller.chmod(0o755)
        with controller.open("a", encoding="utf-8") as handle:
            handle.write("# tampered\n")
        controller.chmod(0o555)
        with self.assertRaisesRegex(LAUNCHER.LaunchFailure, "payload_hash_mismatch"):
            LAUNCHER.load_release(self.install_root, self.uid)

    def test_failed_syntax_check_does_not_change_current(self):
        original = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("if then\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "controller_syntax_invalid"):
            self.install()
        self.assertEqual((self.install_root / "current").resolve().name, original)

    def test_deploy_refuses_live_marker_and_prunes_stale_marker(self):
        self.install()
        active = self.state / "active"
        active.mkdir(parents=True)
        live = active / "live.json"
        live.write_text(json.dumps({"pid": os.getpid(), "release_id": "a" * 64}), encoding="ascii")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_controller_invocations"):
            self.install()
        live.write_text(json.dumps({"pid": 2147483647, "release_id": "a" * 64}), encoding="ascii")
        self.install()
        self.assertFalse(live.exists())

    def test_second_release_can_roll_back(self):
        first = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        second = self.install()["release_id"]
        self.assertNotEqual(first, second)
        result = MANAGER.rollback(
            self.repo, self.install_root, self.state, None, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["release_id"], first)
        self.assertFalse(result["repo_match"])
        self.assertEqual((self.install_root / "previous").resolve().name, second)

    def test_stable_launcher_change_requires_explicit_migration(self):
        self.install()
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# incompatible launcher change\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "stable_launcher_change_requires_migration"):
            self.install()

    def test_launcher_migration_is_old_hash_gated_and_backed_up(self):
        self.install()
        old_bytes = self.launcher.read_bytes()
        old_hash = MANAGER.sha256_bytes(old_bytes)
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# reviewed migration\n")
        replacement_hash = MANAGER.sha256_bytes((self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes())
        result = MANAGER.migrate_launcher(
            self.repo, self.install_root, self.launcher, self.state, self.uid, old_hash, replacement_hash
        )
        self.assertEqual(result["previous_launcher_sha256"], old_hash)
        self.assertEqual(Path(result["backup"]).read_bytes(), old_bytes)
        self.assertEqual(MANAGER.sha256_bytes(self.launcher.read_bytes()), result["launcher_sha256"])
        deployed = self.install()
        self.assertEqual(
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )["release_id"],
            deployed["release_id"],
        )

    def test_launcher_migration_rejects_unexpected_replacement_hash(self):
        self.install()
        old_hash = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# reviewed migration\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "replacement_launcher_hash_unexpected"):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                old_hash, "0" * 64,
            )

    def test_rollback_status_survives_unavailable_repository(self):
        first = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        self.install()
        (self.repo / "scripts/pki-host-anchor.py").unlink()
        result = MANAGER.rollback(
            self.repo, self.install_root, self.state, first, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "rolled_back")
        self.assertIsNone(result["repo_match"])

    def test_restrictive_umask_cannot_change_installed_modes(self):
        previous = os.umask(0o077)
        try:
            self.install()
        finally:
            os.umask(previous)
        release = (self.install_root / "current").resolve()
        self.assertEqual(self.launcher.stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "controller").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "gpgv").stat().st_mode & 0o777, 0o555)
        self.assertEqual((release / "installer_verifier").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "op_agents").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "pki_anchor").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "ssh_config").stat().st_mode & 0o777, 0o444)

    def test_op_binary_is_bound_into_release_bridge(self):
        self.install()
        release = (self.install_root / "current").resolve()
        bridge = (release / "op_agents").read_text(encoding="utf-8")
        self.assertIn(MANAGER.sha256_bytes(self.op_binary.read_bytes()), bridge)
        self.op_binary.write_bytes(b"changed-op\n")
        rejected = subprocess.run(
            ["/bin/bash", str(release / "op_agents"), "read", "unused"],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("op_binary_hash_mismatch", rejected.stderr)
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_release_source_mismatch"):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )

    def test_incomplete_old_lock_is_atomically_reclaimed(self):
        self.state.mkdir(parents=True)
        lock = self.state / "coordination.lock"
        lock.mkdir()
        old = time.time() - LAUNCHER.LOCK_INCOMPLETE_GRACE_SECONDS - 1
        os.utime(lock, (old, old))
        acquired = LAUNCHER.acquire_lock(self.state, timeout=0.2)
        self.assertEqual(acquired, lock)
        LAUNCHER.release_lock(acquired)
        self.assertFalse(lock.exists())

    def test_recent_incomplete_lock_fails_closed(self):
        self.state.mkdir(parents=True)
        (self.state / "coordination.lock").mkdir()
        with self.assertRaisesRegex(LAUNCHER.LaunchFailure, "coordination_lock_timeout"):
            LAUNCHER.acquire_lock(self.state, timeout=0.05)


class ControllerBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.release = self.root / "release"
        self.bin = self.root / "bin"
        self.release.mkdir()
        self.bin.mkdir()
        shutil.copyfile(REPO / "config/ssh_config", self.release / "ssh_config")
        self.log = self.root / "ssh.log"
        mocks = {
            "op-agents": "#!/bin/bash\nprintf 'secret\\n'\n",
            "uuidgen": "#!/bin/bash\nprintf '12345678-1234-4123-8123-123456789abc\\n'\n",
            "sleep": "#!/bin/bash\nexit 0\n",
            "date": "#!/bin/bash\nif [[ \"${1:-}\" == -r ]]; then printf '2033-05-18T03:33:20Z\\n'; else printf '2000000000\\n'; fi\n",
            "ssh": """#!/bin/bash
printf '%s\\n' "$*" >>"$SSH_LOG"
case "$*" in *"sudo -S"*) cat >/dev/null ;; esac
case "$*" in
  *"date -u +%s"*) printf '2000000000\\n' ;;
  *"run_lease.py issue"*)
    if [[ -n "${SSH_LEASE_JSON:-}" ]]; then printf '%s\\n' "$SSH_LEASE_JSON"
    else printf '%s\\n' '{"schema":"secure-sandbox-run-lease-v1","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","profile":"standard","issued_at":2000000000,"expires_at":2000000600,"maximum_expires_at":2000003600,"relay_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","model":"abliterated-model-large-v2","limits":{},"pricing":{},"renewals":0}'
    fi ;;
  *"run_lease.py finalize"*)
    if [[ -n "${SSH_GATEWAY_SUMMARY+x}" ]]; then printf '%s\n' "$SSH_GATEWAY_SUMMARY"
    else
      reason=completed
      case "$*" in *session_failed*) reason=session_failed;; *operator_closed*) reason=operator_closed;; *expired*) reason=expired;; *launch_failed*) reason=launch_failed;; esac
      printf '{"schema":"secure-sandbox-run-lease-summary-v1","lease":{"schema":"secure-sandbox-run-lease-v1","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","profile":"standard","issued_at":2000000000,"expires_at":2000000600,"maximum_expires_at":2000003600,"relay_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","model":"abliterated-model-large-v2","limits":{},"pricing":{},"renewals":0},"final_counters":{"schema":"secure-sandbox-run-lease-counter-v1","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","requests":0,"input_tokens":0,"output_tokens":0,"cost_microusd":0,"updated_at":2000000000},"finalized_at":2000000000,"reason":"%s"}\n' "$reason"
    fi ;;
  *"run_lease_watchdog.py close"*) exit "${SSH_CLOSE_STATUS:-0}" ;;
  *"pki_generation.py verify"*) printf '{"generation_id":"12345678-1234-4123-8123-123456789abc","manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\\n' ;;
  *"research-claude"*) exit "${SSH_FINAL_STATUS:-0}" ;;
esac
exit 0
""",
        }
        for name, body in mocks.items():
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        controller = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        for original, replacement in {
            "/usr/bin/ssh": str(self.bin / "ssh"),
            "/usr/bin/uuidgen": str(self.bin / "uuidgen"),
            "/bin/date": str(self.bin / "date"),
            "/bin/sleep": str(self.bin / "sleep"),
        }.items():
            controller = controller.replace(original, replacement)
        (self.release / "controller").write_text(controller, encoding="utf-8")
        (self.release / "controller").chmod(0o755)
        shutil.copyfile(self.bin / "op-agents", self.release / "op_agents")
        (self.release / "op_agents").chmod(0o755)
        (self.release / "pki_anchor").write_text(
            "#!/bin/bash\nprintf '{\"generation_id\":\"12345678-1234-4123-8123-123456789abc\",\"manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\\n'\n",
            encoding="utf-8",
        )
        (self.release / "pki_anchor").chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def run_controller(self, *arguments, final_status="0", lease_json=None, close_status="0",
                       gateway_summary=None):
        active = self.home / "Library/Application Support/SecureSandbox/controller-state/active"
        active.mkdir(parents=True, exist_ok=True)
        script = f'''marker="$HOME/Library/Application Support/SecureSandbox/controller-state/active/$$-test.json"
printf '{{"pid":%s,"release_id":"%s"}}\\n' "$$" "{'a' * 64}" >"$marker"
SECURE_SANDBOX_ACTIVE_MARKER="$marker" SECURE_SANDBOX_RELEASE_ID="{'a' * 64}" exec "$CONTROLLER" "$@"
'''
        env = os.environ.copy()
        env.update({
            "HOME": str(self.home),
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "SSH_LOG": str(self.log),
            "SSH_FINAL_STATUS": final_status,
            "SSH_CLOSE_STATUS": close_status,
            "CONTROLLER": str(self.release / "controller"),
            "SECURE_SANDBOX_STATE_ROOT": str(self.home / "Library/Application Support/SecureSandbox/controller-state"),
        })
        if lease_json is not None:
            env["SSH_LEASE_JSON"] = lease_json
        if gateway_summary is not None:
            env["SSH_GATEWAY_SUMMARY"] = gateway_summary
        return subprocess.run(["/bin/bash", "-c", script, "test", *arguments], env=env, text=True, capture_output=True)

    def test_new_session_uses_bash32_safe_branch_and_cleans_marker(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--resume", self.log.read_text(encoding="utf-8").splitlines()[-4])
        self.assertEqual(list((self.home / "Library/Application Support/SecureSandbox/controller-state/active").iterdir()), [])

    def test_resume_preserves_uuid_and_registry_check(self):
        session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        result = self.run_controller("--resume", session)
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("session_registry.py contains", log)
        self.assertIn(f"research-claude --resume {session}", log)

    def test_interrupted_remote_session_still_finalizes_and_cleans(self):
        result = self.run_controller(final_status="130")
        self.assertEqual(result.returncode, 130)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertIn("session_failed", log)
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertIn("run_lease_watchdog.py commit", log)
        self.assertNotIn("manage_run_id.py clear", log)
        active = self.home / "Library/Application Support/SecureSandbox/controller-state/active"
        self.assertEqual(list(active.iterdir()), [])

    def test_commit_binds_exact_gateway_summary_file_bytes(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = {
            "schema": "secure-sandbox-run-lease-summary-v1",
            "lease": {
                "schema": "secure-sandbox-run-lease-v1",
                "run_id": "12345678-1234-4123-8123-123456789abc",
                "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "profile": "standard",
                "issued_at": 2000000000,
                "expires_at": 2000000600,
                "maximum_expires_at": 2000003600,
                "relay_sha256": "a" * 64,
                "policy_sha256": "b" * 64,
                "model": "abliterated-model-large-v2",
                "limits": {},
                "pricing": {},
                "renewals": 0,
            },
            "final_counters": {
                "schema": "secure-sandbox-run-lease-counter-v1",
                "run_id": "12345678-1234-4123-8123-123456789abc",
                "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_microusd": 0,
                "updated_at": 2000000000,
            },
            "finalized_at": 2000000000,
            "reason": "completed",
        }
        durable = json.dumps(summary, separators=(",", ":"), sort_keys=True) + "\n"
        expected = hashlib.sha256(durable.encode("utf-8")).hexdigest()
        self.assertIn(
            f"run_lease_watchdog.py commit '12345678-1234-4123-8123-123456789abc' '{expected}'",
            self.log.read_text(encoding="utf-8"),
        )

    def test_invalid_resume_is_rejected_before_remote_access(self):
        result = self.run_controller("--resume", "not-a-uuid")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())

    def test_close_failure_overrides_session_success_and_skips_gateway_commit(self):
        result = self.run_controller(close_status="1")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertNotIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_invalid_gateway_summary_blocks_research_commit(self):
        result = self.run_controller(gateway_summary="")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_gateway_summary_must_bind_run_lease_reason_and_counter_schema(self):
        wrong = json.dumps({"schema":"secure-sandbox-run-lease-summary-v1",
                            "lease":{"schema":"secure-sandbox-run-lease-v1",
                                     "run_id":"12345678-1234-4123-8123-123456789abc",
                                     "lease_id":"12345678-1234-4123-8123-123456789abc"},
                            "final_counters":{},"finalized_at":2000000000,
                            "reason":"completed"})
        result = self.run_controller(gateway_summary=wrong)
        self.assertEqual(result.returncode, 70)
        self.assertNotIn("run_lease_watchdog.py commit", self.log.read_text(encoding="utf-8"))

    def test_gateway_expiry_shell_expression_is_rejected_without_execution(self):
        sentinel = self.root / "arithmetic-executed"
        malicious = json.dumps({
            "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "expires_at": f"x[$(/usr/bin/touch {sentinel})]",
        })
        result = self.run_controller(lease_json=malicious)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sentinel.exists())
        self.assertNotIn("run_lease_watchdog.py arm", self.log.read_text(encoding="utf-8"))

    def test_gateway_lease_id_shell_metacharacters_are_rejected_before_research(self):
        malicious = json.dumps({"lease_id": "' ; id ; '", "expires_at": 2000000600})
        result = self.run_controller(lease_json=malicious)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("run_lease_watchdog.py arm", self.log.read_text(encoding="utf-8"))

    def test_launcher_environment_is_allowlisted(self):
        marker = self.root / "marker"
        dangerous = {
            "BASH_ENV": "/tmp/evil", "ENV": "/tmp/evil", "SHELLOPTS": "xtrace",
            "BASHOPTS": "extdebug", "PYTHONPATH": "/tmp/evil", "DYLD_INSERT_LIBRARIES": "/tmp/evil",
        }
        with mock.patch.dict(os.environ, dangerous, clear=False):
            environment = LAUNCHER.controller_environment(marker, "a" * 64)
        self.assertFalse(set(dangerous) & set(environment))
        self.assertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")


if __name__ == "__main__":
    unittest.main()
