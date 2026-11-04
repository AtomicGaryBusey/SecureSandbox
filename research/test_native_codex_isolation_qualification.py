#!/usr/bin/env python3
"""Hostile tests for native Codex isolation qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from research import native_codex_isolation_qualification as isolation
from research.test_native_codex_protocol_firewall import (
    CODEX_HOME,
    THREAD_ID,
    initialize_result,
    launch_descriptor,
    new_firewall,
    thread_result,
    wire,
)


ATTEMPT_ID = "22222222-2222-4222-8222-222222222222"
BOOT_SHA = hashlib.sha256(
    b"33333333-3333-4333-8333-333333333333\n").hexdigest()
POLICY_SHA = "b" * 64
PROBE_SHA = "c" * 64
TOKEN_SHA = hashlib.sha256(b"nonsecret-fixture-token").hexdigest()
SCOPE_PATH = "/system.slice/secure-sandbox-native-run-fixture.scope"
SUPERVISOR_PATH = "/system.slice/native-harness-supervisor.service"
_TEMPORARIES: list[tempfile.TemporaryDirectory[str]] = []


def tearDownModule() -> None:
    while _TEMPORARIES:
        _TEMPORARIES.pop().cleanup()


def cgroup_sha(path: str) -> str:
    return hashlib.sha256((path + "\n").encode("ascii")).hexdigest()


def ready_firewall():
    firewall = new_firewall()
    firewall.initialize()
    firewall.ingest_server_line(wire({"id": 1, "result": initialize_result()}))
    firewall.start_thread()
    firewall.ingest_server_line(wire({"id": 2, "result": thread_result()}))
    return firewall


def fake_proc(root: Path, pid: int = 4242) -> tuple[Path, Path]:
    process = root / str(pid)
    (process / "ns").mkdir(parents=True)
    for offset, name in enumerate(isolation.NAMESPACE_NAMES, 1):
        (process / "ns" / name).symlink_to(f"{name}:[{1000 + offset}]")
    # field 22 (index 19 after the state field) is process start time.
    fields = ["S"] + [str(index) for index in range(1, 20)]
    (process / "stat").write_text(
        f"{pid} (codex) {' '.join(fields)}\n", encoding="ascii")
    boot = root / "boot_id"
    boot.write_text(
        "33333333-3333-4333-8333-333333333333\n", encoding="ascii")
    return process, boot


def challenge_fixture(directory: Path | None = None) -> tuple[object, dict]:
    firewall = ready_firewall()
    if directory is None:
        temporary = tempfile.TemporaryDirectory()
        _TEMPORARIES.append(temporary)
        directory = Path(temporary.name)
    process, boot = fake_proc(directory)
    challenge = isolation.make_challenge(
        firewall,
        launch_descriptor(),
        appserver_pid=int(process.name),
        service_uid=501,
        token_sha256=TOKEN_SHA,
        policy_manifest_sha256=POLICY_SHA,
        probe_executable_sha256=PROBE_SHA,
        scope_cgroup_sha256=cgroup_sha(SCOPE_PATH),
        allowed_service_cgroup_sha256s=[
            cgroup_sha(SCOPE_PATH), cgroup_sha(SUPERVISOR_PATH)],
        attempt_id=ATTEMPT_ID,
        proc_root=directory,
        boot_id_path=boot,
    )
    return firewall, challenge


def tool_observation(challenge: dict, *, outcome: str = "pass",
                     failures: list[str] | None = None,
                     unsupported: list[str] | None = None) -> dict:
    failure_codes = sorted(failures or [])
    unsupported_codes = sorted(unsupported or [])
    body = {
        "schema": isolation.TOOL_OBSERVATION_SCHEMA,
        "attempt_id": challenge["attempt_id"],
        "challenge_sha256": challenge["challenge_sha256"],
        "outcome": outcome,
        "failure_codes": failure_codes,
        "unsupported_codes": unsupported_codes,
        "namespace_separated": {
            "pid": True, "user": True, "mnt": True, "net": True},
        "child_namespaces": {
            "pid": 2001, "user": 2002, "mnt": 2003, "net": 2004},
        "proc_mount_restricted": True,
        "visible_process_count": 3,
        "parent_access": {
            "environ": "denied-enoent",
            "fd": "denied-enoent",
            "mem": "denied-enoent",
            "process_vm_readv": "denied-esrch",
            "ptrace": "denied-esrch",
        },
        "parent_canary_seen": False,
        "credential_environment_absent": True,
        "token_value_absent": True,
        "parent_canary_environment_absent": True,
        "unexpected_descriptor_count": 0,
        "stdio_descriptors_safe": True,
        "ipv4_blocked": True,
        "ipv6_blocked": True,
        "forced_crash_signal": 6,
        "forced_crash_host_pid": 5252,
        "forced_crash_core_absent": True,
        "escape_marker_absent": True,
        "raw_escape_payload_sha256": challenge[
            "raw_escape_payload_sha256"],
    }
    return {**body, "observation_sha256": isolation.digest(body)}


def root_observation(challenge: dict, *, failed: str | None = None) -> dict:
    checks = {name: True for name in isolation._ROOT_CHECKS}
    if failed is not None:
        checks[failed] = False
    body = {
        "schema": isolation.ROOT_OBSERVATION_SCHEMA,
        "attempt_id": challenge["attempt_id"],
        "challenge_sha256": challenge["challenge_sha256"],
        "checks": checks,
        "service_uid_process_count": 3,
    }
    return {**body, "observation_sha256": isolation.digest(body)}


def pass_evidence(directory: Path | None = None):
    firewall, challenge = challenge_fixture(directory)
    evidence = isolation.evaluate_qualification(
        firewall,
        launch_descriptor(),
        challenge=challenge,
        root_observation=root_observation(challenge),
        tool_observation=tool_observation(challenge),
        policy_manifest_sha256=POLICY_SHA,
        probe_executable_sha256=PROBE_SHA,
        observed_at_unix=1_800_000_000,
        marker_absent=True,
    )
    return firewall, challenge, evidence


class NativeCodexIsolationQualificationTests(unittest.TestCase):
    def assert_error(self, code: str, function) -> None:
        with self.assertRaises(isolation.NativeCodexIsolationError) as captured:
            function()
        self.assertEqual(str(captured.exception), code)

    def test_challenge_binds_ready_firewall_process_and_subject(self) -> None:
        firewall, challenge = challenge_fixture()
        self.assertEqual(
            challenge["launch_descriptor_sha256"],
            launch_descriptor()["descriptor_sha256"])
        self.assertEqual(challenge["appserver_pid"], 4242)
        self.assertEqual(challenge["service_uid"], 501)
        self.assertEqual(challenge["codex_home"], CODEX_HOME)
        self.assertEqual(
            firewall.qualification_authority.thread_id, THREAD_ID)
        self.assertEqual(
            isolation.validate_challenge(challenge), challenge)

        tampered = copy.deepcopy(challenge)
        tampered["service_uid"] = 502
        self.assert_error(
            "native_codex_isolation_challenge_digest_mismatch",
            lambda: isolation.validate_challenge(tampered))

    def test_challenge_rejects_uninitialized_failed_or_mismatched_firewall(self) -> None:
        uninitialized = new_firewall()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process, boot = fake_proc(root)
            options = dict(
                appserver_pid=int(process.name), service_uid=501,
                token_sha256=TOKEN_SHA,
                policy_manifest_sha256=POLICY_SHA,
                probe_executable_sha256=PROBE_SHA,
                scope_cgroup_sha256=cgroup_sha(SCOPE_PATH),
                allowed_service_cgroup_sha256s=[cgroup_sha(SCOPE_PATH)],
                attempt_id=ATTEMPT_ID, proc_root=root, boot_id_path=boot,
            )
            self.assert_error(
                "native_codex_isolation_firewall_not_ready",
                lambda: isolation.make_challenge(
                    uninitialized, launch_descriptor(), **options))
            self.assert_error(
                "native_codex_isolation_firewall_authority_mismatch",
                lambda: isolation.make_challenge(
                    ready_firewall(), launch_descriptor(model="gpt-6-luna"),
                    **options))

    def test_probe_request_is_exact_no_pty_no_stream_no_arbitrary_command(self) -> None:
        _firewall, challenge = challenge_fixture()
        request = json.loads(isolation.build_probe_request(challenge))
        self.assertEqual(set(request), {"id", "method", "params"})
        self.assertEqual(request["method"], "command/exec")
        params = request["params"]
        self.assertEqual(
            params["command"][:2],
            [str(isolation.PROBE_EXECUTABLE), "--encoded-challenge"])
        self.assertEqual(len(params["command"]), 3)
        self.assertFalse(params["tty"])
        self.assertFalse(params["streamStdin"])
        self.assertFalse(params["streamStdoutStderr"])
        self.assertEqual(params["cwd"], isolation.WORKSPACE)
        self.assertEqual(
            params["env"],
            {name: None for name in isolation.DENIED_CREDENTIAL_ENVIRONMENT})
        self.assertEqual(params["sandboxPolicy"], {
            "excludeSlashTmp": True,
            "excludeTmpdirEnvVar": True,
            "networkAccess": False,
            "type": "workspaceWrite",
            "writableRoots": [isolation.WORKSPACE],
        })
        decoded = isolation.decode_probe_challenge(params["command"][2])
        self.assertEqual(decoded, challenge)

    def test_probe_response_keeps_hostile_json_as_captured_content(self) -> None:
        _firewall, challenge = challenge_fixture()
        observation = tool_observation(challenge)
        stdout = (
            challenge["raw_escape_payload"] + "\n"
            + isolation.canonical_bytes(observation).decode("ascii"))
        response = isolation.canonical_bytes({
            "id": f"secure-sandbox-isolation-{ATTEMPT_ID}",
            "result": {"exitCode": 0, "stderr": "", "stdout": stdout},
        })
        self.assertEqual(
            isolation.accept_probe_response(response, challenge=challenge),
            observation)
        malicious = json.loads(response)
        malicious["method"] = "process/spawn"
        self.assert_error(
            "native_codex_isolation_probe_response_invalid",
            lambda: isolation.accept_probe_response(
                isolation.canonical_bytes(malicious), challenge=challenge))

    def test_all_required_hostile_checks_produce_content_free_pass(self) -> None:
        _firewall, challenge, evidence = pass_evidence()
        self.assertEqual(evidence["outcome"], "pass")
        self.assertTrue(all(evidence["checks"].values()))
        self.assertEqual(isolation.validate_evidence(evidence), evidence)
        raw = isolation.canonical_bytes(evidence)
        for forbidden in (
            b"nonsecret-fixture-token", b"ACCESS_TOKEN=", b"CODEX_HOME=",
            challenge["raw_escape_payload"].encode("ascii"),
            challenge["scratch_directory"].encode("ascii"),
        ):
            self.assertNotIn(forbidden, raw)

    def test_each_boundary_failure_prevents_pass(self) -> None:
        cases = {
            "root_executable": ("executable_root_owned", None),
            "namespace": (None, ("namespace_separated", "user", False)),
            "proc": (None, ("proc_mount_restricted", None, False)),
            "environ": (None, ("parent_access", "environ", "readable")),
            "ptrace": (None, ("parent_access", "ptrace", "attached")),
            "vm": (None, ("parent_access", "process_vm_readv", "authorized-efault")),
            "credentials": (None, ("credential_environment_absent", None, False)),
            "fds": (None, ("unexpected_descriptor_count", None, 1)),
            "stdio": (None, ("stdio_descriptors_safe", None, False)),
            "network": (None, ("ipv4_blocked", None, False)),
            "crash": (None, ("forced_crash_core_absent", None, False)),
            "escape": (None, ("escape_marker_absent", None, False)),
        }
        for name, (root_failure, mutation) in cases.items():
            with self.subTest(name=name):
                firewall, challenge = challenge_fixture()
                root = root_observation(challenge, failed=root_failure)
                tool = tool_observation(challenge)
                if mutation is not None:
                    field, nested, value = mutation
                    if nested is None:
                        tool[field] = value
                    else:
                        tool[field][nested] = value
                    body = {key: tool[key] for key in tool
                            if key != "observation_sha256"}
                    tool["observation_sha256"] = isolation.digest(body)
                evidence = isolation.evaluate_qualification(
                    firewall, launch_descriptor(), challenge=challenge,
                    root_observation=root, tool_observation=tool,
                    policy_manifest_sha256=POLICY_SHA,
                    probe_executable_sha256=PROBE_SHA,
                    observed_at_unix=1_800_000_000, marker_absent=True)
                self.assertEqual(evidence["outcome"], "fail")

    def test_unsupported_is_honest_and_never_passes(self) -> None:
        firewall, challenge = challenge_fixture()
        tool = tool_observation(
            challenge, outcome="unsupported",
            unsupported=["process_vm_readv_unsupported"])
        evidence = isolation.evaluate_qualification(
            firewall, launch_descriptor(), challenge=challenge,
            root_observation=root_observation(challenge),
            tool_observation=tool,
            policy_manifest_sha256=POLICY_SHA,
            probe_executable_sha256=PROBE_SHA,
            observed_at_unix=1_800_000_000, marker_absent=True)
        self.assertEqual(evidence["outcome"], "unsupported")
        isolation.validate_evidence(evidence)
        self.assert_error(
            "native_codex_isolation_receipt_not_passed",
            lambda: isolation.publish_pass_receipt(evidence))

    def test_pipe_core_pattern_is_a_root_failure_not_unsupported(self) -> None:
        # The collector must explicitly reject a piped core handler because
        # Linux ignores RLIMIT_CORE for pipe handlers.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pattern = root / "core_pattern"
            pattern.write_text("|/usr/lib/systemd/systemd-coredump\n", encoding="ascii")
            self.assertFalse(isolation._core_pattern_safe(pattern))
            pattern.write_text("core.%p\n", encoding="ascii")
            self.assertTrue(isolation._core_pattern_safe(pattern))

    def test_receipt_gate_is_current_boot_exact_subject_and_120_seconds(self) -> None:
        _firewall, _challenge, evidence = pass_evidence()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            uid, gid = os.geteuid(), os.getegid()
            isolation.publish_pass_receipt(
                evidence, receipt_root=root, trusted_uid=uid,
                trusted_gid=gid)
            with mock.patch.object(
                    isolation.native_codex_policy, "make_launch_descriptor",
                    return_value=launch_descriptor()):
                accepted = isolation.require_live_qualification(
                    {}, receipt_root=root,
                    policy_manifest_sha256=POLICY_SHA,
                    probe_sha256=PROBE_SHA,
                    current_boot_id_sha256=BOOT_SHA,
                    now=1_800_000_119,
                    trusted_uid=uid, trusted_gid=gid)
                self.assertEqual(accepted, evidence["evidence_sha256"])
                self.assert_error(
                    "native_codex_isolation_receipt_not_current",
                    lambda: isolation.require_live_qualification(
                        {}, receipt_root=root,
                        policy_manifest_sha256=POLICY_SHA,
                        probe_sha256=PROBE_SHA,
                        current_boot_id_sha256=BOOT_SHA,
                        now=1_800_000_121,
                        trusted_uid=uid, trusted_gid=gid))
            status = isolation.projection_isolation_status_observation(
                research_release_id="d" * 64, receipt_root=root,
                current_boot_id_sha256=BOOT_SHA, now=1_800_000_119,
                trusted_uid=uid, trusted_gid=gid)
            self.assertEqual(status, {
                "research_release_id": "d" * 64,
                "isolation_attestation_sha256": evidence["evidence_sha256"],
                "observed_at": 1_800_000_000,
                "expires_at": 1_800_000_120,
            })

    def test_prepared_journal_reconciles_crash_or_reboot_to_failure(self) -> None:
        _firewall, challenge = challenge_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            uid, gid = os.geteuid(), os.getegid()
            isolation.record_prepared(
                challenge, journal_root=root, trusted_uid=uid,
                trusted_gid=gid)
            records = isolation.reconcile_interrupted(
                journal_root=root, current_boot_id_sha256="e" * 64,
                trusted_uid=uid, trusted_gid=gid)
            self.assertEqual(len(records), 1)
            reconciled = json.loads(
                (root / f"{ATTEMPT_ID}-reconciled.json").read_bytes())
            self.assertEqual(reconciled["outcome"], "fail")
            self.assertEqual(
                reconciled["reason"], "qualification_reboot_interrupted")
            self.assertEqual(
                isolation.reconcile_interrupted(
                    journal_root=root, current_boot_id_sha256="e" * 64,
                    trusted_uid=uid, trusted_gid=gid),
                [])

    def test_reconciliation_refuses_to_bury_a_still_live_process(self) -> None:
        with tempfile.TemporaryDirectory() as proc_temporary, \
                tempfile.TemporaryDirectory() as journal_temporary:
            proc_root = Path(proc_temporary)
            _firewall, challenge = challenge_fixture(proc_root)
            journal = Path(journal_temporary)
            journal.chmod(0o700)
            uid, gid = os.geteuid(), os.getegid()
            isolation.record_prepared(
                challenge, journal_root=journal,
                trusted_uid=uid, trusted_gid=gid)
            self.assert_error(
                "native_codex_isolation_orphan_process_active",
                lambda: isolation.reconcile_interrupted(
                    journal_root=journal,
                    current_boot_id_sha256=challenge["boot_id_sha256"],
                    proc_root=proc_root,
                    trusted_uid=uid, trusted_gid=gid))
            self.assertFalse(
                (journal / f"{ATTEMPT_ID}-reconciled.json").exists())

    def test_terminal_journal_requires_matching_evidence(self) -> None:
        _firewall, challenge, evidence = pass_evidence()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            uid, gid = os.geteuid(), os.getegid()
            isolation.record_prepared(
                challenge, journal_root=root, trusted_uid=uid,
                trusted_gid=gid)
            isolation.record_terminal(
                challenge, evidence, journal_root=root,
                trusted_uid=uid, trusted_gid=gid)
            self.assertTrue(
                (root / f"{ATTEMPT_ID}-terminal.json").is_file())
            changed = copy.deepcopy(evidence)
            changed["challenge_sha256"] = "f" * 64
            body = {key: changed[key] for key in changed
                    if key != "evidence_sha256"}
            changed["evidence_sha256"] = isolation.digest(body)
            self.assert_error(
                "native_codex_isolation_journal_evidence_mismatch",
                lambda: isolation.record_terminal(
                    challenge, changed, journal_root=root,
                    trusted_uid=uid, trusted_gid=gid))


if __name__ == "__main__":
    unittest.main()
