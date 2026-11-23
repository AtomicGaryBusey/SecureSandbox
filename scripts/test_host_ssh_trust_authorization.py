#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import stat
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT_DIRECTORY = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, SCRIPT_DIRECTORY / filename,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


AUTH = load("host_ssh_trust_operator_authorization", "operator-authorization.py")
CLIENT = load("host_ssh_trust_client", "enroll-host-ssh-trust.py")


class HostSSHTrustAuthorizationTests(unittest.TestCase):
    NOW = 2_000_000_000
    MACHINE = "b" * 64
    RELEASE = "a" * 64

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.repo = self.home / "SecureSandbox"
        self.repo.mkdir(mode=0o755)
        self.runs = self.repo / "runs"
        self.runs.mkdir(mode=0o700)
        self.operator_uid = os.geteuid()
        if self.operator_uid <= 0:
            self.skipTest("requires an unprivileged test account")
        self.machine = self.MACHINE
        self.release_id = self.RELEASE
        self.ssh_config = b"Host SecureSandbox-*\n  IdentitiesOnly yes\n"
        self._write_sources()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _key(seed: int) -> tuple[str, str]:
        blob = (
            struct.pack("!I", len(b"ssh-ed25519")) + b"ssh-ed25519"
            + struct.pack("!I", 32) + bytes([seed]) * 32
        )
        encoded = base64.b64encode(blob).decode("ascii")
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(blob).digest()
        ).decode("ascii").rstrip("=")
        return encoded, fingerprint

    def _write_sources(self) -> None:
        self.keys = {
            "provisioning_key": self._key(1),
            "control_key": self._key(2),
        }
        for name in ("provisioning_key", "control_key"):
            encoded, _fingerprint = self.keys[name]
            path = self.runs / ("provisioning_key.pub" if name == "provisioning_key"
                                else "control_key.pub")
            path.write_text(
                f"ssh-ed25519 {encoded} fixture {name} identity\n"
            )
            path.chmod(0o600)
        lines = []
        self.host_keys = {}
        for offset, alias in enumerate(AUTH.HOST_SSH_TRUST_ALIASES, start=3):
            encoded, fingerprint = self._key(offset)
            self.host_keys[alias] = (encoded, fingerprint)
            lines.append(f"{alias} ssh-ed25519 {encoded}\n")
        known_hosts = self.runs / "known_hosts"
        known_hosts.write_text("".join(lines))
        known_hosts.chmod(0o600)

    def _source_record(self, name: str) -> dict[str, object]:
        relative = AUTH.HOST_SSH_TRUST_SOURCE_PATHS[name]
        path = self.repo / relative
        raw = path.read_bytes()
        info = path.lstat()
        if name == "known_hosts":
            projected = raw
            extra = {
                "host_fingerprints": {
                    alias: self.host_keys[alias][1]
                    for alias in AUTH.HOST_SSH_TRUST_ALIASES
                }
            }
        else:
            encoded, fingerprint = self.keys[name]
            projected = f"ssh-ed25519 {encoded}\n".encode("ascii")
            extra = {"fingerprint": fingerprint}
        return {
            "relative_path": relative,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "nlink": info.st_nlink,
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "projected_sha256": hashlib.sha256(projected).hexdigest(),
            **extra,
        }

    def plan(self, *, operator_uid: int | None = None) -> dict[str, object]:
        uid = self.operator_uid if operator_uid is None else operator_uid
        sources = {
            name: self._source_record(name)
            for name in AUTH.HOST_SSH_TRUST_SOURCE_PATHS
        }
        material = {
            "schema": "secure-sandbox-host-ssh-trust-material-v1",
            "operator_uid": uid,
            "machine_identity_sha256": self.machine,
            "ssh_config_sha256": hashlib.sha256(self.ssh_config).hexdigest(),
            "provisioning_public_key_sha256": sources[
                "provisioning_key"
            ]["projected_sha256"],
            "provisioning_public_key_fingerprint": sources[
                "provisioning_key"
            ]["fingerprint"],
            "control_public_key_sha256": sources[
                "control_key"
            ]["projected_sha256"],
            "control_public_key_fingerprint": sources[
                "control_key"
            ]["fingerprint"],
            "known_hosts_sha256": sources["known_hosts"]["projected_sha256"],
            "known_host_fingerprints": sources[
                "known_hosts"
            ]["host_fingerprints"],
        }
        value: dict[str, object] = {
            "schema": AUTH.HOST_SSH_TRUST_PLAN_SCHEMA,
            "plan_id": "12345678-1234-4234-8234-123456789abc",
            "created_at": self.NOW,
            "expires_at": self.NOW + 300,
            "operator_uid": uid,
            "machine_identity_sha256": self.machine,
            "host_release_id": self.release_id,
            "ssh_config_sha256": hashlib.sha256(self.ssh_config).hexdigest(),
            "previous_trust_id": None,
            "sources": sources,
            "trust_id": hashlib.sha256(AUTH.canonical(material)).hexdigest(),
        }
        value["plan_sha256"] = hashlib.sha256(
            AUTH.canonical(value)
        ).hexdigest()
        return value

    def test_broker_revalidates_exact_sources_and_prompt(self):
        plan = self.plan()
        with mock.patch.object(
            AUTH, "host_ssh_trust_machine_identity", return_value=self.machine,
        ):
            self.assertEqual(AUTH.validate_host_ssh_trust_plan(
                plan, self.repo, self.operator_uid, now=self.NOW,
            ), plan)
        details = "\n".join(AUTH.operation_details({
            "operation": AUTH.HOST_SSH_TRUST_OPERATION,
            "parameters": {"repo": str(self.repo), "plan": plan},
        }))
        self.assertIn(plan["trust_id"], details)
        self.assertIn(plan["plan_sha256"], details)
        self.assertIn(plan["ssh_config_sha256"], details)
        self.assertIn("Previous trust ID: none", details)
        self.assertIn(self.keys["provisioning_key"][1], details)
        for source in plan["sources"].values():
            self.assertIn(source["source_sha256"], details)
            self.assertIn(source["projected_sha256"], details)
        for _encoded, fingerprint in self.host_keys.values():
            self.assertIn(fingerprint, details)

        key = self.runs / "control_key.pub"
        key.write_bytes(key.read_bytes().replace(
            b"fixture control_key identity", b"changed control identity",
        ))
        key.chmod(0o600)
        with mock.patch.object(
            AUTH, "host_ssh_trust_machine_identity", return_value=self.machine,
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "host_ssh_trust_source_binding_changed",
        ):
            AUTH.validate_host_ssh_trust_plan(
                plan, self.repo, self.operator_uid, now=self.NOW,
            )

    def test_broker_rejects_boolean_source_identity(self):
        plan = self.plan()
        plan["sources"]["control_key"]["nlink"] = True
        unsigned = {
            name: item for name, item in plan.items()
            if name != "plan_sha256"
        }
        plan["plan_sha256"] = hashlib.sha256(
            AUTH.canonical(unsigned)
        ).hexdigest()
        with mock.patch.object(
            AUTH, "host_ssh_trust_machine_identity", return_value=self.machine,
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "host_ssh_trust_source_binding_invalid",
        ):
            AUTH.validate_host_ssh_trust_plan(
                plan, self.repo, self.operator_uid, now=self.NOW,
            )

    def test_all_plan_validators_reject_duplicate_host_fingerprints(self):
        plan = self.plan()
        fingerprints = plan["sources"]["known_hosts"]["host_fingerprints"]
        duplicate = next(iter(fingerprints.values()))
        plan["sources"]["known_hosts"]["host_fingerprints"] = {
            alias: duplicate for alias in AUTH.HOST_SSH_TRUST_ALIASES
        }
        plan["plan_sha256"] = hashlib.sha256(AUTH.canonical({
            name: item for name, item in plan.items()
            if name != "plan_sha256"
        })).hexdigest()
        with self.assertRaisesRegex(
            CLIENT.HostSSHTrustClientError, "host_ssh_trust_plan_invalid",
        ):
            CLIENT.validate_plan(
                plan, operator_uid=self.operator_uid, now=self.NOW,
            )
        with mock.patch.object(
            AUTH, "host_ssh_trust_machine_identity", return_value=self.machine,
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "host_ssh_trust_source_binding_invalid",
        ):
            AUTH.validate_host_ssh_trust_plan(
                plan, self.repo, self.operator_uid, now=self.NOW,
            )

    def test_broker_dispatch_authorization_and_receipt_are_fully_bound(self):
        plan = self.plan()
        release = self.root / self.release_id
        release.mkdir()
        (release / "ssh_config").write_bytes(self.ssh_config)
        request_id = "11111111-1111-4111-8111-111111111111"
        request = {
            "schema": AUTH.SCHEMA,
            "request_id": request_id,
            "created_at": self.NOW,
            "expires_at": self.NOW + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.operator_uid,
            "declared_agent": "Codex",
            "declared_session": "host-ssh-trust-test",
            "identity_evidence": "operator-declared",
            "purpose": "Enroll exact Host SSH trust plan",
            "resource": str(AUTH.HOST_SSH_TRUST_ROOT),
            "operation": AUTH.HOST_SSH_TRUST_OPERATION,
            "parameters": {"repo": str(self.repo), "plan": plan},
            "ceremony": "approve",
        }
        identity = SimpleNamespace(pw_dir=str(self.home))
        request_directory = AUTH.request_directory(self.home)
        with mock.patch.object(AUTH.pwd, "getpwuid", return_value=identity):
            AUTH.secure_user_directory(request_directory, self.operator_uid)
            path = request_directory / f"{request_id}.json"
            AUTH.write_request(path, request)
        request_sha256 = hashlib.sha256(AUTH.canonical(request)).hexdigest()
        receipt_root = self.root / "receipts"
        captured: dict[str, object] = {}

        def execute(command, timeout, input_bytes=None):
            self.assertIsNone(input_bytes)
            self.assertNotIn("sudo", command)
            self.assertNotIn("--json", command)
            self.assertEqual(command[:4], [
                "/usr/bin/python3", "-I", str(release / "release_manager"),
                "enroll-host-ssh-trust",
            ])
            authorization = json.loads(
                command[command.index("--authorization-json") + 1]
            )
            pending = json.loads((receipt_root / f"{request_id}.json").read_bytes())
            self.assertEqual(
                authorization["pending_receipt_sha256"],
                hashlib.sha256(AUTH.canonical(pending)).hexdigest(),
            )
            captured["authorization"] = authorization
            result = {
                "schema": AUTH.HOST_SSH_TRUST_RESULT_SCHEMA,
                "status": "enrolled",
                "trust_id": plan["trust_id"],
                "previous_trust_id": plan["previous_trust_id"],
                "manifest_sha256": "c" * 64,
                "plan_sha256": plan["plan_sha256"],
                "authorization_sha256": authorization[
                    "authorization_sha256"
                ],
                "operator_uid": self.operator_uid,
                "machine_identity_sha256": self.machine,
                "ssh_config_sha256": plan["ssh_config_sha256"],
                "enrolled_release_id": self.release_id,
            }
            return subprocess.CompletedProcess(
                command, 0, AUTH.canonical(result), b"",
            )

        with mock.patch.object(AUTH.pwd, "getpwuid", return_value=identity), \
                mock.patch.object(AUTH.time, "time", return_value=self.NOW), \
                mock.patch.object(
                    AUTH, "host_ssh_trust_machine_identity",
                    return_value=self.machine,
                ), mock.patch.object(
                    AUTH, "protected_release_directory", return_value=release,
                ), mock.patch.object(
                    AUTH, "run_privileged_operation", side_effect=execute,
                ):
            status = AUTH.execute_request(
                self.operator_uid, request_id, request_sha256,
                receipt_root=receipt_root, now=self.NOW,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.operator_uid,
                authorization_method="touch-id", emit_output=False,
            )
        self.assertEqual(status, 0)
        authorization = captured["authorization"]
        self.assertEqual(authorization["method"], "touch-id")
        self.assertFalse(authorization["password_fallback"])
        self.assertEqual(authorization["trust_id"], plan["trust_id"])
        self.assertEqual(authorization["plan_sha256"], plan["plan_sha256"])
        self.assertEqual(authorization["host_release_id"], self.release_id)
        unsigned = {
            name: item for name, item in authorization.items()
            if name != "authorization_sha256"
        }
        self.assertEqual(
            authorization["authorization_sha256"],
            hashlib.sha256(AUTH.canonical(unsigned)).hexdigest(),
        )
        receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_bytes()
        )
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["host_ssh_trust_id"], plan["trust_id"])
        self.assertEqual(
            receipt["host_ssh_trust_plan_sha256"], plan["plan_sha256"]
        )
        self.assertEqual(receipt["host_release_id"], self.release_id)
        self.assertEqual(
            receipt["host_ssh_trust_authorization_sha256"],
            authorization["authorization_sha256"],
        )

    def test_touchid_only_policy_rejects_password_dispatch(self):
        self.assertTrue(AUTH.operation_requires_touchid(
            AUTH.HOST_SSH_TRUST_OPERATION
        ))
        plan = self.plan()
        request_id = "11111111-1111-4111-8111-111111111111"
        request = {
            "schema": AUTH.SCHEMA, "request_id": request_id,
            "created_at": self.NOW,
            "expires_at": self.NOW + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.operator_uid,
            "declared_agent": "Codex", "declared_session": "password-bypass",
            "identity_evidence": "operator-declared", "purpose": "Reject bypass",
            "resource": str(AUTH.HOST_SSH_TRUST_ROOT),
            "operation": AUTH.HOST_SSH_TRUST_OPERATION,
            "parameters": {"repo": str(self.repo), "plan": plan},
            "ceremony": "approve",
        }
        identity = SimpleNamespace(pw_dir=str(self.home))
        directory = AUTH.request_directory(self.home)
        with mock.patch.object(AUTH.pwd, "getpwuid", return_value=identity):
            AUTH.secure_user_directory(directory, self.operator_uid)
            AUTH.write_request(directory / f"{request_id}.json", request)
        request_sha256 = hashlib.sha256(AUTH.canonical(request)).hexdigest()
        with mock.patch.object(AUTH.pwd, "getpwuid", return_value=identity), \
                mock.patch.object(AUTH.time, "time", return_value=self.NOW), \
                mock.patch.object(
                    AUTH, "host_ssh_trust_machine_identity",
                    return_value=self.machine,
                ), self.assertRaisesRegex(
                    AUTH.AuthorizationError, "touchid_required",
                ):
            AUTH.execute_request(
                self.operator_uid, request_id, request_sha256,
                receipt_root=self.root / "bypass-receipts", now=self.NOW,
                expected_root_uid=self.operator_uid,
                authorization_method="administrator-password",
            )

    def test_unprivileged_client_validates_plan_result_and_readback(self):
        plan = self.plan(operator_uid=self.operator_uid)
        result = {
            "schema": CLIENT.RESULT_SCHEMA,
            "status": "enrolled",
            "trust_id": plan["trust_id"],
            "previous_trust_id": None,
            "manifest_sha256": "c" * 64,
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": "d" * 64,
            "operator_uid": self.operator_uid,
            "machine_identity_sha256": self.machine,
            "ssh_config_sha256": plan["ssh_config_sha256"],
            "enrolled_release_id": self.release_id,
        }
        status = {
            "schema": CLIENT.STATUS_SCHEMA,
            "status": "verified",
            "trust_id": plan["trust_id"],
            "manifest_sha256": result["manifest_sha256"],
            "manifest_file_sha256": "e" * 64,
            "operator_uid": self.operator_uid,
            "machine_identity_sha256": self.machine,
            "ssh_config_sha256": plan["ssh_config_sha256"],
            "enrolled_release_id": self.release_id,
            "plan_sha256": plan["plan_sha256"],
        }
        responses = iter((plan, result, status))
        commands: list[list[str]] = []

        def run(command, **_kwargs):
            commands.append(command)
            value = next(responses)
            errors = (
                b"SecureSandbox approval request \xe2\x80\x94 exact\n"
                if len(commands) == 2 else b""
            )
            return subprocess.CompletedProcess(
                command, 0, CLIENT.canonical(value), errors,
            )

        with mock.patch.object(
            CLIENT.os, "getuid", return_value=self.operator_uid,
        ), mock.patch.object(
            CLIENT.os, "geteuid", return_value=self.operator_uid,
        ):
            observed = CLIENT.enroll(
                repo=Path("/fixture/SecureSandbox"),
                operator_uid=self.operator_uid,
                agent="Codex", session="thread-1",
                runner=run, now=self.NOW,
            )
        self.assertEqual(observed, result)
        self.assertEqual(commands[0][1], "plan-host-ssh-trust")
        self.assertEqual(commands[1][1], "request")
        self.assertIn("--ceremony", commands[1])
        self.assertEqual(commands[2][1], "status-host-ssh-trust")
        self.assertFalse(any("sudo" in item for command in commands
                             for item in command))
        parameters = json.loads(
            commands[1][commands[1].index("--parameters-json") + 1]
        )
        self.assertEqual(parameters["plan"], plan)

    def test_fresh_noop_result_preserves_selected_manifest_audit_binding(self):
        plan = self.plan(operator_uid=self.operator_uid)
        plan["previous_trust_id"] = plan["trust_id"]
        plan["plan_sha256"] = hashlib.sha256(AUTH.canonical({
            name: item for name, item in plan.items()
            if name != "plan_sha256"
        })).hexdigest()
        selected_release = "f" * 64
        selected_plan = "e" * 64
        authorization = {"authorization_sha256": "d" * 64}
        result = {
            "schema": CLIENT.RESULT_SCHEMA,
            "status": "already-enrolled",
            "trust_id": plan["trust_id"],
            "previous_trust_id": plan["previous_trust_id"],
            "manifest_sha256": "c" * 64,
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "operator_uid": self.operator_uid,
            "machine_identity_sha256": self.machine,
            "ssh_config_sha256": plan["ssh_config_sha256"],
            "enrolled_release_id": selected_release,
        }
        status = {
            "schema": CLIENT.STATUS_SCHEMA,
            "status": "verified",
            "trust_id": plan["trust_id"],
            "manifest_sha256": result["manifest_sha256"],
            "manifest_file_sha256": "1" * 64,
            "operator_uid": self.operator_uid,
            "machine_identity_sha256": self.machine,
            "ssh_config_sha256": plan["ssh_config_sha256"],
            "enrolled_release_id": selected_release,
            "plan_sha256": selected_plan,
        }
        self.assertEqual(CLIENT.validate_result(result, plan), result)
        self.assertEqual(CLIENT.validate_status(status, result, plan), status)
        self.assertEqual(
            AUTH.validate_host_ssh_trust_result(
                result, plan, authorization,
            ),
            result,
        )
        changed = dict(result, status="enrolled")
        with self.assertRaisesRegex(
            CLIENT.HostSSHTrustClientError, "host_ssh_trust_result_invalid",
        ):
            CLIENT.validate_result(changed, plan)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "host_ssh_trust_result_invalid",
        ):
            AUTH.validate_host_ssh_trust_result(
                changed, plan, authorization,
            )

    def test_documented_environment_attribution_is_accepted(self):
        environment = {
            "SECURE_SANDBOX_REQUESTING_AGENT": "Codex",
            "SECURE_SANDBOX_REQUESTING_SESSION":
                "Disposable-Mac-acceptance",
        }
        with mock.patch.dict(CLIENT.os.environ, environment, clear=False):
            arguments = CLIENT.parser().parse_args([])
        self.assertEqual(arguments.requesting_agent, "Codex")
        self.assertEqual(
            arguments.requesting_session, "Disposable-Mac-acceptance",
        )
        self.assertIsNotNone(CLIENT.SAFE_AGENT.fullmatch(
            arguments.requesting_agent,
        ))
        self.assertIsNotNone(CLIENT.SAFE_SESSION.fullmatch(
            arguments.requesting_session,
        ))

    def test_unprivileged_client_fails_closed_on_readback_mismatch(self):
        plan = self.plan(operator_uid=self.operator_uid)
        result = {
            "schema": CLIENT.RESULT_SCHEMA, "status": "enrolled",
            "trust_id": plan["trust_id"], "previous_trust_id": None,
            "manifest_sha256": "c" * 64,
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": "d" * 64,
            "operator_uid": self.operator_uid,
            "machine_identity_sha256": self.machine,
            "ssh_config_sha256": plan["ssh_config_sha256"],
            "enrolled_release_id": self.release_id,
        }
        status = {
            "schema": CLIENT.STATUS_SCHEMA, "status": "verified",
            "trust_id": "f" * 64,
            "manifest_sha256": result["manifest_sha256"],
            "manifest_file_sha256": "e" * 64,
            "operator_uid": self.operator_uid,
            "machine_identity_sha256": self.machine,
            "ssh_config_sha256": plan["ssh_config_sha256"],
            "enrolled_release_id": self.release_id,
            "plan_sha256": plan["plan_sha256"],
        }
        responses = iter((plan, result, status))

        def run(command, **_kwargs):
            return subprocess.CompletedProcess(
                command, 0, CLIENT.canonical(next(responses)), b"",
            )

        with mock.patch.object(
            CLIENT.os, "getuid", return_value=self.operator_uid,
        ), mock.patch.object(
            CLIENT.os, "geteuid", return_value=self.operator_uid,
        ), \
                self.assertRaisesRegex(
                    CLIENT.HostSSHTrustClientError,
                    "host_ssh_trust_readback_invalid",
                ):
            CLIENT.enroll(
                repo=Path("/fixture/SecureSandbox"),
                operator_uid=self.operator_uid,
                agent="Codex", session="thread-1",
                runner=run, now=self.NOW,
            )


if __name__ == "__main__":
    unittest.main()
