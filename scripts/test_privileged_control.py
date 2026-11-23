import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import struct
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("privileged_control", ROOT / "scripts/privileged_control.py")
assert SPEC and SPEC.loader
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
OPERATION_SPEC = importlib.util.spec_from_file_location(
    "privileged_control_operation", ROOT / "scripts/privileged-control-operation.py"
)
assert OPERATION_SPEC and OPERATION_SPEC.loader
OPERATION = importlib.util.module_from_spec(OPERATION_SPEC)
OPERATION_SPEC.loader.exec_module(OPERATION)


class HostSSHTrustTests(unittest.TestCase):
    MACHINE = "8" * 64

    @staticmethod
    def public_key(seed: int) -> tuple[bytes, str, bytes]:
        algorithm = b"ssh-ed25519"
        key = bytes([seed]) * 32
        blob = (struct.pack(">I", len(algorithm)) + algorithm
                + struct.pack(">I", len(key)) + key)
        encoded = __import__("base64").b64encode(blob).decode("ascii").rstrip("=")
        raw = f"ssh-ed25519 {encoded}\n".encode("ascii")
        fingerprint = "SHA256:" + __import__("base64").b64encode(
            hashlib.sha256(blob).digest(),
        ).decode("ascii").rstrip("=")
        return raw, fingerprint, blob

    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="sst.", dir="/tmp"))
        self.uid = os.geteuid()
        self.config = self.temporary / "release" / "ssh_config"
        self.config.parent.mkdir(mode=0o755)
        self.config.write_bytes((ROOT / "config/ssh_config.example").read_bytes())
        self.config.chmod(0o444)
        self.root = self.temporary / "host-ssh-trust"
        generations = self.root / "generations"
        generations.mkdir(mode=0o755, parents=True)
        self.gid = self.root.lstat().st_gid
        self.provisioning, provisioning_fingerprint, _ = self.public_key(1)
        self.control, control_fingerprint, _ = self.public_key(2)
        host_lines = []
        host_fingerprints = {}
        for alias, seed in zip(CONTROL.HOST_KEY_ALIASES, (3, 4, 5)):
            raw, fingerprint, _blob = self.public_key(seed)
            host_lines.append(f"{alias} {raw.decode('ascii').strip()}")
            host_fingerprints[alias] = fingerprint
        self.known_hosts = ("\n".join(host_lines) + "\n").encode("ascii")
        material = {
            "schema": CONTROL.HOST_SSH_TRUST_MATERIAL_SCHEMA,
            "operator_uid": self.uid,
            "machine_identity_sha256": self.MACHINE,
            "ssh_config_sha256": hashlib.sha256(
                self.config.read_bytes(),
            ).hexdigest(),
            "provisioning_public_key_sha256": hashlib.sha256(
                self.provisioning,
            ).hexdigest(),
            "provisioning_public_key_fingerprint": provisioning_fingerprint,
            "control_public_key_sha256": hashlib.sha256(
                self.control,
            ).hexdigest(),
            "control_public_key_fingerprint": control_fingerprint,
            "known_hosts_sha256": hashlib.sha256(self.known_hosts).hexdigest(),
            "known_host_fingerprints": host_fingerprints,
        }
        self.trust_id = CONTROL.host_ssh_trust_digest(material)
        self.generation = generations / self.trust_id
        self.generation.mkdir(mode=0o755)
        for name, raw in (
            ("provisioning_key.pub", self.provisioning),
            ("control_key.pub", self.control),
            ("known_hosts", self.known_hosts),
        ):
            path = self.generation / name
            path.write_bytes(raw); path.chmod(0o444)
        manifest = {
            "schema": CONTROL.HOST_SSH_TRUST_SCHEMA,
            "trust_id": self.trust_id,
            "operator_uid": self.uid,
            "machine_identity_sha256": self.MACHINE,
            "enrolled_release_id": "7" * 64,
            "ssh_config_sha256": material["ssh_config_sha256"],
            "provisioning_public_key_sha256":
                material["provisioning_public_key_sha256"],
            "provisioning_public_key_fingerprint": provisioning_fingerprint,
            "control_public_key_sha256": material["control_public_key_sha256"],
            "control_public_key_fingerprint": control_fingerprint,
            "known_hosts_sha256": material["known_hosts_sha256"],
            "known_host_fingerprints": host_fingerprints,
            "plan_sha256": "9" * 64,
            "enrolled_at": 2_000_000_000,
        }
        manifest["manifest_sha256"] = CONTROL.host_ssh_trust_digest(manifest)
        self.manifest = manifest
        manifest_path = self.generation / "manifest.json"
        manifest_path.write_bytes(CONTROL.canonical_json(manifest) + b"\n")
        manifest_path.chmod(0o444)
        self.generation.chmod(0o555)
        (self.root / "current").symlink_to(f"generations/{self.trust_id}")
        self.provisioning_socket = self.temporary / "provisioning.sock"
        self.control_socket = self.temporary / "control.sock"
        self.socket_stats = {
            path: SimpleNamespace(
                st_dev=1, st_ino=index, st_mode=stat.S_IFSOCK | 0o600,
                st_uid=self.uid, st_gid=self.gid, st_nlink=1,
                st_mtime_ns=1, st_ctime_ns=1,
            )
            for index, path in enumerate(
                (self.provisioning_socket, self.control_socket), 1,
            )
        }

    def tearDown(self):
        if self.generation.exists():
            self.generation.chmod(0o755)
        shutil.rmtree(self.temporary)

    def agent_runner(self, _command, **kwargs):
        sock = kwargs["env"]["SSH_AUTH_SOCK"]
        raw = (self.provisioning if sock == str(self.provisioning_socket)
               else self.control)
        return subprocess.CompletedProcess(
            ["ssh-add", "-L"], 0, raw.rstrip(b"\n") + b" fixture\n", b"",
        )

    def validate(self, **changes):
        arguments = {
            "expected_ssh_config": self.config,
            "trust_root": self.root,
            "trusted_uid": self.uid,
            "trusted_gid": self.gid,
            "effective_uid": self.uid,
            "machine_identity_reader": lambda: self.MACHINE,
            "agent_runner": self.agent_runner,
            "provisioning_agent_socket": self.provisioning_socket,
            "control_agent_socket": self.control_socket,
            "socket_stat_reader": lambda path: self.socket_stats[path],
        }
        arguments.update(changes)
        return CONTROL.validate_client_ssh_trust(self.config, **arguments)

    def rewrite_manifest(self, update):
        self.generation.chmod(0o755)
        path = self.generation / "manifest.json"
        path.chmod(0o644)
        manifest = dict(self.manifest); update(manifest)
        manifest["manifest_sha256"] = CONTROL.host_ssh_trust_digest({
            key: value for key, value in manifest.items()
            if key != "manifest_sha256"
        })
        path.write_bytes(CONTROL.canonical_json(manifest) + b"\n")
        path.chmod(0o444); self.generation.chmod(0o555)

    def test_complete_projection_allows_enrolled_operator_and_root(self):
        value = self.validate()
        self.assertEqual(value["trust_id"], self.trust_id)
        value = self.validate(effective_uid=0)
        self.assertEqual(value["operator_uid"], self.uid)

    def test_wrong_config_path_rejected_before_agent_access(self):
        called = mock.Mock(side_effect=self.agent_runner)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "host_ssh_config_path_invalid"):
            CONTROL.validate_client_ssh_trust(
                self.config, expected_ssh_config=self.config.with_name("other"),
                agent_runner=called,
            )
        called.assert_not_called()

    def test_user_writable_fallback_config_is_rejected(self):
        self.config.chmod(0o644)
        text = self.config.read_text().replace(
            CONTROL.HOST_SSH_TRUST_CONFIG_PATHS[0],
            "%d/SecureSandbox/runs/provisioning_key.pub",
        )
        self.config.write_text(text); self.config.chmod(0o444)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "host_ssh_config_contract_invalid"):
            self.validate()

    def test_direct_root_incompatible_gateway_proxy_is_rejected(self):
        self.config.chmod(0o644)
        self.config.write_text(self.config.read_text().replace(
            CONTROL.HOST_GATEWAY_PROXY_COMMAND,
            ("/usr/bin/python3 -I /usr/local/libexec/secure-sandbox-host/"
             "current/vm_maintenance proxy-gateway --port %p"),
        ))
        self.config.chmod(0o444)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "host_ssh_config_contract_invalid"):
            self.validate()

    def test_writable_config_and_unexpected_generation_member_are_rejected(self):
        self.config.chmod(0o644)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "host_ssh_config_untrusted"):
            self.validate()
        self.config.chmod(0o444)
        self.generation.chmod(0o755)
        extra = self.generation / "fallback-key.pub"
        extra.write_bytes(self.provisioning); extra.chmod(0o444)
        self.generation.chmod(0o555)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "generation_untrusted"):
            self.validate()

    def test_selector_and_generation_metadata_are_enforced(self):
        self.generation.chmod(0o755)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "generation_untrusted"):
            self.validate()
        self.generation.chmod(0o555)
        selector = self.root / "current"; selector.unlink()
        selector.symlink_to(f"../{self.trust_id}")
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "selector_untrusted"):
            self.validate()

    def test_trust_parent_acl_boundary_is_enforced(self):
        original = CONTROL._trusted_directory

        def inspect(path, *args, **kwargs):
            if Path(path) == self.root.parent:
                raise CONTROL.ControlFailure(
                    "host_ssh_trust_parent_untrusted",
                )
            return original(path, *args, **kwargs)

        with mock.patch.object(
            CONTROL, "_trusted_directory", side_effect=inspect,
        ), self.assertRaisesRegex(
            CONTROL.ControlFailure, "host_ssh_trust_parent_untrusted",
        ):
            self.validate()

    def test_manifest_machine_and_operator_are_enforced(self):
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "machine_changed"):
            self.validate(machine_identity_reader=lambda: "6" * 64)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "operator_mismatch"):
            self.validate(effective_uid=self.uid + 1000)

    def test_key_content_and_known_host_aliases_are_enforced(self):
        self.generation.chmod(0o755)
        path = self.generation / "control_key.pub"; path.chmod(0o644)
        path.write_bytes(self.provisioning); path.chmod(0o444)
        self.generation.chmod(0o555)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "key_separation|content_changed"):
            self.validate()

    def test_agent_must_be_single_exact_identity(self):
        def wrong_agent(_command, **kwargs):
            raw, _fingerprint, _blob = self.public_key(6)
            return subprocess.CompletedProcess(
                ["ssh-add", "-L"], 0, raw, b"",
            )
        with self.assertRaisesRegex(CONTROL.ControlFailure, "agent_invalid"):
            self.validate(agent_runner=wrong_agent)

    def test_noncanonical_manifest_is_rejected(self):
        self.generation.chmod(0o755)
        manifest = self.generation / "manifest.json"; manifest.chmod(0o644)
        manifest.write_bytes(json.dumps(self.manifest, indent=2).encode() + b"\n")
        manifest.chmod(0o444); self.generation.chmod(0o555)
        with self.assertRaisesRegex(CONTROL.ControlFailure, "manifest_invalid"):
            self.validate()

    def test_hardlinked_key_and_wrong_agent_socket_owner_are_rejected(self):
        os.link(
            self.generation / "provisioning_key.pub",
            self.temporary / "unexpected-hardlink",
        )
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "provisioning_key_untrusted"):
            self.validate()
        (self.temporary / "unexpected-hardlink").unlink()
        socket_info = self.socket_stats[self.provisioning_socket]
        self.socket_stats[self.provisioning_socket] = SimpleNamespace(
            **{
                name: getattr(socket_info, name)
                for name in (
                    "st_dev", "st_ino", "st_mode", "st_gid", "st_nlink",
                    "st_mtime_ns", "st_ctime_ns",
                )
            },
            st_uid=self.uid + 1,
        )
        with self.assertRaisesRegex(CONTROL.ControlFailure, "agent_invalid"):
            self.validate()

    def test_trust_digests_include_the_canonical_record_newline(self):
        unsigned = {
            key: value for key, value in self.manifest.items()
            if key != "manifest_sha256"
        }
        expected = hashlib.sha256(
            CONTROL.canonical_json(unsigned) + b"\n",
        ).hexdigest()
        without_newline = hashlib.sha256(
            CONTROL.canonical_json(unsigned),
        ).hexdigest()
        self.assertEqual(CONTROL.host_ssh_trust_digest(unsigned), expected)
        self.assertEqual(self.manifest["manifest_sha256"], expected)
        self.assertNotEqual(expected, without_newline)

    def test_config_declares_only_fixed_projection_paths(self):
        text = (ROOT / "config/ssh_config.example").read_text()
        self.assertNotIn("%d/SecureSandbox", text)
        self.assertEqual(text.count(CONTROL.HOST_SSH_TRUST_CONFIG_PATHS[0]), 4)
        self.assertEqual(text.count(CONTROL.HOST_SSH_TRUST_CONFIG_PATHS[1]), 3)
        self.assertEqual(text.count(CONTROL.HOST_SSH_TRUST_CONFIG_PATHS[2]), 7)
        self.assertEqual(text.count("StrictHostKeyChecking yes"), 7)
        self.assertEqual(text.count("IdentitiesOnly yes"), 7)
        self.assertEqual(
            text.count(f"ProxyCommand {CONTROL.HOST_GATEWAY_PROXY_COMMAND}"),
            2,
        )
        self.assertNotIn("current/vm_maintenance proxy-gateway", text)


class ClientSSHIdentityTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("operator identity fixture requires a non-root owner")
        self.temporary = Path(tempfile.mkdtemp(
            prefix="ssop.", dir="/private/tmp",
        ))
        self.home = self.temporary / "operator-home"
        self.bundle = (
            self.home / CONTROL.HOST_OPERATOR_REPOSITORY_NAME
            / CONTROL.HOST_GATEWAY_BUNDLE_RELATIVE
        )
        self.bundle.mkdir(mode=0o700, parents=True)
        (self.home / CONTROL.HOST_OPERATOR_REPOSITORY_NAME).chmod(0o755)
        (self.home / CONTROL.HOST_OPERATOR_REPOSITORY_NAME / "vms").chmod(
            0o700,
        )
        self.home.chmod(0o750)
        self.uid = os.geteuid()
        self.gid = os.getgid()
        for path in (
            self.home,
            self.home / CONTROL.HOST_OPERATOR_REPOSITORY_NAME,
            self.home / CONTROL.HOST_OPERATOR_REPOSITORY_NAME / "vms",
            self.bundle,
        ):
            os.chown(path, -1, self.gid)
        self.account = SimpleNamespace(
            pw_uid=self.uid, pw_gid=self.gid, pw_name="fixtureoperator",
            pw_dir=str(self.home),
        )
        self.manifest = {"operator_uid": self.uid}
        self.provisioning_socket = self.temporary / "provisioning.sock"
        self.socket_stats = {
            self.provisioning_socket: SimpleNamespace(
                st_dev=1, st_ino=1, st_mode=stat.S_IFSOCK | 0o600,
                st_uid=self.uid, st_gid=self.gid, st_nlink=1,
                st_mtime_ns=1, st_ctime_ns=1,
            ),
        }

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def expected_process_options(self):
        return {
            "user": self.uid,
            "group": self.gid,
            "extra_groups": [],
            "cwd": str(self.home),
            "env": {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(self.home),
                "USER": "fixtureoperator",
                "LOGNAME": "fixtureoperator",
                "LANG": "C",
                "LC_ALL": "C",
            },
        }

    def root_options(self):
        return CONTROL.client_ssh_process_options(
            self.manifest, effective_uid=0,
            account_reader=lambda _uid: self.account,
        )

    def arguments(self, command="run"):
        return SimpleNamespace(
            request_id="11111111-1111-4111-8111-111111111111",
            command=command, arguments=[], name="control-status",
            ssh_config="/trusted/config", host="sandbox-gateway-control",
            timeout_seconds=2, stdin_file=None, files=[],
        )

    def test_root_options_validate_account_repo_and_gateway_bundle(self):
        self.assertEqual(self.root_options(), self.expected_process_options())
        self.assertEqual(
            CONTROL.client_ssh_process_options(
                self.manifest, effective_uid=self.uid,
                account_reader=lambda _uid: self.account,
            ),
            {},
        )
        self.bundle.chmod(0o770)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "gateway_bundle_untrusted"):
            self.root_options()

    def test_root_options_reject_writable_or_acl_granted_path_component(self):
        vms = self.bundle.parent
        vms.chmod(0o770)
        with self.assertRaisesRegex(
                CONTROL.ControlFailure, "repository_untrusted"):
            self.root_options()
        vms.chmod(0o700)
        with mock.patch.object(
                CONTROL, "_reject_extended_acl",
                side_effect=CONTROL.ControlFailure(
                    "host_ssh_operator_repository_untrusted",
                )):
            with self.assertRaisesRegex(
                    CONTROL.ControlFailure, "repository_untrusted"):
                self.root_options()

    def test_root_options_admit_only_deny_acl_on_operator_home(self):
        with (mock.patch.object(
                  CONTROL, "_reject_allowing_acl",
              ) as home_acl, mock.patch.object(
                  CONTROL, "_reject_extended_acl",
              ) as strict_acl):
            self.root_options()
        home_acl.assert_called_once()
        self.assertEqual(strict_acl.call_count, 3)
        with mock.patch.object(
                CONTROL, "_reject_allowing_acl",
                side_effect=CONTROL.ControlFailure(
                    "host_ssh_operator_home_untrusted",
                )):
            with self.assertRaisesRegex(
                    CONTROL.ControlFailure, "home_untrusted"):
                self.root_options()

    def test_root_agent_query_drops_to_enrolled_operator(self):
        raw, fingerprint, blob = HostSSHTrustTests.public_key(7)
        socket_path = self.provisioning_socket
        observed = {}

        def runner(_command, **kwargs):
            observed.update(kwargs)
            return subprocess.CompletedProcess(
                ["ssh-add", "-L"], 0,
                raw.rstrip(b"\n") + b" fixture\n", b"",
            )

        with (mock.patch.object(CONTROL.os, "geteuid", return_value=0),
              mock.patch.object(
                  CONTROL.pwd, "getpwuid", return_value=self.account,
              )):
            CONTROL._agent_identity(
                socket_path, self.uid, blob, fingerprint, runner,
                lambda path: self.socket_stats[path],
            )
        self.assertEqual(observed["user"], self.uid)
        self.assertEqual(observed["group"], self.gid)
        self.assertEqual(observed["extra_groups"], [])

    def test_root_direct_ssh_proxy_runs_resolver_as_enrolled_operator(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess(
            ["vm_maintenance", "proxy-gateway"], 0, b"", b"",
        ))
        with (mock.patch.object(
                  CONTROL, "validate_client_ssh_trust",
                  return_value=self.manifest,
              ) as trust, mock.patch.object(
                  CONTROL.os, "geteuid", return_value=0,
              ), mock.patch.object(
                  CONTROL.pwd, "getpwuid", return_value=self.account,
              )):
            status = CONTROL.proxy_gateway_main(
                SimpleNamespace(port="22"), runner=runner,
            )
        self.assertEqual(status, 0)
        trust.assert_called_once_with(CONTROL.HOST_SSH_CONFIG)
        command = runner.call_args.args[0]
        self.assertEqual(command, [
            "/usr/bin/python3", "-I", str(CONTROL.HOST_VM_MAINTENANCE),
            "proxy-gateway", "--port", "22",
        ])
        self.assertFalse(runner.call_args.kwargs["check"])
        for name, value in self.expected_process_options().items():
            self.assertEqual(runner.call_args.kwargs[name], value)

    def test_operator_direct_ssh_proxy_preserves_operator_identity(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess(
            ["vm_maintenance", "proxy-gateway"], 19, b"", b"",
        ))
        with (mock.patch.object(
                  CONTROL, "validate_client_ssh_trust",
                  return_value=self.manifest,
              ), mock.patch.object(
                  CONTROL.os, "geteuid", return_value=self.uid,
              ), mock.patch.object(
                  CONTROL.pwd, "getpwuid", return_value=self.account,
              )):
            status = CONTROL.proxy_gateway_main(
                SimpleNamespace(port="22"), runner=runner,
            )
        self.assertEqual(status, 19)
        self.assertEqual(runner.call_args.kwargs, {"check": False})

    def test_proxy_rejects_noncanonical_port_before_trust_access(self):
        for port in (22, "022", "+22", "23", "22;id", ""):
            with (self.subTest(port=port), mock.patch.object(
                      CONTROL, "validate_client_ssh_trust",
                  ) as trust, self.assertRaisesRegex(
                      CONTROL.ControlFailure, "gateway_proxy_port_invalid",
                  )):
                CONTROL.proxy_gateway_main(
                    SimpleNamespace(port=port), runner=mock.Mock(),
                )
            trust.assert_not_called()

    def test_invalid_trust_prevents_every_ssh_spawn(self):
        failure = CONTROL.ControlFailure("host_ssh_trust_manifest_invalid")
        with (mock.patch.object(
                  CONTROL, "validate_client_ssh_trust", side_effect=failure,
              ), mock.patch.object(
                  CONTROL, "client_ssh_process_options",
              ) as process_options, mock.patch.object(
                  CONTROL.subprocess, "Popen",
              ) as popen, self.assertRaisesRegex(
                  CONTROL.ControlFailure, "host_ssh_trust_manifest_invalid",
              )):
            CONTROL.client_main(self.arguments())
        process_options.assert_not_called()
        popen.assert_not_called()

    def test_root_ordinary_client_drops_every_ssh_process_to_operator(self):
        class Sink:
            def __init__(self):
                self.closed = False

            def write(self, data):
                return len(data)

            def close(self):
                self.closed = True

        process = SimpleNamespace(
            pid=12345, stdin=Sink(), returncode=0,
            wait=lambda timeout=None: 0, poll=lambda: 0,
        )
        with (mock.patch.object(
                  CONTROL, "validate_client_ssh_trust",
                  return_value=self.manifest,
              ), mock.patch.object(CONTROL.os, "geteuid", return_value=0),
              mock.patch.object(
                  CONTROL.pwd, "getpwuid", return_value=self.account,
              ), mock.patch.object(
                  CONTROL.subprocess, "Popen", return_value=process,
              ) as popen, mock.patch.object(
                  CONTROL, "process_group_exists", return_value=False,
              )):
            self.assertEqual(CONTROL.client_main(self.arguments()), 0)
        kwargs = popen.call_args.kwargs
        for name, value in self.expected_process_options().items():
            self.assertEqual(kwargs[name], value)

    def test_root_stream_client_drops_every_ssh_process_to_operator(self):
        real_popen = subprocess.Popen
        observed = {}

        def launch(_command, **kwargs):
            observed.update(kwargs)
            return real_popen(
                [sys.executable, "-c", "import os;os.write(1,b'SSSTRM1\\n')"],
                stdin=kwargs["stdin"], stdout=kwargs["stdout"],
                start_new_session=kwargs["start_new_session"],
                bufsize=kwargs.get("bufsize", -1),
            )

        with (open(os.devnull, "rb", buffering=0) as stdin,
              tempfile.TemporaryFile("w+b", buffering=0) as stdout,
              mock.patch.object(
                  CONTROL, "validate_client_ssh_trust",
                  return_value=self.manifest,
              ), mock.patch.object(CONTROL.os, "geteuid", return_value=0),
              mock.patch.object(
                  CONTROL.pwd, "getpwuid", return_value=self.account,
              ), mock.patch.object(
                  CONTROL.subprocess, "Popen", side_effect=launch,
              ), mock.patch.object(CONTROL.sys, "stdin", stdin),
              mock.patch.object(CONTROL.sys, "stdout", stdout)):
            self.assertEqual(CONTROL.client_main(self.arguments("stream")), 0)
        for name, value in self.expected_process_options().items():
            self.assertEqual(observed[name], value)


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.trust_validator = mock.patch.object(
            CONTROL, "validate_client_ssh_trust",
        )
        self.trust_validator_mock = self.trust_validator.start()
        self.trust_validator_mock.return_value = {
            "operator_uid": max(1, os.geteuid()),
        }
        self.process_options = mock.patch.object(
            CONTROL, "client_ssh_process_options", return_value={},
        )
        self.process_options.start()

    def tearDown(self):
        self.process_options.stop()
        self.trust_validator.stop()

    @staticmethod
    def _stream_arguments(timeout_seconds=2):
        return SimpleNamespace(
            request_id="11111111-1111-4111-8111-111111111111",
            command="stream", arguments=["fixed"], name="native-test-stream",
            ssh_config="/trusted/config", host="sandbox-research-control",
            timeout_seconds=timeout_seconds,
        )

    def _run_stream_child(self, source, stdout, *, timeout_seconds=2):
        real_popen = subprocess.Popen
        launched = []
        observed = {}

        def launch(_command, **kwargs):
            observed.update(kwargs)
            process = real_popen(
                [sys.executable, "-c", source],
                stdin=kwargs["stdin"], stdout=kwargs["stdout"],
                start_new_session=kwargs["start_new_session"],
                bufsize=kwargs.get("bufsize", -1),
            )
            launched.append(process)
            return process

        with open(os.devnull, "rb", buffering=0) as stdin, \
                mock.patch.object(CONTROL.subprocess, "Popen", side_effect=launch), \
                mock.patch.object(CONTROL.sys, "stdin", stdin), \
                mock.patch.object(CONTROL.sys, "stdout", stdout):
            try:
                result = CONTROL.stream_client_main(
                    self._stream_arguments(timeout_seconds),
                    "11111111-1111-4111-8111-111111111111",
                )
                return result, launched, observed
            except BaseException as error:
                error._stream_children = launched  # type: ignore[attr-defined]
                error._stream_observed = observed  # type: ignore[attr-defined]
                raise

    def test_stream_invalid_ready_terminates_and_reaps_ssh(self):
        with tempfile.TemporaryFile("w+b", buffering=0) as output:
            with self.assertRaisesRegex(
                CONTROL.ControlFailure, "client_stream_handshake_invalid"
            ) as raised:
                self._run_stream_child(
                    "import os,time; os.write(1,b'BADREADY'); time.sleep(30)",
                    output,
                )
        children = raised.exception._stream_children  # type: ignore[attr-defined]
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertEqual(
            raised.exception._stream_observed["bufsize"], 0  # type: ignore[attr-defined]
        )

    def test_stream_downstream_epipe_terminates_and_reaps_ssh(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        output = os.fdopen(write_fd, "wb", buffering=0)
        try:
            with self.assertRaises(BrokenPipeError) as raised:
                self._run_stream_child(
                    "import os,time; os.write(1,b'SSSTRM1\\nPAYLOAD'); time.sleep(30)",
                    output,
                )
        finally:
            output.close()
        children = raised.exception._stream_children  # type: ignore[attr-defined]
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())

    def test_stream_coalesced_ready_and_payload_forwards_every_byte(self):
        with tempfile.TemporaryFile("w+b", buffering=0) as output:
            status, children, _observed = self._run_stream_child(
                "import os; os.write(1,b'SSSTRM1\\nPAYLOAD')", output
            )
            output.seek(0)
            self.assertEqual(output.read(), b"PAYLOAD")
        self.assertEqual(status, 0)
        self.assertIsNotNone(children[0].poll())

    def test_stream_no_ready_times_out_and_reaps_ssh(self):
        with tempfile.TemporaryFile("w+b", buffering=0) as output:
            status, children, _observed = self._run_stream_child(
                "import time; time.sleep(30)", output, timeout_seconds=0.2
            )
        self.assertEqual(status, 124)
        self.assertIsNotNone(children[0].poll())

    def test_stream_partial_ready_times_out_and_reaps_ssh(self):
        with tempfile.TemporaryFile("w+b", buffering=0) as output:
            status, children, _observed = self._run_stream_child(
                "import os,time; os.write(1,b'SSST'); time.sleep(30)",
                output, timeout_seconds=0.2,
            )
        self.assertEqual(status, 124)
        self.assertIsNotNone(children[0].poll())

    def test_standalone_stream_sigterm_reaps_owned_ssh_group(self):
        real_popen = subprocess.Popen
        launched = []
        child_started = threading.Event()

        def launch(_command, **kwargs):
            process = real_popen(
                [sys.executable, "-c",
                 "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)"],
                stdin=kwargs["stdin"], stdout=kwargs["stdout"],
                start_new_session=kwargs["start_new_session"],
                bufsize=kwargs.get("bufsize", -1),
            )
            launched.append(process)
            child_started.set()
            return process

        def interrupt():
            self.assertTrue(child_started.wait(2))
            time.sleep(0.2)
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.05)
            os.kill(os.getpid(), signal.SIGTERM)

        sender = threading.Thread(target=interrupt)
        sender.start()
        with open(os.devnull, "rb", buffering=0) as stdin, \
                tempfile.TemporaryFile("w+b", buffering=0) as stdout, \
                mock.patch.object(CONTROL.subprocess, "Popen", side_effect=launch), \
                mock.patch.object(CONTROL.sys, "stdin", stdin), \
                mock.patch.object(CONTROL.sys, "stdout", stdout), \
                self.assertRaisesRegex(CONTROL.ControlFailure, "client_interrupted"):
            CONTROL.stream_client_main(
                self._stream_arguments(5),
                "11111111-1111-4111-8111-111111111111",
            )
        sender.join(timeout=2)
        self.assertFalse(sender.is_alive())
        self.assertEqual(len(launched), 1)
        self.assertIsNotNone(launched[0].poll())

    def test_nonstream_sigterm_after_writer_start_reaps_owned_ssh_group(self):
        real_popen = subprocess.Popen
        real_start = CONTROL.threading.Thread.start
        launched = []

        def launch(_command, **kwargs):
            process = real_popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=kwargs["stdin"],
                start_new_session=kwargs["start_new_session"],
            )
            launched.append(process)
            return process

        def start_and_interrupt(thread):
            real_start(thread)
            # This is the former post-writer-start, pre-cleanup-owner window.
            os.kill(os.getpid(), signal.SIGTERM)

        arguments = SimpleNamespace(
            request_id="11111111-1111-4111-8111-111111111111",
            command="run", arguments=[], name="control-status",
            ssh_config="/trusted/config", host="sandbox-research-control",
            timeout_seconds=5, stdin_file=None, files=[],
        )
        try:
            with mock.patch.object(
                CONTROL.subprocess, "Popen", side_effect=launch,
            ), mock.patch.object(
                CONTROL.threading.Thread, "start", new=start_and_interrupt,
            ), self.assertRaisesRegex(
                CONTROL.ControlFailure, "client_interrupted"
            ):
                CONTROL.client_main(arguments)
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())
            self.assertFalse(CONTROL.process_group_exists(launched[0].pid))
        finally:
            for process in launched:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=2)

    def test_nonstream_sigterm_before_popen_return_reaps_owned_ssh_group(self):
        real_popen = subprocess.Popen
        launched = []

        def launch(_command, **kwargs):
            process = real_popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=kwargs["stdin"],
                start_new_session=kwargs["start_new_session"],
            )
            launched.append(process)
            # The child exists, but the patched Popen has not returned to the
            # caller's ownership assignment yet.
            os.kill(os.getpid(), signal.SIGTERM)
            return process

        arguments = SimpleNamespace(
            request_id="11111111-1111-4111-8111-111111111111",
            command="run", arguments=[], name="control-status",
            ssh_config="/trusted/config", host="sandbox-research-control",
            timeout_seconds=5, stdin_file=None, files=[],
        )
        try:
            with mock.patch.object(
                CONTROL.subprocess, "Popen", side_effect=launch,
            ), self.assertRaisesRegex(
                CONTROL.ControlFailure, "client_interrupted"
            ):
                CONTROL.client_main(arguments)
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())
            self.assertFalse(CONTROL.process_group_exists(launched[0].pid))
        finally:
            for process in launched:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=2)

    def test_stream_sigterm_before_popen_return_reaps_owned_ssh_group(self):
        real_popen = subprocess.Popen
        launched = []

        def launch(_command, **kwargs):
            process = real_popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=kwargs["stdin"], stdout=kwargs["stdout"],
                start_new_session=kwargs["start_new_session"],
                bufsize=kwargs.get("bufsize", -1),
            )
            launched.append(process)
            os.kill(os.getpid(), signal.SIGTERM)
            return process

        try:
            with open(os.devnull, "rb", buffering=0) as stdin, \
                    tempfile.TemporaryFile("w+b", buffering=0) as stdout, \
                    mock.patch.object(
                        CONTROL.subprocess, "Popen", side_effect=launch,
                    ), mock.patch.object(CONTROL.sys, "stdin", stdin), \
                    mock.patch.object(CONTROL.sys, "stdout", stdout), \
                    self.assertRaisesRegex(
                        CONTROL.ControlFailure, "client_interrupted"
                    ):
                CONTROL.stream_client_main(
                    self._stream_arguments(5),
                    "11111111-1111-4111-8111-111111111111",
                )
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())
            self.assertFalse(CONTROL.process_group_exists(launched[0].pid))
        finally:
            for process in launched:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=2)

    def test_nonstream_writer_start_failure_preserves_error_and_reaps_child(self):
        real_popen = subprocess.Popen
        launched = []

        def launch(_command, **kwargs):
            process = real_popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=kwargs["stdin"],
                start_new_session=kwargs["start_new_session"],
            )
            launched.append(process)
            return process

        arguments = SimpleNamespace(
            request_id="11111111-1111-4111-8111-111111111111",
            command="run", arguments=[], name="control-status",
            ssh_config="/trusted/config", host="sandbox-research-control",
            timeout_seconds=5, stdin_file=None, files=[],
        )
        try:
            with mock.patch.object(
                CONTROL.subprocess, "Popen", side_effect=launch,
            ), mock.patch.object(
                CONTROL.threading.Thread, "start",
                side_effect=RuntimeError("writer_start_failed"),
            ), self.assertRaisesRegex(RuntimeError, "writer_start_failed"):
                CONTROL.client_main(arguments)
            self.assertEqual(len(launched), 1)
            self.assertIsNotNone(launched[0].poll())
            self.assertFalse(CONTROL.process_group_exists(launched[0].pid))
        finally:
            for process in launched:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=2)

    def test_memory_proposal_metadata_preserves_origin_and_checks_digest(self):
        proposal_id = "11111111-1111-4111-8111-111111111111"
        request = {"category": "project_context", "title": "Review this",
                   "proposal": "Untrusted text", "rationale": "Untrusted reason",
                   "evidence_refs": []}
        digest = hashlib.sha256(json.dumps(request, separators=(",", ":"),
                                           sort_keys=True).encode()).hexdigest()
        record = {**request, "schema": "secure-sandbox-memory-proposal-v1",
                  "proposal_id": proposal_id,
                  "run_id": "22222222-2222-4222-8222-222222222222",
                  "created_at": "2026-10-29T00:00:00Z", "content_sha256": digest,
                  "authority": "untrusted_proposal", "status": "pending_operator_review"}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / f"{proposal_id}.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            selected = CONTROL.memory_proposal_metadata(path, os.getuid())
            self.assertEqual(selected["run_id"], record["run_id"])
            self.assertEqual(selected["content_sha256"], digest)
            self.assertNotIn("proposal", selected)
            for changed in ({**record, "run_id": "other"},
                            {**record, "proposal": "changed"},
                            {**record, "authority": "operator_adjudication"}):
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(CONTROL.ControlFailure, "untrusted"):
                    CONTROL.memory_proposal_metadata(path, os.getuid())

    def test_poweroff_is_exact_and_role_bound(self):
        command, validator, roles = CONTROL.OPERATIONS["poweroff"]
        self.assertEqual(command, ["/usr/bin/systemctl", "poweroff"])
        self.assertTrue(validator([]))
        self.assertFalse(validator(["now"]))
        self.assertEqual(roles, {"gateway", "research", "target"})

    def test_index_status_operations_are_read_only_exact_dispatches(self):
        source_id = "11111111-1111-4111-8111-111111111111"
        for kind in ("corpus", "codegraph"):
            command, validator, roles = CONTROL.OPERATIONS[f"{kind}-index-status"]
            self.assertEqual(command[-1], "status")
            self.assertTrue(validator([source_id]))
            self.assertFalse(validator([source_id, "extra"]))
            self.assertEqual(roles, {"research"})

    def test_session_policy_runtime_is_read_only_and_source_bounded(self):
        source_id = "11111111-1111-4111-8111-111111111111"
        command, validator, roles = CONTROL.OPERATIONS["session-policy-runtime"]
        self.assertEqual(
            command,
            ["/usr/local/libexec/secure-sandbox/session_policy_runtime.py"],
        )
        self.assertTrue(validator(["none"]))
        self.assertTrue(validator([source_id]))
        self.assertFalse(validator([]))
        self.assertFalse(validator(["none", source_id]))
        self.assertFalse(validator(["../source"]))
        self.assertEqual(roles, {"research"})

    def test_v3_lease_issue_is_content_bound_and_has_no_argv_bypass(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        command, validator, roles = CONTROL.PIPE_OPERATIONS["lease-issue-v3"]
        self.assertEqual(
            command,
            ["/usr/local/libexec/secure-sandbox/run_lease.py", "issue-v3"],
        )
        self.assertTrue(validator([run_id, "standard"]))
        self.assertFalse(validator([run_id, "standard", "extra"]))
        self.assertFalse(validator(["run-1", "standard"]))
        self.assertEqual(roles, {"gateway"})
        self.assertNotIn("lease-issue", CONTROL.OPERATIONS)

    def test_harness_lifecycle_consumer_operations_are_exact_and_research_only(self):
        sha = "a" * 64
        run_cases = {
            "harness-lifecycle-prepare-rollback": ([sha], [sha, sha]),
            "harness-lifecycle-plan-management": (["retire", sha, sha, "0"],
                                                   ["delete", sha, sha, "0"]),
            "harness-lifecycle-recovery-status": ([], [sha]),
            "harness-lifecycle-recover": ([sha], []),
        }
        for name, (valid, invalid) in run_cases.items():
            command, validator, roles = CONTROL.OPERATIONS[name]
            self.assertEqual(command[0], "/usr/local/libexec/secure-sandbox/harness-generation-manager.py")
            self.assertTrue(validator(valid), name)
            self.assertFalse(validator(invalid), name)
            self.assertEqual(roles, {"research"})
        self.assertFalse(CONTROL.OPERATIONS["harness-lifecycle-plan-management"][1](
            ["retire", sha, sha, "10001"]
        ))
        for name in ("harness-lifecycle-stage-activate", "harness-lifecycle-apply"):
            command, validator, roles = CONTROL.PIPE_OPERATIONS[name]
            self.assertEqual(command[0], "/usr/local/libexec/secure-sandbox/harness-generation-manager.py")
            self.assertTrue(validator([])); self.assertFalse(validator([sha]))
            self.assertEqual(roles, {"research"})

    def test_native_rotation_operations_are_pipe_only_and_role_fixed(self):
        expected = {
            "native-harness-stop": ("research", "stop-research-native-harness", {"research"}),
            "native-tunnel-stop": ("gateway", "stop-gateway-native-tunnel", {"gateway"}),
            "native-egress-deny-only": ("installed", "deny-only", {"gateway", "research"}),
            "native-egress-conntrack-delete": ("installed", "conntrack-delete", {"gateway", "research"}),
            "native-egress-apply": ("installed", "successor-policy", {"gateway", "research"}),
            "native-tunnel-start": ("gateway", "start-gateway-native-tunnel", {"gateway"}),
            "native-harness-start": ("research", "start-research-native-harness", {"research"}),
            "native-runs-stop": ("research", "stop-bound-runs", {"research"}),
        }
        for name, (role, step, roles) in expected.items():
            command, validator, actual_roles = CONTROL.PIPE_OPERATIONS[name]
            self.assertEqual(command, [
                "/usr/local/libexec/secure-sandbox/native_guest_control.py",
                role,
                step,
            ])
            self.assertTrue(validator([]), name)
            self.assertFalse(validator(["unexpected"]), name)
            self.assertEqual(actual_roles, roles)
            self.assertNotIn(name, CONTROL.OPERATIONS)

    def test_native_provider_operations_are_exact_research_pipe_dispatches(self):
        for operation in (
            "native-stack-status",
            "native-stack-inspect-status",
            "native-provider-action",
            "native-qualification-authority",
            "native-session-authority",
            "native-session-plan-authority",
            "native-stack-lifecycle-idle",
            "native-stack-catalog-publish",
            "native-stack-catalog-readback",
            "native-stack-lifecycle-release",
            "native-deployment-lifecycle-acquire",
            "native-deployment-lifecycle-recovery-acquire",
            "native-deployment-lifecycle-release",
            "native-program-attestation",
            "native-claude-login-compact",
            "native-projection-isolation-status",
        ):
            command, validator, roles = CONTROL.PIPE_OPERATIONS[operation]
            self.assertEqual(command, [
                "/usr/local/libexec/secure-sandbox/native_provider_controller.py",
                operation,
            ])
            self.assertTrue(validator([]), operation)
            self.assertFalse(validator(["unexpected"]), operation)
            self.assertEqual(roles, {"research"})
            self.assertNotIn(operation, CONTROL.OPERATIONS)
        self.assertNotIn("native-codex-launch", CONTROL.PIPE_OPERATIONS)

        for operation, verb in (
            ("native-codex-session-prepare", "prepare"),
            ("native-codex-session-stop", "stop"),
            ("native-codex-session-status", "status"),
        ):
            command, validator, roles = CONTROL.PIPE_OPERATIONS[operation]
            self.assertEqual(command, [
                "/usr/local/libexec/secure-sandbox/native_codex_session_controller.py",
                verb,
            ])
            self.assertTrue(validator([]))
            self.assertFalse(validator(["unexpected"]))
            self.assertEqual(roles, {"research"})

        for operation, verb in (
            ("native-claude-session-prepare", "prepare"),
            ("native-claude-session-stop", "stop"),
            ("native-claude-session-status", "status"),
        ):
            command, validator, roles = CONTROL.PIPE_OPERATIONS[operation]
            self.assertEqual(command, [
                "/usr/local/libexec/secure-sandbox/native_claude_session_controller.py",
                verb,
            ])
            self.assertTrue(validator([]))
            self.assertFalse(validator(["unexpected"]))
            self.assertEqual(roles, {"research"})

    def test_native_claude_login_is_a_separate_exact_no_capture_stream(self):
        command, validator, roles = CONTROL.STREAM_OPERATIONS[
            "native-claude-login"
        ]
        arguments = [
            "11111111-1111-4111-8111-111111111111",
            "1" * 64, "2" * 64, "3" * 64, "4" * 64,
        ]
        self.assertEqual(command, [
            "/usr/local/libexec/secure-sandbox/native_claude_login_channel.py"
        ])
        self.assertTrue(validator(arguments))
        self.assertFalse(validator(arguments + ["extra"]))
        self.assertEqual(roles, {"research"})
        self.assertNotIn("native-claude-login", CONTROL.PIPE_OPERATIONS)
        self.assertNotIn("native-claude-login", CONTROL.OPERATIONS)

    def test_native_codex_launch_is_a_separate_exact_token_pipe_stream(self):
        command, validator, roles = CONTROL.STREAM_OPERATIONS[
            "native-codex-launch"]
        arguments = [
            "11111111-1111-4111-8111-111111111111", "1" * 64,
        ]
        self.assertEqual(command, [
            "/usr/local/libexec/secure-sandbox/native_codex_session_controller.py",
            "launch",
        ])
        self.assertTrue(validator(arguments))
        self.assertFalse(validator(arguments + ["extra"]))
        self.assertEqual(roles, {"research"})
        self.assertNotIn("native-codex-launch", CONTROL.PIPE_OPERATIONS)
        self.assertNotIn("native-codex-launch", CONTROL.OPERATIONS)

    def test_native_codex_ui_is_a_distinct_exact_sanitized_stream(self):
        command, validator, roles = CONTROL.STREAM_OPERATIONS[
            "native-codex-ui"]
        arguments = [
            "11111111-1111-4111-8111-111111111111",
            "1" * 64, "2" * 64, "3" * 64, "4" * 64,
            "2000000000",
        ]
        self.assertEqual(command, [
            "/usr/local/libexec/secure-sandbox/native_codex_session_controller.py",
            "ui",
        ])
        self.assertTrue(validator(arguments))
        self.assertFalse(validator(arguments[:-1]))
        self.assertFalse(validator(arguments + ["extra"]))
        self.assertEqual(roles, {"research"})
        self.assertNotIn("native-codex-ui", CONTROL.PIPE_OPERATIONS)
        self.assertNotIn("native-codex-ui", CONTROL.OPERATIONS)

    def test_native_claude_launch_is_a_separate_exact_no_capture_stream(self):
        command, validator, roles = CONTROL.STREAM_OPERATIONS[
            "native-claude-launch"]
        arguments = [
            "11111111-1111-4111-8111-111111111111", "1" * 64,
        ]
        self.assertEqual(command, [
            "/usr/local/libexec/secure-sandbox/native_claude_session_controller.py",
            "launch",
        ])
        self.assertTrue(validator(arguments))
        self.assertFalse(validator(arguments + ["extra"]))
        self.assertEqual(roles, {"research"})
        self.assertNotIn("native-claude-launch", CONTROL.PIPE_OPERATIONS)
        self.assertNotIn("native-claude-launch", CONTROL.OPERATIONS)

    def test_round_trip_and_trailing_input_rejected(self):
        stream = io.BytesIO()
        CONTROL.write_request(stream, {"kind": "run", "operation": "pki-verify", "args": []})
        request, payload = CONTROL.read_request(io.BytesIO(stream.getvalue()))
        self.assertEqual(request["operation"], "pki-verify")
        self.assertEqual(payload, b"")
        with self.assertRaisesRegex(CONTROL.ControlFailure, "trailing_input"):
            CONTROL.read_request(io.BytesIO(stream.getvalue() + b"x"))

    def test_oversized_and_truncated_requests_fail_closed(self):
        with self.assertRaisesRegex(CONTROL.ControlFailure, "header_size_invalid"):
            CONTROL.read_request(io.BytesIO(struct.pack(">I", CONTROL.MAX_HEADER + 1)))
        with self.assertRaisesRegex(CONTROL.ControlFailure, "request_truncated"):
            CONTROL.read_request(io.BytesIO(struct.pack(">I", 8) + b"{}"))

    def test_client_deadline_kills_ssh_process_group_and_reports_ambiguity_id(self):
        request_id = "11111111-1111-4111-8111-111111111111"

        class Sink:
            def __init__(self):
                self.data = bytearray()
                self.closed = False

            def write(self, data):
                self.data.extend(data)
                return len(data)

            def close(self):
                self.closed = True

        class HungProcess:
            pid = 12345
            returncode = None
            stdin = Sink()
            wait_calls = 0
            timeouts = []

            def wait(self, timeout=None):
                self.wait_calls += 1
                self.timeouts.append(timeout)
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired(["ssh"], timeout)
                self.returncode = -signal.SIGKILL
                return self.returncode

            def poll(self):
                return self.returncode

        process = HungProcess()

        def signal_group(_group, sent_signal):
            if sent_signal == 0 and process.returncode is not None:
                raise ProcessLookupError

        arguments = SimpleNamespace(
            request_id=request_id, command="run", arguments=[], name="control-status",
            ssh_config="/trusted/config", host="sandbox-gateway-control",
            timeout_seconds=7,
        )
        stderr = io.StringIO()
        with (mock.patch.object(CONTROL.subprocess, "Popen", return_value=process),
              mock.patch.object(
                  CONTROL.os, "killpg", side_effect=signal_group
              ) as killpg,
              mock.patch.object(CONTROL.time, "sleep"),
              mock.patch.object(CONTROL.sys, "stderr", stderr)):
            self.assertEqual(CONTROL.client_main(arguments), 124)
        self.assertIn(mock.call(process.pid, signal.SIGTERM), killpg.call_args_list)
        self.assertIsNotNone(process.returncode)
        self.assertEqual(process.timeouts[0], 7)
        self.assertTrue(process.stdin.closed)
        self.assertGreater(len(process.stdin.data), 4)
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["request_id"], request_id)
        self.assertEqual(failure["error"], "client_deadline_exceeded")

    def test_client_rejects_out_of_range_deadline_before_ssh(self):
        arguments = SimpleNamespace(timeout_seconds=0)
        with self.assertRaisesRegex(CONTROL.ControlFailure, "client_timeout_invalid"):
            CONTROL.client_main(arguments)


class BundleTests(unittest.TestCase):
    def _archive(self, members):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for info, data in members:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
        return output.getvalue()

    def test_verified_regular_file_extracts(self):
        data = b"#!/bin/bash\nexit 0\n"
        info = tarfile.TarInfo("files/install-ok.sh")
        info.size = len(data)
        manifest = [{"path": "install-ok.sh", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": 0o755}]
        with tempfile.TemporaryDirectory() as temporary:
            CONTROL.extract_bundle(self._archive([(info, data)]), manifest, Path(temporary))
            installed = Path(temporary, "install-ok.sh")
            self.assertEqual(installed.read_bytes(), data)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o755)

    def test_symlink_traversal_duplicate_and_digest_mismatch_rejected(self):
        data = b"x"
        manifest = [{"path": "install-x.sh", "size": 1, "sha256": hashlib.sha256(data).hexdigest(), "mode": 0o755}]
        link = tarfile.TarInfo("files/install-x.sh")
        link.type = tarfile.SYMTYPE
        link.linkname = "/bin/sh"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_member_invalid"):
                CONTROL.extract_bundle(self._archive([(link, None)]), manifest, Path(temporary))
        traversal = tarfile.TarInfo("files/../install-x.sh")
        traversal.size = 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_member_invalid"):
                CONTROL.extract_bundle(self._archive([(traversal, data)]), manifest, Path(temporary))
        first = tarfile.TarInfo("files/install-x.sh")
        first.size = 1
        second = tarfile.TarInfo("files/install-x.sh")
        second.size = 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_inventory_mismatch"):
                CONTROL.extract_bundle(self._archive([(first, data), (second, data)]), manifest, Path(temporary))
        wrong = tarfile.TarInfo("files/install-x.sh")
        wrong.size = 1
        bad_manifest = [{**manifest[0], "sha256": "0" * 64}]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_digest_mismatch"):
                CONTROL.extract_bundle(self._archive([(wrong, data)]), bad_manifest, Path(temporary))

    def test_source_mutation_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "a")
            other = Path(temporary, "b")
            source.write_bytes(b"x")
            os.link(source, other)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "source_not_regular"):
                CONTROL.build_bundle([str(source)])

    def test_private_tmp_is_sticky_but_staging_parent_and_secrets_remain_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary, "staging")
            stage = parent / "research-request"
            parent.mkdir(mode=0o700)
            stage.mkdir(mode=0o700)
            secret = stage / "secret"
            secret.write_bytes(b"secret")
            secret.chmod(0o600)

            CONTROL.prepare_private_tmp(stage)

            self.assertEqual(parent.stat().st_mode & 0o7777, 0o700)
            self.assertEqual(stage.stat().st_mode & 0o7777, 0o1777)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)


class DispatchTests(unittest.TestCase):
    def request(self, value, payload=b""):
        value = {**value, "request_id": str(uuid.uuid4())}
        stream = io.BytesIO()
        CONTROL.write_request(stream, value, payload)
        stream.seek(0)
        return stream

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_role_and_argument_validation_precede_execution(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "operation_not_allowed_for_role"):
                CONTROL.dispatch("target", self.request({"kind": "run", "operation": "pki-verify", "args": []}), Path(temporary))
            with self.assertRaisesRegex(CONTROL.ControlFailure, "arguments_invalid"):
                CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "lease-status", "args": ["bad;id"]}), Path(temporary))
        run.assert_not_called()

    def test_v3_watchdog_arm_and_renew_are_content_bound_without_argv_bypasses(self):
        expected = {
            "watchdog-arm-v3":"arm-v3",
            "watchdog-renew-v3":"renew-v3",
        }
        for operation, command_name in expected.items():
            command, validator, roles = CONTROL.PIPE_OPERATIONS[operation]
            self.assertEqual(
                command,
                ["/usr/local/libexec/secure-sandbox/run_lease_watchdog.py", command_name],
            )
            self.assertTrue(validator([]))
            self.assertFalse(validator(["unexpected"]))
            self.assertEqual(roles, {"research"})
        self.assertNotIn("watchdog-arm", CONTROL.OPERATIONS)
        self.assertNotIn("watchdog-renew", CONTROL.OPERATIONS)

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_request_id_is_at_most_once(self, run):
        run.return_value.returncode = 0
        request_id = str(uuid.uuid4())
        value = {"kind": "run", "operation": "lease-status", "args": ["run-1"], "request_id": request_id}
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            first = io.BytesIO()
            CONTROL.write_request(first, value)
            first.seek(0)
            self.assertEqual(CONTROL.dispatch("gateway", first, state), 0)
            replay = io.BytesIO()
            CONTROL.write_request(replay, value)
            replay.seek(0)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "request_replayed"):
                CONTROL.dispatch("gateway", replay, state)
            receipt = json.loads((state / "receipts" / f"{request_id}.json").read_text())
            self.assertEqual((receipt["state"], receipt["status"]), ("completed", 0))
            events = [json.loads(line) for line in (state / "audit.jsonl").read_text().splitlines()]
            self.assertTrue(all(event["request_id"] == request_id for event in events))
            self.assertTrue(all("args" not in event for event in events))
        run.assert_called_once()

    def test_receipt_archival_is_lossless_and_preserves_replay_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_ids = [str(uuid.uuid4()) for _ in range(3)]
            for index, request_id in enumerate(request_ids):
                path = receipts / f"{request_id}.json"
                path.write_bytes(CONTROL.canonical_json({
                    "request_id":request_id,
                    "request_sha256":hashlib.sha256(str(index).encode()).hexdigest(),
                    "schema":"secure-sandbox-privileged-control-receipt-v1",
                    "state":"completed",
                    "status":0,
                }) + b"\n")
                path.chmod(0o600)
                os.utime(path, ns=(index + 1, index + 1))

            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["archived"], 2)
            self.assertEqual(len(list(receipts.iterdir())), 1)
            archive = state / "receipt-archive"
            self.assertEqual(len(list(archive.iterdir())), 2)
            for archived in archive.iterdir():
                original_id = request_ids.index(archived.stem)
                expected = CONTROL.canonical_json({
                    "request_id": archived.stem,
                    "request_sha256": hashlib.sha256(str(original_id).encode()).hexdigest(),
                    "schema": "secure-sandbox-privileged-control-receipt-v1",
                    "state": "completed",
                    "status": 0,
                }) + b"\n"
                self.assertEqual(archived.read_bytes(), expected)

            replayed = next(path.stem for path in archive.iterdir())
            with self.assertRaisesRegex(CONTROL.ControlFailure, "request_replayed"):
                CONTROL.reserve_request(state, {"request_id":replayed})

    def test_receipt_archival_rejects_dangling_destination_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            archive = state / "receipt-archive"
            receipts.mkdir(mode=0o700)
            archive.mkdir(mode=0o700)
            request_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
            for index, request_id in enumerate(request_ids):
                path = receipts / f"{request_id}.json"
                path.write_bytes(CONTROL.canonical_json({
                    "request_id": request_id,
                    "request_sha256": "a" * 64,
                    "schema": "secure-sandbox-privileged-control-receipt-v1",
                    "state": "completed",
                    "status": 0,
                }) + b"\n")
                path.chmod(0o600)
                os.utime(path, ns=(index + 1, index + 1))
            (archive / f"{request_ids[0]}.json").symlink_to("missing")
            with self.assertRaisesRegex(CONTROL.ControlFailure, "archive_collision"):
                CONTROL.archive_control_receipts(state, keep=1)
            self.assertTrue((receipts / f"{request_ids[0]}.json").exists())

    def test_receipt_ledger_lock_serializes_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            request_id = str(uuid.uuid4())
            entered = threading.Event()
            finished = threading.Event()

            def reserve():
                entered.set()
                CONTROL.reserve_request(state, {"request_id": request_id})
                finished.set()

            with CONTROL.receipt_ledger_lock(state):
                worker = threading.Thread(target=reserve)
                worker.start()
                self.assertTrue(entered.wait(1))
                self.assertFalse(finished.wait(0.1))
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertTrue(finished.is_set())

    def test_receipt_archival_keeps_in_progress_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            path = receipts / f"{request_id}.json"
            path.write_bytes(CONTROL.canonical_json({
                "request_id":request_id,
                "request_sha256":"a" * 64,
                "schema":"secure-sandbox-privileged-control-receipt-v1",
                "state":"started",
            }) + b"\n")
            path.chmod(0o600)
            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["archived"], 0)
            self.assertTrue(path.exists())

    def test_receipt_archival_recovers_exact_durable_completion_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            digest = "a" * 64
            canonical = receipts / f"{request_id}.json"
            staged = receipts / f".{request_id}.json.complete"
            canonical.write_bytes(CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": digest,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "started",
            }) + b"\n")
            staged_bytes = CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": digest,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "completed", "status": 0,
            }) + b"\n"
            staged.write_bytes(staged_bytes)
            canonical.chmod(0o600)
            staged.chmod(0o600)
            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["recovered_completions"], 1)
            self.assertEqual(canonical.read_bytes(), staged_bytes)
            self.assertFalse(staged.exists())

    def test_receipt_archival_rejects_mismatched_completion_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            canonical = receipts / f"{request_id}.json"
            staged = receipts / f".{request_id}.json.complete"
            canonical.write_bytes(CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": "a" * 64,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "started",
            }) + b"\n")
            staged.write_bytes(CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": "b" * 64,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "completed", "status": 0,
            }) + b"\n")
            canonical.chmod(0o600)
            staged.chmod(0o600)
            with self.assertRaisesRegex(
                CONTROL.ControlFailure, "completion_recovery_invalid"
            ):
                CONTROL.archive_control_receipts(state, keep=1)
            self.assertTrue(canonical.exists())
            self.assertTrue(staged.exists())

    def test_receipt_archival_losslessly_quarantines_empty_completion_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            canonical = receipts / f"{request_id}.json"
            staged = receipts / f".{request_id}.json.complete"
            canonical_bytes = CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": "a" * 64,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "started",
            }) + b"\n"
            canonical.write_bytes(canonical_bytes)
            staged.write_bytes(b"")
            canonical.chmod(0o600)
            staged.chmod(0o600)
            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["quarantined_empty_completion_stages"], 1)
            self.assertEqual(canonical.read_bytes(), canonical_bytes)
            self.assertFalse(staged.exists())
            quarantined = (
                state / "receipt-recovery" /
                f"{request_id}.empty-completion-stage"
            )
            self.assertTrue(quarantined.exists())
            self.assertEqual(quarantined.read_bytes(), b"")

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_role_bound_policy_and_backup_prefixes(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "arguments_invalid"):
                CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "policy-hash", "args": ["research"]}), state)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "arguments_invalid"):
                CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "rollback-run-leases-gateway", "args": ["run-leases-research-20261020T120000Z-1"]}), state)
        run.assert_not_called()

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_started_audit_is_durable_before_execution(self, run):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            CONTROL, "audit_event", side_effect=[CONTROL.ControlFailure("audit unavailable"), None]
        ):
            with self.assertRaisesRegex(CONTROL.ControlFailure, "audit unavailable"):
                CONTROL.dispatch(
                    "gateway",
                    self.request({"kind": "run", "operation": "lease-status", "args": ["run-1"]}),
                    Path(temporary),
                )
        run.assert_not_called()

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_runtime_exec_uses_argv_and_clean_environment(self, run):
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as temporary:
            result = CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "lease-status", "args": ["run-1"]}), Path(temporary))
        self.assertEqual(result, 0)
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["/usr/local/libexec/secure-sandbox/run_lease.py", "status", "run-1"])
        self.assertNotIn("SHELL", run.call_args.kwargs["env"])

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_pipe_operation_is_role_bound_and_content_bound(self, run):
        payload = b"framed source archive"
        request = {
            "kind": "pipe",
            "operation": "source-import-stage",
            "args": [],
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(CONTROL.dispatch("research", self.request(request, payload), Path(temporary)), 0)
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/local/sbin/secure-sandbox-source-import", "stage"],
        )
        self.assertEqual(run.call_args.kwargs["input"], payload)

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "payload_digest_mismatch"):
                CONTROL.dispatch(
                    "research",
                    self.request({**request, "payload_sha256": "0" * 64}, payload),
                    Path(temporary),
                )
        self.assertEqual(run.call_count, 1)

    def test_deploy_rejects_non_installer_before_fork(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "installer_invalid"):
                CONTROL.dispatch(
                    "gateway",
                    self.request({"kind": "deploy", "installer": "shell.py", "args": [], "files": []}),
                    Path(temporary),
                )


class EntryTests(unittest.TestCase):
    def test_entry_rejects_every_command_except_request(self):
        path = ROOT / "scripts/privileged_control_entry.py"
        spec = importlib.util.spec_from_file_location("privileged_control_entry", path)
        assert spec and spec.loader
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "sh"}, clear=True):
            self.assertEqual(entry.main(), 64)
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "request", "LD_PRELOAD": "/evil"}, clear=True), mock.patch.object(entry.os, "execve", side_effect=RuntimeError) as execute:
            with self.assertRaises(RuntimeError):
                entry.main()
        self.assertEqual(execute.call_args.args[0], "/usr/bin/sudo")
        self.assertNotIn("LD_PRELOAD", execute.call_args.args[2])


class SelfCheckTests(unittest.TestCase):
    @mock.patch.object(CONTROL.subprocess, "run")
    def test_effective_sudo_policy_asks_sudo_after_invalidating_credentials(self, run):
        run.side_effect = [mock.Mock(returncode=0), mock.Mock(returncode=0)]
        self.assertTrue(CONTROL._labadmin_passwordless_sudo_present())
        self.assertEqual(run.call_args_list[0].args[0][-2:], ["/usr/bin/sudo", "-k"])
        self.assertEqual(run.call_args_list[1].args[0][-3:], ["/usr/bin/sudo", "-n", "-l"])

        run.reset_mock()
        run.side_effect = [mock.Mock(returncode=0), mock.Mock(returncode=1)]
        self.assertFalse(CONTROL._labadmin_passwordless_sudo_present())

        run.reset_mock()
        run.side_effect = [mock.Mock(returncode=0), mock.Mock(returncode=2)]
        with self.assertRaisesRegex(CONTROL.ControlFailure, "labadmin_sudo_policy_unavailable"):
            CONTROL._labadmin_passwordless_sudo_present()

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_lifecycle_idle_requires_no_markers_and_exact_pgrep_no_match(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary, "marker")
            run.return_value = mock.Mock(returncode=1)
            self.assertTrue(CONTROL.lifecycle_idle((marker,)))
            run.return_value = mock.Mock(returncode=0)
            self.assertFalse(CONTROL.lifecycle_idle((marker,)))
            run.return_value = mock.Mock(returncode=2)
            self.assertFalse(CONTROL.lifecycle_idle((marker,)))
            marker.write_text("active\n", encoding="ascii")
            run.reset_mock()
            self.assertFalse(CONTROL.lifecycle_idle((marker,)))
            run.assert_not_called()

    def test_self_check_file_is_content_bound_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "policy"
            path.write_bytes(b"policy\n")
            path.chmod(0o644)
            expected = hashlib.sha256(b"policy\n").hexdigest()
            result = CONTROL._self_check_file(
                path, 0o644, path.stat().st_uid, path.stat().st_gid
            )
            self.assertEqual(result["sha256"], expected)
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "control_file_untrusted"):
                CONTROL._self_check_file(
                    link, 0o644, path.stat().st_uid, path.stat().st_gid
                )

    def test_self_check_file_rejects_wrong_mode_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "policy"
            linked = root / "linked"
            path.write_bytes(b"policy\n")
            path.chmod(0o600)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "control_file_untrusted"):
                CONTROL._self_check_file(
                    path, 0o644, path.stat().st_uid, path.stat().st_gid
                )
            os.link(path, linked)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "control_file_untrusted"):
                CONTROL._self_check_file(
                    path, 0o600, path.stat().st_uid, path.stat().st_gid
                )


class RepositoryMigrationTests(unittest.TestCase):
    def test_clean_bootstrap_installers_preserve_fail_closed_boundaries(self):
        research = (ROOT / "scripts/install-research-auditd.sh").read_text(encoding="utf-8")
        target = (ROOT / "scripts/install-target-rootless-docker-provisioning.sh").read_text(encoding="utf-8")
        docker = (ROOT / "scripts/install-rootless-docker.sh").read_text(encoding="utf-8")
        principals = (ROOT / "scripts/install-research-service-principals.sh").read_text(encoding="utf-8")

        self.assertIn('== research', research)
        self.assertIn('== target', target)
        for text in (research, target):
            self.assertIn('/sys/class/net/*/address', text)
            self.assertIn('runtime_interface=', text)
            self.assertIn('ip address flush dev "$runtime_interface"', text)
            self.assertIn('ip link set dev "$runtime_interface" down', text)
            self.assertIn('nft -f /etc/nftables.conf', text)
            self.assertIn('table inet secure_sandbox_maintenance', text)
            self.assertIn('policy drop;', text)
            self.assertIn('ip daddr 10.211.55.1 udp dport 53 accept', text)
            self.assertNotIn('\nnft flush ruleset\n', text)
            self.assertNotIn('nft -f /etc/nftables.conf || true', text)
            self.assertIn('! ip -4 route show default | grep -q .', text)
        self.assertLess(research.index('nft -f "$maintenance_policy"'), research.index('apt-get'))
        self.assertLess(target.index('nft -f "$maintenance_policy"'), target.index('/bin/bash "$installer"'))
        self.assertEqual(docker.count('apt-get update --error-on=any'), 2)
        self.assertIn('nft list table inet secure_sandbox_maintenance', docker)
        self.assertNotIn('nft flush ruleset', docker)
        self.assertNotIn('APT::Sandbox::User=root', docker)
        self.assertIn('execution-broker', principals)
        self.assertIn('This installer is restricted to Research.', principals)

    def test_first_source_integrity_generation_has_reversible_absence_records(self):
        installer = (ROOT / "scripts/install-source-integrity.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "research/rollback_source_integrity.sh").read_text(encoding="utf-8")
        for name in ("managed-settings.json", "research-claude"):
            self.assertIn(name, installer)
            self.assertIn(name, rollback)
        self.assertIn(': > "$backup/$name.absent"', installer)
        self.assertIn('rm -f -- "$destination"', rollback)

    def test_large_claude_binary_is_reassembled_without_raising_control_limits(self):
        installer = (ROOT / "scripts/install-claude-code.sh").read_text(encoding="utf-8")
        self.assertIn('part.00', installer)
        self.assertIn('part.01', installer)
        self.assertIn('part.02', installer)
        self.assertIn('cat "${parts[@]}" > "$assembled_claude"', installer)
        self.assertIn('ae2295ae2da156936bf5831ab01971ce924d0c9a0af174e28d96fffa8d5fa0a6', installer)
        self.assertEqual(CONTROL.MAX_FILE, 128 * 1024 * 1024)
        self.assertEqual(CONTROL.MAX_PAYLOAD, 256 * 1024 * 1024)

    def test_runtime_callers_do_not_execute_the_mutable_workspace_client(self):
        offenders = []
        paths = sorted((ROOT / "scripts").glob("*.sh")) + [
            ROOT / "scripts/labctl",
            ROOT / "scripts/verify-privileged-control-live.py",
        ]
        forbidden = (
            '$root_dir/scripts/privileged_control.py" client',
            'control_client="$root_dir/scripts/privileged_control.py"',
            'CLIENT = ROOT / "scripts/privileged_control.py"',
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            if any(value in text for value in forbidden):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

        source_references = {
            path.name
            for path in (ROOT / "scripts").iterdir()
            if path.is_file() and not path.name.startswith("test_")
            and "scripts/privileged_control.py" in path.read_text(encoding="utf-8")
        }
        self.assertEqual(
            source_references,
            {
                "build-autoinstall-seed.sh",
                "deploy-foundation.sh",
                "deploy-harness-lifecycle-consumer.sh",
                "deploy-legacy-preservation.sh",
                "host-controller-release.py",
                "legacy-vm-preservation.py",
                "native_deployment_payload.py",
                "plan-legacy-vm-preservation.py",
                "privileged-control-operation.py",
                "verify-autoinstall-seed.py",
                "verify-boundaries.sh",
                "verify-privileged-control-live.py",
            },
        )
        foundation = (ROOT / "scripts/deploy-foundation.sh").read_text(encoding="utf-8")
        self.assertIn(
            "control_client=/usr/local/libexec/secure-sandbox-host/current/control_client",
            foundation,
        )
        self.assertIn(
            '--file "$root_dir/scripts/privileged_control.py"',
            foundation,
        )
        self.assertNotIn(
            '$root_dir/scripts/privileged_control.py" client',
            foundation,
        )

    def test_protected_client_callers_use_the_protected_ssh_config(self):
        protected_client = "/usr/local/libexec/secure-sandbox-host/current/control_client"
        protected_config = "/usr/local/libexec/secure-sandbox-host/current/ssh_config"
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            text = path.read_text(encoding="utf-8")
            if protected_client in text and protected_config not in text:
                offenders.append(path.name)
        live = (ROOT / "scripts/verify-privileged-control-live.py").read_text(encoding="utf-8")
        if protected_client not in live or protected_config not in live:
            offenders.append("verify-privileged-control-live.py")
        self.assertEqual(offenders, [])

    def test_no_automated_guest_admin_password_delivery_remains(self):
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            text = path.read_text(encoding="utf-8")
            if "sudo -S" in text or any(
                value in text for value in (
                    "SecureSandbox-Gateway/password",
                    "SecureSandbox-Research/password",
                    "SecureSandbox-Target/password",
                )
            ):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

    def test_labadmin_has_no_passwordless_automation_grants_or_callers(self):
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            text = path.read_text(encoding="utf-8")
            if "labadmin ALL=(root) NOPASSWD:" in text or re.search(
                r"sudo -n (?:/usr/local/sbin/secure-sandbox-source-import|"
                r"/usr/local/libexec/secure-sandbox/(?:dependency_orchestrator|codegraph_indexer)\.py)",
                text,
            ):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

        labctl = (ROOT / "scripts/labctl").read_text(encoding="utf-8")
        for operation in (
            "source-import-stage", "source-import-publish", "dependency-plan",
            "dependency-status", "dependency-apply", "dependency-list", "source-list",
        ):
            self.assertIn(operation, labctl)
            self.assertIn(f'"{operation}"', (ROOT / "scripts/privileged_control.py").read_text(encoding="utf-8"))
        self.assertNotIn('cat /home/agent/research-workspace/repos/INDEX.json', labctl)
        self.assertNotIn('cat /home/agent/research-workspace/dependency-bundles/INDEX.json', labctl)

    def test_privileged_control_install_reload_is_fail_closed_when_ssh_is_active(self):
        installer = (ROOT / "scripts/install-privileged-control.sh").read_text(encoding="utf-8")
        self.assertIn('/usr/bin/systemd-detect-virt --chroot >/dev/null 2>&1', installer)
        self.assertIn('case "$chroot_state_status" in', installer)
        self.assertIn('systemd_chroot_state_invalid:', installer)
        self.assertIn(
            'ssh_state="$(LC_ALL=C /usr/bin/systemctl is-active ssh.service 2>&1)"',
            installer,
        )
        self.assertIn("Running in chroot, ignoring command 'is-active'", installer)
        self.assertIn('[[ "${SYSTEMD_OFFLINE:-}" == 1 ]]', installer)
        self.assertIn('ssh_service_offline_state_untrusted', installer)
        self.assertIn('0:active)', installer)
        self.assertIn('3:inactive)', installer)
        self.assertIn('ssh_service_state_invalid:', installer)
        self.assertIn('ssh_service_not_active_after_reload', installer)
        self.assertIn('0:reloading) sleep 0.1', installer)
        self.assertIn('ssh_service_reload_timeout', installer)
        self.assertIn('systemctl reload ssh.service', installer)
        self.assertNotIn('systemctl reload ssh.service >/dev/null 2>&1 || true', installer)
        self.assertLess(
            installer.index('/usr/bin/systemd-detect-virt --chroot'),
            installer.index('/usr/bin/systemctl is-active ssh.service'),
        )
        self.assertLess(
            installer.index('systemctl reload ssh.service'),
            installer.index('internal control-self-check'),
        )
        self.assertLess(
            installer.index('internal control-self-check'),
            installer.index('echo "privileged-control:installed:$role"'),
        )

    def test_privileged_control_install_service_state_machine(self):
        installer = (ROOT / "scripts/install-privileged-control.sh").read_text(encoding="utf-8")
        service_block = installer.split("# BEGIN TESTABLE_SSH_SERVICE_ACTIVATION\n", 1)[1].split(
            "# END TESTABLE_SSH_SERVICE_ACTIVATION\n", 1
        )[0]

        def run(chroot_status, states=(), *, reload_status=0, systemd_offline=None):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "bin"
                binary.mkdir()
                (root / "states").write_text(
                    "".join(f"{status}\t{state}\n" for status, state in states),
                    encoding="utf-8",
                )
                (root / "counter").write_text("0\n", encoding="ascii")
                (root / "log").write_text("", encoding="ascii")
                (binary / "systemd-detect-virt").write_text(
                    "#!/bin/sh\nexit \"$MOCK_CHROOT_STATUS\"\n", encoding="utf-8"
                )
                (binary / "systemctl").write_text(
                    """#!/bin/sh
set -eu
if [ "$1" = is-active ] && [ "$2" = ssh.service ]; then
  index=$(cat "$MOCK_COUNTER")
  line=$(sed -n "$((index + 1))p" "$MOCK_STATES")
  [ -n "$line" ] || exit 97
  printf '%s\n' "$((index + 1))" > "$MOCK_COUNTER"
  status=${line%%	*}
  state=${line#*	}
  [ -z "$state" ] || printf '%s\n' "$state"
  exit "$status"
fi
if [ "$1" = reload ] && [ "$2" = ssh.service ]; then
  printf 'reload\n' >> "$MOCK_LOG"
  exit "$MOCK_RELOAD_STATUS"
fi
exit 98
""",
                    encoding="utf-8",
                )
                (binary / "sleep").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                for path in binary.iterdir():
                    path.chmod(0o755)
                environment = {
                    "PATH": f"{binary}:/usr/bin:/bin",
                    "MOCK_CHROOT_STATUS": str(chroot_status),
                    "MOCK_COUNTER": str(root / "counter"),
                    "MOCK_STATES": str(root / "states"),
                    "MOCK_LOG": str(root / "log"),
                    "MOCK_RELOAD_STATUS": str(reload_status),
                }
                if systemd_offline is not None:
                    environment["SYSTEMD_OFFLINE"] = systemd_offline
                block = service_block.replace(
                    "/usr/bin/systemd-detect-virt", str(binary / "systemd-detect-virt")
                ).replace("/usr/bin/systemctl", str(binary / "systemctl"))
                result = subprocess.run(
                    ["/bin/bash", "-c", "set -euo pipefail\n" + block + "printf 'complete\\n'"],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                return result, (root / "log").read_text(encoding="ascii")

        chroot, log = run(0)
        self.assertEqual((chroot.returncode, chroot.stdout, log), (0, "complete\n", ""))

        inactive, log = run(1, ((3, "inactive"),))
        self.assertEqual((inactive.returncode, inactive.stdout, log), (0, "complete\n", ""))

        active, log = run(1, ((0, "active"), (0, "active")))
        self.assertEqual((active.returncode, active.stdout, log), (0, "complete\n", "reload\n"))

        ignored, log = run(1, ((0, ""),))
        self.assertEqual(ignored.returncode, 1)
        self.assertIn("ssh_service_state_invalid:unavailable", ignored.stderr)
        self.assertEqual(log, "")

        curtin, log = run(
            1,
            ((0, "Running in chroot, ignoring command 'is-active'"),),
            systemd_offline="1",
        )
        self.assertEqual((curtin.returncode, curtin.stdout, log), (0, "complete\n", ""))

        spoofed_curtin, log = run(
            1, ((0, "Running in chroot, ignoring command 'is-active'"),)
        )
        self.assertEqual(spoofed_curtin.returncode, 1)
        self.assertIn("ssh_service_offline_state_untrusted", spoofed_curtin.stderr)
        self.assertEqual(log, "")

        detector_error, log = run(2)
        self.assertEqual(detector_error.returncode, 1)
        self.assertIn("systemd_chroot_state_invalid:2", detector_error.stderr)
        self.assertEqual(log, "")

        reload_regressed, log = run(1, ((0, "active"), (0, "inactive")))
        self.assertEqual(reload_regressed.returncode, 1)
        self.assertIn("ssh_service_not_active_after_reload:inactive", reload_regressed.stderr)
        self.assertEqual(log, "reload\n")

    def test_no_host_copy_targets_guest_tmp(self):
        offenders = []
        pattern = re.compile(r"sandbox-(?:gateway|research-admin|target-admin):/tmp")
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            if pattern.search(path.read_text(encoding="utf-8")):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

    def test_control_deploy_uses_only_protected_client_and_authenticated_deployments(self):
        operation = (ROOT / "scripts/privileged-control-operation.py").read_text(encoding="utf-8")
        self.assertFalse((ROOT / "scripts/deploy-privileged-control.sh").exists())
        self.assertIn('/usr/local/libexec/secure-sandbox-host/current/control_client', operation)
        self.assertIn('LAUNCHER.acquire_lock', operation)
        self.assertIn('MANAGER.active_markers', operation)
        self.assertIn('DEFERRED_SIGNALS', operation)
        self.assertIn('signal.pthread_sigmask', operation)
        self.assertIn('start_new_session=True', operation)
        self.assertIn('"verify", "--json"', operation)
        self.assertIn('"run", "lifecycle-idle"', operation)
        self.assertIn('deploy_role("sandbox-gateway-control", "gateway"', operation)
        self.assertIn('deploy_role("sandbox-research-control", "research"', operation)
        self.assertIn('deploy_role("sandbox-target-control", "target"', operation)
        self.assertLess(
            operation.index('deploy_role("sandbox-research-control", "research"'),
            operation.index('"run", "lifecycle-idle"'),
        )
        self.assertLess(
            operation.index('"run", "lifecycle-idle"'),
            operation.index('deploy_role("sandbox-gateway-control", "gateway"'),
        )
        self.assertIn('"install-approved-claude-policy.sh"', operation)
        self.assertIn('verify-privileged-control-live.py', operation)
        self.assertNotRegex(operation, r'sandbox-(?:gateway|research-admin|target-admin).*sudo')

    @mock.patch.object(OPERATION, "run_command")
    @mock.patch.object(OPERATION.MANAGER, "active_markers")
    @mock.patch.object(OPERATION.LAUNCHER, "release_lock")
    @mock.patch.object(OPERATION.LAUNCHER, "acquire_lock")
    def test_control_deployment_holds_launch_lock_and_rejects_active_marker(
        self, acquire, release, active_markers, run
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "coordination.lock"
            acquire.return_value = lock
            active_markers.return_value = ["live"]
            self.assertEqual(OPERATION.deploy(root), 1)
            run.assert_not_called()
            release.assert_called_once_with(lock)

    def test_control_deployment_defers_first_termination_signal(self):
        deferred = OPERATION.DeferredSignals()
        deferred.handle(signal.SIGTERM, None)
        deferred.handle(signal.SIGINT, None)
        self.assertEqual(deferred.received, signal.SIGTERM)
        self.assertEqual(OPERATION.interrupted_status(deferred), 128 + signal.SIGTERM)

    @mock.patch.object(OPERATION, "run_command")
    def test_postactivation_host_verifier_requires_exact_floor_denial(self, run):
        denied = {
            "error":"execution_approval_floor_invalid",
            "schema":"secure-sandbox-host-controller-release-v1",
            "status":"rejected",
        }
        run.side_effect = [
            mock.Mock(
                returncode=1, stdout=json.dumps(denied) + "\n", stderr=""
            ),
            mock.Mock(returncode=0, stdout='{"status":"verified"}\n', stderr=""),
        ]
        result = OPERATION.verify_host_controller_release(
            OPERATION.DeferredSignals()
        )
        self.assertEqual(result.returncode, 0)
        fallback = run.call_args_list[1].args[0]
        self.assertIn("verify-postactivation-host-release", fallback)

    @mock.patch.object(OPERATION, "run_command")
    def test_unrelated_host_verifier_failure_does_not_fallback(self, run):
        rejected = {
            "error":"active_release_source_mismatch",
            "schema":"secure-sandbox-host-controller-release-v1",
            "status":"rejected",
        }
        run.return_value = mock.Mock(
            returncode=1, stdout=json.dumps(rejected) + "\n", stderr=""
        )
        with self.assertRaisesRegex(
            RuntimeError, "host_controller_release_verify_failed:1"
        ):
            OPERATION.verify_host_controller_release(
                OPERATION.DeferredSignals()
            )
        run.assert_called_once()

    def test_control_deployment_waits_for_child_after_termination_signal(self):
        with OPERATION.DeferredSignals() as deferred:
            timer = threading.Timer(0.05, os.kill, args=(os.getpid(), signal.SIGTERM))
            timer.start()
            try:
                result = OPERATION.run_command(
                    [
                        sys.executable,
                        "-c",
                        "import time; time.sleep(0.15); print('child-complete')",
                    ],
                    deferred,
                )
            finally:
                timer.join()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "child-complete")
        self.assertEqual(deferred.received, signal.SIGTERM)

    @mock.patch.object(OPERATION, "protected_regular_file", return_value=True)
    @mock.patch.object(OPERATION.MANAGER, "active_markers", return_value=[])
    @mock.patch.object(OPERATION.LAUNCHER, "release_lock")
    @mock.patch.object(OPERATION.LAUNCHER, "acquire_lock")
    def test_control_deployment_propagates_signal_received_during_final_verifier(
        self, acquire, release, _active_markers, _protected_file
    ):
        acquire.return_value = Path("coordination.lock")
        outputs = iter(
            (
                "{}\n",
                "privileged-control:installed:research\n",
                "",
                "privileged-control:installed:gateway\n",
                "privileged-control:installed:target\n",
                "claude-policy:installed; run the post-install safety audit before use\n",
                '{"status":"verified"}\n',
            )
        )

        def run_and_interrupt_final(command, deferred):
            output = next(outputs)
            if command[-1].endswith("verify-privileged-control-live.py"):
                deferred.handle(signal.SIGTERM, None)
            return mock.Mock(returncode=0, stdout=output, stderr="")

        with mock.patch.object(OPERATION, "run_command", side_effect=run_and_interrupt_final):
            self.assertEqual(OPERATION.deploy(Path("state")), 128 + signal.SIGTERM)
        release.assert_called_once_with(Path("coordination.lock"))


if __name__ == "__main__":
    unittest.main()
