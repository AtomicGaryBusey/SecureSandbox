#!/usr/bin/env python3

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PATH = Path(__file__).with_name(
    "harness-lifecycle-acceptance-host-control-migrate.py"
)
SPEC = importlib.util.spec_from_file_location("host_control_migrate", PATH)
MIGRATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MIGRATE)


class FakeLifecycle:
    def __init__(self, observations):
        self.observations = list(observations)
        self.lock = -1

    def require_mutation_prerequisites(self):
        return None

    def acquire_lock(self):
        self.lock = os.open("/dev/null", os.O_RDONLY)
        return self.lock

    def observe(self):
        return self.observations.pop(0), {}


class FakeGui:
    def __init__(self, values=((42,), (42,))):
        self.values = list(values)

    def gui_process_ids(self):
        return self.values.pop(0)


class FakeTransport:
    LEGACY_PREDECESSOR = b"legacy"

    @staticmethod
    def rules(address, *, host_control):
        return f"{address}:{host_control}".encode()

    @staticmethod
    def digest(value):
        import hashlib
        return hashlib.sha256(value).hexdigest()


def transport_result(status="installed", admin_source="10.211.55.2"):
    import hashlib
    predecessor = hashlib.sha256(
        FakeTransport.rules(admin_source, host_control=False)
    ).hexdigest()
    successor = hashlib.sha256(
        FakeTransport.rules(admin_source, host_control=True)
    ).hexdigest()
    return {
        "schema": "secure-sandbox-gateway-host-control-transport-v1",
        "status": status,
        "predecessor_sha256": predecessor,
        "successor_sha256": successor,
        "backup_sha256": predecessor if status == "installed" else None,
        "admin_source": admin_source,
        "host_control_address": "172.30.10.30",
        "authority": "guest-firewall-only",
    }


class HostControlMigrationTests(unittest.TestCase):
    def test_validates_exact_transport_result(self):
        self.assertEqual(
            MIGRATE.validate_result(
                transport_result(), FakeTransport, "10.211.55.2",
            )["status"],
            "installed",
        )
        for mutation in (
            {"authority": "guest-self-report"},
            {"host_control_address": "172.30.10.29"},
            {"successor_sha256": "1" * 64},
            {"backup_sha256": None},
            {"admin_source": "10.211.55.3"},
        ):
            value = {**transport_result(), **mutation}
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                MIGRATE.MigrationError, "migration_result_invalid"
            ):
                MIGRATE.validate_result(
                    value, FakeTransport, "10.211.55.2",
                )

    def test_migration_is_bound_to_protected_payload_and_exact_state(self):
        observed = dict(MIGRATE.EXPECTED_INITIAL)
        lifecycle = FakeLifecycle((observed, observed))
        gui = FakeGui()
        request_id = "11111111-1111-4111-8111-111111111111"
        source_commit = "a" * 40
        manifest = {"manifest_sha256": "b" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            installer = release / MIGRATE.INSTALLER
            payload = release / MIGRATE.PAYLOAD
            installer.parent.mkdir(parents=True)
            installer.write_text("installer")
            payload.write_text("payload")
            completed = subprocess.CompletedProcess(
                [], 0, json.dumps(transport_result()).encode(), b"",
            )
            runner = mock.Mock(return_value=completed)
            with (mock.patch.object(MIGRATE.os, "geteuid", return_value=501),
                  mock.patch.object(
                      MIGRATE, "trusted_operator_home",
                      return_value="/Users/tester",
                  ),
                  mock.patch.object(
                      MIGRATE, "trusted_shared_admin_source",
                      return_value="10.211.55.2",
                  ),
                  mock.patch.object(MIGRATE, "require_active_component")):
                result = MIGRATE.migrate(
                    release, source_commit, manifest, lifecycle, gui,
                    FakeTransport, request_id, runner=runner,
                    control_client=Path("/protected/control_client"),
                    ssh_config=Path("/protected/ssh_config"),
                )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["request_id"], request_id)
        self.assertEqual(result["initial"], observed)
        command = runner.call_args.args[0]
        self.assertEqual(command[:9], [
            "/protected/control_client", "client", "--ssh-config",
            "/protected/ssh_config", "--timeout-seconds", "120",
            "--request-id", request_id, "sandbox-gateway-control",
        ])
        self.assertEqual(command[9:13], [
            "deploy", "install-gateway-host-control-transport.sh",
            "10.211.55.2", "--file",
        ])
        self.assertEqual(command[13], str(installer))
        self.assertEqual(command[14:], ["--file", str(payload)])
        self.assertEqual(runner.call_args.kwargs["env"]["HOME"], "/Users/tester")
        self.assertEqual(lifecycle.observations, [])
        with self.assertRaises(OSError):
            os.fstat(lifecycle.lock)

    def test_rejects_state_drift_before_deployment(self):
        observed = {**MIGRATE.EXPECTED_INITIAL, "gateway_net0": "disconnected"}
        lifecycle = FakeLifecycle((observed,))
        runner = mock.Mock()
        with (mock.patch.object(MIGRATE.os, "geteuid", return_value=501),
              mock.patch.object(
                  MIGRATE, "trusted_shared_admin_source",
                  return_value="10.211.55.2",
              ),
              mock.patch.object(MIGRATE, "require_active_component")):
            with self.assertRaisesRegex(
                MIGRATE.MigrationError, "migration_initial_state_invalid"
            ):
                MIGRATE.migrate(
                    Path("/protected"), "a" * 40,
                    {"manifest_sha256": "b" * 64}, lifecycle, FakeGui(),
                    FakeTransport, "11111111-1111-4111-8111-111111111111",
                    runner=runner,
                )
        runner.assert_not_called()

    def test_trusted_operator_home_rejects_symlink_and_writable_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(home, target_is_directory=True)
            account = SimpleNamespace(pw_dir=str(link))
            with (mock.patch.object(MIGRATE.pwd, "getpwuid", return_value=account),
                  self.assertRaisesRegex(
                      MIGRATE.MigrationError,
                      "migration_operator_home_untrusted",
                  )):
                MIGRATE.trusted_operator_home(os.geteuid())
            home.chmod(0o770)
            account = SimpleNamespace(pw_dir=str(home))
            with (mock.patch.object(MIGRATE.pwd, "getpwuid", return_value=account),
                  self.assertRaisesRegex(
                      MIGRATE.MigrationError,
                      "migration_operator_home_untrusted",
                  )):
                MIGRATE.trusted_operator_home(os.geteuid())

    def test_rejects_noncanonical_request_id_before_deployment(self):
        observed = dict(MIGRATE.EXPECTED_INITIAL)
        lifecycle = FakeLifecycle((observed,))
        runner = mock.Mock()
        with (mock.patch.object(MIGRATE.os, "geteuid", return_value=501),
              mock.patch.object(
                  MIGRATE, "trusted_shared_admin_source",
                  return_value="10.211.55.2",
              ),
              mock.patch.object(MIGRATE, "require_active_component")):
            with self.assertRaisesRegex(
                MIGRATE.MigrationError, "migration_request_id_invalid"
            ):
                MIGRATE.migrate(
                    Path("/protected"), "a" * 40,
                    {"manifest_sha256": "b" * 64}, lifecycle, FakeGui(),
                    FakeTransport, "11111111111141118111111111111111",
                    runner=runner,
                )
        runner.assert_not_called()

    def test_control_failure_is_rejected_with_request_id_reusable(self):
        observed = dict(MIGRATE.EXPECTED_INITIAL)
        lifecycle = FakeLifecycle((observed,))
        completed = subprocess.CompletedProcess([], 17, b"", b"bounded")
        with (mock.patch.object(MIGRATE.os, "geteuid", return_value=501),
              mock.patch.object(
                  MIGRATE, "trusted_shared_admin_source",
                  return_value="10.211.55.2",
              ),
              mock.patch.object(MIGRATE, "require_active_component")):
            with self.assertRaisesRegex(
                MIGRATE.MigrationError, "migration_control_rejected"
            ):
                MIGRATE.migrate(
                    Path("/protected"), "a" * 40,
                    {"manifest_sha256": "b" * 64}, lifecycle, FakeGui(),
                    FakeTransport, "11111111-1111-4111-8111-111111111111",
                    runner=mock.Mock(return_value=completed),
                )

    def test_shared_admin_source_comes_only_from_trusted_parallels_xml(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "network.desktop.xml"
            path.write_text(
                "<ParallelsNetworkConfig><VirtualNetworks><VirtualNetwork>"
                "<NetworkID>Shared</NetworkID><Enabled>1</Enabled>"
                "<NetworkType>1</NetworkType><HostOnlyNetwork>"
                "<HostIPAddress>10.211.55.2</HostIPAddress>"
                "<ParallelsAdapter><Enabled>1</Enabled></ParallelsAdapter>"
                "</HostOnlyNetwork></VirtualNetwork></VirtualNetworks>"
                "</ParallelsNetworkConfig>",
                encoding="ascii",
            )
            path.chmod(0o644)
            self.assertEqual(
                MIGRATE.trusted_shared_admin_source(
                    path, expected_uid=os.geteuid(),
                ),
                "10.211.55.2",
            )
            path.chmod(0o664)
            with self.assertRaisesRegex(
                MIGRATE.MigrationError, "migration_shared_network_untrusted",
            ):
                MIGRATE.trusted_shared_admin_source(
                    path, expected_uid=os.geteuid(),
                )
            path.chmod(0o644)
            added = subprocess.run(
                ["/bin/chmod", "+a", "everyone allow write", str(path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
            if added.returncode == 0:
                try:
                    with self.assertRaisesRegex(
                        MIGRATE.MigrationError,
                        "migration_shared_network_untrusted",
                    ):
                        MIGRATE.trusted_shared_admin_source(
                            path, expected_uid=os.geteuid(),
                        )
                finally:
                    subprocess.run(
                        ["/bin/chmod", "-N", str(path)], check=False,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )


if __name__ == "__main__":
    unittest.main()
