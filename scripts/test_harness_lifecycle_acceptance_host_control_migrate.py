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
    @staticmethod
    def rules(address, *, host_control):
        return f"{address}:{host_control}".encode()

    @staticmethod
    def digest(value):
        import hashlib
        return hashlib.sha256(value).hexdigest()


def transport_result(status="installed"):
    predecessor = "1" * 64
    return {
        "schema": "secure-sandbox-gateway-host-control-transport-v1",
        "status": status,
        "predecessor_sha256": predecessor,
        "successor_sha256": "2" * 64,
        "backup_sha256": predecessor if status == "installed" else None,
        "host_control_address": "172.30.10.30",
        "authority": "guest-firewall-only",
    }


class HostControlMigrationTests(unittest.TestCase):
    def test_validates_exact_transport_result(self):
        self.assertEqual(
            MIGRATE.validate_result(
                transport_result(), FakeTransport,
            )["status"],
            "installed",
        )
        for mutation in (
            {"authority": "guest-self-report"},
            {"host_control_address": "172.30.10.29"},
            {"successor_sha256": "1" * 64},
            {"backup_sha256": None},
        ):
            value = {**transport_result(), **mutation}
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                MIGRATE.MigrationError, "migration_result_invalid"
            ):
                MIGRATE.validate_result(value, FakeTransport)

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
        self.assertEqual(command[9:12], [
            "deploy", "install-gateway-host-control-transport.sh", "--file",
        ])
        self.assertEqual(command[12], str(installer))
        self.assertEqual(command[13:], ["--file", str(payload)])
        self.assertEqual(lifecycle.observations, [])
        with self.assertRaises(OSError):
            os.fstat(lifecycle.lock)

    def test_rejects_state_drift_before_deployment(self):
        observed = {**MIGRATE.EXPECTED_INITIAL, "gateway_net0": "disconnected"}
        lifecycle = FakeLifecycle((observed,))
        runner = mock.Mock()
        with (mock.patch.object(MIGRATE.os, "geteuid", return_value=501),
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

    def test_rejects_noncanonical_request_id_before_deployment(self):
        observed = dict(MIGRATE.EXPECTED_INITIAL)
        lifecycle = FakeLifecycle((observed,))
        runner = mock.Mock()
        with (mock.patch.object(MIGRATE.os, "geteuid", return_value=501),
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


if __name__ == "__main__":
    unittest.main()
