#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import run_lease_process


class RunLeaseProcessTests(unittest.TestCase):
    def test_requires_marker_and_fixed_command(self):
        run_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"; marker.write_text(run_id + "\n")
            command = [run_id, run_lease_process.CLAUDE,
                       "--append-system-prompt-file", "/etc/claude-code/secure-sandbox-persona.md",
                       "--disable-slash-commands", "--no-chrome", "--restricted", "--permission-mode", "manual"]
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker):
                self.assertEqual(run_lease_process.validate_arguments(command)[0], run_id)
                with self.assertRaises(ValueError):
                    run_lease_process.validate_arguments([run_id, "/bin/sh"])
                marker.write_text(str(uuid.uuid4()) + "\n")
                with self.assertRaises(PermissionError):
                    run_lease_process.validate_arguments(command)

    def test_resume_uuid_is_validated(self):
        run_id = str(uuid.uuid4()); session_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"; marker.write_text(run_id + "\n")
            base = [run_id, run_lease_process.CLAUDE,
                    "--append-system-prompt-file", "/etc/claude-code/secure-sandbox-persona.md",
                    "--disable-slash-commands", "--no-chrome", "--restricted", "--permission-mode", "manual", "--resume"]
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker):
                self.assertEqual(run_lease_process.validate_arguments(base + [session_id])[1][-1], session_id)
                with self.assertRaises(ValueError): run_lease_process.validate_arguments(base + ["invalid"])

    def test_invoker_must_be_exact_agent_sudo_identity(self):
        agent = type("Agent", (), {"pw_uid": 1000, "pw_gid": 1000})()
        environment = {"SUDO_USER": "agent", "SUDO_UID": "1000", "SUDO_GID": "1000"}
        with mock.patch("run_lease_process.os.geteuid", return_value=0), \
                mock.patch.dict(os.environ, environment, clear=True):
            run_lease_process.validate_invoker(agent)
        with mock.patch("run_lease_process.os.geteuid", return_value=0), \
                mock.patch.dict(os.environ, {**environment, "SUDO_UID": "1001"}, clear=True):
            with self.assertRaises(PermissionError):
                run_lease_process.validate_invoker(agent)

    def test_scope_command_is_non_delegated_bounded_and_uses_fixed_unit(self):
        run_id = str(uuid.uuid4())
        agent = type("Agent", (), {"pw_name":"agent","pw_uid":1001,"pw_gid":1001,
                                    "pw_dir":"/home/agent"})()
        command = [run_lease_process.CLAUDE, "--restricted"]
        scoped = run_lease_process.scope_command(agent, run_id, command)
        self.assertIn(f"--unit=secure-sandbox-run-{run_id}.scope", scoped)
        self.assertIn("--property=Delegate=no", scoped)
        self.assertIn("--property=KillMode=control-group", scoped)
        self.assertIn("--property=SendSIGKILL=yes", scoped)
        self.assertNotIn("--uid=agent", scoped)
        payload = scoped[scoped.index(run_lease_process.SETPRIV):]
        self.assertEqual(payload[:9], [run_lease_process.SETPRIV, "--reuid=1001",
                                      "--regid=1001", "--clear-groups",
                                      "--inh-caps=-all", "--ambient-caps=-all",
                                      "--bounding-set=-all", "--no-new-privs", "--"])
        self.assertEqual(payload[9:], command)

    def test_rejected_duplicate_does_not_remove_existing_registration(self):
        """A rejected invocation cannot mutate the existing registration."""
        registration = {"supervisor_pid":42,"supervisor_start_time":100}
        self.assertTrue(run_lease_process.registration_belongs_to(registration, 42, 100))
        self.assertFalse(run_lease_process.registration_belongs_to(registration, 43, 100))
        self.assertFalse(run_lease_process.registration_belongs_to(registration, 42, 101))
        source = Path(run_lease_process.__file__).read_text(encoding="utf-8")
        self.assertIn("if claimed:", source)
        self.assertNotIn("PROCESS_FILE.unlink()", source)

    def test_root_state_loader_rejects_writable_or_wrong_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps({"schema": "expected"}) + "\n")
            path.chmod(0o644)
            with mock.patch.object(os, "getuid", return_value=0):
                with self.assertRaises(PermissionError):
                    run_lease_process.load_root_json(path, "expected")
            path.chmod(0o600)
            with mock.patch("pathlib.Path.lstat") as metadata:
                metadata.return_value = type("Metadata", (), {
                    "st_mode": __import__("stat").S_IFREG | 0o600,
                    "st_uid": 0,
                    "st_nlink": 1,
                })()
                with self.assertRaises(ValueError):
                    run_lease_process.load_root_json(path, "wrong")


if __name__ == "__main__": unittest.main()
