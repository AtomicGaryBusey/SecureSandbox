#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_operation", ROOT / "scripts/harness-lifecycle-operation.py"
)
assert SPEC and SPEC.loader
OPERATION = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(OPERATION)


class HarnessLifecycleOperationTests(unittest.TestCase):
    def test_activation_frame_binds_exact_five_files_in_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); generation = "a" * 64
            files = {"artifact":b"binary", "manifest.json":json.dumps(
                {"generation_id":generation}).encode(), "verification.json":b"{}\n",
                "qualification.json":b"{}\n", "adapter.json":b"{}\n"}
            for name, data in files.items():
                (root / name).write_bytes(data); (root / name).chmod(0o600)
            captured = {}
            def control(_kind, _operation, _args=None, payload=None, timeout=0):
                captured["payload"] = payload
                return {"schema":OPERATION.WRAPPER_SCHEMA}
            with mock.patch.object(OPERATION, "control", side_effect=control):
                OPERATION.plan_activate(root)
            payload = captured["payload"]; length = struct.unpack(">I", payload[:4])[0]
            header = json.loads(payload[4:4 + length])
            self.assertEqual([item["name"] for item in header["files"]], list(OPERATION.SAFE_FILES))
            self.assertEqual(header["generation_id"], generation)
            self.assertEqual(payload[4 + length:], b"".join(files[name] for name in OPERATION.SAFE_FILES))

    def test_authorization_uses_protected_broker_and_requires_host_result(self):
        wrapper = {"schema":OPERATION.WRAPPER_SCHEMA}
        result = {"schema":"secure-sandbox-harness-lifecycle-host-result-v1"}
        completed = subprocess.CompletedProcess([], 0, json.dumps(result).encode(), b"")
        with mock.patch.object(OPERATION.subprocess, "run", return_value=completed) as run:
            self.assertEqual(OPERATION.submit("activate", wrapper, "Codex", "thread"), result)
        command = run.call_args.args[0]
        self.assertEqual(command[0], str(OPERATION.BROKER))
        self.assertIn("harness-generation-activate", command)
        self.assertIn("Protected Research harness generation selector", command)

    def test_management_plan_hashes_reason_and_binds_advisory_session_count(self):
        generation = "a" * 64; observed = {}
        def control(kind, operation, args=None, payload=None, timeout=0):
            observed.update(kind=kind, operation=operation, args=args)
            return {"schema":OPERATION.WRAPPER_SCHEMA}
        with (mock.patch.object(OPERATION, "control", side_effect=control),
              mock.patch.object(OPERATION, "session_count", return_value=2)):
            OPERATION.plan_management("revoke", generation, "security incident")
        self.assertEqual(observed["operation"], "harness-lifecycle-plan-management")
        self.assertEqual(observed["args"], ["revoke", generation,
                         hashlib.sha256(b"security incident").hexdigest(), "2"])

    def test_candidate_files_must_be_single_owner_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact"; path.write_bytes(b"x"); path.chmod(0o666)
            with self.assertRaisesRegex(OPERATION.OperationError, "candidate_file_untrusted"):
                OPERATION.trusted_read(path, 10)


if __name__ == "__main__":
    unittest.main()
