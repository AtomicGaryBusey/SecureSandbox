#!/usr/bin/env python3

import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


PATH = Path(__file__).with_name("model_profile_manager.py")
SPEC = importlib.util.spec_from_file_location("model_profile_manager", PATH)
manager = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(manager)


def plan():
    value = {"activation_id":"12345678-1234-4123-8123-123456789abc",
             "broker":{"profile_sha256":"a" * 64}, "created_at":1000,
             "expires_at":1300, "schema":"secure-sandbox-model-profile-activation-plan-v1"}
    value["plan_sha256"] = manager.hashlib.sha256(manager.canonical(value)).hexdigest()
    return value


class ManagerTests(unittest.TestCase):
    def test_plan_digest_and_expiry_are_exact(self):
        value = plan()
        self.assertEqual(manager.validate_plan(json.dumps(value), now=1100), value)
        value["broker"]["profile_sha256"] = "b" * 64
        with self.assertRaises(ValueError): manager.validate_plan(json.dumps(value), now=1100)

    def test_research_failure_rolls_back_gateway(self):
        value = plan(); calls = []
        def fake(_release, host, kind, operation, arguments=None, payload=None):
            calls.append((host, kind, operation, arguments))
            if host == "sandbox-research-control" and kind == "pipe":
                raise RuntimeError("research failed")
            return {"status":"verified"}
        with mock.patch.object(manager, "control", side_effect=fake):
            with self.assertRaises(RuntimeError): manager.activate(value, Path("/release"))
        self.assertIn(("sandbox-gateway-control", "run", "model-profile-rollback",
                       [value["activation_id"]]), calls)


if __name__ == "__main__": unittest.main()
