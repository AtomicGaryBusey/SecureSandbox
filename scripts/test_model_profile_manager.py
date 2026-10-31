#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PATH = Path(__file__).with_name("model_profile_manager.py")
SPEC = importlib.util.spec_from_file_location("model_profile_manager", PATH)
manager = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(manager)


def plan():
    value = {"activation_id":"12345678-1234-4123-8123-123456789abc",
             "broker":{"adapter":"anthropic-messages-v1", "mode":"mock",
                       "allowed_models":["new-model"], "profile_id":"new-profile",
                       "profile_sha256":"a" * 64, "vendor_id":"new-vendor"},
             "created_at":1000,
             "expires_at":1300, "schema":"secure-sandbox-model-profile-activation-plan-v1"}
    value["plan_sha256"] = manager.hashlib.sha256(manager.canonical(value)).hexdigest()
    return value


class ManagerTests(unittest.TestCase):
    prior = {"adapter":"anthropic-messages-v1", "mode":"production",
             "model":"old-model", "profile_id":"old-profile",
             "profile_sha256":"b" * 64, "vendor_id":"old-vendor"}

    @staticmethod
    def desired(value):
        broker = value["broker"]
        return {"activation_id":value["activation_id"], "adapter":broker["adapter"],
                "mode":broker["mode"], "model":broker["allowed_models"][0],
                "plan_sha256":value["plan_sha256"], "profile_id":broker["profile_id"],
                "profile_sha256":broker["profile_sha256"], "status":"verified",
                "vendor_id":broker["vendor_id"]}

    def test_plan_digest_and_expiry_are_exact(self):
        value = plan()
        self.assertEqual(manager.validate_plan(json.dumps(value), now=1100), value)
        value["broker"]["profile_sha256"] = "b" * 64
        with self.assertRaises(ValueError): manager.validate_plan(json.dumps(value), now=1100)

    def test_research_failure_rolls_back_gateway(self):
        value = plan(); calls = []; states = {"gateway":dict(self.prior), "research":dict(self.prior)}
        def fake(_release, host, kind, operation, arguments=None, payload=None):
            calls.append((host, kind, operation, arguments))
            role = "gateway" if "gateway" in host else "research"
            if operation in {"model-profile-status", "model-profile-research-status"}:
                return states[role]
            if operation == "model-profile-activate" and role == "gateway":
                states[role] = self.desired(value); return self.desired(value)
            if host == "sandbox-research-control" and kind == "pipe":
                raise RuntimeError("research failed")
            if operation == "model-profile-rollback":
                states[role] = dict(self.prior)
            return {"status":"verified"}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(manager, "control", side_effect=fake), \
             mock.patch.object(manager, "RECEIPT", Path(directory) / "receipt.json"):
            with self.assertRaisesRegex(RuntimeError, "research failed"):
                manager.activate(value, Path("/release"), Path(directory) / "transactions",
                                 Path(directory) / "receipt.json")
        self.assertIn(("sandbox-gateway-control", "run", "model-profile-rollback",
                       [value["activation_id"]]), calls)

    def test_commit_is_durable_and_reopens_admission_only_after_exact_readback(self):
        value = plan(); calls = []; states = {"gateway":dict(self.prior), "research":dict(self.prior)}
        def fake(_release, host, kind, operation, arguments=None, payload=None):
            calls.append((host, kind, operation, arguments))
            role = "gateway" if "gateway" in host else "research"
            if operation in {"model-profile-status", "model-profile-research-status"}:
                return states[role]
            if operation == "model-profile-activate":
                states[role] = self.desired(value); return self.desired(value)
            return {"status":"verified"}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(manager, "control", side_effect=fake):
            root = Path(directory); receipt = root / "receipt.json"
            result = manager.activate(value, Path("/release"), root / "transactions", receipt)
            transaction = json.loads((root / "transactions" / f"{value['activation_id']}.json").read_text())
            self.assertEqual(transaction["phase"], "committed")
            self.assertEqual(json.loads(receipt.read_text()), result)
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        research_open = calls.index(("sandbox-research-control", "run",
                                     "model-profile-unfence", [value["activation_id"]]))
        gateway_open = calls.index(("sandbox-gateway-control", "run",
                                    "model-profile-unfence", [value["activation_id"]]))
        self.assertLess(research_open, gateway_open)


if __name__ == "__main__": unittest.main()
