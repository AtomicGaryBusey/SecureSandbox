import base64
import json
import os
import stat
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

import execution_service as service


def request(**changes):
    value = {
        "schema": "secure-sandbox-execution-request-v1",
        "request_id": str(uuid.uuid4()),
        "source_id": str(uuid.uuid4()),
        "code_b64": base64.b64encode(b"print(42)").decode(),
        "fixtures": [],
        "timeout_seconds": 5,
    }
    value.update(changes)
    return value


class ExecutionServiceTests(unittest.TestCase):
    def test_config_must_be_root_owned_and_group_read_only(self):
        config = {
            "schema": "secure-sandbox-execution-target-v1",
            "image_id": "sha256:" + "a" * 64,
            "token": "b" * 64,
        }
        trusted = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=os.getgid(), st_nlink=1)
        with mock.patch.object(service.os, "stat", return_value=trusted), \
                mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(config))):
            self.assertEqual(service.load_config(), config)
        untrusted = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid(),
            st_gid=os.getgid(), st_nlink=1)
        with mock.patch.object(service.os, "stat", return_value=untrusted):
            with self.assertRaisesRegex(RuntimeError, "unsafe_config"):
                service.load_config()

    def test_valid_request(self):
        code, fixtures, timeout, _, _ = service.validate_request(request())
        self.assertEqual(code, b"print(42)")
        self.assertEqual(fixtures, [])
        self.assertEqual(timeout, 5)

    def test_rejects_unsafe_fixture_path(self):
        fixture = {"path": "../etc/passwd", "content_b64": "", "sha256": service.hashlib.sha256(b"").hexdigest()}
        with self.assertRaisesRegex(service.Rejected, "unsafe_fixture_path"):
            service.validate_request(request(fixtures=[fixture]))

    def test_rejects_unknown_field(self):
        with self.assertRaisesRegex(service.Rejected, "invalid_request"):
            service.validate_request(request(command="sh"))

    def test_rejects_excessive_timeout(self):
        with self.assertRaisesRegex(service.Rejected, "invalid_timeout"):
            service.validate_request(request(timeout_seconds=11))


if __name__ == "__main__":
    unittest.main()
