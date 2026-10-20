import base64
import unittest
import uuid

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
