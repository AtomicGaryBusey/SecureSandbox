import unittest
from unittest import mock

import execution_mcp


class ExecutionMcpTests(unittest.TestCase):
    def test_lists_only_fixed_tool(self):
        response = execution_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual([tool["name"] for tool in response["result"]["tools"]], ["run_python_fixture"])

    def test_rejects_extra_argument(self):
        response = execution_mcp.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "run_python_fixture", "arguments": {"source_id": "x", "code": "x", "command": "sh"}},
        })
        self.assertEqual(response["error"]["message"], "invalid_arguments")

    def test_broker_timeout_covers_operator_approval_and_target_execution(self):
        connection = mock.Mock()
        connection.getresponse.side_effect = TimeoutError
        with mock.patch.object(execution_mcp.http.client, "HTTPConnection", return_value=connection) as constructor:
            response = execution_mcp.handle({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "run_python_fixture", "arguments": {
                    "source_id": "11111111-1111-4111-8111-111111111111", "code": "pass"}},
            })
        self.assertGreaterEqual(execution_mcp.BROKER_RESPONSE_TIMEOUT_SECONDS, 110)
        constructor.assert_called_once_with(
            "127.0.0.1", 18081, timeout=execution_mcp.BROKER_RESPONSE_TIMEOUT_SECONDS)
        self.assertEqual(response["result"]["structuredContent"], {"error": "execution_broker_unavailable"})

    def test_display_groups_digests_without_changing_structured_values(self):
        value={"stdout_sha256":"a"*64,"image_digest":"sha256:"+"b"*64,"stdout":"a"*64}
        rendered=execution_mcp.display_json(value)
        self.assertIn("aaaaaaaa aaaaaaaa",rendered)
        self.assertIn("sha256:bbbbbbbb bbbbbbbb",rendered)
        self.assertIn('"stdout":"'+"a"*64+'"',rendered)
        self.assertEqual(value["stdout_sha256"],"a"*64)


if __name__ == "__main__":
    unittest.main()
