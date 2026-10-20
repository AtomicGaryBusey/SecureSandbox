import unittest

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


if __name__ == "__main__":
    unittest.main()
