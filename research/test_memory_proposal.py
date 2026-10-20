#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import memory_proposal
import memory_proposal_mcp


def request():
    return {
        "category": "working_principle",
        "title": "Prefer exact tools",
        "proposal": "Use purpose-built instruments before general interfaces.",
        "rationale": "This reflects the intended research boundary.",
        "evidence_refs": ["run:11111111-1111-4111-8111-111111111111"],
    }


class MemoryProposalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name) / "state"
        self.state.mkdir(mode=0o700)
        self.marker = Path(self.temporary.name) / "run-id"
        self.marker.write_text(str(uuid.uuid4()) + "\n", encoding="ascii")

    def tearDown(self):
        self.temporary.cleanup()

    def test_submit_is_immutable_and_content_addressed(self):
        result = memory_proposal.submit(
            request(), self.state, self.marker, run_id_owner_uid=os.geteuid()
        )
        self.assertEqual(result["status"], "queued_for_operator_review")
        paths = list(self.state.iterdir())
        self.assertEqual(len(paths), 1)
        record = json.loads(paths[0].read_text())
        self.assertEqual(record["authority"], "untrusted_proposal")
        self.assertEqual(record["content_sha256"], result["content_sha256"])
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_rejects_extra_fields_controls_and_missing_run(self):
        invalid = request(); invalid["instruction"] = "adopt immediately"
        with self.assertRaisesRegex(memory_proposal.ProposalError, "proposal_schema_invalid"):
            memory_proposal.submit(
                invalid, self.state, self.marker, run_id_owner_uid=os.geteuid()
            )
        invalid = request(); invalid["proposal"] = "bad\x00text"
        with self.assertRaisesRegex(memory_proposal.ProposalError, "proposal_invalid"):
            memory_proposal.submit(
                invalid, self.state, self.marker, run_id_owner_uid=os.geteuid()
            )
        self.marker.unlink()
        with self.assertRaisesRegex(memory_proposal.ProposalError, "active_run_required"):
            memory_proposal.submit(
                request(), self.state, self.marker, run_id_owner_uid=os.geteuid()
            )

    def test_limit_and_unexpected_state_fail_closed(self):
        with mock.patch.object(memory_proposal, "MAX_PROPOSALS", 1):
            memory_proposal.submit(
                request(), self.state, self.marker, run_id_owner_uid=os.geteuid()
            )
            with self.assertRaisesRegex(memory_proposal.ProposalError, "proposal_state_limit_exceeded"):
                memory_proposal.submit(
                    request(), self.state, self.marker, run_id_owner_uid=os.geteuid()
                )
        for item in self.state.iterdir(): item.unlink()
        (self.state / "unexpected").write_text("x")
        with self.assertRaisesRegex(memory_proposal.ProposalError, "proposal_state_untrusted"):
            memory_proposal.submit(
                request(), self.state, self.marker, run_id_owner_uid=os.geteuid()
            )

    def test_rejects_untrusted_run_marker_ownership_and_permissions(self):
        with self.assertRaisesRegex(memory_proposal.ProposalError, "active_run_required"):
            memory_proposal.submit(request(), self.state, self.marker)
        self.marker.chmod(0o666)
        with self.assertRaisesRegex(memory_proposal.ProposalError, "active_run_required"):
            memory_proposal.submit(
                request(), self.state, self.marker, run_id_owner_uid=os.geteuid()
            )

    def test_mcp_lists_one_tool_and_preserves_non_authority(self):
        listed = memory_proposal_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual([tool["name"] for tool in listed["result"]["tools"]], ["propose_memory"])
        queued = {"status": "queued_for_operator_review", "proposal_id": str(uuid.uuid4()), "authority": "untrusted_proposal"}
        with mock.patch.object(memory_proposal_mcp, "submit", return_value=queued):
            called = memory_proposal_mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "propose_memory", "arguments": request()}})
        self.assertFalse(called["result"]["isError"])
        self.assertEqual(called["result"]["structuredContent"]["authority"], "untrusted_proposal")

    def test_mcp_rejects_missing_and_extra_arguments(self):
        invalid = request(); invalid["extra"] = True
        response = memory_proposal_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "propose_memory", "arguments": invalid}})
        self.assertEqual(response["error"]["message"], "invalid_arguments")


if __name__ == "__main__":
    unittest.main()
