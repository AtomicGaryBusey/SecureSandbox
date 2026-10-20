#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import claude_tool_auditor as auditor


class ToolRiskTests(unittest.TestCase):
    def test_detects_sandbox_bypass_without_retaining_command(self):
        record = {
            "type": "assistant",
            "uuid": "assistant-1",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu-1",
                        "name": "Bash",
                        "input": {
                            "command": "printf 'sensitive payload'",
                            "dangerouslyDisableSandbox": True,
                        },
                    }
                ]
            },
        }
        pending = {}
        events = auditor.process_record(record, pending)
        self.assertEqual(events[0]["event_type"], "sandbox_bypass_requested")
        self.assertEqual(events[0]["severity"], "critical")
        self.assertIn("command_sha256=", events[0]["message"])
        self.assertNotIn("sensitive", repr(events))
        self.assertIn("assistant-1", pending)

    def test_correlates_risky_approval(self):
        pending = {
            "assistant-1": [
                {"signal": "sandbox_bypass", "tool": "Bash", "tool_use_id": "toolu-1"}
            ]
        }
        record = {
            "permissionDecision": {"decision": "accept", "source": "user_temporary"},
            "sourceToolAssistantUUID": "assistant-1",
        }
        events = auditor.process_record(record, pending)
        self.assertEqual(events[0]["event_type"], "risky_tool_approval")
        self.assertEqual(events[0]["decision"], "accept")
        self.assertEqual(events[0]["severity"], "critical")
        self.assertNotIn("assistant-1", pending)

    def test_classifies_privilege_policy_and_tunnel_commands(self):
        cases = {
            "sudo id": "privilege_escalation",
            "nft list ruleset": "security_policy_change",
            "ssh -D 1080 example.invalid": "network_tunnel",
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                signals, command_hash = auditor.classify_tool_use(
                    {"input": {"command": command}}
                )
                self.assertIn(expected, signals)
                self.assertEqual(len(command_hash), 64)

    def test_ordinary_shell_command_has_no_risk_signal(self):
        signals, command_hash = auditor.classify_tool_use(
            {"input": {"command": "ls -la ./src"}}
        )
        self.assertEqual(signals, [])
        self.assertEqual(len(command_hash), 64)

    def test_scanner_bootstraps_existing_content_then_reads_appends(self):
        with tempfile.TemporaryDirectory() as directory:
            projects = Path(directory) / "projects"
            journal_directory = projects / "workspace"
            journal_directory.mkdir(parents=True)
            journal = journal_directory / "session.jsonl"
            journal.write_text(
                json.dumps({"type": "assistant", "message": {"content": []}}) + "\n",
                encoding="utf-8",
            )
            state = {"files": {}, "pending": {}}
            with mock.patch.object(auditor, "PROJECTS_ROOT", projects), \
                 mock.patch.object(auditor, "AGENT_UID", os.getuid()):
                self.assertEqual(auditor.scan_once(state, bootstrap=True), [])
                risk = {
                    "type": "assistant",
                    "uuid": "assistant-2",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu-2",
                                "name": "Bash",
                                "input": {
                                    "command": "secret command",
                                    "dangerouslyDisableSandbox": True,
                                },
                            }
                        ]
                    },
                }
                approval = {
                    "permissionDecision": {
                        "decision": "accept",
                        "source": "user_temporary",
                    },
                    "sourceToolAssistantUUID": "assistant-2",
                }
                with journal.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(risk) + "\n")
                    handle.write(json.dumps(approval) + "\n")
                events = auditor.scan_once(state)
            self.assertEqual(
                [event["event_type"] for event in events],
                ["sandbox_bypass_requested", "risky_tool_approval"],
            )
            self.assertNotIn("secret command", repr(events))


if __name__ == "__main__":
    unittest.main()
