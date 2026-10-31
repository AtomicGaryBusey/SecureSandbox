#!/usr/bin/env python3

import json
import unittest

import model_adapters as adapters


class AdapterTests(unittest.TestCase):
    def payload(self):
        return {
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Inspect it"},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "tool-1", "name": "read_file",
                     "input": {"path": "a.py"}},
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tool-1", "content": "safe"},
                ]},
            ],
            "model": "selected-model",
            "stream": True,
            "system": "System",
            "tool_choice": {"type": "auto"},
            "tools": [{"name": "read_file", "description": "Read one file",
                       "input_schema": {"type": "object"}}],
        }

    def test_anthropic_adapter_preserves_path_and_injects_profile_temperature(self):
        result = adapters.prepare_request(
            "anthropic-messages-v1", self.payload(),
            {"temperature_milli": 250}, "selected-model", True,
        )
        self.assertEqual(result.path, "/v1/messages")
        self.assertTrue(result.upstream_streaming)
        self.assertEqual(json.loads(result.body)["temperature"], 0.25)

    def test_openai_responses_translation_is_closed_and_nonstreaming_upstream(self):
        result = adapters.prepare_request(
            "openai-responses-v1", self.payload(),
            {"cyber_access": "daybreak_red", "reasoning_effort": "high",
             "temperature_milli": None}, "selected-model", True,
        )
        value = json.loads(result.body)
        self.assertEqual(result.path, "/v1/responses")
        self.assertFalse(result.upstream_streaming)
        self.assertEqual(value["access_programs"], {"cyber": "daybreak_red"})
        self.assertEqual(value["input"][3]["role"], "tool")
        self.assertEqual(value["tools"][0]["name"], "read_file")
        self.assertFalse(value["store"])

    def test_google_translation_constructs_exact_project_path(self):
        result = adapters.prepare_request(
            "google-openai-chat-v1", self.payload(),
            {"reasoning_effort": "medium", "temperature_milli": None},
            "google/gemini-3.8-flash-cyber", True,
            {"project_id": "secure-sandbox-cyber", "location": "global"},
        )
        self.assertEqual(
            result.path,
            "/v1beta1/projects/secure-sandbox-cyber/locations/global/endpoints/openapi/chat/completions",
        )
        self.assertEqual(json.loads(result.body)["reasoning_effort"], "medium")

    def test_translation_rejects_multimodal_and_unknown_blocks(self):
        for block in ({"type": "image", "source": {}}, {"type": "server_tool_use"}):
            payload = self.payload()
            payload["messages"] = [{"role": "user", "content": [block]}]
            with self.assertRaisesRegex(adapters.AdapterError, "not_allowed"):
                adapters.prepare_request(
                    "openai-responses-v1", payload,
                    {"cyber_access": "standard", "reasoning_effort": "low",
                     "temperature_milli": None}, "selected-model", False,
                )

    def test_responses_normalizes_text_and_local_tool_calls(self):
        raw = json.dumps({
            "id": "resp_1", "model": "selected-model", "status": "completed",
            "output": [
                {"type": "message", "role": "assistant",
                 "content": [{"type": "output_text", "text": "Result"}]},
                {"type": "function_call", "call_id": "call_1", "name": "read_file",
                 "arguments": "{\"path\":\"a.py\"}"},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 7},
        }).encode()
        result = adapters.normalize_response(
            "openai-responses-v1", raw, "selected-model", True,
        )
        self.assertEqual(result.output_tokens, 7)
        self.assertEqual(result.content_type, "text/event-stream")
        self.assertIn(b'event: content_block_start', result.body)
        self.assertIn(b'"name":"read_file"', result.body)
        self.assertIn(b'"stop_reason":"tool_use"', result.body)

    def test_google_chat_normalizes_usage_and_rejects_model_substitution(self):
        value = {
            "id": "chat_1", "model": "google/model", "choices": [{
                "finish_reason": "stop", "message": {"role": "assistant", "content": "Done"},
            }], "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
        result = adapters.normalize_response(
            "google-openai-chat-v1", json.dumps(value).encode(), "google/model", False,
        )
        self.assertEqual(result.output_tokens, 2)
        self.assertEqual(json.loads(result.body)["content"][0]["text"], "Done")
        value["model"] = "other"
        with self.assertRaisesRegex(adapters.AdapterError, "identity_invalid"):
            adapters.normalize_response(
                "google-openai-chat-v1", json.dumps(value).encode(), "google/model", False,
            )

    def test_unknown_finish_usage_and_nonobject_tool_arguments_fail_closed(self):
        base = {
            "id": "chat_1", "model": "google/model", "choices": [{
                "finish_reason": "content_filter", "message": {"role": "assistant", "content": ""},
            }], "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
        with self.assertRaisesRegex(adapters.AdapterError, "finish_reason_invalid"):
            adapters.normalize_response(
                "google-openai-chat-v1", json.dumps(base).encode(), "google/model", False,
            )
        base["choices"][0] = {"finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "tool_calls": [{
                "id": "x", "type": "function",
                "function": {"name": "tool", "arguments": "[]"},
            }]}}
        with self.assertRaisesRegex(adapters.AdapterError, "arguments_invalid"):
            adapters.normalize_response(
                "google-openai-chat-v1", json.dumps(base).encode(), "google/model", False,
            )


if __name__ == "__main__":
    unittest.main()
