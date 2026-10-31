#!/usr/bin/env python3
"""Closed model-provider adapters for the Gateway broker.

The Research relay always speaks the bounded Anthropic Messages shape.  These
pure-data adapters never execute tools or accept caller-selected routing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class AdapterError(ValueError):
    pass


@dataclass(frozen=True)
class PreparedRequest:
    path: str
    body: bytes
    accept: str
    upstream_streaming: bool


@dataclass(frozen=True)
class NormalizedResponse:
    body: bytes
    content_type: str
    output_tokens: int | None


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":"), sort_keys=True).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise AdapterError("adapter_json_invalid") from error


def _text_content(value: object, label: str) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        raise AdapterError(f"{label}_invalid")
    parts: list[str] = []
    for block in value:
        if not isinstance(block, dict) or set(block) - {"type", "text", "cache_control"}:
            raise AdapterError(f"{label}_invalid")
        if block.get("type") != "text" or not isinstance(block.get("text"), str):
            raise AdapterError(f"{label}_invalid")
        parts.append(block["text"])
    return "\n".join(parts)


def _tool_result_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        raise AdapterError("adapter_tool_result_invalid")
    parts = []
    for block in value:
        if (not isinstance(block, dict) or block.get("type") != "text"
                or not isinstance(block.get("text"), str)
                or set(block) - {"type", "text"}):
            raise AdapterError("adapter_tool_result_invalid")
        parts.append(block["text"])
    return "\n".join(parts)


def _openai_messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    system = payload.get("system")
    if system is not None:
        result.append({"content": _text_content(system, "adapter_system"), "role": "system"})
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise AdapterError("adapter_messages_invalid")
    for message in messages:
        if (not isinstance(message, dict) or set(message) != {"content", "role"}
                or message["role"] not in {"user", "assistant"}):
            raise AdapterError("adapter_message_invalid")
        role = message["role"]
        content = message["content"]
        if isinstance(content, str):
            result.append({"content": content, "role": role})
            continue
        if not isinstance(content, list):
            raise AdapterError("adapter_message_content_invalid")
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        tool_results: list[dict[str, str]] = []
        for block in content:
            if not isinstance(block, dict) or not isinstance(block.get("type"), str):
                raise AdapterError("adapter_content_block_invalid")
            kind = block["type"]
            if kind == "text" and set(block) <= {"type", "text", "cache_control"} \
                    and isinstance(block.get("text"), str):
                text_parts.append(block["text"])
            elif (kind == "tool_use" and role == "assistant"
                  and set(block) <= {"type", "id", "name", "input", "cache_control"}
                  and isinstance(block.get("id"), str) and isinstance(block.get("name"), str)
                  and isinstance(block.get("input"), dict)):
                tool_calls.append({
                    "function": {"arguments": _canonical(block["input"]).decode("ascii"),
                                 "name": block["name"]},
                    "id": block["id"], "type": "function",
                })
            elif (kind == "tool_result" and role == "user"
                  and set(block) <= {"type", "tool_use_id", "content", "is_error", "cache_control"}
                  and isinstance(block.get("tool_use_id"), str)
                  and isinstance(block.get("is_error", False), bool)):
                text = _tool_result_text(block.get("content", ""))
                if block.get("is_error"):
                    text = "Tool error: " + text
                tool_results.append({"content": text, "role": "tool",
                                     "tool_call_id": block["tool_use_id"]})
            else:
                raise AdapterError("adapter_content_block_not_allowed")
        if role == "assistant":
            item: dict[str, Any] = {"content": "\n".join(text_parts) or None, "role": role}
            if tool_calls:
                item["tool_calls"] = tool_calls
            result.append(item)
        else:
            if text_parts:
                result.append({"content": "\n".join(text_parts), "role": role})
            result.extend(tool_results)
            if not text_parts and not tool_results:
                raise AdapterError("adapter_empty_message_invalid")
    return result


def _openai_tools(payload: dict[str, Any]) -> list[dict[str, Any]] | None:
    tools = payload.get("tools")
    if tools is None:
        return None
    if not isinstance(tools, list) or len(tools) > 128:
        raise AdapterError("adapter_tools_invalid")
    result = []
    for tool in tools:
        if (not isinstance(tool, dict) or set(tool) - {"name", "description", "input_schema", "cache_control"}
                or not isinstance(tool.get("name"), str)
                or not isinstance(tool.get("input_schema"), dict)
                or ("description" in tool and not isinstance(tool["description"], str))):
            raise AdapterError("adapter_tool_invalid")
        function = {"name": tool["name"], "parameters": tool["input_schema"]}
        if tool.get("description"):
            function["description"] = tool["description"]
        result.append({"function": function, "type": "function"})
    return result


def _openai_tool_choice(value: object) -> object:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"type", "name", "disable_parallel_tool_use"}:
        raise AdapterError("adapter_tool_choice_invalid")
    kind = value.get("type")
    if kind == "auto":
        return "auto"
    if kind == "any":
        return "required"
    if kind == "tool" and isinstance(value.get("name"), str):
        return {"function": {"name": value["name"]}, "type": "function"}
    raise AdapterError("adapter_tool_choice_invalid")


def prepare_request(adapter: str, payload: dict[str, Any], settings: dict[str, Any],
                    model_id: str, client_streaming: bool,
                    deployment: dict[str, str] | None = None) -> PreparedRequest:
    if adapter == "anthropic-messages-v1":
        outgoing = dict(payload)
        outgoing["model"] = model_id
        if settings.get("temperature_milli") is None:
            outgoing.pop("temperature", None)
        else:
            outgoing["temperature"] = settings["temperature_milli"] / 1000
        return PreparedRequest("/v1/messages", _canonical(outgoing),
                               "text/event-stream" if client_streaming else "application/json",
                               client_streaming)
    messages = _openai_messages(payload)
    tools = _openai_tools(payload)
    tool_choice = _openai_tool_choice(payload.get("tool_choice"))
    temperature = settings.get("temperature_milli")
    if adapter == "openai-responses-v1":
        outgoing = {
            "access_programs": {"cyber": settings["cyber_access"]},
            "input": messages,
            "max_output_tokens": payload["max_tokens"],
            "model": model_id,
            "reasoning": {"effort": settings["reasoning_effort"]},
            "store": False,
            "stream": False,
        }
        if tools is not None:
            outgoing["tools"] = [item["function"] | {"type": "function"} for item in tools]
        if tool_choice is not None:
            outgoing["tool_choice"] = tool_choice
        if temperature is not None:
            outgoing["temperature"] = temperature / 1000
        return PreparedRequest("/v1/responses", _canonical(outgoing), "application/json", False)
    if adapter == "google-openai-chat-v1":
        if not isinstance(deployment, dict) or set(deployment) != {"project_id", "location"}:
            raise AdapterError("adapter_google_deployment_invalid")
        outgoing = {
            "messages": messages,
            "max_completion_tokens": payload["max_tokens"],
            "model": model_id,
            "reasoning_effort": settings["reasoning_effort"],
            "stream": False,
        }
        if tools is not None:
            outgoing["tools"] = tools
        if tool_choice is not None:
            outgoing["tool_choice"] = tool_choice
        if temperature is not None:
            outgoing["temperature"] = temperature / 1000
        path = (f"/v1beta1/projects/{deployment['project_id']}/locations/"
                f"{deployment['location']}/endpoints/openapi/chat/completions")
        return PreparedRequest(path, _canonical(outgoing), "application/json", False)
    raise AdapterError("adapter_not_supported")


def _finish_reason(value: object) -> str:
    mapping = {"stop": "end_turn", "completed": "end_turn", "tool_calls": "tool_use",
               "length": "max_tokens", "max_output_tokens": "max_tokens"}
    if value not in mapping:
        raise AdapterError("adapter_finish_reason_invalid")
    return mapping[value]


def _arguments(value: object) -> dict[str, Any]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024 * 1024:
        raise AdapterError("adapter_tool_arguments_invalid")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise AdapterError("adapter_tool_arguments_invalid") from error
    if not isinstance(parsed, dict):
        raise AdapterError("adapter_tool_arguments_invalid")
    return parsed


def _anthropic_message(model_id: str, message_id: str, blocks: list[dict[str, Any]],
                       stop_reason: str, input_tokens: int,
                       output_tokens: int) -> dict[str, Any]:
    return {
        "content": blocks,
        "id": message_id,
        "model": model_id,
        "role": "assistant",
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "type": "message",
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }


def _nonnegative(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AdapterError(f"{label}_invalid")
    return value


def _normalize_responses(value: dict[str, Any], model_id: str) -> tuple[dict[str, Any], int]:
    if value.get("model") != model_id or not isinstance(value.get("id"), str):
        raise AdapterError("adapter_response_identity_invalid")
    output = value.get("output")
    if not isinstance(output, list) or len(output) > 256:
        raise AdapterError("adapter_response_output_invalid")
    blocks: list[dict[str, Any]] = []
    saw_tool = False
    for item in output:
        if not isinstance(item, dict):
            raise AdapterError("adapter_response_item_invalid")
        if item.get("type") == "message" and item.get("role") == "assistant":
            content = item.get("content")
            if not isinstance(content, list):
                raise AdapterError("adapter_response_content_invalid")
            for part in content:
                if (not isinstance(part, dict) or part.get("type") != "output_text"
                        or not isinstance(part.get("text"), str)):
                    raise AdapterError("adapter_response_content_invalid")
                blocks.append({"text": part["text"], "type": "text"})
        elif (item.get("type") == "function_call" and isinstance(item.get("call_id"), str)
              and isinstance(item.get("name"), str)):
            blocks.append({"id": item["call_id"], "input": _arguments(item.get("arguments")),
                           "name": item["name"], "type": "tool_use"})
            saw_tool = True
        else:
            raise AdapterError("adapter_response_item_invalid")
    usage = value.get("usage")
    if not isinstance(usage, dict):
        raise AdapterError("adapter_response_usage_invalid")
    input_tokens = _nonnegative(usage.get("input_tokens"), "adapter_input_tokens")
    output_tokens = _nonnegative(usage.get("output_tokens"), "adapter_output_tokens")
    reason = "tool_use" if saw_tool else _finish_reason(value.get("status"))
    return _anthropic_message(model_id, value["id"], blocks, reason,
                              input_tokens, output_tokens), output_tokens


def _normalize_chat(value: dict[str, Any], model_id: str) -> tuple[dict[str, Any], int]:
    if value.get("model") != model_id or not isinstance(value.get("id"), str):
        raise AdapterError("adapter_response_identity_invalid")
    choices = value.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise AdapterError("adapter_choices_invalid")
    choice = choices[0]
    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise AdapterError("adapter_chat_message_invalid")
    blocks: list[dict[str, Any]] = []
    content = message.get("content")
    if content is not None:
        if not isinstance(content, str):
            raise AdapterError("adapter_chat_content_invalid")
        blocks.append({"text": content, "type": "text"})
    calls = message.get("tool_calls", [])
    if not isinstance(calls, list) or len(calls) > 128:
        raise AdapterError("adapter_chat_tool_calls_invalid")
    for call in calls:
        function = call.get("function") if isinstance(call, dict) else None
        if (not isinstance(call, dict) or call.get("type") != "function"
                or not isinstance(call.get("id"), str) or not isinstance(function, dict)
                or not isinstance(function.get("name"), str)):
            raise AdapterError("adapter_chat_tool_call_invalid")
        blocks.append({"id": call["id"], "input": _arguments(function.get("arguments")),
                       "name": function["name"], "type": "tool_use"})
    usage = value.get("usage")
    if not isinstance(usage, dict):
        raise AdapterError("adapter_response_usage_invalid")
    input_tokens = _nonnegative(usage.get("prompt_tokens"), "adapter_input_tokens")
    output_tokens = _nonnegative(usage.get("completion_tokens"), "adapter_output_tokens")
    return _anthropic_message(model_id, value["id"], blocks,
                              _finish_reason(choice.get("finish_reason")), input_tokens,
                              output_tokens), output_tokens


def anthropic_sse(message: dict[str, Any]) -> bytes:
    events: list[tuple[str, dict[str, Any]]] = []
    start = dict(message)
    blocks = start.pop("content")
    stop_reason = start.pop("stop_reason")
    start["content"] = []
    start["stop_reason"] = None
    start["usage"] = {"input_tokens": message["usage"]["input_tokens"], "output_tokens": 0}
    events.append(("message_start", {"message": start, "type": "message_start"}))
    for index, block in enumerate(blocks):
        if block["type"] == "text":
            initial = {"text": "", "type": "text"}
            delta = {"text": block["text"], "type": "text_delta"}
        elif block["type"] == "tool_use":
            initial = {"id": block["id"], "input": {}, "name": block["name"], "type": "tool_use"}
            delta = {"partial_json": _canonical(block["input"]).decode("ascii"),
                     "type": "input_json_delta"}
        else:
            raise AdapterError("adapter_anthropic_block_invalid")
        events.extend([
            ("content_block_start", {"content_block": initial, "index": index,
                                     "type": "content_block_start"}),
            ("content_block_delta", {"delta": delta, "index": index,
                                     "type": "content_block_delta"}),
            ("content_block_stop", {"index": index, "type": "content_block_stop"}),
        ])
    events.append(("message_delta", {
        "delta": {"stop_reason": stop_reason, "stop_sequence": None},
        "type": "message_delta", "usage": {"output_tokens": message["usage"]["output_tokens"]},
    }))
    events.append(("message_stop", {"type": "message_stop"}))
    return b"".join(
        f"event: {name}\ndata: {_canonical(value).decode('ascii')}\n\n".encode("ascii")
        for name, value in events
    )


def normalize_response(adapter: str, raw: bytes, model_id: str,
                       client_streaming: bool) -> NormalizedResponse:
    if adapter == "anthropic-messages-v1":
        return NormalizedResponse(raw, "text/event-stream" if client_streaming else "application/json", None)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterError("adapter_response_json_invalid") from error
    if not isinstance(value, dict):
        raise AdapterError("adapter_response_json_invalid")
    if adapter == "openai-responses-v1":
        message, output_tokens = _normalize_responses(value, model_id)
    elif adapter == "google-openai-chat-v1":
        message, output_tokens = _normalize_chat(value, model_id)
    else:
        raise AdapterError("adapter_not_supported")
    if client_streaming:
        return NormalizedResponse(anthropic_sse(message), "text/event-stream", output_tokens)
    return NormalizedResponse(_canonical(message), "application/json", output_tokens)
