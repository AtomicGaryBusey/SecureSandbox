#!/usr/bin/env python3
"""Narrow, deny-by-default model API broker for the SecureSandbox Gateway."""

from __future__ import annotations

import argparse
import collections
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import run_lease


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle, parse_constant=_reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError("configuration must be a JSON object")
    return value


def validate_global_addresses(hostname: str, port: int) -> list[str]:
    addresses: list[str] = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(
        hostname, port, type=socket.SOCK_STREAM
    ):
        if family != socket.AF_INET:
            raise ValueError("only IPv4 upstreams are permitted")
        address = sockaddr[0]
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError(f"upstream resolved to non-global address: {address}")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("upstream produced no usable addresses")
    return addresses


def contains_forbidden_remote_tool(payload: dict) -> bool:
    for tool in payload.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        tool_type = str(tool.get("type", "")).lower()
        tool_name = str(tool.get("name", "")).lower()
        # Claude Code client tools have no server-executed type (or explicitly
        # use "custom").  Any other typed tool could execute outside the VM.
        if tool_type and tool_type != "custom":
            return True
        if tool_name in {"web_search", "web_fetch", "code_execution", "computer"}:
            return True
    return False


def contains_image_input(payload: dict) -> bool:
    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "image":
                return True
    return False


def canonical_request_id(value: str | None) -> str:
    if not value:
        raise ValueError("request ID is required")
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError("request ID must be a canonical UUIDv4")
    return str(parsed)


def canonical_run_id(value: str | None) -> str:
    if value in {"preflight", "boundary-test"}:
        return value
    if not value:
        raise ValueError("run ID is required")
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError("run ID must be a canonical UUIDv4")
    return str(parsed)


def usage_output_tokens(value: object) -> int | None:
    if not isinstance(value, dict):
        return None
    candidates = [value.get("usage")]
    message = value.get("message")
    if isinstance(message, dict):
        candidates.append(message.get("usage"))
    for usage in candidates:
        if isinstance(usage, dict):
            tokens = usage.get("output_tokens")
            if isinstance(tokens, int) and not isinstance(tokens, bool) and tokens >= 0:
                return tokens
    return None


class StreamingUsage:
    """Extract content-free cumulative usage from a bounded Anthropic SSE stream."""

    def __init__(self) -> None:
        self.buffer = b""
        self.output_tokens: int | None = None

    def feed(self, chunk: bytes) -> None:
        self.buffer += chunk
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            self._line(line.rstrip(b"\r"))

    def finish(self) -> int | None:
        if self.buffer:
            self._line(self.buffer.rstrip(b"\r"))
            self.buffer = b""
        return self.output_tokens

    def _line(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return
        try:
            value = json.loads(
                line[5:].strip().decode("utf-8"), parse_constant=_reject_json_constant
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return
        tokens = usage_output_tokens(value)
        if tokens is not None:
            self.output_tokens = (
                tokens if self.output_tokens is None else max(self.output_tokens, tokens)
            )


def response_output_tokens(response: bytes, response_type: str) -> int | None:
    if response_type == "text/event-stream":
        usage = StreamingUsage()
        usage.feed(response)
        return usage.finish()
    try:
        value = json.loads(
            response.decode("utf-8"), parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None
    return usage_output_tokens(value)


class FixedAddressHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS with a validated numeric destination and the original TLS name."""

    def __init__(self, hostname: str, address: str, port: int, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout)
        self._validated_address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._validated_address, self.port), self.timeout
        )
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class SlidingWindowLimiter:
    def __init__(self, limit: int, seconds: int):
        self.limit = limit
        self.seconds = seconds
        self._events: dict[str, collections.deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, identity: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.seconds
        with self._lock:
            events = self._events.setdefault(identity, collections.deque())
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


class BrokerHTTPServer(HTTPServer):
    # SO_REUSEADDR permits immediate rebinding across controlled service
    # restarts; it does not permit a second live listener without SO_REUSEPORT.
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: dict):
        super().__init__(address, BrokerHandler)
        self.config = config
        self.limiter = SlidingWindowLimiter(
            int(config["rate_limit_requests"]),
            int(config["rate_limit_window_seconds"]),
        )
        self.lease_store = run_lease.LeaseStore(
            Path(config["lease_state_directory"]),
            Path("/etc/secure-sandbox/run-lease-profiles.json"),
            Path("/etc/secure-sandbox/broker.json"),
            Path("/etc/secure-sandbox/policy.sha256"),
        )


class BrokerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SecureSandboxBroker/1"
    sys_version = ""

    @property
    def broker(self) -> BrokerHTTPServer:
        return self.server  # type: ignore[return-value]

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(float(self.broker.config["client_timeout_seconds"]))

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _audit(self, event: str, **fields: object) -> None:
        record = {
            "ts": int(time.time()),
            "event": event,
            "source": self.client_address[0],
            **fields,
        }
        print(json.dumps(record, separators=(",", ":"), sort_keys=True), flush=True)

    def _identity(self) -> str:
        certificate = self.connection.getpeercert(binary_form=True)
        if not certificate:
            raise PermissionError("client certificate required")
        fingerprint = hashlib.sha256(certificate).hexdigest()
        allowed = self.broker.config["allowed_client_sha256"]
        if fingerprint not in allowed:
            raise PermissionError("client certificate is not allowlisted")
        return fingerprint

    def _reply_json(self, status: int, value: dict) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _deny(
        self, status: int, code: str, request_id: str, run_id: str = "preflight"
    ) -> None:
        self._audit(
            "request_denied",
            request_id=request_id,
            run_id=run_id,
            code=code,
            status=status,
        )
        self._reply_json(status, {"error": {"code": code}, "request_id": request_id})

    def _correlation_context(self) -> tuple[str, str]:
        return (
            canonical_request_id(self.headers.get("X-Sandbox-Request-Id")),
            canonical_run_id(self.headers.get("X-Sandbox-Run-Id")),
        )

    def do_GET(self) -> None:
        request_id = str(uuid.uuid4())
        run_id = "preflight"
        try:
            identity = self._identity()
        except PermissionError:
            self._deny(403, "client_not_authorized", request_id, run_id)
            return
        try:
            request_id, run_id = self._correlation_context()
        except ValueError:
            self._deny(400, "invalid_correlation_header", request_id, run_id)
            return
        if self.path != "/healthz":
            self._deny(404, "path_not_allowed", request_id, run_id)
            return
        self._audit("health", request_id=request_id, run_id=run_id, client=identity[:16])
        self._reply_json(200, {"status": "ok", "mode": self.broker.config["mode"]})

    def do_CONNECT(self) -> None:
        self._deny(405, "connect_not_allowed", str(uuid.uuid4()))

    def do_PUT(self) -> None:
        self._deny(405, "method_not_allowed", str(uuid.uuid4()))

    def do_DELETE(self) -> None:
        self._deny(405, "method_not_allowed", str(uuid.uuid4()))

    def do_PATCH(self) -> None:
        self._deny(405, "method_not_allowed", str(uuid.uuid4()))

    def do_POST(self) -> None:
        started = time.monotonic()
        request_id = str(uuid.uuid4())
        run_id = "preflight"
        try:
            identity = self._identity()
        except PermissionError:
            self._deny(403, "client_not_authorized", request_id, run_id)
            return
        try:
            request_id, run_id = self._correlation_context()
        except ValueError:
            self._deny(400, "invalid_correlation_header", request_id, run_id)
            return

        if self.path not in {"/v1/messages", "/v1/messages/count_tokens"}:
            self._deny(404, "path_not_allowed", request_id, run_id)
            return
        if not self.broker.limiter.allow(identity):
            self._deny(429, "rate_limit_exceeded", request_id, run_id)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._deny(400, "transfer_encoding_not_allowed", request_id, run_id)
            return
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            self._deny(411, "single_content_length_required", request_id, run_id)
            return
        try:
            length = int(lengths[0])
        except (TypeError, ValueError):
            self._deny(400, "invalid_content_length", request_id, run_id)
            return
        maximum = int(self.broker.config["max_request_bytes"])
        if length < 2 or length > maximum:
            self._deny(413, "request_size_not_allowed", request_id, run_id)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            self._deny(415, "json_required", request_id, run_id)
            return
        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            self._deny(400, "invalid_json", request_id, run_id)
            return
        if not isinstance(payload, dict):
            self._deny(400, "json_object_required", request_id, run_id)
            return
        streaming = payload.get("stream", False)
        if not isinstance(streaming, bool):
            self._deny(400, "invalid_stream_value", request_id, run_id)
            return
        if self.path == "/v1/messages/count_tokens" and streaming:
            self._deny(400, "streaming_not_allowed_for_token_count", request_id, run_id)
            return
        model = payload.get("model")
        if model not in self.broker.config["allowed_models"]:
            self._deny(403, "model_not_allowed", request_id, run_id)
            return
        max_tokens = payload.get("max_tokens")
        if self.path == "/v1/messages" and max_tokens is None:
            self._deny(400, "max_tokens_required", request_id, run_id)
            return
        if max_tokens is not None and (
            not isinstance(max_tokens, int)
            or isinstance(max_tokens, bool)
            or max_tokens < 1
            or max_tokens > int(self.broker.config["max_tokens"])
        ):
            self._deny(400, "max_tokens_not_allowed", request_id, run_id)
            return
        if payload.get("policy_ids") is not None:
            self._deny(403, "client_policy_selection_not_allowed", request_id, run_id)
            return
        if contains_forbidden_remote_tool(payload):
            self._deny(403, "remote_network_tool_not_allowed", request_id, run_id)
            return
        if contains_image_input(payload):
            self._deny(403, "image_input_not_allowed", request_id, run_id)
            return

        try:
            reservation = self.broker.lease_store.reserve(
                run_id,
                identity,
                model,
                length,
                0 if self.path == "/v1/messages/count_tokens" else int(max_tokens),
                reservation_id=request_id,
            )
        except run_lease.LeaseDenied as error:
            status = 429 if error.code.endswith("_exhausted") else 403
            self._deny(status, error.code, request_id, run_id)
            return
        except (OSError, ValueError, json.JSONDecodeError):
            self._deny(503, "lease_state_unavailable", request_id, run_id)
            return
        self._audit(
            "lease_reserved",
            request_id=request_id,
            run_id=run_id,
            lease_id=reservation["lease_id"],
            reserved_input_tokens=reservation["reserved"]["input_tokens"],
            reserved_output_tokens=reservation["reserved"]["output_tokens"],
            reserved_cost_microusd=reservation["reserved"]["cost_microusd"],
            cumulative_requests=reservation["cumulative"]["requests"],
            cumulative_input_tokens=reservation["cumulative"]["input_tokens"],
            cumulative_output_tokens=reservation["cumulative"]["output_tokens"],
            cumulative_cost_microusd=reservation["cumulative"]["cost_microusd"],
        )

        if self.broker.config["mode"] == "production" and streaming:
            self._stream_production_response(
                self.path, raw, request_id, run_id, identity, model, length, started
            )
            return

        try:
            status, response, response_type = self._invoke(
                self.path, raw, request_id, streaming
            )
        except Exception as error:
            self._audit(
                "upstream_failed",
                request_id=request_id,
                run_id=run_id,
                error=type(error).__name__,
            )
            self._reply_json(502, {"error": {"code": "upstream_unavailable"}, "request_id": request_id})
            return

        if status < 300:
            actual_output = (
                0
                if self.path == "/v1/messages/count_tokens"
                else response_output_tokens(response, response_type)
            )
            self._settle_lease(run_id, request_id, actual_output)

        self._audit(
            "request_complete",
            request_id=request_id,
            run_id=run_id,
            client=identity[:16],
            model=model,
            request_bytes=length,
            response_bytes=len(response),
            status=status,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        self.send_response(status)
        self.send_header("Content-Type", response_type)
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Sandbox-Request-Id", request_id)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response)
        self.close_connection = True

    def _stream_production_response(
        self,
        path: str,
        body: bytes,
        request_id: str,
        run_id: str,
        identity: str,
        model: str,
        request_bytes: int,
        started: float,
    ) -> None:
        connection: FixedAddressHTTPSConnection | None = None
        response_started = False
        response_bytes = 0
        usage = StreamingUsage()
        try:
            connection, upstream_response = self._open_upstream(path, body, True)
            response_type = upstream_response.getheader("Content-Type", "").split(
                ";", 1
            )[0]
            if upstream_response.status >= 300:
                maximum = int(self.broker.config["max_response_bytes"])
                response = upstream_response.read(maximum + 1)
                if len(response) > maximum:
                    raise RuntimeError("upstream response exceeds limit")
                json.loads(response.decode("utf-8"), parse_constant=_reject_json_constant)
                self.send_response(upstream_response.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response)
                response_bytes = len(response)
                self.close_connection = True
            else:
                if response_type != "text/event-stream":
                    raise RuntimeError("streaming response has unexpected content type")
                self.send_response(upstream_response.status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.send_header("X-Sandbox-Request-Id", request_id)
                self.send_header("Connection", "close")
                self.end_headers()
                response_started = True
                maximum = int(self.broker.config["max_response_bytes"])
                while True:
                    chunk = upstream_response.read1(16384)
                    if not chunk:
                        break
                    response_bytes += len(chunk)
                    if response_bytes > maximum:
                        raise RuntimeError("upstream response exceeds limit")
                    usage.feed(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                self.close_connection = True
                self._settle_lease(run_id, request_id, usage.finish())
            self._audit(
                "request_complete",
                request_id=request_id,
                run_id=run_id,
                client=identity[:16],
                model=model,
                request_bytes=request_bytes,
                response_bytes=response_bytes,
                status=upstream_response.status,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        except Exception as error:
            self._audit(
                "upstream_failed",
                request_id=request_id,
                run_id=run_id,
                error=type(error).__name__,
                response_started=response_started,
            )
            if not response_started:
                self._reply_json(
                    502,
                    {"error": {"code": "upstream_unavailable"}, "request_id": request_id},
                )
            else:
                self.close_connection = True
        finally:
            if connection is not None:
                connection.close()

    def _settle_lease(
        self, run_id: str, request_id: str, output_tokens: int | None
    ) -> None:
        if output_tokens is None:
            self._audit(
                "lease_settlement_failed",
                request_id=request_id,
                run_id=run_id,
                code="provider_usage_unavailable",
            )
            return
        try:
            settlement = self.broker.lease_store.settle(
                run_id, request_id, output_tokens
            )
        except (run_lease.LeaseDenied, OSError, ValueError, json.JSONDecodeError) as error:
            self._audit(
                "lease_settlement_failed",
                request_id=request_id,
                run_id=run_id,
                code=getattr(error, "code", "lease_state_unavailable"),
            )
            return
        self._audit(
            "lease_settled",
            request_id=request_id,
            run_id=run_id,
            lease_id=settlement["lease_id"],
            actual_output_tokens=settlement["actual"]["output_tokens"],
            released_output_tokens=settlement["released"]["output_tokens"],
            cumulative_requests=settlement["cumulative"]["requests"],
            cumulative_input_tokens=settlement["cumulative"]["input_tokens"],
            cumulative_output_tokens=settlement["cumulative"]["output_tokens"],
            cumulative_cost_microusd=settlement["cumulative"]["cost_microusd"],
        )

    def _open_upstream(
        self, path: str, body: bytes, streaming: bool
    ) -> tuple[FixedAddressHTTPSConnection, http.client.HTTPResponse]:
        config = self.broker.config
        upstream = urllib.parse.urlsplit(config["upstream_origin"])
        hostname = upstream.hostname
        if (
            upstream.scheme != "https"
            or hostname is None
            or upstream.username is not None
            or upstream.password is not None
            or upstream.query
            or upstream.fragment
            or upstream.path not in ("", "/")
            or hostname not in config["allowed_upstream_hosts"]
        ):
            raise ValueError("upstream origin is not allowed")
        port = upstream.port or 443
        if port != 443:
            raise ValueError("upstream port is not allowed")
        token_path = os.environ.get("CREDENTIALS_DIRECTORY")
        if not token_path:
            raise RuntimeError("systemd credential directory unavailable")
        token = (Path(token_path) / "provider_token").read_text(encoding="utf-8").strip()
        if not token or "\n" in token or "\r" in token:
            raise ValueError("provider credential is invalid")
        addresses = config["upstream_ipv4"]
        connection = FixedAddressHTTPSConnection(
            hostname,
            addresses[0],
            port,
            float(config["upstream_timeout_seconds"]),
        )
        headers = {
            "Accept": "text/event-stream" if streaming else "application/json",
            "Authorization": f"Bearer {token}",
            "Anthropic-Version": "2023-06-01",
            "Content-Type": "application/json",
            "Host": hostname,
            "User-Agent": "SecureSandboxBroker/1",
        }
        if config.get("session_id"):
            headers["X-Abliteration-Session-Id"] = str(config["session_id"])
        connection.request("POST", path, body=body, headers=headers)
        upstream_response = connection.getresponse()
        if 300 <= upstream_response.status < 400:
            connection.close()
            raise RuntimeError("upstream redirects are forbidden")
        declared = upstream_response.getheader("Content-Length")
        if declared is not None and int(declared) > int(config["max_response_bytes"]):
            connection.close()
            raise RuntimeError("upstream response exceeds limit")
        return connection, upstream_response

    def _invoke(
        self, path: str, body: bytes, request_id: str, streaming: bool
    ) -> tuple[int, bytes, str]:
        config = self.broker.config
        if config["mode"] == "mock":
            if path == "/v1/messages/count_tokens":
                response = {"input_tokens": 42}
                return (
                    200,
                    json.dumps(response, separators=(",", ":")).encode("utf-8"),
                    "application/json",
                )
            response = {
                "id": f"msg_mock_{request_id}",
                "type": "message",
                "role": "assistant",
                "model": "abliterated-model-large-v2",
                "content": [{"type": "text", "text": "secure sandbox broker mock"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 5},
            }
            if streaming:
                events = [
                    ("message_start", {"type": "message_start", "message": response}),
                    ("message_stop", {"type": "message_stop"}),
                ]
                wire = b"".join(
                    f"event: {name}\ndata: {json.dumps(value, separators=(',', ':'))}\n\n".encode()
                    for name, value in events
                )
                return 200, wire, "text/event-stream"
            return (
                200,
                json.dumps(response, separators=(",", ":")).encode("utf-8"),
                "application/json",
            )

        connection, upstream_response = self._open_upstream(path, body, streaming)
        maximum = int(config["max_response_bytes"])
        declared = upstream_response.getheader("Content-Length")
        if declared is not None and int(declared) > maximum:
            raise RuntimeError("upstream response exceeds limit")
        response = upstream_response.read(maximum + 1)
        connection.close()
        if len(response) > maximum:
            raise RuntimeError("upstream response exceeds limit")
        response_type = upstream_response.getheader("Content-Type", "").split(";", 1)[0]
        if streaming and upstream_response.status < 300:
            if response_type != "text/event-stream":
                raise RuntimeError("streaming response has unexpected content type")
            return upstream_response.status, response, "text/event-stream"
        json.loads(response.decode("utf-8"), parse_constant=_reject_json_constant)
        return upstream_response.status, response, "application/json"


def validate_config(config: dict) -> None:
    required = {
        "mode",
        "listen_address",
        "listen_port",
        "server_certificate",
        "server_private_key",
        "client_ca_certificate",
        "allowed_client_sha256",
        "allowed_models",
        "max_request_bytes",
        "max_response_bytes",
        "max_tokens",
        "rate_limit_requests",
        "rate_limit_window_seconds",
        "client_timeout_seconds",
        "upstream_timeout_seconds",
        "upstream_origin",
        "allowed_upstream_hosts",
        "upstream_ipv4",
        "lease_state_directory",
    }
    missing = sorted(required.difference(config))
    if missing:
        raise ValueError(f"missing configuration keys: {', '.join(missing)}")
    if config["mode"] not in ("mock", "production"):
        raise ValueError("mode must be mock or production")
    if config["listen_address"] != "172.30.10.1":
        raise ValueError("broker must bind only to the Gateway control address")
    if int(config["listen_port"]) != 8443:
        raise ValueError("broker must use port 8443")
    if not config["allowed_client_sha256"] or not config["allowed_models"]:
        raise ValueError("client and model allowlists must not be empty")
    if config["allowed_models"] != ["abliterated-model-large-v2"]:
        raise ValueError("model allowlist is not the approved canonical model")
    if config["lease_state_directory"] != "/var/lib/secure-sandbox/run-leases":
        raise ValueError("lease state directory is not approved")
    if config["mode"] == "production" and not config["allowed_upstream_hosts"]:
        raise ValueError("production upstream allowlist must not be empty")
    if config["mode"] == "production":
        if config["upstream_origin"] != "https://api.abliteration.ai":
            raise ValueError("production origin is not the approved provider")
        if config["allowed_upstream_hosts"] != ["api.abliteration.ai"]:
            raise ValueError("production hostname allowlist is not exact")
        if not isinstance(config["upstream_ipv4"], list) or not config["upstream_ipv4"]:
            raise ValueError("production upstream IPv4 pins must not be empty")
        for address in config["upstream_ipv4"]:
            parsed = ipaddress.ip_address(address)
            if parsed.version != 4 or not parsed.is_global:
                raise ValueError("production upstream pins must be global IPv4 addresses")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    config = load_json(args.config)
    validate_config(config)
    if args.validate:
        return 0

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(config["server_certificate"], config["server_private_key"])
    context.load_verify_locations(cafile=config["client_ca_certificate"])

    server = BrokerHTTPServer(
        (config["listen_address"], int(config["listen_port"])), config
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"event": "broker_started", "mode": config["mode"]}), flush=True)
    server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps({"event": "broker_fatal", "error": type(error).__name__}),
            file=sys.stderr,
            flush=True,
        )
        raise
