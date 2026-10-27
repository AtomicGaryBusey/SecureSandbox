#!/usr/bin/env python3
"""Absolute-deadline framing for small, intentionally serialized HTTP brokers."""

from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


DEFAULT_FRAMING_SECONDS = 3.0
DEFAULT_WRITE_SECONDS = 3.0


class RequestIncomplete(ValueError):
    """The peer did not finish the declared request before the deadline."""


class BoundedHTTPServer(HTTPServer):
    """HTTPServer with a bounded accept/TLS-handshake phase.

    Request handlers remain serialized deliberately. Authority-bearing services
    commonly mutate one durable journal or consume one-shot records; parallel
    handlers would weaken those invariants. Absolute framing and write bounds
    ensure a peer cannot hold that serialization point indefinitely.
    """

    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        tls_context: ssl.SSLContext | None = None,
        handshake_seconds: float = DEFAULT_FRAMING_SECONDS,
        bind_and_activate: bool = True,
    ) -> None:
        if handshake_seconds <= 0:
            raise ValueError("handshake_deadline_invalid")
        self.tls_context = tls_context
        self.handshake_seconds = float(handshake_seconds)
        super().__init__(server_address, handler_class, bind_and_activate)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(self.handshake_seconds)
        if self.tls_context is None:
            return connection, address
        wrapped: ssl.SSLSocket | None = None
        deadline = time.monotonic() + self.handshake_seconds
        try:
            wrapped = self.tls_context.wrap_socket(
                connection, server_side=True, do_handshake_on_connect=False)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("tls_handshake_deadline_exceeded")
                wrapped.settimeout(remaining)
                try:
                    wrapped.do_handshake()
                    return wrapped, address
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
        except Exception:
            (wrapped if wrapped is not None else connection).close()
            raise

    def handle_error(self, _request: socket.socket, _client_address: Any) -> None:
        # Never emit request bytes, headers, peer addresses, or exception text.
        # The exception class is enough to distinguish hostile framing from a
        # service defect while keeping the shared runtime content-free.
        error = sys.exc_info()[0]
        name = error.__name__ if error is not None else "UnknownError"
        print(f'{{"event":"bounded_http_handler_failed","error":"{name}"}}',
              file=sys.stderr, flush=True)


class AbsoluteFramingHandler:
    """Mixin for BaseHTTPRequestHandler with an absolute framing deadline."""

    framing_seconds = DEFAULT_FRAMING_SECONDS
    write_seconds = DEFAULT_WRITE_SECONDS

    def framing_timeout_seconds(self) -> float:
        return float(self.framing_seconds)

    def setup(self) -> None:
        super().setup()  # type: ignore[misc]
        timeout = self.framing_timeout_seconds()
        if timeout <= 0:
            raise ValueError("framing_deadline_invalid")
        self.connection.settimeout(timeout)  # type: ignore[attr-defined]
        self._framing_lock = threading.Lock()
        self._framing_state = "open"
        self._framing_timer = threading.Timer(timeout, self._expire_framing)
        self._framing_timer.daemon = True
        self._framing_timer.start()

    def framing_expired(self) -> None:
        """Optional content-free audit hook for a service implementation."""

    def _expire_framing(self) -> None:
        with self._framing_lock:
            if self._framing_state != "open":
                return
            self._framing_state = "expired"
        try:
            self.framing_expired()
        except Exception:
            pass
        try:
            self.connection.shutdown(socket.SHUT_RD)  # type: ignore[attr-defined]
        except OSError:
            pass

    def complete_framing(self) -> bool:
        with self._framing_lock:
            if self._framing_state == "expired":
                return False
            self._framing_state = "complete"
        self._framing_timer.cancel()
        self.connection.settimeout(float(self.write_seconds))  # type: ignore[attr-defined]
        return True

    def read_exact_body(self, length: int) -> bytes:
        body = self.rfile.read(length)  # type: ignore[attr-defined]
        if not self.complete_framing() or len(body) != length:
            raise RequestIncomplete("request_incomplete")
        return body

    def finish(self) -> None:
        if hasattr(self, "_framing_lock"):
            with self._framing_lock:
                if self._framing_state == "open":
                    self._framing_state = "complete"
        if hasattr(self, "_framing_timer"):
            self._framing_timer.cancel()
        try:
            super().finish()  # type: ignore[misc]
        except OSError:
            pass
