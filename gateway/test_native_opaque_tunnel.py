#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import socket
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from shared import native_egress
from shared.test_native_egress import NOW, addresses, authority, inference_grant


PATH = Path(__file__).with_name("native_opaque_tunnel.py")
SPEC = importlib.util.spec_from_file_location("native_opaque_tunnel", PATH)
TUNNEL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(TUNNEL)


def request(host: str = "api.anthropic.com", *headers: str) -> bytes:
    lines = [f"CONNECT {host}:443 HTTP/1.1", f"Host: {host}:443", *headers, "", ""]
    return "\r\n".join(lines).encode("ascii")


def client_hello(
    host: str = "api.anthropic.com", *, split: int | None = None,
    ech: bool = False,
) -> bytes:
    encoded = host.encode("ascii")
    server_name = b"\x00" + len(encoded).to_bytes(2, "big") + encoded
    server_names = len(server_name).to_bytes(2, "big") + server_name
    sni = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    versions_data = b"\x02\x03\x04"
    versions = b"\x00\x2b" + len(versions_data).to_bytes(2, "big") + versions_data
    ech_extension = b"\xfe\x0d\x00\x01\x00" if ech else b""
    extensions = sni + versions + ech_extension
    body = (
        b"\x03\x03"
        + b"R" * 32
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body

    def record(payload: bytes) -> bytes:
        return b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload

    if split is None:
        return record(handshake)
    return record(handshake[:split]) + record(handshake[split:])


def limited_grant(
    *,
    connections: int = 4,
    from_client: int = 4096,
    to_client: int = 4096,
    grant_id: str = "55555555-5555-4555-8555-555555555555",
) -> dict:
    return native_egress.make_grant(
        binding_kind="runtime-authority",
        binding_value=authority(),
        phase=native_egress.PHASE_INFERENCE,
        resolved_ipv4=addresses(
            "anthropic-claude-native-oauth-v1", native_egress.PHASE_INFERENCE
        ),
        issued_at=NOW,
        expires_at=NOW + 60,
        grant_id=grant_id,
        limits={
            "max_connections": connections,
            "max_bytes_from_client": from_client,
            "max_bytes_to_client": to_client,
            "max_connection_seconds": 30,
        },
    )


class DripSocket:
    def __init__(self, value: bytes) -> None:
        self.value = bytearray(value)

    def settimeout(self, _seconds: float) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        if not self.value:
            return b""
        return bytes((self.value.pop(0),))


class SteppedClock:
    def __init__(self, values: list[float]) -> None:
        self.values = iter(values)
        self.last = values[-1]

    def __call__(self) -> float:
        self.last = next(self.values, self.last)
        return self.last


class MutableClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class RelaySocket:
    def __init__(
        self,
        chunks: list[bytes] | None = None,
        on_send: Callable[[], None] | None = None,
    ) -> None:
        self.chunks = list(chunks or [])
        self.on_send = on_send
        self.sent = bytearray()

    def setblocking(self, _blocking: bool) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""

    def send(self, value: memoryview) -> int:
        count = min(1, len(value))
        self.sent.extend(value[:count])
        if self.on_send is not None:
            self.on_send()
        return count

    def shutdown(self, _direction: int) -> None:
        pass


class NativeOpaqueTunnelTests(unittest.TestCase):
    def ledger(self, directory: str) -> object:
        return TUNNEL.PersistentGrantLedger(Path(directory) / "consumption.sqlite3")

    def test_connect_parser_is_exact_and_discards_all_headers(self) -> None:
        self.assertEqual(
            TUNNEL.parse_connect_request(
                request(
                    "api.anthropic.com",
                    "User-Agent: vendor-harness",
                    "Proxy-Connection: keep-alive",
                )
            ),
            ("api.anthropic.com", 443),
        )
        hostile = (
            b"GET https://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
            request("api.anthropic.com", "Proxy-Authorization: Basic c2VjcmV0"),
            request("api.anthropic.com") + b"secret-before-200",
            b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n",
            b"CONNECT evil.example:80 HTTP/1.1\r\nHost: evil.example:80\r\n\r\n",
            b"CONNECT api.anthropic.com:443 HTTP/1.0\r\nHost: api.anthropic.com:443\r\n\r\n",
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
        )
        for value in hostile:
            with self.subTest(value=value[:30]), self.assertRaises(TUNNEL.TunnelError):
                TUNNEL.parse_connect_request(value)

    def test_rejected_connect_authority_cannot_exfiltrate_through_audit(self) -> None:
        grant = inference_grant()
        marker = "covert-marker.attacker.example"
        client_peer, client_server = socket.socketpair()
        events: list[tuple[str, dict]] = []
        with tempfile.TemporaryDirectory() as directory:
            tunnel = TUNNEL.NativeTunnel(
                state_reader=lambda _now: grant,
                ledger=self.ledger(directory),
                connector=lambda _address, _port, _timeout: self.fail("provider connection attempted"),
                clock=lambda: float(NOW),
                audit=lambda event, fields: events.append((event, dict(fields))),
            )
            worker = threading.Thread(target=tunnel.handle, args=(client_server,))
            worker.start()
            client_peer.sendall(request(marker))
            self.assertIn(b"403 Forbidden", client_peer.recv(4096))
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertNotIn(marker, repr(events))
        self.assertEqual(events[-1][0], "native_tunnel_rejected")
        self.assertIsNone(events[-1][1]["hostname"])
        client_peer.close()

    def test_destination_uses_only_pre_authorized_literal_pins(self) -> None:
        grant = inference_grant()
        self.assertEqual(
            TUNNEL.pinned_destinations(grant, "api.anthropic.com"), ("8.8.8.8",)
        )
        self.assertFalse(hasattr(TUNNEL, "default_resolver"))
        with self.assertRaisesRegex(TUNNEL.TunnelError, "not_admitted"):
            TUNNEL.pinned_destinations(grant, "evil.example")

    def test_client_hello_sni_is_exact_bounded_and_fragment_tolerant(self) -> None:
        left, right = socket.socketpair()
        left.sendall(client_hello(split=17))
        self.assertEqual(
            TUNNEL.read_client_hello(right, "api.anthropic.com"),
            client_hello(split=17),
        )
        left.close()
        right.close()

        for hostile in (
            client_hello("evil.example"),
            b"\x17\x03\x03\x00\x01X",
            b"\x16\x03\x01\xff\xff",
        ):
            left, right = socket.socketpair()
            left.sendall(hostile)
            left.shutdown(socket.SHUT_WR)
            with self.assertRaises(TUNNEL.TunnelError):
                TUNNEL.read_client_hello(right, "api.anthropic.com")
            left.close()
            right.close()

    def test_allowed_outer_sni_with_ech_is_rejected(self) -> None:
        left, right = socket.socketpair()
        try:
            left.sendall(client_hello("api.anthropic.com", ech=True))
            with self.assertRaisesRegex(TUNNEL.TunnelError, "ech_forbidden"):
                TUNNEL.read_client_hello(right, "api.anthropic.com")
        finally:
            left.close()
            right.close()

    def test_connect_and_client_hello_deadlines_are_absolute_under_drip(self) -> None:
        drip = DripSocket(client_hello())
        hello_clock = SteppedClock([0.0, 0.01, 0.04, 0.08, 0.11])
        with self.assertRaisesRegex(TUNNEL.TunnelError, "hello_timeout"):
            TUNNEL.read_client_hello(
                drip,
                "api.anthropic.com",
                timeout_seconds=0.10,
                monotonic=hello_clock,
            )

        header_drip = DripSocket(request())
        header_clock = SteppedClock([0.0, 0.01, 0.04, 0.08, 0.11])
        with mock.patch.object(TUNNEL, "HEADER_TIMEOUT_SECONDS", 0.10):
            with self.assertRaisesRegex(TUNNEL.TunnelError, "header_timeout"):
                TUNNEL.read_connect_request(header_drip, monotonic=header_clock)

    def test_state_swap_and_expiry_close_fail_closed(self) -> None:
        original = inference_grant()
        replacement = native_egress.make_grant(
            binding_kind="runtime-authority",
            binding_value=authority(),
            phase=native_egress.PHASE_INFERENCE,
            resolved_ipv4=addresses(
                "anthropic-claude-native-oauth-v1", native_egress.PHASE_INFERENCE
            ),
            issued_at=NOW,
            expires_at=NOW + 600,
            grant_id="44444444-4444-4444-8444-444444444444",
        )
        with self.assertRaisesRegex(TUNNEL.TunnelError, "changed"):
            TUNNEL.same_active_grant(
                lambda _now: replacement, original["grant_sha256"], NOW
            )

        def expired(_now: int) -> dict:
            return native_egress.validate_grant(original, now=original["expires_at"])

        with self.assertRaisesRegex(TUNNEL.TunnelError, "unavailable"):
            TUNNEL.same_active_grant(expired, original["grant_sha256"], NOW)

    def test_grant_is_one_start_and_connection_count_survives_restart(self) -> None:
        grant = limited_grant(connections=1)
        with tempfile.TemporaryDirectory() as directory:
            first = self.ledger(directory)
            digest = first.claim_start(grant, NOW)
            first.acquire(grant)
            first.release(digest)
            second = self.ledger(directory)
            with self.assertRaisesRegex(TUNNEL.TunnelError, "already_started"):
                second.claim_start(grant, NOW)
            with self.assertRaisesRegex(TUNNEL.TunnelError, "limit_exhausted"):
                second.acquire(grant)

    def test_cumulative_byte_ceiling_is_atomic_across_connections(self) -> None:
        grant = limited_grant(from_client=10)
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.ledger(directory)
            digest = ledger.claim_start(grant, NOW)
            ledger.acquire(grant)
            ledger.acquire(grant)
            barrier = threading.Barrier(3)
            outcomes: list[str] = []

            def reserve() -> None:
                barrier.wait()
                try:
                    ledger.reserve_bytes(digest, 6, 0)
                except TUNNEL.TunnelError as error:
                    outcomes.append(str(error))
                else:
                    outcomes.append("accepted")

            workers = [threading.Thread(target=reserve) for _ in range(2)]
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join(timeout=3)
            self.assertCountEqual(
                outcomes, ["accepted", "connect_client_bytes_exhausted"]
            )
            self.assertEqual(ledger.usage(digest)[2], 6)
            ledger.release(digest)
            ledger.release(digest)

    def test_sni_is_verified_before_any_provider_connection(self) -> None:
        grant = inference_grant()
        client_peer, client_server = socket.socketpair()
        called: list[tuple[str, int]] = []
        with tempfile.TemporaryDirectory() as directory:
            tunnel = TUNNEL.NativeTunnel(
                state_reader=lambda _now: grant,
                ledger=self.ledger(directory),
                connector=lambda address, port, _timeout: called.append((address, port)),
                clock=lambda: float(NOW),
                audit=lambda _event, _fields: None,
            )
            worker = threading.Thread(target=tunnel.handle, args=(client_server,))
            worker.start()
            client_peer.sendall(request())
            self.assertIn(b"200 Connection Established", client_peer.recv(4096))
            client_peer.sendall(client_hello("evil.example"))
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(called, [])
        client_peer.close()

    def test_established_tunnel_closes_when_active_grant_is_swapped(self) -> None:
        grant = inference_grant()
        replacement = native_egress.make_grant(
            binding_kind="runtime-authority",
            binding_value=authority(),
            phase=native_egress.PHASE_INFERENCE,
            resolved_ipv4=addresses(
                "anthropic-claude-native-oauth-v1", native_egress.PHASE_INFERENCE
            ),
            issued_at=NOW,
            expires_at=NOW + 600,
            grant_id="66666666-6666-4666-8666-666666666666",
        )
        active = [grant]
        started = time.monotonic()
        clock = lambda: float(NOW) + (time.monotonic() - started)
        client_peer, client_server = socket.socketpair()
        upstream_server, upstream_peer = socket.socketpair()
        for item in (client_peer, client_server, upstream_server, upstream_peer):
            item.settimeout(3)
        events: list[tuple[str, dict]] = []
        hello = client_hello()
        with tempfile.TemporaryDirectory() as directory:
            tunnel = TUNNEL.NativeTunnel(
                state_reader=lambda _now: active[0],
                ledger=self.ledger(directory),
                connector=lambda _address, _port, _timeout: upstream_server,
                clock=clock,
                audit=lambda event, fields: events.append((event, dict(fields))),
            )
            worker = threading.Thread(target=tunnel.handle, args=(client_server,), daemon=True)
            worker.start()
            client_peer.sendall(request())
            self.assertIn(b"200 Connection Established", client_peer.recv(4096))
            client_peer.sendall(hello)
            self.assertEqual(upstream_peer.recv(len(hello)), hello)
            active[0] = replacement
            worker.join(timeout=2.5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(events[-1][0], "native_tunnel_rejected")
        self.assertEqual(events[-1][1]["code"], "connect_grant_changed")
        client_peer.close()
        upstream_peer.close()

    def test_partial_relay_write_revalidates_before_every_send(self) -> None:
        grant = inference_grant()
        replacement = limited_grant(connections=3)
        active = [grant]
        source = RelaySocket(chunks=[b"AB"])
        target = RelaySocket(on_send=lambda: active.__setitem__(0, replacement))

        def ready(readable, writable, _exceptional, _timeout):
            if readable:
                return [source], [], []
            return [], [target] if writable else [], []

        with tempfile.TemporaryDirectory() as directory:
            ledger = self.ledger(directory)
            digest = ledger.claim_start(grant, NOW)
            ledger.acquire(grant)
            with mock.patch.object(TUNNEL.select, "select", side_effect=ready):
                with self.assertRaisesRegex(
                    TUNNEL.TunnelError, "connect_grant_changed"
                ):
                    TUNNEL.relay_bidirectional(
                        source,
                        target,
                        grant,
                        lambda _now: active[0],
                        ledger,
                        clock=lambda: float(NOW),
                        monotonic=lambda: 0.0,
                        deadline=30.0,
                    )
            ledger.release(digest)
        self.assertEqual(bytes(target.sent), b"A")

    def test_preauthentication_capacity_rejects_before_thread_creation(self):
        started = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        handlers: list[int] = []
        events: list[tuple[str, dict]] = []

        class SlowHandler(TUNNEL.socketserver.BaseRequestHandler):
            def handle(self) -> None:
                handlers.append(threading.get_ident())
                started.set()
                release.wait(timeout=2)
                finished.set()

        server = TUNNEL.ThreadedTunnelServer(
            ("127.0.0.1", 0),
            SlowHandler,
            maximum_workers=1,
            bind_and_activate=False,
        )
        server.tunnel = type(
            "AuditTunnel",
            (),
            {
                "audit": staticmethod(
                    lambda event, fields: events.append((event, dict(fields)))
                )
            },
        )()
        first_peer, first_request = socket.socketpair()
        second_peer, second_request = socket.socketpair()
        try:
            server.process_request(first_request, ("127.0.0.1", 1))
            self.assertTrue(started.wait(timeout=1))
            server.process_request(second_request, ("127.0.0.1", 2))
            second_peer.settimeout(1)
            self.assertEqual(second_peer.recv(1), b"")
            self.assertEqual(len(handlers), 1)
            self.assertEqual(events[-1][0], "native_tunnel_rejected")
            self.assertEqual(
                events[-1][1]["code"],
                "connect_preauthentication_capacity_exhausted",
            )
        finally:
            release.set()
            finished.wait(timeout=1)
            server.server_close()
            first_peer.close()
            second_peer.close()

    def test_opaque_relay_never_logs_or_interprets_post_hello_payload(self) -> None:
        grant = inference_grant()
        hello = client_hello()
        client_peer, client_server = socket.socketpair()
        upstream_server, upstream_peer = socket.socketpair()
        for item in (client_peer, client_server, upstream_server, upstream_peer):
            item.settimeout(3)
        events: list[tuple[str, dict]] = []
        with tempfile.TemporaryDirectory() as directory:
            tunnel = TUNNEL.NativeTunnel(
                state_reader=lambda _now: grant,
                ledger=self.ledger(directory),
                connector=lambda address, port, _timeout: upstream_server
                if (address, port) == ("8.8.8.8", 443)
                else None,
                clock=lambda: float(NOW),
                audit=lambda event, fields: events.append((event, dict(fields))),
            )
            worker = threading.Thread(target=tunnel.handle, args=(client_server,), daemon=True)
            worker.start()
            client_peer.sendall(request())
            self.assertIn(b"200 Connection Established", client_peer.recv(4096))
            client_peer.sendall(hello)
            self.assertEqual(upstream_peer.recv(len(hello)), hello)
            client_secret = b"client-bearer-never-log"
            provider_secret = b"provider-content-never-log"
            client_peer.sendall(client_secret)
            self.assertEqual(upstream_peer.recv(len(client_secret)), client_secret)
            upstream_peer.sendall(provider_secret)
            self.assertEqual(client_peer.recv(len(provider_secret)), provider_secret)
            client_peer.shutdown(socket.SHUT_WR)
            upstream_peer.shutdown(socket.SHUT_WR)
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        rendered = repr(events)
        self.assertNotIn(client_secret.decode(), rendered)
        self.assertNotIn(provider_secret.decode(), rendered)
        self.assertEqual(events[-1][0], "native_tunnel_complete")
        self.assertEqual(events[-1][1]["bytes_from_client"], len(hello) + len(client_secret))
        self.assertEqual(events[-1][1]["bytes_to_client"], len(provider_secret))
        client_peer.close()
        upstream_peer.close()

    def test_cumulative_byte_ceiling_closes_tls_without_http_injection(self) -> None:
        hello = client_hello()
        grant = limited_grant(from_client=len(hello) + 4)
        client_peer, client_server = socket.socketpair()
        upstream_server, upstream_peer = socket.socketpair()
        for item in (client_peer, client_server, upstream_server, upstream_peer):
            item.settimeout(3)
        events: list[tuple[str, dict]] = []
        with tempfile.TemporaryDirectory() as directory:
            tunnel = TUNNEL.NativeTunnel(
                state_reader=lambda _now: grant,
                ledger=self.ledger(directory),
                connector=lambda _address, _port, _timeout: upstream_server,
                clock=lambda: float(NOW),
                audit=lambda event, fields: events.append((event, dict(fields))),
            )
            worker = threading.Thread(target=tunnel.handle, args=(client_server,), daemon=True)
            worker.start()
            client_peer.sendall(request())
            self.assertIn(b"200 Connection Established", client_peer.recv(4096))
            client_peer.sendall(hello)
            self.assertEqual(upstream_peer.recv(len(hello)), hello)
            client_peer.sendall(b"12345")
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(client_peer.recv(4096), b"")
        self.assertEqual(events[-1][0], "native_tunnel_rejected")
        self.assertEqual(events[-1][1]["code"], "connect_client_bytes_exhausted")
        client_peer.close()
        upstream_peer.close()

    def test_backward_wall_clock_cannot_extend_monotonic_connection_deadline(self):
        grant = limited_grant()
        client, client_peer = socket.socketpair()
        upstream, upstream_peer = socket.socketpair()
        try:
            wall = SteppedClock([float(NOW), float(NOW - 10_000)])
            monotonic = SteppedClock([0.0, 0.0, 31.0])
            with tempfile.TemporaryDirectory() as directory:
                ledger = self.ledger(directory)
                digest = ledger.claim_start(grant, NOW)
                ledger.acquire(grant)
                with self.assertRaisesRegex(
                    TUNNEL.TunnelError,
                    "duration_exhausted|grant_unavailable",
                ):
                    TUNNEL.relay_bidirectional(
                        client, upstream, grant, lambda _now: grant, ledger,
                        clock=wall, monotonic=monotonic,
                    )
                ledger.release(digest)
        finally:
            client.close(); client_peer.close()
            upstream.close(); upstream_peer.close()

    def test_near_deadline_socket_write_does_not_use_stale_connect_timeout(self):
        connection, peer = socket.socketpair()
        clock = MutableClock(29.0)
        try:
            def delayed_writable(_read, _write, _error, _timeout):
                clock.value = 30.0
                return [], [connection], []

            with mock.patch.object(TUNNEL.select, "select", delayed_writable):
                with self.assertRaisesRegex(
                    TUNNEL.TunnelError, "duration_exhausted"
                ):
                    TUNNEL.send_before_deadline(
                        connection, b"client-hello",
                        deadline=30.0, monotonic=clock,
                    )
            peer.setblocking(False)
            with self.assertRaises(BlockingIOError):
                peer.recv(1)
        finally:
            connection.close()
            peer.close()

    def test_slow_grant_revalidation_cannot_send_after_deadline(self):
        connection, peer = socket.socketpair()
        clock = MutableClock(29.0)
        guard_calls = 0
        try:
            def slow_guard() -> None:
                nonlocal guard_calls
                guard_calls += 1
                if guard_calls == 2:
                    clock.value = 30.0

            with self.assertRaisesRegex(
                TUNNEL.TunnelError, "duration_exhausted"
            ):
                TUNNEL.send_before_deadline(
                    connection, b"client-hello",
                    deadline=30.0, monotonic=clock, guard=slow_guard,
                )
            self.assertEqual(guard_calls, 2)
            peer.setblocking(False)
            with self.assertRaises(BlockingIOError):
                peer.recv(1)
        finally:
            connection.close()
            peer.close()


if __name__ == "__main__":
    unittest.main()
