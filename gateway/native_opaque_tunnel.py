#!/usr/bin/env python3
"""Fail-closed opaque CONNECT tunnel for native vendor harnesses.

The trusted activation path resolves vendor names and records the resulting
global IPv4 literals in a canonical grant. Gateway deliberately has no DNS;
this service connects only to those literal pins. It parses a bounded TLS
ClientHello solely to require that its SNI exactly equals the admitted CONNECT
hostname, rejects ECH because an inner SNI cannot be attested, then relays TLS
bytes without terminating TLS or logging content.  This is intentionally not
an L7 firewall: HTTPS authority/path/body and domain-fronting behind the same
admitted visible TLS name remain outside Gateway's enforcement boundary and
must be constrained by the admitted vendor client/protocol firewall.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import select
import socket
import socketserver
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Mapping

from shared import native_egress


DEFAULT_LISTEN = ("172.30.10.1", 8643)
DEFAULT_GRANT = Path("/var/lib/secure-sandbox/native-egress/active.json")
DEFAULT_LEDGER = Path("/var/lib/native-opaque-tunnel/consumption.sqlite3")
MAX_CONNECT_HEADER_BYTES = 8192
MAX_TLS_RECORD_BYTES = (1 << 14) + 256
MAX_CLIENT_HELLO_BYTES = 64 * 1024
MAX_CLIENT_HELLO_RECORDS = 8
HEADER_TIMEOUT_SECONDS = 5.0
CLIENT_HELLO_TIMEOUT_SECONDS = 5.0
CONNECT_TIMEOUT_SECONDS = 10.0
REVALIDATE_SECONDS = 1.0
ALLOWED_HEADERS = {"host", "proxy-connection", "connection", "user-agent"}
LEDGER_SCHEMA_VERSION = 1


class TunnelError(ValueError):
    """Stable, content-free tunnel rejection."""


def parse_connect_request(raw: bytes) -> tuple[str, int]:
    if not 1 <= len(raw) <= MAX_CONNECT_HEADER_BYTES or not raw.endswith(b"\r\n\r\n"):
        raise TunnelError("connect_framing_invalid")
    if b"\x00" in raw:
        raise TunnelError("connect_encoding_invalid")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise TunnelError("connect_encoding_invalid") from error
    lines = text[:-4].split("\r\n")
    if not lines or len(lines) > 32 or any(not line for line in lines):
        raise TunnelError("connect_headers_invalid")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise TunnelError("connect_method_invalid")
    authority = parts[1]
    if authority.count(":") != 1:
        raise TunnelError("connect_authority_invalid")
    hostname, port_text = authority.rsplit(":", 1)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise TunnelError("connect_authority_invalid")
    if (
        native_egress.HOSTNAME.fullmatch(hostname) is None
        or hostname != hostname.lower()
        or port_text != "443"
    ):
        raise TunnelError("connect_authority_invalid")
    observed: dict[str, str] = {}
    for line in lines[1:]:
        if line[:1] in {" ", "\t"} or ":" not in line:
            raise TunnelError("connect_headers_invalid")
        name, value = line.split(":", 1)
        lowered = name.lower()
        if (
            not name
            or not all(character.isalnum() or character == "-" for character in name)
            or lowered not in ALLOWED_HEADERS
            or lowered in observed
            or any(ord(character) < 32 or ord(character) > 126 for character in value)
            or len(value) > 512
        ):
            raise TunnelError("connect_headers_invalid")
        observed[lowered] = value.strip()
    if observed.get("host") != authority:
        raise TunnelError("connect_host_mismatch")
    return hostname, 443


def read_connect_request(
    connection: socket.socket,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> bytes:
    deadline = monotonic() + HEADER_TIMEOUT_SECONDS
    data = bytearray()
    while b"\r\n\r\n" not in data:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TunnelError("connect_header_timeout")
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(
                min(2048, MAX_CONNECT_HEADER_BYTES + 1 - len(data))
            )
        except (socket.timeout, TimeoutError) as error:
            raise TunnelError("connect_header_timeout") from error
        if not chunk:
            raise TunnelError("connect_incomplete")
        data.extend(chunk)
        if len(data) > MAX_CONNECT_HEADER_BYTES:
            raise TunnelError("connect_oversized")
    end = data.find(b"\r\n\r\n") + 4
    if end != len(data):
        raise TunnelError("connect_eager_payload_rejected")
    return bytes(data)


def pinned_destinations(grant: Mapping[str, Any], hostname: str) -> tuple[str, ...]:
    """Return only activation-authorized IPv4 literals; never perform DNS."""
    destinations = {item["hostname"]: item for item in grant["destinations"]}
    destination = destinations.get(hostname)
    if destination is None or destination["port"] != 443:
        raise TunnelError("connect_destination_not_admitted")
    pins = tuple(destination["ipv4"])
    if not pins:
        raise TunnelError("connect_destination_not_admitted")
    return pins


def _recv_exact(
    connection: socket.socket,
    size: int,
    *,
    deadline: float,
    monotonic: Callable[[], float],
    guard: Callable[[], None] | None,
) -> bytes:
    value = bytearray()
    while len(value) < size:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TunnelError("tls_client_hello_timeout")
        if guard is not None:
            guard()
        connection.settimeout(min(remaining, REVALIDATE_SECONDS))
        try:
            chunk = connection.recv(size - len(value))
        except (socket.timeout, TimeoutError) as error:
            raise TunnelError("tls_client_hello_timeout") from error
        if not chunk:
            raise TunnelError("tls_client_hello_incomplete")
        value.extend(chunk)
    return bytes(value)


def _parse_client_hello_sni(handshake: bytes) -> str:
    if len(handshake) < 4 or handshake[0] != 1:
        raise TunnelError("tls_client_hello_invalid")
    declared = int.from_bytes(handshake[1:4], "big")
    if declared != len(handshake) - 4:
        raise TunnelError("tls_client_hello_invalid")
    body = memoryview(handshake)[4:]
    cursor = 0

    def take(size: int) -> memoryview:
        nonlocal cursor
        if size < 0 or cursor + size > len(body):
            raise TunnelError("tls_client_hello_invalid")
        result = body[cursor : cursor + size]
        cursor += size
        return result

    take(2)
    take(32)
    take(int.from_bytes(take(1), "big"))
    cipher_length = int.from_bytes(take(2), "big")
    if cipher_length < 2 or cipher_length % 2:
        raise TunnelError("tls_client_hello_invalid")
    take(cipher_length)
    compression_length = int.from_bytes(take(1), "big")
    compression = bytes(take(compression_length))
    if compression_length < 1 or 0 not in compression:
        raise TunnelError("tls_client_hello_invalid")
    extensions_length = int.from_bytes(take(2), "big")
    if cursor + extensions_length != len(body):
        raise TunnelError("tls_client_hello_invalid")
    extensions_end = cursor + extensions_length
    seen_extensions: set[int] = set()
    sni: str | None = None
    while cursor < extensions_end:
        extension_type = int.from_bytes(take(2), "big")
        extension_length = int.from_bytes(take(2), "big")
        extension = bytes(take(extension_length))
        if extension_type in seen_extensions:
            raise TunnelError("tls_client_hello_invalid")
        seen_extensions.add(extension_type)
        # Encrypted ClientHello can carry an inner SNI different from the
        # visible outer name.  This tunnel does not terminate TLS, so it cannot
        # attest that inner authority and must reject ECH categorically.
        if extension_type == 0xFE0D:
            raise TunnelError("tls_ech_forbidden")
        if extension_type != 0:
            continue
        if len(extension) < 5 or int.from_bytes(extension[:2], "big") != len(extension) - 2:
            raise TunnelError("tls_sni_invalid")
        names = memoryview(extension)[2:]
        name_cursor = 0
        parsed: list[str] = []
        while name_cursor < len(names):
            if name_cursor + 3 > len(names):
                raise TunnelError("tls_sni_invalid")
            name_type = names[name_cursor]
            name_length = int.from_bytes(names[name_cursor + 1 : name_cursor + 3], "big")
            name_cursor += 3
            if name_type != 0 or name_length < 1 or name_cursor + name_length > len(names):
                raise TunnelError("tls_sni_invalid")
            try:
                name = bytes(names[name_cursor : name_cursor + name_length]).decode("ascii")
            except UnicodeDecodeError as error:
                raise TunnelError("tls_sni_invalid") from error
            name_cursor += name_length
            parsed.append(name)
        if len(parsed) != 1:
            raise TunnelError("tls_sni_invalid")
        sni = parsed[0]
    if cursor != extensions_end or sni is None:
        raise TunnelError("tls_sni_missing")
    if sni != sni.lower() or native_egress.HOSTNAME.fullmatch(sni) is None:
        raise TunnelError("tls_sni_invalid")
    return sni


def read_client_hello(
    connection: socket.socket,
    expected_hostname: str,
    *,
    timeout_seconds: float = CLIENT_HELLO_TIMEOUT_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    guard: Callable[[], None] | None = None,
) -> bytes:
    """Read and validate one bounded ClientHello without terminating TLS."""
    if timeout_seconds <= 0:
        raise TunnelError("tls_client_hello_timeout")
    deadline = monotonic() + min(timeout_seconds, CLIENT_HELLO_TIMEOUT_SECONDS)
    framed = bytearray()
    handshake = bytearray()
    expected_handshake_bytes: int | None = None
    for _ in range(MAX_CLIENT_HELLO_RECORDS):
        header = _recv_exact(
            connection,
            5,
            deadline=deadline,
            monotonic=monotonic,
            guard=guard,
        )
        content_type = header[0]
        version = int.from_bytes(header[1:3], "big")
        record_length = int.from_bytes(header[3:5], "big")
        if (
            content_type != 22
            or not 0x0301 <= version <= 0x0304
            or not 1 <= record_length <= MAX_TLS_RECORD_BYTES
        ):
            raise TunnelError("tls_client_hello_record_invalid")
        payload = _recv_exact(
            connection,
            record_length,
            deadline=deadline,
            monotonic=monotonic,
            guard=guard,
        )
        framed.extend(header)
        framed.extend(payload)
        handshake.extend(payload)
        if len(handshake) > MAX_CLIENT_HELLO_BYTES:
            raise TunnelError("tls_client_hello_oversized")
        if expected_handshake_bytes is None and len(handshake) >= 4:
            if handshake[0] != 1:
                raise TunnelError("tls_client_hello_invalid")
            expected_handshake_bytes = 4 + int.from_bytes(handshake[1:4], "big")
            if expected_handshake_bytes > MAX_CLIENT_HELLO_BYTES:
                raise TunnelError("tls_client_hello_oversized")
        if expected_handshake_bytes is not None:
            if len(handshake) > expected_handshake_bytes:
                raise TunnelError("tls_client_hello_trailing_data")
            if len(handshake) == expected_handshake_bytes:
                break
    else:
        raise TunnelError("tls_client_hello_incomplete")
    if expected_handshake_bytes is None or len(handshake) != expected_handshake_bytes:
        raise TunnelError("tls_client_hello_incomplete")
    observed = _parse_client_hello_sni(bytes(handshake))
    if observed != expected_hostname:
        raise TunnelError("tls_sni_mismatch")
    return bytes(framed)


class GrantReader:
    def __init__(
        self,
        path: Path = DEFAULT_GRANT,
        *,
        expected_uid: int = 0,
        expected_gid: int | None = None,
        expected_mode: int = 0o640,
    ):
        self.path = path
        self.expected_uid = expected_uid
        self.expected_gid = os.getegid() if expected_gid is None else expected_gid
        self.expected_mode = expected_mode

    def __call__(self, now: int) -> dict[str, Any]:
        return native_egress.load_grant(
            self.path,
            now=now,
            expected_uid=self.expected_uid,
            expected_gid=self.expected_gid,
            expected_mode=self.expected_mode,
        )


class PersistentGrantLedger:
    """Durable one-start grant tombstones and cumulative usage counters."""

    def __init__(self, path: Path = DEFAULT_LEDGER) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._prepare()

    def _prepare(self) -> None:
        try:
            parent = self.path.parent.lstat()
        except OSError as error:
            raise TunnelError("grant_ledger_parent_unavailable") from error
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid not in {0, os.geteuid()}
            or parent.st_mode & 0o022
        ):
            raise TunnelError("grant_ledger_parent_untrusted")
        try:
            descriptor = os.open(
                self.path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except FileExistsError:
            pass
        except OSError as error:
            raise TunnelError("grant_ledger_unavailable") from error
        else:
            os.close(descriptor)
        self._validate_file()
        with closing(self._connect()) as database:
            database.executescript(
                """
                PRAGMA trusted_schema=OFF;
                PRAGMA journal_mode=DELETE;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS ledger_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version = 1)
                );
                INSERT OR IGNORE INTO ledger_meta(singleton, schema_version) VALUES (1, 1);
                CREATE TABLE IF NOT EXISTS grants (
                    grant_id TEXT PRIMARY KEY,
                    grant_sha256 TEXT NOT NULL UNIQUE,
                    start_nonce TEXT NOT NULL UNIQUE,
                    started_at INTEGER NOT NULL,
                    max_connections INTEGER NOT NULL,
                    max_bytes_from_client INTEGER NOT NULL,
                    max_bytes_to_client INTEGER NOT NULL,
                    total_connections INTEGER NOT NULL DEFAULT 0,
                    active_connections INTEGER NOT NULL DEFAULT 0,
                    bytes_from_client INTEGER NOT NULL DEFAULT 0,
                    bytes_to_client INTEGER NOT NULL DEFAULT 0,
                    CHECK (total_connections >= 0),
                    CHECK (active_connections >= 0),
                    CHECK (bytes_from_client >= 0),
                    CHECK (bytes_to_client >= 0)
                );
                """
            )
            row = database.execute(
                "SELECT schema_version FROM ledger_meta WHERE singleton = 1"
            ).fetchone()
            if row != (LEDGER_SCHEMA_VERSION,):
                raise TunnelError("grant_ledger_schema_invalid")

    def _validate_file(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as error:
            raise TunnelError("grant_ledger_unavailable") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise TunnelError("grant_ledger_untrusted")

    def _connect(self) -> sqlite3.Connection:
        self._validate_file()
        try:
            database = sqlite3.connect(self.path, timeout=1.0, isolation_level=None)
            database.execute("PRAGMA trusted_schema=OFF")
            database.execute("PRAGMA foreign_keys=ON")
            database.execute("PRAGMA synchronous=FULL")
            return database
        except sqlite3.Error as error:
            raise TunnelError("grant_ledger_unavailable") from error

    def claim_start(self, grant: Mapping[str, Any], now: int) -> str:
        limits = grant["limits"]
        with self._lock, closing(self._connect()) as database:
            try:
                database.execute("BEGIN IMMEDIATE")
                database.execute(
                    """INSERT INTO grants(
                           grant_id, grant_sha256, start_nonce, started_at,
                           max_connections, max_bytes_from_client, max_bytes_to_client
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        grant["grant_id"],
                        grant["grant_sha256"],
                        str(uuid.uuid4()),
                        now,
                        limits["max_connections"],
                        limits["max_bytes_from_client"],
                        limits["max_bytes_to_client"],
                    ),
                )
                database.execute("COMMIT")
            except sqlite3.IntegrityError as error:
                database.execute("ROLLBACK")
                raise TunnelError("grant_already_started") from error
            except sqlite3.Error as error:
                database.execute("ROLLBACK")
                raise TunnelError("grant_ledger_unavailable") from error
        return str(grant["grant_sha256"])

    def acquire(self, grant: Mapping[str, Any]) -> str:
        digest = str(grant["grant_sha256"])
        limits = grant["limits"]
        with self._lock, closing(self._connect()) as database:
            try:
                database.execute("BEGIN IMMEDIATE")
                row = database.execute(
                    """SELECT grant_id, max_connections, max_bytes_from_client,
                              max_bytes_to_client, total_connections, active_connections
                       FROM grants WHERE grant_sha256 = ?""",
                    (digest,),
                ).fetchone()
                expected = (
                    grant["grant_id"],
                    limits["max_connections"],
                    limits["max_bytes_from_client"],
                    limits["max_bytes_to_client"],
                )
                if row is None or row[:4] != expected:
                    raise TunnelError("grant_ledger_binding_mismatch")
                if row[4] >= row[1] or row[5] >= row[1]:
                    raise TunnelError("connect_limit_exhausted")
                database.execute(
                    """UPDATE grants SET total_connections = total_connections + 1,
                              active_connections = active_connections + 1
                       WHERE grant_sha256 = ?""",
                    (digest,),
                )
                database.execute("COMMIT")
            except TunnelError:
                database.execute("ROLLBACK")
                raise
            except sqlite3.Error as error:
                database.execute("ROLLBACK")
                raise TunnelError("grant_ledger_unavailable") from error
        return digest

    def reserve_bytes(self, digest: str, from_client: int, to_client: int) -> None:
        if min(from_client, to_client) < 0 or (not from_client and not to_client):
            raise TunnelError("grant_ledger_delta_invalid")
        with self._lock, closing(self._connect()) as database:
            try:
                database.execute("BEGIN IMMEDIATE")
                row = database.execute(
                    """SELECT max_bytes_from_client, max_bytes_to_client,
                              bytes_from_client, bytes_to_client
                       FROM grants WHERE grant_sha256 = ?""",
                    (digest,),
                ).fetchone()
                if row is None:
                    raise TunnelError("grant_ledger_binding_mismatch")
                new_from = row[2] + from_client
                new_to = row[3] + to_client
                if new_from > row[0]:
                    raise TunnelError("connect_client_bytes_exhausted")
                if new_to > row[1]:
                    raise TunnelError("connect_provider_bytes_exhausted")
                database.execute(
                    """UPDATE grants SET bytes_from_client = ?, bytes_to_client = ?
                       WHERE grant_sha256 = ?""",
                    (new_from, new_to, digest),
                )
                database.execute("COMMIT")
            except TunnelError:
                database.execute("ROLLBACK")
                raise
            except sqlite3.Error as error:
                database.execute("ROLLBACK")
                raise TunnelError("grant_ledger_unavailable") from error

    def release(self, digest: str) -> None:
        with self._lock, closing(self._connect()) as database:
            try:
                database.execute("BEGIN IMMEDIATE")
                row = database.execute(
                    "SELECT active_connections FROM grants WHERE grant_sha256 = ?",
                    (digest,),
                ).fetchone()
                if row is None or row[0] <= 0:
                    raise TunnelError("grant_ledger_release_invalid")
                database.execute(
                    """UPDATE grants SET active_connections = active_connections - 1
                       WHERE grant_sha256 = ?""",
                    (digest,),
                )
                database.execute("COMMIT")
            except TunnelError:
                database.execute("ROLLBACK")
                raise
            except sqlite3.Error as error:
                database.execute("ROLLBACK")
                raise TunnelError("grant_ledger_unavailable") from error

    def usage(self, digest: str) -> tuple[int, int, int, int]:
        with self._lock, closing(self._connect()) as database:
            row = database.execute(
                """SELECT total_connections, active_connections,
                          bytes_from_client, bytes_to_client
                   FROM grants WHERE grant_sha256 = ?""",
                (digest,),
            ).fetchone()
        if row is None:
            raise TunnelError("grant_ledger_binding_mismatch")
        return tuple(int(value) for value in row)  # type: ignore[return-value]


def same_active_grant(
    state_reader: Callable[[int], dict[str, Any]], expected_digest: str, now: int
) -> dict[str, Any]:
    try:
        current = native_egress.validate_grant(state_reader(now), now=now)
    except (OSError, native_egress.NativeEgressError) as error:
        raise TunnelError("connect_grant_unavailable") from error
    if current["grant_sha256"] != expected_digest:
        raise TunnelError("connect_grant_changed")
    return current


def relay_bidirectional(
    client: socket.socket,
    upstream: socket.socket,
    grant: Mapping[str, Any],
    state_reader: Callable[[int], dict[str, Any]],
    ledger: PersistentGrantLedger,
    *,
    initial_from_client: int = 0,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    deadline: float | None = None,
) -> tuple[int, int]:
    digest = grant["grant_sha256"]
    limits = grant["limits"]
    wall_started = clock()
    if deadline is None:
        duration = min(
            float(grant["expires_at"]) - wall_started,
            float(limits["max_connection_seconds"]),
        )
        if duration <= 0:
            raise TunnelError("connect_duration_exhausted")
        deadline = monotonic() + duration
    client.setblocking(False)
    upstream.setblocking(False)
    sockets = [client, upstream]
    open_read = {client: True, upstream: True}
    from_client = initial_from_client
    to_client = 0
    next_validation = monotonic()
    while any(open_read.values()):
        now_monotonic = monotonic()
        if now_monotonic >= deadline:
            raise TunnelError("connect_duration_exhausted")
        if now_monotonic >= next_validation:
            same_active_grant(state_reader, digest, int(clock()))
            next_validation = now_monotonic + REVALIDATE_SECONDS
        readable, _, exceptional = select.select(
            [item for item in sockets if open_read[item]],
            [],
            sockets,
            min(1.0, deadline - now_monotonic),
        )
        if exceptional:
            raise TunnelError("connect_socket_failed")
        for source in readable:
            target = upstream if source is client else client
            try:
                chunk = source.recv(64 * 1024)
            except BlockingIOError:
                continue
            if not chunk:
                open_read[source] = False
                try:
                    target.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            if source is client:
                ledger.reserve_bytes(digest, len(chunk), 0)
                from_client += len(chunk)
            else:
                ledger.reserve_bytes(digest, 0, len(chunk))
                to_client += len(chunk)
            view = memoryview(chunk)
            while view:
                now_monotonic = monotonic()
                if now_monotonic >= deadline:
                    raise TunnelError("connect_duration_exhausted")
                _, writable, failed = select.select(
                    [], [target], [target],
                    min(1.0, deadline - now_monotonic),
                )
                if failed:
                    raise TunnelError("connect_socket_failed")
                if not writable:
                    same_active_grant(state_reader, digest, int(clock()))
                    continue
                sent = target.send(view)
                if sent <= 0:
                    raise TunnelError("connect_socket_failed")
                view = view[sent:]
    return from_client, to_client


def connect_ipv4_literal(
    address: str, port: int,
    timeout_seconds: float = CONNECT_TIMEOUT_SECONDS,
) -> socket.socket:
    """Connect through AF_INET directly so name resolution is impossible."""
    parsed = ipaddress.ip_address(address)
    if (parsed.version != 4 or not parsed.is_global or port != 443
            or not 0 < timeout_seconds <= CONNECT_TIMEOUT_SECONDS):
        raise TunnelError("connect_literal_invalid")
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(timeout_seconds)
    try:
        connection.connect((str(parsed), port))
    except Exception:
        connection.close()
        raise
    return connection


class NativeTunnel:
    def __init__(
        self,
        *,
        state_reader: Callable[[int], dict[str, Any]],
        ledger: PersistentGrantLedger,
        connector: Callable[[str, int, float], socket.socket] = connect_ipv4_literal,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        audit: Callable[[str, Mapping[str, Any]], None] | None = None,
    ) -> None:
        self.state_reader = state_reader
        self.ledger = ledger
        self.connector = connector
        self.clock = clock
        self.monotonic = monotonic
        self.audit = audit or self._default_audit
        self._start_lock = threading.Lock()
        self._started_digest: str | None = None

    @staticmethod
    def _default_audit(event: str, fields: Mapping[str, Any]) -> None:
        print(
            json.dumps(
                {"event": event, **fields},
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            flush=True,
        )

    def start(self) -> dict[str, Any]:
        with self._start_lock:
            now = int(self.clock())
            grant = native_egress.validate_grant(self.state_reader(now), now=now)
            if self._started_digest is None:
                self._started_digest = self.ledger.claim_start(grant, now)
            elif grant["grant_sha256"] != self._started_digest:
                raise TunnelError("connect_grant_changed")
            return grant

    def handle(self, client: socket.socket) -> None:
        grant_digest: str | None = None
        upstream: socket.socket | None = None
        grant: dict[str, Any] | None = None
        hostname: str | None = None
        admitted_hostname: str | None = None
        established = False
        try:
            request = read_connect_request(client)
            hostname, port = parse_connect_request(request)
            grant = self.start()
            pins = pinned_destinations(grant, hostname)
            # Only a hostname selected from the closed grant policy may enter
            # audit data. The raw CONNECT authority is attacker-controlled.
            admitted_hostname = hostname
            grant_digest = self.ledger.acquire(grant)
            wall_now = self.clock()
            connection_duration = min(
                float(grant["expires_at"]) - wall_now,
                float(grant["limits"]["max_connection_seconds"]),
            )
            if connection_duration <= 0:
                raise TunnelError("connect_duration_exhausted")
            connection_deadline = self.monotonic() + connection_duration
            same_active_grant(self.state_reader, grant_digest, int(self.clock()))
            client.sendall(
                b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n"
            )
            established = True
            client_hello = read_client_hello(
                client,
                hostname,
                timeout_seconds=connection_deadline - self.monotonic(),
                monotonic=self.monotonic,
                guard=lambda: same_active_grant(
                    self.state_reader, grant_digest, int(self.clock())
                ),
            )
            same_active_grant(self.state_reader, grant_digest, int(self.clock()))
            self.ledger.reserve_bytes(grant_digest, len(client_hello), 0)
            last_error: Exception | None = None
            for address in pins:
                remaining = connection_deadline - self.monotonic()
                if remaining <= 0:
                    raise TunnelError("connect_duration_exhausted")
                same_active_grant(self.state_reader, grant_digest, int(self.clock()))
                try:
                    upstream = self.connector(
                        address, port, min(CONNECT_TIMEOUT_SECONDS, remaining)
                    )
                except (OSError, TunnelError) as error:
                    last_error = error
                    continue
                break
            if upstream is None:
                raise TunnelError("connect_provider_unavailable") from last_error
            if self.monotonic() >= connection_deadline:
                raise TunnelError("connect_duration_exhausted")
            same_active_grant(self.state_reader, grant_digest, int(self.clock()))
            upstream.sendall(client_hello)
            from_client, to_client = relay_bidirectional(
                client,
                upstream,
                grant,
                self.state_reader,
                self.ledger,
                initial_from_client=len(client_hello),
                clock=self.clock,
                monotonic=self.monotonic,
                deadline=connection_deadline,
            )
            self.audit(
                "native_tunnel_complete",
                {
                    "grant_id": grant["grant_id"],
                    "grant_sha256": grant_digest,
                    "phase": grant["phase"],
                    "vendor_id": grant["vendor_id"],
                    "hostname": admitted_hostname,
                    "bytes_from_client": from_client,
                    "bytes_to_client": to_client,
                },
            )
        except Exception as error:
            code = (
                error.args[0]
                if isinstance(error, TunnelError) and error.args
                else "connect_rejected"
            )
            self.audit(
                "native_tunnel_rejected",
                {
                    "code": code,
                    "grant_sha256": grant_digest,
                    "phase": None if grant is None else grant.get("phase"),
                    "vendor_id": None if grant is None else grant.get("vendor_id"),
                    "hostname": admitted_hostname,
                },
            )
            if not established:
                try:
                    client.sendall(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError:
                    pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass
            if grant_digest is not None:
                try:
                    self.ledger.release(grant_digest)
                except TunnelError:
                    self.audit(
                        "native_tunnel_ledger_failure",
                        {"grant_sha256": grant_digest, "code": "release_failed"},
                    )


class ThreadedTunnelServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True


class TunnelHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        tunnel: NativeTunnel = self.server.tunnel  # type: ignore[attr-defined]
        tunnel.handle(self.request)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-address", default=DEFAULT_LISTEN[0])
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN[1])
    parser.add_argument("--grant", type=Path, default=DEFAULT_GRANT)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    args = parser.parse_args()
    if not 1 <= args.listen_port <= 65535:
        parser.error("listen port is invalid")
    tunnel = NativeTunnel(
        state_reader=GrantReader(args.grant),
        ledger=PersistentGrantLedger(args.ledger),
    )
    grant = tunnel.start()
    with ThreadedTunnelServer(
        (args.listen_address, args.listen_port), TunnelHandler
    ) as server:
        server.tunnel = tunnel  # type: ignore[attr-defined]
        tunnel.audit(
            "native_tunnel_started",
            {
                "listen_address": args.listen_address,
                "listen_port": args.listen_port,
                "grant_id": grant["grant_id"],
                "grant_sha256": grant["grant_sha256"],
            },
        )
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
