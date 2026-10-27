#!/usr/bin/env python3
"""Fair, deadline-bounded request framing for local Unix-socket brokers."""

from __future__ import annotations

import os
import selectors
import socket
import stat
import struct
import time
from collections.abc import Callable
from pathlib import Path

MAX_CLIENTS = 32


def serve(
    socket_path: str | Path,
    max_body: int,
    read_seconds: float,
    handler: Callable[[bytes], bytes],
    incomplete: Callable[[], bytes],
    *,
    allowed_uids: set[int] | None = None,
    unauthorized: Callable[[], bytes] | None = None,
    overloaded: Callable[[], bytes] | None = None,
    failed: Callable[[], bytes] | None = None,
    terminator: bytes | None = None,
    socket_uid: int | None = None,
    socket_gid: int | None = None,
    max_clients: int = MAX_CLIENTS,
    peer_uid: Callable[[socket.socket], int] | None = None,
) -> None:
    if max_body < 1 or read_seconds <= 0 or max_clients < 1:
        raise ValueError("bounded_server_configuration_invalid")
    if terminator == b"":
        raise ValueError("bounded_server_terminator_invalid")
    path = str(socket_path)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise RuntimeError("socket_path_untrusted")
        os.unlink(path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, 0o660)
    if socket_uid is not None or socket_gid is not None:
        os.chown(path, -1 if socket_uid is None else socket_uid,
                 -1 if socket_gid is None else socket_gid)
    server.listen(max_clients)
    server.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(server, selectors.EVENT_READ, None)
    clients: dict[socket.socket, tuple[bytearray, float]] = {}

    def close_client(connection: socket.socket, response: bytes | None = None) -> None:
        try:
            selector.unregister(connection)
        except Exception:
            pass
        clients.pop(connection, None)
        if response is not None:
            try:
                connection.setblocking(True)
                connection.settimeout(1.0)
                connection.sendall(response)
            except OSError:
                pass
        connection.close()

    def dispatch(raw: bytes) -> bytes | None:
        try:
            return handler(raw)
        except Exception:
            return failed() if failed is not None else None

    try:
        while True:
            now = time.monotonic()
            for connection, (_, deadline) in list(clients.items()):
                if now >= deadline:
                    close_client(connection, incomplete())
            timeout = min((deadline - now for _, deadline in clients.values()), default=1.0)
            for key, _ in selector.select(max(0.0, min(timeout, 1.0))):
                if key.fileobj is server:
                    # Bound accepts per selector turn so a connection flood
                    # cannot prevent established clients from making progress.
                    for _ in range(max_clients):
                        try:
                            connection, _ = server.accept()
                        except BlockingIOError:
                            break
                        if allowed_uids is not None:
                            try:
                                if peer_uid is not None:
                                    uid = peer_uid(connection)
                                else:
                                    _pid, uid, _gid = struct.unpack(
                                        "3i", connection.getsockopt(
                                            socket.SOL_SOCKET, socket.SO_PEERCRED,
                                            struct.calcsize("3i")))
                            except (AttributeError, OSError, struct.error):
                                uid = -1
                            if uid not in allowed_uids:
                                if unauthorized is not None:
                                    try:
                                        connection.settimeout(1.0)
                                        connection.sendall(unauthorized())
                                    except OSError:
                                        pass
                                connection.close()
                                continue
                        if len(clients) >= max_clients:
                            if overloaded is not None:
                                try:
                                    connection.settimeout(1.0)
                                    connection.sendall(overloaded())
                                except OSError:
                                    pass
                            connection.close()
                            continue
                        connection.setblocking(False)
                        clients[connection] = (bytearray(), time.monotonic() + read_seconds)
                        selector.register(connection, selectors.EVENT_READ, connection)
                    continue
                connection = key.data
                chunks, deadline = clients[connection]
                try:
                    chunk = connection.recv(min(4096, max_body + 1 - len(chunks)))
                except BlockingIOError:
                    continue
                except OSError:
                    close_client(connection)
                    continue
                if chunk:
                    chunks.extend(chunk)
                    clients[connection] = (chunks, deadline)
                    if len(chunks) > max_body:
                        close_client(connection, dispatch(bytes(chunks)))
                    elif terminator is not None and terminator in chunks:
                        close_client(connection, dispatch(bytes(chunks)))
                else:
                    close_client(connection, dispatch(bytes(chunks)))
    finally:
        for connection in list(clients):
            close_client(connection)
        selector.close()
        server.close()
