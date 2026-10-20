#!/usr/bin/env python3
"""Fair, deadline-bounded request framing for local Unix-socket brokers."""

from __future__ import annotations

import os
import selectors
import socket
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
) -> None:
    path = str(socket_path)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, 0o660)
    server.listen(MAX_CLIENTS)
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

    try:
        while True:
            now = time.monotonic()
            for connection, (_, deadline) in list(clients.items()):
                if now >= deadline:
                    close_client(connection, incomplete())
            timeout = min((deadline - now for _, deadline in clients.values()), default=1.0)
            for key, _ in selector.select(max(0.0, min(timeout, 1.0))):
                if key.fileobj is server:
                    while len(clients) < MAX_CLIENTS:
                        try:
                            connection, _ = server.accept()
                        except BlockingIOError:
                            break
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
                        close_client(connection, handler(bytes(chunks)))
                else:
                    close_client(connection, handler(bytes(chunks)))
    finally:
        for connection in list(clients):
            close_client(connection)
        selector.close()
        server.close()
