#!/usr/bin/env python3
"""Receive opaque age-encrypted transcript chunks into a bounded durable spool."""

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
from http.server import BaseHTTPRequestHandler

from shared.bounded_http import AbsoluteFramingHandler, BoundedHTTPServer, RequestIncomplete

LISTEN = ("172.30.10.1", 9553)
SPOOL = "/var/lib/secure-sandbox/conversation-spool"
MAX_BODY = 5 * 1024 * 1024
MAX_SPOOL = 512 * 1024 * 1024
MAX_SPOOL_ENTRIES = 16384
NAME_RE = re.compile(
    r"^(?:[0-9a-f-]{36}|(?:artifact|source)-[0-9a-f-]{36})-[0-9]{12}-[0-9a-f]{64}\.age$"
)


class SpoolFull(RuntimeError):
    pass


class AlreadyStored(RuntimeError):
    pass


def fsync_spool() -> None:
    descriptor = os.open(SPOOL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def trusted_regular(path: str, allowed_links: tuple[int, ...] = (1,)) -> os.stat_result | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink not in allowed_links
            or metadata.st_uid != os.geteuid()):
        raise ValueError("untrusted spool entry")
    return metadata


def file_matches(path: str, length: int, expected: str, *,
                 allowed_links: tuple[int, ...] = (1,), synchronize: bool = False) -> bool:
    if trusted_regular(path, allowed_links) is None:
        return False
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink not in allowed_links
                or metadata.st_uid != os.geteuid() or metadata.st_size != length):
            return False
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if synchronize:
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest.hexdigest() == expected


def recover_existing_chunk(final: str, temp: str, length: int, expected: str) -> bool:
    final_metadata = trusted_regular(final, (1, 2))
    temp_metadata = trusted_regular(temp, (1, 2))
    if final_metadata is None:
        return False
    if (temp_metadata is not None and final_metadata.st_nlink == 2
            and temp_metadata.st_nlink == 2
            and (final_metadata.st_dev, final_metadata.st_ino)
            == (temp_metadata.st_dev, temp_metadata.st_ino)):
        if not file_matches(
                final, length, expected, allowed_links=(2,), synchronize=True):
            raise ValueError("invalid linked spool recovery state")
        os.unlink(temp)
        fsync_spool()
        return True
    if final_metadata.st_nlink != 1 or not file_matches(final, length, expected):
        raise ValueError("conflicting final spool entry")
    if temp_metadata is not None:
        if temp_metadata.st_nlink != 1:
            raise ValueError("ambiguous temporary spool entry")
        os.unlink(temp)
        fsync_spool()
    return True


def spool_usage() -> tuple[int, int]:
    entries = 0
    total = 0
    with os.scandir(SPOOL) as iterator:
        for entry in iterator:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            entries += 1
            if entries > MAX_SPOOL_ENTRIES:
                raise SpoolFull("spool entry limit exceeded")
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or not (NAME_RE.fullmatch(entry.name)
                            or (entry.name.endswith(".new")
                                and NAME_RE.fullmatch(entry.name[:-4])))):
                raise ValueError("untrusted spool entry")
            total += metadata.st_size
            if total > MAX_SPOOL:
                raise SpoolFull("spool byte limit exceeded")
    return entries, total


def write_all(descriptor: int, body: bytes) -> None:
    view = memoryview(body)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short spool write")
        view = view[written:]


def publish_chunk(name: str, body: bytes, expected: str) -> None:
    final = os.path.join(SPOOL, name)
    temp = final + ".new"
    if recover_existing_chunk(final, temp, len(body), expected):
        raise AlreadyStored
    temp_metadata = trusted_regular(temp)
    entries, total = spool_usage()
    existing_temp_size = temp_metadata.st_size if temp_metadata is not None else 0
    if entries + (0 if temp_metadata is not None else 1) > MAX_SPOOL_ENTRIES:
        raise SpoolFull("spool entry limit exceeded")
    if total - existing_temp_size + len(body) > MAX_SPOOL:
        raise SpoolFull("spool byte limit exceeded")

    if temp_metadata is not None and not file_matches(
            temp, len(body), expected, synchronize=True):
        os.unlink(temp)
        fsync_spool()
        temp_metadata = None
    if temp_metadata is None:
        descriptor = os.open(
            temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640,
        )
        try:
            write_all(descriptor, body)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    try:
        os.link(temp, final, follow_symlinks=False)
    except FileExistsError:
        if not file_matches(final, len(body), expected):
            raise ValueError("conflicting final spool entry")
        os.unlink(temp)
        fsync_spool()
        raise AlreadyStored
    fsync_spool()
    os.unlink(temp)
    fsync_spool()


class Server(BoundedHTTPServer):
    allow_reuse_address = True


class Handler(AbsoluteFramingHandler, BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SecureSandboxArchive/1"
    sys_version = ""
    def log_message(self, *_): return
    def authorized(self):
        certificate=self.connection.getpeercert(binary_form=True)
        return bool(certificate) and hashlib.sha256(certificate).hexdigest() in self.server.allowed_fingerprints
    def reply(self, status, value):
        if not self.complete_framing(): self.close_connection=True; return
        body=json.dumps(value,separators=(",",":")).encode(); self.send_response(status)
        self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body)))
        self.send_header("Connection","close"); self.end_headers(); self.wfile.write(body); self.close_connection=True
    def do_GET(self):
        self.reply(200,{"status":"ok"}) if self.authorized() and self.path=="/healthz" else self.reply(404,{"error":"not_found"})
    def do_PUT(self):
        if not self.authorized(): return self.reply(403,{"error":"not_authorized"})
        name=self.path.removeprefix("/v1/chunks/")
        if not self.path.startswith("/v1/chunks/") or not NAME_RE.fullmatch(name): return self.reply(404,{"error":"not_found"})
        try:
            if self.headers.get("Transfer-Encoding") is not None: raise ValueError
            lengths=self.headers.get_all("Content-Length",failobj=[])
            if len(lengths)!=1: raise ValueError
            length=int(lengths[0]); expected=self.headers.get("X-Content-SHA256","")
            if not 1<=length<=MAX_BODY or expected!=name[-68:-4]: raise ValueError
            final=os.path.join(SPOOL,name)
            temp=final+".new"
            if recover_existing_chunk(final, temp, length, expected):
                return self.reply(412,{"status":"exists"})
            body=self.read_exact_body(length)
            if len(body)!=length or hashlib.sha256(body).hexdigest()!=expected: raise ValueError
            publish_chunk(name, body, expected)
        except AlreadyStored:
            return self.reply(412,{"status":"exists"})
        except SpoolFull:
            return self.reply(507,{"error":"spool_full"})
        except RequestIncomplete:
            self.close_connection=True; return
        except (OSError,ValueError): return self.reply(400,{"error":"invalid_chunk"})
        if name.startswith("artifact-"):
            event="artifact_received"
        elif name.startswith("source-"):
            event="source_manifest_received"
        else:
            event="conversation_chunk_received"
        print(json.dumps({"event":event,"name":name,"bytes":length}),flush=True)
        self.reply(201,{"status":"stored"})
    def framing_expired(self):
        print(json.dumps({"event":"conversation_chunk_rejected","error":"request_incomplete"},separators=(",",":"),sort_keys=True),flush=True)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--config",required=True); args=parser.parse_args()
    with open(args.config,encoding="utf-8") as h: config=json.load(h)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.verify_mode=ssl.CERT_REQUIRED; context.load_cert_chain(config["server_certificate"],config["server_private_key"])
    context.load_verify_locations(cafile=config["client_ca_certificate"])
    allowed=config.get("allowed_client_sha256",[])
    if not isinstance(allowed,list) or not allowed or not all(isinstance(v,str) and len(v)==64 for v in allowed): raise SystemExit("invalid client allowlist")
    server=Server(LISTEN,Handler,tls_context=context); server.allowed_fingerprints=set(allowed); server.serve_forever(.5)

if __name__=="__main__": main()
