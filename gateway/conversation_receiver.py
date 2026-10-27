#!/usr/bin/env python3
"""Receive opaque age-encrypted transcript chunks into a bounded durable spool."""

import argparse
import hashlib
import json
import os
import re
import ssl
from http.server import BaseHTTPRequestHandler

from shared.bounded_http import AbsoluteFramingHandler, BoundedHTTPServer, RequestIncomplete

LISTEN = ("172.30.10.1", 9553)
SPOOL = "/var/lib/secure-sandbox/conversation-spool"
MAX_BODY = 5 * 1024 * 1024
MAX_SPOOL = 512 * 1024 * 1024
NAME_RE = re.compile(
    r"^(?:[0-9a-f-]{36}|(?:artifact|source)-[0-9a-f-]{36})-[0-9]{12}-[0-9a-f]{64}\.age$"
)


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
            if sum(os.path.getsize(os.path.join(SPOOL,n)) for n in os.listdir(SPOOL)) + length > MAX_SPOOL: return self.reply(507,{"error":"spool_full"})
            body=self.read_exact_body(length)
            if len(body)!=length or hashlib.sha256(body).hexdigest()!=expected: raise ValueError
            final=os.path.join(SPOOL,name)
            if os.path.exists(final): return self.reply(412,{"status":"exists"})
            temp=final+".new"; fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
            try: os.write(fd,body); os.fsync(fd)
            finally: os.close(fd)
            os.replace(temp,final); dfd=os.open(SPOOL,os.O_RDONLY); os.fsync(dfd); os.close(dfd)
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
