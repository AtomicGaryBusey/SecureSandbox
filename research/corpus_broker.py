#!/usr/bin/env python3
"""Trusted local broker for receipt-producing corpus operations."""

from __future__ import annotations

import json
import os
import pwd
import socket
import syslog
import time

from bounded_unix_server import serve

from corpus_intelligence import CorpusError, CorpusQueryTimeout, scan_corpus, search_corpus
from evidence_receipts import ReceiptError, active_run, publish, request_hash
from source_integrity import IntegrityError

MAX_BODY = 64 * 1024
REQUEST_READ_SECONDS = 5
SOCKET_PATH = "/run/secure-sandbox-corpus/corpus.sock"
OPERATIONS = {
    "search_corpus": (search_corpus, {"source_id","query","case_sensitive","path_prefix","extensions","offset","limit","context_lines"}),
    "scan_corpus": (scan_corpus, {"source_id","profile","path_prefix","extensions","offset","limit"}),
}


def audit(event: str, instrument: str = "", receipt_id: str = "", status: str = "") -> None:
    value={"event":event,"instrument":instrument[:32],"receipt_id":receipt_id[:64],"status":status[:64]}
    try:
        syslog.openlog("secure-sandbox-evidence-receipts",syslog.LOG_PID,syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO if event == "receipt_published" else syslog.LOG_WARNING,
                      json.dumps(value,separators=(",",":"),sort_keys=True))
    except Exception: pass


def execute(value: object) -> dict:
    if not isinstance(value,dict) or set(value) != {"operation","arguments"}:
        raise CorpusError("invalid_request")
    operation=value["operation"]; arguments=value["arguments"]
    if operation not in OPERATIONS or not isinstance(arguments,dict) or set(arguments)-OPERATIONS[operation][1]:
        raise CorpusError("invalid_request")
    run_id=active_run()
    payload=OPERATIONS[operation][0](**arguments)
    if payload.get("exhaustive") is not True:
        raise CorpusError("result_not_exhaustive")
    projection={"class":"exhaustive_corpus_search","source_id":payload["source_id"],
        "instrument":operation,"run_id":run_id,"request_sha256":request_hash(operation,arguments),
        "result_set_sha256":payload["result_set_sha256"],"exhaustive":True}
    receipt=publish("corpus-broker",operation,projection)
    payload["evidence_receipt"]=receipt
    return payload


def handle(raw: bytes) -> bytes:
    operation=""
    try:
        value=json.loads(raw); operation=str(value.get("operation","")) if isinstance(value,dict) else ""
        result=execute(value)
    except CorpusQueryTimeout as error:
        result={"status":"rejected","error":str(error),**error.safe_metrics}; audit("receipt_rejected",operation,status=str(error))
    except (CorpusError,IntegrityError,ReceiptError,TypeError,json.JSONDecodeError) as error:
        result={"status":"rejected","error":str(error)}; audit("receipt_rejected",operation,status=str(error))
    except Exception as error:
        result={"status":"rejected","error":"internal_error"}; audit("receipt_failed",operation,status=type(error).__name__)
    return json.dumps(result,separators=(",",":"),sort_keys=True).encode()+b"\n"


def receive_request(connection: socket.socket) -> bytes:
    deadline=time.monotonic()+REQUEST_READ_SECONDS; chunks=bytearray()
    while len(chunks)<=MAX_BODY:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError("request_deadline_exceeded")
        connection.settimeout(min(1.0,remaining))
        chunk=connection.recv(min(4096,MAX_BODY+1-len(chunks)))
        if not chunk: break
        chunks.extend(chunk)
    if len(chunks)>MAX_BODY: return b'{"status":"rejected","error":"request_too_large"}\n'
    return handle(bytes(chunks))


def main()->None:
    def bounded_handle(raw: bytes) -> bytes:
        if len(raw)>MAX_BODY: return b'{"status":"rejected","error":"request_too_large"}\n'
        return handle(raw)
    rejected=lambda error: json.dumps({"status":"rejected","error":error},separators=(",",":"),sort_keys=True).encode()+b"\n"
    serve(SOCKET_PATH,MAX_BODY,REQUEST_READ_SECONDS,bounded_handle,
          lambda: rejected("request_incomplete"),
          allowed_uids={0,pwd.getpwnam("agent").pw_uid},
          unauthorized=lambda: rejected("unauthorized_peer"),
          overloaded=lambda: rejected("broker_busy"),
          failed=lambda: rejected("internal_error"))


if __name__=="__main__": main()
