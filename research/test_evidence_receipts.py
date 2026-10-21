#!/usr/bin/env python3

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import corpus_broker
import corpus_intelligence_mcp
import evidence_receipts


def uid4(): return str(uuid.uuid4())
def sha(c="a"): return c*64


class EvidenceReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name); self.root.chmod(0o750)
        for name in ("corpus","execution"): (self.root/name).mkdir(mode=0o750)
        self.uid=os.geteuid(); self.gid=os.getegid(); self.source=uid4(); self.run=uid4()

    def tearDown(self): self.temp.cleanup()

    def corpus_projection(self):
        return {"class":"exhaustive_corpus_search","source_id":self.source,"instrument":"search_corpus",
            "run_id":self.run,"request_sha256":sha("b"),"result_set_sha256":sha("c"),"exhaustive":True}

    def execution_projection(self):
        return {"class":"measured_execution","source_id":self.source,"request_id":uid4(),"run_id":self.run,
            "code_sha256":sha("a"),"stdout_sha256":sha("b"),"stderr_sha256":sha("c"),
            "fixture_manifest_sha256":sha("d"),"image_digest":"sha256:"+sha("e"),"exit_code":1,
            "timed_out":False,"output_limit_exceeded":False,"stdout_truncated":False,"stderr_truncated":False,
            "timeout_seconds":5,"duration_ms":42}

    def test_publish_and_load_exact_projection(self):
        projection=evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)
        final=self.root/"corpus"/f'{projection["receipt_id"]}.json'
        orphan=self.root/"corpus"/f'.{projection["receipt_id"]}.999.new'; os.link(final,orphan)
        evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)
        self.assertFalse(orphan.exists()); self.assertEqual(final.stat().st_nlink,1)
        loaded=evidence_receipts.load_projection(projection["receipt_id"],projection["receipt_sha256"],
            "corpus-broker",self.root,self.uid,self.uid,self.gid)
        self.assertEqual(loaded,projection)
        self.assertNotIn("query",json.dumps(json.loads((self.root/"corpus"/f'{projection["receipt_id"]}.json').read_text())))

    def test_tamper_wrong_producer_and_untrusted_temporary_fail_closed(self):
        projection=evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)
        with self.assertRaisesRegex(evidence_receipts.ReceiptError,"receipt_invalid"):
            evidence_receipts.load_projection(projection["receipt_id"],sha("d"),"corpus-broker",self.root,self.uid,self.uid,self.gid)
        with self.assertRaisesRegex(evidence_receipts.ReceiptError,"receipt_unavailable"):
            evidence_receipts.load_projection(projection["receipt_id"],projection["receipt_sha256"],"execution-broker",self.root,self.uid,self.uid,self.gid)
        temporary=self.root/"corpus"/f".{uid4()}.999.new"; temporary.write_text("partial"); temporary.chmod(0o666)
        with self.assertRaisesRegex(evidence_receipts.ReceiptError,"receipt_state_untrusted"):
            evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)

    def test_atomic_publication_never_overwrites(self):
        fixed=uuid.UUID(uid4())
        with mock.patch.object(evidence_receipts.uuid,"uuid4",return_value=fixed):
            evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)
        final=self.root/"corpus"/f"{fixed}.json"; original=final.read_text()
        changed=self.corpus_projection(); changed["result_set_sha256"]=sha("d")
        with mock.patch.object(evidence_receipts.uuid,"uuid4",return_value=fixed):
            with self.assertRaises(FileExistsError):
                evidence_receipts.publish("corpus-broker","search_corpus",changed,self.root,self.uid,self.gid,self.uid)
        self.assertEqual(final.read_text(),original)

    def test_identical_projection_reuses_receipt(self):
        first=evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)
        second=evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)
        self.assertEqual(first,second); self.assertEqual(len(list((self.root/"corpus").glob("*.json"))),1)

    def test_per_run_and_global_capacity_are_distinct(self):
        with mock.patch.object(evidence_receipts,"MAX_RECEIPTS_PER_RUN",1):
            first=self.corpus_projection()
            evidence_receipts.publish("corpus-broker","search_corpus",first,self.root,self.uid,self.gid,self.uid)
            changed=self.corpus_projection(); changed["request_sha256"]=sha("d")
            with self.assertRaisesRegex(evidence_receipts.ReceiptError,"receipt_run_limit_exceeded"):
                evidence_receipts.publish("corpus-broker","search_corpus",changed,self.root,self.uid,self.gid,self.uid)
        other=self.corpus_projection(); other["run_id"]=uid4(); other["request_sha256"]=sha("e")
        with mock.patch.object(evidence_receipts,"MAX_RECEIPTS",1):
            with self.assertRaisesRegex(evidence_receipts.ReceiptError,"receipt_state_limit_exceeded"):
                evidence_receipts.publish("corpus-broker","search_corpus",other,self.root,self.uid,self.gid,self.uid)

    def test_corrupt_final_blocks_publication(self):
        path=self.root/"corpus"/f"{uid4()}.json"; path.write_text("not json\n"); path.chmod(0o640)
        with self.assertRaisesRegex(evidence_receipts.ReceiptError,"receipt_state_untrusted"):
            evidence_receipts.publish("corpus-broker","search_corpus",self.corpus_projection(),self.root,self.uid,self.gid,self.uid)

    def test_execution_outcome_and_digest_are_strict(self):
        projection=self.execution_projection()
        receipt=evidence_receipts.publish("execution-broker","run_python_fixture",projection,self.root,self.uid,self.gid,self.uid)
        self.assertEqual(receipt["exit_code"],1); self.assertIn("stderr_sha256",receipt)
        bad=self.execution_projection(); bad["image_digest"]=sha("e")
        with self.assertRaisesRegex(evidence_receipts.ReceiptError,"receipt_projection_invalid"):
            evidence_receipts.publish("execution-broker","run_python_fixture",bad,self.root,self.uid,self.gid,self.uid)

    def test_legacy_v1_execution_receipt_remains_readable(self):
        receipt_id=uid4(); evidence=self.execution_projection()
        for key in ("stderr_sha256","exit_code","timed_out","output_limit_exceeded","stdout_truncated","stderr_truncated",
                    "timeout_seconds","duration_ms"):
            evidence.pop(key)
        evidence.pop("class")
        record={"schema":evidence_receipts.LEGACY_SCHEMA,"receipt_id":receipt_id,"producer":"execution-broker",
            "instrument":"run_python_fixture","evidence_class":"measured_execution","produced_at":"2026-10-17T00:00:00Z","evidence":evidence}
        record["content_sha256"]=hashlib.sha256(evidence_receipts.canonical(record)).hexdigest()
        path=self.root/"execution"/f"{receipt_id}.json"; path.write_bytes(evidence_receipts.canonical(record)+b"\n"); path.chmod(0o640)
        loaded=evidence_receipts.load_projection(receipt_id,record["content_sha256"],"execution-broker",self.root,self.uid,self.uid,self.gid)
        self.assertNotIn("exit_code",loaded); self.assertEqual(loaded["class"],"measured_execution")

    def test_legacy_v2_execution_receipt_remains_readable(self):
        receipt_id=uid4(); evidence=self.execution_projection()
        evidence.pop("timeout_seconds"); evidence.pop("duration_ms"); evidence.pop("class")
        record={"schema":evidence_receipts.V2_SCHEMA,"receipt_id":receipt_id,"producer":"execution-broker",
            "instrument":"run_python_fixture","evidence_class":"measured_execution","produced_at":"2026-10-17T00:00:00Z","evidence":evidence}
        record["content_sha256"]=hashlib.sha256(evidence_receipts.canonical(record)).hexdigest()
        path=self.root/"execution"/f"{receipt_id}.json"; path.write_bytes(evidence_receipts.canonical(record)+b"\n"); path.chmod(0o640)
        loaded=evidence_receipts.load_projection(receipt_id,record["content_sha256"],"execution-broker",self.root,self.uid,self.uid,self.gid)
        self.assertNotIn("duration_ms",loaded); self.assertEqual(loaded["exit_code"],1)

    def test_active_run_rejects_untrusted_marker(self):
        marker=self.root/"run-id"; marker.write_text(self.run+"\n"); marker.chmod(0o666)
        with self.assertRaisesRegex(evidence_receipts.ReceiptError,"active_run_untrusted"):
            evidence_receipts.active_run(marker,self.uid)

    def test_active_run_requires_matching_active_lifecycle(self):
        marker=self.root/"run-id"; marker.write_text(self.run+"\n"); marker.chmod(0o600)
        lifecycle=self.root/"active.json"
        base={"schema":"secure-sandbox-run-lifecycle-v2","run_id":self.run,"phase":"closing"}
        lifecycle.write_text(json.dumps(base)+"\n"); lifecycle.chmod(0o644)
        with self.assertRaisesRegex(evidence_receipts.ReceiptError,"active_run_required"):
            evidence_receipts.active_run(marker,self.uid,lifecycle)
        base["phase"]="active"; lifecycle.write_text(json.dumps(base)+"\n")
        self.assertEqual(evidence_receipts.active_run(marker,self.uid,lifecycle),self.run)

    def test_corpus_broker_mints_receipt_from_computed_result(self):
        arguments={"source_id":self.source,"query":"needle"}
        payload={"source_id":self.source,"exhaustive":True,"result_set_sha256":sha("e")}
        receipt={"class":"exhaustive_corpus_search","receipt_id":uid4(),"receipt_sha256":sha("f")}
        operation=mock.Mock(return_value=payload)
        with (mock.patch.object(corpus_broker,"active_run",return_value=self.run),
              mock.patch.dict(corpus_broker.OPERATIONS,{"search_corpus":(operation,corpus_broker.OPERATIONS["search_corpus"][1])}),
              mock.patch.object(corpus_broker,"publish",return_value=receipt) as publish):
            result=corpus_broker.execute({"operation":"search_corpus","arguments":arguments})
        self.assertEqual(result["evidence_receipt"],receipt)
        projection=publish.call_args.args[2]
        self.assertEqual(projection["request_sha256"],evidence_receipts.request_hash("search_corpus",arguments))

    def test_mcp_uses_broker_for_exhaustive_operation(self):
        payload={"schema":"secure-sandbox-corpus-search-v1","source_id":self.source,"exhaustive":True,
            "result_set_sha256":sha("a"),"evidence_receipt":{"receipt_id":uid4()}}
        with mock.patch.object(corpus_intelligence_mcp,"broker",return_value=payload) as broker:
            response=corpus_intelligence_mcp.handle({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"search_corpus","arguments":{"source_id":self.source,"query":"needle"}}})
        self.assertFalse(response["result"]["isError"]); broker.assert_called_once()

    def test_corpus_broker_enforces_total_request_deadline(self):
        connection=mock.Mock(); connection.recv.return_value=b"x"
        with mock.patch.object(corpus_broker.time,"monotonic",side_effect=[0,1,2,3,4,5]):
            with self.assertRaisesRegex(TimeoutError,"request_deadline_exceeded"):
                corpus_broker.receive_request(connection)


if __name__=="__main__": unittest.main()
