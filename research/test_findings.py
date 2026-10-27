#!/usr/bin/env python3

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import finding_admin
import evidence_receipts
import findings_broker
import findings_mcp


def uid4(): return str(uuid.uuid4())
def sha(character="a"): return character * 64


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.state = self.root / "state"; self.state.mkdir(mode=0o700)
        for name in ("candidates","amendments","adjudication","snapshots","archive"):
            (self.state/name).mkdir(mode=0o700)
        self.run_id = uid4(); self.marker = self.root/"run-id"; self.marker.write_text(self.run_id+"\n"); self.marker.chmod(0o644)
        self.policy = self.root/"policy.sha256"; self.policy.write_text(sha("f")+"\n"); self.policy.chmod(0o644)
        self.source_id=uid4(); self.commit="1"*40
        self.index=self.root/"INDEX.json"
        self.index.write_text(json.dumps({"schema":"secure-sandbox-source-registry-v1","sources":[{
            "source_id":self.source_id,"tree_manifest_sha256":sha("b"),"resolved_commit":self.commit,
            "baseline_path":f"baselines/{self.source_id}"}]})+"\n")
        self.workspace=self.root/"workspace"; (self.workspace/"reports").mkdir(parents=True)
        source_file=self.workspace/"baselines"/self.source_id/"src"/"a.py"
        source_file.parent.mkdir(parents=True); source_file.write_text("\n"*7+"pass\n")
        (self.workspace/"reports"/"proof.md").write_text("measured proof\n")
        self.graphs=self.root/"graphs"; self.graphs.mkdir()
        (self.graphs/f"{self.source_id}.json").write_text(json.dumps({"source_id":self.source_id,"codegraph_index_sha256":sha("c")}))
        self.receipts=self.root/"receipts"; self.receipts.mkdir(mode=0o750)
        (self.receipts/"corpus").mkdir(mode=0o750); (self.receipts/"execution").mkdir(mode=0o750)
        self.kw={"state_dir":self.state,"run_id_file":self.marker,"policy_file":self.policy,"source_index":self.index,
                 "workspace":self.workspace,"codegraph_indexes":self.graphs,"receipt_registry":self.receipts,
                 "trusted_uid":os.geteuid(),"state_owner_uid":os.geteuid(),"receipt_root_uid":os.geteuid(),
                 "receipt_producer_uids":{"corpus-broker":os.geteuid(),"execution-broker":os.geteuid()},
                 "receipt_group_gid":os.getegid()}
        self.admin_uid=mock.patch.object(finding_admin,"TRUSTED_UID",os.geteuid()); self.admin_uid.start()

    def tearDown(self):
        self.admin_uid.stop(); self.temp.cleanup()

    def evidence(self, kind="static_source_review"):
        if kind=="static_source_review": return {"class":kind,"source_id":self.source_id,"path":"src/a.py","line":7}
        if kind=="measured_execution":
            projection={"class":kind,"source_id":self.source_id,"request_id":uid4(),"run_id":self.run_id,
                "session_id":uid4(),"approval_id":uid4(),"approval_attestation_sha256":sha("6"),
                "code_sha256":sha("2"),"stdout_sha256":sha("3"),"stderr_sha256":sha("9"),
                "fixture_manifest_sha256":sha("4"),"image_digest":"sha256:"+sha("5"),"exit_code":0,
                "timed_out":False,"output_limit_exceeded":False,"stdout_truncated":False,"stderr_truncated":False,
                "timeout_seconds":5,"duration_ms":17}
            return evidence_receipts.publish("execution-broker","run_python_fixture",projection,self.receipts,os.geteuid(),os.getegid(),os.geteuid())
        if kind=="exhaustive_corpus_search":
            projection={"class":kind,"source_id":self.source_id,"instrument":"search_corpus","run_id":self.run_id,
                "request_sha256":sha("7"),"result_set_sha256":sha("8"),"exhaustive":True}
            return evidence_receipts.publish("corpus-broker","search_corpus",projection,self.receipts,os.geteuid(),os.getegid(),os.geteuid())
        if kind=="static_graph_reachability": return {"class":kind,"source_id":self.source_id,"analysis_id":sha("6"),
            "codegraph_index_sha256":sha("c"),"measured_execution":False,"exhaustive":False,"caller_selected_entrypoint":True}
        if kind=="report_reference": return {"class":kind,"path":"reports/proof.md"}
        raise AssertionError

    def candidate(self, evidence=None, claim="Function contains an unsafe branch"):
        return {"claim":claim,"affected":[{"source_id":self.source_id,"path":"src/a.py","symbol":"unsafe","line":7}],
            "evidence":evidence or [self.evidence()],"reproduction_conditions":"Attacker controls input under default configuration.",
            "limitations":"Static review does not prove execution.","counterargument":"Validation may reject the input earlier.",
            "proposed_severity":"high","severity_rationale":"The affected boundary is privileged."}

    def submit(self, value=None): return findings_broker.submit_candidate(value or self.candidate(),**self.kw)

    def action(self, finding_id, state, method="inspected_evidence", consulted=None):
        return {"action":"transition","finding_id":finding_id,"to_state":state,"verification_method":method,
            "consulted_evidence":consulted or [],"actor":{"id":"architect","role":"architect"},
            "rationale":"Evidence was independently inspected.","conflict_note":"Architect authored the reviewed mechanism."}

    def evidence_digest(self, finding_id):
        record=json.loads((self.state/"candidates"/f"{finding_id}.json").read_text())
        return hashlib.sha256(findings_broker.canonical(record["evidence"][0])).hexdigest()

    def test_submit_is_immutable_server_bound_and_replay_safe(self):
        result=self.submit(); self.assertEqual(result["authority"],"candidate_only")
        record=json.loads((self.state/"candidates"/f'{result["finding_id"]}.json').read_text())
        self.assertEqual(record["run_id"],self.run_id); self.assertEqual(record["policy_generation"],sha("f"))
        self.assertEqual(record["status"],"candidate"); self.assertEqual((self.state/"candidates"/f'{result["finding_id"]}.json').stat().st_mode&0o777,0o600)
        replay=self.submit(); self.assertEqual(replay["status"],"already_submitted"); self.assertEqual(replay["finding_id"],result["finding_id"])

    def test_rejects_authority_fields_bad_source_and_untrusted_run_marker(self):
        value=self.candidate(); value["status"]="validated"
        with self.assertRaisesRegex(findings_broker.FindingError,"candidate_schema_invalid"): self.submit(value)
        value=self.candidate(); value["affected"][0]["source_id"]=uid4()
        with self.assertRaisesRegex(findings_broker.FindingError,"source_not_registered"): self.submit(value)
        self.marker.chmod(0o666)
        with self.assertRaisesRegex(findings_broker.FindingError,"active_run_required"): self.submit()

    def test_unrelated_non_git_source_does_not_poison_registry(self):
        index=json.loads(self.index.read_text())
        index["sources"].append({"source_id":uid4(),"tree_manifest_sha256":sha("9"),"package":"example@1.0.0"})
        self.index.write_text(json.dumps(index))
        self.assertEqual(self.submit()["status"],"submitted")

    def test_partial_temporary_record_is_swept_but_corrupt_final_record_blocks(self):
        temporary=self.state/"candidates"/f".{uid4()}.999.new"
        temporary.write_text("partial"); temporary.chmod(0o600)
        self.assertEqual(self.submit()["status"],"submitted"); self.assertFalse(temporary.exists())
        corrupt=self.state/"candidates"/f"{uid4()}.json"; corrupt.write_text("partial"); corrupt.chmod(0o600)
        self.marker.write_text(uid4()+"\n")
        with self.assertRaisesRegex(findings_broker.FindingError,"finding_state_untrusted"): self.submit()

    def test_publication_never_overwrites_an_existing_final_record(self):
        target=self.state/"candidates"/f"{uid4()}.json"
        target.write_text("original\n"); target.chmod(0o600)
        with self.assertRaises(FileExistsError):
            findings_broker.publish(target,{"replacement":True})
        self.assertEqual(target.read_text(),"original\n")
        self.assertFalse((target.parent/f".{target.stem}.{os.getpid()}.new").exists())

    def test_rejects_nonexistent_or_symlinked_source_paths(self):
        value=self.candidate(); value["affected"][0]["path"]="src/missing.py"
        with self.assertRaisesRegex(findings_broker.FindingError,"source_path_invalid"): self.submit(value)
        link=self.workspace/"baselines"/self.source_id/"src"/"link.py"; link.symlink_to("a.py")
        value=self.candidate(); value["evidence"][0]["path"]="src/link.py"
        with self.assertRaisesRegex(findings_broker.FindingError,"source_path_invalid"): self.submit(value)

    def test_typed_graph_and_report_evidence_are_bound(self):
        result=self.submit(self.candidate([self.evidence("static_graph_reachability"),self.evidence("report_reference")]))
        record=json.loads((self.state/"candidates"/f'{result["finding_id"]}.json').read_text())
        report=record["evidence"][1]; self.assertEqual(report["content_sha256"],hashlib.sha256(b"measured proof\n").hexdigest())
        bad=self.evidence("static_graph_reachability"); bad["codegraph_index_sha256"]=sha("d")
        with self.assertRaisesRegex(findings_broker.FindingError,"codegraph_anchor_mismatch"): self.submit(self.candidate([bad]))

    def test_receipt_backed_evidence_rejects_fabrication_and_mismatch(self):
        valid=self.evidence("exhaustive_corpus_search")
        self.assertEqual(self.submit(self.candidate([valid]))["claim_evidence_support"],"supported")
        self.marker.write_text(uid4()+"\n")
        forged=dict(valid); forged["result_set_sha256"]=sha("9")
        with self.assertRaisesRegex(findings_broker.FindingError,"receipt_projection_mismatch"):
            self.submit(self.candidate([forged]))
        missing=dict(valid); missing["receipt_id"]=uid4()
        with self.assertRaisesRegex(findings_broker.FindingError,"receipt_unavailable"):
            self.submit(self.candidate([missing]))

    def test_execution_claim_is_linted_and_validation_requires_reexecution(self):
        result=self.submit(self.candidate([self.evidence("measured_execution")],"Handler executes an unsafe command"))
        self.assertEqual(result["claim_evidence_support"],"supported"); digest=self.evidence_digest(result["finding_id"])
        with self.assertRaisesRegex(findings_broker.FindingError,"execution_reverification_required"):
            finding_admin.append_event(self.action(result["finding_id"],"validated",consulted=[digest]),self.state)
        recorded=finding_admin.append_event(self.action(result["finding_id"],"validated","re_executed",[digest]),self.state)
        self.assertEqual(recorded["authority"],"operator_adjudication")
        self.assertEqual(finding_admin.verify_journal(self.state/"adjudication"/"journal.jsonl")[0]["authority"],"operator_adjudication")

    def test_cross_run_receipt_is_intentionally_durable_evidence(self):
        earlier_run=uid4()
        projection={"class":"exhaustive_corpus_search","source_id":self.source_id,"instrument":"search_corpus",
            "run_id":earlier_run,"request_sha256":sha("7"),"result_set_sha256":sha("8"),"exhaustive":True}
        receipt=evidence_receipts.publish("corpus-broker","search_corpus",projection,self.receipts,os.geteuid(),os.getegid(),os.geteuid())
        result=self.submit(self.candidate([receipt]))
        self.assertEqual(result["status"],"submitted")
        self.assertEqual(receipt["run_id"],earlier_run)

    def test_amendment_never_changes_state_and_is_replay_safe(self):
        result=self.submit(); request={"finding_id":result["finding_id"],"evidence":[self.evidence("report_reference")],
            "limitations":"Still bounded.","counterargument":"Could be configuration-specific.","note":"Added a review report."}
        amended=findings_broker.submit_amendment(request,**self.kw); replay=findings_broker.submit_amendment(request,**self.kw)
        self.assertEqual(amended["status"],"amended"); self.assertEqual(replay["amendment_id"],amended["amendment_id"])
        self.assertEqual(finding_admin.show_finding(result["finding_id"],self.state)["current_state"],"candidate")

    def test_hash_chained_transitions_and_illegal_transition(self):
        result=self.submit(); fid=result["finding_id"]
        finding_admin.append_event(self.action(fid,"needs_evidence","reasoning_only"),self.state)
        finding_admin.append_event(self.action(fid,"rejected","inspected_evidence"),self.state)
        events=finding_admin.verify_journal(self.state/"adjudication"/"journal.jsonl")
        self.assertEqual(events[1]["prev_entry_sha256"],events[0]["entry_sha256"])
        with self.assertRaisesRegex(findings_broker.FindingError,"transition_invalid"):
            finding_admin.append_event(self.action(fid,"validated","re_executed",[self.evidence_digest(fid)]),self.state)

    def test_validation_snapshots_report_and_detects_mutation(self):
        result=self.submit(self.candidate([self.evidence("report_reference")]))
        digest=self.evidence_digest(result["finding_id"]); (self.workspace/"reports"/"proof.md").write_text("changed\n")
        with mock.patch.object(finding_admin,"WORKSPACE",self.workspace):
            with self.assertRaisesRegex(findings_broker.FindingError,"evidence_report_changed"):
                finding_admin.append_event(self.action(result["finding_id"],"validated",consulted=[digest]),self.state)

    def test_reopen_requires_post_terminal_evidence_and_snapshot_set_can_grow(self):
        result=self.submit(self.candidate([self.evidence("report_reference")]))
        fid=result["finding_id"]; first=self.evidence_digest(fid)
        with mock.patch.object(finding_admin,"WORKSPACE",self.workspace):
            finding_admin.append_event(self.action(fid,"validated",consulted=[first]),self.state)
            terminal=finding_admin.verify_journal(self.state/"adjudication"/"journal.jsonl")[-1]
            self.assertEqual(terminal["terminal_evidence_sha256"],[first])
            reopen={"action":"reopen","finding_id":fid,"new_evidence_sha256":first,
                "actor":{"id":"operator","role":"research_lead"},"rationale":"Reconsider.","conflict_note":"No conflict."}
            with self.assertRaisesRegex(findings_broker.FindingError,"reopen_evidence_required"):
                finding_admin.append_event(reopen,self.state)
            (self.workspace/"reports"/"copy.md").write_text("measured proof\n")
            self.marker.write_text(uid4()+"\n")
            copied=findings_broker.submit_amendment({"finding_id":fid,
                "evidence":[{"class":"report_reference","path":"reports/copy.md"}],
                "limitations":"Same bytes at a new path.","counterargument":"This is not substantively new.",
                "note":"Copied pre-terminal report."},**self.kw)
            copied_record=json.loads((self.state/"amendments"/f'{copied["amendment_id"]}.json').read_text())
            copied_digest=hashlib.sha256(findings_broker.canonical(copied_record["evidence"][0])).hexdigest()
            reopen["new_evidence_sha256"]=copied_digest
            with self.assertRaisesRegex(findings_broker.FindingError,"reopen_evidence_required"):
                finding_admin.append_event(reopen,self.state)
            (self.workspace/"reports"/"proof2.md").write_text("new proof\n")
            self.marker.write_text(uid4()+"\n")
            amendment=findings_broker.submit_amendment({"finding_id":fid,
                "evidence":[{"class":"report_reference","path":"reports/proof2.md"}],
                "limitations":"Still bounded.","counterargument":"May remain non-security relevant.",
                "note":"New post-terminal evidence."},**self.kw)
            record=json.loads((self.state/"amendments"/f'{amendment["amendment_id"]}.json').read_text())
            second=hashlib.sha256(findings_broker.canonical(record["evidence"][0])).hexdigest()
            reopen["new_evidence_sha256"]=second
            finding_admin.append_event(reopen,self.state)
            finding_admin.append_event(self.action(fid,"validated",consulted=[first,second]),self.state)
        self.assertEqual(len(list((self.state/"snapshots"/fid).glob("*.evidence"))),2)

    def test_dispute_transition_and_invalid_relation_fail_closed(self):
        one=self.submit(); self.marker.write_text(uid4()+"\n"); two=self.submit()
        finding_admin.append_event(self.action(one["finding_id"],"disputed","reasoning_only"),self.state)
        self.assertEqual(finding_admin.show_finding(one["finding_id"],self.state)["current_state"],"disputed")
        relation={"action":"relation","finding_id":two["finding_id"],"relation":"duplicate_of",
            "target_finding_id":two["finding_id"],"actor":{"id":"operator","role":"research_lead"},
            "rationale":"Invalid self relation.","conflict_note":"No conflict."}
        with self.assertRaisesRegex(findings_broker.FindingError,"relation_invalid"):
            finding_admin.append_event(relation,self.state)

    def test_relation_and_disposition_free_active_capacity_without_deletion(self):
        one=self.submit(); self.marker.write_text(uid4()+"\n"); two=self.submit()
        relation={"action":"relation","finding_id":two["finding_id"],"relation":"duplicate_of","target_finding_id":one["finding_id"],
            "actor":{"id":"operator","role":"research_lead"},"rationale":"Same root cause.","conflict_note":"No conflict."}
        finding_admin.append_event(relation,self.state)
        finding_admin.append_event(self.action(one["finding_id"],"rejected","inspected_evidence"),self.state)
        disposed=finding_admin.disposition({"action":"dispose","finding_id":one["finding_id"],"actor":{"id":"operator","role":"research_lead"},
            "rationale":"Terminal record archived.","conflict_note":"No conflict."},self.state)
        self.assertEqual(disposed["status"],"disposed"); self.assertTrue((self.state/"archive"/one["finding_id"]/"candidate.json").exists())
        self.assertFalse((self.state/"candidates"/f'{one["finding_id"]}.json').exists())
        replay=finding_admin.disposition({"action":"dispose","finding_id":one["finding_id"],"actor":{"id":"operator","role":"research_lead"},
            "rationale":"Terminal record archived.","conflict_note":"No conflict."},self.state)
        self.assertEqual(replay["content_sha256"],disposed["content_sha256"])

    def test_defensive_listing_survives_corrupt_record(self):
        self.submit(); (self.state/"candidates"/f"{uid4()}.json").write_text("not json\n")
        listed=finding_admin.list_findings(self.state); self.assertTrue(any(item["state"]=="invalid" for item in listed))

    def test_mcp_exposes_only_submit_and_amend(self):
        listed=findings_mcp.handle({"jsonrpc":"2.0","id":1,"method":"tools/list"})
        self.assertEqual([tool["name"] for tool in listed["result"]["tools"]],["submit_candidate_finding","amend_candidate_finding"])
        invalid=self.candidate(); invalid["adjudicator"]="glm"
        response=findings_mcp.handle({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"submit_candidate_finding","arguments":invalid}})
        self.assertEqual(response["error"]["message"],"invalid_arguments")

    def test_transport_rejections_are_audited(self):
        with mock.patch.object(findings_broker,"audit") as audit:
            response=findings_broker.rejected_response("request_too_large")
        self.assertEqual(json.loads(response)["error"],"request_too_large")
        audit.assert_called_once_with({"status":"rejected","error":"request_too_large"},"invalid")

    def test_mcp_oversized_payload_reaches_the_trusted_broker(self):
        sent=bytearray()
        class FakeSocket:
            returned=False
            def settimeout(self, timeout): pass
            def connect(self, path): pass
            def sendall(self, value): sent.extend(value)
            def shutdown(self, direction): pass
            def recv(self, size):
                if self.returned: return b""
                self.returned=True
                return b'{"status":"rejected","error":"request_too_large"}'
            def close(self): pass
        with mock.patch.object(findings_mcp.socket,"socket",return_value=FakeSocket()):
            result=findings_mcp.broker("submit",{"claim":"x"*(findings_mcp.MAX_REQUEST_BYTES+1)})
        self.assertGreater(len(sent),findings_mcp.MAX_REQUEST_BYTES)
        self.assertEqual(result["error"],"request_too_large")

    def test_mcp_framing_rejection_is_forwarded_for_trusted_audit(self):
        class Input:
            def __init__(self): self.buffer=self; self.lines=[b"x"*(128*1024+1),b"tail\n",b""]
            def readline(self, size):
                return self.lines.pop(0)
        with (mock.patch.object(findings_mcp.sys,"stdin",Input()),
              mock.patch.object(findings_mcp,"broker",return_value={"status":"rejected"}) as broker,
              mock.patch("builtins.print")):
            findings_mcp.main()
        broker.assert_called_once_with("transport_reject",{"error":"request_too_large"})

    def test_transport_rejection_operation_accepts_only_fixed_error_tokens(self):
        with mock.patch.object(findings_broker,"audit") as audit:
            result=json.loads(findings_broker.handle(findings_broker.canonical({
                "operation":"transport_reject","arguments":{"error":"request_incomplete"}})))
        self.assertEqual(result,{"status":"rejected","error":"request_incomplete"})
        audit.assert_called_once_with(result,"invalid")

    def test_findings_broker_enforces_total_request_deadline(self):
        connection=mock.Mock(); connection.recv.return_value=b"x"
        with mock.patch.object(findings_broker.time,"monotonic",side_effect=[0,1,2,3,4,5]):
            with self.assertRaisesRegex(TimeoutError,"request_deadline_exceeded"):
                findings_broker.receive_request(connection)


if __name__=="__main__": unittest.main()
