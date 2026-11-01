#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from unittest import mock

from harness_lifecycle_qualification_fixture import (
    ACCEPTANCE_CASES,
    OBSERVER_SCOPE,
    QualificationFixtureError,
    REJECTED_ACCEPTANCE_CASES,
    run_case,
)
from harness_qualification import sha256_value
from harness_qualification_fixture import SyntheticDisposableSupervisor


class HarnessLifecycleQualificationFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 2_000_000_000
        self.qualification_id = "12345678-1234-4123-8123-123456789abc"

    def result(self, case_id: str, **kwargs):
        return run_case(
            case_id, self.now, qualification_id=self.qualification_id, **kwargs,
        )

    def test_all_acceptance_cases_bind_complete_non_admitting_report(self) -> None:
        for case_id, qualification_case in ACCEPTANCE_CASES.items():
            with self.subTest(case_id=case_id):
                value = self.result(case_id)
                self.assertEqual(value["status"], "verified")
                self.assertEqual(value["qualification_case_id"], qualification_case)
                self.assertEqual(value["qualification_case_result"]["status"], "passed")
                self.assertEqual(value["candidate_authority"], "none")
                self.assertFalse(value["production_material_used"])
                self.assertEqual(value["observer_scope"], OBSERVER_SCOPE)
                self.assertFalse(value["physical_evidence_eligible"])
                self.assertEqual(value["report"]["authority"], "none")
                self.assertEqual(len(value["report"]["case_results"]), 30)
                unsigned = dict(value)
                observed = unsigned.pop("fixture_result_sha256")
                self.assertEqual(observed, sha256_value(unsigned))

    def test_denial_cases_prove_attempt_or_secret_absence_without_effect(self) -> None:
        for case_id in REJECTED_ACCEPTANCE_CASES:
            with self.subTest(case_id=case_id):
                value = self.result(case_id)
                evidence = value["selected_evidence"]
                self.assertEqual(value["expected"], "rejected")
                if case_id == "qualification-deny-credential":
                    self.assertFalse(evidence["blocked"])
                    self.assertEqual(evidence["secret_markers"], [])
                else:
                    self.assertTrue(evidence["blocked"])
                    self.assertEqual(evidence["events"], ["policy_denial"])
                    self.assertEqual(len(evidence["attempts"]), 1)
                for field in (
                    "network_connections", "child_processes", "file_changes",
                    "secret_markers",
                ):
                    self.assertEqual(evidence[field], [])

    def test_unknown_case_and_selected_fault_fail_closed(self) -> None:
        with self.assertRaisesRegex(QualificationFixtureError, "case_invalid"):
            self.result("qualification-unknown")
        original = SyntheticDisposableSupervisor.observe

        def network_effect(supervisor, plan, case_id, sequence):
            value = original(supervisor, plan, case_id, sequence)
            if case_id == "isolation-provider-network":
                value["facts"]["network_connections"] = ["203.0.113.1:443"]
            return value

        with mock.patch.object(
            SyntheticDisposableSupervisor, "observe", network_effect,
        ):
            with self.assertRaisesRegex(QualificationFixtureError, "report_rejected"):
                self.result("qualification-deny-network")

    def test_caller_cannot_choose_fixture_path_or_inject_facts(self) -> None:
        with self.assertRaises(TypeError):
            run_case(
                "qualification-no-preexecution", self.now,
                fixture_path="/tmp/candidate.py",  # type: ignore[call-arg]
            )
        with self.assertRaises(TypeError):
            run_case(
                "qualification-no-preexecution", self.now,
                faults={},  # type: ignore[call-arg]
            )

    def test_result_is_canonicalizable_and_contains_no_admission_authority(self) -> None:
        value = self.result("qualification-no-preexecution")
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        self.assertNotIn(b'"authority":"admission"', encoded)
        self.assertNotIn(b'"physical_evidence_eligible":true', encoded)


if __name__ == "__main__":
    unittest.main()
