#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from shared import native_deployment as deployment


class NativeDeploymentContractTests(unittest.TestCase):
    def package(self, role: str = "gateway") -> dict:
        return deployment.make_package(role, [
            {"name": "a.py", "size": 10, "sha256": "a" * 64, "mode": 0o600},
            {"name": "installer.sh", "size": 20, "sha256": "b" * 64,
             "mode": 0o700},
        ])

    def plan(self) -> dict:
        return deployment.make_plan(
            deployment_id="11111111-1111-4111-8111-111111111111",
            host_release_id="1" * 64,
            catalog_sha256="2" * 64,
            gateway_package_sha256="3" * 64,
            research_package_sha256="4" * 64,
            previous_gateway_package_sha256=None,
            previous_research_package_sha256="5" * 64,
            previous_gateway_status_sha256="6" * 64,
            previous_research_status_sha256="7" * 64,
            created_at=1000,
            expires_at=1300,
        )

    def test_package_is_sorted_exact_and_digest_bound(self) -> None:
        value = self.package()
        self.assertEqual([item["name"] for item in value["files"]], [
            "a.py", "installer.sh",
        ])
        self.assertEqual(deployment.validate_package(value), value)
        changed = copy.deepcopy(value)
        changed["files"][0]["size"] += 1
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError, "native_deployment_package_invalid"
        ):
            deployment.validate_package(changed)

    def test_plan_binds_both_packages_predecessors_and_catalog(self) -> None:
        value = self.plan()
        self.assertEqual(deployment.validate_plan(value, now=1100), value)
        identity = deployment.fence_identity(value)
        self.assertEqual(identity["promotion_id"], value["deployment_id"])
        self.assertEqual(identity["plan_sha256"], value["plan_sha256"])
        self.assertEqual(identity["catalog_sha256"], value["catalog_sha256"])
        self.assertEqual(
            identity["previous_catalog_sha256"], value["catalog_sha256"]
        )
        for field in (
            "gateway_package_sha256", "research_package_sha256",
            "previous_gateway_package_sha256",
            "previous_research_package_sha256",
            "previous_gateway_status_sha256",
            "previous_research_status_sha256", "catalog_sha256",
        ):
            changed = copy.deepcopy(value)
            changed[field] = "f" * 64 if changed[field] != "f" * 64 else "e" * 64
            with self.assertRaisesRegex(
                deployment.NativeDeploymentError, "native_deployment_plan_invalid"
            ):
                deployment.validate_plan(changed, now=1100)

    def test_plan_expiry_and_extra_fields_fail_closed(self) -> None:
        value = self.plan()
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError, "native_deployment_plan_expired"
        ):
            deployment.validate_plan(value, now=value["expires_at"])
        value["fallback"] = True
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError, "native_deployment_plan_invalid"
        ):
            deployment.validate_plan(value, now=1100)

    def test_fence_and_release_requests_are_canonical_and_exact(self) -> None:
        plan = self.plan()
        fence = deployment.make_fence_request(plan)
        release = deployment.make_release_request(plan)
        self.assertEqual(
            deployment.validate_fence_request(fence, now=1100), fence
        )
        self.assertEqual(
            deployment.validate_release_request(release, now=1100), release
        )
        changed = copy.deepcopy(fence)
        changed["plan"]["catalog_sha256"] = "f" * 64
        with self.assertRaises(deployment.NativeDeploymentError):
            deployment.validate_fence_request(changed, now=1100)

    def test_recovery_fence_binds_fresh_recovery_authority_to_expired_plan(self) -> None:
        plan = self.plan()
        authorization = deployment.make_authorization(
            plan,
            authorization_id="22222222-2222-4222-8222-222222222222",
            request_sha256="8" * 64,
            pending_receipt_sha256="9" * 64,
            requesting_agent_sha256="a" * 64,
            requesting_session_sha256="b" * 64,
            authorized_at=1400, expires_at=1450,
            operation=deployment.RECOVER_OPERATION,
            recovery_action="resume", active_journal_sha256="c" * 64)
        request = deployment.make_recovery_fence_request(plan, authorization)
        self.assertEqual(
            deployment.validate_recovery_fence_request(request, now=1401),
            request)
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError,
            "native_deployment_authorization_invalid",
        ):
            deployment.validate_recovery_fence_request(request, now=1450)
        changed = copy.deepcopy(request)
        changed["authorization"]["recovery_action"] = "rollback"
        with self.assertRaises(deployment.NativeDeploymentError):
            deployment.validate_recovery_fence_request(changed, now=1401)

    def test_status_distinguishes_exact_absence_and_verified_generation(self) -> None:
        absent = deployment.make_status(
            role="gateway", state="absent", generation_kind="absent",
            package_sha256=None,
            release_id=None, catalog_sha256=None,
            closed_evidence_sha256=None, observed_at=1000,
        )
        self.assertEqual(deployment.validate_status(absent), absent)
        research = deployment.make_status(
            role="research", state="verified", generation_kind="protected",
            package_sha256="1" * 64,
            release_id="2" * 64, catalog_sha256="3" * 64,
            closed_evidence_sha256="4" * 64, observed_at=1000,
        )
        self.assertEqual(deployment.validate_status(research), research)
        changed = copy.deepcopy(research)
        changed["pending"] = True
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError, "native_deployment_status_invalid"
        ):
            deployment.validate_status(changed)

    def test_predecessor_must_match_exact_role_and_generation(self) -> None:
        plan = self.plan()
        self.assertEqual(
            deployment.validate_predecessor(
                plan, role="research", generation_kind="protected",
                package_sha256="5" * 64),
            ("protected", "5" * 64),
        )
        self.assertEqual(
            deployment.validate_predecessor(
                plan, role="gateway", generation_kind="absent",
                package_sha256=None),
            ("absent", None),
        )
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError, "predecessor_mismatch"
        ):
            deployment.validate_predecessor(
                plan, role="research", generation_kind="legacy",
                package_sha256="6" * 64)
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError, "predecessor_invalid"
        ):
            deployment.validate_predecessor(
                plan, role="gateway", generation_kind="legacy",
                package_sha256=None)

    def test_touchid_authority_is_exact_short_lived_and_plan_bound(self) -> None:
        plan = self.plan()
        authorization = deployment.make_authorization(
            plan,
            authorization_id="22222222-2222-4222-8222-222222222222",
            request_sha256="6" * 64,
            pending_receipt_sha256="7" * 64,
            requesting_agent_sha256="8" * 64,
            requesting_session_sha256="9" * 64,
            authorized_at=1100, expires_at=1200,
        )
        self.assertEqual(
            deployment.validate_authorization(authorization, plan, now=1150),
            authorization,
        )
        request = deployment.make_authorized_request(plan, authorization)
        self.assertEqual(
            deployment.validate_authorized_request(
                request, now=1150, expected_host_release_id="1" * 64),
            (plan, authorization),
        )
        for field, replacement in (
            ("password_fallback", True),
            ("method", "password"),
            ("deployment_id", "33333333-3333-4333-8333-333333333333"),
            ("host_release_id", "f" * 64),
        ):
            changed = copy.deepcopy(authorization)
            changed[field] = replacement
            with self.assertRaises(deployment.NativeDeploymentError):
                deployment.validate_authorization(changed, plan, now=1150)
        with self.assertRaisesRegex(
            deployment.NativeDeploymentError,
            "native_deployment_authorization_invalid",
        ):
            deployment.validate_authorization(authorization, plan, now=1200)

    def test_plan_binds_complete_stable_predecessor_projection(self) -> None:
        gateway = deployment.make_status(
            role="gateway", state="absent", generation_kind="absent",
            package_sha256=None, release_id=None, catalog_sha256=None,
            closed_evidence_sha256=None, observed_at=1000)
        research = deployment.make_status(
            role="research", state="verified", generation_kind="protected",
            package_sha256="5" * 64, release_id="a" * 64,
            catalog_sha256="b" * 64, closed_evidence_sha256="c" * 64,
            observed_at=1000)
        plan = deployment.make_plan(
            deployment_id="11111111-1111-4111-8111-111111111111",
            host_release_id="1" * 64, catalog_sha256="b" * 64,
            gateway_package_sha256="2" * 64,
            research_package_sha256="3" * 64,
            previous_gateway_package_sha256=None,
            previous_research_package_sha256="5" * 64,
            previous_gateway_status_sha256=deployment.stable_status_sha256(
                gateway),
            previous_research_status_sha256=deployment.stable_status_sha256(
                research),
            created_at=1000, expires_at=1100)
        deployment.validate_plan_predecessor_statuses(
            plan, gateway_status=gateway, research_status=research)
        for field, value in (
            ("release_id", "d" * 64),
            ("catalog_sha256", "e" * 64),
            ("closed_evidence_sha256", "f" * 64),
            ("generation_kind", "legacy"),
        ):
            changed = copy.deepcopy(research)
            changed[field] = value
            changed = deployment.make_status(
                role=changed["role"], state=changed["state"],
                generation_kind=changed["generation_kind"],
                package_sha256=changed["package_sha256"],
                release_id=changed["release_id"],
                catalog_sha256=changed["catalog_sha256"],
                closed_evidence_sha256=changed["closed_evidence_sha256"],
                observed_at=changed["observed_at"])
            with self.assertRaisesRegex(
                deployment.NativeDeploymentError,
                "predecessor_status_mismatch"):
                deployment.validate_plan_predecessor_status(
                    plan, role="research", status=changed)

    def test_recovery_authority_is_distinct_and_journal_action_bound(self) -> None:
        plan = self.plan()
        authorization = deployment.make_authorization(
            plan,
            authorization_id="22222222-2222-4222-8222-222222222222",
            request_sha256="6" * 64, pending_receipt_sha256="7" * 64,
            requesting_agent_sha256="8" * 64,
            requesting_session_sha256="9" * 64,
            authorized_at=1300, expires_at=1400,
            operation=deployment.RECOVER_OPERATION,
            recovery_action="rollback", active_journal_sha256="a" * 64)
        self.assertEqual(
            deployment.validate_authorization(
                authorization, plan, now=1350), authorization)
        for field, value in (
            ("operation", deployment.APPLY_OPERATION),
            ("recovery_action", "resume"),
            ("active_journal_sha256", "b" * 64),
        ):
            changed = copy.deepcopy(authorization)
            changed[field] = value
            with self.assertRaises(deployment.NativeDeploymentError):
                deployment.validate_authorization(changed, plan, now=1350)


if __name__ == "__main__":
    unittest.main()
