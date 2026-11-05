#!/usr/bin/env python3

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import json
import os
import signal
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import native_deployment_payload
from shared import native_deployment, native_vendor_stack


ROOT = Path(__file__).resolve().parents[1]


def load_driver():
    path = ROOT / "scripts/native-stack-deploy.py"
    loader = importlib.machinery.SourceFileLoader(
        "_secure_sandbox_native_stack_deploy_test", str(path))
    specification = importlib.util.spec_from_loader(loader.name, loader)
    assert specification is not None
    module = importlib.util.module_from_spec(specification)
    loader.exec_module(module)
    module.native_deployment = native_deployment
    module.native_vendor_stack = native_vendor_stack
    module.native_deployment_payload = native_deployment_payload
    return module


deploy = load_driver()


class NativeStackDeployTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.install = self.base / "host"
        self.install.mkdir(mode=0o755)
        self.install.chmod(0o755)
        self.install_fd = os.open(
            self.install, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        fcntl.flock(self.install_fd, fcntl.LOCK_EX)
        self.state = self.base / "deployment"
        self.uid, self.gid = os.geteuid(), os.getegid()
        self.gateway = native_deployment.make_status(
            role="gateway", state="absent", generation_kind="absent",
            package_sha256=None, release_id=None, catalog_sha256=None,
            closed_evidence_sha256=None, observed_at=1000)
        self.research = native_deployment.make_status(
            role="research", state="absent", generation_kind="absent",
            package_sha256=None, release_id=None, catalog_sha256=None,
            closed_evidence_sha256=None, observed_at=1000)
        self.plan = native_deployment.make_plan(
            deployment_id=str(uuid.uuid4()), host_release_id="1" * 64,
            catalog_sha256="2" * 64,
            gateway_package_sha256="3" * 64,
            research_package_sha256="4" * 64,
            previous_gateway_package_sha256=None,
            previous_research_package_sha256=None,
            previous_gateway_status_sha256=(
                native_deployment.stable_status_sha256(self.gateway)),
            previous_research_status_sha256=(
                native_deployment.stable_status_sha256(self.research)),
            created_at=1000, expires_at=4600)

    def tearDown(self) -> None:
        fcntl.flock(self.install_fd, fcntl.LOCK_UN)
        os.close(self.install_fd)
        self.temporary.cleanup()

    def journal(self, *, crash_hook=lambda _phase: None):
        return deploy.Journal(
            self.state, crash_hook=crash_hook,
            trusted_uid=self.uid, trusted_gid=self.gid,
            host_install_fd=self.install_fd,
            host_install_root=self.install)

    def append_authorized(self, journal, *, now: int = 1000):
        return journal.append(
            plan=self.plan, apply_authorization_sha256="5" * 64,
            authorization_sha256="5" * 64,
            payload_container_sha256="6" * 64,
            prior_gateway=self.gateway, prior_research=self.research,
            phase="authorized", event="authorized",
            evidence=deploy.evidence(outcome="authorized"), now=now)

    def append_phase(
        self, journal, phase: str, phase_evidence: dict, *, now: int,
        transport: dict | None = None,
    ):
        return journal.append(
            plan=self.plan, apply_authorization_sha256="5" * 64,
            authorization_sha256="5" * 64,
            payload_container_sha256="6" * 64,
            prior_gateway=self.gateway, prior_research=self.research,
            phase=phase, event=phase, evidence=phase_evidence,
            transport=transport, now=now)

    @staticmethod
    def transport(kind: str) -> dict:
        return {
            "kind": kind, "request_id": str(uuid.uuid4()),
            "semantic_sha256": "a" * 64,
            "payload_sha256": "b" * 64,
        }

    def candidate_statuses(self):
        gateway = native_deployment.make_status(
            role="gateway", state="verified", generation_kind="protected",
            package_sha256=self.plan["gateway_package_sha256"],
            release_id="7" * 64, catalog_sha256=None,
            closed_evidence_sha256="8" * 64, observed_at=1001)
        research = native_deployment.make_status(
            role="research", state="verified", generation_kind="protected",
            package_sha256=self.plan["research_package_sha256"],
            release_id="9" * 64,
            catalog_sha256=self.plan["catalog_sha256"],
            closed_evidence_sha256="c" * 64, observed_at=1002)
        return gateway, research

    def build_candidate_chain(self, journal):
        gateway, research = self.candidate_statuses()
        self.append_authorized(journal, now=1000)
        self.append_phase(
            journal, "fence-requested", deploy.evidence(outcome="requested"),
            now=1001, transport=self.transport("fence"))
        self.append_phase(
            journal, "fenced", deploy.evidence(
                outcome="fenced", fence_evidence_sha256="d" * 64),
            now=1002)
        self.append_phase(
            journal, "gateway-requested", deploy.evidence(outcome="requested"),
            now=1003, transport=self.transport("gateway"))
        self.append_phase(
            journal, "gateway-observed", deploy.evidence(
                outcome="candidate-prior", gateway_status=gateway,
                research_status=self.research), now=1004)
        self.append_phase(
            journal, "research-requested", deploy.evidence(outcome="requested"),
            now=1005, transport=self.transport("research"))
        self.append_phase(
            journal, "research-observed", deploy.evidence(
                outcome="candidate-candidate", gateway_status=gateway,
                research_status=research), now=1006)
        return gateway, research

    def make_release(self, label: bytes) -> tuple[Path, dict, SimpleNamespace]:
        payload_names = {
            "native_stack_deployer", "native_deployment_payloads",
            "native_stack_support", "control_client", "ssh_config",
            "release_manager", "authorization_broker",
            deploy.COORDINATION_CONTRACT_NAME,
        }
        values = {name: label + b":" + name.encode("ascii")
                  for name in payload_names}
        values[deploy.COORDINATION_CONTRACT_NAME] = (
            ROOT / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        hashes = {name: __import__("hashlib").sha256(raw).hexdigest()
                  for name, raw in values.items()}
        release_id = deploy._release_identity(hashes)
        releases = self.install / "releases"
        releases.mkdir(mode=0o755, exist_ok=True)
        release = releases / release_id
        release.mkdir(mode=0o755)
        modes = {}
        for name, raw in values.items():
            mode = 0o444 if name in {
                "native_deployment_payloads", "native_stack_support",
                "ssh_config", deploy.COORDINATION_CONTRACT_NAME,
            } else 0o755
            path = release / name
            path.write_bytes(raw)
            path.chmod(mode)
            modes[name] = mode
        manifest = {
            "schema": "secure-sandbox-host-controller-release-v1",
            "release_id": release_id, "payloads": hashes,
        }
        (release / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="ascii")
        (release / "manifest.json").chmod(0o444)
        release.chmod(0o555)
        floor = {
            "schema": deploy.COORDINATION_FLOOR_SCHEMA,
            "minimum_epoch": 1,
            "established_from_release_id": release_id,
            "established_from_contract_sha256": __import__(
                "hashlib").sha256(
                    values[deploy.COORDINATION_CONTRACT_NAME]).hexdigest(),
        }
        floor_path = self.install / deploy.COORDINATION_FLOOR_NAME
        if not floor_path.exists():
            floor_raw = deploy.canonical(floor)
            floor_path.write_bytes(floor_raw)
            floor_path.chmod(0o600)
            contract = json.loads(
                values[deploy.COORDINATION_CONTRACT_NAME])
            enforcement_path = (
                self.install / deploy.COORDINATION_ENFORCEMENT_NAME)
            enforcement_path.write_bytes(deploy.canonical({
                "schema": deploy.COORDINATION_ENFORCEMENT_SCHEMA,
                "minimum_epoch": contract["epoch"],
                "minimum_features": contract["features"],
                "authoritative_floor_sha256": __import__(
                    "hashlib").sha256(floor_raw).hexdigest(),
            }))
            enforcement_path.chmod(0o444)
        manager = SimpleNamespace(
            EXPECTED_MODES=modes,
            verified_release=lambda *_args, **_kwargs: (release, manifest),
        )
        return release, manifest, manager

    def test_read_only_absence_and_invalid_consume_leave_no_state(self) -> None:
        journal = self.journal()
        journal.lock(create=False)
        try:
            self.assertIsNone(journal.load())
            self.assertFalse(self.state.exists())
            coordinator = deploy.Coordinator.__new__(deploy.Coordinator)
            coordinator.journal = journal
            coordinator.release = SimpleNamespace(release_id="1" * 64)
            coordinator.validate_plan_response = mock.Mock(
                side_effect=deploy.NativeStackDeployError(
                    "native_deployment_plan_response_invalid"))
            with self.assertRaisesRegex(
                deploy.NativeStackDeployError, "plan_response_invalid"
            ):
                coordinator.apply(
                    {}, {}, now=1000,
                    receipt_verifier=lambda *_args: None)
            self.assertFalse(self.state.exists())
        finally:
            journal.unlock()

    def test_promote_creates_journal_only_after_admission(self) -> None:
        journal = self.journal()
        journal.lock(create=False)
        try:
            journal.promote()
            record = self.append_authorized(journal)
            self.assertEqual(journal.load()[1][-1], record)
        finally:
            journal.unlock()

    def test_real_sigkill_boundaries_are_reconciled(self) -> None:
        hooks = (
            "transaction-root-created", "exclusive-temp-fsynced",
            "exclusive-linked", "exclusive-temp-unlinked",
            "atomic-temp-fsynced", "atomic-replaced",
        )
        for hook in hooks:
            with self.subTest(hook=hook):
                state = self.base / ("state-" + hook)
                child = os.fork()
                if child == 0:
                    journal = deploy.Journal(
                        state,
                        crash_hook=lambda phase: (
                            os.kill(os.getpid(), signal.SIGKILL)
                            if phase == hook else None),
                        trusted_uid=self.uid, trusted_gid=self.gid,
                        host_install_fd=self.install_fd,
                        host_install_root=self.install)
                    journal.lock(create=True)
                    self.append_authorized(journal)
                    os._exit(99)
                waited, status = os.waitpid(child, 0)
                self.assertEqual(waited, child)
                self.assertTrue(os.WIFSIGNALED(status))
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                journal = deploy.Journal(
                    state, trusted_uid=self.uid, trusted_gid=self.gid,
                    host_install_fd=self.install_fd,
                    host_install_root=self.install)
                journal.lock(create=False)
                try:
                    loaded = journal.load()
                    if hook == "transaction-root-created":
                        self.assertIsNone(loaded)
                        self.assertTrue(any(
                            item.is_dir() for item in
                            (state / "transactions").iterdir()))
                    else:
                        self.assertEqual(
                            loaded[1][-1]["phase"], "authorized")
                finally:
                    journal.unlock()

    def test_pending_publication_substitution_fails_without_cleanup(self) -> None:
        directory = self.base / "publication"
        directory.mkdir(mode=0o700)
        raw = deploy.canonical({"value": 1})
        for publisher, name, hook in (
            (deploy._exclusive_file, "record.json", "exclusive-temp-fsynced"),
            (deploy._atomic_file, "active.json", "atomic-temp-fsynced"),
        ):
            with self.subTest(publisher=publisher.__name__):
                target = directory / name
                pending = directory / f".{name}.pending"
                retained = directory / f".{name}.retained"

                def substitute(phase: str) -> None:
                    if phase != hook:
                        return
                    pending.rename(retained)
                    pending.write_bytes(raw)
                    pending.chmod(0o600)

                with self.assertRaisesRegex(
                    deploy.NativeStackDeployError, "pending_changed"
                ):
                    publisher(
                        target, raw, crash_hook=substitute,
                        trusted_uid=self.uid, trusted_gid=self.gid)
                self.assertTrue(pending.exists())
                self.assertTrue(retained.exists())
                self.assertFalse(target.exists())
                pending.unlink()
                retained.unlink()

    def test_research_pending_request_can_replay_before_probe(self) -> None:
        journal = self.journal()
        journal.lock(create=True)
        try:
            gateway, _research = self.candidate_statuses()
            self.append_authorized(journal, now=1000)
            self.append_phase(
                journal, "fence-requested",
                deploy.evidence(outcome="requested"), now=1001,
                transport=self.transport("fence"))
            self.append_phase(
                journal, "fenced", deploy.evidence(
                    outcome="fenced", fence_evidence_sha256="d" * 64),
                now=1002)
            self.append_phase(
                journal, "gateway-requested",
                deploy.evidence(outcome="requested"), now=1003,
                transport=self.transport("gateway"))
            self.append_phase(
                journal, "gateway-observed", deploy.evidence(
                    outcome="candidate-prior", gateway_status=gateway,
                    research_status=self.research), now=1004)
            self.append_phase(
                journal, "research-requested",
                deploy.evidence(outcome="requested"), now=1005,
                transport=self.transport("research"))
            self.append_phase(
                journal, "recovery-required", deploy.evidence(
                    outcome="transport-ambiguous"), now=1006)
            replay = self.append_phase(
                journal, "research-requested",
                deploy.evidence(outcome="requested"), now=1007,
                transport=self.transport("research-replay"))
            self.assertEqual(replay["phase"], "research-requested")
        finally:
            journal.unlock()

    def test_real_sigkill_terminal_publication_is_reconciled(self) -> None:
        for hook in (
            "exclusive-temp-fsynced", "exclusive-linked",
            "exclusive-temp-unlinked", "terminal-published",
            "terminal-active-unlinked",
        ):
            with self.subTest(hook=hook):
                state = self.base / ("terminal-" + hook)
                journal = deploy.Journal(
                    state, trusted_uid=self.uid, trusted_gid=self.gid,
                    host_install_fd=self.install_fd,
                    host_install_root=self.install)
                journal.lock(create=True)
                gateway, research = self.build_candidate_chain(journal)
                self.append_phase(
                    journal, "release-requested",
                    deploy.evidence(outcome="requested"), now=1007,
                    transport=self.transport("release"))
                self.append_phase(
                    journal, "release-observed", deploy.evidence(
                        outcome="candidate-candidate",
                        gateway_status=gateway, research_status=research,
                        fence_evidence_sha256="d" * 64,
                        terminal_sha256="e" * 64,
                        result_sha256="f" * 64), now=1008)
                terminal = self.append_phase(
                    journal, "committed", deploy.evidence(
                        outcome="committed", gateway_status=gateway,
                        research_status=research,
                        terminal_sha256="e" * 64), now=1009)
                journal.unlock()
                child = os.fork()
                if child == 0:
                    child_journal = deploy.Journal(
                        state,
                        crash_hook=lambda phase: (
                            os.kill(os.getpid(), signal.SIGKILL)
                            if phase == hook else None),
                        trusted_uid=self.uid, trusted_gid=self.gid,
                        host_install_fd=self.install_fd,
                        host_install_root=self.install)
                    child_journal.lock(create=False)
                    child_journal.complete(terminal)
                    os._exit(99)
                waited, status = os.waitpid(child, 0)
                self.assertEqual(waited, child)
                self.assertTrue(os.WIFSIGNALED(status))
                recovered = deploy.Journal(
                    state, trusted_uid=self.uid, trusted_gid=self.gid,
                    host_install_fd=self.install_fd,
                    host_install_root=self.install)
                recovered.lock(create=False)
                try:
                    self.assertIsNone(recovered.load())
                finally:
                    recovered.unlock()

    def test_release_authority_rejects_selector_hybrid_and_bytecode_cache(self) -> None:
        first, _first_manifest, manager = self.make_release(b"first")
        second, _second_manifest, _second_manager = self.make_release(b"second")
        current = self.install / "current"
        current.symlink_to(second)
        with mock.patch.object(
             deploy, "_module_from_bytes", return_value=manager), \
             mock.patch.object(deploy, "_activate_support"):
            with self.assertRaisesRegex(
                deploy.NativeStackDeployError, "host_release_changed"
            ):
                with deploy.ReleaseAuthority(
                    release=first, install_root=self.install,
                    host_install_fd=self.install_fd,
                    expected_uid=self.uid):
                    pass
        current.unlink()
        current.symlink_to(first)
        cache = first / "__pycache__"
        first.chmod(0o755)
        cache.mkdir(mode=0o755)
        (cache / "release_manager.pyc").write_bytes(b"attacker")
        first.chmod(0o555)
        with mock.patch.object(
             deploy, "_module_from_bytes", return_value=manager), \
             mock.patch.object(deploy, "_activate_support"):
            with self.assertRaisesRegex(
                deploy.NativeStackDeployError, "cache_forbidden"
            ):
                with deploy.ReleaseAuthority(
                    release=first, install_root=self.install,
                    host_install_fd=self.install_fd,
                    expected_uid=self.uid):
                    pass

    def test_release_authority_rejects_install_transition_but_gate_may_read(self) -> None:
        release, _manifest, manager = self.make_release(b"transition")
        (self.install / "current").symlink_to(release)
        marker = self.install / deploy.INSTALL_TRANSITION_PENDING_NAME
        marker.write_text("{}\n", encoding="ascii")
        marker.chmod(0o600)
        with mock.patch.object(
             deploy, "_module_from_bytes", return_value=manager), \
             mock.patch.object(deploy, "_activate_support"):
            with self.assertRaisesRegex(
                deploy.NativeStackDeployError,
                "host_install_transition_active",
            ):
                with deploy.ReleaseAuthority(
                    release=release, install_root=self.install,
                    host_install_fd=self.install_fd,
                    expected_uid=self.uid):
                    pass
            with deploy.ReleaseAuthority(
                release=release, install_root=self.install,
                host_install_fd=self.install_fd,
                expected_uid=self.uid,
                allow_install_transition=True,
            ):
                pass

    def test_runtime_holds_promotion_gate_before_session_and_releases_reverse(self) -> None:
        events: list[str] = []

        class Context:
            def __init__(self, name: str, fail: bool = False):
                self.name, self.fail = name, fail
            def __enter__(self):
                events.append(self.name + ":enter")
                if self.fail:
                    raise RuntimeError("active")
                return self
            def __exit__(self, *_args):
                events.append(self.name + ":exit")

        manager = SimpleNamespace(_pending_records=lambda: [])
        sessions = SimpleNamespace(
            locked=lambda: Context("session"), _records=lambda: [])
        release = SimpleNamespace(
            install_fd=self.install_fd, release_id="a" * 64,
            release=self.base / ("a" * 64),
            payload=lambda _name: b"verified")
        manager_module = SimpleNamespace(
            NativeStackManager=lambda *_args, **_kwargs: manager)
        session_module = SimpleNamespace(
            NativeStackSessionManager=lambda *_args, **_kwargs: sessions,
            TERMINAL_PHASES={"committed"})
        promotion_module = SimpleNamespace(
            promotion_admission=lambda *_args, **_kwargs: Context("promotion"))
        with deploy.NativeRuntimeAuthority(
            release, manager_module=manager_module,
            session_module=session_module,
            promotion_module=promotion_module,
        ):
            events.append("body")
        self.assertEqual(events, [
            "promotion:enter", "session:enter", "body",
            "session:exit", "promotion:exit",
        ])

        rejected = SimpleNamespace(
            promotion_admission=lambda *_args, **_kwargs: Context(
                "rejected", fail=True))
        with self.assertRaisesRegex(
            deploy.NativeStackDeployError,
            "catalog_promotion_gate_rejected",
        ):
            deploy.NativeRuntimeAuthority(
                release, manager_module=manager_module,
                session_module=session_module,
                promotion_module=rejected,
            ).__enter__()
    def test_package_alias_classification_preserves_forward_intent(self) -> None:
        gateway_prior = native_deployment.make_status(
            role="gateway", state="verified", generation_kind="protected",
            package_sha256="3" * 64, release_id="7" * 64,
            catalog_sha256=None, closed_evidence_sha256="8" * 64,
            observed_at=1000)
        research_prior = native_deployment.make_status(
            role="research", state="verified", generation_kind="protected",
            package_sha256="9" * 64, release_id="a" * 64,
            catalog_sha256="2" * 64,
            closed_evidence_sha256="b" * 64, observed_at=1000)
        plan = native_deployment.make_plan(
            deployment_id=str(uuid.uuid4()), host_release_id="1" * 64,
            catalog_sha256="2" * 64,
            gateway_package_sha256="3" * 64,
            research_package_sha256="4" * 64,
            previous_gateway_package_sha256="3" * 64,
            previous_research_package_sha256="9" * 64,
            previous_gateway_status_sha256=(
                native_deployment.stable_status_sha256(gateway_prior)),
            previous_research_status_sha256=(
                native_deployment.stable_status_sha256(research_prior)),
            created_at=1000, expires_at=4600)
        self.assertEqual(deploy.classify_pair(
            plan, gateway_prior, research_prior,
            gateway_prior, research_prior), "candidate-prior")
        research_candidate = native_deployment.make_status(
            role="research", state="verified", generation_kind="protected",
            package_sha256="4" * 64, release_id="c" * 64,
            catalog_sha256="2" * 64,
            closed_evidence_sha256="d" * 64, observed_at=1001)
        self.assertEqual(deploy.classify_pair(
            plan, gateway_prior, research_prior,
            gateway_prior, research_candidate), "candidate-candidate")

    def test_recovery_plan_survives_pending_probe(self) -> None:
        for phase, expected in (
            ("gateway-requested", ["resume"]),
            ("research-requested", ["resume"]),
            ("compensation-requested", ["rollback"]),
        ):
            with self.subTest(phase=phase):
                records = [{
                    "plan": self.plan,
                    "prior_gateway": self.gateway,
                    "prior_research": self.research,
                    "payload_container_sha256": "6" * 64,
                    "phase": "authorized",
                }, {
                    "phase": phase, "evidence": {"outcome": "requested"},
                }, {
                    "phase": "recovery-required",
                    "evidence": {"outcome": "transport-ambiguous"},
                }]
                coordinator = deploy.Coordinator.__new__(deploy.Coordinator)
                coordinator.journal = SimpleNamespace(load=lambda: ({
                    "record_sha256": "7" * 64,
                    "deployment_id": self.plan["deployment_id"],
                    "host_release_id": self.plan["host_release_id"],
                }, records))
                coordinator.probe_pair = mock.Mock(
                    side_effect=deploy.NativeStackDeployError(
                        "native_deployment_probe_failed"))
                result = deploy._CoordinatorRecoveryMixin.recovery_plan(
                    coordinator)
                self.assertEqual(result["observed_pair"], "unavailable")
                self.assertEqual(result["allowed_actions"], expected)

    def test_recovery_plan_rejects_observed_mixed_state(self) -> None:
        records = [{
            "plan": self.plan, "prior_gateway": self.gateway,
            "prior_research": self.research,
            "payload_container_sha256": "6" * 64,
            "phase": "authorized",
        }, {
            "phase": "gateway-requested",
            "evidence": {"outcome": "requested"},
        }, {
            "phase": "recovery-required",
            "evidence": {"outcome": "transport-ambiguous"},
        }]
        mixed = native_deployment.make_status(
            role="gateway", state="verified", generation_kind="protected",
            package_sha256="f" * 64, release_id="e" * 64,
            catalog_sha256=None, closed_evidence_sha256="d" * 64,
            observed_at=1001)
        coordinator = deploy.Coordinator.__new__(deploy.Coordinator)
        coordinator.journal = SimpleNamespace(load=lambda: ({
            "record_sha256": "7" * 64,
            "deployment_id": self.plan["deployment_id"],
            "host_release_id": self.plan["host_release_id"],
        }, records))
        coordinator.probe_pair = lambda: (mixed, self.research)
        with self.assertRaisesRegex(
            deploy.NativeStackDeployError, "cross_plane_state_unknown"
        ):
            deploy._CoordinatorRecoveryMixin.recovery_plan(coordinator)

    def test_pending_request_intent_replays_before_any_probe(self) -> None:
        gateway_candidate, research_candidate = self.candidate_statuses()
        for phase, method_name, replay_result in (
            ("gateway-requested", "install_gateway", (
                "candidate-prior", gateway_candidate, self.research)),
            ("research-requested", "install_research", (
                "candidate-candidate", gateway_candidate,
                research_candidate)),
        ):
            with self.subTest(phase=phase):
                active = "7" * 64
                plan_response = {
                    "schema": deploy.PLAN_RESPONSE_SCHEMA,
                    "plan": self.plan, "prior_gateway": self.gateway,
                    "prior_research": self.research,
                    "payload_container_sha256": "6" * 64,
                    "response_sha256": "8" * 64,
                }
                current = {
                    "schema": deploy.RECOVERY_PLAN_SCHEMA,
                    "active_journal_sha256": active,
                    "deployment_id": self.plan["deployment_id"],
                    "host_release_id": self.plan["host_release_id"],
                    "phase": "recovery-required",
                    "observed_pair": "unavailable",
                    "allowed_actions": ["resume"],
                    "plan_response": plan_response,
                    "gateway_status_sha256": None,
                    "research_status_sha256": None,
                    "recovery_plan_sha256": "9" * 64,
                }
                authorization = native_deployment.make_authorization(
                    self.plan, authorization_id=str(uuid.uuid4()),
                    request_sha256="a" * 64,
                    pending_receipt_sha256="b" * 64,
                    requesting_agent_sha256="c" * 64,
                    requesting_session_sha256="d" * 64,
                    authorized_at=1200, expires_at=1250,
                    operation=native_deployment.RECOVER_OPERATION,
                    recovery_action="resume",
                    active_journal_sha256=active)
                records = [{
                    "phase": "authorized", "plan": self.plan,
                    "prior_gateway": self.gateway,
                    "prior_research": self.research,
                    "payload_container_sha256": "6" * 64,
                    "apply_authorization_sha256": "5" * 64,
                }, {
                    "phase": phase, "evidence": {"outcome": "requested"},
                }, {
                    "phase": "recovery-required",
                    "evidence": {"outcome": "transport-ambiguous"},
                }]
                coordinator = deploy.Coordinator.__new__(deploy.Coordinator)
                coordinator.release = SimpleNamespace(release_id="1" * 64)
                coordinator.journal = SimpleNamespace(
                    load=lambda: ({"record_sha256": active}, records))
                coordinator.recovery_plan = lambda: current
                coordinator.validate_plan_response = lambda *_args, **_kwargs: (
                    self.plan, self.gateway, self.research)
                coordinator._context = lambda *_args, **_kwargs: {
                    "plan": self.plan, "authorization": authorization,
                    "prior_gateway": self.gateway,
                    "prior_research": self.research,
                    "apply_authorization_sha256": "5" * 64,
                }
                coordinator._mark_recovery_required = lambda *_args, **_kwargs: None
                events = []
                coordinator.probe_pair = lambda: events.append("probe")
                setattr(
                    coordinator, method_name,
                    lambda _context, result=replay_result: (
                        events.append("replay") or result))
                coordinator.acquire_fence = lambda *_args, **_kwargs: events.append(
                    "acquire")
                terminal = {"phase": "committed"}
                coordinator._run_forward = lambda *_args, **_kwargs: (
                    events.append("forward") or terminal)
                result = deploy._CoordinatorRecoveryMixin.recover(
                    coordinator, current, authorization, now=1201,
                    receipt_verifier=lambda *_args: None)
                self.assertEqual(result, terminal)
                self.assertEqual(events, ["replay", "forward"])

    def test_recovery_fence_uses_distinct_touchid_bound_transports(self) -> None:
        authorization = native_deployment.make_authorization(
            self.plan, authorization_id=str(uuid.uuid4()),
            request_sha256="a" * 64,
            pending_receipt_sha256="b" * 64,
            requesting_agent_sha256="c" * 64,
            requesting_session_sha256="d" * 64,
            authorized_at=4700, expires_at=4750,
            operation=native_deployment.RECOVER_OPERATION,
            recovery_action="resume", active_journal_sha256="e" * 64)
        context = {
            "plan": self.plan, "authorization": authorization,
            "prior_gateway": self.gateway,
            "prior_research": self.research,
            "apply_authorization_sha256": "5" * 64,
        }
        coordinator = deploy.Coordinator.__new__(deploy.Coordinator)
        coordinator.catalog_raw = b"{}\n"
        coordinator.bases = {"research-fence-recovery-acquire.zip": b"base"}
        coordinator._append = lambda *_args, **_kwargs: None
        reply = {
            "schema": native_deployment.FENCE_REPLY_SCHEMA,
            "deployment_id": self.plan["deployment_id"],
            "plan_sha256": self.plan["plan_sha256"],
            "fence_sha256": "1" * 64,
            "catalog_sha256": self.plan["catalog_sha256"],
            "state": "fenced", "evidence_sha256": "2" * 64,
        }
        captured = {}

        def deploy_call(_context, **kwargs):
            captured.update(kwargs)
            return 0, native_deployment.canonical(reply)

        coordinator._journaled_deploy = deploy_call
        with mock.patch.object(
            native_deployment_payload, "complete_fence_payload",
            side_effect=lambda raw, operation, dynamic: (
                captured.update({
                    "payload_operation": operation,
                    "dynamic": dynamic,
                }) or ({
                    "install-native-deployment-fence-recovery-bootstrap.sh":
                    (b"wrapper", 0o700),
                }, {"package_sha256": "f" * 64}))):
            result = coordinator.acquire_fence(
                context, observed_research=self.research)
        self.assertEqual(result, reply)
        self.assertEqual(captured["payload_operation"], "recovery-acquire")
        self.assertEqual(
            captured["installer"],
            "install-native-deployment-fence-recovery-bootstrap.sh")
        request = json.loads(captured["dynamic"][
            "native-deployment-recovery-fence-request.json"])
        self.assertEqual(
            request["authorization"]["authorization_sha256"],
            authorization["authorization_sha256"])

        candidate_gateway, candidate_research = self.candidate_statuses()
        del candidate_gateway
        piped = {}
        coordinator._journaled_pipe = lambda _context, **kwargs: (
            piped.update(kwargs) or (0, native_deployment.canonical(reply)))
        result = coordinator.acquire_fence(
            context, observed_research=candidate_research)
        self.assertEqual(result, reply)
        self.assertEqual(
            piped["operation"],
            "native-deployment-lifecycle-recovery-acquire")

    def test_verified_byte_execution_never_uses_or_writes_pyc(self) -> None:
        source = self.base / "verified_payload"
        source.write_bytes(b"VALUE = 1\n")
        source.chmod(0o755)
        cache = self.base / "__pycache__"
        cache.mkdir()
        planted = cache / "verified_payload.cpython-313.pyc"
        planted.write_bytes(b"attacker")
        before = sorted(item.relative_to(self.base) for item in self.base.rglob("*"))
        module = deploy._module_from_bytes(
            source.read_bytes(), "_verified_payload", str(source))
        after = sorted(item.relative_to(self.base) for item in self.base.rglob("*"))
        self.assertEqual(module.VALUE, 1)
        self.assertEqual(before, after)
        self.assertEqual(planted.read_bytes(), b"attacker")


if __name__ == "__main__":
    unittest.main()
