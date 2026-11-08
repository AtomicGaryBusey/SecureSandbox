#!/usr/bin/env python3
"""Hostile tests for release/launcher pair transitions.

This module is intentionally separate from the broad release-manager suite.
It reuses that suite's realistic retained-candidate fixture by composition so
the tests exercise installed release trees, public authorities, authorization
receipts, and stable launchers rather than replacing them with dictionaries.
"""

from __future__ import annotations

import contextlib
import fcntl
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Iterator, Mapping
from unittest import mock

from scripts import test_host_controller_release as RELEASE_FIXTURES


REPO = Path(__file__).resolve().parent.parent
MANAGER = RELEASE_FIXTURES.MANAGER
LAUNCHER = RELEASE_FIXTURES.LAUNCHER
REAL_ENSURE_NO_LEGACY_PROCESSES = MANAGER.ensure_no_d8653cb_release_processes


class SimulatedProcessDeath(BaseException):
    """A process-death seam that must not enter transactional cleanup."""


class InjectedActivationFailure(RuntimeError):
    """A recoverable target failure used to enter source restoration."""


class PairFixture:
    """One realistic temporary Host installation with retained candidates."""

    def __init__(self, case: unittest.TestCase):
        self.case = case
        self.release = RELEASE_FIXTURES.HostControllerReleaseTests(
            methodName="runTest"
        )
        self.release.setUp()
        self.root = self.release.root
        self.repo = self.release.repo
        self.install_root = self.release.install_root
        self.launcher = self.release.launcher
        self.state = self.release.state
        self.uid = self.release.uid
        self.op_binary = self.release.op_binary
        self.gpgv_binary = self.release.gpgv_binary
        self._real_tracked_source = MANAGER.native_host_candidate_tracked_source
        self._launcher_suffixes: dict[Path, bytes] = {}
        self._tracked_source_patch = mock.patch.object(
            MANAGER,
            "native_host_candidate_tracked_source",
            side_effect=self._tracked_source,
        )
        self._tracked_source_patch.start()
        self.base_candidate = self.release.native_host_candidate_binding()
        self.register_launcher_generation(
            self.base_candidate, b"\n# hostile retained launcher generation A\n"
        )

    def close(self) -> None:
        self._tracked_source_patch.stop()
        self.release.tearDown()
        self.release.doCleanups()

    def _tracked_source(
        self,
        repo: Path,
        generation: Path,
        candidate: Mapping[str, object],
        relative: Path,
    ) -> bytes:
        value = self._real_tracked_source(
            repo, generation, candidate, relative
        )
        if Path(relative) == MANAGER.LAUNCHER_SOURCE:
            value += self._launcher_suffixes.get(
                Path(generation).resolve(), b""
            )
        return value

    def register_launcher_generation(
        self,
        binding: tuple[Path, Mapping[str, object]],
        suffix: bytes,
    ) -> None:
        generation, _candidate = binding
        self._launcher_suffixes[generation.resolve()] = suffix

    def new_candidate(
        self, label: str,
    ) -> tuple[Path, dict[str, object]]:
        generation, candidate = self.base_candidate
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo,
            self.op_binary,
            self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        binding = self.release.alternate_native_host_candidate({
            "controller": values["controller"]
            + f"\n# hostile pair release {label}\n".encode("ascii"),
        })
        self.register_launcher_generation(
            binding,
            f"\n# hostile retained launcher generation {label}\n".encode(
                "ascii"
            ),
        )
        return binding

    def launcher_bytes(
        self, binding: tuple[Path, Mapping[str, object]],
    ) -> bytes:
        generation, candidate = binding
        return MANAGER.native_host_candidate_tracked_source(
            self.repo,
            generation,
            candidate,
            MANAGER.LAUNCHER_SOURCE,
        )

    def describe_candidate(
        self, binding: tuple[Path, Mapping[str, object]],
        *, source_stable_sha256: str | None,
    ) -> tuple[dict[str, bytes], dict[str, str], str, bytes, str]:
        generation, candidate = binding
        values, hashes, release_id = MANAGER.source_payload(
            self.repo,
            self.op_binary,
            self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        launcher = self.launcher_bytes(binding)
        _plan, plan_sha256 = MANAGER.authorized_host_release_target_plan(
            release_id=release_id,
            payloads=hashes,
            candidate_record=candidate,
            target_launcher_sha256=MANAGER.sha256_bytes(launcher),
            source_stable_sha256=source_stable_sha256,
        )
        return values, hashes, release_id, launcher, plan_sha256

    def install(
        self,
        binding: tuple[Path, Mapping[str, object]] | None = None,
    ) -> dict[str, object]:
        return self.release.install(
            self.base_candidate if binding is None else binding
        )

    def rollback(self, target_id: str | None = None) -> dict[str, object]:
        return self.release.authorized_rollback(target_id)

    def public_pair(self) -> tuple[dict[str, object], str]:
        observed = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid
        )
        assert observed is not None
        return observed

    def pending_transition(self) -> dict[str, object]:
        outstanding = MANAGER.read_pending_host_pair_transition(
            self.install_root, self.uid, allow_absent=False
        )
        assert outstanding is not None
        transition, descriptor = outstanding
        os.close(descriptor)
        return transition


class HostPairTransitionHostileTests(unittest.TestCase):
    @contextlib.contextmanager
    def pair_fixture(self) -> Iterator[PairFixture]:
        fixture = PairFixture(self)
        try:
            yield fixture
        finally:
            fixture.close()

    def assert_stable_pair(
        self,
        fixture: PairFixture,
        *,
        release_id: str,
        launcher_bytes: bytes,
    ) -> dict[str, object]:
        stable, stable_sha256 = fixture.public_pair()
        self.assertEqual(
            stable["schema"],
            MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA,
        )
        pair = stable["pair"]
        self.assertEqual(pair["release_id"], release_id)
        self.assertEqual(
            pair["launcher_sha256"], MANAGER.sha256_bytes(launcher_bytes)
        )
        self.assertEqual(
            os.readlink(fixture.install_root / "current"),
            f"releases/{release_id}",
        )
        self.assertEqual(fixture.launcher.read_bytes(), launcher_bytes)

        authority = MANAGER.native_host_candidate_authority(
            fixture.install_root, release_id, fixture.uid, public_only=True
        )
        self.assertEqual(
            authority["schema"],
            MANAGER.NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA,
        )
        self.assertEqual(
            authority["launcher_sha256"], pair["launcher_sha256"]
        )
        tree, tree_sha256 = MANAGER.installed_native_host_release_tree_identity(
            fixture.install_root / "releases" / release_id, fixture.uid
        )
        self.assertEqual(tree, authority["release_tree_identity"])
        self.assertEqual(
            tree_sha256, authority["release_tree_identity_sha256"]
        )
        self.assertEqual(
            tree_sha256, pair["release_tree_identity_sha256"]
        )
        verified, verified_sha256, path, _manifest, observed_authority = (
            MANAGER.verified_host_release_launcher_pair(
                fixture.install_root,
                fixture.launcher,
                fixture.uid,
                public_only=True,
            )
        )
        self.assertEqual((verified, verified_sha256), (stable, stable_sha256))
        self.assertEqual(path.name, release_id)
        self.assertEqual(observed_authority, authority)
        loaded, loaded_id = LAUNCHER.load_release(
            fixture.install_root,
            fixture.uid,
            launcher_path=fixture.launcher,
        )
        self.assertEqual((loaded.name, loaded_id), (release_id, release_id))
        full = MANAGER.verify(
            fixture.repo,
            fixture.install_root,
            fixture.launcher,
            fixture.uid,
            fixture.op_binary,
            fixture.gpgv_binary,
        )
        self.assertEqual(full["release_id"], release_id)
        return stable

    def assert_public_pair_denied(self, fixture: PairFixture) -> None:
        with self.assertRaises(MANAGER.ReleaseFailure):
            MANAGER.verified_host_release_launcher_pair(
                fixture.install_root,
                fixture.launcher,
                fixture.uid,
                public_only=True,
            )
        with self.assertRaises(MANAGER.ReleaseFailure):
            MANAGER.verify(
                fixture.repo,
                fixture.install_root,
                fixture.launcher,
                fixture.uid,
                fixture.op_binary,
                fixture.gpgv_binary,
            )
        with self.assertRaises(LAUNCHER.LaunchFailure):
            LAUNCHER.load_release(
                fixture.install_root,
                fixture.uid,
                launcher_path=fixture.launcher,
            )

    @staticmethod
    def rewrite_record(path: Path, value: Mapping[str, object], mode: int) -> None:
        path.chmod(mode | 0o200)
        path.write_bytes(MANAGER.canonical_state_record(dict(value)))
        path.chmod(mode)

    def crash_during_install(
        self,
        fixture: PairFixture,
        checkpoint: str,
        binding: tuple[Path, Mapping[str, object]],
    ) -> None:
        def die(name: str) -> None:
            if name == checkpoint:
                raise SimulatedProcessDeath(name)

        with (
            mock.patch.object(
                MANAGER, "host_pair_transition_checkpoint", side_effect=die
            ),
            self.assertRaises(SimulatedProcessDeath),
        ):
            fixture.install(binding)

    def test_install_rollback_distinct_launcher_generations_and_floor(self):
        with self.pair_fixture() as fixture:
            first = fixture.install()
            first_id = str(first["release_id"])
            first_launcher = fixture.launcher_bytes(fixture.base_candidate)
            self.assert_stable_pair(
                fixture,
                release_id=first_id,
                launcher_bytes=first_launcher,
            )

            second_candidate = fixture.new_candidate("B")
            second_launcher = fixture.launcher_bytes(second_candidate)
            self.assertNotEqual(first_launcher, second_launcher)
            second = fixture.install(second_candidate)
            second_id = str(second["release_id"])
            self.assertNotEqual(first_id, second_id)
            self.assert_stable_pair(
                fixture,
                release_id=second_id,
                launcher_bytes=second_launcher,
            )

            rolled_back = fixture.rollback()
            self.assertEqual(rolled_back["release_id"], first_id)
            self.assert_stable_pair(
                fixture,
                release_id=first_id,
                launcher_bytes=first_launcher,
            )
            installed_sha256 = MANAGER.sha256_bytes(first_launcher)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "stable_launcher_pair_transition_required",
            ):
                MANAGER.migrate_launcher(
                    fixture.repo,
                    fixture.install_root,
                    fixture.launcher,
                    fixture.state,
                    fixture.uid,
                    installed_sha256,
                    MANAGER.sha256_bytes(second_launcher),
                )
            self.assertEqual(fixture.launcher.read_bytes(), first_launcher)

    def test_named_bootstrap_replay_revalidates_floor_and_censuses_predecessor(
        self,
    ):
        for checkpoint in ("PREPARED", "PUBLIC_PENDING"):
            with self.subTest(checkpoint=checkpoint), self.pair_fixture() as fixture:
                def terminate(phase: str) -> None:
                    if phase == checkpoint:
                        raise SimulatedProcessDeath()

                with (
                    mock.patch.object(
                        MANAGER, "host_pair_transition_checkpoint",
                        side_effect=terminate,
                    ),
                    self.assertRaises(SimulatedProcessDeath),
                ):
                    fixture.install()
                transition = fixture.pending_transition()
                admission = transition["bootstrap_admission"]
                floor = MANAGER.native_host_candidate_floor(
                    fixture.install_root, fixture.uid,
                )
                self.assertEqual(
                    admission["native_host_candidate_floor_sha256"], floor[1]
                )
                self.assertEqual(
                    admission["candidate_record_sha256"],
                    floor[0]["candidate_record_sha256"],
                )
                predecessor = (
                    fixture.install_root / "releases"
                    / admission["established_from_predecessor_release_id"]
                )
                censused: list[tuple[Path, tuple[Path, ...]]] = []

                def census(
                    release: Path, _root: Path, _uid: int, *,
                    extra_aliases: tuple[Path, ...] = (),
                ) -> None:
                    censused.append((release, extra_aliases))

                with (
                    mock.patch.object(
                        MANAGER, "ensure_no_d8653cb_release_processes",
                        side_effect=census,
                    ),
                    mock.patch.object(
                        MANAGER.time, "time",
                        return_value=transition["expires_at"] + 1,
                    ),
                ):
                    recovered = MANAGER.recover_host_pair_transition(
                        fixture.install_root, fixture.launcher,
                        fixture.state, fixture.uid,
                    )
                self.assertEqual(
                    recovered["status"], "host_pair_transition_recovered"
                )
                self.assertTrue(any(
                    release.resolve() == predecessor.resolve()
                    and aliases == (fixture.launcher,)
                    for release, aliases in censused
                ))

    def test_generic_bootstrap_recovery_rejects_missing_or_changed_admission(
        self,
    ):
        mutations = {
            "missing": lambda value: value.pop("bootstrap_admission"),
            "mode": lambda value: value["bootstrap_admission"].update({
                "establishment_mode": "candidate-schema-bootstrap",
                "established_from_predecessor_release_id": (
                    MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                ),
            }),
            "candidate": lambda value: value["bootstrap_admission"].update({
                "candidate_record_sha256": "f" * 64,
            }),
            "floor": lambda value: value["bootstrap_admission"].update({
                "native_host_candidate_floor_sha256": "f" * 64,
            }),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label), self.pair_fixture() as fixture:
                def terminate(phase: str) -> None:
                    if phase == "PREPARED":
                        raise SimulatedProcessDeath()

                with (
                    mock.patch.object(
                        MANAGER, "host_pair_transition_checkpoint",
                        side_effect=terminate,
                    ),
                    self.assertRaises(SimulatedProcessDeath),
                ):
                    fixture.install()
                pending_path = (
                    fixture.install_root
                    / MANAGER.INSTALL_TRANSITION_PENDING_NAME
                )
                changed = json.loads(pending_path.read_bytes())
                mutate(changed)
                changed["transition_sha256"] = (
                    MANAGER.host_pair_transition_digest(changed)
                )
                pending_path.write_bytes(
                    MANAGER.canonical_state_record(changed)
                )
                pending_path.chmod(0o600)
                with (
                    mock.patch.object(
                        MANAGER, "ensure_no_d8653cb_release_processes",
                    ) as census,
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "host_pair_(bootstrap_(admission_invalid|binding_invalid)"
                        "|transition_invalid)",
                    ),
                ):
                    MANAGER.recover_host_pair_transition(
                        fixture.install_root, fixture.launcher,
                        fixture.state, fixture.uid,
                    )
                census.assert_not_called()
                self.assertTrue(pending_path.exists())
                self.assertFalse(
                    (fixture.install_root
                     / MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME).exists()
                )

    def test_named_bootstrap_replay_fences_newly_loaded_predecessor_process(
        self,
    ):
        with self.pair_fixture() as fixture:
            def terminate(phase: str) -> None:
                if phase == "PUBLIC_PENDING":
                    raise SimulatedProcessDeath()

            with (
                mock.patch.object(
                    MANAGER, "host_pair_transition_checkpoint",
                    side_effect=terminate,
                ),
                self.assertRaises(SimulatedProcessDeath),
            ):
                fixture.install()
            transition = fixture.pending_transition()
            predecessor = (
                fixture.install_root / "releases"
                / transition["bootstrap_admission"][
                    "established_from_predecessor_release_id"
                ]
            )
            process = subprocess.Popen(
                [
                    sys.executable, "-c", "import time; time.sleep(60)",
                    str(predecessor / "authorization_broker"),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                time.sleep(0.05)
                with (
                    mock.patch.object(
                        MANAGER, "process_ids", return_value=(process.pid,),
                    ),
                    mock.patch.object(
                        MANAGER, "ensure_no_d8653cb_release_processes",
                        side_effect=REAL_ENSURE_NO_LEGACY_PROCESSES,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "native_coordination_legacy_operation_active",
                    ),
                ):
                    MANAGER.recover_host_pair_transition(
                        fixture.install_root, fixture.launcher,
                        fixture.state, fixture.uid,
                    )
                pending, _pending_sha256 = fixture.public_pair()
                self.assertEqual(
                    pending["schema"],
                    MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
                )
                self.assertTrue(
                    (fixture.install_root
                     / MANAGER.INSTALL_TRANSITION_PENDING_NAME).exists()
                )
                self.assertFalse((fixture.install_root / "current").exists())
            finally:
                process.terminate()
                process.wait(timeout=10)
            with mock.patch.object(
                MANAGER, "process_ids", return_value=(process.pid,),
            ), mock.patch.object(
                MANAGER, "ensure_no_d8653cb_release_processes",
                side_effect=REAL_ENSURE_NO_LEGACY_PROCESSES,
            ):
                recovered = MANAGER.recover_host_pair_transition(
                    fixture.install_root, fixture.launcher,
                    fixture.state, fixture.uid,
                )
            self.assertEqual(
                recovered["status"], "host_pair_transition_recovered"
            )

    def test_true_process_death_replays_every_durable_checkpoint(self):
        checkpoints = (
            "PREPARED",
            "PUBLIC_PENDING",
            "SERVICES_FENCED",
            "LAUNCHER_SELECTED",
            "PREVIOUS_SELECTED",
            "RELEASE_SELECTED",
            "SERVICES_SELECTED",
            "FINALIZATION_STAGED",
            "TERMINAL_PUBLISHED",
            "STABLE_PUBLISHED",
        )
        for checkpoint in checkpoints:
            with self.subTest(checkpoint=checkpoint), self.pair_fixture() as fixture:
                source = fixture.install()
                source_id = str(source["release_id"])
                source_launcher = fixture.launcher_bytes(
                    fixture.base_candidate
                )
                source_stable, source_stable_sha256 = fixture.public_pair()
                candidate = fixture.new_candidate(f"crash-{checkpoint}")
                (
                    _values,
                    _hashes,
                    target_id,
                    target_launcher,
                    _plan_sha256,
                ) = fixture.describe_candidate(
                    candidate,
                    source_stable_sha256=source_stable_sha256,
                )
                self.assertNotEqual(source_id, target_id)
                self.assertNotEqual(source_launcher, target_launcher)

                self.crash_during_install(fixture, checkpoint, candidate)

                public, _public_sha256 = fixture.public_pair()
                if checkpoint == "PREPARED":
                    self.assertEqual(public, source_stable)
                    self.assert_stable_pair(
                        fixture,
                        release_id=source_id,
                        launcher_bytes=source_launcher,
                    )
                elif checkpoint == "STABLE_PUBLISHED":
                    self.assertEqual(
                        public["schema"],
                        MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA,
                    )
                    self.assert_stable_pair(
                        fixture,
                        release_id=target_id,
                        launcher_bytes=target_launcher,
                    )
                else:
                    self.assertEqual(
                        public["schema"],
                        MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
                    )
                    self.assert_public_pair_denied(fixture)

                self.assertTrue(
                    (fixture.install_root
                     / MANAGER.INSTALL_TRANSITION_PENDING_NAME).is_file()
                )
                recovered = MANAGER.recover_host_pair_transition(
                    fixture.install_root,
                    fixture.launcher,
                    fixture.state,
                    fixture.uid,
                )
                self.assertEqual(
                    recovered["status"], "host_pair_transition_recovered"
                )
                self.assertEqual(recovered["release_id"], target_id)
                self.assertFalse(
                    os.path.lexists(
                        fixture.install_root
                        / MANAGER.INSTALL_TRANSITION_PENDING_NAME
                    )
                )
                stable = self.assert_stable_pair(
                    fixture,
                    release_id=target_id,
                    launcher_bytes=target_launcher,
                )
                self.assertEqual(
                    stable["committed_transition_id"],
                    recovered["transition_id"],
                )

    def test_expired_ordinary_authorization_cannot_begin_pair_activation(self):
        for checkpoint in ("PREPARED", "PUBLIC_PENDING", "SERVICES_FENCED"):
            with self.subTest(checkpoint=checkpoint), self.pair_fixture() as fixture:
                installed = fixture.install()
                source_id = str(installed["release_id"])
                source_launcher = fixture.launcher_bytes(fixture.base_candidate)
                source_stable, _source_sha256 = fixture.public_pair()
                candidate = fixture.new_candidate(f"expired-{checkpoint}")
                (
                    _values, _hashes, _target_id, target_launcher, _plan,
                ) = fixture.describe_candidate(
                    candidate,
                    source_stable_sha256=fixture.public_pair()[1],
                )
                self.crash_during_install(fixture, checkpoint, candidate)
                transition = fixture.pending_transition()

                with (
                    mock.patch.object(
                        MANAGER.time, "time",
                        return_value=transition["expires_at"],
                    ),
                    mock.patch.object(
                        MANAGER, "install_launcher_generation",
                        wraps=MANAGER.install_launcher_generation,
                    ) as install_launcher,
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "host_pair_transition_expired",
                    ),
                ):
                    MANAGER.recover_host_pair_transition(
                        fixture.install_root, fixture.launcher,
                        fixture.state, fixture.uid,
                    )

                target_launcher_sha256 = MANAGER.sha256_bytes(target_launcher)
                self.assertFalse(any(
                    call.args[2] == target_launcher_sha256
                    for call in install_launcher.call_args_list
                ))

                self.assertEqual(
                    os.readlink(fixture.install_root / "current"),
                    f"releases/{source_id}",
                )
                self.assertEqual(fixture.launcher.read_bytes(), source_launcher)
                self.assertTrue(
                    (fixture.install_root
                     / MANAGER.INSTALL_TRANSITION_PENDING_NAME).is_file()
                )
                public, _public_sha256 = fixture.public_pair()
                if checkpoint == "PREPARED":
                    self.assertEqual(public, source_stable)
                else:
                    self.assertEqual(
                        public["schema"],
                        MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
                    )
                    self.assert_public_pair_denied(fixture)

    def test_authorization_live_at_boundary_minus_one_can_activate(self):
        with self.pair_fixture() as fixture:
            fixture.install()
            candidate = fixture.new_candidate("expiry-boundary-live")
            _values, _hashes, target_id, target_launcher, _plan = (
                fixture.describe_candidate(
                    candidate,
                    source_stable_sha256=fixture.public_pair()[1],
                )
            )
            self.crash_during_install(fixture, "PREPARED", candidate)
            transition = fixture.pending_transition()
            with mock.patch.object(
                MANAGER.time, "time",
                return_value=transition["expires_at"] - 1,
            ):
                recovered = MANAGER.recover_host_pair_transition(
                    fixture.install_root, fixture.launcher,
                    fixture.state, fixture.uid,
                )
            self.assertEqual(recovered["release_id"], target_id)
            self.assert_stable_pair(
                fixture, release_id=target_id,
                launcher_bytes=target_launcher,
            )

    def test_expiry_between_fence_and_launcher_selection_restores_source(self):
        with self.pair_fixture() as fixture:
            installed = fixture.install()
            source_id = str(installed["release_id"])
            source_launcher = fixture.launcher_bytes(fixture.base_candidate)
            candidate = fixture.new_candidate("expiry-race")
            _source_stable, source_stable_sha256 = fixture.public_pair()
            (
                _values, _hashes, _target_id, target_launcher, _plan,
            ) = fixture.describe_candidate(
                candidate, source_stable_sha256=source_stable_sha256,
            )
            self.crash_during_install(fixture, "PUBLIC_PENDING", candidate)
            transition = fixture.pending_transition()
            real_freshness_check = (
                MANAGER.ensure_host_pair_transition_activation_current
            )
            checks = 0

            def expire_on_second_check(value, *, now=None):
                nonlocal checks
                checks += 1
                instant = (
                    transition["expires_at"] - 1
                    if checks == 1 else transition["expires_at"]
                )
                return real_freshness_check(value, now=instant)

            with (
                mock.patch.object(
                    MANAGER,
                    "ensure_host_pair_transition_activation_current",
                    side_effect=expire_on_second_check,
                ),
                mock.patch.object(
                    MANAGER, "install_launcher_generation",
                    wraps=MANAGER.install_launcher_generation,
                ) as install_launcher,
            ):
                recovered = MANAGER.recover_host_pair_transition(
                    fixture.install_root, fixture.launcher,
                    fixture.state, fixture.uid,
                )
            self.assertEqual(checks, 2)
            target_launcher_sha256 = MANAGER.sha256_bytes(target_launcher)
            self.assertFalse(any(
                call.args[2] == target_launcher_sha256
                for call in install_launcher.call_args_list
            ))
            self.assertEqual(recovered["release_id"], source_id)
            stable = self.assert_stable_pair(
                fixture, release_id=source_id,
                launcher_bytes=source_launcher,
            )
            terminal = MANAGER.verified_public_host_pair_terminal(
                fixture.install_root, fixture.uid, stable,
            )
            self.assertIsNotNone(terminal)
            assert terminal is not None
            self.assertEqual(terminal[0]["status"], "source_restored")

    def test_expired_transition_converges_after_durable_pair_mutation(self):
        for checkpoint in ("LAUNCHER_SELECTED", "RELEASE_SELECTED"):
            with self.subTest(checkpoint=checkpoint), self.pair_fixture() as fixture:
                fixture.install()
                candidate = fixture.new_candidate(
                    f"expired-durable-prefix-{checkpoint}"
                )
                _values, _hashes, target_id, target_launcher, _plan = (
                    fixture.describe_candidate(
                        candidate,
                        source_stable_sha256=fixture.public_pair()[1],
                    )
                )
                self.crash_during_install(fixture, checkpoint, candidate)
                transition = fixture.pending_transition()
                with mock.patch.object(
                    MANAGER.time, "time",
                    return_value=transition["expires_at"] + 1,
                ):
                    recovered = MANAGER.recover_host_pair_transition(
                        fixture.install_root, fixture.launcher,
                        fixture.state, fixture.uid,
                    )
                self.assertEqual(recovered["release_id"], target_id)
                self.assert_stable_pair(
                    fixture, release_id=target_id,
                    launcher_bytes=target_launcher,
                )

    def test_true_death_during_source_restore_launcher_prefix_replays(self):
        with self.pair_fixture() as fixture:
            source = fixture.install()
            source_id = str(source["release_id"])
            source_launcher = fixture.launcher_bytes(fixture.base_candidate)
            _source_stable, source_stable_sha256 = fixture.public_pair()
            candidate = fixture.new_candidate("restore-crash")
            (
                _values,
                _hashes,
                target_id,
                target_launcher,
                _plan_sha256,
            ) = fixture.describe_candidate(
                candidate,
                source_stable_sha256=source_stable_sha256,
            )
            restoring_source = False

            def interrupt_restore(name: str) -> None:
                nonlocal restoring_source
                if name == "SERVICES_SELECTED" and not restoring_source:
                    restoring_source = True
                    raise InjectedActivationFailure("target activation")
                if name == "LAUNCHER_SELECTED" and restoring_source:
                    raise SimulatedProcessDeath("source restore launcher")

            with (
                mock.patch.object(
                    MANAGER,
                    "host_pair_transition_checkpoint",
                    side_effect=interrupt_restore,
                ),
                self.assertRaises(SimulatedProcessDeath),
            ):
                fixture.install(candidate)

            public, _public_sha256 = fixture.public_pair()
            self.assertEqual(
                public["schema"],
                MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
            )
            self.assertEqual(
                os.readlink(fixture.install_root / "current"),
                f"releases/{target_id}",
            )
            self.assertEqual(fixture.launcher.read_bytes(), source_launcher)
            self.assertNotEqual(source_launcher, target_launcher)
            self.assert_public_pair_denied(fixture)

            recovered = MANAGER.recover_host_pair_transition(
                fixture.install_root,
                fixture.launcher,
                fixture.state,
                fixture.uid,
            )
            self.assertEqual(recovered["release_id"], target_id)
            self.assertNotEqual(recovered["release_id"], source_id)
            self.assert_stable_pair(
                fixture,
                release_id=target_id,
                launcher_bytes=target_launcher,
            )

    def test_stable_published_recovery_rejects_substituted_journal_terminal(self):
        with self.pair_fixture() as fixture:
            fixture.install()
            candidate = fixture.new_candidate("stable-terminal-substitution")
            self.crash_during_install(
                fixture, "STABLE_PUBLISHED", candidate,
            )
            stable, _stable_sha256 = fixture.public_pair()
            transition = fixture.pending_transition()
            self.assertEqual(
                stable["committed_transition_id"],
                transition["transition_id"],
            )
            changed = json.loads(json.dumps(transition))
            terminal = changed["terminal"]
            self.assertIsInstance(terminal, dict)
            terminal["authorization_receipt_sha256"] = "0" * 64
            terminal["terminal_sha256"] = (
                MANAGER.host_pair_terminal_digest(terminal)
            )
            pending_path = (
                fixture.install_root
                / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            )
            self.rewrite_record(pending_path, changed, 0o600)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_pair_terminal_mismatch",
            ):
                MANAGER.recover_host_pair_transition(
                    fixture.install_root,
                    fixture.launcher,
                    fixture.state,
                    fixture.uid,
                )
            self.assertTrue(pending_path.is_file())
            observed = fixture.pending_transition()
            self.assertEqual(
                observed["terminal"]["authorization_receipt_sha256"],
                "0" * 64,
            )

    def test_public_pending_private_journal_mismatches_fail_closed(self):
        for damage in ("missing", "mismatched"):
            with self.subTest(damage=damage), self.pair_fixture() as fixture:
                fixture.install()
                candidate = fixture.new_candidate(f"journal-{damage}")
                self.crash_during_install(
                    fixture, "PUBLIC_PENDING", candidate
                )
                pending_path = (
                    fixture.install_root
                    / MANAGER.INSTALL_TRANSITION_PENDING_NAME
                )
                if damage == "missing":
                    pending_path.unlink()
                    expected = "host_pair_transition_missing"
                else:
                    public_path = (
                        fixture.install_root
                        / MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
                    )
                    public = json.loads(public_path.read_bytes())
                    public["transition_sha256"] = "0" * 64
                    self.rewrite_record(public_path, public, 0o444)
                    expected = "host_release_launcher_pair_pending_conflict"
                self.assert_public_pair_denied(fixture)
                with self.assertRaisesRegex(MANAGER.ReleaseFailure, expected):
                    MANAGER.recover_host_pair_transition(
                        fixture.install_root,
                        fixture.launcher,
                        fixture.state,
                        fixture.uid,
                    )

        with self.subTest(damage="legacy-v1"), self.pair_fixture() as fixture:
            installed = fixture.install()
            release_id = str(installed["release_id"])
            launcher = fixture.launcher_bytes(fixture.base_candidate)
            legacy = {
                "schema": MANAGER.INSTALL_TRANSITION_SCHEMA,
                "transition_id": "11111111-1111-4111-8111-111111111111",
            }
            path = (
                fixture.install_root
                / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            )
            path.write_bytes(MANAGER.canonical_state_record(legacy))
            path.chmod(0o600)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_pair_transition_legacy_active"
            ):
                MANAGER.recover_host_pair_transition(
                    fixture.install_root,
                    fixture.launcher,
                    fixture.state,
                    fixture.uid,
                )
            self.assert_stable_pair(
                fixture, release_id=release_id, launcher_bytes=launcher
            )

    def test_committed_terminal_binding_missing_or_tampered_fails_closed(self):
        for damage in ("stable-terminal-mismatch", "missing", "tampered"):
            with self.subTest(damage=damage), self.pair_fixture() as fixture:
                fixture.install()
                stable, _stable_sha256 = fixture.public_pair()
                transition_id = str(stable["committed_transition_id"])
                terminal_path = (
                    fixture.install_root
                    / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
                    / f"{transition_id}.json"
                )
                self.assertTrue(terminal_path.is_file())
                if damage == "stable-terminal-mismatch":
                    changed = dict(stable)
                    changed["committed_terminal_sha256"] = "0" * 64
                    self.rewrite_record(
                        fixture.install_root
                        / MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME,
                        changed,
                        0o444,
                    )
                elif damage == "missing":
                    terminal_path.unlink()
                else:
                    terminal = json.loads(terminal_path.read_bytes())
                    terminal["authorization_receipt_sha256"] = "0" * 64
                    terminal["terminal_sha256"] = (
                        MANAGER.host_pair_terminal_digest(terminal)
                    )
                    self.rewrite_record(terminal_path, terminal, 0o444)
                self.assert_public_pair_denied(fixture)

    def test_authorization_receipt_for_plan_a_cannot_drive_plan_b(self):
        with self.pair_fixture() as fixture:
            installed = fixture.install()
            source_id = str(installed["release_id"])
            source_launcher = fixture.launcher_bytes(fixture.base_candidate)
            _stable, source_stable_sha256 = fixture.public_pair()
            plan_a_candidate = fixture.new_candidate("plan-A")
            (
                _a_values,
                _a_hashes,
                _a_release_id,
                _a_launcher,
                plan_a_sha256,
            ) = fixture.describe_candidate(
                plan_a_candidate,
                source_stable_sha256=source_stable_sha256,
            )
            request_id, request_sha256 = fixture.release.authorize_host_pair(
                "host-controller-install", plan_a_sha256
            )

            plan_b_candidate = fixture.new_candidate("plan-B")
            generation_b, candidate_b = plan_b_candidate
            (
                _b_values,
                _b_hashes,
                release_b,
                _b_launcher,
                plan_b_sha256,
            ) = fixture.describe_candidate(
                plan_b_candidate,
                source_stable_sha256=source_stable_sha256,
            )
            self.assertNotEqual(plan_a_sha256, plan_b_sha256)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_release_target_plan_changed"
            ):
                MANAGER.install(
                    fixture.repo,
                    fixture.install_root,
                    fixture.launcher,
                    fixture.state,
                    fixture.uid,
                    fixture.op_binary,
                    fixture.gpgv_binary,
                    release_b,
                    native_host_generation=generation_b,
                    expected_native_host_candidate=candidate_b,
                    authorization_request_id=request_id,
                    authorization_request_sha256=request_sha256,
                    authorized_target_plan_sha256=plan_a_sha256,
                )
            self.assertFalse(
                os.path.lexists(
                    fixture.install_root
                    / MANAGER.INSTALL_TRANSITION_PENDING_NAME
                )
            )
            self.assert_stable_pair(
                fixture,
                release_id=source_id,
                launcher_bytes=source_launcher,
            )

    def acl_add_remove(self, target: Path) -> tuple[int, int]:
        before = target.lstat().st_ctime_ns
        time.sleep(0.01)
        added = subprocess.run(
            ["/bin/chmod", "+a", "everyone allow write", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if added.returncode != 0:
            self.skipTest("Darwin extended ACL fixture unavailable")
        removed = subprocess.run(
            ["/bin/chmod", "-N", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(removed.returncode, 0, removed.stderr)
        return before, target.lstat().st_ctime_ns

    def test_authority_v2_ctime_detects_acl_add_remove_every_tree_level(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin ctime/ACL contract")
        levels = ("release-root", "payload", "nested-bundle")
        for level in levels:
            with self.subTest(level=level), self.pair_fixture() as fixture:
                installed = fixture.install()
                release = (
                    fixture.install_root
                    / "releases"
                    / str(installed["release_id"])
                )
                target = {
                    "release-root": release,
                    "payload": release / "controller",
                    "nested-bundle": (
                        release
                        / MANAGER.AUTHORIZATION_UI_APP_NAME
                        / MANAGER.AUTHORIZATION_UI_EXECUTABLE
                    ),
                }[level]
                before, after = self.acl_add_remove(target)
                self.assertNotEqual(before, after)
                self.assert_public_pair_denied(fixture)

    def test_authority_v2_allows_xattrs_present_at_publication(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin xattr contract")
        with self.pair_fixture() as fixture:
            publish = MANAGER.publish_native_host_candidate_authority

            def publish_with_xattrs(
                install_root: Path,
                expected_uid: int,
                **keywords: object,
            ) -> dict[str, object]:
                release = (
                    install_root / "releases" / str(keywords["release_id"])
                )
                targets = (
                    release,
                    release / "controller",
                    release
                    / MANAGER.AUTHORIZATION_UI_APP_NAME
                    / MANAGER.AUTHORIZATION_UI_EXECUTABLE,
                )
                for index, target in enumerate(targets):
                    original_mode = target.stat().st_mode & 0o777
                    target.chmod(original_mode | 0o200)
                    try:
                        subprocess.run(
                            [
                                "/usr/bin/xattr",
                                "-w",
                                f"com.zebeth.securesandbox.hostile{index}",
                                "present-before-authority",
                                str(target),
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                    finally:
                        target.chmod(original_mode)
                return publish(
                    install_root, expected_uid, **keywords
                )

            with mock.patch.object(
                MANAGER,
                "publish_native_host_candidate_authority",
                side_effect=publish_with_xattrs,
            ):
                installed = fixture.install()
            self.assert_stable_pair(
                fixture,
                release_id=str(installed["release_id"]),
                launcher_bytes=fixture.launcher_bytes(
                    fixture.base_candidate
                ),
            )

    def test_authority_v2_detects_stale_writer_sibling_same_byte_mutation(self):
        with self.pair_fixture() as fixture:
            publish = MANAGER.publish_native_host_candidate_authority
            stale: dict[str, object] = {}

            def publish_with_stale_writer(
                install_root: Path,
                expected_uid: int,
                **keywords: object,
            ) -> dict[str, object]:
                target = (
                    install_root
                    / "releases"
                    / str(keywords["release_id"])
                    / "controller"
                )
                original_mode = target.stat().st_mode & 0o777
                first_byte = target.read_bytes()[:1]
                target.chmod(original_mode | 0o200)
                descriptor = os.open(
                    target, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                )
                target.chmod(original_mode)
                stale.update({
                    "descriptor": descriptor,
                    "first_byte": first_byte,
                    "target": target,
                })
                return publish(
                    install_root, expected_uid, **keywords
                )

            descriptor = -1
            try:
                with mock.patch.object(
                    MANAGER,
                    "publish_native_host_candidate_authority",
                    side_effect=publish_with_stale_writer,
                ):
                    installed = fixture.install()
                descriptor = int(stale["descriptor"])
                target = Path(stale["target"])
                authority = MANAGER.native_host_candidate_authority(
                    fixture.install_root,
                    str(installed["release_id"]),
                    fixture.uid,
                    public_only=True,
                )
                expected_digest = authority["release_tree_identity"][
                    "controller"
                ]["sha256"]
                time.sleep(0.01)
                self.assertEqual(
                    os.pwrite(descriptor, bytes(stale["first_byte"]), 0), 1
                )
                os.fsync(descriptor)
                self.assertEqual(
                    MANAGER.sha256_bytes(target.read_bytes()),
                    expected_digest,
                )
                self.assert_public_pair_denied(fixture)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

    def test_host_shared_lock_contention_returns_promptly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "installed"
            state_root = root / "state"
            install_root.mkdir(mode=0o755)
            descriptor = os.open(
                install_root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                launcher_path = REPO / "scripts/secure-sandbox-claude-launcher.py"
                program = f"""
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('lock_hostile_launcher', {str(launcher_path)!r})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.INSTALL_ROOT = Path({str(install_root)!r})
module.STATE_ROOT = Path({str(state_root)!r})
raise SystemExit(module.main())
"""
                started = time.monotonic()
                completed = subprocess.run(
                    [sys.executable, "-c", program],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                elapsed = time.monotonic() - started
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("controller_host_transition_active", completed.stderr)
        self.assertLess(elapsed, 2.0)

    def test_post_replacement_census_rejects_paused_old_launcher_binding(self):
        with self.pair_fixture() as fixture:
            installed = fixture.install()
            source_id = str(installed["release_id"])
            source_launcher = fixture.launcher_bytes(fixture.base_candidate)
            candidate = fixture.new_candidate("paused-census")
            _values, _hashes, target_id, target_launcher, _plan = (
                fixture.describe_candidate(
                    candidate,
                    source_stable_sha256=fixture.public_pair()[1],
                )
            )
            calls: list[tuple[str, str]] = []

            def census(
                release: Path,
                install_root: Path,
                expected_uid: int,
                *,
                extra_aliases: tuple[Path, ...] = (),
            ) -> None:
                live_sha256 = MANAGER.sha256_bytes(
                    fixture.launcher.read_bytes()
                )
                calls.append((release.name, live_sha256))
                self.assertEqual(extra_aliases, (fixture.launcher,))
                if len(calls) == 1:
                    self.assertEqual(
                        live_sha256, MANAGER.sha256_bytes(target_launcher)
                    )
                    paused_generation = (
                        fixture.uid, 1_900_000_000, 123_456, 3
                    )
                    with (
                        mock.patch.object(
                            MANAGER, "process_ids", return_value=(4242,)
                        ),
                        mock.patch.object(
                            MANAGER,
                            "process_status_generation_or_absent",
                            return_value=paused_generation,
                        ),
                        mock.patch.object(
                            MANAGER,
                            "process_executable_path",
                            return_value="/usr/bin/python3",
                        ),
                        mock.patch.object(
                            MANAGER,
                            "process_arguments_inventory",
                            return_value=(
                                "./secure-sandbox-claude",
                                "--paused-before-lock",
                            ),
                        ),
                    ):
                        REAL_ENSURE_NO_LEGACY_PROCESSES(
                            release,
                            install_root,
                            expected_uid,
                            extra_aliases=extra_aliases,
                        )
                self.assertEqual(
                    live_sha256, MANAGER.sha256_bytes(source_launcher)
                )

            with (
                mock.patch.object(
                    MANAGER,
                    "ensure_no_d8653cb_release_processes",
                    side_effect=census,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "native_coordination_legacy_operation_active",
                ),
            ):
                fixture.install(candidate)
            self.assertEqual(len(calls), 2)
            stable = self.assert_stable_pair(
                fixture,
                release_id=source_id,
                launcher_bytes=source_launcher,
            )
            terminal = MANAGER.verified_public_host_pair_terminal(
                fixture.install_root, fixture.uid, stable
            )
            self.assertIsNotNone(terminal)
            assert terminal is not None
            self.assertEqual(terminal[0]["status"], "source_restored")
            self.assertNotEqual(target_id, source_id)

    def test_bare_public_verifiers_recompute_tree_without_private_repo(self):
        with self.pair_fixture() as fixture:
            installed = fixture.install()
            release_id = str(installed["release_id"])
            stable, stable_sha256 = fixture.public_pair()
            generation, _candidate = fixture.base_candidate
            candidate_root = generation.parent
            repo_mode = fixture.repo.stat().st_mode & 0o777
            candidate_mode = candidate_root.stat().st_mode & 0o777
            manager_snapshot = MANAGER.installed_native_host_release_tree_identity
            launcher_snapshot = LAUNCHER._snapshot_release_tree
            candidate_root.chmod(0)
            fixture.repo.chmod(0)
            try:
                with (
                    mock.patch.object(
                        MANAGER,
                        "installed_native_host_release_tree_identity",
                        wraps=manager_snapshot,
                    ) as manager_tree,
                    mock.patch.object(
                        LAUNCHER,
                        "_snapshot_release_tree",
                        wraps=launcher_snapshot,
                    ) as launcher_tree,
                    mock.patch.object(
                        MANAGER,
                        "native_host_candidate_record",
                        side_effect=AssertionError(
                            "private candidate traversal"
                        ),
                    ),
                    mock.patch.object(
                        MANAGER,
                        "native_host_candidate_tracked_source",
                        side_effect=AssertionError("private source traversal"),
                    ),
                    mock.patch.object(
                        MANAGER,
                        "source_payload",
                        side_effect=AssertionError("repository traversal"),
                    ),
                ):
                    verified = MANAGER.verified_host_release_launcher_pair(
                        fixture.install_root,
                        fixture.launcher,
                        fixture.uid,
                        public_only=True,
                    )
                    loaded, loaded_id = LAUNCHER.load_release(
                        fixture.install_root,
                        fixture.uid,
                        launcher_path=fixture.launcher,
                    )
                self.assertEqual(verified[0], stable)
                self.assertEqual(verified[1], stable_sha256)
                self.assertEqual(verified[2].name, release_id)
                self.assertEqual((loaded.name, loaded_id), (release_id, release_id))
                self.assertGreaterEqual(manager_tree.call_count, 1)
                self.assertGreaterEqual(launcher_tree.call_count, 1)
            finally:
                fixture.repo.chmod(repo_mode)
                candidate_root.chmod(candidate_mode)


if __name__ == "__main__":
    unittest.main()
