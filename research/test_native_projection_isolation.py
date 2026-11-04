#!/usr/bin/env python3

from __future__ import annotations

import unittest
from unittest import mock

from research import native_projection_isolation as isolation


class NativeProjectionIsolationTests(unittest.TestCase):
    def test_native_manifest_is_the_only_release_authority(self) -> None:
        with mock.patch.object(
            isolation.native_research_release, "verify_installed",
            return_value={"release_id": "3" * 64},
        ), mock.patch.object(
            isolation.qualification, "projection_isolation_status_observation",
            return_value={
                "research_release_id": "3" * 64,
                "isolation_attestation_sha256": "5" * 64,
                "observed_at": 100, "expires_at": 220,
            },
        ) as observe:
            value = isolation.status_observation()
        self.assertEqual(value["research_release_id"], "3" * 64)
        observe.assert_called_once_with(research_release_id="3" * 64)

    def test_release_mismatch_rejects_before_isolation_observer(self) -> None:
        with mock.patch.object(
            isolation.native_research_release, "verify_installed",
            side_effect=isolation.native_research_release.NativeResearchReleaseError(
                "native_research_release_readback_mismatch"),
        ), self.assertRaisesRegex(
            isolation.NativeProjectionIsolationError, "release_untrusted"
        ):
            isolation.status_observation()


if __name__ == "__main__":
    unittest.main()
