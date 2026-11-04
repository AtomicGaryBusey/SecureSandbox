#!/usr/bin/env python3
"""Protected bridge from the native Research release to live isolation."""

from __future__ import annotations

from typing import Any

from research import native_codex_isolation_qualification as qualification
from shared import native_research_release


class NativeProjectionIsolationError(RuntimeError):
    """Stable fail-closed projection observation error."""


def _native_release_identity() -> str:
    try:
        release = native_research_release.verify_installed()
    except (OSError,
            native_research_release.NativeResearchReleaseError) as error:
        raise NativeProjectionIsolationError(
            "native_projection_release_untrusted") from error
    return release["release_id"]


def status_observation(
    authority: object, descriptor: object,
) -> dict[str, Any]:
    """Return the exact subject PASS or reject without a projection."""
    release = _native_release_identity()
    try:
        return qualification.projection_isolation_status_observation(
            authority, descriptor_value=descriptor,
            research_release_id=release)
    except qualification.NativeCodexIsolationError as error:
        raise NativeProjectionIsolationError(
            "native_projection_isolation_unqualified") from error
