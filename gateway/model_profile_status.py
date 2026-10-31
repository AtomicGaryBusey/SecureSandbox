#!/usr/bin/env python3
"""Return the non-secret identity of the active Gateway model profile."""

import json
import os
import re
import stat
from pathlib import Path


CONFIG = Path("/etc/secure-sandbox/broker.json")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,47}$")


def status(path: Path = CONFIG, trusted_uid: int = 0) -> dict[str, object]:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != trusted_uid
            or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o640):
        raise PermissionError("model_profile_config_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    models = value.get("allowed_models")
    result: dict[str, object] = {
        "adapter": value.get("adapter"),
        "mode": value.get("mode"),
        "model": models[0] if isinstance(models, list) and len(models) == 1 else None,
        "profile_id": value.get("profile_id"),
        "profile_sha256": value.get("profile_sha256"),
        "schema": "secure-sandbox-active-model-profile-v1",
        "upstream_origin": value.get("upstream_origin"),
        "vendor_id": value.get("vendor_id"),
    }
    if (result["adapter"] not in {
            "anthropic-messages-v1", "openai-responses-v1", "google-openai-chat-v1"}
            or result["mode"] not in {"mock", "production"}
            or not isinstance(result["model"], str) or not result["model"]
            or not isinstance(result["upstream_origin"], str)
            or NAME.fullmatch(str(result["profile_id"])) is None
            or NAME.fullmatch(str(result["vendor_id"])) is None
            or SHA256.fullmatch(str(result["profile_sha256"])) is None):
        raise ValueError("model_profile_config_invalid")
    return result


if __name__ == "__main__":
    print(json.dumps(status(), ensure_ascii=True, separators=(",", ":"), sort_keys=True))
