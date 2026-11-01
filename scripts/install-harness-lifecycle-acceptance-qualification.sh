#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
campaign_id="${1:-}"
source_commit="${2:-}"
[[ "$campaign_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
  || { echo "Invalid campaign identity." >&2; exit 2; }
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "Invalid source commit." >&2; exit 2; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json \
   && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] \
  || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }

declare -a sources=(
  /tmp/harness-lifecycle-acceptance-qualification.py
  /tmp/harness_lifecycle_acceptance.py
  /tmp/harness_lifecycle_qualification_fixture.py
  /tmp/harness_qualification.py
  /tmp/harness_qualification_fixture.py
  /tmp/claude_core_adapter.py
  /tmp/malicious_harness.py
  /tmp/campaign.json
)
for source in "${sources[@]}"; do
  [[ -f "$source" && ! -L "$source" ]] \
    || { echo "Missing regular qualification deployment source." >&2; exit 2; }
done
python3 -m py_compile "${sources[@]:0:7}"
python3 - "$campaign_id" "$source_commit" /tmp/campaign.json <<'PY'
import json, pathlib, sys
campaign_id, source_commit, path = sys.argv[1:]
raw = pathlib.Path(path).read_bytes()
value = json.loads(raw)
canonical = (json.dumps(value, ensure_ascii=True, allow_nan=False,
                        separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
valid = (
    raw == canonical
    and value.get("campaign_id") == campaign_id
    and value.get("source_commit") == source_commit
    and value.get("environment") == "disposable-mac"
    and value.get("production_data_present") is False
    and value.get("production_credentials_present") is False
    and value.get("synthetic_credentials_only") is True
    and value.get("authority") == "acceptance-evidence-only"
)
if not valid:
    raise SystemExit("acceptance campaign binding invalid")
PY

base=/usr/local/libexec/secure-sandbox/harness-lifecycle-acceptance-qualification
state=/var/lib/secure-sandbox/harness-lifecycle-acceptance
release="$base/$source_commit"
campaign="$state/$campaign_id"
temporary="$base/.${source_commit}.new-$$"
if [[ ! -e "$base" && ! -L "$base" ]]; then
  install -d -o root -g root -m 755 "$base"
fi
[[ -d "$base" && ! -L "$base" && "$(stat -c %U:%G:%a "$base")" == root:root:755 ]] \
  || { echo "Qualification release root is untrusted." >&2; exit 1; }
lock="$base/.install.lock"
if ! mkdir -m 700 "$lock"; then
  echo "Another qualification installation is in progress." >&2
  exit 1
fi
cleanup() {
  [[ ! -e "$temporary" ]] || rm -rf -- "$temporary"
  rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -e "$release" && ! -L "$release" ]]; then
  install -d -o root -g root -m 755 \
    "$temporary" "$temporary/scripts" "$temporary/shared" \
    "$temporary/fixtures" "$temporary/fixtures/harness-qualification"
  install -o root -g root -m 555 "${sources[0]}" \
    "$temporary/scripts/harness-lifecycle-acceptance-qualification.py"
  for index in 1 2 3 4 5; do
    install -o root -g root -m 444 "${sources[$index]}" \
      "$temporary/shared/$(basename "${sources[$index]}")"
  done
  install -o root -g root -m 444 "${sources[6]}" \
    "$temporary/fixtures/harness-qualification/malicious_harness.py"
  sync -d "$temporary"
  mv "$temporary" "$release"
  sync -d "$base"
fi
[[ -d "$release" && ! -L "$release" && "$(stat -c %U:%G:%a "$release")" == root:root:755 ]] \
  || { echo "Installed qualification release is untrusted." >&2; exit 1; }

declare -a destinations=(
  scripts/harness-lifecycle-acceptance-qualification.py
  shared/harness_lifecycle_acceptance.py
  shared/harness_lifecycle_qualification_fixture.py
  shared/harness_qualification.py
  shared/harness_qualification_fixture.py
  shared/claude_core_adapter.py
  fixtures/harness-qualification/malicious_harness.py
)
for index in 0 1 2 3 4 5 6; do
  expected_mode=444
  [[ "$index" -eq 0 ]] && expected_mode=555
  destination="$release/${destinations[$index]}"
  [[ -f "$destination" && ! -L "$destination" \
     && "$(stat -c %U:%G:%a "$destination")" == "root:root:$expected_mode" ]] \
    || { echo "Installed qualification file is untrusted." >&2; exit 1; }
  cmp -s "${sources[$index]}" "$destination" \
    || { echo "Installed qualification release differs from campaign source." >&2; exit 1; }
done
[[ "$(find "$release" -type f -printf . | wc -c)" -eq 7 \
   && "$(find "$release" -mindepth 1 -type d -printf . | wc -c)" -eq 4 \
   && "$(find "$release" -type l -printf . | wc -c)" -eq 0 \
   && "$(find "$release" -mindepth 1 ! -type f ! -type d -printf . | wc -c)" -eq 0 ]] \
  || { echo "Installed qualification inventory is untrusted." >&2; exit 1; }
while IFS= read -r directory; do
  [[ "$(stat -c %U:%G:%a "$directory")" == root:root:755 ]] \
    || { echo "Installed qualification directory is untrusted." >&2; exit 1; }
done < <(find "$release" -type d -print)

if [[ ! -e "$state" && ! -L "$state" ]]; then
  install -d -o root -g root -m 700 "$state"
fi
[[ -d "$state" && ! -L "$state" && "$(stat -c %U:%G:%a "$state")" == root:root:700 ]] \
  || { echo "Acceptance state root is untrusted." >&2; exit 1; }
if [[ ! -e "$campaign" && ! -L "$campaign" ]]; then
  install -d -o root -g root -m 700 "$campaign"
  install -o root -g root -m 600 /tmp/campaign.json "$campaign/campaign.json"
  install -d -o root -g root -m 700 "$campaign/qualification-fixtures"
  sync -d "$campaign"
  sync -d "$state"
else
  [[ -d "$campaign" && ! -L "$campaign" \
     && "$(stat -c %U:%G:%a "$campaign")" == root:root:700 \
     && -d "$campaign/qualification-fixtures" && ! -L "$campaign/qualification-fixtures" \
     && "$(stat -c %U:%G:%a "$campaign/qualification-fixtures")" == root:root:700 ]] \
    || { echo "Qualification campaign state is untrusted." >&2; exit 1; }
  cmp -s /tmp/campaign.json "$campaign/campaign.json" \
    || { echo "Qualification campaign identity collision." >&2; exit 1; }
fi

"$release/scripts/harness-lifecycle-acceptance-qualification.py" --help >/dev/null
echo "harness-lifecycle-acceptance-qualification:installed:$campaign_id:$source_commit"
