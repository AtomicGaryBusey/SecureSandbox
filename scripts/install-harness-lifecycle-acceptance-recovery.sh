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
  /tmp/harness-lifecycle-acceptance-recovery.py
  /tmp/harness_lifecycle_acceptance.py
  /tmp/harness_lifecycle_acceptance_fixture.py
  /tmp/harness_generation_store.py
  /tmp/harness_lifecycle.py
  /tmp/harness_runtime_binding.py
  /tmp/privileged_workflow.py
  /tmp/campaign.json
)
for source in "${sources[@]}"; do
  [[ -f "$source" && ! -L "$source" ]] \
    || { echo "Missing regular acceptance deployment source." >&2; exit 2; }
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

base=/usr/local/libexec/secure-sandbox/harness-lifecycle-acceptance-recovery
state=/var/lib/secure-sandbox/harness-lifecycle-acceptance
release="$base/$source_commit"
campaign="$state/$campaign_id"
temporary="$base/.${source_commit}.new-$$"
trap 'rm -rf -- "$temporary"' EXIT
if [[ ! -e "$base" && ! -L "$base" ]]; then
  install -d -o root -g root -m 755 "$base"
fi
[[ ! -L "$base" && "$(stat -c %U:%G:%a "$base")" == root:root:755 ]] \
  || { echo "Acceptance release root is untrusted." >&2; exit 1; }
if [[ ! -e "$release" && ! -L "$release" ]]; then
  install -d -o root -g root -m 755 "$temporary"
  install -o root -g root -m 755 "${sources[0]}" "$temporary/recovery.py"
  for source in "${sources[@]:1:6}"; do
    install -o root -g root -m 644 "$source" "$temporary/$(basename "$source")"
  done
  sync -d "$temporary"
  mv "$temporary" "$release"
  sync -d "$base"
fi
[[ -d "$release" && ! -L "$release" \
   && "$(stat -c %U:%G:%a "$release")" == root:root:755 ]] \
  || { echo "Installed acceptance release is untrusted." >&2; exit 1; }
shopt -s nullglob dotglob
release_entries=("$release"/*)
[[ "${#release_entries[@]}" -eq 7 ]] \
  || { echo "Installed acceptance release inventory is untrusted." >&2; exit 1; }
for index in 0 1 2 3 4 5 6; do
  source="${sources[$index]}"
  name="$(basename "$source")"
  [[ "$index" -eq 0 ]] && name=recovery.py
  expected_mode=644
  [[ "$index" -eq 0 ]] && expected_mode=755
  [[ -f "$release/$name" && ! -L "$release/$name" \
     && "$(stat -c %U:%G:%a "$release/$name")" == "root:root:$expected_mode" ]] \
    || { echo "Installed acceptance file is untrusted." >&2; exit 1; }
  cmp -s "$source" "$release/$name" \
    || { echo "Installed acceptance release differs from campaign source." >&2; exit 1; }
done

if [[ ! -e "$state" && ! -L "$state" ]]; then
  install -d -o root -g root -m 700 "$state"
fi
[[ ! -L "$state" && "$(stat -c %U:%G:%a "$state")" == root:root:700 ]] \
  || { echo "Acceptance state root is untrusted." >&2; exit 1; }
if [[ -e "$campaign" || -L "$campaign" ]]; then
  [[ -d "$campaign" && ! -L "$campaign" \
     && "$(stat -c %U:%G:%a "$campaign")" == root:root:700 ]] \
    || { echo "Acceptance campaign state is untrusted." >&2; exit 1; }
  cmp -s /tmp/campaign.json "$campaign/campaign.json" \
    || { echo "Acceptance campaign identity collision." >&2; exit 1; }
else
  install -d -o root -g root -m 700 "$campaign"
  install -o root -g root -m 600 /tmp/campaign.json "$campaign/campaign.json"
  sync -d "$campaign"
  sync -d "$state"
fi
[[ -f "$campaign/campaign.json" && ! -L "$campaign/campaign.json" \
   && "$(stat -c %U:%G:%a "$campaign/campaign.json")" == root:root:600 ]] \
  || { echo "Acceptance campaign record is untrusted." >&2; exit 1; }

"$release/recovery.py" --help >/dev/null
echo "harness-lifecycle-acceptance-recovery:installed:$campaign_id:$source_commit"
