#!/bin/bash
set -euo pipefail
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Target." >&2; exit 1; }
service_source="${1:-/tmp/execution_service.py}"
unit_source="${2:-/tmp/secure-sandbox-execution.service}"
builder="${3:-/tmp/build-python-runtime.sh}"
token_file="${4:-/tmp/execution-token}"
shared_init="${5:-/tmp/__init__.py}"
bounded_http="${6:-/tmp/bounded_http.py}"
for path in "$service_source" "$unit_source" "$builder" "$token_file" "$shared_init" "$bounded_http"; do
  [[ -f "$path" && ! -L "$path" ]] || { echo "Missing artifact: $path" >&2; exit 2; }
done
python3 -m py_compile "$service_source"
bash -n "$builder"
token="$(tr -d '\r\n' < "$token_file")"
[[ "$token" =~ ^[A-Za-z0-9]{64}$ ]] || { echo "Invalid execution token." >&2; exit 2; }

install -d -o labadmin -g labadmin -m 700 /home/labadmin/.local/libexec/secure-sandbox \
  /home/labadmin/.local/share/secure-sandbox-execution/jobs /home/labadmin/.config/systemd/user
install -d -o labadmin -g labadmin -m 755 /home/labadmin/.local/libexec/secure-sandbox/shared
install -o labadmin -g labadmin -m 644 "$shared_init" /home/labadmin/.local/libexec/secure-sandbox/shared/__init__.py
install -o labadmin -g labadmin -m 755 "$bounded_http" /home/labadmin/.local/libexec/secure-sandbox/shared/bounded_http.py
install -o labadmin -g labadmin -m 755 "$service_source" /home/labadmin/.local/libexec/secure-sandbox/execution_service.py
install -o labadmin -g labadmin -m 644 "$unit_source" /home/labadmin/.config/systemd/user/secure-sandbox-execution.service
image_id="$(bash "$builder")"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Runtime image build failed." >&2; exit 1; }
config_tmp="$(mktemp /tmp/secure-sandbox-execution-config.XXXXXX)"
trap 'rm -f -- "$config_tmp"' EXIT
jq -n --arg token "$token" --arg image "$image_id" \
  '{schema:"secure-sandbox-execution-target-v1",token:$token,image_id:$image}' \
  > "$config_tmp"
install -o labadmin -g labadmin -m 600 "$config_tmp" /home/labadmin/.config/secure-sandbox-execution.json
rm -f "$token_file"
uid="$(id -u labadmin)"; runtime="/run/user/$uid"
docker=(sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" DOCKER_HOST="unix://$runtime/docker.sock" docker)
sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user daemon-reload
sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user enable secure-sandbox-execution.service
sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user restart secure-sandbox-execution.service
sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user is-active --quiet secure-sandbox-execution.service
while IFS= read -r old_image; do
  [[ -z "$old_image" ]] && continue
  resolved_old="$("${docker[@]}" image inspect --format '{{.Id}}' "$old_image")"
  [[ "$resolved_old" == "$image_id" ]] && continue
  "${docker[@]}" image rm "$resolved_old" >/dev/null
done < <("${docker[@]}" image ls -q --no-trunc --filter label=org.securesandbox.runtime=python-fixture-v1 | sort -u)
[[ "$("${docker[@]}" image inspect --format '{{.Id}}' "$image_id")" == "$image_id" ]] \
  || { echo "Configured runtime image disappeared during cleanup." >&2; exit 1; }
echo "disposable-execution-target:installed:$image_id"
