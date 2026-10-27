#!/bin/bash
set -euo pipefail
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Target." >&2; exit 1; }
backup_root=/var/lib/secure-sandbox/policy-backups
pending="$backup_root/disposable-execution-target-install.pending"
backup_keys=(root-service root-shared-init root-bounded-http root-unit root-config legacy-service legacy-shared-init legacy-bounded-http legacy-unit legacy-config)
backup_destinations=(
  /usr/local/libexec/secure-sandbox/execution_service.py
  /usr/local/libexec/secure-sandbox/shared/__init__.py
  /usr/local/libexec/secure-sandbox/shared/bounded_http.py
  /etc/systemd/user/secure-sandbox-execution.service
  /etc/secure-sandbox/execution-target.json
  /home/labadmin/.local/libexec/secure-sandbox/execution_service.py
  /home/labadmin/.local/libexec/secure-sandbox/shared/__init__.py
  /home/labadmin/.local/libexec/secure-sandbox/shared/bounded_http.py
  /home/labadmin/.config/systemd/user/secure-sandbox-execution.service
  /home/labadmin/.config/secure-sandbox-execution.json
)
restore_backup() {
  local backup_id="$1" backup="$backup_root/$1" index destination key uid runtime
  [[ "$backup_id" =~ ^disposable-execution-target-[0-9]{8}T[0-9]{6}Z-[0-9]+$ \
     && -d "$backup" && ! -L "$backup" ]] || return 1
  for index in "${!backup_destinations[@]}"; do
    destination="${backup_destinations[$index]}"; key="${backup_keys[$index]}"
    if [[ -f "$backup/$key" && ! -L "$backup/$key" ]]; then
      mkdir -p "$(dirname "$destination")"
      cp -p --no-dereference "$backup/$key" "$destination"
    elif [[ -f "$backup/$key.absent" ]]; then
      rm -f -- "$destination"
    else
      return 1
    fi
  done
  uid="$(id -u labadmin)"; runtime="/run/user/$uid"
  sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user daemon-reload || true
  if sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user is-active --quiet secure-sandbox-execution.service; then
    sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user restart secure-sandbox-execution.service || true
  fi
  rm -f -- "$pending"
  sync -d "$backup_root"
}
if [[ -e "$pending" || -L "$pending" ]]; then
  [[ -f "$pending" && ! -L "$pending" && "$(stat -c %U:%G:%a "$pending")" = root:root:600 ]] \
    || { echo "Untrusted Target install recovery marker." >&2; exit 1; }
  restore_backup "$(cat "$pending")" \
    || { echo "Target install recovery failed." >&2; exit 1; }
fi
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
image_id="$(bash "$builder")"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Runtime image build failed." >&2; exit 1; }

backup_id="disposable-execution-target-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="$backup_root/$backup_id"
install -d -o root -g root -m 700 "$backup_root" "$backup"
for index in "${!backup_destinations[@]}"; do
  destination="${backup_destinations[$index]}"; key="${backup_keys[$index]}"
  if [[ -f "$destination" && ! -L "$destination" ]]; then
    cp -p --no-dereference "$destination" "$backup/$key"
  else
    : > "$backup/$key.absent"
  fi
done
chmod -R go-rwx "$backup"
printf '%s\n' "$backup_id" > "$pending.new"
chown root:root "$pending.new"; chmod 600 "$pending.new"; mv "$pending.new" "$pending"
sync -d "$backup_root"
rollback_on_error() { trap - ERR HUP INT TERM; restore_backup "$backup_id" || true; }
trap rollback_on_error ERR
trap 'rollback_on_error; exit 70' HUP INT TERM

install -d -o labadmin -g labadmin -m 700 \
  /home/labadmin/.local/share/secure-sandbox-execution/jobs
install -d -o root -g root -m 755 /etc/systemd/user
install -d -o root -g root -m 755 /etc/secure-sandbox
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox/shared
install -o root -g root -m 644 "$shared_init" /usr/local/libexec/secure-sandbox/shared/__init__.py
install -o root -g root -m 755 "$bounded_http" /usr/local/libexec/secure-sandbox/shared/bounded_http.py
install -o root -g root -m 755 "$service_source" /usr/local/libexec/secure-sandbox/execution_service.py
install -o root -g root -m 644 "$unit_source" /etc/systemd/user/secure-sandbox-execution.service
rm -f -- /home/labadmin/.local/libexec/secure-sandbox/execution_service.py \
  /home/labadmin/.local/libexec/secure-sandbox/shared/__init__.py \
  /home/labadmin/.local/libexec/secure-sandbox/shared/bounded_http.py
rm -f -- /home/labadmin/.config/systemd/user/secure-sandbox-execution.service \
  /home/labadmin/.config/secure-sandbox-execution.json
rmdir /home/labadmin/.local/libexec/secure-sandbox/shared \
  /home/labadmin/.local/libexec/secure-sandbox /home/labadmin/.local/libexec 2>/dev/null || true
config_tmp="$(mktemp /tmp/secure-sandbox-execution-config.XXXXXX)"
trap 'rm -f -- "$config_tmp"' EXIT
jq -n --arg token "$token" --arg image "$image_id" \
  '{schema:"secure-sandbox-execution-target-v1",token:$token,image_id:$image}' \
  > "$config_tmp"
install -o root -g labadmin -m 640 "$config_tmp" /etc/secure-sandbox/execution-target.json
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
trap - ERR HUP INT TERM
rm -f -- "$pending"
sync -d "$backup_root"
echo "disposable-execution-target:installed:$image_id"
