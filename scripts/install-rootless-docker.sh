#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

# The outer provisioning transaction owns the exact-interface, default-deny
# maintenance firewall and its fail-closed restoration.
nft list table inet secure_sandbox_maintenance >/dev/null

export DEBIAN_FRONTEND=noninteractive
apt-get update --error-on=any
package_staging="$(mktemp -d /var/tmp/secure-sandbox-docker-packages.XXXXXX)"
chown _apt:nogroup "$package_staging"
chmod 0700 "$package_staging"
verified_staging="$(mktemp -d /var/tmp/secure-sandbox-docker-verified.XXXXXX)"
chmod 0700 "$verified_staging"
key_staging="$package_staging/docker.asc"
gpg_home="$(mktemp -d /var/tmp/secure-sandbox-docker-gpg.XXXXXX)"
chmod 0700 "$gpg_home"
cleanup_staging() {
  rm -rf -- "$package_staging"
  rm -rf -- "$verified_staging"
  rm -rf -- "$gpg_home"
}
trap cleanup_staging EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

verified_debs=()
require_clean_dpkg_state() {
  local audit pending_triggers
  audit="$(dpkg --audit)"
  [[ -z "$audit" ]] || {
    echo "Dirty dpkg state refused before verified package installation: $audit" >&2
    exit 2
  }
  pending_triggers="$(cat /var/lib/dpkg/triggers/Unincorp 2>/dev/null || true)"
  [[ -z "$pending_triggers" ]] || {
    echo "Pending dpkg triggers refused before verified package installation." >&2
    exit 2
  }
}
download_verified_deb() {
  local package="$1" version="$2" expected_sha256="$3" directory deb sealed architecture
  directory="$package_staging/$package"
  install -d -o _apt -g nogroup -m 0700 "$directory"
  (cd "$directory" && apt-get download "$package=$version")
  shopt -s nullglob
  local candidates=("$directory"/*.deb)
  shopt -u nullglob
  [[ "${#candidates[@]}" -eq 1 ]] || { echo "Expected one archive for $package=$version." >&2; exit 2; }
  deb="${candidates[0]}"
  sealed="$verified_staging/$package.deb"
  install -o root -g root -m 0600 "$deb" "$sealed"
  [[ "$(stat -c '%u:%g:%a:%h' "$sealed")" == "0:0:600:1" ]]
  [[ "$(sha256sum "$sealed" | awk '{print $1}')" == "$expected_sha256" ]] || {
    echo "Package digest mismatch for $package=$version." >&2
    exit 2
  }
  architecture="$(dpkg-deb -f "$sealed" Architecture)"
  [[ "$(dpkg-deb -f "$sealed" Package)" == "$package" \
      && "$(dpkg-deb -f "$sealed" Version)" == "$version" \
      && ( "$architecture" == "$(dpkg --print-architecture)" || "$architecture" == all ) ]] || {
    echo "Package identity mismatch for $package=$version." >&2
    exit 2
  }
  verified_debs+=("$sealed")
}

install_closed_package_set() {
  local allowed_regex="$1" plan unexpected
  shift
  require_clean_dpkg_state
  plan="$(apt-get --simulate --no-install-recommends install "$@")"
  unexpected="$(printf '%s\n' "$plan" | awk '
      /^(Inst|Conf|Remv|Purg) / { print $1 " " $2 }
    ' | awk -v allowed="$allowed_regex" '
      $1 != "Inst" && $1 != "Conf" { print; next }
      $2 !~ allowed { print }
    ')"
  [[ -z "$unexpected" ]] || {
    echo "Unbound or destructive package action refused: $unexpected" >&2
    exit 2
  }
  apt-get install -y --no-install-recommends --no-download "$@"
  require_clean_dpkg_state
}

download_verified_deb ca-certificates 20260816ubuntu0.26.04.1 5b6326f1932cfd7be57130561dc78192f09ed9f58bfbe6606ed0c50510c3b6cd
download_verified_deb curl 8.18.0-1ubuntu2.8 c36ec0de66d79adc9f8748d54cd0b2ac6b3d3458e0145dd83c9524345fb9e562
download_verified_deb uidmap 1:4.17.4-2ubuntu3 3ddb0a35548d850ce2210dc904b9cc9d2e2a067bc456675724345ca9b42a8baf
download_verified_deb slirp4netns 1.3.3-1 f6ad432a1fffefcd53058b9ae6f3afa4a2e7a1a25ce1a737d8e0f62d0bc263a9
download_verified_deb fuse-overlayfs 1.14-1build2 e38c2876a2437edd3f4ea1205af7c740d3591f5368c679b7a3a8629d14fcb99c
install_closed_package_set '^(ca-certificates|curl|uidmap|slirp4netns|fuse-overlayfs)$' "${verified_debs[@]}"
install -m 0755 -d /etc/apt/keyrings
sudo -u _apt curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$key_staging"
install -o root -g root -m 0600 "$key_staging" "$verified_staging/docker.asc"
key_staging="$verified_staging/docker.asc"
[[ "$(stat -c '%u:%g:%a:%h' "$key_staging")" == "0:0:600:1" ]]
[[ "$(sha256sum "$key_staging" | awk '{print $1}')" == 1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570 ]] || {
  echo "Docker repository key digest mismatch." >&2
  exit 2
}
docker_key_fingerprint="$(gpg --homedir "$gpg_home" --batch --show-keys --with-colons "$key_staging" \
  | awk -F: '$1 == "pub" { saw_pub=1; next } saw_pub && $1 == "fpr" { print $10; exit }')"
[[ "$docker_key_fingerprint" == 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 ]] || {
  echo "Docker repository key fingerprint mismatch." >&2
  exit 2
}
install -o root -g root -m 0644 "$key_staging" /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

. /etc/os-release
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
Architectures: $(dpkg --print-architecture)
EOF

apt-get update --error-on=any
verified_debs=()
download_verified_deb containerd.io 2.4.2-3~ubuntu.26.04~resolute b7a3ddf7d19a14c820b447cf4bfdd66dacfab20dfbdbd65c309616ccd8f8db0e
download_verified_deb docker-buildx-plugin 0.38.1-1~ubuntu.26.04~resolute caf05489330bb894554db18727c7f40a4d4ea3e346c616d9f0c37e287d2d4fc7
download_verified_deb docker-ce 5:29.9.2-1~ubuntu.26.04~resolute 537a81dbbf75ef308565f5822284bee9d160ad7b2fd3a5dc851b52a6d1a96d31
download_verified_deb docker-ce-cli 5:29.9.2-1~ubuntu.26.04~resolute 347ae1721630f33a6802a235a178f1b7c13ec6ae13f8dffa64cb08efe3005d5d
download_verified_deb docker-ce-rootless-extras 5:29.9.2-1~ubuntu.26.04~resolute 7795f8a2a264c03b1d305a7099638b8d81e3e67a955b069599ec7d52058f7e5a
download_verified_deb docker-compose-plugin 5.6.1-1~ubuntu.26.04~resolute 9aabff6db3373089a66488845ca46adbbf4e8cdecf81920a22ce51595e117d51
install_closed_package_set '^(containerd.io|docker-buildx-plugin|docker-ce|docker-ce-cli|docker-ce-rootless-extras|docker-compose-plugin)$' "${verified_debs[@]}"

systemctl disable --now docker.service docker.socket containerd.service
systemctl mask docker.service docker.socket containerd.service
rm -f /var/run/docker.sock
for unit in docker.service docker.socket containerd.service; do
  [[ "$(systemctl is-enabled "$unit")" == masked ]]
  ! systemctl is-active --quiet "$unit"
done
[[ ! -e /var/run/docker.sock ]]
loginctl enable-linger labadmin
uid="$(id -u labadmin)"
run_dir="/run/user/$uid"
systemctl start "user@$uid.service"
for _ in {1..30}; do
  [[ -S "$run_dir/bus" ]] && break
  sleep 1
done
[[ -S "$run_dir/bus" ]] || { echo "labadmin user manager did not create its private bus" >&2; exit 2; }
[[ "$(stat -c '%u:%g:%a' "$run_dir")" == "$uid:$uid:700" ]] || {
  echo "labadmin runtime directory metadata is not trusted" >&2
  exit 2
}

cat > /etc/modules-load.d/docker.conf <<'EOF'
br_netfilter
EOF
modprobe br_netfilter

install -d -m 700 -o labadmin -g labadmin /home/labadmin/.config
install -d -m 700 -o labadmin -g labadmin /home/labadmin/.config/docker
cat > /home/labadmin/.config/docker/daemon.json <<'EOF'
{
  "live-restore": false,
  "log-driver": "local",
  "log-opts": {
    "max-file": "3",
    "max-size": "10m"
  },
  "no-new-privileges": true,
  "userland-proxy": false
}
EOF
chown labadmin:labadmin /home/labadmin/.config/docker/daemon.json
chmod 600 /home/labadmin/.config/docker/daemon.json

sudo -u labadmin \
  HOME=/home/labadmin \
  USER=labadmin \
  LOGNAME=labadmin \
  XDG_RUNTIME_DIR="$run_dir" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$run_dir/bus" \
  dockerd-rootless-setuptool.sh install --force

sudo -u labadmin \
  HOME=/home/labadmin \
  USER=labadmin \
  LOGNAME=labadmin \
  XDG_RUNTIME_DIR="$run_dir" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$run_dir/bus" \
  systemctl --user reset-failed docker.service

sudo -u labadmin \
  HOME=/home/labadmin \
  USER=labadmin \
  LOGNAME=labadmin \
  XDG_RUNTIME_DIR="$run_dir" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$run_dir/bus" \
  systemctl --user enable --now docker.service

cleanup_staging
trap - EXIT INT TERM
echo 'rootless-docker-installed'
