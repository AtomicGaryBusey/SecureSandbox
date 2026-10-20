#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

restore_firewall() {
  nft -f /etc/nftables.conf
}
trap restore_firewall EXIT INT TERM

# Provisioning is performed only on the clean golden image. Restore the
# default-deny policy even when package installation fails.
nft flush ruleset

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl uidmap slirp4netns fuse-overlayfs
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
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

apt-get update
apt-get install -y \
  containerd.io \
  docker-buildx-plugin \
  docker-ce \
  docker-ce-cli \
  docker-ce-rootless-extras \
  docker-compose-plugin

systemctl disable --now docker.service docker.socket containerd.service || true
rm -f /var/run/docker.sock
loginctl enable-linger labadmin

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

uid="$(id -u labadmin)"
run_dir="/run/user/$uid"
install -d -m 700 -o labadmin -g labadmin "$run_dir"

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

echo 'rootless-docker-installed'
