#!/bin/zsh
set -euo pipefail

workspace_dir="$(cd "$(dirname "$0")/.." && pwd)"
vm_dir="$workspace_dir/vms"
release_directory="$workspace_dir/artifacts/ubuntu-26.04.1"
verifier="/usr/local/libexec/secure-sandbox-host/current/installer_verifier"

gateway_vm="SecureSandbox-Gateway"
research_vm="SecureSandbox-Research"
target_vm="SecureSandbox-Target"

[[ -x "$verifier" && ! -L "$verifier" ]] || { print -u2 "Root-owned installer verifier is unavailable; deploy the host-controller release first."; exit 1; }
iso_path="$(/usr/bin/sudo /usr/bin/python3 "$verifier" --release-directory "$release_directory" --promote --path-only)"
[[ "$iso_path" == /Library/Application\ Support/SecureSandbox/installers/*.iso ]] || {
  print -u2 "Installer verifier returned an invalid protected path."
  exit 1
}

for vm_name in "$gateway_vm" "$research_vm" "$target_vm"; do
  if prlctl list --all --no-header --output name | /usr/bin/grep -Fqx "$vm_name"; then
    print -u2 "Refusing to overwrite existing VM: $vm_name"
    exit 1
  fi
done

/bin/mkdir -p "$vm_dir"

create_base_vm() {
  local vm_name="$1"
  local cpus="$2"
  local memory_mb="$3"
  local disk_mb="$4"

  prlctl create "$vm_name" --distribution ubuntu --dst "$vm_dir" --no-hdd
  prlctl set "$vm_name" --description "SecureSandbox disposable Ubuntu ARM64 lab VM"
  prlctl set "$vm_name" --cpus "$cpus"
  prlctl set "$vm_name" --memsize "$memory_mb"
  prlctl set "$vm_name" --device-add hdd --type expand --size "$disk_mb" --iface sata
  prlctl set "$vm_name" --device-set cdrom0 --image "$iso_path"
  prlctl set "$vm_name" --device-bootorder "cdrom0 hdd0"
  prlctl set "$vm_name" --bios-type efi-arm64 --efi-secure-boot on --select-boot-device off

  prlctl set "$vm_name" --isolate-vm on
  prlctl set "$vm_name" --shf-host off --shf-host-defined off --shf-host-automount off
  prlctl set "$vm_name" --shf-guest off --shf-guest-automount off
  prlctl set "$vm_name" --shf-guest-automount-cloud-drives off
  prlctl set "$vm_name" --shf-guest-automount-network-drives off
  prlctl set "$vm_name" --shf-guest-automount-removable-drives off
  prlctl set "$vm_name" --shared-profile off
  prlctl set "$vm_name" --sh-app-host-to-guest off --sh-app-guest-to-host off
  prlctl set "$vm_name" --show-guest-app-folder-in-dock off
  prlctl set "$vm_name" --bounce-dock-icon-when-app-flashes off
  prlctl set "$vm_name" --smart-mount off --smart-mount-removable-drives off
  prlctl set "$vm_name" --smart-mount-dvd-drives off --smart-mount-network-shares off
  prlctl set "$vm_name" --shared-clipboard off --shared-cloud off
  prlctl set "$vm_name" --sync-vm-hostname off --sync-ssh-ids off
  prlctl set "$vm_name" --show-dev-tools off --share-host-location off --rosetta-linux off
  prlctl set "$vm_name" --auto-share-camera off --auto-share-smart-card off --support-usb30 off
  prlctl set "$vm_name" --auto-share-gamepad off
  prlctl set "$vm_name" --sync-host-printers off --sync-default-printer off --show-host-printer-ui off
  prlctl set "$vm_name" --nested-virt off --pmu-virt off --battery-status off
  prlctl set "$vm_name" --3d-accelerate off --vertical-sync off
  prlctl set "$vm_name" --high-resolution off --high-resolution-in-guest off
  prlctl set "$vm_name" --native-scaling-in-guest off
  prlctl set "$vm_name" --time-sync off --disable-timezone-sync on
  prlctl set "$vm_name" --autostart off --autostop stop --on-window-close ask
  prlctl set "$vm_name" --tools-autoupdate no --usedefanswers off

  # Device deletion is stronger than relying on integration toggles that have
  # historically been reset by Parallels defaults.
  prlctl set "$vm_name" --device-del usb
  prlctl set "$vm_name" --device-del sound0
  prlctl set "$vm_name" --device-del serial0
}

create_base_vm "$gateway_vm" 1 2048 12288
prlctl set "$gateway_vm" --device-add net --type host-only --iface control-net --adapter-type virtio

create_base_vm "$research_vm" 4 6144 51200
prlctl set "$research_vm" --device-add net --type host-only --iface control-net --adapter-type virtio
prlctl set "$research_vm" --device-add net --type host-only --iface lab-net --adapter-type virtio

create_base_vm "$target_vm" 2 4096 40960
prlctl set "$target_vm" --device-add net --type host-only --iface lab-net --adapter-type virtio

for vm_name in "$gateway_vm" "$research_vm" "$target_vm"; do
  prlctl list "$vm_name" --info
done
