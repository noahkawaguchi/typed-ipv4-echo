#!/usr/bin/env bash
set -euo pipefail

#
# Script to create a TUN device.
#
# Requires CAP_NET_ADMIN capabilities (e.g. by running this script with sudo).
# After being created, the device can then be accessed by the user who ran the
# script without needing the capabilities.
#
# The device persists until reboot. It can also be removed manually with
# `sudo ip link del tun0`.
#

# Optional environment variable configuration
device_name=${TUN_DEVICE_NAME:-tun0}
ip_cidr=${TUN_IP_CIDR:-10.0.0.1/24}

# Get original non-root user when run with sudo
real_user=${SUDO_USER:-$USER}

if ip addr show "$device_name" >/dev/null 2>&1; then
  echo "Device $device_name already exists" >&2
  exit 1
fi

ip tuntap add dev "$device_name" mode tun user "$real_user"
ip addr add "$ip_cidr" dev "$device_name"
ip link set "$device_name" up

echo "TUN device created: name=$device_name, CIDR=$ip_cidr, user=$real_user"
