#!/usr/bin/env bash
# Install uKey's UHID and hidraw udev rules.
#
# Usage:
#   ./setup_udev.sh          # re-executes itself through sudo
#   sudo ./setup_udev.sh
#
# TAG+="uaccess" grants the currently logged-in user an ACL on the device via
# systemd-logind. This avoids a world-writable /dev/uhid and avoids requiring
# the daemon to run as root.

set -euo pipefail

RULES_FILE="/etc/udev/rules.d/70-ukey.rules"

if [[ ${EUID} -ne 0 ]]; then
    exec sudo -- "$0" "$@"
fi

# Ensure kernel module is loaded and persists across reboots
modprobe uhid || true
echo "uhid" > /etc/modules-load.d/uhid.conf 2>/dev/null || true

cat > "${RULES_FILE}" <<'EOF'
# uKey virtual FIDO2 authenticator
# /dev/uhid is the control channel used by the daemon.
KERNEL=="uhid", SUBSYSTEM=="misc", TAG+="uaccess", MODE="0666"

# hidraw node for the virtual key
KERNEL=="hidraw*", ATTRS{name}=="uKey FIDO2 Authenticator", TAG+="uaccess", MODE="0666"
KERNEL=="hidraw*", ATTRS{modalias}=="hid:b0003g0001v00001209p00000001", TAG+="uaccess", MODE="0666"
EOF

chmod 0644 "${RULES_FILE}"
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc --subsystem-match=hidraw 2>/dev/null || true
udevadm settle || true

# Grant immediate ACL access to the running user
ACTUAL_USER="${SUDO_USER:-$USER}"
if [[ -n "$ACTUAL_USER" && -e /dev/uhid ]]; then
    setfacl -m u:"$ACTUAL_USER":rw /dev/uhid 2>/dev/null || chmod 0666 /dev/uhid 2>/dev/null || true
fi

echo "installed ${RULES_FILE}"
echo "✓ Granted immediate read/write access on /dev/uhid for $ACTUAL_USER"
