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

if [[ ! -e /dev/uhid ]]; then
    echo "warning: /dev/uhid does not exist; is CONFIG_UHID enabled in the kernel?" >&2
fi

cat > "${RULES_FILE}" <<'EOF'
# uKey virtual FIDO2 authenticator
#
# /dev/uhid is the control channel used by the daemon.
KERNEL=="uhid", SUBSYSTEM=="misc", TAG+="uaccess", MODE="0660"

# hidraw node for the virtual key. The first rule is the one from the project
# specification. On current kernels the UHID HID parent has no "name" sysfs
# attribute (only uevent/modalias), so the modalias fallback below is what
# actually matches the virtual device on those systems.
KERNEL=="hidraw*", ATTRS{name}=="uKey FIDO2 Authenticator", TAG+="uaccess", MODE="0660"
KERNEL=="hidraw*", ATTRS{modalias}=="hid:b0003g0001v00001209p00000001", TAG+="uaccess", MODE="0660"
EOF

chmod 0644 "${RULES_FILE}"
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc --subsystem-match=hidraw
udevadm settle || true

echo "installed ${RULES_FILE}"
echo "If the device is already running, restart the daemon so udev re-applies access."
echo "Verify with: getfacl /dev/uhid /dev/hidraw*  (uaccess ACL for your user)"
