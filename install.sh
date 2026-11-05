#!/usr/bin/env bash
# ==============================================================================
# uKey user installer for Fedora
# Installs udev permissions, a Python virtual environment, and a user service.
# Safe defaults: loopback signer bridge, auto-lock disabled.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

CONFIG_PATH="${UKEY_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/ukey/config.json}"
export UKEY_CONFIG="$CONFIG_PATH"

echo -e "${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}   uKey user installer (Fedora)${NC}"
echo -e "${CYAN}   udev permissions + virtual FIDO2 daemon + user service${NC}"
echo -e "${CYAN}========================================================================${NC}\n"

if ! command -v dnf >/dev/null 2>&1; then
    echo -e "${RED}This installer currently supports Fedora only.${NC}"
    echo "Use the manual setup in README.md on other distributions."
    exit 1
fi

# Step 1: Install kernel rules and permissions via sudo
echo -e "${CYAN}[1/5] Configuring /dev/uhid kernel permissions...${NC}"
sudo "$SCRIPT_DIR/setup_udev.sh"

# Step 2: Ensure validation tools are present
echo -e "\n${CYAN}[2/5] Checking optional validation tools...${NC}"
if ! rpm -q fido2-tools &>/dev/null; then
    echo -e "${YELLOW}Installing fido2-tools for validation...${NC}"
    sudo dnf install -y fido2-tools
else
    echo -e "${GREEN}✓ fido2-tools is installed.${NC}"
fi

# Step 3: Verify Python virtual environment
echo -e "\n${CYAN}[3/5] Verifying Python virtual environment...${NC}"
if [[ ! -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv "$SCRIPT_DIR/.venv"
    "$SCRIPT_DIR/.venv/bin/pip" install --upgrade pip
    "$SCRIPT_DIR/.venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
fi
echo -e "${GREEN}✓ Python virtual environment ready.${NC}"

# Step 4: Install the user service and safe default configuration
echo -e "\n${CYAN}[4/5] Installing systemd user service...${NC}"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"

sed "s|%h/.local/share/ukey|$SCRIPT_DIR|g" \
    "$SCRIPT_DIR/systemd/ukey.service" > "$SYSTEMD_USER_DIR/ukey.service"

systemctl --user daemon-reload
systemctl --user enable ukey.service
systemctl --user restart ukey.service

if [[ ! -f "$CONFIG_PATH" ]]; then
    "$SCRIPT_DIR/scripts/ukeyctl" config set auto_lock false >/dev/null
    echo -e "${GREEN}✓ Wrote safe defaults to $CONFIG_PATH${NC}"
else
    echo -e "${GREEN}✓ Kept existing configuration at $CONFIG_PATH${NC}"
fi

echo -e "${GREEN}✓ systemd user service 'ukey.service' enabled and started.${NC}"

# Step 5: Verify status
echo -e "\n${CYAN}[5/5] Verifying service health...${NC}"
sleep 1
if systemctl --user is-active --quiet ukey.service; then
    echo -e "${GREEN}✓ uKey is running.${NC}"
else
    echo -e "${YELLOW}Service is not active yet. Check: systemctl --user status ukey${NC}"
fi

echo -e "\n${GREEN}========================================================================${NC}"
echo -e "${BOLD}${GREEN}Installation complete${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo -e "• Default transport: USB via ${BOLD}adb reverse${NC}, loopback ${CYAN}127.0.0.1:8443${NC}"
echo -e "• Default behavior: auto-lock ${BOLD}disabled${NC}; phone disconnect leaves the session unlocked"
echo -e "• Opt in to Wi-Fi: ${CYAN}ukeyctl config set wireless true${NC}"
echo -e "• Opt in to auto-lock: ${CYAN}ukeyctl config set auto_lock true${NC}"
echo -e "• Apply changes: ${CYAN}systemctl --user restart ukey${NC}"
echo -e "• Config file: ${CYAN}${CONFIG_PATH}${NC}"
echo -e "• Status: ${CYAN}ukeyctl status${NC}"
echo -e "• Logs: ${CYAN}ukeyctl logs${NC}\n"
