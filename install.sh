#!/usr/bin/env bash
# ==============================================================================
# uKey: 1-Command Production Installer & Systemd Service Enabler
# Turns uKey into a permanent, silent Linux background service on boot.
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

echo -e "${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}   🛡️  uKey — 1-Command Production Installer for Linux                ${NC}"
echo -e "${CYAN}   Installs systemd background service, udev rules & PAM integration   ${NC}"
echo -e "${CYAN}========================================================================${NC}\n"

# Step 1: Install kernel rules and permissions via sudo
echo -e "${CYAN}[1/5] Configuring /dev/uhid kernel permissions...${NC}"
sudo "$SCRIPT_DIR/setup_udev.sh"

# Step 2: Ensure required Fedora packages
echo -e "\n${CYAN}[2/5] Checking required system packages...${NC}"
MISSING_PKGS=()
for pkg in pam-u2f pamu2fcfg fido2-tools; do
    if ! rpm -q "$pkg" &>/dev/null; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Installing missing packages: ${MISSING_PKGS[*]}...${NC}"
    sudo dnf install -y "${MISSING_PKGS[@]}"
else
    echo -e "${GREEN}✓ All required system packages installed.${NC}"
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

# Step 4: Install systemd user service
echo -e "\n${CYAN}[4/5] Installing systemd background service...${NC}"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"

cp "$SCRIPT_DIR/systemd/ukey.service" "$SYSTEMD_USER_DIR/ukey.service"

systemctl --user daemon-reload
systemctl --user enable --now ukey.service

echo -e "${GREEN}✓ systemd service 'ukey.service' enabled and started!${NC}"

# Step 5: Verify status
echo -e "\n${CYAN}[5/5] Verifying service health...${NC}"
sleep 1
if systemctl --user is-active --quiet ukey.service; then
    echo -e "${GREEN}✓ uKey is actively running in the background!${NC}"
else
    echo -e "${YELLOW}Service starting... check with: systemctl --user status ukey${NC}"
fi

LAN_IP=$(hostname -I | awk '{print $1}')

echo -e "\n${GREEN}========================================================================${NC}"
echo -e "${BOLD}${GREEN}🎉 INSTALLATION COMPLETE — uKey is now a native Linux Service!          ${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo -e "• ${BOLD}Runs silently on every boot:${NC} You never have to type a terminal command again."
echo -e "• ${BOLD}Phone Connection Target:${NC} Host: ${CYAN}${LAN_IP}${NC}   Port: ${CYAN}8443${NC}"
echo -e "• ${BOLD}Check service status anytime:${NC} systemctl --user status ukey"
echo -e "• ${BOLD}Live logs:${NC} journalctl --user -u ukey -f\n"
