#!/usr/bin/env bash
# ==============================================================================
# uKey User Installer (Linux)
# Fedora 43 is the tested path. Other distro branches are best-effort.
# Installs udev permissions, validation tools, Python venv, and a user service.
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
echo -e "${BOLD}${CYAN}   uKey User Installer (Fedora-tested)${NC}"
echo -e "${CYAN}   udev permissions + virtual FIDO2 daemon + systemd user service${NC}"
echo -e "${CYAN}========================================================================${NC}\n"

# Detect distribution
DISTRO="unknown"
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
fi

echo -e "Detected distribution: ${BOLD}${PRETTY_NAME:-$DISTRO}${NC}"

# Step 1: Install kernel rules and permissions via sudo
echo -e "\n${CYAN}[1/5] Configuring /dev/uhid kernel permissions...${NC}"
sudo "$SCRIPT_DIR/setup_udev.sh"

# Step 2: Ensure validation tools are present across distros
echo -e "\n${CYAN}[2/5] Checking required system packages and tools...${NC}"

install_distro_packages() {
    case "$DISTRO" in
        fedora|rhel|centos|almalinux|rocky)
            if ! command -v fido2-token &>/dev/null; then
                echo -e "${YELLOW}Installing fido2-tools via dnf...${NC}"
                sudo dnf install -y fido2-tools python3-pip
            fi
            ;;
        ubuntu|debian|pop|linuxmint|elementary)
            if ! command -v fido2-token &>/dev/null || ! dpkg -s python3-venv &>/dev/null; then
                echo -e "${YELLOW}Installing fido2-tools and python3-venv via apt-get...${NC}"
                sudo apt-get update -qq
                sudo apt-get install -y fido2-tools python3-venv python3-pip
            fi
            ;;
        arch|manjaro|endeavouros)
            if ! command -v fido2-token &>/dev/null; then
                echo -e "${YELLOW}Installing libfido2 via pacman...${NC}"
                sudo pacman -S --noconfirm --needed libfido2 python python-pip
            fi
            ;;
        opensuse*|sles)
            if ! command -v fido2-token &>/dev/null; then
                echo -e "${YELLOW}Installing fido2-tools via zypper...${NC}"
                sudo zypper install -y fido2-tools python3 python3-pip
            fi
            ;;
        *)
            if [[ "${DISTRO_LIKE:-}" == *"debian"* || "${DISTRO_LIKE:-}" == *"ubuntu"* ]]; then
                sudo apt-get update -qq && sudo apt-get install -y fido2-tools python3-venv python3-pip
            elif [[ "${DISTRO_LIKE:-}" == *"arch"* ]]; then
                sudo pacman -S --noconfirm --needed libfido2 python python-pip
            elif [[ "${DISTRO_LIKE:-}" == *"fedora"* || "${DISTRO_LIKE:-}" == *"rhel"* ]]; then
                sudo dnf install -y fido2-tools python3-pip
            else
                echo -e "${YELLOW}Unrecognized distro family. Ensure python3-venv and fido2-tools are installed.${NC}"
            fi
            ;;
    esac
}

install_distro_packages
echo -e "${GREEN}✓ System prerequisites checked.${NC}"

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
echo -e "${BOLD}${GREEN}Installation complete!${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo -e "• Dashboard: ${BOLD}${CYAN}http://127.0.0.1:8444${NC}"
echo -e "• Terminal UI: ${CYAN}ukeyctl menu${NC}"
echo -e "• Safe defaults: Auto-lock ${BOLD}disabled${NC}, loopback ${CYAN}127.0.0.1:8443${NC}"
echo -e "• Opt in to Wi-Fi: ${CYAN}ukeyctl config set wireless true${NC}"
echo -e "• Opt in to auto-lock: ${CYAN}ukeyctl config set auto_lock true${NC}"
echo -e "• Roadmap, not working: PAM/CTAP1 (CTAPHID_MSG returns 6d 00)"
echo -e "• Roadmap, untested: SSH ${CYAN}ecdsa-sk${NC} end-to-end"
echo -e "• Apply changes: ${CYAN}systemctl --user restart ukey${NC}"
echo -e "• Status: ${CYAN}ukeyctl status${NC}\n"
