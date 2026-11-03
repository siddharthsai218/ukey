#!/usr/bin/env bash
# ==============================================================================
# uKey: Safe PAM Sudo Configuration Script
# Configures pam_u2f for passwordless sudo with 100% safe password fallback.
# ==============================================================================

set -euo pipefail

PAM_FILE="/etc/pam.d/sudo"
BACKUP_FILE="/etc/pam.d/sudo.ukey.bak"
ACTUAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(getent passwd "$ACTUAL_USER" | cut -d: -f6)
U2F_CONFIG_DIR="$USER_HOME/.config/Yubico"
U2F_KEYS_FILE="$U2F_CONFIG_DIR/u2f_keys"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   uKey — Safe Linux PAM Sudo Configuration Tool            ${NC}"
echo -e "${CYAN}============================================================${NC}"

# Handle Restore Argument
if [[ "${1:-}" == "--restore" || "${1:-}" == "--uninstall" ]]; then
    if [[ -f "$BACKUP_FILE" ]]; then
        sudo cp "$BACKUP_FILE" "$PAM_FILE"
        echo -e "${GREEN}✓ Successfully restored original $PAM_FILE from backup.${NC}"
        echo -e "${GREEN}✓ uKey PAM configuration removed.${NC}"
        exit 0
    else
        echo -e "${RED}Error: Backup file $BACKUP_FILE not found!${NC}"
        exit 1
    fi
fi

# Ensure running with sudo
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Please run with sudo: sudo ./scripts/setup_pam_sudo.sh${NC}"
    exit 1
fi

# Step 1: Check required packages
echo -e "\n${CYAN}[1/4] Checking required system packages...${NC}"
MISSING_PKGS=()
if ! rpm -q pam-u2f &>/dev/null; then
    MISSING_PKGS+=("pam-u2f")
fi
if ! rpm -q pamu2fcfg &>/dev/null; then
    MISSING_PKGS+=("pamu2fcfg")
fi
if ! rpm -q fido2-tools &>/dev/null; then
    MISSING_PKGS+=("fido2-tools")
fi

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Installing missing packages: ${MISSING_PKGS[*]}...${NC}"
    dnf install -y "${MISSING_PKGS[@]}"
else
    echo -e "${GREEN}✓ pam-u2f and fido2-tools are already installed.${NC}"
fi

# Step 2: Ensure Yubico directory exists for the user
echo -e "\n${CYAN}[2/4] Verifying user enrollment directory...${NC}"
sudo -u "$ACTUAL_USER" mkdir -p "$U2F_CONFIG_DIR"

if [[ ! -f "$U2F_KEYS_FILE" || ! -s "$U2F_KEYS_FILE" ]]; then
    echo -e "${YELLOW}No enrolled uKey credentials found at $U2F_KEYS_FILE.${NC}"
    echo -e "${CYAN}Please ensure the uKey daemon and phone are running, then run:${NC}"
    echo -e "   pamu2fcfg -o pam://\$(hostname) -i pam://\$(hostname) > $U2F_KEYS_FILE"
    echo -e "${YELLOW}Touch your phone fingerprint sensor when prompted.${NC}\n"
    
    read -rp "Do you want to enroll your connected uKey right now? (y/N): " enroll_choice
    if [[ "$enroll_choice" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Running pamu2fcfg... Touch your phone biometric now:${NC}"
        sudo -u "$ACTUAL_USER" pamu2fcfg -o "pam://$(hostname)" -i "pam://$(hostname)" > "$U2F_KEYS_FILE"
        echo -e "${GREEN}✓ Enrolled uKey credentials saved to $U2F_KEYS_FILE.${NC}"
    else
        echo -e "${YELLOW}Skipping enrollment. You can create $U2F_KEYS_FILE manually.${NC}"
        exit 0
    fi
else
    echo -e "${GREEN}✓ Existing uKey credential found at $U2F_KEYS_FILE.${NC}"
fi

# Step 3: Backup /etc/pam.d/sudo
echo -e "\n${CYAN}[3/4] Backing up $PAM_FILE...${NC}"
if [[ ! -f "$BACKUP_FILE" ]]; then
    cp "$PAM_FILE" "$BACKUP_FILE"
    echo -e "${GREEN}✓ Created backup at $BACKUP_FILE.${NC}"
else
    echo -e "${GREEN}✓ Backup already exists at $BACKUP_FILE.${NC}"
fi

# Step 4: Inject pam_u2f into /etc/pam.d/sudo safely
echo -e "\n${CYAN}[4/4] Configuring PAM stack...${NC}"
PAM_LINE="auth       sufficient   pam_u2f.so authfile=$U2F_KEYS_FILE cue prompt=Touch\\ phone\\ biometric\\ or\\ press\\ Enter\\ for\\ password:"

if grep -q "pam_u2f.so" "$PAM_FILE"; then
    echo -e "${YELLOW}pam_u2f.so is already configured in $PAM_FILE.${NC}"
else
    # Prepend PAM_LINE safely using a temporary file
    TMP_PAM=$(mktemp)
    {
        echo "# Added by uKey installer"
        echo "$PAM_LINE"
        echo ""
        cat "$PAM_FILE"
    } > "$TMP_PAM"
    cp "$TMP_PAM" "$PAM_FILE"
    rm -f "$TMP_PAM"
    echo -e "${GREEN}✓ Added pam_u2f module to $PAM_FILE with 'sufficient' priority.${NC}"
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}✓ uKey Sudo Authentication successfully configured!        ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "How it works in your terminal:"
echo -e "1. Run: ${CYAN}sudo dnf update${NC}"
echo -e "2. Touch your phone fingerprint -> ${GREEN}Unlocked in 0.4s!${NC}"
echo -e "3. Or press ${CYAN}Enter${NC} -> ${YELLOW}Instant fallback to password in 0.0s!${NC}"
echo -e "4. Or press ${CYAN}Ctrl+C${NC} -> ${RED}Exits command immediately.${NC}"
echo -e "\nTo undo anytime: ${CYAN}sudo ./scripts/setup_pam_sudo.sh --restore${NC}\n"
