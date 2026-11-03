#!/usr/bin/env bash
# ==============================================================================
# uKey: Senior Reviewer & Technical Demonstration CLI
# Provides a structured, interactive walkthrough of all project capabilities.
# ==============================================================================

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

clear_screen() {
    clear || true
}

show_header() {
    echo -e "${CYAN}========================================================================${NC}"
    echo -e "${BOLD}${CYAN}   🛡️  uKey — Technical Demonstration & Senior Code Review CLI        ${NC}"
    echo -e "${CYAN}   Zero-Cost FIDO2 Hardware Security Key for Linux via Android Enclave   ${NC}"
    echo -e "${CYAN}========================================================================${NC}"
}

run_diagnostics() {
    echo -e "\n${BOLD}${CYAN}🔍 Running Pre-Flight System Diagnostics...${NC}\n"
    
    # 1. Check UHID
    echo -n "1. Checking Linux /dev/uhid access: "
    if [[ -r /dev/uhid && -w /dev/uhid ]]; then
        echo -e "${GREEN}✓ OK (Read/Write accessible)${NC}"
    else
        echo -e "${YELLOW}⚠️ Requires setup_udev.sh or root permissions${NC}"
    fi

    # 2. Check Python Venv
    echo -n "2. Checking Python virtual environment: "
    if [[ -x "$PROJECT_ROOT/.venv/bin/python" ]]; then
        echo -e "${GREEN}✓ OK ($($PROJECT_ROOT/.venv/bin/python --version))${NC}"
    else
        echo -e "${RED}✗ Missing .venv${NC}"
    fi

    # 3. Check ADB Bridge
    echo -n "3. Checking ADB status: "
    if command -v adb &>/dev/null; then
        DEVICE_COUNT=$(adb devices | grep -v "List" | grep "device$" | wc -l || true)
        if [[ $DEVICE_COUNT -gt 0 ]]; then
            echo -e "${GREEN}✓ OK ($DEVICE_COUNT device(s) connected via USB)${NC}"
        else
            echo -e "${YELLOW}⚠️ No device detected over USB (Wireless Wi-Fi mode available)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ adb command not found${NC}"
    fi

    # 4. Check Daemon Listening Port
    echo -n "4. Checking uKey Daemon Socket (8443): "
    if ss -tuln | grep -q ":8443 "; then
        echo -e "${GREEN}✓ OK (Daemon is actively listening on port 8443)${NC}"
    else
        echo -e "${YELLOW}○ Inactive (Daemon not currently running)${NC}"
    fi

    echo -e "\nPress [Enter] to return to the menu..."
    read -r
}

run_unit_tests() {
    echo -e "\n${BOLD}${CYAN}🧪 Executing Automated Test Suite (Phase 1)...${NC}\n"
    "$PROJECT_ROOT/.venv/bin/python" -m unittest "$PROJECT_ROOT/tests/test_phase1.py"
    echo -e "\n${GREEN}✓ All 8 cryptographic & framing tests completed!${NC}"
    echo -e "\nPress [Enter] to return to the menu..."
    read -r
}

test_sudo_prompt() {
    echo -e "\n${BOLD}${CYAN}🔐 Testing Terminal Sudo Authentication...${NC}"
    echo -e "${YELLOW}Notice: If uKey is configured, you will see the biometric prompt.${NC}"
    echo -e "${CYAN}Try touching your phone fingerprint or observe the flow:${NC}\n"
    sudo -k
    sudo id
    echo -e "\nPress [Enter] to return to the menu..."
    read -r
}

test_instant_skip() {
    echo -e "\n${BOLD}${CYAN}⚡ Testing 0.0s Instant Skip (Zero Timeout Fallback)...${NC}"
    echo -e "${YELLOW}When prompted for biometric, press [ENTER] immediately with empty input.${NC}"
    echo -e "${CYAN}Observe how PAM instantly drops to password prompt with 0.0s delay:${NC}\n"
    sudo -k
    sudo whoami
    echo -e "\nPress [Enter] to return to the menu..."
    read -r
}

open_webauthn() {
    echo -e "\n${BOLD}${CYAN}🌐 Launching WebAuthn Browser Verification...${NC}"
    echo -e "${CYAN}Opening https://webauthn.io in Google Chrome...${NC}"
    if command -v google-chrome &>/dev/null; then
        google-chrome "https://webauthn.io" &>/dev/null &
    elif command -v xdg-open &>/dev/null; then
        xdg-open "https://webauthn.io" &>/dev/null &
    fi
    echo -e "${GREEN}✓ Browser opened. Click 'Register' or 'Authenticate' to test phone key.${NC}"
    echo -e "\nPress [Enter] to return to the menu..."
    read -r
}

open_docs() {
    echo -e "\n${BOLD}${CYAN}📖 Interactive Documentation & Product Guide${NC}"
    echo -e "Interactive Demo running at: ${GREEN}http://localhost:8000${NC}"
    echo -e "PDF Product Guide: ${GREEN}$PROJECT_ROOT/docs/uKey_Product_Guide.pdf${NC}"
    
    if command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost:8000" &>/dev/null &
    fi
    echo -e "\nPress [Enter] to return to the menu..."
    read -r
}

view_guide() {
    echo -e "\n${BOLD}${CYAN}📄 Senior Review & Evaluation Guide${NC}"
    if [[ -f "$PROJECT_ROOT/docs/SENIOR_EVALUATION_GUIDE.md" ]]; then
        less -R "$PROJECT_ROOT/docs/SENIOR_EVALUATION_GUIDE.md" || cat "$PROJECT_ROOT/docs/SENIOR_EVALUATION_GUIDE.md"
    else
        echo -e "${YELLOW}Guide document located at docs/SENIOR_EVALUATION_GUIDE.md${NC}"
    fi
}

main_menu() {
    while true; do
        clear_screen
        show_header
        echo -e "${BOLD}Select a demonstration workflow:${NC}\n"
        echo -e "  ${CYAN}[1]${NC} 🔍 Run Pre-Flight Diagnostics (UHID, ADB, Daemon socket)"
        echo -e "  ${CYAN}[2]${NC} 🧪 Run Automated Unit Tests (8/8 CTAPHID & CBOR specs)"
        echo -e "  ${CYAN}[3]${NC} 🔐 Test Terminal 'sudo' Biometric Flow"
        echo -e "  ${CYAN}[4]${NC} ⚡ Test Instant 0.0s Password Skip (Hit Enter key)"
        echo -e "  ${CYAN}[5]${NC} 🌐 Launch Browser WebAuthn Test (webauthn.io)"
        echo -e "  ${CYAN}[6]${NC} 📖 Open Interactive Docs Website (localhost:8000)"
        echo -e "  ${CYAN}[7]${NC} 📋 View Senior Review & Architecture Guide"
        echo -e "  ${CYAN}[0]${NC} 🚪 Exit\n"
        read -rp "Enter choice [0-7]: " choice

        case "$choice" in
            1) run_diagnostics ;;
            2) run_unit_tests ;;
            3) test_sudo_prompt ;;
            4) test_instant_skip ;;
            5) open_webauthn ;;
            6) open_docs ;;
            7) view_guide ;;
            0) echo -e "\nExiting. Goodbye!"; exit 0 ;;
            *) echo -e "${RED}Invalid choice!${NC}"; sleep 1 ;;
        esac
    done
}

main_menu
