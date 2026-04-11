#!/usr/bin/env bash
# Unofficial Bash Strict Mode
set -euo pipefail

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}=======================================${NC}"
echo -e "${CYAN}   Installing check-log CLI Tool...    ${NC}"
echo -e "${CYAN}=======================================${NC}"

# 1. Check if pipx is installed
if ! command -v pipx &> /dev/null; then
    echo -e "${RED}[!] Error: 'pipx' is not installed.${NC}"
    echo -e "We use pipx to install Python CLI tools safely in isolated environments."
    echo -e "Please install it first:"
    echo -e "  Ubuntu/Debian: ${YELLOW}sudo apt install pipx${NC}"
    echo -e "  macOS:         ${YELLOW}brew install pipx${NC}"
    echo -e "  Arch Linux:    ${YELLOW}sudo pacman -S pipx${NC}"
    exit 1
fi

# 2. Find the directory of this script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

# 3. Install the package
echo -e "${CYAN}[*] Building and isolating package via pipx...${NC}"
if pipx install --force "$SCRIPT_DIR"; then
    echo -e "${GREEN}[+] Successfully installed 'check-log'!${NC}"
else
    echo -e "${RED}[!] Installation failed.${NC}"
    exit 1
fi

# 4. PATH Detection (pipx ensurepath is safer than manually editing rc files)
echo -e "${CYAN}[*] Ensuring ~/.local/bin is in your PATH...${NC}"
pipx ensurepath &> /dev/null

echo -e "\n${GREEN}=======================================${NC}"
echo -e "${GREEN}        INSTALLATION COMPLETE!         ${NC}"
echo -e "${GREEN}=======================================${NC}"
echo -e "\nIf this is your first time installing a pipx tool, you may need to restart your terminal."
echo -e "Run: ${YELLOW}source ~/.bashrc${NC} (or ~/.zshrc)"
echo -e "\nTest the installation by running:"
echo -e "  ${CYAN}check-log --help${NC}\n"