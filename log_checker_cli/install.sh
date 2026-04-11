#!/bin/bash

echo "Installing Logs Checker (check-log)..."

# 1. Install the package locally for the user
pipx install --force .

# 2. Automatically detect the shell and add to PATH if missing
SHELL_CONFIG=""
case $SHELL in
    */zsh)  SHELL_CONFIG="$HOME/.zshrc" ;;
    */bash) SHELL_CONFIG="$HOME/.bashrc" ;;
    *)      SHELL_CONFIG="$HOME/.profile" ;; # Fallback for others
esac

if [ -f "$SHELL_CONFIG" ]; then
    if ! grep -q ".local/bin" "$SHELL_CONFIG"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_CONFIG"
        echo "Added ~/.local/bin to your PATH in $SHELL_CONFIG"
    fi
fi

# 3. Create the reports folder relative to the script location
# This cross-platform way works on both Linux and macOS
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
mkdir -p "$SCRIPT_DIR/src/evidence_protector/reports/html"
mkdir -p "$SCRIPT_DIR/src/evidence_protector/reports/csv"
mkdir -p "$SCRIPT_DIR/src/evidence_protector/reports/json"

echo "--------------------------------------------------------"
echo "Installation complete!"
echo "IMPORTANT: Restart your terminal OR run: source $SHELL_CONFIG"
echo "Then try typing: check-log --help"