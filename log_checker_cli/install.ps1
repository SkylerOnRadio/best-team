# Stop execution immediately if any command fails
$ErrorActionPreference = "Stop"

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "   Installing check-log CLI Tool...    " -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan

# 1. Check if Python is installed
Write-Host "[*] Verifying Python installation..." -ForegroundColor Cyan
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Error: Python is not installed or not in your PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.8+ from https://python.org"
    Write-Host "IMPORTANT: Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

# 2. Install/Upgrade pipx
Write-Host "[*] Ensuring pipx is installed..." -ForegroundColor Cyan
if (!(Get-Command pipx -ErrorAction SilentlyContinue)) {
    Write-Host "    pipx not found in PATH. Installing via pip..." -ForegroundColor DarkGray
    python -m pip install --user pipx --upgrade | Out-Null
    
    # Add common Python paths to the current session so pipx works immediately
    $env:PATH += ";$env:USERPROFILE\.local\bin;$env:APPDATA\Python\Scripts"
    
    # Ensure it's permanently in the PATH for future sessions
    python -m pipx ensurepath | Out-Null
} else {
    Write-Host "    pipx is already installed." -ForegroundColor DarkGray
}

# 3. Find the directory of this script (so it installs correctly from anywhere)
$ScriptDir = $PSScriptRoot
# Fallback in case the script is dot-sourced
if ([string]::IsNullOrEmpty($ScriptDir)) { $ScriptDir = (Get-Location).Path }

# 4. Install the package securely via pipx
Write-Host "[*] Building and isolating package via pipx..." -ForegroundColor Cyan
try {
    # Using 'python -m pipx' instead of just 'pipx' handles edge cases where the PATH hasn't refreshed
    python -m pipx install --force "$ScriptDir"
    Write-Host "[+] Successfully installed 'check-log'!" -ForegroundColor Green
} catch {
    Write-Host "[!] Installation failed. Please check the error output above." -ForegroundColor Red
    exit 1
}

# 5. Outro & Instructions
Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "        INSTALLATION COMPLETE!         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 IMPORTANT: You must CLOSE and REOPEN your terminal for PATH changes to apply." -ForegroundColor Yellow
Write-Host "After restarting, test the installation by running:"
Write-Host "  check-log --help" -ForegroundColor Cyan
Write-Host ""