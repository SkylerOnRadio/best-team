Write-Host "Installing Logs Checker (check-log) for Windows..." -ForegroundColor Cyan

# 1. Check if Python is installed
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python not found. Please install Python from python.org first." -ForegroundColor Red
    exit
}

# 2. Install/Upgrade pipx
Write-Host "Ensuring pipx is installed..." -ForegroundColor Gray
python -m pip install --user pipx --upgrade

# 3. Force-refresh the PATH for the current session
# This prevents the "pipx.exe not found" error without needing a restart mid-script
$env:PATH += ";$env:USERPROFILE\.local\bin"
python -m pipx ensurepath

# 4. Install the tool
Write-Host "Installing Logs Checker..." -ForegroundColor Gray
# Using 'python -m pipx' is safer than calling the .exe directly if the path is fresh
python -m pipx install . --force

# 5. Create the reports folder structure
$ReportPath = Join-Path $HOME "Documents\Forensic_Reports"
$Folders = "html", "csv", "json"

foreach ($f in $Folders) {
    $Path = Join-Path $ReportPath $f
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
        Write-Host "Created folder: $Path" -ForegroundColor DarkGray
    }
}

Write-Host "--------------------------------------------------------" -ForegroundColor White
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host "🚀 IMPORTANT: Please CLOSE and REOPEN your terminal." -ForegroundColor Yellow
Write-Host "Then try typing: check-log --help" -ForegroundColor Cyan