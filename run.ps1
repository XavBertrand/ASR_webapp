# Launcher script for Jetson ASR on Windows
# Simple version without emojis

param(
    [switch]$Clean = $false
)

Write-Host "=== Jetson ASR - Lancement Windows ===" -ForegroundColor Green

# Check Python
try {
    $pythonVersion = python --version 2>$null
    Write-Host "[OK] Python detecte: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Python non trouve!" -ForegroundColor Red
    Write-Host "Installer Python depuis https://python.org" -ForegroundColor Yellow
    Read-Host "Appuyer sur Entree pour quitter"
    exit 1
}

# Clean virtual environment if requested
if ($Clean -and (Test-Path "venv")) {
    Write-Host "[INFO] Suppression environnement virtuel existant..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force venv
}

# Create virtual environment if needed
if (-not (Test-Path "venv")) {
    Write-Host "[INFO] Creation environnement virtuel..." -ForegroundColor Cyan
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERREUR] Echec creation environnement virtuel" -ForegroundColor Red
        Read-Host "Appuyer sur Entree pour quitter"
        exit 1
    }
}

# Activate virtual environment
Write-Host "[INFO] Activation environnement virtuel..." -ForegroundColor Cyan
& "venv\Scripts\Activate.ps1"

if (-not $env:VIRTUAL_ENV) {
    Write-Host "[ERREUR] Echec activation environnement virtuel" -ForegroundColor Red
    Read-Host "Appuyer sur Entree pour quitter"
    exit 1
}

# Move to server directory
if (Test-Path "server") {
    Set-Location server
} else {
    Write-Host "[ERREUR] Dossier 'server' non trouve!" -ForegroundColor Red
    Read-Host "Appuyer sur Entree pour quitter"
    exit 1
}

# Upgrade pip
Write-Host "[INFO] Mise a jour pip..." -ForegroundColor Cyan
python -m pip install --upgrade pip --quiet

# Install dependencies
Write-Host "[INFO] Installation dependances..." -ForegroundColor Cyan
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERREUR] Echec installation dependances" -ForegroundColor Red
        Read-Host "Appuyer sur Entree pour quitter"
        exit 1
    }
} else {
    Write-Host "[ATTENTION] Fichier requirements.txt non trouve" -ForegroundColor Yellow
}

# Create recordings directory
if (-not (Test-Path "recordings")) {
    New-Item -ItemType Directory -Name "recordings" | Out-Null
    Write-Host "[OK] Dossier recordings cree" -ForegroundColor Green
}

# Get local IP
$localIP = "Non detecte"
try {
    $networkAdapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -ne "127.0.0.1" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.PrefixOrigin -eq "Dhcp"
    }
    if ($networkAdapters) {
        $localIP = $networkAdapters[0].IPAddress
    }
} catch {
    Write-Host "[INFO] Detection IP automatique echouee" -ForegroundColor Yellow
}

# Display connection info
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Serveur pret a demarrer!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Local:      http://localhost:8000" -ForegroundColor White
Write-Host "Mobile:     http://$localIP:8000" -ForegroundColor White
Write-Host "Health:     http://localhost:8000/health" -ForegroundColor White
Write-Host "Dossier:    $(Get-Location)\recordings" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nCtrl+C pour arreter le serveur`n" -ForegroundColor Yellow

# Start server
if (Test-Path "app.py") {
    python app.py
} else {
    Write-Host "[ERREUR] Fichier app.py non trouve!" -ForegroundColor Red
    Read-Host "Appuyer sur Entree pour quitter"
    exit 1
}