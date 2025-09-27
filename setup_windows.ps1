# Setup script for Jetson ASR on Windows
# Encoding: UTF-8

Write-Host "=== Installation Jetson ASR pour Windows ===" -ForegroundColor Green

# Function to check admin privileges
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check Python
Write-Host "`n[1] Verification de Python..." -ForegroundColor Cyan
try {
    $pythonVersion = python --version 2>$null
    Write-Host "[OK] Python detecte: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Python non trouve!" -ForegroundColor Red
    Write-Host "Telecharger Python: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "IMPORTANT: Cochez 'Add Python to PATH' lors de l'installation!" -ForegroundColor Red

    $response = Read-Host "Ouvrir le site de telechargement? (o/N)"
    if ($response -eq "o" -or $response -eq "O") {
        Start-Process "https://www.python.org/downloads/"
    }
    exit 1
}

# Check pip
Write-Host "`n[2] Verification de pip..." -ForegroundColor Cyan
try {
    $pipVersion = pip --version 2>$null
    Write-Host "[OK] pip detecte: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] pip non trouve! Reinstaller Python avec pip inclus" -ForegroundColor Red
    exit 1
}

# Check Git
Write-Host "`n[3] Verification de Git..." -ForegroundColor Cyan
try {
    $gitVersion = git --version 2>$null
    Write-Host "[OK] Git detecte: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "[INFO] Git non trouve (optionnel)" -ForegroundColor Yellow
    Write-Host "Telecharger Git: https://git-scm.com/download/win" -ForegroundColor Cyan
}

# Check ffmpeg
Write-Host "`n[4] Verification de ffmpeg..." -ForegroundColor Cyan
try {
    $ffmpegTest = ffmpeg -version 2>$null
    if ($ffmpegTest) {
        Write-Host "[OK] ffmpeg detecte et fonctionnel!" -ForegroundColor Green
    } else {
        throw "ffmpeg non accessible"
    }
} catch {
    Write-Host "[INFO] ffmpeg non installe" -ForegroundColor Yellow
    Write-Host "Options d'installation:" -ForegroundColor Cyan
    Write-Host "1. Via Chocolatey (automatique)" -ForegroundColor White
    Write-Host "2. Manuel depuis https://ffmpeg.org/download.html" -ForegroundColor White

    $installMethod = Read-Host "Installer ffmpeg via Chocolatey? (o/N)"
    if ($installMethod -eq "o" -or $installMethod -eq "O") {
        # Check Chocolatey
        try {
            $chocoVersion = choco --version 2>$null
            Write-Host "[OK] Chocolatey detecte: $chocoVersion" -ForegroundColor Green

            if (Test-Admin) {
                Write-Host "Installation de ffmpeg via Chocolatey..." -ForegroundColor Cyan
                choco install ffmpeg -y
                Write-Host "[OK] ffmpeg installe!" -ForegroundColor Green
            } else {
                Write-Host "[ATTENTION] Privileges administrateur requis" -ForegroundColor Yellow
                Write-Host "Relancer PowerShell en tant qu'administrateur" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "[INFO] Chocolatey non installe" -ForegroundColor Yellow
            if (Test-Admin) {
                $installChoco = Read-Host "Installer Chocolatey d'abord? (o/N)"
                if ($installChoco -eq "o" -or $installChoco -eq "O") {
                    Write-Host "Installation de Chocolatey..." -ForegroundColor Cyan
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = 3072
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

                    Write-Host "Installation de ffmpeg..." -ForegroundColor Cyan
                    choco install ffmpeg -y
                }
            } else {
                Write-Host "[ATTENTION] Privileges administrateur requis pour Chocolatey" -ForegroundColor Red
            }
        }
    }
}

# Check PowerShell execution policy
Write-Host "`n[5] Verification politique PowerShell..." -ForegroundColor Cyan
$policy = Get-ExecutionPolicy
if ($policy -eq "Restricted") {
    Write-Host "[ATTENTION] Politique d'execution restrictive" -ForegroundColor Yellow
    Write-Host "Pour permettre l'execution des scripts:" -ForegroundColor Cyan
    Write-Host "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor White

    $changePolicy = Read-Host "Changer la politique maintenant? (o/N)"
    if ($changePolicy -eq "o" -or $changePolicy -eq "O") {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Host "[OK] Politique mise a jour!" -ForegroundColor Green
    }
} else {
    Write-Host "[OK] Politique PowerShell: $policy" -ForegroundColor Green
}

# Final summary
Write-Host "`n=== Installation terminee ===" -ForegroundColor Green
Write-Host "Pour lancer l'application:" -ForegroundColor White
Write-Host "  PowerShell: .\run.ps1" -ForegroundColor Green
Write-Host "  Batch:      .\run.bat" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Read-Host "Appuyer sur Entree pour continuer"