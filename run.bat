@echo off
setlocal enabledelayedexpansion

echo.
echo ========================================
echo 🚀 Jetson ASR - Lancement Windows
echo ========================================
echo.

REM Vérifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python non trouvé!
    echo    Installez Python depuis https://python.org
    echo    Assurez-vous de cocher 'Add to PATH'
    pause
    exit /b 1
)

echo ✅ Python détecté

REM Créer environnement virtuel si nécessaire
if not exist "venv" (
    echo 📦 Création de l'environnement virtuel...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ Erreur création environnement virtuel
        pause
        exit /b 1
    )
)

REM Activer environnement virtuel
echo 🔧 Activation environnement virtuel...
call venv\Scripts\activate.bat

REM Aller dans le dossier server
cd server

REM Installer dépendances
echo ⬇️ Installation des dépendances...
pip install -r requirements.txt
if errorlevel 1 (
    echo ❌ Erreur installation dépendances
    pause
    exit /b 1
)

REM Créer dossier recordings
if not exist "recordings" (
    mkdir recordings
    echo 📁 Dossier recordings créé
)

REM Obtenir l'IP locale (approximatif)
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    set "ip=%%a"
    set "ip=!ip: =!"
    if not "!ip!"=="127.0.0.1" (
        set "localIP=!ip!"
        goto :found
    )
)
:found

echo.
echo ==========================================
echo 🌟 Serveur prêt à démarrer!
echo ==========================================
echo 🖥️  Local:      http://localhost:8000
if defined localIP echo 📱 Mobile:     http://!localIP!:8000
echo 🏥 Health:     http://localhost:8000/health
echo ==========================================
echo.
echo 🎤 Ctrl+C pour arrêter le serveur
echo.

REM Démarrer serveur
python app.py

pause