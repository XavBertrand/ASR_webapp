@echo off
chcp 65001 >nul
echo.
echo === Jetson ASR - Windows ===
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python non trouve!
    echo Installer depuis https://python.org
    pause
    exit /b 1
)

if not exist "venv" (
    echo [INFO] Creation environnement virtuel...
    python -m venv venv
)

echo [INFO] Activation environnement...
call venv\Scripts\activate.bat

cd server

echo [INFO] Installation dependances...
pip install -r requirements.txt --quiet

if not exist "recordings" mkdir recordings

echo.
echo ========================================
echo Serveur pret!
echo ========================================
echo Local:  http://localhost:8000
echo ========================================
echo.

python app.py
pause