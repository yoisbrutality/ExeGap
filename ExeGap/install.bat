@echo off
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════╗
echo ║                      EXEGAP 3.0.1 INSTALLER                      ║
echo ║           Advanced PE Binary Analysis & Decompilation Suite      ║
echo ╚══════════════════════════════════════════════════════════════════╝
echo.

echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Python not found in PATH!
    echo.
    echo     Please install Python 3.8 or later from:
    echo     https://www.python.org/downloads/
    echo.
    echo     IMPORTANT: During installation, check "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [+] Python %PYTHON_VERSION% detected

cd /d "%~dp0"

echo.
echo [*] Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1

echo [*] Installing dependencies...
python -m pip install -r requirements.txt --upgrade
if %errorlevel% neq 0 (
    echo [!] Failed to install dependencies
    echo     Try running as Administrator or check your internet connection
    pause
    exit /b 1
)

echo [+] Dependencies installed successfully!

echo.
echo [*] Building standalone executable (PyInstaller)...
echo     This may take 2-5 minutes...
echo.

python build_exe.py
if %errorlevel% neq 0 (
    echo [!] Build failed!
    echo     Make sure PyInstaller is installed: pip install pyinstaller
    pause
    exit /b 1
)

echo.
echo ╔══════════════════════════════════════════════════════════════════╗
echo ║                    INSTALLATION & BUILD SUCCESSFUL!              ║
echo ║                                                                  ║
echo ║  ExeGap.exe has been created in this folder!                     ║
echo ║                                                                  ║
echo ║  Quick Start:                                                    ║
echo ║    ExeGap.exe --help              Show all commands              ║
echo ║    ExeGap.exe gui                 Launch GUI application         ║
echo ║    ExeGap.exe analyze file.exe    Analyze binary                 ║
echo ║    ExeGap.exe dashboard           Start web dashboard            ║
echo ║                                                                  ║
echo ║  Documentation:                                                  ║
echo ║    README.md       - Project overview and quick start            ║
echo ║    USAGE.md        - Detailed command reference                  ║
echo ║    BUILD_GUIDE.md  - Advanced build and deployment info          ║
echo ║                                                                  ║
echo ╚══════════════════════════════════════════════════════════════════╝

echo.
echo [+] Installation complete!
echo [*] You can now double-click ExeGap.exe or run it from Command Prompt

pause
exit /b 0
