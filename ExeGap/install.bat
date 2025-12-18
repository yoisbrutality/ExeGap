@echo off

cls
echo.
echo ╔══════════════════════════════════════════════════════════════════╗
echo ║                      EXEGAP 3.0.0 INSTALLER                      ║
echo ║           Advanced PE Binary Analysis & Decompilation Suite      ║
echo ╚══════════════════════════════════════════════════════════════════╝
echo.

echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Python not found!
    echo.
    echo Please install Python 3.8 or later from: https://www.python.org
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo [+] %PYTHON_VERSION%

cd /d "%~dp0"

echo.
echo [*] Installing dependencies...
python -m pip install -r requirements.txt --upgrade
if %errorlevel% neq 0 (
    echo [!] Failed to install dependencies
    pause
    exit /b 1
)

echo [+] Dependencies installed successfully!

echo.
echo [*] Building ExeGap executable...
echo    This may take 2-5 minutes...
echo.

python build_exe.py
if %errorlevel% neq 0 (
    echo [!] Build failed!
    pause
    exit /b 1
)

echo.
echo ╔══════════════════════════════════════════════════════════════════╗
echo ║                    BUILD SUCCESSFUL!                             ║
echo ║                                                                  ║
echo ║  ExeGap.exe has been created and is ready to use!               ║
echo ║                                                                  ║
echo ║  Quick Start:                                                    ║
echo ║    ExeGap.exe --help              Show all commands             ║
echo ║    ExeGap.exe gui                 Launch GUI application        ║
echo ║    ExeGap.exe analyze file.exe    Analyze binary               ║
echo ║    ExeGap.exe dashboard           Start web dashboard          ║
echo ║                                                                  ║
echo ║  Documentation:                                                  ║
echo ║    README.md       - Overview and quick start                   ║
echo ║    USAGE.md        - Comprehensive usage guide                  ║
echo ║    BUILD_GUIDE.md  - Build and deployment info                 ║
echo ║                                                                  ║
echo ╚══════════════════════════════════════════════════════════════════╝

echo.
echo [+] Installation complete!
echo [*] You can now run: ExeGap.exe

pause
exit /b 0