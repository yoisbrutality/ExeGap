#!/bin/bash

clear

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                      EXEGAP 3.0.1 INSTALLER                      ║"
echo "║           Advanced PE Binary Analysis & Decompilation Suite      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

echo "[*] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[!] ERROR: Python3 not found!"
    echo ""
    echo "    Please install Python 3.8 or later:"
    echo "    - Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "    - Fedora:        sudo dnf install python3 python3-pip"
    echo "    - macOS (brew):  brew install python"
    echo ""
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>/dev/null || echo "Unknown")
echo "[+] $PYTHON_VERSION detected"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SCRIPT_DIR" || { echo "[!] Failed to change to script directory"; exit 1; }

echo ""
echo "[*] Upgrading pip..."
python3 -m pip install --upgrade pip >/dev/null 2>&1

echo "[*] Installing dependencies from requirements.txt..."
python3 -m pip install -r requirements.txt --upgrade

if [ $? -ne 0 ]; then
    echo "[!] Failed to install dependencies"
    echo "    Tip: Try running with '--user' flag or in a virtual environment"
    exit 1
fi

echo "[+] Dependencies installed successfully!"

echo ""
echo "[*] Building standalone executable (PyInstaller)..."
echo "    This may take 2-5 minutes depending on your system..."
echo ""

python3 build_exe.py

if [ $? -ne 0 ]; then
    echo "[!] Build failed!"
    echo "    Check if PyInstaller is installed: pip install pyinstaller"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    INSTALLATION & BUILD SUCCESSFUL!              ║"
echo "║                                                                  ║"
echo "║  ExeGap has been built and is ready to use!                      ║"
echo "║                                                                  ║"
echo "║  Quick Start Commands:                                           ║"
echo "║    ./ExeGap          # Run CLI (if executable has permissions)   ║"
echo "║    python exegap.py gui           Launch GUI application         ║"
echo "║    python exegap.py analyze file  Analyze binary                 ║"
echo "║    python exegap.py dashboard     Start web dashboard            ║"
echo "║                                                                  ║"
echo "║  Documentation:                                                  ║"
echo "║    README.md       - Project overview and quick start            ║"
echo "║    USAGE.md        - Detailed command reference                  ║"
echo "║    BUILD_GUIDE.md  - Advanced build and deployment info          ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "[+] Installation complete!"
echo "[*] Tip: To run the built binary directly, use: chmod +x ExeGap && ./ExeGap"
echo ""
