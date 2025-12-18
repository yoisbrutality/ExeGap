#!/bin/bash

clear

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                      EXEGAP 3.0.0 INSTALLER                      ║"
echo "║           Advanced PE Binary Analysis & Decompilation Suite      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

echo "[*] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[!] ERROR: Python3 not found!"
    echo ""
    echo "Please install Python 3.8 or later"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "[+] $PYTHON_VERSION"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo ""
echo "[*] Installing dependencies..."
python3 -m pip install -r requirements.txt --upgrade
if [ $? -ne 0 ]; then
    echo "[!] Failed to install dependencies"
    exit 1
fi

echo "[+] Dependencies installed successfully!"

echo ""
echo "[*] Building ExeGap executable..."
echo "    This may take 2-5 minutes..."
echo ""

python3 build_exe.py
if [ $? -ne 0 ]; then
    echo "[!] Build failed!"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    BUILD SUCCESSFUL!                             ║"
echo "║                                                                  ║"
echo "║  ExeGap has been built and is ready to use!                     ║"
echo "║                                                                  ║"
echo "║  Quick Start:                                                    ║"
echo "║    python exegap.py --help        Show all commands             ║"
echo "║    python exegap.py gui           Launch GUI application        ║"
echo "║    python exegap.py analyze file  Analyze binary               ║"
echo "║    python exegap.py dashboard     Start web dashboard          ║"
echo "║                                                                  ║"
echo "║  Documentation:                                                  ║"
echo "║    README.md       - Overview and quick start                   ║"
echo "║    USAGE.md        - Comprehensive usage guide                  ║"
echo "║    BUILD_GUIDE.md  - Build and deployment info                 ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

echo ""
echo "[+] Installation complete!"