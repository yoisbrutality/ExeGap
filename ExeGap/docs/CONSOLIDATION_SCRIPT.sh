#!/bin/bash

echo "ExeGap Legacy Script Cleanup"
echo "============================"
echo ""
echo "This will remove the following legacy Python scripts:"
echo "  - api_hook_detector.py -> integrated into src/core/security_analyzer.py"
echo "  - cli.py -> merged into main.py"
echo "  - config_extractor.py -> consolidated as src/core/config_extractor.py"  
echo "  - dashboard.py -> web interface still available"
echo "  - decompiler_suite.py -> functionality in core modules"
echo "  - dotnet_analyzer.py -> src/core/dotnet_handler.py"
echo "  - extractor.py -> integrated into src/core/file_carver.py"
echo "  - windows_integration.py -> src/utils/windows_integration.py"
echo "  - examples.py -> documentation and examples/"
echo ""

mkdir -p _legacy_backup
echo "Backing up legacy scripts..."
for file in api_hook_detector.py cli.py config_extractor.py dashboard.py decompiler_suite.py dotnet_analyzer.py extractor.py examples.py windows_integration.py; do
    if [ -f "$file" ]; then
        cp "$file" "_legacy_backup/"
        echo "  Backed up: $file"
    fi
done

echo ""
echo "Backup created in _legacy_backup/ directory"
echo "Legacy scripts have been consolidated into the new modular structure."
echo ""
echo "New structure:"
echo "  src/core/              - Core analysis modules"
echo "  src/gui/               - PyQt5 GUI application"
echo "  src/utils/             - Utilities and helpers"
echo "  src/web/               - Web dashboard"
echo "  main.py               - Unified CLI interface"
echo "  build_exe.py          - Build system"
echo ""
echo "To use ExeGap:"
echo "  python main.py --help"
echo ""