#!/usr/bin/env python3
"""
ExeGap Application Launcher
Unified entry point for all ExeGap tools
"""
import sys
import os
from pathlib import Path

def main():
    if getattr(sys, 'frozen', False):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    sys.path.insert(0, base_dir)

    try:
        import main
        cli = main.ExeGapCLI()
        sys.exit(cli.run())
    except ImportError as e:
        print(f"[!] Failed to import main module: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
