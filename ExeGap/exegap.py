#!/usr/bin/env python3
"""
ExeGap Application Launcher
Unified entry point for all ExeGap tools
"""
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    from main import ExeGapCLI
    
    cli = ExeGapCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()