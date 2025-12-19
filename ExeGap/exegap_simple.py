#!/usr/bin/env python3
"""
ExeGap Wrapper - Direct entry point
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from main import ExeGapCLI
    cli = ExeGapCLI()
    sys.exit(cli.run())
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
