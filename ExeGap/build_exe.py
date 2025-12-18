#!/usr/bin/env python3
"""
ExeGap Installation and Build Script
Installs dependencies and builds the executable
"""
import subprocess
import sys
import os
import shutil
import platform

def run_command(cmd, description=""):
    if description:
        print(f"\n[*] {description}...")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=False)
        return result.returncode == 0
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def main():
    print("""
    ╔═════════════════════════════════════════════════════════════════╗
    ║           EXEGAP 3.0.0 - Installation & Build Script           ║
    ║      Advanced PE Binary Analysis & Decompilation Suite         ║
    ╚═════════════════════════════════════════════════════════════════╝
    """)
    
    python_exe = sys.executable
    print(f"[+] Python detected: {python_exe}")
    print(f"[+] Python version: {sys.version}")
    print(f"[+] Platform: {platform.platform()}")

    if not run_command(f'"{python_exe}" -m pip install -r requirements.txt', "Installing packages"):
        print("[!] Failed to install dependencies")
        sys.exit(1)
    
    print("[+] Dependencies installed successfully!")

    print("\n[*] Building standalone executable...")
    de: python ; coding: utf-8 -*-
import sys
from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ['exegap.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config', 'config'),
        ('data', 'data'),
        ('src', 'src'),
    ],
    hiddenimports=[
        'pefile',
        'capstone',
        'flask',
        'jinja2',
        'werkzeug',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ExeGap',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ExeGap'
)
'''
    
    spec_file = 'ExeGap.spec'
    with open(spec_file, 'w') as f:
        f.write(spec_content)
    
    print(f"[+] Created spec file: {spec_file}")
    
    # Run PyInstaller
    cmd = f'"{python_exe}" -m PyInstaller {spec_file} --distpath dist --buildpath build_temp'
        print("[!] PyInstaller build failed")
        sys.exit(1)
    
    # Move executable to appropriate location
    exe_path = "dist/ExeGap/ExeGap.exe"
    final_exe = "ExeGap.exe"
    if os.path.exists(exe_path):
        shutil.copy(exe_path, final_exe)
        print(f"\n[+] Executable created: {final_exe}")
        print(f"[+] Full path: {os.path.abspath(final_exe)}")
    else:
        print("[!] Executable not found at expected location")
        print(f"[*] Looking in dist directory...")
        exe_files = []
        for root, dirs, files in os.walk("dist"):
            for file in files:
                if file.endswith(".exe"):
                    exe_files.append(os.path.join(root, file))
        
        if exe_files:
            print(f"[+] Found executables: {exe_files}")
            shutil.copy(exe_files[0], final_exe)
            print(f"[+] Copied to: {final_exe}")
    
    # Cleanup
    for temp_dir in ["build_temp", ".pyinstaller"]:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    
    print("""
    ╔═════════════════════════════════════════════════════════════════╗
    ║                   BUILD COMPLETE!                               ║
    ║                                                                  ║
    ║  ExeGap.exe has been successfully created!                      ║
    ║                                                                  ║
    ║  Usage:                                                          ║
    ║    ExeGap.exe analyze <file>                                    ║
    ║    ExeGap.exe gui                                               ║
    ║    ExeGap.exe dashboard                                         ║
    ║    ExeGap.exe batch <directory>                                 ║
    ║                                                                  ║
    ║  Documentation: README.md, USAGE.md                             ║
    ╚═════════════════════════════════════════════════════════════════╝
    """)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())