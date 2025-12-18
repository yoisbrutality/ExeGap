# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Specification for ExeGap
Creates professional standalone executable
"""

block_cipher = None

a = Analysis(
    ['exegap.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'pefile',
        'capstone',
        'flask',
        'requests',
        'jinja2',
        'werkzeug',
        'PyQt5',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

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
    icon='build/exegap.ico',
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

