# Build Guide

Compile ExeGap to a standalone .exe file.

## Quick Build

```bash
# 1. Make sure you have Python 3.8+
python --version

# 2. Build
python build_exe.py

# 3. Done - ExeGap.exe is ready
.\ExeGap.exe --help
```

That's it. The build script handles everything:
- Installs dependencies
- Packages all files
- Creates a standalone executable (~150-200MB)
- Cleans up temporary files

## After Building

You'll have:
- `ExeGap.exe` - Ready to use standalone executable
- `dist/ExeGap/` - Full packaged version with all files
- Original source files remain unchanged

## Test It

```bash
# Show help
ExeGap.exe --help

# Launch GUI
ExeGap.exe gui

# Try analyzing a file
ExeGap.exe analyze sample.exe
```

## Deployment

### Option 1: Just the .exe
Copy `ExeGap.exe` to any Windows PC. No installation needed.

### Option 2: Full Package
Copy entire `dist/ExeGap` folder. Includes everything in one place.

### Option 3: Share with Others
- Standalone `ExeGap.exe` is portable
- No Python installation required on target machine
- Just send the .exe file

## Troubleshooting

**"PyInstaller not found"**
```bash
pip install PyInstaller
```

**"Missing module" error**
```bash
pip install -r requirements.txt --force-reinstall
```

**Build is slow**
```bash
# Try without compression
python build_exe.py
```

**Executable is huge**
This is normal - it includes Python + all libraries. You can reduce size by:
- Using only needed features in config
- Removing unused modules (advanced users)

## System Requirements

- Windows 7 or later
- Python 3.8+ (for building; not needed for the .exe)
- 1GB disk space for build process
- 150-200MB disk space for final .exe

## What's Included in the .exe

- Python 3.8+ runtime
- All required libraries (PyQt5, pefile, capstone, Flask, etc.)
- Configuration system
- GUI framework
- All analysis modules

The .exe is completely self-contained and doesn't need Python installed on the target machine.