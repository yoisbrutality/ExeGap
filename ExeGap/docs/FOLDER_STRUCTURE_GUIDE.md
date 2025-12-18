# ExeGap Folder Structure Guide

## Root Folder Organization

The ExeGap project has been reorganized into a clean, professional structure for better maintainability.

### Current Root Structure

```
ExeGap/
├── README.md                 ← Start here for overview
├── main.py                   ← Main entry point
├── requirements.txt          ← Python dependencies
├── build_exe.py              ← Build to executable
├── exegap.py                 ← Alternative entry point
├── install.bat               ← Windows installer
├── install.sh                ← Linux installer
│
├── src/                      ← Source code
│   ├── core/                 ← Analysis engines (pe_analyzer, security_analyzer, file_carver, etc.)
│   ├── gui/                  ← PyQt5 desktop GUI
│   ├── utils/                ← Utilities and helpers
│   └── web/                  ← Flask web dashboard
│
├── config/                   ← Configuration files
│   └── exegap.json           ← Main configuration
│
├── data/                     ← Sample data and resources
│   └── [sample files]
│
├── build/                    ← Build automation
│   └── build.spec            ← PyInstaller specification
│
├── docs/                     ← Documentation & Guides ⭐
│   ├── README.md             ← Project overview
│   ├── QUICK_REFERENCE.md    ← Command cheat sheet
│   ├── BUILD_GUIDE.md        ← Compilation guide
│   ├── QUICKSTART_GUIDE.md   ← Setup instructions
│   ├── CONSOLIDATION_REPORT.md  ← Technical details
│   ├── PROJECT_COMPLETION_STATUS.md  ← Feature inventory
│   ├── VERIFICATION_CHECKLIST.md  ← Status verification
│   └── [other guides]
│
├── examples/                 ← Usage examples (coming soon)
│   └── [example scripts]
│
├── _legacy/                  ← Archived legacy scripts
│   ├── api_hook_detector.py  ← Archived (in security_analyzer.py)
│   ├── cli.py                ← Archived (in main.py)
│   ├── config_extractor.py   ← Archived (new module in src/core/)
│   ├── dashboard.py          ← Archived (in src/web/)
│   ├── decompiler_suite.py   ← Archived (distributed in core modules)
│   ├── dotnet_analyzer.py    ← Archived (in dotnet_handler.py)
│   ├── extractor.py          ← Archived (in file_carver.py)
│   ├── examples.py           ← Archived
│   └── windows_integration.py  ← Archived (new module in src/utils/)
│
└── scripts/                  ← Helper scripts
    └── [utility scripts]
```

## Folder Purposes

### 📁 Root Folder
**Purpose**: Quick access to main entry points and configuration

**Contains**:
- `main.py` - Unified CLI interface (RUN THIS)
- `build_exe.py` - Build automation
- `requirements.txt` - Dependencies
- `README.md` - Project overview

**Use**: Start here! `python main.py --help`

---

### 📁 src/
**Purpose**: All source code organized by function

**Subfolders**:

#### src/core/
- **pe_analyzer.py** - PE binary structure analysis
- **security_analyzer.py** - Threat detection, API hooks
- **file_carver.py** - Embedded file extraction
- **dotnet_handler.py** - .NET assembly analysis
- **config_extractor.py** - Secret extraction

#### src/gui/
- **gui_application.py** - PyQt5 desktop interface

#### src/utils/
- **__init__.py** - Config, reports, logging
- **windows_integration.py** - Windows metadata, signatures

#### src/web/
- **dashboard.py** - Flask web dashboard

---

### 📁 docs/
**Purpose**: All documentation and guides

**Contains**:
- **README.md** - Project overview
- **QUICK_REFERENCE.md** - Command cheat sheet
- **BUILD_GUIDE.md** - Compilation instructions
- **QUICKSTART_GUIDE.md** - Setup and getting started
- **CONSOLIDATION_REPORT.md** - Technical consolidation details
- **PROJECT_COMPLETION_STATUS.md** - Feature inventory
- **VERIFICATION_CHECKLIST.md** - Status verification

**Use**: `docs/QUICK_REFERENCE.md` for common commands

---

### 📁 config/
**Purpose**: Configuration files

**Contains**:
- `exegap.json` - Main configuration file

**Use**: Define default settings, paths, credentials

---

### 📁 data/
**Purpose**: Sample data and test resources

**Contains**:
- Sample PE files
- Test data
- Resources

**Use**: Testing and demonstration

---

### 📁 build/
**Purpose**: Build automation files

**Contains**:
- `build.spec` - PyInstaller specification file

**Use**: Used by `build_exe.py` to create standalone executable

---

### 📁 examples/
**Purpose**: Usage examples (currently empty, planned)

**Will Contain**:
- Python script examples
- Analysis workflows
- Integration examples

**Use**: Reference for how to use ExeGap programmatically

---

### 📁 _legacy/
**Purpose**: Archived original scripts (reference only)

**Contains**:
- All original root-level Python scripts
- Now integrated into src/ modules

**Use**: Historical reference
**Note**: Do NOT modify or run these directly

**Archived Scripts**:
- `api_hook_detector.py` → Now: `src/core/security_analyzer.py`
- `cli.py` → Now: `main.py`
- `config_extractor.py` → Now: `src/core/config_extractor.py`
- `dashboard.py` → Now: `src/web/dashboard.py`
- `decompiler_suite.py` → Now: Distributed across core modules
- `dotnet_analyzer.py` → Now: `src/core/dotnet_handler.py`
- `extractor.py` → Now: `src/core/file_carver.py`
- `examples.py` → Now: Reference/documentation
- `windows_integration.py` → Now: `src/utils/windows_integration.py`

---

### 📁 scripts/
**Purpose**: Helper and utility scripts

**Will Contain**:
- Installation helpers
- Maintenance scripts
- Deployment tools

**Use**: Build and deployment automation

---

## Import Structure

### Code Organization

All imports now reference the organized structure:

```python
from src.core import PEAnalyzer, SecurityAnalyzer, FileCarver
from src.utils import ConfigManager, ReportGenerator
from src.core import ConfigExtractor

from .config_extractor import ConfigExtractor
from .security_analyzer import SecurityAnalyzer
```

### How It Works

```
main.py
  ├── imports from src/core/
  │   ├── pe_analyzer.py
  │   ├── security_analyzer.py (uses config_extractor)
  │   ├── file_carver.py
  │   └── dotnet_handler.py
  │
  ├── imports from src/utils/
  │   ├── __init__.py (config, reports)
  │   └── windows_integration.py
  │
  └── imports from src/web/
      └── dashboard.py
```

---

## File Usage Reference

### To Analyze a Binary
```bash
python main.py analyze sample.exe
```

### To Generate Reports
```bash
python main.py report analysis.json output.html
```

### To Build Executable
```bash
python build_exe.py
```

### To View Documentation
```bash
cat docs/QUICK_REFERENCE.md

code docs/QUICK_REFERENCE.md
```

### To Access Legacy Scripts
```bash
cat _legacy/api_hook_detector.py
```

---

## Benefits of New Organization

✅ **Clean Root** - Only essential files in root folder  
✅ **Clear Structure** - Easy to find any module  
✅ **Professional** - Enterprise-level organization  
✅ **Scalable** - Easy to add new modules  
✅ **Documented** - docs/ folder for all guides  
✅ **Archived** - Legacy code preserved for reference  
✅ **Maintainable** - Clear separation of concerns  

---

## Migration Notes

### Before (Messy)
```
ExeGap/
├── 9 root-level Python scripts
├── 17+ documentation files
├── installation scripts
├── build files
└── src/ folder (with proper code)
```

### After (Clean)
```
ExeGap/
├── Essential files (main.py, requirements.txt)
├── src/ (organized code)
├── docs/ (all documentation)
├── _legacy/ (archived scripts)
├── examples/ (future examples)
└── [other organized folders]
```

---

## Recommendations

### For Users
1. Start with `README.md` in root
2. Check `docs/QUICK_REFERENCE.md` for commands
3. Run `python main.py --help` for options

### For Developers
1. Check `src/core/` for analysis modules
2. Check `src/utils/` for utilities
3. Check `docs/CONSOLIDATION_REPORT.md` for architecture

### For Maintenance
1. Keep root folder clean
2. Add new modules to appropriate `src/` subdirectories
3. Update documentation in `docs/` folder
4. Archive old code in `_legacy/` if needed

---

## Summary

**Old**: 9 scripts scattered in root, 17+ docs, messy structure  
**New**: Professional organization with clear folders for code, docs, config, and examples

**Result**: Much easier to find things, maintain code, and add new features!