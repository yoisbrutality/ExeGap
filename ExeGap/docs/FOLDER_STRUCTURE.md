# Folder Structure

How the project is organized.

```
ExeGap/
├── README.md                 ← Overview
├── main.py                   ← Run this
├── requirements.txt          ← Dependencies
├── build_exe.py              ← Build to .exe
│
├── src/                      ← Source code
│   ├── core/
│   │   ├── pe_analyzer.py        ← Binary analysis
│   │   ├── security_analyzer.py  ← Hook detection
│   │   ├── file_carver.py        ← Extract files
│   │   ├── dotnet_handler.py     ← .NET analysis
│   │   └── config_extractor.py   ← Find secrets
│   ├── gui/
│   │   └── gui_application.py    ← Desktop UI
│   ├── utils/
│   │   ├── __init__.py           ← Config, logging
│   │   └── windows_integration.py ← Windows tools
│   └── web/
│       └── dashboard.py          ← Web UI
│
├── config/
│   └── exegap.json           ← Settings
│
├── data/                     ← Resources
│
├── build/                    ← Build files
│
├── docs/                     ← Documentation
│   ├── README.md
│   ├── QUICK_REFERENCE.md
│   ├── BUILD_GUIDE.md
│   ├── USAGE.md
│   └── ...
│
├── _legacy/                  ← Old scripts (archived)
│
└── examples/                 ← Example scripts
```

## Where Things Are

| What | Where | Purpose |
|------|-------|---------|
| Main entry point | `main.py` | Run all commands |
| Analysis code | `src/core/` | The actual work |
| GUI app | `src/gui/` | Desktop interface |
| Web app | `src/web/` | Dashboard |
| Config | `config/exegap.json` | Customize behavior |
| Help | `docs/` | Read the guides |

## Quick Start

```bash
# See all commands
python main.py --help

# Analyze a file
python main.py analyze target.exe

# Launch GUI
python main.py gui

# Start web dashboard
python main.py dashboard --port 5000
```

That's it. You don't need to worry about the internal folder structure - just use `main.py`.

## For Developers

If you want to modify the code:

- **Add security detection**: Edit `src/core/security_analyzer.py`
- **Improve PE parsing**: Edit `src/core/pe_analyzer.py`
- **Add file types to carving**: Edit `src/core/file_carver.py`
- **Enhance GUI**: Edit `src/gui/gui_application.py`
- **Customize reports**: Edit `src/utils/__init__.py`

Each module is independent and well-documented.

## Configuration

Edit `config/exegap.json` to change defaults:

```json
{
  "analysis": {
    "carve_files": true,
    "detect_packing": true,
    "analyze_dotnet": true
  },
  "output": {
    "directory": "analysis_results"
  }
}
```

That's all you need to know. See [USAGE.md](USAGE.md) for examples.